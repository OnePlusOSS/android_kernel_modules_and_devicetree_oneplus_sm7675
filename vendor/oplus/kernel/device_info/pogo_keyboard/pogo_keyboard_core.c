#include "pogo_keyboard.h"
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/clk.h>
#include <linux/debugfs.h>
#include <linux/fb.h>
#include <linux/firmware.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <uapi/linux/sched/types.h>
#include <linux/pm.h>
#include <linux/pm_wakeirq.h>
#include <linux/serial_8250.h>
#include <linux/proc_fs.h>
#include <linux/input/mt.h>
#include "owb.h"
#include <soc/oplus/dft/kernel_fb.h>
#ifndef CONFIG_REMOVE_OPLUS_FUNCTION
#include <soc/oplus/system/oplus_project.h>
#endif
#if IS_ENABLED(CONFIG_QCOM_PANEL_EVENT_NOTIFIER) && defined(CONFIG_OPLUS_POGOPIN_FUNCTION)
#include <linux/soc/qcom/panel_event_notifier.h>
#include <linux/msm_drm_notify.h>
#include <drm/drm_panel.h>
#endif

#if IS_ENABLED(CONFIG_DEVICE_MODULES_DRM_MEDIATEK) && defined(CONFIG_OPLUS_POGOPIN_FUNCTION)
#include "mtk_disp_notify.h"
#endif

#define KB_SN_HIDE_BIT_START   7
#define KB_SN_HIDE_BIT_LEN  12
#define KB_SN_HIDE_STAR_ASCII  42
struct pogo_keyboard_data *pogo_keyboard_client = NULL;
static int test_type = 0;
char TAG[60] = { 0 };

//max numbers of interval for plug-out detection.
//heartbeat interval from keyboard is 100ms.
//keyboard initialization takes about 400ms and after that first heartbeat packet is reported.
//that's to say during keyboard plug-in stage host will treat keyboard plug-out if host cannot receive heartbeat packet within 400ms.
//but host only wait 200ms after keyboard attechment is finished.
//note the host timer is 50ms.
static int max_disconnect_count = 10;
static int max_plug_in_disconnect_count = 40;
static int sn_report_count = 0;

static DECLARE_WAIT_QUEUE_HEAD(waiter);
static DECLARE_WAIT_QUEUE_HEAD(read_waiter);

//static BLOCKING_NOTIFIER_HEAD(pogo_keyboard_notifier_list);

static int pogo_keyboard_event_process(unsigned char pogo_keyboard_event);
#ifdef CONFIG_PLUG_SUPPORT
static irqreturn_t keyboard_core_plug_irq_handler(int irq, void *data);
#endif
static irqreturn_t pogo_keyboard_irq_handler(int irq, void *data);
static struct file *pogo_keyboard_port_to_file(struct uart_port *port);
#ifdef CONFIG_POWER_CTRL_SUPPORT
static void pogo_keyboard_power_enable(int value);
#endif
static int pogo_keyboard_enable_uart_tx(int value);
static int pogo_keyboard_plat_remove(struct platform_device *device);
static int pogo_keyboard_plat_suspend(struct platform_device *device);
static int pogo_keyboard_plat_resume(struct platform_device *device);
static int pogo_keyboard_input_connect(void);
static void pogo_keyboard_input_disconnect(void);
static bool pogo_keyboard_key_up(void);
static bool pogo_keyboard_touch_up(void);

void pogo_keyboard_show_buf(void *buf, int count)
{
    int i = 0;
    char temp[513] = { 0 };
    int len = 0;
    char *pbuf = (char *)buf;
    if (count > UART_BUFFER_SIZE)
        count = UART_BUFFER_SIZE;
    for (i = 0; i < count; i++) {
        len += sprintf(temp + len, "%02x", pbuf[i]);
    }
    kb_debug("%s:show_buf  len:[%d]  %s\n", TAG, count, temp);
    memset(TAG, 0, sizeof(TAG));
}

void pogo_keyboard_info_buf(void *buf, int count)
{
    int i = 0;
    char temp[513] = { 0 };
    int len = 0;
    char sync_buf[] = { 0x2f,0x04,0x05,0xaa,0xbb };
    char *pbuf = (char *)buf;
    if (count > UART_BUFFER_SIZE)
        count = UART_BUFFER_SIZE;
    if (memcmp(sync_buf, buf, sizeof(sync_buf)) == 0) {
        return;
    }
    for (i = 0; i < count; i++) {
        len += sprintf(temp + len, "%02x", pbuf[i]);
    }
    kb_info("%s:info_buf  len:[%d]  %s\n", TAG, count, temp);
    memset(TAG, 0, sizeof(TAG));
}

// start heartbeat monitor timer only when keyboard is attached. value = 1 starts timer while 0 stops.
void pogo_keyboard_heartbeat_switch(int value)
{
    ktime_t ktime = ktime_set(0, 1000 * 1000 * 50); //50ms, note that heartbeat from keyboard is 100ms(may be adjusted in the future)

    if (pogo_keyboard_client == NULL) {
        return;
    }

    if (value == 1) {
        pm_wakeup_event(&pogo_keyboard_client->plat_dev->dev, 50 + 20);
        hrtimer_start(&pogo_keyboard_client->heartbeat_timer, ktime, HRTIMER_MODE_REL);
    } else if (value == 0) {
        hrtimer_cancel(&pogo_keyboard_client->heartbeat_timer);
    }
}

// start/stop keyboard attachement first detection timer. value = 1 starts timer while 0 stops.
void pogo_keyboard_plug_switch(int value)
{
    ktime_t ktime = ktime_set(0, 1000 * 1000 * 20); //20ms

    if (pogo_keyboard_client == NULL || pogo_keyboard_client->plug_timer_one_time) {
        return;
    }

    if (value == 1) {
        pogo_keyboard_client->plug_timer_one_time = true;
        hrtimer_start(&pogo_keyboard_client->plug_timer, ktime, HRTIMER_MODE_REL);
    } else if (value == 0) {
        hrtimer_cancel(&pogo_keyboard_client->plug_timer);
    }
}

void pogo_keyboard_poweroff_timer_switch(bool state)
{
    ktime_t ktime = ktime_set(0, 1000 * 1000 * POWEROFF_TIMER_EXPIRY);

    if (pogo_keyboard_client == NULL) {
        return;
    }

    if (state) {
        pm_wakeup_event(&pogo_keyboard_client->plat_dev->dev, POWEROFF_TIMER_EXPIRY + 20);
        hrtimer_start(&pogo_keyboard_client->poweroff_timer, ktime, HRTIMER_MODE_REL);
    } else {
        hrtimer_cancel(&pogo_keyboard_client->poweroff_timer);
    }
}

void pogo_keyboard_plugin_check_timer_switch(bool state)
{
    ktime_t ktime = ktime_set(0, 1000 * 1000 * 20);

    if (pogo_keyboard_client == NULL) {
        return;
    }

    if (state) {
        pm_wakeup_event(&pogo_keyboard_client->plat_dev->dev, 40);
        hrtimer_start(&pogo_keyboard_client->plugin_check_timer, ktime, HRTIMER_MODE_REL);
    } else {
        hrtimer_cancel(&pogo_keyboard_client->plugin_check_timer);
    }
}

// api to send event to "pogo_keyboard_task".
static void pogo_keyboard_event_send(unsigned char value)
{
    struct pogo_keyboard_event send_event = { 0 };
    unsigned long flags;

    kb_info("%s %d new event:%d\n", __func__, __LINE__, value);

    spin_lock_irqsave(&pogo_keyboard_client->event_fifo_lock, flags);
    if (kfifo_avail(&pogo_keyboard_client->event_fifo) >= sizeof(struct pogo_keyboard_event)) {
        send_event.event = value;
        kfifo_in(&pogo_keyboard_client->event_fifo, &send_event, sizeof(struct pogo_keyboard_event));
        pogo_keyboard_client->flag = 1;
        wake_up_interruptible(&waiter);
    }
    spin_unlock_irqrestore(&pogo_keyboard_client->event_fifo_lock, flags);
}

//计算crc16
static unsigned short app_compute_crc16(unsigned short crc, unsigned char data, unsigned short polynomial)
{
    unsigned char i = 0;
    for (i = 0; i < 8; i++) {
        if ((((crc & 0x8000) >> 8) ^ (data & 0x80)) != 0) {
            crc <<= 1;         // shift left once
            crc ^= polynomial; // XOR with polynomial
        } else {
            crc <<= 1;         // shift left once
        }
        data <<= 1;            // Next data bit
    }
    return crc;
}

//获取crc16
unsigned short app_crc16_get(unsigned char *buf, unsigned short len, unsigned char crc_type)
{
    unsigned char i = 0;
    unsigned short crc = 0;
    unsigned short polynomial = 0;
    unsigned short crc_ibm_init_val = 0;

    if (pogo_keyboard_client && pogo_keyboard_client->crc_ibm_init_val) {
        crc_ibm_init_val = pogo_keyboard_client->crc_ibm_init_val;
    } else {
        crc_ibm_init_val = CRC_IBM_INIT_VAL;
    }
    polynomial = (crc_type == CRC_TYPE_IBM) ? POLYNOMIAL_IBM : POLYNOMIAL_CCITT;
    crc = (crc_type == CRC_TYPE_IBM) ? crc_ibm_init_val : CRC_CCITT_INIT_VAL;

    for (i = 0; i < len; i++) {
        crc = app_compute_crc16(crc, buf[i], polynomial);
    }
    if (crc_type == CRC_TYPE_IBM) {
        return crc;
    } else {
        return (unsigned short)(~crc);
    }
}

// put payloads into one wire bus protocol packet.
int uart_package_data(char *buf, int len, unsigned char *p_out, int *p_len)
{
    unsigned short i = 0;
    unsigned short need_len = 0;
    unsigned short crc16 = 0;

    //头同步码8Byte 0x55
    for (i = 0; i < 8; i++) {
        p_out[i] = ONE_WIRE_BUS_PACKET_HEAD_SYNC_CODE;
    }
    //起始码
    p_out[8] = ONE_WIRE_BUS_PACKET_XXX_START_CODE;
    //源地址
    p_out[9] = ONE_WIRE_BUS_PACKET_PAD_ADDR;
    //目标地址
    p_out[10] = ONE_WIRE_BUS_PACKET_KEYBOARD_ADDR;
    //主命令
    p_out[11] = buf[0];
    len = buf[1];
    //总长度
    p_out[12] = len;
    //子命令数据
    for (i = 0; i < len; i++) {
        p_out[13 + i] = buf[i + 2];
    }
    crc16 = app_crc16_get(&p_out[8], len + 5, CRC_TYPE_IBM);
    //CRC16
    p_out[13 + len] = (unsigned char)(crc16 >> 8);
    p_out[14 + len] = (unsigned char)(crc16 & 0x00ff);
    //结束码
    p_out[15 + len] = ONE_WIRE_BUS_PACKET_XXX_END_CODE;
    //尾同步码4byte 0xAA
    for (i = 0; i < 4; i++) {
        p_out[16 + len + i] = ONE_WIRE_BUS_PACKET_TAIL_SYNC_CODE;
    }
    need_len = 16 + len + 4;
    *p_len = need_len;
    sprintf(TAG, "%s ciphertext %d", __func__, __LINE__);
    pogo_keyboard_show_buf(p_out, *p_len);
    return 0;
}

int uart_unpack_data(char *buf, int len, unsigned char *out_buf, int *out_len)
{
    if (len > 6) {
        *out_len = len - 6;//6:start+addr1+addr2 +  end+sync+sync
        memcpy(out_buf, &buf[3], *out_len);
    }
    return 0;
}

static int upload_pogopin_kevent_data(unsigned char *payload)
{
    struct kernel_packet_info *user_msg_info;
    char log_tag[] = KEVENT_LOG_TAG;
    char event_id_pogopin[] = KEVENT_EVENT_ID;
    int len;
    int retry = 3;
    int ret = 0;

    user_msg_info = (struct kernel_packet_info *)kmalloc(
			sizeof(char) * POGOPIN_TRIGGER_MSG_LEN, GFP_KERNEL);
    if (!user_msg_info) {
        kb_err("%s: Allocation failed\n", __func__);
        return -ENOMEM;
    }

    memset(user_msg_info, 0, POGOPIN_TRIGGER_MSG_LEN);
    strncpy(user_msg_info->payload, payload, MAX_POGOPIN_PAYLOAD_LEN);
    user_msg_info->payload[MAX_POGOPIN_PAYLOAD_LEN - 1] = '\0';
    len = strlen(user_msg_info->payload);

    user_msg_info->type = 1;
    strncpy(user_msg_info->log_tag, log_tag, MAX_POGOPIN_EVENT_TAG_LEN);
    user_msg_info->log_tag[MAX_POGOPIN_EVENT_TAG_LEN - 1] = '\0';
    strncpy(user_msg_info->event_id, event_id_pogopin, MAX_POGOPIN_EVENT_ID_LEN);
    user_msg_info->event_id[MAX_POGOPIN_EVENT_ID_LEN - 1] = '\0';
    user_msg_info->payload_length = len + 1;

    do {
        ret = fb_kevent_send_to_user(user_msg_info);
        if (!ret)
            break;
        msleep(10);
    } while (retry --);

    kfree(user_msg_info);
    return ret;
}
// handle uart received data. NOTE: called by uart rx interrupt handler.
static int pogo_keyboard_mod_data_process(char *buf, int len)
{
    int value = buf[0];
    int sn_len = 0;
    int ret;

    pogo_keyboard_client->disconnect_count = 0;
    switch (value) {
        case ONE_WIRE_BUS_PACKET_GENRRAL_KEY_CMD:
            kb_debug("%s %d GENRRAL_KEY\n", __func__, __LINE__);
            pogo_keyboard_input_report(&buf[1]);
            break;
        case ONE_WIRE_BUS_PACKET_MEDIA_KEY_CMD:
            kb_debug("%s %d MEDIA_KEY\n", __func__, __LINE__);
            pogo_keyboard_mm_input_report(&buf[1]);
            break;
        case ONE_WIRE_BUS_PACKET_TOUCHPAD_CMD:
            kb_debug("%s %d TOUCHPAD\n", __func__, __LINE__);
            touchpad_input_report(&buf[1]);
            break;
        case ONE_WIRE_BUS_PACKET_SYNC_UPLOAD_CMD:
            // kb_debug("%s %d SYNC status:%2x\n", __func__, __LINE__, pogo_keyboard_client->pogo_keyboard_status);
            // packet format: 0x2F + 0x04(len=4) + 1-byte sub-cmd + 3-byte data.
            if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS) == 0) {
                //获取MAC地址及品牌标志
                if (buf[2] == 0x01 && buf[3] == 0x02) {
                    pogo_keyboard_client->keyboard_brand = buf[4];
                    memcpy((unsigned char *)&pogo_keyboard_client->mac_addr, &buf[5], 6);
                    if (pogo_keyboard_client->pogopin_touch_support && buf[1] > 9) {
                        pogo_keyboard_client->touchpad_disable_state = buf[11];
                    }
                } else if (buf[2] == 0x05 && buf[3] == 0x02) {
                    pogo_keyboard_client->keyboard_brand = buf[5];
                    memcpy((unsigned char *)&pogo_keyboard_client->mac_addr, &buf[6], 6);
                    if (pogo_keyboard_client->pogopin_touch_support && buf[1] > 10) {
                        pogo_keyboard_client->touchpad_disable_state = buf[12];
                    }
                }

                kb_info("%s %d plug in\n", __func__, __LINE__);
                pogo_keyboard_client->plug_in_count = 0; // reset heartbeat counter.
                pogo_keyboard_event_send(KEYBOARD_PLUG_IN_EVENT);

            } else if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS) != 0) {
                //     sub-cmd = 0x01: power-up sync packet, 3-byte data = 0xCC.
                //     sub-cmd = 0x05: heartbeat packet, 3-byte data = 0xAA 0xBB 0BIT:CAPSLOCK|1BIT:NUMLOCK|2BIT:MUTE|3BIT:MIC|4BIT:FNLOCK.
                if (buf[2] == 0x01) { //by power on data for after plug out quick plug in connect status not update
                    //获取MAC地址及品牌标志
                    if (buf[3] == 0x02) {
                        pogo_keyboard_client->keyboard_brand = buf[4];
                        memcpy((unsigned char *)&pogo_keyboard_client->mac_addr, &buf[5], 6);
                        if (pogo_keyboard_client->pogopin_touch_support && buf[1] > 9) {
                            pogo_keyboard_client->touchpad_disable_state = buf[11];
                        }
                    }
                    pogo_keyboard_client->pogo_keyboard_status &= ~KEYBOARD_CONNECT_STATUS;
                    pogo_keyboard_client->plug_in_count = 0;
                    kb_info("%s %d quick plug out and quick plug in\n", __func__, __LINE__);
                    pogo_keyboard_event_send(KEYBOARD_PLUG_IN_EVENT);
                } else if (buf[2] == 0x05 && buf[3] == 0x02) {
                    if (pogo_keyboard_client->pogopin_touch_support && (buf[1] > 10) &&
                        (pogo_keyboard_client->pogo_report_touch_status == 1)) {
                        pogo_keyboard_client->pogo_report_touch_status = 0;
                        pogo_keyboard_client->touchpad_disable_state = buf[12];
                        pogo_keyboard_event_send(KEYBOARD_REPORT_TOUCH_STATUS_EVENT);
                    }
                    if ((buf[4] & 0x01) != ((pogo_keyboard_client->pogo_keyboard_status >> 2) & 0x01)) { //by heartbeet data sync capslock status
                        //sync capslock led status if status reported from keyboard differs from host.
                        //note definition: KEYBOARD_CAPSLOCK_ON_STATUS  (1<<2)
                        kb_info("%s %d sync capslock:%02x\n", __func__, __LINE__, buf[5]);
                        if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_LCD_ON_STATUS) != 0) {//send led cmd to kb only if lcd is on.
                            if (((pogo_keyboard_client->pogo_keyboard_status >> 2) & 0x01) == 0x01)
                                pogo_keyboard_event_send(KEYBOARD_CAPSLOCK_ON_EVENT);
                            else
                                pogo_keyboard_event_send(KEYBOARD_CAPSLOCK_OFF_EVENT);
                        }
                    }
                    if (pogo_keyboard_client->pogopin_touch_support)
                        pogo_keyboard_touch_up();
                }

                if (buf[2] == 0x05 && (pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_LCD_ON_STATUS) == 0) {
                    pogo_keyboard_client->sync_lcd_state_cnt++;
                    if(pogo_keyboard_client->sync_lcd_state_cnt >= SYNC_LCD_STATE_CNT_MAX) {
                        pogo_keyboard_client->sync_lcd_state_cnt = 0;
                        pogo_keyboard_event_send(KEYBOARD_HOST_LCD_OFF_EVENT);
                    }
                }
            }
            break;
        case ONE_WIRE_BUS_PACKET_PARAM_SET_ACK_CMD:
        case ONE_WIRE_BUS_PACKET_OTA_ACK_CMD:
        case ONE_WIRE_BUS_PACKET_I2C_READ_ACK_CMD:
        case ONE_WIRE_BUS_PACKET_USER_GENERAL_ACK_CMD:
        case ONE_WIRE_BUS_PACKET_OTA_CMD:
        case ONE_WIRE_BUS_PACKET_PARAM_SET_CMD:
        case ONE_WIRE_BUS_PACKET_USER_GENERAL_CMD:
        case ONE_WIRE_BUS_PACKET_USER_PASSTHROUGH_CMD:
        case ONE_WIRE_BUS_PACKET_USER_PASSTHROUGH_ACK_CMD:
            if (pogo_keyboard_client->read_flag == 1) {
                kb_debug("%s %d	value:0x%2x cmd:0x%2x \n", __func__, __LINE__, value, pogo_keyboard_client->write_buf[0]);
                // judgment below is based on the assumption that response cmd code = send cmd code + 1. not universal.
                if (value == (int)pogo_keyboard_client->write_buf[0] || value == (int)pogo_keyboard_client->write_buf[0] + 1) {
                    pogo_keyboard_client->read_flag = 0;
                    wake_up_interruptible(&read_waiter);
                }
            }

            if (value == ONE_WIRE_BUS_PACKET_USER_GENERAL_ACK_CMD && buf[2] == 0x0e) {
                kb_info("keyboard batt level:%d charge:%d state:0x%x\n", buf[4], (buf[5] >> 4) & 0x03, buf[5]);
                pogo_keyboard_client->pogo_battery_power_level = (u8)buf[4];
            } else if(value == ONE_WIRE_BUS_PACKET_USER_GENERAL_ACK_CMD && buf[2] == 0x0b) {
                sn_len = (buf[3] > DEFAULT_SN_LEN) ? DEFAULT_SN_LEN : buf[3];
                ret = memcmp(pogo_keyboard_client->report_sn, &buf[4], sn_len);
                if (ret == 0 && sn_report_count >= 2) {
                    kb_info("%s:same keyboard SN ,not report\n", __func__);
                    break;
                } else if(ret != 0) {
                    sn_report_count = 0;
                }
                memset(pogo_keyboard_client->report_sn, 0, sizeof(pogo_keyboard_client->report_sn));
                memcpy(pogo_keyboard_client->report_sn, &buf[4], sn_len);
                pogo_keyboard_event_send(KEYBOARD_REPORT_SN_EVENT);
            }
            if (pogo_keyboard_client->pogopin_fw_support &&
                value == ONE_WIRE_BUS_PACKET_USER_PASSTHROUGH_ACK_CMD && buf[2] == 0x08) {
                if (buf[3] < DEFAULT_KBVER_LEN || buf[3] > KBVER_LEN_MAX) {
                    kb_err("%s %d, get keyboard version is not right format!!!\n", __func__, __LINE__);
                } else {
                    pogo_keyboard_client->kbver_len = buf[3] - 1;
                    memset(pogo_keyboard_client->report_kbver, 0, sizeof(pogo_keyboard_client->report_kbver));
                    memcpy(pogo_keyboard_client->report_kbver, &buf[4], pogo_keyboard_client->kbver_len);
                    pogo_keyboard_event_send(KEYBOARD_REPORT_KBVER_EVENT);
                }
            }
            //report log
            if (value == ONE_WIRE_BUS_PACKET_USER_GENERAL_ACK_CMD && buf[2] == 0x10) {
                if (buf[3] > KBLOG_LEN_MAX) {
                    kb_err("%s %d, log len too long!!!\n", __func__, __LINE__);
                } else {
                    pogo_keyboard_client->kblog_len = buf[3];
                    memset(pogo_keyboard_client->report_kblog, 0, sizeof(pogo_keyboard_client->report_kblog));
                    memcpy(pogo_keyboard_client->report_kblog, &buf[4], pogo_keyboard_client->kblog_len);
                    pogo_keyboard_event_send(KEYBOARD_REPORT_KBLOG_EVENT);
                }
            }
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

bool pogo_keyboard_data_is_valid(char *buf, int len)
{
    char flag = 0;
    unsigned short crc16 = 0;
    if (len < 5) {
        kb_err("keyboard data is not valid!!!\n");
        return false;
    }
    flag = buf[2];
    crc16 = (buf[len - 5] << 8) | buf[len - 4];
    kb_debug("flag:%2x crc16:%4x cal_crc:%4x\n", flag, crc16, app_crc16_get(buf, len - 5, CRC_TYPE_IBM));
    if (flag == ONE_WIRE_BUS_PACKET_KEYBOARD_ADDR || flag == ONE_WIRE_BUS_PACKET_PAD_ADDR) {
        if (crc16 == app_crc16_get(buf, len - 5, CRC_TYPE_IBM))
            return true;
        else
            return false;
    } else {
        return false;
    }
}

int pogo_keyboard_store_recv_data(char *buf, int len)
{
    int ret = 0;
    if (buf[0] == pogo_keyboard_client->write_buf[0]) {
        memcpy(pogo_keyboard_client->write_check_buf, buf, len);
        pogo_keyboard_client->write_len = len;
        ret = len;
        sprintf(TAG, "%s  %d write_check_buf ", __func__, __LINE__);
        pogo_keyboard_show_buf(pogo_keyboard_client->write_check_buf, len);
    } else if (buf[0] == (int)pogo_keyboard_client->write_buf[0] + 1) {
        memcpy(pogo_keyboard_client->read_buf, buf, len);
        pogo_keyboard_client->read_len = len;
        ret = len;
        sprintf(TAG, "%s  %d read_buf ", __func__, __LINE__);
        pogo_keyboard_show_buf(pogo_keyboard_client->read_buf, len);
    }
    return ret;
}

// handle uart received data, called by uart rx interrupt handler.
int pogo_keyboard_recv(char *buf, int len)
{
    static bool recv_start_flag = false;
    static bool recv_decode_flag = false;
    static unsigned char head_sync_code_cnt = 0;
    static unsigned char rec_temp_buf_index = 0;
    static char recv_buf[UART_BUFFER_SIZE] = { 0 };
    char data_buf[UART_BUFFER_SIZE] = { 0 };
    int out_len = 0;
    char rx_data;
    int i = 0;
    int ret = 0;
    unsigned char recv_decode_cnt = 0;
    sprintf(TAG, "%s  %d recv ", __func__, __LINE__);
    if (len > 1)
        pogo_keyboard_show_buf(buf, len);

    // the process below is based on the assumption that only one packet per transfer!!
    for (i = 0; i < len; i++) {
        rx_data = buf[i];

        if (rx_data == ONE_WIRE_BUS_PACKET_HEAD_SYNC_CODE) {
            head_sync_code_cnt++;
        } else if (rx_data == ONE_WIRE_BUS_PACKET_XXX_START_CODE || rx_data == ONE_WIRE_BUS_PACKET_XXX_REPEAT_CODE) {
            //收到起始码后，再判断起始码之前有没有收到连续的头同步码
            if (head_sync_code_cnt >= 4) {
                rec_temp_buf_index = 0;
                recv_start_flag = true;
            }
            head_sync_code_cnt = 0;
        } else {
            head_sync_code_cnt = 0;
        }

        if (recv_start_flag == true) {
            recv_buf[rec_temp_buf_index++] = rx_data;
            if (rec_temp_buf_index >= 3
                && recv_buf[rec_temp_buf_index - 1] == ONE_WIRE_BUS_PACKET_TAIL_SYNC_CODE
                && recv_buf[rec_temp_buf_index - 2] == ONE_WIRE_BUS_PACKET_TAIL_SYNC_CODE
                && recv_buf[rec_temp_buf_index - 3] == ONE_WIRE_BUS_PACKET_XXX_END_CODE) {
                //当收到0xFE,0xAA,0xAA字段时，认为接收到完整一包了，并开始进行包处理
                recv_start_flag = false;
                recv_decode_flag = true;
                recv_decode_cnt++;
                if(recv_decode_cnt > 3) {
                    recv_decode_flag = false;
                    break;
                }
            }
        }

        if (rec_temp_buf_index >= UART_BUFFER_SIZE) {
            rec_temp_buf_index = 0;
            recv_start_flag = false;
        }

        if (recv_decode_flag == true) {
            recv_decode_flag = false;
            if (rec_temp_buf_index > 6 &&
                pogo_keyboard_data_is_valid(recv_buf, rec_temp_buf_index)) {
                uart_unpack_data(recv_buf, rec_temp_buf_index, data_buf, &out_len);
                // sprintf(TAG, "%s  %d recv ", __func__, __LINE__);
                // pogo_keyboard_info_buf(data_buf, out_len);
                pogo_keyboard_store_recv_data(data_buf, out_len);

                ret = pogo_keyboard_mod_data_process(data_buf, out_len);
                if (ret) {
                    kb_err("%s %d pogo_keyboard_mod_data_process fail: %d\r\n", __func__, __LINE__, ret);
                }

            }
            rec_temp_buf_index = 0;
        }
    }
    return ret;

}

int pogo_keyboard_recv_callback(char *buf, int len)
{
    return pogo_keyboard_recv(buf, len);
}

int pogo_keyboard_get_valid_data(char *buf, int len, unsigned char *out_buf, int *out_len)
{
    int count = 0;
    count = len - 11 - 4; //11: sync*8+start+addr1+addr2  4:sync*4
    memcpy(out_buf, &buf[11], count);
    *out_len = count;
    return count;
}

ssize_t tty_write_ex(const char *buf, size_t count)
{
    ssize_t ret = 0;
    if (pogo_keyboard_client->file_client == NULL) {
        kb_err("TN %s %d err: file_client is null!\n", __func__, __LINE__);
        return -1;
    }
    ret = pogo_tty_write(pogo_keyboard_client->file_client, buf, count, NULL);
    if (ret < 0) {
        kb_err("TN %s %d err:%zd!\n", __func__, __LINE__, ret);
        return -1;
    }
    return ret;
}

static int pogo_keyboard_write(void *buf, int len)
{
    int ret = 0;
    int out_len = 0;
    int count = 3;
    void *pbuf = buf;
    char write_buf[255] = { 0 };
    //char read_buf[255] = {0};
    int write_len = 0;
    int i = 0;
    sprintf(TAG, "%s text %d", __func__, __LINE__);
    pogo_keyboard_info_buf(pbuf, len);
    memset(pogo_keyboard_client->write_buf, 0, sizeof(pogo_keyboard_client->write_buf));
    //memcpy(pogo_keyboard_client->write_buf, buf, len);
    ret = uart_package_data(pbuf, len, write_buf, &write_len);
    if (ret) {
        kb_err("%s %d err\r\n", __func__, __LINE__);
        return ret;
    }
    pogo_keyboard_get_valid_data(write_buf, write_len, pogo_keyboard_client->write_buf, &out_len);
    pogo_keyboard_client->read_flag = 1;
    for (i = 0; i < count; i++) {
        ret = tty_write_ex(write_buf, write_len);
        if (ret > 0) {
            break;
        }
    }
    if (i >= count) {
        kb_err("%s %d ret:%d i:%d err\r\n", __func__, __LINE__, ret, i);
        return ret;
    }

    wait_event_interruptible_timeout(read_waiter, pogo_keyboard_client->read_flag != 1, HZ / 20);//timeout 50ms

    if (pogo_keyboard_client->read_flag == 1) {
        kb_debug("%s %d read_flag:%d  \r\n", __func__, __LINE__, pogo_keyboard_client->read_flag);
    }
    if (pogo_keyboard_client->write_len <= 0) {
        kb_err("%s %d read_flag:%d  write_len:%d\r\n", __func__, __LINE__, pogo_keyboard_client->read_flag, pogo_keyboard_client->write_len);
        pogo_keyboard_client->read_flag = 0;
        return -1;
    }

    kb_debug("%s %d  %2x %2x\n", __func__, __LINE__, pogo_keyboard_client->write_buf[out_len - 2], pogo_keyboard_client->write_check_buf[out_len - 2]);
    if (pogo_keyboard_client->write_buf[0] == pogo_keyboard_client->write_check_buf[0] &&
        pogo_keyboard_client->write_buf[out_len - 2] == pogo_keyboard_client->write_check_buf[out_len - 2]) { //compare cmd and crc
        ret = 0;
        kb_debug("%s %d is same,write %d data ok ret:%d i:%d!\n", __func__, __LINE__, out_len, ret, i);
    } else {
        ret = -1;
        kb_err("%s %d is not same %d data err!\n", __func__, __LINE__, out_len);
    }

    pogo_keyboard_client->write_len = 0;
    memset(pogo_keyboard_client->write_check_buf, 0, UART_BUFFER_SIZE);
    return ret;
}

static int pogo_keyboard_read(void *buf, int *r_len)
{

    kb_debug("%s %d start\r\n", __func__, __LINE__);
    pogo_keyboard_client->read_flag = 1;
    wait_event_interruptible_timeout(read_waiter, pogo_keyboard_client->read_flag != 1, HZ / 10);//timeout 100ms

    if (pogo_keyboard_client->read_flag == 1) {
        kb_debug("%s %d read_flag:%d  \r\n", __func__, __LINE__, pogo_keyboard_client->read_flag);
    }
    if (pogo_keyboard_client->read_len <= 0) {
        kb_err("%s %d read_len:%d  err\r\n", __func__, __LINE__, pogo_keyboard_client->read_len);
        pogo_keyboard_client->read_flag = 0;
        return -1;
    }
    kb_info("%s %d read_flag:%d len:%d ok\r\n", __func__, __LINE__, pogo_keyboard_client->read_flag, pogo_keyboard_client->read_len);


    memcpy(buf, pogo_keyboard_client->read_buf, pogo_keyboard_client->read_len);
    *r_len = pogo_keyboard_client->read_len;


    memset(pogo_keyboard_client->read_buf, 0, sizeof(pogo_keyboard_client->read_buf));
    sprintf(TAG, "%s text %d", __func__, __LINE__);
    pogo_keyboard_show_buf(buf, *r_len);
    pogo_keyboard_client->read_len = 0;
    memset(pogo_keyboard_client->read_buf, 0, UART_BUFFER_SIZE);

    return 0;
}

static int pogo_keyboard_write_and_read(void *w_buf, int w_len, void *r_buf, int *r_len)
{
    int ret = 0;
    int i = 0;
    int count = 3;
    pm_stay_awake(&pogo_keyboard_client->plat_dev->dev);

    for (i = 0; i < count; i++) {
        kb_debug("%s %d read_flag:%d i:%d start\r\n", __func__, __LINE__, pogo_keyboard_client->read_flag, i);
        ret = pogo_keyboard_write(w_buf, w_len);
        if (ret) {
            mdelay(50);
            continue;
        }

        if (r_buf == NULL) {
            break;
        }

        ret = pogo_keyboard_read(r_buf, r_len);
        if (ret == 0) {
            break;
        }
    }
    pm_relax(&pogo_keyboard_client->plat_dev->dev);
    if (i >= count) {
        kb_err("%s %d  ret:%d i:%d err\r\n", __func__, __LINE__, ret, i);
        return ret;
    }
    kb_debug("%s %d ret:%d i:%d ok\r\n", __func__, __LINE__, ret, i);
    return 0;
}

#if defined(CONFIG_KB_DEBUG_FS)
//read touchpad version from keyboard.
int  pogo_keyboard_tp_ver(void)
{

    char ver_reg[] = { ONE_WIRE_BUS_PACKET_I2C_WRITE_CMD, 0x01, 0x07 };

    char temp[100] = { 0 };
    int read_len = 0;
    int ret = 0;

    ret = pogo_keyboard_write_and_read(ver_reg, sizeof(ver_reg), temp, &read_len);
    if (ret < 0) {
        kb_err("%s %d err:ret:%d \n", __func__, __LINE__, ret);
        return ret;
    }
    //kb_debug("%s %d write:ret:%d \n",__func__,__LINE__,ret);

    pogo_keyboard_show_buf(temp, read_len);
    return 0;
}

//read keyboard version.
int  pogo_keyboard_ver(void)
{
    char ver_reg[] = { ONE_WIRE_BUS_PACKET_USER_PASSTHROUGH_CMD, 0x03, 0x08,0x01, 0x01 };
    char buf[] = { ONE_WIRE_BUS_PACKET_USER_PASSTHROUGH_ACK_CMD };
    char temp[100] = { 0 };
    int read_len = 0;
    int count = 3;
    int ret = 0;
    int i = 0;
    for (i = 0; i < count; i++) {
        ret = pogo_keyboard_write_and_read(ver_reg, sizeof(ver_reg), temp, &read_len);
        if (ret < 0) {
            kb_err("%s %d err:ret:%d \n", __func__, __LINE__, ret);
            continue;
        }
        if (memcmp(temp, buf, sizeof(buf)) == 0) {
            break;
        }
    }

    if (i >= count) {
        kb_err("%s %d err:ret:%d \n", __func__, __LINE__, ret);
        return -1;
    }
    return 0;

}

void pogo_keyboard_reliability_test(void)
{
    int i = 0;
    int ret = 0;
    int sum = 0;
    int count = 3;//2000;
    kb_debug("%s %d start i:%d\n", __func__, __LINE__, i);
    for (i = 0; i < count; i++) {
        if (test_type == 1) {
            ret = pogo_keyboard_ver();
        } else if (test_type == 2) {
            ret = pogo_keyboard_tp_ver();
        } else {
            kb_err("%s %d no test mode %d\r\n", __func__, __LINE__, test_type);
            return;
        }
        if (ret != 0) {
            kb_err("%s %d i:%d err\r\n", __func__, __LINE__, i);
            sum++;
        }
    }
    if (sum != 0) {
        kb_err("%s %d fail! sum:%d\r\n", __func__, __LINE__, sum);
    }
    kb_debug("%s %d end ok i:%d sum:%d \n", __func__, __LINE__, i, sum);
}

void pogo_keyboard_test(void)
{
    pogo_keyboard_reliability_test();
}
#endif//CONFIG_KB_DEBUG_FS

int pogo_keyboard_get_charge_current(void)
{
    char info_reg[] = {ONE_WIRE_BUS_PACKET_USER_GENERAL_CMD, 0x03, 0x09, 0x01, 0x01};
    char buf[] = {ONE_WIRE_BUS_PACKET_USER_GENERAL_ACK_CMD, 0x06, 0x09, 0x04};
    char temp[128] = {0};
    int read_len = 0;
    int count = 3;
    int ret = 0, i = 0;
    int charge_current = -1;

    for (i = 0; i < count; i++) {
        ret = pogo_keyboard_write_and_read(info_reg, sizeof(info_reg), temp, &read_len);
        if (ret < 0) {
            kb_err("%s %d err:ret:%d \n", __func__, __LINE__, ret);
            continue;
        }
        if (memcmp(temp, buf, sizeof(buf)) == 0) {
            break;
        }
    }
    if (i >= count) {
        kb_err("%s %d err:ret:%d \n", __func__, __LINE__, ret);
        return charge_current;
    }
    charge_current = (temp[7] << 8) + temp[6];
    kb_debug("%s %d current=%dmA\n", __func__, __LINE__, charge_current);

    return charge_current;
}
// output leds control cmd to keyboard.
static int pogo_keyboard_set_led(char event)
{
    int ret = 0;
    char led_buf[] = { ONE_WIRE_BUS_PACKET_PARAM_SET_CMD, 0x06, 0x0D, 0x04, 0x00, 0x00, 0x00, 0x00 };

    kb_debug("%s %d pogo_keyboard_event:%d  pogo_keyboard_status:0x%02x\n", __func__, __LINE__, event, pogo_keyboard_client->pogo_keyboard_status);


    if (pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CAPSLOCK_ON_STATUS) {
        led_buf[4] = 0x01;
    }
    if (pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_MUTEDISABLE_ON_STATUS) {
        led_buf[6] = 0x01;
    }
    if (pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_MICDISABLE_ON_STATUS) {
        led_buf[7] = 0x01;
    }

    kb_debug("%s %d pogo_keyboard_event:%d  pogo_keyboard_status:0x%02x\n", __func__, __LINE__, event, pogo_keyboard_client->pogo_keyboard_status);

    // if(event >= KEYBOARD_CAPSLOCK_ON_EVENT)
    mdelay(15);
    switch (event) {
        case  KEYBOARD_HOST_LCD_ON_EVENT:
            kb_debug("%s %d %d\r\n", __func__, __LINE__, event);
            ret = pogo_keyboard_write(led_buf, sizeof(led_buf));
            if (ret) {
                kb_err("%s %d err\r\n", __func__, __LINE__);
                return ret;
            }
            break;
        case KEYBOARD_HOST_LCD_OFF_EVENT:
            kb_debug("%s %d %d\r\n", __func__, __LINE__, event);
            memset(&led_buf[4], 0, 4);
            ret = pogo_keyboard_write(led_buf, sizeof(led_buf));
            if (ret) {
                kb_err("%s %d err\r\n", __func__, __LINE__);
                //return ret;
            }
            break;
        case KEYBOARD_PLUG_IN_EVENT:
            kb_debug("%s %d %d\r\n", __func__, __LINE__, event);;
            ret = pogo_keyboard_write(led_buf, sizeof(led_buf));
            if (ret) {
                kb_err("%s %d err\r\n", __func__, __LINE__);
                //return ret;
            }
            break;
        case KEYBOARD_PLUG_OUT_EVENT:  /* for pre development test*/
            kb_debug("%s %d %d\r\n", __func__, __LINE__, event);
            memset(&led_buf[4], 0, 4);
            ret = pogo_keyboard_write(led_buf, sizeof(led_buf));
            if (ret) {
                kb_err("%s %d err\r\n", __func__, __LINE__);
                //return ret;
            }
            break;

        case KEYBOARD_CAPSLOCK_ON_EVENT:
            kb_debug("%s %d %d\r\n", __func__, __LINE__, event);

            led_buf[4] = 0x01;
            ret = pogo_keyboard_write(led_buf, sizeof(led_buf));
            if (ret) {
                kb_err("%s %d err\r\n", __func__, __LINE__);
                //return ret;
            }

            break;
        case KEYBOARD_CAPSLOCK_OFF_EVENT:
            kb_debug("%s %d %d\r\n", __func__, __LINE__, event);

            led_buf[4] = 0x00;
            ret = pogo_keyboard_write(led_buf, sizeof(led_buf));
            if (ret) {
                kb_err("%s %d err\r\n", __func__, __LINE__);
                //return ret;
            }

            break;


        case KEYBOARD_MUTEDISABLE_ON_EVENT:
            kb_debug("%s %d %d\r\n", __func__, __LINE__, event);

            led_buf[6] = 0x01;
            ret = pogo_keyboard_write(led_buf, sizeof(led_buf));
            if (ret) {
                kb_err("%s %d err\r\n", __func__, __LINE__);
                //return ret;
            }

            break;
        case KEYBOARD_MUTEDISABLE_OFF_EVENT:
            kb_debug("%s %d %d\r\n", __func__, __LINE__, event);

            led_buf[6] = 0x00;
            ret = pogo_keyboard_write(led_buf, sizeof(led_buf));
            if (ret) {
                kb_err("%s %d err\r\n", __func__, __LINE__);
                //return ret;
            }


            break;

        case KEYBOARD_MICDISABLE_ON_EVENT:
            kb_debug("%s %d %d\r\n", __func__, __LINE__, event);

            led_buf[7] = 0x01;
            ret = pogo_keyboard_write(led_buf, sizeof(led_buf));
            if (ret) {
                kb_err("%s %d err\r\n", __func__, __LINE__);
                return ret;
            }

            break;
        case KEYBOARD_MICDISABLE_OFF_EVENT:
            kb_debug("%s %d %d\r\n", __func__, __LINE__, event);

            led_buf[7] = 0x00;
            ret = pogo_keyboard_write(led_buf, sizeof(led_buf));
            if (ret) {
                kb_err("%s %d err\r\n", __func__, __LINE__);
                //return ret;
            }

            break;
        default:
            kb_err("%s %d no event to do err\r\n", __func__, __LINE__);
            break;
    }
    sprintf(TAG, "%s %d", __func__, __LINE__);
    pogo_keyboard_show_buf(led_buf, sizeof(led_buf));
    kb_debug("%s %d pogo_keyboard_event:%d  pogo_keyboard_status:0x%02x\n", __func__, __LINE__, event, pogo_keyboard_client->pogo_keyboard_status);
    return ret;
}

// sync host lcd/screen on/off(sleep/wakeup state) state to keyboard. state=1 means wakeup while 0 means going to sleep.
static int pogo_keyboard_set_lcd_state(bool state)
{
    int ret = 0;
    char write_buf[] = { ONE_WIRE_BUS_PACKET_USER_GENERAL_CMD, 0x03, 0x02, 0x01, 0x01 };
    char buf[] = { ONE_WIRE_BUS_PACKET_USER_GENERAL_ACK_CMD, 0x04, 0x02, 0x02, 0x01};
    char read_buf[255] = { 0 };
    int read_len = 0;
    int i = 0;

    kb_debug("%s %d state:%d\r\n", __func__, __LINE__, state);
    if (state) {
        write_buf[4] = 0x00;
        buf[4] = 0x00;
    } else {
        write_buf[4] = 0x01;
        buf[4] = 0x01;
    }
    for (i = 0; i < 3; i++) {
        ret = pogo_keyboard_write_and_read(write_buf, sizeof(write_buf), read_buf, &read_len);
        if (ret) {
            continue;
        }
        if (memcmp(read_buf, buf, sizeof(buf)) == 0) {

            if (read_buf[5] == 1)
                break;

        }
    }
    if (i >= 3) {
        kb_err("%s %d err ret:0x%02x status:%d\n", __func__, __LINE__, ret, read_buf[5]);
        return ret;
    }

    sprintf(TAG, "%s %d", __func__, __LINE__);
    pogo_keyboard_show_buf(read_buf, read_len);
    kb_debug("%s %d ok ret:0x%02x status:%d\n", __func__, __LINE__, ret, read_buf[5]);

    return 0;
}

static int pogo_keyboard_get_sn(void)
{
    char sn_reg[] = {ONE_WIRE_BUS_PACKET_USER_GENERAL_CMD, 0x04, 0x0b, 0x02, 0x02, 0x14};
    char buf[] = { ONE_WIRE_BUS_PACKET_USER_GENERAL_ACK_CMD };
    char temp[100] = { 0 };
    int read_len = 0;
    int count = 3;
    int ret = 0;
    int i = 0;
    for (i = 0; i < count; i++) {
        ret = pogo_keyboard_write_and_read(sn_reg, sizeof(sn_reg), temp, &read_len);
        if (ret < 0) {
            kb_err("%s %d err:ret:%d \n", __func__, __LINE__, ret);
            continue;
        }
        if (memcmp(temp, buf, sizeof(buf)) == 0 && temp[2] == 0x0b) {
            break;
        }
    }

    if (i >= count) {
        kb_err("%s %d err:ret:%d \n", __func__, __LINE__, ret);
        return -1;
    }
    return 0;

}

/*OTA update online
1.read mcu keyboard version
2.send ota file infomation
3.send ota file datas
4.send ota end infomation
5.ota end reset mcu
*/

static int pogo_keyboard_mcu_version(void)
{
    int ret = 0;
    char write_buf[] = { ONE_WIRE_BUS_PACKET_OTA_CMD, 0x03, 0x01, 0x01, 0x01};
    char buf[] = { ONE_WIRE_BUS_PACKET_OTA_ACK_CMD, 0x06, 0x01, 0x04};
    char read_buf[255] = { 0 };
    int read_len = 0;
    int i = 0;

    for (i = 0; i < 3; i++) {
        ret = pogo_keyboard_write_and_read(write_buf, sizeof(write_buf), read_buf, &read_len);
        if (ret) {
            continue;
        }
        if (memcmp(read_buf, buf, sizeof(buf)) == 0) {
            pogo_keyboard_client->kpdmcu_mcu_version = (read_buf[5] << 8) | read_buf[4];
            kb_debug("%s %d, kpdmcu_mcu_version:0x%x\n", __func__, __LINE__, pogo_keyboard_client->kpdmcu_mcu_version);
            break;
        } else {
            ret = -EINVAL;
        }
    }
    if (i >= 3) {
        kb_err("%s %d err ret:0x%02x\n", __func__, __LINE__, ret);
        pogo_keyboard_client->kpdmcu_mcu_version = 0;
        return ret;
    }
    return 0;
}

static int pogo_keyboard_ota_start_end(u32 len, u32 start_addr, u32 checksum, int version, bool start)
{
    int ret = 0;
    char write_buf[18] = { ONE_WIRE_BUS_PACKET_OTA_CMD, 0x10, 0x02, 0x0E};
    char buf[5] = { ONE_WIRE_BUS_PACKET_OTA_ACK_CMD, 0x04, 0x02, 0x02, 0x00};
    char read_buf[255] = { 0 };
    int read_len = 0;
    int i = 0;

    pm_stay_awake(&pogo_keyboard_client->plat_dev->dev);
    //ack len: ota start 0x04, ota end 0x07
    buf[1] = start ? 0x04 : 0x0b;
    //sub cmd : ota start 0x02, ota end 0x04
    write_buf[2] = start ? 0x02 : 0x04;
    buf[2] = start ? 0x02 : 0x04;
    //ack data len: ota start 0x02, ota end 0x05
    buf[3] = start ? 0x02 : 0x09;
    //ota file info data: 4byte len + 4byte start address + 1byte checksum + 2byte version
    write_buf[4] = (char)(len & 0xff);
    write_buf[5] = (char)((len & 0xff00) >> 8);
    write_buf[6] = (char)((len & 0xff0000) >> 16);
    write_buf[7] = (char)((len & 0xff000000) >> 24);
    write_buf[8] = (char)(start_addr & 0xff);
    write_buf[9] = (char)((start_addr & 0xff00) >> 8);
    write_buf[10] = (char)((start_addr & 0xff0000) >> 16);
    write_buf[11] = (char)((start_addr & 0xff000000) >> 24);
    write_buf[12] = (char)(checksum & 0xff);
    write_buf[13] = (char)((checksum & 0xff00) >> 8);
    write_buf[14] = (char)((checksum & 0xff0000) >> 16);
    write_buf[15] = (char)((checksum & 0xff000000) >> 24);
    write_buf[16] = (char)(version & 0xff);
    write_buf[17] = (char)((version & 0xff00) >> 8);

    for (i = 0; i < 3; i++) {
        ret = pogo_keyboard_write(write_buf, sizeof(write_buf));
        if (ret) {
            mdelay(50);
            continue;
        }
        mdelay(200);
        ret = pogo_keyboard_read(read_buf, &read_len);
        if (ret == 0) {
            if (memcmp(read_buf, buf, sizeof(buf)) == 0) {
                kb_debug("%s %d send ota file infomation success.\n", __func__, __LINE__);
                break;
            } else {
                kb_err("%s %d, read status:%d\n", __func__, __LINE__, read_buf[4]);
                ret = -EINVAL;
            }
        } else {
            mdelay(50);
            continue;
        }
    }
    if (i >= 3) {
        kb_err("%s %d err ret:0x%02x\n", __func__, __LINE__, ret);
        return ret;
    }
    pm_relax(&pogo_keyboard_client->plat_dev->dev);
    return 0;
}

static int pogo_keyboard_ota_write_datas(const unsigned char *fw_data, u32 len)
{
    int ret = 0;
    int i = 0;
    int j = 0;
    char write_buf[ONE_WRITY_LEN_MAX + 11] =
            { ONE_WIRE_BUS_PACKET_OTA_CMD, ONE_WRITY_LEN_MAX + 9, 0x03, ONE_WRITY_LEN_MAX + 7};
    char buf[11] = { ONE_WIRE_BUS_PACKET_OTA_ACK_CMD, 0x09, 0x03, 0x07};
    char read_buf[255] = { 0 };
    int read_len = 0;
    u32 write_len = 0, fw_len = 0, fw_offset = 0;
    char send_rx[ONE_WRITY_LEN_MAX] = {0};
    int package_index = 0;

    fw_len = len;
    while (fw_len) {
        write_len = (fw_len < ONE_WRITY_LEN_MAX) ? fw_len : ONE_WRITY_LEN_MAX;
        kb_debug("%s %d write_len:0x%08x\n", __func__, __LINE__, write_len);
        for(i = 0; i < write_len; i++) {
            send_rx[i] = fw_data[fw_offset + i];
        }
        if(fw_len < ONE_WRITY_LEN_MAX) {
            for(i = 0; i < ONE_WRITY_LEN_MAX - fw_len; i++) {
                //fill one package with 0x00
                send_rx[ONE_WRITY_LEN_MAX - i -1] = 0x00;
            }
        }
        write_buf[1] = (fw_len < ONE_WRITY_LEN_MAX) ? fw_len + 9 : ONE_WRITY_LEN_MAX + 9;
        write_buf[3] = (fw_len < ONE_WRITY_LEN_MAX) ? fw_len + 7 : ONE_WRITY_LEN_MAX + 7;
        //ota  write datas: 4byte offset address + 2byte package index + 1byte len + (n-7)byte datas
        write_buf[4] = (char)(fw_offset & 0xff);
        write_buf[5] = (char)((fw_offset & 0xff00) >> 8);
        write_buf[6] = (char)((fw_offset & 0xff0000) >> 16);
        write_buf[7] = (char)((fw_offset & 0xff000000) >> 24);
        write_buf[8] = (char)(package_index & 0xff);
        write_buf[9] = (char)((package_index & 0xff00) >> 8);
        write_buf[10] = write_len;
        memcpy(&write_buf[11], send_rx, sizeof(send_rx));

        for (j = 0; j < 3; j++) {
            ret = pogo_keyboard_write_and_read(write_buf, sizeof(write_buf), read_buf, &read_len);
            if (ret) {
                continue;
            }
            if (memcmp(read_buf, buf, 4) == 0) {
                if ((read_buf[4] == 0) &&
                    ((memcmp(&read_buf[5], &write_buf[8], 2)) == 0) &&
                    ((memcmp(&read_buf[7], &write_buf[4], 4)) == 0)) {
                    kb_debug("%s %d send ota data success, package_index:%d, fw_offset:0x%08x\n",
                        __func__, __LINE__, package_index, fw_offset);
                    break;
                } else {
                    pogo_keyboard_show_buf(read_buf, read_len);
                    kb_debug("%s %d send ota data ack status:%d\n", __func__, __LINE__, read_buf[4]);
                    ret = -EINVAL;
                }
            } else {
                ret = -EINVAL;
            }
        }
        if (j >= 3) {
            kb_err("%s %d err ret:0x%02x\n", __func__, __LINE__, ret);
            return ret;
        }

        package_index++;
        fw_offset += write_len;
        fw_len -= write_len;
        kb_debug("%s %d package_index:%d,fw_offset:0x%08x,fw_len:0x%08x\n", __func__, __LINE__, package_index, fw_offset, fw_len);
        if(pogo_keyboard_client->fw_update_progress < FW_PROGRESS_96 * FW_PERCENTAGE_100) {
            pogo_keyboard_client->fw_update_progress = FW_PROGRESS_3 * FW_PERCENTAGE_100 +
                FW_PROGRESS_93 * (len - fw_len) * FW_PERCENTAGE_100 / len;
        } else {
            pogo_keyboard_client->fw_update_progress = FW_PROGRESS_96 * FW_PERCENTAGE_100  +
                FW_PROGRESS_93 * (len - fw_len) * FW_PERCENTAGE_100 / len;
        }
    }

    return 0;
}

static int pogo_keyboard_ota_end_reset(void)
{
    int ret = 0;
    char write_buf[] = { ONE_WIRE_BUS_PACKET_OTA_CMD, 0x06, 0x05, 0x04, 0x57, 0x4e, 0x38, 0x30};
    char buf[] = { ONE_WIRE_BUS_PACKET_OTA_ACK_CMD, 0x03, 0x05, 0x01, 0x00};
    char read_buf[255] = { 0 };
    int read_len = 0;
    int i = 0;

    for (i = 0; i < 3; i++) {
        ret = pogo_keyboard_write_and_read(write_buf, sizeof(write_buf), read_buf, &read_len);
        if (ret) {
            continue;
        }
        if (memcmp(read_buf, buf, sizeof(buf)) == 0) {
            kb_debug("%s %d  success!!!\n", __func__, __LINE__);
            break;
        } else {
            kb_debug("%s %d ota reset ack status:%d\n", __func__, __LINE__, read_buf[4]);
            ret = -EINVAL;
        }
    }
    if (i >= 3) {
        kb_err("%s %d err ret:0x%02x\n", __func__, __LINE__, ret);
        return ret;
    }
    return 0;
}

void pogo_keyboard_led_report(int key_value)
{
    char value = 0;
    if (!(key_value == KEY_CAPSLOCK || key_value == KEY_MUTE || key_value == KEY_MICDISABLE))
        return;
    kb_debug("%s %d key_value:%d\r\n", __func__, __LINE__, key_value);

    // NOTE: currently caps lock led is controlled by upper system layer while nothing is done here.
    // should other leds follow the same? need further consideration in the future.
    if (key_value == KEY_CAPSLOCK) {
        return;
        if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CAPSLOCK_ON_STATUS) == 0) {
            pogo_keyboard_client->pogo_keyboard_status |= KEYBOARD_CAPSLOCK_ON_STATUS;
        } else {
            pogo_keyboard_client->pogo_keyboard_status &= (~KEYBOARD_CAPSLOCK_ON_STATUS);
        }

        kb_debug("%s %d key_value:%d value:%d\r\n", __func__, __LINE__, key_value, value);

    } else if (key_value == KEY_MUTE) {
        if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_MUTEDISABLE_ON_STATUS) == 0) {
            pogo_keyboard_client->pogo_keyboard_status |= KEYBOARD_MUTEDISABLE_ON_STATUS;
        } else {
            pogo_keyboard_client->pogo_keyboard_status &= (~KEYBOARD_MUTEDISABLE_ON_STATUS);
        }
        value = pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_MUTEDISABLE_ON_STATUS;
        input_event(pogo_keyboard_client->input_pogo_keyboard, EV_LED, LED_MUTE, !!value);
        kb_debug("%s %d key_value:%d value:%d\r\n", __func__, __LINE__, key_value, value);

    } else if (key_value == KEY_MICDISABLE) {
        if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_MICDISABLE_ON_STATUS) == 0) {
            pogo_keyboard_client->pogo_keyboard_status |= KEYBOARD_MICDISABLE_ON_STATUS;
        } else {
            pogo_keyboard_client->pogo_keyboard_status &= (~KEYBOARD_MICDISABLE_ON_STATUS);
        }
        value = pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_MICDISABLE_ON_STATUS;
        input_event(pogo_keyboard_client->input_pogo_keyboard, EV_LED, LED_MIC_MUTE, !!value);
        kb_debug("%s %d key_value:%d value:%d\r\n", __func__, __LINE__, key_value, value);
    }

}

void pogo_keyboard_led_process(int code, int value)
{
    unsigned char event = 0;

    kb_info("%s %d  type:led code:0x%02x value:0x%02x\n", __func__, __LINE__, code, value);
    switch (code) {
        case LED_CAPSL:
            if (value == 1) {
                event = KEYBOARD_CAPSLOCK_ON_EVENT;
                pogo_keyboard_client->pogo_keyboard_status |= KEYBOARD_CAPSLOCK_ON_STATUS;
            } else {
                event = KEYBOARD_CAPSLOCK_OFF_EVENT;
                pogo_keyboard_client->pogo_keyboard_status &= (~KEYBOARD_CAPSLOCK_ON_STATUS);
            }
            break;
        case LED_MUTE:
            if (value == 1) {
                event = KEYBOARD_MUTEDISABLE_ON_EVENT;
                pogo_keyboard_client->pogo_keyboard_status |= KEYBOARD_MUTEDISABLE_ON_STATUS;
            } else {
                event = KEYBOARD_MUTEDISABLE_OFF_EVENT;
                pogo_keyboard_client->pogo_keyboard_status &= (~KEYBOARD_MUTEDISABLE_ON_STATUS);
            }
            break;
        case LED_MIC_MUTE:
            if (value == 1) {
                event = KEYBOARD_MICDISABLE_ON_EVENT;
                pogo_keyboard_client->pogo_keyboard_status |= KEYBOARD_MICDISABLE_ON_STATUS;
            } else {
                event = KEYBOARD_MICDISABLE_OFF_EVENT;
                pogo_keyboard_client->pogo_keyboard_status &= (~KEYBOARD_MICDISABLE_ON_STATUS);
            }
            break;
        default:
            kb_debug("%s %d  type:led code:0x%2x value:0x%2x no support err!\n", __func__, __LINE__, code, value);
            return;
    }
    if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_LCD_ON_STATUS) == 0)
        return;

    pogo_keyboard_event_send(event);
}

// monitor lcd/screen on/off state.
void pogo_keyboard_sync_lcd_state(bool lcd_on_state)
{
    kb_debug("%s %d lcd_on_state:%d\n", __func__, __LINE__, lcd_on_state);
    if (lcd_on_state) {
        kb_info("%s %d pogo_keyboard goto wakeup\r\n", __func__, __LINE__);
        pogo_keyboard_event_send(KEYBOARD_HOST_LCD_ON_EVENT);
    } else {
        kb_info("%s %d pogo_keyboard goto sleep\r\n", __func__, __LINE__);
        pogo_keyboard_event_send(KEYBOARD_HOST_LCD_OFF_EVENT);
    }

    return;
}

static int pogo_keyboard_enable_uart_tx(int value)
{
    if (pogo_keyboard_client->file_client == NULL)
        return -1;
    if (value == 1) {
        if (gpio_get_value(pogo_keyboard_client->tx_en_gpio) == 0) {
            kb_info("%s %d %d 0x%02x\n", __func__, __LINE__, value, pogo_keyboard_client->pogo_keyboard_status);
            //gpio_direction_output(pogo_keyboard_client->tx_en_gpio, 1);
            gpio_set_value(pogo_keyboard_client->tx_en_gpio, 1);
            udelay(450);//for set mode valid
        }
    } else if (value == 0) {
        if (gpio_get_value(pogo_keyboard_client->tx_en_gpio) == 1) {
            kb_info("%s %d %d\n", __func__, __LINE__, value);
            udelay(300); //for set mode valid
            gpio_set_value(pogo_keyboard_client->tx_en_gpio, 0);
            //gpio_direction_output(pogo_keyboard_client->tx_en_gpio, 0);
        }
    }
    return 0;
}

bool pogo_keyboard_is_support(struct uart_port *port)
{
    bool ret = false;
    if (!port || !pogo_keyboard_client)
        return false;
    if (!strncmp(port->name, pogo_keyboard_client->tty_name, strlen(pogo_keyboard_client->tty_name))) {
        ret = true;
    }
    return ret;
}

static int pogo_keyboard_get_dts_info(struct platform_device *pdev)
{
    struct device_node *node = NULL;
    struct platform_device *device = pdev;
    u32 temp_data = 0;
    int ret = 0;

    kb_debug("%s %d start\n", __func__, __LINE__);

    node = device->dev.of_node;
    if (!node) {
        kb_err("of node is not null\n");
        return -EINVAL;
    }

    ret = of_property_read_string(node, "tty-name-string", (const char **)&pogo_keyboard_client->tty_name);
    if (ret) {
        kb_err("%s %d read tty name err: %d\n", __func__, __LINE__, ret);
        return ret;
    }

    if (of_get_property(node, "touchpad-xy-max", NULL)) {
        pogo_keyboard_client->pogopin_touch_support = true;
        ret = of_property_read_u32_index(node, "touchpad-xy-max", 0, &pogo_keyboard_client->touchpad_x_max);
        if (ret) {
            kb_err("%s %d read touchpad-xy-max err: %d\n", __func__, __LINE__, ret);
            return ret;
        }
        ret = of_property_read_u32_index(node, "touchpad-xy-max", 1, &pogo_keyboard_client->touchpad_y_max);
        if (ret) {
            kb_err("%s %d read touchpad-xy-max err: %d\n", __func__, __LINE__, ret);
            return ret;
        }
    }

    pogo_keyboard_client->pogo_battery_support = of_property_read_bool(node, "pogopin-battery-support");
    kb_info("%s %d pogo_keyboard_client->pogo_battery_support: %d\n", __func__, __LINE__, pogo_keyboard_client->pogo_battery_support);

    if (of_get_property(node, "id-product", NULL)) {
        ret = of_property_read_u32_index(node, "id-product", 0, &temp_data);
        if (ret) {
            kb_err("%s %d read id-product err: %d\n", __func__, __LINE__, ret);
            return ret;
        }
        pogo_keyboard_client->pogo_id_product = (unsigned short)temp_data;
    }

    if (of_get_property(node, "crc-ibm-init-val", NULL)) {
        ret = of_property_read_u32_index(node, "crc-ibm-init-val", 0, &temp_data);
        if (ret) {
            kb_err("%s %d read crc-ibm-init-val err: %d\n", __func__, __LINE__, ret);
            return ret;
        }
        pogo_keyboard_client->crc_ibm_init_val = (unsigned short)temp_data;
        pogo_keyboard_client->get_crc_ibm_from_dts = true;
    }

    if (of_get_property(node, "pogopin-kb-fw-support", NULL)) {
        kb_debug("%s %d pogopin-kb-fw-support\n", __func__, __LINE__);
        pogo_keyboard_client->pogopin_fw_support = true;
        ret = of_property_read_u32_index(node, "ota-customize-datas", 0, &temp_data);
        if (ret) {
            kb_err("%s %d read ota_start_addr err: %d\n", __func__, __LINE__, ret);
            return ret;
        }
        pogo_keyboard_client->ota_start_addr = temp_data;

        ret = of_property_read_u32_index(node, "ota-customize-datas", 1, &temp_data);
        if (ret) {
            kb_err("%s %d ota_get_version_addr err: %d\n", __func__, __LINE__, ret);
            return ret;
        }
        pogo_keyboard_client->ota_get_version_addr = temp_data;

        ret = of_property_read_u32_index(node, "ota-customize-datas", 2, &temp_data);
        if (ret) {
            kb_err("%s %d read ota_one_write_len_max err: %d\n", __func__, __LINE__, ret);
            return ret;
        }
        pogo_keyboard_client->ota_send_data_start_addr = temp_data;

        ret = of_property_read_string(node, "ota-firmware-name", (const char **)&pogo_keyboard_client->ota_firmware_name);
        if (ret) {
            kb_err("%s %d read ota_firmware_name err: %d\n", __func__, __LINE__, ret);
            return ret;
        }
    }

#ifdef CONFIG_PLUG_SUPPORT
    pogo_keyboard_client->plug_gpio = of_get_named_gpio(node, "plug-gpios", 0);
    if (!gpio_is_valid(pogo_keyboard_client->plug_gpio)) {
        kb_err("plug_gpio is not valid %d\n", pogo_keyboard_client->plug_gpio);
        return -EINVAL;
    }
    kb_debug("%s %d plug_gpio:%d\n", __func__, __LINE__, pogo_keyboard_client->plug_gpio);

    ret = gpio_request_one(pogo_keyboard_client->plug_gpio, GPIOF_DIR_IN, "keyboard_plug_gpio");
    if (ret) {
        kb_err("%s %d gpio_request_one err:%d\n", __func__, __LINE__, ret);
        return ret;
    }

    pogo_keyboard_client->plug_irq = gpio_to_irq(pogo_keyboard_client->plug_gpio);
    ret = devm_request_threaded_irq(&device->dev, pogo_keyboard_client->plug_irq, keyboard_core_plug_irq_handler,
        NULL, IRQF_TRIGGER_LOW | IRQF_ONESHOT, "keyboard_plug_irq", NULL);
    if (ret < 0) {
        kb_err("request irq failed : %d\n", pogo_keyboard_client->plug_irq);
        return -EINVAL;
    }

    enable_irq_wake(pogo_keyboard_client->plug_irq);


    /*
    pogo_keyboard_client->power_en_gpio = of_get_named_gpio(node,"power-en-gpios", 0);
    if (!gpio_is_valid(pogo_keyboard_client->power_en_gpio)) {
        kb_err("power_en_gpio is not valid %d\n", pogo_keyboard_client->power_en_gpio);
        return -EINVAL;
    }
    gpio_direction_output(pogo_keyboard_client->power_en_gpio,0);

*/

#endif

    pogo_keyboard_client->pinctrl = devm_pinctrl_get(&device->dev);
    if (IS_ERR(pogo_keyboard_client->pinctrl)) {
        kb_err("%s %d devm_pinctrl_get  err\n", __func__, __LINE__);
        return -1;
    }

    // pogo_keyboard_client->uart_tx_set = pinctrl_lookup_state(pogo_keyboard_client->pinctrl, "uart_tx_set");
    // if(IS_ERR(pogo_keyboard_client->uart_tx_set)) {
    // 	kb_err("%s %d pinctrl_lookup_state uart_tx_set err\n",__func__,__LINE__);
    // 	return -1;
    // }
    // pogo_keyboard_client->uart_tx_clear = pinctrl_lookup_state(pogo_keyboard_client->pinctrl,"uart_tx_clear");
    // if(IS_ERR(pogo_keyboard_client->uart_tx_clear)){
    // 	kb_err("%s %d pinctrl_lookup_state uart_tx_clear err\n",__func__,__LINE__);
    // 	return -1;
    // }

    pogo_keyboard_client->uart_rx_set = pinctrl_lookup_state(pogo_keyboard_client->pinctrl, "uart_rx_set");
    if (IS_ERR(pogo_keyboard_client->uart_rx_set)) {
        kb_err("%s %d pinctrl_lookup_state uart_rx_set err\n", __func__, __LINE__);
        return -1;
    }
    pogo_keyboard_client->uart_rx_clear = pinctrl_lookup_state(pogo_keyboard_client->pinctrl, "uart_rx_clear");
    if (IS_ERR(pogo_keyboard_client->uart_rx_clear)) {
        kb_err("%s %d pinctrl_lookup_state uart_rx_clear err\n", __func__, __LINE__);
        return -1;
    }
    ret = pinctrl_select_state(pogo_keyboard_client->pinctrl, pogo_keyboard_client->uart_rx_set);
    kb_debug("%s %d pinctrl_select_state:%d\n", __func__, __LINE__, ret);

#ifdef CONFIG_BOARD_V4_SUPPORT
    pogo_keyboard_client->uart_wake_gpio_pin = pinctrl_lookup_state(pogo_keyboard_client->pinctrl, "uart_wake_gpio");
    if (IS_ERR(pogo_keyboard_client->uart_wake_gpio_pin)) {
        kb_err("%s %d pinctrl_lookup_state uart_wake_gpio_pin err\n", __func__, __LINE__);
        return -1;
    }
    pinctrl_select_state(pogo_keyboard_client->pinctrl, pogo_keyboard_client->uart_wake_gpio_pin);

    pogo_keyboard_client->uart_wake_gpio = of_get_named_gpio(node, "uart-wake-gpio", 0);
    if (!gpio_is_valid(pogo_keyboard_client->uart_wake_gpio)) {
        kb_err("uart_wake_gpio is not valid %d\n", pogo_keyboard_client->uart_wake_gpio);
        return -EINVAL;
    }
    ret = gpio_request_one(pogo_keyboard_client->uart_wake_gpio, GPIOF_DIR_IN, "uart_wake_gpio");
    if (ret) {
        kb_err("%s %d gpio_request_one err:%d\n", __func__, __LINE__, ret);
        return ret;
    }

    pogo_keyboard_client->uart_wake_gpio_irq = gpio_to_irq(pogo_keyboard_client->uart_wake_gpio);
    device_init_wakeup(&pogo_keyboard_client->plat_dev->dev, true);
    ret = dev_pm_set_wake_irq(&pogo_keyboard_client->plat_dev->dev, pogo_keyboard_client->uart_wake_gpio_irq);
    if (ret) {
        kb_err("dev_pm_set_wake_irq failed : %d\n", pogo_keyboard_client->uart_wake_gpio_irq);
        return ret;
    }
    ret = devm_request_threaded_irq(&device->dev, pogo_keyboard_client->uart_wake_gpio_irq, NULL,
        pogo_keyboard_irq_handler, IRQF_TRIGGER_FALLING | IRQF_ONESHOT, "keyboard_wake_irq", NULL);
    if (ret < 0) {
        kb_err("request irq failed : %d\n", pogo_keyboard_client->uart_wake_gpio_irq);
        return -EINVAL;
    }
    kb_debug("%s %d  uart_wake_gpio_irq \n", __func__, __LINE__);

    pogo_keyboard_client->tx_en_gpio = of_get_named_gpio(node, "uart-tx-en-gpio", 0);
    if (!gpio_is_valid(pogo_keyboard_client->uart_wake_gpio)) {
        kb_err("uart_wake_gpio is not valid %d\n", pogo_keyboard_client->uart_wake_gpio);
        return -EINVAL;
    }
    kb_debug("%s %d uart_wake_gpio:%d tx_en_gpio:%d uart_wake_gpio_irq:%d\n", __func__, __LINE__, pogo_keyboard_client->uart_wake_gpio,
        pogo_keyboard_client->tx_en_gpio, pogo_keyboard_client->uart_wake_gpio_irq);
    gpio_direction_output(pogo_keyboard_client->tx_en_gpio, 0);

#endif

    if (of_get_property(node, "pogopin-power-supply", NULL)) {
        kb_debug("%s %d get vcc from ldo\n", __func__, __LINE__);
        pogo_keyboard_client->get_vcc_from_ldo = true;
        if (!pogo_keyboard_client->vcc_reg) {
            pogo_keyboard_client->vcc_reg = devm_regulator_get(&device->dev, "pogopin-power");
            if (IS_ERR(pogo_keyboard_client->vcc_reg)) {
                ret = PTR_ERR(pogo_keyboard_client->vcc_reg);
                kb_err("%s %d Failed to get regulator vcc:%d\n", __func__, __LINE__, ret);
                pogo_keyboard_client->vcc_reg = NULL;
                return ret;
            } else {
                kb_debug("%s %d vcc regulator get success!!!\n", __func__, __LINE__);
            }
        }
    } else {
        pogo_keyboard_client->pogo_power_enable = pinctrl_lookup_state(pogo_keyboard_client->pinctrl, "pogo_power_enable");
        if (IS_ERR(pogo_keyboard_client->pogo_power_enable)) {
            kb_err("%s %d pinctrl_lookup_state pogo_power_enable err\n", __func__, __LINE__);
            return -1;
        }
        pogo_keyboard_client->pogo_power_disable = pinctrl_lookup_state(pogo_keyboard_client->pinctrl, "pogo_power_disable");
        if (IS_ERR(pogo_keyboard_client->pogo_power_disable)) {
            kb_err("%s %d pinctrl_lookup_state pogo_power_disable err\n", __func__, __LINE__);
            return -1;
        }
        pinctrl_select_state(pogo_keyboard_client->pinctrl, pogo_keyboard_client->pogo_power_disable);
    }

    kb_debug("%s %d ret: %d ok\n", __func__, __LINE__, ret);
    return 0;
}

static char *pogo_keyboard_get_keyboard_name(void)
{
    int ret = 0, name_cnt = 0;

    kb_debug("%s %d\n", __func__, __LINE__);

    if (pogo_keyboard_client == NULL) {
        kb_err("pogo_keyboard_client is null\n");
        return NULL;
    }

    if (pogo_keyboard_client->keyboard_brand == 0) {
        kb_err("keyboard_brand is empty\n");
        return NULL;
    }

    name_cnt = of_property_count_strings(pogo_keyboard_client->plat_dev->dev.of_node, "keyboard-name-strings");
    if (pogo_keyboard_client->keyboard_brand > name_cnt) {
        kb_err("keyboard_brand out of range\n");
        return NULL;
    }

    if (pogo_keyboard_client->is_confidential != true) {
	ret = of_property_read_string_index(pogo_keyboard_client->plat_dev->dev.of_node, "keyboard-name-strings",
	   pogo_keyboard_client->keyboard_brand - 1, (const char **)&pogo_keyboard_client->keyboard_name);
	if (ret) {
	   kb_err("%s %d read keyboard name err: %d\n", __func__, __LINE__, ret);
	   return NULL;
	}
    } else {
	pogo_keyboard_client->keyboard_name = (pogo_keyboard_client->keyboard_brand - 1) ? "OnePlus Keyboard" : "OPPO Pad Keyboard";
    }
    return pogo_keyboard_client->keyboard_name;
}

static char *pogo_keyboard_get_keyboard_ble_name(void)
{
    int ret = 0, name_cnt = 0;

    kb_debug("%s %d\n", __func__, __LINE__);

    if (pogo_keyboard_client == NULL) {
        kb_err("%s %d pogo_keyboard_client is null\n", __func__, __LINE__);
        return NULL;
    }

    if (pogo_keyboard_client->keyboard_brand == 0) {
        kb_err("%s %d keyboard_brand error\n", __func__, __LINE__);
        return NULL;
    }

    name_cnt = of_property_count_strings(pogo_keyboard_client->plat_dev->dev.of_node, "keyboard-ble-name-strings");
    if (pogo_keyboard_client->keyboard_brand > name_cnt) {
        kb_err("%s %d keyboard_brand out of range\n", __func__, __LINE__);
        return NULL;
    }

    if (pogo_keyboard_client->is_confidential != true) {
	ret = of_property_read_string_index(pogo_keyboard_client->plat_dev->dev.of_node, "keyboard-ble-name-strings",
	   pogo_keyboard_client->keyboard_brand - 1, (const char **)&pogo_keyboard_client->keyboard_ble_name);
	if (ret) {
	   kb_err("%s %d read keyboard name err: %d\n", __func__, __LINE__, ret);
	   return NULL;
	}
    } else {
	pogo_keyboard_client->keyboard_ble_name = (pogo_keyboard_client->keyboard_brand - 1) ? "OnePlus Keyboard" : "OPPO Pad Keyboard";
    }
    return pogo_keyboard_client->keyboard_ble_name;
}

#ifdef CONFIG_POWER_CTRL_SUPPORT
// turn on/off vcc for keyboard.
static void pogo_keyboard_power_enable(int value)
{
    int ret = 0;
    if (pogo_keyboard_client == NULL)
        return;

    if (pogo_keyboard_client->get_vcc_from_ldo) {
        if (value == 1) {
            if (pogo_keyboard_client->vcc_reg && !regulator_is_enabled(pogo_keyboard_client->vcc_reg)) {
                ret = regulator_enable(pogo_keyboard_client->vcc_reg);
                if(!ret) {
                    kb_debug("%s %d enable vcc success!!!\n", __func__, __LINE__);
                } else {
                    kb_debug("%s %d enable vcc failed!!!\n", __func__, __LINE__);
                }
            } else {
                kb_debug("%s %d vcc is on or null, keep!!!\n", __func__, __LINE__);
            }
        } else if (value == 0) {
            if (pogo_keyboard_client->vcc_reg && regulator_is_enabled(pogo_keyboard_client->vcc_reg)) {
                ret = regulator_disable(pogo_keyboard_client->vcc_reg);
                if(!ret) {
                    kb_debug("%s %d disable vcc success!!!\n", __func__, __LINE__);
                } else {
                    kb_debug("%s %d disable vcc failed!!!\n", __func__, __LINE__);
                }
            } else {
                kb_debug("%s %d vcc is off or null, keep!!!\n", __func__, __LINE__);
            }
        }
    } else {
        if (value == 1) {
            pinctrl_select_state(pogo_keyboard_client->pinctrl, pogo_keyboard_client->pogo_power_enable);
            kb_debug("%s %d enable value:%d\n", __func__, __LINE__, value);
        } else if (value == 0) {
            pinctrl_select_state(pogo_keyboard_client->pinctrl, pogo_keyboard_client->pogo_power_disable);
            kb_debug("%s %d enable value:%d\n", __func__, __LINE__, value);
        }
    }
}
#endif

#ifdef CONFIG_BOARD_V4_SUPPORT
// handler for uart rx wakup interrupt(press key while pad is in sleep) and keyboard attachment detection.
static irqreturn_t pogo_keyboard_irq_handler(int irq, void *data)
{
    int value;

    // process only when keyboard is not connected.
    if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS) == 0) {
        /*low level:plug in irq handler*/

        kb_debug("%s %d\n", __func__, __LINE__);
        // keyboard will drive a low signal through TRX data pin by keyboard hardware design.
        value = gpio_get_value(pogo_keyboard_client->uart_wake_gpio);
        if (value == 0) {
            kb_debug("%s %d disable_irq_nosync\n", __func__, __LINE__);
            disable_irq_nosync(irq);
            pogo_keyboard_client->check_disconnect_count = 0;
            pogo_keyboard_client->check_connect_count = 0;
            pogo_keyboard_plugin_check_timer_switch(true);
        }
    }
    return IRQ_HANDLED;
}
#else
static irqreturn_t pogo_keyboard_rx_gpio_irq_handler(int irq, void *data)
{
    kb_debug("%s %d   \n", __func__, __LINE__);
    disable_irq_wake(pogo_keyboard_client->uart_rx_gpio_irq);
    pogo_keyboard_event_send(KEYBOARD_HOST_RX_UART_EVENT);
    return IRQ_HANDLED;
}
#endif

#if defined(CONFIG_KB_DEBUG_FS) //debugging file nodes.
static int  pogo_keyboard_plug_set(int value)
{
    int ret = 0;

    if (value == 1) {
        kb_debug("%s %d \n", __func__, __LINE__);
        ret = pogo_keyboard_input_connect();
    } else {
        pogo_keyboard_input_disconnect();
        kb_debug("%s %d \n", __func__, __LINE__);
    }

    return ret;
}

static int  pogo_keyboard_gpio_input_set(int value)
{
    int ret;
    static int data = 0;
    if (data == 0)
        data = 1;
    else
        data = 0;
    kb_debug("%s %d  value:%d data:%d\n", __func__, __LINE__, value, data);
    if (value == 9) {
        if (data == 1) {
            pogo_keyboard_client->pogo_gpio_clear = pinctrl_lookup_state(pogo_keyboard_client->pinctrl, "uart_wake_pull_up");
            if (IS_ERR(pogo_keyboard_client->pogo_gpio_clear)) {
                kb_err("%s %d pinctrl_lookup_state uart_wake_pull_up err\n", __func__, __LINE__);
                return -1;
            }
            ret = pinctrl_select_state(pogo_keyboard_client->pinctrl, pogo_keyboard_client->pogo_gpio_clear);
            if (ret) {
                kb_err("%s %d pinctrl_select_state uart_wake_pull_up err:%d\n", __func__, __LINE__, ret);
                return ret;
            }
            kb_debug("%s %d pinctrl_select_state uart_wake_pull_up ret:%d\n", __func__, __LINE__, ret);
        } else {
            pogo_keyboard_client->pogo_gpio_clear = pinctrl_lookup_state(pogo_keyboard_client->pinctrl, "uart_wake_gpio");
            if (IS_ERR(pogo_keyboard_client->pogo_gpio_clear)) {
                kb_err("%s %d pinctrl_lookup_state uart_wake_gpio err\n", __func__, __LINE__);
                return -1;
            }
            ret = pinctrl_select_state(pogo_keyboard_client->pinctrl, pogo_keyboard_client->pogo_gpio_clear);
            if (ret) {
                kb_err("%s %d pinctrl_select_state uart_wake_gpio err:%d\n", __func__, __LINE__, ret);
                return ret;
            }
            kb_debug("%s %d pinctrl_select_state uart_wake_gpio ret:%d\n", __func__, __LINE__, ret);
        }



    } else if (value == 10) {
        if (data == 1) {
            pogo_keyboard_client->pogo_gpio_clear = pinctrl_lookup_state(pogo_keyboard_client->pinctrl, "uart_rx_pull_up");
            if (IS_ERR(pogo_keyboard_client->pogo_gpio_clear)) {
                kb_err("%s %d pinctrl_lookup_state uart_rx_pull_up err\n", __func__, __LINE__);
                return -1;
            }
            ret = pinctrl_select_state(pogo_keyboard_client->pinctrl, pogo_keyboard_client->pogo_gpio_clear);
            if (ret) {
                kb_err("%s %d pinctrl_select_state uart_rx_pull_up err:%d\n", __func__, __LINE__, ret);
                return ret;
            }
            kb_debug("%s %d pinctrl_select_state uart_rx_pull_up ret:%d\n", __func__, __LINE__, ret);
        } else {
            pogo_keyboard_client->pogo_gpio_clear = pinctrl_lookup_state(pogo_keyboard_client->pinctrl, "uart_rx_set");
            if (IS_ERR(pogo_keyboard_client->pogo_gpio_clear)) {
                kb_err("%s %d pinctrl_lookup_state uart_rx_set err\n", __func__, __LINE__);
                return -1;
            }
            ret = pinctrl_select_state(pogo_keyboard_client->pinctrl, pogo_keyboard_client->pogo_gpio_clear);
            if (ret) {
                kb_err("%s %d pinctrl_select_state uart_rx_set err:%d\n", __func__, __LINE__, ret);
                return ret;
            }
            kb_debug("%s %d pinctrl_select_state uart_rx_set ret:%d\n", __func__, __LINE__, ret);
        }
    }
    return 0;
}

static ssize_t tx_mode_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    char *after;
    unsigned long value = simple_strtoul(buf, &after, 10);
    kb_debug("%s %d   %s  %lu\n", __func__, __LINE__, buf, value);
    if (value == 1) {
        pogo_keyboard_enable_uart_tx(1);
    } else if (value == 0) {
        pogo_keyboard_enable_uart_tx(0);
    }
    return count;
}

static ssize_t tx_mode_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    return 0;
}

static ssize_t test_mode_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    char *after;
    unsigned long value = simple_strtoul(buf, &after, 10);
    static int data = 0;
    kb_debug("%s %d   %s  %lu\n", __func__, __LINE__, buf, value);
    switch (value) {
        case 1:
        case 2:
            test_type = value;
            kb_debug("%s %d   %s  test_type:%d\n", __func__, __LINE__, buf, test_type);
            pogo_keyboard_event_send(KEYBOARD_TEST_EVENT);
            break;
        case 3:
            if (pogo_keyboard_client->port)
                pogo_keyboard_port_to_file(pogo_keyboard_client->port);
            break;

        case 4:
            if (data == 0) {
                data = 1;
            } else {
                data = 0;
            }
            kb_debug("%s %d   tx_en_gpio value:%d\n", __func__, __LINE__, data);
            gpio_direction_output(pogo_keyboard_client->tx_en_gpio, data);
            break;

        case 5:
            if (pogo_keyboard_client->get_vcc_from_ldo) {
                if (data == 0) {
                    data = 1;
                    if (pogo_keyboard_client->vcc_reg && !regulator_is_enabled(pogo_keyboard_client->vcc_reg))
                        (void)regulator_enable(pogo_keyboard_client->vcc_reg);
                } else {
                    data = 0;
                    if (pogo_keyboard_client->vcc_reg && regulator_is_enabled(pogo_keyboard_client->vcc_reg))
                        (void)regulator_disable(pogo_keyboard_client->vcc_reg);
                }
            }
            kb_debug("%s %d   power en value:%d\n", __func__, __LINE__, data);

            break;
        case 6:
            if (data == 0) {
                data = 1;
                pinctrl_select_state(pogo_keyboard_client->pinctrl, pogo_keyboard_client->uart_rx_clear);
                kb_debug("%s %d   uart_rx_clear value:%d\n", __func__, __LINE__, data);
            } else {
                data = 0;
                pinctrl_select_state(pogo_keyboard_client->pinctrl, pogo_keyboard_client->uart_wake_clear);
                kb_debug("%s %d   uart_wake_clear value:%d\n", __func__, __LINE__, data);
            }
            break;
        case 7:
            if (data == 0) {
                data = 1;

            } else {
                data = 0;

            }
            kb_debug("%s %d   heartbeat_switch value:%d\n", __func__, __LINE__, data);
            pogo_keyboard_heartbeat_switch(data);
            break;
        case 8:
            if (data == 0) {
                data = 1;
            } else {
                data = 0;
            }
            kb_debug("%s %d   input_connect value:%d\n", __func__, __LINE__, data);
            pogo_keyboard_plug_set(data);
            break;
        case 9:
        case 10:
            pogo_keyboard_gpio_input_set(value);
            break;
        case 11:
            if (data == 0) {
                data = 1;
                pogo_debug_en = true;
            } else {
                data = 0;
                pogo_debug_en = false;
            }
            break;
        case 12:
            max_disconnect_count++;
            kb_debug("%s %d  max_disconnect_count:%d\n", __func__, __LINE__, max_disconnect_count);
            break;
        case 13:
            max_disconnect_count--;
            kb_debug("%s %d  max_disconnect_count:%d\n", __func__, __LINE__, max_disconnect_count);
            break;
        case 14:
            max_plug_in_disconnect_count++;
            kb_debug("%s %d  max_plug_in_disconnect_count:%d\n", __func__, __LINE__, max_plug_in_disconnect_count);
            break;
        case 15:
            max_plug_in_disconnect_count--;
            kb_debug("%s %d  max_plug_in_disconnect_count:%d\n", __func__, __LINE__, max_plug_in_disconnect_count);
            break;

        default:
            break;

    }
    return count;
}

static ssize_t test_mode_show(struct device *dev, struct device_attribute *attr, char *buf)
{

    return 0;
}

static ssize_t keyboard_status_show(struct device *dev, struct device_attribute *attr, char *buf)
{

    return sprintf(buf, "status:0x%02x\n", pogo_keyboard_client->pogo_keyboard_status);
}

static DEVICE_ATTR(tx_mode, S_IRUGO | S_IWUSR, tx_mode_show, tx_mode_store);
static DEVICE_ATTR(test_mode, S_IRUGO | S_IWUSR, test_mode_show, test_mode_store);
static DEVICE_ATTR(keyboard_status, S_IRUGO | S_IWUSR, keyboard_status_show, NULL);

static struct attribute *pogo_keyboard_attributes[] = {
    &dev_attr_tx_mode.attr,
    &dev_attr_test_mode.attr,
    &dev_attr_keyboard_status.attr,
    NULL
};

static struct attribute_group pogo_keyboard_attribute_group = {
    .attrs = pogo_keyboard_attributes
};
#endif//CONFIG_KB_DEBUG_FS

static int pogo_keyboard_input_connect(void)
{
    int ret = 0;
    if (!pogo_keyboard_client->input_pogo_keyboard) {
        ret = pogo_keyboard_input_init(pogo_keyboard_get_keyboard_name());
        if (ret) {
            kb_err("%s %d pogo_keyboard_input_init err:%d\n", __func__, __LINE__, ret);
            return ret;
        }
    }

    if (pogo_keyboard_client->pogopin_touch_support && !pogo_keyboard_client->input_touchpad) {
        ret = touchpad_input_init();
        if (ret) {
            kb_err("%s %d touchpad_input_init err:%d\n", __func__, __LINE__, ret);
            return ret;
        }
    }
    return 0;
}

static void pogo_keyboard_input_disconnect(void)
{
    if (pogo_keyboard_client->input_touchpad) {

        input_unregister_device(pogo_keyboard_client->input_touchpad);
        //input_free_device(pogo_keyboard_client->input_touchpad);
        kb_debug("%s %d input_unregister_device \n", __func__, __LINE__);
        pogo_keyboard_client->input_touchpad = NULL;
    }
    if (pogo_keyboard_client->input_pogo_keyboard) {
        input_unregister_device(pogo_keyboard_client->input_pogo_keyboard);
        //input_free_device(pogo_keyboard_client->input_pogo_keyboard);
        kb_debug("%s %d input_unregister_device \n", __func__, __LINE__);
        pogo_keyboard_client->input_pogo_keyboard = NULL;
    }
    return;
}

static void pogo_keyboard_report_toggle_key(void)
{
    if (!pogo_keyboard_client || !pogo_keyboard_client->input_pogo_keyboard)
        return;
    kb_debug("%s %d \n", __func__, __LINE__);
    input_report_key(pogo_keyboard_client->input_pogo_keyboard, KEY_TOUCHPAD_TOGGLE, 1);
    input_sync(pogo_keyboard_client->input_pogo_keyboard);
    mdelay(10);
    input_report_key(pogo_keyboard_client->input_pogo_keyboard, KEY_TOUCHPAD_TOGGLE, 0);
    input_sync(pogo_keyboard_client->input_pogo_keyboard);
}

static bool pogo_keyboard_key_up(void)
{
    bool ret = false;
    if (!pogo_keyboard_client || !pogo_keyboard_client->input_pogo_keyboard)
        return ret;

    if (pogo_keyboard_client->is_down) {
        input_report_key(pogo_keyboard_client->input_pogo_keyboard, pogo_keyboard_client->down_code, 0);
        input_sync(pogo_keyboard_client->input_pogo_keyboard);
        memset(pogo_keyboard_client->old, 0, sizeof(pogo_keyboard_client->old));
        pogo_keyboard_client->is_down = false;
        kb_debug("%s %d key code %d up\n", __func__, __LINE__, pogo_keyboard_client->down_code);
        ret = true;
    }
    if (pogo_keyboard_client->is_mmdown) {
        input_report_key(pogo_keyboard_client->input_pogo_keyboard, pogo_keyboard_client->down_mmcode, 0);
        input_sync(pogo_keyboard_client->input_pogo_keyboard);
        memset(pogo_keyboard_client->mm_old, 0, sizeof(pogo_keyboard_client->mm_old));
        pogo_keyboard_client->is_mmdown = false;
        kb_debug("%s %d key mmcode %d up\n", __func__, __LINE__, pogo_keyboard_client->down_mmcode);
        ret = true;
    }
    return ret;
}

static bool pogo_keyboard_touch_up(void)
{
    bool ret = false;
    int i = 0;
    if (!pogo_keyboard_client || !pogo_keyboard_client->input_touchpad)
        return ret;

    if (pogo_keyboard_client->touch_down) { //finger all up
        kb_debug("%s %d touch_down %d\n", __func__, __LINE__, pogo_keyboard_client->touch_down);
        input_mt_report_slot_state(pogo_keyboard_client->input_touchpad, MT_TOOL_FINGER, false);
        input_report_key(pogo_keyboard_client->input_touchpad, BTN_TOOL_FINGER, 0);
        for (i = 0; i < TOUCH_FINGER_MAX; i++) {
            if (BIT(i) & pogo_keyboard_client->touch_down) {
                input_mt_slot(pogo_keyboard_client->input_touchpad, i);
                input_mt_report_slot_state(pogo_keyboard_client->input_touchpad, MT_TOOL_FINGER, false);
                kb_debug("%s %d finger up id:%d\n", __func__, __LINE__, i);
            }
        }
        input_report_key(pogo_keyboard_client->input_touchpad, BTN_TOUCH, 0);
        input_sync(pogo_keyboard_client->input_touchpad);
        pogo_keyboard_client->touch_temp = 0;
        pogo_keyboard_client->touch_down = 0;
        kb_debug("%s %d finger all up\n", __func__, __LINE__);
        ret = true;
    }
    return ret;
}

static void pogo_keyboard_connect_send_uevent(void)
{
    char status_string[32], mac_string[32], name_string[64], sn_string[32];
    char *envp[] = { status_string, mac_string, name_string, sn_string, NULL };
    char *keyboard_ble_name = NULL;
    int ret = 0;

    snprintf(status_string, sizeof(status_string), "pogopin_status=%d", pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS);

    snprintf(mac_string, sizeof(mac_string), "mac_addr=%012llx", pogo_keyboard_client->mac_addr);
    keyboard_ble_name = pogo_keyboard_get_keyboard_ble_name();
    if (keyboard_ble_name == NULL) {
        keyboard_ble_name = KEYBOARD_NAME;
    }
    snprintf(name_string, sizeof(name_string), "keyboard_ble_name=%s", keyboard_ble_name);

    snprintf(sn_string, sizeof(sn_string), "report_sn=%s", pogo_keyboard_client->report_sn);

    ret = kobject_uevent_env(&pogo_keyboard_client->uevent_dev->kobj, KOBJ_CHANGE, envp);
    if (ret) {
        kb_err("%s: kobject_uevent_fail, ret = %d", __func__, ret);
    }

    kb_debug("send uevent:%s %s %s %s.\n", status_string, mac_string, name_string, sn_string);
}

static int pogo_keyboard_event_process(unsigned char pogo_keyboard_event)
{
    int ret = 0;
    char report[MAX_POGOPIN_PAYLOAD_LEN];
    char hidcode[KB_SN_HIDE_BIT_LEN];

    kb_debug("%s %d pogo_keyboard_event:%d  pogo_keyboard_status:0x%02x\n", __func__, __LINE__, pogo_keyboard_event, pogo_keyboard_client->pogo_keyboard_status);
    switch (pogo_keyboard_event) {
        case KEYBOARD_PLUG_IN_EVENT:
            if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS) == 0 &&
                atomic_read(&pogo_keyboard_client->vcc_on)) {
                pogo_keyboard_client->pogo_keyboard_status |= KEYBOARD_CONNECT_STATUS;

                ret = pogo_keyboard_input_connect();
                if (ret) {
                    kb_err("%s %d pogo_keyboard_input_connect err!\n", __func__, __LINE__);
                    //break;
                } else {
                    pogo_keyboard_key_up();
                    if (pogo_keyboard_client->pogopin_touch_support)
                        pogo_keyboard_touch_up();
                }
                pogo_keyboard_get_sn();
                pogo_keyboard_client->keypad_pluginout_state = 1;//for factory test detect
                pogo_keyboard_heartbeat_switch(1);
                pogo_keyboard_client->poweroff_timer_check_count = 0;
                pogo_keyboard_client->sync_lcd_state_cnt = 0;
                if (pogo_keyboard_client->pogopin_fw_support) {
                    pogo_keyboard_ver();
                    pogo_keyboard_client->kpd_fw_status = FW_UPDATE_READY;
                    pogo_keyboard_client->fw_update_progress = 0;
                }
                pogo_keyboard_connect_send_uevent();
            }
            break;
        case KEYBOARD_PLUG_OUT_EVENT:
            if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS) != 0) {
                pogo_keyboard_enable_uart_tx(0);
#ifdef CONFIG_POWER_CTRL_SUPPORT
                // pogo_keyboard_power_enable(0);
#endif
                kb_debug("%s %d \n", __func__, __LINE__);
                if (pogo_keyboard_client->pogopin_touch_support)
                    ret = pogo_keyboard_touch_up();
                if (pogo_keyboard_key_up() || ret)
                    mdelay(10);
                pogo_keyboard_input_disconnect();
                pogo_keyboard_client->pogo_keyboard_status &= ~KEYBOARD_CONNECT_STATUS;
                pogo_keyboard_connect_send_uevent();
                pogo_keyboard_client->keypad_pluginout_state = 0;//for factory test detect
                kb_debug("%s %d \n", __func__, __LINE__);
            }

            break;

        case KEYBOARD_HOST_LCD_ON_EVENT:
            pogo_keyboard_client->pogo_keyboard_status |= KEYBOARD_LCD_ON_STATUS;
            if (pogo_keyboard_client->pogopin_touch_support)
                pogo_keyboard_client->pogo_report_touch_status = 1;
            if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS) != 0) {

                ret = pogo_keyboard_set_lcd_state(true);
                if (ret) {
                    kb_err("%s %d pogo_keyboard_set_lcd_state err!\n", __func__, __LINE__);
                }
            }
            pogo_keyboard_heartbeat_switch(true);
            pogo_keyboard_key_up();
            if (pogo_keyboard_client->pogopin_touch_support)
                pogo_keyboard_touch_up();
            break;

        case KEYBOARD_HOST_LCD_OFF_EVENT:
            if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS) != 0) {
                if (!pogo_keyboard_client->pogopin_fw_support ||
                    pogo_keyboard_client->kpd_fw_status != FW_UPDATE_START ) {
                    ret = pogo_keyboard_set_lcd_state(false);
                    if (ret) {
                        kb_err("%s %d pogo_keyboard_set_lcd_state err!\n", __func__, __LINE__);
                    }
                } else {
                    kb_err("%s %d pogo keyboard ota started, keep keyboard wake!\n", __func__, __LINE__);
                }
                pogo_keyboard_heartbeat_switch(false);
            }
            pogo_keyboard_client->pogo_keyboard_status &= ~KEYBOARD_LCD_ON_STATUS;
            pogo_keyboard_client->sync_lcd_state_cnt = 0;
            break;

        case KEYBOARD_CAPSLOCK_ON_EVENT:
        case KEYBOARD_CAPSLOCK_OFF_EVENT:
        case KEYBOARD_MUTEDISABLE_ON_EVENT:
        case KEYBOARD_MUTEDISABLE_OFF_EVENT:
        case KEYBOARD_MICDISABLE_ON_EVENT:
        case KEYBOARD_MICDISABLE_OFF_EVENT:
            if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS) != 0) {
                pogo_keyboard_set_led(pogo_keyboard_event);
            }
            break;

        case KEYBOARD_HOST_RX_GPIO_EVENT:
            enable_irq_wake(pogo_keyboard_client->uart_wake_gpio_irq);
            break;
        case KEYBOARD_HOST_RX_UART_EVENT:
            disable_irq_wake(pogo_keyboard_client->uart_wake_gpio_irq);
            break;
        case KEYBOARD_POWER_ON_EVENT:
            if (atomic_read(&pogo_keyboard_client->vcc_on)) {
                pogo_keyboard_heartbeat_switch(1);
#ifdef CONFIG_POWER_CTRL_SUPPORT
                pogo_keyboard_power_enable(1);
#endif
                pogo_keyboard_client->disconnect_count = 0;
                pogo_keyboard_client->plug_in_count = 0;
            }
            break;
        case KEYBOARD_POWER_OFF_EVENT:
            if (!atomic_read(&pogo_keyboard_client->vcc_on)) {
#ifdef CONFIG_POWER_CTRL_SUPPORT
                pogo_keyboard_power_enable(0);
#endif
                if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS) != 0) {
                    pogo_keyboard_event_send(KEYBOARD_PLUG_OUT_EVENT);
                }
            }

            kb_debug("%s %d KEYBOARD_POWER_OFF_EVENT %d\n", __func__, __LINE__, pogo_keyboard_client->poweroff_timer_check_count);
            if (pogo_keyboard_client->poweroff_timer_check_count < POWEROFF_TIMER_CHECK_MAX) {
                pogo_keyboard_client->poweroff_disconnect_count = 0;
                pogo_keyboard_client->poweroff_connect_count = 0;
                pogo_keyboard_client->poweroff_timer_check_count++;
                pogo_keyboard_poweroff_timer_switch(true);
            } else {
                kb_debug("%s %d enable_irq\n", __func__, __LINE__);
                enable_irq(pogo_keyboard_client->uart_wake_gpio_irq);
            }
            break;

#if defined(CONFIG_KB_DEBUG_FS) // debugging apis.
        case KEYBOARD_HOST_CHECK_EVENT:
            ret = pogo_keyboard_ver();
            if (ret != 0) {
                pogo_keyboard_input_disconnect();
                pogo_keyboard_client->pogo_keyboard_status &= ~KEYBOARD_CONNECT_STATUS;
#ifdef CONFIG_POWER_CTRL_SUPPORT
                pogo_keyboard_power_enable(0);
#endif
            }
            break;
        case KEYBOARD_REPORT_SN_EVENT:
            memset(report, 0, sizeof(report));
            memset(hidcode, KB_SN_HIDE_STAR_ASCII, sizeof(hidcode));
            snprintf(report, MAX_POGOPIN_PAYLOAD_LEN - 1, "$$sn@@%s", pogo_keyboard_client->report_sn);
            kb_info("%s: keyboard sn:%s\n", __func__, report);
            memcpy(&report[KB_SN_HIDE_BIT_START], hidcode, sizeof(hidcode));
            ret = upload_pogopin_kevent_data(report);
            if (ret)
                kb_err("%s:pogopin report sn err\n", __func__);
            if (sn_report_count < 2)
                sn_report_count ++;
            break;
        case KEYBOARD_REPORT_KBVER_EVENT:
            pogo_keyboard_client->kpdmcu_mcu_version =
                (pogo_keyboard_client->report_kbver[8] & 0x0f) << 8 |
                (pogo_keyboard_client->report_kbver[10] & 0x0f) << 4 |
                (pogo_keyboard_client->report_kbver[12] & 0x0f);
            kb_info("%s %d, keyboard version: 0x%04x\n", __func__, __LINE__, pogo_keyboard_client->kpdmcu_mcu_version);
            if (pogo_keyboard_client->kpdmcu_mcu_version < pogo_keyboard_client->kpdmcu_fw_data_ver) {
                pogo_keyboard_client->is_kpdmcu_need_fw_update = true;
            } else {
                pogo_keyboard_client->is_kpdmcu_need_fw_update = false;
            }
            break;
        case KEYBOARD_REPORT_KBLOG_EVENT:
            memset(report, 0, sizeof(report));
            snprintf(report, MAX_POGOPIN_PAYLOAD_LEN - 1, "%s", pogo_keyboard_client->report_kblog);
            kb_info("%s: keyboard log:%s\n", __func__, report);
            break;
        case KEYBOARD_REPORT_TOUCH_STATUS_EVENT:
            pogo_keyboard_report_toggle_key();
            break;
        case KEYBOARD_TEST_EVENT:
            pogo_keyboard_test(); //for test
            break;
#endif//CONFIG_KB_DEBUG_FS

        default:
            kb_err("%s %d no event do!\n", __func__, __LINE__);
            break;
    }
    kb_debug("%s %d pogo_keyboard_event:%d  pogo_keyboard_status:0x%02x\n", __func__, __LINE__, pogo_keyboard_event, pogo_keyboard_client->pogo_keyboard_status);
    return 0;
}

#ifdef CONFIG_PLUG_SUPPORT
static irqreturn_t keyboard_core_plug_irq_handler(int irq, void *data)
{
    int value = 0;
    value = gpio_get_value(pogo_keyboard_client->plug_gpio);
    if (value == 1) {
        irq_set_irq_type(pogo_keyboard_client->plug_irq, IRQ_TYPE_LEVEL_LOW);
    } else {
        irq_set_irq_type(pogo_keyboard_client->plug_irq, IRQ_TYPE_LEVEL_HIGH);
    }
    kb_info("plug irq gpio = %d\r\n", value);
    if (value == 0) {
#ifdef CONFIG_POWER_CTRL_SUPPORT
        pogo_keyboard_power_enable(1); // different from trx low signal interrupt, why turn on vcc directly within int handler?
#endif
        pm_stay_awake(&pogo_keyboard_client->plat_dev->dev);
        kb_info("%s %d %d\n", __func__, __LINE__, value);
    } else {
        kb_debug("%s %d %d\n", __func__, __LINE__, value);
        pogo_keyboard_event_send(KEYBOARD_PLUG_OUT_EVENT);
    }
    return IRQ_HANDLED;
}
#endif

static int pogo_keyboard_event_handler(void *unused)
{
    struct pogo_keyboard_event new_event = { 0 };
    int ret = 0;

    do {
        if (kfifo_is_empty(&pogo_keyboard_client->event_fifo)) {
            kb_debug("%s %d waiter\n", __func__, __LINE__);
            wait_event_interruptible(waiter, pogo_keyboard_client->flag != 0);
        } else {
            ret = kfifo_out(&pogo_keyboard_client->event_fifo, &new_event, sizeof(struct pogo_keyboard_event));
            if (ret == sizeof(struct pogo_keyboard_event)) {
                pogo_keyboard_event_process(new_event.event);
            } else {
                kb_err("%s %d  kfifo_out err!\n", __func__, __LINE__);
            }
            pogo_keyboard_client->flag = 0;
        }
    } while (!kthread_should_stop());

    kb_debug("touch_event_handler exit\n");
    return 0;
}

int pogo_keyboard_write_callback(void *param, int enable)
{
    if (enable == 1) {
        pogo_keyboard_enable_uart_tx(1);
        kb_debug("%s %d write start\n", __func__, __LINE__);
    } else if (enable == 0) {
        pogo_keyboard_enable_uart_tx(0);
        kb_debug("%s %d write end\n", __func__, __LINE__);
    } else {
        kb_err("%s %d  param err!\n", __func__, __LINE__);
        return -1;
    }
    return 0;
}

struct file *pogo_keyboard_port_to_file(struct uart_port *port)
{
    struct uart_port *uart_port = port;
    struct uart_state *state = uart_port->state;
    struct tty_struct *tty = state->port.itty;
    struct tty_file_private *priv;
    struct file *filp = NULL;
    spin_lock(&tty->files_lock);
    list_for_each_entry(priv, &tty->tty_files, list)
    {
        if (priv != NULL) {
            if (!strncmp(port->name, pogo_keyboard_client->tty_name, strlen(pogo_keyboard_client->tty_name))) {
                filp = priv->file;
                // kb_debug("%s %d  %p found", __func__, __LINE__, filp);
            }
        }
    }
    spin_unlock(&tty->files_lock);
    return filp;
}

// called only once by system uart driver when uart port is opened/ready to detect keyboard attachment.
int pogo_keyboard_init_callback(void *port, int type)
{
    struct file *filp;

    if (!port)
        return -1;
    if (type == 1) {
        pogo_keyboard_client->port = (struct uart_port *)port;
        filp = pogo_keyboard_port_to_file(pogo_keyboard_client->port);
        if (pogo_keyboard_client->file_client == NULL && filp != NULL) {
            pogo_keyboard_client->file_client = filp;
            pogo_keyboard_plug_switch(1);
            // kb_info("%s %d  init ok\n", __func__, __LINE__);
        }
        kb_debug("%s %d  start %p\n", __func__, __LINE__, pogo_keyboard_client->file_client);
    } else if (type == 0) {
        pogo_keyboard_client->file_client = NULL;
        pogo_keyboard_client->port = NULL;
        kb_debug("%s %d  end\n", __func__, __LINE__);
    } else {
        kb_err("%s %d  param err!\n", __func__, __LINE__);
        return -1;
    }
    return 0;
}

#if IS_ENABLED(CONFIG_QCOM_PANEL_EVENT_NOTIFIER) && defined(CONFIG_OPLUS_POGOPIN_FUNCTION)
static void pogo_keyboard_drm_notifier_callback(enum panel_event_notifier_tag tag,
    struct panel_event_notification *notification, void *priv)
{
    if (!notification) {
        kb_err("Invalid notification\n");
        return;
    }

    switch (notification->notif_type) {
        case DRM_PANEL_EVENT_UNBLANK:
            kb_info("%s %d event:%d pogo_keyboard goto wakeup\n", __func__, __LINE__, notification->notif_data.early_trigger);
            if (!notification->notif_data.early_trigger) {
                pogo_keyboard_sync_lcd_state(true);
            }
            break;
        case DRM_PANEL_EVENT_BLANK:
            kb_info("%s %d event:%d pogo_keyboard goto sleep\n", __func__, __LINE__, notification->notif_data.early_trigger);
            if (!notification->notif_data.early_trigger) {
                pogo_keyboard_sync_lcd_state(false);
            }
            break;
        case DRM_PANEL_EVENT_BLANK_LP:
            break;
        case DRM_PANEL_EVENT_FPS_CHANGE:
            break;
        default:
            break;
    }
}

static int pogo_keyboard_register_drm_notify(void)
{
    int i = 0, count = 0;
    struct device_node *np = NULL;
    struct device_node *node = NULL;
    struct drm_panel *panel = NULL;
    void *cookie = NULL;

    np = of_find_node_by_name(NULL, "oplus,dsi-display-dev");
    if (!np) {
        kb_err("device tree info. missing\n");
        return 0;
    }
    count = of_count_phandle_with_args(np, "oplus,dsi-panel-primary", NULL);
    if (count <= 0) {
        kb_err("primary panel no found\n");
        return 0;
    }
    for (i = 0; i < count; i++) {
        node = of_parse_phandle(np, "oplus,dsi-panel-primary", i);
        panel = of_drm_find_panel(node);
        of_node_put(node);
        if (!IS_ERR(panel)) {
            pogo_keyboard_client->active_panel = panel;
            kb_err("find active_panel\n");
            break;
        }
    }

    if (i >= count) {
        kb_err("%s %d can't find active panel\n", __func__, __LINE__);
        return -ENODEV;
    }

    cookie = panel_event_notifier_register(
        PANEL_EVENT_NOTIFICATION_PRIMARY,
        PANEL_EVENT_NOTIFIER_CLIENT_POGOPIN,
        panel, &pogo_keyboard_drm_notifier_callback,
        NULL);
    if (!cookie) {
        kb_err("Unable to register pogo_keyboard_panel_notifier\n");
        return -EINVAL;
    } else {
        pogo_keyboard_client->notifier_cookie = cookie;
        kb_info("success register pogo_keyboard_panel_notifier\n");
    }

    kb_info("%s %d ok\n", __func__, __LINE__);
    return 0;
}
#endif

#if IS_ENABLED(CONFIG_DEVICE_MODULES_DRM_MEDIATEK) && defined(CONFIG_OPLUS_POGOPIN_FUNCTION)
static int pogo_keyboard_mtk_disp_notifier_callback(struct notifier_block *nb,
    unsigned long value, void *v)
{
    struct pogo_keyboard_data *pogo_data =
        container_of(nb, struct pogo_keyboard_data, disp_notifier);
    int *data = (int *)v;

    if (pogo_data && v) {
        kb_info("%s %d ,event: %lu, blank:%d\n", __func__, __LINE__, value, *data);
        if (value == MTK_DISP_EVENT_BLANK) {
            if (*data == MTK_DISP_BLANK_UNBLANK) {
                kb_info("%s %d pogo_keyboard goto wakeup\n", __func__, __LINE__);
                pogo_keyboard_sync_lcd_state(true);
            }
        } else if (value == MTK_DISP_EARLY_EVENT_BLANK) {
            if (*data == MTK_DISP_BLANK_POWERDOWN) {
                kb_info("%s %d pogo_keyboard goto sleep\n", __func__, __LINE__);
                pogo_keyboard_sync_lcd_state(false);
            }

        }
    } else {
        kb_err("%s %d pogo_data or v is NULL!!!\n", __func__, __LINE__);
        return -1;
    }
    return 0;
}
#endif

static int pogo_keyboard_lcd_event_register(void)
{
    int ret = 0;

#if IS_ENABLED(CONFIG_QCOM_PANEL_EVENT_NOTIFIER) && defined(CONFIG_OPLUS_POGOPIN_FUNCTION)
    ret = pogo_keyboard_register_drm_notify();
#endif

#if IS_ENABLED(CONFIG_DEVICE_MODULES_DRM_MEDIATEK) && defined(CONFIG_OPLUS_POGOPIN_FUNCTION)
    pogo_keyboard_client->disp_notifier.notifier_call = pogo_keyboard_mtk_disp_notifier_callback;
    mtk_disp_notifier_register("pogo_keyboard", &pogo_keyboard_client->disp_notifier);
#endif
    return ret;
}

static void pogo_keyboard_lcd_event_unregister(void)
{
    if (!pogo_keyboard_client->lcd_notify_reg) {
        return;
    }

#if IS_ENABLED(CONFIG_QCOM_PANEL_EVENT_NOTIFIER) && defined(CONFIG_OPLUS_POGOPIN_FUNCTION)
    if (pogo_keyboard_client->active_panel && pogo_keyboard_client->notifier_cookie)
        panel_event_notifier_unregister(pogo_keyboard_client->notifier_cookie);
#endif

#if IS_ENABLED(CONFIG_DEVICE_MODULES_DRM_MEDIATEK) && defined(CONFIG_OPLUS_POGOPIN_FUNCTION)
    mtk_disp_notifier_unregister(&pogo_keyboard_client->disp_notifier);
#endif
}

#define LCD_REG_RETRY_COUNT_MAX		100
#define LCD_REG_RETRY_DELAY_MS		100
static void pogo_keyboard_lcd_notify_reg_work(struct work_struct *work)
{
    static int retry_count = 0;
    int ret = 0;

    if (retry_count >= LCD_REG_RETRY_COUNT_MAX)
        return;

    ret = pogo_keyboard_lcd_event_register();
    if (ret < 0) {
        retry_count++;
        kb_info("lcd panel not ready, count=%d\n", retry_count);
        schedule_delayed_work(&pogo_keyboard_client->lcd_notify_reg_work,
            msecs_to_jiffies(LCD_REG_RETRY_DELAY_MS));
        return;
    }
    retry_count = 0;
    pogo_keyboard_client->lcd_notify_reg = true;
}

#ifdef CONFIG_OPLUS_POGOPIN_FUNCTION
extern struct pogo_keyboard_operations *get_pogo_keyboard_operations(void);
#else
struct pogo_keyboard_operations *get_pogo_keyboard_operations(void)
{
    return NULL;
}
#endif

static void pogo_keyboard_register_callback(void)
{
    struct pogo_keyboard_operations *client = get_pogo_keyboard_operations();
    kb_debug("%s %d start\n", __func__, __LINE__);
    if (client == NULL)
        return;
    if (client->init == NULL) {
        client->init = pogo_keyboard_init_callback;
        client->write = pogo_keyboard_write_callback;
        client->recv = pogo_keyboard_recv_callback;
        client->resume = pogo_keyboard_plat_resume;
        client->suspend = pogo_keyboard_plat_suspend;
        client->remove = pogo_keyboard_plat_remove;
        client->check = pogo_keyboard_is_support;
        kb_info("%s %d end\n", __func__, __LINE__);
    }
    kb_debug("%s %d end\n", __func__, __LINE__);
}

static void pogo_keyboard_unregister_callback(void)
{
    struct pogo_keyboard_operations *client = get_pogo_keyboard_operations();
    kb_debug("%s %d start\n", __func__, __LINE__);
    if (client == NULL)
        return;
    if (client->init) {
        client->init = NULL;
        client->write = NULL;
        client->recv = NULL;
        client->resume = NULL;
        client->suspend = NULL;
        client->remove = NULL;
        client->check = NULL;
        kb_info("%s %d end\n", __func__, __LINE__);
    }
    kb_debug("%s %d end\n", __func__, __LINE__);
}

// timer for first keyboard attachment detection after system init. run only once.
static enum hrtimer_restart keyboard_core_plug_hrtimer(struct hrtimer *timer)
{
    int value = 0;

    if (pogo_keyboard_client->file_client == NULL) {
        return HRTIMER_NORESTART;
    }

    value = gpio_get_value(pogo_keyboard_client->uart_wake_gpio); // will get 0 if keyboard is attached(trx pin low).

#ifdef CONFIG_PLUG_SUPPORT
    value = gpio_get_value(pogo_keyboard_client->plug_gpio); // will get 0 if keyboard is attached(hall sensor).
#endif
    kb_debug("gpio read value = %d\r\n", value);
    if (value == 0) {
        if (!atomic_read(&pogo_keyboard_client->vcc_on)) {
            atomic_set(&pogo_keyboard_client->vcc_on, 1);
            kb_debug("%s %d %d disable_irq_nosync\n", __func__, __LINE__, value);
            pogo_keyboard_event_send(KEYBOARD_POWER_ON_EVENT);
            disable_irq_nosync(pogo_keyboard_client->uart_wake_gpio_irq);
        }

    }

    return HRTIMER_NORESTART;
}

// timer for monitoring keyboard heartbeat report periodically.
static enum hrtimer_restart keyboard_core_heartbeat_hrtimer(struct hrtimer *timer)
{
    // kb_debug("disconnect_count = %d max_disconnect_count = %d max_plug_in_disconnect_count = %d\n",
    //     pogo_keyboard_client->disconnect_count, max_disconnect_count, max_plug_in_disconnect_count);

    if (pogo_keyboard_client->disconnect_count >= max_disconnect_count && pogo_keyboard_client->plug_in_count >= max_plug_in_disconnect_count) {
        if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS) || atomic_read(&pogo_keyboard_client->vcc_on)) {
            atomic_set(&pogo_keyboard_client->vcc_on, 0);
            kb_info("%s %d plug out for disconnect_count = %d\n", __func__, __LINE__, pogo_keyboard_client->disconnect_count);
            pogo_keyboard_event_send(KEYBOARD_POWER_OFF_EVENT);
        }
        pogo_keyboard_client->disconnect_count = 0;
        pogo_keyboard_client->plug_in_count = 0;
    } else {
        pogo_keyboard_client->disconnect_count++;
        if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS) || atomic_read(&pogo_keyboard_client->vcc_on)) {
            pogo_keyboard_heartbeat_switch(1); // restart the timer.
        }
    }

    if (pogo_keyboard_client->plug_in_count <= max_plug_in_disconnect_count)
        pogo_keyboard_client->plug_in_count++;

    return HRTIMER_NORESTART;
}

static enum hrtimer_restart keyboard_core_poweroff_hrtimer(struct hrtimer *timer)
{
    int value = 0;

    value = gpio_get_value(pogo_keyboard_client->uart_wake_gpio);
    if (value == 0) {
        pogo_keyboard_client->poweroff_disconnect_count = 0;
        pogo_keyboard_client->poweroff_connect_count++;
    } else {
        pogo_keyboard_client->poweroff_connect_count = 0;
        pogo_keyboard_client->poweroff_disconnect_count++;
    }

    if (pogo_keyboard_client->poweroff_disconnect_count >= POWEROFF_DISCONNECT_MAX) {
        kb_info("%s %d no restart and enable irq\n", __func__, __LINE__);
        enable_irq(pogo_keyboard_client->uart_wake_gpio_irq);
        return HRTIMER_NORESTART;
    }

    if (pogo_keyboard_client->poweroff_connect_count >= POWEROFF_CONNECT_MAX) {
        kb_info("%s %d power on! %d %d\n", __func__, __LINE__, pogo_keyboard_client->pogo_keyboard_status, atomic_read(&pogo_keyboard_client->vcc_on));
        if ((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS) == 0) {
            if (!atomic_read(&pogo_keyboard_client->vcc_on)) {
                atomic_set(&pogo_keyboard_client->vcc_on, 1);
                pogo_keyboard_event_send(KEYBOARD_POWER_ON_EVENT);// signal main event task to do the following attachement procedure.
                pm_wakeup_event(&pogo_keyboard_client->plat_dev->dev, 2500);
            }
        }
        return HRTIMER_NORESTART;
    }

    pogo_keyboard_poweroff_timer_switch(true);
    return HRTIMER_NORESTART;
}

static enum hrtimer_restart keyboard_core_plugin_check_hrtimer(struct hrtimer *timer)
{
    int value = 0;

    kb_debug("%s %d\n", __func__, __LINE__);

    if(pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS)
    {
        kb_info("%s %d keyboard connected, exit\n", __func__, __LINE__);
        return HRTIMER_NORESTART;
    }

    value = gpio_get_value(pogo_keyboard_client->uart_wake_gpio);
    if(value == 0) {
        pogo_keyboard_client->check_disconnect_count = 0;
        pogo_keyboard_client->check_connect_count++;
    } else {
        pogo_keyboard_client->check_connect_count = 0;
        pogo_keyboard_client->check_disconnect_count++;
    }

    if(pogo_keyboard_client->check_disconnect_count >= PLUGIN_CHECK_CHECK_MAX/2) {
        kb_info("%s %d no restart and enable irq\n", __func__, __LINE__);
        enable_irq(pogo_keyboard_client->uart_wake_gpio_irq);
        return HRTIMER_NORESTART;
    }

    if(pogo_keyboard_client->check_connect_count >= PLUGIN_CHECK_CHECK_MAX) {
        kb_info("%s %d power on! %d %d\n", __func__, __LINE__, pogo_keyboard_client->pogo_keyboard_status, atomic_read(&pogo_keyboard_client->vcc_on));
        if((pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS) == 0){
            if (!atomic_read(&pogo_keyboard_client->vcc_on)){
                atomic_set(&pogo_keyboard_client->vcc_on, 1);
                pogo_keyboard_event_send(KEYBOARD_POWER_ON_EVENT);// signal main event task to do the following attachement procedure.
                pm_wakeup_event(&pogo_keyboard_client->plat_dev->dev, 500);
            }
        }
        return HRTIMER_NORESTART;
    }

    pogo_keyboard_plugin_check_timer_switch(true);
    return HRTIMER_NORESTART;
}

static int pogo_keyboard_start_up_init(void)
{
    pogo_keyboard_client->pogo_keyboard_status |= KEYBOARD_LCD_ON_STATUS;
    kb_debug("%s %d pogo_keyboard_status:0x%02x\n", __func__, __LINE__, pogo_keyboard_client->pogo_keyboard_status);
    atomic_set(&pogo_keyboard_client->vcc_on, 0);
    hrtimer_init(&pogo_keyboard_client->plug_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    pogo_keyboard_client->plug_timer.function = keyboard_core_plug_hrtimer;

    hrtimer_init(&pogo_keyboard_client->heartbeat_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    pogo_keyboard_client->heartbeat_timer.function = keyboard_core_heartbeat_hrtimer;

    hrtimer_init(&pogo_keyboard_client->poweroff_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    pogo_keyboard_client->poweroff_timer.function = keyboard_core_poweroff_hrtimer;

    hrtimer_init(&pogo_keyboard_client->plugin_check_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    pogo_keyboard_client->plugin_check_timer.function = keyboard_core_plugin_check_hrtimer;

    return 0;
}

static ssize_t proc_tty_name_read(struct file *file, char __user *user_buf,
    size_t count, loff_t *ppos)
{
    int ret = 0;

    kb_debug("%s, %d\n", __func__, __LINE__);
    if (pogo_keyboard_client && pogo_keyboard_client->tty_name) {
        ret = simple_read_from_buffer(user_buf, count, ppos, pogo_keyboard_client->tty_name, strlen(pogo_keyboard_client->tty_name));
    }
    return ret;
}

static const struct proc_ops proc_tty_name_ops = {
    .proc_read = proc_tty_name_read,
    .proc_open = simple_open,
    .proc_lseek = default_llseek,
};

static ssize_t proc_crc_ibm_read(struct file *file, char __user *user_buf,
    size_t count, loff_t *ppos)
{
    int ret = 0;
    char buf[8] = {0};

    if (pogo_keyboard_client && pogo_keyboard_client->crc_ibm_init_val) {
        snprintf(buf, sizeof(buf), "%d", pogo_keyboard_client->crc_ibm_init_val);
        ret = simple_read_from_buffer(user_buf, count, ppos, buf, strlen(buf));

    }
    return ret;
}

static const struct proc_ops proc_crc_ibm_ops = {
    .proc_read = proc_crc_ibm_read,
    .proc_open = simple_open,
    .proc_lseek = default_llseek,
};

static ssize_t proc_touchpad_state_read(struct file *file, char __user *user_buf,
    size_t count, loff_t *ppos)
{
    int ret = 0;
    char buf[8] = {0};

    kb_debug("%s, %d\n", __func__, __LINE__);
    if (pogo_keyboard_client) {
        snprintf(buf, sizeof(buf), "%u", pogo_keyboard_client->touchpad_disable_state);
        ret = simple_read_from_buffer(user_buf, count, ppos, buf, strlen(buf));
    }

    return ret;
}

static ssize_t proc_battery_power_level_read(struct file *file, char __user *user_buf,
    size_t count, loff_t *ppos)
{
    int ret = 0;
    char buf[8] = {0};
    kb_debug("%s, %d\n", __func__, __LINE__);
    if (pogo_keyboard_client && (pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS)) {
        snprintf(buf, sizeof(buf), "%u", pogo_keyboard_client->pogo_battery_power_level);
        ret = simple_read_from_buffer(user_buf, count, ppos, buf, strlen(buf));
    }
    return ret;
}

static ssize_t proc_battery_charge_current_read(struct file *file, char __user *user_buf,
    size_t count, loff_t *ppos)
{
    int ret = 0;
    int pogo_battery_charge_current = 0;
    char buf[8] = {0};

    if (pogo_keyboard_client && (pogo_keyboard_client->pogo_keyboard_status & KEYBOARD_CONNECT_STATUS)) {
        pogo_battery_charge_current = pogo_keyboard_get_charge_current();
        if (pogo_battery_charge_current < 0)
             kb_err("%s, send cmd to keyboard to read charge current fail\n", __func__);
    }
    snprintf(buf, sizeof(buf), "%d", pogo_battery_charge_current);
    ret = simple_read_from_buffer(user_buf, count, ppos, buf, strlen(buf));

    return ret;
}

static const struct proc_ops proc_battery_power_level_ops = {
    .proc_read = proc_battery_power_level_read,
    .proc_open = simple_open,
    .proc_lseek = default_llseek,
};
static const struct proc_ops proc_battery_charge_current_ops = {
    .proc_read = proc_battery_charge_current_read,
    .proc_open = simple_open,
    .proc_lseek = default_llseek,
};
static const struct proc_ops proc_touchpad_state_ops = {
    .proc_read = proc_touchpad_state_read,
    .proc_open = simple_open,
    .proc_lseek = default_llseek,
};
static ssize_t proc_keypad_state_read(struct file *file, char __user *user_buf,
    size_t count, loff_t *ppos)
{
    int ret = 0;
    char buf[8] = {0};

    kb_debug("%s, %d\n", __func__, __LINE__);
    if (pogo_keyboard_client) {
        snprintf(buf, sizeof(buf), "%u", pogo_keyboard_client->keypad_pluginout_state);
        ret = simple_read_from_buffer(user_buf, count, ppos, buf, strlen(buf));
    }

    return ret;
}

static const struct proc_ops proc_keypad_state_ops = {
    .proc_read = proc_keypad_state_read,
    .proc_open = simple_open,
    .proc_lseek = default_llseek,
};

static ssize_t proc_kpdmcu_fw_update_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    uint8_t ret = 0;
    char page[4] = {0};

    if (pogo_keyboard_client) {
        snprintf(page, 3, "%d\n", pogo_keyboard_client->kpd_fw_status);
        ret = simple_read_from_buffer(buf, count, ppos, page, strlen(page));
    }

    return ret;
}

static ssize_t proc_kpdmcu_fw_update_write(struct file *file, const char __user *buf, size_t count, loff_t *lo)
{
    char write_data[2] = { 0 };

    if (count > 2) {
        kb_err("%s %d count: %zd > 2\n", __func__, __LINE__, count);
        return count;
    }

    if (copy_from_user(&write_data, buf, count)) {
        kb_err("%s %d read proc input error.\n", __func__, __LINE__);
        return count;
    }

    if(!pogo_keyboard_client || pogo_keyboard_client->kpd_fw_status == FW_UPDATE_START)
        return count;

    if(write_data[0] == '1'){
        pogo_keyboard_client->kpdmcu_fw_update_force = false;
        schedule_work(&pogo_keyboard_client->kpdmcu_fw_update_work);
    } else if(write_data[0] == '2') {
        pogo_keyboard_client->kpdmcu_fw_update_force = true;
        schedule_work(&pogo_keyboard_client->kpdmcu_fw_update_work);
    } else {
        pogo_keyboard_client->kpdmcu_fw_update_force = false;
    }

    return count;
}

static const struct proc_ops proc_kpdmcu_fw_update_ops = {
    .proc_read = proc_kpdmcu_fw_update_read,
    .proc_write = proc_kpdmcu_fw_update_write,
    .proc_lseek = default_llseek,
};

static ssize_t proc_kpdmcu_fw_check_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    uint8_t ret = 0;
    char page[PROC_PAGE_LEN] = {0};
    bool need_update_fw = false;
    u32 fw_count = 0;
    int index = 0;

    if (pogo_keyboard_client) {
        need_update_fw = pogo_keyboard_client->is_kpdmcu_need_fw_update;

        if(need_update_fw)
            fw_count += pogo_keyboard_client->kpdmcu_fw_cnt;

        index = snprintf(page, PROC_PAGE_LEN - 1, "%s:%04x:%d:%d:%d\n",
                pogo_keyboard_client->report_kbver,
                pogo_keyboard_client->kpdmcu_fw_data_ver, fw_count,
                need_update_fw, pogo_keyboard_client->fw_update_progress / FW_PERCENTAGE_100);

        ret = simple_read_from_buffer(buf, count, ppos, page, index);
    }

    return ret;
}

static ssize_t proc_kpdmcu_fw_check_write(struct file *file, const char __user *buf, size_t count, loff_t *lo)
{
    char write_data[2] = { 0 };

    if (count > 2) {
        kb_err("%s %d count: %zd > 2\n", __func__, __LINE__, count);
        return count;
    }

    if (copy_from_user(&write_data, buf, count)) {
        kb_err("%s %d read proc input error!!!\n", __func__, __LINE__);
        return count;
    }

    if(write_data[0] == '1' && pogo_keyboard_client != NULL)
        schedule_delayed_work(&pogo_keyboard_client->kpdmcu_fw_data_version_work, 0);

    return count;
}

static const struct proc_ops proc_kpdmcu_fw_check_ops = {
    .proc_read = proc_kpdmcu_fw_check_read,
    .proc_write = proc_kpdmcu_fw_check_write,
    .proc_lseek = default_llseek,
};

const struct firmware *get_fw_firmware(struct pogo_keyboard_data *pogo_data, const char *patch)
{
    struct platform_device *pdev = pogo_data->plat_dev;
    char *fw_patch = NULL;
    int retry = 2;
    int ret = 0;
    const struct firmware *fw_entry = NULL;

    fw_patch = kzalloc(MAX_FW_NAME_LENGTH, GFP_KERNEL);
    if(fw_patch == NULL)
        return NULL;

    snprintf(fw_patch, MAX_FW_NAME_LENGTH, "%s", patch);
    kb_info("%s %d fw_path is :%s\n", __func__, __LINE__, fw_patch);
    do {
        ret = request_firmware(&fw_entry, fw_patch, &pdev->dev);
        if(ret < 0) {
            kb_err("%s %d Failed to request fw\n", __func__, __LINE__);
            msleep(100);
        } else {
            break;
        }
    } while ((ret < 0) && (--retry > 0));

    kb_info("%s %d fw_path is :%s\n", __func__, __LINE__, fw_patch);
    kfree(fw_patch);
    return fw_entry;
}

static int kpd_fw_isvalid(const unsigned char *fw_data, u32 count, u32 *checksum, int *version)
{
    u32 start_addr = 0;
    u32 get_ver_addr = 0;
    u32 get_chechsum_addr = 0;
    u32 get_checksum = 0;
    u32 add_checksum = 0;
    u32 index = 0;
    u32 i = 0;

    start_addr = pogo_keyboard_client->ota_start_addr;
    get_ver_addr = pogo_keyboard_client->ota_get_version_addr;
    index = pogo_keyboard_client->ota_send_data_start_addr;
    i = index;
    get_chechsum_addr = get_ver_addr - 4;
    kb_debug("%s %d start_addr:0x%x, get_ver_addr:0x%x, ota_send_data_start_addr:0x%x\n",
            __func__, __LINE__, start_addr, get_ver_addr, index);
    if (count < get_ver_addr | count < index) {
        kb_err("%s %d ota file count is too small,please check!!!\n", __func__, __LINE__);
        return -EINVAL;
    }
    do {
        add_checksum += (u32)fw_data[i];
    } while (++i < count);

    get_checksum = (u32)fw_data[get_chechsum_addr] |
                   (u32)fw_data[get_chechsum_addr + 1] << 8 |
                   (u32)fw_data[get_chechsum_addr + 2] << 16 |
                   (u32)fw_data[get_chechsum_addr + 3] << 24;
    if (get_checksum != add_checksum) {
        kb_debug("%s %d add_checksum:0x%08x, get_checksum:0x%08x\n", __func__, __LINE__, add_checksum, get_checksum);
        kb_err("%s %d ota file checksum is not right,please check!!!\n", __func__, __LINE__);
        return -EINVAL;
    }
    *checksum = get_checksum;

    pogo_keyboard_client->kpdmcu_fw_data_ver = (int)fw_data[get_ver_addr + 1] << 8 |
                                                (int)fw_data[get_ver_addr];
    *version = pogo_keyboard_client->kpdmcu_fw_data_ver;
    if (pogo_keyboard_client->kpdmcu_mcu_version < pogo_keyboard_client->kpdmcu_fw_data_ver) {
        pogo_keyboard_client->is_kpdmcu_need_fw_update = true;
    } else {
        pogo_keyboard_client->is_kpdmcu_need_fw_update = false;
    }
    kb_debug("%s %d, fw verison is 0x%04x\n", __func__, __LINE__, *version);
    return 0;

}

static void kpdmcu_fw_data_version_thread(struct work_struct *work)
{

    const struct firmware *fw_entry = NULL;
    u32 checksum = 0;
    int version = 0;
    int ret = 0;

    if(pogo_keyboard_client == NULL) {
        kb_err("%s %d pogo_keyboard_client is NULL!!!\n", __func__, __LINE__);
        return;
    }

    if(pogo_keyboard_client->ota_firmware_name == NULL) {
        kb_err("%s %d ota_firmware_name is NULL!!!\n", __func__, __LINE__);
        return;
    }

    fw_entry = get_fw_firmware(pogo_keyboard_client, pogo_keyboard_client->ota_firmware_name);
    if(fw_entry != NULL) {
        pogo_keyboard_client->kpdmcu_fw_cnt = (u32)(fw_entry->size / 1024);
        kb_debug("%s %d, kpdmcu_fw_cnt:%uKB\n", __func__, __LINE__, pogo_keyboard_client->kpdmcu_fw_cnt);
        ret = kpd_fw_isvalid(fw_entry->data, fw_entry->size, &checksum, &version);
        if (ret) {
            kb_err("%s %d kpd fw is not valid!!!\n", __func__, __LINE__);
        }
    } else {
        kb_err("%s %d kpd mcu request firmware fail\n", __func__, __LINE__);
        return;
    }

    release_firmware(fw_entry);
    fw_entry = NULL;
}

static int kpd_fw_update(const unsigned char *fw_data, u32 count, u32 checksum, int version)
{
    int ret = 0;
    int retry = 3;
    int i = 0;
    u32 start_addr = 0;
    u32 index = 0;
    u32 len = 0;

    start_addr = pogo_keyboard_client->ota_start_addr;
    index = pogo_keyboard_client->ota_send_data_start_addr;
    len =  count - index;
    ret = pogo_keyboard_mcu_version();
    if (ret) {
        kb_err("%s %d get mcu version fail\n", __func__, __LINE__);
        return ret;
    }
    ret = pogo_keyboard_ota_start_end(len, start_addr, checksum, version, 1);
    if (ret) {
        kb_err("%s %d send ota file infomation fail\n", __func__, __LINE__);
        return ret;
    }
    for (i = 0; i < retry; i++)
    {
        ret = pogo_keyboard_ota_write_datas(&fw_data[index], len);
        if (ret) {
            kb_err("%s %d ota write datas fail, retry: %d\n", __func__, __LINE__, i);
        } else {
            kb_err("%s %d ota write datas success!!!\n", __func__, __LINE__);
            break;
        }
    }
    if (i >= retry) {
        kb_err("%s %d ota write datas fail\n", __func__, __LINE__);
        return ret;
    }
    ret = pogo_keyboard_ota_start_end(len, start_addr, checksum, version, 0);
    if (ret) {
        kb_err("%s %d send ota end infomation fail\n", __func__, __LINE__);
        return ret;
    }

    ret = pogo_keyboard_ota_end_reset();
    if (ret) {
        kb_err("%s %d send ota end reset fail\n", __func__, __LINE__);
        return ret;
    }

    return ret;
}

static void kpdmcu_fw_update_thread(struct work_struct *work)
{
    const unsigned char *firmware_data = NULL;
    u32 fw_data_count = 0;
    u32 checksum = 0;
    int version = 0;
    const struct firmware *fw_entry = NULL;
    int ret = 0;

    if(pogo_keyboard_client == NULL) {
        pogo_keyboard_client->kpd_fw_status = FW_UPDATE_READY;
        return;
    }

    if (pogo_keyboard_client->pogopin_wakelock)
        __pm_stay_awake(pogo_keyboard_client->pogopin_wakelock);
    mutex_lock(&pogo_keyboard_client->fw_lock);

    pogo_keyboard_client->kpd_fw_status = FW_UPDATE_START;
    pogo_keyboard_client->kpdmcu_update_end = false;

    pogo_keyboard_client->fw_update_progress = FW_PROGERSS_1 * FW_PERCENTAGE_100;

    if(pogo_keyboard_client->is_kpdmcu_need_fw_update == false && pogo_keyboard_client->kpdmcu_fw_update_force == false) {
        kb_debug("%s %d, not need fw update\n", __func__, __LINE__);
    } else {
        if(pogo_keyboard_client->ota_firmware_name == NULL) {
            kb_err("%s %d ota_firmware_name is NULL!!!\n", __func__, __LINE__);
            goto out;
        }
        fw_entry = get_fw_firmware(pogo_keyboard_client, pogo_keyboard_client->ota_firmware_name);
        if(fw_entry != NULL) {
            fw_data_count = (u32)fw_entry->size;
            firmware_data = fw_entry->data;
            kb_debug("%s %d, fw count 0X%x\n", __func__, __LINE__, fw_data_count);
            ret = kpd_fw_isvalid(firmware_data, fw_data_count, &checksum, &version);
            if (ret) {
                kb_debug("%s %d This bin file is not right!!!\n", __func__, __LINE__);
                pogo_keyboard_client->kpd_fw_status = FW_UPDATE_FAIL;
                goto out1;
            }
        } else {
            kb_err("%s %d, fw request firmware fail\n", __func__, __LINE__);
            pogo_keyboard_client->kpd_fw_status = FW_UPDATE_FAIL;
            goto out;
        }

        pogo_keyboard_client->fw_update_progress = FW_PROGRESS_2 * FW_PERCENTAGE_100;

        ret = kpd_fw_update(firmware_data, fw_data_count, checksum, version);
        if(ret) {
            pogo_keyboard_client->kpd_fw_status = FW_UPDATE_FAIL;
            goto out1;
        }
        pogo_keyboard_client->kpdmcu_update_end = true;
    }

    pogo_keyboard_client->kpd_fw_status = FW_UPDATE_SUC;
    pogo_keyboard_client->fw_update_progress = FW_PROGRESS_100 * FW_PERCENTAGE_100;
    kb_debug("%s %d, fw update success!\n", __func__, __LINE__);
out1:
    release_firmware(fw_entry);
    fw_entry = NULL;
    firmware_data = NULL;
out:
    mutex_unlock(&pogo_keyboard_client->fw_lock);
    if (pogo_keyboard_client->pogopin_wakelock)
        __pm_relax(pogo_keyboard_client->pogopin_wakelock);
}

static int pogo_keyboard_init_proc(void)
{
    int ret = 0;
    struct proc_dir_entry *prEntry_keyboard = NULL;
    struct proc_dir_entry *prEntry_tmp = NULL;

    kb_err("%s %d\n", __func__, __LINE__);
    prEntry_keyboard = proc_mkdir("pogopin", NULL);
    if (prEntry_keyboard == NULL) {
        kb_err("%s %d couldn't create entry\n", __func__, __LINE__);
        ret = -ENOMEM;
    }

    prEntry_tmp = proc_create("tty_name", 0444, prEntry_keyboard, &proc_tty_name_ops);
    if (prEntry_tmp == NULL) {
        kb_err("%s %d couldn't create proc entry\n", __func__, __LINE__);
        ret = -ENOMEM;
    }

    if (pogo_keyboard_client->get_crc_ibm_from_dts) {
        prEntry_tmp = proc_create("crc_ibm_init_val", 0444, prEntry_keyboard, &proc_crc_ibm_ops);
        if (prEntry_tmp == NULL) {
            kb_err("%s %d couldn't create crc_ibm_init_val entry\n", __func__, __LINE__);
            ret = -ENOMEM;
        }
    }

    if (pogo_keyboard_client->pogopin_touch_support) {
        prEntry_tmp = proc_create("kbd_touch_status", 0444, prEntry_keyboard, &proc_touchpad_state_ops);
        if (prEntry_tmp == NULL) {
            kb_err("%s %d couldn't create proc entry\n", __func__, __LINE__);
            ret = -ENOMEM;
        }
    }

    if (pogo_keyboard_client->pogo_battery_support) {
        prEntry_tmp = proc_create("kbd_battery_power_level", 0444, prEntry_keyboard, &proc_battery_power_level_ops);
        if (prEntry_tmp == NULL) {
            kb_err("%s %d couldn't create proc entry:kbd_battery_power_level\n", __func__, __LINE__);
            ret = -ENOMEM;
        }
        prEntry_tmp = proc_create("kbd_battery_charge_current", 0444, prEntry_keyboard, &proc_battery_charge_current_ops);
        if (prEntry_tmp == NULL) {
            kb_err("%s %d couldn't create proc entry:kbd_battery_charge_current\n", __func__, __LINE__);
            ret = -ENOMEM;
        }
    }
    /*for factory test detect*/
    prEntry_tmp = proc_create("kbd_keypad_status", 0444, prEntry_keyboard, &proc_keypad_state_ops);
    if (prEntry_tmp == NULL) {
        kb_err("%s %d couldn't create proc entry\n", __func__, __LINE__);
        ret = -ENOMEM;
    }

    if (pogo_keyboard_client->pogopin_fw_support) {
        prEntry_tmp = proc_create_data("kpdmcu_fw_update", 0666, prEntry_keyboard, &proc_kpdmcu_fw_update_ops, pogo_keyboard_client);
        if (prEntry_tmp == NULL) {
            kb_err("%s %d create kpdmcu_fw_update proc entry failed.\n", __func__, __LINE__);
        }

        prEntry_tmp = proc_create_data("kpdmcu_fw_check", 0666, prEntry_keyboard, &proc_kpdmcu_fw_check_ops, pogo_keyboard_client);
        if (prEntry_tmp == NULL) {
            kb_err("%s %d create kpdmcu_fw_check proc entry failed.\n", __func__, __LINE__);
        }
    }

    return ret;
}

static int pogo_keyboard_init_device_uevent(void)
{
    int status = 0;
    dev_t devt;

    pogo_keyboard_client->uevent_class = class_create(THIS_MODULE, "pogopin");
    if (pogo_keyboard_client->uevent_class == NULL) {
        return EINVAL;
    }

    status = alloc_chrdev_region(&devt, 0, 1, "keyboard");
    if (status < 0) {
        class_destroy(pogo_keyboard_client->uevent_class);
        return status;
    }

    pogo_keyboard_client->uevent_dev = device_create(pogo_keyboard_client->uevent_class, NULL, devt, NULL, "%s", KEYBOARD_NAME);
    if (pogo_keyboard_client->uevent_dev == NULL) {
        unregister_chrdev_region(devt, 1);
        class_destroy(pogo_keyboard_client->uevent_class);
        return EINVAL;
    }

    pogo_keyboard_client->uevent_dev->devt = devt;

    return 0;
}

static void pogo_keyboard_deinit_device_uevent(void)
{
    device_destroy(pogo_keyboard_client->uevent_class, pogo_keyboard_client->uevent_dev->devt);
    unregister_chrdev_region(pogo_keyboard_client->uevent_dev->devt, 1);
    class_destroy(pogo_keyboard_client->uevent_class);
}

int pogo_keyboard_plat_probe(struct platform_device *device)
{
    int ret = 0;

    kb_debug("%s %d start\n", __func__, __LINE__);

    pogo_keyboard_client = kzalloc(sizeof(*pogo_keyboard_client), GFP_KERNEL);
    if (!pogo_keyboard_client) {
        kb_err("%s %d kzalloc err\n", __func__, __LINE__);
        return -ENOMEM;
    }
    mutex_init(&pogo_keyboard_client->mutex);

    ret = kfifo_alloc(&pogo_keyboard_client->event_fifo,
        sizeof(struct pogo_keyboard_event) * POGO_KEYBOARD_EVENT_MAX, GFP_KERNEL);
    if (ret) {
        kb_err("%s %d kfifo_alloc fail\n", __func__, __LINE__);
        goto err_kfifo_alloc;
    }
    spin_lock_init(&pogo_keyboard_client->event_fifo_lock);

    pogo_keyboard_client->pogo_keyboard_task = kthread_run(pogo_keyboard_event_handler, 0, "pogo_keyboard_task");
    if (IS_ERR_OR_NULL(pogo_keyboard_client->pogo_keyboard_task)) {
        kb_err("%s %d kthread_run err\n", __func__, __LINE__);
        pogo_keyboard_client->pogo_keyboard_task = NULL;
    }
    pogo_keyboard_client->plat_dev = device;
#ifndef CONFIG_REMOVE_OPLUS_FUNCTION
    pogo_keyboard_client->is_confidential = is_confidential();  //get confidential status.
#else
    pogo_keyboard_client->is_confidential = false;
#endif
    pogo_keyboard_start_up_init();
    ret = pogo_keyboard_get_dts_info(device);
    if (ret != 0) {
        goto err_dts_info;
    }
    ret = pogo_keyboard_input_wakeup_init();
    if (ret != 0) {
        goto err_wakeup_init;
    }

#if defined(CONFIG_KB_DEBUG_FS)
    ret = sysfs_create_group(&device->dev.kobj, &pogo_keyboard_attribute_group);
    if (ret != 0) {
        kb_err("%s %d sysfs_create_group err\n", __func__, __LINE__);
        goto err_create_group;
    }
#endif//CONFIG_KB_DEBUG_FS

    ret = pogo_keyboard_init_device_uevent();
    if (ret != 0) {
        kb_err("%s %d pogo_keyboard_init_device_uevent err\n", __func__, __LINE__);
        goto err_init_uevent;
    }

    ret = pogo_keyboard_init_proc();
    if (ret != 0) {
        kb_err("%s %d pogo_keyboard_init_proc err\n", __func__, __LINE__);
        goto err_init_proc;
    }

    pogo_keyboard_register_callback();

    INIT_DELAYED_WORK(&pogo_keyboard_client->lcd_notify_reg_work, pogo_keyboard_lcd_notify_reg_work);
    schedule_delayed_work(&pogo_keyboard_client->lcd_notify_reg_work, 0);

    if (pogo_keyboard_client->pogopin_fw_support) {
        pogo_keyboard_client->kpdmcu_fw_update_force = false;
        pogo_keyboard_client->is_kpdmcu_need_fw_update = false;
        pogo_keyboard_client->kpdmcu_update_end = false;
        pogo_keyboard_client->kpdmcu_fw_cnt = 0;
        pogo_keyboard_client->kpd_fw_status = FW_UPDATE_READY;
        pogo_keyboard_client->fw_update_progress = 0;
        INIT_DELAYED_WORK(&pogo_keyboard_client->kpdmcu_fw_data_version_work, kpdmcu_fw_data_version_thread);
        schedule_delayed_work(&pogo_keyboard_client->kpdmcu_fw_data_version_work, round_jiffies_relative(msecs_to_jiffies(30 * 1000)));
        INIT_WORK(&pogo_keyboard_client->kpdmcu_fw_update_work, kpdmcu_fw_update_thread);
    }

    kb_info("%s %d ok\n", __func__, __LINE__);

    return 0;

err_init_proc:
    pogo_keyboard_deinit_device_uevent();
err_init_uevent:
#ifdef CONFIG_KB_DEBUG_FS
    sysfs_remove_group(&device->dev.kobj, &pogo_keyboard_attribute_group);
err_create_group:
#endif
err_wakeup_init:
err_dts_info:
err_kfifo_alloc:
    kfree(pogo_keyboard_client);

    return ret;
}

static int pogo_keyboard_plat_remove(struct platform_device *device)
{
    pogo_keyboard_unregister_callback();
    if (pogo_keyboard_client->input_wakeup) {
        input_unregister_device(pogo_keyboard_client->input_wakeup);
        input_free_device(pogo_keyboard_client->input_wakeup);
        kb_debug("%s %d input_unregister_device \n", __func__, __LINE__);
        pogo_keyboard_client->input_wakeup = NULL;
    }
    if (pogo_keyboard_client->input_touchpad) {

        input_unregister_device(pogo_keyboard_client->input_touchpad);
        input_free_device(pogo_keyboard_client->input_touchpad);
        kb_debug("%s %d input_unregister_device \n", __func__, __LINE__);
        pogo_keyboard_client->input_touchpad = NULL;
    }
    if (pogo_keyboard_client->input_pogo_keyboard) {
        input_unregister_device(pogo_keyboard_client->input_pogo_keyboard);
        input_free_device(pogo_keyboard_client->input_pogo_keyboard);
        kb_debug("%s %d input_unregister_device \n", __func__, __LINE__);
        pogo_keyboard_client->input_pogo_keyboard = NULL;
    }
#ifdef CONFIG_KB_DEBUG_FS
    sysfs_remove_group(&device->dev.kobj, &pogo_keyboard_attribute_group);
#endif

    pogo_keyboard_lcd_event_unregister();
    pogo_keyboard_deinit_device_uevent();

    if (pogo_keyboard_client) {
        kfree(pogo_keyboard_client);
    }
    kb_debug("%s %d \n", __func__, __LINE__);
    return 0;
}

static int pogo_keyboard_plat_suspend(struct platform_device *device)
{
    kb_info("%s %d \n", __func__, __LINE__);
    return 0;
}

static int pogo_keyboard_plat_resume(struct platform_device *device)
{
    kb_info("%s %d \n", __func__, __LINE__);
    return 0;
}

static void pogo_keyboard_plat_shutdown(struct platform_device *device)
{
    kb_debug("%s %d \n", __func__, __LINE__);
}


static const struct of_device_id pogo_keyboard_plat_of_match[] = {
    {.compatible = KEYBOARD_CORE_NAME,},
    {},
};
static struct platform_driver pogo_keyboard_plat_driver = {
    .probe = pogo_keyboard_plat_probe,
    .remove = pogo_keyboard_plat_remove,
    // .suspend = pogo_keyboard_plat_suspend,
    // .resume = pogo_keyboard_plat_resume,
    .shutdown = pogo_keyboard_plat_shutdown,
    .driver = {
        .name = KEYBOARD_CORE_NAME,
        .owner = THIS_MODULE,
        .of_match_table = pogo_keyboard_plat_of_match,
    }
};


static int __init pogo_keyboard_mod_init(void)
{
    int ret = 0;
    kb_debug("%s %d start\n", __func__, __LINE__);


    ret = platform_driver_register(&pogo_keyboard_plat_driver);
    if (ret) {
        kb_err("%s %d platform_driver_register err\n", __func__, __LINE__);
        return ret;
    }
    kb_info("%s %d ok\n", __func__, __LINE__);
    return 0;
}

static void __exit pogo_keyboard_mod_exit(void)
{
    platform_driver_unregister(&pogo_keyboard_plat_driver);
    kb_info("%s %d ok\n", __func__, __LINE__);
}

module_init(pogo_keyboard_mod_init);
module_exit(pogo_keyboard_mod_exit);

MODULE_AUTHOR("Tinno Team Inc");
MODULE_DESCRIPTION("Tinno Keyboard Driver v1.0");
MODULE_LICENSE("GPL");
