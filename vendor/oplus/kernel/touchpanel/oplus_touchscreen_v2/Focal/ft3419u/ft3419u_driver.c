// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 */

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/gpio.h>
#include <linux/string.h>

#include "ft3419u_core.h"

struct chip_data_ft3419u *g_fts_data = NULL;

/*******Part0:LOG TAG Declear********************/

#ifdef TPD_DEVICE
#undef TPD_DEVICE
#define TPD_DEVICE "focaltech,ft3419u"
#else
#define TPD_DEVICE "focaltech,ft3419u"
#endif
#define TPD_INFO(a, arg...)  pr_err("[TP]"TPD_DEVICE ": " a, ##arg)
/*
#define TPD_DEBUG(a, arg...)\
	do {\
		if (LEVEL_DEBUG == tp_debug)\
			pr_err("[TP]"TPD_DEVICE ": " a, ##arg);\
	}while(0)
*/


#define FTS_REG_UPGRADE                             0xFC
#define FTS_UPGRADE_AA                              0xAA
#define FTS_UPGRADE_55                              0x55
#define FTS_DELAY_UPGRADE_AA                        10
#define FTS_DELAY_UPGRADE_RESET                     80
#define FTS_UPGRADE_LOOP                            10

#define FTS_ROMBOOT_CMD_SET_PRAM_ADDR               0xAD
#define FTS_ROMBOOT_CMD_SET_PRAM_ADDR_LEN           4
#define FTS_ROMBOOT_CMD_WRITE                       0xAE
#define FTS_ROMBOOT_CMD_START_APP                   0x08
#define FTS_DELAY_PRAMBOOT_START                    100
#define FTS_ROMBOOT_CMD_ECC                         0xCC
#define FTS_ROMBOOT_CMD_ECC_NEW_LEN                 8
#define FTS_ECC_FINISH_TIMEOUT                      100
#define FTS_ROMBOOT_CMD_ECC_FINISH                  0xCE
#define FTS_ROMBOOT_CMD_ECC_READ                    0xCD
#define FTS_PRAM_SADDR                              0x000000
#define FTS_DRAM_SADDR                              0xD00000
#define FTS_DELAY_READ_ID                           20

#define FTS_CMD_RESET                               0x07
#define FTS_CMD_START1                              0x55
#define FTS_CMD_START2                              0xAA
#define FTS_CMD_START_DELAY                         12
#define FTS_CMD_READ_ID                             0x90
#define FTS_CMD_DATA_LEN                            0xB0
#define FTS_CMD_ERASE_APP                           0x61
#define FTS_RETRIES_REASE                           50
#define FTS_RETRIES_DELAY_REASE                     400
#define FTS_REASE_APP_DELAY                         1350
#define FTS_CMD_ECC_INIT                            0x64
#define FTS_CMD_ECC_CAL                             0x65
#define FTS_RETRIES_ECC_CAL                         10
#define FTS_RETRIES_DELAY_ECC_CAL                   50
#define FTS_CMD_ECC_READ                            0x66
#define FTS_CMD_FLASH_STATUS                        0x6A
#define FTS_CMD_WRITE                               0xBF
#define FTS_RETRIES_WRITE                           100
#define FTS_RETRIES_DELAY_WRITE                     1

#define FTS_CMD_GAME_AIUINIT_EN                     0xC9
#define FTS_CMD_GAME_AIUINIT                        0xCA

#define FTS_CMD_FLASH_STATUS_NOP                    0x0000
#define FTS_CMD_FLASH_STATUS_ECC_OK                 0xF055
#define FTS_CMD_FLASH_STATUS_ERASE_OK               0xF0AA
#define FTS_CMD_FLASH_STATUS_WRITE_OK               0x1000

#define POINT_REPORT_CHECK_WAIT_TIME                200    /* unit:ms */
#define PRC_INTR_INTERVALS                          100    /* unit:ms */

#define PRAMBOOT_MIN_SIZE                           0x120
#define PRAMBOOT_MAX_SIZE                           (64*1024)


#define AL2_FCS_COEF                ((1 << 15) + (1 << 10) + (1 << 3))

enum GESTURE_ID {
	GESTURE_RIGHT2LEFT_SWIP = 0x20,
	GESTURE_LEFT2RIGHT_SWIP = 0x21,
	GESTURE_DOWN2UP_SWIP = 0x22,
	GESTURE_UP2DOWN_SWIP = 0x23,
	GESTURE_DOUBLE_TAP = 0x24,
	GESTURE_DOUBLE_SWIP = 0x25,
	GESTURE_RIGHT_VEE = 0x51,
	GESTURE_LEFT_VEE = 0x52,
	GESTURE_DOWN_VEE = 0x53,
	GESTURE_UP_VEE = 0x54,
	GESTURE_O_CLOCKWISE = 0x57,
	GESTURE_O_ANTICLOCK = 0x30,
	GESTURE_W = 0x31,
	GESTURE_M = 0x32,
	GESTURE_FINGER_PRINT = 0x26,
	GESTURE_SINGLE_TAP = 0x27,
	GESTURE_HEART_ANTICLOCK = 0x55,
	GESTURE_HEART_CLOCKWISE = 0x59,
};

static void focal_esd_check_enable(void *chip_data, bool enable);
static int fts_hw_reset(struct chip_data_ft3419u *ts_data, u32 delayms);


/*********************************************************
 *              proc/ftxxxx-debug                        *
 *********************************************************/
#define PROC_READ_REGISTER                      1
#define PROC_WRITE_REGISTER                     2
#define PROC_WRITE_DATA                         6
#define PROC_READ_DATA                          7
#define PROC_SET_TEST_FLAG                      8
#define PROC_HW_RESET                           11
#define PROC_NAME                               "ftxxxx-debug"
#define PROC_BUF_SIZE                           256

static ssize_t fts_debug_write(struct file *filp, const char __user *buff, size_t count, loff_t *ppos)
{
	u8 *writebuf = NULL;
	u8 tmpbuf[PROC_BUF_SIZE] = { 0 };
	int buflen = count;
	int writelen = 0;
	int ret = 0;
	char tmp[PROC_BUF_SIZE];
	struct chip_data_ft3419u *ts_data = PDE_DATA(file_inode(filp));
	struct ftxxxx_proc *proc;

	if (!ts_data) {
		TPD_INFO("ts_data is null");
		return 0;
	}
	proc = &ts_data->proc;

	if (buflen <= 1) {
		TPD_INFO("apk proc wirte count(%d) fail", buflen);
		return -EINVAL;
	}

	if (buflen > PROC_BUF_SIZE) {
		writebuf = (u8 *)kzalloc(buflen * sizeof(u8), GFP_KERNEL);
		if (NULL == writebuf) {
			TPD_INFO("apk proc wirte buf zalloc fail");
			return -ENOMEM;
		}
	} else {
		writebuf = tmpbuf;
	}

	if (copy_from_user(writebuf, buff, buflen)) {
		TPD_INFO("[APK]: copy from user error!!");
		ret = -EFAULT;
		goto proc_write_err;
	}

	proc->opmode = writebuf[0];
	switch (proc->opmode) {
	case PROC_SET_TEST_FLAG:
		TPD_INFO("[APK]: PROC_SET_TEST_FLAG = %x", writebuf[1]);
		if (writebuf[1] == 0) {
			focal_esd_check_enable(ts_data, true);
		} else {
			focal_esd_check_enable(ts_data, false);
		}
		break;

	case PROC_READ_REGISTER:
		proc->cmd[0] = writebuf[1];
		break;

	case PROC_WRITE_REGISTER:
		ret = touch_i2c_write_byte(ts_data->client, writebuf[1], writebuf[2]);
		if (ret < 0) {
			TPD_INFO("PROC_WRITE_REGISTER write error");
			goto proc_write_err;
		}
		break;

	case PROC_READ_DATA:
		writelen = buflen - 1;
		ret = touch_i2c_write(ts_data->client, writebuf + 1, writelen);
		if (ret < 0) {
			TPD_INFO("PROC_READ_DATA write error");
			goto proc_write_err;
		}
		break;

	case PROC_WRITE_DATA:
		writelen = buflen - 1;
		ret = touch_i2c_write(ts_data->client, writebuf + 1, writelen);
		if (ret < 0) {
			TPD_INFO("PROC_WRITE_DATA write error");
			goto proc_write_err;
		}
		break;

	case PROC_HW_RESET:
		if (buflen < PROC_BUF_SIZE) {
			snprintf(tmp, PROC_BUF_SIZE, "%s", writebuf + 1);
			tmp[buflen - 1] = '\0';
			if (strncmp(tmp, "focal_driver", 12) == 0) {
				TPD_INFO("APK execute HW Reset");
				fts_hw_reset(ts_data, 0);
			}
		}
		break;

	default:
		break;
	}

	ret = buflen;
proc_write_err:
	if ((buflen > PROC_BUF_SIZE) && writebuf) {
		kfree(writebuf);
		writebuf = NULL;
	}

	return ret;
}

static ssize_t fts_debug_read(struct file *filp, char __user *buff, size_t count, loff_t *ppos)
{
	int ret = 0;
	int num_read_chars = 0;
	int buflen = count;
	u8 *readbuf = NULL;
	u8 tmpbuf[PROC_BUF_SIZE] = { 0 };
	struct chip_data_ft3419u *ts_data = PDE_DATA(file_inode(filp));
	struct ftxxxx_proc *proc;

	if (!ts_data) {
		TPD_INFO("ts_data is null");
		return 0;
	}
	proc = &ts_data->proc;

	if (buflen <= 0) {
		TPD_INFO("apk proc read count(%d) fail", buflen);
		return -EINVAL;
	}

	if (buflen > PROC_BUF_SIZE) {
		readbuf = (u8 *)kzalloc(buflen * sizeof(u8), GFP_KERNEL);
		if (NULL == readbuf) {
			TPD_INFO("apk proc wirte buf zalloc fail");
			return -ENOMEM;
		}
	} else {
		readbuf = tmpbuf;
	}

	switch (proc->opmode) {
	case PROC_READ_REGISTER:
		num_read_chars = 1;
		ret = touch_i2c_read(ts_data->client, &proc->cmd[0], 1, &readbuf[0], num_read_chars);
		if (ret < 0) {
			TPD_INFO("PROC_READ_REGISTER read error");
			goto proc_read_err;
		}
		break;
	case PROC_WRITE_REGISTER:
		break;

	case PROC_READ_DATA:
		num_read_chars = buflen;
		ret = touch_i2c_read(ts_data->client, NULL, 0, readbuf, num_read_chars);
		if (ret < 0) {
			TPD_INFO("PROC_READ_DATA read error");
			goto proc_read_err;
		}
		break;

	case PROC_WRITE_DATA:
		break;

	default:
		break;
	}

	ret = num_read_chars;
proc_read_err:
	if (copy_to_user(buff, readbuf, num_read_chars)) {
		TPD_INFO("copy to user error");
		ret = -EFAULT;
	}

	if ((buflen > PROC_BUF_SIZE) && readbuf) {
		kfree(readbuf);
		readbuf = NULL;
	}

	return ret;
}
/*
static const struct file_operations fts_proc_fops = {
	.owner  = THIS_MODULE,
	.read   = fts_debug_read,
	.write  = fts_debug_write,
};
*/
DECLARE_PROC_OPS(fts_proc_fops, simple_open, fts_debug_read, fts_debug_write, NULL);

static int fts_create_apk_debug_channel(struct chip_data_ft3419u *ts_data)
{
	struct ftxxxx_proc *proc = &ts_data->proc;

	proc->proc_entry = proc_create_data(PROC_NAME, 0777, NULL, &fts_proc_fops, ts_data);
	if (NULL == proc->proc_entry) {
		TPD_INFO("create proc entry fail");
		return -ENOMEM;
	}
	TPD_INFO("Create proc entry success!");
	return 0;
}

static void fts_release_apk_debug_channel(struct chip_data_ft3419u *ts_data)
{
	struct ftxxxx_proc *proc = &ts_data->proc;

	if (proc->proc_entry) {
		proc_remove(proc->proc_entry);
	}
}


/*******Part1:Call Back Function implement*******/

static int fts_rstgpio_set(struct hw_resource *hw_res, bool on)
{
	if (gpio_is_valid(hw_res->reset_gpio)) {
		TPD_INFO("Set the reset_gpio \n");
		gpio_direction_output(hw_res->reset_gpio, on);

	} else {
		TPD_INFO("reset is invalid!!\n");
	}

	return 0;
}

/*
 * return success: 0; fail : negative
 */
static int fts_hw_reset(struct chip_data_ft3419u *ts_data, u32 delayms)
{
	TPD_INFO("%s.\n", __func__);
	fts_rstgpio_set(ts_data->hw_res, false); /* reset gpio*/
	msleep(5);
	fts_rstgpio_set(ts_data->hw_res, true); /* reset gpio*/

	if (delayms) {
		msleep(delayms);
	}

	return 0;
}
static int fts_power_control(void *chip_data, bool enable)
{
	int ret = 0;

	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;

	if (true == enable) {
		fts_rstgpio_set(ts_data->hw_res, false);
		msleep(1);
		ret = tp_powercontrol_avdd(ts_data->hw_res, true);

		if (ret) {
			return -1;
		}
		ret = tp_powercontrol_vddi(ts_data->hw_res, true);

		if (ret) {
			return -1;
		}
		msleep(POWEWRUP_TO_RESET_TIME);
		fts_rstgpio_set(ts_data->hw_res, true);
		msleep(RESET_TO_NORMAL_TIME);

	} else {
		fts_rstgpio_set(ts_data->hw_res, false);
		msleep(1);
		ret = tp_powercontrol_avdd(ts_data->hw_res, false);

		if (ret) {
			return -1;
		}
		ret = tp_powercontrol_vddi(ts_data->hw_res, false);

		if (ret) {
			return -1;
		}
	}

	return ret;
}

static int focal_dump_reg_state(void *chip_data, char *buf)
{
	int count = 0;
	u8 regvalue = 0;
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;

	/*power mode 0:active 1:monitor 3:sleep*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_POWER_MODE);
	count += sprintf(buf + count, "Power Mode:0x%02x\n", regvalue);

	/*FW version*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_FW_VER);
	count += sprintf(buf + count, "FW Ver:0x%02x\n", regvalue);

	/*Vendor ID*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_VENDOR_ID);
	count += sprintf(buf + count, "Vendor ID:0x%02x\n", regvalue);

	/* 1 Gesture mode,0 Normal mode*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_GESTURE_EN);
	count += sprintf(buf + count, "Gesture Mode:0x%02x\n", regvalue);

	/* 3 charge in*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_CHARGER_MODE_EN);
	count += sprintf(buf + count, "charge stat:0x%02x\n", regvalue);

	/*Interrupt counter*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_INT_CNT);
	count += sprintf(buf + count, "INT count:0x%02x\n", regvalue);

	/*Flow work counter*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_FLOW_WORK_CNT);
	count += sprintf(buf + count, "ESD count:0x%02x\n", regvalue);

	return count;
}

static int focal_get_fw_version(void *chip_data)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	return touch_i2c_read_byte(ts_data->client, FTS_REG_FW_VER);
}

static void focal_esd_check_enable(void *chip_data, bool enable)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	ts_data->esd_check_enabled = enable;
}

static bool focal_get_esd_check_flag(void *chip_data)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	return ts_data->esd_check_need_stop;
}

static int fts_esd_handle(void *chip_data)
{
	int ret = -1;
	int i = 0;
	static int flow_work_cnt_last = 0;
	static int err_cnt = 0;
	static int i2c_err = 0;
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;

	if (!ts_data->esd_check_enabled) {
		goto NORMAL_END;
	}

	ret = touch_i2c_read_byte(ts_data->client, 0x00);

	if ((ret & 0x70) == 0x40) { /*work in factory mode*/
		goto NORMAL_END;
	}

	for (i = 0; i < 3; i++) {
		ret = touch_i2c_read_byte(ts_data->client, FTS_REG_CHIP_ID);

		if (ret != FTS_VAL_CHIP_ID) {
			TPD_INFO("%s: read chip_id failed!(ret:%x)\n", __func__, ret);
			msleep(10);
			i2c_err++;

		} else {
			i2c_err = 0;
			break;
		}
	}

	ret = touch_i2c_read_byte(ts_data->client, FTS_REG_FLOW_WORK_CNT);

	if (ret < 0) {
		TPD_INFO("%s: read FTS_REG_FLOW_WORK_CNT failed!\n", __func__);
		i2c_err++;
	}

	if (flow_work_cnt_last == ret) {
		err_cnt++;

	} else {
		err_cnt = 0;
	}

	flow_work_cnt_last = ret;

	if ((err_cnt >= 5) || (i2c_err >= 3)) {
		TPD_INFO("esd check failed, start reset!\n");
		disable_irq_nosync(ts_data->client->irq);
		tp_touch_btnkey_release(ts_data->tp_index);
		fts_hw_reset(ts_data, RESET_TO_NORMAL_TIME);
		enable_irq(ts_data->client->irq);
		flow_work_cnt_last = 0;
		err_cnt = 0;
		i2c_err = 0;
	}

NORMAL_END:
	return 0;
}


static void fts_release_all_finger(struct touchpanel_data *ts)
{
#ifdef TYPE_B_PROTOCOL
	int i = 0;

	if (!ts->touch_count || !ts->irq_slot)
		return;

	mutex_lock(&ts->report_mutex);
	for (i = 0; i < ts->max_num; i++) {
		input_mt_slot(ts->input_dev, i);
		input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, 0);
	}
	input_report_key(ts->input_dev, BTN_TOUCH, 0);
	input_report_key(ts->input_dev, BTN_TOOL_FINGER, 0);
	input_sync(ts->input_dev);
	mutex_unlock(&ts->report_mutex);
	TPD_INFO("fts_release_all_finger");
	ts->view_area_touched = 0; /*realse all touch point,must clear this flag*/
	ts->touch_count = 0;
	ts->irq_slot = 0;
#endif
}

static void fts_prc_func(struct work_struct *work)
{
	struct chip_data_ft3419u *ts_data = container_of(work,
	                                   struct chip_data_ft3419u, prc_work.work);
	unsigned long cur_jiffies = jiffies;
	unsigned long intr_timeout = msecs_to_jiffies(PRC_INTR_INTERVALS);

	if (ts_data->ts->is_suspended)
		return;

	intr_timeout += ts_data->intr_jiffies;
	if (time_after(cur_jiffies, intr_timeout)) {
		if (!ts_data->ts->is_suspended)
			fts_release_all_finger(ts_data->ts);
		ts_data->prc_mode = 0;
		/*FTS_DEBUG("interval:%lu", (cur_jiffies - ts_data->intr_jiffies) * 1000 / HZ);*/
	} else {
		queue_delayed_work(ts_data->ts_workqueue, &ts_data->prc_work,
		                   msecs_to_jiffies(POINT_REPORT_CHECK_WAIT_TIME));
		ts_data->prc_mode = 1;
	}
}

static void fts_prc_queue_work(struct chip_data_ft3419u *ts_data)
{
	ts_data->intr_jiffies = jiffies;
	if (!ts_data->prc_mode) {
		queue_delayed_work(ts_data->ts_workqueue, &ts_data->prc_work,
		                   msecs_to_jiffies(POINT_REPORT_CHECK_WAIT_TIME));
		ts_data->prc_mode = 1;
	}
}



static int fts_point_report_check_init(struct chip_data_ft3419u *ts_data)
{
	TPD_INFO("point check init");

	if (ts_data->ts_workqueue) {
		INIT_DELAYED_WORK(&ts_data->prc_work, fts_prc_func);
	} else {
		TPD_INFO("fts workqueue is NULL, can't run point report check function");
		return -EINVAL;
	}

	return 0;
}

static int fts_point_report_check_exit(struct chip_data_ft3419u *ts_data)
{
	TPD_INFO("point check exit");
	cancel_delayed_work_sync(&ts_data->prc_work);
	return 0;
}


static bool fts_fwupg_check_flash_status(struct chip_data_ft3419u *ts_data,
        u16 flash_status, int retries, int retries_delay)
{
	int ret = 0;
	int i = 0;
	u8 cmd = 0;
	u8 val[2] = { 0 };
	u16 read_status = 0;

	for (i = 0; i < retries; i++) {
		cmd = FTS_CMD_FLASH_STATUS;
		ret = touch_i2c_read_block(ts_data->client, cmd, 2, val);
		read_status = (((u16)val[0]) << 8) + val[1];

		if (flash_status == read_status) {
			return true;
		}

		TPD_DEBUG("flash status fail,ok:%04x read:%04x, retries:%d", flash_status,
		          read_status, i);
		msleep(retries_delay);
	}

	TPD_INFO("flash status fail,ok:%04x read:%04x, retries:%d", flash_status,
	         read_status, i);
	return false;
}

/*upgrade function*/
static u8 pb_file_ft3419u[] = {
#include "./FT5452J_Pramboot_V4.1_20210427.h"
};

static int ft3419u_fwupg_get_boot_state(struct chip_data_ft3419u *ts_data, enum FW_STATUS *fw_sts)
{
	int ret = 0;
	u8 cmd[4] = { 0 };
	u8 val[3] = { 0 };

	TPD_INFO("**********read boot id**********");
	if (!fw_sts) {
		TPD_INFO("fw_sts is null");
		return -EINVAL;
	}

	ret = touch_i2c_write_byte(ts_data->client, FTS_CMD_START1, FTS_CMD_START2);
	if (ret < 0) {
		TPD_INFO("write 55 AA cmd fail");
		return ret;
	}

	msleep(FTS_CMD_START_DELAY);
	cmd[0] = FTS_CMD_READ_ID;
	cmd[1] = cmd[2] = cmd[3] = 0x00;
	ret = touch_i2c_read(ts_data->client, cmd, 4, val, 2);
	if (ret < 0) {
		TPD_INFO("write 90 cmd fail");
		return ret;
	}

	TPD_INFO("read boot id:0x%02x%02x", val[0], val[1]);
	if ((val[0] == FTS_VAL_RB_ID) && (val[1] == FTS_VAL_RB_ID2)) {
		TPD_INFO("tp run in romboot");
		*fw_sts = FTS_RUN_IN_ROM;
	} else if ((val[0] == FTS_VAL_PB_ID) && (val[1] == FTS_VAL_PB_ID2)) {
		TPD_INFO("tp run in pramboot");
		*fw_sts = FTS_RUN_IN_PRAM;
	}

	return 0;
}

static bool ft3419u_fwupg_check_state(struct chip_data_ft3419u *ts_data, enum FW_STATUS rstate)
{
	int ret = 0;
	int i = 0;
	enum FW_STATUS cstate = FTS_RUN_IN_ERROR;

	for (i = 0; i < FTS_UPGRADE_LOOP; i++) {
		ret = ft3419u_fwupg_get_boot_state(ts_data, &cstate);
		/* TPD_INFO("fw state=%d, retries=%d", cstate, i); */
		if (cstate == rstate)
			return true;
		msleep(FTS_DELAY_READ_ID);
	}

	return false;
}

static int ft3419u_fwupg_reset_to_romboot(struct chip_data_ft3419u *ts_data)
{
	int ret = 0;
	int i = 0;
	u8 cmd = FTS_CMD_RESET;
	enum FW_STATUS state = FTS_RUN_IN_ERROR;

	ret = touch_i2c_write_block(ts_data->client, cmd, 0, NULL);
	if (ret < 0) {
		TPD_INFO("pram/rom/bootloader reset cmd write fail");
		return ret;
	}
	mdelay(10);

	for (i = 0; i < FTS_UPGRADE_LOOP; i++) {
		ret = ft3419u_fwupg_get_boot_state(ts_data, &state);
		if (FTS_RUN_IN_ROM == state)
			break;
		mdelay(5);
	}
	if (i >= FTS_UPGRADE_LOOP) {
		TPD_INFO("reset to romboot fail");
		return -EIO;
	}

	return 0;
}

static void ft3419u_crc16_calc_host(u8 *pbuf, u32 length, u16 *ecc)
{
	u32 i = 0;
	u32 j = 0;
	u16 tmp_ecc = 0;

	for (i = 0; i < length; i += 2) {
		tmp_ecc ^= ((pbuf[i] << 8) | (pbuf[i + 1]));
		for (j = 0; j < 16; j ++) {
			if (tmp_ecc & 0x01)
				tmp_ecc = (u16)((tmp_ecc >> 1) ^ AL2_FCS_COEF);
			else
				tmp_ecc >>= 1;
		}
	}

	*ecc = tmp_ecc;
}

static int ft3419u_pram_ecc_cal(struct chip_data_ft3419u *ts_data, u32 start_addr, u32 ecc_length, u16 *ecc)
{
	int ret = 0;
	u8 val[2] = { 0 };
	u8 tmp = 0;
	int i = 0;
	u8 cmd[FTS_ROMBOOT_CMD_ECC_NEW_LEN] = { 0 };

	TPD_INFO("read out pramboot checksum");
	cmd[0] = FTS_ROMBOOT_CMD_ECC;
	cmd[1] = (start_addr >> 16) & 0xFF;
	cmd[2] = (start_addr >> 8) & 0xFF;
	cmd[3] = (start_addr) & 0xFF;
	cmd[4] = (ecc_length >> 16) & 0xFF;
	cmd[5] = (ecc_length >> 8) & 0xFF;
	cmd[6] = (ecc_length) & 0xFF;
	cmd[7] = 0xCC;
	ret = touch_i2c_write(ts_data->client, cmd, FTS_ROMBOOT_CMD_ECC_NEW_LEN);
	if (ret < 0) {
		TPD_INFO("write pramboot ecc cal cmd fail");
		return ret;
	}

	cmd[0] = FTS_ROMBOOT_CMD_ECC_FINISH;
	for (i = 0; i < FTS_ECC_FINISH_TIMEOUT; i++) {
        msleep(1);
        ret = touch_i2c_read_byte(ts_data->client, cmd[0]);
        if (ret < 0) {
			TPD_INFO("ecc_finish read cmd fail");
			return ret;
        }
        tmp = 0x33;
        if (tmp == ret)
			break;
	}
	if (i >= FTS_ECC_FINISH_TIMEOUT) {
        TPD_INFO("wait ecc finish fail");
        return -EIO;
	}

	msleep(10);
	cmd[0] = FTS_ROMBOOT_CMD_ECC_READ;
	ret = touch_i2c_read_block(ts_data->client, cmd[0], 2, val);
	if (ret < 0) {
		TPD_INFO("read pramboot ecc fail");
		return ret;
	}

	*ecc = ((u16)(val[0] << 8) + val[1]);
	return 0;
}

static int ft3419u_pram_write_buf(struct chip_data_ft3419u *ts_data, u8 *buf, u32 len)
{
	int ret = 0;
	u32 i = 0;
	u32 j = 0;
	u32 offset = 0;
	u32 remainder = 0;
	u32 packet_number;
	u32 packet_len = 0;
	u8 packet_buf[BYTES_PER_TIME + 6] = { 0 };
	u32 cmdlen = 0;

	TPD_INFO("write pramboot to pram,pramboot len=%d", len);
	if (!buf || (len < PRAMBOOT_MIN_SIZE) || (len > (PRAMBOOT_MAX_SIZE))) {
		TPD_INFO("buf/pramboot length(%d) fail", len);
		return -EINVAL;
	}

	packet_number = len / BYTES_PER_TIME;
	remainder = len % BYTES_PER_TIME;
	if (remainder > 0)
		packet_number++;
	packet_len = BYTES_PER_TIME;

	for (i = 0; i < packet_number; i++) {
		offset = i * BYTES_PER_TIME;
		/* last packet */
		if ((i == (packet_number - 1)) && remainder)
			packet_len = remainder;

		packet_buf[0] = FTS_ROMBOOT_CMD_SET_PRAM_ADDR;
		packet_buf[1] = (offset >> 16) & 0xFF;
		packet_buf[2] = (offset >> 8) & 0xFF;
		packet_buf[3] = (offset) & 0xFF;

		ret = touch_i2c_write(ts_data->client, packet_buf, FTS_ROMBOOT_CMD_SET_PRAM_ADDR_LEN);
		if (ret < 0) {
			TPD_INFO("pramboot set write address(%d) fail", i);
			return ret;
		}

		packet_buf[0] = FTS_ROMBOOT_CMD_WRITE;
		cmdlen = 1;

		for (j = 0; j < packet_len; j++) {
			packet_buf[cmdlen + j] = buf[offset + j];
		}

		ret = touch_i2c_write(ts_data->client, packet_buf, packet_len + cmdlen);
		if (ret < 0) {
			TPD_INFO("pramboot write data(%d) fail", i);
			return ret;
		}
	}

	return 0;
}

static int ft3419u_pram_start(struct chip_data_ft3419u *ts_data)
{
	u8 cmd = FTS_ROMBOOT_CMD_START_APP;
	int ret = 0;

	TPD_INFO("remap to start pramboot");

	ret = touch_i2c_write_block(ts_data->client, cmd, 0, NULL);
	if (ret < 0) {
		TPD_INFO("write start pram cmd fail");
		return ret;
	}
	msleep(FTS_DELAY_PRAMBOOT_START);

	return 0;
}

static int fts_ft3419u_write_pramboot_private(struct chip_data_ft3419u *ts_data)
{
	int ret = 0;
	bool state = 0;
	enum FW_STATUS status = FTS_RUN_IN_ERROR;
	u16 ecc_in_host = 0;
	u16 ecc_in_tp = 0;
	u8 *pb_buf = pb_file_ft3419u;
	u32 pb_len = sizeof(pb_file_ft3419u);

	TPD_INFO("**********pram write and init**********");
	if (pb_len < 0x120) {
		TPD_INFO("pramboot length(%d) fail", pb_len);
		return -EINVAL;
	}

	TPD_INFO("check whether tp is in romboot or not ");
	/* need reset to romboot when non-romboot state */
	ret = ft3419u_fwupg_get_boot_state(ts_data, &status);
	if (status != FTS_RUN_IN_ROM) {
		TPD_INFO("tp isn't in romboot, need send reset to romboot");
		ret = ft3419u_fwupg_reset_to_romboot(ts_data);
		if (ret < 0) {
			TPD_INFO("reset to romboot fail");
			return ret;
		}
	}

	/* write pramboot to pram */
	ret = ft3419u_pram_write_buf(ts_data, pb_buf, pb_len);
	if (ret < 0) {
		TPD_INFO("write pramboot buffer fail");
		return ret;
	}

	/* check CRC */
	ft3419u_crc16_calc_host(pb_buf, pb_len, &ecc_in_host);
	ret = ft3419u_pram_ecc_cal(ts_data, 0, pb_len, &ecc_in_tp);
	if (ret < 0) {
		TPD_INFO("read pramboot ecc fail");
		return ret;
	}

	TPD_INFO("pram ecc in tp:%x, host:%x", ecc_in_tp, ecc_in_host);
	/*  pramboot checksum != fw checksum, upgrade fail */
	if (ecc_in_host != ecc_in_tp) {
		TPD_INFO("pramboot ecc check fail");
		return -EIO;
	}

	/*start pram*/
	ret = ft3419u_pram_start(ts_data);
	if (ret < 0) {
		TPD_INFO("pram start fail");
		return ret;
	}

	TPD_INFO("after write pramboot, confirm run in pramboot");
	state = ft3419u_fwupg_check_state(ts_data, FTS_RUN_IN_PRAM);
	if (!state) {
		TPD_INFO("not in pramboot");
		return -EIO;
	}

	return 0;
}

static int fts_fwupg_enter_into_boot(struct chip_data_ft3419u *ts_data)
{
	int ret = 0;
	int i = 0;
	u8 cmd[4] = { 0 };
	u8 id[2] = { 0 };

	do {
		/*reset to boot*/
		ret = touch_i2c_write_byte(ts_data->client, FTS_REG_UPGRADE, FTS_UPGRADE_AA);

		if (ret < 0) {
			TPD_INFO("write FC=0xAA fail");
			return ret;
		}

		msleep(FTS_DELAY_UPGRADE_AA);

		ret = touch_i2c_write_byte(ts_data->client, FTS_REG_UPGRADE, FTS_UPGRADE_55);

		if (ret < 0) {
			TPD_INFO("write FC=0x55 fail");
			return ret;
		}

		msleep(FTS_DELAY_UPGRADE_RESET);

		/*read boot id*/
        ret = touch_i2c_write_byte(ts_data->client, FTS_CMD_START1, FTS_CMD_START2);
		if (ret < 0) {
			TPD_INFO("write 0x55 0xAA fail");
			return ret;
		}

		cmd[0] = FTS_CMD_READ_ID;
        cmd[1] = cmd[2] = cmd[3] = 0;
		ret = touch_i2c_read(ts_data->client, cmd, 4, id, 2);

		if (ret < 0) {
			TPD_INFO("read boot id fail");
			return ret;
		}

		TPD_INFO("read boot id:0x%02x%02x", id[0], id[1]);

		if ((id[0] == 0x54) && (id[1] == 0x52)) {
			break;
		}
	} while (i++ < FTS_UPGRADE_LOOP);

	if (i >= 10) {
		TPD_INFO("read boot id fail");
		return -EIO;
	}


	ret = fts_ft3419u_write_pramboot_private(ts_data);
	if (ret < 0) {
		TPD_INFO("pram write_init fail");
		return ret;
	}

	return 0;
}

static int fts_fwupg_erase(struct chip_data_ft3419u *ts_data, u32 delay)
{
	int ret = 0;
	u8 cmd = 0;
	bool flag = false;

	TPD_INFO("**********erase now**********");

	/*send to erase flash*/
	cmd = FTS_CMD_ERASE_APP;
	ret = touch_i2c_write_block(ts_data->client, cmd, 0, NULL);

	if (ret < 0) {
		TPD_INFO("send erase cmd fail");
		return ret;
	}

	msleep(delay);

	/* read status 0xF0AA: success */
	flag = fts_fwupg_check_flash_status(ts_data, FTS_CMD_FLASH_STATUS_ERASE_OK,
	                                    FTS_RETRIES_REASE, FTS_RETRIES_DELAY_REASE);

	if (!flag) {
		TPD_INFO("check ecc flash status fail");
		return -EIO;
	}

	return 0;
}

static int fts_flash_write_buf(struct chip_data_ft3419u *ts_data, u32 saddr,
                               u8 *buf, u32 len, u32 delay)
{
	int ret = 0;
	u32 i = 0;
	u32 j = 0;
	u32 packet_number = 0;
	u32 packet_len = 0;
	u32 addr = 0;
	u32 offset = 0;
	u32 remainder = 0;
	u32 cmdlen = 0;
	u8 packet_buf[BYTES_PER_TIME + 6] = { 0 };
	u8 cmd = 0;
	u8 val[2] = { 0 };
	u16 read_status = 0;
	u16 wr_ok = 0;

	TPD_INFO("**********write data to flash**********");
	TPD_INFO("data buf start addr=0x%x, len=0x%x", saddr, len);
	packet_number = len / BYTES_PER_TIME;
	remainder = len % BYTES_PER_TIME;

	if (remainder > 0) {
		packet_number++;
	}

	packet_len = BYTES_PER_TIME;
	TPD_INFO("write data, num:%d remainder:%d", packet_number, remainder);

	for (i = 0; i < packet_number; i++) {
		offset = i * BYTES_PER_TIME;
		addr = saddr + offset;
		cmdlen = 6;
		packet_buf[0] = FTS_CMD_WRITE;
		packet_buf[1] = (addr >> 16) & 0xFF;
		packet_buf[2] = (addr >> 8) & 0xFF;
		packet_buf[3] = (addr) & 0xFF;

		/* last packet */
		if ((i == (packet_number - 1)) && remainder) {
			packet_len = remainder;
		}

		packet_buf[4] = (packet_len >> 8) & 0xFF;
		packet_buf[5] = (packet_len) & 0xFF;
		memcpy(&packet_buf[cmdlen], &buf[offset], packet_len);
		ret = touch_i2c_write_block(ts_data->client, packet_buf[0],
		                            packet_len + cmdlen - 1, &packet_buf[1]);

		if (ret < 0) {
			TPD_INFO("app write fail");
			return ret;
		}

		mdelay(delay);

		/* read status */
		wr_ok = FTS_CMD_FLASH_STATUS_WRITE_OK + addr / packet_len;

		for (j = 0; j < FTS_RETRIES_WRITE; j++) {
			cmd = FTS_CMD_FLASH_STATUS;
			ret = touch_i2c_read_block(ts_data->client, cmd, 2, val);
			read_status = (((u16)val[0]) << 8) + val[1];

			/* TPD_DEBUG("%x %x", wr_ok, read_status); */
			if (wr_ok == read_status) {
				break;
			}

			mdelay(FTS_RETRIES_DELAY_WRITE);
		}
	}

	return 0;
}

static int fts_fwupg_ecc_cal_host(u8 *buf, u32 len)
{
	u8 ecc = 0;
	u32 i = 0;

	for (i = 0; i < len; i++) {
		ecc ^= buf[i];
	}

	return (int)ecc;
}

int fts_fwupg_ecc_cal_tp(struct chip_data_ft3419u *ts_data, u32 saddr, u32 len)
{
	int ret = 0;
	u8 wbuf[7] = { 0 };
	u8 val[2] = { 0 };
	int ecc = 0;
	bool bflag = false;

	TPD_INFO("**********read out checksum**********");
	/* check sum init */
	wbuf[0] = FTS_CMD_ECC_INIT;
	ret = touch_i2c_write_block(ts_data->client, wbuf[0] & 0xff, 0, NULL);

	if (ret < 0) {
		TPD_INFO("ecc init cmd write fail");
		return ret;
	}

	/* send commond to start checksum */
	wbuf[0] = FTS_CMD_ECC_CAL;
	wbuf[1] = (saddr >> 16) & 0xFF;
	wbuf[2] = (saddr >> 8) & 0xFF;
	wbuf[3] = (saddr);
	wbuf[4] = (len >> 16) & 0xFF;
	wbuf[5] = (len >> 8) & 0xFF;
	wbuf[6] = (len);
	TPD_INFO("ecc calc startaddr:0x%04x, len:%d", saddr, len);
	ret = touch_i2c_write_block(ts_data->client, wbuf[0] & 0xff, 6, &wbuf[1]);

	if (ret < 0) {
		TPD_INFO("ecc calc cmd write fail");
		return ret;
	}

	msleep(len / 256);

	/* read status if check sum is finished */
	bflag = fts_fwupg_check_flash_status(ts_data, FTS_CMD_FLASH_STATUS_ECC_OK,
	                                     FTS_RETRIES_ECC_CAL,
	                                     FTS_RETRIES_DELAY_ECC_CAL);

	if (!bflag) {
		TPD_INFO("ecc flash status read fail");
		return -EIO;
	}

	/* read out check sum */
	wbuf[0] = FTS_CMD_ECC_READ;
	ret = touch_i2c_read_block(ts_data->client, wbuf[0], 2, val);

	if (ret < 0) {
		TPD_INFO("ecc read cmd write fail");
		return ret;
	}

	ecc = val[0];

	return ecc;
}

static int fts_upgrade(struct chip_data_ft3419u *ts_data, u8 *buf, u32 len)
{
	struct monitor_data *monitor_data = ts_data->monitor_data;
	int ret = 0;
	u32 start_addr = 0;
	u8 cmd[4] = { 0 };
	int ecc_in_host = 0;
	int ecc_in_tp = 0;

	if (!buf) {
		TPD_INFO("fw_buf is invalid");
		return -EINVAL;
	}

	/* enter into upgrade environment */
	ret = fts_fwupg_enter_into_boot(ts_data);

	if (ret < 0) {
		tp_healthinfo_report(monitor_data, HEALTH_FW_UPDATE, "Enter pramboot/bootloader failed");
		TPD_INFO("enter into pramboot/bootloader fail,ret=%d", ret);
		goto fw_reset;
	}

	cmd[0] = FTS_CMD_DATA_LEN;
	cmd[1] = (len >> 16) & 0xFF;
	cmd[2] = (len >> 8) & 0xFF;
	cmd[3] = (len) & 0xFF;
	ret = touch_i2c_write_block(ts_data->client, cmd[0], 3, &cmd[1]);

	if (ret < 0) {
		tp_healthinfo_report(monitor_data, HEALTH_FW_UPDATE, "FTS_CMD_DATA_LEN failed");
		TPD_INFO("data len cmd write fail");
		goto fw_reset;
	}

	/*erase*/
	ret = fts_fwupg_erase(ts_data, FTS_REASE_APP_DELAY);

	if (ret < 0) {
		tp_healthinfo_report(monitor_data, HEALTH_FW_UPDATE, "FTS_REASE_APP_DELAY failed");
		TPD_INFO("erase cmd write fail");
		goto fw_reset;
	}

	/* write app */
	start_addr = 0;
	ret = fts_flash_write_buf(ts_data, start_addr, buf, len, 1);

	if (ret < 0) {
		tp_healthinfo_report(monitor_data, HEALTH_FW_UPDATE, "Flash Write failed");
		TPD_INFO("flash write fail");
		goto fw_reset;
	}

	ecc_in_host = fts_fwupg_ecc_cal_host(buf, len);
	ecc_in_tp = fts_fwupg_ecc_cal_tp(ts_data, start_addr, len);

	if (ecc_in_tp < 0) {
		tp_healthinfo_report(monitor_data, HEALTH_FW_UPDATE, "ECC Read failed");
		TPD_INFO("ecc read fail");
		goto fw_reset;
	}

	TPD_INFO("ecc in tp:%x, host:%x", ecc_in_tp, ecc_in_host);

	if (ecc_in_tp != ecc_in_host) {
		tp_healthinfo_report(monitor_data, HEALTH_FW_UPDATE, "ECC Read failed");
		TPD_INFO("ecc check fail");
		goto fw_reset;
	}

	TPD_INFO("upgrade success, reset to normal boot");
	cmd[0] = FTS_CMD_RESET;
	ret = touch_i2c_write_block(ts_data->client, cmd[0], 0, NULL);

	if (ret < 0) {
		tp_healthinfo_report(monitor_data, HEALTH_FW_UPDATE, "FTS_CMD_RESET failed");
		TPD_INFO("reset to normal boot fail");
	}

	msleep(200);
	return 0;

fw_reset:
	TPD_INFO("upgrade fail, reset to normal boot");
	cmd[0] = FTS_CMD_RESET;
	ret = touch_i2c_write_block(ts_data->client, cmd[0], 0, NULL);

	if (ret < 0) {
		tp_healthinfo_report(monitor_data, HEALTH_FW_UPDATE, "FTS_CMD_RESET failed");
		TPD_INFO("reset to normal boot fail");
	}

	return -EIO;
}


static fw_check_state fts_fw_check(void *chip_data,
                                   struct resolution_info *resolution_info, struct panel_info *panel_data)
{
	u8 cmd[4] = { 0 };
	u8 id[2] = { 0 };
	char dev_version[MAX_DEVICE_VERSION_LENGTH] = {0};
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;

	id[0] = touch_i2c_read_byte(ts_data->client, FTS_REG_CHIP_ID);
	id[1] = touch_i2c_read_byte(ts_data->client, FTS_REG_CHIP_ID2);

	if ((id[0] != FTS_VAL_CHIP_ID) || (id[1] != FTS_VAL_CHIP_ID2)) {
		cmd[0] = 0x55;
		touch_i2c_write_block(ts_data->client, cmd[0], 0, NULL);
		msleep(12);
		cmd[0] = 0x90;
        cmd[1] = cmd[2] = cmd[3] = 0;
		touch_i2c_read(ts_data->client, cmd, 4, id, 2);
		TPD_INFO("boot id:0x%02x%02x, fw abnormal", id[0], id[1]);
		return FW_ABNORMAL;
	}

	/*fw check normal need update tp_fw  && device info*/
	ts_data->fwver = touch_i2c_read_byte(ts_data->client, FTS_REG_FW_VER);
	panel_data->tp_fw = ts_data->fwver;
	TPD_INFO("FW VER:%d", panel_data->tp_fw);

	if (panel_data->manufacture_info.version) {
		sprintf(dev_version, "%04x", panel_data->tp_fw);
		strlcpy(&(panel_data->manufacture_info.version[7]), dev_version, 5);
	}

	return FW_NORMAL;
}

int fts_reset_proc(int hdelayms)
{
	TPD_INFO("tp reset");
	fts_rstgpio_set(g_fts_data->hw_res, false); /* reset gpio*/
	msleep(5);
	fts_rstgpio_set(g_fts_data->hw_res, true); /* reset gpio*/

	if (hdelayms) {
		msleep(hdelayms);
	}

	return 0;
}

#define OFFSET_FW_DATA_FW_VER 0x010E
static fw_update_state fts_fw_update(void *chip_data, const struct firmware *fw,
                                     bool force)
{
	int ret = 0;
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	u8 *buf = NULL;
	u32 len = 0;

	if (!fw) {
		TPD_INFO("fw is null");
		return FW_UPDATE_ERROR;
	}

	buf = (u8 *)fw->data;
	len = (int)fw->size;

	if ((len < 0x120) || (len > (120 * 1024))) {
		TPD_INFO("fw_len(%d) is invalid", len);
		return FW_UPDATE_ERROR;
	}

	if (force || (buf[OFFSET_FW_DATA_FW_VER] != ts_data->fwver)) {
		TPD_INFO("Need update, force(%d)/fwver:Host(0x%02x),TP(0x%02x)", force,
		         buf[OFFSET_FW_DATA_FW_VER], ts_data->fwver);
		focal_esd_check_enable(ts_data, false);
		ret = fts_upgrade(ts_data, buf, len);
		focal_esd_check_enable(ts_data, true);

		if (ret < 0) {
			TPD_INFO("fw update fail");
			return FW_UPDATE_ERROR;
		}

		return FW_UPDATE_SUCCESS;
	}

	return FW_NO_NEED_UPDATE;
}


static int fts_enter_factory_work_mode(struct chip_data_ft3419u *ts_data,
                                       u8 mode_val)
{
	int ret = 0;
	int retry = 20;
	u8 regval = 0;

	TPD_INFO("%s:enter %s mode", __func__, (mode_val == 0x40) ? "factory" : "work");
	ret = touch_i2c_write_byte(ts_data->client, DEVIDE_MODE_ADDR, mode_val);

	if (ret < 0) {
		TPD_INFO("%s:write mode(val:0x%x) fail", __func__, mode_val);
		return ret;
	}

	while (--retry) {
		regval = touch_i2c_read_byte(ts_data->client, DEVIDE_MODE_ADDR);

		if (regval == mode_val) {
			break;
		}

		msleep(20);
	}

	if (!retry) {
		TPD_INFO("%s:enter mode(val:0x%x) timeout", __func__, mode_val);
		return -EIO;
	}

	msleep(FACTORY_TEST_DELAY);
	return 0;
}

static int fts_start_scan(struct chip_data_ft3419u *ts_data)
{
	int ret = 0;
	int retry = 50;
	u8 regval = 0;
	u8 scanval = FTS_FACTORY_MODE_VALUE | (1 << 7);

	TPD_INFO("%s: start to scan a frame", __func__);
	ret = touch_i2c_write_byte(ts_data->client, DEVIDE_MODE_ADDR, scanval);

	if (ret < 0) {
		TPD_INFO("%s:start to scan a frame fail", __func__);
		return ret;
	}

	while (--retry) {
		regval = touch_i2c_read_byte(ts_data->client, DEVIDE_MODE_ADDR);

		if (regval == FTS_FACTORY_MODE_VALUE) {
			break;
		}

		msleep(20);
	}

	if (!retry) {
		TPD_INFO("%s:scan a frame timeout", __func__);
		return -EIO;
	}

	return 0;
}

static int fts_get_rawdata(struct chip_data_ft3419u *ts_data, int *raw,
                           bool is_diff)
{
	int ret = 0;
	int i = 0;
	int byte_num = ts_data->hw_res->tx_num * ts_data->hw_res->rx_num * 2;
	int size = 0;
	int packet_len = 0;
	int offset = 0;
	u8 raw_addr = 0;
	u8 regval = 0;
	u8 *buf = NULL;

	TPD_INFO("%s:call", __func__);
	/*kzalloc buffer*/
	buf = kzalloc(byte_num, GFP_KERNEL);

	if (!buf) {
		TPD_INFO("%s:kzalloc for raw byte buf fail", __func__);
		return -ENOMEM;
	}

	ret = fts_enter_factory_work_mode(ts_data, FTS_FACTORY_MODE_VALUE);

	if (ret < 0) {
		TPD_INFO("%s:enter factory mode fail", __func__);
		goto raw_err;
	}

	if (is_diff) {
		regval = touch_i2c_read_byte(ts_data->client, FACTORY_REG_DATA_SELECT);
		ret = touch_i2c_write_byte(ts_data->client, FACTORY_REG_DATA_SELECT, 0x01);

		if (ret < 0) {
			TPD_INFO("%s:write 0x01 to reg0x06 fail", __func__);
			goto reg_restore;
		}
	}

	ret = fts_start_scan(ts_data);

	if (ret < 0) {
		TPD_INFO("%s:scan a frame fail", __func__);
		goto reg_restore;
	}

	ret = touch_i2c_write_byte(ts_data->client, FACTORY_REG_LINE_ADDR, 0xAA);

	if (ret < 0) {
		TPD_INFO("%s:write 0xAA to reg0x01 fail", __func__);
		goto reg_restore;
	}

	raw_addr = FACTORY_REG_RAWDATA_ADDR_MC_SC;
	ret = touch_i2c_read_block(ts_data->client, raw_addr, MAX_PACKET_SIZE, buf);
	size = byte_num - MAX_PACKET_SIZE;
	offset = MAX_PACKET_SIZE;

	while (size > 0) {
		if (size >= MAX_PACKET_SIZE) {
			packet_len = MAX_PACKET_SIZE;

		} else {
			packet_len = size;
		}

		ret = touch_i2c_read(ts_data->client, NULL, 0, buf + offset, packet_len);

		if (ret < 0) {
			TPD_INFO("%s:read raw data(packet:%d) fail", __func__,
			         offset / MAX_PACKET_SIZE);
			goto reg_restore;
		}

		size -= packet_len;
		offset += packet_len;
	}

	for (i = 0; i < byte_num; i = i + 2) {
		raw[i >> 1] = (int)(short)((buf[i] << 8) + buf[i + 1]);
	}

reg_restore:

	if (is_diff) {
		ret = touch_i2c_write_byte(ts_data->client, FACTORY_REG_DATA_SELECT, regval);

		if (ret < 0) {
			TPD_INFO("%s:restore reg0x06 fail", __func__);
		}
	}

raw_err:
	kfree(buf);
	ret = fts_enter_factory_work_mode(ts_data, FTS_WORK_MODE_VALUE);

	if (ret < 0) {
		TPD_INFO("%s:enter work mode fail", __func__);
	}

	return ret;
}

static void fts_delta_read(struct seq_file *s, void *chip_data)
{
	int ret = 0;
	int i = 0;
	int j = 0;
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	int *raw = NULL;
	int tx_num = ts_data->hw_res->tx_num;
	int rx_num = ts_data->hw_res->rx_num;

	TPD_INFO("%s:start to read diff data", __func__);
	focal_esd_check_enable(ts_data, false);   /*no allowed esd check*/

	raw = kzalloc(tx_num * rx_num * sizeof(int), GFP_KERNEL);

	if (!raw) {
		seq_printf(s, "kzalloc for raw fail\n");
		goto raw_fail;
	}

	ret = touch_i2c_write_byte(ts_data->client, FTS_REG_AUTOCLB_ADDR, 0x01);

	if (ret < 0) {
		TPD_INFO("%s, write 0x01 to reg 0xee failed \n", __func__);
	}

	ret = fts_get_rawdata(ts_data, raw, true);

	if (ret < 0) {
		seq_printf(s, "get diff data fail\n");
		goto raw_fail;
	}

	for (i = 0; i < tx_num; i++) {
		seq_printf(s, "\n[%2d]", i + 1);

		for (j = 0; j < rx_num; j++) {
			seq_printf(s, " %5d,", raw[i * rx_num + j]);
		}
	}

	seq_printf(s, "\n");

raw_fail:
	touch_i2c_write_byte(ts_data->client, FTS_REG_AUTOCLB_ADDR, 0x00);
	focal_esd_check_enable(ts_data, true);
	kfree(raw);
}

static void fts_baseline_read(struct seq_file *s, void *chip_data)
{
	int ret = 0;
	int i = 0;
	int j = 0;
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	int *raw = NULL;
	int tx_num = ts_data->hw_res->tx_num;
	int rx_num = ts_data->hw_res->rx_num;

	TPD_INFO("%s:start to read raw data", __func__);
	focal_esd_check_enable(ts_data, false);

	raw = kzalloc(tx_num * rx_num * sizeof(int), GFP_KERNEL);

	if (!raw) {
		seq_printf(s, "kzalloc for raw fail\n");
		goto raw_fail;
	}

	ret = fts_get_rawdata(ts_data, raw, false);

	if (ret < 0) {
		seq_printf(s, "get raw data fail\n");
		goto raw_fail;
	}

	for (i = 0; i < tx_num; i++) {
		seq_printf(s, "\n[%2d]", i + 1);

		for (j = 0; j < rx_num; j++) {
			seq_printf(s, " %5d,", raw[i * rx_num + j]);
		}
	}

	seq_printf(s, "\n");

raw_fail:
	focal_esd_check_enable(ts_data, true);
	kfree(raw);
}

static void fts_main_register_read(struct seq_file *s, void *chip_data)
{
	u8 regvalue = 0;
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;

	/*TP FW version*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_FW_VER);
	seq_printf(s, "TP FW Ver:0x%02x\n", regvalue);

	/*Vendor ID*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_VENDOR_ID);
	seq_printf(s, "Vendor ID:0x%02x\n", regvalue);

	/*Gesture enable*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_GESTURE_EN);
	seq_printf(s, "Gesture Mode:0x%02x\n", regvalue);

	/*charge in*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_CHARGER_MODE_EN);
	seq_printf(s, "charge state:0x%02x\n", regvalue);

	/*edge limit*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_EDGE_LIMIT);
	seq_printf(s, "edge Mode:0x%02x\n", regvalue);

	/*game mode*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_GAME_MODE_EN);
	seq_printf(s, "Game Mode:0x%02x\n", regvalue);

	/*FOD mode*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_FOD_EN);
	seq_printf(s, "FOD Mode:0x%02x\n", regvalue);

	/*Interrupt counter*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_INT_CNT);
	seq_printf(s, "INT count:0x%02x\n", regvalue);

	/*Flow work counter*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_FLOW_WORK_CNT);
	seq_printf(s, "ESD count:0x%02x\n", regvalue);

	/*Panel ID*/
	regvalue = touch_i2c_read_byte(ts_data->client, FTS_REG_MODULE_ID);
	seq_printf(s, "PANEL ID:0x%02x\n", regvalue);

	return;
}

static int fts_enable_black_gesture(struct chip_data_ft3419u *ts_data,
                                    bool enable)
{
	int ret = 0;
	int config1 = 0xff;
	int config2 = 0xff;
	int config4 = 0xff;
	int state = ts_data->gesture_state;

	if (enable) {
		SET_GESTURE_BIT(state, RIGHT2LEFT_SWIP, config1, 0)
		SET_GESTURE_BIT(state, LEFT2RIGHT_SWIP, config1, 1)
		SET_GESTURE_BIT(state, DOWN2UP_SWIP, config1, 2)
		SET_GESTURE_BIT(state, UP2DOWN_SWIP, config1, 3)
		SET_GESTURE_BIT(state, DOU_TAP, config1, 4)
		SET_GESTURE_BIT(state, DOU_SWIP, config1, 5)
		SET_GESTURE_BIT(state, SINGLE_TAP, config1, 7)
		SET_GESTURE_BIT(state, CIRCLE_GESTURE, config2, 0)
		SET_GESTURE_BIT(state, W_GESTURE, config2, 1)
		SET_GESTURE_BIT(state, M_GESTRUE, config2, 2)
		SET_GESTURE_BIT(state, RIGHT_VEE, config4, 1)
		SET_GESTURE_BIT(state, LEFT_VEE, config4, 2)
		SET_GESTURE_BIT(state, DOWN_VEE, config4, 3)
		SET_GESTURE_BIT(state, UP_VEE, config4, 4)
		SET_GESTURE_BIT(state, HEART, config4, 5)
	} else {
		config1 = 0;
		config2 = 0;
		config4 = 0;
	}

	TPD_INFO("MODE_GESTURE, write 0xD0=%d", enable);
	TPD_INFO("%s: config1:%x, config2:%x config4:%x\n", __func__, config1, config2, config4);

	ret = touch_i2c_write_byte(ts_data->client, FTS_REG_GESTURE_CONFIG1, config1);
	if (ret < 0) {
		TPD_INFO("%s: write FTS_REG_GESTURE_CONFIG1 enable(%x=%x) fail", __func__, FTS_REG_GESTURE_CONFIG1, config1);
	}
	ret = touch_i2c_write_byte(ts_data->client, FTS_REG_GESTURE_CONFIG2, config2);
	if (ret < 0) {
		TPD_INFO("%s: write FTS_REG_GESTURE_CONFIG2 enable(%x=%x) fail", __func__, FTS_REG_GESTURE_CONFIG2, config2);
	}
	ret = touch_i2c_write_byte(ts_data->client, FTS_REG_GESTURE_CONFIG4, config4);
	if (ret < 0) {
		TPD_INFO("%s: write FTS_REG_GESTURE_CONFIG4 enable(%x=%x) fail", __func__, FTS_REG_GESTURE_CONFIG4, config4);
	}
	ret = touch_i2c_write_byte(ts_data->client, FTS_REG_GESTURE_EN, enable);
	if (ret < 0) {
		TPD_INFO("%s: write FTS_REG_GESTURE_EN enable(%x=%x) fail", __func__, FTS_REG_GESTURE_EN, enable);
	}

	return ret;
}

static int fts_enable_edge_limit(struct chip_data_ft3419u *ts_data, int enable)
{
	u8 edge_mode = 0;

	/*0:Horizontal, 1:Vertical*/
	if (enable == VERTICAL_SCREEN) {
		edge_mode = 0;

	} else if (enable == LANDSCAPE_SCREEN_90) {
		edge_mode = 1;

	} else if (enable == LANDSCAPE_SCREEN_270) {
		edge_mode = 2;
	}

	TPD_INFO("MODE_EDGE, write 0x8C=%d", edge_mode);
	return touch_i2c_write_byte(ts_data->client, FTS_REG_EDGE_LIMIT, edge_mode);
}

static int fts_enable_charge_mode(struct chip_data_ft3419u *ts_data, bool enable)
{
	TPD_INFO("MODE_CHARGE, write 0x8B=%d", enable);
	return touch_i2c_write_byte(ts_data->client, FTS_REG_CHARGER_MODE_EN, enable);
}

static int fts_enable_game_mode(struct chip_data_ft3419u *ts_data, bool enable)
{
	struct touchpanel_data *ts = i2c_get_clientdata(ts_data->client);
	int ret = 0;

	if (ts == NULL) {
		return 0;
	}

	if (ts->aiunit_game_info_support) {
		ret = touch_i2c_write_byte(ts_data->client, FTS_CMD_GAME_AIUINIT_EN, enable);
		TPD_INFO("%s: game aiuinit C9 set\n", __func__);
		if (ret < 0) {
			TPD_INFO("%s: write game aiuinit enable(%x=%x) fail", __func__, FTS_CMD_GAME_AIUINIT_EN, enable);
		}
		msleep(1);
	}
	TPD_INFO("MODE_GAME, write 0x86=%d", enable);
	return touch_i2c_write_byte(ts_data->client, FTS_REG_GAME_MODE_EN, !enable);
}

static int fts_enable_headset_mode(struct chip_data_ft3419u *ts_data,
                                   bool enable)
{
	TPD_INFO("MODE_HEADSET, write 0xC3=%d \n", enable);
	return touch_i2c_write_byte(ts_data->client, FTS_REG_HEADSET_MODE_EN, enable);
}

static int fts_mode_switch(void *chip_data, work_mode mode, int flag)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	int ret = 0;

	switch (mode) {
	case MODE_NORMAL:
		TPD_INFO("MODE_NORMAL");
		break;

	case MODE_SLEEP:
		TPD_INFO("MODE_SLEEP, write 0xA5=3");
		ret = touch_i2c_write_byte(ts_data->client, FTS_REG_POWER_MODE, 0x03);

		if (ret < 0) {
			TPD_INFO("%s: enter into sleep failed.\n", __func__);
			goto mode_err;
		}

		break;

	case MODE_GESTURE:
		TPD_INFO("MODE_GESTURE, Melo, ts->is_suspended = %d \n",
		         ts_data->ts->is_suspended);

		if (ts_data->ts->is_suspended) {                             /* do not pull up reset when doing resume*/
			if (ts_data->last_mode == MODE_SLEEP) {
				fts_hw_reset(ts_data, RESET_TO_NORMAL_TIME);
			}
		}

		ret = fts_enable_black_gesture(ts_data, flag);

		if (ret < 0) {
			TPD_INFO("%s: enable gesture failed.\n", __func__);
			goto mode_err;
		}

		break;

	/*    case MODE_GLOVE:*/
	/*        break;*/

	case MODE_EDGE:
		ret = fts_enable_edge_limit(ts_data, flag);

		if (ret < 0) {
			TPD_INFO("%s: enable edg limit failed.\n", __func__);
			goto mode_err;
		}

		break;

	case MODE_FACE_DETECT:
		break;

	case MODE_CHARGE:
		ret = fts_enable_charge_mode(ts_data, flag);

		if (ret < 0) {
			TPD_INFO("%s: enable charge mode failed.\n", __func__);
			goto mode_err;
		}

		break;

	case MODE_GAME:
		ret = fts_enable_game_mode(ts_data, flag);

		if (ret < 0) {
			TPD_INFO("%s: enable game mode failed.\n", __func__);
			goto mode_err;
		}

		break;

	case MODE_HEADSET:
		ret = fts_enable_headset_mode(ts_data, flag);

		if (ret < 0) {
			TPD_INFO("%s: enable headset mode failed.\n", __func__);
			goto mode_err;
		}

		break;

	default:
		TPD_INFO("%s: Wrong mode.\n", __func__);
		goto mode_err;
	}

	ts_data->last_mode = mode;
	return 0;
mode_err:
	return ret;
}



/*
 * return success: 0; fail : negative
 */
static int fts_reset(void *chip_data)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;

	TPD_INFO("%s:call\n", __func__);
	fts_hw_reset(ts_data, RESET_TO_NORMAL_TIME);

	return 0;
}

static int  fts_reset_gpio_control(void *chip_data, bool enable)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	return fts_rstgpio_set(ts_data->hw_res, enable);
}

static int fts_get_vendor(void *chip_data, struct panel_info *panel_data)
{
	int len = 0;

	len = strlen(panel_data->fw_name);

	if ((len > 3) && (panel_data->fw_name[len - 3] == 'i') && \
	    (panel_data->fw_name[len - 2] == 'm')
	    && (panel_data->fw_name[len - 1] == 'g')) {
		TPD_INFO("tp_type = %d, panel_data->fw_name = %s\n", panel_data->tp_type,
		         panel_data->fw_name);
	}

	TPD_INFO("tp_type = %d, panel_data->fw_name = %s\n", panel_data->tp_type,
	         panel_data->fw_name);

	return 0;
}

static int fts_get_chip_info(void *chip_data)
{
	u8 cmd = 0x90;
	u8 id[2] = { 0 };
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;

	id[0] = touch_i2c_read_byte(ts_data->client, FTS_REG_CHIP_ID);
	id[1] = touch_i2c_read_byte(ts_data->client, FTS_REG_CHIP_ID2);
	TPD_INFO("read chip id:0x%02x%02x", id[0], id[1]);

	if ((id[0] == FTS_VAL_CHIP_ID) && (id[1] == FTS_VAL_CHIP_ID2)) {
		return 0;
	}

	TPD_INFO("fw is invalid, need read boot id");
	cmd = 0x55;
	touch_i2c_write_block(ts_data->client, cmd, 0, NULL);
	msleep(12);
	cmd = 0x90;
	touch_i2c_read_block(ts_data->client, cmd, 2, id);
	TPD_INFO("read boot id:0x%02x%02x", id[0], id[1]);

	if ((id[0] == FTS_VAL_BT_ID) && (id[1] == FTS_VAL_BT_ID2)) {
		return 0;
	}

	return 0;
}

static int fts_ftm_process(void *chip_data)
{
	int ret = 0;

	ret = fts_mode_switch(chip_data, MODE_SLEEP, true);

	if (ret < 0) {
		TPD_INFO("%s:switch mode to MODE_SLEEP fail", __func__);
		return ret;
	}

	ret = fts_power_control(chip_data, false);

	if (ret < 0) {
		TPD_INFO("%s:power on fail", __func__);
		return ret;
	}

	return 0;
}

static void fts_read_fod_info(struct chip_data_ft3419u *ts_data)
{
	int ret = 0;
	u8 cmd = FTS_REG_FOD_INFO;
	u8 val[FTS_REG_FOD_INFO_LEN] = { 0 };

	ret = touch_i2c_read_block(ts_data->client, cmd, FTS_REG_FOD_INFO_LEN, val);

	if (ret < 0) {
		TPD_INFO("%s:read FOD info fail", __func__);
		return;
	}

	TPD_DEBUG("%s:FOD info buffer:%x %x %x %x %x %x %x %x %x", __func__, val[0],
	          val[1], val[2], val[3], val[4], val[5], val[6], val[7], val[8]);
	ts_data->fod_info.fp_id = val[0];
	ts_data->fod_info.event_type = val[1];

	if (val[8] == 0) {
		ts_data->fod_info.fp_down = 1;

	} else if (val[8] == 1) {
		ts_data->fod_info.fp_down = 0;
	}

	ts_data->fod_info.fp_area_rate = val[2];
	ts_data->fod_info.fp_x = (val[4] << 8) + val[5];
	ts_data->fod_info.fp_y = (val[6] << 8) + val[7];
}

static u32 fts_u32_trigger_reason(void *chip_data, int gesture_enable,
                                  int is_suspended)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	int ret = 0;
	u8 cmd = FTS_REG_POINTS;
	u8 cmd_grip = FTS_REG_GRIP;
	u32 result_event = 0;
	u8 *buf = ts_data->rbuf;

	fts_prc_queue_work(ts_data);

	memset(buf, 0xFF, FTS_MAX_POINTS_GRIP_LENGTH);

	if (ts_data->ts->palm_to_sleep_enable && !is_suspended) {
		ret = touch_i2c_read_byte(ts_data->client, FTS_REG_PALM_TO_SLEEP_STATUS);
		if (ret < 0) {
			TPD_INFO("touch_i2c_read_byte PALM_TO_SLEEP_STATUS fail\n");
		} else {
			if(ret == 0x01) {
				SET_BIT(result_event, IRQ_PALM);
				TPD_INFO("fts_enable_palm_to_sleep enable\n");
				return result_event;
			}
		}
	}

	if (gesture_enable && is_suspended) {
		ret = touch_i2c_read_byte(ts_data->client, FTS_REG_GESTURE_EN);
		if (ret == 0x01) {
			return IRQ_GESTURE;
		}
	}

	ret = touch_i2c_read_block(ts_data->client, cmd, FTS_POINTS_ONE, &buf[0]);
	if (ret < 0) {
		TPD_INFO("read touch point one fail");
		return IRQ_IGNORE;
	}

	if (ts_data->ft3419u_grip_v2_support) {
		ret = touch_i2c_read_block(ts_data->client, cmd_grip, FTS_GRIP_ONE, &buf[FTS_MAX_POINTS_LENGTH]);
		if (ret < 0) {
			TPD_INFO("[prevent-ft] read grip_info one fail");
		}
	}

	if ((buf[0] == 0xFF) && (buf[1] == 0xFF) && (buf[2] == 0xFF)) {
		TPD_INFO("Need recovery TP state");
		return IRQ_FW_AUTO_RESET;
	}

	/*confirm need print debug info*/
	if (ts_data->rbuf[0] != ts_data->irq_type) {
		SET_BIT(result_event, IRQ_FW_HEALTH);
	}

	ts_data->irq_type = ts_data->rbuf[0];

	/*normal touch*/
	SET_BIT(result_event, IRQ_TOUCH);
	TPD_DEBUG("%s, fgerprint, is_suspended = %d, fp_en = %d, ", __func__,
	          is_suspended, ts_data->fp_en);
	TPD_DEBUG("%s, fgerprint, touched = %d, event_type = %d, fp_down = %d, fp_down_report = %d, ",
	          __func__, ts_data->ts->view_area_touched, ts_data->fod_info.event_type,
	          ts_data->fod_info.fp_down, ts_data->fod_info.fp_down_report);

	if (!is_suspended && ts_data->fp_en) {
		fts_read_fod_info(ts_data);

		if ((ts_data->fod_info.event_type == FTS_EVENT_FOD)
		    && (ts_data->fod_info.fp_down)) {
			if (!ts_data->fod_info.fp_down_report) {    /* 38, 1, 0*/
				ts_data->fod_info.fp_down_report = 1;
				SET_BIT(result_event, IRQ_FINGERPRINT);
				TPD_DEBUG("%s, fgerprint, set IRQ_FINGERPRINT when fger down but not reported! \n",
				          __func__);
			}

			/*            if (ts_data->fod_info.fp_down_report) {      38, 1, 1*/
			/*            }*/

		} else if ((ts_data->fod_info.event_type == FTS_EVENT_FOD)
		           && (!ts_data->fod_info.fp_down)) {
			if (ts_data->fod_info.fp_down_report) {     /* 38, 0, 1*/
				ts_data->fod_info.fp_down_report = 0;
				SET_BIT(result_event, IRQ_FINGERPRINT);
				TPD_DEBUG("%s, fgerprint, set IRQ_FINGERPRINT when fger up but still reported! \n",
				          __func__);
			}

			/*                if (!ts_data->fod_info.fp_down_report) {     38, 0, 0*/
			/*                }*/
		}
	}

	return result_event;
}

static int fts_get_touch_points(void *chip_data, struct point_info *points,
                                int max_num)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	int ret = 0;
	int retval = 0;
	int i = 0;
	int obj_attention = 0;
	int base = 0;
	int base_prevent = 0;
	int touch_point = 0;
	u8 point_num = 0;
	u8 pointid = 0;
	u8 event_flag = 0;
	u8 cmd = FTS_REG_POINTS_N;
	u8 cmd_grip = FTS_REG_GRIP_N;
	u8 *buf = ts_data->rbuf;

	if (buf[FTS_POINTS_ONE - 1] == 0xFF) {
		if (ts_data->ft3419u_grip_v2_support == FALSE)
			ret = touch_i2c_read_byte(ts_data->client, FTS_REG_POINTS_LB);
	} else {
		ret = touch_i2c_read_block(ts_data->client, cmd, FTS_POINTS_TWO,
		                           &buf[FTS_POINTS_ONE]);

		if (ts_data->ft3419u_grip_v2_support) {
			retval = touch_i2c_read_block(ts_data->client, cmd_grip, FTS_GRIP_TWO,
			               &buf[FTS_MAX_POINTS_LENGTH + FTS_GRIP_ONE]);
			if (retval < 0) {
				TPD_INFO("[prevent-ft] read grip_info two fail");
			}
		}
	}

	if (ret < 0) {
		TPD_INFO("read touch point two fail");
		return -EINVAL;
	}

	/*    fts_show_touch_buffer(buf, FTS_MAX_POINTS_LENGTH);*/

	point_num = buf[1] & 0xFF;

	if (point_num > max_num) {
		TPD_INFO("invalid point_num(%d),max_num(%d)", point_num, max_num);
		return -EINVAL;
	}

	for (i = 0; i < max_num; i++) {
		base = 6 * i;
		base_prevent = 4 * i;
		pointid = (buf[4 + base]) >> 4;

		if (pointid >= FTS_MAX_ID) {
			break;

		} else if (pointid >= max_num) {
			TPD_INFO("ID(%d) beyond max_num(%d)", pointid, max_num);
			return -EINVAL;
		}

		touch_point++;
		if (!ts_data->high_resolution_support && !ts_data->high_resolution_support_x8) {
			points[pointid].x = ((buf[2 + base] & 0x0F) << 8) + (buf[3 + base] & 0xFF);
			points[pointid].y = ((buf[4 + base] & 0x0F) << 8) + (buf[5 + base] & 0xFF);
			points[pointid].touch_major = buf[7 + base];
			points[pointid].width_major = buf[7 + base];
			points[pointid].z = buf[6 + base];
			event_flag = (buf[2 + base] >> 6);

			if (ts_data->ft3419u_grip_v2_support) {
				points[pointid].tx_press = buf[62 + base_prevent];
				points[pointid].rx_press = buf[63 + base_prevent];
				points[pointid].tx_er = buf[65 + base_prevent];
				points[pointid].rx_er = buf[64 + base_prevent];
				TPD_DEBUG("[prevent-ft] id:%2d x:%3d y:%3d | tx_press:%3d rx_press:%3d tx_er:%3d rx_er:%3d", pointid, points[pointid].x, points[pointid].y,
					points[pointid].tx_press, points[pointid].rx_press, points[pointid].tx_er, points[pointid].rx_er);
			}
		} else if (ts_data->high_resolution_support_x8) {
			points[pointid].x = ((buf[2 + base] & 0x20) >> 5) +
					((buf[2 + base] & 0x0F) << 11) +
					((buf[3 + base] & 0xFF) << 3) +
					((buf[6 + base] & 0xC0) >> 5);
			points[pointid].y = ((buf[2 + base] & 0x10) >> 4) +
					((buf[4 + base] & 0x0F) << 11) +
					((buf[5 + base] & 0xFF) << 3) +
					((buf[6 + base] & 0x30) >> 3);
			points[pointid].touch_major = buf[7 + base];
			points[pointid].width_major = buf[7 + base];
			points[pointid].z = buf[6 + base] & 0x0F;
			event_flag = (buf[2 + base] >> 6);

			if (ts_data->ft3419u_grip_v2_support) {
				points[pointid].tx_press = buf[62 + base_prevent];
				points[pointid].rx_press = buf[63 + base_prevent];
				points[pointid].tx_er = buf[65 + base_prevent];
				points[pointid].rx_er = buf[64 + base_prevent];
				TPD_DEBUG("[prevent-ft] id:%2d x:%3d y:%3d | tx_press:%3d rx_press:%3d tx_er:%3d rx_er:%3d", pointid, points[pointid].x, points[pointid].y,
					points[pointid].tx_press, points[pointid].rx_press, points[pointid].tx_er, points[pointid].rx_er);
			}
		}

		points[pointid].status = 0;

		if ((event_flag == 0) || (event_flag == 2)) {
			points[pointid].status = 1;
			obj_attention |= (1 << pointid);

			if (point_num == 0) {
				TPD_INFO("abnormal touch data from fw");
				return -EIO;
			}
		}
	}

	if (touch_point == 0) {
		TPD_INFO("no touch point information");
		return -EINVAL;
	}

	return obj_attention;
}

static void fts_health_report(void *chip_data, struct monitor_data *mon_data)
{
	int ret = 0;
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;

	ret = touch_i2c_read_byte(ts_data->client, 0x01);
	if(ret != 0xff) {
		if ((ret & 0x01) && (ts_data->water_mode == 0)) {
			ts_data->water_mode = 1;
			TPD_INFO("%s:water flag =%d", __func__, ts_data->water_mode);
		}
		if ((!(ret & 0x01)) && (ts_data->water_mode == 1)) {
			ts_data->water_mode = 0;
			TPD_INFO("%s:water flag =%d", __func__, ts_data->water_mode);
		}
	}
	TPD_INFO("Health register(0x01):0x%x", ret);
	ret = touch_i2c_read_byte(ts_data->client, FTS_REG_HEALTH_1);
	TPD_INFO("Health register(0xFD):0x%x", ret);
	ret = touch_i2c_read_byte(ts_data->client, FTS_REG_HEALTH_2);
	TPD_INFO("Health register(0xFE):0x%x", ret);
}

static int fts_get_gesture_info(void *chip_data, struct gesture_info *gesture)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	int ret = 0;
	u8 cmd = FTS_REG_GESTURE_OUTPUT_ADDRESS;
	u8 buf[FTS_GESTURE_DATA_LEN] = { 0 };
	u8 gesture_id = 0;
	u8 point_num = 0;

	ret = touch_i2c_read_block(ts_data->client, cmd, FTS_GESTURE_DATA_LEN - 2,
	                           &buf[2]);

	if (ret < 0) {
		TPD_INFO("read gesture data fail");
		return ret;
	}

	gesture_id = buf[2];
	point_num = buf[3];
	TPD_INFO("gesture_id=%d, point_num=%d", gesture_id, point_num);

	switch (gesture_id) {
	case GESTURE_DOUBLE_TAP:
		gesture->gesture_type = DOU_TAP;
		break;

	case GESTURE_UP_VEE:
		gesture->gesture_type = UP_VEE;
		break;

	case GESTURE_DOWN_VEE:
		gesture->gesture_type = DOWN_VEE;
		break;

	case GESTURE_LEFT_VEE:
		gesture->gesture_type = LEFT_VEE;
		break;

	case GESTURE_RIGHT_VEE:
		gesture->gesture_type = RIGHT_VEE;
		break;

	case GESTURE_O_CLOCKWISE:
		gesture->clockwise = 1;
		gesture->gesture_type = CIRCLE_GESTURE;
		break;

	case GESTURE_O_ANTICLOCK:
		gesture->clockwise = 0;
		gesture->gesture_type = CIRCLE_GESTURE;
		break;

	case GESTURE_DOUBLE_SWIP:
		gesture->gesture_type = DOU_SWIP;
		break;

	case GESTURE_LEFT2RIGHT_SWIP:
		gesture->gesture_type = LEFT2RIGHT_SWIP;
		break;

	case GESTURE_RIGHT2LEFT_SWIP:
		gesture->gesture_type = RIGHT2LEFT_SWIP;
		break;

	case GESTURE_UP2DOWN_SWIP:
		gesture->gesture_type = UP2DOWN_SWIP;
		break;

	case GESTURE_DOWN2UP_SWIP:
		gesture->gesture_type = DOWN2UP_SWIP;
		break;

	case GESTURE_M:
		gesture->gesture_type = M_GESTRUE;
		break;

	case GESTURE_W:
		gesture->gesture_type = W_GESTURE;
		break;

	case GESTURE_FINGER_PRINT:
		fts_read_fod_info(ts_data);
		TPD_INFO("FOD event type:0x%x", ts_data->fod_info.event_type);
		TPD_DEBUG("%s, fgerprint, touched = %d, fp_down = %d, fp_down_report = %d, \n",
		          __func__, ts_data->ts->view_area_touched, ts_data->fod_info.fp_down,
		          ts_data->fod_info.fp_down_report);

		if (ts_data->fod_info.event_type == FTS_EVENT_FOD) {
			if (ts_data->fod_info.fp_down && !ts_data->fod_info.fp_down_report) {
				gesture->gesture_type = FINGER_PRINTDOWN;
				ts_data->fod_info.fp_down_report = 1;

			} else if (!ts_data->fod_info.fp_down && ts_data->fod_info.fp_down_report) {
				gesture->gesture_type = FRINGER_PRINTUP;
				ts_data->fod_info.fp_down_report = 0;
			}

			gesture->Point_start.x = ts_data->fod_info.fp_x;
			gesture->Point_start.y = ts_data->fod_info.fp_y;
			gesture->Point_end.x = ts_data->fod_info.fp_area_rate;
			gesture->Point_end.y = 0;
		}

		break;

	case GESTURE_SINGLE_TAP:
		gesture->gesture_type = SINGLE_TAP;
		break;

	default:
		gesture->gesture_type = UNKOWN_GESTURE;
	}

	if ((gesture->gesture_type != FINGER_PRINTDOWN)
	    && (gesture->gesture_type != FRINGER_PRINTUP)
	    && (gesture->gesture_type != UNKOWN_GESTURE)) {
		gesture->Point_start.x = (u16)((buf[4] << 8) + buf[5]);
		gesture->Point_start.y = (u16)((buf[6] << 8) + buf[7]);
		gesture->Point_end.x = (u16)((buf[8] << 8) + buf[9]);
		gesture->Point_end.y = (u16)((buf[10] << 8) + buf[11]);
		gesture->Point_1st.x = (u16)((buf[12] << 8) + buf[13]);
		gesture->Point_1st.y = (u16)((buf[14] << 8) + buf[15]);
		gesture->Point_2nd.x = (u16)((buf[16] << 8) + buf[17]);
		gesture->Point_2nd.y = (u16)((buf[18] << 8) + buf[19]);
		gesture->Point_3rd.x = (u16)((buf[20] << 8) + buf[21]);
		gesture->Point_3rd.y = (u16)((buf[22] << 8) + buf[23]);
		gesture->Point_4th.x = (u16)((buf[24] << 8) + buf[25]);
		gesture->Point_4th.y = (u16)((buf[26] << 8) + buf[27]);
	}

	return 0;
}

static void fts_enable_fingerprint_underscreen(void *chip_data, uint32_t enable)
{
	int ret = 0;
	u8 val = 0xFF;
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;


	TPD_INFO("%s:enable=%d", __func__, enable);
	ret = touch_i2c_read_byte(ts_data->client, FTS_REG_FOD_EN);

	if (ret < 0) {
		TPD_INFO("%s: read FOD enable(%x) fail", __func__, FTS_REG_FOD_EN);
		return;
	}

	TPD_DEBUG("%s, fgerprint, touched = %d, event_type = %d, fp_down = %d. fp_down_report = %d \n",
	          __func__, ts_data->ts->view_area_touched, ts_data->fod_info.event_type,
	          ts_data->fod_info.fp_down, ts_data->fod_info.fp_down_report);
	val = ret;

	if (enable) {
		val |= 0x02;
		ts_data->fp_en = 1;

		if ((!ts_data->ts->view_area_touched)
		    && (ts_data->fod_info.event_type != FTS_EVENT_FOD)
		    && (!ts_data->fod_info.fp_down)
		    && (ts_data->fod_info.fp_down_report)) {   /* notouch, !38, 0, 1*/
			ts_data->fod_info.fp_down_report = 0;
			TPD_DEBUG("%s, fgerprint, fp_down_report status abnormal (notouch, 38!, 0, 1), needed to be reseted! \n",
			          __func__);
		}

	} else {
		val &= 0xFD;
		ts_data->fp_en = 0;
		ts_data->fod_info.fp_down = 0;
		ts_data->fod_info.event_type = 0;
		/*        ts_data->fod_info.fp_down_report = 0;*/
	}

	TPD_INFO("%s:write %x=%x.", __func__, FTS_REG_FOD_EN, val);
	ret = touch_i2c_write_byte(ts_data->client, FTS_REG_FOD_EN, val);

	if (ret < 0) {
		TPD_INFO("%s: write FOD enable(%x=%x) fail", __func__, FTS_REG_FOD_EN, val);
	}
}

static void fts_enable_gesture_mask(void *chip_data, uint32_t enable)
{
	int ret = 0;
	int config1 = 0xff;
	int config2 = 0xff;
	int config4 = 0xff;
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	int state = ts_data->gesture_state;

	if (enable) {
		SET_GESTURE_BIT(state, RIGHT2LEFT_SWIP, config1, 0)
		SET_GESTURE_BIT(state, LEFT2RIGHT_SWIP, config1, 1)
		SET_GESTURE_BIT(state, DOWN2UP_SWIP, config1, 2)
		SET_GESTURE_BIT(state, UP2DOWN_SWIP, config1, 3)
		SET_GESTURE_BIT(state, DOU_TAP, config1, 4)
		SET_GESTURE_BIT(state, DOU_SWIP, config1, 5)
		SET_GESTURE_BIT(state, SINGLE_TAP, config1, 7)
		SET_GESTURE_BIT(state, CIRCLE_GESTURE, config2, 0)
		SET_GESTURE_BIT(state, W_GESTURE, config2, 1)
		SET_GESTURE_BIT(state, M_GESTRUE, config2, 2)
		SET_GESTURE_BIT(state, RIGHT_VEE, config4, 1)
		SET_GESTURE_BIT(state, LEFT_VEE, config4, 2)
		SET_GESTURE_BIT(state, DOWN_VEE, config4, 3)
		SET_GESTURE_BIT(state, UP_VEE, config4, 4)
		SET_GESTURE_BIT(state, HEART, config4, 5)
	} else {
		config1 = 0;
		config2 = 0;
		config4 = 0;
	}

	TPD_INFO("%s: config1:%x, config2:%x config4:%x\n", __func__, config1, config2, config4);
	ret = touch_i2c_write_byte(ts_data->client, FTS_REG_GESTURE_CONFIG1, config1);
	if (ret < 0) {
		TPD_INFO("%s: write FTS_REG_GESTURE_CONFIG1 enable(%x=%x) fail", __func__, FTS_REG_GESTURE_CONFIG1, config1);
	}
	ret = touch_i2c_write_byte(ts_data->client, FTS_REG_GESTURE_CONFIG2, config2);
	if (ret < 0) {
		TPD_INFO("%s: write FTS_REG_GESTURE_CONFIG2 enable(%x=%x) fail", __func__, FTS_REG_GESTURE_CONFIG2, config2);
	}
	ret = touch_i2c_write_byte(ts_data->client, FTS_REG_GESTURE_CONFIG4, config4);
	if (ret < 0) {
		TPD_INFO("%s: write FTS_REG_GESTURE_CONFIG4 enable(%x=%x) fail", __func__, FTS_REG_GESTURE_CONFIG4, config4);
	}

	msleep(1);
	TPD_INFO("%s, enable[%d] register[FTS_REG_GESTURE_CONFIG1. FTS_REG_GESTURE_CONFIG2. FTS_REG_GESTURE_CONFIG4]", __func__, enable);
}

static void fts_screenon_fingerprint_info(void *chip_data,
        struct fp_underscreen_info *fp_tpinfo)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;

	memset(fp_tpinfo, 0, sizeof(struct fp_underscreen_info));
	TPD_INFO("FOD event type:0x%x", ts_data->fod_info.event_type);

	if (ts_data->fod_info.fp_down) {
		fp_tpinfo->touch_state = FINGERPRINT_DOWN_DETECT;

	} else {
		fp_tpinfo->touch_state = FINGERPRINT_UP_DETECT;
	}

	fp_tpinfo->area_rate = ts_data->fod_info.fp_area_rate;
	fp_tpinfo->x = ts_data->fod_info.fp_x;
	fp_tpinfo->y = ts_data->fod_info.fp_y;

	TPD_INFO("FOD Info:touch_state:%d,area_rate:%d,x:%d,y:%d[fp_down:%d]",
	         fp_tpinfo->touch_state, fp_tpinfo->area_rate, fp_tpinfo->x,
	         fp_tpinfo->y, ts_data->fod_info.fp_down);
}

static void fts_register_info_read(void *chip_data, uint16_t register_addr,
                                   uint8_t *result, uint8_t length)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	u8 addr = (u8)register_addr;

	touch_i2c_read_block(ts_data->client, addr, length, result);
}

static void fts_set_touch_direction(void *chip_data, uint8_t dir)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	ts_data->touch_direction = dir;
}

static uint8_t fts_get_touch_direction(void *chip_data)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	return ts_data->touch_direction;
}

static int fts_smooth_lv_set(void *chip_data, int level)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;

	TPD_INFO("set smooth lv to %d", level);

	return touch_i2c_write_byte(ts_data->client, FTS_REG_SMOOTH_LEVEL, level);
}

static int fts_sensitive_lv_set(void *chip_data, int level)
{
	int ret = 0;
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;

	TPD_INFO("set sensitive lv to %d", level);

	ret = touch_i2c_write_byte(ts_data->client, FTS_REG_STABLE_DISTANCE_AFTER_N, level);
	if (ret < 0) {
		TPD_INFO("write FTS_REG_STABLE_DISTANCE_AFTER_N fail");
		return ret;
	}

	ret = touch_i2c_write_byte(ts_data->client, FTS_REG_STABLE_DISTANCE, level);
	if (ret < 0) {
		TPD_INFO("write FTS_REG_STABLE_DISTANCE fail");
		return ret;
	}

	return 0;
}

static int fts_set_high_frame_rate(void *chip_data, int level, int time)
{
	int ret = 0;
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	struct touchpanel_data *ts = i2c_get_clientdata(ts_data->client);

	TPD_INFO("set high_frame_rate to %d, keep %ds", level, time);
	if (level != 0) {
		level = 4;
	}
	level = level | (!ts->noise_level);

	ret = touch_i2c_write_byte(ts_data->client, FTS_REG_GAME_MODE_EN, level);
	if (ret < 0) {
		return ret;
	}
	if (level) {
		ret = touch_i2c_write_byte(ts_data->client, FTS_REG_HIGH_FRAME_TIME, time);
	}
	return ret;
}

static void fts_set_gesture_state(void *chip_data, int state)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	TPD_INFO("%s:state:%d!\n", __func__, state);
	ts_data->gesture_state = state;
}

static void fts_aiunit_game_info(void *chip_data)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	u8 cmd[MAX_AIUNIT_SET_NUM * 10 + 1] = { 0 };
	int i = 0;
	int ret = 0;

	if (ts_data == NULL) {
		return;
	}

	if (ts_data->ts->is_suspended) {
		return;
	}

	if (ts_data->ts->aiunit_game_enable) {
		ret = touch_i2c_write_byte(ts_data->client, FTS_CMD_GAME_AIUINIT_EN, 1);
			if (ret < 0)
				TPD_INFO("%s, write 1 to reg 0xc9 failed \n", __func__);
			msleep(3);
				ret = touch_i2c_read_byte(ts_data->client, FTS_CMD_GAME_AIUINIT_EN);
			if (ret == 1) {
				TPD_INFO("%s: aiunit game info enter suc.\n", __func__);
			} else {
				TPD_INFO("%s: aiunit game info enter fail.\n", __func__);
			}
	} else {
		ret = touch_i2c_write_byte(ts_data->client, FTS_CMD_GAME_AIUINIT_EN, 0);
			if (ret < 0)
				TPD_INFO("%s, write 0 to reg 0xc9 failed \n", __func__);
			msleep(3);
				ret = touch_i2c_read_byte(ts_data->client, FTS_CMD_GAME_AIUINIT_EN);
			if (ret == 0) {
				TPD_INFO("%s: aiunit game info exit suc.\n", __func__);
			} else {
				TPD_INFO("%s: aiunit game info exit fail.\n", __func__);
		}
	}

	cmd[0] = FTS_CMD_GAME_AIUINIT;
	for (i = 0; i < MAX_AIUNIT_SET_NUM; i++) {
		cmd[10 * i + 1] = ts_data->ts->tp_ic_aiunit_game_info[i].gametype;
		cmd[10 * i + 2] = ts_data->ts->tp_ic_aiunit_game_info[i].aiunit_game_type;
		cmd[10 * i + 3] = ts_data->ts->tp_ic_aiunit_game_info[i].left & 0xff;
		cmd[10 * i + 4] = (ts_data->ts->tp_ic_aiunit_game_info[i].left >> 8) & 0xff;
		cmd[10 * i + 5] = ts_data->ts->tp_ic_aiunit_game_info[i].top & 0xff;
		cmd[10 * i + 6] = (ts_data->ts->tp_ic_aiunit_game_info[i].top >> 8) & 0xff;
		cmd[10 * i + 7] = ts_data->ts->tp_ic_aiunit_game_info[i].right & 0xff;
		cmd[10 * i + 8] = (ts_data->ts->tp_ic_aiunit_game_info[i].right >> 8) & 0xff;
		cmd[10 * i + 9] = ts_data->ts->tp_ic_aiunit_game_info[i].bottom & 0xff;
		cmd[10 * i + 10] = (ts_data->ts->tp_ic_aiunit_game_info[i].bottom >> 8) & 0xff;
		TPD_INFO("type:%x,%x left:%x,%x top:%x,%x right:%x,%x bottom:%x,%x.", \
				cmd[10 * i + 1], cmd[10 * i + 2], \
				cmd[10 * i + 3], cmd[10 * i + 4], \
				cmd[10 * i + 5], cmd[10 * i + 6], \
				cmd[10 * i + 7], cmd[10 * i + 8], \
				cmd[10 * i + 9], cmd[10 * i + 10]);
	}

	ret = touch_i2c_write(ts_data->client, cmd, 10 * MAX_AIUNIT_SET_NUM + 1);
	if (ret < 0) {
		TPD_INFO("fts tp aiunit game write fail");
	}
}

static void fts_rate_white_list_ctrl(void *chip_data, int value)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	u8 send_value = FTS_120HZ_REPORT_RATE;
	int ret = 0;

	TPD_INFO("fts_rate_white_list_ctrl to  value: %d", value);
	if (ts_data == NULL) {
		return;
	}

	if (ts_data->ts->is_suspended) {
		return;
	}

	switch(value) {
		/* TP RATE */
	case FTS_WRITE_RATE_120:
		send_value = FTS_120HZ_REPORT_RATE;
		break;
	case FTS_WRITE_RATE_180:
		send_value = FTS_180HZ_REPORT_RATE;
		break;
	case FTS_WRITE_RATE_240:
		send_value = FTS_240HZ_REPORT_RATE;
		break;
	case FTS_WRITE_RATE_360:
		send_value = FTS_360HZ_REPORT_RATE;
		break;
	case FTS_WRITE_RATE_720:
		send_value = FTS_720HZ_REPORT_RATE;
		break;
	default:
		TPD_INFO("%s: report rate = %d, not support\n", __func__, value);
		return;
	}

	ret = touch_i2c_write_byte(ts_data->client, FTS_REG_REPORT_RATE, send_value);

	if (ret < 0) {
		TPD_INFO("write FTS_REG_REPORT_RATE fail");
		return;
	}
}

static int fts_diaphragm_touch_lv_set(void *chip_data, int value)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	int ret = 0;
	int regvalue = 0;

	TPD_INFO("fts_diaphragm_touch_lv_set to %d", value);
	if (ts_data == NULL) {
		return 0;
	}

	switch(value) {
	case DIAPHRAGM_DEFAULT_MODE:
		regvalue = FTS_DIAPHRAGM_MODE_0;
		break;
	case DIAPHRAGM_FILM_MODE:
		regvalue = FTS_DIAPHRAGM_MODE_1;
		break;
	case DIAPHRAGM_WATERPROOF_MODE:
		regvalue = FTS_DIAPHRAGM_MODE_2;
		break;
	case DIAPHRAGM_FILM_WATERPROOF_MODE:
		regvalue = FTS_DIAPHRAGM_MODE_3;
		break;
	default:
		TPD_INFO("%s: report rate = %d, not support\n", __func__, value);
		return 0;
	}
	ret = touch_i2c_write_byte(ts_data->client, FTS_REG_DIAPHRAGM_TOUCH_MODE_EN, regvalue);
	if (ret < 0) {
		TPD_INFO("write FTS_REG_DIAPHRAGM_TOUCH_MODE_EN fail");
		return 0;
	}

	return 0;
}

static void fts_get_water_mode(void *chip_data)
{
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)chip_data;
	struct touchpanel_data *ts = i2c_get_clientdata(ts_data->client);
	TPD_INFO("%s: water flag %d!\n", __func__, ts_data->water_mode);
	if (ts_data->water_mode == 1) {
		ts->water_mode = 1;
	}
	else {
		ts->water_mode = 0;
	}
}

static void fts_force_water_mode(void *chip_data, bool enable)
{
	TPD_INFO("%s: %s force_water_mode is not supported .\n", __func__, enable ? "Enter" : "Exit");
}

static struct oplus_touchpanel_operations fts_ops = {
	.power_control              = fts_power_control,
	.get_vendor                 = fts_get_vendor,
	.get_chip_info              = fts_get_chip_info,
	.fw_check                   = fts_fw_check,
	.mode_switch                = fts_mode_switch,
	.reset                      = fts_reset,
	.reset_gpio_control         = fts_reset_gpio_control,
	.fw_update                  = fts_fw_update,
	.set_high_frame_rate        = fts_set_high_frame_rate,
	.trigger_reason             = fts_u32_trigger_reason,
	.get_touch_points           = fts_get_touch_points,
	.health_report              = fts_health_report,
	.get_gesture_info           = fts_get_gesture_info,
	.ftm_process                = fts_ftm_process,
	.enable_fingerprint         = fts_enable_fingerprint_underscreen,
	.enable_gesture_mask        = fts_enable_gesture_mask,
	.screenon_fingerprint_info  = fts_screenon_fingerprint_info,
	.register_info_read         = fts_register_info_read,
	.set_touch_direction        = fts_set_touch_direction,
	.get_touch_direction        = fts_get_touch_direction,
	.esd_handle                 = fts_esd_handle,
	.smooth_lv_set              = fts_smooth_lv_set,
	.sensitive_lv_set           = fts_sensitive_lv_set,
	.set_gesture_state          = fts_set_gesture_state,
	.aiunit_game_info           = fts_aiunit_game_info,
	.rate_white_list_ctrl       = fts_rate_white_list_ctrl,
	.diaphragm_touch_lv_set     = fts_diaphragm_touch_lv_set,
	.get_water_mode             = fts_get_water_mode,
	.force_water_mode           = fts_force_water_mode,
};

static struct focal_auto_test_operations ft3419u_test_ops = {
	.auto_test_preoperation = ft3419u_auto_preoperation,
	.test1 = ft3419u_noise_autotest,
	.test2 = ft3419u_rawdata_autotest,
	.test3 = ft3419u_uniformity_autotest,
	.test4 = ft3419u_scap_cb_autotest,
	.test5 = ft3419u_scap_rawdata_autotest,
	.test6 = ft3419u_short_test,
	.test7 = ft3419u_panel_differ_test,
	.auto_test_endoperation = ft3419u_auto_endoperation,
};

static struct engineer_test_operations ft3419u_engineer_test_ops = {
	.auto_test              = focal_auto_test,
};

static struct debug_info_proc_operations fts_debug_info_proc_ops = {
	.delta_read        = fts_delta_read,
	/*key_trigger_delta_read = fts_key_trigger_delta_read,*/
	.baseline_read = fts_baseline_read,
	.main_register_read = fts_main_register_read,
	/*.self_delta_read   = fts_self_delta_read,*/
};

struct focal_debug_func focal_debug_ops = {
	.esd_check_enable       = focal_esd_check_enable,
	.get_esd_check_flag     = focal_get_esd_check_flag,
	.get_fw_version         = focal_get_fw_version,
	.dump_reg_sate          = focal_dump_reg_state,
};

static int ft3419u_parse_dts(struct chip_data_ft3419u *ts_data, struct i2c_client *client)
{
	struct device *dev;
	struct device_node *np;

	dev = &client->dev;
	np = dev->of_node;

	ts_data->high_resolution_support = of_property_read_bool(np, "high_resolution_support");
	ts_data->high_resolution_support_x8 = of_property_read_bool(np, "high_resolution_support_x8");
	TPD_INFO("%s:high_resolution_support is:%d %d\n", __func__, ts_data->high_resolution_support, ts_data->high_resolution_support_x8);

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int fts_tp_probe(struct i2c_client *client)
#else
static int fts_tp_probe(struct i2c_client *client,
                        const struct i2c_device_id *id)
#endif
{
	struct chip_data_ft3419u *ts_data = NULL;
	struct touchpanel_data *ts = NULL;
	u64 time_counter = 0;
	int ret = -1;

	TPD_INFO("%s  is called\n", __func__);

	reset_healthinfo_time_counter(&time_counter);

	/*step1:Alloc chip_info*/
	ts_data = kzalloc(sizeof(struct chip_data_ft3419u), GFP_KERNEL);

	if (ts_data == NULL) {
		TPD_INFO("ts_data kzalloc error\n");
		ret = -ENOMEM;
		return ret;
	}

	memset(ts_data, 0, sizeof(*ts_data));
	g_fts_data = ts_data;

	ts_data->ts_workqueue = create_singlethread_workqueue("fts_wq");
	if (!ts_data->ts_workqueue) {
		TPD_INFO("create fts workqueue fail");
	}

	fts_point_report_check_init(ts_data);

	/*step2:Alloc common ts*/
	ts = common_touch_data_alloc();

	if (ts == NULL) {
		TPD_INFO("ts kzalloc error\n");
		goto ts_malloc_failed;
	}

	memset(ts, 0, sizeof(*ts));

	/*step3:binding client && dev for easy operate*/
	ts_data->dev = ts->dev;
	ts_data->client = client;
	ts_data->hw_res = &ts->hw_res;
	ts_data->irq_num = ts->irq;
	ts_data->ts = ts;
	ts_data->monitor_data = &ts->monitor_data;
	ts->debug_info_ops = &fts_debug_info_proc_ops;
	ts->client = client;
	ts->irq = client->irq;
	i2c_set_clientdata(client, ts);
	ts->dev = &client->dev;
	ts->chip_data = ts_data;

	/*step4:file_operations callback binding*/
	ts->ts_ops = &fts_ops;
	ts->engineer_ops = &ft3419u_engineer_test_ops;
	ts->com_test_data.chip_test_ops = &ft3419u_test_ops;

	ts->private_data = &focal_debug_ops;
	ft3419u_parse_dts(ts_data, client);

	/*step5:register common touch*/
	ret = register_common_touch_device(ts);

	if (ret < 0) {
		goto err_register_driver;
	}

	ts_data->ft3419u_grip_v2_support = ts->kernel_grip_support;

	/*step6:create ftxxxx-debug related proc files*/
	fts_create_apk_debug_channel(ts_data);

	/*step7:Chip Related function*/
	focal_create_sysfs(client);

	if (ts->health_monitor_support) {
		tp_healthinfo_report(&ts->monitor_data, HEALTH_PROBE, &time_counter);
	}
	ts_data->probe_done = 1;
	TPD_INFO("%s, probe normal end\n", __func__);

	return 0;

err_register_driver:
	common_touch_data_free(ts);
	ts = NULL;

ts_malloc_failed:
	kfree(ts_data);
	ts_data = NULL;
/*	ret = -1;*/

	TPD_INFO("%s, probe error\n", __func__);

	return ret;
}

static void fts_tp_shutdown(struct i2c_client *client)
{
	struct touchpanel_data *ts = i2c_get_clientdata(client);

	TPD_INFO("%s is called\n", __func__);
	tp_shutdown(ts);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
static void fts_tp_remove(struct i2c_client *client)
#else
static int fts_tp_remove(struct i2c_client *client)
#endif
{
	struct touchpanel_data *ts = i2c_get_clientdata(client);
	struct chip_data_ft3419u *ts_data = (struct chip_data_ft3419u *)ts->chip_data;

	TPD_INFO("%s is called\n", __func__);
	fts_point_report_check_exit(ts_data);
	fts_release_apk_debug_channel(ts_data);
	kfree(ts_data);
	ts_data = NULL;

	kfree(ts);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
#else
	return 0;
#endif
}

static int fts_i2c_suspend(struct device *dev)
{
	struct touchpanel_data *ts = dev_get_drvdata(dev);

	TPD_INFO("%s: is called\n", __func__);
	tp_pm_suspend(ts);


	return 0;
}

static int fts_i2c_resume(struct device *dev)
{
	struct touchpanel_data *ts = dev_get_drvdata(dev);

	TPD_INFO("%s is called\n", __func__);
	tp_pm_resume(ts);


	return 0;
}

static const struct i2c_device_id tp_id[] = {
	{ TPD_DEVICE, 0 },
	{ }
};

static struct of_device_id tp_match_table[] = {
	{ .compatible = TPD_DEVICE, },
	{ },
};

static const struct dev_pm_ops tp_pm_ops = {
	.suspend = fts_i2c_suspend,
	.resume = fts_i2c_resume,
};

static struct i2c_driver tp_i2c_driver = {
	.probe          = fts_tp_probe,
	.remove         = fts_tp_remove,
	.id_table       = tp_id,
	.shutdown       = fts_tp_shutdown,
	.driver         = {
		.name   = TPD_DEVICE,
		.of_match_table =  tp_match_table,
		.pm = &tp_pm_ops,
	},
};

static int __init tp_driver_init_ft3419u(void)
{
	TPD_INFO("%s is called\n", __func__);

	if (!tp_judge_ic_match(TPD_DEVICE)) {
		return 0;
	}

	if (i2c_add_driver(&tp_i2c_driver) != 0) {
		TPD_INFO("unable to add i2c driver.\n");
		return 0;
	}

	return 0;
}

/* should never be called */
static void __exit tp_driver_exit_ft3419u(void)
{
	i2c_del_driver(&tp_i2c_driver);
	return;
}
#ifdef CONFIG_TOUCHPANEL_LATE_INIT
late_initcall(tp_driver_init_ft3419u);
#else
module_init(tp_driver_init_ft3419u);
#endif
module_exit(tp_driver_exit_ft3419u);

MODULE_DESCRIPTION("Touchscreen FT3419U Driver");
MODULE_LICENSE("GPL");
