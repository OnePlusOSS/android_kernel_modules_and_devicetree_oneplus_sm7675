#ifndef __GW_FPGA_H
#define __GW_FPGA_H

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/gpio.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/sizes.h>
#include <linux/fcntl.h>
#include <linux/delay.h>
#include <linux/miscdevice.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/mtd/map.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_gpio.h>
#include <linux/hrtimer.h>
#include <asm/io.h>
#include <asm/delay.h>
#include <linux/platform_device.h>
#include <linux/kthread.h>
#include <uapi/linux/sched/types.h>
#include <linux/syscalls.h>
#include <linux/sched/clock.h>
#include <uapi/linux/time.h>

#define MISC_NAME "dev_fpga"

#define FPGA_NAME "oplus_fpga"

#define FPGA_INFO(fmt, args...) \
        pr_info("[%s][%s][%d]:" fmt, \
            FPGA_NAME, __func__, __LINE__, ##args)

#define FPGA_WARN(fmt, args...)\
        pr_warn("[%s][%s][%d]:" fmt, \
            FPGA_NAME, __func__, __LINE__, ##args)

#define FPGA_ERR(fmt, args...) \
        pr_err("[%s][%s][%d]:" fmt, \
            FPGA_NAME, __func__, __LINE__, ##args)


#define ID_GW1N4 0x100381B
#define ID_GW1N2 0x0100181B
#define ID_GW1N_2_1P5 0x0120681B
#define FPGA_DEV_IDCODE ID_GW1N_2_1P5
#define ON_PROTRCT_TCK 1 // program one Xpage Interrupt protection,Ensure that the clock is continuous and not interrupted.

//#define LOWRATE 1  //To use goConfigIP, you need to open this macro definition.
#define ADJ_TCK_FREQ 1 // Calibrate the tck output frequency

struct device_node *jtag_io_device_node; // jtag 的设备树节点
int g_tck_io;                            // 保存获取得到的tck引脚编号 r
int g_tms_io;                            // 保存获取得到的tms引脚编号 g
int g_tdi_io;                            // 保存获取得到的tdi引脚编号 b
int g_tdo_io;

int g_mode_io;
int g_vccx_io;
int g_vcco_io;
int g_vcc_io;

void __iomem *tck_mem_base;
void __iomem *tms_mem_base;
void __iomem *tdi_mem_base;
void __iomem *tdo_mem_base;


#define PIN_TCK g_tck_io
#define PIN_TMS g_tms_io
#define PIN_TDI g_tdi_io
#define PIN_TDO g_tdo_io

u32 g_tck_delay_len = 200;

#ifdef ADJ_TCK_FREQ

#define DELAY_LEN g_tck_delay_len

#include <linux/jiffies.h>

#include <linux/time.h>
// delay_cyle 初始值和结束值
#define SET_DELAY_CYLE_S 0
#define SET_DELAY_CYLE_E 2000
#define TIME_HZ 1000000 //时间精度 是1us
//调整到频率值
#define TO_1_0MHZ 1000000
#define TO_2_0MHZ 2000000
#define TO_2_5MHZ 2500000
#define TO_4_0MHZ 4000000
//测量时间
#define SET_1MS 1000
#define SET_10MS 10000
#define SET_100MS 100000

#else

#define DELAY_LEN 0

#endif

/*
#define PIN_TCK 18
#define PIN_TMS 11
#define PIN_TDI 8
#define PIN_TDO 7

static struct gpio jtag_gpios[] = {
    {PIN_TCK, GPIOF_OUT_INIT_LOW,  "jtag_TCK" },
    {PIN_TMS, GPIOF_OUT_INIT_LOW,  "jtag_TMS" },
    {PIN_TDI, GPIOF_OUT_INIT_LOW,  "jtag_TDI" },
    {PIN_TDO, GPIOF_IN,            "jtag_TDO" }
};
*/

#ifdef ADJ_TCK_FREQ

#define DELAY_LEN g_tck_delay_len

#define CAL_TO_2_5MHZ 2500000

#define BUFSIZE (1024 * 1024)
#define PAGESIZE 256


#define WIRINGPI 0
// #define GPIODLIB
#define NO_VERIFY 0
#define VERIFY 1
#define PROG_BACKGROUND 1
#define PROG_GENERAL 0

//#define DELAY_LEN 0 // delay_us(DELAY_LEN);
#define USE_FREQ_XHZ TO_2_0MHZ

// JTAG Pins, channel 0
// #define TCK_1 gpio_set_value(PIN_TCK, 1)
//#define TCK_1 gpio_set_value(PIN_TCK, 1)
//#define TCK_0 gpio_set_value(PIN_TCK, 0)

/*#define TCK_1 writeb(0x02, tck_mem_base)
#define TCK_0 writeb(0x0, tck_mem_base)

#define TMS_1 writeb(0x02, tms_mem_base)
#define TMS_0 writeb(0x0, tms_mem_base)

#define TDI_1 writeb(0x02, tdi_mem_base)
#define TDI_0 writeb(0x0, tdi_mem_base)*/

#define TCK_1 *(volatile u32 __force *)tck_mem_base = 0x2
#define TCK_0 *(volatile u32 __force *)tck_mem_base = 0x0

//#define TCK_1 writel(0x2, tck_mem_base)
//#define TCK_0 writel(0x0, tck_mem_base)

#define TMS_1 *(volatile u32 __force *)tms_mem_base = 0x2
#define TMS_0 *(volatile u32 __force *)tms_mem_base = 0x0

#define TDI_1 *(volatile u32 __force *)tdi_mem_base = 0x2
#define TDI_0 *(volatile u32 __force *)tdi_mem_base = 0x0

#define GW_TDO *(const volatile u32 __force *)tdo_mem_base //readPort()

#define jtag_runtest jtag_run_test

#define GW_TCK(a) \
    if (a) {        \
        TCK_1;}    \
    else {         \
        TCK_0;}    \
/*#define GW_TCK(a) \
    if (a) {        \
        TCK_1;}    \
    else {         \
        TCK_0;}*/
#define GW_TMS(a) \
    if (a)        \
        TMS_1;    \
    else          \
        TMS_0
#define GW_TDI(a) \
    if (a)        \
        TDI_1;    \
    else          \
        TDI_0

u8 *dbg_buf = NULL;
u64 dbg_buf_len = 0;
inline void delay_xxx(u32 nsecs)
{
#if 0
	int cnt = 0;
	u64 target = __arch_counter_get_cntvct();
	target += 9; // 1000 ns
	while (__arch_counter_get_cntvct() < target) {
		cnt++;
	}
	dbg_buf[dbg_buf_len++] = cnt;
#else
	//ndelay(500);
	u64 target = sched_clock();
	int cnt = 0;
	target += 250;

	while (sched_clock() < target) {
		cnt++;
	}
	dbg_buf[dbg_buf_len++] = cnt;
#endif
}

//#define delay_xxx(x) osal_time_udelay(x)
#define delay_ms(x) msleep(x)

uint8_t first_configgpio = 0;
static char *fpga_buf = NULL;

//#define u8 uint8_t
//#define u16 uint16_t
//#define u32 uint32_t

//typedef unsigned char uint8_t;
//typedef unsigned short uint16_t;
//typedef unsigned int uint32_t;

typedef enum {
	TAP_RESET,
	TAP_IDLE,
	TAP_DRSELECT,
	TAP_DRCAPTURE,
	TAP_DRSHIFT,
	TAP_DREXIT1,
	TAP_DRPAUSE,
	TAP_DREXIT2,
	TAP_DRUPDATE,
	TAP_IRSELECT,
	TAP_IRCAPTURE,
	TAP_IRSHIFT,
	TAP_IREXIT1,
	TAP_IRPAUSE,
	TAP_IREXIT2,
	TAP_IRUPDATE,
	TAP_UNKNOWN
} tap_def;

typedef enum {
	ISC_NOOP = 0x02,
	ISC_ERASE = 0x05,
	ERASE_DONE = 0x09,
	READ_ID_CODE = 0x11,
	INIT_ADDRESS = 0x12,
	READ_USER_CODE = 0x13,
	ISC_ENABLE = 0x15,
	SPIFLASH_MODE = 0x16,
	FAST_PROGRAM = 0x17,
	READ_STATUS_CODE = 0x41,
	JTAG_EF_PROGRAM = 0x71,
	JTAG_EF_READ = 0x73,
	JTAG_EF_ERASE = 0x75,
	JTAG_EF_2ND_ENABLE = 0x78,
	JTAG_EF_2ND_DISABLE = 0x79,
	ISC_DISABLE = 0x3A,
	REPROGRAM = 0x3C,
	REINIT = 0X3F,
	Bypass = 0xFF

} GWFPGA_Inst_Def;

#define ENABLE 1
#define DISABLE 0

#define NO_VERIFY 0
#define VERIFY 1

#define GW_IOC_VERSION  'F'
#define GW_IOC_EN   (_IOW(GW_IOC_VERSION, 0, unsigned char))
#define GW_IOC_LOAD_PATH    (_IOW(GW_IOC_VERSION, 1, unsigned char))

#endif

struct fpga_dw_pri {
	struct kthread_worker       *kworker;
	struct kthread_work     pump_messages;
	struct hrtimer          tck_hrtimer;
	ktime_t                    tck_time;
	struct hrtimer          runtest_hrtimer;
	ktime_t                    runtest_time;
	wait_queue_head_t   waiter;
	bool wakeup_flag;
	u8 *data_buf;
	u32 data_len;
};
#endif /*__GW_PORT_H */
