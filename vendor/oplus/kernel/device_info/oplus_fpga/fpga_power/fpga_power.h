#ifndef __FPGA_POWER_H
#define __FPGA_POWER_H

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/sizes.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/hrtimer.h>
#include <linux/platform_device.h>


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


struct fpga_power_data {
	int clk_switch_gpio;
	int sleep_en_gpio;
	struct pinctrl *pinctrl;
	struct pinctrl_state *fpga_ative;
	struct pinctrl_state *fpga_sleep;
	struct pinctrl_state *fpga_clk_switch_ative;
	struct pinctrl_state *fpga_clk_switch_sleep;
};



#endif /*__FPGA_MONITOR_H */
