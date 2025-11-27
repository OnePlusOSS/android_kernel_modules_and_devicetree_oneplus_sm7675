#ifndef __FPGA_MONITOR_H
#define __FPGA_MONITOR_H

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
#include <linux/version.h>
#include "../../../../fs/proc/internal.h"
#include <soc/oplus/system/oplus_project.h>

#include "fpga_exception.h"

#define FPGA_MNT_I2C_NAME "fpga_monitor"
#define FPGA_PROC_NAME "fpga"

#define FPGA_IO_TX                (1 << 7)
#define FPGA_IO_RX                (1 << 6)
#define FPGA_I2C_TX               (1 << 5)
#define FPGA_I2C_RX               (1 << 4)
#define FPGA_SPI_TX               (1 << 3)
#define FPGA_SPI_RX               (1 << 2)

#define FPGA_M_IO_RX_POLL_BIT     (1 << 5)
#define FPGA_M_I2C_RX_POLL_BIT    (1 << 4)
#define FPGA_M_SPI_RX_POLL_BIT    (1 << 3)
#define FPGA_S_IO_RX_POLL_BIT     (1 << 2)
#define FPGA_S_I2C_RX_POLL_BIT    (1 << 1)
#define FPGA_S_SPI_RX_POLL_BIT    (1 << 0)

#define EXCEP_FPGA_VERIFY_DATA_BIT (7 * 8)
#define ERR_STATUS_BIT             (6 * 8)
#define REG_MASTER_IO_RX_ERR_BIT   (5 * 8)
#define REG_MASTER_I2C_RX_ERR_BIT  (4 * 8)
#define REG_MASTER_SPI_RX_ERR_BIT  (3 * 8)
#define REG_SLAVE_IO_RX_ERR_BIT    (2 * 8)
#define REG_SLAVE_I2C_RX_ERR_BIT   (1 * 8)
#define REG_SLAVE_SPI_RX_ERR_BIT   (0 * 8)

#define FPGA_REG_ADDR             0x00
#define FPGA_REG_MAX_ADD            40
#define FPGA_BUF_OP_MAX_ADD         64

#define REG_MASTER_VER_YEAR       0x00
#define REG_MASTER_VER_MON        0x01
#define REG_MASTER_VER_DAY        0x02
#define REG_MASTER_VERSION        0x03

#define REG_SLAVE_VER_YEAR        0x04
#define REG_SLAVE_VER_MON         0x05
#define REG_SLAVE_VER_DAY         0x06
#define REG_SLAVE_VERSION         0x07

#define REG_IO_TX_ERR             0x08
#define REG_IO_RX_ERR             0x09

#define REG_I2C_TX_ERR            0x0a
#define REG_I2C_RX_ERR            0x0b

#define REG_PRIMARY_SPI_ERR       0x0c
#define REG_SUB_SPI_ERR           0x0d

#define REG_SLAVER_ERR            0x0e
#define REG_GPIO_STATUS_ERR       0x0f
#define REG_I2C_STATUS_ERR        0x10

#define REG_SLAVER_ERR_CODE       0xff

#define REG_MASTER_IO_RX_ERR      0x0a
#define REG_MASTER_I2C_RX_ERR     0x0f
#define REG_MASTER_SPI_RX_ERR     0x24
#define REG_SLAVE_IO_RX_ERR       0x16
#define REG_SLAVE_I2C_RX_ERR      0x1b
#define REG_SLAVE_SPI_RX_ERR      0x25

#define EXCEP_FPGA_VERIFY_DATA    0xAA
#define EXCEP_FPGA_FIRSTCHECK_DATA 0x80

#define RST_CONTROL_TIME          1
#define CLK_TO_SLEEP_CONTROL_TIME 35 /*us*/
#define RST_TO_NORMAL_TIME        5000

#define POWER_CONTROL_TIME        50
#define PAGESIZE                  512
#define FPGA_POWER_DEBUG          0
#define FPGA_POWER_DEBUG_MAX_TIMES 5

#define FPGA_MONITOR_WORK_TIME    3000      /*ms*/
#define FPGA_MONITOR_WORK_SLOWDOWN_TIME (24 * 60 * 60 * 1000 / 2)  /*ms*/

#define FPGA_MONITOR_WORK_MAX_TIME (24 * 60 * 60 * 1000)

#define FPGA_FIFO_ELEMENT_MAX     128
#define FPGA_FIFO_TIMEOUT_MAX     (100 * 1000 * 1000)

#define MAX_I2C_RETRY_TIME        2

#define FPGA_UEFI_UPDATE_OK       0
#define FPGA_UEFI_UPDATE_NG       1

#define FPGA_SUSPEND_I2C_ERR_CODE    (-9)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#define DECLARE_PROC_OPS(name, open_func, read_func, write_func, release_func) \
                    static const struct proc_ops name = { \
                        .proc_open  = open_func,      \
                        .proc_write = write_func,     \
                        .proc_read  = read_func,      \
                        .proc_release = release_func, \
                        .proc_lseek = default_llseek, \
                    }
#else
#define DECLARE_PROC_OPS(name, open_func, read_func, write_func, release_func) \
                    static const struct file_operations name = { \
                        .open  = open_func,      \
                        .write = write_func,     \
                        .read  = read_func,      \
                        .release = release_func, \
                        .owner = THIS_MODULE,    \
                    }
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
#define PDE_DATA pde_data
#endif

typedef enum {
	GEN_ERR_CODE = 0,
	RST_CONTROL = 1,
	POWER_CONTROL,
	VCC_CORE_CONTROL,
	VCC_IO_CONTROL,
	POWER_CONTROL_PROBE_START,
	POWER_CONTROL_PROBE_STOP,
	IDLE_TO_ACTIVE,
	ATCMD_POWER_ON,
	ATCMD_POWER_OFF,
} HW_CTRL_TYPE;

struct fpga_power_data {
	int clk_switch_gpio;
	int sleep_en_gpio;
	int rst_gpio;
	int fpga_err_gpio;
	int fgpa_err_intr_gpio;
	int vcc_core_gpio;/*1P2*/
	int vcc_io_gpio;/*1P8*/
	struct pinctrl *pinctrl;
	struct pinctrl_state *fpga_ative;
	struct pinctrl_state *fpga_sleep;
	struct pinctrl_state *fpga_clk_switch_ative;
	struct pinctrl_state *fpga_clk_switch_sleep;
	struct pinctrl_state *fpga_rst_ative;
	struct pinctrl_state *fpga_rst_sleep;
	struct pinctrl_state *fpga_err_low;
	struct pinctrl_state *fpga_err_high;
	/*power*/
	struct regulator *vcc_core;                    /*power 1.2v 1P2*/
	struct regulator *vcc_io;                      /*power 1.8 1p8*/
	uint32_t vcc_core_volt;
	uint32_t vcc_io_volt;
};

struct fpga_status_t {
	u64 m_io_rx_err_cnt;
	u64 m_io_tx_err_cnt;
	u64 m_i2c_rx_err_cnt;
	u64 m_i2c_tx_err_cnt;
	u64 m_spi_rx_err_cnt;
	u64 m_spi_tx_err_cnt;
	u64 s_io_rx_err_cnt;
	u64 s_io_tx_err_cnt;
	u64 s_i2c_rx_err_cnt;
	u64 s_i2c_tx_err_cnt;
	u64 s_spi_rx_err_cnt;
	u64 s_spi_tx_err_cnt;
	u64 slave_err_cnt;
	u64 gpio_status_err_cnt;
	u64 i2c_status_err_cnt;
};

struct fpga_mnt_pri {
	struct i2c_client *client;
	struct device *dev;
	struct workqueue_struct *hb_workqueue;
	struct delayed_work      hb_work;
	struct work_struct resume_work;
	struct fpga_status_t all_status;
	struct fpga_status_t status;
	struct proc_dir_entry *pr_entry;
	struct clk *fpga_ck;
	u32 prj_id;
	u32 version_m;
	u32 version_s;
	int update_flag;
	int hw_control_rst;
	u32 fpga_monitor_time;
	int heartbeat_switch;
	char name[64];
	char version[64];
	char fw_path[64];
	char clk_name[16];
	char *payload;
	struct fpga_power_data hw_data;
	struct mutex mutex;
	/*debug*/
#if FPGA_POWER_DEBUG
	struct workqueue_struct *power_debug_wq;
	struct delayed_work      power_debug_work;
	u32 power_debug_work_count;
#endif
	bool bus_ready;
	bool power_ready;
	bool health_monitor_support;
	bool check_recovery_running;
	struct fpga_exception_data exception_data;
};

int fpga_powercontrol_vccio(struct fpga_power_data *hw_data, bool on);
int fpga_powercontrol_vcccore(struct fpga_power_data *hw_data, bool on);
int fpga_power_uninit(struct fpga_mnt_pri *fpga);
int fpga_power_init(struct fpga_mnt_pri *fpga);
#endif
