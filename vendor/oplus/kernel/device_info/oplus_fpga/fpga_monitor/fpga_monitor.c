#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/i2c.h>
#include <linux/mutex.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/soc/qcom/smem.h>
#include <linux/clk.h>
#include <linux/pinctrl/consumer.h>

#include "fpga_monitor.h"
#if IS_ENABLED(CONFIG_OPLUS_FPGA_NOTIFY)
#include <soc/oplus/fpga_notify.h>
#endif
#include "fpga_common_api.h"
#include "fpga_exception.h"
#include "fpga_mid.h"
#include "fpga_proc.h"
#include <linux/time.h>
#define CREATE_TRACE_POINTS
#include "fpga_trace.h"
#define SMEM_OPLUS_FPGA_PROP  123

#define FAILD_MAX_RETRY_TIMES  2

struct fpga_mnt_pri *g_mnt_pri = NULL;
int g_bf_flag = 0;

static long get_timestamp_ms(void)
{
	struct timespec64 now;
	ktime_get_real_ts64(&now);
	return timespec64_to_ns(&now) / NSEC_PER_MSEC;
}

static void u8ArrayToHexString(const uint8_t *array, size_t array_len, char *hex_str, size_t hex_str_len) {
	int offset = 0;
	int i = 0;
	for (i = 0; i < array_len; ++i) {
		if (offset + 2 < hex_str_len) {
			offset += snprintf(hex_str + offset, hex_str_len - offset, "%02X", array[i]);
		} else {
			FPGA_ERR("Output buffer too small.\n");
			return;
		}
	}
	hex_str[offset] = '\0';
}

int fpga_power_init(struct fpga_mnt_pri *fpga)
{
	int ret = 0;

	if (!fpga) {
		FPGA_ERR("fpga is null\n");
		return -EINVAL;
	}

	/* 1.2v*/
	fpga->hw_data.vcc_core = regulator_get(fpga->dev, "vcc_core");

	if (IS_ERR_OR_NULL(fpga->hw_data.vcc_core)) {
		FPGA_ERR("Regulator get failed vcc_core, ret = %d\n", ret);
	} else {
		if (regulator_count_voltages(fpga->hw_data.vcc_core) > 0) {
			if (fpga->hw_data.vcc_core_volt) {
				ret = regulator_set_voltage(fpga->hw_data.vcc_core, fpga->hw_data.vcc_core_volt,
							    fpga->hw_data.vcc_core_volt);
			} else {
				ret = regulator_set_voltage(fpga->hw_data.vcc_core, 1120000, 1120000);
			}
			if (ret) {
				FPGA_ERR("Regulator vcc_core failed vcc_core rc = %d\n", ret);
				goto err;
			}
		} else {
			FPGA_ERR("regulator_count_voltages is not support\n");
		}
	}

	/* vdd 1.8v*/
	fpga->hw_data.vcc_io = regulator_get(fpga->dev, "vcc_io");

	if (IS_ERR_OR_NULL(fpga->hw_data.vcc_io)) {
		FPGA_ERR("Regulator get failed vcc_io, ret = %d\n", ret);
	} else {
		if (regulator_count_voltages(fpga->hw_data.vcc_io) > 0) {
			if (fpga->hw_data.vcc_core_volt) {
				ret = regulator_set_voltage(fpga->hw_data.vcc_io, fpga->hw_data.vcc_io_volt,
							    fpga->hw_data.vcc_io_volt);
			} else {
				ret = regulator_set_voltage(fpga->hw_data.vcc_io, 1800000, 1800000);
			}
			if (ret) {
				FPGA_ERR("Regulator vcc_io failed vcc_io rc = %d\n", ret);
				goto err;
			}
		} else {
			FPGA_ERR("regulator_count_voltages is not support\n");
		}
	}

	return 0;

err:
	return ret;
}

int fpga_power_uninit(struct fpga_mnt_pri *fpga)
{
	if (!fpga) {
		FPGA_ERR("fpga is null\n");
		return -EINVAL;
	}
	if (!IS_ERR_OR_NULL(fpga->hw_data.vcc_io)) {
		regulator_put(fpga->hw_data.vcc_io);
		FPGA_INFO("regulator_put vcc_io\n");
	}
	if (!IS_ERR_OR_NULL(fpga->hw_data.vcc_core)) {
		regulator_put(fpga->hw_data.vcc_core);
		FPGA_INFO("regulator_put vcc_core\n");
	}

	return 0;
}

int fpga_powercontrol_vccio(struct fpga_power_data *hw_data, bool on)
{
	int ret = 0;

	if (on) {
		if (!IS_ERR_OR_NULL(hw_data->vcc_io)) {
			FPGA_INFO("Enable the Regulator vcc_io.\n");
			ret = regulator_enable(hw_data->vcc_io);

			if (ret) {
				FPGA_ERR("Regulator vcc_io enable failed ret = %d\n", ret);
				return ret;
			}
		}

		if (hw_data->vcc_io_gpio > 0) {
			FPGA_INFO("Enable the vcc_io_gpio\n");
			ret = gpio_direction_output(hw_data->vcc_io_gpio, 1);

			if (ret) {
				FPGA_ERR("enable the vcc_io_gpio failed.\n");
				return ret;
			}
		}

	} else {
		if (!IS_ERR_OR_NULL(hw_data->vcc_io)) {
			FPGA_INFO("disable the vcc_io\n");
			ret = regulator_disable(hw_data->vcc_io);
			if (ret) {
				FPGA_ERR("Regulator vcc_io disable failed rc = %d\n", ret);
				return ret;
			}
		}

		if (hw_data->vcc_io_gpio > 0) {
			FPGA_INFO("disable the vcc_io_gpio\n");
			ret = gpio_direction_output(hw_data->vcc_io_gpio, 0);

			if (ret) {
				FPGA_ERR("disable the vcc_io_gpio failed.\n");
				return ret;
			}
		}
	}

	return 0;
}
EXPORT_SYMBOL(fpga_powercontrol_vccio);

int fpga_powercontrol_vcccore(struct fpga_power_data *hw_data, bool on)
{
	int ret = 0;

	if (on) {
		if (!IS_ERR_OR_NULL(hw_data->vcc_core)) {
			FPGA_INFO("Enable the Regulator vcc_core.\n");
			ret = regulator_enable(hw_data->vcc_core);

			if (ret) {
				FPGA_ERR("Regulator vcc_core enable failed ret = %d\n", ret);
				return ret;
			}
		}

		if (hw_data->vcc_core_gpio > 0) {
			FPGA_INFO("Enable the vcc_core_gpio\n");
			ret = gpio_direction_output(hw_data->vcc_core_gpio, 1);

			if (ret) {
				FPGA_ERR("enable the vcc_core_gpio failed.\n");
				return ret;
			}
		}

	} else {
		if (!IS_ERR_OR_NULL(hw_data->vcc_core)) {
			FPGA_INFO("disable the vcc_io\n");
			ret = regulator_disable(hw_data->vcc_core);
			if (ret) {
				FPGA_ERR("Regulator vcc_core disable failed rc = %d\n", ret);
				return ret;
			}
		}

		if (hw_data->vcc_core_gpio > 0) {
			FPGA_INFO("disable the vcc_core_gpio\n");
			ret = gpio_direction_output(hw_data->vcc_core_gpio, 0);

			if (ret) {
				FPGA_ERR("disable the vcc_core_gpio failed.\n");
				return ret;
			}
		}
	}

	return 0;
}
EXPORT_SYMBOL(fpga_powercontrol_vcccore);

static void fpga_sw_rst(struct fpga_mnt_pri *mnt_pri)
{
	int ret = 0;
	struct fpga_power_data *pdata = NULL;
	struct fpga_status_t *status = NULL;

	FPGA_INFO("enter\n");
	fpga_poll_wakeup(mnt_pri,EXCEP_SOFT_REST_ERR);
	if (!mnt_pri) {
		FPGA_ERR("mnt_pri is null\n");
		return;
	}
	pdata = &mnt_pri->hw_data;
	status = &mnt_pri->status;

	status->m_io_rx_err_cnt = 0;
	status->m_i2c_rx_err_cnt = 0;
	status->m_spi_rx_err_cnt = 0;
	status->s_io_rx_err_cnt = 0;
	status->s_i2c_rx_err_cnt = 0;
	status->s_spi_rx_err_cnt = 0;

	ret = gpio_direction_output(pdata->rst_gpio, 0);
	usleep_range(RST_CONTROL_TIME, RST_CONTROL_TIME);

	ret |= gpio_direction_output(pdata->rst_gpio, 1);

	mnt_pri->hw_control_rst = ret;
	return;
}

static void fpga_hw_rst(struct fpga_mnt_pri *mnt_pri)
{
	struct fpga_status_t *status = NULL;
	if (!mnt_pri) {
		FPGA_ERR("mnt_pri is null\n");
		return;
	}

	status = &mnt_pri->status;
	status->m_io_rx_err_cnt = 0;
	status->m_i2c_rx_err_cnt = 0;
	status->m_spi_rx_err_cnt = 0;
	status->s_io_rx_err_cnt = 0;
	status->s_i2c_rx_err_cnt = 0;
	status->s_spi_rx_err_cnt = 0;
	mnt_pri->power_ready = false;

	// rst: vcccore down, then delay 1ms, vccio down
	fpga_powercontrol_vcccore(&mnt_pri->hw_data, false);
	mdelay(1);   // mdelay is accurate, msleep is not aacurete(cpu schedule)
	fpga_powercontrol_vccio(&mnt_pri->hw_data, false);

	msleep(POWER_CONTROL_TIME);

	fpga_powercontrol_vccio(&mnt_pri->hw_data, true);
	mdelay(1);
	fpga_powercontrol_vcccore(&mnt_pri->hw_data, true);
	msleep(50); // hw_rst then follow sw_rst, new request must sleep 50ms

	mnt_pri->power_ready = true;
}

/*
0x0b/0x10/0x17/0x1c不为2
0x0d/0x12/0x19/0x1e不为1
0x0c/0x0e/0x11/0x13/0x18/0x1A/0x1D/0x1F不为0
0x0a/0x0f/0x16/0x1b为0x0A  修改阈值达到0x0A(大于等于)，固件就上报异常中断，我们检测达到后进行处理
0x24/0x25为0x0A则触发复位---用于静电测试的临时版本
*/
static int fpga_reg_compare(u8 *buf, int len)
{
	int ret = 0;

	if ((buf[0x0b] == 2) && (buf[0x10] == 2) && (buf[0x17] == 2) && (buf[0x1c] == 2)
		&& (buf[0x0d] == 1) && (buf[0x12] == 1) && (buf[0x19] == 1) && (buf[0x1e] == 1)
		&& (buf[0x0c] == 0) && (buf[0x0e] == 0) && (buf[0x11] == 0) && (buf[0x13] == 0)
		&& (buf[0x18] == 0) && (buf[0x1a] == 0) && (buf[0x1d] == 0) && (buf[0x1f] == 0)
		&& (buf[0x0a] < 0x0a) && (buf[0x0f] < 0x0a) && (buf[0x16] < 0x0a)
		&& (buf[0x1b] < 0x0a) && (buf[0x24] < 0x0a) && (buf[0x25] < 0x0a)) {
		ret = 0;
	} else {
		ret = 1;
	}

	return ret;
}

static void fpga_find_code_error_increase(struct fpga_mnt_pri *mnt_pri, u8 *buf)
{
	struct fpga_status_t *status;
	struct fpga_status_t *all_status;
	unsigned char err_status = EXCEP_FPGA_FIRSTCHECK_DATA;
	uint64_t wakeup_param = 0;
	char hex_str[FPGA_REG_MAX_ADD * 2 + 1] = {0};

	if (!mnt_pri || !buf) {
		FPGA_ERR("error:mnt_pri.\n");
		return;
	}

	status = &mnt_pri->status;
	all_status = &mnt_pri->all_status;

	if ((status->m_io_rx_err_cnt != buf[REG_MASTER_IO_RX_ERR]) ||
		(status->m_i2c_rx_err_cnt != buf[REG_MASTER_I2C_RX_ERR]) ||
		(status->m_spi_rx_err_cnt != buf[REG_MASTER_SPI_RX_ERR]) ||
		(status->s_io_rx_err_cnt != buf[REG_SLAVE_IO_RX_ERR]) ||
		(status->s_i2c_rx_err_cnt != buf[REG_SLAVE_I2C_RX_ERR]) ||
		(status->s_spi_rx_err_cnt != buf[REG_SLAVE_SPI_RX_ERR])) {
		FPGA_ERR("Fpga find error code.\n");

		u8ArrayToHexString(buf, FPGA_REG_MAX_ADD, hex_str, sizeof(hex_str));
		trace_fpga_stat(get_timestamp_ms(), 0, 0, hex_str, 0, 0, 0, 1, 0, 0, 0, 0);
		fpga_exception_report(EXCEP_FAULT_CODE_RECORD_ERR);

		err_status |= (status->m_io_rx_err_cnt != buf[REG_MASTER_IO_RX_ERR]) ? FPGA_M_IO_RX_POLL_BIT : 0;
		err_status |= (status->m_i2c_rx_err_cnt != buf[REG_MASTER_I2C_RX_ERR]) ? FPGA_M_I2C_RX_POLL_BIT : 0;
		err_status |= (status->m_spi_rx_err_cnt != buf[REG_MASTER_SPI_RX_ERR]) ? FPGA_M_SPI_RX_POLL_BIT : 0;
		err_status |= (status->s_io_rx_err_cnt != buf[REG_SLAVE_IO_RX_ERR]) ? FPGA_S_IO_RX_POLL_BIT : 0;
		err_status |= (status->s_i2c_rx_err_cnt != buf[REG_SLAVE_I2C_RX_ERR]) ? FPGA_S_I2C_RX_POLL_BIT : 0;
		err_status |= (status->s_spi_rx_err_cnt != buf[REG_SLAVE_SPI_RX_ERR]) ? FPGA_S_SPI_RX_POLL_BIT : 0;

		wakeup_param |= (uint64_t)EXCEP_FPGA_VERIFY_DATA << EXCEP_FPGA_VERIFY_DATA_BIT;
		wakeup_param |= (uint64_t)err_status << ERR_STATUS_BIT;
		wakeup_param |= (uint64_t)buf[REG_MASTER_IO_RX_ERR] << REG_MASTER_IO_RX_ERR_BIT;
		wakeup_param |= (uint64_t)buf[REG_MASTER_I2C_RX_ERR] << REG_MASTER_I2C_RX_ERR_BIT;
		wakeup_param |= (uint64_t)buf[REG_MASTER_SPI_RX_ERR] << REG_MASTER_SPI_RX_ERR_BIT;
		wakeup_param |= (uint64_t)buf[REG_SLAVE_IO_RX_ERR] << REG_SLAVE_IO_RX_ERR_BIT;
		wakeup_param |= (uint64_t)buf[REG_SLAVE_I2C_RX_ERR] << REG_SLAVE_I2C_RX_ERR_BIT;
		wakeup_param |= (uint64_t)buf[REG_SLAVE_SPI_RX_ERR];
		fpga_poll_wakeup(mnt_pri, wakeup_param);
		FPGA_ERR("fail:%*ph\n", FPGA_REG_MAX_ADD, buf);
	}

	status->m_io_rx_err_cnt = buf[REG_MASTER_IO_RX_ERR];
	status->m_i2c_rx_err_cnt = buf[REG_MASTER_I2C_RX_ERR];
	status->m_spi_rx_err_cnt = buf[REG_MASTER_SPI_RX_ERR];
	status->s_io_rx_err_cnt = buf[REG_SLAVE_IO_RX_ERR];
	status->s_i2c_rx_err_cnt = buf[REG_SLAVE_I2C_RX_ERR];
	status->s_spi_rx_err_cnt = buf[REG_SLAVE_SPI_RX_ERR];
	return;
}
static bool fpga_check_code_error_full(struct fpga_mnt_pri *mnt_pri, u8 *buf)
{
	struct fpga_status_t *status;
	struct fpga_status_t *all_status;
	status = &mnt_pri->status;
	all_status = &mnt_pri->all_status;

	if (!mnt_pri || !buf) {
		FPGA_ERR("error:mnt_pri.\n");
		return false;
	}
	if ((0x0a <= buf[REG_MASTER_IO_RX_ERR]) ||
		(0x0a <= buf[REG_MASTER_I2C_RX_ERR]) ||
		(0x0a <= buf[REG_MASTER_SPI_RX_ERR]) ||
		(0x0a <= buf[REG_SLAVE_IO_RX_ERR]) ||
		(0x0a <= buf[REG_SLAVE_I2C_RX_ERR]) ||
		(0x0a <= buf[REG_SLAVE_SPI_RX_ERR])) {
		FPGA_ERR("Fpga find error code --> full.\n");
		return true;
	}
	return false;
}

static bool fpga_check_i2c_and_comp_reg(struct fpga_mnt_pri *mnt_pri, u8 *buf)
{
	int retry_times = 0;
	int ret = 0;
	if (!mnt_pri) {
		FPGA_ERR("error:mnt_pri.\n");
		return false;
	}
	for (retry_times = 0; retry_times < FAILD_MAX_RETRY_TIMES; retry_times++) {
		if (retry_times == 0) {
			msleep(10);  // first time sleep 10ms
		} else {
			msleep(5);  // other sleep 5ms
		}
		memset(buf, 0, 40);
		ret = fpga_i2c_read(mnt_pri, FPGA_REG_ADDR, buf, FPGA_REG_MAX_ADD);
		if (ret >= 0) {
			if (fpga_reg_compare(buf, FPGA_REG_MAX_ADD) == 0) {
				fpga_find_code_error_increase(mnt_pri, buf);
				FPGA_ERR("i2c ok,compare reg ok, retry_times %d.\n",retry_times);
				return true;
			} else {
				FPGA_ERR("i2c ok,but compare reg fail,retry_times %d.\n",retry_times);
				FPGA_ERR("fail:%*ph\n", FPGA_REG_MAX_ADD, buf);
			}
		} else if (ret == FPGA_SUSPEND_I2C_ERR_CODE) {
			FPGA_INFO("current status is suspend, ignore this check, return true!\n");
			return true;
		} else {
			FPGA_ERR("i2c read fail, retry_times %d.\n",retry_times);
		}
	}

	FPGA_ERR("i2c read fail or reg check fail.\n");
	return false;
}

static bool fpga_check_and_recovery(struct fpga_mnt_pri *mnt_pri)
{
	u8 buf[FPGA_REG_MAX_ADD] = {0};
	char hex_str[FPGA_REG_MAX_ADD * 2 + 1] = {0};
	int ret;
	bool need_rest = false;
	bool recovery_result = true;
	int sw_retry_times = 0;
	int hw_retry_times = 0;
	if (!mnt_pri) {
		FPGA_ERR("fpga_check_and_recovery mnt_pri is NULL and return!\n");
		return false;
	}

	mutex_lock(&mnt_pri->mutex);    /* mutex_lock here will block here if another thread can not get mutex */
	mnt_pri->check_recovery_running = true;
	ret = fpga_i2c_read(mnt_pri, FPGA_REG_ADDR, buf, FPGA_REG_MAX_ADD);
	u8ArrayToHexString(buf, FPGA_REG_MAX_ADD, hex_str, sizeof(hex_str));
	if (ret == FPGA_SUSPEND_I2C_ERR_CODE) {
		FPGA_INFO("current fpga is suspend status, ignore this check!\n");
		mnt_pri->check_recovery_running = false;
		mutex_unlock(&mnt_pri->mutex);
		return true;
	}
	if (ret < 0) {
		FPGA_ERR("fpga_i2c_read fail need reset!\n");
		trace_fpga_stat(get_timestamp_ms(), 0, 0, hex_str, 1, 0, 0, 0, 0, 0, 0, 0);
		fpga_poll_wakeup(mnt_pri,EXCEP_I2C_READ_ERR);
		need_rest = true;
	}
	do {
		if (need_rest)
		{
			fpga_exception_report(EXCEP_SOFT_REST_ERR);

			for (sw_retry_times = 0; sw_retry_times < FAILD_MAX_RETRY_TIMES; sw_retry_times++) {
#if IS_ENABLED(CONFIG_OPLUS_FPGA_NOTIFY)
				fpga_call_notifier(FPGA_RST_START, NULL);
#endif
				trace_fpga_stat(get_timestamp_ms(), 0, 0, hex_str, 0, 1, 0, 0, 0, 0, 0, 0);
				msleep(20);  // send start notify then sleep 20ms, charger stop trans at most 20ms, then reset
				fpga_sw_rst(mnt_pri);
				ret = fpga_check_i2c_and_comp_reg(mnt_pri, buf);
				if (ret == false) {
					FPGA_ERR("SWRST: [%d]rst check reg failed,continue reset.\n", sw_retry_times);
				} else {
#if IS_ENABLED(CONFIG_OPLUS_FPGA_NOTIFY)
					fpga_call_notifier(FPGA_RST_END, NULL);
#endif
					FPGA_ERR("SWRST: [%d]rst check reg ok, break!\n",sw_retry_times);
					recovery_result = true;   // recovery ok
					break;
				}
			}
			FPGA_ERR("before hard reset g_bf_flag is %d.\n", g_bf_flag);
			if ((sw_retry_times == FAILD_MAX_RETRY_TIMES) && (g_bf_flag != 1)) { //hw reset
				fpga_exception_report(EXCEP_HARD_REST_ERR);
				for (hw_retry_times = 0; hw_retry_times < FAILD_MAX_RETRY_TIMES; hw_retry_times++) {
					FPGA_ERR("sw retry over max retry times and enter hw reset!\n");
#if IS_ENABLED(CONFIG_OPLUS_FPGA_NOTIFY)
					fpga_call_notifier(FPGA_RST_START, NULL);
#endif
					msleep(20);  // send start notify then sleep 20ms, charger stop trans at most 20ms, then reset
					fpga_hw_rst(mnt_pri);
					fpga_sw_rst(mnt_pri);
					trace_fpga_stat(get_timestamp_ms(), 0, 0, hex_str, 0, 0, 1, 0, 0, 0, 0, 0);
					fpga_poll_wakeup(mnt_pri,EXCEP_HARD_REST_ERR);

					ret = fpga_check_i2c_and_comp_reg(mnt_pri, buf);
					if (ret == false) {
						FPGA_ERR("HWRST: [%d]rst check reg failed,continue reset.\n", hw_retry_times);
					} else {
#if IS_ENABLED(CONFIG_OPLUS_FPGA_NOTIFY)
						fpga_call_notifier(FPGA_RST_END, NULL);
#endif
						FPGA_ERR("HWRST: [%d]rst check reg ok, break!\n",hw_retry_times);
						recovery_result = true;    // recovery ok
						break;
					}
				}
			}
			if (hw_retry_times == FAILD_MAX_RETRY_TIMES) {
				FPGA_ERR("!!! after hw rest,fpga offline.\n");
				trace_fpga_stat(get_timestamp_ms(), 0, 0, hex_str, 0, 0, 0, 0, 1, 0, 0, 0);
				fpga_exception_report(EXCEP_HARD_RESET_NOT_RECOVERY_ERR);
				fpga_poll_wakeup(mnt_pri, EXCEP_HARD_RESET_NOT_RECOVERY_ERR);
				recovery_result = false;
				break;
			}
		} else {
			FPGA_INFO("reg:%*ph\n", FPGA_REG_MAX_ADD, buf);
			fpga_find_code_error_increase(mnt_pri, buf);
			if (fpga_check_code_error_full(mnt_pri, buf)) {
				need_rest = true;
				FPGA_ERR("code_error_full ,need to reset\n");
				continue;
			}
			if (fpga_reg_compare(buf, FPGA_REG_MAX_ADD) != 0) {
				trace_fpga_stat(get_timestamp_ms(), 0, 0, hex_str, 0, 0, 0, 0, 1, 0, 0, 0);
				FPGA_ERR("fpga_reg_compare fail need to reset\n");
				need_rest = true;
				continue;
			}
		}
		need_rest = false;
	} while(need_rest);

	mnt_pri->check_recovery_running = false;
	mutex_unlock(&mnt_pri->mutex);

	return recovery_result;
}

static void fpga_heartbeat_work(struct work_struct *work)
{
	struct fpga_mnt_pri *mnt_pri = container_of(work, struct fpga_mnt_pri, hb_work.work);
	u8 buf[FPGA_REG_MAX_ADD] = {0};
	bool need_slowdown = false;
	static int fpga_heartbeat_time = 0;

	if (mnt_pri->check_recovery_running) {
		/* heartbeat work receive the stop signal, return */
		FPGA_INFO("check is running and this time cancled and goto next queued delayed work!\n");
		goto out;
	}

	fpga_heartbeat_time++;

	if (!mnt_pri || (!mnt_pri->bus_ready) || (!mnt_pri->power_ready)) {
		FPGA_INFO("bus not ready! exit\n");
		goto out;
	}
#if FPGA_POWER_DEBUG
	if (mnt_pri->power_debug_work_count <= FPGA_POWER_DEBUG_MAX_TIMES) {
		FPGA_INFO("%d.\n", mnt_pri->power_debug_work_count);
		goto out;
	}
#endif

	FPGA_INFO("fpga_heartbeat_work check and recovery.\n");
	if (!fpga_check_and_recovery(mnt_pri)) {
		// recovery(sw reset & hw reset) not ok, need to slowdown
		need_slowdown = true;
	}

out:
	if (fpga_heartbeat_time >= 600) {//5min
		FPGA_INFO("heartbeat time beyond 5min,reg:%*ph\n", FPGA_REG_MAX_ADD, buf);
		fpga_heartbeat_time = 0;
	}

	if ((mnt_pri->fpga_monitor_time > 0) && (mnt_pri->fpga_monitor_time < FPGA_MONITOR_WORK_MAX_TIME)) {
		queue_delayed_work(mnt_pri->hb_workqueue, &mnt_pri->hb_work, msecs_to_jiffies(mnt_pri->fpga_monitor_time));
		return;
	}

	if (need_slowdown) {
		queue_delayed_work(mnt_pri->hb_workqueue, &mnt_pri->hb_work, msecs_to_jiffies(FPGA_MONITOR_WORK_SLOWDOWN_TIME));
	} else {
		queue_delayed_work(mnt_pri->hb_workqueue, &mnt_pri->hb_work, msecs_to_jiffies(FPGA_MONITOR_WORK_TIME));
	}
	return;
}

int is_fpga_work_okay(void)
{
	int ret;
	bool result = false;
	FPGA_INFO("is_fpga_work_okay enter!\n");

	if (!g_mnt_pri) {
		FPGA_ERR("g_mnt_pri is NULL .\n");
		return -1;
	}
	if ((!g_mnt_pri->bus_ready) || (!g_mnt_pri->power_ready)) {
		FPGA_ERR("fpga is not ready to work.\n");
		return -1;
	}

	result = fpga_check_and_recovery(g_mnt_pri);
	if (result) {
		FPGA_INFO("is_fpga_work_okay fpga result ok!\n");
		ret = 0;
	} else {
		FPGA_ERR("is_fpga_work_okay fpga result fail!\n");
		ret = -1;
	}
	FPGA_INFO("is_fpga_work_okay end!\n");

	return ret;
}
EXPORT_SYMBOL(is_fpga_work_okay);

#if IS_ENABLED(CONFIG_OPLUS_FPGA_NOTIFY)
static int oplus_fpga_monitor_state_change(struct notifier_block *nb, unsigned long ev, void *v)
{
	struct fpga_power_data *pdata = NULL;

	FPGA_ERR(" call, event is %lu.\n", ev);

	if (!g_mnt_pri) {
		FPGA_ERR("g_mnt_pri is null\n ");
		return 0;
	}
	pdata = &g_mnt_pri->hw_data;

	if (ev == FPGA_GEN_HWRST) {
		FPGA_ERR("FPGA_GEN_HWRST...\n ");
		fpga_powercontrol_vcccore(pdata, false);
		mdelay(1);
		fpga_powercontrol_vccio(pdata, false);
	}
	if (ev == FPGA_GEN_SWRST) {
		FPGA_ERR("FPGA_GEN_SWRST...\n ");
		gpio_direction_output(pdata->rst_gpio, 0);
		pinctrl_select_state(pdata->pinctrl, pdata->fpga_rst_sleep);
	}
	if (ev == FPGA_GEN_ERRCODE) {
		FPGA_INFO("FPGA_GEN_ERRCODE...\n ");
		fpga_gen_errcode(g_mnt_pri);
	}
	return 0;
}

static struct notifier_block oplus_fpga_monitor_state_notifier_block = {
	.notifier_call = oplus_fpga_monitor_state_change,
};
#endif

static int fpga_dts_init(struct fpga_mnt_pri *mnt_pri)
{
	int rc;
	int ret;
	unsigned int temp;
	struct fpga_power_data *pdata = NULL;
	struct device_node *np = NULL;
	const char *clock_name;

	pdata = &mnt_pri->hw_data;

	if (!mnt_pri->dev) {
		FPGA_ERR("mnt_pri->dev is null\n");
		return -EINVAL;
	}

	np = mnt_pri->dev->of_node;
	if (!np) {
		FPGA_ERR("np is null\n");
		return -EINVAL;
	}

	pdata->clk_switch_gpio = of_get_named_gpio(np, "clk-switch-gpio", 0);
	rc = gpio_is_valid(pdata->clk_switch_gpio);
	if (!rc) {
		FPGA_ERR("gpio_is_valid fail clk_switch_gpio[%d]\n", pdata->clk_switch_gpio);
	} else {
		rc = gpio_request(pdata->clk_switch_gpio, "clk-switch-gpio");
		if (rc) {
			FPGA_ERR("unable to request clk_switch_gpio [%d]\n", pdata->clk_switch_gpio);
		} else {
			gpio_direction_output(pdata->clk_switch_gpio, 0);
			FPGA_INFO("clk_switch_gpio[%d]\n", pdata->clk_switch_gpio);
		}
	}

	pdata->sleep_en_gpio = of_get_named_gpio(np, "sleep-en-gpio", 0);
	rc = gpio_is_valid(pdata->sleep_en_gpio);
	if (!rc) {
		FPGA_ERR("gpio_is_valid fail sleep_en_gpio[%d]\n", pdata->sleep_en_gpio);
	} else {
		rc = gpio_request(pdata->sleep_en_gpio, "sleep-en-gpio");
		if (rc) {
			FPGA_ERR("unable to request sleep_en_gpio [%d]\n", pdata->sleep_en_gpio);
		} else {
			gpio_direction_output(pdata->sleep_en_gpio, 0);
			FPGA_INFO("sleep_en_gpio[%d]\n",pdata->sleep_en_gpio);
		}
	}

	pdata->rst_gpio = of_get_named_gpio(np, "rst-gpio", 0);
	rc = gpio_is_valid(pdata->rst_gpio);
	if (!rc) {
		FPGA_ERR("gpio_is_valid fail rst_gpio[%d]\n", pdata->rst_gpio);
	} else {
		rc = gpio_request(pdata->rst_gpio, "rst-gpio");
		if (rc) {
			FPGA_ERR("unable to request rst_gpio [%d]\n", pdata->rst_gpio);
		} else {
			FPGA_INFO("rst_gpio[%d]\n",pdata->rst_gpio);
			gpio_direction_output(pdata->rst_gpio, 1);
		}
	}

	pdata->fpga_err_gpio = of_get_named_gpio(np, "fpga_err_gpio", 0);
	rc = gpio_is_valid(pdata->fpga_err_gpio);
	if (!rc) {
		FPGA_ERR("gpio_is_valid fail fpga_err_gpio[%d]\n", pdata->fpga_err_gpio);
	} else {
		rc = gpio_request(pdata->fpga_err_gpio, "fpga_err_gpio");
		if (rc) {
			FPGA_ERR("unable to request fpga_err_gpio [%d]\n", pdata->fpga_err_gpio);
		} else {
			FPGA_INFO("fpga_err_gpio[%d]\n",pdata->fpga_err_gpio);
			gpio_direction_output(pdata->fpga_err_gpio, 1);
		}
	}

	pdata->fgpa_err_intr_gpio = of_get_named_gpio(np, "fgpa_err_intr_gpio", 0);
	rc = gpio_is_valid(pdata->fgpa_err_intr_gpio);
	if (!rc) {
		FPGA_ERR("gpio_is_valid fail fgpa_err_intr_gpio[%d]\n", pdata->fgpa_err_intr_gpio);
	} else {
		rc = gpio_request(pdata->fgpa_err_intr_gpio, "fgpa_err_intr_gpio");
		if (rc) {
			FPGA_ERR("unable to request fgpa_err_intr_gpio [%d]\n", pdata->fgpa_err_intr_gpio);
		} else {
			FPGA_INFO("fgpa_err_intr_gpio[%d]\n",pdata->fgpa_err_intr_gpio);
			gpio_direction_input(pdata->fgpa_err_intr_gpio);
		}
	}


	pdata->vcc_core_gpio = of_get_named_gpio(np, "vcc-core-gpio", 0);
	rc = gpio_is_valid(pdata->vcc_core_gpio);
	if (!rc) {
		FPGA_ERR("gpio_is_valid fail vcc_core_gpio[%d]\n", pdata->vcc_core_gpio);
	} else {
		rc = gpio_request(pdata->vcc_core_gpio, "vcc-core-gpio");
		if (rc) {
			FPGA_ERR("unable to request vcc_core_gpio [%d]\n", pdata->vcc_core_gpio);
		} else {
			FPGA_INFO("vcc_core_gpio[%d]\n",pdata->vcc_core_gpio);
		}
	}

	pdata->vcc_io_gpio = of_get_named_gpio(np, "vcc-io-gpio", 0);
	rc = gpio_is_valid(pdata->vcc_io_gpio);
	if (!rc) {
		FPGA_ERR("gpio_is_valid fail vcc_io_gpio[%d]\n", pdata->vcc_io_gpio);
	} else {
		rc = gpio_request(pdata->vcc_io_gpio, "vcc-io-gpio");
		if (rc) {
			FPGA_ERR("unable to request vcc_io_gpio [%d]\n", pdata->vcc_io_gpio);
		} else {
			FPGA_INFO("vcc_io_gpio[%d]\n",pdata->vcc_io_gpio);
		}
	}

	rc = of_property_read_u32(np, "vcc_core_volt", &pdata->vcc_core_volt);
	if (rc < 0) {
		pdata->vcc_core_volt = 0;
		FPGA_ERR("vcc_core_volt not defined\n");
	}

	rc = of_property_read_u32(np, "vcc_io_volt", &pdata->vcc_io_volt);
	if (rc < 0) {
		pdata->vcc_io_volt = 0;
		FPGA_ERR("vcc_io_volt not defined\n");
	}

	memset(mnt_pri->clk_name, 0, 16);
	rc = of_property_read_string(np, "clock-names", &clock_name);
	if (rc < 0) {
		FPGA_ERR("clock-names not defined, use default\n");
		strncpy(mnt_pri->clk_name, "bb_clk4", 16);
	} else {
		FPGA_INFO("got clk name : %s.\n", clock_name);
		strncpy(mnt_pri->clk_name, clock_name, 16);
	}

	rc = of_property_read_u32(np, "platform_support_project_dir", &temp);
	if (rc < 0) {
		FPGA_ERR("platform_support_project_dir not specified\n");
		temp = 24001;
	}
	memset(mnt_pri->fw_path, 0, 64);
	ret = snprintf(mnt_pri->fw_path, 64, "%d", temp);
	FPGA_INFO("platform_support_project_dir: %s.\n", mnt_pri->fw_path);

	pdata->pinctrl = devm_pinctrl_get(mnt_pri->dev);
	if (IS_ERR_OR_NULL(pdata->pinctrl)) {
		FPGA_ERR("get pinctrl fail\n");
		return -EINVAL;
	}

	pdata->fpga_ative = pinctrl_lookup_state(pdata->pinctrl, "fpga_ative");
	if (IS_ERR_OR_NULL(pdata->fpga_ative)) {
		FPGA_ERR("Failed to get the state fpga_ative pinctrl handle\n");
		return -EINVAL;
	}

	pdata->fpga_sleep = pinctrl_lookup_state(pdata->pinctrl, "fpga_sleep");
	if (IS_ERR_OR_NULL(pdata->fpga_sleep)) {
		FPGA_ERR("Failed to get the state fpga_sleep pinctrl handle\n");
		return -EINVAL;
	}

	pdata->fpga_clk_switch_ative = pinctrl_lookup_state(pdata->pinctrl, "fpga_clk_switch_ative");
	if (IS_ERR_OR_NULL(pdata->fpga_clk_switch_ative)) {
		FPGA_ERR("Failed to get the state fpga_clk_switch_ative pinctrl handle\n");
		return -EINVAL;
	}

	pdata->fpga_clk_switch_sleep = pinctrl_lookup_state(pdata->pinctrl, "fpga_clk_switch_sleep");
	if (IS_ERR_OR_NULL(pdata->fpga_clk_switch_sleep)) {
		FPGA_ERR("Failed to get the state fpga_clk_switch_sleep pinctrl handle\n");
		return -EINVAL;
	}

	pdata->fpga_rst_ative = pinctrl_lookup_state(pdata->pinctrl, "fpga_rst_ative");
	if (IS_ERR_OR_NULL(pdata->fpga_rst_ative)) {
		FPGA_ERR("Failed to get the state fpga_rst_ative pinctrl handle\n");
		return -EINVAL;
	}

	pdata->fpga_rst_sleep = pinctrl_lookup_state(pdata->pinctrl, "fpga_rst_sleep");
	if (IS_ERR_OR_NULL(pdata->fpga_rst_sleep)) {
		FPGA_ERR("Failed to get the state fpga_rst_sleep pinctrl handle\n");
		return -EINVAL;
	}

	pdata->fpga_err_low = pinctrl_lookup_state(pdata->pinctrl, "fpga_err_low");
	if (IS_ERR_OR_NULL(pdata->fpga_err_low)) {
		FPGA_ERR("Failed to get the state fpga_err_low pinctrl handle\n");
		return -EINVAL;
	}

	pdata->fpga_err_high = pinctrl_lookup_state(pdata->pinctrl, "fpga_err_high");
	if (IS_ERR_OR_NULL(pdata->fpga_err_high)) {
		FPGA_ERR("Failed to get the state fpga_err_high pinctrl handle\n");
		return -EINVAL;
	}

	pinctrl_select_state(pdata->pinctrl, pdata->fpga_ative);

	FPGA_INFO("end\n");
	return 0;
}

static int fpga_monitor_init(struct fpga_mnt_pri *mnt_pri)
{
	int ret;
	u8 buf[FPGA_REG_MAX_ADD] = {0};
	char hex_str[FPGA_REG_MAX_ADD * 2 + 1] = {0};
	struct fpga_status_t *status = &mnt_pri->status;
	struct fpga_status_t *all_status = &mnt_pri->all_status;

	status->m_io_rx_err_cnt = 0;
	status->m_i2c_rx_err_cnt = 0;
	status->m_spi_rx_err_cnt = 0;
	status->s_io_rx_err_cnt = 0;
	status->s_i2c_rx_err_cnt = 0;
	status->s_spi_rx_err_cnt = 0;
	all_status->m_io_rx_err_cnt = 0;
	all_status->m_i2c_rx_err_cnt = 0;
	all_status->m_spi_rx_err_cnt = 0;
	all_status->s_io_rx_err_cnt = 0;
	all_status->s_i2c_rx_err_cnt = 0;
	all_status->s_spi_rx_err_cnt = 0;

	mnt_pri->prj_id = get_project();
	FPGA_INFO("prj_id %d\n", mnt_pri->prj_id);

	ret = fpga_i2c_read(mnt_pri, FPGA_REG_ADDR, buf, 8);
	u8ArrayToHexString(buf, FPGA_REG_MAX_ADD, hex_str, sizeof(hex_str));
	if (ret < 0) {
		FPGA_ERR("fpga i2c read failed! ret %d\n", ret);
		trace_fpga_stat(get_timestamp_ms(), 0, 0, hex_str, 1, 0, 0, 0, 0, 0, 0, 0);
	} else {
		FPGA_INFO("fpga_monitor_init: reg:%*ph\n", 8, buf);
		mnt_pri->version_m = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
		mnt_pri->version_s = buf[4] << 24 | buf[5] << 16 | buf[6] << 8 | buf[7];
		trace_fpga_stat(get_timestamp_ms(), mnt_pri->version_m, mnt_pri->version_s, hex_str, 0, 0, 0, 0, 0, 0, 0, 0);
	}
	return 0;
}

uint8_t fpga_get_bf_from_cmdline(void)
{
	struct device_node *node;
	const char *bootparams = NULL;
	char *str;
	int ret;
	int bf = 0;

	node = of_find_node_by_path("/chosen");
	if (node) {
		ret = of_property_read_string(node, "bootargs", &bootparams);
		if (!bootparams || ret < 0) {
			return 0;
		}
		str = strstr(bootparams, "oplus_fpga_bf=");
		if (str) {
			str += strlen("oplus_fpga_bf=");
			FPGA_INFO("fpga_get_bf_from_cmdline get str is %s\n", str);
			ret = get_option(&str, &bf);
			if (ret == 1) {
				if (bf == 1) {
					FPGA_INFO("fpga_get_bf_from_cmdline get cmdline bf is 1\n");
					return 1;
				} else {
					FPGA_INFO("fpga_get_bf_from_cmdline get cmdline bf is 0\n");
					return 0;
				}
			}
		}
	}
	return 0;
}

#if FPGA_POWER_DEBUG
static void fpga_power_debug_work(struct work_struct *work)
{
	struct fpga_mnt_pri *mnt_pri = container_of(work, struct fpga_mnt_pri, power_debug_work.work);

	FPGA_INFO("enter\n");
	fpga_sw_rst(mnt_pri);
	FPGA_INFO("exit\n");

	mnt_pri->power_debug_work_count++;
	if (mnt_pri->power_debug_work_count <= FPGA_POWER_DEBUG_MAX_TIMES) {
		queue_delayed_work(mnt_pri->power_debug_wq, &mnt_pri->power_debug_work, msecs_to_jiffies(100));
	}
}
#endif

static void resume_check_work(struct work_struct *work)
{
	FPGA_ERR("resume_check_work enter!\n");
	struct fpga_mnt_pri *mnt_pri = container_of(work, struct fpga_mnt_pri, resume_work);
	msleep(200);
	if (!fpga_check_and_recovery(mnt_pri)) {
		FPGA_ERR("fpga resume check and recovery fail!\n");
	}
}

static irqreturn_t fpga_err_thread_fn(int irq, void *dev_id)
{
	FPGA_INFO("fpga_err_interrupt_handler enter!\n");
	bool ret = false;
	char hex_str[FPGA_REG_MAX_ADD * 2 + 1] = {0};
	trace_fpga_stat(get_timestamp_ms(), 0, 0, hex_str, 0, 0, 0, 0, 0, 1, 0, 0);
	struct fpga_mnt_pri *mnt_pri = (struct fpga_mnt_pri *)dev_id;
	ret = fpga_check_and_recovery(mnt_pri);
	if (!ret) {
		FPGA_ERR("fpga_check_and_recovery fail\n");
	}
	return IRQ_HANDLED;
}

#define FPGA_ERR_INTR_NAME "fpga_fw_err_intr"
#define FPGA_ERR_INTR_GPIO_NUM 196

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int fpga_monitor_probe(struct i2c_client *i2c)
#else
static int fpga_monitor_probe(struct i2c_client *i2c, const struct i2c_device_id *id)
#endif
{
	struct fpga_mnt_pri *mnt_pri;
	int ret;
	int fpga_fw_err_irq;

	FPGA_INFO("probe start\n");

	mnt_pri = devm_kzalloc(&i2c->dev, sizeof(struct fpga_mnt_pri), GFP_KERNEL);
	if (!mnt_pri) {
		FPGA_ERR("alloc memory failed!");
		return -ENOMEM;
	}

	mutex_init(&mnt_pri->mutex);

	mnt_pri->client = i2c;
	mnt_pri->dev = &i2c->dev;
	mnt_pri->hb_workqueue = create_singlethread_workqueue("fpga_monitor");
	INIT_DELAYED_WORK(&mnt_pri->hb_work, fpga_heartbeat_work);

	INIT_WORK(&mnt_pri->resume_work, resume_check_work);

	i2c_set_clientdata(i2c, mnt_pri);

	mnt_pri->payload = kzalloc(1024, GFP_KERNEL);
	if (!mnt_pri->payload) {
  		FPGA_ERR("alloc payload memory failed!");
		mnt_pri->payload = NULL;
	}

	mnt_pri->pr_entry = proc_mkdir(FPGA_PROC_NAME, NULL);
	if (mnt_pri->pr_entry == NULL) {
		FPGA_ERR("Couldn't create fpga proc entry\n");
		return -EINVAL;
	}

	ret = fpga_dts_init(mnt_pri);
	if (ret) {
		return -EINVAL;
	}

	ret = fpga_power_init(mnt_pri);
	if (ret) {
		FPGA_ERR("fpga_power_control error,ret%d\n", ret);
	}

	ret = fpga_powercontrol_vccio(&mnt_pri->hw_data, true);
	if (ret) {
		FPGA_ERR("fpga_powercontrol_vccio error,ret%d\n", ret);
	}
	mdelay(1);  // mdelay is accurate, msleep is not aacurete(cpu schedule)
	ret = fpga_powercontrol_vcccore(&mnt_pri->hw_data, true);
	if (ret) {
		FPGA_ERR("fpga_powercontrol_vcccore error,ret%d\n", ret);
	}

	ret = fpga_monitor_init(mnt_pri);
	if (ret) {
		return -EINVAL;
	}

	ret = fpga_proc_create(mnt_pri);
	if (ret) {
		return -EINVAL;
	}

	queue_delayed_work(mnt_pri->hb_workqueue, &mnt_pri->hb_work, msecs_to_jiffies(1000));

#if FPGA_POWER_DEBUG
	mnt_pri->power_debug_work_count = 0;
	mnt_pri->power_debug_wq = create_singlethread_workqueue("fpga_power_debug_wq");
	INIT_DELAYED_WORK(&mnt_pri->power_debug_work, fpga_power_debug_work);
	queue_delayed_work(mnt_pri->power_debug_wq, &mnt_pri->power_debug_work, msecs_to_jiffies(100));
#endif

	mnt_pri->fpga_ck = devm_clk_get(mnt_pri->dev, mnt_pri->clk_name);
	if (IS_ERR(mnt_pri->fpga_ck)) {
		FPGA_ERR("failed to get %s.\n", mnt_pri->clk_name);
	}
	mnt_pri->hw_control_rst = 0;
	mnt_pri->bus_ready = true;
	mnt_pri->power_ready = true;
	mnt_pri->check_recovery_running = false;
	mnt_pri->fpga_monitor_time = 0;    /* default value 0, indicate no rus config set */
	mnt_pri->heartbeat_switch = -1;    /* default value -1, indicate no rus config set */
	g_mnt_pri = mnt_pri;
#if IS_ENABLED(CONFIG_OPLUS_FPGA_NOTIFY)
	ret = fpga_register_notifier(&oplus_fpga_monitor_state_notifier_block);
	if (ret != 0) {
		FPGA_ERR("fpga_register_notifier failed!\n");
	}
#endif

	/* interrupt gpio196 method:IRQF_TRIGGER_HIGH, normal low-->abnormal high 30us */
	fpga_fw_err_irq = gpio_to_irq(mnt_pri->hw_data.fgpa_err_intr_gpio);
	if (fpga_fw_err_irq < 0) {
		FPGA_ERR("request fpga_fw_err_irq fail\n");
	}
	FPGA_ERR("fpga_fw_err_irq is %d\n", fpga_fw_err_irq);
	ret = devm_request_threaded_irq(&i2c->dev, fpga_fw_err_irq, NULL, fpga_err_thread_fn,
						IRQF_TRIGGER_RISING  | IRQF_ONESHOT, FPGA_ERR_INTR_NAME, mnt_pri);
	if (ret) {
		FPGA_ERR("request request_threaded_irq fail\n");
	}

	g_bf_flag = fpga_get_bf_from_cmdline();

	FPGA_INFO("fpga_monitor_probe sucess\n");
	return 0;
}

void fpga_monitor_remove(struct i2c_client *i2c)
{
	struct fpga_mnt_pri *mnt_pri = i2c_get_clientdata(i2c);

	FPGA_INFO("is called\n");
	if (!mnt_pri) {
		FPGA_ERR("mnt_pri is null\n");
		return;
	}

	cancel_delayed_work_sync(&mnt_pri->hb_work);
	flush_workqueue(mnt_pri->hb_workqueue);
	destroy_workqueue(mnt_pri->hb_workqueue);

#if FPGA_POWER_DEBUG
	cancel_delayed_work_sync(&mnt_pri->power_debug_work);
	flush_workqueue(mnt_pri->power_debug_wq);
	destroy_workqueue(mnt_pri->power_debug_wq);
#endif

	remove_proc_entry(FPGA_PROC_NAME, NULL);
	if (mnt_pri->payload) {
		kfree(mnt_pri->payload);
	}
	kfree(mnt_pri);
	FPGA_INFO("remove sucess\n");
}

static int fpga_monitor_suspend(struct device *dev)
{
	struct fpga_mnt_pri *mnt_pri = dev_get_drvdata(dev);

	FPGA_INFO("is called\n");

	if (!mnt_pri) {
		FPGA_ERR("mnt_pri is null\n");
		return 0;
	}
	cancel_delayed_work_sync(&mnt_pri->hb_work);
	mnt_pri->bus_ready = false;

	return 0;
}

static int fpga_monitor_resume(struct device *dev)
{
	struct fpga_mnt_pri *mnt_pri = dev_get_drvdata(dev);

	FPGA_INFO("is called\n");

	if (!mnt_pri) {
		FPGA_ERR("mnt_pri is null\n");
		return 0;
	}
	mnt_pri->bus_ready = true;
	schedule_work(&mnt_pri->resume_work);
	if (mnt_pri->heartbeat_switch != 0) {    // no rus set off, continue start work
		queue_delayed_work(mnt_pri->hb_workqueue, &mnt_pri->hb_work, msecs_to_jiffies(FPGA_MONITOR_WORK_TIME));
	}
	return 0;
}

static int fpga_monitor_suspend_late(struct device *dev)
{
	struct fpga_power_data *pdata = NULL;
	struct fpga_mnt_pri *mnt_pri = dev_get_drvdata(dev);

	if (!mnt_pri) {
		FPGA_ERR("mnt_pri is null\n");
		return 0;
	}
	pdata = &mnt_pri->hw_data;

	FPGA_INFO("enter\n");

	gpio_direction_output(pdata->sleep_en_gpio, 1);
	gpio_direction_output(pdata->clk_switch_gpio, 1);

	if (mnt_pri->fpga_ck) {
		FPGA_INFO("disable fpga clk.\n");
		clk_disable_unprepare(mnt_pri->fpga_ck);
	}

	return 0;
}

static int fpga_monitor_resume_early(struct device *dev)
{
	struct fpga_power_data *pdata = NULL;
	struct fpga_mnt_pri *mnt_pri = dev_get_drvdata(dev);

	if (!mnt_pri) {
		FPGA_ERR("mnt_pri is null\n");
		return 0;
	}
	pdata = &mnt_pri->hw_data;

	FPGA_INFO("enter\n");

	if (mnt_pri->fpga_ck) {
		FPGA_INFO("enable fpga clk.\n");
		clk_prepare_enable(mnt_pri->fpga_ck);
	}

	gpio_direction_output(pdata->clk_switch_gpio, 0);
	gpio_direction_output(pdata->sleep_en_gpio, 0);

	return 0;
}

static const struct dev_pm_ops fpga_monitor_pm_ops = {
	.suspend = fpga_monitor_suspend,
	.resume = fpga_monitor_resume,
	.suspend_late = fpga_monitor_suspend_late,
	.resume_early = fpga_monitor_resume_early,
};

static const struct of_device_id fpga_i2c_dt_match[] = {
	{
		.compatible = "oplus,fpga_monitor",
	},
	{}
};

static const struct i2c_device_id fpga_i2c_id[] = {
	{ FPGA_MNT_I2C_NAME, 0 },
	{ }
};

static struct i2c_driver fpga_i2c_driver = {
	.probe    = fpga_monitor_probe,
	.remove   = fpga_monitor_remove,
	.id_table = fpga_i2c_id,
	.driver   = {
		.name           = FPGA_MNT_I2C_NAME,
		.owner          = THIS_MODULE,
		.of_match_table = fpga_i2c_dt_match,
		.pm = &fpga_monitor_pm_ops,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};

static void fpga_monitor_load_work_handler(struct work_struct *work);
static DECLARE_WORK(fpga_monitor_load_work, fpga_monitor_load_work_handler);

static void fpga_monitor_load_work_handler(struct work_struct *work)
{
	int ret = 0;

	FPGA_INFO("is called\n");
	ret = i2c_add_driver(&fpga_i2c_driver);
	if (ret) {
		FPGA_ERR("Failed to register I2C driver %s, rc = %d", FPGA_MNT_I2C_NAME, ret);
	} else {
		FPGA_INFO("typec_switch: success to register I2C driver\n");
	}
}

static int fpga_monitor_dev_probe(struct platform_device *pdev)
{
	FPGA_INFO("is called\n");
	schedule_work(&fpga_monitor_load_work);
	return 0;
}


static int __exit fpga_monitor_dev_remove(struct platform_device *pdev)
{
	FPGA_INFO("is called\n");
	return -EBUSY;
}

void fpga_monitor_dev_shutdown(struct platform_device *pdev)
{

	FPGA_INFO("is called\n");
	if (!g_mnt_pri) {
		FPGA_ERR("g_mnt_pri is null\n");
		return;
	}
	cancel_delayed_work_sync(&g_mnt_pri->hb_work);
	flush_workqueue(g_mnt_pri->hb_workqueue);
	destroy_workqueue(g_mnt_pri->hb_workqueue);

	cancel_work_sync(&g_mnt_pri->resume_work);

#if FPGA_POWER_DEBUG
	cancel_delayed_work_sync(&g_mnt_pri->power_debug_work);
	flush_workqueue(g_mnt_pri->power_debug_wq);
	destroy_workqueue(g_mnt_pri->power_debug_wq);
#endif
	FPGA_INFO("power down.\n");
	fpga_powercontrol_vcccore(&g_mnt_pri->hw_data, false);
	mdelay(1);
	fpga_powercontrol_vccio(&g_mnt_pri->hw_data, false);
}

static const struct of_device_id fpga_monitor_dev_of_match[] = {
	{ .compatible = "fpga_monitor_dev", },
	{ },
};
MODULE_DEVICE_TABLE(of, fpga_monitor_dev_of_match);

static struct platform_driver fpga_monitor_dev_driver = {
	.probe = fpga_monitor_dev_probe,
	.remove = __exit_p(fpga_monitor_dev_remove),
	.shutdown = fpga_monitor_dev_shutdown,
	.driver = {
		.name = "fpga_monitor_dev",
		.owner = THIS_MODULE,
		.of_match_table = fpga_monitor_dev_of_match,
	},
};

static int __init fpga_monitor_dev_init(void)
{
	int ret;

	ret = platform_driver_register(&fpga_monitor_dev_driver);
	if (ret) {
		FPGA_ERR("Failed to register fpga_monitor_dev_driver, ret = %d", ret);
	}

	return ret;
}

static void __exit fpga_monitor_dev_exit(void)
{
	platform_driver_unregister(&fpga_monitor_dev_driver);
	FPGA_INFO("Do nothing.\n");
}
subsys_initcall(fpga_monitor_dev_init);
module_exit(fpga_monitor_dev_exit);

MODULE_DESCRIPTION("FPGA I2C driver");
MODULE_LICENSE("GPL v2");
