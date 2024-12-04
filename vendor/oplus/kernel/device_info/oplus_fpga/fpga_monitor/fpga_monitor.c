#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/i2c.h>
#include <linux/mutex.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>
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
#include "fpga_healthinfo.h"

#define SMEM_OPLUS_FPGA_PROP  123

static int g_fpga_hw_reset_cnt = 0;

static int fpga_power_init(struct fpga_mnt_pri *fpga)
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
				ret = regulator_set_voltage(fpga->hw_data.vcc_core, 1200000, 1200000);
			}
			if (ret) {
				FPGA_ERR("Regulator vcc_core failed vcc_core rc = %d\n", ret);
				goto err;
			}
			/*
			ret = regulator_set_load(fpga->hw_data.vcc_core, 200000);
			if (ret < 0) {
			    FPGA_ERR("Failed to set vcc_core mode(rc:%d)\n", ret);
			    goto err;
			}*/
		} else {
			FPGA_ERR("regulator_count_voltages is not support\n");
		}
	}

	/* vdd 2.8v*/
	fpga->hw_data.vcc_io = regulator_get(fpga->dev, "vcc_io");

	if (IS_ERR_OR_NULL(fpga->hw_data.vcc_io)) {
		FPGA_ERR("Regulator get failed vcc_core, ret = %d\n", ret);
	} else {
		if (regulator_count_voltages(fpga->hw_data.vcc_io) > 0) {
			if (fpga->hw_data.vcc_core_volt) {
				ret = regulator_set_voltage(fpga->hw_data.vcc_io, fpga->hw_data.vcc_io_volt,
							    fpga->hw_data.vcc_io_volt);
			} else {
				ret = regulator_set_voltage(fpga->hw_data.vcc_io, 1800000, 1800000);
			}
			if (ret) {
				FPGA_ERR("Regulator vcc_core failed vcc_core rc = %d\n", ret);
				goto err;
			}
			/*
			ret = regulator_set_load(fpga->hw_data.vcc_core, 200000);
			if (ret < 0) {
			    FPGA_ERR("Failed to set vcc_core mode(rc:%d)\n", ret);
			    goto err;
			}*/
		} else {
			FPGA_ERR("regulator_count_voltages is not support\n");
		}
	}

	return 0;

err:
	return ret;
}

static int fpga_power_uninit(struct fpga_mnt_pri *fpga)
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
				FPGA_ERR("Regulator vcc_io enable failed rc = %d\n", ret);
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
				FPGA_ERR("Regulator vcc_core enable failed rc = %d\n", ret);
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

static void fpga_rst_control(struct fpga_mnt_pri *mnt_pri)
{
	int ret = 0;
	struct fpga_power_data *pdata = NULL;

	FPGA_INFO("enter\n");

	if (!mnt_pri) {
		FPGA_ERR("mnt_pri is null\n");
		return;
	}

	pdata = &mnt_pri->hw_data;

#if IS_ENABLED(CONFIG_OPLUS_FPGA_NOTIFY)
	fpga_call_notifier(FPGA_RST_START, NULL);
#endif

	ret = gpio_direction_output(pdata->rst_gpio, 0);
	ret |= pinctrl_select_state(pdata->pinctrl, pdata->fpga_rst_sleep);
	usleep_range(RST_CONTROL_TIME, RST_CONTROL_TIME);

	ret |= gpio_direction_output(pdata->rst_gpio, 1);
	ret |= pinctrl_select_state(pdata->pinctrl, pdata->fpga_rst_ative);
	usleep_range(RST_TO_NORMAL_TIME, RST_TO_NORMAL_TIME);

#if IS_ENABLED(CONFIG_OPLUS_FPGA_NOTIFY)
	fpga_call_notifier(FPGA_RST_END, NULL);
#endif
	mnt_pri->hw_control_rst = ret;
	return;
}

int fpga_i2c_read(struct fpga_mnt_pri *mnt_pri,
		  u8 reg, u8 *data, size_t len)
{
	struct i2c_client *client = mnt_pri->client;
	struct i2c_msg msg[2];
	u8 buf[1];
	int ret;
	unsigned char retry;

	buf[0] = reg;

	msg[0].addr = client->addr;
	msg[0].flags = 0;
	msg[0].len = 0x01;
	msg[0].buf = &buf[0];

	msg[1].addr = client->addr;;
	msg[1].flags = I2C_M_RD;
	msg[1].len = len;
	msg[1].buf = data;

	for (retry = 0; retry < MAX_I2C_RETRY_TIME; retry++) {
		if (i2c_transfer(client->adapter, msg, 2) == 2) {
			ret = len;
			break;
		}
		msleep(20);
	}

	if (retry == MAX_I2C_RETRY_TIME) {
		FPGA_ERR("%s: I2C read over retry limit\n", __func__);
		ret = -EIO;
		return ret;
	}

	return ret;
}

int fpga_i2c_write(struct fpga_mnt_pri *mnt_pri,
		   u8 reg, u8 *data, size_t len)
{
	struct i2c_client *client = mnt_pri->client;
	struct i2c_msg msg[1];
	int ret;
	unsigned char retry;

	u8 *buf = kzalloc(len + 1, GFP_KERNEL);
	if (buf == NULL) {
		FPGA_ERR("buf alloc failed! \n");
		return -ENOMEM;
	}

	buf[0] = reg;
	memcpy(buf + 1, data, len);

	msg[0].addr = client->addr;
	msg[0].flags = 0;
	msg[0].len = len + 1;
	msg[0].buf = buf;


	for (retry = 0; retry < MAX_I2C_RETRY_TIME; retry++) {
		if (i2c_transfer(client->adapter, msg, 1) == 1) {
			ret = len + 1;
			break;
		}
		msleep(20);
	}

	if (retry == MAX_I2C_RETRY_TIME) {
		FPGA_ERR("%s: I2C write over retry limit\n", __func__);
		ret = -EIO;
		return ret;
	}
	kfree(buf);
	return ret;
}
/*
0x0b/0x10/0x17/0x1c不为2
0x0d/0x12/0x19/0x1e不为1
0x0c/0x0e/0x11/0x13/0x18/0x1A/0x1D/0x1F不为0
0x0a/0x0f/0x16/0x1b为0xFF
0x24/0x25为0xFF则触发复位---用于静电测试的临时版本
*/

static int fpga_check_reg_buffer(struct fpga_mnt_pri *mnt_pri, u8 *buf, int len)
{
	int i = 0;
	int ret = 0;

	if ((buf[0x0b] == 2) && (buf[0x10] == 2) && (buf[0x17] == 2) && (buf[0x1c] == 2)
		&& (buf[0x0d] == 1) && (buf[0x12] == 1) && (buf[0x19] == 1) && (buf[0x1e] == 1)
		&& (buf[0x0c] == 0) && (buf[0x0e] == 0) && (buf[0x11] == 0) && (buf[0x13] == 0)
		&& (buf[0x18] == 0) && (buf[0x1a] == 0) && (buf[0x1d] == 0) && (buf[0x1f] == 0)
		&& (buf[0x0a] != 0xff) && (buf[0x0f] != 0xff) && (buf[0x16] != 0xff)
		&& (buf[0x1b] != 0xff) && (buf[0x24] != 0xff) && (buf[0x25] != 0xff)) {
		return 0;
	}
	/*sw reset*/
	for (i = 0; i < 3; i ++) {
		FPGA_INFO("%s: enter sw reset-->%d.\n", __func__, i);
		if (g_fpga_hw_reset_cnt < 3)
			fpga_rst_control(mnt_pri);
		msleep(500);
		memset(buf, 0, sizeof(buf));
		ret = fpga_i2c_read(mnt_pri, FPGA_REG_ADDR, buf, FPGA_REG_MAX_ADD);
		if (ret < 0) {
			FPGA_ERR("%s: after sw reset, fpga_i2c_read error.\n", __func__);
			continue;
		}
		FPGA_INFO("reg:%*ph\n", FPGA_REG_MAX_ADD, buf);
		if ((buf[0x0b] == 2) && (buf[0x10] == 2) && (buf[0x17] == 2) && (buf[0x1c] == 2)
			&& (buf[0x0d] == 1) && (buf[0x12] == 1) && (buf[0x19] == 1) && (buf[0x1e] == 1)
			&& (buf[0x0c] == 0) && (buf[0x0e] == 0) && (buf[0x11] == 0) && (buf[0x13] == 0)
			&& (buf[0x18] == 0) && (buf[0x1a] == 0) && (buf[0x1d] == 0) && (buf[0x1f] == 0)
			&& (buf[0x0a] != 0xff) && (buf[0x0f] != 0xff) && (buf[0x16] != 0xff)
			&& (buf[0x1b] != 0xff) && (buf[0x24] != 0xff) && (buf[0x25] != 0xff)) {
			return 0;
		}
	}
	/*hw reset*/
	for (i = 0; i < 3; i ++) {
		FPGA_INFO("%s: enter hw reset-->%d.\n", __func__, i);
		if (g_fpga_hw_reset_cnt < 3) {
			fpga_powercontrol_vccio(&mnt_pri->hw_data, false);
			fpga_powercontrol_vcccore(&mnt_pri->hw_data, false);
			msleep(POWER_CONTROL_TIME);
			fpga_powercontrol_vcccore(&mnt_pri->hw_data, true);
			fpga_powercontrol_vccio(&mnt_pri->hw_data, true);
			msleep(10);
			fpga_rst_control(mnt_pri);
		}
		msleep(500);

		memset(buf, 0, sizeof(buf));
		ret = fpga_i2c_read(mnt_pri, FPGA_REG_ADDR, buf, FPGA_REG_MAX_ADD);
		if (ret < 0) {
			FPGA_ERR("%s: after hw reset, fpga_i2c_read error.\n", __func__);
			continue;
		}
		FPGA_INFO("reg:%*ph\n", FPGA_REG_MAX_ADD, buf);
		if ((buf[0x0b] == 2) && (buf[0x10] == 2) && (buf[0x17] == 2) && (buf[0x1c] == 2)
			&& (buf[0x0d] == 1) && (buf[0x12] == 1) && (buf[0x19] == 1) && (buf[0x1e] == 1)
			&& (buf[0x0c] == 0) && (buf[0x0e] == 0) && (buf[0x11] == 0) && (buf[0x13] == 0)
			&& (buf[0x18] == 0) && (buf[0x1a] == 0) && (buf[0x1d] == 0) && (buf[0x1f] == 0)
			&& (buf[0x0a] != 0xff) && (buf[0x0f] != 0xff) && (buf[0x16] != 0xff)
			&& (buf[0x1b] != 0xff) && (buf[0x24] != 0xff) && (buf[0x25] != 0xff)) {
			return 0;
		}
	}
	return ret;
}

static void fpga_heartbeat_work(struct work_struct *work)
{
	struct fpga_mnt_pri *mnt_pri = container_of(work, struct fpga_mnt_pri, hb_work.work);
	u8 buf[FPGA_REG_MAX_ADD] = {0};
	int ret;
	int i = 0;
	int sw_retry_times = 0;
	int hw_retry_times = 0;
	char payload[1024] = {0x00};
	char *result = NULL;

	if ((!mnt_pri->bus_ready) || (!mnt_pri->power_ready)) {
		FPGA_INFO("%s, bus not ready! exit\n", __func__);
		goto out;
	}

	for (i = 0; i < 3; i++) {
		memset(buf, 0, sizeof(buf));
		ret = fpga_i2c_read(mnt_pri, FPGA_REG_ADDR, buf, FPGA_REG_MAX_ADD);
		if (ret > 0) {
			break;
		}
		if (g_fpga_hw_reset_cnt < 3)
			fpga_rst_control(mnt_pri);
		msleep(500);
	}
	sw_retry_times = i;
	if (sw_retry_times == 3) {
		FPGA_ERR("fpga i2c read failed: Need hw reset.\n");
		for (i = 0; i < 3; i++) {
			if (g_fpga_hw_reset_cnt < 3) {
				fpga_powercontrol_vccio(&mnt_pri->hw_data, false);
				fpga_powercontrol_vcccore(&mnt_pri->hw_data, false);
				msleep(POWER_CONTROL_TIME);
				fpga_powercontrol_vcccore(&mnt_pri->hw_data, true);
				fpga_powercontrol_vccio(&mnt_pri->hw_data, true);
				msleep(10);
				fpga_rst_control(mnt_pri);
			}
			msleep(500);
			memset(buf, 0, sizeof(buf));
			ret = fpga_i2c_read(mnt_pri, FPGA_REG_ADDR, buf, FPGA_REG_MAX_ADD);
			if (ret > 0) {
				break;
			}
		}
		hw_retry_times = i;
		if (hw_retry_times == 3) {
			g_fpga_hw_reset_cnt += 1;
			FPGA_ERR("fpga i2c read failed: hw reset also failed.\n");
			fpga_kevent_fb(payload, 1024, FPGA_FB_BUS_TRANS_TYPE,
					"NULL$$EventField@@fpgaStatusRead$$i2creadret@@%d", ret);
			goto out;
		}
	}

	FPGA_INFO("reg:%*ph\n", FPGA_REG_MAX_ADD, buf);
	ret = fpga_check_reg_buffer(mnt_pri, buf, FPGA_REG_MAX_ADD);
	if (ret == 0) {
		mnt_pri->version_m = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
		mnt_pri->version_s = buf[4] << 24 | buf[5] << 16 | buf[6] << 8 | buf[7];
		g_fpga_hw_reset_cnt = 0;
	} else {
		g_fpga_hw_reset_cnt += 1;
		result = (char *)kzalloc(1024, GFP_KERNEL);
		if (!result) {
			FPGA_INFO("%s: kzalloc error\n", __func__);
			fpga_kevent_fb(payload, 1024, FPGA_FB_REG_ERR_TYPE,
						"NULL$$EventField@@fpgaRegStatusRead$$kzalloc@@%d", ret);
		} else {
			ret = snprintf(result, 1023, "NULL$$EventField@@fpgaRegStatusRead$$reg@@%*ph", FPGA_REG_MAX_ADD, buf);
			fpga_kevent_fb(payload, 1024, FPGA_FB_REG_ERR_TYPE, result, ret);
			kfree(result);
		}
	}

out:
	queue_delayed_work(mnt_pri->hb_workqueue, &mnt_pri->hb_work, msecs_to_jiffies(FPGA_MONITOR_WORK_TIME));
	return;
}

static int fpga_info_func(struct seq_file *s, void *v)
{
	struct fpga_mnt_pri *info = (struct fpga_mnt_pri *) s->private;


	seq_printf(s, "Device m version:\t\t0x%08x\n", info->version_m);
	seq_printf(s, "Device s version:\t\t0x%08x\n", info->version_s);

	seq_printf(s, "Device manufacture:\t\t%s\n", info->manufacture);

	seq_printf(s, "Device fw_path:\t\t%s\n", info->fw_path);

	return 0;
}

static int fpga_info_open(struct inode *inode, struct file *file)
{
	return single_open(file, fpga_info_func, PDE_DATA(inode));
}

DECLARE_PROC_OPS(fpga_info_node_fops, fpga_info_open, seq_read, NULL, single_release);

static ssize_t proc_fpga_status_read(struct file *file,
				     char __user *user_buf, size_t count, loff_t *ppos)
{
	int ret = 0;
	struct fpga_mnt_pri *mnt_pri = PDE_DATA(file_inode(file));
	char page[PAGESIZE] = {0};
	int status = 0;
	u8 buf[FPGA_REG_MAX_ADD] = {0};

	if (!mnt_pri) {
		FPGA_ERR("%s error:file_inode.\n", __func__);
		return ret;
	}

	memset(buf, 0, sizeof(buf));
	ret = fpga_i2c_read(mnt_pri, FPGA_REG_ADDR, buf, FPGA_REG_MAX_ADD);
	if (ret < 0) {
		FPGA_ERR("fpga i2c read failed: ret %d\n", ret);
		status = 1;
	} else {
		if (buf[REG_SLAVER_ERR] == REG_SLAVER_ERR_CODE) {
			status = 1;
		} else {
			status = 0;
		}
	}

	snprintf(page, PAGESIZE - 1, "%d\n", status);

	ret = simple_read_from_buffer(user_buf, count, ppos, page, strlen(page));
	return ret;
}

DECLARE_PROC_OPS(fpga_status_node_fops, simple_open, proc_fpga_status_read, NULL, NULL);

static ssize_t fpga_hw_control_read(struct file *file,
				     char __user *user_buf, size_t count, loff_t *ppos)
{
	int ret = 0;
	struct fpga_mnt_pri *mnt_pri = PDE_DATA(file_inode(file));
	char page[PAGESIZE] = {0};
	int status = 1;

	if (!mnt_pri) {
		FPGA_ERR("%s error:file_inode.\n", __func__);
		snprintf(page, PAGESIZE - 1, "%d\n", status);
		return ret;
	}

	snprintf(page, PAGESIZE - 1, "%d\n", mnt_pri->hw_control_rst);
	mnt_pri->hw_control_rst = 0;

	ret = simple_read_from_buffer(user_buf, count, ppos, page, strlen(page));
	return ret;
}

static ssize_t fpga_hw_control_write(struct file *file,
				     const char __user *buffer, size_t count, loff_t *ppos)
{
	int ret = 0;
	int mode = 0;
	int voltage = 0;
	char buf[6] = {0};
	struct fpga_mnt_pri *mnt_pri = PDE_DATA(file_inode(file));
	struct fpga_power_data *pdata = NULL;

	if (!mnt_pri) {
		FPGA_ERR("%s error:file_inode.\n", __func__);
		mnt_pri->hw_control_rst = 1;
		return count;
	}

	pdata = &mnt_pri->hw_data;

	if (count > 6) {
		FPGA_ERR("%s error:count:%lu.\n", __func__, count);
		mnt_pri->hw_control_rst = 1;
		return count;
	}

	if (copy_from_user(buf, buffer, count)) {
		FPGA_ERR("%s: read proc input error.\n", __func__);
		mnt_pri->hw_control_rst = 1;
		return count;
	}

	sscanf(buf, "%d,%d", &mode, &voltage);

	FPGA_INFO("mode:%d,voltage %d\n", mode, voltage);

	mutex_lock(&mnt_pri->mutex);
	switch (mode) {
	case RST_CONTROL:
		fpga_rst_control(mnt_pri);
		break;

	case POWER_CONTROL:
#if IS_ENABLED(CONFIG_OPLUS_FPGA_NOTIFY)
		fpga_call_notifier(FPGA_RST_START, NULL);
#endif
		ret = fpga_powercontrol_vccio(&mnt_pri->hw_data, false);
		ret |= fpga_powercontrol_vcccore(&mnt_pri->hw_data, false);
		msleep(500);
		ret |= fpga_powercontrol_vcccore(&mnt_pri->hw_data, true);
		ret |= fpga_powercontrol_vccio(&mnt_pri->hw_data, true);
		usleep_range(RST_TO_NORMAL_TIME, RST_TO_NORMAL_TIME);
#if IS_ENABLED(CONFIG_OPLUS_FPGA_NOTIFY)
		fpga_call_notifier(FPGA_RST_END, NULL);
#endif
		FPGA_INFO("POWER_CONTROL\n");
		break;

	case VCC_CORE_CONTROL:
		mnt_pri->hw_data.vcc_core_volt = voltage;
#if IS_ENABLED(CONFIG_OPLUS_FPGA_NOTIFY)
		fpga_call_notifier(FPGA_RST_START, NULL);
#endif
		ret |= fpga_power_uninit(mnt_pri);
		ret |= fpga_power_init(mnt_pri);
		ret |= fpga_powercontrol_vcccore(&mnt_pri->hw_data, true);
		ret |= fpga_powercontrol_vccio(&mnt_pri->hw_data, true);
		usleep_range(RST_TO_NORMAL_TIME, RST_TO_NORMAL_TIME);
#if IS_ENABLED(CONFIG_OPLUS_FPGA_NOTIFY)
		fpga_call_notifier(FPGA_RST_END, NULL);
#endif
		FPGA_INFO("VCC_CORE_CONTROL\n");
		break;

	case VCC_IO_CONTROL:
		mnt_pri->hw_data.vcc_io_volt = voltage;
#if IS_ENABLED(CONFIG_OPLUS_FPGA_NOTIFY)
		fpga_call_notifier(FPGA_RST_START, NULL);
#endif
		ret |= fpga_power_uninit(mnt_pri);
		ret |= fpga_power_init(mnt_pri);
		ret |= fpga_powercontrol_vcccore(&mnt_pri->hw_data, true);
		ret |= fpga_powercontrol_vccio(&mnt_pri->hw_data, true);
		usleep_range(RST_TO_NORMAL_TIME, RST_TO_NORMAL_TIME);
#if IS_ENABLED(CONFIG_OPLUS_FPGA_NOTIFY)
		fpga_call_notifier(FPGA_RST_END, NULL);
#endif
		FPGA_INFO("VCC_IO_CONTROL\n");
		break;
#if FPGA_POWER_DEBUG
	case POWER_CONTROL_PROBE_START:
		cancel_delayed_work_sync(&mnt_pri->power_debug_work);
		FPGA_INFO("POWER_CONTROL_PROBE_START\n");
		break;

	case POWER_CONTROL_PROBE_STOP:
		queue_delayed_work(mnt_pri->power_debug_wq, &mnt_pri->power_debug_work, msecs_to_jiffies(FPGA_MONITOR_WORK_TIME));
		FPGA_INFO("POWER_CONTROL_PROBE_STOP\n");
		break;
#endif
	case ATCMD_POWER_ON:
		ret |= fpga_powercontrol_vcccore(&mnt_pri->hw_data, true);
		ret |= fpga_powercontrol_vccio(&mnt_pri->hw_data, true);
		mnt_pri->power_ready = true;
		FPGA_INFO("ATCMD_POWER_ON\n");
		break;
	case ATCMD_POWER_OFF:
		ret |= fpga_powercontrol_vccio(&mnt_pri->hw_data, false);
		ret |= fpga_powercontrol_vcccore(&mnt_pri->hw_data, false);
		mnt_pri->power_ready = false;
		FPGA_INFO("ATCMD_POWER_OFF\n");
		break;
	default:
		break;
	}
	mutex_unlock(&mnt_pri->mutex);
	mnt_pri->hw_control_rst = ret;

	return count;
}

DECLARE_PROC_OPS(fpga_hw_control_fops, simple_open, fpga_hw_control_read, fpga_hw_control_write, NULL);

static ssize_t proc_fpga_work_state_read(struct file *file,
		char __user *user_buf, size_t count, loff_t *ppos)
{
	int ret = 0;
	struct fpga_mnt_pri *mnt_pri = PDE_DATA(file_inode(file));
	struct fpga_power_data *pdata = NULL;
	char page[PAGESIZE] = {0};

	if (!mnt_pri) {
		FPGA_ERR("%s error:file_inode.\n", __func__);
		return ret;
	}

	pdata = &mnt_pri->hw_data;

	FPGA_INFO("%s:fpga state change to suspend\n", __func__);

	gpio_direction_output(pdata->clk_switch_gpio, 1);
	gpio_direction_output(pdata->sleep_en_gpio, 1);
	msleep(100);
	FPGA_INFO("%s:fpga state change to resume\n", __func__);
	gpio_direction_output(pdata->clk_switch_gpio, 0);
	gpio_direction_output(pdata->sleep_en_gpio, 0);

	snprintf(page, PAGESIZE - 1, "%d\n", 0);

	ret = simple_read_from_buffer(user_buf, count, ppos, page, strlen(page));
	return ret;
}

DECLARE_PROC_OPS(fpga_work_state_fops, simple_open, proc_fpga_work_state_read, NULL, NULL);

static ssize_t proc_fpga_update_flag_read(struct file *file,
		char __user *user_buf, size_t count, loff_t *ppos)
{
	int ret = 0;
	struct fpga_mnt_pri *mnt_pri = PDE_DATA(file_inode(file));
	char page[PAGESIZE] = {0};

	if (!mnt_pri) {
		FPGA_ERR("%s error:file_inode.\n", __func__);
		return ret;
	}
	snprintf(page, PAGESIZE - 1, "%d\n", mnt_pri->update_flag);

	ret = simple_read_from_buffer(user_buf, count, ppos, page, strlen(page));
	return ret;
}

DECLARE_PROC_OPS(fpga_update_flag_fops, simple_open, proc_fpga_update_flag_read, NULL, NULL);

static int proc_dump_register_read_func(struct seq_file *s, void *v)
{
	int ret = 0;
	u8 *page = NULL;
	u8 _buf[PAGESIZE] = {0};
	u8 reg_buf[FPGA_REG_MAX_ADD] = {0};
	int i = 0;
	struct fpga_mnt_pri *mnt_pri = (struct fpga_mnt_pri *) s->private;
	struct fpga_power_data *pdata = NULL;
	struct fpga_status_t *status = &mnt_pri->status;
	struct fpga_status_t *all_status = &mnt_pri->all_status;

	if (!mnt_pri) {
		FPGA_ERR("%s error:file_inode.\n", __func__);
		seq_printf(s, "%s error:file_inode.\n", __func__);
		return ret;
	}

	pdata = &mnt_pri->hw_data;

	if (!mnt_pri->bus_ready) {
		FPGA_INFO("%s, bus not ready! exit\n", __func__);
		seq_printf(s, "%s, bus not ready! exit\n", __func__);
		return 0;
	}

	memset(reg_buf, 0, sizeof(reg_buf));
	ret = fpga_i2c_read(mnt_pri, FPGA_REG_ADDR, reg_buf, FPGA_REG_MAX_ADD);
	if (ret < 0) {
		FPGA_ERR("fpga i2c read failed: ret %d\n", ret);
		seq_printf(s, "fpga i2c read failed: ret %d\n", ret);
		return 0;
	}

	page = (u8 *)kzalloc(2048, GFP_KERNEL);
	if (!page) {
		seq_printf(s, "proc_dump_register_read_func : kzalloc page error\n");
		return 0;
	}

	for (i = 0; i < FPGA_REG_MAX_ADD; i++) {
		memset(_buf, 0, sizeof(_buf));
		snprintf(_buf, sizeof(_buf), "reg 0x%x:0x%x\n", i, reg_buf[i]);
		strlcat(page, _buf, 2048);
	}

	seq_printf(s, "%s\n", page);
	kfree(page);
	seq_printf(s, "io_tx = %llu\n", status->io_tx_err_cnt);
	seq_printf(s, "io_rx = %llu\n", status->io_rx_err_cnt);
	seq_printf(s, "i2c_tx = %llu\n", status->i2c_tx_err_cnt);
	seq_printf(s, "i2c_rx = %llu\n", status->i2c_rx_err_cnt);
	seq_printf(s, "spi_tx = %llu\n", status->spi_tx_err_cnt);
	seq_printf(s, "spi_rx = %llu\n", status->spi_rx_err_cnt);
	seq_printf(s, "slave_err_cnt = %llu\n", status->slave_err_cnt);

	seq_printf(s, "all_io_tx = %llu\n", all_status->io_tx_err_cnt);
	seq_printf(s, "all_io_rx = %llu\n", all_status->io_rx_err_cnt);
	seq_printf(s, "all_i2c_tx = %llu\n", all_status->i2c_tx_err_cnt);
	seq_printf(s, "all_i2c_rx = %llu\n", all_status->i2c_rx_err_cnt);
	seq_printf(s, "all_spi_tx = %llu\n", all_status->spi_tx_err_cnt);
	seq_printf(s, "all_spi_rx = %llu\n", all_status->spi_rx_err_cnt);
	seq_printf(s, "all_slave_err_cnt = %llu\n", all_status->slave_err_cnt);

	return 0;
}

static int dump_register_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_dump_register_read_func, PDE_DATA(inode));
}

DECLARE_PROC_OPS(fpga_dump_info_fops, dump_register_open, seq_read, NULL, single_release);

static int fpga_health_monitor_read_func(struct seq_file *s, void *v)
{
	struct fpga_mnt_pri *mnt_pri = (struct fpga_mnt_pri *) s->private;
	struct monitor_data *monitor_data = NULL;

	if (!mnt_pri) {
		FPGA_ERR("%s error:file_inode.\n", __func__);
		return 0;
	}
	monitor_data = &mnt_pri->moni_data;

	if (!monitor_data) {
		FPGA_ERR("monitor_data is null.\n");
		return 0;
	}

	mutex_lock(&mnt_pri->mutex);
	seq_printf(s, "fpga_m_version:\t\t%d\n", mnt_pri->version_m);
	seq_printf(s, "fpga_s_version:\t\t%d\n", mnt_pri->version_s);
	seq_printf(s, "fpga_manufacture:\t\t%s\n", mnt_pri->manufacture);
	fpga_healthinfo_read(s, monitor_data);

	mutex_unlock(&mnt_pri->mutex);
	return 0;
}

static ssize_t health_monitor_control(struct file *file, const char __user *buf, size_t count, loff_t *lo)
{
	struct fpga_mnt_pri *mnt_pri = PDE_DATA(file_inode(file));
	struct monitor_data *monitor_data = NULL;
	char buffer[4] = {0};
	int tmp = 0;

	if (!mnt_pri) {
		FPGA_ERR("%s error:file_inode.\n", __func__);
		return count;
	}
	monitor_data = &mnt_pri->moni_data;

	if (!monitor_data) {
		FPGA_ERR("monitor_data is null.\n");
		return count;
	}

	if (count > 2) {
		goto EXIT;
	}
	if (copy_from_user(buffer, buf, count)) {
		FPGA_ERR("%s: read proc input error.\n", __func__);
		goto EXIT;
	}

	mutex_lock(&mnt_pri->mutex);
	if (1 == sscanf(buffer, "%d", &tmp) && tmp == 0) {
		fpga_healthinfo_clear(monitor_data);
	} else {
		FPGA_ERR("invalid operation\n");
	}
	mutex_unlock(&mnt_pri->mutex);

EXIT:
	return count;
}

static int health_monitor_open(struct inode *inode, struct file *file)
{
	return single_open(file, fpga_health_monitor_read_func, PDE_DATA(inode));
}

DECLARE_PROC_OPS(fpga_health_monitor_fops, health_monitor_open, seq_read, health_monitor_control, single_release);

int fpga_proc_create(struct fpga_mnt_pri *mnt_pri)
{
	struct proc_dir_entry *d_entry;

	d_entry = proc_create_data("info", S_IRUGO, mnt_pri->pr_entry, &fpga_info_node_fops, mnt_pri);
	if (d_entry == NULL) {
		FPGA_ERR("Couldn't create fpga info proc data\n");
		return -EINVAL;
	}

	d_entry = proc_create_data("status", S_IRUGO, mnt_pri->pr_entry, &fpga_status_node_fops, mnt_pri);
	if (d_entry == NULL) {
		FPGA_ERR("Couldn't create fpga status proc data\n");
		return -EINVAL;
	}
	d_entry = proc_create_data("hw_control", (S_IRUGO | S_IWUGO), mnt_pri->pr_entry, &fpga_hw_control_fops, mnt_pri);
	if (d_entry == NULL) {
		FPGA_ERR("Couldn't create fpga hw_contorl proc data\n");
		return -EINVAL;
	}
	d_entry = proc_create_data("work_state", S_IRUGO, mnt_pri->pr_entry, &fpga_work_state_fops, mnt_pri);
	if (d_entry == NULL) {
		FPGA_ERR("Couldn't create fpga hw_contorl proc data\n");
		return -EINVAL;
	}
	d_entry = proc_create_data("update_flag", S_IRUGO, mnt_pri->pr_entry, &fpga_update_flag_fops, mnt_pri);
	if (d_entry == NULL) {
		FPGA_ERR("Couldn't create fpga update_flag proc data\n");
		return -EINVAL;
	}
	d_entry = proc_create_data("dump_info", S_IRUGO, mnt_pri->pr_entry, &fpga_dump_info_fops, mnt_pri);
	if (d_entry == NULL) {
		FPGA_ERR("Couldn't create fpga dump_info proc data\n");
		return -EINVAL;
	}
	d_entry = proc_create_data("health_info", S_IRUGO, mnt_pri->pr_entry, &fpga_health_monitor_fops, mnt_pri);
	if (d_entry == NULL) {
		FPGA_ERR("Couldn't create fpga health_info proc data\n");
		return -EINVAL;
	}

	return 0;
}

static int fpga_dts_init(struct fpga_mnt_pri *mnt_pri)
{
	int rc;
	int ret;
	unsigned int temp;
	struct fpga_power_data *pdata = NULL;
	struct device_node *np = NULL;

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
			FPGA_INFO("%s:clk_switch_gpio[%d]\n", __func__, pdata->clk_switch_gpio);
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
			FPGA_INFO("%s:sleep_en_gpio[%d]\n", __func__, pdata->sleep_en_gpio);
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
			FPGA_INFO("%s:rst_gpio[%d]\n", __func__, pdata->rst_gpio);
			gpio_direction_output(pdata->rst_gpio, 1);
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
			FPGA_INFO("%s:vcc_core_gpio[%d]\n", __func__, pdata->vcc_core_gpio);
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
			FPGA_INFO("%s:vcc_io_gpio[%d]\n", __func__, pdata->vcc_io_gpio);
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

	rc = of_property_read_u32(np, "platform_support_project_dir", &temp);
	if (rc < 0) {
		FPGA_INFO("platform_support_project_dir not specified\n");
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

	pinctrl_select_state(pdata->pinctrl, pdata->fpga_ative);
	pinctrl_select_state(pdata->pinctrl, pdata->fpga_clk_switch_ative);
	pinctrl_select_state(pdata->pinctrl, pdata->fpga_rst_ative);

	FPGA_INFO("end\n");
	return 0;
}

static int fpga_monitor_init(struct fpga_mnt_pri *mnt_pri)
{
/*
	int ret;
	u8 buf[32] = {0};
*/
	mnt_pri->prj_id = get_project();
	FPGA_INFO("prj_id %d\n", mnt_pri->prj_id);
	strncpy(mnt_pri->manufacture, "GAOYUN", 64 - 1);
/*
	ret = fpga_i2c_read(mnt_pri, FPGA_REG_ADDR, buf, 14);
	if (ret < 0) {
		FPGA_ERR("read failed! ret %d\n", ret);
		return -1;
	}
	mnt_pri->version_m = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
	mnt_pri->version_s = buf[4] << 24 | buf[5] << 16 | buf[6] << 8 | buf[7];
*/
	return 0;
}

#if FPGA_POWER_DEBUG
static void fpga_power_debug_work(struct work_struct *work)
{
	struct fpga_mnt_pri *mnt_pri = container_of(work, struct fpga_mnt_pri, power_debug_work.work);

	FPGA_INFO("%s:enter\n", __func__);
	fpga_rst_control(mnt_pri);
	FPGA_INFO("%s:exit\n", __func__);

	mnt_pri->power_debug_work_count++;
	if (mnt_pri->power_debug_work_count <= FPGA_POWER_DEBUG_MAX_TIMES) {
		queue_delayed_work(mnt_pri->power_debug_wq, &mnt_pri->power_debug_work, msecs_to_jiffies(FPGA_MONITOR_WORK_TIME));
	}
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int fpga_monitor_probe(struct i2c_client *i2c)
#else
static int fpga_monitor_probe(struct i2c_client *i2c, const struct i2c_device_id *id)
#endif
{
	struct fpga_mnt_pri *mnt_pri;
	int ret;
	size_t size;
	int update_rst;
	int *pfpga_update_rst = NULL;

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

	i2c_set_clientdata(i2c, mnt_pri);

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
		FPGA_ERR("fpga_power_control error，ret%d\n", ret);
	}

	ret = fpga_powercontrol_vcccore(&mnt_pri->hw_data, true);
	if (ret) {
		FPGA_ERR("fpga_powercontrol_vcccore error，ret%d\n", ret);
	}
	msleep(1);
	ret = fpga_powercontrol_vccio(&mnt_pri->hw_data, true);
	if (ret) {
		FPGA_ERR("fpga_powercontrol_vccio error，ret%d\n", ret);
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
	mnt_pri->power_debug_wq = create_singlethread_workqueue("fpga_power_debug_wq");
	INIT_DELAYED_WORK(&mnt_pri->power_debug_work, fpga_power_debug_work);
	queue_delayed_work(mnt_pri->power_debug_wq, &mnt_pri->power_debug_work, msecs_to_jiffies(100));
#endif

	mnt_pri->health_monitor_support = true;
	if (mnt_pri->health_monitor_support) {
		mnt_pri->moni_data.health_monitor_support = mnt_pri->health_monitor_support;
		ret = fpga_healthinfo_init(mnt_pri->dev, &mnt_pri->moni_data);
		if (ret < 0) {
			FPGA_ERR("health info init failed.\n");
		}
	}
	mnt_pri->hw_control_rst = 0;
/*
	mnt_pri->fpga_ck = devm_clk_get(mnt_pri->dev, "bb_clk4");
	if (IS_ERR(mnt_pri->fpga_ck)) {
		FPGA_ERR("failed to get bb_clk4\n");
	}
*/
	mnt_pri->bus_ready = true;
	mnt_pri->power_ready = true;
	pfpga_update_rst = (int *)qcom_smem_get(QCOM_SMEM_HOST_ANY, SMEM_OPLUS_FPGA_PROP, &size);
	if (IS_ERR(pfpga_update_rst)) {
		FPGA_INFO("qcom_smem_get failed.\n");
		mnt_pri->update_flag = FPGA_UEFI_UPDATE_NG;
	} else {
		update_rst = *pfpga_update_rst;
		if (update_rst == 0x55aa0001) {
			FPGA_INFO("uefi update success.\n");
			mnt_pri->update_flag = FPGA_UEFI_UPDATE_OK;
		} else {
			FPGA_INFO("uefi update failed, rst = 0x%x.\n", update_rst);
			mnt_pri->update_flag = FPGA_UEFI_UPDATE_NG;
		}
	}

	FPGA_INFO("fpga_monitor_probe sucess\n");
	return 0;
}

void fpga_monitor_remove(struct i2c_client *i2c)
{
	struct fpga_mnt_pri *mnt_pri = i2c_get_clientdata(i2c);

	cancel_delayed_work_sync(&mnt_pri->hb_work);
	flush_workqueue(mnt_pri->hb_workqueue);
	destroy_workqueue(mnt_pri->hb_workqueue);

#if FPGA_POWER_DEBUG
	cancel_delayed_work_sync(&mnt_pri->power_debug_work);
	flush_workqueue(mnt_pri->power_debug_wq);
	destroy_workqueue(mnt_pri->power_debug_wq);
#endif

	remove_proc_entry(FPGA_PROC_NAME, NULL);
	kfree(mnt_pri);
	FPGA_INFO("remove sucess\n");
}

static int fpga_monitor_suspend(struct device *dev)
{
	struct fpga_mnt_pri *mnt_pri = dev_get_drvdata(dev);

	FPGA_INFO("%s is called\n", __func__);

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

	FPGA_INFO("%s is called\n", __func__);

	if (!mnt_pri) {
		FPGA_ERR("mnt_pri is null\n");
		return 0;
	}
	mnt_pri->bus_ready = true;
	queue_delayed_work(mnt_pri->hb_workqueue, &mnt_pri->hb_work, msecs_to_jiffies(FPGA_MONITOR_WORK_TIME));
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
		FPGA_INFO("%s disable fpga clk.\n", __func__);
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
		FPGA_INFO("%s enable fpga clk.\n", __func__);
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
	//   .remove   = fpga_monitor_remove,
	.id_table = fpga_i2c_id,
	.driver   = {
		.name           = FPGA_MNT_I2C_NAME,
		.owner          = THIS_MODULE,
		.of_match_table = fpga_i2c_dt_match,
		.pm = &fpga_monitor_pm_ops,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};

static int __init fpga_init(void)
{
	int ret;

	FPGA_INFO("1: try to register I2C driver\n");

	ret = i2c_add_driver(&fpga_i2c_driver);
	if (ret) {
		FPGA_INFO("Failed to register I2C driver %s, rc = %d", FPGA_MNT_I2C_NAME, ret);
	} else {
		FPGA_INFO("typec_switch: success to register I2C driver\n");
	}
	return 0;
}

static void __exit fpga_exit(void)
{
	i2c_del_driver(&fpga_i2c_driver);
	FPGA_INFO("i2c_del_driverr\n");
}
module_init(fpga_init);
module_exit(fpga_exit);

MODULE_DESCRIPTION("FPGA I2C driver");
MODULE_LICENSE("GPL v2");
