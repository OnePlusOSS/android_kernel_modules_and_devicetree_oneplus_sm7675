#include <linux/i2c.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include "fpga_monitor.h"
#include "fpga_mid.h"
#include "fpga_common_api.h"
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
		FPGA_ERR("I2C write over retry limit\n");
		ret = -EIO;
		return ret;
	}
	kfree(buf);
	return ret;
}

int fpga_i2c_read(struct fpga_mnt_pri *mnt_pri,
		  u8 reg, u8 *data, size_t len)
{
	struct i2c_client *client = mnt_pri->client;
	struct fpga_power_data *pdata = NULL;
	struct i2c_msg msg[2];
	u8 buf[1];
	int ret;
	unsigned char retry;
	int sleep_status = 0;
	int clk_switch_status = 0;

	pdata = &mnt_pri->hw_data;
	sleep_status = gpio_get_value(pdata->sleep_en_gpio);
	clk_switch_status = gpio_get_value(pdata->clk_switch_gpio);

	if ((sleep_status == 1) && (clk_switch_status == 1)) {
		FPGA_INFO("current status is suspend, so ignor this check!\n");
		return FPGA_SUSPEND_I2C_ERR_CODE;
	}

	buf[0] = reg;

	msg[0].addr = client->addr;
	msg[0].flags = 0;
	msg[0].len = 0x01;
	msg[0].buf = &buf[0];

	msg[1].addr = client->addr;
	msg[1].flags = I2C_M_RD;
	msg[1].len = len;
	msg[1].buf = data;

	for (retry = 0; retry < MAX_I2C_RETRY_TIME; retry++) {
		if (i2c_transfer(client->adapter, msg, 2) == 2) {
			ret = len;
			break;
		}
		msleep(10);
	}

	/* after read fail read gpio again and recheck gpio status */
	sleep_status = gpio_get_value(pdata->sleep_en_gpio);
	clk_switch_status = gpio_get_value(pdata->clk_switch_gpio);
	if ((sleep_status == 1) && (clk_switch_status == 1)) {
		FPGA_INFO("read again current status is suspend, so ignor this check!\n");
		return FPGA_SUSPEND_I2C_ERR_CODE;
	}

	if (retry == MAX_I2C_RETRY_TIME) {
		FPGA_ERR("I2C read over retry limit\n");
		ret = -EIO;
		return ret;
	}

	return ret;
}
