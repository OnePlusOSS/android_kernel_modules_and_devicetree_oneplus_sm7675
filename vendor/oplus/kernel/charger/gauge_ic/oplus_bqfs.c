// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2018-2023 Oplus. All rights reserved.
 */

#define pr_fmt(fmt) "[bq27426] %s(%d): " fmt, __func__, __LINE__

#include <linux/version.h>
#include <asm/unaligned.h>
#include <linux/acpi.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/idr.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/of_gpio.h>
#include <linux/param.h>
#include <linux/platform_device.h>
#include <linux/power_supply.h>
#include <linux/random.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <asm/div64.h>

#include "../oplus_charger.h"
#include "oplus_bq27541.h"

#define IIC_ADDR_OF_2_KERNEL(addr) ((u8)((u8)addr >> 1))
#define CMD_MAX_DATA_SIZE	32

typedef enum {
	CMD_INVALID = 0,
	CMD_R,
	CMD_W,
	CMD_C,
	CMD_X,
} cmd_type_t;


typedef struct {
	cmd_type_t cmd_type;
	uint8_t addr;
	uint8_t reg;
	union {
		uint8_t bytes[CMD_MAX_DATA_SIZE + 1];
		uint16_t delay;
	} data;
	uint8_t  data_len;
	uint16_t line_num;
} bqfs_cmd_t;

static int bqfs_read_word(struct chip_bq27541 *chip, int cmd, int *returnData)
{
	if (!chip->client) {
		chg_err(" chip->client NULL, return\n");
		return 0;
	}
	if(oplus_is_rf_ftm_mode()) {
		return 0;
	}
	if (cmd == BQ27541_BQ27411_CMD_INVALID) {
		return 0;
	}

	mutex_lock(&chip->chip_mutex);
	*returnData = i2c_smbus_read_word_data(chip->client, cmd);

	if (*returnData < 0) {
		chg_err("reg0x%x read err, rc = %d\n", cmd, *returnData);
		mutex_unlock(&chip->chip_mutex);
		return *returnData;
	}
	mutex_unlock(&chip->chip_mutex);

	return 0;
}

static int bqfs_write_word(struct chip_bq27541 *chip, int cmd, int writeData)
{
	int rc = 0;

	if (!chip->client) {
		pr_err(" chip->client NULL, return\n");
		return 0;
	}
	if(oplus_is_rf_ftm_mode()) {
		return 0;
	}
	if (cmd == BQ27541_BQ27411_CMD_INVALID) {
		return 0;
	}
	mutex_lock(&chip->chip_mutex);
	rc = i2c_smbus_write_word_data(chip->client, cmd, writeData);

	if (rc < 0) {
		pr_err("reg0x%x write 0x%x err, rc = %d\n", cmd, writeData, rc);
		mutex_unlock(&chip->chip_mutex);
		return rc;
	}
	mutex_unlock(&chip->chip_mutex);
	return 0;
}

static s32 bqfs_fg_read_block(struct chip_bq27541 *chip, uint8_t addr, uint8_t reg, uint8_t *buf, uint8_t len)
{
	static struct i2c_msg msg[2];
	u8 i2c_addr = IIC_ADDR_OF_2_KERNEL(addr);
	s32 ret;

	if (!chip || !chip->client || !chip->client->adapter)
		return -ENODEV;

	if (oplus_is_rf_ftm_mode())
		return 0;

	mutex_lock(&chip->chip_mutex);

	msg[0].addr = i2c_addr;
	msg[0].flags = 0;
	msg[0].buf = &(reg);
	msg[0].len = sizeof(u8);
	msg[1].addr = i2c_addr;
	msg[1].flags = I2C_M_RD;
	msg[1].buf = buf;
	msg[1].len = len;
	ret = (s32)i2c_transfer(chip->client->adapter, msg, ARRAY_SIZE(msg));

	mutex_unlock(&chip->chip_mutex);
	return ret;
}
static s32 bqfs_fg_write_block(struct chip_bq27541 *chip, uint8_t addr, uint8_t reg, uint8_t *buf, uint8_t len)
{
#define WRITE_BUF_MAX_LEN 32
	static struct i2c_msg msg[1];
	static u8 write_buf[WRITE_BUF_MAX_LEN];
	u8 i2c_addr = IIC_ADDR_OF_2_KERNEL(addr);
	u8 length = len;
	s32 ret;

	if (!chip || !chip->client || !chip->client->adapter)
		return -ENODEV;

	if (oplus_is_rf_ftm_mode())
		return 0;

	if ((length <= 0) || (length + 1 >= WRITE_BUF_MAX_LEN)) {
		pr_err("i2c write buffer fail: length invalid!\n");
		return -1;
	}

	mutex_lock(&chip->chip_mutex);
	memset(write_buf, 0, WRITE_BUF_MAX_LEN * sizeof(u8));
	write_buf[0] = reg;
	memcpy(&write_buf[1], buf, length);

	msg[0].addr = i2c_addr;
	msg[0].flags = 0;
	msg[0].buf = write_buf;
	msg[0].len = sizeof(u8) * (length + 1);

	ret = i2c_transfer(chip->client->adapter, msg, ARRAY_SIZE(msg));
	if (ret < 0) {
		pr_err("i2c write buffer fail: can't write reg 0x%02X\n", reg);
	}

	mutex_unlock(&chip->chip_mutex);
	return (ret < 0) ? ret : 0;
}

static bool bqfs_fg_fw_update_write_block(struct chip_bq27541 *chip, uint8_t addr, uint8_t reg, uint8_t* buf, uint8_t len)
{
#define I2C_BLK_SIZE	30
	int ret;
	uint8_t wr_len = 0;

	while (len > I2C_BLK_SIZE) {
		ret = bqfs_fg_write_block(chip, addr, reg + wr_len, buf + wr_len, I2C_BLK_SIZE);
		if (ret < 0)
			return false;
		wr_len += I2C_BLK_SIZE;
		len -= I2C_BLK_SIZE;
	}

	if (len) {
		ret = bqfs_fg_write_block(chip, addr, reg + wr_len, buf + wr_len, len);
		if (ret < 0)
			return false;
	}

	return true;
}

static bool bqfs_fg_fw_update_cmd(struct chip_bq27541 *chip, const bqfs_cmd_t *cmd)
{
	int ret;
	uint8_t tmp_buf[10];

	switch (cmd->cmd_type) {
	case CMD_R:
		ret = bqfs_fg_read_block(chip, cmd->addr, cmd->reg, (uint8_t *)&cmd->data.bytes, cmd->data_len);
		if (ret < 0)
			return false;
		else
			return true;
		break;
	case CMD_W:
		return bqfs_fg_fw_update_write_block(chip, cmd->addr, cmd->reg,
					(uint8_t *)&cmd->data.bytes,
					cmd->data_len);
	case CMD_C:
		if (bqfs_fg_read_block(chip, cmd->addr, cmd->reg, tmp_buf, cmd->data_len) < 0)
			return false;
		if (memcmp(tmp_buf, cmd->data.bytes, cmd->data_len))
			return false;

		return true;
	case CMD_X:
		mdelay(cmd->data.delay);
		return true;
	default:
		chg_err("Unsupported command at line %d\n", cmd->line_num);
		return false;
	}
}

static void bqfs_cntl_cmd(struct chip_bq27541 *chip, int subcmd)
{
	bqfs_write_word(chip, BQ27426_REG_CNTL, subcmd);
}

static void bqfs_cntl_subcmd(struct chip_bq27541 *chip, int subcmd)
{
	bqfs_write_word(chip, 0x3E, subcmd);
}

static int bq27426_sealed(struct chip_bq27541 *chip)
{
	int value = 0;
	bqfs_cntl_cmd(chip, BQ27426_SUBCMD_CTNL_STATUS);
	usleep_range(10000, 10000);
	bqfs_read_word(chip, BQ27426_REG_CNTL, &value);

	if (value & BIT(13)) {
		pr_err("bq27426 sealed, value = %x return 1\n", value);
		return 1;
	} else {
		pr_err("bq27426 unseal, value = %x return 0\n", value);
		return 0;
	}
}

static int bq27426_unseal(struct chip_bq27541 *chip)
{
	int retry = 2;
	int rc = 0;
	int value = 0;
	if (!bq27426_sealed(chip)) {
		pr_err("bq27426 unsealed, return\n");
		return rc;
	}

	do {
		bqfs_cntl_cmd(chip, 0x8000);
		usleep_range(10000, 10000);
		bqfs_cntl_cmd(chip, 0x8000);
		usleep_range(10000, 10000);
		bqfs_cntl_cmd(chip, BQ27426_SUBCMD_CTNL_STATUS);
		usleep_range(10000, 10000);
		bqfs_read_word(chip, BQ27426_REG_CNTL, &value);
		if (!(value & BIT(13))) {
			retry = 0;
			rc = 0;
		} else {
			retry--;
			rc = -1;
		}
	} while (retry > 0);
	pr_err("%s [%d][0x%x]\n", __func__, rc, value);

	return rc;
}

static int bq27426_seal(struct chip_bq27541 *chip)
{
	int retry = 2;
	int rc = 0;
	int value = 0;
	if (bq27426_sealed(chip)) {
		pr_err("bq8z610 sealed, return\n");
		return rc;
	}

	do {
		bqfs_cntl_cmd(chip, 0x0020);
		usleep_range(10000, 10000);

		bqfs_cntl_cmd(chip, BQ27426_SUBCMD_CTNL_STATUS);
		usleep_range(10000, 10000);

		bqfs_read_word(chip, BQ27426_REG_CNTL, &value);
		if (value & BIT(13)) {
			retry = 0;
			rc = 0;
		} else {
			retry--;
			rc = -1;
		}
	} while (retry > 0);
	pr_err("%s [%d][0x%x]\n", __func__, rc, value);

	return rc;
}

void bq27426_modify_soc_smooth_parameter(struct chip_bq27541 *chip, bool on)
{
	int rc = 0;
	int value = 0;
	u8 oldl_csum = 0, byte0 = 0, byte1_old = 0, byte1_new = 0, new_csum = 0, temp = 0;

	if (bq27426_unseal(chip)) {
		chg_err("bq27426_unseal fail !\n");
		return;
	}

	gauge_i2c_txsubcmd_onebyte(chip, 0x61, 0x00);

	bqfs_cntl_subcmd(chip, 0x0040);
	usleep_range(10000, 10000);

	bqfs_read_word(chip, 0x40, &value);
	if ((on && (value & BIT(13))) || (!on && !(value & BIT(13)))) {
		rc = -1;
		goto smooth_exit;
	}

	bqfs_cntl_cmd(chip, 0x0013);
	usleep_range(1100000, 1100000);
	bq27541_read_i2c_onebyte(chip, 0x06, &temp);

	gauge_i2c_txsubcmd_onebyte(chip, 0x61, 0x00);

	bqfs_cntl_subcmd(chip, 0x0040);
	usleep_range(10000, 10000);

	bq27541_read_i2c_onebyte(chip, 0x60, &oldl_csum);

	bqfs_read_word(chip, 0x40, &value);
	byte0 = value & 0xFF;
	byte1_old = value >> 8;

	if (on)
		byte1_new = byte1_old | BIT(5);
	else
		byte1_new = byte1_old & ~BIT(5);
	value = (byte0 | (byte1_new << 8));
	bqfs_write_word(chip, 0x40, value);

	temp = (0xFF - oldl_csum - byte1_old) % 256;
	new_csum = 0xFF - (temp + byte1_new) % 256;

	gauge_i2c_txsubcmd_onebyte(chip, 0x60, new_csum);
	bqfs_cntl_cmd(chip, 0x0042);
	usleep_range(1100000, 1100000);

	rc = 1;

smooth_exit:

	if (bq27426_seal(chip))
		chg_err("bq27411 seal fail\n");

	chg_err("[%d, %d] [0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x] end\n", on, rc, byte0, byte1_old, value, temp, new_csum, oldl_csum);
}

void bqfs_init(struct chip_bq27541 *chip)
{
#define BQFS_INIT_RETRY_MAX	3
#define BQFS_CMD_X_LEN	2
#define BQFS_CMD_SHITF	8
	struct device_node *node = chip->dev->of_node;
	struct device_node *bqfs_node = NULL;
	struct device *dev = &chip->client->dev;
	unsigned char *p;
	bqfs_cmd_t cmd;
	u8 *pBuf = NULL;
	int read_buf = 0, bqfs_dm = 0, value_dm = 0, bqfs_unfilt = 0;
	int i, buflen, len;
	int rc = -1, rec_cnt = 0, retry_times = 0;

	if (!chip)
		return;

	bqfs_node = of_find_node_by_name(node, "battery_bqfs_params");
	if (bqfs_node == NULL) {
		chg_err(": Can't find child node \"battery_bqfs_params\"");
		return;
	}

	rc = of_property_read_u32(bqfs_node, "bqfs_dm", &bqfs_dm);
	if (rc) {
		bqfs_dm = 0;
	}

	rc = of_property_read_u32(bqfs_node, "bqfs_unfilt", &bqfs_unfilt);
	if (rc) {
		bqfs_unfilt = BQ27426_BQFS_FILT;
	}

	bqfs_read_word(chip, BQ27426_REG_FLAGS, &read_buf);
	bqfs_cntl_cmd(chip, BQ27426_SUBCMD_DM_CODE);
	bqfs_read_word(chip, BQ27426_REG_CNTL, &value_dm);

	if (!(read_buf & BIT(5)) && (value_dm == bqfs_dm) && !(read_buf & BIT(4))) {
		chg_err(" [0x%x %d %d]\n", read_buf, value_dm, bqfs_dm);
		chip->bqfs_init = true;
		return;
	}

	buflen = of_property_count_u8_elems(bqfs_node, "sinofs_bqfs_data");
	pBuf = (u8 *)devm_kzalloc(dev, buflen, 0);
	if (pBuf == NULL) {
		rc = 1;
		chg_err(": kzalloc error\n");
		goto main_process_error;
	}

	rc = of_property_read_u8_array(bqfs_node, "sinofs_bqfs_data", pBuf, buflen);
	if (rc) {
		chg_err(": read dts sinofs_bqfs_data fail\n");
		goto main_process_error;
	}

	if (bq27426_unseal(chip)) {
		chg_err("bq27426_unseal fail !\n");
		goto main_process_error;
	}

BQFS_EXECUTE_CMD_RETRY:
	p = (unsigned char *)pBuf;
	rec_cnt = 0;
	while (p < pBuf + buflen) {
		cmd.cmd_type = *p++;

		if (cmd.cmd_type == CMD_X) {
			len = *p++;
			if (len != BQFS_CMD_X_LEN)
				goto main_process_error;

			cmd.data.delay = *p << BQFS_CMD_SHITF | *(p + 1);
			p += BQFS_CMD_X_LEN;
		} else {
			cmd.addr = *p++;
			cmd.reg  = *p++;
			cmd.data_len = *p++;
			for (i = 0; i < cmd.data_len; i++)
				cmd.data.bytes[i] = *p++;
		}

		rec_cnt++;
		if (!bqfs_fg_fw_update_cmd(chip, &cmd)) {
			retry_times++;
			chg_err("Failed at [%d, %d]\n", rec_cnt, retry_times);
			if (retry_times < BQFS_INIT_RETRY_MAX)
				goto BQFS_EXECUTE_CMD_RETRY;
			else
				goto BQFS_EXECUTE_CMD_ERR;
		}
		mdelay(5);
	}
	chip->bqfs_init = true;
	chg_err("Parameter update Successfully,bqfs_init %d\n", chip->bqfs_init);

BQFS_EXECUTE_CMD_ERR:
	if (bq27426_seal(chip))
		chg_err("bq27411 seal fail\n");

main_process_error:
	if (pBuf)
		devm_kfree(dev, pBuf);
	chg_err(" end[%d %d 0x%x 0x%x]\n", rc, chip->bqfs_init, value_dm, read_buf);
	return;
}

MODULE_DESCRIPTION("TI FG FW UPDATE Driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("JJ Kong");
