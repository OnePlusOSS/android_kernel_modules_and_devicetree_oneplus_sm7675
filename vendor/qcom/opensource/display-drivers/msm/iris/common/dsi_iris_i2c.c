// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015-2019, The Linux Foundation. All rights reserved.
 * Copyright (C) 2017-2020, Pixelworks, Inc.
 *
 * These files contain modifications made by Pixelworks, Inc., in 2019-2020.
 */

#include <linux/i2c.h>
#include "dsi_display.h"
#include "dsi_iris_api.h"
#include "dsi_iris_i2c.h"
#include "dsi_iris_lightup.h"
#include "dsi_iris_log.h"


#define IRIS_PURE_COMPATIBLE_NAME  "pixelworks,iris-i2c"
#define IRIS_PURE_I2C_DRIVER_NAME  "pixelworks-i2c"

/*iris i2c handle*/
static struct i2c_client  *iris_pure_i2c_handle;

int iris_pure_i2c_single_read(uint32_t addr, uint32_t *val)
{
	int ret = -1;
	uint8_t *w_data_list = NULL;
	uint8_t *r_data_list = NULL;
	struct i2c_msg msgs[2];
	struct iris_cfg *pcfg = iris_get_cfg();

	if (!iris_pure_i2c_handle || !val) {
		IRIS_LOGE("%s, %d: the parameter is not right\n", __func__, __LINE__);
		return -EINVAL;
	}

	memset(msgs, 0, 2 * sizeof(msgs[0]));

	w_data_list = kmalloc(5, GFP_KERNEL);
	if (!w_data_list) {
		IRIS_LOGE("%s, %d: allocate memory fails\n", __func__, __LINE__);
		return -ENOMEM;
	}

	r_data_list = kmalloc(4, GFP_KERNEL);
	if (!r_data_list) {
		IRIS_LOGE("%s, %d: allocate memory fails\n", __func__, __LINE__);
		kfree(w_data_list);
		return -ENOMEM;
	}

	w_data_list[0] = 0xcc;
	w_data_list[1] = (addr >> 0) & 0xff;
	w_data_list[2] = (addr >> 8) & 0xff;
	w_data_list[3] = (addr >> 16) & 0xff;
	w_data_list[4] = (addr >> 24) & 0xff;

	r_data_list[0] = 0x00;
	r_data_list[1] = 0x00;
	r_data_list[2] = 0x00;
	r_data_list[3] = 0x00;

	msgs[0].addr = (iris_pure_i2c_handle->addr & 0xff);
	msgs[0].flags = 0;
	msgs[0].buf = w_data_list;
	msgs[0].len = 5;

	msgs[1].addr = (iris_pure_i2c_handle->addr & 0xff);
	msgs[1].flags = I2C_M_RD;
	msgs[1].buf = r_data_list;
	msgs[1].len = 4;

	mutex_lock(&pcfg->i2c_read_mutex);
	ret = i2c_transfer(iris_pure_i2c_handle->adapter, &msgs[0], 1);
	if (ret == 1) {
		ret = 0;
	} else {
		ret = ret < 0 ? ret : -EIO;
		IRIS_LOGE("%s, %d: i2c_transfer failed, write cmd, addr = 0x%08x, ret = %d\n",
			__func__, __LINE__, addr, ret);
	}

	if (ret == 0) {
		udelay(20);
		ret = i2c_transfer(iris_pure_i2c_handle->adapter, &msgs[1], 1);
		if (ret == 1) {
			ret = 0;
		} else {
			ret = ret < 0 ? ret : -EIO;
			IRIS_LOGE("%s, %d: i2c_transfer failed, read cmd, addr = 0x%08x, ret = %d\n",
				__func__, __LINE__, addr, ret);
		}
	}
	mutex_unlock(&pcfg->i2c_read_mutex);

	if (ret == 0) {
		*val = (r_data_list[0] << 24) |
			(r_data_list[1] << 16) |
			(r_data_list[2] << 8) |
			(r_data_list[3] << 0);
	}

	kfree(w_data_list);
	kfree(r_data_list);
	w_data_list = NULL;
	r_data_list = NULL;

	return ret;

}

int iris_pure_i2c_single_write(uint32_t addr, uint32_t val)
{

	int ret = 0;
	struct i2c_msg msg;
	uint8_t *data_list = NULL;

	if (!iris_pure_i2c_handle) {
		IRIS_LOGE("%s, %d: the parameter is not right\n", __func__, __LINE__);
		return -EINVAL;
	}

	memset(&msg, 0, sizeof(msg));

	data_list = kmalloc(9, GFP_KERNEL);
	if (!data_list) {
		IRIS_LOGE("%s, %d: allocate memory fails\n", __func__, __LINE__);
		return -ENOMEM;
	}

	data_list[0] = 0xcc;
	data_list[1] = (addr >> 0) & 0xff;
	data_list[2] = (addr >> 8) & 0xff;
	data_list[3] = (addr >> 16) & 0xff;
	data_list[4] = (addr >> 24) & 0xff;
	data_list[5] = (val >> 24) & 0xff;
	data_list[6] = (val >> 16) & 0xff;
	data_list[7] = (val >> 8) & 0xff;
	data_list[8] = (val >> 0) & 0xff;

	msg.addr = (iris_pure_i2c_handle->addr & 0xff);
	msg.flags = 0;
	msg.buf = data_list;
	msg.len = 9;

	ret = i2c_transfer(iris_pure_i2c_handle->adapter, &msg, 1);
	if (ret == 1) {
		ret = 0;
	} else {
		ret = ret < 0 ? ret : -EIO;
		IRIS_LOGE("%s, %d: i2c_transfer failed, write cmd, addr = 0x%08x, ret = %d\n",
			__func__, __LINE__, addr, ret);
	}

	kfree(data_list);
	data_list = NULL;
	return ret;
}

int iris_pure_i2c_burst_write(uint32_t addr, uint32_t *val, uint16_t reg_num)
{

	int i;
	int ret = -1;
	u32 msg_len = 0;
	struct i2c_msg msg;
	uint8_t *data_list = NULL;

	if (!val || reg_num < 1 || !iris_pure_i2c_handle) {
		IRIS_LOGE("%s, %d: the parameter is not right\n", __func__, __LINE__);
		return -EINVAL;
	}

	memset(&msg, 0x00, sizeof(msg));

	msg_len = 5 + reg_num * 4;

	data_list = kmalloc(msg_len, GFP_KERNEL);
	if (data_list == NULL) {
		IRIS_LOGE("%s, %d: allocate memory fails\n", __func__, __LINE__);
		return -ENOMEM;
	}

	data_list[0] = 0xfc;
	data_list[1] = (addr >> 0) & 0xff;
	data_list[2] = (addr >> 8) & 0xff;
	data_list[3] = (addr >> 16) & 0xff;
	data_list[4] = (addr >> 24) & 0xff;

	for (i = 0; i < reg_num; i++) {
		data_list[i*4 + 5] = (val[i] >> 24) & 0xff;
		data_list[i*4 + 6] = (val[i] >> 16) & 0xff;
		data_list[i*4 + 7] = (val[i] >> 8) & 0xff;
		data_list[i*4 + 8] = (val[i] >> 0) & 0xff;
	}

	msg.addr = (iris_pure_i2c_handle->addr & 0xff);
	msg.flags = 0;
	msg.buf = data_list;
	msg.len = msg_len;

	ret = i2c_transfer(iris_pure_i2c_handle->adapter, &msg, 1);
	if (ret == 1) {
		ret = 0;
	} else {
		ret = ret < 0 ? ret : -EIO;
		IRIS_LOGE("%s, %d: i2c_transfer failed, write cmd, addr = 0x%08x, ret = %d\n",
			__func__, __LINE__, addr, ret);
	}

	kfree(data_list);
	data_list = NULL;
	return ret;

}

static void __iris_convert_dsi_to_i2c(uint8_t *payload, uint32_t len)
{
	uint8_t slot, gap;
	uint32_t header, address, i;
	uint32_t *pval = (uint32_t *)(payload + 1);

	header = cpu_to_le32(pval[0]);
	address = cpu_to_le32(pval[1]);
	IRIS_LOGI("%s,%d: header = 0x%08x, addr = 0x%08x", __func__, __LINE__, pval[0], pval[1]);

	if ((header & 0xf) == 0xc) {  //direct bus
		slot = (header >> 24) & 0xf;
		switch (slot) {
		case 0:
		case 1:
			header = 0x00000000;
			break;
		case 2:
			header = 0x00000000;
			address += 0xFF200000;
			break;
		case 3:
			header = 0x00000000;
			if ((address >= 0x7380) && (address < 0x1BEF0)) {
				address += 0xFF200000;
			} else if ((address >= 0x1BEF0) && (address < 0x2FDE0)) {
				address += 0xFF220000;
			} else if ((address >= 0x108000) && (address < 0x11BEF0)) {
				address += 0xFF240000;
			} else if ((address >= 0x11BEF0) && (address < 0x12FDE0)) {
				address += 0xFF260000;
			} else {
				IRIS_LOGE("%s(): invalid addr in slot 3\n", __func__);
				return;
			}
			break;
		default:
			IRIS_LOGE("%s(): invalid direct bus slot num %d\n", __func__, slot);
			return;
		}
		pval[0] = header;
		pval[1] = address;
	}

	if (pval[0] == 0xfffffff4) {
		payload[0] = 0xcc;
		gap = 2;
	} else {
		payload[0] = 0xfc;
		gap = 1;
	}

	for (i = 2; i < (len - 1)/4;) {
		pval[i] = cpu_to_be32(pval[i]);
		i += gap;
	}

	IRIS_LOGI("%s,%d: header = 0x%08x, addr = 0x%08x", __func__, __LINE__, pval[0], pval[1]);
	memcpy(&payload[1], &payload[5], len - 5);
	for (i = 0; i < len - 4; i++)
		IRIS_LOGD("%s,%d: payload[%d] = 0x%02x", __func__, __LINE__, i, payload[i]);
}

int iris_pure_i2c_multi_write(struct iris_i2c_msg *dsi_msg, uint32_t msg_num)
{

	int ret = -1;
	uint32_t i = 0;
	uint32_t byte_count = 0;
	uint32_t total_len = 0;
	struct i2c_msg *i2c_msg;

	if ((dsi_msg == NULL) || (msg_num == 0)) {
		IRIS_LOGE("%s, %d: pbuf is NULL or num = 0\n", __func__, __LINE__);
		return -EINVAL;
	}

	for (i = 0; i < msg_num; i++) {
		if (dsi_msg[i].len > I2C_MSG_MAX_LEN) {
			IRIS_LOGE("%s: msg len exceed max i2c xfer len\n", __func__);
			return -EINVAL;
		}

		total_len += dsi_msg[i].len;
		if (total_len > IRIS_I2C_BUF_LEN) {
			IRIS_LOGE("%s: total len exceed max i2c buf len\n", __func__);
			return -EINVAL;
		}
	}

	i2c_msg = vmalloc(sizeof(struct i2c_msg) * msg_num);
	if (!i2c_msg) {
		IRIS_LOGE("%s, %d: allocate memory fails\n", __func__, __LINE__);
		return -ENOMEM;
	}

	for (i = 0; i < msg_num; i++) {
		byte_count = dsi_msg[i].len;
		i2c_msg[i].buf = kmalloc(byte_count + 1, GFP_KERNEL);
		if (!i2c_msg[i].buf) {
			IRIS_LOGE("%s, %d: allocate memory fails\n", __func__, __LINE__);
			ret = -ENOMEM;
			goto error;
		}

		i2c_msg[i].addr = (iris_pure_i2c_handle->addr) & 0xff;
		i2c_msg[i].flags = 0;
		i2c_msg[i].len = byte_count + 1 - 4;
		memcpy(i2c_msg[i].buf + 1, dsi_msg[i].buf, byte_count);
		__iris_convert_dsi_to_i2c(i2c_msg[i].buf, byte_count + 1);
	}

	ret = i2c_transfer(iris_pure_i2c_handle->adapter, i2c_msg, msg_num);
	if (ret == msg_num) {
		ret = 0;
	} else {
		ret = ret < 0 ? ret : -EIO;
		IRIS_LOGE("%s: i2c_transfer failed, ret=%d\n", __func__, ret);
	}

error:
	for (i = 0; i < msg_num; i++) {
		kfree(i2c_msg[i].buf);
		i2c_msg[i].buf = NULL;
	}
	vfree(i2c_msg);
	i2c_msg = NULL;
	return ret;
}

static int iris_pure_i2c_probe(struct i2c_client *client,
		const struct i2c_device_id *dev_id)
{
	iris_pure_i2c_handle = client;
	IRIS_LOGI("%s,%d: %p\n", __func__, __LINE__, iris_pure_i2c_handle);
	return 0;
}

static void iris_pure_i2c_remove(struct i2c_client *client)
{
	iris_pure_i2c_handle = NULL;
}

static const struct i2c_device_id iris_pure_i2c_id_table[] = {
	{IRIS_PURE_I2C_DRIVER_NAME, 0},
	{},
};


static const struct of_device_id iris_pure_match_table[] = {
	{.compatible = IRIS_PURE_COMPATIBLE_NAME,},
	{ },
};

static struct i2c_driver plx_pure_i2c_driver = {
	.driver = {
		.name = IRIS_PURE_I2C_DRIVER_NAME,
		.owner = THIS_MODULE,
		.of_match_table = iris_pure_match_table,
	},
	.probe = iris_pure_i2c_probe,
	.remove =  iris_pure_i2c_remove,
	.id_table = iris_pure_i2c_id_table,
};


int iris_pure_i2c_bus_init(void)
{
	int ret;

	IRIS_LOGD("%s()\n", __func__);
	iris_pure_i2c_handle = NULL;
	ret = i2c_add_driver(&plx_pure_i2c_driver);
	if (ret != 0)
		IRIS_LOGE("iris pure i2c add driver fail: %d\n", ret);
	return 0;
}

void iris_pure_i2c_bus_exit(void)
{

	i2c_del_driver(&plx_pure_i2c_driver);
	iris_pure_i2c_remove(iris_pure_i2c_handle);
}
