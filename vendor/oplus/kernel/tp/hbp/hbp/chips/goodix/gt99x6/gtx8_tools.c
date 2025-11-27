// SPDX-License-Identifier: GPL-2.0-only
/*
 * Goodix Touchscreen Driver
 * Copyright (C) 2020 - 2021 Goodix, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be a reference
 * to you, when you are integrating the GOODiX's CTP IC into your system,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/ioctl.h>

#include "gt99x6_core.h"

#include "../../../utils/debug.h"


#define GOODIX_TOOLS_NAME "gtp_tools"
#define GOODIX_TOOLS_VER_MAJOR 1
#define GOODIX_TOOLS_VER_MINOR 0
static const u16 goodix_tools_ver =
	((GOODIX_TOOLS_VER_MAJOR << 8) + (GOODIX_TOOLS_VER_MINOR));

#define GOODIX_TS_IOC_MAGIC 'G'
#define NEGLECT_SIZE_MASK (~(_IOC_SIZEMASK << _IOC_SIZESHIFT))

#define GTP_IRQ_ENABLE _IO(GOODIX_TS_IOC_MAGIC, 0)
#define GTP_DEV_RESET _IO(GOODIX_TS_IOC_MAGIC, 1)
#define GTP_SEND_COMMAND (_IOW(GOODIX_TS_IOC_MAGIC, 2, u8) & NEGLECT_SIZE_MASK)
#define GTP_SEND_CONFIG (_IOW(GOODIX_TS_IOC_MAGIC, 3, u8) & NEGLECT_SIZE_MASK)
#define GTP_ASYNC_READ (_IOR(GOODIX_TS_IOC_MAGIC, 4, u8) & NEGLECT_SIZE_MASK)
#define GTP_SYNC_READ (_IOR(GOODIX_TS_IOC_MAGIC, 5, u8) & NEGLECT_SIZE_MASK)
#define GTP_ASYNC_WRITE (_IOW(GOODIX_TS_IOC_MAGIC, 6, u8) & NEGLECT_SIZE_MASK)
#define GTP_READ_CONFIG (_IOW(GOODIX_TS_IOC_MAGIC, 7, u8) & NEGLECT_SIZE_MASK)
#define GTP_ESD_ENABLE _IO(GOODIX_TS_IOC_MAGIC, 8)
#define GTP_TOOLS_VER (_IOR(GOODIX_TS_IOC_MAGIC, 9, u8) & NEGLECT_SIZE_MASK)
#define GTP_TOOLS_CTRL_SYNC \
	(_IOW(GOODIX_TS_IOC_MAGIC, 10, u8) & NEGLECT_SIZE_MASK)

#define MAX_BUF_LENGTH (16 * 1024)

#define I2C_MSG_HEAD_LEN 20

/* read data asynchronous,
 * success return data length, otherwise return < 0
 */
static int async_read(struct gt_core *ts_core, void __user *arg)
{
	u8 *databuf = NULL;
	int ret = 0;
	u32 reg_addr, length;
	u8 i2c_msg_head[I2C_MSG_HEAD_LEN];
	const struct goodix_thp_hw_ops *hw_ops = ts_core->hw_ops;

	ret = copy_from_user(&i2c_msg_head, arg, I2C_MSG_HEAD_LEN);
	if (ret)
		return -EFAULT;

	reg_addr = i2c_msg_head[0] + (i2c_msg_head[1] << 8) +
		   (i2c_msg_head[2] << 16) + (i2c_msg_head[3] << 24);
	length = i2c_msg_head[4] + (i2c_msg_head[5] << 8) +
		 (i2c_msg_head[6] << 16) + (i2c_msg_head[7] << 24);
	if (length > MAX_BUF_LENGTH) {
		hbp_err("buffer too long:%d > %d\n", length, MAX_BUF_LENGTH);
		return -EINVAL;
	}
	databuf = kzalloc(length, GFP_KERNEL);
	if (!databuf)
		return -ENOMEM;

	if (hw_ops->read(ts_core, reg_addr, databuf, length)) {
		ret = -EBUSY;
		hbp_err("Read i2c failed\n");
		goto err_out;
	}
	ret = copy_to_user((u8 *)arg + I2C_MSG_HEAD_LEN, databuf, length);
	if (ret) {
		ret = -EFAULT;
		hbp_err("Copy_to_user failed\n");
		goto err_out;
	}
	ret = length;
err_out:
	kfree(databuf);
	return ret;
}

/* write data to i2c asynchronous,
 * success return bytes write, else return <= 0
 */
static int async_write(struct gt_core *ts_core, void __user *arg)
{
	u8 *databuf;
	int ret = 0;
	u32 reg_addr, length;
	u8 i2c_msg_head[I2C_MSG_HEAD_LEN];
	const struct goodix_thp_hw_ops *hw_ops = ts_core->hw_ops;

	ret = copy_from_user(&i2c_msg_head, arg, I2C_MSG_HEAD_LEN);
	if (ret) {
		hbp_err("Copy data from user failed\n");
		return -EFAULT;
	}
	reg_addr = i2c_msg_head[0] + (i2c_msg_head[1] << 8) +
		   (i2c_msg_head[2] << 16) + (i2c_msg_head[3] << 24);
	length = i2c_msg_head[4] + (i2c_msg_head[5] << 8) +
		 (i2c_msg_head[6] << 16) + (i2c_msg_head[7] << 24);
	if (length > MAX_BUF_LENGTH) {
		hbp_err("buffer too long:%d > %d\n", length, MAX_BUF_LENGTH);
		return -EINVAL;
	}

	databuf = kzalloc(length, GFP_KERNEL);
	if (!databuf)
		return -ENOMEM;

	ret = copy_from_user(databuf, (u8 *)arg + I2C_MSG_HEAD_LEN, length);
	if (ret) {
		ret = -EFAULT;
		hbp_err("Copy data from user failed\n");
		goto err_out;
	}

	if (hw_ops->write(ts_core, reg_addr, databuf, length)) {
		ret = -EBUSY;
		hbp_err("Write data to device failed\n");
	} else {
		ret = length;
	}

err_out:
	kfree(databuf);
	return ret;
}

/**
 * goodix_tools_ioctl - ioctl implementation
 *
 * @filp: Pointer to file opened
 * @cmd: Ioctl opertion command
 * @arg: Command data
 * Returns >=0 - succeed, else failed
 */
static long goodix_tools_ioctl(struct file *filp, unsigned int cmd,
			       unsigned long arg)
{
	int ret = 0;
	struct gt_core *ts_core = container_of(
		filp->private_data, struct gt_core, tool_misc_dev);
	const struct goodix_thp_hw_ops *hw_ops = ts_core->hw_ops;
    u8 val;

	if (_IOC_TYPE(cmd) != GOODIX_TS_IOC_MAGIC) {
		hbp_err("Bad magic num:%c\n", _IOC_TYPE(cmd));
		return -ENOTTY;
	}

	switch (cmd & NEGLECT_SIZE_MASK) {
	case GTP_IRQ_ENABLE:
		if (arg == 1) {
			// hw_ops->irq_enable(ts_core, true);
			hbp_info("IRQ enabled\n");
		} else if (arg == 0) {
			// hw_ops->irq_enable(ts_core, false);
			hbp_info("IRQ disabled\n");
		} else {
			hbp_info("Irq aready set with, arg = %ld\n", arg);
		}
		ret = 0;
		break;
	case GTP_ESD_ENABLE:
        hbp_err("not support esd in HBP4.0\n");
        ret = -EINVAL;
		break;
	case GTP_DEV_RESET:
		// hw_ops->reset(ts_core, 100);
        val = 0;
        hw_ops->write(ts_core, 0xD808, &val, 1);
		break;
	case GTP_SEND_COMMAND:
		/* deprecated command */
		hbp_err("the GTP_SEND_COMMAND function has been removed\n");
		ret = -EINVAL;
		break;
	case GTP_SEND_CONFIG:
        hbp_err("remove send config\n");
        ret = -EINVAL;
		break;
	case GTP_READ_CONFIG:
        hbp_err("remove read config\n");
        ret = -EINVAL;
		break;
	case GTP_ASYNC_READ:
		ret = async_read(ts_core, (void __user *)arg);
		if (ret < 0)
			hbp_err("Async data read failed\n");
		break;
	case GTP_SYNC_READ:
		hbp_info("unsupport sync read\n");
		break;
	case GTP_ASYNC_WRITE:
		ret = async_write(ts_core, (void __user *)arg);
		if (ret < 0)
			hbp_err("Async data write failed\n");
		break;
	case GTP_TOOLS_VER:
		ret = copy_to_user((u8 *)arg, &goodix_tools_ver, sizeof(u16));
		if (ret)
			hbp_err("failed copy driver version info to user\n");
		break;
	case GTP_TOOLS_CTRL_SYNC:
        hbp_info("unsupport ctrl sync\n");
		break;
	default:
		hbp_err("Invalid cmd\n");
		ret = -ENOTTY;
		break;
	}

//err_out:
	return ret;
}

#ifdef CONFIG_COMPAT
static long goodix_tools_compat_ioctl(struct file *file, unsigned int cmd,
				      unsigned long arg)
{
	void __user *arg32 = compat_ptr(arg);

	if (!file->f_op || !file->f_op->unlocked_ioctl)
		return -ENOTTY;
	return file->f_op->unlocked_ioctl(file, cmd, (unsigned long)arg32);
}
#endif

static int goodix_tools_open(struct inode *inode, struct file *filp)
{
	hbp_info("success open tools\n");
	return 0;
}

static int goodix_tools_release(struct inode *inode, struct file *filp)
{
    hbp_info("release tools\n");
	return 0;
}

static const struct file_operations goodix_tools_fops = {
	.open = goodix_tools_open,
	.release = goodix_tools_release,
	.unlocked_ioctl = goodix_tools_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = goodix_tools_compat_ioctl,
#endif
};

/**
 * goodix_tools_init - init goodix tools device and register a miscdevice
 *
 * return: 0 success, else failed
 */
int gt_tools_init(struct gt_core *core_data)
{
	struct miscdevice *miscdev = &core_data->tool_misc_dev;
	int ret;

	if (core_data->board_data.chip_type == GT9966 || core_data->board_data.chip_type == GT9926)
		sprintf(core_data->tool_misc_dev_name, "%s", GOODIX_TOOLS_NAME);
	else
		sprintf(core_data->tool_misc_dev_name, "%s.1", GOODIX_TOOLS_NAME);

	miscdev->minor = MISC_DYNAMIC_MINOR;
	miscdev->name = core_data->tool_misc_dev_name;
	miscdev->fops = &goodix_tools_fops;
	ret = misc_register(miscdev);
	if (ret)
		hbp_err("Debug tools miscdev register failed\n");
	else
		hbp_info("Debug tools miscdev register success\n");

	return ret;
}

void gt_tools_exit(struct gt_core *core_data)
{
	struct miscdevice *miscdev = &core_data->tool_misc_dev;

	misc_deregister(miscdev);
	hbp_info("Debug tools miscdev exit\n");
}
