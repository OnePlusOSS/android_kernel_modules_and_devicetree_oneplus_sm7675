// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 */
#include <linux/err.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <asm/current.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#include "fpga_exception.h"
#include "fpga_common_api.h"

#if IS_ENABLED(CONFIG_OPLUS_FEATURE_OLC)
#include <soc/oplus/dft/olc.h>

#define FPGA_MODULE_ID           0x35
#define FPGA_RESERVED_ID         256

static int fpga_olc_raise_exception(fpga_excep_type excep_tpye, void *summary, unsigned int summary_size)
{
	struct exception_info *exp_info = NULL;
	int ret = -1;
	struct timespec64 time;

	FPGA_INFO("%s:enter,type:%d\n", __func__, excep_tpye);

	exp_info = kmalloc(sizeof(struct exception_info), GFP_KERNEL);

	if (!exp_info) {
		return -ENOMEM;
	}

	if (excep_tpye > 0xfff) {
		FPGA_ERR("%s: excep_tpye:%d is beyond 0xfff\n", __func__, excep_tpye);
		goto free_exp;
	}
	ktime_get_ts64(&time);
	exp_info->time = time.tv_sec;
	exp_info->exceptionId = (FPGA_RESERVED_ID << 20) | (FPGA_MODULE_ID << 12) | excep_tpye;
	exp_info->exceptionType = EXCEPTION_KERNEL;
	exp_info->level = 0;
	exp_info->atomicLogs = LOG_KERNEL | LOG_MAIN | LOG_SYSTRACE;

	ret = olc_raise_exception(exp_info);
	if (ret) {
		FPGA_ERR("%s: raise fail, ret:%d\n", __func__, ret);
	}

free_exp:
	kfree(exp_info);
	return ret;
}
#else
static  int fpga_olc_raise_exception(fpga_excep_type excep_tpye, void *summary, unsigned int summary_size)
{
	return 0;
}
#endif /* CONFIG_OPLUS_KEVENT_UPLOAD_DELETE */

int fpga_exception_report(void *fpga_exception_data, fpga_excep_type excep_tpye, void *summary, unsigned int summary_size)
{
	int ret = -1;

	struct fpga_exception_data *exception_data = (struct fpga_exception_data *)fpga_exception_data;

	if (!exception_data) {
		return 0;
	}

	switch (excep_tpye) {
	default:
		ret = fpga_olc_raise_exception(excep_tpye, summary, summary_size);
		break;
	}

	return ret;
}
EXPORT_SYMBOL(fpga_exception_report);
