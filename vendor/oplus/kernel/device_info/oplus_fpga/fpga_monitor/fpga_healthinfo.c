// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 */

#include <linux/err.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/ktime.h>
#include <asm/current.h>
#include <linux/version.h>
#include <linux/seq_file.h>

#include "fpga_healthinfo.h"
#include "fpga_common_api.h"

#if defined(CONFIG_OPLUS_FEATURE_FEEDBACK) || defined(CONFIG_OPLUS_FEATURE_FEEDBACK_MODULE)
#include <soc/oplus/system/kernel_fb.h>

void fpga_kevent_fb(char *payload, unsigned int payload_size, const char *event_id, char *str, int ret)
{
	memset(payload, 0, payload_size);

#if defined(CONFIG_OPLUS_FEATURE_FEEDBACK) || defined(CONFIG_OPLUS_FEATURE_FEEDBACK_MODULE)
	scnprintf(payload, sizeof(payload_size), str, ret);
	oplus_kevent_fb(FB_TRI_STATE_KEY, event_id, payload);
#endif
	return;
}
#else
void fpga_kevent_fb(char *payload, unsigned int payload_size, const char *event_id, char *str, int ret)
{
	return;
}
#endif

int fpga_healthinfo_report(void *data, healthinfo_type type,
			   void *value)
{
	struct monitor_data *p_monitor_data = (struct monitor_data *)data;

	if (!p_monitor_data || !p_monitor_data->health_monitor_support) {
		FPGA_ERR("data is null!\n");
		return -EINVAL;
	}
	/*
	    switch (type) {
	    default:
	        break;
	    }
	*/
	return 0;
}
EXPORT_SYMBOL(fpga_healthinfo_report);

int fpga_healthinfo_read(struct seq_file *s, void *data)
{
	struct monitor_data *p_monitor_data = (struct monitor_data *)data;

	if (!p_monitor_data || !p_monitor_data->health_monitor_support) {
		FPGA_ERR("data is null!\n");
		return -EINVAL;
	}

	return 0;
}

int fpga_healthinfo_clear(void *data)
{
	struct monitor_data *p_monitor_data = (struct monitor_data *)data;

	if (!p_monitor_data || !p_monitor_data->health_monitor_support) {
		FPGA_ERR("data is null!\n");
		return -EINVAL;
	}

	FPGA_INFO("Clear health info Now!\n");


	FPGA_INFO("Clear health info Finish!\n");

	return 0;
}

int fpga_healthinfo_init(struct device *dev, void *data)
{
	struct monitor_data *p_monitor_data = (struct monitor_data *)data;

	if (!p_monitor_data || !p_monitor_data->health_monitor_support) {
		FPGA_ERR("data is null!\n");
		return -EINVAL;
	}
	return 0;
}
