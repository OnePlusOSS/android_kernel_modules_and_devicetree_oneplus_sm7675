/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 */

#ifndef _FPGA_HEALTHONFO_
#define _FPGA_HEALTHONFO_

#define KEVENT_LOG_TAG              "psw_bsp_tp"
#define KEVENT_EVENT_ID             "tp_fatal_report"

#define FPGA_FB_REG_ERR_TYPE        "10001"
#define FPGA_FB_BUS_TRANS_TYPE      "10002"

typedef enum {
	HEALTH_INTERF = 1,
	HEALTH_IRQ_DATA,
	HEALTH_STATE_COUNT,
} healthinfo_type;

struct monitor_data {
	void  *chip_data; /*debug info data*/
	bool health_monitor_support;
};

int fpga_healthinfo_report(void *data, healthinfo_type type,
			   void *value);

int fpga_healthinfo_read(struct seq_file *s, void *data);

int fpga_healthinfo_clear(void *data);

int fpga_healthinfo_init(struct device *dev, void *data);

void fpga_kevent_fb(char *payload, unsigned int payload_size, const char *event_id, char *str, int ret);

#endif /* _FPGA_HEALTHONFO_ */
