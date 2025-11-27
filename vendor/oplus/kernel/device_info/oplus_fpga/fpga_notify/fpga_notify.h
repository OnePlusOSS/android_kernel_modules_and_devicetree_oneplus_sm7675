// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 */

#ifndef _FPGA_NOTIFY_H
#define _FPGA_NOTIFY_H

enum fpga_notifier_tag {
	FPGA_NONE,
	FPGA_RST_START,
	FPGA_RST_END,
	FPGA_POWER_ON_START,
	FPGA_POWER_ON_END,
	FPGA_GEN_HWRST,
	FPGA_GEN_SWRST,
	FPGA_GEN_ERRCODE
};

/* caller API */
int fpga_register_notifier(struct notifier_block *nb);
int fpga_unregister_notifier(struct notifier_block *nb);

/* callee API */
void fpga_call_notifier(unsigned long action, void *data);

#endif /* _FPGA_NOTIFY_H */
