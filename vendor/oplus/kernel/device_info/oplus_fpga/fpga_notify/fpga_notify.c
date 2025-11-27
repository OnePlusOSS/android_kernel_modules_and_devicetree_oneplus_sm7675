// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 */

#include <linux/module.h>
#include <linux/export.h>
#include <linux/notifier.h>
#include "fpga_notify.h"

static BLOCKING_NOTIFIER_HEAD(fpga_notifier_list);

int fpga_register_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&fpga_notifier_list, nb);
}
EXPORT_SYMBOL(fpga_register_notifier);

int fpga_unregister_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&fpga_notifier_list, nb);
}
EXPORT_SYMBOL(fpga_unregister_notifier);

void fpga_call_notifier(unsigned long action, void *data)
{
	blocking_notifier_call_chain(&fpga_notifier_list, action, data);
}
EXPORT_SYMBOL(fpga_call_notifier);

MODULE_DESCRIPTION("FPGA Notify Driver");
MODULE_LICENSE("GPL");
