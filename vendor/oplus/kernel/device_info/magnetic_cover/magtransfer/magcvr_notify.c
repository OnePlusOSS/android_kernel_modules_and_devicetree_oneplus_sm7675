/***
  notify for other driver
**/

/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "magcvr_notify.h"

static int g_magcvr_current_pos = -1;

static BLOCKING_NOTIFIER_HEAD(magcvr_notifier_list);

int magcvr_event_register_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&magcvr_notifier_list, nb);
}
EXPORT_SYMBOL(magcvr_event_register_notifier);

int magcvr_event_unregister_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&magcvr_notifier_list, nb);
}
EXPORT_SYMBOL(magcvr_event_unregister_notifier);

int magcvr_event_call_notifier(unsigned long action, void *data)
{
	blocking_notifier_call_chain(&magcvr_notifier_list, action, data);
	return 0;
}
EXPORT_SYMBOL(magcvr_event_call_notifier);

void magcvr_set_current_pos(int magcvr_pos)
{
	g_magcvr_current_pos = magcvr_pos;
}
EXPORT_SYMBOL(magcvr_set_current_pos);

int magcvr_get_current_pos(void)
{
	return g_magcvr_current_pos;
}
EXPORT_SYMBOL(magcvr_get_current_pos);

MODULE_DESCRIPTION("magcvr Event Notify Driver");
MODULE_LICENSE("GPL");
