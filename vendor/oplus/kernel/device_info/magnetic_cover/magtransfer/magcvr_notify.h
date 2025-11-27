// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 */

#ifndef _MAGCVR_EVENTNOTIFY_H
#define _MAGCVR_EVENTNOTIFY_H

#define EVENT_ACTION_FOR_MAGCVR 0x01

enum MAGCVR_CALL_PARA {
	MAGCVR_CALL_FAR  = 0,
	MAGCVR_CALL_NEAR = 1,
	MAGCVR_CALL_IIC_FAIL = 100,
	MAGCVR_CALL_IC_FAIL  = 101,
};

#include <linux/module.h>
#include <linux/export.h>
#include <linux/notifier.h>

struct magcvr_notify_event {
	int type;
};

/* caller API */
int magcvr_event_register_notifier(struct notifier_block *nb);
int magcvr_event_unregister_notifier(struct notifier_block *nb);
int magcvr_event_call_notifier(unsigned long action, void *data);
void magcvr_set_current_pos(int magcvr_pos);
int magcvr_get_current_pos(void);

#endif /* _MAGCVR_EVENTNOTIFY_H */
