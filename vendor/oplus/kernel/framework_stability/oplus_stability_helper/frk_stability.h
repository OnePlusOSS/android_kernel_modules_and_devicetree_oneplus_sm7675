/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2022 Oplus. All rights reserved.
 */

#ifndef __OPLUS_FRK_STABILITY_H__
#define __OPLUS_FRK_STABILITY_H__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/genetlink.h>

#define REGISTER_TRACE_VH(vender_hook, handler) { \
		ret = register_trace_android_vh_##vender_hook(handler, NULL); \
		if (ret) { \
			pr_err("failed to register_trace_"#vender_hook", ret=%d\n", ret); \
			return ret; \
		} \
	}

#define UNREGISTER_TRACE_VH(vender_hook, handler) { \
		unregister_trace_android_vh_##vender_hook(handler, NULL); \
	}


#define SYSTEM_UID	1000
#define binder_watcher_debug(x...) \
	do { \
		printk_ratelimited(x); \
	} while (0)

#define thread_watcher_debug(x...) \
	do { \
		printk_ratelimited(x); \
	} while (0)

#endif  /* endif */
