// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020-2022 Oplus. All rights reserved.
 */

#define pr_fmt(fmt) "oplus_locking_strategy:" fmt

#include <linux/sched.h>
#include <linux/module.h>

#include "locking_main.h"

unsigned int g_opt_enable;
unsigned int g_opt_debug;

static int __init locking_opt_init(void)
{
	int ret = 0;

	g_opt_enable |= LK_MUTEX_ENABLE;
	g_opt_enable |= LK_RWSEM_ENABLE;
	g_opt_enable |= LK_FUTEX_ENABLE;
#ifdef CONFIG_OPLUS_LOCKING_OSQ
	g_opt_enable |= LK_OSQ_ENABLE;
#endif
#ifdef CONFIG_OPLUS_LOCKING_PIFUTEX
	g_opt_enable |= LK_PIFUTEX_ENABLE;
#endif

#ifdef CONFIG_LOCKING_PROTECT
	g_opt_enable |= LK_PROTECT_ENABLE;
	sched_assist_locking_init();
#endif
	lk_sysfs_init();
	register_rwsem_vendor_hooks();
	register_mutex_vendor_hooks();
	register_futex_vendor_hooks();
#ifdef CONFIG_OPLUS_LOCKING_PIFUTEX
	register_rtmutex_vendor_hooks();
#endif
#ifdef CONFIG_OPLUS_LOCKING_MONITOR
	kern_lstat_init();
#endif

	return ret;
}

static void __exit locking_opt_exit(void)
{
	g_opt_enable = 0;

	unregister_rwsem_vendor_hooks();
	unregister_mutex_vendor_hooks();
	unregister_futex_vendor_hooks();
#ifdef CONFIG_OPLUS_LOCKING_PIFUTEX
	unregister_rtmutex_vendor_hooks();
#endif
	lk_sysfs_exit();
#ifdef CONFIG_OPLUS_LOCKING_MONITOR
	kern_lstat_exit();
#endif
}

module_init(locking_opt_init);
module_exit(locking_opt_exit);
module_param_named(locking_enable, g_opt_enable, uint, 0660);
module_param_named(locking_debug, g_opt_debug, uint, 0660);
MODULE_DESCRIPTION("Oplus Locking Strategy Vender Hooks Driver");
MODULE_LICENSE("GPL v2");
