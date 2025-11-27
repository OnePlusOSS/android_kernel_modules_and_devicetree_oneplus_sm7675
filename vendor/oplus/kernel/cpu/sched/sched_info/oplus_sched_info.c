// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 Oplus. All rights reserved.
 */

#include "osi_base.h"
#include "osi_tasktrack.h"
#include "osi_hotthread.h"
#include "osi_topology.h"
#include "osi_freq.h"
#include "osi_cputime.h"
#include "osi_cpuload.h"
#include "osi_version.h"
#include "osi_enable.h"
#include "osi_debug.h"
#include "osi_cpuloadmonitor.h"
#include "osi_healthinfo.h"
#include "osi_amu.h"

#if IS_ENABLED(CONFIG_OPLUS_PERF_SCHEDINFO)
#include "perf_schedinfo.h"
#endif

static struct proc_dir_entry *d_task_info;
static struct proc_dir_entry *d_cpu_jank_info;

#if IS_ENABLED(CONFIG_OPLUS_PROCS_LOAD_STATE)
	extern int osi_procs_cpu_usage_init(void);
#endif

#ifdef CONFIG_IRQ_TIME_ACCOUNTING
void android_vh_irqtime_account_process_tick_handler(
			void *unused,
			struct task_struct *p, struct rq *rq, int user_tick, int ticks)
{
	jankinfo_update_time_info(rq, p, ticks*TICK_NSEC);
}
#else
void android_vh_account_task_time_handler(void *unused,
			struct task_struct *p, struct rq *rq, int user_tick, int ticks)
{
	jankinfo_update_time_info(rq, p, ticks*TICK_NSEC);
}
#endif

void android_vh_cpufreq_fast_switch_handler(void *unused,
			struct cpufreq_policy *policy, unsigned int *target_freq,
			unsigned int old_target_freq)
{
	osi_cpufreq_transition_handler(policy, *target_freq);
}


static int jank_register_hook(void)
{
	int ret = 0;

#ifdef CONFIG_IRQ_TIME_ACCOUNTING
	REGISTER_TRACE_VH(android_vh_irqtime_account_process_tick,
			android_vh_irqtime_account_process_tick_handler);
#else
	REGISTER_TRACE_VH(android_vh_account_task_time,
			android_vh_account_task_time_handler);
#endif

	REGISTER_TRACE_VH(android_vh_cpufreq_fast_switch,
			android_vh_cpufreq_fast_switch_handler);

	return ret;
}

static int jank_unregister_hook(void)
{
	int ret = 0;

#ifdef CONFIG_IRQ_TIME_ACCOUNTING
	UNREGISTER_TRACE_VH(android_vh_irqtime_account_process_tick,
			android_vh_irqtime_account_process_tick_handler);
#else
	UNREGISTER_TRACE_VH(android_vh_account_task_time,
			android_vh_account_task_time_handler);
#endif

	UNREGISTER_TRACE_VH(android_vh_cpufreq_fast_switch,
			android_vh_cpufreq_fast_switch_handler);

	return ret;
}

#define JANK_INFO_DIR				"jank_info"
#define JANK_INFO_PROC_NODE			"cpu_jank_info"

static int __init jank_info_init(void)
{
	struct proc_dir_entry *proc_entry;

	cluster_init();
	jank_cpuload_init();

	d_task_info = proc_mkdir(JANK_INFO_DIR, NULL);
	if (!d_task_info) {
		pr_err("create task_info fail\n");
		goto err_task_info;
	}

	d_cpu_jank_info = proc_mkdir(JANK_INFO_PROC_NODE, d_task_info);
	if (!d_cpu_jank_info) {
		pr_err("create cpu_jank_info fail\n");
		goto err_jank_info;
	}

	proc_entry = jank_enable_proc_init(d_cpu_jank_info);
	if (!proc_entry) {
		pr_err("create jank_info_enable fail\n");
		goto err_jank_info_enable;
	}


	proc_entry = jank_debug_proc_init(d_cpu_jank_info);
	if (!proc_entry) {
		pr_err("create debug fail\n");
		goto err_debug;
	}

	proc_entry = jank_tasktrack_proc_init(d_cpu_jank_info);
	if (!proc_entry) {
		pr_err("create task_track fail\n");
		goto err_task_track;
	}

	proc_entry = jank_cpuload_proc_init(d_cpu_jank_info);
	if (!proc_entry) {
		pr_err("create cpu_load fail\n");
		goto err_cpu_load;
	}

	proc_entry = jank_version_proc_init(d_cpu_jank_info);
	if (!proc_entry) {
		pr_err("create version fail\n");
		goto err_cpu_version;
	}

	proc_entry = jank_calcload_proc_init(d_cpu_jank_info);
	if (!proc_entry) {
		pr_err("create calcload fail\n");
		goto err_calcload;
	}

#if IS_ENABLED(CONFIG_OPLUS_PERF_SCHEDINFO)
	proc_entry = perf_schedinfo_init(d_cpu_jank_info);
	if (!proc_entry) {
		pr_err("create cpu perf schedinfo fail\n");
		goto err_perf_schedinfo;
	}
#endif

	osi_hotthread_proc_init(d_cpu_jank_info);
	osi_base_proc_init(d_cpu_jank_info);
	osi_freq_init(d_cpu_jank_info);
	jank_register_hook();
	tasktrack_init();
	jank_calcload_init();
	oplus_healthinfo_proc_fs_init();

#if IS_ENABLED(CONFIG_OPLUS_PROCS_LOAD_STATE)
	osi_procs_cpu_usage_init();
#endif

	return 0;

#if IS_ENABLED(CONFIG_OPLUS_PERF_SCHEDINFO)
err_perf_schedinfo:
	perf_schedinfo_exit(d_cpu_jank_info);
#endif

err_calcload:
	jank_calcload_proc_deinit(d_cpu_jank_info);

err_cpu_version:
	jank_version_proc_deinit(d_cpu_jank_info);

err_cpu_load:
	jank_cpuload_proc_deinit(d_cpu_jank_info);

err_task_track:
	jank_tasktrack_proc_deinit(d_cpu_jank_info);

err_debug:
	jank_debug_proc_deinit(d_cpu_jank_info);

err_jank_info_enable:
	jank_enable_proc_deinit(d_cpu_jank_info);

err_jank_info:
	remove_proc_entry(JANK_INFO_PROC_NODE, d_task_info);

err_task_info:
	remove_proc_entry(JANK_INFO_DIR, NULL);
	return -ENOMEM;
}

void __exit __maybe_unused jank_info_exit(void)
{
	jank_unregister_hook();
	tasktrack_deinit();
	jank_calcload_exit();

	jank_calcload_proc_deinit(d_cpu_jank_info);
	jank_version_proc_deinit(d_cpu_jank_info);
	jank_cpuload_proc_deinit(d_cpu_jank_info);
	osi_hotthread_proc_deinit(d_cpu_jank_info);
	osi_freq_exit(d_cpu_jank_info);
	jank_tasktrack_proc_deinit(d_cpu_jank_info);
	jank_debug_proc_deinit(d_cpu_jank_info);
	jank_enable_proc_deinit(d_cpu_jank_info);

	remove_proc_entry(JANK_INFO_PROC_NODE, d_task_info);
	remove_proc_entry(JANK_INFO_DIR, NULL);
	oplus_healthinfo_proc_fs_exit();
}

module_init(jank_info_init);
module_exit(jank_info_exit);

MODULE_DESCRIPTION("oplus_schedinfo");
MODULE_LICENSE("GPL v2");

