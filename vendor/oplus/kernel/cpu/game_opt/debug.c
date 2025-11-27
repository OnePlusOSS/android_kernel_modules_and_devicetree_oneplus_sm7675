// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 Oplus. All rights reserved.
 */

#include <uapi/linux/sched/types.h>
#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <trace/hooks/sched.h>

#include "game_ctrl.h"

#define SKIP_GAMESELF_SCHED_SETAFFINITY (1 << 0)
#define DEBUG_SCHED_SETAFFINITY_INFO (1 << 1)

int g_debug_enable = 0;
int skip_gameself_setaffinity = 0;
static DEFINE_MUTEX(d_mutex);

static noinline int tracing_mark_write(const char *buf)
{
	trace_printk(buf);
	return 0;
}

inline void systrace_c_printk(const char *msg, unsigned long val)
{
	if (g_debug_enable == 1) {
		char buf[128];
		snprintf(buf, sizeof(buf), "C|99999|%s|%lu\n", msg, val);
		tracing_mark_write(buf);
	}
}

inline void systrace_c_signed_printk(const char *msg, long val)
{
	if (g_debug_enable == 1) {
		char buf[128];
		snprintf(buf, sizeof(buf), "C|99999|%s|%ld\n", msg, val);
		tracing_mark_write(buf);
	}
}

inline void htb_systrace_c_printk(const char *prefix, int digit, const char *comm, int val)
{
	if (g_debug_enable == 1) {
		char buf[128];
		snprintf(buf, sizeof(buf), "C|99999|%s_%d_%.5s|%d\n", prefix, digit, comm, val);
		tracing_mark_write(buf);
	}
}

static ssize_t debug_enable_proc_write(struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int ret;

	ret = simple_write_to_buffer(page, sizeof(page) - 1, ppos, buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(page, "%d", &g_debug_enable);
	if (ret != 1)
		return -EINVAL;

	return count;
}

static ssize_t debug_enable_proc_read(struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int len;

	len = sprintf(page, "%d\n", g_debug_enable);

	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static const struct proc_ops debug_enable_proc_ops = {
	.proc_write		= debug_enable_proc_write,
	.proc_read		= debug_enable_proc_read,
	.proc_lseek		= default_llseek,
};

static void sched_setaffinity_early_hook(void *unused, struct task_struct *p,
	const struct cpumask *in_mask, bool *skip)
{
	if (p->tgid == game_pid) {
		if ((skip_gameself_setaffinity & SKIP_GAMESELF_SCHED_SETAFFINITY) && (current->tgid == p->tgid)) {
			*skip = true;
		}

		if ((skip_gameself_setaffinity & DEBUG_SCHED_SETAFFINITY_INFO) || (g_debug_enable == 2)) {
			pr_info("gameopt, %s: c_comm=%s, c_pid=%d, c_tgid=%d, comm=%s, pid=%d, tgid=%d, in_mask=%*pbl, cpus_ptr=%*pbl, skip=%d\n",
				__func__, current->comm, current->pid, current->tgid, p->comm, p->pid, p->tgid,
				cpumask_pr_args(in_mask), cpumask_pr_args(p->cpus_ptr), *skip ? 1: 0);
		}
	}
}

static ssize_t skip_gameself_setaffinity_proc_write(struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int ret, value;
	static bool register_trace = false;

	ret = simple_write_to_buffer(page, sizeof(page) - 1, ppos, buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(page, "%d", &value);
	if (ret != 1)
		return -EINVAL;

	mutex_lock(&d_mutex);
	skip_gameself_setaffinity = value;
	if (skip_gameself_setaffinity > 0) {
		if (!register_trace) {
			register_trace_android_vh_sched_setaffinity_early(sched_setaffinity_early_hook, NULL);
			register_trace = true;
		}
	} else {
		if (register_trace) {
			unregister_trace_android_vh_sched_setaffinity_early(sched_setaffinity_early_hook, NULL);
			register_trace = false;
		}
	}
	mutex_unlock(&d_mutex);

	return count;
}

static ssize_t skip_gameself_setaffinity_proc_read(struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int len;

	len = sprintf(page, "%d\n", skip_gameself_setaffinity);

	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static const struct proc_ops skip_gameself_setaffinity_proc_ops = {
	.proc_write		= skip_gameself_setaffinity_proc_write,
	.proc_read		= skip_gameself_setaffinity_proc_read,
	.proc_lseek		= default_llseek,
};

int debug_init(void)
{
	proc_create_data("debug_enable", 0644, game_opt_dir, &debug_enable_proc_ops, NULL);
	proc_create_data("skip_gameself_setaffinity", 0644, game_opt_dir, &skip_gameself_setaffinity_proc_ops, NULL);

	return 0;
}
