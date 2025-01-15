// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024-2030 Oplus. All rights reserved.
 */

#include <linux/mm.h>
#include <linux/jiffies.h>
#include <linux/sizes.h>
#include <linux/workqueue.h>
#include <linux/swap.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/sched/signal.h>
#include <linux/types.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/seq_file.h>
#include <linux/fdtable.h>
#include <linux/printk.h>

#include "lowmem_watcher.h"
#include "mem_stat.h"
#include "frk_netlink.h"

#define PAGES(size)	((size) >> PAGE_SHIFT)
#define K(x)		((x) << (PAGE_SHIFT - 10))

#define REPORT_INTERVAL		10 * HZ
#define REPORT_ANON_LEAK	1
#define REPORT_DMABUF_LEAK	2
#define REPORT_OTHER_LEAK	3

struct report_info {
	int report_abnormal_type;	/* memory leak type */
	int report_abnormal_size;	/* memory leak size */
	pid_t report_abnormal_pid;	/* memory leak process pid */
	int total;			/* total memory */
	int free;			/* free memory */
	int available;			/* available memory */
};

struct dmabuf_dump {
	unsigned long size;
};

struct mem_config {
	u64 report_interval;
	u64 last_report_time;
	unsigned long total_mem;
	unsigned long watermark_lowmem;
	unsigned long watermark_anon;
	unsigned long watermark_dmabuf;
};
static struct mem_config g_mem_config;

static void lowmem_report_func(struct work_struct *work);

static DECLARE_WORK(lowmem_report_work, lowmem_report_func);

static void report_to_userspace(struct report_info *info)
{
	int lowmem_report_infos[6] = { 0 };
	lowmem_report_infos[0] = info->report_abnormal_type;
	lowmem_report_infos[1] = info->report_abnormal_size;
	lowmem_report_infos[2] = info->report_abnormal_pid;
	lowmem_report_infos[3] = info->total;
	lowmem_report_infos[4] = info->free;
	lowmem_report_infos[5] = info->available;
	printk("report lowmem info to framework, abnormal_type:%d, abnormal_size:%d, abnormal_pid:%d, total:%d, free:%d, available:%d",
		info->report_abnormal_type, info->report_abnormal_size, info->report_abnormal_pid, info->total, info->free, info->available);
	send_to_frk(LOWMEM_WATCHER_EVENT, ARRAY_SIZE(lowmem_report_infos), lowmem_report_infos);
}

static struct task_struct *find_lock_task_mm(struct task_struct *p)
{
	struct task_struct *t;

	rcu_read_lock();
	for_each_thread(p, t) {
		task_lock(t);
		if (likely(t->mm))
			goto found;
		task_unlock(t);
	}
	t = NULL;
found:
	rcu_read_unlock();
	return t;
}

static void anon_usage(struct report_info *info)
{
	struct task_struct *p;
	struct task_struct *tsk;
	unsigned long task_anon_size;

	pid_t pid = 0;
	unsigned long abnormal_size = 0;

	rcu_read_lock();
	for_each_process(p) {
		tsk = find_lock_task_mm(p);
		if (!tsk) {
			continue;
		}
		task_anon_size = get_mm_counter(tsk->mm, MM_ANONPAGES);
		if (task_anon_size > abnormal_size) {
			abnormal_size = task_anon_size;
			pid = tsk->pid;
		}
		task_unlock(tsk);
	}
	rcu_read_unlock();

	info->report_abnormal_pid = pid;
	info->report_abnormal_size = K(abnormal_size);
}

static int iterate_dmabuf_cb(const void *p, struct file *file, unsigned index)
{
	struct dmabuf_dump *dump_info = (typeof(dump_info))p;
	struct dma_buf *dmabuf;

	if (!file || !file->private_data || !is_dma_buf_file(file)) {
		return 0;
	}

	dmabuf = file->private_data;
	if (!dmabuf->size) {
		return 0;
	}

	dump_info->size += dmabuf->size;
	return 0;
}

static void dmabuf_usage(struct report_info *info)
{
	struct task_struct *tsk;
	struct dmabuf_dump dump_info;

	pid_t pid = 0;
	unsigned long abnormal_size = 0;

	rcu_read_lock();
	for_each_process(tsk) {
		if (tsk->flags & PF_KTHREAD) {
			continue;
		}

		dump_info.size = 0;
		task_lock(tsk);
		iterate_fd(tsk->files, 0, iterate_dmabuf_cb, (void *)&dump_info);
		task_unlock(tsk);

		if (dump_info.size > abnormal_size) {
			abnormal_size = dump_info.size;
			pid = tsk->pid;
		}
	}
	rcu_read_unlock();
	info->report_abnormal_pid = pid;
	info->report_abnormal_size = abnormal_size / SZ_1K;
}

static int sys_dmabuf_cb(const struct dma_buf *dmabuf, void *priv)
{
	struct dmabuf_dump *dump_info = (typeof(dump_info))priv;

	dump_info->size += dmabuf->size;
	return 0;
}

static unsigned long sys_dmabuf_pages(void)
{
	struct dmabuf_dump dump_info;

	dump_info.size = 0;
	dma_buf_get_each(sys_dmabuf_cb, (void *)&dump_info);
	return dump_info.size / SZ_4K;
}

static void filling_lowmem_info(struct report_info *info)
{
	info->report_abnormal_type = 0;
	info->report_abnormal_size = 0;
	info->report_abnormal_pid = 0;
	info->total = K(g_mem_config.total_mem);
	info->free = K(sys_freeram());
	info->available = K(si_mem_available());
}

static void do_lowmem_report(struct mem_config *confg)
{
	struct sysinfo si;
	struct report_info info;
	unsigned long anon_size;
	unsigned long dmabuf_size;

	si_swapinfo(&si);
	filling_lowmem_info(&info);

	/* REPORT_ANON_LEAK */
	anon_size = sys_anon_pages();
	if ((anon_size + si.totalswap - si.freeswap) > confg->watermark_anon) {
		info.report_abnormal_type = REPORT_ANON_LEAK;
		anon_usage(&info);
		goto report;
	}

	/* REPORT_DMABUF_LEAK */
	dmabuf_size = sys_dmabuf_pages();
	if (dmabuf_size > confg->watermark_dmabuf) {
		info.report_abnormal_type = REPORT_DMABUF_LEAK;
		dmabuf_usage(&info);
		goto report;
	}

	/* REPORT_OTHER_LEAK */
	info.report_abnormal_type = REPORT_OTHER_LEAK;

report:
	report_to_userspace(&info);
}

static void lowmem_report_func(struct work_struct *work)
{
	do_lowmem_report(&g_mem_config);
}

void lowmem_report(void *ignore, int order, gfp_t gfp_flags)
{
	struct mem_config *confg = &g_mem_config;
	static atomic_t atomic_lmk = ATOMIC_INIT(0);
	long free;
	unsigned long file;
	u64 now;

	if (atomic_inc_return(&atomic_lmk) > 1) {
		goto done;
	}

	now = get_jiffies_64();
	if (time_before64(now, (confg->last_report_time + confg->report_interval))) {
		goto done;
	}

	free = sys_freeram() - sys_free_cma();
	file = sys_inactive_file() + sys_active_file();
	if (free < 0) {
		free = 0;
	}
	if (free + file > confg->watermark_lowmem) {
		goto done;
	}

	confg->last_report_time = now;
	schedule_work(&lowmem_report_work);
done:
	atomic_dec(&atomic_lmk);
}

void init_mem_confg(void)
{
	struct mem_config *confg = &g_mem_config;
	unsigned long total_mem =  totalram_pages();

	confg->total_mem = total_mem;
	confg->report_interval = REPORT_INTERVAL;
	confg->watermark_anon = total_mem / 2;
	confg->watermark_dmabuf = PAGES(SZ_2G + SZ_1G);

	if (total_mem >= PAGES(SZ_4G + SZ_8G)) {
		confg->watermark_lowmem = PAGES(SZ_1G + SZ_512M);
	} else if (total_mem >= PAGES(SZ_2G + SZ_2G)) {
		confg->watermark_lowmem = PAGES(SZ_1G);
	} else if (total_mem >= PAGES(SZ_2G + SZ_1G)) {
		confg->watermark_lowmem = PAGES(SZ_512M);
	} else {
		confg->watermark_lowmem = PAGES(SZ_512M);
	}
}
