// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Oplus. All rights reserved.
 */

#include <linux/cpu.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/cpufreq.h>
#include <linux/cpumask.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/syscore_ops.h>
#include <trace/hooks/cpufreq.h>

#include "game_ctrl.h"

struct tracked_task {
	struct task_struct *task;
	pid_t pid;
	bool running;
};
struct tracked_task active_tasks[MAX_TRACKED_TASK_NUM];
struct tracked_task tracked_tasks[MAX_TRACKED_TASK_NUM];
static int tracked_task_num = 0;

struct sched_cluster_info {
	int cpu;
	struct cpumask related_cpus;

	u64 curr_window_exec;
	u64 curr_window_scale;
	u64 prev_window_exec;
	u64 prev_window_scale;

	int window_busy;
	int window_util;
} sched_clusters[MAX_SCHED_CLUSTER_NUM];
static int cluster_num = 0;

struct frame_group_info {
	u64 window_start;
	u64 mark_start;
	int nr_running;
	struct cpumask running_cpumask;

	u64 curr_window_exec;
	u64 curr_window_scale;
	u64 prev_window_exec;
	u64 prev_window_scale;

	int window_busy;
	int window_util;
} frame_group;

#define FPS_120_WINDOW_SIZE 8333333 /* ns */
static u64 std_window_size = FPS_120_WINDOW_SIZE;

static bool frame_load_track_enable = false;

static DEFINE_RAW_SPINLOCK(fl_raw_spinlock);
static DEFINE_MUTEX(fl_mutex);

static struct proc_dir_entry *frame_load_track_dir = NULL;
static void frame_load_init_delay(void);

/*----------- frame group clock ------------------*/
static ktime_t ktime_last;
static bool fg_ktime_suspended;

u64 fg_ktime_get_ns(void)
{
	if (unlikely(fg_ktime_suspended))
		return ktime_to_ns(ktime_last);

	return ktime_get_ns();
}

static void fg_resume(void)
{
	fg_ktime_suspended = false;
}

static int fg_suspend(void)
{
	ktime_last = ktime_get();
	fg_ktime_suspended = true;
	return 0;
}

static struct syscore_ops fg_syscore_ops = {
	.resume		= fg_resume,
	.suspend	= fg_suspend
};
/*----------- frame group clock ------------------*/

static void build_sched_cluster_info(void)
{
	int i, j;
	struct cpufreq_policy policy;
	struct cpumask temp_mask;

	cpumask_copy(&temp_mask, cpu_present_mask);

	for_each_cpu(i, &temp_mask) {
		if (unlikely(cpufreq_get_policy(&policy, i)))
			continue;

		for_each_cpu(j, policy.related_cpus)
			cpumask_clear_cpu(j, &temp_mask);

		sched_clusters[cluster_num].cpu = policy.cpu;
		cpumask_copy(&sched_clusters[cluster_num].related_cpus, policy.related_cpus);

		printk("frame_load: cluster_num=%d, cpu=%d\n", cluster_num, policy.cpu);

		cluster_num++;
		if (unlikely(cluster_num >= MAX_SCHED_CLUSTER_NUM))
			break;
	}
}

#define DIV64_U64_ROUNDUP(X, Y) div64_u64((X) + (Y - 1), Y)
static inline u64 scale_exec_time(u64 delta, int cpu)
{
	u64 task_exec_scale;
	struct cpufreq_policy *policy = cpufreq_cpu_get_raw(cpu);

	if (unlikely(policy == NULL))
		return delta;

	task_exec_scale = DIV64_U64_ROUNDUP(policy->cur *
				arch_scale_cpu_capacity(cpu),
				policy->cpuinfo.max_freq);

	return (delta * task_exec_scale) >> 10;
}

void add_tasks_to_frame_group(pid_t *tracked_pids, int tracked_pid_num)
{
	int i, j;
	struct task_struct *task;
	unsigned long flags;

	if (!frame_load_track_enable)
		return;

	if (unlikely(tracked_pid_num > MAX_TRACKED_TASK_NUM))
		return;

	mutex_lock(&fl_mutex);
	if (!frame_load_track_enable)
		goto unlock_mutex;

	for (i = 0, j = 0; i < tracked_pid_num; i++) {
		rcu_read_lock();
		task = find_task_by_vpid(tracked_pids[i]);
		if (task) {
			active_tasks[j].task = task;
			active_tasks[j].pid = tracked_pids[i];
			j++;
		}
		rcu_read_unlock();
	}

	raw_spin_lock_irqsave(&fl_raw_spinlock, flags);

	tracked_task_num = j;
	frame_group.nr_running = 0;
	cpumask_clear(&frame_group.running_cpumask);

	frame_group.curr_window_exec = 0;
	frame_group.curr_window_scale = 0;
	for (i = 0; i < cluster_num; i++) {
		struct sched_cluster_info * cluster = &sched_clusters[i];
		cluster->curr_window_exec = 0;
		cluster->curr_window_scale = 0;
	}
	for (i = 0; i < tracked_task_num; i++) {
		tracked_tasks[i].task = active_tasks[i].task;
		tracked_tasks[i].pid = active_tasks[i].pid;
		tracked_tasks[i].running = false;
	}

	raw_spin_unlock_irqrestore(&fl_raw_spinlock, flags);

unlock_mutex:
	mutex_unlock(&fl_mutex);
}

static void update_frame_group_load(u64 wallclock)
{
	int i;
	struct cpumask temp_mask;
	u64 delta_exec, exec_scale, max_exec_scale = 0;

	/* lockdep_assert_held(&fl_raw_spinlock); */

	if (unlikely(wallclock <= frame_group.mark_start))
		return;

	delta_exec = wallclock - frame_group.mark_start;

	for (i = 0; i < cluster_num; i++) {
		struct sched_cluster_info *cluster = &sched_clusters[i];

		if (cpumask_and(&temp_mask, &cluster->related_cpus, &frame_group.running_cpumask)) {
			exec_scale = scale_exec_time(delta_exec, cluster->cpu);
			cluster->curr_window_exec += delta_exec;
			cluster->curr_window_scale += exec_scale;

			if (g_debug_enable == 1) {
				char buf[64];
				snprintf(buf, sizeof(buf), "cluster%d_exec\n", i);
				systrace_c_printk(buf, cluster->curr_window_exec);
				snprintf(buf, sizeof(buf), "cluster%d_scale\n", i);
				systrace_c_printk(buf, cluster->curr_window_scale);
			}

			if (exec_scale > max_exec_scale)
				max_exec_scale = exec_scale;
		}
	}

	frame_group.curr_window_exec += delta_exec;
	frame_group.curr_window_scale += max_exec_scale;

	systrace_c_printk("frame_exec", frame_group.curr_window_exec);
	systrace_c_printk("frame_scale", frame_group.curr_window_scale);
}

static inline struct tracked_task* get_tracked_task(struct task_struct *task)
{
	int i;

	/* lockdep_assert_held(&fl_raw_spinlock); */

	for (i = 0; i < tracked_task_num; i++) {
		if ((tracked_tasks[i].task == task) && (tracked_tasks[i].pid == task->pid))
			return &tracked_tasks[i];
	}

	return NULL;
}

static void frame_sched_switch(void *data, bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state)
{
	unsigned long flags;
	struct tracked_task* prev_tracked_task;
	struct tracked_task* next_tracked_task;
	u64 wallclock;

	if (!frame_load_track_enable)
		return;

	if ((prev->tgid != game_pid) && (next->tgid != game_pid))
		return;

	raw_spin_lock_irqsave(&fl_raw_spinlock, flags);
	if (!frame_load_track_enable)
		goto unlock_raw_spin;

	prev_tracked_task = get_tracked_task(prev);
	next_tracked_task = get_tracked_task(next);

	if (!prev_tracked_task && !next_tracked_task)
		goto unlock_raw_spin;

	if ((prev_tracked_task && !prev_tracked_task->running) && !next_tracked_task)
		goto unlock_raw_spin;

	if ((prev_tracked_task && prev_tracked_task->running) && next_tracked_task) {
		prev_tracked_task->running = false;
		next_tracked_task->running = true;
		goto unlock_raw_spin;
	}

	wallclock = fg_ktime_get_ns();

	if (frame_group.nr_running > 0)
		update_frame_group_load(wallclock);

	if (prev_tracked_task && prev_tracked_task->running) {
		prev_tracked_task->running = false;
		frame_group.nr_running--;
		cpumask_clear_cpu(task_cpu(prev), &frame_group.running_cpumask);
	}

	if (next_tracked_task) {
		next_tracked_task->running = true;
		frame_group.nr_running++;
		cpumask_set_cpu(task_cpu(prev), &frame_group.running_cpumask);
	}

	if (frame_group.nr_running > 0)
		frame_group.mark_start = wallclock;

	systrace_c_printk("nr_running", frame_group.nr_running);

unlock_raw_spin:
	raw_spin_unlock_irqrestore(&fl_raw_spinlock, flags);
}

static void frame_android_vh_cpufreq_fast_switch(void *data, struct cpufreq_policy *policy,
		unsigned int *target_freq, unsigned int old_target_freq)
{
	unsigned long flags;
	u64 wallclock;

	if (!frame_load_track_enable)
		return;

	raw_spin_lock_irqsave(&fl_raw_spinlock, flags);
	if (!frame_load_track_enable)
		goto unlock_raw_spin;

	wallclock = fg_ktime_get_ns();

	if (frame_group.nr_running > 0) {
		update_frame_group_load(wallclock);
		frame_group.mark_start = wallclock;
	}

unlock_raw_spin:
	raw_spin_unlock_irqrestore(&fl_raw_spinlock, flags);
}

static void rollover_frame_group_window(void)
{
	u64 wallclock = fg_ktime_get_ns();
	u64 window_size;
	int i, util;
	unsigned long flags;

	raw_spin_lock_irqsave(&fl_raw_spinlock, flags);

	if (unlikely(wallclock <= frame_group.window_start))
		goto out;

	window_size = wallclock - frame_group.window_start;

	if (frame_group.nr_running > 0) {
		update_frame_group_load(wallclock);
		frame_group.mark_start = wallclock;
	}

	systrace_c_printk("window_start", 1);
	systrace_c_printk("window_start", 0);
	systrace_c_printk("window_size", window_size);

	for (i = 0; i < cluster_num; i++) {
		struct sched_cluster_info * cluster = &sched_clusters[i];

		cluster->prev_window_exec = cluster->curr_window_exec;
		cluster->curr_window_exec = 0;
		cluster->prev_window_scale = cluster->curr_window_scale;
		cluster->curr_window_scale = 0;
		cluster->window_busy = (cluster->prev_window_exec * 100) / window_size;
		util = div_u64((cluster->prev_window_scale << SCHED_CAPACITY_SHIFT), std_window_size);
		cluster->window_util = util > 1024 ? 1024 : util;

		if (g_debug_enable == 1) {
			char buf[64];
			snprintf(buf, sizeof(buf), "cluster%d_exec\n", i);
			systrace_c_printk(buf, 0);
			snprintf(buf, sizeof(buf), "cluster%d_scale\n", i);
			systrace_c_printk(buf, 0);
			snprintf(buf, sizeof(buf), "cluster%d_busy\n", i);
			systrace_c_printk(buf, cluster->window_busy);
			snprintf(buf, sizeof(buf), "cluster%d_util\n", i);
			systrace_c_printk(buf, cluster->window_util);
		}
	}

	frame_group.prev_window_exec = frame_group.curr_window_exec;
	frame_group.curr_window_exec = 0;
	frame_group.prev_window_scale = frame_group.curr_window_scale;
	frame_group.curr_window_scale = 0;
	frame_group.window_busy = (frame_group.prev_window_exec * 100) / window_size;
	util = div_u64((frame_group.prev_window_scale << SCHED_CAPACITY_SHIFT), std_window_size);
	frame_group.window_util = util > 1024 ? 1024 : util;

	systrace_c_printk("frame_exec", 0);
	systrace_c_printk("frame_scale", 0);
	systrace_c_printk("frame_busy", frame_group.window_busy);
	systrace_c_printk("frame_util", frame_group.window_util);

out:
	frame_group.window_start = wallclock;

	raw_spin_unlock_irqrestore(&fl_raw_spinlock, flags);
}

static char frame_load_buf[256];
static ssize_t flb_len;
static bool frame_load_is_ready = false;

static void read_frame_load_data(void)
{
	int i;

	rollover_frame_group_window();

	memset(frame_load_buf, 0, sizeof(frame_load_buf));
	flb_len = 0;

	flb_len = snprintf(frame_load_buf, sizeof(frame_load_buf), "%d %d\n",
			frame_group.window_busy, frame_group.window_util);

	for (i = 0; i < cluster_num; i++) {
		struct sched_cluster_info * cluster = &sched_clusters[i];
		flb_len += snprintf(frame_load_buf + flb_len, sizeof(frame_load_buf) - flb_len, "%d %d\n",
			cluster->window_busy, cluster->window_util);
	}
}

void fl_notify_frame_produce(void)
{
	if (!frame_load_track_enable)
		return;

	mutex_lock(&fl_mutex);
	if (!frame_load_track_enable)
		goto unlock_mutex;

	read_frame_load_data();
	frame_load_is_ready = true;

unlock_mutex:
	mutex_unlock(&fl_mutex);
}

static int frame_load_show(struct seq_file *m, void *v)
{
	mutex_lock(&fl_mutex);

	if (!frame_load_is_ready)
		read_frame_load_data();
	frame_load_is_ready = false;

	if (flb_len > 0)
		seq_puts(m, frame_load_buf);

	mutex_unlock(&fl_mutex);

	return 0;
}

static int frame_load_proc_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, frame_load_show, inode);
}

static const struct proc_ops frame_load_proc_ops = {
	.proc_open		= frame_load_proc_open,
	.proc_read		= seq_read,
	.proc_lseek		= seq_lseek,
	.proc_release	= single_release,
};

static int tracked_tasks_show(struct seq_file *m, void *v)
{
	char task_name[TASK_COMM_LEN];
	int i;

	mutex_lock(&fl_mutex);
	for (i = 0; i < tracked_task_num; i++) {
		if (get_task_name(tracked_tasks[i].pid, tracked_tasks[i].task, task_name))
			seq_printf(m, "comm=%-16s  pid=%-6d\n", task_name, tracked_tasks[i].pid);
	}
	mutex_unlock(&fl_mutex);

	return 0;
}

static int tracked_tasks_proc_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, tracked_tasks_show, inode);
}

static const struct proc_ops tracked_tasks_proc_ops = {
	.proc_open		= tracked_tasks_proc_open,
	.proc_read		= seq_read,
	.proc_lseek		= seq_lseek,
	.proc_release	= single_release,
};

static ssize_t std_window_size_proc_write(struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int ret, value;
	unsigned long flags;

	ret = simple_write_to_buffer(page, sizeof(page) - 1, ppos, buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(page, "%d", &value);
	if (ret != 1)
		return -EINVAL;

	raw_spin_lock_irqsave(&fl_raw_spinlock, flags);
	if (value > 0)
		std_window_size = value;
	else
		std_window_size = FPS_120_WINDOW_SIZE;
	raw_spin_unlock_irqrestore(&fl_raw_spinlock, flags);

	return count;
}

static ssize_t std_window_size_proc_read(struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int len;

	len = sprintf(page, "%llu\n", std_window_size);

	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static const struct proc_ops std_window_size_proc_ops = {
	.proc_write		= std_window_size_proc_write,
	.proc_read		= std_window_size_proc_read,
	.proc_lseek		= default_llseek,
};

static void reset_frame_load_state(void)
{
	int i;

	/* lockdep_assert_held(&fl_raw_spinlock); */

	tracked_task_num = 0;
	frame_group.nr_running = 0;
	cpumask_clear(&frame_group.running_cpumask);

	for (i = 0; i < cluster_num; i++) {
		struct sched_cluster_info * cluster = &sched_clusters[i];

		cluster->prev_window_exec = 0;
		cluster->curr_window_exec = 0;
		cluster->prev_window_scale = 0;
		cluster->curr_window_scale = 0;
		cluster->window_busy = 0;
		cluster->window_util = 0;
	}

	frame_group.prev_window_exec = 0;
	frame_group.curr_window_exec = 0;
	frame_group.prev_window_scale = 0;
	frame_group.curr_window_scale = 0;
	frame_group.window_busy = 0;
	frame_group.window_util = 0;

	frame_group.window_start = fg_ktime_get_ns();
}

static ssize_t flt_enable_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int ret, value;
	unsigned long flags;

	ret = simple_write_to_buffer(page, sizeof(page) - 1, ppos, buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(page, "%d", &value);
	if (ret != 1)
		return -EINVAL;

	/* one time */
	frame_load_init_delay();

	mutex_lock(&fl_mutex);
	raw_spin_lock_irqsave(&fl_raw_spinlock, flags);

	frame_load_track_enable = value > 0 ? true : false;
	reset_frame_load_state();

	raw_spin_unlock_irqrestore(&fl_raw_spinlock, flags);
	mutex_unlock(&fl_mutex);

	return count;
}

static ssize_t flt_enable_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int len;

	len = sprintf(page, "%d\n", frame_load_track_enable ? 1 : 0);

	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static const struct proc_ops flt_enable_proc_ops = {
	.proc_write		= flt_enable_proc_write,
	.proc_read		= flt_enable_proc_read,
	.proc_lseek		= default_llseek,
};

static void frame_load_init_delay(void)
{
	static bool initialized = false;

	if (!initialized) {
		build_sched_cluster_info();

		register_syscore_ops(&fg_syscore_ops);

		register_trace_sched_switch(frame_sched_switch, NULL);
		register_trace_android_vh_cpufreq_fast_switch(frame_android_vh_cpufreq_fast_switch, NULL);

		proc_create_data("tracked_tasks", 0440, frame_load_track_dir, &tracked_tasks_proc_ops, NULL);
		proc_create_data("std_window_size", 0660, frame_load_track_dir, &std_window_size_proc_ops, NULL);
		proc_create_data("frame_load", 0440, frame_load_track_dir, &frame_load_proc_ops, NULL);

		initialized = true;
	}
}

void frame_load_init(void)
{
	frame_load_track_dir = proc_mkdir("frame_load_track", game_opt_dir);
	if (!frame_load_track_dir) {
		pr_err("fail to mkdir /proc/game_opt/frame_load_track\n");
		return;
	}

	proc_create_data("flt_enable", 0660, frame_load_track_dir, &flt_enable_proc_ops, NULL);
}
