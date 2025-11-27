#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/time.h>
#include <linux/hrtimer.h>
#include <linux/proc_fs.h>
#include <trace/events/sched.h>
#include <trace/hooks/sched.h>
#include <uapi/linux/sched/types.h>
#include <linux/errno.h>

#include "early_detect.h"
#include "cpufreq_limits.h"

#include "debug.h"

#define NSEC_PER_USEC 1000L
#define RENDER_LONG_SLEEP_NR 1
#define RENDER_SHORT_RUNTIME_NR 2

#define MAX_RUNTIME_HISTORY_SIZE 4
#define DEFAULT_RENDER_SLEEP_TIME_US 3000
#define DEFAULT_BUFFER2_RENDER_SLEEP_TIME_US 4000
#define DEFAULT_RENDER_RUNTIME_US 1000
#define DEFAULT_FRAME_ELAPSED_TIME_US 5000
#define DEFAULT_RENDER_BUSY_TIME_US 4000
#define DEFAULT_RENDER_WAKEUP_TIMES 50

static atomic_t ed_enable = ATOMIC_INIT(0);
static atomic_t render_task_pid = ATOMIC_INIT(-1);
static int target_fps = 0;

static atomic_t hrtimer_expiry_nr = ATOMIC_INIT(0);

static bool render_long_sleep_detect = false;
static atomic_t arg_render_sleep_time_us =
	ATOMIC_INIT(DEFAULT_RENDER_SLEEP_TIME_US);
static atomic_t arg_buffer2_render_sleep_time_us =
	ATOMIC_INIT(DEFAULT_BUFFER2_RENDER_SLEEP_TIME_US); /* buffer_num == 2 */
static atomic_t queued_buffer_num = ATOMIC_INIT(0);
static atomic_t time_sensitive = ATOMIC_INIT(0);
static u64 runtime_history[MAX_RUNTIME_HISTORY_SIZE];

static bool render_short_runtime_detect = false;
static atomic_t arg_render_runtime_us = ATOMIC_INIT(
	DEFAULT_RENDER_RUNTIME_US); /* threshold for detecting short runtime */
static atomic_t arg_frame_elapsed_time_us =
	ATOMIC_INIT(DEFAULT_FRAME_ELAPSED_TIME_US);
static int arg_render_busy_time_us = DEFAULT_RENDER_BUSY_TIME_US;

static bool render_wakeup_too_many_times_detect = false;
static atomic_t render_wakeup_times = ATOMIC_INIT(0);
static atomic_t arg_render_wakeup_times =
	ATOMIC_INIT(DEFAULT_RENDER_WAKEUP_TIMES);
static atomic_t render_wakeup_too_many_times_need_boost = ATOMIC_INIT(0);

static bool render_running = false;
static u64 render_start_running_ts;
static u64 render_frame_runtime;
static u64 new_frame_produce_ts;

static struct hrtimer render_long_sleep_hrtimer;
static struct hrtimer render_short_runtime_hrtimer;

static struct task_struct *thread;
static struct kthread_work ed_work;
static struct kthread_worker ed_worker;

struct proc_dir_entry *oplus_game_dir = NULL;
struct proc_dir_entry *early_detect_dir = NULL;

static DEFINE_MUTEX(ed_mutex);
static DEFINE_RAW_SPINLOCK(ed_lock);

bool debug_enable = true;

void early_detect_set_render_task(int pid)
{
	if (atomic_read(&ed_enable)) {
		atomic_set(&render_task_pid, pid);
	}
}
EXPORT_SYMBOL_GPL(early_detect_set_render_task);

static enum hrtimer_restart ed_hrtimer_callback(struct hrtimer *timer)
{
	int nr = 0;

	if (timer == &render_long_sleep_hrtimer) {
		nr = RENDER_LONG_SLEEP_NR;
	} else if (timer == &render_short_runtime_hrtimer) {
		nr = RENDER_SHORT_RUNTIME_NR;
	} else {
		nr = -1;
	}

	if (nr > 0) {
		atomic_set(&hrtimer_expiry_nr, nr);
		kthread_queue_work(&ed_worker, &ed_work);

		if (nr == RENDER_LONG_SLEEP_NR && render_short_runtime_detect) {
			hrtimer_try_to_cancel(&render_short_runtime_hrtimer);
		}

		if (nr == RENDER_SHORT_RUNTIME_NR && render_long_sleep_detect) {
			hrtimer_try_to_cancel(&render_long_sleep_hrtimer);
		}
	}

	return HRTIMER_NORESTART;
}

static void ed_hrtimer_start(int buffer_num)
{
	u64 expire_nsecs;
	/* if render_task_pid == -1, invalid render pid, downgrade to frame timeout boost only */
	if (render_short_runtime_detect && atomic_read(&time_sensitive) &&
	    (buffer_num == 1) && (atomic_read(&render_task_pid) != -1)) {
		expire_nsecs =
			atomic_read(&arg_frame_elapsed_time_us) * NSEC_PER_USEC;
		hrtimer_start(&render_short_runtime_hrtimer,
			      ktime_set(0, expire_nsecs), HRTIMER_MODE_REL);
	}
}

/* within ed_mutex mutex_lock */
static void ed_hrtimer_cancel(void)
{
	if (render_short_runtime_detect)
		hrtimer_cancel(&render_short_runtime_hrtimer);
}

/* within ed_mutex mutex_lock */
static void ed_hrtimer_cancel_all(void)
{
	if (render_long_sleep_detect)
		hrtimer_cancel(&render_long_sleep_hrtimer);

	ed_hrtimer_cancel();
}

static void ed_hrtimer_init(void)
{
	hrtimer_init(&render_long_sleep_hrtimer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_REL);
	hrtimer_init(&render_short_runtime_hrtimer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_REL);

	render_long_sleep_hrtimer.function = ed_hrtimer_callback;
	render_short_runtime_hrtimer.function = ed_hrtimer_callback;
}

static void update_render_frame_runtime(u64 runtime, bool reset)
{
	if (reset) {
		render_frame_runtime = 0;
	} else {
		render_frame_runtime += runtime;
	}
}

static void apply_render_frame_runtime(int buffer_num)
{
	int i;
	u64 sum = 0, avg, demand;

	for (i = 0; i < MAX_RUNTIME_HISTORY_SIZE - 1; i++) {
		runtime_history[i] = runtime_history[i + 1];
		sum += runtime_history[i];
	}

	runtime_history[i] = render_frame_runtime;
	sum += runtime_history[i];

	avg = div64_u64(sum, MAX_RUNTIME_HISTORY_SIZE);
	demand = max(avg, render_frame_runtime);

	if (buffer_num == 1 || buffer_num == 2) {
		atomic_set(&time_sensitive,
			   demand > arg_render_busy_time_us * NSEC_PER_USEC ?
				   1 :
				   0);
	} else {
		atomic_set(&time_sensitive, 0);
	}

	systrace_c_printk("avg", avg);
	systrace_c_printk("demand", demand);
	systrace_c_printk("time_sensitive", atomic_read(&time_sensitive));
}

static void reset_render_wakeup_times(void)
{
	if (render_wakeup_too_many_times_detect) {
		systrace_c_printk("render_wakeup_times",
				  atomic_read(&render_wakeup_times));
		atomic_set(&render_wakeup_times, 0);
	}
}

static void __maybe_unused try_to_wake_up_success_hook(void *unused,
						       struct task_struct *task)
{
	if (!atomic_read(&ed_enable))
		return;

	if (task->pid != atomic_read(&render_task_pid))
		return;

	if (render_wakeup_too_many_times_detect) {
		int a_render_wakeup_times =
			atomic_read(&arg_render_wakeup_times);
		if ((a_render_wakeup_times > 0) &&
		    (atomic_add_return(1, &render_wakeup_times) ==
		     a_render_wakeup_times)) {
			atomic_set(&render_wakeup_too_many_times_need_boost, 1);
			kthread_queue_work(&ed_worker, &ed_work);
		}
	}
}

static void sched_switch_hook(void *unused, bool preempt,
			      struct task_struct *prev,
			      struct task_struct *next, unsigned int prev_state)
{
	bool render_start, render_stop;
	u64 now;
	unsigned long flags;
	pid_t rndr_task_pid;
	if (!atomic_read(&ed_enable)) {
		return;
	}

	rndr_task_pid = atomic_read(&render_task_pid);
	systrace_c_printk("render_task_pid", rndr_task_pid);
	render_start = (next->pid == rndr_task_pid);
	render_stop = (prev->pid == rndr_task_pid);
	if (!render_start && !render_stop) {
		return;
	}

	systrace_c_printk("render_start", !!render_start);
	systrace_c_printk("render_stop", !!render_stop);

	now = ktime_get_ns();
	raw_spin_lock_irqsave(&ed_lock, flags);
	if (render_start) {
		render_running = true;
		render_start_running_ts = now;
	} else {
		u64 runtime;
		render_running = false;

		if (now > render_start_running_ts) {
			runtime = now - render_start_running_ts;
			update_render_frame_runtime(runtime, false);
		}
	}
	raw_spin_unlock_irqrestore(&ed_lock, flags);

	if (render_long_sleep_detect) {
		if (render_start) {
			hrtimer_try_to_cancel(&render_long_sleep_hrtimer);
		} else if (atomic_read(&time_sensitive) && prev_state > 0) {
			int buffer_num = atomic_read(&queued_buffer_num);
			int a_render_sleep_time_us =
				atomic_read(&arg_render_sleep_time_us);
			int a_buffer2_render_sleep_time_us =
				atomic_read(&arg_buffer2_render_sleep_time_us);
			u64 expire_nsecs = 0;

			if (buffer_num == 1 && a_render_sleep_time_us > 0) {
				expire_nsecs =
					NSEC_PER_USEC * a_render_sleep_time_us;
			} else if (buffer_num == 2 &&
				   a_buffer2_render_sleep_time_us > 0) {
				expire_nsecs = NSEC_PER_USEC *
					       a_buffer2_render_sleep_time_us;
			}

			if (expire_nsecs > 0) {
				hrtimer_start(&render_long_sleep_hrtimer,
					      ktime_set(0, expire_nsecs),
					      HRTIMER_MODE_REL);
			}
		}
	}
}

static void ed_freq_boost_request(enum ED_BOOST_TYPE boost_type)
{
	switch (boost_type) {
	case ED_BOOST_EDB:
		systrace_c_printk("ed_freq_boost", boost_type);
		do_ed_freq_boost_request(boost_type);
		systrace_c_printk("ed_freq_boost", ED_BOOST_NONE);
		break;
	default:
		do_ed_freq_boost_request(boost_type);
		break;
	}
}

static void cancel_ed(void)
{
	atomic_set(&render_task_pid, -1);
	mutex_lock(&ed_mutex);
	ed_hrtimer_cancel_all();
	kthread_cancel_work_sync(&ed_work);
	ed_freq_boost_request(ED_BOOST_NONE);
	reset_render_wakeup_times();
	mutex_unlock(&ed_mutex);
}

static void ed_work_fn(struct kthread_work *work)
{
	int nr;
	u64 now;
	bool need_boost;
	unsigned long flags;

	nr = atomic_read(&hrtimer_expiry_nr);
	atomic_set(&hrtimer_expiry_nr, 0);

	if (!atomic_read(&ed_enable) || nr == 0) {
		ed_freq_boost_request(ED_BOOST_NONE);
		return;
	}

	/* TODO: add try_to_wake_up hook to count wakeup times */
	if (atomic_read(&render_wakeup_too_many_times_need_boost) == 1) {
		atomic_set(&render_wakeup_too_many_times_need_boost, 0);

		systrace_c_printk("render_wakeup_too_many_times", 1);
		systrace_c_printk("render_wakeup_too_many_times", 0);

		ed_freq_boost_request(ED_BOOST_EDB);
		return;
	}

	now = ktime_get_ns();

	raw_spin_lock_irqsave(&ed_lock, flags);
	need_boost = (now > new_frame_produce_ts) &&
		     ((now - new_frame_produce_ts) > (NSEC_PER_MSEC * 2));
	if (nr == RENDER_SHORT_RUNTIME_NR) { /* render_short_running */
		if (need_boost) {
			int a_render_runtime_us =
				atomic_read(&arg_render_runtime_us);

			if (render_running && now > render_start_running_ts) {
				u64 runtime = now - render_start_running_ts;
				render_start_running_ts = now;
				update_render_frame_runtime(runtime, false);
			}

			if (a_render_runtime_us > 0)
				need_boost =
					render_frame_runtime <
					a_render_runtime_us * NSEC_PER_USEC;
			else
				need_boost = false;

			if (need_boost && (debug_enable == 1)) {
				char buf[128];
				int a_frame_elapsed_time_us =
					atomic_read(&arg_frame_elapsed_time_us);

				snprintf(buf, sizeof(buf),
					 "render_frame_runtime_%u_%u",
					 a_render_runtime_us,
					 a_frame_elapsed_time_us);

				systrace_c_printk(buf, render_frame_runtime);
				systrace_c_printk(buf, 0);
			}
		}
	}
	raw_spin_unlock_irqrestore(&ed_lock, flags);

	if (need_boost) {
		if (nr == RENDER_SHORT_RUNTIME_NR) {
			systrace_c_printk("edb short runtime", 1);
			systrace_c_printk("edb short runtime", 0);
		} else if (nr == RENDER_LONG_SLEEP_NR) {
			systrace_c_printk("edb long sleep", 1);
			systrace_c_printk("edb long sleep", 0);
		}
		ed_freq_boost_request(ED_BOOST_EDB);
	}
}

static int ed_kthread_create(void)
{
	int ret;
	struct sched_param param = {.sched_priority = MAX_RT_PRIO - 1 };

	kthread_init_work(&ed_work, ed_work_fn);
	kthread_init_worker(&ed_worker);
	thread = kthread_create(kthread_worker_fn, &ed_worker, "g_ed");
	if (IS_ERR(thread)) {
		pr_err("[fpsgo ed] failed to create g_ed thread: %ld\n",
		       PTR_ERR(thread));
		return PTR_ERR(thread);
	}

	ret = sched_setscheduler_nocheck(thread, SCHED_FIFO, &param);
	if (ret) {
		kthread_stop(thread);
		pr_warn("[fpsgo ed] %s: failed to set g_ed thread SCHED_FIFO\n",
			__func__);
		return ret;
	}

	wake_up_process(thread);

	return 0;
}

static void ed_kthread_exit(void)
{
	if (thread) {
		kthread_stop(thread);
	}
}

/* START: cread early detect proc files */
static ssize_t frame_produce_proc_write(struct file *file,
					const char __user *buf, size_t count,
					loff_t *ppos)
{
	char page[32] = { 0 };
	int ret;
	int buffer_num;
	u64 now;
	u64 frame_produce_ts;
	int real_fps;
	int frame_drop_threshold;
	unsigned long flags;

	ret = simple_write_to_buffer(page, sizeof(page) - 1, ppos, buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(page, "%llu %d %d %d", &frame_produce_ts, &buffer_num,
		     &real_fps, &frame_drop_threshold);
	if (ret != 4) {
		return -EINVAL;
	}

	if (!atomic_read(&ed_enable)) {
		return 0;
	}

	systrace_c_printk("frame_produce", 1);
	systrace_c_printk("frame_produce", 0);
	systrace_c_printk("buffer_num", buffer_num);

	now = ktime_get_ns();
	mutex_lock(&ed_mutex);
	raw_spin_lock_irqsave(&ed_lock, flags);
	new_frame_produce_ts = now;
	if (render_running && now > render_start_running_ts) {
		u64 runtime = now - render_start_running_ts;
		render_start_running_ts = now;
		update_render_frame_runtime(runtime, false);
	}
	apply_render_frame_runtime(buffer_num);
	update_render_frame_runtime(0, true);
	reset_render_wakeup_times();
	raw_spin_unlock_irqrestore(&ed_lock, flags);

	atomic_set(&queued_buffer_num, buffer_num);

	ed_hrtimer_cancel();
	kthread_cancel_work_sync(&ed_work);
	ed_freq_boost_request(ED_BOOST_NONE);
	ed_hrtimer_start(buffer_num);

	mutex_unlock(&ed_mutex);

	return count;
}

static const struct proc_ops frame_produce_proc_ops = {
	.proc_write = frame_produce_proc_write,
	.proc_lseek = default_llseek,
};

static ssize_t target_fps_proc_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	char page[32] = { 0 };
	int ret;
	int fps;

	ret = simple_write_to_buffer(page, sizeof(page) - 1, ppos, buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(page, "%d", &fps);
	if (ret != 1)
		return -EINVAL;

	mutex_lock(&ed_mutex);
	target_fps = fps;
	mutex_unlock(&ed_mutex);

	return count;
}

static ssize_t target_fps_proc_read(struct file *file, char __user *buf,
				    size_t count, loff_t *ppos)
{
	char page[32] = { 0 };
	int len;

	mutex_lock(&ed_mutex);
	len = sprintf(page, "%d\n", target_fps);
	mutex_unlock(&ed_mutex);

	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static const struct proc_ops target_fps_proc_ops = {
	.proc_write = target_fps_proc_write,
	.proc_read = target_fps_proc_read,
	.proc_lseek = default_llseek,
};

static ssize_t ed_enable_proc_write(struct file *file, const char __user *buf,
				    size_t count, loff_t *ppos)
{
	char page[32] = { 0 };
	int ret, value;
	bool enable;

	ret = simple_write_to_buffer(page, sizeof(page) - 1, ppos, buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(page, "%d", &value);
	if (ret != 1)
		return -EINVAL;

	if (value != 0 && value != 1)
		return -EINVAL;

	enable = value == 1;

	if (atomic_read(&ed_enable) != enable) {
		atomic_set(&ed_enable, enable);
		if (!atomic_read(&ed_enable)) {
			cancel_ed();
		}
	}

	return count;
}

static ssize_t ed_enable_proc_read(struct file *file, char __user *buf,
				   size_t count, loff_t *ppos)
{
	char page[32] = { 0 };
	int len;

	len = sprintf(page, "%d\n", atomic_read(&ed_enable));

	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static const struct proc_ops ed_enable_proc_ops = {
	.proc_write = ed_enable_proc_write,
	.proc_read = ed_enable_proc_read,
	.proc_lseek = default_llseek,
};

static ssize_t ed_args_proc_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	char page[256] = { 0 };
	int ret;

	int a_max_boost_time_ms;
	int a_buffer2_frame_timeout_offset;
	int a_frame_drop_release_max_limits_offset;
	int a_frame_short_timeout_offset;
	int a_frame_long_timeout_offset;
	int a_render_busy_time_mode;
	int a_render_busy_time_us;
	int a_render_sleep_time_us;
	int a_buffer2_render_sleep_time_us;
	int a_render_runtime_us;
	int a_frame_elapsed_time_us;
	int a_render_wakeup_times;

	int arg_max_boost_time_ms;

	ret = simple_write_to_buffer(page, sizeof(page) - 1, ppos, buf, count);
	if (ret <= 0)
		return ret;

	mutex_lock(&ed_mutex);

	/* reset switches */
	render_long_sleep_detect = false;
	render_short_runtime_detect = false;
	render_wakeup_too_many_times_detect = false;

	/* reset arguments */
	arg_max_boost_time_ms = 100;
	arg_render_busy_time_us = 0;
	atomic_set(&arg_render_sleep_time_us, 0);
	atomic_set(&arg_buffer2_render_sleep_time_us, 0);
	atomic_set(&arg_render_runtime_us, 0);
	atomic_set(&arg_frame_elapsed_time_us, 0);
	atomic_set(&arg_render_wakeup_times, 0);

	ret = sscanf(page, "%d %d %d %d %d %d %d %d %d %d %d %d",
		     &a_max_boost_time_ms, &a_buffer2_frame_timeout_offset,
		     &a_frame_drop_release_max_limits_offset,
		     &a_frame_short_timeout_offset,
		     &a_frame_long_timeout_offset, &a_render_busy_time_mode,
		     &a_render_busy_time_us, &a_render_sleep_time_us,
		     &a_buffer2_render_sleep_time_us, &a_render_runtime_us,
		     &a_frame_elapsed_time_us, &a_render_wakeup_times);

	if (ret != 12) {
		/* in order to reset switches and arguments */
		if (ret == 1 && a_max_boost_time_ms == -1)
			ret = count;
		else
			ret = -EINVAL;

		mutex_unlock(&ed_mutex);
		return ret;
	}

	if (a_render_busy_time_us > 0) {
		arg_render_busy_time_us = a_render_busy_time_us;

		if (a_render_sleep_time_us > 0) {
			atomic_set(&arg_render_sleep_time_us,
				   a_render_sleep_time_us);
			render_long_sleep_detect = true;
		}
		if (a_buffer2_render_sleep_time_us > 0) {
			atomic_set(&arg_buffer2_render_sleep_time_us,
				   a_buffer2_render_sleep_time_us);
		}

		if (a_render_runtime_us > 0 && a_frame_elapsed_time_us > 0 &&
		    a_render_runtime_us < a_frame_elapsed_time_us) {
			atomic_set(&arg_render_runtime_us, a_render_runtime_us),
				atomic_set(&arg_frame_elapsed_time_us,
					   a_frame_elapsed_time_us),
				render_short_runtime_detect = true;
		}
	}

	if (a_render_wakeup_times > 0) {
		atomic_set(&arg_render_wakeup_times, a_render_wakeup_times);
		render_wakeup_too_many_times_detect = true;
	}

	mutex_unlock(&ed_mutex);

	return count;
}

static ssize_t ed_args_proc_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	char page[256] = { 0 };
	int len;

	mutex_lock(&ed_mutex);
	len = sprintf(
		page,
		"mbt_ms=%d, b2ft_offset=%d, fst_offset=%d, flt_offset=%d, rbt_us=%d,"
		" rst_us=%d, b2rst_us=%d, rrt_us=%d, fet_us=%d, rw_times=%d\n",
		-1, -1, -1, -1, arg_render_busy_time_us,
		atomic_read(&arg_render_sleep_time_us),
		atomic_read(&arg_buffer2_render_sleep_time_us),
		atomic_read(&arg_render_runtime_us),
		atomic_read(&arg_frame_elapsed_time_us),
		atomic_read(&arg_render_wakeup_times));
	mutex_unlock(&ed_mutex);

	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static const struct proc_ops ed_args_proc_ops = {
	.proc_write = ed_args_proc_write,
	.proc_read = ed_args_proc_read,
	.proc_lseek = default_llseek,
};

static int proc_ops_init(void)
{
	oplus_game_dir = proc_mkdir("oplus_cpu_game", NULL);
	if (!oplus_game_dir) {
		pr_err("[OPLUS_GMAE] fail to mkdir /proc/oplus_cpu_game\n");
		return -ENOMEM;
	}

	early_detect_dir = proc_mkdir("early_detect", oplus_game_dir);
	if (!early_detect_dir) {
		pr_err("[OPLUS_GAME] fail to mkdir /proc/oplus_cpu_game/early_detect\n");
		return -ENOMEM;
	}
	proc_create_data("frame_produce", 0220, early_detect_dir,
			 &frame_produce_proc_ops, NULL);
	proc_create_data("target_fps", 0664, early_detect_dir,
			 &target_fps_proc_ops, NULL);
	proc_create_data("ed_enable", 0664, early_detect_dir,
			 &ed_enable_proc_ops, NULL);
	proc_create_data("ed_args", 0664, early_detect_dir, &ed_args_proc_ops,
			 NULL);

	return 0;
}

static void proc_ops_exit(void)
{
	proc_remove(early_detect_dir);
	proc_remove(oplus_game_dir);
}
/* END: cread early detect proc files */

void early_detect_init(void)
{
	if (ed_kthread_create()) {
		return;
	}

	ed_hrtimer_init();

	if (proc_ops_init()) {
		return;
	}

	/* Register vender hooks in kernel/sched/core.c
	 * TODO register_trace_android_rvh_try_to_wake_up_success(
	 *     try_to_wake_up_success_hook, NULL);
	 * everytime the kernel code picks next task, trigger this hook. */
	register_trace_sched_switch(sched_switch_hook, NULL);
}

void early_detect_exit(void)
{
	unregister_trace_sched_switch(sched_switch_hook, NULL);
	proc_ops_exit();
	mutex_lock(&ed_mutex);
	ed_hrtimer_cancel_all();
	mutex_unlock(&ed_mutex);
	ed_kthread_exit();
}
