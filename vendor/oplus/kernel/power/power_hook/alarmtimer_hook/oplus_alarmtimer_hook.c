#include <linux/delay.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <clocksource/arm_arch_timer.h>
#include <linux/err.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/alarmtimer.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/wakeup_reason.h>
#include <linux/tracepoint.h>
#include <linux/list.h>
#include <trace/events/alarmtimer.h>
#include <linux/suspend.h>
#include <linux/workqueue.h>
#include <linux/rtc.h>
#include <linux/sched.h>

#include "../utils/oplus_power_hook_utils.h"
#include "oplus_alarmtimer_hook.h"

#define ALARM_RESTART   "alarm_restart"
#define TIMERFD_POLL    "timerfd_poll"

#define OPLUS_ALARMTIMER_HOOK_ON     "oplus_alarmtimer_hook_on"
#define OPLUS_TIMER_STATS            "oplus_timer_stats"

#define CLOCK_REALTIME_ALARM   8
#define CLOCK_BOOTTIME_ALARM   9

#define NON_TIMERFD_ALARM_MAX  50
#define ALARM_STAT_ARRAY_SIZE  50

#define ALARM_NUMTYPE 2

struct timerfd_ctx {
	union {
		struct hrtimer tmr;
		struct alarm alarm;
	} t;
	ktime_t tintv;
	ktime_t moffs;
	wait_queue_head_t wqh;
	u64 ticks;
	int clockid;
	short unsigned expired;
	short unsigned settime_flags;
	struct rcu_head rcu;
	struct list_head clist;
	spinlock_t cancel_lock;
	bool might_cancel;
};

struct alarm_info {
	char comm[TASK_COMM_LEN];
	int pid;
	long long exp;
	void *func;
};

struct fired_alarm_info {
	struct alarm *alarm;
	struct alarm_info fired_alarm;
	struct work_struct ntf_work;
};

typedef struct non_timerfd_alarm_info {
	struct alarm_info alarm_info[NON_TIMERFD_ALARM_MAX];
	//unsigned int start;
	unsigned int end;
	spinlock_t lock;
}ntf_alarm_info;

struct trigger_stat {
	char comm[TASK_COMM_LEN];
	int pid;
	unsigned int cnt;
};

struct trigger_info {
	struct trigger_stat stats[ALARM_STAT_ARRAY_SIZE];
	unsigned int array_size;
};

static struct trigger_info alarm_trigger;

static struct alarm *restart_alarm[ALARM_NUMTYPE] = {NULL};
static int alarm_type;

static bool has_alarm_fired = false;
static struct fired_alarm_info fired_alarm_info;
static struct workqueue_struct *ntf_wq = NULL;

static ntf_alarm_info non_timerfd_alarms;
static suspend_state_t oplus_pm_suspend_target_state = PM_SUSPEND_ON;

static struct proc_dir_entry *oplus_lpm                      = NULL;
static struct proc_dir_entry *oplus_alarmtimer_hook_on_proc  = NULL;
static struct proc_dir_entry *oplus_timer_stats_proc         = NULL;

static void ntf_alarm_work(struct work_struct *work);

static bool alarmtimer_hook_on = true;

static void alarmtimer_start_trace_probe(void *unused, struct alarm *alarm, ktime_t now);
static void alarmtimer_fired_trace_probe(void *unused, struct alarm *alarm, ktime_t now);

static struct tracepoints_table alarmtimer_tracepoints_table[] = {
    {.name = "alarmtimer_start",   .func = alarmtimer_start_trace_probe  },
    {.name = "alarmtimer_fired",   .func = alarmtimer_fired_trace_probe  }
};

void ntf_alarms_init(ntf_alarm_info *ntf_alarms)
{
	memset(&ntf_alarms->alarm_info, 0, (sizeof(struct alarm_info) * NON_TIMERFD_ALARM_MAX));
	ntf_alarms->end   = 0;
	spin_lock_init(&ntf_alarms->lock);
}

void ntf_alarms_add(struct alarm *alarm, struct alarm_info *alarm_elm)
{
	strncpy(alarm_elm->comm, current->comm, TASK_COMM_LEN - 1);
	alarm_elm->comm[TASK_COMM_LEN - 1] = '\0';

	alarm_elm->pid  = current->pid;
	alarm_elm->exp  = ktime_to_ms(alarm->node.expires);
	alarm_elm->func = alarm->function;
}

void ntf_alarms_clear(struct alarm_info *alarm_elm)
{
	memset(alarm_elm->comm, 0, TASK_COMM_LEN);
	alarm_elm->pid  = -1;
	alarm_elm->exp  = 0;
	alarm_elm->func = NULL;
}

static inline bool isalarm(struct timerfd_ctx *ctx)
{
	return ctx->clockid == CLOCK_REALTIME_ALARM ||
		ctx->clockid == CLOCK_BOOTTIME_ALARM;
}

static void alarm_trigger_reset(struct trigger_info *alarm_trig)
{
	memset(&alarm_trig->stats, 0, (sizeof(struct trigger_stat) * ALARM_STAT_ARRAY_SIZE));
	alarm_trig->array_size = 0;
}

static void alarm_trigger_add(struct alarm_info *frd_alarm, struct trigger_info *alarm_trig)
{
	int i;

	for(i = 0; i < ALARM_STAT_ARRAY_SIZE; i++) {
		if(alarm_trig->stats[i].pid == frd_alarm->pid) {
			alarm_trig->stats[i].cnt++;
			break;
		}

		if((alarm_trig->stats[i].pid == 0) && (strlen(alarm_trig->stats[i].comm) == 0)) {
			alarm_trig->stats[i].pid  = frd_alarm->pid;
			strncpy(alarm_trig->stats[i].comm, frd_alarm->comm, TASK_COMM_LEN - 1);
			alarm_trig->stats[i].comm[TASK_COMM_LEN - 1] = '\0';
			alarm_trig->stats[i].cnt++;

			alarm_trig->array_size++;
			if(alarm_trig->array_size >= ALARM_STAT_ARRAY_SIZE) {
				alarm_trig->array_size = ALARM_STAT_ARRAY_SIZE;
			}
			break;
		}
	}

	if(i >= ALARM_STAT_ARRAY_SIZE) {
		pr_info("[alarmtimer_hook][alarm_trigger full] comm:%s pid:%d\n",
				frd_alarm->comm, frd_alarm->pid);
	}
}


/*
 * kretprobe alarm_restart()
 * hook on function entry to get parameter “alarm”
 */
static int krp_handler_alarm_restart(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct alarm *temp_alarm = (struct alarm *)regs->regs[0];
	alarm_type = temp_alarm->type;

	if(alarm_type < ALARM_NUMTYPE) {
		restart_alarm[alarm_type] = temp_alarm;
	}

	return 0;
}

static struct kretprobe krp_alarm_restart = {
	.entry_handler		= krp_handler_alarm_restart,
	.kp = {
		.symbol_name	= ALARM_RESTART,
	},
};


static int kp_handler_alarm_restart(struct kprobe *kp, struct pt_regs *regs)
{
	unsigned long flags = 0;
	//record none timerfd_alarmproc from restart alarm
	if(restart_alarm[alarm_type] &&
		!is_timerfd_alarmproc_function(restart_alarm[alarm_type]->function)) {
		spin_lock_irqsave(&non_timerfd_alarms.lock, flags);
		ntf_alarms_add(restart_alarm[alarm_type], \
			&non_timerfd_alarms.alarm_info[non_timerfd_alarms.end]);
		non_timerfd_alarms.end = ((non_timerfd_alarms.end + 1) % NON_TIMERFD_ALARM_MAX);
		spin_unlock_irqrestore(&non_timerfd_alarms.lock, flags);
	}

	restart_alarm[alarm_type] = NULL;

	return 0;
}

/*
 * Kprobe alarmtimer_restart()
 * hook before:
 * alarmtimer_restart()
 *    -->spin_unlock_irqrestore(&base->lock, flags)
 * after: alarmtimer_enqueue()
 */
static struct kprobe kp_alarm_restart = {
	.symbol_name = ALARM_RESTART,
	.pre_handler = kp_handler_alarm_restart,
	.offset = 0xA0,
};


static void handler_timerfd_poll(struct file *file)
{
	struct timerfd_ctx *ctx = NULL;
	long long exp;

	if(file) {
		ctx = (struct timerfd_ctx *)file->private_data;
	}

	if(ctx && (oplus_pm_suspend_target_state == PM_SUSPEND_TO_IDLE) &&
			has_alarm_fired && ctx->expired && isalarm(ctx)) {
		exp = ktime_to_ms(ctx->t.alarm.node.expires);

		pr_debug("[alarmtimer_hook][timerfd alarm expired] comm:%s pid:%d exp:%llu\n",
				current->comm, current->pid, exp);

		if(fired_alarm_info.fired_alarm.func &&
				is_timerfd_alarmproc_function(fired_alarm_info.fired_alarm.func) &&
				(fired_alarm_info.fired_alarm.exp == exp)) {

			strncpy(fired_alarm_info.fired_alarm.comm, current->comm, TASK_COMM_LEN - 1);
			fired_alarm_info.fired_alarm.comm[TASK_COMM_LEN - 1] = '\0';
			fired_alarm_info.fired_alarm.pid  = current->pid;

			alarm_trigger_add(&fired_alarm_info.fired_alarm, &alarm_trigger);

			pr_info("[alarmtimer_hook][timerfd alarm fired] comm:%s pid:%d exp:%llu\n",
					fired_alarm_info.fired_alarm.comm,
					fired_alarm_info.fired_alarm.pid,
					fired_alarm_info.fired_alarm.exp);

			has_alarm_fired = false;
			oplus_pm_suspend_target_state = PM_SUSPEND_ON;
			memset(&fired_alarm_info.fired_alarm, 0, sizeof(struct alarm_info));
		}
	}
}


/*
 * kretprobe timerfd_poll()
 * hook on function entry to get parameter “file”
 */
static int krp_handler_timerfd_poll(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct file *timerfd_file;
	timerfd_file = (struct file *)regs->regs[0];

	handler_timerfd_poll(timerfd_file);

	return 0;
}

static struct kretprobe krp_timerfd_poll = {
	.entry_handler		= krp_handler_timerfd_poll,
	.kp = {
		.symbol_name	= TIMERFD_POLL,
	},
};


static void alarmtimer_start_trace_probe(void *unused, struct alarm *alarm, ktime_t now)
{
	//record none timerfd_alarmproc alarm
	if(alarm->function && !is_timerfd_alarmproc_function(alarm->function)) {
		spin_lock_bh(&non_timerfd_alarms.lock);
		ntf_alarms_add(alarm, &non_timerfd_alarms.alarm_info[non_timerfd_alarms.end]);
		non_timerfd_alarms.end = ((non_timerfd_alarms.end + 1) % NON_TIMERFD_ALARM_MAX);
		spin_unlock_bh(&non_timerfd_alarms.lock);

	}
}


static void ntf_alarm_work(struct work_struct *work)
{
	int i;
	bool find_kernel_alarm_source = false;
	long long exp;
	struct alarm *alarm;
	long long non_timerfd_exp;

	struct fired_alarm_info *fired_info = container_of(work, struct fired_alarm_info, ntf_work);

	alarm = fired_info->alarm;
	exp = ktime_to_ms(alarm->node.expires);

	memset(&fired_alarm_info.fired_alarm, 0, sizeof(struct alarm_info));
	fired_alarm_info.fired_alarm.exp  = exp;
	fired_alarm_info.fired_alarm.func = alarm->function;

	pr_info("[alarmtimer_hook][fired alarm] exp:%llu func:%ps\n",
		exp, fired_alarm_info.fired_alarm.func);

	if((oplus_pm_suspend_target_state == PM_SUSPEND_TO_IDLE) &&
		fired_alarm_info.fired_alarm.func &&
		(!is_timerfd_alarmproc_function(fired_alarm_info.fired_alarm.func))) {
		spin_lock_bh(&non_timerfd_alarms.lock);
		for(i = 0; i < NON_TIMERFD_ALARM_MAX; i++) {
			non_timerfd_exp = non_timerfd_alarms.alarm_info[i].exp;
			if(fired_alarm_info.fired_alarm.exp == non_timerfd_exp) {
				strncpy(fired_alarm_info.fired_alarm.comm, \
					non_timerfd_alarms.alarm_info[i].comm, TASK_COMM_LEN - 1);
				fired_alarm_info.fired_alarm.comm[TASK_COMM_LEN - 1] = '\0';
				fired_alarm_info.fired_alarm.pid = non_timerfd_alarms.alarm_info[i].pid;

				find_kernel_alarm_source = true;
				ntf_alarms_clear(&non_timerfd_alarms.alarm_info[i]);
				break;
			}
		}
		spin_unlock_bh(&non_timerfd_alarms.lock);

		if(find_kernel_alarm_source) {
			alarm_trigger_add(&fired_alarm_info.fired_alarm, &alarm_trigger);
			pr_info("[alarmtimer_hook][kernel alarm fired] comm:%s pid:%d exp:%llu\n",
						fired_alarm_info.fired_alarm.comm,
						fired_alarm_info.fired_alarm.pid,
						fired_alarm_info.fired_alarm.exp);
		} else {
			pr_info("[alarmtimer_hook] alarm exp:%llu not found trigger source\n",
						fired_alarm_info.fired_alarm.exp);
		}

		has_alarm_fired = false;
		oplus_pm_suspend_target_state = PM_SUSPEND_ON;
	}
}


/* we use alarm->function to distinguish the fired alarm come from timerfd(i.e. AlarmManger)
 * or come from kernel, and check the trigger source from different place
 *
 *				alarm->function
 *                      		|
 *		-------------------------------------------------
 *		|						|
 *	alarm set from timerfd				alarm not set from timerfd
 *	callback is timerfd_alarmproc 			callback not timerfd_alarmpro
 *		|					(i.e. alarm_handle_timer)
 *		|						|
 *	find trigger source from timerfd_poll		find trigger source from
 *							alarm_start/alarm_restart
 */
static void alarmtimer_fired_trace_probe(void *unused, struct alarm *alarm, ktime_t now)
{
	oplus_pm_suspend_target_state = pm_suspend_target_state;

	if(oplus_pm_suspend_target_state == PM_SUSPEND_TO_IDLE) {
		has_alarm_fired = true;
		fired_alarm_info.alarm = alarm;
		queue_work(ntf_wq, &fired_alarm_info.ntf_work);
	}
}


static ssize_t oplus_alarmtimer_hook_write(struct file *file,
		const char __user *buff, size_t len, loff_t *data)
{

	char buf[10] = {0};
	unsigned int val = 0;
	int tpt_size = sizeof(alarmtimer_tracepoints_table)/sizeof(alarmtimer_tracepoints_table[0]);

	if (len > sizeof(buf))
		return -EFAULT;

	if (copy_from_user((char *)buf, buff, len))
		return -EFAULT;

	if (kstrtouint(buf, sizeof(buf), &val))
		return -EINVAL;

	alarmtimer_hook_on = !!(val);
	if(alarmtimer_hook_on) {
		enable_kprobe_func(&krp_alarm_restart.kp);
		enable_kprobe_func(&kp_alarm_restart);
		enable_kprobe_func(&krp_timerfd_poll.kp);

		find_and_register_tracepoint_probe(alarmtimer_tracepoints_table, tpt_size);

	} else {
		disable_kprobe_func(&krp_alarm_restart.kp);
		disable_kprobe_func(&kp_alarm_restart);
		disable_kprobe_func(&krp_timerfd_poll.kp);

		unregister_tracepoint_probe(alarmtimer_tracepoints_table, tpt_size);
	}

	return len;
}

static int oplus_alarmtimer_hook_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "%d\n", alarmtimer_hook_on);

	return 0;
}

static int oplus_alarmtimer_hook_open(struct inode *inode, struct file *file)
{
	int ret = 0;

	ret = single_open(file, oplus_alarmtimer_hook_show, NULL);

	return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
static const struct proc_ops oplus_alarmtimer_hook_fops = {
	.proc_open		= oplus_alarmtimer_hook_open,
	.proc_write		= oplus_alarmtimer_hook_write,
	.proc_read		= seq_read,
	.proc_lseek 		= default_llseek,
	.proc_release		= seq_release,
};
#else
static const struct file_operations oplus_alarmtimer_hook_fops = {
	.open			= oplus_alarmtimer_hook_open,
	.write			= oplus_alarmtimer_hook_write,
	.read			= seq_read,
	.proc_lseek 		= seq_lseek,
	.proc_release		= seq_release,
};
#endif


static ssize_t oplus_timer_stats_write(struct file *file,
		const char __user *buff, size_t len, loff_t *data)
{

	char buf[10] = {0};
	unsigned int val = 1;
	bool reset = false;

	if (len > sizeof(buf))
		return -EFAULT;

	if (copy_from_user((char *)buf, buff, len))
		return -EFAULT;

	if (kstrtouint(buf, sizeof(buf), &val))
		return -EINVAL;

	reset = !(val);
	if(reset) {
		alarm_trigger_reset(&alarm_trigger);
	}

	return len;
}


static int oplus_timer_stats_show(struct seq_file *seq, void *v)
{
	int i;
	char *alarm_comm = "unnamed";

	seq_printf(seq, "PID      comm                 cnt\n");

	for(i = 0; i < alarm_trigger.array_size; i++) {
		if(strlen(alarm_trigger.stats[i].comm) != 0) {
			alarm_comm = alarm_trigger.stats[i].comm;
		}

		seq_printf(seq, "%-8d %-20s %d\n",
				alarm_trigger.stats[i].pid,
				alarm_comm,
				alarm_trigger.stats[i].cnt);
	}

	return 0;
}

static int oplus_timer_stats_open(struct inode *inode, struct file *file)
{
	int ret = 0;

	ret = single_open(file, oplus_timer_stats_show, NULL);

	return 0;
}


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
static const struct proc_ops oplus_timer_stats_fops = {
	.proc_open		= oplus_timer_stats_open,
	.proc_write		= oplus_timer_stats_write,
	.proc_read		= seq_read,
	.proc_lseek 		= default_llseek,
	.proc_release		= seq_release,
};
#else
static const struct file_operations oplus_timer_stats_fops = {
	.open			= oplus_timer_stats_open,
	.write			= oplus_timer_stats_write,
	.read			= seq_read,
	.proc_lseek 		= seq_lseek,
	.proc_release		= seq_release,
};
#endif


int alarmtimer_hook_init(void)
{
	int ret = 0;
	int tpt_size = 0;

	ntf_alarms_init(&non_timerfd_alarms);

	ntf_wq = create_workqueue("ntf_wq");
	INIT_WORK(&(fired_alarm_info.ntf_work),ntf_alarm_work);

	alarm_trigger_reset(&alarm_trigger);

	ret = register_kretprobe(&krp_alarm_restart);
	if (ret < 0) {
		pr_info("[alarmtimer_hook] register alarm_restart kretprobe failed with %d", ret);
	}

	ret = register_kprobe(&kp_alarm_restart);
	if (ret < 0) {
		pr_info("[alarmtimer_hook] register alarm_restart kprobe failed with %d", ret);
	}

	ret = register_kretprobe(&krp_timerfd_poll);
	if (ret < 0) {
		pr_info("[alarmtimer_hook] register timerfd_poll kretprobe failed with %d\n", ret);
	}

	tpt_size = sizeof(alarmtimer_tracepoints_table) / sizeof(alarmtimer_tracepoints_table[0]);
	find_and_register_tracepoint_probe(alarmtimer_tracepoints_table, tpt_size);

	pr_info("[alarmtimer_hook] module init successfully!");

	oplus_lpm = get_oplus_lpm_dir();
	if(!oplus_lpm) {
		pr_info("[alarmtimer_hook] not found /proc/oplus_lpm proc path\n");
		goto out;
	}

	oplus_alarmtimer_hook_on_proc = proc_create(OPLUS_ALARMTIMER_HOOK_ON, 0664,
						oplus_lpm, &oplus_alarmtimer_hook_fops);
	if(!oplus_alarmtimer_hook_on_proc)
		pr_info("[alarmtimer_hook] failed to create proc node oplus_alarmtimer_hook_on\n");

	oplus_timer_stats_proc = proc_create(OPLUS_TIMER_STATS, 0664,
						oplus_lpm, &oplus_timer_stats_fops);
	if(!oplus_timer_stats_proc)
		pr_info("[alarmtimer_hook] failed to create proc node oplus_timer_stats\n");

out:
	return 0;
}

void alarmtimer_hook_exit(void)
{
	int tpt_size = 0;

	unregister_kretprobe(&krp_alarm_restart);
	unregister_kprobe(&kp_alarm_restart);

	unregister_kretprobe(&krp_timerfd_poll);

	tpt_size = sizeof(alarmtimer_tracepoints_table) / sizeof(alarmtimer_tracepoints_table[0]);
	unregister_tracepoint_probe(alarmtimer_tracepoints_table, tpt_size);
}
