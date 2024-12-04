// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Oplus. All rights reserved.
 */

#define pr_fmt(fmt) "fqm_monitor: " fmt

#include <linux/module.h>
#include <linux/pm_qos.h>
#include <linux/cpumask.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/cpufreq.h>
#include <linux/rwlock.h>
#include <linux/spinlock.h>
#include <trace/hooks/power.h>

#include "fqm_sysfs.h"
#include <linux/atomic.h>
#include <linux/seq_file.h>
#include <linux/topology.h>
#include <linux/device.h>
#include <linux/sched/cpufreq.h>
#define FREQ_REQUEST_TIMEOUT_DEFAULE (180 * MSEC_PER_SEC)
#define FQM_PERIOD (180)
#define CALLER_FROM_DEV_PM_QOS "__dev_pm_qos_add_request"

bool fqm_cpufreq_policy_ready;
int default_fqm_threshold;
int max_cluster_num;
int threshold[5];

#define MAX_CLUSTER_NR    (4)
#define MAX_FREQ_TABLE_CNT (25)
#define MAX_FREQ_MONITOR_REQ_CNT (64)
#define MAX_CSTACK_LENGTH    (128)

struct freq_element {
	int min;
	int max;
	u64 updated_time;
	char cstack[MAX_CSTACK_LENGTH];
};

struct freq_variation_table {
	int larget_min;
	int smallest_max;
	int index;
	int cid;
	int last_min;
	int last_max;
	struct freq_element elm[MAX_FREQ_TABLE_CNT];
};

struct freq_request_monitor {
	struct list_head node;
	struct freq_qos_request *req;
	struct delayed_work delay_work;
	int cpu;
	int pid;
	int cluster_nr;
	struct freq_variation_table tables;
	u64 last_update_time;
	unsigned long callstack[4];
};

static bool fqm_dump_enable;
static DEFINE_RWLOCK(moni_rwlock);
static struct freq_request_monitor monitors;
static atomic_t g_monitors_req_cnt;

static void set_of_freq_table(struct freq_qos_request *req, int new_value,
	struct freq_request_monitor *monitor, int cid, char *callstack, u64 ts);

bool get_fqm_dump_val(void)
{
	return fqm_dump_enable;
}

void set_fqm_dump_val(int val)
{
	fqm_dump_enable = !!val;
}

int fqm_get_cluster_nr(void)
{
	int __arch_nr_clusters = -1;
	int max_id = 0;
	unsigned int cpu;

	/* assume socket id is monotonic increasing without gap. */
	for_each_possible_cpu(cpu) {
		struct cpu_topology *cpu_topo = &cpu_topology[cpu];

		if (cpu_topo->package_id > max_id)
			max_id = cpu_topo->package_id;
	}
	__arch_nr_clusters = max_id + 1;
	return __arch_nr_clusters;
}

static __always_inline char *get_cstack(char *cstack)
{
	snprintf(cstack, MAX_CSTACK_LENGTH - 1, "%ps<-%ps<-%ps<-%ps",
		(void *)__builtin_return_address(1),
		(void *)__builtin_return_address(2),
		(void *)__builtin_return_address(3),
		(void *)__builtin_return_address(4));
	cstack[MAX_CSTACK_LENGTH - 1] = '\0';
	return (char *)cstack;
}

int fqm_dump(struct seq_file *s, void *v)
{
	struct freq_request_monitor *moni;
	int cnt = 0;
	int max_cluster = -1;
	struct freq_variation_table *table = NULL;
	int index = 0;
	unsigned long flags;

	if (!get_fqm_dump_val())
		return 0;
	read_lock_irqsave(&moni_rwlock, flags);
	max_cluster = monitors.cluster_nr;
	seq_printf(s, "cnt, %d\n", atomic_read(&g_monitors_req_cnt));
	seq_printf(s, "req, index, timestamp, cluster, pid, larget_min, smallest_max, min, max, max_cluster, stack\n");
	list_for_each_entry(moni, &monitors.node, node) {
		if (cnt > MAX_FREQ_MONITOR_REQ_CNT) {
			seq_printf(s, "Too many requests, stop printing");
			break;
		}
		table = &moni->tables;
		for (index = 0; index < MAX_FREQ_TABLE_CNT; index++) {
			if (table->elm[index].min == 0 && table->elm[index].max == 0)
				continue;
			seq_printf(
				s, "%lu, %d, %llu, %d, %d, %d, %d, %d, %d, %d, %s\n",
				(unsigned long)moni->req % 100000,
				index,
				table->elm[index].updated_time,
				table->cid,
				moni->pid,
				table->larget_min,
				table->smallest_max,
				table->elm[index].min,
				table->elm[index].max,
				max_cluster,
				table->elm[index].cstack);
		}
		cnt++;
	}
	read_unlock_irqrestore(&moni_rwlock, flags);
	return 0;
}

static noinline int tracing_mark_write(const char *buf)
{
	trace_printk(buf);
	return 0;
}

void freqqos_update_systrace_c(int type, int new_value, unsigned long callstack1,
				unsigned long callstack2)
{
	char buf[256];
	bool is_min = true;

	if (type == FREQ_QOS_MAX)
		is_min = false;

	snprintf(buf, sizeof(buf), "C|8888|%s_freq_%ps<-%ps|%d\n",
			is_min ? "min" : "max", (void *)callstack1, (void *)callstack2, new_value);

	tracing_mark_write(buf);
}

static inline bool valid_cluster_id(unsigned int cluster_id)
{
	return (cluster_id >= 0) && (cluster_id < max_cluster_num);
}

void fqm_set_threshold(int value, unsigned int cluster_id)
{
	unsigned long flags;

	if (!valid_cluster_id(cluster_id))
		return;

	write_lock_irqsave(&moni_rwlock, flags);
	threshold[cluster_id] = value;
	write_unlock_irqrestore(&moni_rwlock, flags);
}

int fqm_get_threshold(unsigned int cluster_id)
{
	int thres;
	unsigned long flags;

	if (!valid_cluster_id(cluster_id))
		return 0;

	read_lock_irqsave(&moni_rwlock, flags);
	thres = threshold[cluster_id];
	read_unlock_irqrestore(&moni_rwlock, flags);

	return thres;
}

static struct cpufreq_policy *get_policy_from_req(struct freq_qos_request *req)
{
	struct freq_constraints *qos = req->qos;
	struct cpufreq_policy *policy = container_of(qos, struct cpufreq_policy, constraints);

	return policy;
}

static void freqqos_min_release(struct freq_qos_request *req)
{
	struct freq_constraints *qos;
	struct cpufreq_policy *policy;
	unsigned int first_cpu;
	int cluster_id;
	unsigned int min_freq;

	if (unlikely(!g_fqm_monitor_enable))
		return;

	if (unlikely(!fqm_cpufreq_policy_ready))
		return;

	qos = req->qos;
	if (!qos)
		return;

	policy = get_policy_from_req(req);
	if(!policy)
		return;

	first_cpu = cpumask_first(policy->related_cpus);
	cluster_id = topology_cluster_id(first_cpu);
	min_freq = qos->min_freq.target_value;

	if (min_freq > threshold[cluster_id]) {
		freq_qos_update_request(req, FREQ_QOS_MIN_DEFAULT_VALUE);
		pr_info("%sFREQ_QOS_MIN lasted for too long, release min freq for cluster%d\n", __func__, cluster_id);
	}
}

static void fqm_delayed_work_handler(struct work_struct *work)
{
	struct freq_request_monitor *moni, *temp_moni;
	u64 now = ktime_to_ms(ktime_get());
	bool lasted_timeout = false;
	bool is_min = true;
	unsigned long flags;

	if (unlikely(!g_fqm_monitor_enable))
		return;

	if (list_empty(&monitors.node))
		return;

	moni = container_of(work, struct freq_request_monitor, delay_work.work);

	read_lock_irqsave(&moni_rwlock, flags);
	list_for_each_entry(temp_moni, &monitors.node, node) {
		if (temp_moni == moni) {
			if ((now - moni->last_update_time) > FREQ_REQUEST_TIMEOUT_DEFAULE)
				lasted_timeout = true;

			if (moni->req->type == FREQ_QOS_MAX) {
				/*freq_qos_update_request(moni->req, FREQ_QOS_MAX_DEFAULT_VALUE);*/
				is_min = false;
			}
			break;
		}
	}
	read_unlock_irqrestore(&moni_rwlock, flags);

	if (lasted_timeout) {
		if (is_min)
			freqqos_min_release(moni->req);

		if (unlikely(g_fqm_debug_enable)) {
			pr_info("FREQ_QOS_%s lasted for too long\n", is_min ? "MIN" : "MAX");
			read_lock_irqsave(&moni_rwlock, flags);
			list_for_each_entry(moni, &monitors.node, node) {
				pr_info("dump all request req_type=%d cpu=%d req_min_value=%d req_max_value=%d req_from_pid=%d"
					"last_update_time=%llu req_interval=%llu, callstack:(%ps<-%ps<-%ps<-%ps)\n",
					moni->req->type, moni->cpu, moni->req->qos->min_freq.target_value, moni->req->qos->max_freq.target_value,
					moni->pid, moni->last_update_time, (now - moni->last_update_time),
					(void *)moni->callstack[0], (void *)moni->callstack[1], (void *)moni->callstack[2], (void *)moni->callstack[3]);
			}
			read_unlock_irqrestore(&moni_rwlock, flags);
		}
	}
}

static char callstack[4][64];

bool is_from_pm_dev_qos(struct freq_qos_request *req)
{
	int i;

	snprintf(callstack[0], sizeof(callstack[0]), "%ps", __builtin_return_address(0));
	snprintf(callstack[1], sizeof(callstack[1]), "%ps", __builtin_return_address(1));
	snprintf(callstack[2], sizeof(callstack[2]), "%ps", __builtin_return_address(2));
	snprintf(callstack[3], sizeof(callstack[3]), "%ps", __builtin_return_address(3));

	/*
	 * here only freq_qos is cared, so just skip __dev_pm_qos_add_request()
	 */
	for (i = 0; i < ARRAY_SIZE(callstack); i++) {
		if (!strncmp(callstack[i], CALLER_FROM_DEV_PM_QOS, 24))
			return true;
	}

	return false;
}

void freq_qos_add_request_handler(void *unused, struct freq_constraints *qos,
				struct freq_qos_request *req, enum freq_qos_req_type type,
				int value, int ret)
{
	unsigned long flags;
	struct freq_request_monitor *new_moni = NULL;
	struct task_struct *task = current;
	struct cpufreq_policy *policy = NULL;
	u64 now = ktime_to_ms(ktime_get());
	char cstack[MAX_CSTACK_LENGTH] = {'\0'};

	if (unlikely(!g_fqm_monitor_enable))
		return;

	policy = get_policy_from_req(req);
	if (!policy)
		return;

	if (is_from_pm_dev_qos(req))
		return;

	new_moni = kzalloc(sizeof(struct freq_request_monitor), GFP_ATOMIC);
	if (!new_moni) {
		pr_err("Failed to allocate new_moni\n");
		return;
	}

	req->android_oem_data1 = (u64)new_moni;

	write_lock_irqsave(&moni_rwlock, flags);
	list_add_tail(&(new_moni->node), &(monitors.node));
	INIT_DELAYED_WORK(&new_moni->delay_work, fqm_delayed_work_handler);
	new_moni->req = req;
	new_moni->cpu = cpumask_first(policy->related_cpus);
	new_moni->pid = task->pid;
	new_moni->last_update_time = now;
	new_moni->callstack[0] = (unsigned long)__builtin_return_address(0);
	new_moni->callstack[1] = (unsigned long)__builtin_return_address(1);
	new_moni->callstack[2] = (unsigned long)__builtin_return_address(2);
	new_moni->callstack[3] = (unsigned long)__builtin_return_address(3);

	if (get_fqm_dump_val()) {
		atomic_inc(&g_monitors_req_cnt);
		memset(&new_moni->tables, 0, sizeof(struct freq_variation_table));
		set_of_freq_table(req, value, new_moni,
			topology_cluster_id(policy->cpu), get_cstack(cstack), now);
	}

	write_unlock_irqrestore(&moni_rwlock, flags);

	schedule_delayed_work(&new_moni->delay_work, FQM_PERIOD * HZ);

	if (unlikely(g_fqm_debug_enable)) {
		trace_printk("%s: comm=%s type=%d value=%d ret=%d\n", __func__, task->comm, type, value, ret);
		pr_info("new_moni add! cpu=%d request_from pid=%d comm=%s last_update_time=%llu callstack:(%ps<-%ps<-%ps<-%ps)\n",
		new_moni->cpu, task->pid, task->comm, new_moni->last_update_time, (void *)new_moni->callstack[0],
		(void *)new_moni->callstack[1], (void *)new_moni->callstack[2], (void *)new_moni->callstack[3]);
	}
}

void freq_qos_remove_request_handler(void *unused, struct freq_qos_request *req)
{
	struct freq_constraints *qos = req->qos;
	int type = req->type;
	struct freq_request_monitor *monitor, *temp;
	unsigned long flags;
	bool found = false;
	bool is_min = true;

	write_lock_irqsave(&moni_rwlock, flags);
	list_for_each_entry_safe(monitor, temp, &(monitors.node), node) {
		if (monitor->req == req) {
			found = true;
			list_del(&(monitor->node));
			cancel_delayed_work(&monitor->delay_work);
			req->android_oem_data1 = 0;
			kfree(monitor);
			atomic_dec(&g_monitors_req_cnt);
			break;
		}
	}
	write_unlock_irqrestore(&moni_rwlock, flags);

	if (unlikely(g_fqm_debug_enable)) {
		if (found) {
			pr_info("type=%d value=%d\n", type, is_min ? qos->min_freq.target_value : qos->max_freq.target_value);
		} else {
			pr_warn("req not found in monitors! comm=%s type=%d\n", current->comm, type);
		}
	}
}

static void set_of_freq_table(struct freq_qos_request *req, int new_value,
	struct freq_request_monitor *monitor, int cid, char *callstack, u64 ts)
{
	u64 now = ts;
	int index = -1;
	struct freq_variation_table *table = &monitor->tables;

	switch (req->type) {
	case FREQ_QOS_MIN:
		if (new_value == table->last_min)
			return;
		break;
	case FREQ_QOS_MAX:
		if (new_value == table->last_max)
			return;
		break;
	default:
		return;
	}

	if (table->index > MAX_FREQ_TABLE_CNT - 1)
		table->index = 0;

	index = table->index;
	table->cid = cid;
	table->elm[index].min = table->last_min;
	table->elm[index].max = table->last_max;
	table->elm[index].updated_time = now;
	memcpy(table->elm[index].cstack, callstack, MAX_CSTACK_LENGTH);

	switch (req->type) {
	case FREQ_QOS_MIN:
		table->elm[index].min = new_value;
		table->last_min = new_value;
		table->larget_min =  table->larget_min == 0 ? new_value : (
			table->larget_min < new_value ? new_value : table->larget_min);
		break;
	case FREQ_QOS_MAX:
		table->elm[index].max = new_value;
		table->last_max = new_value;
		table->smallest_max = table->smallest_max == 0 ? new_value : (
			table->smallest_max > new_value ? new_value : table->smallest_max);
		break;
	default:
		break;
	}
	table->index++;
}

static void monitor_req_update_for_dump(struct freq_qos_request *req, int new_value)
{
	struct freq_request_monitor *tmp, *monitor = NULL;
	u64 now = ktime_to_ms(ktime_get());
	struct cpufreq_policy *policy;
	bool found = false;
	unsigned long flags;
	char cstack[MAX_CSTACK_LENGTH] = {'\0'};

	read_lock_irqsave(&moni_rwlock, flags);
	if (req == NULL || list_empty(&monitors.node)) {
		read_unlock_irqrestore(&moni_rwlock, flags);
		return;
	}
	read_unlock_irqrestore(&moni_rwlock, flags);
	policy = get_policy_from_req(req);
	if (!policy)
		return;

	read_lock_irqsave(&moni_rwlock, flags);
	list_for_each_entry(tmp, &(monitors.node), node) {
		if (tmp->req == req) {
			found = true;
			monitor = tmp;
			break;
		}
	}
	read_unlock_irqrestore(&moni_rwlock, flags);

	if (found) {
		write_lock_irqsave(&moni_rwlock, flags);
		set_of_freq_table(req, new_value, monitor,
			topology_cluster_id(policy->cpu), get_cstack(cstack), now);
		write_unlock_irqrestore(&moni_rwlock, flags);

		if (!delayed_work_pending(&monitor->delay_work))
			schedule_delayed_work(&monitor->delay_work, FQM_PERIOD * HZ);
		return;
	}

	monitor = kzalloc(sizeof(struct freq_request_monitor), GFP_ATOMIC);
	if (!monitor)
		return;

	req->android_oem_data1 = (u64)monitor;
	atomic_inc(&g_monitors_req_cnt);
	write_lock_irqsave(&moni_rwlock, flags);
	list_add_tail(&(monitor->node), &(monitors.node));
	INIT_DELAYED_WORK(&monitor->delay_work, fqm_delayed_work_handler);
	monitor->req = req;
	monitor->cpu = cpumask_first(policy->related_cpus);
	monitor->pid = current->pid;
	monitor->last_update_time = now;
	memset(&monitor->tables, 0, sizeof(struct freq_variation_table));
	set_of_freq_table(req, new_value, monitor,
		topology_cluster_id(policy->cpu), get_cstack(cstack), now);
	write_unlock_irqrestore(&moni_rwlock, flags);
	schedule_delayed_work(&monitor->delay_work, FQM_PERIOD * HZ);
}

static void monitor_req_update(struct freq_qos_request *req, int new_value)
{
	struct freq_request_monitor *tmp, *monitor = NULL;
	u64 now = ktime_to_ms(ktime_get());
	struct cpufreq_policy *policy;
	bool found = false;
	unsigned long flags;

	if (req == NULL || list_empty(&monitors.node))
		return;

	policy = get_policy_from_req(req);
	if (!policy)
		return;

	read_lock_irqsave(&moni_rwlock, flags);
	list_for_each_entry(tmp, &(monitors.node), node) {
		if (tmp->req == req) {
			found = true;
			monitor = tmp;
			break;
		}
	}
	read_unlock_irqrestore(&moni_rwlock, flags);

	if (found) {
		write_lock_irqsave(&moni_rwlock, flags);
		monitor->callstack[0] = (unsigned long)__builtin_return_address(0);
		monitor->callstack[1] = (unsigned long)__builtin_return_address(1);
		monitor->callstack[2] = (unsigned long)__builtin_return_address(2);
		monitor->callstack[3] = (unsigned long)__builtin_return_address(3);
		monitor->last_update_time = now;
		write_unlock_irqrestore(&moni_rwlock, flags);

		if (!delayed_work_pending(&monitor->delay_work))
			schedule_delayed_work(&monitor->delay_work, FQM_PERIOD * HZ);
		if (unlikely(g_fqm_debug_enable)) {
			pr_info("%s req_type=%d cpu=%d req_min_value=%d req_max_value=%d req_from_pid=%d last_update_time=%llu callstack:(%ps<-%ps<-%ps<-%ps)\n",
			__func__, req->type, monitor->cpu, req->qos->min_freq.target_value, req->qos->max_freq.target_value, monitor->pid, monitor->last_update_time,
			(void *)monitor->callstack[0], (void *)monitor->callstack[1], (void *)monitor->callstack[2], (void *)monitor->callstack[3]);
			freqqos_update_systrace_c(req->type, new_value, monitor->callstack[1], monitor->callstack[2]);
		}
	} else {
		monitor = kzalloc(sizeof(struct freq_request_monitor), GFP_ATOMIC);
		if (!monitor) {
			pr_err("Failed to allocate monitor\n");
			return;
		}

		req->android_oem_data1 = (u64)monitor;

		write_lock_irqsave(&moni_rwlock, flags);
		list_add_tail(&(monitor->node), &(monitors.node));
		INIT_DELAYED_WORK(&monitor->delay_work, fqm_delayed_work_handler);
		monitor->req = req;
		monitor->cpu = cpumask_first(policy->related_cpus);
		monitor->pid = current->pid;
		monitor->last_update_time = now;
		monitor->callstack[0] = (unsigned long)__builtin_return_address(0);
		monitor->callstack[1] = (unsigned long)__builtin_return_address(1);
		monitor->callstack[2] = (unsigned long)__builtin_return_address(2);
		monitor->callstack[3] = (unsigned long)__builtin_return_address(3);
		write_unlock_irqrestore(&moni_rwlock, flags);

		pr_info("new_moni update! cpu=%d req_type=%d req_min_value=%d req_max_value=%d request_from pid=%d comm=%s"
			"last_update_time=%llu callstack:(%ps<-%ps<-%ps<-%ps)\n",
			monitor->cpu, req->type, req->qos->min_freq.target_value, req->qos->max_freq.target_value, current->pid, current->comm, monitor->last_update_time,
			(void *)monitor->callstack[0], (void *)monitor->callstack[1], (void *)monitor->callstack[2], (void *)monitor->callstack[3]);
		schedule_delayed_work(&monitor->delay_work, FQM_PERIOD * HZ);
	}
}

void freq_qos_update_request_handler(void *unused, struct freq_qos_request *req, int new_value)
{
	struct freq_constraints *qos = req->qos;
	int type = req->type;
	int old_value = 0;

	if (unlikely(!g_fqm_monitor_enable))
		return;

	if (get_fqm_dump_val()) {
		monitor_req_update_for_dump(req, new_value);
		return;
	}

	/* FREQ_QOS_MIN = 1, FREQ_QOS_MAX = 2,*/
	if (type == FREQ_QOS_MIN)
		old_value = qos->min_freq.target_value;
	else if (type == FREQ_QOS_MAX)
		old_value = qos->max_freq.target_value;

	if (old_value == new_value)
		return;

	monitor_req_update(req, new_value);
}

static int fqm_cpufreq_policy_notifier_callback(struct notifier_block *nb, unsigned long val, void *data)
{
	struct cpufreq_policy *policy = (struct cpufreq_policy *)data;

	if (IS_ERR_OR_NULL(policy)) {
		pr_err("%s:null cpu policy\n", __func__);
		return NOTIFY_DONE;
	}
	if (val != CPUFREQ_CREATE_POLICY)
		return NOTIFY_DONE;

	fqm_cpufreq_policy_ready = true;

	return NOTIFY_DONE;
}

static struct notifier_block fqm_cpufreq_policy_notifier = {
	.notifier_call = fqm_cpufreq_policy_notifier_callback,
};

static void fqm_cluster_init(void)
{
	unsigned int cpu, idx, i;
	int max_cluster_id = 0;

	for_each_possible_cpu(cpu) {
		idx = topology_cluster_id(cpu);
		if (idx > max_cluster_id)
			max_cluster_id = idx;
	}

	max_cluster_num = max_cluster_id + 1;

	for (i = 0; i < max_cluster_num; i++)
		threshold[i] = default_fqm_threshold;

	pr_info("fqm_max_cluster_num_get! max_cluster_num = %d\n", max_cluster_num);
}

static void unregister_fqm_vendor_hooks(void)
{
	unregister_trace_android_vh_freq_qos_update_request(freq_qos_update_request_handler, NULL);
	unregister_trace_android_vh_freq_qos_add_request(freq_qos_add_request_handler, NULL);
	unregister_trace_android_vh_freq_qos_remove_request(freq_qos_remove_request_handler, NULL);
}

static int register_fqm_vendor_hooks(void)
{
	int ret = 0;

	/* register vendor hook in kernel/power/qos.c*/
	ret |= register_trace_android_vh_freq_qos_update_request(freq_qos_update_request_handler, NULL);
	ret |= register_trace_android_vh_freq_qos_add_request(freq_qos_add_request_handler, NULL);
	ret |= register_trace_android_vh_freq_qos_remove_request(freq_qos_remove_request_handler, NULL);
	if (ret) {
		pr_err("fqm register vendor hooks failed!\n");
		return ret;
	}

	return 0;
}

static int __init oplus_freqqos_monitor_init(void)
{
	struct freq_request_monitor *moni = NULL;
	int ret = 0;

	moni = &monitors;
	INIT_LIST_HEAD(&moni->node);
	INIT_DELAYED_WORK(&moni->delay_work, fqm_delayed_work_handler);
	moni->req = NULL;
	moni->cpu = -1;
	moni->pid = 0;
	moni->last_update_time = 0;
	moni->cluster_nr = fqm_get_cluster_nr();
	moni->callstack[0] = 0;
	moni->callstack[1] = 0;
	moni->callstack[2] = 0;
	moni->callstack[3] = 0;
	default_fqm_threshold = 4000000;

	fqm_cluster_init();

	ret = freqqos_monitor_proc_init();
	if (ret)
		return ret;

	ret = cpufreq_register_notifier(&fqm_cpufreq_policy_notifier, CPUFREQ_POLICY_NOTIFIER);
	if (ret)
		return ret;

	ret = register_fqm_vendor_hooks();
	if (ret)
		return ret;

	g_fqm_monitor_enable = 1;
	fqm_dump_enable = false;
	atomic_set(&g_monitors_req_cnt, 0);
	pr_info("oplus_freqqos_monitor init\n");

	return ret;
}

static void __exit oplus_freqqos_monitor_exit(void)
{
	unregister_fqm_vendor_hooks();

	freqqos_monitor_proc_exit();

	g_fqm_monitor_enable = 0;

	pr_info("oplus_freqqos_monitor exit\n");
}

module_init(oplus_freqqos_monitor_init);
module_exit(oplus_freqqos_monitor_exit);
MODULE_DESCRIPTION("OPLUS FREQQOS_MONITOR");
MODULE_LICENSE("GPL v2");
