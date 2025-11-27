#include <linux/kernel.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/cpufreq.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>

#include "cpufreq_limits.h"
#include "early_detect.h"
#include "debug.h"

struct cpu_freq_status {
	unsigned int min;
	unsigned int max;
};

static DEFINE_PER_CPU(struct cpu_freq_status, edb_cpu_stats);
static DEFINE_PER_CPU(struct cpu_freq_status, final_cpu_stats);
static DEFINE_PER_CPU(struct freq_qos_request, qos_req_min);

static cpumask_var_t limit_cpumask;

static unsigned int ed_boost_type = ED_BOOST_NONE;
static DEFINE_MUTEX(g_mutex);

static int *policy2cpu;

oplus_game_update_cpu_freq_cb_t oplus_game_update_cpu_freq_cb;
EXPORT_SYMBOL_GPL(oplus_game_update_cpu_freq_cb);
#define update_cpu_max_freq()                                                  \
	do {                                                                   \
		if (oplus_game_update_cpu_freq_cb) {                           \
			oplus_game_update_cpu_freq_cb();                       \
		}                                                              \
	} while (0)

int oplus_game_get_max_freq(int policy)
{
	if (ed_boost_type == ED_BOOST_EDB) {
		return per_cpu(final_cpu_stats, policy2cpu[policy]).max;
	}

	return FREQ_QOS_MIN_DEFAULT_VALUE;
}
EXPORT_SYMBOL_GPL(oplus_game_get_max_freq);

static int get_cpu_policy_num(void)
{
	int cpu;
	int num = 0;
	struct cpufreq_policy *policy;

	for_each_possible_cpu (cpu) {
		policy = cpufreq_cpu_get(cpu);

		if (policy) {
			pr_info("%s, policy[%d]: first:%d, min:%d, max:%d",
				__func__, num, cpu, policy->min, policy->max);

			num++;
			cpu = cpumask_last(policy->related_cpus);
			cpufreq_cpu_put(policy);
		}
	}

	return num;
}

static int freq_qos_request_init(void)
{
	unsigned int cpu;
	int ret;
	int policy_num = 0;
	int max_policy_num;

	struct cpufreq_policy *policy;
	struct cpufreq_policy *last_policy = NULL;
	struct freq_qos_request *req;

	max_policy_num = get_cpu_policy_num();
	policy2cpu = kcalloc(max_policy_num, sizeof(int), GFP_KERNEL);
	if (!policy2cpu) {
		pr_err("%s: Failed to kcalloc policy2cpu\n", __func__);
		return -EINVAL;
	}

	for_each_present_cpu (cpu) {
		policy = cpufreq_cpu_get(cpu);
		if (!policy) {
			pr_err("%s: Failed to get cpufreq policy for cpu%d\n",
			       __func__, cpu);
			ret = -EINVAL;
			goto cleanup;
		}
		if (policy != last_policy && policy_num < max_policy_num) {
			policy2cpu[policy_num] = cpu;
			policy_num++;
		}
		last_policy = policy;

		per_cpu(edb_cpu_stats, cpu).min = FREQ_QOS_MIN_DEFAULT_VALUE;
		per_cpu(final_cpu_stats, cpu).min = FREQ_QOS_MIN_DEFAULT_VALUE;
		req = &per_cpu(qos_req_min, cpu);
		ret = freq_qos_add_request(&policy->constraints, req,
					   FREQ_QOS_MIN,
					   FREQ_QOS_MIN_DEFAULT_VALUE);
		if (ret < 0) {
			pr_err("%s: Failed to add min freq constraint (%d)\n",
			       __func__, ret);
			cpufreq_cpu_put(policy);
			goto cleanup;
		}

		per_cpu(edb_cpu_stats, cpu).max =
			FREQ_QOS_MIN_DEFAULT_VALUE; /* by designed */
		per_cpu(final_cpu_stats, cpu).max = FREQ_QOS_MAX_DEFAULT_VALUE;

		cpufreq_cpu_put(policy);
	}
	return 0;

cleanup:
	for_each_present_cpu (cpu) {
		req = &per_cpu(qos_req_min, cpu);
		if (req && freq_qos_request_active(req))
			freq_qos_remove_request(req);

		per_cpu(edb_cpu_stats, cpu).min = FREQ_QOS_MIN_DEFAULT_VALUE;
		per_cpu(edb_cpu_stats, cpu).max =
			FREQ_QOS_MIN_DEFAULT_VALUE; /* by designed */
		per_cpu(final_cpu_stats, cpu).min = FREQ_QOS_MIN_DEFAULT_VALUE;
		per_cpu(final_cpu_stats, cpu).max = FREQ_QOS_MAX_DEFAULT_VALUE;
	}
	return ret;
}

static void __freq_qos_request_reset(void)
{
	int i, j, cpu;
	struct cpumask present_mask;
	struct cpufreq_policy policy;
	struct freq_qos_request *req;

	cpumask_copy(&present_mask, cpu_present_mask);

	cpus_read_lock();
	for_each_cpu (i, &present_mask) {
		if (cpufreq_get_policy(&policy, i))
			continue;

		for_each_cpu (j, policy.related_cpus)
			cpumask_clear_cpu(j, &present_mask);

		cpu = policy.cpu;

		if (per_cpu(final_cpu_stats, cpu).min !=
		    FREQ_QOS_MIN_DEFAULT_VALUE) {
			per_cpu(final_cpu_stats, cpu).min =
				FREQ_QOS_MIN_DEFAULT_VALUE;
			req = &per_cpu(qos_req_min, cpu);
			freq_qos_update_request(req,
						FREQ_QOS_MIN_DEFAULT_VALUE);
		}

		if (per_cpu(final_cpu_stats, cpu).max !=
		    FREQ_QOS_MAX_DEFAULT_VALUE) {
			per_cpu(final_cpu_stats, cpu).max =
				FREQ_QOS_MAX_DEFAULT_VALUE;
			update_cpu_max_freq();
		}
	}
	cpus_read_unlock();
}

static void __ed_freq_boost_request(void)
{
	int i, j, cpu;
	struct cpumask present_mask;
	struct cpufreq_policy policy;
	struct freq_qos_request *req;
	unsigned int edb_min, final_min;
	unsigned int edb_max, final_max;

	cpumask_copy(&present_mask, cpu_present_mask);

	cpus_read_lock();
	for_each_cpu (i, &present_mask) {
		if (cpufreq_get_policy(&policy, i))
			continue;

		for_each_cpu (j, policy.related_cpus)
			cpumask_clear_cpu(j, &present_mask);

		cpu = policy.cpu;

		if (ed_boost_type & ED_BOOST_EDB) {
			edb_min = per_cpu(edb_cpu_stats, cpu).min;
			final_min = edb_min;
		}
		if (per_cpu(final_cpu_stats, cpu).min != final_min) {
			per_cpu(final_cpu_stats, cpu).min = final_min;
			req = &per_cpu(qos_req_min, cpu);
			freq_qos_update_request(req, final_min);
		}
		systrace_c_printk("cpu min", final_min);
		systrace_c_printk("cpu min", 0);

		if (ed_boost_type & ED_BOOST_EDB) {
			edb_max = per_cpu(edb_cpu_stats, cpu).max;
			final_max = edb_max;
		}
		if (per_cpu(final_cpu_stats, cpu).min != final_min) {
			per_cpu(final_cpu_stats, cpu).max = final_max;
			update_cpu_max_freq();
		}
		systrace_c_printk("cpu max", final_max);
		systrace_c_printk("cpu max", 0);
	}
	cpus_read_unlock();
}

void do_ed_freq_boost_request(unsigned int boost_type)
{
	mutex_lock(&g_mutex);

	if (boost_type > ED_BOOST_NONE) {
		if (ed_boost_type & boost_type)
			goto unlock;
		ed_boost_type |= boost_type;
	} else {
		if (ed_boost_type == ED_BOOST_NONE)
			goto unlock;
		ed_boost_type = ED_BOOST_NONE;
	}

	if (ed_boost_type > ED_BOOST_NONE) {
		__ed_freq_boost_request();
	} else {
		__freq_qos_request_reset();
	}

unlock:
	mutex_unlock(&g_mutex);
}

static ssize_t edb_set_cpu_min_freq(const char *buf, size_t count)
{
	int i, j, ntokens = 0;
	unsigned int val, cpu;
	const char *cp = buf;
	struct cpufreq_policy policy;

	while ((cp = strpbrk(cp + 1, " :")))
		ntokens++;

	/* CPU:value pair */
	if (!(ntokens % 2))
		return -EINVAL;

	cp = buf;
	cpumask_clear(limit_cpumask);
	for (i = 0; i < ntokens; i += 2) {
		if (sscanf(cp, "%u:%u", &cpu, &val) != 2)
			return -EINVAL;
		if (cpu > (num_present_cpus() - 1))
			return -EINVAL;

		per_cpu(edb_cpu_stats, cpu).min = val;

		cpumask_set_cpu(cpu, limit_cpumask);

		cp = strnchr(cp, strlen(cp), ' ');
		cp++;
	}

	for_each_cpu (i, limit_cpumask) {
		if (cpufreq_get_policy(&policy, i))
			continue;

		for_each_cpu (j, policy.related_cpus) {
			cpumask_clear_cpu(j, limit_cpumask);
			per_cpu(edb_cpu_stats, j).min =
				per_cpu(edb_cpu_stats, i).min;
		}
	}

	return count;
}

static ssize_t edb_cpu_min_freq_proc_write(struct file *file,
					   const char __user *buf, size_t count,
					   loff_t *ppos)
{
	char page[256] = { 0 };
	int ret;

	ret = simple_write_to_buffer(page, sizeof(page) - 1, ppos, buf, count);
	if (ret <= 0)
		return ret;

	mutex_lock(&g_mutex);
	ret = edb_set_cpu_min_freq(page, ret);
	mutex_unlock(&g_mutex);

	return ret;
}

static int edb_cpu_min_freq_show(struct seq_file *m, void *v)
{
	int cpu;

	mutex_lock(&g_mutex);
	for_each_present_cpu (cpu)
		seq_printf(m, "%d:%u ", cpu, per_cpu(edb_cpu_stats, cpu).min);
	seq_printf(m, "\n");
	mutex_unlock(&g_mutex);

	return 0;
}

static int edb_cpu_min_freq_proc_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, edb_cpu_min_freq_show, inode);
}

static const struct proc_ops edb_cpu_min_freq_proc_ops = {
	.proc_open = edb_cpu_min_freq_proc_open,
	.proc_write = edb_cpu_min_freq_proc_write,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static ssize_t edb_set_cpu_max_freq(const char *buf, size_t count)
{
	int i, j, ntokens = 0;
	unsigned int val, cpu;
	const char *cp = buf;
	struct cpufreq_policy policy;

	while ((cp = strpbrk(cp + 1, " :")))
		ntokens++;

	/* CPU:value pair */
	if (!(ntokens % 2))
		return -EINVAL;

	cp = buf;
	cpumask_clear(limit_cpumask);
	for (i = 0; i < ntokens; i += 2) {
		if (sscanf(cp, "%u:%u", &cpu, &val) != 2)
			return -EINVAL;
		if (cpu > (num_present_cpus() - 1))
			return -EINVAL;

		per_cpu(edb_cpu_stats, cpu).max = min_t(
			uint, val, (unsigned int)FREQ_QOS_MAX_DEFAULT_VALUE);

		cpumask_set_cpu(cpu, limit_cpumask);

		cp = strnchr(cp, strlen(cp), ' ');
		cp++;
	}

	for_each_cpu (i, limit_cpumask) {
		if (cpufreq_get_policy(&policy, i))
			continue;

		for_each_cpu (j, policy.related_cpus) {
			cpumask_clear_cpu(j, limit_cpumask);
			per_cpu(edb_cpu_stats, j).max =
				per_cpu(edb_cpu_stats, i).max;
		}
	}

	return count;
}

static ssize_t edb_cpu_max_freq_proc_write(struct file *file,
					   const char __user *buf, size_t count,
					   loff_t *ppos)
{
	char page[256] = { 0 };
	int ret;

	ret = simple_write_to_buffer(page, sizeof(page) - 1, ppos, buf, count);
	if (ret <= 0)
		return ret;

	mutex_lock(&g_mutex);
	ret = edb_set_cpu_max_freq(page, ret);
	mutex_unlock(&g_mutex);

	return ret;
}

static int edb_cpu_max_freq_show(struct seq_file *m, void *v)
{
	int cpu;

	mutex_lock(&g_mutex);
	for_each_present_cpu (cpu)
		seq_printf(m, "%d:%u ", cpu, per_cpu(edb_cpu_stats, cpu).max);
	seq_printf(m, "\n");
	mutex_unlock(&g_mutex);

	return 0;
}

static int edb_cpu_max_freq_proc_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, edb_cpu_max_freq_show, inode);
}

static const struct proc_ops edb_cpu_max_freq_proc_ops = {
	.proc_open = edb_cpu_max_freq_proc_open,
	.proc_write = edb_cpu_max_freq_proc_write,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

int cpufreq_limits_init(void)
{
	int ret;

	if (!alloc_cpumask_var(&limit_cpumask, GFP_KERNEL))
		return -ENOMEM;

	ret = freq_qos_request_init();
	if (ret) {
		pr_err("%s: Failed to init qos requests policy for ret=%d\n",
		       __func__, ret);
		return ret;
	}

	proc_create_data("edb_cpu_min_freq", 0664, early_detect_dir,
			 &edb_cpu_min_freq_proc_ops, NULL);
	proc_create_data("edb_cpu_max_freq", 0664, early_detect_dir,
			 &edb_cpu_max_freq_proc_ops, NULL);

	return 0;
}

void cpufreq_limits_exit(void)
{
	kfree(policy2cpu);
}