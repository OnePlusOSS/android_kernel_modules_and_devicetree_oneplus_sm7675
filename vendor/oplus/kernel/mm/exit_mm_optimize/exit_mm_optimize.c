// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 */

#include <linux/module.h>
#include <linux/cpufreq.h>
#include <linux/types.h>
#include <linux/swap.h>
#include <linux/proc_fs.h>
#include <linux/gfp.h>
#include <linux/printk.h>
#include <linux/mmzone.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/pagemap.h>
#include <linux/page-flags.h>
#include <linux/debugfs.h>
#include <linux/memcontrol.h>
#include <linux/huge_mm.h>
#include <linux/freezer.h>
#include <trace/hooks/dtask.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <uapi/linux/sched/types.h>

#define MAX_BUF_LEN 32
#define MAX_UID_LEN 2048
#define BATCH_4M (1 << 10)
static struct proc_dir_entry *memcg_name_entry;
static struct proc_dir_entry *enable_entry;
static struct proc_dir_entry *root_dir_entry;
extern s64 get_mem_cgroup_app_uid(struct mem_cgroup *memcg);
extern char *get_mem_cgroup_app_name(struct mem_cgroup *memcg);
extern struct mem_cgroup *get_next_memcg(struct mem_cgroup *prev);
extern void get_next_memcg_break(struct mem_cgroup *memcg);
extern struct cpufreq_policy *cpufreq_cpu_get(unsigned int cpu);
static atomic_t exit_mm_optimize_enable = ATOMIC_INIT(0);
static atomic_long_t reclaimed_count = ATOMIC_INIT(0);
static atomic_long_t total_reclaimed_pages = ATOMIC_INIT(0);
static struct task_struct *oplus_exit_mm_kthread = NULL;
wait_queue_head_t exit_mm_optimize_wait;
static atomic_t exit_mm_optimize_runnable = ATOMIC_INIT(0);
spinlock_t memcg_array_lock;
spinlock_t memcg_check_lock;
LIST_HEAD(memcg_array_list);
LIST_HEAD(memcg_check_list);

struct memcg_array_entry
{
	char name[MAX_BUF_LEN];
	struct list_head list;
};

static unsigned long memcg_lru_pages(struct mem_cgroup *memcg, enum lru_list lru, bool chp)
{
	int zid;
	unsigned long nr = 0;
	struct mem_cgroup_per_node *mz;

	if (!memcg)
		return 0;

	if (!chp) {
		mz = memcg->nodeinfo[0];
		for (zid = 0; zid < MAX_NR_ZONES; zid++)
			nr += READ_ONCE(mz->lru_zone_size[zid][lru]);
	}
#ifdef CONFIG_CONT_PTE_HUGEPAGE_64K_ZRAM
	if (chp) {
		struct chp_lruvec *lruvec;
		lruvec = (struct chp_lruvec *)memcg->deferred_split_queue.split_queue_len;
		for (zid = 0; zid < MAX_NR_ZONES; zid++)
			nr += READ_ONCE(lruvec->lru_zone_size[zid][lru]);
	}
#endif

	return nr;
}

/* Shrink by free a batch of pages */
static int shrink_memcg_pages(char *memcg_name, struct mem_cgroup *memcg,
			      unsigned long nr_need_reclaim,
			      unsigned long batch,
			      bool may_swap, bool chp)
{
	int ret = 0;
	unsigned long nr_reclaimed = 0;
	gfp_t gfp_mask = GFP_KERNEL;
#ifdef CONFIG_CONT_PTE_HUGEPAGE_64K_ZRAM
	if (chp)
		gfp_mask |= POOL_USER_ALLOC;
#endif

	while (nr_reclaimed < nr_need_reclaim) {
		unsigned long reclaimed;
		reclaimed = try_to_free_mem_cgroup_pages(memcg, batch, gfp_mask, may_swap);

		if (reclaimed == 0)
			break;

		nr_reclaimed += reclaimed;

		/* Abort shrink when receive SIGUSR2 */
		if (unlikely(sigismember(&current->pending.signal, SIGUSR2) ||
			     sigismember(&current->signal->shared_pending.signal, SIGUSR2))) {
			printk("%s abort shrink while shrinking\n", memcg_name);
			ret = -EINTR;
			break;
		}
	}

	atomic_long_add(nr_reclaimed, &total_reclaimed_pages);
	printk("%s try to reclaim %lu pages and reclaim %lu pages\n", memcg_name, nr_need_reclaim, nr_reclaimed);
	return nr_reclaimed;
}

static void shrink_memcg_file_pages(struct mem_cgroup *memcg, char *memcg_name)
{
	struct lruvec *lruvec;
	unsigned long memcg_active_file_before = 0;
	unsigned long memcg_inactive_file_before = 0;
	unsigned long memcg_needed_reclaim = 0;

	unsigned long nr_reclaimed = 0;
	unsigned long batch = BATCH_4M;
	pg_data_t *pgdat = NODE_DATA(0);
	LIST_HEAD(page_list_inactive);
	LIST_HEAD(page_list_active);
	lruvec = mem_cgroup_lruvec(memcg, pgdat);
	memcg_inactive_file_before = memcg_lru_pages(memcg, LRU_INACTIVE_FILE, false);
	memcg_active_file_before = memcg_lru_pages(memcg, LRU_ACTIVE_FILE, false);
	memcg_needed_reclaim = memcg_inactive_file_before + memcg_active_file_before;
	nr_reclaimed = shrink_memcg_pages(memcg_name, memcg, memcg_needed_reclaim, batch, false, false);
	printk("name %s nr_reclaimed %lu\n", memcg_name, nr_reclaimed);
}

static struct mem_cgroup *find_memcg_by_uid(int uid, char *memcg_name)
{
	struct mem_cgroup *memcg = NULL;

	while ((memcg = get_next_memcg(memcg))) {
		if (get_mem_cgroup_app_uid(memcg) == uid) {
			strncpy(memcg_name, get_mem_cgroup_app_name(memcg), MAX_BUF_LEN - 1);
			get_next_memcg_break(memcg);
			break;
		}
	}
	return memcg;
}

static struct mem_cgroup *find_memcg_by_name(char *memcg_name)
{
	struct mem_cgroup *memcg = NULL;

	while ((memcg = get_next_memcg(memcg))) {
		if (strcmp(memcg_name, get_mem_cgroup_app_name(memcg)) == 0) {
			get_next_memcg_break(memcg);
			break;
		}
	}
	return memcg;
}

static int is_element_in_list(char *memcg_name, struct list_head *list_array)
{
	struct memcg_array_entry *memcg_entry;
	struct memcg_array_entry *next;

	if (memcg_name == NULL) {
		return 0;
	}

	if (list_empty(list_array)) {
		return 0;
	}

	list_for_each_entry_safe(memcg_entry, next, list_array, list) {
		if (!strcmp(memcg_name, memcg_entry->name)) {
			return 1;
		}
	}

	return 0;
}

static void exit_check(void *data, struct task_struct *tsk)
{
	pid_t tgid;
	struct task_struct *tsk_check = tsk;
	struct mem_cgroup *memcg = NULL;
	int uid = from_kuid(&init_user_ns, task_uid(tsk_check));
	int enable = atomic_read(&exit_mm_optimize_enable);

	if (!enable) {
		return;
	}

	get_task_struct(tsk_check);
	tgid = tsk_check->tgid;
	if (rcu_dereference(tsk_check->real_parent) == NULL ||
		strcmp(rcu_dereference(tsk_check->real_parent)->comm, "main")) {
		put_task_struct(tsk_check);
		return;
	}
	if ((tsk_check->flags & PF_EXITING) && tsk_check != NULL && tsk_check->mm != NULL && uid > 10000 &&
	    tgid == tsk_check->pid && tsk_check->group_leader == tsk_check) {
		char memcg_name[MAX_BUF_LEN] = {'\0'};
		memcg = find_memcg_by_uid(uid, memcg_name);
		if (memcg != NULL) {
			spin_lock_irq(&memcg_check_lock);
			if (!is_element_in_list(memcg_name, &memcg_check_list)) {
				spin_unlock_irq(&memcg_check_lock);
				put_task_struct(tsk_check);
				return;
			}
			spin_unlock_irq(&memcg_check_lock);

			spin_lock_irq(&memcg_array_lock);
			if (!is_element_in_list(memcg_name, &memcg_array_list)) {
				struct memcg_array_entry *memcg_entry = kmalloc(sizeof(struct memcg_array_entry), GFP_KERNEL);
				memset(memcg_entry, 0, sizeof(struct memcg_array_entry));
				if (memcg_entry) {
					strncpy(memcg_entry->name, memcg_name, MAX_BUF_LEN - 1);
					list_add(&memcg_entry->list, &memcg_array_list);
				}
			}
			spin_unlock_irq(&memcg_array_lock);

			if (atomic_read(&exit_mm_optimize_runnable) == 0) {
				atomic_set(&exit_mm_optimize_runnable, 1);
				wake_up_interruptible(&exit_mm_optimize_wait);
			}
		}
	}
	put_task_struct(tsk_check);
}

void set_exit_mm_cpus(void)
{
	struct cpumask mask;
	struct cpumask *cpumask = &mask;
	pg_data_t *pgdat = NODE_DATA(0);
	unsigned int cpu = 0, cpufreq_max_tmp = 0;
	struct cpufreq_policy *policy_max;
	static bool set_exit_mm_success = false;

	if (unlikely(!oplus_exit_mm_kthread))
		return;

	if (likely(set_exit_mm_success))
		return;
	for_each_possible_cpu(cpu) {
		struct cpufreq_policy *policy = cpufreq_cpu_get(cpu);

		if (policy == NULL)
			continue;

		if (policy->cpuinfo.max_freq >= cpufreq_max_tmp) {
			cpufreq_max_tmp = policy->cpuinfo.max_freq;
			policy_max = policy;
		}
	}

	cpumask_copy(cpumask, cpumask_of_node(pgdat->node_id));
	cpumask_andnot(cpumask, cpumask, policy_max->related_cpus);

	if (!cpumask_empty(cpumask)) {
		set_cpus_allowed_ptr(oplus_exit_mm_kthread, cpumask);
		set_exit_mm_success = true;
	}
}

static int exit_mm_thread(void *data)
{
	struct memcg_array_entry *memcg_entry;
	struct memcg_array_entry *next;
	struct mem_cgroup *memcg = NULL;
	LIST_HEAD(memcg_list);

	current->flags |= PF_MEMALLOC;
	set_freezable();

	while (!kthread_should_stop()) {
		wait_event_freezable(exit_mm_optimize_wait, (atomic_read(&exit_mm_optimize_runnable) == 1));

		set_exit_mm_cpus();

		spin_lock_irq(&memcg_array_lock);
		if (list_empty(&memcg_array_list)) {
			spin_unlock_irq(&memcg_array_lock);
			atomic_set(&exit_mm_optimize_runnable, 0);
			continue;
		}

		list_for_each_entry_safe(memcg_entry, next, &memcg_array_list, list) {
			list_del(&memcg_entry->list);
			list_add(&memcg_entry->list, &memcg_list);
		}
		spin_unlock_irq(&memcg_array_lock);

		list_for_each_entry_safe(memcg_entry, next, &memcg_list, list) {
			list_del(&memcg_entry->list);
			memcg = find_memcg_by_name(memcg_entry->name);
			if (memcg != NULL) {
				atomic_long_add(1, &reclaimed_count);
				shrink_memcg_file_pages(memcg, memcg_entry->name);
			}
			kfree(memcg_entry);
		}
		atomic_set(&exit_mm_optimize_runnable, 0);
	}

	current->flags &= ~(PF_MEMALLOC);

	return 0;
}

static int create_oplus_exit_mm_thread(void)
{
	struct sched_param param = {
	    .sched_priority = DEFAULT_PRIO,
	};
	init_waitqueue_head(&exit_mm_optimize_wait);

	if (oplus_exit_mm_kthread != NULL) {
		return 0;
	}

	oplus_exit_mm_kthread = kthread_create(exit_mm_thread, NULL, "oplus_exit_mm_thread");
	if (IS_ERR(oplus_exit_mm_kthread)) {
		return -EINVAL;
	}
	sched_setscheduler_nocheck(oplus_exit_mm_kthread, SCHED_NORMAL, &param);
	set_user_nice(oplus_exit_mm_kthread, PRIO_TO_NICE(param.sched_priority));
	wake_up_process(oplus_exit_mm_kthread);
	return 0;
}

static ssize_t oplus_memcg_name_ops_write(struct file *file, const char __user *buff, size_t len, loff_t *ppos)
{
	char kbuf[MAX_UID_LEN] = {'\0'};
	char *str;
	char *token;
	struct memcg_array_entry *memcg_entry;
	struct memcg_array_entry *next;
	const char delimiters[] = ",";
	int str_len = len;

	if (str_len > MAX_UID_LEN - 1) {
		str_len = MAX_UID_LEN - 1;
	}

	if (copy_from_user(&kbuf, buff, str_len))
		return -EFAULT;

	kbuf[str_len] = '\0';

	str = strstrip(kbuf);

	list_for_each_entry_safe(memcg_entry, next, &memcg_check_list, list) {
		list_del(&memcg_entry->list);
		kfree(memcg_entry);
	}

	if (!str) {
		return -EINVAL;
	}

	spin_lock_irq(&memcg_check_lock);

	while ((token = strsep(&str, delimiters)) != NULL) {
		struct memcg_array_entry *memcg_check_entry = kmalloc(sizeof(struct memcg_array_entry), GFP_KERNEL);
		if (memcg_check_entry) {
			int len = strlen(token);
			memset(memcg_check_entry, 0, sizeof(struct memcg_array_entry));
			strncpy(memcg_check_entry->name, token, len);
			list_add(&memcg_check_entry->list, &memcg_check_list);
		}
	}

	spin_unlock_irq(&memcg_check_lock);

	return len;
}

static ssize_t oplus_enable_ops_write(struct file *file, const char __user *buff, size_t len, loff_t *ppos)
{
	int ret;
	char kbuf[MAX_BUF_LEN] = {'\0'};
	char *str;
	int val;

	if (len > MAX_BUF_LEN - 1) {
		return -EINVAL;
	}

	if (copy_from_user(&kbuf, buff, len))
		return -EFAULT;
	kbuf[len] = '\0';

	str = strstrip(kbuf);
	if (!str) {
		return -EINVAL;
	}

	ret = kstrtoint(str, 10, &val);
	if (ret) {
		return -EINVAL;
	}

	if (ret != 0 && ret != 1) {
		return -EINVAL;
	}

	printk("exit_mm_optimize_enable is %d\n", val);
	if (val == 1) {
		if (create_oplus_exit_mm_thread() == 0) {
			printk("create success!!\n");
			atomic_set(&exit_mm_optimize_enable, 1);
		}
		else {
			atomic_set(&exit_mm_optimize_enable, 0);
		}
		return len;
	}
	atomic_set(&exit_mm_optimize_enable, val);

	return len;
}

static ssize_t oplus_enable_ops_read(struct file *file, char __user *buffer, size_t count, loff_t *off)
{
	char kbuf[MAX_BUF_LEN] = {'\0'};
	int len;

	len = snprintf(kbuf, MAX_BUF_LEN, "%d\n", atomic_read(&exit_mm_optimize_enable));

	if (len > *off)
		len -= *off;
	else
		len = 0;

	if (copy_to_user(buffer, kbuf + *off, (len < count ? len : count)))
		return -EFAULT;

	*off += (len < count ? len : count);
	return (len < count ? len : count);
}

static int memcg_name_show(struct seq_file *m, void *arg)
{
	struct memcg_array_entry *memcg_entry;
	struct memcg_array_entry *next;
	spin_lock_irq(&memcg_check_lock);
	if (list_empty(&memcg_check_list)) {
		spin_unlock_irq(&memcg_check_lock);
		return 0;
	}

	list_for_each_entry_safe(memcg_entry, next, &memcg_check_list, list) {
		seq_printf(m, "%s\n", memcg_entry->name);
	}
	spin_unlock_irq(&memcg_check_lock);
	return 0;
}

static int exit_mm_stat_show(struct seq_file *m, void *arg)
{
	seq_printf(m, "reclaimed_count  %lu\n", atomic_long_read(&reclaimed_count));
	seq_printf(m, "reclaimed_pages %lu\n", atomic_long_read(&total_reclaimed_pages));
	return 0;
}

static const struct proc_ops proc_oplus_memcg_name_ops = {
	.proc_write = oplus_memcg_name_ops_write,
};

static const struct proc_ops proc_oplus_enable_ops = {
	.proc_write = oplus_enable_ops_write,
	.proc_read = oplus_enable_ops_read,
};

static int __init create_mm_optimize_proc(void)
{
	root_dir_entry = proc_mkdir("oplus_exit_mm_opitimize", NULL);

	memcg_name_entry = proc_create((root_dir_entry ? "memcg_name" : "oplus_exit_mm_opitimize/memcg_name"),
				       0666, root_dir_entry, &proc_oplus_memcg_name_ops);

	enable_entry = proc_create((root_dir_entry ? "enable" : "oplus_exit_mm_opitimize/enable"),
				   0666, root_dir_entry, &proc_oplus_enable_ops);

	proc_create_single("memcg_name_show", 0, root_dir_entry, memcg_name_show);

	proc_create_single("exit_mm_stat", 0, root_dir_entry, exit_mm_stat_show);

	if (memcg_name_entry && enable_entry) {
		return 0;
	}

	printk("Register create_mm_optimize_proc failed.\n");
	return -ENOMEM;
}

static void remove_exit_mm_optimize_proc(void)
{
	proc_remove(memcg_name_entry);
	memcg_name_entry = NULL;
	proc_remove(enable_entry);
	enable_entry = NULL;
	remove_proc_entry("memcg_name_show", root_dir_entry);
	remove_proc_entry("exit_mm_stat", root_dir_entry);
	proc_remove(root_dir_entry);
	root_dir_entry = NULL;
}

static int __init exit_mm_optimize_init(void)
{
	int rc;
	spin_lock_init(&memcg_array_lock);
	spin_lock_init(&memcg_check_lock);
	rc = register_trace_android_vh_exit_check(exit_check, NULL);
	if (rc != 0) {
		printk("register_trace_android_vh_exit_check failed! rc=%d\n", rc);
		return rc;
	}

	rc = create_mm_optimize_proc();
	if (rc != 0) {
		unregister_trace_android_vh_exit_check(exit_check, NULL);
		printk("create_mm_optimize_proc failed! rc=%d\n", rc);
		return rc;
	}

	return 0;
}

static void exit_mm_optimize_exit(void)
{
	unregister_trace_android_vh_exit_check(exit_check, NULL);
	remove_exit_mm_optimize_proc();
}

module_init(exit_mm_optimize_init);
module_exit(exit_mm_optimize_exit);
MODULE_LICENSE("GPL");
