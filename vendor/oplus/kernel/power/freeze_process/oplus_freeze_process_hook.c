#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/timer.h>
#include <linux/device.h>
#include <linux/suspend.h>
#include <linux/interrupt.h>
#include <linux/kern_levels.h>
#include <linux/sched.h>
#include <linux/printk.h>
#include <linux/ktime.h>
#include <linux/sched/signal.h>
#include <linux/rculist.h>

#define HANDLE_FREEZE_TASKS        "try_to_freeze_tasks"

#define SYSTEM_SERVER_PROCESS      "system_server"
#define KHUNG_TASK_PROCESS         "khungtaskd"

#define OPLUS_FREEZE_DIR                  "oplus_freeze_process"
#define SYSTEM_SERVER_ORDER_ADV_ENABLE    "ss_order_adv_enable"

static struct proc_dir_entry    *oplus_freeze_proc = NULL;
static struct proc_dir_entry    *oplus_freeze_hook_on_proc  = NULL;

static bool ss_order_adv_enable = true;


static void kp_handler_freeze_process(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{
	struct task_struct *g;
	struct task_struct *pos = NULL, *ss = NULL;

	if(ss_order_adv_enable) {
		rcu_read_lock();
		for_each_process(g) {
			if(!pos && !strncmp(g->comm, KHUNG_TASK_PROCESS, TASK_COMM_LEN)) {
				pos = g;
			}
			if(!ss && !strncmp(g->comm, SYSTEM_SERVER_PROCESS, TASK_COMM_LEN)) {
				ss = g;
			}

			if(pos && ss)
				break;
		}
		rcu_read_unlock();

		if(pos && ss) {
			write_lock_irq(&tasklist_lock);
			list_del_rcu(&ss->tasks);
			list_add_rcu(&ss->tasks, &pos->tasks);
			write_unlock_irq(&tasklist_lock);
		}
	}
}

static struct kprobe kp_handle_freeze_process = {
	.symbol_name  = HANDLE_FREEZE_TASKS,
	.post_handler = kp_handler_freeze_process,
	.offset       = 0x70,
};

static ssize_t oplus_freeze_hook_write(struct file *file,
		const char __user *buff, size_t len, loff_t *data)
{

	char buf[10] = {0};
	unsigned int val = 0;

	if (len > sizeof(buf))
		return -EFAULT;

	if (copy_from_user((char *)buf, buff, len))
		return -EFAULT;

	if (kstrtouint(buf, sizeof(buf), &val))
		return -EINVAL;

	ss_order_adv_enable = !!(val);

	return len;
}

static int oplus_freeze_hook_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "%d\n", ss_order_adv_enable);

	return 0;
}

static int oplus_freeze_hook_open(struct inode *inode, struct file *file)
{
	int ret = 0;

	ret = single_open(file, oplus_freeze_hook_show, NULL);

	return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
static const struct proc_ops oplus_freeze_hook_fops = {
	.proc_open		= oplus_freeze_hook_open,
	.proc_write		= oplus_freeze_hook_write,
	.proc_read		= seq_read,
	.proc_lseek 		= default_llseek,
	.proc_release		= seq_release,
};
#else
static const struct file_operations oplus_freeze_hook_fops = {
	.open			= oplus_freeze_hook_open,
	.write			= oplus_freeze_hook_write,
	.read			= seq_read,
	.proc_lseek 		= seq_lseek,
	.proc_release		= seq_release,
};
#endif

int freeze_process_hook_init(void)
{
	int ret = 0;

	ret = register_kprobe(&kp_handle_freeze_process);
	if (ret < 0) {
		pr_info("[freeze_process_hook] register freeze process kprobe failed with %d\n", ret);
		goto out;
	}
	pr_info("[freeze_process_hook] module init successfully!\n");

	oplus_freeze_proc = proc_mkdir(OPLUS_FREEZE_DIR, NULL);
	if(!oplus_freeze_proc) {
		goto err_create_freeze_proc;
	}

	oplus_freeze_hook_on_proc = proc_create(SYSTEM_SERVER_ORDER_ADV_ENABLE, 0664, \
					oplus_freeze_proc, &oplus_freeze_hook_fops);
	if(!oplus_freeze_hook_on_proc) {
		pr_info("[freeze_process_hook] failed to create proc ss_order_adv_enable\n");
		goto err_create_freeze_hook_on;
	}

	return 0;

err_create_freeze_hook_on:
	remove_proc_entry(OPLUS_FREEZE_DIR, NULL);
	oplus_freeze_proc = NULL;

err_create_freeze_proc:
	unregister_kprobe(&kp_handle_freeze_process);

out:
	return -ENOENT;
}

void freeze_process_hook_exit(void)
{
	unregister_kprobe(&kp_handle_freeze_process);

	proc_remove(oplus_freeze_hook_on_proc);
	remove_proc_entry(OPLUS_FREEZE_DIR, NULL);
}

module_init(freeze_process_hook_init);
module_exit(freeze_process_hook_exit);

MODULE_AUTHOR("Colin.Liu");
MODULE_DESCRIPTION("oplus freeze process hook module");
MODULE_LICENSE("GPL v2");
