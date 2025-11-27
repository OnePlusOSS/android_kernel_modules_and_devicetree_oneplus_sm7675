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

#include "../utils/oplus_power_hook_utils.h"

#define HANDLE_WAKEUP_SOURCE_REPORT  "wakeup_source_report_event"
#define OPLUS_NETLINK_HOOK_ON        "oplus_netlink_hook_on"
#define NETLINK_WAKEUPSOURCE         "NETLINK"

static struct proc_dir_entry *oplus_lpm                   = NULL;
static struct proc_dir_entry *oplus_netlink_hook_on_proc  = NULL;

static bool netlink_hook_on = false;


static int kp_handler_netlink_wakeupsource(struct kprobe *kp, struct pt_regs *regs)
{
	struct wakeup_source *ws;
	static ktime_t last_time, now_time;
	ktime_t delta;
	ws = (struct wakeup_source *)regs->regs[0];

	now_time = ktime_get();
	delta = ktime_sub(now_time, last_time);
	if (!in_interrupt() &&
		ws && !strcmp(ws->name, NETLINK_WAKEUPSOURCE) &&
		(ktime_to_ns(delta) > 5 * NSEC_PER_SEC)) {
		pr_info("[oplus_lpm_hook_netlink_start]\n");
		dump_stack();
		pr_info("[oplus_lpm_hook_netlink_end]\n");
		last_time = now_time;
	}

	return 0;
}

static struct kprobe kp_handle_netlink_wakeupsource = {
	.symbol_name = HANDLE_WAKEUP_SOURCE_REPORT,
	.pre_handler = kp_handler_netlink_wakeupsource,
	.offset = 0x0,
};

static ssize_t oplus_netlink_hook_write(struct file *file,
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

	netlink_hook_on = !!(val);
	if(netlink_hook_on) {
		enable_kprobe_func(&kp_handle_netlink_wakeupsource);
	} else {
		disable_kprobe_func(&kp_handle_netlink_wakeupsource);
	}

	return len;
}

static int oplus_netlink_hook_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "%d\n", netlink_hook_on);

	return 0;
}

static int oplus_netlink_hook_open(struct inode *inode, struct file *file)
{
	int ret = 0;

	ret = single_open(file, oplus_netlink_hook_show, NULL);

	return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
static const struct proc_ops oplus_netlink_hook_fops = {
	.proc_open		= oplus_netlink_hook_open,
	.proc_write		= oplus_netlink_hook_write,
	.proc_read		= seq_read,
	.proc_lseek 		= default_llseek,
	.proc_release		= seq_release,
};
#else
static const struct file_operations oplus_netlink_hook_fops = {
	.open			= oplus_netlink_hook_open,
	.write			= oplus_netlink_hook_write,
	.read			= seq_read,
	.proc_lseek 		= seq_lseek,
	.proc_release		= seq_release,
};
#endif


int netlink_wakeupsource_hook_init(void)
{
	int ret = 0;

	ret = register_kprobe(&kp_handle_netlink_wakeupsource);
	if (ret < 0) {
		pr_info("[netlink_wakeupsource_hook] register netlink wakeupsource kprobe failed with %d\n", ret);
	}

	pr_info("[netlink_wakeupsource_hook] module init successfully!\n");

	disable_kprobe_func(&kp_handle_netlink_wakeupsource);

	oplus_lpm = get_oplus_lpm_dir();
	if(!oplus_lpm) {
		pr_info("[netlink_wakeupsource_hook] not found /proc/oplus_lpm proc path\n");
		goto out;
	}

	oplus_netlink_hook_on_proc = proc_create(OPLUS_NETLINK_HOOK_ON, 0664, \
					oplus_lpm, &oplus_netlink_hook_fops);
	if(!oplus_netlink_hook_on_proc)
		pr_info("[netlink_wakeupsource_hook] failed to create proc node oplus_netlink_hook_on\n");

out:
	return 0;
}

void netlink_wakeupsource_hook_exit(void)
{
	unregister_kprobe(&kp_handle_netlink_wakeupsource);

	proc_remove(oplus_netlink_hook_on_proc);
}

