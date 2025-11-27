#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/irq.h>
#include <linux/msi.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/irqdomain.h>
#include <linux/wakeup_reason.h>
#include <linux/suspend.h>
#include <trace/events/irq.h>
#include "../kernel/irq/internals.h"

#include "../utils/oplus_power_hook_utils.h"

#define HANDLE_FASTEOI_IRQ    "handle_fasteoi_irq"
#define HANDLE_LEVEL_IRQ      "handle_level_irq"
#define HANDLE_EDGE_IRQ       "handle_edge_irq"

static struct irq_desc *fasteoi_irq_desc = NULL;
static struct irq_desc *level_irq_desc   = NULL;
static struct irq_desc *edge_irq_desc    = NULL;


#define OPLUS_IRQ_HOOK_ON     "oplus_irq_hook_on"

static struct proc_dir_entry *oplus_lpm               = NULL;
static struct proc_dir_entry *oplus_irq_hook_on_proc  = NULL;

static bool irq_hook_on = true;

#ifdef CONFIG_SUSPEND
static bool oplus_idle_should_enter_s2idle(void)
{
	enum s2idle_states *orig_s2idle_state = NULL;

	if(pm_suspend_target_state == PM_SUSPEND_TO_IDLE) {
		if(!orig_s2idle_state) {
			orig_s2idle_state = \
				(enum s2idle_states *)generic_kallsyms_lookup_name("s2idle_state");
			if(!orig_s2idle_state) {
				pr_info("[irq_wakeup_hook] s2idle_state symbol get failed\n");
				return false;
			}
		}
		return unlikely(*orig_s2idle_state == S2IDLE_STATE_ENTER);
	} else
		return false;
}
#else
static bool oplus_idle_should_enter_s2idle(void) { return false; }
#endif


/*
 * kretprobe handle_fasteoi_irq()
 * hook on function entry to get parameter irq “desc”
 */
static int krp_handler_fasteoi_irq(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	fasteoi_irq_desc = (struct irq_desc *)regs->regs[0];

	return 0;
}

static struct kretprobe krp_handle_fasteoi_irq = {
	.entry_handler		= krp_handler_fasteoi_irq,
	.kp = {
		.symbol_name	= HANDLE_FASTEOI_IRQ,
	},
};

static void kp_handler_fasteoi_irq(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{
	unsigned int irq;
	const char *name = "(unnamed)";

	if(oplus_idle_should_enter_s2idle() &&
		fasteoi_irq_desc &&
		fasteoi_irq_desc->no_suspend_depth &&
		!irqd_is_wakeup_set(&fasteoi_irq_desc->irq_data)) {

		irq = irq_desc_get_irq(fasteoi_irq_desc);

		if (fasteoi_irq_desc->action && fasteoi_irq_desc->action->name)
			name = fasteoi_irq_desc->action->name;

		log_abnormal_wakeup_reason("NO_SUSPEND IRQ %u %s",
							    irq, name);

		fasteoi_irq_desc = NULL;
	}
}

/*
 * Kprobe handle_fasteoi_irq()
 * hook after:
 * handle_fasteoi_irq()
 *    -->raw_spin_lock(&desc->lock)
 */
static struct kprobe kp_handle_fasteoi_irq = {
	.symbol_name = HANDLE_FASTEOI_IRQ,
	.post_handler = kp_handler_fasteoi_irq,
	.offset = 0x28,
};


/*
 * kretprobe handle_level_irq()
 * hook on function entry to get parameter irq “desc”
 */
static int krp_handler_level_irq(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	level_irq_desc = (struct irq_desc *)regs->regs[0];

	return 0;
}

static struct kretprobe krp_handle_level_irq = {
	.entry_handler		= krp_handler_level_irq,
	.kp = {
		.symbol_name	= HANDLE_LEVEL_IRQ,
	},
};

static void kp_handler_level_irq(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{
	unsigned int irq;
	const char *name = "(unnamed)";

	if(oplus_idle_should_enter_s2idle() &&
		level_irq_desc &&
		level_irq_desc->no_suspend_depth &&
		!irqd_is_wakeup_set(&level_irq_desc->irq_data)) {

		irq = irq_desc_get_irq(level_irq_desc);

		if (level_irq_desc->action && level_irq_desc->action->name)
			name = level_irq_desc->action->name;

		log_abnormal_wakeup_reason("NO_SUSPEND IRQ %u %s",
							    irq, name);

		level_irq_desc = NULL;
	}
}

/*
 * Kprobe handle_level_irq()
 * hook after:
 * handle_level_irq()
 *    -->raw_spin_lock(&desc->lock)
 */
static struct kprobe kp_handle_level_irq = {
	.symbol_name = HANDLE_LEVEL_IRQ,
	.post_handler = kp_handler_level_irq,
	.offset = 0x20,
};

/*
 * kretprobe handle_edge_irq()
 * hook on function entry to get parameter irq “desc”
 */
static int krp_handler_edge_irq(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	edge_irq_desc = (struct irq_desc *)regs->regs[0];

	return 0;
}

static struct kretprobe krp_handle_edge_irq = {
	.entry_handler		= krp_handler_edge_irq,
	.kp = {
		.symbol_name	= HANDLE_EDGE_IRQ,
	},
};

static void kp_handler_edge_irq(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{
	unsigned int irq;
	const char *name = "(unnamed)";

	if(oplus_idle_should_enter_s2idle() &&
		edge_irq_desc &&
		edge_irq_desc->no_suspend_depth &&
		!irqd_is_wakeup_set(&edge_irq_desc->irq_data)) {

		irq = irq_desc_get_irq(edge_irq_desc);

		if (edge_irq_desc->action && edge_irq_desc->action->name)
			name = edge_irq_desc->action->name;

		log_abnormal_wakeup_reason("NO_SUSPEND IRQ %u %s",
							    irq, name);

		edge_irq_desc = NULL;
	}
}

/*
 * Kprobe handle_edge_irq()
 * hook after:
 * handle_edge_irq()
 *    -->raw_spin_lock(&desc->lock)
 */
static struct kprobe kp_handle_edge_irq = {
	.symbol_name = HANDLE_EDGE_IRQ,
	.post_handler = kp_handler_edge_irq,
	.offset = 0x20,
};


static ssize_t oplus_irq_hook_write(struct file *file,
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

	irq_hook_on = !!(val);
	if(irq_hook_on) {
		enable_kprobe_func(&krp_handle_fasteoi_irq.kp);
		enable_kprobe_func(&kp_handle_fasteoi_irq);

		enable_kprobe_func(&krp_handle_level_irq.kp);
		enable_kprobe_func(&kp_handle_level_irq);

		enable_kprobe_func(&krp_handle_edge_irq.kp);
		enable_kprobe_func(&kp_handle_edge_irq);
	} else {
		disable_kprobe_func(&krp_handle_fasteoi_irq.kp);
		disable_kprobe_func(&kp_handle_fasteoi_irq);

		disable_kprobe_func(&krp_handle_level_irq.kp);
		disable_kprobe_func(&kp_handle_level_irq);

		disable_kprobe_func(&krp_handle_edge_irq.kp);
		disable_kprobe_func(&kp_handle_edge_irq);
	}

	return len;
}

static int oplus_irq_hook_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "%d\n", irq_hook_on);

	return 0;
}

static int oplus_irq_hook_open(struct inode *inode, struct file *file)
{
	int ret = 0;

	ret = single_open(file, oplus_irq_hook_show, NULL);

	return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
static const struct proc_ops oplus_irq_hook_fops = {
	.proc_open		= oplus_irq_hook_open,
	.proc_write		= oplus_irq_hook_write,
	.proc_read		= seq_read,
	.proc_lseek 		= default_llseek,
	.proc_release		= seq_release,
};
#else
static const struct file_operations oplus_irq_hook_fops = {
	.open			= oplus_irq_hook_open,
	.write			= oplus_irq_hook_write,
	.read			= seq_read,
	.proc_lseek 		= seq_lseek,
	.proc_release		= seq_release,
};
#endif

int irq_wakeup_hook_init(void)
{
	int ret = 0;

	ret = register_kretprobe(&krp_handle_fasteoi_irq);
	if (ret < 0) {
		pr_info("[irq_wakeup_hook] register fasteoi irq kretprobe failed with %d\n", ret);
	}

	ret = register_kprobe(&kp_handle_fasteoi_irq);
	if (ret < 0) {
		pr_info("[irq_wakeup_hook] register fasteoi irq kprobe failed with %d\n", ret);
	}

	ret = register_kretprobe(&krp_handle_level_irq);
	if (ret < 0) {
		pr_info("[irq_wakeup_hook] register level irq kretprobe failed with %d\n", ret);
	}

	ret = register_kprobe(&kp_handle_level_irq);
	if (ret < 0) {
		pr_info("[irq_wakeup_hook] register level irq kprobe failed with %d\n", ret);
	}

	ret = register_kretprobe(&krp_handle_edge_irq);
	if (ret < 0) {
		pr_info("[irq_wakeup_hook] register edge irq kretprobe failed with %d\n", ret);
	}

	ret = register_kprobe(&kp_handle_edge_irq);
	if (ret < 0) {
		pr_info("[irq_wakeup_hook] register edge irq kprobe failed with %d\n", ret);
	}

	pr_info("[irq_wakeup_hook] module init successfully!\n");

	oplus_lpm = get_oplus_lpm_dir();
	if(!oplus_lpm) {
		pr_info("[irq_wakeup_hook] not found /proc/oplus_lpm proc path\n");
		goto out;
	}

	oplus_irq_hook_on_proc = proc_create(OPLUS_IRQ_HOOK_ON, 0664, \
					oplus_lpm, &oplus_irq_hook_fops);
	if(!oplus_irq_hook_on_proc)
		pr_info("[irq_wakeup_hook] failed to create proc node oplus_irq_hook_on\n");

out:
	return 0;
}

void irq_wakeup_hook_exit(void)
{
	unregister_kretprobe(&krp_handle_fasteoi_irq);
	unregister_kprobe(&kp_handle_fasteoi_irq);

	unregister_kretprobe(&krp_handle_level_irq);
	unregister_kprobe(&kp_handle_level_irq);

	unregister_kretprobe(&krp_handle_edge_irq);
	unregister_kprobe(&kp_handle_edge_irq);
}
