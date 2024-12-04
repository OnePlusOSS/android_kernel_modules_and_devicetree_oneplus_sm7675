#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/errno.h>
#include <linux/f2fs_fs.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "fs/f2fs/f2fs.h"
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include <uapi/linux/sched/types.h>
#include <linux/suspend.h>
#include <linux/platform_device.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/rwsem.h>
#include <linux/timer.h>
#include <linux/reboot.h>
#include <linux/signal.h>
#include "kernel/trace/trace_probe.h"
#include <linux/kstrtox.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <linux/of.h>
#include <linux/rtc.h>
#include <linux/kthread.h>
#include <linux/moduleparam.h>
#include <linux/namei.h>
#include <linux/uprobes.h>
#include <linux/time64.h>
#include <linux/sched/clock.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/err.h>

#define WRITE_BUFSIZE        4
#define OPLUS_F2FS_PRINTK "[F2FS]"
#define SIGVOLD_GET_LOG (SIGRTMIN + 0x13)
#define BOOT_MAX_ERRLOG_NUM  2
#define LOGLEVEL_BASE        48
#define KERN_EME_LEVEL       0
#define KERN_ERR_LEVEL       3
#define KERN_WAEN_LEVEL      4
#define KERN_DBG_LEVEL       7
#define DElTA_T              60
static int boot_geterrlog_num = 0;
static struct proc_dir_entry *oplus_f2fslog_storage_procfs;
static struct proc_dir_entry *oplus_f2fslog_level;
extern int pr_storage(const char *fmt, ...);
static int f2fslog_level = KERN_WAEN_LEVEL;
static u64 timestamp[2] = {0};

static struct task_struct *f2fs_get_task_struct_by_comm(const char *comm) {
    struct task_struct *task;

    for_each_process(task) {
        if (strcmp(task->comm, comm) == 0) {
            return task;
        }
    }

    return NULL;
}

static int oplus_f2fslog_storage_show(struct seq_file *m, void *v)
{
    seq_printf(m, "f2fslog level: %d\n", f2fslog_level);
    pr_storage("f2fslog level: %d\n", f2fslog_level);
    return 0;
}

static int oplus_f2fslog_storage_open(struct inode *inode, struct file *file)
{
    return single_open(file, oplus_f2fslog_storage_show, inode->i_private);
}

static ssize_t oplus_f2fslog_storage_write(struct file *file, const char __user *buffer,
                size_t count, loff_t *ppos)
{
    char kbuf[5] = {0};
    int ret = 0, tmp = 0;

    if (count > WRITE_BUFSIZE) {
        printk("input str is too long %s %d\n", __FUNCTION__, __LINE__);
        return -EINVAL;
    }

    tmp = f2fslog_level;

    if (copy_from_user(kbuf, buffer, count)) {
        printk("copy data from user buffer failed %s %d\n", __FUNCTION__, __LINE__);
    }

    ret = kstrtoint(kbuf, 10, &f2fslog_level);
    if(ret == 0){
        printk("kstrtoint success %s %d %s %d\n",kbuf, f2fslog_level, __FUNCTION__, __LINE__);
    } else {
        printk("kstrtoint fail\n");
    }

    if(f2fslog_level > KERN_DBG_LEVEL || f2fslog_level < KERN_EME_LEVEL) {
        f2fslog_level = tmp;
        printk("f2fs log level set error %d %s %d\n", f2fslog_level, __FUNCTION__, __LINE__);
    }

    return count;
}

static struct proc_ops oplus_f2fsloglevel_proc_ops = {
    .proc_open          = oplus_f2fslog_storage_open,
    .proc_read          = seq_read,
    .proc_write         = oplus_f2fslog_storage_write,
    .proc_release       = single_release,
    .proc_lseek         = default_llseek,
};

void f2fs_printk_wrapper(struct f2fs_sb_info *sbi, const char *fmt, ...)
{
    va_list args;
    char buf[1024];
    int level, log_level;
    struct va_format vaf;
    struct task_struct *task;
    unsigned long ts = 0;

    level = printk_get_level(fmt);
    log_level = level - LOGLEVEL_BASE;
    if(log_level > f2fslog_level || log_level < KERN_EME_LEVEL || log_level > KERN_DBG_LEVEL) {
        return;
    }

    ts = local_clock();
    do_div(ts, 1000000000);
    timestamp[1] = ts;

    va_start(args, fmt);
    vaf.fmt = printk_skip_level(fmt);
    vaf.va = &args;

    //skip printk_skip_level for print
    fmt = printk_skip_level(fmt);

    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    pr_storage(OPLUS_F2FS_PRINTK "[%s][%c]: %s\n", sbi ? sbi->sb->s_id : "unknown", level , buf);

    if(boot_geterrlog_num < BOOT_MAX_ERRLOG_NUM && log_level <= KERN_ERR_LEVEL) {
        if(timestamp[1] - timestamp[0] > DElTA_T) {
            task = f2fs_get_task_struct_by_comm("Binder:vold");
            printk("%s, %d\n", __FUNCTION__, __LINE__);
            if (!task) {
                pr_err(OPLUS_F2FS_PRINTK "No task_struct found for process\n");
                pr_storage(OPLUS_F2FS_PRINTK "No task_struct found for process\n");
            } else{
                send_sig_info(SIGVOLD_GET_LOG, SEND_SIG_PRIV, task);
            }

            boot_geterrlog_num ++;
            timestamp[0] = timestamp[1];
        }
    }
}

static int handler_f2fslog_storage_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct f2fs_sb_info *sbi = (struct f2fs_sb_info *)regs->regs[0];
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0))
    const char *fmt = (const char *)regs->regs[1];
    unsigned long arg2 = regs->regs[2];
    unsigned long arg3 = regs->regs[3];

    f2fs_printk_wrapper(sbi, fmt, arg2, arg3);

#else
    const char *fmt = (const char *)regs->regs[2];
    unsigned long arg3 = regs->regs[3];
    unsigned long arg4 = regs->regs[4];

    f2fs_printk_wrapper(sbi, fmt, arg3, arg4);
#endif
    return 0;
}

static struct kprobe oplus_f2fs_printk_kp = {
    .symbol_name = "f2fs_printk",
    .pre_handler = handler_f2fslog_storage_pre,
};

static int __init oplus_f2fshook_init(void) {
    int ret;
    printk("oplus_f2fshook_init\n");
    ret = register_kprobe(&oplus_f2fs_printk_kp);
    if (ret < 0) {
        printk(" register_kprobe f2fs kprobe_register_kp failed, return %d\n", ret);
        return ret;
    }

    oplus_f2fslog_storage_procfs = proc_mkdir("f2fslog_storage", NULL);
    if (!oplus_f2fslog_storage_procfs) {
        printk(" Failed to create oplus_f2fs_debug procfs\n");
        return -EFAULT;
    }

    oplus_f2fslog_level = proc_create("f2fslog_level", 0644, oplus_f2fslog_storage_procfs, &oplus_f2fsloglevel_proc_ops);
    if (oplus_f2fslog_level == NULL) {
        printk(" Failed to create storage_reliable procfs\n");
        return -EFAULT;
    }

    return 0;
}

static void __exit oplus_f2fshook_exit(void)
{
    unregister_kprobe(&oplus_f2fs_printk_kp);
    if(NULL == oplus_f2fslog_storage_procfs || NULL == oplus_f2fslog_level) {
        printk(" oplus_f2fshook_register or oplus_f2fshook_unregister is NULL\n");
        return;
    }

    remove_proc_entry("f2fslog_storage", oplus_f2fslog_storage_procfs);
    remove_proc_entry("f2fslog_level", oplus_f2fslog_level);
}

module_init(oplus_f2fshook_init);
module_exit(oplus_f2fshook_exit);
MODULE_LICENSE("GPL v2");
