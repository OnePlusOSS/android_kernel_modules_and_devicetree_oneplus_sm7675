#include <uapi/linux/sched/types.h>
#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <trace/hooks/sched.h>

#include "debug.h"
#include "early_detect.h"

static int g_debug_enable = 0;

static noinline int tracing_mark_write(const char *buf)
{
	trace_printk("%s", buf);
	return 0;
}

inline void systrace_c_printk(const char *msg, unsigned long val)
{
	if (g_debug_enable) {
		char buf[128];
		snprintf(buf, sizeof(buf), "C|99999|%s|%lu\n", msg, val);
		tracing_mark_write(buf);
	}
}

static ssize_t debug_enable_proc_write(struct file *file,
				       const char __user *buf, size_t count,
				       loff_t *ppos)
{
	char page[32] = { 0 };
	int ret;

	ret = simple_write_to_buffer(page, sizeof(page) - 1, ppos, buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(page, "%d", &g_debug_enable);
	if (ret != 1)
		return -EINVAL;

	return count;
}

static ssize_t debug_enable_proc_read(struct file *file, char __user *buf,
				      size_t count, loff_t *ppos)
{
	char page[32] = { 0 };
	int len;

	len = sprintf(page, "%d\n", g_debug_enable);

	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static const struct proc_ops debug_enable_proc_ops = {
	.proc_write = debug_enable_proc_write,
	.proc_read = debug_enable_proc_read,
	.proc_lseek = default_llseek,
};

int debug_init(void)
{
	proc_create_data("debug_enable", 0666, early_detect_dir,
			 &debug_enable_proc_ops, NULL);

	return 0;
}