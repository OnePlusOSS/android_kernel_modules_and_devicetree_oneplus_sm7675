//SPDX-License-Identifier: GPL-2.0 only
/*
 * Copyright (C) 2023 Oplus. All rights reserved.
 */
#include <linux/proc_fs.h>

#include "fqm_main.h"

#define FREQQOS_MONITOR_NODE "oplus_freqreq_monitor"

static struct proc_dir_entry *freqqos_monitor_proc;

int g_fqm_monitor_enable;
int g_fqm_debug_enable;

static ssize_t proc_fqm_debug_write(struct file *file, const char __user *buf,
                size_t count, loff_t *ppos)
{
	char buffer[13];
	int err, val;

	memset(buffer, 0, sizeof(buffer));

	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;

	if (copy_from_user(buffer, buf, count))
		return -EFAULT;

	buffer[count] = '\0';
	err = kstrtoint(strstrip(buffer), 10, &val);
	if (err)
		return err;

	g_fqm_debug_enable = val;

	return count;
}

static ssize_t proc_fqm_debug_read(struct file *file, char __user *buf,
            size_t count, loff_t *ppos)
{
	char buffer[13];
	size_t len = 0;

	len = snprintf(buffer, sizeof(buffer), "enabled=%d\n", g_fqm_debug_enable);

	return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static const struct proc_ops fqm_freq_debug_fops = {
	.proc_write                = proc_fqm_debug_write,
	.proc_read                 = proc_fqm_debug_read,
};

static ssize_t proc_enable_write(struct file *file, const char __user *buf,
                size_t count, loff_t *ppos)
{
	char buffer[13];
	int err, val;

	memset(buffer, 0, sizeof(buffer));

	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;

	if (copy_from_user(buffer, buf, count))
		return -EFAULT;

	buffer[count] = '\0';
	err = kstrtoint(strstrip(buffer), 10, &val);
	if (err)
		return err;

	g_fqm_monitor_enable = !!val;

	return count;
}

static ssize_t proc_enable_read(struct file *file, char __user *buf,
            size_t count, loff_t *ppos)
{
	char buffer[13];
	size_t len = 0;

	len = snprintf(buffer, sizeof(buffer), "enabled=%d\n", g_fqm_monitor_enable);

	return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static const struct proc_ops fqm_freq_enable_fops = {
	.proc_write                = proc_enable_write,
	.proc_read                 = proc_enable_read,
};

static ssize_t proc_threshold_write(struct file *file, const char __user *buf,
                size_t count, loff_t *ppos)
{
	int i = 0, err;
	char buffer[256];
	char *temp_str, *token;
	char str_val[5][8];

	memset(buffer, 0, sizeof(buffer));

	if(count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;

	if(copy_from_user(buffer, buf, count))
		return -EFAULT;

	buffer[count] = '\0';
	temp_str = strstrip(buffer);
	while ((token = strsep(&temp_str, " ")) && *token && (i < max_cluster_num)) {
		int threshold = 0;
		strlcpy(str_val[i], token, sizeof(str_val[i]));
		err = kstrtoint(strstrip(str_val[i]), 10, &threshold);
		if(err)
			pr_err("faild to write threshold (i=%d str=%s)\n", i, str_val[i]);

		if (threshold > 0 && threshold < default_fqm_threshold)
			fqm_set_threshold(threshold, i);
		i++;
	}

	return count;
}

static ssize_t proc_threshold_read(struct file *file, char __user *buf,
            size_t count, loff_t *ppos)
{
	char buffer[256];
	int i;
	size_t len = 0;

	for(i = 0; i < max_cluster_num; ++i)
		len += snprintf(buffer + len, sizeof(buffer) - len, "%d ", fqm_get_threshold(i));

	len += snprintf(buffer + len, sizeof(buffer) - len, "\n");

	return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static const struct proc_ops fqm_freq_threshold_fops = {
	.proc_write                = proc_threshold_write,
	.proc_read                 = proc_threshold_read,
};

static int fqm_freq_dump_show(struct seq_file *s, void *v)
{
	return fqm_dump(s, v);
}

static int fqm_freq_dump_open(struct inode *inode, struct file *file)
{
	return single_open(file, fqm_freq_dump_show, NULL);
}

static const struct proc_ops fqm_dump_fops = {
	.proc_open = fqm_freq_dump_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static ssize_t proc_read_int(struct file *filp,
	char __user *buff, size_t count, loff_t *offp, int val)
{
	char kbuf[128];
	int len = 0;

	len = scnprintf(kbuf, sizeof(kbuf), "%d\n", val);

	if (*offp >= len)
		return 0;

	if (count > len - *offp)
		count = len - *offp;

	if (copy_to_user(buff, kbuf + *offp, count))
		return -EFAULT;

	*offp += count;
	return count;
}

static ssize_t proc_write_int(struct file *file,
	const char __user *buf, size_t count, loff_t *ppos, int *val)
{
	char kbuf[128];
	int ret;

	if (count > sizeof(kbuf) - 1)
		count = sizeof(kbuf) - 1;

	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;

	kbuf[count] = 0;

	ret = kstrtoint(kbuf, 10, val);
	if (ret < 0)
		return ret;
	return count;
}

static ssize_t fqm_dump_read(struct file *filp, char __user *buff, size_t count, loff_t *offp)
{
	return proc_read_int(filp, buff, count, offp, get_fqm_dump_val());
}

static ssize_t fqm_dump_write(struct file *file, const char __user *buf,
	size_t count, loff_t *ppos)
{
	int val = 0;
	ssize_t cnt;

	cnt = proc_write_int(file, buf, count, ppos, &val);
	set_fqm_dump_val(val);
	return cnt;
}

static const struct proc_ops fqm_dump_enable_fops = {
	.proc_write	= fqm_dump_write,
	.proc_read	= fqm_dump_read,
};

int freqqos_monitor_proc_init(void)
{
	int ret = 0;
	struct proc_dir_entry *pentry;

	freqqos_monitor_proc = proc_mkdir(FREQQOS_MONITOR_NODE, NULL);
	if (!freqqos_monitor_proc) {
		pr_err("failed to create oplus_freqreq_monitor\n");
		goto err_create_freqqos_monitor;
	}

	pentry = proc_create("freq_threshold", 0666, freqqos_monitor_proc, &fqm_freq_threshold_fops);
	if (!pentry) {
		pr_err("failed to create freq_threshold\n");
		goto err_create_freq_threshold;
	}

	pentry = proc_create("fqm_enable", 0666, freqqos_monitor_proc, &fqm_freq_enable_fops);
	if (!pentry) {
		pr_err("failed to create fqm_enable");
		goto err_create_fqm_enable;
	}

	pentry = proc_create("fqm_debug", 0666, freqqos_monitor_proc, &fqm_freq_debug_fops);
	if (!pentry) {
		pr_err("failed to create fqm_debug");
		goto err_create_fqm_debug;
	}
	pentry = proc_create("fqm_dump", 0644, freqqos_monitor_proc, &fqm_dump_fops);
	if (!pentry) {
		pr_err("failed to create fqm_dump");
		goto err_create_fqm_dump;
	}
	pr_info("oplus_freqqos_monitor_proc_init!");

	pentry = proc_create("fqm_dump_enable", 0644, freqqos_monitor_proc, &fqm_dump_enable_fops);
	if (!pentry) {
		pr_err("failed to create fqm_dump_enable");
		goto err_create_fqm_dump_enable;
	}
	return ret;

err_create_fqm_dump_enable:
	remove_proc_entry("fqm_dump", freqqos_monitor_proc);
err_create_fqm_dump:
	remove_proc_entry("fqm_debug", freqqos_monitor_proc);
err_create_fqm_debug:
	remove_proc_entry("fqm_enable", freqqos_monitor_proc);
err_create_fqm_enable:
	remove_proc_entry("freq_threshold", freqqos_monitor_proc);
err_create_freq_threshold:
	remove_proc_entry(FREQQOS_MONITOR_NODE, NULL);
err_create_freqqos_monitor:
	return -ENOENT;
}

void freqqos_monitor_proc_exit(void)
{
	remove_proc_entry("fqm_dump_enable", freqqos_monitor_proc);
	remove_proc_entry("fqm_dump", freqqos_monitor_proc);
	remove_proc_entry("fqm_debug", freqqos_monitor_proc);
	remove_proc_entry("fqm_enable", freqqos_monitor_proc);
	remove_proc_entry("freq_threshold", freqqos_monitor_proc);
	remove_proc_entry(FREQQOS_MONITOR_NODE, NULL);
}
