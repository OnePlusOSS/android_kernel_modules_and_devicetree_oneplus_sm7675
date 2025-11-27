// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Oplus. All rights reserved.
 */

#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#include "binder_vip.h"
#include "binder_vip_sysfs.h"

#define OPLUS_BINDER_PROC_DIR	"oplus_vip_binder"

static struct proc_dir_entry *d_oplus_binder;


extern ssize_t taxi_thread_test_show(struct file *file, char __user *user_buf,
					 size_t count, loff_t *ppos);
extern ssize_t taxi_thread_test_store(struct file *file,
					  const char __user *user_buf, size_t count,
					  loff_t *ppos);
extern ssize_t taxi_thread_switch_vip_policy_group_show(struct file *file, char __user *user_buf,
					 size_t count, loff_t *ppos);
extern ssize_t taxi_thread_switch_vip_policy_group_store(struct file *file,
					  const char __user *user_buf, size_t count,
					  loff_t *ppos);
extern ssize_t taxi_thread_target_test_show(struct file *file, char __user *user_buf,
					 size_t count, loff_t *ppos);
extern ssize_t taxi_thread_target_test_store(struct file *file,
					  const char __user *user_buf, size_t count,
					  loff_t *ppos);
extern int cur_vip_policy_type_group;
static ssize_t proc_vip_policy_group_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	count = taxi_thread_test_store(file, (const char __user *)buf, count, ppos);

	return count;
}

static ssize_t proc_vip_policy_group_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	int ret;
	ret = taxi_thread_test_show(file, (char __user *)buf, count, ppos);

	return ret;/*simple_read_from_buffer(buf, count, ppos, buffer, len);*/
}

static ssize_t proc_switch_vip_policy_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	count = taxi_thread_switch_vip_policy_group_store(file, (const char __user *)buf, count, ppos);

	return count;
}

static ssize_t proc_switch_vip_policy_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	int ret;
	ret = taxi_thread_switch_vip_policy_group_show(file, (char __user *)buf, count, ppos);

	return ret;/*simple_read_from_buffer(buf, count, ppos, buffer, len);*/
}

static ssize_t proc_test_vip_server_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	count = taxi_thread_target_test_store(file, (const char __user *)buf, count, ppos);
	return count;
}

static ssize_t proc_test_vip_server_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	int ret;
	ret = taxi_thread_target_test_show(file, (char __user *)buf, count, ppos);

	return ret;/*simple_read_from_buffer(buf, count, ppos, buffer, len);*/
}

static const struct proc_ops proc_vip_policy_group_fops = {
	.proc_write		= proc_vip_policy_group_write,
	.proc_read		= proc_vip_policy_group_read,
	.proc_lseek		= default_llseek,
};

static const struct proc_ops proc_switch_vip_policy_fops = {
	.proc_write		= proc_switch_vip_policy_write,
	.proc_read		= proc_switch_vip_policy_read,
	.proc_lseek		= default_llseek,
};

static const struct proc_ops proc_test_vip_server_fops = {
	.proc_write		= proc_test_vip_server_write,
	.proc_read		= proc_test_vip_server_read,
	.proc_lseek		= default_llseek,
};

int oplus_binder_vip_sysfs_init(void)
{
	struct proc_dir_entry *proc_node;

	d_oplus_binder = proc_mkdir(OPLUS_BINDER_PROC_DIR, NULL);
	if (!d_oplus_binder) {
		pr_err("failed to create proc dir d_oplus_binder\n");
		goto err_create_d_oplus_binder;
	}

	proc_node = proc_create("vip_policy_group", 0666, d_oplus_binder, &proc_vip_policy_group_fops);
	if (!proc_node) {
		pr_err("failed to create proc node vip_policy_group\n");
		goto err_create_vip_policy_group;
	}

	proc_node = proc_create("switch_vip_policy", 0666, d_oplus_binder, &proc_switch_vip_policy_fops);
	if (!proc_node) {
		pr_err("failed to create proc node switch_vip_policy\n");
		goto err_create_switch_vip_policy;
	}

	proc_node = proc_create("test_vip_server", 0666, d_oplus_binder, &proc_test_vip_server_fops);
	if (!proc_node) {
		pr_err("failed to create proc node test_vip_server\n");
		goto err_create_test_vip_server;
	}

	pr_info("%s success\n", __func__);
	return 0;

err_create_test_vip_server:
	remove_proc_entry("switch_vip_policy", d_oplus_binder);

err_create_switch_vip_policy:
	remove_proc_entry("vip_policy_group", d_oplus_binder);

err_create_vip_policy_group:
	remove_proc_entry(OPLUS_BINDER_PROC_DIR, NULL);

err_create_d_oplus_binder:
	return -ENOENT;
}

void oplus_binder_vip_sysfs_deinit(void)
{
	remove_proc_entry("vip_policy_group", d_oplus_binder);
	remove_proc_entry("switch_vip_policy", d_oplus_binder);
	remove_proc_entry("test_vip_server", d_oplus_binder);
	remove_proc_entry(OPLUS_BINDER_PROC_DIR, NULL);
}
