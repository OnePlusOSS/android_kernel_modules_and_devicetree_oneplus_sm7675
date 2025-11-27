// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Oplus. All rights reserved.
 */
#define pr_fmt(fmt) KBUILD_MODNAME " %s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/proc_fs.h>

#include "../../../drivers/misc/mediatek/slbc/slbc_ipi.h"
#include "../../../drivers/misc/mediatek/slbc/slbc.h"

#include "oplus_slc.h"
#include "osml.h"

static int dbg_msg;
static int window_size = 32; /* default 32 */
static int hitrate_uid = -1; /* uid from hit rate get */
static int csize_uid = -1; /* uid from cache size get */
static int force_uid = -1; /* uid to force */
static int cache_size = -1; /* cache size from uid set force */
static int slbc_disable; /* enable or disable slbc */
static int hint;
static unsigned int c_config[ID_GPU]; /* only 2 master can be set ceil, ID_CPU=1, ID_GPU=2, c_config[0] save cpu, c_config[1] save gpu */
static unsigned int f_config[ID_GPU]; /* only 2 master can be set force, ID_CPU=1, ID_GPU=2, c_config[0] save cpu, c_config[1] save gpu */
static int hb_uid = -1; /* uid which need to get hit bw */
static int cpu_usage = -1;
static int gpu_usage = -1;
static int other_usage = -1;
static int cdwb_disable; /* cdwb switch, default:0 (enable), disable:1 */

static ssize_t dbg_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int ret, dbg_enable;

	ret = simple_write_to_buffer(page, sizeof(page), ppos, buf, count);
	if (ret <= 0)
		return -EINVAL;

	ret = sscanf(page, "%d", &dbg_enable);
	if (ret != 1)
		return -EINVAL;

	if (!!dbg_enable == dbg_msg)
		return count;

	dbg_msg = !!dbg_enable;

	return count;
}

static ssize_t dbg_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int len;

	len = sprintf(page, "%d\n", dbg_msg);
	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static const struct proc_ops dbg_proc_ops = {
	.proc_write		= dbg_proc_write,
	.proc_read		= dbg_proc_read,
	.proc_lseek		= default_llseek,
};

static ssize_t slbc_dis_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int ret, slc_off, disable;

	ret = simple_write_to_buffer(page, sizeof(page), ppos, buf, count);
	if (ret <= 0)
		return -EINVAL;

	ret = sscanf(page, "%d", &slc_off);
	if (ret != 1)
		return -EINVAL;

	if (slbc_disable == !!slc_off)
		return count;

	disable = !!slc_off;

	ret = slbc_sspm_slc_disable(disable);
	if (!ret) {
		slbc_disable = disable;
		pr_info("slc %s success!!!\n", (!!slc_off) ? "disable" : "enable");
	} else
		pr_err("slc %s failed!!!\n", (!!slc_off) ? "disable" : "enable");

	return count;
}

static ssize_t slbc_dis_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int len;

	len = sprintf(page, "%d\n", slbc_disable);
	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static const struct proc_ops slbc_dis_proc_ops = {
	.proc_write		= slbc_dis_proc_write,
	.proc_read		= slbc_dis_proc_read,
	.proc_lseek		= default_llseek,
};

static ssize_t hitrate_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int len;

	if (hitrate_uid >= ID_MAX || hitrate_uid <= ID_PD) {
		pr_err("uid not match! uid=%d\n", hitrate_uid);
		return 0;
	}

	len = sprintf(page, "%d\n", slbc_get_cache_hit_rate(hitrate_uid));
	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static ssize_t hitrate_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int ret, uid;

	ret = simple_write_to_buffer(page, sizeof(page), ppos, buf, count);
	if (ret <= 0)
		return -EINVAL;

	ret = sscanf(page, "%d", &uid);
	if (ret != 1)
		return -EINVAL;

	if (uid <= ID_PD || uid >= ID_MAX)
		return -EINVAL;

	hitrate_uid = uid;

	return count;
}

static const struct proc_ops hitrate_proc_ops = {
	.proc_write		= hitrate_proc_write,
	.proc_read		= hitrate_proc_read,
	.proc_lseek		= default_llseek,
};

static ssize_t window_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int len;

	len = sprintf(page, "%d\n", window_size);
	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static ssize_t window_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int ret, window;

	ret = simple_write_to_buffer(page, sizeof(page), ppos, buf, count);
	if (ret <= 0)
		return -EINVAL;

	ret = sscanf(page, "%x", &window);
	if (ret != 1)
		return -EINVAL;

	if (window < 1 || window > 1000) {
		pr_err("window out of bound, window=%d,0x%x\n", window, window);
		return -EINVAL;
	}

	if (window == window_size)
		return count;

	ret = slbc_window(window);
	if (!ret) {
		window_size = window;
		if (dbg_msg)
			pr_info("window set success\n");
	} else {
		pr_err("window set failed\n");
	}

	return count;
}

static const struct proc_ops window_proc_ops = {
	.proc_write		= window_proc_write,
	.proc_read		= window_proc_read,
	.proc_lseek		= default_llseek,
};

static ssize_t csize_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int len;

	if (csize_uid <= ID_PD)
		return 0;

	len = sprintf(page, "%d\n", slbc_get_cache_size(csize_uid));
	/* if ret < 0, it gets cache size failed, otherwise, >=0 means success */
	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static ssize_t csize_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int ret, uid;

	ret = simple_write_to_buffer(page, sizeof(page), ppos, buf, count);
	if (ret <= 0)
		return -EINVAL;

	ret = sscanf(page, "%d", &uid);
	if (ret != 1)
		return -EINVAL;

	if (uid <= ID_PD || uid >= ID_MAX)
		return -EINVAL;

	csize_uid = uid;

	return count;
}

static const struct proc_ops csize_proc_ops = {
	.proc_write		= csize_proc_write,
	.proc_read		= csize_proc_read,
	.proc_lseek		= default_llseek,
};

static ssize_t force_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int len;

	len = sprintf(page, "uid=%d, force size=%d\n", force_uid, cache_size);
	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static ssize_t force_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int ret, uid, size;

	ret = simple_write_to_buffer(page, sizeof(page), ppos, buf, count);
	if (ret <= 0)
		return -EINVAL;

	ret = sscanf(page, "%d,%d", &uid, &size);
	if (ret != 2)
		return -EINVAL;

	if (uid <= ID_PD || uid >= ID_MAX)
		return -EINVAL;

	if (size > SLC_MAX_SIZE || size < 0)
		return -EINVAL;


	/* set force from uid and size */
	ret = slbc_force_cache(uid, size);
	if (!ret) {
		force_uid = uid;
		cache_size = size;
		f_config[uid-1] = size;
		pr_info("force uid success uid=%d, size=%d\n", uid, size);
	} else {
		f_config[uid-1] = 0;
		pr_err("force uid failed, uid=%d, size=%d\n", uid, size);
	}

	return count;
}

static const struct proc_ops force_proc_ops = {
	.proc_write		= force_proc_write,
	.proc_read		= force_proc_read,
	.proc_lseek		= default_llseek,
};

static ssize_t fconfig_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int len;

	len = sprintf(page, "cpu=%u, gpu=%u\n", f_config[ID_CPU-1], f_config[ID_GPU-1]);
	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static const struct proc_ops fconfig_proc_ops = {
	.proc_read		= fconfig_proc_read,
	.proc_lseek		= default_llseek,
};

static ssize_t ceil_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int len;

	len = sprintf(page, "cpu=%u, gpu=%u\n", c_config[ID_CPU-1], c_config[ID_GPU-1]);
	return simple_read_from_buffer(buf, count, ppos, page, len);
}
/* ceil = 0 means release ceil of uid */
static ssize_t ceil_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int ret, uid, size;

	ret = simple_write_to_buffer(page, sizeof(page), ppos, buf, count);
	if (ret <= 0)
		return -EINVAL;

	ret = sscanf(page, "%d,%d", &uid, &size);
	if (ret != 2)
		return -EINVAL;

	/* only C/G can be set */
	if (uid != ID_CPU && uid != ID_GPU)
		return -EINVAL;

	/* size limitation */
	if (size > SLC_MAX_SIZE || size < 0)
		return -EINVAL;

	if (size == 0)
		pr_info("cancel ceil setting of uid=%d\n", uid);

	/* set ceil from uid and size, size = 0 to cancel ceil setting of uid */
	ret = slbc_ceil(uid, size);
	if (ret)
		pr_err("uid set ceil failed, uid=%d, size=%d\n", uid, size);
	else {
		c_config[uid-1] = size;
		if (dbg_msg)
			pr_info("uid set ceil success, uid=%d, size=%d\n", uid, size);
	}

	return count;
}

static const struct proc_ops ceil_proc_ops = {
	.proc_write		= ceil_proc_write,
	.proc_read		= ceil_proc_read,
	.proc_lseek		= default_llseek,
};

/* 100ms sample rate */
static ssize_t hb_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int len;

	if (hb_uid < 0)
		return 0;

	/* get hit bw by uid */
	len = sprintf(page, "%d\n", slbc_get_cache_hit_bw(hb_uid));
	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static ssize_t hb_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int ret, uid;

	ret = simple_write_to_buffer(page, sizeof(page), ppos, buf, count);
	if (ret <= 0)
		return -EINVAL;

	ret = sscanf(page, "%d", &uid);
	if (ret != 1)
		return -EINVAL;

	if (uid <= ID_PD || uid >= ID_MAX)
		return -EINVAL;

	hb_uid = uid;
	return count;
}

static const struct proc_ops slbc_hb_proc_ops = {
	.proc_write		= hb_proc_write,
	.proc_read		= hb_proc_read,
	.proc_lseek		= default_llseek,
};

/* cache usage */
static ssize_t cusage_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int len, ret;

	ret = slbc_get_cache_usage(&cpu_usage, &gpu_usage, &other_usage);

	if (ret)
		return 0;

	len = sprintf(page, "%d,%d,%d\n", cpu_usage, gpu_usage, other_usage);
	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static const struct proc_ops slbc_cusage_proc_ops = {
	.proc_read		= cusage_proc_read,
	.proc_lseek		= default_llseek,
};

static ssize_t hint_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int len;

	len = sprintf(page, "hint=%d\n", hint);
	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static ssize_t hint_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int ret, input;

	ret = simple_write_to_buffer(page, sizeof(page), ppos, buf, count);
	if (ret <= 0)
		return -EINVAL;

	ret = sscanf(page, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	if (input < 0)
		return -EINVAL;

	/* NEED TO UPDATE HERE */
	hint = input;

	return count;
}

static const struct proc_ops hint_proc_ops = {
	.proc_write		= hint_proc_write,
	.proc_read		= hint_proc_read,
	.proc_lseek		= default_llseek,
};

static ssize_t dis_cdwb_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int len;

	len = sprintf(page, "cdwb=%d\n", cdwb_disable);
	return simple_read_from_buffer(buf, count, ppos, page, len);
}

static ssize_t dis_cdwb_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char page[32] = {0};
	int ret, input;

	ret = simple_write_to_buffer(page, sizeof(page), ppos, buf, count);
	if (ret <= 0)
		return -EINVAL;

	ret = sscanf(page, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	if (input < 0)
		return -EINVAL;

	if (!!input == cdwb_disable)
		return -EINVAL;

	cdwb_disable = !!input;
#if IS_ENABLED(CONFIG_MTK_SLBC_MT6989)
	oplus_slc_cdwb_switch(cdwb_disable);
#endif

	return count;
}

static const struct proc_ops dis_cdwb_proc_ops = {
	.proc_write		= dis_cdwb_proc_write,
	.proc_read		= dis_cdwb_proc_read,
	.proc_lseek		= default_llseek,
};

static void create_slc_proc(void)
{
	if (!oplus_slc_dir)
		return;

	proc_create_data("dbg", 0664, oplus_slc_dir, &dbg_proc_ops, NULL);

	/* slbc ceil set */
	proc_create_data("ceil", 0664, oplus_slc_dir, &ceil_proc_ops, NULL);
	/* slbc window set */
	proc_create_data("window", 0664, oplus_slc_dir, &window_proc_ops, NULL);
	/* slbc uid cache hit rate get */
	proc_create_data("hitrate", 0664, oplus_slc_dir, &hitrate_proc_ops, NULL);
	/* slbc uid cache size get (allocated size, not used size) */
	proc_create_data("size", 0664, oplus_slc_dir, &csize_proc_ops, NULL);
	/* slbc uid force size set */
	proc_create_data("force", 0664, oplus_slc_dir, &force_proc_ops, NULL);
	/* slbc enable */
	proc_create_data("disable", 0664, oplus_slc_dir, &slbc_dis_proc_ops, NULL);
	/* slbc get_cache_hit_bw */
	proc_create_data("hitbw", 0664, oplus_slc_dir, &slbc_hb_proc_ops, NULL);
	/* slbc get cache usage */
	proc_create_data("usage", 0664, oplus_slc_dir, &slbc_cusage_proc_ops, NULL);
	/* check CPU and GPU force config */
	proc_create_data("fcfg", 0664, oplus_slc_dir, &fconfig_proc_ops, NULL);

	proc_create_data("hint", 0664, oplus_slc_dir, &hint_proc_ops, NULL);

	proc_create_data("dis_cdwb", 0664, oplus_slc_dir, &dis_cdwb_proc_ops, NULL);
}

static int __init oplus_slc_init(void)
{
	oplus_slc_dir = proc_mkdir("oplus_slc", NULL);
	if (!oplus_slc_dir) {
		pr_err("fail to mkdir /proc/oplus_slc\n");
		return -ENOMEM;
	}

	create_slc_proc();

	osml_init(oplus_slc_dir);

	pr_fmt("oplus_slc init\n");

	return 0;
}

static void __exit oplus_slc_exit(void)
{
	if (oplus_slc_dir) {
		remove_proc_entry("dbg", oplus_slc_dir);
		remove_proc_entry("ceil", oplus_slc_dir);
		remove_proc_entry("window", oplus_slc_dir);
		remove_proc_entry("hitrate", oplus_slc_dir);
		remove_proc_entry("size", oplus_slc_dir);
		remove_proc_entry("force", oplus_slc_dir);
		remove_proc_entry("disable", oplus_slc_dir);
		remove_proc_entry("hitbw", oplus_slc_dir);
		remove_proc_entry("usage", oplus_slc_dir);
		remove_proc_entry("fcfg", oplus_slc_dir);
		remove_proc_entry("hint", oplus_slc_dir);
		remove_proc_entry("oplus_slc", NULL);
		oplus_slc_dir = NULL;
	}
	osml_exit();
	pr_fmt("oplus slc exit");
}

module_init(oplus_slc_init);
module_exit(oplus_slc_exit);
MODULE_LICENSE("GPL v2");
