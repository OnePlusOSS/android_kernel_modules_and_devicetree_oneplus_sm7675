// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Oplus. All rights reserved.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kprobes.h>

#include "frame_boost.h"
#include "frame_group.h"
#include "frame_debug.h"
#if IS_ENABLED(CONFIG_OPLUS_FEATURE_SCHED_ASSIST)
#include <../kernel/oplus_cpu/sched/sched_assist/sa_common.h>
#endif

struct fbg_vendor_hook fbg_hook;
extern struct frame_group *frame_boost_groups[MAX_NUM_FBG_ID];

static struct kprobe kp = {
	.symbol_name    = "rb_simple_write",
};

#if IS_ENABLED(CONFIG_OPLUS_FEATURE_SF_SLIDE_BOOST)
static inline bool slide_boost_scene(void)
{
	return sysctl_slide_boost_enabled || sysctl_input_boost_enabled
		|| sched_assist_scene(SA_ANIM) || sched_assist_scene(SA_GPU_COMPOSITION);
}

static inline unsigned long task_util(struct task_struct *p)
{
	return READ_ONCE(p->se.avg.util_avg);
}

static inline bool sf_skip_min_cpu(struct task_struct *p)
{
	return task_util(p) >= sysctl_slide_min_util;
}

bool slide_rt_boost(struct task_struct *p)
{
	struct oplus_task_struct *ots = get_oplus_task_struct(p);

	if (IS_ERR_OR_NULL(ots))
		return false;

	if (test_bit(IM_FLAG_SURFACEFLINGER, &ots->im_flag) || test_bit(IM_FLAG_RENDERENGINE, &ots->im_flag)) {
		if (slide_boost_scene() && sf_skip_min_cpu(p))
			return true;
	}

	return false;
}
EXPORT_SYMBOL_GPL(slide_rt_boost);
#endif

static inline bool vaild_stune_boost_type(unsigned int type)
{
	return (type >= 0) && (type < BOOST_MAX_TYPE);
}

void fbg_set_stune_boost(int value, int grp_id, unsigned int type)
{
	struct frame_group *grp = NULL;

	if (!vaild_stune_boost_type(type))
		return;
	grp = frame_boost_groups[grp_id];
	if (!grp)
		return;
	grp->stune_boost[type] = value;
}
EXPORT_SYMBOL_GPL(fbg_set_stune_boost);

int fbg_get_stune_boost(int grp_id, unsigned int type)
{
	struct frame_group *grp = NULL;

	if (!vaild_stune_boost_type(type))
		return 0;
	grp = frame_boost_groups[grp_id];
	if (!grp)
		return 0;
	return grp->stune_boost[type];
}
EXPORT_SYMBOL_GPL(fbg_get_stune_boost);


static void __kprobes rb_simple_write_handler_post(struct kprobe *p, struct pt_regs *regs,
	unsigned long flags)
{
	fbg_dbg_reset();
}


/******************
 * moduler function
 *******************/
static int __init oplus_frame_boost_init(void)
{
	int ret = 0;

	fbg_sysctl_init();

	ret = frame_info_init();
	if (ret != 0)
		goto out;

	ret = frame_group_init();
	if (ret != 0)
		goto out;

	/* please register your hooks at the end of init. */
	register_frame_group_vendor_hooks();

	fbg_migrate_task_callback = fbg_skip_migration;
	fbg_android_rvh_schedule_callback = fbg_android_rvh_schedule_handler;
	kp.post_handler = rb_simple_write_handler_post;
	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		goto out;
	}
	fbg_dbg_init();
	ofb_debug("oplus_bsp_frame_boost.ko init succeed!!\n");

out:
	return ret;
}

module_init(oplus_frame_boost_init);
MODULE_DESCRIPTION("Oplus Frame Boost Moduler");
MODULE_LICENSE("GPL v2");
