// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 Oplus. All rights reserved.
 */

#include <linux/ioctl.h>
#include <linux/compat.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <../fs/proc/internal.h>

#include <../kernel/oplus_cpu/sched/sched_assist/sa_common.h>
#include <../kernel/oplus_cpu/sched/frame_boost/frame_boost.h>

#include "frame_ioctl.h"
#include "ua_ioctl_common.h"

#define FRAMEBOOST_PROC_NODE "oplus_frame_boost"
#define INVALID_VAL (INT_MIN)

static struct proc_dir_entry *frame_boost_proc;

#ifdef CONFIG_ARCH_MEDIATEK
u64 curr_frame_start;
EXPORT_SYMBOL(curr_frame_start);
u64 prev_frame_start;
EXPORT_SYMBOL(prev_frame_start);
#endif /* CONFIG_ARCH_MEDIATEK */

static void crtl_update_refresh_rate(int pid, int tid, unsigned int vsyncNs)
{
	unsigned int frame_rate =  NSEC_PER_SEC / (unsigned int)(vsyncNs);
	bool is_sf = false;
	int grp_id = 0;
	unsigned long im_flag = IM_FLAG_NONE;

	im_flag = oplus_get_im_flag(current);
	is_sf = (test_bit(IM_FLAG_SURFACEFLINGER, &im_flag));
	if (is_sf) {
		/*
		 * set sf frame rate as max frame rate
		 */
		set_frame_rate(SF_FRAME_GROUP_ID, frame_rate);
		set_frame_group_window_size(SF_FRAME_GROUP_ID, vsyncNs);
		return;
	}

	/* frame rate will be updated by UI thread(pid) and render thread(tid) */
	if (pid != current->pid && tid != current->pid)
		return;

	grp_id = task_get_frame_group_id(pid);
	if (!is_active_multi_frame_fbg(grp_id) && (grp_id != GAME_FRAME_GROUP_ID))
		return;

	if (set_frame_rate(grp_id, frame_rate))
		set_frame_group_window_size(grp_id, vsyncNs);
}

/*********************************
 * frame boost ioctl proc
 *********************************/
static long ofb_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	int grp_id = 0;
	struct ofb_ctrl_data data;
	void __user *uarg = (void __user *)arg;

	if (_IOC_TYPE(cmd) != OFB_MAGIC)
		return -EINVAL;

	if (_IOC_NR(cmd) >= CMD_ID_MAX)
		return -EINVAL;

	if (copy_from_user(&data, uarg, sizeof(data))) {
		ofb_err("invalid address");
		return -EFAULT;
	}

	if (unlikely(sysctl_frame_boost_debug & DEBUG_VERBOSE))
		ofb_debug("CMD_ID[%d], stage[%d], pid[%d], tid[%d] vsyncNs[%lld] buffer_count[%d] next_vsync[%d]\n",
			_IOC_NR(cmd), data.stage, data.pid, data.tid, data.vsyncNs,
				data.m_rtg.frame_buffer_count, data.m_rtg1.data);

	switch (cmd) {
	case CMD_ID_SET_FPS:
		if (data.vsyncNs <= 0)
			return -EINVAL;
		crtl_update_refresh_rate(data.pid, data.tid, (unsigned int)data.vsyncNs);
		break;
	case CMD_ID_BOOST_HIT:
		/* App which is not our frame boost target may request frame vsync(like systemui),
		 * just ignore hint from them! Return zero to avoid too many androd error log
		 */

		if ((data.pid != current->pid) && (data.tid != current->pid))
				return ret;

		grp_id = task_get_frame_group_id(data.pid);
		if (grp_id <= 0)
			return grp_id;

		if (data.stage == BOOST_FRAME_START) {
#ifdef CONFIG_ARCH_MEDIATEK
			u64 frame_start_time = ktime_get_ns();

			if (curr_frame_start != frame_start_time)
					prev_frame_start = curr_frame_start;
			curr_frame_start = frame_start_time;
#endif /* CONFIG_ARCH_MEDIATEK */

			/*sf, inputmethod and game frame group handle frame state separately*/
			if (grp_id == SF_FRAME_GROUP_ID ||
				grp_id == GAME_FRAME_GROUP_ID ||
				grp_id == INPUTMETHOD_FRAME_GROUP_ID)
				return ret;

			set_frame_state(grp_id, FRAME_START, data.m_rtg.frame_buffer_count, -1);
			rollover_frame_group_window(grp_id);
			default_group_update_cpufreq(grp_id);
		}

		if (data.stage == FRAME_BOOST_END) {
			/*sf, inputmethod and game frame group handle frame state separately*/
			if (grp_id == SF_FRAME_GROUP_ID ||
				grp_id == GAME_FRAME_GROUP_ID ||
				grp_id == INPUTMETHOD_FRAME_GROUP_ID)
				return ret;
			fbg_set_end_exec(grp_id);
			set_frame_state(grp_id, FRAME_END, data.m_rtg.frame_buffer_count, data.m_rtg1.data);
			default_group_update_cpufreq(grp_id);
		}

		/* TODO stune for multi group, not for sf group. BOOST_UTIL_FRAME_RATE could be 0? */
		if (data.stage == BOOST_OBTAIN_VIEW) {
			if (!is_multi_frame_fbg(grp_id))
				return -INVALID_FBG_ID;
			if (get_frame_rate(grp_id) >= fbg_get_stune_boost(grp_id, BOOST_UTIL_FRAME_RATE)) {
				set_frame_util_min(grp_id, fbg_get_stune_boost(grp_id, BOOST_UTIL_MIN_OBTAIN_VIEW), true);
				default_group_update_cpufreq(grp_id);
			}
		}

		/* TODO stune for multi group, not for sf group */
		if (data.stage == BOOST_FRAME_TIMEOUT) {
			if (!is_multi_frame_fbg(grp_id))
				return -INVALID_FBG_ID;
			if (get_frame_rate(grp_id) >= fbg_get_stune_boost(grp_id, BOOST_UTIL_FRAME_RATE) &&
				check_putil_over_thresh(grp_id, fbg_get_stune_boost(grp_id, BOOST_UTIL_MIN_THRESHOLD))) {
				set_frame_util_min(grp_id, fbg_get_stune_boost(grp_id, BOOST_UTIL_MIN_TIMEOUT), true);
				default_group_update_cpufreq(grp_id);
			}
		}

		if (data.stage == BOOST_SET_RENDER_THREAD)
			set_render_thread(grp_id, data.pid, data.tid);

		if (data.stage == BOOST_INPUT_START) {
			if (is_active_multi_frame_fbg(grp_id)) {
				set_frame_state(grp_id, FRAME_START, -1, 1);
				rollover_frame_group_window(grp_id);
				set_frame_util_min(grp_id, fbg_get_stune_boost(grp_id, BOOST_UTIL_MIN_TIMEOUT), true);
			} else if (grp_id != INPUTMETHOD_FRAME_GROUP_ID) {
				return ret;
			}
			input_set_boost_start(grp_id);
		}

		break;
	case CMD_ID_END_FRAME:
		/* ofb_debug("CMD_ID_END_FRAME pid:%d tid:%d", data.pid, data.tid); */
		break;
	case CMD_ID_SF_FRAME_MISSED:
		/* ofb_debug("CMD_ID_END_FRAME pid:%d tid:%d", data.pid, data.tid); */
		break;
	case CMD_ID_SF_COMPOSE_HINT:
		/* ofb_debug("CMD_ID_END_FRAME pid:%d tid:%d", data.pid, data.tid); */
		break;
	case CMD_ID_IS_HWUI_RT:
		/* ofb_debug("CMD_ID_END_FRAME pid:%d tid:%d", data.pid, data.tid); */
		break;
	case CMD_ID_SET_TASK_TAGGING:
		/* ofb_debug("CMD_ID_END_FRAME pid:%d tid:%d", data.pid, data.tid); */
		break;
	default:
		/* ret = -EINVAL; */
		break;
	}

	return ret;
}

static int fbg_set_task_preferred_cluster(void __user *uarg)
{
	struct ofb_ctrl_cluster data;

	if (uarg == NULL)
		return -EINVAL;

	if (copy_from_user(&data, uarg, sizeof(data)))
		return -EFAULT;

	return __fbg_set_task_preferred_cluster(data.tid, data.cluster_id);
}

static long fbg_add_task_to_group(void __user *uarg)
{
	struct ofb_key_thread_info info;
	unsigned int thread_num;
	unsigned int i;

	if (uarg == NULL)
		return -EINVAL;

	if (copy_from_user(&info, uarg, sizeof(struct ofb_key_thread_info))) {
		ofb_debug("%s: copy_from_user fail\n", __func__);
		return -EFAULT;
	}

	/* sanity check a loop boundary */
	thread_num = info.thread_num;
	if (thread_num > MAX_KEY_THREAD_NUM)
		thread_num = MAX_KEY_THREAD_NUM;

	for (i = 0; i < thread_num; i++)
		add_task_to_game_frame_group(info.tid[i], info.add);

	return 0;
}

static void get_frame_util_info(struct ofb_frame_util_info *info)
{
	memset(info, 0, sizeof(struct ofb_frame_util_info));
	fbg_get_frame_scale(&info->frame_scale);
	fbg_get_frame_busy(&info->frame_busy);
}

static long fbg_notify_frame_start(void __user *uarg)
{
	struct ofb_frame_util_info info;

	if (uarg == NULL)
		return -EINVAL;
/* TODO find which multi group game ui be added */
	set_frame_state(GAME_FRAME_GROUP_ID, FRAME_START, -1, -1);
	rollover_frame_group_window(GAME_FRAME_GROUP_ID);

	get_frame_util_info(&info);
	if (copy_to_user(uarg, &info, sizeof(struct ofb_frame_util_info))) {
		ofb_debug("%s: copy_to_user fail\n", __func__);
		return -EFAULT;
	}

	return 0;
}

static bool is_ofb_extra_cmd(unsigned int cmd)
{
	return _IOC_TYPE(cmd) == OFB_EXTRA_MAGIC;
}

static long handle_ofb_extra_cmd(unsigned int cmd, void __user *uarg)
{
	switch (cmd) {
	case CMD_ID_SET_TASK_PREFERED_CLUSTER:
		return fbg_set_task_preferred_cluster(uarg);
	case CMD_ID_ADD_TASK_TO_GROUP:
		return fbg_add_task_to_group(uarg);
	case CMD_ID_NOTIFY_FRAME_START:
		return fbg_notify_frame_start(uarg);
	default:
		return -ENOTTY;
	}

	return 0;
}

static void setup_stune_data(struct ofb_stune_data *stune_data, int grp_id)
{
	if ((stune_data->util_frame_rate >= 0) && (stune_data->util_frame_rate <= 240))
		fbg_set_stune_boost(stune_data->util_frame_rate, grp_id, BOOST_UTIL_FRAME_RATE);
	if ((stune_data->vutil_margin >= -16) && (stune_data->vutil_margin <= 16))
		set_frame_margin(stune_data->m_rtg.group_id, stune_data->vutil_margin);

	if (is_multi_frame_fbg(grp_id)) {
		if ((stune_data->boost_freq >= 0) && (stune_data->boost_freq <= 100))
			fbg_set_stune_boost(stune_data->boost_freq, grp_id, BOOST_DEF_FREQ);
		if ((stune_data->boost_migr >= 0) && (stune_data->boost_migr <= 100))
			fbg_set_stune_boost(stune_data->boost_migr, grp_id, BOOST_DEF_MIGR);
		if ((stune_data->util_min_threshold >= 0) && (stune_data->util_min_threshold <= 1024))
			fbg_set_stune_boost(stune_data->util_min_threshold, grp_id, BOOST_UTIL_MIN_THRESHOLD);
		if ((stune_data->util_min_obtain_view >= 0) && (stune_data->util_min_obtain_view <= 1024))
			fbg_set_stune_boost(stune_data->util_min_obtain_view, grp_id, BOOST_UTIL_MIN_OBTAIN_VIEW);
		if ((stune_data->util_min_timeout >= 0) && (stune_data->util_min_timeout <= 1024))
			fbg_set_stune_boost(stune_data->util_min_timeout, grp_id, BOOST_UTIL_MIN_TIMEOUT);
		if (stune_data->ed_task_boost_mid_duration >= 0)
			fbg_set_stune_boost(stune_data->ed_task_boost_mid_duration, grp_id, BOOST_ED_TASK_MID_DURATION);
		if ((stune_data->ed_task_boost_mid_util >= 0) && (stune_data->ed_task_boost_mid_util <= 1024))
			fbg_set_stune_boost(stune_data->ed_task_boost_mid_util, grp_id, BOOST_ED_TASK_MID_UTIL);
		if (stune_data->ed_task_boost_max_duration >= 0)
			fbg_set_stune_boost(stune_data->ed_task_boost_max_duration, grp_id, BOOST_ED_TASK_MAX_DURATION);
		if ((stune_data->ed_task_boost_max_util >= 0) && (stune_data->ed_task_boost_max_util <= 1024))
			fbg_set_stune_boost(stune_data->ed_task_boost_max_util, grp_id, BOOST_ED_TASK_MAX_UTIL);
		if (stune_data->ed_task_boost_timeout_duration >= 0)
			fbg_set_stune_boost(stune_data->ed_task_boost_timeout_duration, grp_id, BOOST_ED_TASK_TIME_OUT_DURATION);
	} else if (grp_id == SF_FRAME_GROUP_ID) {
		if ((stune_data->boost_sf_freq_nongpu >= 0) && (stune_data->boost_sf_freq_nongpu <= 100))
			fbg_set_stune_boost(stune_data->boost_sf_freq_nongpu, grp_id, BOOST_SF_FREQ_NONGPU);
		if ((stune_data->boost_sf_migr_nongpu >= 0) && (stune_data->boost_sf_migr_nongpu <= 100))
			fbg_set_stune_boost(stune_data->boost_sf_migr_nongpu, grp_id, BOOST_SF_MIGR_NONGPU);
		if ((stune_data->boost_sf_freq_gpu >= 0) && (stune_data->boost_sf_freq_gpu <= 100))
			fbg_set_stune_boost(stune_data->boost_sf_freq_gpu, grp_id, BOOST_SF_FREQ_GPU);
		if ((stune_data->boost_sf_migr_gpu >= 0) && (stune_data->boost_sf_migr_gpu <= 100))
			fbg_set_stune_boost(stune_data->boost_sf_migr_gpu, grp_id, BOOST_SF_MIGR_GPU);
	}
}

static long ofb_sys_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	int grp_id = 0;
	struct ofb_ctrl_data data;
	struct ofb_stune_data stune_data;
	void __user *uarg = (void __user *)arg;

	if (is_ofb_extra_cmd(cmd)) {
		return handle_ofb_extra_cmd(cmd, uarg);
	}

	if (_IOC_TYPE(cmd) != OFB_MAGIC)
		return -EINVAL;

	if (_IOC_NR(cmd) >= CMD_ID_MAX)
		return -EINVAL;

	switch (cmd) {
	case CMD_ID_BOOST_HIT:
		if (copy_from_user(&data, uarg, sizeof(data))) {
			ofb_debug("invalid address");
			return -EFAULT;
		}

		if (unlikely(sysctl_frame_boost_debug & DEBUG_KMSG))
			ofb_debug("CMD_ID[%d], stage[%d], grp_id[%d], pid[%d], tid[%d]\n",
					_IOC_NR(cmd), data.stage, data.m_rtg.group_id, data.pid, data.tid);

		/* for multi group (app), game ui and render thread also use multi group */
		if (data.stage == BOOST_MOVE_FG) {
			grp_id = data.m_rtg.group_id;
			if (grp_id == -1) {
				grp_id = alloc_multi_fbg();
				ret = grp_id;
				if (grp_id < 0)
					return grp_id;
			} else if (grp_id == 0) { /*for single RTG*/
				grp_id = MULTI_FBG_ID + 1;
				ret = set_static_fbg(grp_id);
				if (ret < 0)
					return grp_id;

			} else if (!is_active_multi_frame_fbg(grp_id))
				return -INVALID_FBG_ID;
			else if (data.pid == -1 || data.tid == -1) {
				clear_all_static_frame_task_lock(grp_id);
				release_multi_fbg(grp_id);
				return grp_id;
			}
			set_ui_thread(grp_id, data.pid, data.tid);
			set_render_thread(grp_id, data.pid, data.tid);
			set_frame_state(grp_id, FRAME_END, 0, 0);
			rollover_frame_group_window(grp_id);
			ret = grp_id;
		}

		/* input method app move to top */
		if (data.stage == BOOST_MOVE_FG_IMS) {
			grp_id = INPUTMETHOD_FRAME_GROUP_ID;
			if (data.pid == -1 || data.tid == -1) {
				clear_all_static_frame_task_lock(grp_id);
				return grp_id;
			}
			set_ui_thread(grp_id, data.pid, data.tid);
			set_render_thread(grp_id, data.pid, data.tid);
			/* bypass hwui setting for stability issue
			set_hwui_thread(grp_id, data.pid, data.hwtid1, data.hwtid2);
			*/
			/*TODO get inputmethod group stune data */
			fbg_set_group_policy_util(grp_id, fbg_get_stune_boost(grp_id, BOOST_UTIL_MIN_TIMEOUT));
			ret = grp_id;
		}

		if (data.stage == BOOST_ADD_FRAME_TASK) {
			/* Should this stage suport SF/GAME/INPUT group? */
			grp_id = data.m_rtg.group_id;
			if (grp_id == 0)
				grp_id = MULTI_FBG_ID + 1;
			if (!is_active_multi_frame_fbg(grp_id))
				return -INVALID_FBG_ID;
			if (add_rm_related_frame_task(grp_id, data.pid, data.tid, data.capacity_need,
				data.m_rtg.related_depth, data.m_rtg1.related_width))
				ret = grp_id;
			else
				ret = 0;
		}

		if (data.stage == BOOST_ADD_FRAME_TASK_IMS) {
			grp_id = INPUTMETHOD_FRAME_GROUP_ID;
			if (add_rm_related_frame_task(grp_id, data.pid, data.tid, data.capacity_need,
				data.m_rtg.related_depth, data.m_rtg1.related_width))
				ret = grp_id;
			else
				ret = 0;
		}

		break;
	case CMD_ID_SET_SF_MSG_TRANS:
		if (copy_from_user(&data, uarg, sizeof(data))) {
			ofb_debug("invalid address");
			return -EFAULT;
		}

		if (unlikely(sysctl_frame_boost_debug & DEBUG_VERBOSE))
			ofb_debug("CMD_ID[%d], stage[%d], pid[%d], tid[%d]\n",
					_IOC_NR(cmd), data.stage, data.pid, data.tid);

		if (data.stage == BOOST_MSG_TRANS_START) {
			rollover_frame_group_window(SF_FRAME_GROUP_ID);
			update_frame_group_buffer_count();
		}

		if (data.stage == BOOST_SF_EXECUTE) {
			if (data.pid == data.tid) {
				set_sf_thread(data.pid, data.tid);
			} else {
				set_renderengine_thread(data.pid, data.tid);
			}
		}

		break;
	case CMD_ID_BOOST_STUNE: {
		if (copy_from_user(&stune_data, uarg, sizeof(stune_data))) {
			ofb_debug("invalid address");
			return -EFAULT;
		}
		/* TODO stune for group id */
		grp_id = stune_data.m_rtg.group_id;
		if (!is_fbg(grp_id))
			return -INVALID_FBG_ID;

		if (STUNE_SF == stune_data.boost_freq && grp_id != SF_FRAME_GROUP_ID) {
			return -INVALID_FBG_ID;
		}

		if (grp_id == SF_FRAME_GROUP_ID) {
			if (STUNE_DEF == stune_data.boost_freq) {
				stune_data.boost_freq = 0;

				stune_data.boost_sf_freq_nongpu = 0;
				stune_data.boost_sf_migr_nongpu = 0;
				#ifdef CONFIG_ARCH_MEDIATEK
				stune_data.boost_sf_freq_gpu = 60;
				stune_data.boost_sf_migr_gpu = 60;
				#else
				stune_data.boost_sf_freq_gpu = 30;
				stune_data.boost_sf_migr_gpu = 30;
				#endif /* CONFIG_ARCH_MEDIATEK */
			} else if (STUNE_SF == stune_data.boost_freq) {
				stune_data.boost_freq = 0;
			}
		}
		setup_stune_data(&stune_data, grp_id);
		}
		break;
	case CMD_ID_BOOST_STUNE_GPU: {
		bool boost_allow;

		if (copy_from_user(&stune_data, uarg, sizeof(stune_data))) {
			ofb_debug("invalid address");
			return -EFAULT;
		}

		/* This frame is not using client composition if data.level is zero.
		* But we still keep client composition setting with one frame extension.
		*/
		/* now sf control stune_data itself */
		/* if (check_last_compose_time(stune_data.m_rtg.level) && !stune_data.m_rtg.level)
			boost_allow = false; */

		boost_allow = !!stune_data.m_rtg.level;
		fbg_set_stune_boost(boost_allow, SF_FRAME_GROUP_ID, BOOST_SF_IN_GPU);
		}
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

#ifdef CONFIG_COMPAT
static long ofb_ctrl_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return ofb_ioctl(file, cmd, (unsigned long)(compat_ptr(arg)));
}

static long ofb_sys_ctrl_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return ofb_sys_ioctl(file, cmd, (unsigned long)(compat_ptr(arg)));
}
#endif

static int ofb_ctrl_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int ofb_ctrl_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct proc_ops ofb_ctrl_fops = {
	.proc_ioctl	= ofb_ioctl,
	.proc_open	= ofb_ctrl_open,
	.proc_release	= ofb_ctrl_release,
#ifdef CONFIG_COMPAT
	.proc_compat_ioctl	= ofb_ctrl_compat_ioctl,
#endif
	.proc_lseek		= default_llseek,
};

static const struct proc_ops ofb_sys_ctrl_fops = {
	.proc_ioctl	= ofb_sys_ioctl,
	.proc_open	= ofb_ctrl_open,
	.proc_release	= ofb_ctrl_release,
#ifdef CONFIG_COMPAT
	.proc_compat_ioctl	= ofb_sys_ctrl_compat_ioctl,
#endif
	.proc_lseek 	= default_llseek,
};

static ssize_t proc_stune_boost_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
#define          OPT_STR_MAX   3

	int grp_id;
	int boost_type;
	int boost_val;
	char *str, *token;
	char buffer[256];
	char opt_str[OPT_STR_MAX][8];
	int err = 0;
	int cnt = 0;

	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;

	if (copy_from_user(buffer, buf, count))
		return -EFAULT;

	buffer[count] = '\0';
	str = strstrip(buffer);
	while ((token = strsep(&str, " ")) && *token && (cnt < OPT_STR_MAX)) {
		strlcpy(opt_str[cnt], token, sizeof(opt_str[cnt]));
		cnt += 1;
	}

	if (cnt != OPT_STR_MAX) {
			return -EFAULT;
	}
	err = kstrtoint(strstrip(opt_str[0]), 10, &grp_id);
	if (err)
		return err;

	err = kstrtoint(strstrip(opt_str[1]), 10, &boost_type);
	if (err)
		return err;

	err = kstrtoint(strstrip(opt_str[2]), 10, &boost_val);
	if (err)
		return err;

	if ((grp_id > 1 && grp_id < MAX_NUM_FBG_ID) && (boost_type >= 0 && boost_type < BOOST_MAX_TYPE)) {
		if (boost_type == BOOST_UTIL_FRAME_RATE) {
				fbg_set_stune_boost(max(0, min(boost_val, 240)), grp_id,  boost_type);
		} else if ((boost_type == BOOST_UTIL_MIN_THRESHOLD) || (boost_type == BOOST_UTIL_MIN_OBTAIN_VIEW) || (boost_type == BOOST_UTIL_MIN_TIMEOUT)) {
				fbg_set_stune_boost(max(0, min(boost_val, 1024)), grp_id, boost_type);
		} else if ((boost_type == BOOST_ED_TASK_MID_DURATION) || (boost_type == BOOST_ED_TASK_MID_UTIL) ||
				(boost_type == BOOST_ED_TASK_MAX_DURATION) || (boost_type == BOOST_ED_TASK_MAX_UTIL) || (boost_type == BOOST_ED_TASK_TIME_OUT_DURATION)) {
				fbg_set_stune_boost(boost_val, grp_id, boost_type);
		} else {
				fbg_set_stune_boost(min(boost_val, 100), grp_id, boost_type);
		}
		ofb_debug("write boost grp_id=%d, boost_type=%d, boost_val:%d\n", grp_id, boost_type, boost_val);
	}
	return count;
}

static char *get_stune_boost_name(int type)
{
	switch (type) {
	case BOOST_DEF_MIGR:
		return "migr";
	case BOOST_DEF_FREQ:
		return "freq";
	case BOOST_UTIL_FRAME_RATE:
		return "fps";
	case BOOST_UTIL_MIN_THRESHOLD:
		return "min_threshold";
	case BOOST_UTIL_MIN_OBTAIN_VIEW:
		return "min_obtain_view";
	case BOOST_UTIL_MIN_TIMEOUT:
		return "min_timeout";
	case BOOST_SF_IN_GPU:
		return "sf_in_gpu";
	case BOOST_SF_MIGR_NONGPU:
		return "sf_migr_nongpu";
	case BOOST_SF_FREQ_NONGPU:
		return "sf_freq_nongpu";
	case BOOST_SF_MIGR_GPU:
		return "sf_migr_gpu";
	case BOOST_SF_FREQ_GPU:
		return "sf_freq_gpu";
	case BOOST_ED_TASK_MID_DURATION:
		return "ed_min_duration";
	case BOOST_ED_TASK_MID_UTIL:
		return "ed_min_util";
	case BOOST_ED_TASK_MAX_DURATION:
		return "ed_max_duration";
	case BOOST_ED_TASK_MAX_UTIL:
		return "ed_max_util";
	case BOOST_ED_TASK_TIME_OUT_DURATION:
		return "ed_timeout";
	default:
		return "unknown";
	}
}

static ssize_t proc_stune_boost_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	char buffer[4096];
	int i, grp_id;
	size_t len = 0;

	for (grp_id = 1; grp_id < MAX_NUM_FBG_ID; grp_id++) {
		len += snprintf(buffer + len, sizeof(buffer) - len, "grp_id:%d\n", grp_id);
		for (i = 0; i < BOOST_MAX_TYPE; ++i)
			len += snprintf(buffer + len, sizeof(buffer) - len, "%s:%d ",
				get_stune_boost_name(i), fbg_get_stune_boost(grp_id, i));
		len += snprintf(buffer + len, sizeof(buffer) - len, "\n");
	}
	len += snprintf(buffer + len, sizeof(buffer) - len, "\n");

	return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static const struct proc_ops ofb_stune_boost_fops = {
	.proc_write		= proc_stune_boost_write,
	.proc_read		= proc_stune_boost_read,
	.proc_lseek		= default_llseek,
};

static int info_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, info_show, NULL);
}

static const struct proc_ops ofb_frame_group_info_fops = {
	.proc_open	= info_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static ssize_t proc_game_ed_info_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	char buffer[128] = {0};
	int ret;
	int ed_duration;
	int ed_user_pid;

	ret = simple_write_to_buffer(buffer, sizeof(buffer), ppos, buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(buffer, "%d %d", &ed_duration, &ed_user_pid);
	if (ret != 2)
		return -EINVAL;

	fbg_game_set_ed_info(ed_duration, ed_user_pid);

	return count;
}

static ssize_t proc_game_ed_info_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	char buffer[128];
	size_t len;
	int ed_duration;
	int ed_user_pid;

	fbg_game_get_ed_info(&ed_duration, &ed_user_pid);
	len = snprintf(buffer, sizeof(buffer), "ed_duration = %d ns, ed_user_pid = %d\n",
		ed_duration, ed_user_pid);

	return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static const struct proc_ops ofb_game_ed_info_fops = {
	.proc_write		= proc_game_ed_info_write,
	.proc_read		= proc_game_ed_info_read,
	.proc_lseek		= default_llseek,
};

#define GLOBAL_SYSTEM_UID KUIDT_INIT(1000)
#define GLOBAL_SYSTEM_GID KGIDT_INIT(1000)
int frame_ioctl_init(void)
{
	int ret = 0;
	struct proc_dir_entry *pentry;

	frame_boost_proc = proc_mkdir(FRAMEBOOST_PROC_NODE, NULL);

	pentry = proc_create("ctrl", S_IRWXUGO, frame_boost_proc, &ofb_ctrl_fops);
	if (!pentry)
		goto ERROR_INIT;

	pentry = proc_create("sys_ctrl", (S_IRWXU|S_IRWXG), frame_boost_proc, &ofb_sys_ctrl_fops);
	if (!pentry) {
		goto ERROR_INIT;
	} else {
		pentry->uid = GLOBAL_SYSTEM_UID;
		pentry->gid = GLOBAL_SYSTEM_GID;
	}

	pentry = proc_create("stune_boost", (S_IRUGO|S_IWUSR|S_IWGRP), frame_boost_proc, &ofb_stune_boost_fops);
	if (!pentry)
		goto ERROR_INIT;

	pentry = proc_create("info", S_IRUGO, frame_boost_proc, &ofb_frame_group_info_fops);
	if (!pentry)
		goto ERROR_INIT;

	pentry = proc_create("game_ed_info", (S_IRUGO|S_IWUSR|S_IWGRP), frame_boost_proc, &ofb_game_ed_info_fops);
	if (!pentry)
		goto ERROR_INIT;

	return ret;

ERROR_INIT:
	remove_proc_entry(FRAMEBOOST_PROC_NODE, NULL);
	return -ENOENT;
}

int frame_ioctl_exit(void)
{
	int ret = 0;

	if (frame_boost_proc != NULL)
		remove_proc_entry(FRAMEBOOST_PROC_NODE, NULL);

	return ret;
}
