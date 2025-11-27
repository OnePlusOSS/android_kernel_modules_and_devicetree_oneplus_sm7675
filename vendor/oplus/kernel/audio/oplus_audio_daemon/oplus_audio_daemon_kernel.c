/******************************************************************************
** File: - OplusAudioDaemon.cpp
**
** Copyright (C), 2024-2028, OPLUS Mobile Comm Corp., Ltd
**
** Description:
**     Implementation of OPLUS audio driver Daemon system.
**
** Version: 1.0
************************************************************************************/
#include <linux/err.h>
#include <linux/sysfs.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/ktime.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <sound/control.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <soc/oplus/system/oplus_mm_kevent_fb.h>
#include "oplus_audio_daemon_kernel.h"

#define KEY_OPLUS_AUDIO_DAEMON_KERNEL_RUS            "OPLUS_AUDIORUS_DM_KEL="
#define KEY_OPLUS_AUDIO_DAEMON_KERNEL_SUPPORT        "oplus_audio_daemon_kel="

#define DAEMON_EVENT_RUS_MAX_LEN   256
#define DAEMON_EVENT_INFO_LEN      64
#define LIMIT_10MIN                   600
#define LIMIT_1H                      3600
#define ADSP_RESET_LIMIT_TIME         LIMIT_10MIN
#define FEEDBACK_DELAY_10S            10
#define FEEDBACK_LIMIT_10MIN          LIMIT_10MIN

enum {
	TRIGGER_ADSP_RESET = 0,
	TRIGGER_BY_SELF,
	TRIGGER_TYPE_MAX
};

enum {
	IMMEDIATE = 0,
	DELAY_WORK,
	RESTRICTION_TYPE_MAX
};

/* copy from adsp_helper.h */
enum adsp_type {
	ADSP_TYPE_UNKNOWN = -1,
	ADSP_TYPE_NONE = 0,
	ADSP_TYPE_HIFI3 = 1,
	ADSP_TYPE_RV55 = 2,
	ADSP_TYPE_NUM,
};

typedef struct audio_daemon_record {
	unsigned int rcd_cnt; /* record continue error count */
	unsigned int trg_cnt; /* trigger count since boot up */
	bool need_trigger; /* need to trigger recovery */
	bool working; /* thread has created and is running */
	/* for feedback event daemon: record start time of error;
		* for other daemon:          record last feedback event time;
	*/
	ktime_t start_time;
	ktime_t last_trg_time; /* last trigger time */
} audio_daemon_record_t;

struct audio_daemon {
	bool init;
	bool support;
	unsigned int type;
	struct delayed_work trg_work;
	bool working;
	ktime_t adsp_reset_time;
	audio_daemon_record_t rd[DAEMON_TYPE_ALL_MAX];
	struct mutex lock;
};

typedef struct audio_daemon_cfg {
	bool enable;
	unsigned int cnt_thd; /* threadhold for continue error count to trigger recovery */
	unsigned int trg_type; /* trigger type */
	unsigned int delay_s; /* delay seconds only for trg_type DELAY_WORK */
	unsigned int trg_restriciton; /* restriciton for trigger */
	/* for feedback event daemon: max interval time between twice daemon feedback event;
		* for other daemon:          min continue error times for trigger daemon;
	*/
	int time_thd;
	int limit_trg_time; /* trigger time limit */
	unsigned int limit_trg_cnt; /* trigger count limit*/
	unsigned int event_id; /* feedback event id for daemon */
	char cmp_info[DAEMON_EVENT_INFO_LEN]; /* feedback event error info need for daemon */
} audio_daemon_cfg_t;


static audio_daemon_cfg_t g_dm_cfg[DAEMON_TYPE_ALL_MAX] = {
	[FEEDBACK_EVENT_RESERVE1] = {false, 3,     TRIGGER_BY_SELF,        0,   IMMEDIATE,        0,  LIMIT_1H,     10000,  0,  ""},
	[FEEDBACK_EVENT_RESERVE2] = {false, 3,     TRIGGER_BY_SELF,        0,   IMMEDIATE,        0,  LIMIT_1H,     10000,  0,  ""},
	[FEEDBACK_EVENT_RESERVE3] = {false, 3,     TRIGGER_BY_SELF,        0,   IMMEDIATE,        0,  LIMIT_1H,     10000,  0,  ""},
};

#if IS_ENABLED(CONFIG_AUDIO_DAEMON_KERNEL_QCOM) /* for qcom */
static struct audio_daemon g_dm = {.init = false, .support = true, .type = DAEMON_TYPE_ALL_MAX, .working = false, .adsp_reset_time = 0};
extern bool oplus_daemon_adsp_ssr(void);
#elif IS_ENABLED(CONFIG_AUDIO_DAEMON_KERNEL_MTK_HIFI) /* for mtk hifi adsp */
static struct audio_daemon g_dm = {.init = false, .support = true, .type = DAEMON_TYPE_ALL_MAX, .working = false, .adsp_reset_time = 0};
extern bool oplus_daemon_hifi_ssr(void);
extern int get_adsp_type(void);
#elif IS_ENABLED(CONFIG_AUDIO_DAEMON_KERNEL_MTK_RV) /* for mtk rv adsp */
static struct audio_daemon g_dm = {.init = false, .support = true, .type = DAEMON_TYPE_ALL_MAX, .working = false, .adsp_reset_time = 0};
extern bool oplus_daemon_rv_ssr(void);
extern int get_adsp_type(void);
#else /* set default support = false */
static struct audio_daemon g_dm = {.init = false, .support = false, .type = DAEMON_TYPE_ALL_MAX, .working = false, .adsp_reset_time = 0};
#endif

static void oplus_audio_daemon_trigger_func(struct work_struct *work)
{
	unsigned int type = DAEMON_TYPE_ALL_MAX;
	unsigned int trg_type = TRIGGER_TYPE_MAX;
	int trg_limit_tm = 0;
	ktime_t last_trg_tm = 0;
	ktime_t now_time = 0;
	bool trigger_flag = false;
	bool trg_result = false;
	char fb_info[MAX_PAYLOAD_DATASIZE] = {0};

	pr_info("%s(), enter +++++ type=%u", __func__, g_dm.type);

	mutex_lock(&g_dm.lock);
	type = g_dm.type;
	if (type >= DAEMON_TYPE_ALL_MAX) {
		g_dm.type = DAEMON_TYPE_ALL_MAX;
		g_dm.working = false;
		pr_info("%s(), type=%u invalid, return", __func__, type);
		mutex_unlock(&g_dm.lock);
		return;
	}
	if (!g_dm_cfg[type].enable || !g_dm.rd[type].need_trigger) {
		g_dm.type = DAEMON_TYPE_ALL_MAX;
		g_dm.working = false;
		pr_info("%s(), type=%u, enable=%d, need_trigger=%d, return",
			__func__, type, g_dm_cfg[type].enable, g_dm.rd[type].need_trigger);
		mutex_unlock(&g_dm.lock);
		return;
	}
	pr_info("%s(), type=%d, trg_restriciton=%d", __func__, type, g_dm_cfg[type].trg_restriciton);

	trg_limit_tm = g_dm_cfg[type].limit_trg_time;
	last_trg_tm = g_dm.rd[type].last_trg_time;
	now_time = ktime_get();
	trg_type = g_dm_cfg[type].trg_type;
	if (trg_type == TRIGGER_ADSP_RESET) {
		trg_limit_tm = (trg_limit_tm > ADSP_RESET_LIMIT_TIME) ? trg_limit_tm : ADSP_RESET_LIMIT_TIME;
		last_trg_tm = (last_trg_tm > g_dm.adsp_reset_time) ? last_trg_tm : g_dm.adsp_reset_time;
		if (ktime_after(now_time, ktime_add_ms(last_trg_tm, trg_limit_tm * 1000))) {
			trigger_flag = true;
			g_dm.rd[type].trg_cnt++;
			g_dm.rd[type].last_trg_time = now_time;
			g_dm.adsp_reset_time = now_time;
		} else {
			pr_info("%s(), trigger too often, trg_type=%u, delt time %lld, limit time %d(ms)",
				__func__, trg_type, ktime_ms_delta(now_time, last_trg_tm), trg_limit_tm * 1000);
		}
	} else {
		if (ktime_after(now_time, ktime_add_ms(last_trg_tm, trg_limit_tm * 1000))) {
			trigger_flag = true;
			g_dm.rd[type].trg_cnt++;
			g_dm.rd[type].last_trg_time = now_time;
		} else {
			pr_info("%s(), trigger too often, trg_type=%u, delt time %lld, limit time %d(ms)",
				__func__, trg_type, ktime_ms_delta(now_time, last_trg_tm), trg_limit_tm * 1000);
		}
	}
	scnprintf(fb_info, MAX_PAYLOAD_DATASIZE,
		"payload@@daemon for kernel, type=%u,rcd_cnt=%u,error continue time=%lld(ms),"
		"trg_type=%u,already trg_cnt=%u,last trg delt time=%lld(ms)",
		type, g_dm.rd[type].rcd_cnt, ktime_ms_delta(now_time, g_dm.rd[type].start_time),
		trg_type, g_dm.rd[type].trg_cnt, ktime_ms_delta(now_time, last_trg_tm));

	/* clear record info */
	g_dm.rd[type].rcd_cnt = 0;
	g_dm.rd[type].start_time = 0;
	g_dm.rd[type].need_trigger = false;
	g_dm.rd[type].working = false;
	g_dm.type = DAEMON_TYPE_ALL_MAX;
	g_dm.working = false;
	mutex_unlock(&g_dm.lock);

	if (trigger_flag) {
		if (trg_type == TRIGGER_ADSP_RESET) {
#if IS_ENABLED(CONFIG_AUDIO_DAEMON_KERNEL_QCOM)
			trg_result = oplus_daemon_adsp_ssr();
#endif /* CONFIG_AUDIO_DAEMON_KERNEL_QCOM */
#if IS_ENABLED(CONFIG_AUDIO_DAEMON_KERNEL_MTK_HIFI)
			if (ADSP_TYPE_HIFI3 == get_adsp_type()) {
				trg_result = oplus_daemon_hifi_ssr();
			}
#endif /* CONFIG_AUDIO_DAEMON_KERNEL_MTK_HIFI */
#if IS_ENABLED(CONFIG_AUDIO_DAEMON_KERNEL_MTK_RV)
			if (ADSP_TYPE_RV55 == get_adsp_type()) {
				trg_result = oplus_daemon_rv_ssr();
			}
#endif /* CONFIG_AUDIO_DAEMON_KERNEL_MTK_RV */
			if (trg_result) {
				pr_err("%s(), ######## trigger adsp crash by audio daemon kernel, type=%u #########", __func__, type);
			} else {
				pr_err("%s(), %s, trigger adsp crash failed", __func__, fb_info);
				scnprintf(fb_info + strlen(fb_info), sizeof(fb_info) - strlen(fb_info), ", trigger adsp crash failed");
			}
		}
		mm_fb_audio_fatal_delay(10050, FEEDBACK_LIMIT_10MIN, FEEDBACK_DELAY_10S, "%s", fb_info);
	}

	pr_info("%s(), exit ----- type=%u", __func__, type);
}


/******************************************************************************
 * Function    : oplus_audio_daemon_record
 * Description : record continue count and start time for daemon type
 * Parameters  :
 *     @type: daemon type
 * Returns     : void
 * Attention   : this function can't use for feedback event daemon,
 *               g_dm.rd[type].start_time and g_dm_cfg[type].time_thd have different meanings,
 *               feedback event daemon need use oplusAudioDaemonFeedbackEvent
 ******************************************************************************/
void oplus_audio_daemon_record(unsigned int type)
{
	if (!g_dm.init || !g_dm.support) {
		return;
	}

	if (type >= DAEMON_TYPE_ALL_MAX) {
		pr_info("%s(), type=%u invalid, return", __func__, type);
		return;
	}
	if (!g_dm_cfg[type].enable) {
		pr_info("%s(), type=%u not enable, return", __func__, type);
		return;
	}

	mutex_lock(&g_dm.lock);
	if ((0 == g_dm.rd[type].rcd_cnt) || (0 == g_dm.rd[type].start_time)) {
		g_dm.rd[type].start_time = ktime_get();
	}
	g_dm.rd[type].rcd_cnt++;
	pr_info("%s(), type=%d, rcd_cnt=%u", __func__, type, g_dm.rd[type].rcd_cnt);
	mutex_unlock(&g_dm.lock);
}

/******************************************************************************
 * Function    : oplus_audio_daemon_check
 * Description : check whether continue count and contine time is out of threshold
 *               count threshold: configurated in g_dm_cfg[type].cnt_thd
 *               time threshold: configurated in g_dm_cfg[type].time_thd
 * Parameters  :
 *     @type: daemon type
 * Returns     : true: out of threshold, need to trigger daemon operation
 *               false: not out of threshold, do nothing
 * Attention   : this function can't use for feedback event daemon,
 *               g_dm.rd[type].start_time and g_dm_cfg[type].time_thd have different meanings,
 *               feedback event daemon need use oplusAudioDaemonFeedbackEvent
 ******************************************************************************/
bool oplus_audio_daemon_check(unsigned int type)
{
	bool ret = false;
	ktime_t now_time = 0;

	if (!g_dm.init || !g_dm.support) {
		return false;
	}

	if (type >= DAEMON_TYPE_ALL_MAX) {
		pr_info("%s(), type=%u invalid, return", __func__, type);
		return false;
	}
	if (!g_dm_cfg[type].enable) {
		pr_info("%s(), type=%u not enable, return", __func__, type);
		return false;
	}

	mutex_lock(&g_dm.lock);
	if (g_dm.working) {
		pr_info("%s(), someone already waiting for trigger, type=%u, return", __func__, type);
		goto exit;
	}

	if (g_dm.rd[type].need_trigger) {
		pr_info("%s(), type=%u is already waiting for trigger, return", __func__, type);
		goto exit;
	}
	if (g_dm.rd[type].rcd_cnt >= g_dm_cfg[type].cnt_thd) {
		if (g_dm.rd[type].start_time != 0) {
			now_time = ktime_get();
			if (ktime_after(now_time,
					ktime_add_ms(g_dm.rd[type].start_time, g_dm_cfg[type].time_thd * 1000))) {
				ret = true;
				pr_info("%s(), type=%u, rcd_cnt=%u, continue time %lld ms, need trigger",
					__func__, type, g_dm.rd[type].rcd_cnt, ktime_ms_delta(now_time, g_dm.rd[type].start_time));
			}
		}
	}

exit:
	mutex_unlock(&g_dm.lock);
	return ret;
}

/******************************************************************************
 * Function    : oplus_audio_daemon_trigger
 * Description : trigger daemon operation for daemon type
 *               if no trigger restriciton (config IMMEDIATE), trigger now
 *                otherwise, create a thread to wait for trigger
 * Parameters  :
 *     @type: daemon type
 * Returns     : true: success to trigger or create a thread
 *               false: failed to trigger or create a thread
 ******************************************************************************/
bool oplus_audio_daemon_trigger(unsigned int type)
{
	int ret = false;
	int trg_limit_tm = 0;
	ktime_t last_trg_tm = 0;
	ktime_t now_time = 0;

	if (type >= DAEMON_TYPE_ALL_MAX) {
		pr_info("%s(), type=%u invalid, return", __func__, type);
		return false;
	}
	if (!g_dm_cfg[type].enable) {
		pr_info("%s(), type=%u not enable, return", __func__, type);
		return false;
	}

	pr_info("%s(), type=%u, trg_restriciton=%u", __func__, type, g_dm_cfg[type].trg_restriciton);

	mutex_lock(&g_dm.lock);
	if (g_dm.working) {
		pr_info("%s(), someone already waiting for trigger, type=%u, return", __func__, type);
		mutex_unlock(&g_dm.lock);
		return false;
	}

	if (g_dm.rd[type].trg_cnt >= g_dm_cfg[type].limit_trg_cnt) {
		pr_info("%s(), type=%u has trigger for %u times, can't trigger more", __func__, type, g_dm.rd[type].trg_cnt);
		mutex_unlock(&g_dm.lock);
		return false;
	}

	if (g_dm_cfg[type].trg_restriciton == IMMEDIATE) {
		if (g_dm_cfg[type].trg_type != TRIGGER_BY_SELF) {
			g_dm.rd[type].need_trigger = true;
			g_dm.rd[type].working = true;
			g_dm.working = true;
			g_dm.type = type;
			schedule_delayed_work(&g_dm.trg_work, 0);
		} else {
			trg_limit_tm = g_dm_cfg[type].limit_trg_time;
			last_trg_tm = g_dm.rd[type].last_trg_time;
			now_time = ktime_get();
			if (ktime_after(now_time, ktime_add_ms(last_trg_tm, trg_limit_tm * 1000))) {
				/* trigger by self */
				mm_fb_audio_fatal_delay(10050, FEEDBACK_LIMIT_10MIN, FEEDBACK_DELAY_10S,
					"payload@@daemon for kernel,type=%u,rcd_cnt=%u,error continue time=%lld(ms),"
					"trg_type=%u,already trg_cnt=%u,last trg delt time=%lld(ms)",
					type, g_dm.rd[type].rcd_cnt, ktime_ms_delta(now_time, g_dm.rd[type].start_time),
					g_dm_cfg[type].trg_type, g_dm.rd[type].trg_cnt, ktime_ms_delta(now_time, last_trg_tm));

				g_dm.rd[type].last_trg_time = now_time;
				g_dm.rd[type].trg_cnt++;
				ret = true;
			} else {
				pr_info("%s(), trigger too often, trg_type=%u, delt time %lld, limit time %d(ms)",
					__func__, g_dm_cfg[type].trg_type, ktime_ms_delta(now_time, last_trg_tm), trg_limit_tm * 1000);
				ret = false;
			}
			/* clear record info */
			g_dm.rd[type].rcd_cnt = 0;
			g_dm.rd[type].start_time = 0;
			g_dm.type = DAEMON_TYPE_ALL_MAX;
		}
	} else if (g_dm_cfg[type].trg_restriciton == DELAY_WORK) {
		g_dm.rd[type].need_trigger = true;
		g_dm.rd[type].working = true;
		g_dm.working = true;
		g_dm.type = type;
		schedule_delayed_work(&g_dm.trg_work, g_dm_cfg[type].delay_s * HZ);
		ret = true;
	} else {
		pr_info("%s(), unsupport trg_restriciton=%u for delay work", __func__, g_dm_cfg[type].trg_restriciton);
	}
	mutex_unlock(&g_dm.lock);

	pr_info("%s(), exit, type=%u, ret=%d", __func__, type, ret);
	return ret;
}

/******************************************************************************
 * Function    : oplus_audio_daemon_clear_record
 * Description : clear continue count and start time of daemon type
 *               if daemon operation is triggering, notify to exit
 * Parameters  :
 *     @type: daemon type
 * Returns     : void
 ******************************************************************************/
void oplus_audio_daemon_clear_record(unsigned int type)
{
	bool need_cancel = false;

	if (!g_dm.init || !g_dm.support) {
		return;
	}

	if (type >= DAEMON_TYPE_ALL_MAX) {
		pr_info("%s(), type=%u invalid, return", __func__, type);
		return;
	}
	if (!g_dm_cfg[type].enable) {
		pr_info("%s(), type=%u not enable, return", __func__, type);
		return;
	}

	mutex_lock(&g_dm.lock);
	if ((g_dm.rd[type].rcd_cnt > 0) || g_dm.rd[type].need_trigger || g_dm.rd[type].working) {
		g_dm.rd[type].rcd_cnt = 0;
		g_dm.rd[type].start_time = 0;
		g_dm.rd[type].need_trigger = false;
		if (g_dm.rd[type].working) {
			need_cancel = true;
		}
		pr_info("%s(), clear success, type:%u, need_cancel=%d", __func__, type, need_cancel);
	}
	mutex_unlock(&g_dm.lock);

	if (need_cancel) {
		cancel_delayed_work_sync(&g_dm.trg_work);
	}
}

bool oplus_audio_daemon_record_check_trigger(unsigned int type)
{
	int ret = false;

	oplus_audio_daemon_record(type);
	if (oplus_audio_daemon_check(type)) {
		ret = oplus_audio_daemon_trigger(type);
	}

	return ret;
}

bool oplus_audio_daemon_record_or_clear(bool is_err, unsigned int type)
{
	int ret = false;

	if (is_err) {
		oplus_audio_daemon_record(type);
		if (oplus_audio_daemon_check(type)) {
			ret = oplus_audio_daemon_trigger(type);
		}
	} else {
		oplus_audio_daemon_clear_record(type);
	}

	return ret;
}

bool oplus_is_daemon_event_id(unsigned int event_id)
{
	bool ret = false;
	int i = FEEDBACK_EVENT_RESERVE1;

	if (!g_dm.init || !g_dm.support) {
		return false;
	}
	for (i = FEEDBACK_EVENT_RESERVE1; i <= FEEDBACK_EVENT_RESERVE3; i++) {
		if (g_dm_cfg[i].enable && (g_dm_cfg[i].event_id == event_id)) {
			ret = true;
			break;
		}
	}
	return ret;
}

bool oplus_compare_feedback_info(unsigned int type, char *fb_info)
{
	char cmp_info[DAEMON_EVENT_INFO_LEN] = "";
	char *pinfo = NULL;
	char *ptmp = NULL;
	char *psubstr = NULL;
	bool flag = false;

	/* cmp_info string can be several substring separated by '|', or can be only one substring without '|'.
		* all substring in cmp_info should be in fb_info.
		* eg:
		* cmp_info: abc|123             --- substring include 'abc' and '123'
		* fb_info: "test 123 and abc"   --- substring 'abc' and '123' all in fb_info
	*/
	if (NULL == strchr(g_dm_cfg[type].cmp_info, '|')) {
		/* only one substring need to compare */
		if (strstr(fb_info, g_dm_cfg[type].cmp_info)) {
			flag = true;
		}
	} else {
		/* copy cmp_info */
		memcpy(cmp_info, g_dm_cfg[type].cmp_info, DAEMON_EVENT_INFO_LEN - 1);
		cmp_info[DAEMON_EVENT_INFO_LEN - 1] = '\0';
		pinfo = (char *)cmp_info;
		/* parser and compare every substring, if one of them is not matched, flag = false */
		flag = true;
		ptmp = strsep(&pinfo, "|");
		while (ptmp != NULL) {
			psubstr = ptmp;
			/* get next sub config string */
			ptmp = strsep(&pinfo, "|");

			if (NULL == strstr(fb_info, psubstr)) {
				flag = false;
				break;
			}
		}
	}
	pr_info("%s(), flag = %d, cmp_info:%s, fb_info:%s", __FUNCTION__, flag, g_dm_cfg[type].cmp_info, fb_info);
	return flag;
}

/******************************************************************************
 * Function    : oplusAudioDaemonFeedbackEvent
 * Description : record feedback event count and check whether need to trigger daemon
 * Parameters  :
 *    @event_id: feedback event_id
 *    @fnln    : feedback function and line
 *    @payload : feedback information
 * Returns     : bool, true: trigger daemon; false: not trigger daemon
 * Attention   : this function only use for feedback event daemon which type is FEEDBACK_EVENT_RESERVE1 ~ FEEDBACK_EVENT_RESERVE3
 ******************************************************************************/
bool oplus_audio_daemon_feedback_event(unsigned int event_id, char *fb_info)
{
	unsigned int type = FEEDBACK_EVENT_RESERVE1;
	int64_t now_time = 0;
	bool flag = false;
	bool ret = false;

	if (!g_dm.init || !g_dm.support) {
		return false;
	}
	if (!fb_info) {
		pr_info("%s(), input param is null", __FUNCTION__);
		return false;
	}

	for (type = FEEDBACK_EVENT_RESERVE1; type <= FEEDBACK_EVENT_RESERVE3; type++) {
		/* compare event_id and cmp_info */
		if (g_dm_cfg[type].enable &&
				(event_id == g_dm_cfg[type].event_id) &&
				oplus_compare_feedback_info(type, fb_info)) {
			now_time = ktime_get();

			mutex_lock(&g_dm.lock);

			if ((g_dm_cfg[type].time_thd != 0) &&
				ktime_after(now_time, ktime_add_ms(g_dm.rd[type].start_time, g_dm_cfg[type].time_thd * 1000))) {
				/* interval time between twice daemon feedback event is larger than time_thd, restart record count */
				g_dm.rd[type].rcd_cnt = 1;
			} else {
				g_dm.rd[type].rcd_cnt++;
				if (g_dm.rd[type].rcd_cnt >= g_dm_cfg[type].cnt_thd) {
					flag = true;
					pr_info("%s(), type=%u, rcd_cnt=%u, need trigger", __FUNCTION__, type, g_dm.rd[type].rcd_cnt);
				}
			}

			g_dm.rd[type].start_time = now_time;
			pr_info("%s(), type=%d, rcd_cnt=%u, start_time=%lld", __FUNCTION__,
				type, g_dm.rd[type].rcd_cnt, (long long)g_dm.rd[type].start_time);

			mutex_unlock(&g_dm.lock);
			break;
		}
	}

	if (flag) {
		ret = oplus_audio_daemon_trigger(type);
	}

	return ret;
}

EXPORT_SYMBOL(oplus_audio_daemon_record);
EXPORT_SYMBOL(oplus_audio_daemon_check);
EXPORT_SYMBOL(oplus_audio_daemon_trigger);
EXPORT_SYMBOL(oplus_audio_daemon_clear_record);
EXPORT_SYMBOL(oplus_audio_daemon_record_check_trigger);
EXPORT_SYMBOL(oplus_audio_daemon_record_or_clear);
EXPORT_SYMBOL(oplus_is_daemon_event_id);
EXPORT_SYMBOL(oplus_audio_daemon_feedback_event);

static void oplus_get_audio_daemon_cfg(char *pcfg)
{
	char *ptmp = NULL;
	char *psubcfg = NULL;
	unsigned int type = DAEMON_TYPE_ALL_MAX;
	audio_daemon_cfg_t event_cfg;
	int len = 0;
	char cfg_info[DAEMON_EVENT_RUS_MAX_LEN] = "";
	char *pinfo = NULL;
	char tmp_cmp_info[DAEMON_EVENT_RUS_MAX_LEN] = "";
	int cmp_info_len = 0;
	int val = 0;

	if (!pcfg) {
		pr_err("%s(), input param invalid", __FUNCTION__);
		return;
	}
	pr_info("%s(), rus config string:%s", __FUNCTION__, pcfg);

	/* RUS daemon config value format:
		every sub config enclosed by [], support up to 5 sub config;
		sub config value separated by #，compare information string can't include space symbol.
		eg:
		value="[6#1#3#2#0#3#5#3600#10#10008#pal_stream_open|speaker][2#1#3#2#0#3#5#3600#5#0#none]"
	*/
	/* get sub config string */
	len = strlen(pcfg);
	len = len > (sizeof(cfg_info) - 1) ? (sizeof(cfg_info) - 1) : len;
	memcpy(cfg_info, pcfg, len);
	cfg_info[len] = '\0';
	pinfo = (char *)cfg_info;
	ptmp = strsep(&pinfo, "]");
	while (ptmp != NULL) {
		psubcfg = ptmp;
		/* get next sub config string */
		ptmp = strsep(&pinfo, "]");

		if ((*psubcfg != '[') || (strlen(psubcfg) > DAEMON_EVENT_RUS_MAX_LEN)) {
			pr_err("%s(), sub config not start with [ or lenght > %d, psubcfg=%s", __FUNCTION__, DAEMON_EVENT_RUS_MAX_LEN, psubcfg);
			continue;
		}
		/* skip '[' */
		psubcfg++;

		/* parser sub config string */
		val = sscanf(psubcfg, "%u#%d#%u#%u#%u#%u#%d#%d#%u#%u#%s",
			&type,
			(int *)&event_cfg.enable,   &event_cfg.cnt_thd,
			&event_cfg.trg_type,        &event_cfg.delay_s,
			&event_cfg.trg_restriciton, &event_cfg.time_thd,
			&event_cfg.limit_trg_time,  &event_cfg.limit_trg_cnt,
			&event_cfg.event_id,        tmp_cmp_info);

		if ((val == 11) && (type < DAEMON_TYPE_ALL_MAX)) {
			g_dm_cfg[type].enable = event_cfg.enable;
			g_dm_cfg[type].cnt_thd = event_cfg.cnt_thd;
			g_dm_cfg[type].trg_type = event_cfg.trg_type;
			g_dm_cfg[type].delay_s = event_cfg.delay_s;
			g_dm_cfg[type].trg_restriciton = event_cfg.trg_restriciton;
			g_dm_cfg[type].time_thd = event_cfg.time_thd;
			g_dm_cfg[type].limit_trg_time = event_cfg.limit_trg_time;
			g_dm_cfg[type].limit_trg_cnt = event_cfg.limit_trg_cnt;
			g_dm_cfg[type].event_id = event_cfg.event_id;

			cmp_info_len = strlen(tmp_cmp_info);
			if (cmp_info_len >= sizeof(g_dm_cfg[type].cmp_info)) {
				cmp_info_len = sizeof(g_dm_cfg[type].cmp_info) - 1;
				pr_err("%s(), event info is too long, only get %d chars", __FUNCTION__, cmp_info_len);
			}
			memcpy(g_dm_cfg[type].cmp_info, tmp_cmp_info, cmp_info_len);
			g_dm_cfg[type].cmp_info[cmp_info_len] = '\0';

			pr_info("%s(), update RUS config:[%u]=%d,%u,%u,%u,%u,%d,%d,%u,%u,%s",
				__FUNCTION__,                      type,
				g_dm_cfg[type].enable,           g_dm_cfg[type].cnt_thd,
				g_dm_cfg[type].trg_type,         g_dm_cfg[type].delay_s,
				g_dm_cfg[type].trg_restriciton,  g_dm_cfg[type].time_thd,
				g_dm_cfg[type].limit_trg_time,   g_dm_cfg[type].limit_trg_cnt,
				g_dm_cfg[type].event_id,         g_dm_cfg[type].cmp_info);
		} else {
			pr_err("%s(), invalid config, val=%d, psubcfg=%s", __FUNCTION__, val, psubcfg);
		}
	}
}

static ssize_t oplus_audio_daemon_kernel_read(struct file *file,
				char __user *buf,
				size_t count,
				loff_t *ppos)
{
	return 0;
}

static ssize_t oplus_audio_daemon_kernel_write(struct file *file,
				const char __user *buf,
				size_t count,
				loff_t *lo)
{
	char info[DAEMON_EVENT_RUS_MAX_LEN + 1] = {0};
	char *pval = NULL;

	if (copy_from_user(info, buf,
			DAEMON_EVENT_RUS_MAX_LEN > count ? count : DAEMON_EVENT_RUS_MAX_LEN)) {
		pr_err("%s(), Fail copy to user buf:(%p),count:%zd", __func__, buf, count);
		return -EFAULT;
	}
	info[DAEMON_EVENT_RUS_MAX_LEN] ='\0'; /* make sure last bype is eof */
	pr_info("%s(), %s", __func__, info);

	if (strstr(info, KEY_OPLUS_AUDIO_DAEMON_KERNEL_RUS)) {
		pval = info + strlen(KEY_OPLUS_AUDIO_DAEMON_KERNEL_RUS);
		oplus_get_audio_daemon_cfg(pval);
	} else if (strstr(info, KEY_OPLUS_AUDIO_DAEMON_KERNEL_SUPPORT)) {
		pval = info + strlen(KEY_OPLUS_AUDIO_DAEMON_KERNEL_SUPPORT);
		if (pval && (!strncmp(pval, "true", 4) || !strncmp(pval, "yes", 3))) {
			pr_info("%s(), set support audio kernel daemon", __func__);
			g_dm.support = true;
		} else {
			pr_info("%s(), set unsupport audio kernel daemon", __func__);
			g_dm.support = false;
		}
	} else {
		pr_err("%s(), unknown info:%s", __func__, info);
	}

	return count;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
static const struct proc_ops audio_daemon_kel_fops = {
	.proc_read  = oplus_audio_daemon_kernel_read,
	.proc_write = oplus_audio_daemon_kernel_write,
	.proc_open  = simple_open,
};
#else
static const struct file_operations audio_daemon_kel_fops = {
	.read  = oplus_audio_daemon_kernel_read,
	.write = oplus_audio_daemon_kernel_write,
	.open  = simple_open,
	.owner = THIS_MODULE,
};
#endif

int oplus_audio_daemon_init(void)
{
	struct proc_dir_entry *d_entry = NULL;

	d_entry = proc_create_data("audio_daemon_kel", 0666, NULL,
				   &audio_daemon_kel_fops, NULL);
	if (!d_entry) {
		pr_err("failed to create audio_daemon_kel node\n");
		return -ENODEV;
	}

	g_dm.support = true;
	g_dm.type = DAEMON_TYPE_ALL_MAX;
	INIT_DELAYED_WORK(&g_dm.trg_work, oplus_audio_daemon_trigger_func);
	g_dm.working = false;
	g_dm.adsp_reset_time = 0;
	memset(g_dm.rd, 0, sizeof(g_dm.rd));
	mutex_init(&g_dm.lock);
	g_dm.init = true;

	pr_info("%s: init success\n", __func__);
	return 0;
}

void oplus_audio_daemon_deinit(void)
{
	g_dm.init = false;
	cancel_delayed_work_sync(&g_dm.trg_work);
	mutex_destroy(&g_dm.lock);
	pr_info("%s: deinit\n", __func__);
}

module_init(oplus_audio_daemon_init);
module_exit(oplus_audio_daemon_deinit);

MODULE_DESCRIPTION("Oplus Audio Kernel Daemon");
MODULE_LICENSE("GPL");
