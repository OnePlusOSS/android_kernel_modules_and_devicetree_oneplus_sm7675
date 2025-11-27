// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022-2030 Oplus. All rights reserved.
 * Description : combination key monitor, such as volup + pwrkey
 * Version : 1.0
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": %s: %d: " fmt, __func__, __LINE__

#include <linux/types.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/workqueue.h>
#include <linux/notifier.h>
#include <linux/input.h>
#include <linux/ktime.h>
#if IS_ENABLED(CONFIG_OPLUS_FEATURE_KEYEVENT_HANDLER)
#include "../../include/keyevent_handler.h"
#endif
#if IS_ENABLED(CONFIG_OPLUS_FEATURE_THEIA)
#include "../../include/theia_send_event.h"
#include "../../include/theia_bright_black_check.h"
#endif

#define CREATE_TRACE_POINTS
#include "combkey_trace.h"
#include <linux/time.h>

#if IS_ENABLED(CONFIG_OPLUS_FEATURE_FEEDBACK)
#include <soc/oplus/dft/kernel_fb.h>
#endif

#define KEY_DOWN_VALUE 1
#define KEY_UP_VALUE 0

static struct delayed_work g_check_combkey_long_press_work;
static struct delayed_work g_check_pwrkey_long_press_work;
#define CHECK_COMBKEY_LONG_PRESS_MS 6000
#define CHECK_PWRKEY_LONG_PRESS_MS 8000

#define SYSTEM_ID 20120
#define COMBKEY_DCS_TAG      "CriticalLog"
#define COMBKEY_DCS_EVENTID  "Theia"
#define PWRKEY_LONG_PRESS    "TheiaPwkLongPress"
#define BUTTON_DEBOUNCE_TYPE "10001"

static bool is_pwrkey_down;
static bool is_volumup_down;
static bool is_volumup_pwrkey_down;
static u64 pwrkey_press_count;
static u64 volup_press_count;

struct key_press_time_data {
	u64 curr_down_time;
	u64 curr_up_time;
	u64 key_handle_interval;
};

static unsigned int combkey_monitor_events[] = {
	KEY_POWER,
	KEY_VOLUMEUP,
};
static size_t combkey_monitor_events_nr = ARRAY_SIZE(combkey_monitor_events);

static void combkey_long_press_callback(struct work_struct *work)
{
	pr_info("called. send pwr_resin_bark to theia.\n");
	theia_send_event(THEIA_EVENT_KPDPWR_RESIN_BARK, THEIA_LOGINFO_KERNEL_LOG | THEIA_LOGINFO_ANDROID_LOG,
		0, "kpdpwr_resin_bark happen");
}

static long get_timestamp_ms(void)
{
	struct timespec64 now;
	ktime_get_real_ts64(&now);
	return timespec64_to_ns(&now) / NSEC_PER_MSEC;
}

static void pwrkey_long_press_callback(struct work_struct *work)
{
	pr_info("called. send long press pwrkey to theia.\n");
	/*
	theia_send_event(THEIA_EVENT_PWK_LONGPRESS, THEIA_LOGINFO_KERNEL_LOG
		 | THEIA_LOGINFO_ANDROID_LOG | THEIA_LOGINFO_DUMPSYS_SF | THEIA_LOGINFO_BINDER_INFO,
		0, "pwrkey long press happen");
	*/
	trace_combkey_monitor(get_timestamp_ms(), SYSTEM_ID, COMBKEY_DCS_TAG, COMBKEY_DCS_EVENTID, PWRKEY_LONG_PRESS);
}

static int combkey_monitor_notifier_call(struct notifier_block *nb, unsigned long type, void *data)
{
	struct keyevent_notifier_param *param = data;
	struct key_press_time_data pwr_tm_data = {
		.curr_down_time = 0,
		.curr_up_time = 0,
		.key_handle_interval = 0
	};
	struct key_press_time_data volup_tm_data = {
		.curr_down_time = 0,
		.curr_up_time = 0,
		.key_handle_interval = 0
	};
#if IS_ENABLED(CONFIG_OPLUS_FEATURE_FEEDBACK)
	char payload[1024] = {0x00};
#endif

	pr_info("called. event_code = %u, value = %d\n", param->keycode, param->down);

	if (param->keycode == KEY_POWER) {
		pr_info("pwrkey handle enter.\n");
		if (param->down == KEY_DOWN_VALUE) {
			is_pwrkey_down = true;
			set_pwk_flag(true);
			pr_info("pwrkey pressed, call pwrkey monitor checker.\n");

			pwr_tm_data.curr_down_time = ktime_to_ms(ktime_get());
			pr_info("pwrkey pressed, call pwrkey monitor checker. curr_down_time = %llu\n", pwr_tm_data.curr_down_time);
			black_screen_timer_restart();
			bright_screen_timer_restart();
		} else if (param->down == KEY_UP_VALUE) {
			is_pwrkey_down = false;
			pwr_tm_data.curr_up_time = ktime_to_ms(ktime_get());
			pwr_tm_data.key_handle_interval = pwr_tm_data.curr_up_time - pwr_tm_data.curr_down_time;
			pr_info("pwrkey key released, curr_up_time = %llu, key_handle_interval = %llu\n",
						pwr_tm_data.curr_up_time, pwr_tm_data.key_handle_interval);
			pwrkey_press_count++;
#if IS_ENABLED(CONFIG_OPLUS_FEATURE_FEEDBACK)
			memset(payload, 0 , sizeof(payload));
			scnprintf(payload, sizeof(payload),
				"NULL$$EventField@@pwrkey$$FieldData@@cnt%llu$$detailData@@up_%llu,down_%llu,interval_%llu",
				pwrkey_press_count, pwr_tm_data.curr_up_time, pwr_tm_data.curr_down_time, pwr_tm_data.key_handle_interval);
			oplus_kevent_fb(FB_TRI_STATE_KEY, BUTTON_DEBOUNCE_TYPE, payload);
#endif
		}
	} else if (param->keycode == KEY_VOLUMEUP) {
		pr_info("volumup key handle enter\n");
		if (param->down == KEY_DOWN_VALUE) {
			is_volumup_down = true;
			volup_tm_data.curr_down_time = ktime_to_ms(ktime_get());
			pr_info("volumup key pressed, curr_down_time = %llu\n", volup_tm_data.curr_down_time);
		} else if (param->down == KEY_UP_VALUE) {
			is_volumup_down = false;
			volup_tm_data.curr_up_time = ktime_to_ms(ktime_get());
			volup_tm_data.key_handle_interval = volup_tm_data.curr_up_time - volup_tm_data.curr_down_time;
			pr_info("volumup key released, curr_up_time = %llu, key_handle_interval = %llu\n",
						volup_tm_data.curr_up_time, volup_tm_data.key_handle_interval);
			volup_press_count++;
#if IS_ENABLED(CONFIG_OPLUS_FEATURE_FEEDBACK)
			memset(payload, 0 , sizeof(payload));
			scnprintf(payload, sizeof(payload),
				"NULL$$EventField@@volumeupkey$$FieldData@@cnt%llu$$detailData@@up_%llu,down_%llu,interval_%llu",
				volup_press_count, volup_tm_data.curr_up_time, volup_tm_data.curr_down_time, volup_tm_data.key_handle_interval);
			oplus_kevent_fb(FB_TRI_STATE_KEY, BUTTON_DEBOUNCE_TYPE, payload);
#endif
		}
	}

	/* combination key pressed, start to calculate duration */
	if (is_pwrkey_down && is_volumup_down) {
		is_volumup_pwrkey_down = true;
		pr_info("volup_pwrkey combination key pressed.\n");
		schedule_delayed_work(&g_check_combkey_long_press_work, msecs_to_jiffies(CHECK_COMBKEY_LONG_PRESS_MS));
	} else {
		if (is_volumup_pwrkey_down) {
			is_volumup_pwrkey_down = false;
			pr_info("volup_pwrkey combination key canceled.\n");
			cancel_delayed_work(&g_check_combkey_long_press_work);
		}
	}

	/* only power key pressed, start to calculate duration */
	if (is_pwrkey_down && !is_volumup_down) {
		pr_info("power key pressed.\n");
		schedule_delayed_work(&g_check_pwrkey_long_press_work, msecs_to_jiffies(CHECK_PWRKEY_LONG_PRESS_MS));
	} else {
		pr_info("power key canceled.\n");
		cancel_delayed_work(&g_check_pwrkey_long_press_work);
	}

	return NOTIFY_DONE;
}

static struct notifier_block combkey_monitor_notifier = {
	.notifier_call = combkey_monitor_notifier_call,
	.priority = 128,
};

static int __init combkey_monitor_init(void)
{
	pr_info("called.\n");
	keyevent_register_notifier(&combkey_monitor_notifier, combkey_monitor_events, combkey_monitor_events_nr);
	INIT_DELAYED_WORK(&g_check_combkey_long_press_work, combkey_long_press_callback);
	INIT_DELAYED_WORK(&g_check_pwrkey_long_press_work, pwrkey_long_press_callback);
	return 0;
}

static void __exit combkey_monitor_exit(void)
{
	pr_info("called.\n");
	cancel_delayed_work_sync(&g_check_combkey_long_press_work);
	cancel_delayed_work_sync(&g_check_pwrkey_long_press_work);
	keyevent_unregister_notifier(&combkey_monitor_notifier, combkey_monitor_events, combkey_monitor_events_nr);
}

module_init(combkey_monitor_init);
module_exit(combkey_monitor_exit);

MODULE_DESCRIPTION("oplus_combkey_monitor");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL v2");
