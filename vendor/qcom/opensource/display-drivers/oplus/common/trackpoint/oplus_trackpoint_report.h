// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023-2023 Oplus. All rights reserved.
 */


#ifndef _OPLUS_TRACKPOINT_REPORT_
#define _OPLUS_TRACKPOINT_REPORT_

/*
 * trackpoint include info trackpoint and exception trackpoint
 * info trackpoint is for data stats
 * exception trackpoint is for bug fix, so will upload log
 */
#define TRACKPOINT_TYPE_INFO		1
#define TRACKPOINT_TYPE_EXCEPTION	2

/*
 * the trackpoint_id is the event_id in database at dataserver
 */
#define DRM_TRACKPOINT_EVENTID	12002
#define GPU_TRACKPOINT_EVENTID	12005

#define MESSAGE_MAX_SIZE		512
#define FUNC_LINE_MAX_SIZE		128

struct trackpoint {
	int type;
	int event_id;
	int sub_event_id;
	char message[MESSAGE_MAX_SIZE];
	char func_line[FUNC_LINE_MAX_SIZE];
};

int trackpoint_report(struct trackpoint *tp);

#define display_info_trackpoint_report(fmt, ...) \
	do { \
		struct trackpoint tp = { \
			.type = TRACKPOINT_TYPE_INFO, \
			.event_id = DRM_TRACKPOINT_EVENTID, \
			.sub_event_id = 0, \
		}; \
		scnprintf(tp.message, sizeof(tp.message), fmt, ##__VA_ARGS__); \
		scnprintf(tp.func_line, sizeof(tp.func_line), "%s:%d", __func__, __LINE__); \
		trackpoint_report(&tp); \
	} while (0)

#define display_exception_trackpoint_report(fmt, ...) \
	do { \
		struct trackpoint tp = { \
			.type = TRACKPOINT_TYPE_EXCEPTION, \
			.event_id = DRM_TRACKPOINT_EVENTID, \
			.sub_event_id = 0, \
		}; \
		scnprintf(tp.message, sizeof(tp.message), fmt, ##__VA_ARGS__); \
		scnprintf(tp.func_line, sizeof(tp.func_line), "%s:%d", __func__, __LINE__); \
		trackpoint_report(&tp); \
	} while (0)

#define gpu_info_trackpoint_report(fmt, ...) \
	do { \
		struct trackpoint tp = { \
			.type = TRACKPOINT_TYPE_INFO, \
			.event_id = GPU_TRACKPOINT_EVENTID, \
			.sub_event_id = 0, \
		}; \
		scnprintf(tp.message, sizeof(tp.message), fmt, ##__VA_ARGS__); \
		scnprintf(tp.func_line, sizeof(tp.func_line), "%s:%d", __func__, __LINE__); \
		trackpoint_report(&tp); \
	} while (0)

#define gpu_exception_trackpoint_report(fmt, ...) \
	do { \
		struct trackpoint tp = { \
			.type = TRACKPOINT_TYPE_EXCEPTION, \
			.event_id = GPU_TRACKPOINT_EVENTID, \
			.sub_event_id = 0, \
		}; \
		scnprintf(tp.message, sizeof(tp.message), fmt, ##__VA_ARGS__); \
		scnprintf(tp.func_line, sizeof(tp.func_line), "%s:%d", __func__, __LINE__); \
		trackpoint_report(&tp); \
	} while (0)

#endif /* _OPLUS_TRACKPOINT_REPORT_ */

