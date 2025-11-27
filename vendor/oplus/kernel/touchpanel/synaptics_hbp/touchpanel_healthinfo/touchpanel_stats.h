// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2018-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022, Qualcomm Innovation Center, Inc. All rights reserved.
*/

#if !defined(_TRACE_TOUCH_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_TOUCH_H

#include <linux/tracepoint.h>

/*--- TP 101157-101176 (define in "oplusfault_extension_astoms.proto")---*/
#define TOUCH_STATS_KERNEL_FAULT            101157
#define TOUCH_STATS_ESD_FAULT               101158
#define TOUCH_STATS_FW_UPDATE_FAULT         101159
#define TOUCH_STATS_DAEMON_MONITOR_FAULT    101160
#define TOUCH_STATS_STATE_MACHINE_FAULT     101161

#undef TRACE_SYSTEM
#define TRACE_SYSTEM touchpanel

TRACE_EVENT(stats_report,
	TP_PROTO(int id, const char* tp_ic, const char* fw_ver, const char* detail_info),
	TP_ARGS(id, tp_ic, fw_ver, detail_info),
	TP_STRUCT__entry(
		__field(int,		id)
		__string(tp_ic,		tp_ic)
		__string(fw_ver,	fw_ver)
		__string(detail_info,	detail_info)
	),
	TP_fast_assign(
		__entry->id = id;
		__assign_str(tp_ic,		tp_ic);
		__assign_str(fw_ver,	fw_ver);
		__assign_str(detail_info,	detail_info);
	),
	TP_printk("id:%d tp_ic:%s fw_ver:%s detail_info:%s",
		__entry->id, __get_str(tp_ic), __get_str(fw_ver),__get_str(detail_info))
);

#endif /* _TRACE_TOUCH_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH  ../../../vendor/oplus/kernel/touchpanel/synaptics_hbp/touchpanel_healthinfo

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE touchpanel_stats

/* This part must be outside protection */
#include <trace/define_trace.h>
