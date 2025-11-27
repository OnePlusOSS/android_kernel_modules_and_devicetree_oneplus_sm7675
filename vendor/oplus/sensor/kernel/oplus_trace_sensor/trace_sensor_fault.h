#if !defined(_TRACE_SENSOR_FAULT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SENSOR_FAULT_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM sensor

TRACE_EVENT(sensor_fault,

	TP_PROTO(long time_s, int app_id, const char* log_tag, const char* event_id, const char* log_type, int error_count),

	TP_ARGS(time_s, app_id, log_tag, event_id, log_type, error_count),

	TP_STRUCT__entry(
		__field(	long,	time_s)
		__field(	int,	app_id)
		__string(	log_tag,	log_tag)
		__string(	event_id,	event_id)
		__string(	log_type,	log_type)
		__field(	int,	error_count)
	),

	TP_fast_assign(
		__entry->time_s = time_s;
		__entry->app_id = app_id;
		__assign_str(log_tag, log_tag);
		__assign_str(event_id, event_id);
		__assign_str(log_type, log_type);
		__entry->error_count = error_count;
	),

	TP_printk("time_s:%ld app_id:%d log_tag:%s event_id:%s log_type:%s error_count:%d",
			__entry->time_s, __entry->app_id, __get_str(log_tag),
			__get_str(event_id), __get_str(log_type), __entry->error_count)
);

#undef TRACE_INCLUDE_PATH
#if defined(CFG_OPLUS_ARCH_IS_QCOM)
#define TRACE_INCLUDE_PATH  ../../drivers/soc/oplus/oplus_trace_sensor
#elif defined(CFG_OPLUS_ARCH_IS_MTK)
#define TRACE_INCLUDE_PATH  ../../../kernel_device_modules-6.6/drivers/soc/oplus/oplus_trace_sensor
#endif
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace_sensor_fault

/* This part must be outside protection */
#include <trace/define_trace.h>

#endif

