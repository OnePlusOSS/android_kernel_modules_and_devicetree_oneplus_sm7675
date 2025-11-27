// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Oplus. All rights reserved.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM fpga_stat

#if !defined(_FPGA_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _FPGA_TRACE_H

#include <linux/tracepoint.h>

TRACE_EVENT(fpga_stat,
	TP_PROTO(long timestamp_ms, long mversion, long sversion, const char *fpga_register, int fpga_i2c_read_fail, int fpga_soft_reset, int fpga_hard_reset, int fpga_fault_code_record, int fpga_hard_reset_not_recovery, int fpga_intr_upload, int fpga_exit_lpm_mode, int heart_event),
	TP_ARGS(timestamp_ms, mversion, sversion, fpga_register, fpga_i2c_read_fail, fpga_soft_reset, fpga_hard_reset, fpga_fault_code_record, fpga_hard_reset_not_recovery, fpga_intr_upload, fpga_exit_lpm_mode, heart_event),
	TP_STRUCT__entry(
		__field(long,		timestamp_ms)
		__field(long,	mversion)
		__field(long,	sversion)
		__dynamic_array(char, fpga_register, strlen(fpga_register) + 1)
		__field(int, fpga_i2c_read_fail)
		__field(int, fpga_soft_reset)
		__field(int, fpga_hard_reset)
		__field(int, fpga_fault_code_record)
		__field(int, fpga_hard_reset_not_recovery)
		__field(int, fpga_intr_upload)
		__field(int, fpga_exit_lpm_mode)
		__field(int, heart_event)),

	TP_fast_assign(
		__entry->timestamp_ms	= timestamp_ms;
		__entry->mversion		= mversion;
		__entry->sversion		= sversion;
		strncpy(__get_dynamic_array(fpga_register), fpga_register, strlen(fpga_register) + 1),
		__entry->fpga_i2c_read_fail	= fpga_i2c_read_fail;
		__entry->fpga_soft_reset	= fpga_soft_reset;
		__entry->fpga_hard_reset	= fpga_hard_reset;
		__entry->fpga_fault_code_record	= fpga_fault_code_record;
		__entry->fpga_hard_reset_not_recovery	= fpga_hard_reset_not_recovery;
		__entry->fpga_intr_upload	= fpga_intr_upload;
		__entry->fpga_exit_lpm_mode	= fpga_exit_lpm_mode;
		__entry->heart_event	= heart_event),
		TP_printk("timestamp_ms:%ld mversion:%ld sversion:%ld fpga_register:%s fpga_i2c_read_fail:%d fpga_soft_reset:%d fpga_hard_reset:%d fpga_fault_code_record:%d fpga_hard_reset_not_recovery:%d fpga_intr_upload:%d fpga_exit_lpm_mode:%d heart_event:%d",
		__entry->timestamp_ms, __entry->mversion, __entry->sversion, __get_str(fpga_register), __entry->fpga_i2c_read_fail, __entry->fpga_soft_reset, __entry->fpga_hard_reset, __entry->fpga_fault_code_record, __entry->fpga_hard_reset_not_recovery, __entry->fpga_intr_upload, __entry->fpga_exit_lpm_mode, __entry->heart_event)

);
#endif /* _FPGA_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../../vendor/oplus/kernel/device_info/oplus_fpga/fpga_monitor
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE fpga_trace

/* This part must be outside protection */
#include <trace/define_trace.h>
