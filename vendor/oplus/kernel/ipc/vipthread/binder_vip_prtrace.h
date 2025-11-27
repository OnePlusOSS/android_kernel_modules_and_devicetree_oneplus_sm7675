/***********************************************************
** Copyright (C), 2008-2019, OPLUS Mobile Comm Corp., Ltd.
** File: binder_vip_ptrace.h
** Description: Add for vip thread policy for binder
**
** Version: 1.0
** Date : 2023/10/07
** Author: #, 2023/10/07, add for vip thread policy
**
** ------------------ Revision History:------------------------
** <author>      <data>      <version >       <desc>
** Feng Song    2023/10/07      1.0       VIP BINDER THREAD POLICY
****************************************************************/
#ifndef _PRTRACE_H_
#define _PRTRACE_H_

#define PRTRACE_SWITCH 1

#define PRTRACE_BUFSIZE 256

#define PRTRACE_SHOWLINE 1

#if PRTRACE_SWITCH

static void binder_vip_tracing_mark_write(const char * f, int linenum, char type, int pid, const char *fmt, ...) {
	if (trace_debug_enable) {
		char buf[PRTRACE_BUFSIZE];
		unsigned int offset = 0;
		va_list args;
		if (pid == 0)
			offset = scnprintf(buf, sizeof(buf), "%c|%u|", type, current->tgid);
		else
			offset = scnprintf(buf, sizeof(buf), "%c|%u|", type, pid);

		va_start(args, fmt);
		offset += vscnprintf(buf + offset, sizeof(buf) - offset, fmt, args);
		va_end(args);
#if PRTRACE_SHOWLINE
		if (type != 'C')
			scnprintf(buf + offset, sizeof(buf) - offset, " (%s: %d)", f, linenum);
#endif
		preempt_disable();
		trace_printk(buf);
		preempt_enable();
	}
}
#else
static inline void binder_vip_tracing_mark_write(const char * f, int linenum, char type, int pid, const char *fmt, ...) {}
#endif


#define PRTRACE_BEGIN(fmt, args...) binder_vip_tracing_mark_write("binder_vip", __LINE__, 'B', 0, fmt, ##args);
#define PRTRACE_END(fmt, args...) binder_vip_tracing_mark_write("binder_vip", __LINE__, 'E', 0, fmt, ##args);

#define PRTRACE(fmt, args...)	\
do {	\
	binder_vip_tracing_mark_write("binder_vip", __LINE__, 'I', 0, fmt, ##args);	\
} while (0);

/*name is char *, value is int*/
#define PRTRACE_INT(name, value) binder_vip_tracing_mark_write("binder_vip", __LINE__, 'C', 0, "%s|%d", name, value);

/* 	Define your counter name with format, fmt should contains only one '|', and ends with "|%d".
	Obey the format of tracing counter!
	e.g. PRTRACE_CUSTOM_INT("nr_reclaimed_%u|%d", current->tgid, nr_reclaimed);	*/
#define PRTRACE_CUSTOM_INT(pid, fmt, args...) binder_vip_tracing_mark_write(__FILE__, __LINE__, 'C', pid, fmt, ##args);

#endif /* _PRTRACE_H_ */
