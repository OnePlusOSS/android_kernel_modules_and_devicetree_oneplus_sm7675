/***********************************************************
** Copyright (C), 2008-2019, OPLUS Mobile Comm Corp., Ltd.
** File: binder_vip.h
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
#undef TRACE_SYSTEM
#define TRACE_SYSTEM binder_vip

#if !defined(_BINDER_VIP_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _BINDER_VIP_TRACE_H

#include <linux/tracepoint.h>

struct binder_buffer;
struct binder_node;
struct binder_proc;
struct binder_alloc;
struct binder_ref_data;
struct binder_thread;
struct binder_transaction;
struct binder_transaction_data;


TRACE_EVENT(binder_vip_ioctl,
	TP_PROTO(uint32_t cmd),
	TP_ARGS(cmd),
	TP_STRUCT__entry(
		__field(uint32_t, cmd)),
	TP_fast_assign(
		__entry->cmd = cmd;),
	TP_printk("cmd=0x%x %d",
		  __entry->cmd,
		  _IOC_NR(__entry->cmd))
);

TRACE_EVENT(binder_vip_trans_handler,
	TP_PROTO(struct binder_proc *target_proc, struct binder_proc *proc, struct binder_transaction_data *tr),
	TP_ARGS(target_proc, proc, tr),
	TP_STRUCT__entry(
		__field(char *, target_proc_name)
		__field(char *, proc_name)
		__field(int, code)
		__field(int, flag)
		__field(bool, vip_flag)),
	TP_fast_assign(
		__entry->target_proc_name = target_proc->tsk->comm;
		__entry->proc_name = proc->tsk->comm;
		__entry->code = tr->code;
		__entry->flag = tr->flags;
		__entry->vip_flag = !!(tr->flags & TF_TAXI_THREAD_WAY);),
	TP_printk("targete_proc_name=%s proc_name=%s tr_code=%u tr_flag=%u vip_request=%u",
		  __entry->target_proc_name,
		  __entry->proc_name,
		  __entry->code,
		  __entry->flag,
		  __entry->vip_flag)
);

TRACE_EVENT(binder_vip_has_work_ilocked_handler,
	TP_PROTO(struct binder_thread *thread, bool do_proc_work, bool *has_work, int *skip),
	TP_ARGS(thread, do_proc_work, has_work, skip),
	TP_STRUCT__entry(
		__field(char *, proc_name)
		__field(int, thread_pid)
		__field(bool, has_work)
		__field(int, skip)
		__field(bool, vip_thread_flag)
		__field(bool, do_proc_work)),
	TP_fast_assign(
		__entry->proc_name = thread->proc->tsk->comm;
		__entry->thread_pid = thread->pid;
		__entry->has_work = *has_work;
		__entry->skip = *skip;
		__entry->vip_thread_flag = !!(thread->looper & BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED);
		__entry->do_proc_work = do_proc_work;),
	TP_printk("proc_name=%s thread_pid=%u has_work=%u skip=%u vip_thread_flag=%u do_proc_work=%u",
		  __entry->proc_name,
		  __entry->thread_pid,
		  __entry->has_work,
		  __entry->skip,
		  __entry->vip_thread_flag,
		  __entry->do_proc_work)

);

TRACE_EVENT(binder_vip_spawn_new_thread_handler,
	TP_PROTO(struct binder_thread *thread, struct binder_proc *proc, bool *skip),
	TP_ARGS(thread, proc, skip),
	TP_STRUCT__entry(
		__field(char *, proc_name)
		__field(int, thread_pid)
		__field(bool, skip)
		__field(bool, vip_thread_flag)
		__field(int, requested_threads_started)
		__field(int, max_threads)
		__field(int, vip_save_threads)
		__field(int, vip_thread_policy_max_threads)),
	TP_fast_assign(
		struct oplus_task_struct *ots = get_oplus_task_struct(proc->tsk);
		__entry->proc_name = thread->proc->tsk->comm;
		__entry->thread_pid = thread->pid;
		__entry->skip = *skip;
		__entry->vip_thread_flag = !!(thread->looper & BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED);
		__entry->requested_threads_started = proc->requested_threads_started;
		__entry->max_threads = proc->max_threads;
		__entry->vip_save_threads = ots->vip_save_threads;
		__entry->vip_thread_policy_max_threads = ots->vip_thread_policy_max_threads;),
	TP_printk(
	"proc_name=%s thread_pid=%u skip=%u vip_thread_flag=%u requested_threads_started=%u max_threads=%u vip_save_threads=%u vip_thread_policy_max_threads=%u",
		  __entry->proc_name,
		  __entry->thread_pid,
		  __entry->skip,
		  __entry->vip_thread_flag,
		  __entry->requested_threads_started,
		  __entry->max_threads,
		  __entry->vip_save_threads,
		  __entry->vip_thread_policy_max_threads)

);

TRACE_EVENT(binder_vip_looper_state_exited_handler,
	TP_PROTO(struct binder_thread *thread, struct binder_proc *proc),
	TP_ARGS(thread, proc),
	TP_STRUCT__entry(
		__field(char *, proc_name)
		__field(int, thread_pid)
		__field(bool, vip_thread_flag)
		__field(int, requested_threads_started)
		__field(int, max_threads)),
	TP_fast_assign(
		__entry->proc_name = thread->proc->tsk->comm;
		__entry->thread_pid = thread->pid;
		__entry->vip_thread_flag = !!(thread->looper & BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED);
		__entry->requested_threads_started = proc->requested_threads_started;
		__entry->max_threads = proc->max_threads;),
	TP_printk("proc_name=%s thread_pid=%u vip_thread_flag=%u requested_threads_started=%u max_threads=%u",
		  __entry->proc_name,
		  __entry->thread_pid,
		  __entry->vip_thread_flag,
		  __entry->requested_threads_started,
		  __entry->max_threads)

);

TRACE_EVENT(binder_vip_looper_state_registerered_handler,
	TP_PROTO(struct binder_thread *thread, struct binder_proc *proc),
	TP_ARGS(thread, proc),
	TP_STRUCT__entry(
		__field(char *, proc_name)
		__field(int, thread_pid)
		__field(bool, vip_thread_flag)
		__field(int, requested_threads_started)
		__field(int, max_threads)),
	TP_fast_assign(
		__entry->proc_name = thread->proc->tsk->comm;
		__entry->thread_pid = thread->pid;
		__entry->vip_thread_flag = !!(thread->looper & BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED);
		__entry->requested_threads_started = proc->requested_threads_started;
		__entry->max_threads = proc->max_threads;),
	TP_printk("proc_name=%s thread_pid=%u vip_thread_flag=%u requested_threads_started=%u max_threads=%u",
		  __entry->proc_name,
		  __entry->thread_pid,
		  __entry->vip_thread_flag,
		  __entry->requested_threads_started,
		  __entry->max_threads)

);

TRACE_EVENT(binder_select_worklist_on_vip_thread_handler,
	TP_PROTO(struct binder_thread *thread, struct binder_proc *proc,  struct list_head **list, bool *no_work),
	TP_ARGS(thread, proc, list, no_work),
	TP_STRUCT__entry(
		__field(char *, proc_name)
		__field(int, thread_pid)
		__field(bool, vip_thread_flag)
		__field(bool, proc_list_flag)
		__field(bool, no_work)
		__field(int, requested_threads_started)
		__field(int, max_threads)),
	TP_fast_assign(
		__entry->proc_name = thread->proc->tsk->comm;
		__entry->thread_pid = thread->pid;
		__entry->vip_thread_flag = !!(thread->looper & BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED);
		__entry->proc_list_flag = (*list == &proc->todo);
		__entry->no_work = *no_work;
		__entry->requested_threads_started = proc->requested_threads_started;
		__entry->max_threads = proc->max_threads;),
	TP_printk("proc_name=%s thread_pid=%u vip_thread_flag=%u proc_list_flag=%u no_work=%u requested_threads_started=%u max_threads=%u",
		  __entry->proc_name,
		  __entry->thread_pid,
		  __entry->vip_thread_flag,
		  __entry->proc_list_flag,
		  __entry->no_work,
		  __entry->requested_threads_started,
		  __entry->max_threads)

);



#endif /* _BINDER_TRACE_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE binder_vip_trace
#include <trace/define_trace.h>
