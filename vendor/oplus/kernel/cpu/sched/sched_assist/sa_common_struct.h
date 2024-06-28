/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020-2022 Oplus. All rights reserved.
 */

/*
this file is splited from the sa_common.h to adapt the OKI,
IS_ENABLED is not allowed in here, because the macro will not work in OKI.
*/

#define MAX_CLUSTER            (4)

/*#if IS_ENABLED(CONFIG_OPLUS_FEATURE_CPU_JANKINFO)*/
/* hot-thread */
struct task_record {
#define RECOED_WINSIZE			(1 << 8)
#define RECOED_WINIDX_MASK		(RECOED_WINSIZE - 1)
	u8 winidx;
	u8 count;
};

#define MAX_TASK_COMM_LEN 256
struct uid_struct {
	uid_t uid;
	u64 uid_total_cycle;
	u64 uid_total_inst;
	spinlock_t lock;
	char leader_comm[TASK_COMM_LEN];
	char cmdline[MAX_TASK_COMM_LEN];
};

struct  amu_uid_entry {
	uid_t uid;
	struct uid_struct *uid_struct;
	struct hlist_node node;
};

/*#endif*/

/*#if IS_ENABLED(CONFIG_OPLUS_LOCKING_STRATEGY)*/
struct locking_info {
	u64 waittime_stamp;
	u64 holdtime_stamp;
	/* Used in torture acquire latency statistic.*/
	u64 acquire_stamp;
	/*
	 * mutex or rwsem optimistic spin start time. Because a task
	 * can't spin both on mutex and rwsem at one time, use one common
	 * threshold time is OK.
	 */
	u64 opt_spin_start_time;
	struct task_struct *holder;
	u32 waittype;
	bool ux_contrib;
	/*
	 * Whether task is ux when it's going to be added to mutex or
	 * rwsem waiter list. It helps us check whether there is ux
	 * task on mutex or rwsem waiter list. Also, a task can't be
	 * added to both mutex and rwsem at one time, so use one common
	 * field is OK.
	 */
	bool is_block_ux;
	u32 kill_flag;
	/* for cfs enqueue smoothly.*/
	struct list_head node;
	struct task_struct *owner;
	struct list_head lock_head;
	u64 clear_seq;
	atomic_t lock_depth;
};
/*#endif*/

/* Please add your own members of task_struct here :) */
struct oplus_task_struct {
	/* CONFIG_OPLUS_FEATURE_SCHED_ASSIST */
	struct rb_node ux_entry;
	raw_spinlock_t ux_entry_lock;
	struct rb_node exec_time_node;
	struct task_struct *task;
	atomic64_t inherit_ux;
	u64 enqueue_time;
	u64 inherit_ux_start;
	/* u64 sum_exec_baseline; */
	u64 total_exec;
	u64 vruntime;
	u64 preset_vruntime;
	int ux_state;
	u8 ux_depth;
	s8 ux_priority;
	s8 ux_nice;
	s8 im_flag;
	pid_t affinity_pid;
	pid_t affinity_tgid;
	unsigned long state;
/*#if IS_ENABLED(CONFIG_OPLUS_FEATURE_ABNORMAL_FLAG)*/
	int abnormal_flag;
/*#endif*/
	/* CONFIG_OPLUS_FEATURE_SCHED_SPREAD */
	int lb_state;
	int ld_flag:1;
	/* CONFIG_OPLUS_FEATURE_TASK_LOAD */
	int is_update_runtime:1;
	int target_process;
	u64 wake_tid;
	u64 running_start_time;
	bool update_running_start_time;
	u64 exec_calc_runtime;
/*#if IS_ENABLED(CONFIG_OPLUS_FEATURE_CPU_JANKINFO)*/
	struct task_record record[MAX_CLUSTER];	/* 2*u64 */
	u64 block_start_time;
/*#endif*/
	/* CONFIG_OPLUS_FEATURE_FRAME_BOOST */
	struct list_head fbg_list;
	raw_spinlock_t fbg_list_entry_lock;
	bool fbg_running; /* task belongs to a group, and in running */
	u8 fbg_state;
	s8 preferred_cluster_id;
	s8 fbg_depth;
	u64 last_wake_ts;
/*#ifdef CONFIG_LOCKING_PROTECT*/
	unsigned long locking_start_time;
	struct list_head locking_entry;
	int locking_depth;
/*#endif*/

/*#if IS_ENABLED(CONFIG_OPLUS_LOCKING_STRATEGY)*/
	struct locking_info lkinfo;
/*#endif*/

/*#if IS_ENABLED(CONFIG_OPLUS_FEATURE_FDLEAK_CHECK)*/
	u8 fdleak_flag;
/*#endif*/

/*#if IS_ENABLED(CONFIG_OPLUS_FEATURE_LOADBALANCE)*/
	/* for loadbalance */
	struct plist_node rtb;		/* rt boost task */

	/*
	 * The following variables are used to calculate the time
	 * a task spends in the running/runnable state.
	 */
	u64 snap_run_delay;
	unsigned long snap_pcount;
/*#endif*/

/*#if IS_ENABLED(CONFIG_OPLUS_FEATURE_PIPELINE)*/
	atomic_t pipeline_cpu;
/*#endif*/

	/* for oplus secure guard */
	int sg_flag;
	int sg_scno;
	uid_t sg_uid;
	uid_t sg_euid;
	gid_t sg_gid;
	gid_t sg_egid;
/*#if IS_ENABLED(CONFIG_ARM64_AMU_EXTN) && IS_ENABLED(CONFIG_OPLUS_FEATURE_CPU_JANKINFO)*/
	struct uid_struct *uid_struct;
	u64 amu_instruct;
	u64 amu_cycle;
/*#endif*/
	/* for binder ux */
	int binder_async_ux_enable;
	bool binder_async_ux_sts;
	int binder_thread_mode;
	struct binder_node *binder_thread_node;
} ____cacheline_aligned;

/*#if IS_ENABLED(CONFIG_OPLUS_FEATURE_LOADBALANCE)*/
#define INVALID_PID						(-1)
struct oplus_lb {
	/* used for active_balance to record the running task. */
	pid_t pid;
};
/*#endif*/
