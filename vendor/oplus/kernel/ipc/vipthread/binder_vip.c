/***********************************************************
** Copyright (C), 2008-2019, OPLUS Mobile Comm Corp., Ltd.
** File: vip_binder.h
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/poll.h>
#include <linux/debugfs.h>
#include <linux/rbtree.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/pid_namespace.h>
#include <linux/security.h>
#include <linux/spinlock.h>
#include <linux/ratelimit.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/sizes.h>
#include <linux/android_vendor.h>

#include <uapi/linux/sched/types.h>
#include <uapi/linux/android/binder.h>

#include <asm/cacheflush.h>

#include <linux/proc_fs.h>
#include <drivers/android/binder_internal.h>
#include <drivers/android/binder_trace.h>
#include <trace/hooks/binder.h>

#include "binder_vip.h"
#include "binder_vip_sysfs.h"

/*for: use func: get_oplus_task_struct() */
#if IS_ENABLED(CONFIG_OPLUS_FEATURE_SCHED_ASSIST)
#include <../kernel/oplus_cpu/sched/sched_assist/sa_common.h>
#endif

rwlock_t	binder_vip_policy_group_rwlock; /* Lock on binder_vip_policy_group */
rwlock_t	binder_vip_policy_group_copy_rwlock; /* Lock on copy of binder_vip_policy_group */

static const char * const binder_vip_command_strings[] = {
	"BC_TRANSACTION",
};

bool binder_vip_policy_enable = false;
struct binder_vip_policy_summary vip_policy_summary;

enum {
	BINDER_LOOPER_STATE_REGISTERED  = 0x01,
	BINDER_LOOPER_STATE_ENTERED     = 0x02,
	BINDER_LOOPER_STATE_EXITED      = 0x04,
	BINDER_LOOPER_STATE_INVALID     = 0x08,
	BINDER_LOOPER_STATE_WAITING     = 0x10,
	BINDER_LOOPER_STATE_POLL        = 0x20,
	BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED  = 0x1000, /*TAXI thread*/
};

enum {
	BINDER_DEBUG_USER_ERROR             = 1U << 0,
	BINDER_DEBUG_FAILED_TRANSACTION     = 1U << 1,
	BINDER_DEBUG_DEAD_TRANSACTION       = 1U << 2,
	BINDER_DEBUG_OPEN_CLOSE             = 1U << 3,
	BINDER_DEBUG_DEAD_BINDER            = 1U << 4,
	BINDER_DEBUG_DEATH_NOTIFICATION     = 1U << 5,
	BINDER_DEBUG_READ_WRITE             = 1U << 6,
	BINDER_DEBUG_USER_REFS              = 1U << 7,
	BINDER_DEBUG_THREADS                = 1U << 8,
	BINDER_DEBUG_TRANSACTION            = 1U << 9,
	BINDER_DEBUG_TRANSACTION_COMPLETE   = 1U << 10,
	BINDER_DEBUG_FREE_BUFFER            = 1U << 11,
	BINDER_DEBUG_INTERNAL_REFS          = 1U << 12,
	BINDER_DEBUG_PRIORITY_CAP           = 1U << 13,
	BINDER_DEBUG_SPINLOCKS              = 1U << 14,
	BINDER_DEBUG_VIP_THREAD              = 1U << 15,
};

#define CREATE_TRACE_POINTS
#include "binder_vip_trace.h"

static uint32_t binder_debug_mask = BINDER_DEBUG_USER_ERROR |
	BINDER_DEBUG_FAILED_TRANSACTION | BINDER_DEBUG_DEAD_TRANSACTION;

#define binder_debug(mask, x...) \
	do { \
		if (binder_debug_mask & mask) \
			pr_info_ratelimited(x); \
	} while (0)

module_param_named(vip_binder_debug_mask, binder_debug_mask, uint, 0644);

static uint32_t vip_binder_max_threads = 0;
static bool trace_debug_enable = 0;
#include "binder_vip_prtrace.h"
module_param_named(trace_debug_enable, trace_debug_enable, bool, 0644);

module_param_named(vip_binder_max_threads, vip_binder_max_threads, uint, 0644);

enum e_vip_policy_type {
	e_vip_policy_type_all = 0,
	e_vip_policy_type_flag_mask,
	e_vip_policy_type_vip_thread,
};

/**
 * binder_inner_proc_lock() - Acquire inner lock for given binder_proc
 * @proc:         struct binder_proc to acquire
 *
 * Acquires proc->inner_lock. Used to protect todo lists
 */
#define binder_inner_proc_lock(proc) _binder_inner_proc_lock(proc, __LINE__)
static void
_binder_inner_proc_lock(struct binder_proc *proc, int line)
	__acquires(&proc->inner_lock)
{
	binder_debug(BINDER_DEBUG_SPINLOCKS,
		     "%s: line=%d\n", __func__, line);
	spin_lock(&proc->inner_lock);
}

/**
 * binder_inner_proc_unlock() - Release inner lock for given binder_proc
 * @proc:         struct binder_proc to acquire
 *
 * Release lock acquired via binder_inner_proc_lock()
 */
#define binder_inner_proc_unlock(proc) _binder_inner_proc_unlock(proc, __LINE__)
static void
_binder_inner_proc_unlock(struct binder_proc *proc, int line)
	__releases(&proc->inner_lock)
{
	binder_debug(BINDER_DEBUG_SPINLOCKS,
		     "%s: line=%d\n", __func__, line);
	spin_unlock(&proc->inner_lock);
}

static bool binder_worklist_empty_ilocked(struct list_head *list)
{
	return list_empty(list);
}

bool binder_has_work_taxi_thread_ilocked(struct binder_thread *thread)
{
	bool found = false;
	struct binder_work *w = NULL;
	struct list_head *list = &thread->proc->todo;
	struct binder_transaction *t = NULL;

	list_for_each_entry(w, list, entry) {/*taxi thread: select taxi work*/
		if (w->type != BINDER_WORK_TRANSACTION)
			continue;
		t = container_of(w, struct binder_transaction, work);
		WARN_ON(t == NULL);
		if (t && t->flags & TF_TAXI_THREAD_WAY) {/*taxi thread: find the taxi transaction*/
			list_move(&w->entry, &thread->proc->todo);
			found = true;
			break;
		}
	}

	return found;
}

bool binder_has_vip_work_ilocked(struct binder_thread *thread, bool do_proc_work, int *skip)
{
	bool vip_thread = !!(thread->looper & BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED);
	bool has_work = false;

	if (vip_thread) {
		*skip = 1;
		has_work = thread->process_todo ||
			thread->looper_need_return ||
			(do_proc_work &&
			 binder_has_work_taxi_thread_ilocked(thread));
#ifdef USING_GKI /*TODO: it will be removed if oki code upstream*/
		if (!has_work) {
			*skip = 0;
		}
#endif
	}
	return has_work;
}


/**
 * binder_select_thread_ilocked() - selects a thread for doing proc work.
 * @proc:	process to select a thread from
 *
 * Note that calling this function moves the thread off the waiting_threads
 * list, so it can only be woken up by the caller of this function, or a
 * signal. Therefore, callers *should* always wake up the thread this function
 * returns.
 *
 * Return:	If there's a thread currently waiting for process work,
 *		returns that thread. Otherwise returns NULL.
 */
static struct binder_thread *
binder_select_thread_ilocked(struct binder_proc *proc)
{
	struct binder_thread *thread;

	assert_spin_locked(&proc->inner_lock);
	thread = list_first_entry_or_null(&proc->waiting_threads,
					  struct binder_thread,
					  waiting_thread_node);

	if (thread)
		list_del_init(&thread->waiting_thread_node);

	return thread;
}

/**
 * binder_select_vip_thread_ilocked() - selects a vip thread for doing vip work.
 * @proc:	process to select a thread from
 *
 * Note that calling this function moves the thread off the waiting_threads
 * list, so it can only be woken up by the caller of this function, or a
 * signal. Therefore, callers *should* always wake up the thread this function
 * returns.
 *
 * Return:	If there's a thread currently waiting for process work,
 *		returns that thread. Otherwise returns NULL.
 */
static struct binder_thread *
binder_select_vip_thread_ilocked(struct binder_proc *proc)
{
	struct binder_thread *thread = NULL;
	bool found = false;

	assert_spin_locked(&proc->inner_lock);

	list_for_each_entry(thread, &proc->waiting_threads, waiting_thread_node) {
		if (!!!(thread->looper & (BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED))) {/*select normal thread*/
			found = true;
			break;
		}
	}

	if (found) {
		list_del_init(&thread->waiting_thread_node);
	} else {
		thread = NULL;
	}

	return thread;
}

static bool binder_available_for_proc_work_ilocked(struct binder_thread *thread)
{
	return !thread->transaction_stack &&
		binder_worklist_empty_ilocked(&thread->todo) &&
		(thread->looper & (BINDER_LOOPER_STATE_ENTERED |
				   BINDER_LOOPER_STATE_REGISTERED));
}

static bool binder_vip_white_list_check(struct binder_vip_policy *binder_vip_policy,
				uint32_t tr_code,
				struct binder_proc *proc,
				struct binder_proc *target_proc)
{
	int i = 0;
	bool found = false;
	int debug_map_no = 0;

	if (binder_vip_policy == NULL) {return false;}
	if (binder_vip_policy->info == NULL) {return false;}
	for (i = 0; i < binder_vip_policy->info->tr_code_size; i++) {
		if (binder_vip_policy->info->tr_code[i] == tr_code) {
			found = true;
			break;
		}
	}

	if (binder_vip_policy->info->tr_code_size == 0) found = true;
	if (!found)
		return found;
	debug_map_no++;
	found = false;
	if (strlen(binder_vip_policy->info->server_proc_name) > 0 &&
		strncmp(binder_vip_policy->info->server_proc_name, target_proc->tsk->comm, strlen(target_proc->tsk->comm)) == 0) {
		found = true;
	}

	if (strlen(binder_vip_policy->info->server_proc_name) == 0) found = true;
	if (!found)
		return found;
	debug_map_no++;
	found = false;
	if (strlen(binder_vip_policy->info->client_proc_name) > 0 &&
		strncmp(binder_vip_policy->info->client_proc_name, proc->tsk->comm, strlen(proc->tsk->comm)) == 0) {
		found = true;
	}

	if (strlen(binder_vip_policy->info->client_proc_name) == 0) {found = true;}
	if (found) {
		debug_map_no++;
	}
	binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d from %s to %s found %d debug_map_no %d",
			__func__, __LINE__,
			proc->tsk->comm, target_proc->tsk->comm, found,
			debug_map_no);
	return found;
}

/*TAXI thread: copy from hans helper*/
void binder_taxi_thread_trans_handler(struct binder_proc *target_proc,
				struct binder_proc *proc,
				struct binder_thread *thread,
				struct binder_transaction_data *tr)
{
	char buf_data[INTERFACETOKEN_BUFF_SIZE];
	size_t buf_data_size;
	char buf[INTERFACETOKEN_BUFF_SIZE] = {0};
	int i = 0;
	int j = 0;
	bool found = false;
	struct binder_vip_policy *binder_vip_policy = NULL;
	int  cur_vip_policy_type_group;
	struct list_head *vip_white_list;
	uint8_t policy_type = 200;/*init as 200, 200 is not support type*/
	int debug_map_no = -1;

	if (target_proc
	    /*&& (task_uid(target_proc->tsk).val > MIN_USERAPP_UID)*/
	    && (proc->pid != target_proc->pid)) {
		buf_data_size = tr->data_size > INTERFACETOKEN_BUFF_SIZE ?INTERFACETOKEN_BUFF_SIZE:tr->data_size;
		if (!copy_from_user(buf_data, (char*)tr->data.ptr.buffer, buf_data_size)) {
	            /*1.skip first PARCEL_OFFSET bytes (useless data)
	              2.make sure the invalid address issue is not occuring(j =PARCEL_OFFSET+1, j+=2)
	              3.java layer uses 2 bytes char. And only the first bytes has the data.(p+=2)*/
			if (buf_data_size > PARCEL_OFFSET) {
				char *p = (char *)(buf_data) + PARCEL_OFFSET;
				j = PARCEL_OFFSET + 1;
				while (i < INTERFACETOKEN_BUFF_SIZE && j < buf_data_size && *p != '\0') {
					buf[i++] = *p;
					j += 2;
					p += 2;
				}
				if (i == INTERFACETOKEN_BUFF_SIZE)
					buf[i-1] = '\0';
				else
					buf[i] = '\0';
			}
			binder_debug(BINDER_DEBUG_VIP_THREAD,
				"vip thread filter: %s:%d, %s, %u from %s to %s vip request flag from user %d\n",
				__func__, __LINE__, buf, tr->code,  proc->tsk->comm, target_proc->tsk->comm, !!(tr->flags & TF_TAXI_THREAD_WAY));
		}
	}
	if (binder_vip_policy_enable == false) {/*disable vip request*/
		tr->flags &= ~TF_TAXI_THREAD_WAY;
		return;
	}

	read_lock(&binder_vip_policy_group_rwlock);
	cur_vip_policy_type_group = vip_policy_summary.cur_vip_policy_type_group;
	vip_white_list = &vip_policy_summary.vip_white_list[cur_vip_policy_type_group];
	list_for_each_entry(binder_vip_policy, vip_white_list, vip_entry) {
		if (!binder_vip_policy->info) {
			WARN_ON(1);
			continue;
		}
		if (strncmp(binder_vip_policy->info->interface_token, buf, strlen(buf)) == 0) {
			found = true;

			binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d binder_vip_policy info(%d %s %s %s) tr_code(%u)",
			        __func__, __LINE__, binder_vip_policy->info->policy_type, binder_vip_policy->info->server_proc_name, binder_vip_policy->info->client_proc_name,
			        binder_vip_policy->info->interface_token, tr->code);
			break;
		}
	}
	if (found) {
		uint8_t policy_type = binder_vip_policy->info->policy_type;
		debug_map_no++;
		switch (policy_type) {
		case e_vip_policy_type_flag_mask: {
			found = false;

			if (!!(tr->flags & (TF_TAXI_THREAD_WAY | TF_TAXI_UX_WAY)))
				found = true;
			else
				break;

			found = binder_vip_white_list_check(binder_vip_policy, tr->code, proc, target_proc);
			if (!found) {
				tr->flags &= ~(TF_TAXI_THREAD_WAY | TF_TAXI_UX_WAY);
			}
		}
		break;
		case e_vip_policy_type_all: {
			found = false;
			tr->flags &= ~(TF_TAXI_THREAD_WAY | TF_TAXI_UX_WAY);
			found = binder_vip_white_list_check(binder_vip_policy, tr->code, proc, target_proc);
			if(found) {
				tr->flags |= TF_TAXI_THREAD_WAY;
				tr->flags |= TF_TAXI_UX_WAY;
			}
		}
		break;
		case e_vip_policy_type_vip_thread: {
			found = false;
			tr->flags &= ~(TF_TAXI_THREAD_WAY | TF_TAXI_UX_WAY);
			found = binder_vip_white_list_check(binder_vip_policy, tr->code, proc, target_proc);
			if(found) {
				tr->flags |= TF_TAXI_THREAD_WAY;
			}
		}
		break;
		default:
			found = false;
		break;
		}
		binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d tr->flags %u vip_request (%d) from %s to %s found %d policy_type(%d) by %s",
							__func__, __LINE__, tr->flags, !!(tr->flags & TF_TAXI_THREAD_WAY),
							proc->tsk->comm, target_proc->tsk->comm, found, policy_type,
							binder_vip_policy->info->interface_token);

	} else {
		tr->flags &= ~(TF_TAXI_THREAD_WAY | TF_TAXI_UX_WAY);
		if (strncmp(target_proc->tsk->comm, "mple.sfhangtest", strlen(target_proc->tsk->comm)) == 0
		    && strncmp(proc->tsk->comm, "surfaceflinger", strlen(proc->tsk->comm)) == 0) {
		    tr->flags |= TF_TAXI_THREAD_WAY;
		}
		binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d tr->flags %u vip_request (%d) from %s to %s found %d policy_type(%d) by %s debug_map_no %d",
							__func__, __LINE__, tr->flags, !!(tr->flags & TF_TAXI_THREAD_WAY),
							proc->tsk->comm, target_proc->tsk->comm, found, policy_type,
							buf, debug_map_no);
	}
	read_unlock(&binder_vip_policy_group_rwlock);
}

struct binder_thread *binder_proc_transaction_vip_thread_selected(struct binder_transaction *t,
									struct binder_proc *proc,
									struct binder_thread *thread,
									bool pending_async)
{
	bool vip_rpc = !!(t->flags & TF_TAXI_THREAD_WAY);
	bool vip_thread = !!(thread->looper & BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED);

	/*taxi rpc can use any free thread*/
	if (vip_rpc)
		goto out;
	if (vip_thread) {/*client rpc is not vip request but thread is vip thread*/
		struct binder_thread *taxi_thread = thread;
		thread = binder_select_vip_thread_ilocked(proc);
		list_add(&taxi_thread->waiting_thread_node, &proc->waiting_threads);

		binder_debug(BINDER_DEBUG_VIP_THREAD,
			"%s %d client normal rpc in vip server.debuginfo(proc[%s:%d] tr[%u:%d]  thread[%d:%d])\n",
			__func__, __LINE__,
			proc->tsk->comm, proc->tsk->pid, t->code, t->flags, thread?thread->pid:0, thread?thread->looper:0);
	}
out:
	return thread;
}

bool binder_look_for_proc_work_on_vip_thread(struct list_head **list,
						struct binder_proc *proc,
						struct binder_thread *thread,
						int wait_for_proc_work)
{
	struct binder_work *w = NULL;
	struct binder_transaction *t = NULL;
	bool vip_thread = !!(thread->looper & BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED);
	bool found = false;

	if (!vip_thread) /*normal thread: just set found as true*/
		goto out;
	if (*list && *list == &proc->todo) { /*deal with: *list have been assignde, mostly it not called*/
		goto proc_todo;
	}

	if (!binder_worklist_empty_ilocked(&thread->todo)) {
		*list = &thread->todo;
		found = true;
		goto out;
	} else if (!binder_worklist_empty_ilocked(&proc->todo) && wait_for_proc_work) {
proc_todo:
		*list = &proc->todo;
		found = false;
		list_for_each_entry(w, *list, entry) {/*taxi thread: select taxi work*/
			WARN_ON(w == NULL);
			if (w && w->type != BINDER_WORK_TRANSACTION)
				continue;
			t = container_of(w, struct binder_transaction, work);
			if (!t) {
				WARN_ON(1);
				continue;
			}
			if (t->flags & TF_TAXI_THREAD_WAY) {/*taxi thread: find the taxi transaction*/
				list_move(&w->entry, &proc->todo);
				found = true;
				if (t->from && t->from->proc)
					binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d vip rpc work map the vip thread, server:%s client:%s",
				__func__, __LINE__, proc->tsk->comm, t->from->proc->tsk->comm);
				else
					binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d vip rpc work map the vip thread, server:%s client:%p", __func__, __LINE__, proc->tsk->comm, t->from);
				break;
			} else {
			}
		}
	} else {
		found = false;
	}
out:
        if (!found)
                binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d no vip rpc work map the vip thread, server:%s", __func__, __LINE__, proc->tsk->comm);
	return found;
}

static long binder_vip_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	void __user *ubuf = (void __user *)arg;

	binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d debug steps %d\n", __func__, __LINE__, _IOC_NR(cmd));

	trace_binder_vip_ioctl(cmd);
	/*add new policy here*/
	switch(cmd) {
	case 0: {
                /*cur_vip_policy_type_group = 0;*/
		vip_policy_summary.cur_vip_policy_type_group = e_vip_policy_group_default;
	}
	break;
	case 1: {
                /*cur_vip_policy_type_group = 1;*/
		vip_policy_summary.cur_vip_policy_type_group = e_vip_policy_group_app_switch;
	}
	break;
	case VIP_BINDER_SUBMIT_VIP_TOKENS: {
                int group_id;
                struct vip_token_group vip_token_group;

                read_lock(&binder_vip_policy_group_rwlock);
                group_id = vip_policy_summary.cur_vip_policy_type_group ? 0: 1;
                read_unlock(&binder_vip_policy_group_rwlock);

                if (copy_from_user(&vip_token_group, ubuf, sizeof(vip_token_group))) {
                        ret = -EINVAL;
                        goto err;
                }
		/*step 1:update new tokens in copy group*/
                write_lock(&binder_vip_policy_group_copy_rwlock);
                ret = binder_vip_update_vip_token_group_ilocked(group_id, &vip_token_group);
                write_unlock(&binder_vip_policy_group_copy_rwlock);

		/*step 2:switch copy group list as current group */
		write_lock(&binder_vip_policy_group_rwlock);
		vip_policy_summary.cur_vip_policy_type_group = group_id;
		write_unlock(&binder_vip_policy_group_rwlock);

                /*step 3:clear new copy group*/
                read_lock(&binder_vip_policy_group_rwlock);
                group_id = vip_policy_summary.cur_vip_policy_type_group ? 0: 1;
                read_unlock(&binder_vip_policy_group_rwlock);

                write_lock(&binder_vip_policy_group_copy_rwlock);
                binder_vip_clear_vip_token_group_ilocked(group_id);
                write_unlock(&binder_vip_policy_group_copy_rwlock);
        }
	break;
        case VIP_BINDER_CLEAR_TOKENS: {
                int group_id = vip_policy_summary.cur_vip_policy_type_group;
		/*step 1:switch copy group list as current group */
		write_lock(&binder_vip_policy_group_rwlock);
		vip_policy_summary.cur_vip_policy_type_group = group_id ? 0: 1;
		write_unlock(&binder_vip_policy_group_rwlock);

		/*step 2:clear now new copy group*/
                write_lock(&binder_vip_policy_group_copy_rwlock);
                binder_vip_clear_vip_token_group_ilocked(group_id);
                write_unlock(&binder_vip_policy_group_copy_rwlock);
        }
        break;
        case VIP_BINDER_SET_ENABLE_STATE: {
                u8 enable;
                if (copy_from_user(&enable, ubuf, sizeof(enable))) {
                        ret = -EINVAL;
                        goto err;
                }
                binder_vip_policy_enable = enable > 0 ? true:false;
		binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d debug binder_vip_policy_enable=%d enable=%d\n",
			__func__, __LINE__, binder_vip_policy_enable, enable);
        }
        break;
        case VIP_BINDER_GET_ENABLE_STATE: {
                u8 enable = binder_vip_policy_enable? 1: 0;
                if (copy_to_user(ubuf, &enable, sizeof(enable))) {
                        ret = -EINVAL;
                        goto err;
                }
        }
        break;
        case VIP_BINDER_SWITCH_GROUP_ID: {
                u32 group_id;
                if (copy_from_user(&group_id, ubuf, sizeof(group_id))) {
                        ret = -EINVAL;
                        goto err;
                }
                write_lock(&binder_vip_policy_group_rwlock);
                vip_policy_summary.cur_vip_policy_type_group = group_id;
                write_unlock(&binder_vip_policy_group_rwlock);
        }
        break;
	case VIP_BINDER_SET_DEBUG_TRACE_STATE: {
                u8 enable;
                if (copy_from_user(&enable, ubuf, sizeof(enable))) {
                        ret = -EINVAL;
                        goto err;
                }
                trace_debug_enable = enable > 0 ? true:false;
		binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d debug trace_debug_enable=%d enable=%d\n",
			__func__, __LINE__, binder_vip_policy_enable, enable);
        }
        break;
        case VIP_BINDER_GET_DEBUG_TRACE_STATE: {
                u8 enable = trace_debug_enable? 1: 0;
                if (copy_to_user(ubuf, &enable, sizeof(enable))) {
                        ret = -EINVAL;
                        goto err;
                }
        }
        break;
	default:
		break;
	}
	binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d debug steps exit ioctl %d\n", __func__, __LINE__, ret);
err:
	return ret;
}

const struct file_operations binder_vip_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = binder_vip_ioctl,
	/*.mmap = binder_mmap,
	.open = binder_open,
	.flush = binder_flush,
	.release = binder_release,*/
};

static int __init init_vipbinder_device(const char *name)
{
	int ret;
	struct binder_vip_device *binder_vip_device;

	binder_vip_device = kzalloc(sizeof(*binder_vip_device), GFP_KERNEL);
	if (!binder_vip_device)
		return -ENOMEM;

	binder_vip_device->miscdev.fops = &binder_vip_fops;
	binder_vip_device->miscdev.minor = MISC_DYNAMIC_MINOR;
	binder_vip_device->miscdev.name = name;
	binder_vip_device->miscdev.mode = 0777;

	ret = misc_register(&binder_vip_device->miscdev);
	if (ret < 0) {
		kfree(binder_vip_device);
		return ret;
	}

	return ret;
}

/*file node for : vip policy group*/
ssize_t taxi_thread_test_show(struct file *file, char __user *user_buf,
					 size_t count, loff_t *ppos)
{
	ssize_t ret = 0;
	static int loop_cnt = 0;
	bool found = false;
	struct binder_vip_policy *binder_vip_policy = NULL;
	char taxi_thread_rpc_name[MAX_TAXI_THREAD_RPC_NAME_LEN] = {0, };
	int  cur_vip_policy_type_group = vip_policy_summary.cur_vip_policy_type_group;
	struct list_head *vip_white_list = &vip_policy_summary.vip_white_list[cur_vip_policy_type_group];
	char tr_codes[128] = {0, };
	int i = 0;

	if (*ppos >= MAX_TAXI_THREAD_RPC_NAME_LEN)
		 return 0;
	if (*ppos + count > MAX_TAXI_THREAD_RPC_NAME_LEN)
		count = MAX_TAXI_THREAD_RPC_NAME_LEN - *ppos;

	memset(taxi_thread_rpc_name, '\0', sizeof(taxi_thread_rpc_name));

	binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d  cur_vip_policy_type_group %d %d\n", __func__, __LINE__,
		cur_vip_policy_type_group,
		vip_policy_summary.cur_vip_policy_type_group);
	read_lock(&binder_vip_policy_group_rwlock);
	list_for_each_entry(binder_vip_policy, vip_white_list, vip_entry) {
		if (binder_vip_policy->info->index == loop_cnt) {
			loop_cnt++;
			found = true;
			break;
		}
	}
	binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d  cur_vip_policy_type_group %d %d %d\n", __func__, __LINE__,
		cur_vip_policy_type_group,
		vip_policy_summary.cur_vip_policy_type_group, found);
	if (found) {
		binder_debug(BINDER_DEBUG_VIP_THREAD,
        		     "%s %d songfengtest %d\n", __func__, __LINE__, binder_vip_policy->info->tr_code_size);
		for(i = 0; i < binder_vip_policy->info->tr_code_size; i++)
			binder_debug(BINDER_DEBUG_VIP_THREAD,
        		     "%s %d songfengtest %d\n", __func__, __LINE__, binder_vip_policy->info->tr_code[i]);
	}

	if (found && binder_vip_policy) {
		for (i = 0; i < binder_vip_policy->info->tr_code_size; i++) {
			sprintf(tr_codes, "%s%d", tr_codes, binder_vip_policy->info->tr_code[i]);
			if (i < binder_vip_policy->info->tr_code_size - 1)
				sprintf(tr_codes, "%s|", tr_codes);
		}
		sprintf(taxi_thread_rpc_name, "%s,%s,%s,%s,%d,%d,%d",
			binder_vip_policy->info->interface_token, tr_codes,
			binder_vip_policy->info->client_proc_name, binder_vip_policy->info->server_proc_name,
			(int)binder_vip_policy->info->policy_type,
			binder_vip_policy->info->handle, binder_vip_policy->info->index);

	} else {
		sprintf(taxi_thread_rpc_name, "index is %d, policy found is %d", loop_cnt, found);
		loop_cnt = 0;
	}

	read_unlock(&binder_vip_policy_group_rwlock);

	if (copy_to_user(user_buf, *ppos + taxi_thread_rpc_name, count)) {
		binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d Failed to copy to user \n", __func__, __LINE__);
	}
	binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d the set rpc name is :%s \n", __func__, __LINE__, taxi_thread_rpc_name);
	ret = strlen(taxi_thread_rpc_name);
	*ppos += count;
	ret = count;
	return ret;
}

/*file node for : vip policy group*/
ssize_t taxi_thread_test_store(struct file *file,
					  const char __user *user_buf, size_t count,
					  loff_t *ppos)
{
	int ret = 0;
	ssize_t buf_size;
	char *token;
	char *opts;
	char *orig;
	ssize_t loop_cnt = 0;
	int index = -1;
	bool found = false;
	char taxi_thread_rpc_name[MAX_TAXI_THREAD_RPC_NAME_LEN] = {0, };
	struct binder_vip_policy *binder_vip_policy;

	int  cur_vip_policy_type_group = vip_policy_summary.cur_vip_policy_type_group;
	struct list_head *vip_white_list = &vip_policy_summary.vip_white_list[cur_vip_policy_type_group];

	memset(taxi_thread_rpc_name, '\0', sizeof(taxi_thread_rpc_name));
	buf_size = min(count, (size_t)(sizeof(taxi_thread_rpc_name)-1));
	if (copy_from_user(taxi_thread_rpc_name, user_buf, buf_size)) {
		binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d Failed to copy from user \n", __func__, __LINE__);
		return -EFAULT;
	}
	taxi_thread_rpc_name[buf_size] = 0;
	opts = kstrdup(taxi_thread_rpc_name, GFP_KERNEL);
	if (!opts)
		return -ENOMEM;
	orig = opts;
	binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d debug steps %s \n", __func__, __LINE__, taxi_thread_rpc_name);
	token = strsep(&opts, ",");
	binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d debug steps %s token:%s\n", __func__, __LINE__, taxi_thread_rpc_name, token);

	write_lock(&binder_vip_policy_group_rwlock);
	if (token) {
		list_for_each_entry(binder_vip_policy, vip_white_list, vip_entry) {
			index = binder_vip_policy->info->index > index ? binder_vip_policy->info->index : index;
			if (strncmp(binder_vip_policy->info->interface_token, strstrip(token), strlen(strstrip(token))) == 0) {
				found = true;
				break;
			}
		}
	}
	binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d debug steps found %d \n", __func__, __LINE__, found);
	if (!found) {
		binder_vip_policy = kzalloc(sizeof(*binder_vip_policy), GFP_KERNEL);
		if (!binder_vip_policy) {
                        buf_size = -ENOMEM;
                        goto out;
		}
		binder_vip_policy->info = kzalloc(sizeof(struct binder_vip_policy_info), GFP_KERNEL);
		if (!binder_vip_policy->info) {
                        buf_size = -ENOMEM;
                        goto out;
		}
		binder_vip_policy->info->index = index + 1;
		WARN_ON(binder_vip_policy->info->index < 0);
	}
	while (token != NULL) {
		binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d debug steps loop_cnt %zd %s \n", __func__, __LINE__, loop_cnt, token);
		switch(loop_cnt) {
		case 0:/*interface token*/
			memset(binder_vip_policy->info->interface_token, '\0', sizeof(binder_vip_policy->info->interface_token));
			strncpy(binder_vip_policy->info->interface_token, token, strlen(strstrip(token)));
		break;
		case 1: {/* trcode*/
			int tr_code;
			char *tr_token;
                        binder_vip_policy->info->tr_code_size = 0;
			while((tr_token = strsep(&token, "|")) != NULL) {
                                tr_code = -1;
				if (strlen(strstrip(tr_token)) > 0) {
				ret = kstrtoint(strstrip(tr_token), 10, &tr_code);}
                                if (tr_code > 0) {
                                        if (binder_vip_policy->info->tr_code_size == 0)
                                                binder_vip_policy->info->tr_code
                                                                = kzalloc(sizeof(uint32_t), GFP_KERNEL);
                                        else
                                                binder_vip_policy->info->tr_code
                                                                = krealloc(binder_vip_policy->info->tr_code, sizeof(uint32_t), GFP_KERNEL);
                                        binder_vip_policy->info->tr_code[binder_vip_policy->info->tr_code_size] = tr_code;
                                        binder_vip_policy->info->tr_code_size++;
                                }
			}
		}
		break;
		case 2: {/* client_proc_name*/
			int len = strlen(strstrip(token));
			int start_pos = 0;
			if (len >= TASK_COMM_LEN - 1) {
				start_pos += len - TASK_COMM_LEN + 1;
				len = TASK_COMM_LEN - 1;
			}
			memset(binder_vip_policy->info->client_proc_name, '\0', sizeof(binder_vip_policy->info->client_proc_name));
			strncpy(binder_vip_policy->info->client_proc_name, strstrip(token) + start_pos, len);
		}
		break;
		case 3: {/* server_proc_name*/
			int len = strlen(strstrip(token));
			int start_pos = 0;
			if (len >= TASK_COMM_LEN - 1) {
				start_pos += len - TASK_COMM_LEN + 1;
				len = TASK_COMM_LEN - 1;
			}
			memset(binder_vip_policy->info->server_proc_name, '\0', sizeof(binder_vip_policy->info->server_proc_name));
			strncpy(binder_vip_policy->info->server_proc_name, strstrip(token) + start_pos, len);
		}
		break;
		case 4: {/* policy_type*/
			int policy_type;
			ret = kstrtoint(strstrip(token), 10, &policy_type);
			binder_vip_policy->info->policy_type = (uint8_t)policy_type;
		}
		break;
		case 5: {/* handle*/
			int handle;
			ret = kstrtoint(strstrip(token), 10, &handle);
			binder_vip_policy->info->handle = handle;
		}
		break;
		default:
		break;
		}
		token = strsep(&opts, ",");
		loop_cnt++;
	}
	binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d debug steps found %d \n", __func__, __LINE__, found);

	if (!found) {
		INIT_LIST_HEAD(&binder_vip_policy->vip_entry);
		list_add(&binder_vip_policy->vip_entry, vip_white_list);
	}
out:
	write_unlock(&binder_vip_policy_group_rwlock);
	kfree(orig);
	return buf_size;
}

/*file node for : vip policy group*/
const struct file_operations taxi_thread_test_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = taxi_thread_test_show,
	.write = taxi_thread_test_store,
};

/*file node for : it will be removed*/
ssize_t taxi_thread_target_test_show(struct file *file, char __user *user_buf,
					 size_t count, loff_t *ppos)
{
	ssize_t ret = 0;
	char taxi_thread_target_name[MAX_TAXI_THREAD_RPC_NAME_LEN] = {0, };
	memset(taxi_thread_target_name, '\0', sizeof(taxi_thread_target_name)-1);
	if (*ppos >= MAX_TAXI_THREAD_RPC_NAME_LEN)
		 return 0;
	if (*ppos + count > MAX_TAXI_THREAD_RPC_NAME_LEN)
		count = MAX_TAXI_THREAD_RPC_NAME_LEN - *ppos;

	if (copy_to_user(user_buf, *ppos + taxi_thread_target_name, count)) {
		binder_debug(BINDER_DEBUG_VIP_THREAD,
			"%s %d Failed to copy to user\r\n",
			__func__, __LINE__);
	}
	binder_debug(BINDER_DEBUG_VIP_THREAD,
		"%s %d the set rpc name server is :%s \n",
		__func__, __LINE__,
		taxi_thread_target_name);
	ret = strlen(taxi_thread_target_name);
	*ppos += count;
	ret = count;
	return ret;
}

/*file node for : it will be removed*/
ssize_t taxi_thread_target_test_store(struct file *file,
					  const char __user *user_buf, size_t count,
					  loff_t *ppos)
{
	ssize_t buf_size;
	char taxi_thread_target_name[MAX_TAXI_THREAD_RPC_NAME_LEN] = {0, };
	memset(taxi_thread_target_name, '\0', sizeof(taxi_thread_target_name)-1);
	buf_size = min(count, (size_t)(sizeof(taxi_thread_target_name)-1));
	if (copy_from_user(taxi_thread_target_name, user_buf, buf_size)) {
		binder_debug(BINDER_DEBUG_VIP_THREAD,
			"%s %d Failed to copy from user\r\n",
			__func__, __LINE__);
		return -EFAULT;
	}
	taxi_thread_target_name[buf_size] = 0;

	if (strncmp(strstrip(taxi_thread_target_name), "enable", strlen("enable")) == 0) {
		binder_vip_policy_enable = true;
	} else if (strncmp(strstrip(taxi_thread_target_name), "disable", strlen("disable")) == 0) {
		binder_vip_policy_enable = false;
	}
	binder_debug(BINDER_DEBUG_VIP_THREAD,
			"%s %d taxi_thread_target_name %s %zu binder_vip_policy_enable %d\r\n",
			__func__, __LINE__, taxi_thread_target_name, strlen(taxi_thread_target_name), binder_vip_policy_enable);

	return buf_size;
}

/*file node for : it will be removed*/
const struct file_operations taxi_thread_target_test_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = taxi_thread_target_test_show,
	.write = taxi_thread_target_test_store,
};

/*file node for : current vip policy group index*/
ssize_t taxi_thread_switch_vip_policy_group_show(struct file *file, char __user *user_buf,
					 size_t count, loff_t *ppos)
{
	char buffer[20];
	size_t len = 0;
        int  cur_vip_policy_type_group = vip_policy_summary.cur_vip_policy_type_group;

	read_lock(&binder_vip_policy_group_rwlock);
	len = snprintf(buffer, sizeof(buffer), "%d\n", cur_vip_policy_type_group);
	read_unlock(&binder_vip_policy_group_rwlock);

	return simple_read_from_buffer(user_buf, count, ppos, buffer, len);
}

/*file node for : current vip policy group index*/
ssize_t taxi_thread_switch_vip_policy_group_store(struct file *file,
					  const char __user *user_buf, size_t count,
					  loff_t *ppos)
{
	char buffer[8];
	int err, val;

	memset(buffer, 0, sizeof(buffer));

	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;

	if (copy_from_user(buffer, user_buf, count))
		return -EFAULT;

	buffer[count] = '\0';
	err = kstrtoint(strstrip(buffer), 10, &val);
	if (err)
		return err;
	write_lock(&binder_vip_policy_group_rwlock);
	if (val >=0 && val <= 2)
		vip_policy_summary.cur_vip_policy_type_group = val;
	write_unlock(&binder_vip_policy_group_rwlock);
		return count;
}

/*file node for : current vip policy group index*/
const struct file_operations taxi_thread_switch_vip_policy_group_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = taxi_thread_switch_vip_policy_group_show,
	.write = taxi_thread_switch_vip_policy_group_store,
};

const struct binder_debugfs_entry binder_vip_debugfs_entries[] = {
	{
		.name = "taxi_thread_test_vip_policy_group",
		.mode = 0664,
		.fops = &taxi_thread_test_fops,
		.data = NULL,
	},
	{
		.name = "taxi_thread_test_vip_server",
		.mode = 0664,
		.fops = &taxi_thread_target_test_fops,
		.data = NULL,
	},
	{
		.name = "taxi_thread_switch_vip_policy",
		.mode = 0664,
		.fops = &taxi_thread_switch_vip_policy_group_fops,
		.data = NULL,
	},
	{} /* terminator */
};

static void binder_vip_debugfs_init(void)
{
	struct dentry *binder_debugfs_dir_entry_root;
	binder_debugfs_dir_entry_root = debugfs_create_dir("vip_binder", NULL);
	if (binder_debugfs_dir_entry_root) {
		const struct binder_debugfs_entry *db_entry;

		binder_vip_for_each_debugfs_entry(db_entry)
			debugfs_create_file(db_entry->name,
						db_entry->mode,
						binder_debugfs_dir_entry_root,
						db_entry->data,
						db_entry->fops);
	}
}

static void binder_vip_set_tr_code_default(struct binder_vip_policy_info *info)
{
	info->tr_code_size = 0;
	info->tr_code = NULL;
}

int binder_vip_policy_init_default(void)
{
	int ret = 0;

	struct binder_vip_policy *binder_vip_policy = kzalloc(sizeof(*binder_vip_policy), GFP_KERNEL);
	if (!binder_vip_policy)
		return -ENOMEM;
	binder_vip_policy->info = kzalloc(sizeof(struct binder_vip_policy_info), GFP_KERNEL);
	if (!binder_vip_policy->info)
		return -ENOMEM;
	binder_vip_set_tr_code_default(binder_vip_policy->info);

	binder_vip_policy->info->tr_code_size = 1;
	binder_vip_policy->info->tr_code = kzalloc(binder_vip_policy->info->tr_code_size * sizeof(uint32_t), GFP_KERNEL);
	if (!binder_vip_policy->info->tr_code)
		return -ENOMEM;

	binder_vip_policy->info->tr_code[0] = 25;

	binder_vip_policy->info->index = 0;
	strncpy(binder_vip_policy->info->interface_token, "android.app.IActivityManager", strlen("android.app.IActivityManager"));

	binder_vip_policy->info->policy_type = e_vip_policy_type_all;
	binder_vip_policy->info->handle = -1;
	INIT_LIST_HEAD(&binder_vip_policy->vip_entry);
	list_add(&binder_vip_policy->vip_entry, &vip_policy_summary.vip_white_list[0]);

	binder_vip_policy = kzalloc(sizeof(*binder_vip_policy), GFP_KERNEL);
	if (!binder_vip_policy)
		return -ENOMEM;
	binder_vip_policy->info = kzalloc(sizeof(struct binder_vip_policy_info), GFP_KERNEL);
	if (!binder_vip_policy->info)
		return -ENOMEM;
	binder_vip_set_tr_code_default(binder_vip_policy->info);
	binder_vip_policy->info->tr_code_size = 1;
	binder_vip_policy->info->tr_code = kzalloc(binder_vip_policy->info->tr_code_size * sizeof(uint32_t), GFP_KERNEL);
	if (!binder_vip_policy->info->tr_code)
		return -ENOMEM;

	binder_vip_policy->info->tr_code[0] = 1;

	binder_vip_policy->info->index = 1;
	strncpy(binder_vip_policy->info->interface_token, "android.gui.IWindowInfosListener", strlen("android.gui.IWindowInfosListener"));
	strncpy(binder_vip_policy->info->server_proc_name, "system_server", strlen("system_server"));
	binder_vip_policy->info->policy_type = e_vip_policy_type_all;
	binder_vip_policy->info->handle = -1;
	INIT_LIST_HEAD(&binder_vip_policy->vip_entry);
	list_add(&binder_vip_policy->vip_entry, &vip_policy_summary.vip_white_list[0]);

	binder_vip_policy = kzalloc(sizeof(*binder_vip_policy), GFP_KERNEL);
	if (!binder_vip_policy)
		return -ENOMEM;
	binder_vip_policy->info = kzalloc(sizeof(struct binder_vip_policy_info), GFP_KERNEL);
	if (!binder_vip_policy->info)
		return -ENOMEM;
	binder_vip_set_tr_code_default(binder_vip_policy->info);
	binder_vip_policy->info->tr_code_size = 1;
	binder_vip_policy->info->tr_code = kzalloc(binder_vip_policy->info->tr_code_size * sizeof(uint32_t), GFP_KERNEL);
	if (!binder_vip_policy->info->tr_code)
		return -ENOMEM;

	binder_vip_policy->info->tr_code[0] = 1;

	binder_vip_policy->info->index = 2;
	strncpy(binder_vip_policy->info->interface_token, "android.gui.IWindowInfosPublisher", strlen("android.gui.IWindowInfosPublisher"));
	strncpy(binder_vip_policy->info->server_proc_name, "surfaceflinger", strlen("surfaceflinger"));
	binder_vip_policy->info->policy_type = e_vip_policy_type_all;
	binder_vip_policy->info->handle = -1;
	INIT_LIST_HEAD(&binder_vip_policy->vip_entry);
	list_add(&binder_vip_policy->vip_entry, &vip_policy_summary.vip_white_list[0]);


	return ret;
}

int binder_vip_policy_init_app_switch(void)
{
	int ret = 0;

	struct binder_vip_policy *binder_vip_policy = kzalloc(sizeof(*binder_vip_policy), GFP_KERNEL);
	if (!binder_vip_policy)
		return -ENOMEM;
	binder_vip_policy->info = kzalloc(sizeof(struct binder_vip_policy_info), GFP_KERNEL);
	if (!binder_vip_policy->info)
		return -ENOMEM;
	binder_vip_set_tr_code_default(binder_vip_policy->info);
	binder_vip_policy->info->tr_code_size = 1;
	binder_vip_policy->info->tr_code = kzalloc(binder_vip_policy->info->tr_code_size * sizeof(uint32_t), GFP_KERNEL);
	if (!binder_vip_policy->info->tr_code)
		return -ENOMEM;

	binder_vip_policy->info->tr_code[0] = 25;

	binder_vip_policy->info->index = 0;
	strncpy(binder_vip_policy->info->interface_token, "android.app.IActivityManager", strlen("android.app.IActivityManager"));
	binder_vip_policy->info->policy_type = e_vip_policy_type_flag_mask;
	binder_vip_policy->info->handle = -1;
	INIT_LIST_HEAD(&binder_vip_policy->vip_entry);
	list_add(&binder_vip_policy->vip_entry, &vip_policy_summary.vip_white_list[1]);

	binder_vip_policy = kzalloc(sizeof(*binder_vip_policy), GFP_KERNEL);
	if (!binder_vip_policy)
		return -ENOMEM;
	binder_vip_policy->info = kzalloc(sizeof(struct binder_vip_policy_info), GFP_KERNEL);
	if (!binder_vip_policy->info)
		return -ENOMEM;
	binder_vip_set_tr_code_default(binder_vip_policy->info);
	binder_vip_policy->info->tr_code_size = 2;
	binder_vip_policy->info->tr_code = kzalloc(binder_vip_policy->info->tr_code_size * sizeof(uint32_t), GFP_KERNEL);
	if (!binder_vip_policy->info->tr_code)
		return -ENOMEM;

	binder_vip_policy->info->tr_code[0] = 1;
	binder_vip_policy->info->tr_code[1] = 2;


	binder_vip_policy->info->index = 1;
	strncpy(binder_vip_policy->info->interface_token, "android.window.ITaskOrganizer", strlen("android.window.ITaskOrganizer"));
	binder_vip_policy->info->tr_code[0] = 1;
	binder_vip_policy->info->tr_code[1] = 2;
	/*strncpy(binder_vip_policy->info->server_proc_name, "system_server", strlen("system_server"));*/
	binder_vip_policy->info->policy_type = e_vip_policy_type_all;
	binder_vip_policy->info->handle = -1;
	INIT_LIST_HEAD(&binder_vip_policy->vip_entry);
	list_add(&binder_vip_policy->vip_entry, &vip_policy_summary.vip_white_list[1]);

	binder_vip_policy = kzalloc(sizeof(*binder_vip_policy), GFP_KERNEL);
	if (!binder_vip_policy)
		return -ENOMEM;
	binder_vip_policy->info = kzalloc(sizeof(struct binder_vip_policy_info), GFP_KERNEL);
	if (!binder_vip_policy->info)
		return -ENOMEM;
	binder_vip_set_tr_code_default(binder_vip_policy->info);
	binder_vip_policy->info->tr_code_size = 2;
	binder_vip_policy->info->tr_code = kzalloc(binder_vip_policy->info->tr_code_size * sizeof(uint32_t), GFP_KERNEL);
	if (!binder_vip_policy->info->tr_code)
		return -ENOMEM;

	binder_vip_policy->info->tr_code[0] = 4;
	binder_vip_policy->info->tr_code[1] = 9;

	binder_vip_policy->info->index = 2;
	strncpy(binder_vip_policy->info->interface_token, "android.view.IRemoteAnimationRunner", strlen("android.view.IRemoteAnimationRunner"));
	binder_vip_policy->info->tr_code[0] = 4;
	binder_vip_policy->info->tr_code[1] = 9;
	/*strncpy(binder_vip_policy->info->server_proc_name, "surfaceflinger", strlen("system_server"));*/
	binder_vip_policy->info->policy_type = e_vip_policy_type_all;
	binder_vip_policy->info->handle = -1;
	INIT_LIST_HEAD(&binder_vip_policy->vip_entry);
	list_add(&binder_vip_policy->vip_entry, &vip_policy_summary.vip_white_list[1]);


	return ret;
}

void binder_vip_set_vip_server(struct binder_proc *proc)
{
	struct binder_vip_policy *binder_vip_policy;
	struct oplus_task_struct *ots = NULL;
	struct list_head *vip_white_list;
	int  cur_vip_policy_type_group;

	binder_inner_proc_lock(proc);
	if (IS_ERR_OR_NULL(proc->tsk)) {
		binder_inner_proc_unlock(proc);
		return;
	}
	ots = get_oplus_task_struct(proc->tsk);
	binder_inner_proc_unlock(proc);

	if (IS_ERR_OR_NULL(ots)) {
		return;
	}
	read_lock(&binder_vip_policy_group_rwlock);
	cur_vip_policy_type_group = vip_policy_summary.cur_vip_policy_type_group;
	vip_white_list = &vip_policy_summary.vip_white_list[cur_vip_policy_type_group];

	binder_inner_proc_lock(proc);
	list_for_each_entry(binder_vip_policy, vip_white_list, vip_entry) {
		if (!binder_vip_policy->info) {
			continue;
		}
		if (IS_ERR_OR_NULL(proc->tsk)) {
			break;
		}
		if (strncmp(binder_vip_policy->info->server_proc_name, proc->tsk->comm, strlen(proc->tsk->comm)) == 0) {
			ots->vip_save_threads = 1;/*keep 1, saved threads use last thread in max threads*/
			binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d %d:%d BR_SPAWN_LOOPER %s %d %d\n", __func__, __LINE__,
					proc->pid, task_uid(proc->tsk).val ,
			proc->tsk->comm, ots->vip_thread_policy_max_threads, ots->vip_save_threads);
			break;
		}
	}
	binder_inner_proc_unlock(proc);
	read_unlock(&binder_vip_policy_group_rwlock);

	binder_inner_proc_lock(proc);
	if (IS_ERR_OR_NULL(proc->tsk)) {
		binder_inner_proc_unlock(proc);
		return;
	}
	if (task_uid(proc->tsk).val > MIN_USERAPP_UID && task_uid(proc->tsk).val < MAX_OTHER_USERAPP_UID && proc->max_threads > 4) {
        	binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d %d:%d BR_SPAWN_LOOPER %s %d %d\n", __func__, __LINE__,
				proc->pid, task_uid(proc->tsk).val ,
				proc->tsk->comm, ots->vip_thread_policy_max_threads, ots->vip_save_threads);
		ots->vip_save_threads = 1;
	}
	/*this is just for test vip max threads*/
	if (strncmp("mple.sfhangtest", proc->tsk->comm, strlen(proc->tsk->comm)) == 0) {
		if (vip_binder_max_threads)
			ots->vip_thread_policy_max_threads = vip_binder_max_threads;
		else
			ots->vip_thread_policy_max_threads = 1;
		ots->vip_save_threads = 1;

		binder_debug(BINDER_DEBUG_VIP_THREAD, "%s %d %d:%d BR_SPAWN_LOOPER %s %d %d\n", __func__, __LINE__,
				proc->pid, task_uid(proc->tsk).val ,
				proc->tsk->comm, ots->vip_thread_policy_max_threads, ots->vip_save_threads);
	}
	binder_inner_proc_unlock(proc);
}

void binder_vip_clear_vip_token_group_ilocked(int group_id)
{
        struct binder_vip_policy *binder_vip_policy, *temp;
        struct list_head *vip_white_list = &vip_policy_summary.vip_white_list[group_id];
	list_for_each_entry_safe(binder_vip_policy, temp, vip_white_list, vip_entry) {
		kfree(binder_vip_policy->info->tr_code);
		kfree(binder_vip_policy->info);
		list_del(&binder_vip_policy->vip_entry);
		kfree(binder_vip_policy);
	}
        INIT_LIST_HEAD(vip_white_list);
}
/*file node for : vip policy group*/
int binder_vip_update_vip_token_group_ilocked(int group_id,  struct vip_token_group *in_group)
{
	int ret = 0;
        int i = 0;
	int j = 0;
	struct list_head *vip_white_list = &vip_policy_summary.vip_white_list[group_id];

        binder_debug(BINDER_DEBUG_VIP_THREAD,
        		     "%s %d server_proc_name %d\n", __func__, __LINE__, in_group->token_size);
        binder_vip_clear_vip_token_group_ilocked(group_id);
        for (i = 0; i < in_group->token_size; i++) {
		struct vip_token vip_token;
		uint32_t *tr_code_ptr;

                struct binder_vip_policy *binder_vip_policy = kzalloc(sizeof(*binder_vip_policy), GFP_KERNEL);
                if (!binder_vip_policy) {
                        ret = -ENOMEM;
                        goto err;
                }
                INIT_LIST_HEAD(&binder_vip_policy->vip_entry);
                binder_vip_policy->info = kzalloc(sizeof(struct binder_vip_policy_info), GFP_KERNEL);
                if (!binder_vip_policy->info) {
                        kfree(binder_vip_policy);
                        ret = -ENOMEM;
                        goto err;
                }
                binder_vip_set_tr_code_default(binder_vip_policy->info);


                if (copy_from_user(&vip_token, (void __user *)(in_group->tokens_head+i), sizeof(vip_token))) {
                        kfree(binder_vip_policy->info);
                        kfree(binder_vip_policy);
                        ret = -EINVAL;
                        goto err;
                }
                binder_debug(BINDER_DEBUG_VIP_THREAD,
        		     "%s %d %s %s %s\n", __func__, __LINE__, vip_token.interface_token, vip_token.server_proc_name, vip_token.client_proc_name);
                binder_vip_policy->info->index = i;
                snprintf(binder_vip_policy->info->interface_token, sizeof(binder_vip_policy->info->interface_token), "%s", vip_token.interface_token);
                snprintf(binder_vip_policy->info->server_proc_name, sizeof(binder_vip_policy->info->server_proc_name), "%s", vip_token.server_proc_name);
                snprintf(binder_vip_policy->info->client_proc_name, sizeof(binder_vip_policy->info->client_proc_name), "%s", vip_token.client_proc_name);

		if (vip_token.tr_code_size) {
			tr_code_ptr = kzalloc(vip_token.tr_code_size * sizeof(uint32_t), GFP_KERNEL);
			if (!tr_code_ptr) {
				kfree(binder_vip_policy->info);
				kfree(binder_vip_policy);
				ret = -EINVAL;
				goto err;
			}
			if (copy_from_user(tr_code_ptr, (void __user *)(vip_token.tr_codes), sizeof(uint32_t) * vip_token.tr_code_size)) {
	                                kfree(binder_vip_policy->info);
	                                kfree(binder_vip_policy);
					kfree(tr_code_ptr);
	                                ret = -EINVAL;
	                                goto err;
			}
			binder_vip_policy->info->tr_code = tr_code_ptr;
			binder_vip_policy->info->tr_code_size = vip_token.tr_code_size;
		}
		binder_debug(BINDER_DEBUG_VIP_THREAD,
        		     "%s %d %d\n", __func__, __LINE__, binder_vip_policy->info->tr_code_size);
		for(j = 0; j < binder_vip_policy->info->tr_code_size; j++)
			binder_debug(BINDER_DEBUG_VIP_THREAD,
        		     "%s %d %d\n", __func__, __LINE__, binder_vip_policy->info->tr_code[j]);
                binder_vip_policy->info->policy_type = vip_token.type;

                binder_vip_policy->info->handle = -1;/*will be remove*/
                list_add(&binder_vip_policy->vip_entry, vip_white_list);
	}
err:
	return ret;
}


void binder_vip_spawn_loop_thread(struct binder_proc *proc, struct binder_thread *thread, bool *skip)
{
	struct oplus_task_struct *ots = get_oplus_task_struct(proc->tsk);
	*skip = false;

	if (((proc->requested_threads == 0 &&
	    list_empty(&thread->proc->waiting_threads) &&
	    proc->requested_threads_started >= proc->max_threads &&
	    proc->requested_threads_started < proc->max_threads + ots->vip_thread_policy_max_threads) &&
	    (thread->looper & (BINDER_LOOPER_STATE_REGISTERED |
	     BINDER_LOOPER_STATE_ENTERED))) &&
	     binder_has_work_taxi_thread_ilocked(thread)) {
		*skip = true;

		binder_debug(BINDER_DEBUG_VIP_THREAD,
				     "%s %d %d:%d BR_SPAWN_LOOPER %s %d\n", __func__, __LINE__,
				     proc->pid, thread->pid, proc->tsk->comm, ots->vip_thread_policy_max_threads);
	}
	PRTRACE("proc=%s info(%d:%d)", proc->tsk->comm, ots->vip_save_threads, ots->vip_thread_policy_max_threads);
}

void binder_vip_thread_bc_register_looper(struct binder_proc *proc, struct binder_thread *thread)
{
	struct oplus_task_struct *ots = get_oplus_task_struct(proc->tsk);
        /*TAXI THREAD: check if the last threads, if it is. save it*/
	if (proc->max_threads < proc->requested_threads_started + ots->vip_save_threads) {/*saved thread from last threads in max threads*/
		thread->looper |= BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED;
		binder_debug(BINDER_DEBUG_VIP_THREAD,
			"%s %d new vip thread vip while save thread existed  debuginfo: thread[%d:%d:%d:%d] proc[%d:%s] \n",
			__func__, __LINE__,
			proc->max_threads, proc->requested_threads_started,
			ots->vip_save_threads, ots->vip_thread_policy_max_threads,
			proc->tsk->pid, proc->tsk->comm);
	}
        if (proc->requested_threads_started >= proc->max_threads &&
	    proc->requested_threads_started < proc->max_threads + ots->vip_thread_policy_max_threads) {
                thread->looper |= BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED;

                binder_debug(BINDER_DEBUG_VIP_THREAD,
			"%s %d new vip thread vip while save thread existed  debuginfo: thread[%d:%d:%d:%d] proc[%d:%s] \n",
			__func__, __LINE__,
			proc->max_threads, proc->requested_threads_started,
			ots->vip_save_threads, ots->vip_thread_policy_max_threads,
			proc->tsk->pid, proc->tsk->comm);
        }

	PRTRACE("proc=%s info(%d:%d)", proc->tsk->comm, ots->vip_save_threads, ots->vip_thread_policy_max_threads);
}

void binder_vip_thread_bc_exit_looper(struct binder_proc *proc, struct binder_thread *thread)
{
	struct oplus_task_struct *ots = get_oplus_task_struct(proc->tsk);

        if (!!(thread->looper & BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED)) {
                thread->looper &= ~BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED;
        }
	PRTRACE("proc=%s info(%d:%d)", proc->tsk->comm, ots->vip_save_threads, ots->vip_thread_policy_max_threads);

        binder_debug(BINDER_DEBUG_VIP_THREAD,
             "%s %d %d:%d BC_EXIT_LOOPER %s %d\n", __func__, __LINE__,
             proc->pid, thread->pid, proc->tsk->comm, ots->vip_thread_policy_max_threads);
}

static int binder_vip_policy_add_white_node(void)
{
	int ret = 0;
#ifdef BINDER_VIP_INIT_DEFAULT_WHITE_LIST
	ret = binder_vip_policy_init_default();
#endif
	return ret;
}

static void binder_vip_trace_todo_list(struct binder_transaction *t, struct binder_proc *target_proc)
{
	struct binder_work *w = NULL;
	struct binder_proc *proc = NULL;
	struct binder_node *node = t->buffer->target_node;
	/*bool vip_request = !!(t->flags & TF_TAXI_THREAD_WAY);*/
	bool oneway = !!(t->flags & TF_ONE_WAY);
	unsigned int async_todo_size = 0;
	if (!node || trace_debug_enable == false || !oneway)
		return;
	proc = node->proc;

	PRTRACE_CUSTOM_INT(target_proc->tsk->pid, "VIP_TODO_%d|%d", node->debug_id, async_todo_size);

	list_for_each_entry(w, &node->async_todo, entry) {/*taxi thread: select taxi work*/
		async_todo_size++;
	}

	PRTRACE_CUSTOM_INT(target_proc->tsk->pid, "VIP_TODO_%d|%d", node->debug_id, async_todo_size);
}

/*TODO: vh define&register start*/
void android_vh_binder_proc_vip_transaction_handler(void *unused,
						struct binder_proc *proc, struct binder_transaction *t,
						struct binder_thread **binder_th, int node_debug_id, bool pending_async, bool sync, bool *skip)
{
	bool vip_request = !!(t->flags & TF_TAXI_THREAD_WAY);


	if (binder_vip_policy_enable == false) {/*disable vip policy*/
		return;
	}

	binder_vip_trace_todo_list(t, proc);

	if (vip_request) /*vip request ,just return use orignial logic*/
		goto out;
	if (*skip) { /**skip is true: it is from obthread logic,and choose the thread*/
		/*vip policy need recheck if normal client rpc get the vip thread*/
		if (*binder_th) {
			*binder_th = binder_proc_transaction_vip_thread_selected(t, proc, *binder_th, pending_async);
		}
	} else {
		if (*binder_th == NULL && !pending_async) {
			*skip = true;
			*binder_th = binder_select_thread_ilocked(proc);
			if (*binder_th)
				*binder_th = binder_proc_transaction_vip_thread_selected(t, proc, *binder_th, pending_async);
		}
	}
out:
	PRTRACE("thread=0x%x proc_name=%s skip=%d vip_request=%d", binder_th, proc->tsk->comm,  *skip, vip_request);
        binder_debug(BINDER_DEBUG_VIP_THREAD,
			"%s %d client normal rpc in vip server.debuginfo(proc[%s:%d] tr[%u:%d]  thread[%d:%d] pending_async %d)\n",
			__func__, __LINE__,
			proc->tsk->comm, proc->tsk->pid, t->code, t->flags,
			(*binder_th)?(*binder_th)->pid:0, (*binder_th)?(*binder_th)->looper:0, pending_async);
        return;
}

void android_vh_binder_select_worklist_on_vip_thread_handler(void *unused,
								struct list_head **list,
								struct binder_thread *thread,
								struct binder_proc *proc,
								int wait_for_proc_work,
								bool *skip)
{
	bool found = false;
	bool no_work = false;
	bool vip_thread = !!(thread->looper & BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED);

	if (binder_vip_policy_enable == false) {/*disable vip policy*/
		return;
	}

	trace_binder_select_worklist_on_vip_thread_handler(thread, proc, list, &no_work);

	if (vip_thread) {
		*skip = true;
		found = binder_look_for_proc_work_on_vip_thread(list, proc, thread, wait_for_proc_work);
		if (!found) {
			no_work = true;
			*list = NULL;
		}
	}

	trace_binder_select_worklist_on_vip_thread_handler(thread, proc, list, &no_work);

	return;
}

void android_vh_binder_ioctl_end_handler(void *unused,
						struct task_struct *tsk,
						unsigned int cmd, unsigned long arg,
				                struct binder_thread *thread,
				                struct binder_proc *proc,
				                int *ret)
{
	void __user *ubuf = (void __user *)arg;

	if (binder_vip_policy_enable == false) {/*disable vip policy*/
		return;
	}

	switch (cmd) {
	case BINDER_SET_MAX_THREADS: {
		binder_vip_set_vip_server(proc);
        break;
	}
	case BINDER_ENABLE_VIP_THREAD_POLICY: {
        	uint32_t enable = 0;
		struct oplus_task_struct *ots = get_oplus_task_struct(proc->tsk);
        	if (copy_from_user(&enable, ubuf, sizeof(enable))) {
        		*ret = -EFAULT;
        		return;
        	}
        	binder_inner_proc_lock(proc);
		ots->vip_thread_policy_max_threads = (int)enable;
        	binder_inner_proc_unlock(proc);
	break;
	}
        default:
        	{};
        }
}

void android_vh_binder_vip_looper_state_registerered_handler(void *unused,
				                struct binder_thread *thread,
                                                struct binder_proc *proc)
{
	if (binder_vip_policy_enable == false) {/*disable vip policy*/
		return;
	}

	trace_binder_vip_looper_state_registerered_handler(thread, proc);
        binder_vip_thread_bc_register_looper(proc, thread);
	trace_binder_vip_looper_state_registerered_handler(thread, proc);
}

void android_vh_binder_vip_looper_state_exited_handler(void *unused,
				                struct binder_thread *thread,
                                                struct binder_proc *proc)
{
	if (binder_vip_policy_enable == false) {/*disable vip policy*/
		return;
	}

	trace_binder_vip_looper_state_exited_handler(thread, proc);
        binder_vip_thread_bc_exit_looper(proc, thread);
	trace_binder_vip_looper_state_exited_handler(thread, proc);
}

void android_vh_binder_vip_spawn_new_thread_handler(void *unused,
				                struct binder_thread *thread,
                                                struct binder_proc *proc,
                                                bool *skip)
{
	if (binder_vip_policy_enable == false) {/*disable vip policy*/
		return;
	}

	trace_binder_vip_spawn_new_thread_handler(thread, proc, skip);
        binder_vip_spawn_loop_thread(proc, thread, skip);
	trace_binder_vip_spawn_new_thread_handler(thread, proc, skip);
}

void android_vh_binder_vip_has_work_ilocked_handler(void *unused,
				                struct binder_thread *thread,
                                                bool do_proc_work,
                                                bool *has_work)
{
	int skip = 0;
	if (binder_vip_policy_enable == false) {/*disable vip policy*/
		return;
	}
	if (*has_work == false)
		return;
	if (!!(thread->looper & BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED) == false) /*normal thread, direct return*/
		return;
	if (thread->looper & BINDER_LOOPER_STATE_POLL)
		return;
	trace_binder_vip_has_work_ilocked_handler(thread, do_proc_work, has_work, &skip);
	*has_work = binder_has_vip_work_ilocked(thread, do_proc_work, &skip);
	trace_binder_vip_has_work_ilocked_handler(thread, do_proc_work, has_work, &skip);

	PRTRACE("has_work=0x%x skip=%d vip_thread=%d", *has_work,  skip,
		!!(thread->looper & BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED));
}

void android_vh_binder_vip_trans_handler(void *unused,
			                struct binder_proc *target_proc, struct binder_proc *proc,
	                                struct binder_thread *thread, struct binder_transaction_data *tr)
{
	if (binder_vip_policy_enable == false) {/*disable vip policy*/
		return;
	}

	trace_binder_vip_trans_handler(target_proc, proc, tr);
        binder_taxi_thread_trans_handler(target_proc, proc, thread, tr);
	trace_binder_vip_trans_handler(target_proc, proc, tr);

	PRTRACE("target=%s src=%s code=%u flags=0x%0x vip_request=%d",
		target_proc->tsk->comm, proc->tsk->comm, tr->code, tr->flags, !!(tr->flags & TF_TAXI_THREAD_WAY));
}

void android_vh_binder_vip_wakeup_ilocked_handler(void *unused, struct task_struct *task, bool sync, struct binder_proc *proc)
{
	struct binder_thread *thread = NULL;
	struct oplus_task_struct *ots = NULL;
	struct rb_node *n;
	bool is_vip_server = false;
	bool task_is_vip = false;

	if (binder_vip_policy_enable == false) {/*disable vip policy*/
		return;
	}

	if (IS_ERR_OR_NULL(proc->tsk)) {
		return;
	}
	ots = get_oplus_task_struct(proc->tsk);
	if (IS_ERR_OR_NULL(ots)) {
		return;
	}
	is_vip_server = ots->vip_save_threads >= 1 ? true : false;
	if (!is_vip_server) {
		return;
	}
	if (proc->requested_threads_started < proc->max_threads) {/*vip thread have not been spawned*/
		return;
	}

	/*check the current thread is not the vip thread*/
	for (n = rb_first(&proc->threads); n != NULL; n = rb_next(n)) {
		thread = rb_entry(n, struct binder_thread, rb_node);
		if (thread->looper & BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED) {/*vip thread*/
			if (thread->task == task) {
				task_is_vip = true;
				break;
			}
		} else if (thread->task == task) {
			task_is_vip = false;
			break;
		}
	}

	if (!task_is_vip) {
		return;
	}
	/*if current thread is vip, need wakeup one normal thread*/
	thread = binder_select_thread_ilocked(proc);
	if (thread) {
		if (sync)
			wake_up_interruptible_sync(&thread->wait);
		else
			wake_up_interruptible(&thread->wait);
		return;
	}

	/*if there are no normal thread in waiting , wakeup poll thread, refence binder_wakeup_poll_threads_ilocked*/
	for (n = rb_first(&proc->threads); n != NULL; n = rb_next(n)) {
		thread = rb_entry(n, struct binder_thread, rb_node);
		if (thread->looper & BINDER_LOOPER_STATE_POLL &&
		    binder_available_for_proc_work_ilocked(thread)) {
			if (sync)
				wake_up_interruptible_sync(&thread->wait);
			else
				wake_up_interruptible(&thread->wait);
		}
	}
}

void android_vh_binder_vip_wait_for_work_handler(void *unused,
  			bool do_proc_work, struct binder_thread *thread, struct binder_proc *proc)
{
	if (binder_vip_policy_enable == false) {/*disable vip policy*/
		return;
	}
	if (!!!(thread->looper & BINDER_LOOPER_TAXI_THREAD_STATE_REGISTERED)) {/*normal thread, just return*/
		return;
	}
	/*MOVE VIP THREAD TO LIST TAIL, BECAUSE VIP THREAD SHOULD BE LAST BE CHOOSED IN WAITTING THREAD*/
	if(do_proc_work) {
		list_del_init(&thread->waiting_thread_node);
		list_add_tail(&thread->waiting_thread_node,
					 &proc->waiting_threads);
	}
}

void register_binder_vip_policy_vendor_hooks(void)
{
	/*reusing current vendor hook list*/
	/*reusing current vendor hook in func binder_proc_transaction*/
        register_trace_android_vh_binder_proc_transaction_entry(android_vh_binder_proc_vip_transaction_handler, NULL);
	/*reuseing current vendor hook in func binder_thread_write cmd: BC_REGISTER_LOOPER*/
        register_trace_android_vh_binder_looper_state_registered(android_vh_binder_vip_looper_state_registerered_handler, NULL);
	/*reuseing current vendor hook in func binder_transaction */
        register_trace_android_vh_binder_trans(android_vh_binder_vip_trans_handler, NULL);

	/*register_trace_android_vh_binder_thread_read(android_vh_binder_select_worklist_on_vip_thread_handler, NULL);*/
	/*register_trace_android_vh_binder_vip_select_worklist(android_vh_binder_select_worklist_on_vip_thread_handler, NULL);*/
	/*update current vh param, and change some logic in binder.c*/
	register_trace_android_vh_binder_has_special_work_ilocked(android_vh_binder_vip_has_work_ilocked_handler, NULL);
	/*register_trace_android_vh_binder_vip_has_work_ilocked(android_vh_binder_vip_has_work_ilocked_handler, NULL);*/
#define REQUEST_NEW_VH_HOOK
#ifdef REQUEST_NEW_VH_HOOK
	/*TODO: need request new vendor hook: it is for dynamic vip thread (>=2) in func binder_thread_read */
        register_trace_android_vh_binder_spawn_new_thread(android_vh_binder_vip_spawn_new_thread_handler, NULL);

	/*TODO: new vendor hook list shoulbe be requested in func binder_ioctl*/
        register_trace_android_vh_binder_ioctl_end(android_vh_binder_ioctl_end_handler, NULL);
	/*TODO: need request new vendor hook:it maybe can removed . in func binder_thread_write cmd: BC_EXIT_LOOPER*/
        register_trace_android_vh_binder_looper_exited(android_vh_binder_vip_looper_state_exited_handler, NULL);

	register_trace_android_vh_binder_select_special_worklist(android_vh_binder_select_worklist_on_vip_thread_handler, NULL);

	register_trace_android_vh_binder_wakeup_ilocked(android_vh_binder_vip_wakeup_ilocked_handler, NULL);
	register_trace_android_vh_binder_wait_for_work(android_vh_binder_vip_wait_for_work_handler, NULL);
#endif
}
/*vh codes end*/

static int __init binder_vip_policy_init(void)
{
        int ret = 0;

        int i = 0;

        for (i = 0; i < MAX_BINDER_VIP_WHITE_LIST_CNT; i++)
		INIT_LIST_HEAD(&vip_policy_summary.vip_white_list[i]);
        ret = init_vipbinder_device("vip_binder");

        binder_vip_policy_add_white_node();
        binder_vip_debugfs_init();
        oplus_binder_vip_sysfs_init();
        rwlock_init(&binder_vip_policy_group_rwlock);
	rwlock_init(&binder_vip_policy_group_copy_rwlock);
	register_binder_vip_policy_vendor_hooks();
        return ret;
}

static void __exit binder_vip_policy_deinit(void)
{
	int i = 0;
	for (i = 0; i < MAX_BINDER_VIP_WHITE_LIST_CNT; i++) {
		write_lock(&binder_vip_policy_group_rwlock);
		binder_vip_clear_vip_token_group_ilocked(i);
		write_unlock(&binder_vip_policy_group_rwlock);
	}
	oplus_binder_vip_sysfs_deinit();
}

module_exit(binder_vip_policy_deinit);
device_initcall(binder_vip_policy_init);

MODULE_DESCRIPTION("Oplus VIP BINDER");
MODULE_LICENSE("GPL v2");
