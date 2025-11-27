// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Oplus. All rights reserved.
 */

#include <linux/sched.h>
#ifdef CONFIG_HMBIRD_SCHED
#include <linux/sched/ext.h>
#endif
#include "sa_common.h"
#include "sa_hmbird.h"

#ifdef CONFIG_HMBIRD_SCHED
struct hmbird_ops_t *hmbird_sched_ops = NULL;
void register_hmbird_sched_ops(struct hmbird_ops_t *ops)
{
	if (!ops)
		return;
	if (cmpxchg(&hmbird_sched_ops, NULL, ops))
		pr_warn("hmbird_sched_ops has already been registered!\n");
}
EXPORT_SYMBOL_GPL(register_hmbird_sched_ops);

bool test_task_is_hmbird(struct task_struct *p)
{
	if (p && hmbird_sched_ops && hmbird_sched_ops->task_is_scx
			&& hmbird_sched_ops->task_is_scx(p))
		return true;
	else
		return false;
}
EXPORT_SYMBOL(test_task_is_hmbird);

static void __set_ux_task_dsq_id(struct task_struct *task,
	int ux_state, int sub_ux_state, unsigned long new_dsq, int set_dsq)
{
	unsigned long old_dsq = 0;
	bool truly_set = false;

	if (!task) {
		return;
	}
	if ((task->prio >= 0) && (task->prio < MAX_RT_PRIO)) {
		goto end;
	}

	old_dsq = sched_get_dsq_id(task);
	switch(set_dsq) {
	case SET_DSQ_WHEN_STATIC_UX:
		if (old_dsq == 0 || new_dsq < old_dsq) {
			truly_set = true;
			sched_set_dsq_id(task, new_dsq);
			sched_set_dsq_sync_ux(task, DSQ_SYNC_STATIC_UX);
		}
		break;
	case SET_DSQ_WHEN_INHERIT_UX:
		if (old_dsq == 0 || new_dsq < old_dsq) {
			truly_set = true;
			sched_set_dsq_id(task, new_dsq);
			sched_set_dsq_sync_ux(task, DSQ_SYNC_INHERIT_UX);
		}
		break;
	case UNSET_DSQ_WHEN_UX:
		if (sched_get_dsq_sync_ux(task)) {
			truly_set = true;
			sched_set_dsq_id(task, 0);
			sched_set_dsq_sync_ux(task, 0);
		}
		break;
	default:
		break;
	}

end:
	if (unlikely(global_debug_enabled & DEBUG_SET_DSQ_ID)) {
		pr_info("hmbird_set: set_dsq = %d truly_set = %d ux_state = 0x%x sub_ux_state = 0x%x prio = %d \
			current(pid = %d comm = %s) set(pid = %d tgid = %d comm = %s) old_dsq = %lu new_dsq = %lu \
			final_dsq = %lu final_sp = %lu dsq_sync_ux = %d\n",
			set_dsq, truly_set, ux_state, sub_ux_state, task->prio, current->pid, current->comm,
			task->pid, task->tgid, task->comm, old_dsq, new_dsq, sched_get_dsq_id(task),
			sched_get_sched_prop(task), sched_get_dsq_sync_ux(task));
	}
}

/* if this task set as ux, we promise it's low-latency in hmbird-sched */
void set_ux_task_dsq_id(struct task_struct *task)
{
	int ux_state = -1;
	int sub_ux_state = -1;
	bool static_ux, inherit_ux;
	struct oplus_task_struct *ots = NULL;

	if (!task) {
		return;
	}

	get_task_struct(task);

	ots = get_oplus_task_struct(task);
	if (!IS_ERR_OR_NULL(ots)) {
		ux_state = ots->ux_state;
		sub_ux_state = ots->sub_ux_state;
	}
	static_ux = !!oplus_get_static_ux_state(task);
	inherit_ux = !!oplus_get_inherited_ux_state(task);

	/*
	* inherit_ux should be checked before static_ux,
	* because ux state maybe both static and inherit,
	* for example, ux_state = 0x4, sub_ux_state = 0x10004, inherit_type = 3
	*/
	if (inherit_ux) {
		__set_ux_task_dsq_id(task, ux_state, sub_ux_state,
			SCHED_PROP_DEADLINE_LEVEL4, SET_DSQ_WHEN_INHERIT_UX);
	} else if (static_ux) {
		__set_ux_task_dsq_id(task, ux_state, sub_ux_state,
			SCHED_PROP_DEADLINE_LEVEL4, SET_DSQ_WHEN_STATIC_UX);
	} else {
		__set_ux_task_dsq_id(task, ux_state, sub_ux_state, 0, UNSET_DSQ_WHEN_UX);
	}

	put_task_struct(task);
}

#else
bool test_task_is_hmbird(struct task_struct *p)
{
	return false;
}

void set_ux_task_dsq_id(struct task_struct *task)
{
}
#endif
