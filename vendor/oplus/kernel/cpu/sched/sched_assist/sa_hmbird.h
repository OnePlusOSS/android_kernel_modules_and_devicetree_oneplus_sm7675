/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 Oplus. All rights reserved.
 */


#ifndef _SA_HMBIRD_H_
#define _SA_HMBIRD_H_

struct hmbird_ops_t {
	bool (*task_is_scx)(struct task_struct *p);
};

enum SET_DSQ_WHEN_UX {
	SET_DSQ_WHEN_STATIC_UX,
	SET_DSQ_WHEN_INHERIT_UX,
	UNSET_DSQ_WHEN_UX,
};
void set_ux_task_dsq_id(struct task_struct *task);
bool test_task_is_hmbird(struct task_struct *p);

#endif /* _SA_HMBIRD_H_ */
