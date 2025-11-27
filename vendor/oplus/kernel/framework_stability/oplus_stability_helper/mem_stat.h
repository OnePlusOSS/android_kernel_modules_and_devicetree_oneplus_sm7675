// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024-2030 Oplus. All rights reserved.
 */

#ifndef _MEM_STAT_H
#define _MEM_STAT_H
#include <linux/mm.h>
#include <linux/mmzone.h>

static inline unsigned long sys_freeram(void)
{
	return global_zone_page_state(NR_FREE_PAGES);
}

static inline unsigned long sys_free_cma(void)
{
	return global_zone_page_state(NR_FREE_CMA_PAGES);
}

static inline unsigned long sys_inactive_file(void)
{
	return global_node_page_state(NR_ACTIVE_FILE);
}

static inline unsigned long sys_active_file(void)
{
	return global_node_page_state(NR_INACTIVE_FILE);
}

static inline unsigned long sys_anon_pages(void)
{
	return global_node_page_state(NR_ANON_MAPPED);
}

#endif /* _MEM_STAT_H */
