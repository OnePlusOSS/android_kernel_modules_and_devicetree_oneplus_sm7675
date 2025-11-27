// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024-2030 Oplus. All rights reserved.
 */

#ifndef _LOWMEM_HELPER_H
#define _LOWMEM_HELPER_H

void lowmem_report(void *ignore, int order, gfp_t gfp_flags);
void init_mem_confg(void);

#endif /* _LOWMEM_HELPER_H */
