// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024-2030 Oplus. All rights reserved.
 */

#ifndef _LOWMEM_HELPER_H
#define _LOWMEM_HELPER_H
#include <linux/shrinker.h>

void lowmem_report(void *ignore, struct shrinker *shrinker, long *freeable);
void init_mem_confg(void);

#endif /* _LOWMEM_HELPER_H */
