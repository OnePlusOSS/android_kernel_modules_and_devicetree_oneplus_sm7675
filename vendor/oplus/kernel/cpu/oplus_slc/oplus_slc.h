/* SPDX-License-Identifier: GPL-2.0-only
 *
 * oplus_slc.h
 *
 * header file of oplus_slc module
 *
 * Copyright (c) 2023 Oplus. All rights reserved.
 *
 */

#ifndef _OPLUS_SLC_H
#define _OPLUS_SLC_H

#define TARGET_DEFAULT 0
#define SLC_MAX_SIZE 10

struct proc_dir_entry *oplus_slc_dir;

extern void oplus_slc_cdwb_switch(bool disable);

#endif /* _OPLUS_SLC_H */
