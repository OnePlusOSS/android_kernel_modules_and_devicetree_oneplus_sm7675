/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __OSML_H
#define __OSML_H
/* in ged/src/ged_dvfs.c */
extern unsigned long osml_ged_dvfs_get_gpu_cur_freq(void);

extern void osml_init(struct proc_dir_entry *parent_dir);
extern void osml_exit(void);

#endif /* __OSML_H */
