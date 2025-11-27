#ifndef __UFS_METRICS_H__
#define __UFS_METRICS_H__

#include <linux/fs.h>

void ufs_register_tracepoint_probes(void);
void ufs_unregister_tracepoint_probes(void);
int ufs_metrics_proc_open(struct inode *inode, struct file *file);
#ifdef CONFIG_OPLUS_FEATURE_STORAGE_IOLATENCY_STATS
int ioLatencyStat_proc_open(struct inode *inode, struct file *file);
#endif /* CONFIG_OPLUS_FEATURE_STORAGE_IOLATENCY_STATS */
void ufs_metrics_reset(void);
void ufs_metrics_init(void);

#endif /* __UFS_METRICS_H__ */