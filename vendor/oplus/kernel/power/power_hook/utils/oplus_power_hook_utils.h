#ifndef _OPLUS_POWER_HOOK_UTILS_H
#define _OPLUS_POWER_HOOK_UTILS_H
#include <linux/version.h>
#include <linux/kprobes.h>
#include "../alarmtimer_hook/oplus_alarmtimer_hook.h"

typedef enum alarmtimer_restart (*timerfd_alarmproc_t)(struct alarm *alarm, ktime_t now);

unsigned long generic_kallsyms_lookup_name(const char *name);
void power_hook_util_init(void);

bool is_file_exist(const char * dir_path);
struct proc_dir_entry *get_oplus_lpm_dir(void);

int enable_kprobe_func(struct kprobe *kp);
int disable_kprobe_func(struct kprobe *kp);

void find_and_register_tracepoint_probe(struct tracepoints_table *tp_table, unsigned int array_size);
void unregister_tracepoint_probe(struct tracepoints_table *tp_table, unsigned int array_size);

bool is_timerfd_alarmproc_function(timerfd_alarmproc_t func);

struct proc_dir_entry *pde_subdir_find_func(struct proc_dir_entry *dir, const char *name, unsigned int len);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
struct proc_dir_entry *get_proc_root(void);
#endif
#endif /* _OPLUS_POWER_HOOK_UTILS_H */
