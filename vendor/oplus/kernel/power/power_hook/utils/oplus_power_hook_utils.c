#include <linux/version.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/tracepoint.h>
#include <linux/alarmtimer.h>
#include <linux/ktime.h>
#include <linux/rbtree.h>
#include <linux/proc_fs.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0))
#include <linux/kallsyms.h>
#endif

#include "../alarmtimer_hook/oplus_alarmtimer_hook.h"
#include "oplus_power_hook_utils.h"

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0))
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)))
#include "../../../../../../kernel-5.15/fs/proc/internal.h"
#endif
#else
#include "fs/proc/internal.h"
#endif

extern struct proc_dir_entry *oplus_lpm_proc;

typedef int (*kern_path_t)(const char *name, unsigned int flags, struct path *path);
typedef void (*path_put_t)(const struct path *path);
static kern_path_t kern_path_sym = NULL;
static path_put_t  path_put_sym  = NULL;

typedef int (*enable_kprobe_t)(struct kprobe *kp);
typedef int (*disable_kprobe_t)(struct kprobe *kp);
static enable_kprobe_t   enable_kprobe_sym  = NULL;
static disable_kprobe_t  disable_kprobe_sym = NULL;

//typedef enum alarmtimer_restart (*timerfd_alarmproc_t)(struct alarm *alarm, ktime_t now);
static timerfd_alarmproc_t timerfd_alarmproc_sym = NULL;

static struct tracepoints_table *intrest_tracepoints_table;
static unsigned int tpt_size;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0))
unsigned long generic_kallsyms_lookup_name(const char *name)
{
        struct kprobe kp;
	int *kp_addr;

	kp.symbol_name = name;
	register_kprobe(&kp);
	kp_addr = kp.addr;
	unregister_kprobe(&kp);

	return (unsigned long)kp_addr;
}
#else
static unsigned long (*kallsyms_lookup_name_sym)(const char *name) = NULL;

static int _kallsyms_lookup_kprobe(struct kprobe *p, struct pt_regs *regs)
{
        return 0;
}

/*
 * get symbol of kallsyms_lookup_name() function
 */
static int *get_kallsyms_func(void)
{
        struct kprobe kp_kallsyms_lookup_name;
	int *kallsyms_lookup_name_addr;
        int ret;

	kp_kallsyms_lookup_name.pre_handler = _kallsyms_lookup_kprobe;
	kp_kallsyms_lookup_name.symbol_name = "kallsyms_lookup_name";

	ret = register_kprobe(&kp_kallsyms_lookup_name);
	if(ret < 0) {
		pr_info("[oplus_power_hook] register kallsyms_lookup_name failed with %d\n", ret);
		return 0;
	}

	kallsyms_lookup_name_addr = kp_kallsyms_lookup_name.addr;

	unregister_kprobe(&kp_kallsyms_lookup_name);
	return kallsyms_lookup_name_addr;
}

unsigned long generic_kallsyms_lookup_name(const char *name)
{
        if(!kallsyms_lookup_name_sym) {
                kallsyms_lookup_name_sym = (void *)get_kallsyms_func();
                if(!kallsyms_lookup_name_sym) {
			pr_info("[oplus_power_hook] kallsyms_lookup_name symbol get failed\n");
                        return 0;
		}
        }

        return kallsyms_lookup_name_sym(name);
}
#endif

#else
unsigned long generic_kallsyms_lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}
#endif

static int kern_path_func(const char *name, unsigned int flags, struct path *path)
{
	int ret = 0;

	if(!kern_path_sym) {
		kern_path_sym = (kern_path_t)generic_kallsyms_lookup_name("kern_path");
		if(!kern_path_sym) {
			pr_info("[oplus_power_hook] kern_path symbol get failed\n");
			return -EINVAL;
		}
	}

	ret = kern_path_sym(name, flags, path);

	return ret;
}

static void  path_put_func(const struct path *path)
{

	if(!path_put_sym) {
		path_put_sym = (path_put_t)generic_kallsyms_lookup_name("path_put");
		if(!path_put_sym) {
			pr_info("[oplus_power_hook] path_put symbol get failed\n");
		}
	}

	path_put_sym(path);
}

int enable_kprobe_func(struct kprobe *kp)
{
	int ret = 0;

	if(!enable_kprobe_sym) {
		enable_kprobe_sym = (enable_kprobe_t)generic_kallsyms_lookup_name("enable_kprobe");
		if(!enable_kprobe_sym) {
			pr_info("[oplus_power_hook] enable_kprobe symbol get failed\n");
			return -EINVAL;
		}
	}

	ret = enable_kprobe_sym(kp);

	return ret;
}

int disable_kprobe_func(struct kprobe *kp)
{
	int ret = 0;

	if(!disable_kprobe_sym) {
		disable_kprobe_sym = \
			(disable_kprobe_t)generic_kallsyms_lookup_name("disable_kprobe");
		if(!disable_kprobe_sym) {
			pr_info("[oplus_power_hook] disable_kprobe symbol get failed\n");
			return -EINVAL;
		}
	}

	ret = disable_kprobe_sym(kp);

	return ret;
}

bool is_file_exist(const char * file_path)
{
	struct path path;
	int err;

	if(!file_path) {
		return false;
	}

	err = kern_path_func(file_path, LOOKUP_FOLLOW, &path);
	if(!err) {
		path_put_func(&path);
		pr_debug("[oplus_power_hook] file %s exist\n", file_path);
		return true;
	}

	pr_info("[oplus_power_hook] file %s not exist\n", file_path);
	return false;
}

bool is_timerfd_alarmproc_function(timerfd_alarmproc_t func)
{
	if(!func)
 		return false;

	if(!timerfd_alarmproc_sym) {
		timerfd_alarmproc_sym = \
			(timerfd_alarmproc_t)generic_kallsyms_lookup_name("timerfd_alarmproc");
		if(!timerfd_alarmproc_sym) {
			pr_info("[oplus_power_hook] timerfd_alarmproc symbol get failed\n");
			return false;
		}
	}

	return (func == timerfd_alarmproc_sym);
}


struct proc_dir_entry *get_oplus_lpm_dir(void)
{
	return oplus_lpm_proc;
}

static void lookup_tracepoints(struct tracepoint *tp, void *ignore)
{
	int i;

	for (i = 0; i < tpt_size; i++) {
		if (!strcmp(intrest_tracepoints_table[i].name, tp->name)) {
			pr_debug("[oplus_power_hook] tracepoint %s found\n",
					intrest_tracepoints_table[i].name);
			intrest_tracepoints_table[i].tp = tp;
		}
	}
}

void tracepoint_cleanup(int index)
{
	int i;
	struct tracepoints_table *tpt;

	for (i = 0; i < index; i++) {
		tpt = &intrest_tracepoints_table[i];
		if (tpt->registered) {
			tracepoint_probe_unregister(tpt->tp, tpt->func, NULL);
			tpt->registered = false;
        }
    }
}

/*
 * when use not export tracepoint, will occur undefined error when compile
 * so we get a not export tracepoint by go through tracepoint list, then register a probe function
 * if a tracepoint has already export, it's better use "register_trace_##name" to register a
 * probe function tracepoint export by "EXPORT_TRACEPOINT_SYMBOL_GPL"、"EXPORT_TRACEPOINT_SYMBOL"
 */
void find_and_register_tracepoint_probe(struct tracepoints_table *tp_table, unsigned int array_size)
{
	struct tracepoints_table *tpt;
	int i;
	int ret;

	intrest_tracepoints_table = tp_table;
	tpt_size = array_size;

	for_each_kernel_tracepoint(lookup_tracepoints, NULL);

	for (i = 0; i < array_size; i++) {
		tpt = &intrest_tracepoints_table[i];
		if (tpt->tp) {
			pr_debug("[oplus_power_hook] register %s tracepoint function %ps\n",
					tpt->name, tpt->func);
			ret = tracepoint_probe_register(tpt->tp, tpt->func,  NULL);
			if (ret) {
				pr_info("[oplus_power_hook] couldn't activate tracepoint %pf\n",
										tpt->func);
				tracepoint_cleanup(i);
			}
			tpt->registered = true;
		}
	}
}

void unregister_tracepoint_probe(struct tracepoints_table *tp_table, unsigned int array_size)
{
	int i;
	struct tracepoints_table *tpt;

	for (i = 0; i < array_size; i++) {
		tpt = &intrest_tracepoints_table[i];
		if (tpt->registered) {
			tracepoint_probe_unregister(tpt->tp, tpt->func, NULL);
			tpt->registered = false;
		}
	}
}

static int proc_match(const char *name, struct proc_dir_entry *de, unsigned int len)
{
	if (len < de->namelen)
		return -1;
	if (len > de->namelen)
		return 1;

	return memcmp(name, de->name, len);
}

struct proc_dir_entry *pde_subdir_find_func(struct proc_dir_entry *dir,
					      const char *name,
					      unsigned int len)
{
	struct rb_node *node = dir->subdir.rb_node;

	while (node) {
		struct proc_dir_entry *de = rb_entry(node,
						     struct proc_dir_entry,
						     subdir_node);
		int result = proc_match(name, de, len);

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return de;
	}
	return NULL;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
struct proc_dir_entry *get_proc_root(void)
{
	struct proc_dir_entry *orig_proc_root = NULL;

	if(!orig_proc_root) {
		orig_proc_root = (struct proc_dir_entry *)generic_kallsyms_lookup_name("proc_root");
		if(!orig_proc_root) {
			pr_info("[power_hook] proc_root symbol get failed\n");
		}
	}

	return orig_proc_root;
}
#endif

void power_hook_util_init(void)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	if(!kallsyms_lookup_name_sym) {
		kallsyms_lookup_name_sym = (void *)get_kallsyms_func();
	}
#endif
}
