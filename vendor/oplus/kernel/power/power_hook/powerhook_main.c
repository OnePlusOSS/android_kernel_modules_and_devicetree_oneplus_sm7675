#include <linux/version.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include "irq_wakeup_hook/oplus_irq_wakeup_hook.h"
#include "alarmtimer_hook/oplus_alarmtimer_hook.h"
#include "netlink_hook/oplus_netlink_hook.h"
#include "utils/oplus_power_hook_utils.h"

#define OPLUS_LPM_DIR       "oplus_lpm"
#define OPLUS_LPM_DIR_PROC  "/proc/oplus_lpm"

struct proc_dir_entry *oplus_lpm_proc = NULL;

void create_oplus_lpm_dir(void)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0))
	oplus_lpm_proc = proc_mkdir(OPLUS_LPM_DIR, NULL);
#else
	if(!is_file_exist(OPLUS_LPM_DIR_PROC)) {
		oplus_lpm_proc = proc_mkdir(OPLUS_LPM_DIR, NULL);
	} else {
		oplus_lpm_proc = pde_subdir_find_func(get_proc_root(),
				OPLUS_LPM_DIR, strlen(OPLUS_LPM_DIR));
	}
#endif
}

static int __init power_hook_init(void)
{
#if IS_ENABLED(CONFIG_OPLUS_FEATURE_IRQ_WAKEUP_HOOK) || IS_ENABLED(CONFIG_OPLUS_FEATURE_ALARMTIMER_HOOK)  || IS_ENABLED(CONFIG_OPLUS_FEATURE_NETLINK_HOOK)
	int ret = 0;
#endif

	power_hook_util_init();

	create_oplus_lpm_dir();

#if IS_ENABLED(CONFIG_OPLUS_FEATURE_IRQ_WAKEUP_HOOK)
	ret = irq_wakeup_hook_init();
	if (ret < 0) {
		pr_info("[power_hook] module failed to init irq wakeup hook.\n");
		return ret;
	}
#endif

#if IS_ENABLED(CONFIG_OPLUS_FEATURE_ALARMTIMER_HOOK)
	ret = alarmtimer_hook_init();
	if (ret < 0) {
		pr_info("[power_hook] module failed to init alarmtimer hook.\n");
		return ret;
	}
#endif


#if IS_ENABLED(CONFIG_OPLUS_FEATURE_NETLINK_HOOK)
	ret = netlink_wakeupsource_hook_init();
	if (ret < 0) {
		pr_info("[power_hook] module failed to init netlink hook.\n");
		return ret;
	}
#endif

	pr_info("[power_hook] all module init successfully!");

	return 0;
}

static void __exit power_hook_exit(void)
{
#if IS_ENABLED(CONFIG_OPLUS_FEATURE_IRQ_WAKEUP_HOOK)
	irq_wakeup_hook_exit();
#endif

#if IS_ENABLED(CONFIG_OPLUS_FEATURE_ALARMTIMER_HOOK)
	alarmtimer_hook_exit();
#endif

#if IS_ENABLED(CONFIG_OPLUS_FEATURE_NRTLINK_HOOK)
	netlink_wakeupsource_hook_exit();
#endif

	pr_info("[power_hook] all module exit successfully!");
}


module_init(power_hook_init);
module_exit(power_hook_exit);

MODULE_AUTHOR("Colin.Liu");
MODULE_DESCRIPTION("oplus power hook module");
MODULE_LICENSE("GPL v2");
