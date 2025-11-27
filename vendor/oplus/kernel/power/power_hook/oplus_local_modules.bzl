load("//build/kernel/kleaf:kernel.bzl", "ddk_headers")
load("//build/kernel/oplus:oplus_modules_define.bzl", "define_oplus_ddk_module")
load("//build/kernel/oplus:oplus_modules_dist.bzl", "ddk_copy_to_dist_dir")

def define_oplus_local_modules():

    define_oplus_ddk_module(
        name = "oplus_power_hook",
#        outs = "oplus_power_hook.ko",
        srcs = native.glob([
            "**/*.h",
            "powerhook_main.c",
            "utils/oplus_power_hook_utils.c",
            "alarmtimer_hook/oplus_alarmtimer_hook.c",
            "irq_wakeup_hook/oplus_irq_wakeup_hook.c",
            "netlink_hook/oplus_netlink_hook.c",
        ]),
#        conditional_srcs = {
#            "CONFIG_OPLUS_FEATURE_IRQ_WAKEUP_HOOK": {
#                True:  ["irq_wakeup_hook/oplus_irq_wakeup_hook.c"],
#            },
#            "CONFIG_OPLUS_FEATURE_ALARMTIMER_HOOK": {
#                True:  ["alarmtimer_hook/oplus_alarmtimer_hook.c"],
#            },
#        },
        includes = ["."],
	local_defines = ["OPLUS_FEATURE_POWER_HOOK","CONFIG_OPLUS_FEATURE_IRQ_WAKEUP_HOOK","CONFIG_OPLUS_FEATURE_ALARMTIMER_HOOK","CONFIG_OPLUS_FEATURE_NETLINK_HOOK"],
    )

    ddk_copy_to_dist_dir(
        name = "oplus_power_hook",
        module_list = [
            "oplus_power_hook",
        ],
    )
