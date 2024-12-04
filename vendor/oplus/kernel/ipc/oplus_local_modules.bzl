load("//build/kernel/kleaf:kernel.bzl", "ddk_headers")
load("//build/kernel/oplus:oplus_modules_define.bzl", "define_oplus_ddk_module")
load("//build/kernel/oplus:oplus_modules_dist.bzl", "ddk_copy_to_dist_dir")

def define_oplus_local_modules():

    define_oplus_ddk_module(
        name = "oplus_binder_strategy",
        srcs = native.glob([
            "binder_main.c",
            "binder_sched.c",
            "binder_sysfs.c",
            "*.h",
        ]),
        ko_deps = [":oplus_vip_binder"],
        includes = [".", "vipthread"],
        local_defines = [
             "CONFIG_OPLUS_BINDER_STRATEGY",
             "CONFIG_OPLUS_BINDER_PRIO_SKIP",
             "CONFIG_ANDROID_BINDER_IPC_VIP_THREAD"
        ],
    )

    define_oplus_ddk_module(
        name = "oplus_vip_binder",
        srcs = native.glob([
            "vipthread/binder_vip.c",
            "vipthread/binder_vip_sysfs.c",
            "vipthread/binder_vip_hash.c",
            "vipthread/binder_vip_hash.h",
            "vipthread/binder_vip_prtrace.h",
            "vipthread/binder_vip_sysfs.h",
            "vipthread/binder_vip_trace.h",
        ]),
        hdrs  = native.glob([
            "vipthread/binder_vip.h",
        ]),
        includes = [".", "vipthread"],
        local_defines = ["CONFIG_ANDROID_BINDER_IPC_VIP_THREAD"],
    )

    ddk_headers(
        name = "config_headers",
        hdrs  = native.glob([
            "**/*.h",
        ]),
        includes = ["."],
    )

#    ddk_headers(
#        name = "config_headers",
#        hdrs  = native.glob([
#            "binder_sched.h",
#        ]),
#        includes = ["."],
#    )

    ddk_copy_to_dist_dir(
        name = "oplus_binder_strategy",
        module_list = [
            "oplus_binder_strategy",
            "oplus_vip_binder",
        ],
    )
