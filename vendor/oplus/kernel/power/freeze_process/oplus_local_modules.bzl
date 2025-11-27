load("//build/kernel/kleaf:kernel.bzl", "ddk_headers")
load("//build/kernel/oplus:oplus_modules_define.bzl", "define_oplus_ddk_module")
load("//build/kernel/oplus:oplus_modules_dist.bzl", "ddk_copy_to_dist_dir")

def define_oplus_local_modules():

    define_oplus_ddk_module(
        name = "oplus_freeze_process",
        #outs = "oplus_freeze_process.ko",
        srcs = native.glob([
            "**/*.h",
            "oplus_freeze_process_hook.c",
        ]),
        includes = ["."],
	local_defines = ["CONFIG_OPLUS_FEATURE_FREEZE_PROCESS_HOOK"],
    )

    ddk_copy_to_dist_dir(
        name = "oplus_freeze_process",
        module_list = [
            "oplus_freeze_process",
        ],
    )
