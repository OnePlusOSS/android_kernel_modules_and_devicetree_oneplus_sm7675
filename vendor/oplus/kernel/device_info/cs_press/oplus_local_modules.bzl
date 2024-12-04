load("//build/kernel/kleaf:kernel.bzl", "ddk_headers")
load("//build/kernel/oplus:oplus_modules_define.bzl", "define_oplus_ddk_module")
load("//build/kernel/oplus:oplus_modules_dist.bzl", "ddk_copy_to_dist_dir")

def define_oplus_local_modules():

    define_oplus_ddk_module(
        name = "oplus_bsp_cs_press_f71",
        srcs = native.glob([
            "*.h",
            "cs_press_f71.c"
        ]),
        includes = ["."],
    )
    ddk_copy_to_dist_dir(
        name = "oplus_bsp_cs_press_f71",
        module_list = [
            "oplus_bsp_cs_press_f71",
        ],
    )