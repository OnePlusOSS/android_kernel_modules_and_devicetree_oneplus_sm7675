load("//build/kernel/kleaf:kernel.bzl", "ddk_headers")
load("//build/kernel/oplus:oplus_modules_define.bzl", "define_oplus_ddk_module")
load("//build/kernel/oplus:oplus_modules_dist.bzl", "ddk_copy_to_dist_dir")

def define_oplus_local_modules():

    define_oplus_ddk_module(
        name = "oplus_rpmh_statics",
        #outs = "oplus_rpmh_statics.ko",
        srcs = native.glob([
            "**/*.h",
            "oplus_rpmh_statics.c",
        ]),
        includes = ["."],
    )

    ddk_copy_to_dist_dir(
        name = "oplus_rpmh_statics",
        module_list = [
            "oplus_rpmh_statics",
        ],
    )
