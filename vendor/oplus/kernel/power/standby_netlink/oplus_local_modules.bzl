load("//build/kernel/kleaf:kernel.bzl", "ddk_headers")
load("//build/kernel/oplus:oplus_modules_define.bzl", "define_oplus_ddk_module")
load("//build/kernel/oplus:oplus_modules_dist.bzl", "ddk_copy_to_dist_dir")

def define_oplus_local_modules():

    define_oplus_ddk_module(
        name = "oplus_standby_netlink",
        srcs = native.glob([
            "standby_netlink.h",
            "standby_netlink.c",
            "netlink_handler.c",
            "standby_netlink_deps.h",
            "standby_netlink_deps.c"
        ]),
        includes = ["."],
        conditional_defines = {
            "mtk":  ["CONFIG_OPLUS_STANDBY_NETLINK_MTK"],
            "qcom":  ["CONFIG_OPLUS_STANDBY_NETLINK_QCOM"],
        },
        local_defines = ["OPLUS_FEATURE_STANDBY_NETLINK"],
    )

    ddk_copy_to_dist_dir(
        name = "oplus_standby_netlink",
        module_list = [
            "oplus_standby_netlink",
        ],
    )
