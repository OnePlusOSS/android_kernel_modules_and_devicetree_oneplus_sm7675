load("//build/kernel/kleaf:kernel.bzl", "ddk_headers")
load("//build/kernel/oplus:oplus_modules_define.bzl", "define_oplus_ddk_module")
load("//build/kernel/oplus:oplus_modules_dist.bzl", "ddk_copy_to_dist_dir")

def define_oplus_local_modules():
    define_oplus_ddk_module(
        name = "oplus_magnetic_cover",
        srcs = native.glob([
            "**/*.h",
            "magcvr_src/abstract/magnetic_cover_core.c",
#            "magcvr_src/transfer/magcvr_notify.c", /* need set intree for other driver used */
        ]),
        includes = ["."],
        local_defines = ["CONFIG_OPLUS_MAGCVR_NOTIFY"],
        conditional_defines = {
#            "qcom":  ["CONFIG_QCOM_PANEL_EVENT_NOTIFIER"],
#            "mtk":  ["CONFIG_OPLUS_MTK_DRM_GKI_NOTIFY"],
        },
    )

    define_oplus_ddk_module(
        name = "oplus_magcvr_ak09973",
        srcs = native.glob([
            "**/*.h",
            "magcvr_src/hardware/magcvr_ak09973.c"
        ]),
        ko_deps = [
            "//vendor/oplus/kernel/device_info/magnetic_cover:oplus_magnetic_cover",
        ],
        includes = ["."],
    )

    define_oplus_ddk_module(
        name = "oplus_magcvr_mxm1120",
        srcs = native.glob([
            "**/*.h",
            "magcvr_src/hardware/magcvr_mxm1120.c"
        ]),
        ko_deps = [
            "//vendor/oplus/kernel/device_info/magnetic_cover:oplus_magnetic_cover",
        ],
        includes = ["."],
    )

    define_oplus_ddk_module(
        name = "oplus_magcvr_mkh100a",
        srcs = native.glob([
            "**/*.h",
            "magcvr_src/hardware/magcvr_mkh100a.c"
        ]),
        ko_deps = [
            "//vendor/oplus/kernel/device_info/magnetic_cover:oplus_magnetic_cover",
        ],
        includes = ["."],
    )

    ddk_headers(
        name = "config_headers",
        hdrs  = native.glob([
            "**/*.h",
        ]),
        includes = [".","magcvr_notify"],
    )

    ddk_copy_to_dist_dir(
        name = "oplus_magnetic_cover",
        module_list = [
             "oplus_magnetic_cover",
             "oplus_magcvr_ak09973",
             "oplus_magcvr_mxm1120",
        ],
    )
