load("//build/kernel/kleaf:kernel.bzl", "ddk_headers")
load("//build/kernel/oplus:oplus_modules_define.bzl", "define_oplus_ddk_module")
load("//build/kernel/oplus:oplus_modules_dist.bzl", "ddk_copy_to_dist_dir")

def define_oplus_local_modules():

    define_oplus_ddk_module(
        name = "oplus_bsp_game_opt",
        srcs = native.glob([
            "**/*.h",
            "cpu_load.c",
            "cpufreq_limits.c",
            "debug.c",
            "early_detect.c",
            "fake_cpufreq.c",
            "game_ctrl.c",
            "rt_info.c",
            "task_util.c",
        ]),
        includes = ["."],
        copts = select({
            "//build/kernel/kleaf:kocov_is_true": ["-fprofile-arcs", "-ftest-coverage"],
            "//conditions:default": [],
        }),
    )

    ddk_copy_to_dist_dir(
        name = "oplus_bsp_game",
        module_list = [
            "oplus_bsp_game_opt",
        ],
    )
