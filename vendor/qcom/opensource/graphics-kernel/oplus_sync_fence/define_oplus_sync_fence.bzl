load("//build/kernel/kleaf:kernel.bzl", "ddk_module")
load("//build/bazel_common_rules/dist:dist.bzl", "copy_to_dist_dir")
load("//msm-kernel:target_variants.bzl", "get_all_variants")

def _define_module(target, variant):
    tv = "{}_{}".format(target, variant)
    rule_name = "{}_oplus_sync_fence".format(tv)
    ddk_module(
        name = rule_name,
        kernel_build = "//msm-kernel:{}".format(tv),
        srcs = ["src/oplus_sync_file.c"],
        deps = [
            "//msm-kernel:all_headers",
        ],
        out = "oplus_sync_fence.ko",
        kconfig = "Kconfig",
        defconfig = "defconfig",
        visibility = ["//visibility:public"]
    )

    copy_to_dist_dir(
        name = "{}_dist".format(rule_name),
        data = [":{}".format(rule_name)],
        dist_dir = "out/target/product/{}/dlkm/lib/modules".format(target),
        flat = True,
        wipe_dist_dir = False,
        allow_duplicate_filenames = False,
        mode_overrides = {"**/*": "644"},
        log = "info",
    )

def define_oplus_sync_fence():
    for (t, v) in get_all_variants():
        _define_module(t, v)
