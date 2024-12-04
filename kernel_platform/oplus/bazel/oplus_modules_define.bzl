load("//build/kernel/kleaf:kernel.bzl", "ddk_module")
load("//msm-kernel:target_variants.bzl", "get_all_la_variants")
load(":oplus_modules_variant.bzl",
"bazel_support_target",
"bazel_support_variant"
)
load(":oplus_modules_variant.bzl", "OPLUS_FEATURES")

bazel_support_platform = "qcom"
bazel_wifionly = None

"""
将以 OPLUS_FEATURE_ 打头的环境变量转换为字典
"""
def oplus_ddk_get_oplus_features():
    oplus_feature_list = {}
    for o in OPLUS_FEATURES.strip().split(' '):
        lst = o.split('=')
        if len(lst) != 2:
            # print('Info: environment variable [%s]' % o)
            continue
        oplus_feature_list[lst[0]] = lst[1]

    return oplus_feature_list


"""
将以 OPLUS_FEATURE_ 打头的环境变量转换为列表
"""
def get_oplus_features_as_list():
    oplus_features = []
    for o in OPLUS_FEATURES.strip().split(' '):
        lst = o.split('=')
        if len(lst) != 2:
            # print('Info: environment variable [%s]' % o)
            continue
        oplus_features.append(o)

    return oplus_features


def define_oplus_ddk_module(
    name,
    srcs = None,
    header_deps = [],
    ko_deps = [],
    hdrs = None,
    includes = None,
    conditional_srcs = None,
    conditional_defines = None,
    linux_includes = None,
    out = None,
    local_defines = None,
    copts = None,
    conditional_build = None):

    # 从编译中移除编译条件不满足的模块
    if conditional_build:
        # 对来自环境变量的OPLUS_FEATURES进行解码
        oplus_feature_list = oplus_ddk_get_oplus_features()

        skip = 0
        for k in conditional_build:
            v = conditional_build[k]
            sv1 = str(v).upper()
            sv2 = str(oplus_feature_list.get(k, 'foo')).upper()
            if sv1 != sv2:
                skip += 1

        if skip > 0:
            print("Remove: compilation conditions are not met in %s" % name)
            print("Settings:", oplus_feature_list)
            print("Conditionals:", conditional_build)
            return
        else:
            print("Added: compilation conditions are met in %s" % name)

    if srcs == None:
        srcs = native.glob(
            [
                "**/*.c",
                "**/*.h",
            ],
            exclude = [
                ".*",
                ".*/**",
            ],
        )

    if out == None:
        out = name + ".ko"

    flattened_conditional_defines = None
    if conditional_defines:
        for config_vendor, config_defines in conditional_defines.items():
            if config_vendor == bazel_support_platform:
                if flattened_conditional_defines:
                    flattened_conditional_defines = flattened_conditional_defines + config_defines
                else:
                    flattened_conditional_defines = config_defines

    if flattened_conditional_defines:
        if local_defines:
            local_defines =  local_defines + flattened_conditional_defines
        else:
            local_defines = flattened_conditional_defines

    #fail("debug need variable {}".format(local_defines))

    #for (targets, variant) in get_all_la_variants():
    for targets in bazel_support_target:
        for variant in bazel_support_variant:
            ddk_module(
                name = "{}".format(name),
                srcs = srcs,
                out = "{}".format(out),
                local_defines = local_defines,
                copts = copts,
                includes = includes,
                conditional_srcs = conditional_srcs,
                linux_includes = linux_includes,
                hdrs = hdrs,
                deps = ["//msm-kernel:all_headers"] + header_deps + ko_deps,
                kernel_build = "//msm-kernel:{}_{}".format(targets,variant),
                visibility = ["//visibility:public"]
            )


