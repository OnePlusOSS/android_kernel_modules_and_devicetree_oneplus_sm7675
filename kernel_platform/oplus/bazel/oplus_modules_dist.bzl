load("//build/bazel_common_rules/dist:dist.bzl", "copy_to_dist_dir")
load("//msm-kernel:target_variants.bzl", "get_all_la_variants")
load(":oplus_modules_variant.bzl",
"bazel_support_target",
"bazel_support_variant"
)

load(":oplus_modules_define.bzl", "oplus_ddk_get_oplus_features")

def ddk_copy_to_dist_dir(
        name = None,
        module_list = [],
        conditional_builds = None):

    data = []

    if name == None:
        name = "ddk_oplus_default"

    # 当编译条件存在时，处理条件编译的代码
    # Handle conditionally compiled code when a compilation condition exists
    if conditional_builds:
        # 获取从环境变量传递过来的变量, oplus_feature_list 是一个字典
        # Get variables passed from environment variables
        oplus_feature_list = oplus_ddk_get_oplus_features()
        for module in module_list:
            # 当存在该模块的编译条件时，将编译条件与环境变量设置一一对应
            # 只有所有的条件均符合时，才进行编译
            # When there are compilation conditions for this module,
            # map the compilation conditions to the environment variable settings one-to-one.
            # Only compile if all conditions are met
            conditional_build = conditional_builds.get(module, None)
            if conditional_build:
                skip = 0
                for k in conditional_build:
                    v = conditional_build[k]
                    sv1 = str(v).upper()
                    sv2 = str(oplus_feature_list.get(k, 'foo')).upper()
                    if sv1 != sv2:
                        skip += 1
                if skip > 0:
                    print("Remove: compilation conditions are not met in %s" % module)
                    print("Settings:", oplus_feature_list)
                    print("Conditionals:", conditional_build)
                    continue
                else:
                    print("Added: compilation conditions are met in %s" % module)
                    data.append(":{}".format(module))
            else:
                data.append(":{}".format(module))
    else:
        # 否则走原生流程
        # raw pass: modules has no conditional compilation options
        for module in module_list:
            data.append(":{}".format(module))

    if len(data) == 0:
        return

    #for (targets, variant) in get_all_la_variants():
    for targets in bazel_support_target:
        for variant in bazel_support_variant:
            copy_to_dist_dir(
                name = "{}_{}_{}_dist".format(targets,variant,name),
                data = data,
                dist_dir = "out/target/product/{}_{}/dlkm/lib/modules/".format(targets,variant),
                flat = True,
                wipe_dist_dir = False,
                allow_duplicate_filenames = False,
                mode_overrides = {"**/*": "644"},
            )

