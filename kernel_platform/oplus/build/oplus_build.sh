#!/bin/sh
#set -x
set -e
function usage() {
    echo -e "
Description:
    这个脚本用于编译高通平台kernel相关的目标
    请确保在vnd全编译过的环境使用
    vendor下高通原生KO请直接使用./mk_android.sh -t user -n xxx编译模块

OPTIONS:
    -t, --type
        Build type(user/userdebug/eng) (Default: userdebug)
    -p, --platform
        Specifies platform(SM8750/SM8650/SM8550)
    -b, --build
        Specifies build targets,can be one or a combination of the following
        vmlinux: kernel
        dtb：dtb
        dtbo: dtbo
        abl: abl
        in-tree-ko: drivers/power/oplus/v2/oplus_chg_v2.ko
        out-of-tree-ko: ../vendor/oplus/kernel/boot/oplus_phoenix
        techpack dtbs：vendor/qcom/proprietary/display-devicetree camera-devicetree vendor/qcom/proprietary/camera-devicetree/
        base dtbs: sun.dtb sunp-v2.dtb dodge-23821-sun-overlay.dtbo petrel-24001-sun-overlay.dtbo
Usage:
    1 ./kernel_platform/oplus/build/oplus_build.sh -t user -p SM8650 -b kernel
    仅修改kernel代码只需要vmlinux更新
    
    2 ./kernel_platform/oplus/build/oplus_build.sh -t user -p SM8650 -b drivers/power/oplus/v2/oplus_chg_v2.ko ../vendor/oplus/kernel/boot/oplus_phoenix
    不需要更新vmlinux，只有KO的修改。
    oplus ddk KO编译必须完全参考kernel_platform/oplus/config/modules.ext.oplus填写target，不能随意删除路径
    in-tree KO参考kernel_platform/msm-kernel/pineapple.bzl->_pineapple_in_tree_modules = [ ]
    
    3 ./kernel_platform/oplus/build/oplus_build.sh -t user -p SM8650 -b dtbo/dtb
    所有dtb dtbo全部编译，这种会通过触发kernel编译实现，相对耗时多些
    
    4 ./kernel_platform/oplus/build/oplus_build.sh -t user -p SM8650 -b dodge-23821-sun-overlay.dtbo/sun.dtb
    清楚的知道dts修改在哪个dtb dtbo生效，可以直接指定具体dtbo、dtb编译,这种只针对kernel_platform下的，
    如果vendor/qcom下的模块自己的dts请参考5
    
    5. ./kernel_platform/oplus/build/oplus_build.sh -t user -p SM8650 -b camera-devicetree vendor/qcom/proprietary/camera-devicetree/
    针对只修改了模块自己dts的场景
"
}

function build_in_tree_ko () {
    cd ${KERNEL_ROOT}
    for ko_path in $IN_TREE_KO; do
        if ./tools/bazel query //msm-kernel:${KERNEL_TARGET}_${KERNEL_VARIANT}/${ko_path}
        then
            mapfile -t build_flags < "${ANDROID_KP_OUT_DIR}/dist/build_opts.txt"
            set -x
            ./tools/bazel build "${build_flags[@]}" //msm-kernel:${KERNEL_TARGET}_${KERNEL_VARIANT}/${ko_path}
            set +x
        else
            echo -e "\033[0;31m in tree ko target is wrong\033[0m"
            exit 1
        fi

        ls -lh ${INTREE_MODULE_OUT}/${ko_path}

        file=$(find ${ANDROID_KERNEL_OUT} -type f -name $(basename "${INTREE_MODULE_OUT}/${ko_path}"))
        if [ -n "$file" ]; then
            echo "copying "${INTREE_MODULE_OUT}/${ko_path}" -> $file"
            cp "${INTREE_MODULE_OUT}/${ko_path}" "$file"
            if echo "$file" | grep -q "vendor_dlkm"; then
                echo "${ko_path} 打包在vendor_dlkm,可以直接push或者编译vendor_dlkm.img验证修改" >> ${message}
                #VENDOR_DLKMIMAGE=1
            else
                echo "${ko_path} 打包在vendor_boot,需要编译vendor_boot.img验证修改" >> ${message}
                VENDORBOOTIMAGE=1
            fi
        fi
        cp ${INTREE_MODULE_OUT}/${ko_path}  ${ANDROID_KP_OUT_DIR}/dist
    done
    cd -
}

function build_base_dtbs () {
    cd ${KERNEL_ROOT}
    for dtb in $BASE_DTBS; do
        if ./tools/bazel query //msm-kernel:${KERNEL_TARGET}_${KERNEL_VARIANT}/${dtb}
        then
            mapfile -t build_flags < "${ANDROID_KP_OUT_DIR}/dist/build_opts.txt"
            set -x
            ./tools/bazel build "${build_flags[@]}" //msm-kernel:${KERNEL_TARGET}_${KERNEL_VARIANT}/${dtb}
            set +x
        else
            echo -e "\033[0;31mbase dtb/dtbo name is wrong\033[0m" 
            exit 1
        fi

        ls -lh ${INTREE_MODULE_OUT}/${dtb}
        echo "copying ${INTREE_MODULE_OUT}/${dtb} --> ${ANDROID_KERNEL_OUT}/kp-dtbs"
        cp ${INTREE_MODULE_OUT}/${dtb}  ${ANDROID_KERNEL_OUT}/kp-dtbs
        cp ${INTREE_MODULE_OUT}/${dtb}  ${ANDROID_KP_OUT_DIR}/dist
        if [ "${dtb%.dtbo}" != "$dtb" ]; then
            echo "${dtb} 打包在dtbo.img,需要编译dtbo.img验证修改" >> ${message}
        elif [ "${dtb%.dtb}" != "$dtb" ]; then
            echo "${dtb} 打包在vendor_boot,需要编译vendor_boot.img验证修改" >> ${message}
        fi
    done
    cd -
}

function get_opt() {
    # 使用getopt解析参数
    OPTS=`getopt -o t:p:b:h --long type:,platform:,build:,help -- "$@"`
    if [[ $? != 0 ]]; then
      usage
      exit 1
    fi
    eval set -- "$OPTS"

    # 提取参数
    while true; do
      case "$1" in
        -t|--type)
          O_BUILD_TYPE=$2
          shift 2
          ;;
        -p|--platform)
          O_BUILD_PLATFORM=$2
          shift 2
          ;;
        -b|--build)
          O_BUILD_TARGETS=$2
          shift 2
          ;;
        -h|--help)
          usage
          exit 0
          ;;
        --)
          shift
          break
          ;;
        *)
          usage
          exit 0
          ;;
      esac
    done
    O_BUILD_TARGETS+=" $@"
}

get_opt "$@"

echo "O_BUILD_TYPE=$O_BUILD_TYPE"
echo "O_BUILD_PLATFORM=$O_BUILD_PLATFORM"
echo "O_BUILD_TARGETS=$O_BUILD_TARGETS"
if [ -z "$O_BUILD_TYPE" ] || [ -z "$O_BUILD_PLATFORM" ] || [ -z "$O_BUILD_TARGETS" ];then
    usage
    exit 1
fi

TOPDIR=$(readlink -f $(cd $(dirname "$0");cd ../../../;pwd))
pushd $TOPDIR

#使能bazel cache
source  vendor/oplus/build/ci/functions.sh
fn_try_speedup_build

#获取kernel编译KERNEL_TARGET、KERNEL_VARIANT
source vendor/oplus/build/platform/vnd/$O_BUILD_PLATFORM/envsetup.sh
KERNEL_TARGET=${OPLUS_KERNEL_PARAM:-sun}
if [ "$O_BUILD_TYPE" == "userdebug" ];then
    KERNEL_VARIANT=consolidate
else
    KERNEL_VARIANT=${OPLUS_USER_KERNEL_VARIANT:-gki}
fi

#set env
export TARGET_BUILD_VARIANT=$O_BUILD_TYPE
export ANDROID_BUILD_TOP=${TOPDIR}
export ANDROID_KERNEL_OUT=${ANDROID_BUILD_TOP}/device/qcom/${KERNEL_TARGET}-kernel
export ANDROID_KP_OUT_DIR="out/msm-kernel-${KERNEL_TARGET}-${KERNEL_VARIANT}"
export ANDROID_PRODUCT_OUT=${TOPDIR}/out/target/product/$COMPILE_PLATFORM
export TARGET_BOARD_PLATFORM=$KERNEL_TARGET
KERNEL_ROOT=${TOPDIR}/kernel_platform
INTREE_MODULE_OUT=$(cd kernel_platform;find out/bazel/output_user_root/ -type d -wholename '*/execroot/__main__/bazel-out/k8-fastbuild/bin' | head -n 1)/msm-kernel/${KERNEL_TARGET}_${KERNEL_VARIANT}
#是否全编译环境检测
if ! cat "$ANDROID_PRODUCT_OUT/previous_build_config.mk" | grep -qw "$O_BUILD_TYPE"; then
    echo -e "
\033[0;31m当前编译类型跟全编译类型不同，请跟全编译选择相同编译类型，当前:$O_BUILD_TYPE，全编译:$(cat "$ANDROID_PRODUCT_OUT/previous_build_config.mk")
    \033[0m"
    exit 1
fi
if [ ! -e $ANDROID_KERNEL_OUT ];then
    echo -e "
\033[0;31mit's new downloaded code, kernel has not yet been compiled, please build kpl with:
OPLUS_BUILD_JSON=build.json ./mk_android.sh -t user/userdebug -b kpl
    \033[0m"
    exit 1
fi

#设置编译控制宏
message=$(mktemp)
RECOMPILE_EXT_MODULE=0
RECOMPILE_KERNEL=0
RECOMPILE_ABL=0
RECOMPILE_TECHPACK_DTBO=0
RECOMPILE_MERGE_DTBS=0
IN_TREE_KO=""
EXT_MODULES=""
BASE_DTBS=""
for target in $O_BUILD_TARGETS; do
    if [ "$target" = "kernel" ]; then
        RECOMPILE_KERNEL=1
        BOOTIMAGE=1
        SYSTEM_DLKMIMAGE=1
    elif [ "$target" = "dtbo" ];then
        RECOMPILE_KERNEL=1
        RECOMPILE_MERGE_DTBS=1
        RECOMPILE_TECHPACK_DTBO=1
        DTBOIMAGE=1
    elif [ "$target" = "dtb" ];then
        RECOMPILE_KERNEL=1
        RECOMPILE_MERGE_DTBS=1
        VENDORBOOTIMAGE=1
    elif [ "$target" = "abl" ]; then
        RECOMPILE_ABL=1
        ABOOT=1
    elif [ "${target%.ko}" != "$target" ]; then
        IN_TREE_KO="$IN_TREE_KO $target"
    elif [ "${target%.dtbo}" != "$target" ]; then
        BASE_DTBS="$BASE_DTBS $target"
        RECOMPILE_MERGE_DTBS=1
        DTBOIMAGE=1
    elif [ "${target%.dtb}" != "$target" ]; then
        BASE_DTBS="$BASE_DTBS $target"
        RECOMPILE_MERGE_DTBS=1
        VENDORBOOTIMAGE=1
    elif [ "${target%-devicetree}" != "$target" ]; then
        RECOMPILE_TECHPACK_DTBO=1
        RECOMPILE_MERGE_DTBS=1
        DTBOIMAGE=1
    elif echo "$target" | grep -q "\.\./vendor/oplus"; then
        if [ -f "${target#../}/BUILD.bazel" ]; then
            EXT_MODULES="$EXT_MODULES $target"
            RECOMPILE_EXT_MODULE=1
            #VENDOR_DLKMIMAGE=1
        fi
    else
        echo  -e "\033[0;31mERROR:无法处理 $target\033[0m"
        WRONG_TARGET=1
    fi
done

if [ "$WRONG_TARGET" == "1" ];then
    usage
    exit 1
fi

#去除开头空格
IN_TREE_KO="${IN_TREE_KO# }"
EXT_MODULES="${EXT_MODULES# }"
BASE_DTBS="${BASE_DTBS# }"

echo "RECOMPILE_KERNEL=$RECOMPILE_KERNEL"
echo "RECOMPILE_EXT_MODULE=$RECOMPILE_EXT_MODULE"
echo "RECOMPILE_ABL=$RECOMPILE_ABL"
echo "RECOMPILE_TECHPACK_DTBO=$RECOMPILE_TECHPACK_DTBO"
echo "RECOMPILE_MERGE_DTBS=$RECOMPILE_MERGE_DTBS"
echo "IN_TREE_KO=$IN_TREE_KO"
echo "EXT_MODULES=$EXT_MODULES"
echo "BASE_DTBS=$BASE_DTBS"
echo "KERNEL_TARGET=$KERNEL_TARGET"
echo "KERNEL_VARIANT=$KERNEL_VARIANT"

#处理单独的in-tree ko和*.dtb *.dtbo
if [ -n "$IN_TREE_KO" ];then
    echo -e "\033[0;32mbuild in-tree ko $IN_TREE_KO\033[0m"
    build_in_tree_ko
fi

if [ -n "$BASE_DTBS" ] && [ "$RECOMPILE_KERNEL" == "0" ];then
    echo -e "\033[0;32mbuild base dtb/dtbo $BASE_DTBS\033[0m"
    build_base_dtbs
fi

#备份 $ANDROID_KERNEL_OUT/.config  $ANDROID_KERNEL_OUT/Module.symvers
#防止编译vendor_boot、vendor_dlkm时会触发高通原生KO编译
tmpdir=$(mktemp -d)
rsync -a $ANDROID_KERNEL_OUT/.config $tmpdir
rsync -a $ANDROID_KERNEL_OUT/Module.symvers $tmpdir

#整体编译kernel，不需要编译的部分已经加宏控制
if [ "$RECOMPILE_KERNEL" == "1" ] || [ "$RECOMPILE_ABL" == "1" ] || [ "$RECOMPILE_EXT_MODULE" == "1" ] || [ "$RECOMPILE_MERGE_DTBS" == "1" ];then
    RECOMPILE_KERNEL=$RECOMPILE_KERNEL RECOMPILE_ABL=$RECOMPILE_ABL RECOMPILE_EXT_MODULE=$RECOMPILE_EXT_MODULE \
    EXT_MODULES=$EXT_MODULES RECOMPILE_TECHPACK_DTBO=$RECOMPILE_TECHPACK_DTBO RECOMPILE_MERGE_DTBS=$RECOMPILE_MERGE_DTBS \
    ./kernel_platform/build/android/prepare_vendor.sh $KERNEL_TARGET $KERNEL_VARIANT
fi
#如果内容一样就带时间戳还原.config Module.symvers
if diff -q $ANDROID_KERNEL_OUT/.config $tmpdir/.config && diff -q $ANDROID_KERNEL_OUT/Module.symvers $tmpdir/Module.symvers;then
    rsync -a $tmpdir/.config $ANDROID_KERNEL_OUT/
    rsync -a $tmpdir/Module.symvers $ANDROID_KERNEL_OUT/
fi
rm -rf $tmpdir

#生成对应img
IAMGES=""
if [ "$SYSTEM_DLKMIMAGE" == "1" ]; then
    IAMGES="$IAMGES system_dlkmimage"
fi

if [ "$BOOTIMAGE" == "1" ]; then
    IAMGES="$IAMGES bootimage"
fi

if [ "$VENDORBOOTIMAGE" == "1" ]; then
    IAMGES="$IAMGES vendorbootimage"
fi

if [ "$VENDOR_DLKMIMAGE" == "1" ]; then
    IAMGES="$IAMGES vendor_dlkmimage"
fi

if [ "$ABOOT" == "1" ];then
    IAMGES="$IAMGES aboot"
fi

if [ "$DTBOIMAGE" == "1" ];then
    IAMGES="$IAMGES dtboimage"
fi
#去除开头空格
IAMGES="${IAMGES# }"

#编译img
if [ -n "$IAMGES" ];then
    echo -e "\033[0;32m./mk_android.sh -t $O_BUILD_TYPE -n "$IAMGES"\033[0m"
    ./mk_android.sh -t $O_BUILD_TYPE -n "$IAMGES"
fi

#输出验证建议信息
tput setaf 1
cat ${message}
echo
tput setaf 2
echo "vendor/oplus下的oplus DDK KO一般在vendor_dlkm,可以直接push或者编译vendor_dlkm.img验证修改，只有登记在
kernel_platform/oplus/config/modules.vendor_boot.list.oplus中的才会打包在vendor_boot中在init第一阶段加载
KO生成路径在device/qcom/sun-kernel，push前先使用如下命令做好strip
kernel_platform/prebuilts/clang/host/linux-x86/llvm-binutils-stable/llvm-strip -S *.ko -o yourpath/*.ko"
echo
tput setaf 1
if [ -n "$IAMGES" ];then
    echo "根据您指定的target，已为您编译出 $IAMGES.请确保您没有修改过Android.mk Android.bp否则-N生成的image会失效"
    echo
fi
tput setaf 2
echo "如果发现本脚本使用-n生成的image有问题，可以尝试使用./mk_android.sh -t user -m xxx"
rm ${message}
tput sgr0
popd
