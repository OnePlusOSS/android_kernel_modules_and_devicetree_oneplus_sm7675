#!/bin/bash

# Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#     * Neither the name of The Linux Foundation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Changes from Qualcomm Innovation Center are provided under the following license:
# Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause-Clear

## prepare_vendor.sh prepares kernel/build's output for direct consumption in AOSP
# - Script assumes running after lunch w/Android build environment variables available
# - Select which kernel target+variant (defconfig) to use
#    - Default target based on TARGET_PRODUCT from lunch
#    - Default variant based on corresponding target's build.config
# - Remove all Android.mk and Android.bp files from source so they don't conflict with Android's
#   Kernel Platform has same clang/gcc prebuilt projects, which both have Android.mk/Android.bp that
#   would conflict
# - Compile in-vendor-tree devicetrees
# - Overlay those devicetrees onto the kernel platform's dtb/dtbos
#
# The root folder for kernel prebuilts in Android build system is following:
# KP_OUT = device/qcom/$(TARGET_PRODUCT)-kernel
# Default boot.img kernel Image: $(KP_OUT)/Image
# All Kernel Platform DLKMs: $(KP_OUT)/*.ko
# Processed Board UAPI Headers: $(KP_OUT)/kernel-headers
# First-stage DLKMs listed in $(KP_OUT)/modules.load
#   - If not present, all modules are for first-stage init
# Second-stage blocklist listed in $(KP_OUT)/modules.blocklist
#   - If not present, no modules should be blocked
# DTBs, DTBOs, dtb.img, and dtbo.img in $(KP_OUT)/merged-dtbs/
#
# The following optional arguments can be passed to prepare_vendor.sh:
#  prepare_vendor.sh [KERNEL_TARGET [KERNEL_VARIANT [OUT_DIR]]]
#   See below for descriptions of the arguments and default behavior when unspecified.
#   Note that in order for KERNEL_VARIANT to be defined, KERNEL_TARGET must also be
#   explicitly mentioned. Similarly, in order for OUT_DIR to be mentioned,
#   KERNEL_TARGET and KERNEL_VARIANT must also be mentioned.
#
# The following environment variables are considered during execution
#   ANDROID_KERNEL_OUT - The output location to copy artifacts to.
#                        If unset, then ANDROID_BUILD_TOP and TARGET_BOARD_PLATFORM
#                        (usually set by Android's "lunch" command)
#                        are used to figure it out
#   KERNEL_TARGET      - Kernel target to use. This variable can also be the first argument
#                        to prepare_vendor.sh [KERNEL_TARGET], or is copied from
#                        BOARD_TARGET_PRODUCT
#   KERNEL_VARIANT     - Kernel target variant to use. This variable can also be the second argument
#                        to prepare_vendor.sh [KERNEL_TARGET] [KERNEL_VARIANT]. If left unset,
#                        the default kernel variant is used for the kernel target.
#   OUT_DIR            - Kernel Platform output folder for the KERNEL_TARGET and KERNEL_VARIANT.
#                        This variable can also be the third argument to
#                        prepare_vendor.sh [KERNEL_TARGET] [KERNEL_VARIANT] [OUT_DIR].
#                        If left unset, conventional locations will be checked:
#                        $ANDROID_BUILD_TOP/out/$BRANCH and $KP_ROOT_DIR/out/$BRANCH
#   DIST_DIR           - Kernel Platform dist folder for the KERNEL_TARGET and KERNEL_VARIANT
#   RECOMPILE_KERNEL   - Recompile the kernel platform
#   LTO                - Specify Link-Time Optimization level. See LTO_VALUES in kleaf/constants.bzl
#                        for list of valid values.
#   EXTRA_KBUILD_ARGS  - Arguments to pass to kernel build (build_with_bazel.py)
#
# To compile out-of-tree kernel objects and set up the prebuilt UAPI headers,
# these environment variables must be set.
# ${ANDROID_BUILD_TOP}/vendor/**/*-devicetree/
#   ANDROID_BUILD_TOP   - The root source tree folder
#   ANDROID_PRODUCT_OUT - The root output folder. Output is placed in ${OUT}/obj/DLKM_OBJ
# Currently only DTBs are compiled from folders matching this pattern:

set -e
OUT_DIR=""
# rel_path <to> <from>
# Generate relative directory path to reach directory <to> from <from>
function rel_path() {
  python -c "import os.path; import sys; print(os.path.relpath(sys.argv[1], sys.argv[2]))" "$1" "$2"
}

ROOT_DIR=$($(dirname $(readlink -f $0))/../gettop.sh)
echo "  kernel platform root: $ROOT_DIR"

# Merge vendor devicetree overlays

if [ "$1" == "dtb-only" ]; then
  if [ -z "$2" ]; then
    echo "Please mention the target ..."
    exit 1
  fi

  TARGET=$2

  BASE_DT=${ROOT_DIR}/../device/qcom/${TARGET}-kernel
  TECHPACK_DT="${ROOT_DIR}/../out/target/product/${TARGET}/obj/DLKM_OBJ"

  if [ ! -e "${BASE_DT}" ] || [ ! -e "${TECHPACK_DT}" ]; then
    echo "Either base dt or techpack dt is missing ..."
    exit 1
  fi

  cd "${ROOT_DIR}"
  echo "  Merging vendor devicetree overlays"
  ./build/android/merge_dtbs.sh \
      "${BASE_DT}"/kp-dtbs \
      "${TECHPACK_DT}" \
      "${BASE_DT}"/dtbs
  exit 0
fi

################################################################################
# Discover where to put Android output
if [ -z "${ANDROID_KERNEL_OUT}" ]; then
  if [ -z "${ANDROID_BUILD_TOP}" ]; then
    echo "ANDROID_BUILD_TOP is not set. Have you run lunch yet?" 1>&2
    exit 1
  fi

  if [ -z "${TARGET_BOARD_PLATFORM}" ]; then
    echo "TARGET_BOARD_PLATFORM is not set. Have you run lunch yet?" 1>&2
    exit 1
  fi

  ANDROID_KERNEL_OUT=${ANDROID_BUILD_TOP}/device/qcom/${TARGET_BOARD_PLATFORM}-kernel
fi
if [ ! -e ${ANDROID_KERNEL_OUT} ]; then
  mkdir -p ${ANDROID_KERNEL_OUT}
fi

################################################################################
# Determine requested kernel target and variant

if [ -z "${KERNEL_TARGET}" ]; then
  KERNEL_TARGET=${1:-${TARGET_BOARD_PLATFORM}}
fi

if [ -z "${KERNEL_VARIANT}" ]; then
  KERNEL_VARIANT=${2}
fi

#V_Upgrade TODO 2024/3/26 for userdebug
if [ "${KERNEL_VARIANT}" = "consolidate" ]; then
  KERNEL_VARIANT=gki
fi
#V_Upgrade TODO 2024/3/26 for userdebug

case "${KERNEL_TARGET}" in
  taro)
    KERNEL_TARGET="waipio"
    ;;
  volcano)
    KERNEL_TARGET="pineapple"
    ;;
  anorak61)
    KERNEL_TARGET="anorak"
    ;;
esac

################################################################################
# Configure LTO
if [ -n "$LTO" ]; then
  LTO_KBUILD_ARG="--lto=$LTO"
fi

# Configure PGO
if [ "${KERNEL_PGO_FLAG}" = "1" ]; then
  PGO_KBUILD_ARG="--pgo=inst"
elif [ "${KERNEL_PGO_FLAG}" = "2" ]; then
  PGO_KBUILD_ARG="--pgo=pgo"
else
  PGO_KBUILD_ARG="--pgo=none"
fi

if [ -n "$OPLUS_KERNEL_MODULE_COVERAGE" ]; then
  GCOV_KBUILD_ARG="--kocov"
fi

if [ "$KERNEL_SANITIZER" == "kasan" ]; then
  EXTRA_KBUILD_ARGS+=" --kasan"
  LTO_KBUILD_ARG="--lto=none"
elif [ "$KERNEL_SANITIZER" == "kcsan" ]; then
  EXTRA_KBUILD_ARGS+=" --kcsan"
  LTO_KBUILD_ARG="--lto=none"
fi

################################################################################
# Create a build config used for this run of prepare_vendor
# Temporary KP output directory so as to not accidentally touch a prebuilt KP output folder
export TEMP_KP_OUT_DIR=$(mktemp -d ${ANDROID_PRODUCT_OUT:+-p ${ANDROID_PRODUCT_OUT}})
trap "rm -rf ${TEMP_KP_OUT_DIR}" exit
(
  cd ${ROOT_DIR}
  OUT_DIR=${TEMP_KP_OUT_DIR} ./build/brunch ${KERNEL_TARGET} ${KERNEL_VARIANT}
)

################################################################################
# If KERNEL_VARIANT is still unset at this point, grab it from the brunch output
if [ -z "$KERNEL_VARIANT" ]; then
  KERNEL_VARIANT=$(cd "$ROOT_DIR" && source build/_setup_env.sh && echo "$VARIANT")
fi

################################################################################
# Determine output folder
# ANDROID_KP_OUT_DIR is the output directory from Android Build System perspective
ANDROID_KP_OUT_DIR="${3:-${OUT_DIR}}"
if [ -z "${ANDROID_KP_OUT_DIR}" ]; then
  ANDROID_KP_OUT_DIR="out/msm-kernel-${KERNEL_TARGET}-${KERNEL_VARIANT}"

  if [ -n "${ANDROID_BUILD_TOP}" -a -e "${ANDROID_BUILD_TOP}/${ANDROID_KP_OUT_DIR}" ] ; then
    ANDROID_KP_OUT_DIR="${ANDROID_BUILD_TOP}/${ANDROID_KP_OUT_DIR}"
  else
    ANDROID_KP_OUT_DIR="${ROOT_DIR}/${ANDROID_KP_OUT_DIR}"
  fi
fi

# Clean up temporary KP output directory
rm -rf ${TEMP_KP_OUT_DIR}
trap - EXIT
echo "  kernel platform output: ${ANDROID_KP_OUT_DIR}"

################################################################################
# Set up recompile and copy variables
set -x
if [ ! -e "${ANDROID_KERNEL_OUT}/Image" ]; then
  COPY_NEEDED=1
fi

if [ ! -e "${ANDROID_KERNEL_OUT}/build.config" ] || \
  ! diff -q "${ANDROID_KERNEL_OUT}/build.config" "${ROOT_DIR}/build.config" ; then
  COPY_NEEDED=1
fi

if [ ! -e "${ANDROID_KP_OUT_DIR}/dist/Image" -a "${COPY_NEEDED}" == "1" ]; then
  RECOMPILE_KERNEL=1
fi
set +x

cp "${ROOT_DIR}/build.config" "${ANDROID_KERNEL_OUT}/build.config"

# Make sure Bazel extensions are linked properly
if [ ! -f "${ROOT_DIR}/build/msm_kernel_extensions.bzl" ] \
      && [ -f "${ROOT_DIR}/msm-kernel/msm_kernel_extensions.bzl" ]; then
  ln -fs "../msm-kernel/msm_kernel_extensions.bzl" "${ROOT_DIR}/build/msm_kernel_extensions.bzl"
fi
if [ ! -f "${ROOT_DIR}/build/abl_extensions.bzl" ] \
      && [ -f "${ROOT_DIR}/bootable/bootloader/edk2/abl_extensions.bzl" ]; then
  ln -fs "../bootable/bootloader/edk2/abl_extensions.bzl" "${ROOT_DIR}/build/abl_extensions.bzl"
fi

# If prepare_vendor.sh fails and nobody checked the error code, make sure the android build fails
# by removing the kernel Image which is needed to build boot.img
if [ "${RECOMPILE_KERNEL}" == "1" -o "${COPY_NEEDED}" == "1" ]; then
  rm -f ${ANDROID_KERNEL_OUT}/Image ${ANDROID_KERNEL_OUT}/vmlinux ${ANDROID_KERNEL_OUT}/System.map
fi

if [ -n "$OPLUS_KERNEL_STABILITY_DEBUG" ]; then
  EXTRA_KBUILD_ARGS+=" --notrim --nokmi_symbol_list_strict_mode --nokmi_symbol_list_violations_check"
  EXTRA_KBUILD_ARGS+=" --defconfig_fragment=//msm-kernel:arch/arm64/configs/oplus_debug_defconfig"
fi

################################################################################
# Read environment variables and write to bzl file
OPLUS_FEATURES=$(export|grep -e "^declare -x OPLUS_FEATURE_BSP_"|sed 's/declare -x //g'|sed 's/"//g'|tr '\n' ' ')
# setup build parameters before building external modules
./kernel_platform/oplus/bazel/oplus_modules_variant.sh ${KERNEL_TARGET} ${KERNEL_VARIANT} "${OPLUS_FEATURES}"

################################################################################
if [ "${RECOMPILE_KERNEL}" == "1" ]; then
  echo
  echo "  Recompiling kernel"
  echo "kpl-time-check kernel start $(date +%H:%M:%S)"

  # shellcheck disable=SC2086
  "${ROOT_DIR}/build_with_bazel.py" \
    -t "$KERNEL_TARGET" "$KERNEL_VARIANT" $LTO_KBUILD_ARG $PGO_KBUILD_ARG $GCOV_KBUILD_ARG $EXTRA_KBUILD_ARGS \
    --out_dir "${ANDROID_KP_OUT_DIR}"

  COPY_NEEDED=1
  echo "kpl-time-check kernel end $(date +%H:%M:%S)"
fi

################################################################################
# Set up recompile and copy variables for edk2
ANDROID_ABL_OUT_DIR=${ANDROID_KERNEL_OUT}/kernel-abl


if [ "${KERNEL_TARGET}" == "autoghgvm" ]; then
  ABL_IMAGE=LinuxLoader.efi
  DIST_ABL_IMAGE=LinuxLoader_${TARGET_BUILD_VARIANT}.efi
else
  ABL_IMAGE=unsigned_abl.elf
  DIST_ABL_IMAGE=unsigned_abl_${TARGET_BUILD_VARIANT}.elf
fi

if [ ! -e "${ANDROID_ABL_OUT_DIR}/abl-${TARGET_BUILD_VARIANT}/${ABL_IMAGE}" ] || \
    ! diff -q "${ANDROID_ABL_OUT_DIR}/abl-${TARGET_BUILD_VARIANT}/${ABL_IMAGE}" \
  "${ANDROID_KP_OUT_DIR}/abl/unsigned_abl_${TARGET_BUILD_VARIANT}.elf" ; then
  COPY_ABL_NEEDED=1
fi

if [ ! -e "${ANDROID_KP_OUT_DIR}/abl/unsigned_abl_${TARGET_BUILD_VARIANT}.elf" ] && \
   [ "${COPY_ABL_NEEDED}" == "1" ]; then
  RECOMPILE_ABL=1
fi

if [ "${RECOMPILE_ABL}" == "1" -o "${COPY_ABL_NEEDED}" == "1" ]; then
  rm -rf ${ANDROID_ABL_OUT_DIR}/abl-${TARGET_BUILD_VARIANT}
fi

################################################################################
if [ "${RECOMPILE_ABL}" == "1" ] && [ -n "${TARGET_BUILD_VARIANT}" ] && \
   [ "${KERNEL_TARGET}" != "autogvm" ] && [ "${KERNEL_TARGET}" != "autoghgvm" ]; then
  echo
  echo "  Recompiling edk2"
  echo "kpl-time-check edk2 start $(date +%H:%M:%S)"
    (
      cd "${ROOT_DIR}"

      ./tools/bazel run \
        --"//bootable/bootloader/edk2:target_build_variant=${TARGET_BUILD_VARIANT}" \
        "//msm-kernel:${KERNEL_TARGET}_${KERNEL_VARIANT}_abl_dist" \
        -- --dist_dir "${ANDROID_KP_OUT_DIR}/abl"
    )

  COPY_ABL_NEEDED=1
  echo "kpl-time-check edk2 end $(date +%H:%M:%S)"
fi

##################################oplus mixed build##############################################

if [ "${RECOMPILE_EXT_MODULE}" != "0" ]; then
    echo "kpl-time-check oplus DDK start $(date +%H:%M:%S)"
    for file in Image vmlinux System.map .config Module.symvers build_opts.txt; do
        cp ${ANDROID_KP_OUT_DIR}/dist/${file} ${ANDROID_KERNEL_OUT}/
    done
    echo
    echo "   build oplus external modules : ${CHIPSET_COMPANY}"
    (
      cd ${ROOT_DIR}
      set -x
      if [[ -f "oplus/config/modules.ext.oplus" && "$(cat oplus/config/modules.ext.oplus | wc -l)" -gt 0 ]]; then
        # setup build parameters before building external modules
        ./oplus/bazel/oplus_modules_variant.sh ${KERNEL_TARGET} ${KERNEL_VARIANT} "${OPLUS_FEATURES}"
        export CONFIG_OPLUS_FEATURE_MIXED_BUILD="y"
        export CONFIG_OPLUS_FEATURE_MIXED_VND=${CHIPSET_COMPANY}
        KBUILD_OPTIONS+=("CHIPSET_COMPANY=${CHIPSET_COMPANY}")
        KBUILD_OPTIONS+=("OPLUS_VND_BUILD_PLATFORM=${OPLUS_VND_BUILD_PLATFORM}")
        KBUILD_OPTIONS+=("OPLUS_FEATURE_BSP_DRV_VND_INJECT_TEST=${OPLUS_FEATURE_BSP_DRV_INJECT_TEST}")
        if [ -z "${EXT_MODULES}" ];then
            EXT_MODULES=$(cat oplus/config/modules.ext.oplus)
        fi
        EXT_MODULES=$EXT_MODULES\
        KBUILD_OPTIONS=${KBUILD_OPTIONS[@]} \
        OUT_DIR=${ANDROID_EXT_MODULES_OUT} \
        KERNEL_KIT=${ANDROID_KERNEL_OUT} \
        ./build/build_module.sh
      fi
    )
    EXT_MODULES=""
    COPY_NEEDED=1
    echo "kpl-time-check oplus DDK end $(date +%H:%M:%S)"
fi
##########################oplus add mixed build#############################################

################################################################################
if [ "${COPY_NEEDED}" == "1" ]; then
  echo "kpl-time-check kernel copy start $(date +%H:%M:%S)"
  if [ ! -e "${ANDROID_KP_OUT_DIR}" ]; then
    echo "!! kernel platform output directory doesn't exist. Bad path or output wasn't copied?"
    exit 1
  fi

  echo
  echo "  Preparing prebuilt folder ${ANDROID_KERNEL_OUT}"
  #build kernel will delete ${ANDROID_KP_OUT_DIR}/dist/ and lost oplus DDK ko
  #so move oplus module copy here
  set -x
  echo "mixedbuild oplus module copy"
  # copy oplus external modules to dist directory and append to the end of the vendor_dlkm.modules.load
  if [ -d ${ANDROID_KP_OUT_DIR}/../vendor/oplus ]; then
      find ${ANDROID_KP_OUT_DIR}/../vendor/oplus -name "*.ko" | xargs -i cp {} ${ANDROID_KP_OUT_DIR}/dist/
      find ${ANDROID_KP_OUT_DIR}/../vendor/oplus -name "*.ko" -printf "%f\n" > ${ANDROID_KP_OUT_DIR}/dist/oplus_modules_all
      cat ${ANDROID_KP_OUT_DIR}/dist/oplus_modules_all ${ROOT_DIR}/oplus/config/modules.vendor_boot.list.oplus | sort | uniq -u > ${ANDROID_KP_OUT_DIR}/dist/oplus_modules_vendor_dlkm

      if [ -e ${ANDROID_KP_OUT_DIR}/dist/vendor_dlkm.modules.load ]; then
         cat ${ANDROID_KP_OUT_DIR}/dist/oplus_modules_vendor_dlkm  >> ${ANDROID_KP_OUT_DIR}/dist/vendor_dlkm.modules.load
      fi

      if [ -e ${ANDROID_KP_OUT_DIR}/dist/modules.load ]; then
        cat ${ROOT_DIR}/oplus/config/modules.vendor_boot.list.oplus >> ${ANDROID_KP_OUT_DIR}/dist/modules.load
      fi
  fi
  set +x
  first_stage_kos=$(mktemp)
  if [ -e ${ANDROID_KP_OUT_DIR}/dist/modules.load ]; then
    cat ${ANDROID_KP_OUT_DIR}/dist/modules.load | \
      xargs -L 1 basename | \
      xargs -L 1 find ${ANDROID_KP_OUT_DIR}/dist/ -name > ${first_stage_kos}
  else
    find ${ANDROID_KP_OUT_DIR}/dist/ -name \*.ko > ${first_stage_kos}
  fi

  rm -f ${ANDROID_KERNEL_OUT}/*.ko ${ANDROID_KERNEL_OUT}/modules.*
  if [ -s "${first_stage_kos}" ]; then
    cp $(cat ${first_stage_kos}) ${ANDROID_KERNEL_OUT}/
  else
    echo "  WARNING!! No first stage modules found"
  fi

  if [ -e ${ANDROID_KP_OUT_DIR}/dist/modules.blocklist ]; then
    cp ${ANDROID_KP_OUT_DIR}/dist/modules.blocklist ${ANDROID_KERNEL_OUT}/modules.blocklist
  fi

  if [ -e ${ANDROID_KP_OUT_DIR}/dist/modules.load ]; then
    cp ${ANDROID_KP_OUT_DIR}/dist/modules.load ${ANDROID_KERNEL_OUT}/modules.load
  fi

  unprotected_dlkm_kos=$(mktemp)
  if [ -e ${ANDROID_KP_OUT_DIR}/dist/vendor_dlkm.modules.unprotectedlist ]; then
    cat ${ANDROID_KP_OUT_DIR}/dist/vendor_dlkm.modules.unprotectedlist | \
    tr " " "\n" | xargs -L 1 basename | \
    xargs -L 1 find ${ANDROID_KP_OUT_DIR}/dist/ -name > ${unprotected_dlkm_kos}
  else
    echo "  vendor_dlkm.modules.unprotectedlist file is not found or is empty"
  fi

  system_dlkm_kos=$(mktemp)
  if [ -s ${ANDROID_KP_OUT_DIR}/dist/system_dlkm.modules.load ]; then
    xargs -L 1 -a "${ANDROID_KP_OUT_DIR}/dist/system_dlkm.modules.load" basename | \
    sed -e "s|^|${ANDROID_KP_OUT_DIR}/dist/|g" | \
    grep -v -F -f ${unprotected_dlkm_kos} > "$system_dlkm_kos"
  else
    echo "  system_dlkm_kos.modules.load file is not found or is empty"
  fi

  rm -rf ${ANDROID_KERNEL_OUT}/system_dlkm/*
  rm -rf ${ANDROID_PRODUCT_OUT}/system_dlkm*
  system_dlkm_archive="${ANDROID_KP_OUT_DIR}/dist/system_dlkm_staging_archive.tar.gz"
  if [ -e "$system_dlkm_archive" ]; then
    mkdir -p "${ANDROID_KERNEL_OUT}/system_dlkm/"
    # Unzip the system_dlkm staging tar copied from kernel_platform to system_dlkm out directory
    tar -xf "$system_dlkm_archive" -C "${ANDROID_KERNEL_OUT}/system_dlkm/"
  else
    echo "  WARNING!! No system_dlkm (second stage) modules found"
  fi

  rm -f ${ANDROID_KERNEL_OUT}/vendor_dlkm/*.ko ${ANDROID_KERNEL_OUT}/vendor_dlkm/modules.*
  second_stage_kos=$(find ${ANDROID_KP_OUT_DIR}/dist/ -name \*.ko | \
    grep -v -F -f ${first_stage_kos} -f ${system_dlkm_kos} || true)
  if [ -n "${second_stage_kos}" ]; then
    mkdir -p ${ANDROID_KERNEL_OUT}/vendor_dlkm
    cp ${second_stage_kos} ${ANDROID_KERNEL_OUT}/vendor_dlkm
  else
    echo "  WARNING!! No vendor_dlkm (second stage) modules found"
  fi

  if [ -e ${ANDROID_KP_OUT_DIR}/dist/vendor_dlkm.modules.blocklist ]; then
    cp ${ANDROID_KP_OUT_DIR}/dist/vendor_dlkm.modules.blocklist \
      ${ANDROID_KERNEL_OUT}/vendor_dlkm/modules.blocklist
  fi

  if [ -e ${ANDROID_KP_OUT_DIR}/dist/vendor_dlkm.modules.load ]; then
    cp ${ANDROID_KP_OUT_DIR}/dist/vendor_dlkm.modules.load \
      ${ANDROID_KERNEL_OUT}/vendor_dlkm/modules.load
  fi

  if [ -e ${ANDROID_KP_OUT_DIR}/dist/system_dlkm.modules.blocklist ]; then
    cp ${ANDROID_KP_OUT_DIR}/dist/system_dlkm.modules.blocklist \
      ${ANDROID_KERNEL_OUT}/vendor_dlkm/system_dlkm.modules.blocklist
  fi

  if [ -e "${ANDROID_KP_OUT_DIR}/dist/board_extra_cmdline_${KERNEL_TARGET}_${KERNEL_VARIANT}" ];
  then
    cp "${ANDROID_KP_OUT_DIR}/dist/board_extra_cmdline_${KERNEL_TARGET}_${KERNEL_VARIANT}" \
      "${ANDROID_KERNEL_OUT}/extra_cmdline"
  fi

  if [ -e "${ANDROID_KP_OUT_DIR}/dist/board_extra_bootconfig_${KERNEL_TARGET}_${KERNEL_VARIANT}" ];
  then
    cp "${ANDROID_KP_OUT_DIR}/dist/board_extra_bootconfig_${KERNEL_TARGET}_${KERNEL_VARIANT}" \
      "${ANDROID_KERNEL_OUT}/extra_bootconfig"
  fi

  files=(
    "Image"
    "vmlinux"
    "System.map"
    ".config"
    "Module.symvers"
    "kernel-uapi-headers.tar.gz"
    "build_opts.txt"
  )

  cp "${files[@]/#/${ANDROID_KP_OUT_DIR}/dist/}" ${ANDROID_KERNEL_OUT}/

  rm -rf ${ANDROID_KERNEL_OUT}/kp-dtbs
  mkdir ${ANDROID_KERNEL_OUT}/kp-dtbs
  cp ${ANDROID_KP_OUT_DIR}/dist/*.dtb* ${ANDROID_KERNEL_OUT}/kp-dtbs/

  if [ -f "${ANDROID_KP_OUT_DIR}/dist/dpm.img" ]; then
    cp "${ANDROID_KP_OUT_DIR}/dist/dpm.img" "${ANDROID_KERNEL_OUT}/kp-dtbs/"
  fi

  rm -rf ${ANDROID_KERNEL_OUT}/host
  cp -r ${ANDROID_KP_OUT_DIR}/host ${ANDROID_KERNEL_OUT}/

  rm -rf "${ANDROID_KERNEL_OUT}/debug"
  debug_tar="${ANDROID_KP_OUT_DIR}/dist/${KERNEL_TARGET}_${KERNEL_VARIANT}_debug.tar.gz"
  if [ -f "$debug_tar" ]; then
    mkdir -p "${ANDROID_KERNEL_OUT}/debug"
    tar -C "${ANDROID_KERNEL_OUT}/debug" -xf "$debug_tar"
  fi

  if [ -z "${KERNEL_VARIANT}" ]; then
    KERNEL_VARIANT=${2}
    echo "$KERNEL_VARIANT" > ${ANDROID_KERNEL_OUT}/_variant
  fi

  rm ${first_stage_kos}
  rm ${unprotected_dlkm_kos}
  rm ${system_dlkm_kos}
  echo "kpl-time-check kernel copy end $(date +%H:%M:%S)"
fi


################################################################################
if [ "${COPY_ABL_NEEDED}" == "1" ]; then
  ABL_BUILD_VARIANT=("${TARGET_BUILD_VARIANT}")
  [ -z "${ABL_BUILD_VARIANT}" ] && ABL_BUILD_VARIANT=("userdebug" "user")
  for variant in "${ABL_BUILD_VARIANT[@]}"
  do
    if [ "${KERNEL_TARGET}" == "autoghgvm" ]; then
      file_list="LinuxLoader_${variant}.debug LinuxLoader_${variant}.efi"
    else
      file_list="LinuxLoader_${variant}.debug unsigned_abl_${variant}.elf"
    fi
    for file in ${file_list}; do
      if [ -e ${ANDROID_KP_OUT_DIR}/abl/${file} ]; then
        if [ ! -e "${ANDROID_ABL_OUT_DIR}/abl-${variant}" ]; then
          mkdir -p ${ANDROID_ABL_OUT_DIR}/abl-${variant}
        fi
        FILE_NAME=$(echo ${file} | sed 's/_'${variant}'//g')
        cp ${ANDROID_KP_OUT_DIR}/abl/${file} ${ANDROID_ABL_OUT_DIR}/abl-${variant}/${FILE_NAME}
      fi
    done
  done
fi

################################################################################

if [ -n "${ANDROID_PRODUCT_OUT}" ] && [ -n "${ANDROID_BUILD_TOP}" ]; then
  ANDROID_TO_KP=$(rel_path ${ROOT_DIR} ${ANDROID_BUILD_TOP})
  KP_TO_ANDROID=$(rel_path ${ANDROID_BUILD_TOP} ${ROOT_DIR})
  if [[ "${ANDROID_TO_KP}" != "kernel_platform" ]] ; then
    echo "!! Kernel platform source is currently only supported to be in ${ANDROID_BUILD_TOP}/kernel_platform"
    echo "!! Move kernel platform source or try creating a symlink."
    exit 1
  fi

  ################################################################################
  echo
  echo "  cleaning up kernel_platform tree for Android"

  set -x
  find ${ROOT_DIR} \( -name Android.mk -o -name Android.bp \) \
      -a -not -path ${ROOT_DIR}/common/Android.bp -a -not -path ${ROOT_DIR}/msm-kernel/Android.bp \
      -delete
  set +x

  ################################################################################
  echo
  echo "  Preparing UAPI headers for Android"
  echo "kpl-time-check Preparing UAPI headers start $(date +%H:%M:%S)"

  if [ ! -e ${ANDROID_KERNEL_OUT}/kernel-uapi-headers.tar.gz ]; then
    echo "!! Did not find exported kernel UAPI headers"
    echo "!! was kernel platform compiled with SKIP_CP_KERNEL_HDR?"
    exit 1
  fi

  rm -rf ${ANDROID_KERNEL_OUT}/kernel-uapi-headers
  mkdir ${ANDROID_KERNEL_OUT}/kernel-uapi-headers
  tar xf ${ANDROID_KERNEL_OUT}/kernel-uapi-headers.tar.gz \
      -C ${ANDROID_KERNEL_OUT}/kernel-uapi-headers

  set -x
  ${ROOT_DIR}/build/android/export_headers.py \
    ${ANDROID_KERNEL_OUT}/kernel-uapi-headers/usr/include \
    ${ANDROID_BUILD_TOP}/bionic/libc/kernel/uapi \
    ${ANDROID_KERNEL_OUT}/kernel-headers \
    arm64
  set +x

  echo "kpl-time-check Preparing UAPI headers end $(date +%H:%M:%S)"
  # Intentionally aligned with Android's location in order to have a consistent location for output,
  # This isn't necessary from technical point, but helps to avoid making Android build system
  # redundantly do the same thing.
  ANDROID_EXT_MODULES_COMMON_OUT=${ANDROID_PRODUCT_OUT}/obj/DLKM_OBJ
  ANDROID_EXT_MODULES_OUT=${ANDROID_EXT_MODULES_COMMON_OUT}/kernel_platform

  ################################################################################
  echo
  echo "  setting up Android tree for compiling modules"
  echo "kpl-time-check setting up Android tree start $(date +%H:%M:%S)"
  (
    cd ${ROOT_DIR}
    set -x
    OUT_DIR=${ANDROID_EXT_MODULES_OUT} \
    KERNEL_KIT=${ANDROID_KERNEL_OUT} \
    ./build/build_module.sh
    set +x
  )
  echo "kpl-time-check setting up Android tree end $(date +%H:%M:%S)"

  ################################################################################
  echo
  if [ "${RECOMPILE_TECHPACK_DTBO}" != "0" ]; then
    echo "  Compiling vendor devicetree overlays"
    echo "kpl-time-check Compiling vendor devicetree start $(date +%H:%M:%S)"
        for project in $(cd ${ANDROID_BUILD_TOP} && find -L vendor/ -type d -name "*-devicetree")
        do
            if [ ! -e "${project}/Makefile" ]; then
              echo "${project} does not have expected build configuration files, skipping..."
              continue
            fi

            echo "Building ${project}"

            (
              cd ${ROOT_DIR}
              set -x
              OUT_DIR=${ANDROID_EXT_MODULES_OUT} \
              EXT_MODULES="${KP_TO_ANDROID}/${project}" \
              KERNEL_KIT=${ANDROID_KERNEL_OUT} \
              ./build/build_module.sh dtbs
              set +x
            )
        done
        echo "kpl-time-check Compiling vendor devicetree end $(date +%H:%M:%S)"
  fi
  ################################################################################
  echo
  if [ "${RECOMPILE_MERGE_DTBS}" != "0" ]; then
    echo "  Merging vendor devicetree overlays"

    echo "kpl-time-check Merging vendor devicetree start $(date +%H:%M:%S)"
    rm -rf ${ANDROID_KERNEL_OUT}/dtbs
    mkdir ${ANDROID_KERNEL_OUT}/dtbs

    (
        cd ${ROOT_DIR}
        OUT_DIR=${ANDROID_EXT_MODULES_OUT} ./build/android/merge_dtbs.sh \
          ${ANDROID_KERNEL_OUT}/kp-dtbs \
          ${ANDROID_EXT_MODULES_COMMON_OUT} \
          ${ANDROID_KERNEL_OUT}/dtbs
    )
    echo "kpl-time-check Merging vendor devicetree end $(date +%H:%M:%S)"
  fi
fi
if [ ! -d "${ANDROID_BUILD_TOP}/out" ];then
    mkdir -p ${ANDROID_BUILD_TOP}/out
fi
cp -r ${ANDROID_KP_OUT_DIR}/* ${ANDROID_BUILD_TOP}/out/
