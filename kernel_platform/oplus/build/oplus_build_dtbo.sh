#!/bin/bash

source kernel_platform/oplus/build/oplus_setup.sh $1 $2
init_build_environment

function build_kernel_cmd() {
    build_start_time

    if [ "${variants_type}" == "consolidate" ]; then
       LTO=thin RECOMPILE_KERNEL=0  COPY_NEEDED=0 RECOMPILE_EXT_MODULE=0 \
       ./kernel_platform/build/android/prepare_vendor.sh $variants_platform $variants_type 2>&1 |tee ${TOPDIR}/LOGDIR/build_$(date +"%Y_%m_%d_%H_%M_%S").log
    else
       RECOMPILE_KERNEL=0  COPY_NEEDED=0 RECOMPILE_EXT_MODULE=0 \
       ./kernel_platform/build/android/prepare_vendor.sh $variants_platform $variants_type 2>&1 |tee ${TOPDIR}/LOGDIR/build_$(date +"%Y_%m_%d_%H_%M_%S").log
    fi
    build_end_time
}


build_kernel_cmd
