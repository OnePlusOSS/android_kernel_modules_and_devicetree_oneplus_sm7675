#!/bin/bash

source kernel_platform/oplus/build/oplus_setup.sh $1 $2
init_build_environment

function get_prebuild_image() {
    mkdir -p ${ORIGIN_IMAGE}/qcom/
    mkdir -p ${ORIGIN_IMAGE}/mtk/
    IMAGE_SERVER="xxx"
    wget ${IMAGE_SERVER}/compile.ini  -O ${ORIGIN_IMAGE}/compile.ini
    OFP_DRI=`cat ${ORIGIN_IMAGE}/compile.ini | grep "ofp_folder =" | awk '{print $3 }'`
    wget ${IMAGE_SERVER}/${OFP_DRI}/IMAGES/vendor_boot.img -O ${ORIGIN_IMAGE}/qcom/vendor_boot.img
    wget ${IMAGE_SERVER}/${OFP_DRI}/IMAGES/vendor_dlkm.img -O ${ORIGIN_IMAGE}/qcom/vendor_dlkm.img
    IMAGE_SERVER="xxx"
    wget ${IMAGE_SERVER}/compile.ini  -O ${ORIGIN_IMAGE}/compile.ini
    OFP_DRI=`cat ${ORIGIN_IMAGE}/compile.ini | grep "ofp_folder =" | awk '{print $3 }'`
    wget ${IMAGE_SERVER}/${OFP_DRI}/IMAGES/vendor_boot.img -O ${ORIGIN_IMAGE}/mtk/vendor_boot.img
    wget ${IMAGE_SERVER}/${OFP_DRI}/IMAGES/vendor_dlkm.img -O ${ORIGIN_IMAGE}/mtk/vendor_dlkm.img
}

get_vendor_boot_ko() {
    echo "get_vendor_boot_ko"
    PLATFORM=$1
    rm -rf ${VENDOR_BOOT_TMP_IMAGE}/*
    mkdir -p ${IMAGE_OUT}/${PLATFORM}/
    boot_mkargs=$(${PYTHON_TOOL} ${UNPACK_BOOTIMG_TOOL} --boot_img ${ORIGIN_IMAGE}/${PLATFORM}/vendor_boot.img --out ${VENDOR_BOOT_TMP_IMAGE}/origin --format=mkbootimg)
    index="00"
    for index in  $index
    do
        echo " index  $index "
        mv ${VENDOR_BOOT_TMP_IMAGE}/origin/vendor_ramdisk${index} ${VENDOR_BOOT_TMP_IMAGE}/vendor_ramdisk${index}.lz4
        ${LZ4} -d ${VENDOR_BOOT_TMP_IMAGE}/vendor_ramdisk${index}.lz4
        rm ${VENDOR_BOOT_TMP_IMAGE}/vendor_ramdisk${index}.lz4
        mkdir -p ${VENDOR_BOOT_TMP_IMAGE}/ramdisk${index}
        mv ${VENDOR_BOOT_TMP_IMAGE}/vendor_ramdisk${index} ${VENDOR_BOOT_TMP_IMAGE}/ramdisk${index}/vendor_ramdisk${index}
        pushd  ${VENDOR_BOOT_TMP_IMAGE}/ramdisk${index}
        ${CPIO} -idu < ${VENDOR_BOOT_TMP_IMAGE}/ramdisk${index}/vendor_ramdisk${index}

        popd
        rm ${VENDOR_BOOT_TMP_IMAGE}/ramdisk${index}/vendor_ramdisk${index}
        cp ${VENDOR_BOOT_TMP_IMAGE}/ramdisk00/lib/modules/*.ko ${IMAGE_OUT}/${PLATFORM}/
    done
}

get_vendor_dlkm_erofs_ko() {
    echo "get_vendor_dlkm_erofs_ko"
    PLATFORM=$1
    rm -rf ${VENDOR_DLKM_TMP_IMAGE}/*
    mkdir -p ${VENDOR_DLKM_TMP_IMAGE}
    ${SIMG2IMG} ${ORIGIN_IMAGE}/${PLATFORM}/vendor_dlkm.img  ${VENDOR_DLKM_TMP_IMAGE}/vendor_dlkm.img
    ${TOOLS}/erofs_unpack.sh ${VENDOR_DLKM_TMP_IMAGE}/vendor_dlkm.img  ${VENDOR_DLKM_TMP_IMAGE}/mnt ${VENDOR_DLKM_TMP_IMAGE}/vendor_dlkm
    cp ${VENDOR_DLKM_TMP_IMAGE}/vendor_dlkm/lib/modules/*.ko ${IMAGE_OUT}/${PLATFORM}/
}

build_start_time
get_prebuild_image
get_vendor_boot_ko qcom
get_vendor_dlkm_erofs_ko qcom
get_vendor_boot_ko mtk
get_vendor_dlkm_erofs_ko mtk
print_end_help
build_end_time