LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES   		  := $(wildcard $(LOCAL_PATH)/**/*) $(wildcard $(LOCAL_PATH)/*)
LOCAL_MODULE              := oplus_sync_fence.ko
LOCAL_MODULE_KBUILD_NAME  := oplus_sync_fence.ko
LOCAL_MODULE_TAGS         := optional
LOCAL_MODULE_DEBUG_ENABLE := true
LOCAL_MODULE_DDK_BUILD 	  := true
LOCAL_MODULE_PATH         := $(KERNEL_MODULES_OUT)

BOARD_VENDOR_KERNEL_MODULES += $(LOCAL_MODULE_PATH)/$(LOCAL_MODULE)

include $(TOP)/device/qcom/common/dlkm/Build_external_kernelmodule.mk
