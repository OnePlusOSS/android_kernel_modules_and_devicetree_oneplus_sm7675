# SPDX-License-Identifier: GPL-2.0

$(info "CONFIG_OPLUS_DEVICE_INFO_MTK_PLATFORM is $(CONFIG_OPLUS_DEVICE_INFO_MTK_PLATFORM)")

ifeq ($(CONFIG_OPLUS_DEVICE_INFO_MTK_PLATFORM),y)
    ccflags-y += -DCFG_OPLUS_ARCH_IS_MTK
    ccflags-y += -I$(srctree)/drivers/misc/mediatek/scp/include
else ifeq ($(CONFIG_OPLUS_DEVICE_INFO_MTK_PLATFORM),m)
    ccflags-y += -DCFG_OPLUS_ARCH_IS_MTK
    ccflags-y += -I$(srctree)/drivers/misc/mediatek/scp/include
else
    ccflags-y += -DCFG_OPLUS_ARCH_IS_QCOM
endif

obj-$(CONFIG_OPLUS_FEATURE_TRACE_SENSOR) += oplus_trace_sensor.o

