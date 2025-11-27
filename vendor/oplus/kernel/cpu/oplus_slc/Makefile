# SPDX-License-Identifier: GPL-2.0-only

GCOV_PROFILE := y
ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/slbc
ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/include/mt-plat

obj-$(CONFIG_OPLUS_FEATURE_SLC) += oplus_slc.o
oplus_slc-y := oplus_slc_main.o osml.o
