#
# Makefile for the haptic drivers.
#
ifeq ($(DEVICE_MODULES_PATH),)
DEVICE_MODULES_PATH = $(srctree)
else
LINUXINCLUDE := $(DEVCIE_MODULES_INCLUDE) $(LINUXINCLUDE)
endif

ccflags-y += -DOPLUS_FEATURE_CHG_BASIC
ifeq ($(CONFIG_OPLUS_CHARGER_MTK),y)
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/include/mt-plat
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/include
endif

oplus_haptic-y += haptic_common/haptic_common_driver.o
oplus_haptic-$(CONFIG_AW_HAPTIC) += aw_haptic/haptic_hv.o
oplus_haptic-$(CONFIG_AW_HAPTIC) += aw_haptic/aw8692x.o
oplus_haptic-$(CONFIG_AW_HAPTIC) += aw_haptic/aw869xx.o
oplus_haptic-$(CONFIG_AW_HAPTIC) += aw_haptic/aw8693xs.o
oplus_haptic-$(CONFIG_SIH_HAPTIC) += si_haptic/haptic.o
oplus_haptic-$(CONFIG_SIH_HAPTIC) += si_haptic/sih688x_func_config.o
oplus_haptic-$(CONFIG_SIH_HAPTIC) += si_haptic/haptic_mid.o
oplus_haptic-$(CONFIG_SIH_HAPTIC) += si_haptic/sih688x.o
oplus_haptic-$(CONFIG_SIH_HAPTIC) += si_haptic/sih688x_reg.o
oplus_haptic-$(CONFIG_SIH_HAPTIC) += si_haptic/haptic_regmap.o

obj-$(CONFIG_OPLUS_HAPTIC_COMMON) += oplus_haptic.o
