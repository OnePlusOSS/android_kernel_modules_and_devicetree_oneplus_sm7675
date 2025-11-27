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

obj-$(CONFIG_SIH_VIBRATOR) += si_haptic.o
si_haptic-objs             := haptic.o sih688x_func_config.o haptic_mid.o sih688x.o sih688x_reg.o haptic_misc.o haptic_regmap.o