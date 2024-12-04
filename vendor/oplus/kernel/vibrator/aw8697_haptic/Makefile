#for AWINIC AW8697 Haptic
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

obj-$(CONFIG_AW8697_HAPTIC) += aw8697.o
obj-$(CONFIG_AW8697_HAPTIC)	+= haptic.o
haptic-objs			:= aw8692x.o aw869xx.o haptic_hv.o

obj-$(CONFIG_HAPTIC_FEEDBACK)	+= haptic_feedback.o