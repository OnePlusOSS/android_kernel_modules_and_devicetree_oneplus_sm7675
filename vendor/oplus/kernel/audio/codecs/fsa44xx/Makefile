# FSA4480 object
ifeq ($(DEVICE_MODULES_PATH),)
    DEVICE_MODULES_PATH = $(srctree)
endif
ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/typec/mux
ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/typec/tcpc/inc
obj-$(CONFIG_SND_SOC_FSA) += fsa4480-i2c.o
