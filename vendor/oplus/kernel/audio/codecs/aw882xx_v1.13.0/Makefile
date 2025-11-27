#for AWINIC AW882XX Smart PA
#MODULE_NAME = snd-soc-aw882xx
ifeq ($(DEVICE_MODULES_PATH),)
    DEVICE_MODULES_PATH = $(srctree)
endif

subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/sound/soc/mediatek/common
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/sound/soc/mediatek/audio_dsp
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/audio_ipi/include
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/include
subdir-ccflags-y += -I$(srctree)/drivers/base

# debugging support (also enables trace_printk)
ccflags-y += -Werror
ccflags-y += -DOPLUS_ARCH_EXTENDS
ccflags-y += -DOPLUS_FEATURE_SPEAKER_MUTE
ccflags-y += $(call cc-option,-Wno-date-time,)
ccflags-y += $(call cc-option,-Wno-visibility,)
ccflags-y += $(call cc-option,-Wno-incompatible-pointer-types,)

snd-soc-aw882xx-objs += aw882xx_bin_parse.o
snd-soc-aw882xx-objs += aw882xx_calib.o
snd-soc-aw882xx-objs += aw882xx_device.o
snd-soc-aw882xx-objs += aw882xx_dsp.o
snd-soc-aw882xx-objs += aw882xx_init.o
snd-soc-aw882xx-objs += aw882xx_monitor.o
snd-soc-aw882xx-objs += aw882xx_spin.o
snd-soc-aw882xx-objs += aw882xx.o

obj-m += snd-soc-aw882xx.o
