ifeq ($(DEVICE_MODULES_PATH),)
DEVICE_MODULES_PATH = $(srctree)
else
endif

ifeq ($(subst ",,$(CONFIG_MTK_SENSOR_ARCHITECTURE)),1.0)
ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensors-1.0/accelerometer/inc
ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensors-1.0/hwmon/include
ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensors-1.0/sensorHub/inc_v1
ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/scp/$(CONFIG_MTK_PLATFORM)
ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/scp/cm4
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/scp
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/scp/include
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/scp/cm4
else
# sensor 2.0 start
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensor/2.0/mtk_nanohub
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensor/2.0/mtk_nanohub/nanohub
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensor/2.0/core
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/scp/$(CONFIG_MTK_PLATFORM)
subdir-ccflags-y += -D CONFIG_OPLUS_SENSOR_MTK68XX
ifeq ($(findstring k419, $(TARGET_PRODUCT)), k419)
subdir-ccflags-y += -D LINUX_KERNEL_VERSION_419
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/scp/include
endif
ifeq ($(CONFIG_MTK_TINYSYS_SCP_CM4_SUPPORT),y)
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/scp/cm4
else
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/scp/rv
endif

endif
# sensor 2.0 end

ifeq ($(CONFIG_OPLUS_SENSOR_DEVINFO_V2),m)
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/scp/include
obj-$(CONFIG_OPLUS_SENSOR_DEVINFO_V2) += sensor_devinfo_v2.o
else
obj-$(CONFIG_NANOHUB)	+= sensor_devinfo.o
endif
obj-$(CONFIG_OPLUS_SENSOR_FB_MTK) += oplus_sensor_feedback/
