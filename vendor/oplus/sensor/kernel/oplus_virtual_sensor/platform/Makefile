ifeq ($(DEVICE_MODULES_PATH),)
DEVICE_MODULES_PATH := $(srctree)
else
endif

ifeq ($(subst ",,$(CONFIG_MTK_SENSOR_ARCHITECTURE)),1.0)
ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensors-1.0/oplus_virtual_sensor
ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensors-1.0/hwmon/include
ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensors-1.0/sensorHub/inc_v1
else
ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensor/2.0/mtk_nanohub
ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensor/2.0/mtk_nanohub/nanohub
ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensor/2.0/core
endif
ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/scp/$(CONFIG_MTK_PLATFORM)

obj-y   +=  sensor_event/
obj-y   +=  sensor_device/
obj-y   +=  sensor_cmd/
