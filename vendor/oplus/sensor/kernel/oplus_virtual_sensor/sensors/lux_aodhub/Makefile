ifeq ($(DEVICE_MODULES_PATH),)
DEVICE_MODULES_PATH = $(srctree)
else
endif

ifeq ($(subst ",,$(CONFIG_MTK_SENSOR_ARCHITECTURE)),1.0)
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensors-1.0/oplus_virtual_sensor
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensors-1.0/oplus_virtual_sensor/platform/sensor_cmd
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensors-1.0/oplus_virtual_sensor/platform/sensor_device
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensors-1.0/oplus_virtual_sensor/platform/sensor_event
else
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensor/2.0/oplus_virtual_sensor
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensor/2.0/oplus_virtual_sensor/platform/sensor_cmd
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensor/2.0/oplus_virtual_sensor/platform/sensor_device
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensor/2.0/oplus_virtual_sensor/platform/sensor_event
endif

obj-$(CONFIG_OPLUS_FEATURE_LUX_AOD)	:=  lux_aodhub.o
