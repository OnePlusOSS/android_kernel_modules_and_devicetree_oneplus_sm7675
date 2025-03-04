ifeq ($(DEVICE_MODULES_PATH),)
DEVICE_MODULES_PATH = $(srctree)
else
endif

ifeq ($(subst ",,$(CONFIG_MTK_SENSOR_ARCHITECTURE)),1.0)
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensors-1.0/hwmon/include
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensors-1.0/sensorHub/inc_v1
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/scp/$(CONFIG_MTK_PLATFORM)
subdir-ccflags-y += -D _OPLUS_SENSOR_HUB_VI
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensors-1.0/oplus_virtual_sensor/platform/sensor_cmd
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensors-1.0/oplus_virtual_sensor/platform/sensor_device
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensors-1.0/oplus_virtual_sensor/platform/sensor_event
else
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensor/2.0/mtk_nanohub
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensor/2.0/mtk_nanohub/nanohub
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensor/2.0/core
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/scp/$(CONFIG_MTK_PLATFORM)
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/scp/include
ifeq ($(CONFIG_MTK_TINYSYS_SCP_CM4_SUPPORT),y)
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/scp/cm4
else
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/scp/rv
endif
subdir-ccflags-y += -D _OPLUS_SENSOR_HUB_V2
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensor/2.0/oplus_virtual_sensor/platform/sensor_cmd
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensor/2.0/oplus_virtual_sensor/platform/sensor_device
subdir-ccflags-y += -I$(DEVICE_MODULES_PATH)/drivers/misc/mediatek/sensor/2.0/oplus_virtual_sensor/platform/sensor_event
endif


ifeq ($(CONFIG_OPLUS_VIRTUAL_SENSOR),m)
subdir-ccflags-y += -D _USE_VIRTUAL_SENSOR_AS_MODULE
obj-$(CONFIG_OPLUS_VIRTUAL_SENSOR) += virtual_sensor.o
ifeq ($(CONFIG_OPLUS_FEATURE_LAY_DETECT), m)
subdir-ccflags-y += -D CONFIG_OPLUS_FEATURE_LAY_DETECT
endif
ifeq ($(CONFIG_OPLUS_FEATURE_PALM_DETECT), m)
subdir-ccflags-y += -D CONFIG_OPLUS_FEATURE_PALM_DETECT
endif
ifeq ($(CONFIG_OPLUS_FEATURE_BACK_TAP_DETECT), m)
subdir-ccflags-y += -D CONFIG_OPLUS_FEATURE_BACK_TAP_DETECT
endif
ifeq ($(CONFIG_OPLUS_FEATURE_ROTATION_DETECT), m)
subdir-ccflags-y += -D CONFIG_OPLUS_FEATURE_ROTATION_DETECT
endif
ifeq ($(CONFIG_OPLUS_FEATURE_ELEVATOR_DETECT), m)
subdir-ccflags-y += -D CONFIG_OPLUS_FEATURE_ELEVATOR_DETECT
endif
ifeq ($(CONFIG_OPLUS_FEATURE_ACTIVITY_RECOGNITION), m)
subdir-ccflags-y += -D CONFIG_OPLUS_FEATURE_ACTIVITY_RECOGNITION
endif
ifeq ($(CONFIG_OPLUS_FEATURE_PHONE_PROX), m)
subdir-ccflags-y += -D CONFIG_OPLUS_FEATURE_PHONE_PROX
endif
ifeq ($(CONFIG_OPLUS_FEATURE_GESTURE_PROX), m)
subdir-ccflags-y += -D CONFIG_OPLUS_FEATURE_GESTURE_PROX
endif
ifeq ($(CONFIG_OPLUS_FEATURE_AMBIENTE_PROX), m)
subdir-ccflags-y += -D CONFIG_OPLUS_FEATURE_AMBIENTE_PROX
endif
else
obj-y += virtual_sensor.o
endif # CONFIG_OPLUS_VIRTUAL_SENSOR end


obj-y += platform/
obj-y += sensors/
