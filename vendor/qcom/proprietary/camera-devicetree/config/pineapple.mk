dtbo-$(CONFIG_ARCH_PINEAPPLE)	:= pineapple-camera.dtbo
#dtbo-$(CONFIG_ARCH_PINEAPPLE)	+= pineapple-camera-v2.dtbo \
#									pineapple-camera-sensor-cdp.dtbo \
#									pineapple-camera-sensor-mtp.dtbo \
#									pineapple-camera-sensor-hdk.dtbo \
#									pineapple-camera-sensor-qrd.dtbo
#OPLUS_DTS_OVERLAY start
dtbo-$(CONFIG_ARCH_PINEAPPLE) += oplus/waffle-camera-overlay.dtbo \

dtbo-$(CONFIG_ARCH_PINEAPPLE) += oplus/waffle-camera-overlay-evb.dtbo \

dtbo-$(CONFIG_ARCH_PINEAPPLE) += oplus/pangu-camera-overlay.dtbo \

dtbo-$(CONFIG_ARCH_PINEAPPLE) += oplus/enzo-camera-overlay.dtbo \

dtbo-$(CONFIG_ARCH_PINEAPPLE) += oplus/pangu-camera-overlay-evb.dtbo \

dtbo-$(CONFIG_ARCH_PINEAPPLE) += oplus/pangu-camera-overlay-t0.dtbo \

dtbo-$(CONFIG_ARCH_PINEAPPLE) += oplus/caihong-camera-overlay.dtbo \

dtbo-$(CONFIG_ARCH_PINEAPPLE) += oplus/corvette-camera-overlay.dtbo \

dtbo-$(CONFIG_ARCH_CLIFFS)    += oplus/divo-camera-overlay.dtbo \

#OPLUS_DTS_OVERLAY end

dtbo-$(CONFIG_ARCH_CLIFFS)    += cliffs-camera.dtbo
#OPLUS_DTS_OVERLAY start
dtbo-$(CONFIG_ARCH_CLIFFS)    += oplus/audi-camera-overlay.dtbo \

dtbo-$(CONFIG_ARCH_CLIFFS)    += oplus/bale-camera-overlay.dtbo \

dtbo-$(CONFIG_ARCH_CLIFFS)    += oplus/baleC-camera-overlay.dtbo \

dtbo-$(CONFIG_ARCH_PINEAPPLE) += oplus/kaitian-camera-overlay.dtbo \
#OPLUS_DTS_OVERLAY end
#dtbo-$(CONFIG_ARCH_CLIFFS)	+= cliffs-camera-sensor-cdp.dtbo \
#								cliffs-camera-sensor-mtp.dtbo \
#								cliffs-camera-sensor-qrd.dtbo
