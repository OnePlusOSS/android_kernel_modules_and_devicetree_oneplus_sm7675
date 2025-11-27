#
# Makefile for the Synaptics TCM touchscreen driver.
#

# Each configuration option enables a list of files.

oplus_bsp_tp_hbp_syna_s3910-y := syna_tcm2.o
oplus_bsp_tp_hbp_syna_s3910-y += syna_tcm2_sysfs.o
oplus_bsp_tp_hbp_syna_s3910-y += tcm/synaptics_touchcom_core_v1.o
oplus_bsp_tp_hbp_syna_s3910-y += tcm/synaptics_touchcom_core_v2.o
oplus_bsp_tp_hbp_syna_s3910-y += tcm/synaptics_touchcom_func_base.o
oplus_bsp_tp_hbp_syna_s3910-y += tcm/synaptics_touchcom_func_touch.o
oplus_bsp_tp_hbp_syna_s3910-y += tcm/synaptics_touchcom_func_reflash.o
oplus_bsp_tp_hbp_syna_s3910-y += tcm/synaptics_touchcom_func_romboot.o

obj-$(CONFIG_TOUCHSCREEN_HBP_SYNA_S3910) += oplus_bsp_tp_hbp_syna_s3910.o
