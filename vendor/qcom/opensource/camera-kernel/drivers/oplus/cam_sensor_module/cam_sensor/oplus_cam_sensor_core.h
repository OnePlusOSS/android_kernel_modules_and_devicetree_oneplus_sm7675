/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017-2018, The Linux Foundation. All rights reserved.
 */

#ifndef _OPLUS_CAM_SENSOR_CORE_H_
#define _OPLUS_CAM_SENSOR_CORE_H_
#include "cam_sensor_dev.h"

#define CAM_IMX615_SENSOR_ID 0x615
#define CAM_IMX06A_SENSOR_ID 0xa18a
#define CAM_IMX471_SENSOR_ID 0x0471

/* vendor_id id is 512(0x0200),it is short module if vendor_id <= 287(0x011f),it is long(0x011f) or long(0x010f) module*/
#define CAM_S5KJN5_SENSOR_ID 0x38E5
#define S5KJN5_SHORT_SENSOR_ID  511
#define S5KJN5_SHORT_VENDOR_ID  511

struct cam_sensor_i2c_reg_setting_array {
	struct cam_sensor_i2c_reg_array reg_setting[CAM_OEM_INITSETTINGS_SIZE_MAX];
	unsigned short size;
	enum camera_sensor_i2c_type addr_type;
	enum camera_sensor_i2c_type data_type;
	unsigned short delay;
};


struct cam_sensor_settings {
	struct cam_sensor_i2c_reg_setting_array streamoff;
	struct cam_sensor_i2c_reg_setting_array imx615_setting;
	struct cam_sensor_i2c_reg_setting_array imx615_setting_fab2;
	struct cam_sensor_i2c_reg_setting_array imx766_setting;
	struct cam_sensor_i2c_reg_setting_array imx709_setting;
	struct cam_sensor_i2c_reg_setting_array imx709_aon_irq_setting;
	struct cam_sensor_i2c_reg_setting_array imx709_aon_irq_he_clr_setting;
	struct cam_sensor_i2c_reg_setting_array imx581_setting;
	struct cam_sensor_i2c_reg_setting_array imx989_setting;
	struct cam_sensor_i2c_reg_setting_array imx890_setting;
	struct cam_sensor_i2c_reg_setting_array imx888_setting;
	struct cam_sensor_i2c_reg_setting_array ov64b40_setting;
	struct cam_sensor_i2c_reg_setting_array imx858_setting;
	struct cam_sensor_i2c_reg_setting_array lyt808_setting;
	struct cam_sensor_i2c_reg_setting_array imx06A_setting;
	struct cam_sensor_i2c_reg_setting_array imx06A_setting_MP;
	struct cam_sensor_i2c_reg_setting_array imx355_setting;
	struct cam_sensor_i2c_reg_setting_array imx882_setting;
	struct cam_sensor_i2c_reg_setting_array imx809_setting;
	struct cam_sensor_i2c_reg_setting_array s5k3p9_setting;
	struct cam_sensor_i2c_reg_setting_array sc1320cs_setting;
	struct cam_sensor_i2c_reg_setting_array sc820cs_setting;
	struct cam_sensor_i2c_reg_setting_array s5kjn5_t_setting;
	struct cam_sensor_i2c_reg_setting_array imx906_setting;
	struct cam_sensor_i2c_reg_setting_array imx471_setting;
	struct cam_sensor_i2c_reg_setting_array ov02b_setting;
	struct cam_sensor_i2c_reg_setting_array imx896_setting;
	struct cam_sensor_i2c_reg_setting_array gc32e2_setting;
};

int cam_ftm_power_down(struct cam_sensor_ctrl_t *s_ctrl);
int cam_ftm_power_up(struct cam_sensor_ctrl_t *s_ctrl);
void cam_sensor_get_dt_data(struct cam_sensor_ctrl_t *s_ctrl);

bool cam_ftm_if_do(void);
#ifdef OPLUS_FEATURE_CAMERA_COMMON
int oplus_shift_sensor_mode(struct cam_sensor_ctrl_t *s_ctrl);
int oplus_cam_sensor_apply_settings(struct cam_sensor_ctrl_t *s_ctrl);
#endif

int cam_sensor_stop(struct cam_sensor_ctrl_t *s_ctrl);
int cam_sensor_start(struct cam_sensor_ctrl_t *s_ctrl, void *arg);
int32_t post_cam_sensor_driver_cmd(struct cam_sensor_ctrl_t *s_ctrl,void *arg);
int cam_sensor_power_up_advance(struct cam_sensor_ctrl_t *s_ctrl);
int cam_sensor_power_down_advance(struct cam_sensor_ctrl_t *s_ctrl);
int cam_sensor_read_qsc(struct cam_sensor_ctrl_t *s_ctrl);
bool cam_sensor_bypass_qsc(struct cam_sensor_ctrl_t *s_ctrl);

int cam_sensor_match_id_oem(struct cam_sensor_ctrl_t *s_ctrl,uint32_t chip_id);
int cam_sensor_read_uniqueid(struct cam_sensor_ctrl_t *s_ctrl, void *arg);

int32_t cam_sensor_update_id_info(struct cam_cmd_probe_v2 *probe_info,
    struct cam_sensor_ctrl_t *s_ctrl);

int SensorRegWrite(struct cam_sensor_ctrl_t *s_ctrl,uint32_t addr, uint32_t data);

int sensor_burst_write(struct cam_sensor_ctrl_t *s_ctrl);

#endif /* _OPLUS_CAM_SENSOR_CORE_H_ */
