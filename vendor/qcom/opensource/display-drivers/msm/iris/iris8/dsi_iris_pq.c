// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015-2019, The Linux Foundation. All rights reserved.
 * Copyright (C) 2017-2020, Pixelworks, Inc.
 *
 * These files contain modifications made by Pixelworks, Inc., in 2019-2020.
 */
#include <video/mipi_display.h>
#include <sde_encoder_phys.h>
#include "dsi_iris_api.h"
#include "dsi_iris_lightup.h"
#include "dsi_iris_lightup_ocp.h"
#include "dsi_iris_lp.h"
#include "dsi_iris_pq.h"
#include "dsi_iris_lut.h"
#include "dsi_iris_ioctl.h"
#include "dsi_iris_timing_switch.h"
#include "dsi_iris_log.h"
#include "dsi_iris_memc.h"
#include "dsi_iris_reg_i8.h"
#include "dsi_iris_dts_fw.h"

void iris_quality_setting_off_i8(void)
{
	//TODO
}

void iris_end_dpp_i8(bool bcommit)
{
	//TODO
}

void iris_pq_parameter_init_i8(void)
{
	//TODO
}

void iris_cm_ratio_set_i8(void)
{
	//TODO
}

void iris_cm_color_gamut_set_i8(u32 level, bool bcommit)
{
	IRIS_LOGI("cm color gamut=%d", level);
}

void iris_lux_set_i8(u32 level, bool update)
{
	IRIS_LOGW("lux value =%d", level);
}

void iris_al_enable_i8(bool enable)
{
	IRIS_LOGW("al enable =%d", enable);
}

void iris_pwil_dport_disable_i8(bool enable, u32 value)
{
	IRIS_LOGD("%s, pwil_dport_disable = %d, count = %d", __func__, enable, value);
}

int iris_update_backlight_i8(u32 bl_lvl)
{
	int rc = 0;

	return rc;
}

void iris_dom_set_i8(int mode)
{
	//TODO
}

void iris_csc2_para_set_i8(uint32_t *values)
{
	//TODO
}

void iris_pwil_dpp_en_i8(bool dpp_en)
{
	IRIS_LOGD("%s, dpp_en = %d", __func__, dpp_en);
}

void iris_scurve_enable_set_i8(u32 level)
{
	IRIS_LOGD("scurve level=%d", level);
}

void iris_blending_mode_set(u32 level)
{
	IRIS_LOGD("blending mode=%d", level);
}
