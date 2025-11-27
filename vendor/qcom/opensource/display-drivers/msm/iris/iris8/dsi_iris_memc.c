// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015-2019, The Linux Foundation. All rights reserved.
 * Copyright (C) 2017-2020, Pixelworks, Inc.
 *
 * These files contain modifications made by Pixelworks, Inc., in 2019-2020.
 */

#include <linux/types.h>
#include <dsi_drm.h>
#include <sde_encoder_phys.h>
#include "dsi_display.h"
#include "dsi_panel.h"
#include "dsi_iris.h"
#include "dsi_iris_api.h"
#include "dsi_iris_lightup.h"
#include "dsi_iris_lightup_ocp.h"
#include "dsi_iris_lp.h"
#include "dsi_iris_pq.h"
#include "dsi_iris_log.h"
#include "dsi_iris_memc.h"
#include "dsi_iris_dual_i8.h"
#include "dsi_iris_memc_i8.h"
#include "dsi_iris_emv_i8.h"
#include "dsi_iris_memc_helper.h"
#include "dsi_iris_timing_switch.h"
#include "dsi_iris_i3c.h"
#include "dsi_iris_dts_fw.h"
#include "dsi_iris_reg_i8.h"
#include "dsi_iris_cmpt.h"



int iris_low_latency_mode_get_i8(void)
{
	struct iris_cfg *pcfg = iris_get_cfg();

	return pcfg->memc_info.low_latency_mode;
}

void iris_update_panel_ap_te_i8(u32 new_te)
{
	struct iris_cfg *pcfg = iris_get_cfg();

	pcfg->panel_te = new_te;
	pcfg->ap_te = new_te;
}
void iris_frc_timing_setting_update_i8(void)
{
	//TODO
}

void iris_parse_memc_param0_i8(struct device_node *np)
{
	//TODO
}

void iris_parse_memc_param1_i8(void)
{
	//TODO
}

void iris_frc_setting_init_i8(void)
{
	//TODO
}

void iris_mcu_state_set_i8(u32 mode)
{
	//TODO
}

void iris_memc_vfr_video_update_monitor_i8(struct iris_cfg *pcfg, struct dsi_display *display)
{
	//TODO
}

void iris_dsi_rx_mode_switch_i8(uint8_t rx_mode)
{
	//TODO
}

int iris_dbgfs_memc_init_i8(struct dsi_display *display)
{
	return 0;
}


int iris_configure_memc_i8(u32 type, u32 value)
{
	int rc = 0;

	return rc;
}

int iris_configure_ex_memc_i8(u32 type, u32 count, u32 *values)
{
	int rc = 0;

	return rc;
}

int iris_configure_get_memc_i8(u32 type, u32 count, u32 *values)
{
	int rc = 0;

	return rc;
}

void iris_init_memc_i8(void)
{
	//TODO
}

void iris_lightoff_memc_i8(void)
{
	//TODO
}

void iris_enable_memc_i8(struct dsi_panel *panel)
{
	//TODO
}

bool iris_not_allow_sde_off_primary_i8(void)
{
	bool rc = false;

	return rc;
}

bool iris_not_allow_sde_off_secondary_i8(void)
{
	bool rc= false;

	return rc;
}

void iris_memc_func_init_i8(struct iris_memc_func *memc_func)
{
	memc_func->register_osd_irq = iris_register_osd_irq_i8;
	memc_func->update_panel_ap_te = iris_update_panel_ap_te_i8;
	memc_func->inc_osd_irq_cnt = iris_inc_osd_irq_cnt_i8;
	memc_func->is_display1_autorefresh_enabled = iris_is_display1_autorefresh_enabled_i8;
	memc_func->pt_sr_set = NULL;
	memc_func->configure_memc = iris_configure_memc_i8;
	memc_func->configure_ex_memc = iris_configure_ex_memc_i8;
	memc_func->configure_get_memc = iris_configure_get_memc_i8;
	memc_func->init_memc = iris_init_memc_i8;
	memc_func->lightoff_memc = iris_lightoff_memc_i8;
	memc_func->enable_memc = iris_enable_memc_i8;
	memc_func->sr_update = NULL;
	memc_func->frc_setting_init = iris_frc_setting_init_i8;
	memc_func->dbgfs_memc_init = iris_dbgfs_memc_init_i8;
	memc_func->parse_memc_param0 = iris_parse_memc_param0_i8;
	memc_func->parse_memc_param1 = iris_parse_memc_param1_i8;
	memc_func->frc_timing_setting_update = iris_frc_timing_setting_update_i8;
	memc_func->pt_sr_reset = NULL;
	memc_func->mcu_state_set = iris_mcu_state_set_i8;
	memc_func->mcu_ctrl_set = NULL;
	memc_func->memc_vfr_video_update_monitor = iris_memc_vfr_video_update_monitor_i8;
	memc_func->low_latency_mode_get = iris_low_latency_mode_get_i8;
	memc_func->health_care = NULL;
	memc_func->not_allow_off_primary = iris_not_allow_sde_off_primary_i8;
	memc_func->not_allow_off_secondary = iris_not_allow_sde_off_secondary_i8;
	memc_func->blending_enable = iris_dual_blending_enable_i8;
	memc_func->dsi_rx_mode_switch = iris_dsi_rx_mode_switch_i8;
}
