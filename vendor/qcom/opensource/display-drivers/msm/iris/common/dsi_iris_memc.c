// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015-2019, The Linux Foundation. All rights reserved.
 * Copyright (C) 2017-2020, Pixelworks, Inc.
 *
 * These files contain modifications made by Pixelworks, Inc., in 2019-2020.
 */

#include <linux/types.h>
#include <linux/kernel.h>
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


static struct iris_memc_func memc_func;

static void _iris_demo_wnd_set(void)
{
	u32 chip = iris_get_chip_type();

	if (chip == CHIP_IRIS7)
		iris_demo_wnd_set_i7();
	else
		iris_demo_wnd_set_i7p();
}

static void _iris_demo_wnd_init(void)
{
	struct iris_cfg *pcfg = iris_get_cfg();

	pcfg->demo_cur_start_x = pcfg->demo_start_x;
	pcfg->demo_cur_start_y = pcfg->demo_start_y;
	pcfg->demo_cur_end_x = pcfg->demo_end_x;
	pcfg->demo_cur_end_y = pcfg->demo_end_y;

	if (pcfg->demo_duration == 0)
		return;

	switch (pcfg->demo_from) {
	case DEMO_TOP:
		pcfg->demo_cur_end_y   = pcfg->demo_start_y;
		break;
	case DEMO_BOTTOM:
		pcfg->demo_cur_start_y = pcfg->demo_end_y;
		break;
	case DEMO_LEFT:
		pcfg->demo_cur_end_x   = pcfg->demo_start_x;
		break;
	case DEMO_RIGHT:
		pcfg->demo_cur_start_x = pcfg->demo_end_x;
		break;
	}
}

static void _iris_demo_wnd_calc(void)
{
	struct iris_cfg *pcfg = iris_get_cfg();

	switch (pcfg->demo_from) {
	case DEMO_TOP:
		if (pcfg->demo_end_y > pcfg->demo_cur_end_y + pcfg->demo_step)
			pcfg->demo_cur_end_y += pcfg->demo_step;
		else
			pcfg->demo_cur_end_y = pcfg->demo_end_y;
		break;
	case DEMO_BOTTOM:
		if (pcfg->demo_start_y + pcfg->demo_step < pcfg->demo_cur_start_y)
			pcfg->demo_cur_start_y -= pcfg->demo_step;
		else
			pcfg->demo_cur_start_y = pcfg->demo_start_y;
		break;
	case DEMO_LEFT:
		if (pcfg->demo_end_x > pcfg->demo_cur_end_x + pcfg->demo_step)
			pcfg->demo_cur_end_x += pcfg->demo_step;
		else
			pcfg->demo_cur_end_x = pcfg->demo_end_x;
		break;
	case DEMO_RIGHT:
		if (pcfg->demo_start_x + pcfg->demo_step < pcfg->demo_cur_start_x)
			pcfg->demo_cur_start_x -= pcfg->demo_step;
		else
			pcfg->demo_cur_start_x = pcfg->demo_start_x;
		break;
	}
}

static void _iris_demo_wnd_step_calc(void)
{
	int range = 0;
	struct iris_cfg *pcfg = iris_get_cfg();

	if (pcfg->demo_duration == 0) {
		pcfg->demo_step = 0;
		return;
	}

	switch (pcfg->demo_from) {
	case DEMO_TOP:
	case DEMO_BOTTOM:
		range = pcfg->demo_end_y - pcfg->demo_start_y;
		break;
	case DEMO_LEFT:
	case DEMO_RIGHT:
		range = pcfg->demo_end_x - pcfg->demo_start_x;
		break;
	}
	pcfg->demo_step = max_t(uint32_t, range * pcfg->demo_interval / pcfg->demo_duration, 2);
}

static bool _iris_demo_wnd_move_is_done(void)
{
	struct iris_cfg *pcfg = iris_get_cfg();

	if (pcfg->demo_cur_start_x == pcfg->demo_start_x &&
	    pcfg->demo_cur_start_y == pcfg->demo_start_y &&
	    pcfg->demo_cur_end_x   == pcfg->demo_end_x &&
	    pcfg->demo_cur_end_y   == pcfg->demo_end_y)
		return true;
	else
		return false;
}

static void _iris_demo_wnd_proc(struct work_struct *wk)
{
	struct iris_cfg *pcfg = iris_get_cfg();

	mutex_lock(&pcfg->panel->panel_lock);
	if (pcfg->pwil_mode != FRC_MODE) {
		pcfg->demo_state = DEMO_OFF;
		mutex_unlock(&pcfg->panel->panel_lock);
		return;
	}
	_iris_demo_wnd_calc();
	_iris_demo_wnd_set();
	if (_iris_demo_wnd_move_is_done())
		pcfg->demo_state = DEMO_STILL;
	else
		queue_delayed_work(pcfg->demo_wnd_wq, &pcfg->demo_wnd_wk, msecs_to_jiffies(pcfg->demo_interval));
	mutex_unlock(&pcfg->panel->panel_lock);
}

static void _iris_demo_wnd_wq_init(void)
{
	struct iris_cfg *pcfg = iris_get_cfg();

	pcfg->demo_wnd_wq = create_singlethread_workqueue("demo_wnd_wq");
	INIT_DELAYED_WORK(&pcfg->demo_wnd_wk, _iris_demo_wnd_proc);
}

static void _iris_demo_wnd_border_color_calc(void)
{
	uint8_t y, u, v;
	uint32_t argb, alpha, r, g, b;
	struct iris_cfg *pcfg = iris_get_cfg();

	argb = pcfg->demo_argb;
	alpha = (argb >> 24) & 0xff;
	r = (argb >> 16) & 0xff;
	g = (argb >> 8) & 0xff;
	b = argb & 0xff;

	y = ((66 * r + 129 * g + 25 * b) >> 8) + 16;
	u = ((-38 * r - 74 * g + 112 * b) >> 8) + 128;
	v = ((112 * r - 94 * g - 18 * b) >> 8) + 128;

	pcfg->demo_color_en = !!(alpha != 0);
	pcfg->demo_color = (y << 16) | (v << 8) | u;
}

static void _iris_demo_wnd_var_init(struct iris_cfg *pcfg, u32 *values)
{
	struct iris_frc_setting *frc = &pcfg->frc_setting;
	pcfg->demo_enable   = values[0] ? true : false;
	pcfg->demo_duration = values[1];
	pcfg->demo_from     = values[2];
	pcfg->demo_argb     = values[3];
	pcfg->demo_start_x  = values[4] * frc->mv_hres / 4096;
	pcfg->demo_start_y  = values[5] * frc->mv_vres / 4096;
	pcfg->demo_end_x    = values[6] * frc->mv_hres / 4096;
	pcfg->demo_end_x   += pcfg->demo_start_x;
	pcfg->demo_end_x    = min(pcfg->demo_end_x, frc->mv_hres);
	pcfg->demo_end_y    = values[7] * frc->mv_vres / 4096;
	pcfg->demo_end_y   += pcfg->demo_start_y;
	pcfg->demo_end_y    = min(pcfg->demo_end_y, frc->mv_vres);

	pcfg->demo_step = 0;
	pcfg->demo_interval = 1000 / pcfg->panel_te;
	pcfg->demo_offset = 1;
	pcfg->demo_border = CEILING(frc->mv_vres, 100);
	pcfg->demo_border = max_t(uint32_t, pcfg->demo_border, 2);
	pcfg->demo_border = min_t(uint32_t, pcfg->demo_border, 7);
	pcfg->demo_state = DEMO_INITED;
}

int iris_demo_wnd_conf(u32 count, u32 *values)
{
	int ret = -1;
	struct iris_cfg *pcfg = iris_get_cfg();

	if (count != 8 || pcfg->pwil_mode != FRC_MODE) {
		ret = -EINVAL;
		return ret;
	}

	IRIS_LOGI("%s: en[%u] duration[%u] from[%u] argb[%07x] pos[%u %u %u %u]",
		__func__,
		values[0],
		values[1],
		values[2],
		values[3],
		values[4],
		values[5],
		values[6],
		values[7]);

	_iris_demo_wnd_var_init(pcfg, values);
	_iris_demo_wnd_border_color_calc();
	_iris_demo_wnd_step_calc();
	_iris_demo_wnd_init();
	if (pcfg->demo_duration == 0) {
		_iris_demo_wnd_set();
		pcfg->demo_state = DEMO_STILL;
	} else {
		mutex_unlock(&pcfg->panel->panel_lock);
		iris_wait_vsync();
		mutex_lock(&pcfg->panel->panel_lock);
		queue_delayed_work(pcfg->demo_wnd_wq, &pcfg->demo_wnd_wk, msecs_to_jiffies(pcfg->demo_offset));
	}

	return 0;
}

void iris_memc_func_init(void)
{
	u32 chip = iris_get_chip_type();

	if (chip == CHIP_IRIS7)
		iris_memc_func_init_i7(&memc_func);
	else if (chip == CHIP_IRIS7P)
		iris_memc_func_init_i7p(&memc_func);
	else if (chip == CHIP_IRIS8)
		iris_memc_func_init_i8(&memc_func);
}

void iris_register_osd_irq(void *disp)
{
	if (!memc_func.register_osd_irq)
		return;

	memc_func.register_osd_irq(disp);
}

void iris_update_panel_ap_te(u32 new_te)
{
	if (!memc_func.update_panel_ap_te)
		return;

	memc_func.update_panel_ap_te(new_te);
}

void iris_inc_osd_irq_cnt(void)
{
	if (!memc_func.inc_osd_irq_cnt)
		return;

	memc_func.inc_osd_irq_cnt();
}

bool iris_is_display1_autorefresh_enabled(void *phys_enc)
{
	bool rc = false;

	if (!memc_func.is_display1_autorefresh_enabled)
		return rc;

	rc = memc_func.is_display1_autorefresh_enabled(phys_enc);

	return rc;
}

void iris_pt_sr_set(int enable, int processWidth, int processHeight)
{
	if (!memc_func.pt_sr_set)
		return;

	memc_func.pt_sr_set(enable, processWidth, processHeight);
}

int iris_configure_memc(u32 type, u32 value)
{
	int rc = 0;

	if (!memc_func.configure_memc)
		return rc;

	rc = memc_func.configure_memc(type, value);

	return rc;
}

int iris_configure_ex_memc(u32 type, u32 count, u32 *values)
{
	int rc = 0;

	if (!memc_func.configure_ex_memc)
		return rc;

	rc = memc_func.configure_ex_memc(type, count, values);

	return rc;
}

int iris_configure_get_memc(u32 type, u32 count, u32 *values)
{
	int rc = 0;

	if (!memc_func.configure_get_memc)
		return rc;

	rc = memc_func.configure_get_memc(type, count, values);

	return rc;
}

void iris_init_memc(void)
{
	if (!memc_func.init_memc)
		return;

	memc_func.init_memc();
	_iris_demo_wnd_wq_init();
}

void iris_lightoff_memc(void)
{
	if (!memc_func.lightoff_memc)
		return;

	memc_func.lightoff_memc();
}

void iris_enable_memc(struct dsi_panel *panel)
{
	if (!memc_func.enable_memc)
		return;

	memc_func.enable_memc(panel);
}

void iris_sr_update(void)
{
	if (!memc_func.sr_update)
		return;

	memc_func.sr_update();
}

void iris_frc_setting_init(void)
{
	if (!memc_func.frc_setting_init)
		return;

	memc_func.frc_setting_init();
}

int iris_dbgfs_memc_init(struct dsi_display *display)
{
	int rc = 0;

	if (!memc_func.dbgfs_memc_init)
		return rc;

	rc = memc_func.dbgfs_memc_init(display);

	return rc;
}

void iris_parse_memc_param0(struct device_node *np)
{
	if (!memc_func.parse_memc_param0)
		return;

	memc_func.parse_memc_param0(np);
}

void iris_parse_memc_param1(void)
{
	if (!memc_func.parse_memc_param1)
		return;

	memc_func.parse_memc_param1();
}

void iris_frc_timing_setting_update(void)
{
	if (!memc_func.frc_timing_setting_update)
		return;

	memc_func.frc_timing_setting_update();
}

void iris_pt_sr_reset(void)
{
	if (!memc_func.pt_sr_reset)
		return;

	memc_func.pt_sr_reset();
}

void iris_mcu_state_set(u32 mode)
{
	if (!memc_func.mcu_state_set)
		return;

	memc_func.mcu_state_set(mode);
}

void iris_mcu_ctrl_set(u32 ctrl)
{
	if (!memc_func.mcu_ctrl_set)
		return;

	memc_func.mcu_ctrl_set(ctrl);
}

void iris_memc_vfr_video_update_monitor(struct iris_cfg *pcfg, struct dsi_display *display)
{
	if (!memc_func.memc_vfr_video_update_monitor)
		return;

	memc_func.memc_vfr_video_update_monitor(pcfg, display);
}

int iris_low_latency_mode_get(void)
{
	int rc = 0;

	if (!memc_func.low_latency_mode_get)
		return rc;

	rc = memc_func.low_latency_mode_get();

	return rc;
}

bool iris_health_care(void)
{
	bool rc = 0;

	if (!memc_func.health_care)
		return rc;

	rc = memc_func.health_care();

	return rc;
}

void iris_dsi_rx_mode_switch(u8 rx_mode)
{
	struct iris_cfg *pcfg = iris_get_cfg();

	if (pcfg->abyp_ctrl.abypass_mode != PASS_THROUGH_MODE)
		return;

	if (!memc_func.dsi_rx_mode_switch)
		return;

	memc_func.dsi_rx_mode_switch(rx_mode);
}

bool iris_not_allow_off_primary(void)
{
	if (!memc_func.not_allow_off_primary)
		return false;

	return memc_func.not_allow_off_primary();
}

bool iris_not_allow_off_secondary(void)
{
	if (!memc_func.not_allow_off_secondary)
		return false;

	return memc_func.not_allow_off_secondary();
}

int iris_blending_enable(bool enable)
{
	if (!memc_func.blending_enable)
		return 0;

	return memc_func.blending_enable(enable);
}
