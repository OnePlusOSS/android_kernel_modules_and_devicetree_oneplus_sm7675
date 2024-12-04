/***************************************************************
** Copyright (C), 2022, OPLUS Mobile Comm Corp., Ltd
**
** File : oplus_bl.c
** Description : oplus display backlight
** Version : 2.0
** Date : 2021/02/22
** Author : Display
******************************************************************/

#include "oplus_bl.h"
#include "oplus_display_interface.h"
#include "oplus_display_high_frequency_pwm.h"
#include "oplus_display_panel_seed.h"
#include "oplus_onscreenfingerprint.h"
#if defined(CONFIG_PXLW_IRIS)
#include "dsi_iris_api.h"
#endif

#define AVALON_MAX_NOMAL_BRIGHTNESS 3268

char oplus_global_hbm_flags = 0x0;
static int enable_hbm_enter_dly_on_flags = 0;
static int enable_hbm_exit_dly_on_flags = 0;
extern u32 oplus_last_backlight;
extern bool refresh_rate_change;
extern const char *cmd_set_prop_map[];
extern bool send_demura_after_hbm_off_flag;
ktime_t aod_off_te_timestamp;
ktime_t lhbm_off_te_timestamp;

int oplus_panel_parse_bl_config(struct dsi_panel *panel)
{
	int rc = 0;
	u32 val = 0;
	struct dsi_parser_utils *utils = &panel->utils;

#if defined(CONFIG_PXLW_IRIS)
	if (iris_is_chip_supported() && (!strcmp(panel->type, "secondary"))) {
		LCD_INFO("iris secondary panel no need config\n");
		return 0;
	}
#endif

	rc = utils->read_u32(utils->data, "oplus,dsi-bl-normal-max-level", &val);
	if (rc) {
		LCD_INFO("[%s] oplus,dsi-bl-normal-max-level undefined, default to bl max\n",
				panel->oplus_priv.vendor_name);
		panel->bl_config.bl_normal_max_level = panel->bl_config.bl_max_level;
	} else {
		panel->bl_config.bl_normal_max_level = val;
	}

	/* avalon normal max backlight level is 3268, audi is 3238 */
	if (is_project(24211) || is_project(24212)) {
		panel->bl_config.bl_normal_max_level = AVALON_MAX_NOMAL_BRIGHTNESS;
	}

	LCD_INFO("[%s] bl_max_level=%d\n", panel->oplus_priv.vendor_name,
			panel->bl_config.bl_max_level);

	rc = utils->read_u32(utils->data, "oplus,dsi-brightness-normal-max-level",
		&val);
	if (rc) {
		LCD_INFO("[%s] oplus,dsi-brightness-normal-max-level undefined, default to brightness max\n",
				panel->oplus_priv.vendor_name);
		panel->bl_config.brightness_normal_max_level = panel->bl_config.brightness_max_level;
	} else {
		panel->bl_config.brightness_normal_max_level = val;
	}

	/* avalon normal max backlight level is 3268, audi is 3238 */
	if (is_project(24211) || is_project(24212)) {
		panel->bl_config.brightness_normal_max_level = AVALON_MAX_NOMAL_BRIGHTNESS;
	}

	LCD_INFO("[%s] brightness_normal_max_level=%d\n",
			panel->oplus_priv.vendor_name,
			panel->bl_config.brightness_normal_max_level);

	rc = utils->read_u32(utils->data, "oplus,dsi-brightness-default-level", &val);
	if (rc) {
		LCD_INFO("[%s] oplus,dsi-brightness-default-level undefined, default to brightness normal max\n",
				panel->oplus_priv.vendor_name);
		panel->bl_config.brightness_default_level = panel->bl_config.brightness_normal_max_level;
	} else {
		panel->bl_config.brightness_default_level = val;
	}
	LCD_INFO("[%s] brightness_default_level=%d\n",
			panel->oplus_priv.vendor_name,
			panel->bl_config.brightness_default_level);

	rc = utils->read_u32(utils->data, "oplus,dsi-dc-backlight-threshold", &val);
	if (rc) {
		LCD_INFO("[%s] oplus,dsi-dc-backlight-threshold undefined, default to 260\n",
				panel->oplus_priv.vendor_name);
		panel->bl_config.dc_backlight_threshold = 260;
		panel->bl_config.oplus_dc_mode = false;
	} else {
		panel->bl_config.dc_backlight_threshold = val;
		panel->bl_config.oplus_dc_mode = true;
	}
	LCD_INFO("[%s] dc_backlight_threshold=%d, oplus_dc_mode=%d\n",
			panel->oplus_priv.vendor_name,
			panel->bl_config.dc_backlight_threshold,
			panel->bl_config.oplus_dc_mode);

	rc = utils->read_u32(utils->data, "oplus,dsi-global-hbm-case-id", &val);
	if (rc) {
		LCD_INFO("[%s] oplus,dsi-global-hbm-case-id undefined, default to 0\n",
				panel->oplus_priv.vendor_name);
		val = GLOBAL_HBM_CASE_NONE;
	} else if (val >= GLOBAL_HBM_CASE_MAX) {
		LCD_ERR("[%s] oplus,dsi-global-hbm-case-id is invalid:%d\n",
				panel->oplus_priv.vendor_name, val);
		val = GLOBAL_HBM_CASE_NONE;
	}
	panel->bl_config.global_hbm_case_id = val;
	LCD_INFO("[%s] global_hbm_case_id=%d\n",
			panel->oplus_priv.vendor_name,
			panel->bl_config.global_hbm_case_id);

	rc = utils->read_u32(utils->data, "oplus,dsi-global-hbm-threshold", &val);
	if (rc) {
		LCD_INFO("[%s] oplus,dsi-global-hbm-threshold undefined, default to brightness normal max + 1\n",
				panel->oplus_priv.vendor_name);
		panel->bl_config.global_hbm_threshold = panel->bl_config.brightness_normal_max_level + 1;
	} else {
		panel->bl_config.global_hbm_threshold = val;
	}
	LCD_INFO("[%s] global_hbm_threshold=%d\n",
			panel->oplus_priv.vendor_name,
			panel->bl_config.global_hbm_threshold);

	panel->bl_config.global_hbm_scale_mapping = utils->read_bool(utils->data,
			"oplus,dsi-global-hbm-scale-mapping");
	LCD_INFO("oplus,dsi-global-hbm-scale-mapping: %s\n",
			panel->bl_config.global_hbm_scale_mapping ? "true" : "false");

#ifdef OPLUS_FEATURE_DISPLAY
	rc = utils->read_u32(utils->data, "oplus,dsi_bl_limit_max_brightness", &val);

	if (rc) {
		LCD_INFO("[%s] oplus,dsi_bl_limit_max_brightness undefined, default to 4094\n",
			panel->oplus_priv.vendor_name);
		panel->bl_config.oplus_limit_max_bl_mode = false;
	} else {
		panel->bl_config.oplus_limit_max_bl_mode = true;
		panel->bl_config.oplus_limit_max_bl = val;
	}

	panel->bl_config.oplus_demura2_offset_support = utils->read_bool(utils->data,
			"oplus,dsi_demura2_offset_support");
	LCD_INFO("oplus,dsi_demura2_offset_support: %s\n",
			panel->bl_config.oplus_demura2_offset_support ? "true" : "false");
#endif

	return 0;
}

static int oplus_display_panel_dly(struct dsi_panel *panel, bool hbm_switch)
{
	if (hbm_switch) {
		if (enable_hbm_enter_dly_on_flags)
			enable_hbm_enter_dly_on_flags++;
		if (0 == oplus_global_hbm_flags) {
			if (dsi_panel_tx_cmd_set(panel, DSI_CMD_DLY_ON)) {
				return 0;
			}
			enable_hbm_enter_dly_on_flags = 1;
		} else if (4 == enable_hbm_enter_dly_on_flags) {
			if (dsi_panel_tx_cmd_set(panel, DSI_CMD_DLY_OFF)) {
				return 0;
			}
			enable_hbm_enter_dly_on_flags = 0;
		}
	} else {
		if (oplus_global_hbm_flags == 1) {
			if (dsi_panel_tx_cmd_set(panel, DSI_CMD_DLY_ON)) {
				return 0;
			}
			enable_hbm_exit_dly_on_flags = 1;
		} else {
			if (enable_hbm_exit_dly_on_flags)
				enable_hbm_exit_dly_on_flags++;
			if (3 == enable_hbm_exit_dly_on_flags) {
				enable_hbm_exit_dly_on_flags = 0;
				if (dsi_panel_tx_cmd_set(panel, DSI_CMD_DLY_OFF)) {
					return 0;
				}
			}
		}
	}
	return 0;
}

int oplus_panel_global_hbm_mapping(struct dsi_panel *panel, u32 *backlight_level)
{
	int rc = 0;
	u32 bl_lvl = *backlight_level;
	u32 global_hbm_switch_cmd = 0;
	bool global_hbm_dly = false;
	struct dsi_cmd_desc *cmds;
	size_t tx_len;
	u8 *tx_buf;
	u32 count;
	int i;

	if (bl_lvl > panel->bl_config.bl_normal_max_level) {
		if (!oplus_global_hbm_flags) {
			global_hbm_switch_cmd = DSI_CMD_HBM_ENTER_SWITCH;
		}
	} else if (oplus_global_hbm_flags) {
		global_hbm_switch_cmd = DSI_CMD_HBM_EXIT_SWITCH;
	}

	switch (panel->bl_config.global_hbm_case_id) {
	case GLOBAL_HBM_CASE_1:
		break;
	case GLOBAL_HBM_CASE_2:
		if (bl_lvl > panel->bl_config.bl_normal_max_level) {
			if (panel->bl_config.global_hbm_scale_mapping) {
				bl_lvl = (bl_lvl - panel->bl_config.bl_normal_max_level) * 100000
						/ (panel->bl_config.bl_max_level - panel->bl_config.bl_normal_max_level)
						* (panel->bl_config.bl_max_level - panel->bl_config.global_hbm_threshold)
						/ 100000 + panel->bl_config.global_hbm_threshold;
			} else if (bl_lvl < panel->bl_config.global_hbm_threshold) {
				bl_lvl = panel->bl_config.global_hbm_threshold;
			}
		}
		break;
	case GLOBAL_HBM_CASE_3:
		if (bl_lvl > panel->bl_config.bl_normal_max_level) {
			bl_lvl = bl_lvl + panel->bl_config.global_hbm_threshold
					- panel->bl_config.bl_normal_max_level - 1;
		}
		break;
	case GLOBAL_HBM_CASE_4:
		global_hbm_switch_cmd = 0;
		if (bl_lvl <= PANEL_MAX_NOMAL_BRIGHTNESS) {
			if (oplus_global_hbm_flags) {
				global_hbm_switch_cmd = DSI_CMD_HBM_EXIT_SWITCH;
			}
			bl_lvl = backlight_buf[bl_lvl];
		} else if (bl_lvl > HBM_BASE_600NIT) {
			if (!oplus_global_hbm_flags) {
				global_hbm_switch_cmd = DSI_CMD_HBM_ENTER_SWITCH;
			}
			global_hbm_dly = true;
			bl_lvl = backlight_600_800nit_buf[bl_lvl - HBM_BASE_600NIT];
		} else if (bl_lvl > PANEL_MAX_NOMAL_BRIGHTNESS) {
			if (oplus_global_hbm_flags) {
				global_hbm_switch_cmd = DSI_CMD_HBM_EXIT_SWITCH;
			}
			bl_lvl = backlight_500_600nit_buf[bl_lvl - PANEL_MAX_NOMAL_BRIGHTNESS];
		}
		break;
	default:
		global_hbm_switch_cmd = 0;
		break;
	}

	bl_lvl = bl_lvl < panel->bl_config.bl_max_level ? bl_lvl :
			panel->bl_config.bl_max_level;

	if (global_hbm_switch_cmd > 0) {
		/* Update the 0x51 value when sending hbm enter/exit command */
		cmds = panel->cur_mode->priv_info->cmd_sets[global_hbm_switch_cmd].cmds;
		count = panel->cur_mode->priv_info->cmd_sets[global_hbm_switch_cmd].count;
		for (i = 0; i < count; i++) {
			tx_len = cmds[i].msg.tx_len;
			tx_buf = (u8 *)cmds[i].msg.tx_buf;
			if ((3 == tx_len) && (0x51 == tx_buf[0])) {
				tx_buf[1] = (bl_lvl >> 8) & 0xFF;
				tx_buf[2] = bl_lvl & 0xFF;
				break;
			}
		}

		if (global_hbm_dly) {
			oplus_display_panel_dly(panel, true);
		}

		rc = dsi_panel_tx_cmd_set(panel, global_hbm_switch_cmd);
		oplus_global_hbm_flags = (global_hbm_switch_cmd == DSI_CMD_HBM_ENTER_SWITCH);
	}

	*backlight_level = bl_lvl;
	return 0;
}

int oplus_display_panel_get_global_hbm_status(void)
{
	return oplus_global_hbm_flags;
}

void oplus_display_panel_set_global_hbm_status(int global_hbm_status)
{
	oplus_global_hbm_flags = global_hbm_status;
	LCD_INFO("set oplus_global_hbm_flags = %d\n", global_hbm_status);
}

void oplus_panel_set_aod_off_te_timestamp(struct dsi_panel *panel) {
	aod_off_te_timestamp = panel->te_timestamp;
}

void oplus_panel_set_lhbm_off_te_timestamp(struct dsi_panel *panel) {
	lhbm_off_te_timestamp = panel->te_timestamp;
}

void oplus_panel_directional_onepulse_lhbm_off_handle(
	struct dsi_panel *panel,
	u32 pwm_switch_state_last) {
	ktime_t cur_time;
	s64 interval;
	s64 delay;
	s64 us_per_frame;

	us_per_frame = panel->cur_mode->priv_info->vsync_period;
	if (oplus_panel_pwm_onepulse_is_enabled(panel) && pwm_switch_state_last != panel->pwm_params.oplus_pwm_switch_state) {
		cur_time = ktime_get();
		interval = ktime_to_us(ktime_sub(cur_time, lhbm_off_te_timestamp));
		if (interval > us_per_frame && interval < us_per_frame * 2) {
			/* pwm switch cmd shound not send in the frame next to lhbm off */
			delay = us_per_frame * 2 - interval;
			if (delay > 0) {
				LCD_INFO("need to delay, for the interval between the te of lhbm off and cur time was %d\n", delay);
				usleep_range(delay, delay + 200);
			}
		}
	}
}

void oplus_panel_directional_onepulse_poweron_handle(
	struct dsi_panel *panel,
	u32 pwm_switch_state_last) {
	ktime_t cur_time;
	u32 interval;
	u32 delay;

	if (oplus_panel_pwm_onepulse_is_enabled(panel) && pwm_switch_state_last != panel->pwm_params.oplus_pwm_switch_state) {
		if (oplus_last_backlight == 0 || oplus_last_backlight == 1) {
			/* first power on backlight */
			cur_time = ktime_get();
			interval = ktime_to_us(ktime_sub(cur_time, aod_off_te_timestamp));
			if (interval < 34000) {
				/* delay cmd to the next frame of aod_off for preventing black screen */
				delay = 34000 - interval;
				LCD_INFO("need to delay for the interval between the te of aod off and cur time was %d\n", delay);
				usleep_range(delay, delay + 200);
			}
		}
	}
}

void oplus_panel_backlight_demura_dbv_switch(struct dsi_panel *panel, u32 bl_lvl)
{
	int rc = 0;
	u32 bl_demura_last_mode = panel->oplus_priv.bl_demura_mode;
	u32 bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE0;
	char *tx_buf;
	struct dsi_panel_cmd_set custom_cmd_set;

	if (!panel->oplus_priv.oplus_bl_demura_dbv_support)
		return;

	if (bl_lvl == 0 || bl_lvl == 1)
		return;

	if(!strcmp(panel->name, "AA577 P 3 A0020 dsc cmd mode panel")) {
		return;
	}

	if (!strcmp(panel->name, "AA567 P 3 A0004 dsc cmd mode panel")) {
		if ((bl_lvl >= 8) && (bl_lvl <= 1087)) {
			panel->oplus_priv.bl_demura_mode = 0;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE0;
		} else if ((bl_lvl >= 1088) && (bl_lvl < 1768)) {
			panel->oplus_priv.bl_demura_mode = 1;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE1;
		} else if ((bl_lvl >= 1768) && (bl_lvl < 2689)) {
			panel->oplus_priv.bl_demura_mode = 2;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE2;
		} else if (2689 <= bl_lvl) {
			panel->oplus_priv.bl_demura_mode = 3;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE3;
		}
	} else if (!strcmp(panel->name, "P 7 AB715 dsc cmd mode panel")) {
		if (1 <= bl_lvl && bl_lvl < 652) {
			panel->oplus_priv.bl_demura_mode = 0;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE0;
		} else if (652 <= bl_lvl && bl_lvl < 1088) {
			panel->oplus_priv.bl_demura_mode = 1;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE1;
		} else if (1088 <= bl_lvl) {
			panel->oplus_priv.bl_demura_mode = 2;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE2;
		}
	} else if (!strcmp(panel->name, "AC172 P 7 A0001 dsc cmd mode panel")) {
		if ((bl_lvl >= 0x08) && (bl_lvl < 0x1F5)) {
			panel->oplus_priv.bl_demura_mode = 0;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE0;
		} else if ((bl_lvl >= 0x1F6) && (bl_lvl < 0x3F1)) {
			panel->oplus_priv.bl_demura_mode = 1;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE1;
		} else if ((bl_lvl >= 0x3F2) && (bl_lvl < 0x561)) {
			panel->oplus_priv.bl_demura_mode = 2;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE2;
		} else if ((bl_lvl >= 0x562) && (bl_lvl < 0xDBA)) {
			panel->oplus_priv.bl_demura_mode = 3;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE3;
		} else if (bl_lvl >= 0xDBB) {
			panel->oplus_priv.bl_demura_mode = 4;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE4;
		}
	} else {
		if (bl_lvl <= 3515)
			return;

		if (PANEL_LOADING_EFFECT_MODE2 != __oplus_get_seed_mode())
			return;

		if ((bl_lvl > 3515) && (bl_lvl <= 3543)) {
			panel->oplus_priv.bl_demura_mode = 0;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE0;
		} else if ((bl_lvl > 3543) && (bl_lvl <= 3600)) {
			panel->oplus_priv.bl_demura_mode = 1;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE1;
		} else if ((bl_lvl > 3600) && (bl_lvl <= 3680)) {
			panel->oplus_priv.bl_demura_mode = 2;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE2;
		} else if ((bl_lvl > 3680) && (bl_lvl <= 3720)) {
			panel->oplus_priv.bl_demura_mode = 3;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE3;
		} else if ((bl_lvl > 3720) && (bl_lvl <= 3770)) {
			panel->oplus_priv.bl_demura_mode = 4;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE4;
		} else if ((bl_lvl > 3770) && (bl_lvl <= 3860)) {
			panel->oplus_priv.bl_demura_mode = 5;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE5;
		} else if ((bl_lvl > 3860) && (bl_lvl <= 3949)) {
			panel->oplus_priv.bl_demura_mode = 6;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE6;
		}  else if ((bl_lvl > 3949) && (bl_lvl <= 4094)) {
			panel->oplus_priv.bl_demura_mode = 7;
			bl_demura_mode = DSI_CMD_DEMURA_DBV_MODE7;
		}

		custom_cmd_set = panel->cur_mode->priv_info->cmd_sets[bl_demura_mode];
		tx_buf = (char*)custom_cmd_set.cmds[custom_cmd_set.count - 1].msg.tx_buf;

		if (tx_buf[0] == 0x51) {
			tx_buf[1] = (bl_lvl >> 8);
			tx_buf[2] = (bl_lvl & 0xFF);
		} else {
			LCD_INFO("invaild format of cmd %s\n", cmd_set_prop_map[bl_demura_mode]);
		}
	}

	LCD_INFO("send_demura_after_hbm_off_flag = %d\n", send_demura_after_hbm_off_flag);
	if ((panel->oplus_priv.bl_demura_mode != bl_demura_last_mode || send_demura_after_hbm_off_flag) && (panel->power_mode == SDE_MODE_DPMS_ON)) {
		rc = dsi_panel_tx_cmd_set(panel, bl_demura_mode);
		send_demura_after_hbm_off_flag = false;
	}
	if (rc) {
		DSI_ERR("[%s] failed to send bl_demura_mode, rc=%d\n", panel->name, rc);
		return;
	}
}

int oplus_panel_need_to_set_demura2_offset(struct dsi_panel *panel)
{
	if (!panel) {
		LCD_ERR("Invalid panel params\n");
		return -EINVAL;
	}

	if (panel->bl_config.oplus_demura2_offset_support) {
		panel->bl_config.need_to_set_demura2_offset = true;
	}

	return 0;
}

int oplus_display_panel_set_demura2_offset(void)
{
	u32 bl_lvl = 0;
	int rc = 0;
	struct dsi_display *display = NULL;
	struct dsi_panel *panel = NULL;
	static bool last_hbm_status = false;
	bool current_hbm_status = false;
	u32 last_demura2_offset = 0;
	u32 cmd_set_demura2_offset = DSI_CMD_SET_DEMURA2_OFFSET0;

	display = get_main_display();
	if (!display) {
		DSI_ERR("[%s] failed to set demura2 offset, Invalid params\n", panel->name);
		return -EINVAL;
	}

	panel = display->panel;
	if (!panel) {
		DSI_ERR("[%s] failed to set demura2 offset, Invalid params\n", panel->name);
		return -EINVAL;
	}

	if (!panel->bl_config.oplus_demura2_offset_support) {
		DSI_DEBUG("[%s] don't support demura2 offset\n", panel->name);
		return rc;
	}

	last_demura2_offset = panel->bl_config.demura2_offset;
	bl_lvl = panel->bl_config.bl_level;
	current_hbm_status = oplus_ofp_get_hbm_state();

	if (current_hbm_status) {
		/* Enter HBM, bl_lvl set as backlight for entering HBM */
		bl_lvl = 0x0F00;
	} else if (last_hbm_status != current_hbm_status) {
		/* Exit HBM, force update demura2 offset */
		panel->bl_config.need_to_set_demura2_offset = true;
	}

	if ((bl_lvl >= 0x08) && (bl_lvl < 0x144)) {
		panel->bl_config.demura2_offset = 0;
		cmd_set_demura2_offset = DSI_CMD_SET_DEMURA2_OFFSET0;
	} else if ((bl_lvl >= 0x144) && (bl_lvl < 0x2D1)) {
		panel->bl_config.demura2_offset = 1;
		cmd_set_demura2_offset = DSI_CMD_SET_DEMURA2_OFFSET1;
	} else if ((bl_lvl >= 0x2D1) && (bl_lvl < 0x522)) {
		panel->bl_config.demura2_offset = 2;
		cmd_set_demura2_offset = DSI_CMD_SET_DEMURA2_OFFSET2;
	} else if ((bl_lvl >= 0x522) && (bl_lvl < 0xE7D)) {
		panel->bl_config.demura2_offset = 3;
		cmd_set_demura2_offset = DSI_CMD_SET_DEMURA2_OFFSET3;
	} else if (bl_lvl >= 0xE7D) {
		panel->bl_config.demura2_offset = 4;
		cmd_set_demura2_offset = DSI_CMD_SET_DEMURA2_OFFSET4;
	} else {
		return rc;
	}

	if ((panel->bl_config.demura2_offset != last_demura2_offset
			|| panel->bl_config.need_to_set_demura2_offset)
			&& panel->power_mode == SDE_MODE_DPMS_ON) {
		mutex_lock(&display->display_lock);
		mutex_lock(&panel->panel_lock);

		rc |= dsi_display_override_dma_cmd_trig(display, DSI_TRIGGER_SW_SEOF);
		rc |= dsi_panel_tx_cmd_set(panel, cmd_set_demura2_offset);
		rc |= dsi_display_override_dma_cmd_trig(display, DSI_TRIGGER_NONE);

		mutex_unlock(&panel->panel_lock);
		mutex_unlock(&display->display_lock);

		if (rc) {
			DSI_ERR("[%s] failed to send demura2 offset cmd, rc=%d\n", panel->name, rc);
			return rc;
		}
		panel->bl_config.need_to_set_demura2_offset = false;
	}

	last_hbm_status = current_hbm_status;

	return rc;
}
