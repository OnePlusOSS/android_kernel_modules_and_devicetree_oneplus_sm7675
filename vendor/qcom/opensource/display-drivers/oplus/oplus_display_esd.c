/***************************************************************
** Copyright (C), 2022, OPLUS Mobile Comm Corp., Ltd
**
** File : oplus_display_esd.c
** Description : oplus esd feature
** Version : 2.0
** Date : 2021/11/26
** Author : Display
******************************************************************/

#include "oplus_display_esd.h"

int esd_check_mode = 0;

int oplus_panel_parse_esd_reg_read_configs(struct dsi_panel *panel)
{
	struct drm_panel_esd_config *esd_config;
	int rc = 0;
	u32 tmp;
	struct dsi_parser_utils *utils = &panel->utils;

	if (!panel) {
		LCD_ERR("Invalid Params\n");
		return -EINVAL;
	}

	esd_config = &panel->esd_config;
	if (!esd_config)
		return -EINVAL;

	/*
	 * oplus,mdss-dsi-panel-status-match-modes is a 32-bit
	 * binary flag. Bit value identified how to match the return
	 * value of each register. The value 0(default) means equal,
	 * and the value 1 means not equal.
	 */
	rc = utils->read_u32(utils->data, "oplus,mdss-dsi-panel-status-match-modes", &tmp);
	if (!rc) {
		esd_config->status_match_modes = tmp;
		LCD_INFO("Successed to read ESD match modes=0x%08X\n",
				esd_config->status_match_modes);
	} else {
		esd_config->status_match_modes = 0x0;
		LCD_ERR("Failed to read ESD match modes, set default modes=0x%08X\n",
				esd_config->status_match_modes);
	}

	return rc;
}

bool oplus_panel_validate_reg_read(struct dsi_panel *panel)
{
	int i = 0, tmp = 0;
	u32 *lenp, len = 0, cmd_count = 0;
	u32 data_offset = 0, group_offset = 0, value_offset = 0;
	u32 cmd_index = 0, data_index = 0, group_index = 0;
	u32 match_modes = 0, mode = 0;
	bool matched, group_mode0_matched, group_mode1_matched, group_matched;
	struct drm_panel_esd_config *config;
	char payload[1024] = "";
	u32 cnt = 0;

	if (!panel) {
		LCD_ERR("Invalid params\n");
		return false;
	}

	config = &(panel->esd_config);

	match_modes = config->status_match_modes;
	lenp = config->status_valid_params ?: config->status_cmds_rlen;
	cmd_count = config->status_cmd.count;

	for (i = 0; i < cmd_count; i++)
		len += lenp[i];

	group_matched = false;
	group_mode1_matched = true;
	for (group_index = 0, group_offset = 0; group_index < config->groups; ++group_index) {
		group_mode0_matched = true;

		for (cmd_index = 0, data_offset = 0; cmd_index < cmd_count; ++cmd_index) {
			mode = (match_modes >> cmd_index) & 0x01;
			tmp = 0;

			for (data_index = 0; data_index < lenp[cmd_index]; ++data_index) {
				matched = true;
				value_offset = group_offset + data_offset + data_index;

				if (!mode && config->return_buf[data_offset + data_index] !=
						config->status_value[value_offset]) {
					matched = false;
					group_mode0_matched = false;
				}
				else if (mode && config->return_buf[data_offset + data_index] ==
						config->status_value[value_offset]) {
					matched = false;
					tmp++;
				}

				LCD_DEBUG("ESD check at index/group:[%d/%d] exp:[0x%02X] ret:[0x%02X] mode:[%u] matched:[%d]\n",
						data_offset + data_index,
						group_index,
						config->status_value[value_offset],
						config->return_buf[data_offset + data_index],
						mode,
						matched);
			}

			if (tmp == lenp[cmd_index])
					group_mode1_matched = false;

			data_offset += lenp[cmd_index];
		}

		group_matched = (group_matched || group_mode0_matched) && group_mode1_matched;

		LCD_DEBUG("ESD check matching: group:[%d] mode0/mode1/matched:[%d/%d/%d]\n",
				group_index,
				group_mode0_matched,
				group_mode1_matched,
				group_matched);

		group_offset += len;
	}

	if (group_matched)
		return true;

	cnt += scnprintf(payload + cnt, sizeof(payload) - cnt, "DisplayDriverID@@408$$");
	cnt += scnprintf(payload + cnt, sizeof(payload) - cnt, "ESD:");
	for (i = 0; i < len; ++i)
		cnt += scnprintf(payload + cnt, sizeof(payload) - cnt, " [0x%02X]", config->return_buf[i]);
	DSI_MM_ERR("ESD check failed:%s\n", payload);

	return false;
}

int oplus_display_status_check_mipi_err_gpio(struct dsi_display *display)
{
	unsigned int mipi_err_gpio_value = 1;
	struct dsi_panel *panel;
	char payload[1024] = "";
	u32 cnt = 0;

	if (!display || !display->panel) {
		LCD_INFO("Invalid display or panel params!\n");
		return 1;
	}

	panel = display->panel;

	if (!gpio_is_valid(panel->esd_config.mipi_err_flag_gpio)) {
		LCD_INFO("mipi err flag GPIO's are valid\n");
		goto error;
	}

	mipi_err_gpio_value = gpio_get_value(panel->esd_config.mipi_err_flag_gpio);

	LCD_INFO("esd mipi err flag status : %d\n", mipi_err_gpio_value);
	if (mipi_err_gpio_value == 0) {
		LCD_ERR("esd mipi err flag check failed, mipi_err_gpio_value = %d\n", mipi_err_gpio_value);
		cnt += scnprintf(payload + cnt, sizeof(payload) - cnt, "DisplayDriverID@@408$$");
		cnt += scnprintf(payload + cnt, sizeof(payload) - cnt, "ESD:");
		cnt += scnprintf(payload + cnt, sizeof(payload) - cnt, " [mipi err flag gpio status: %d]", mipi_err_gpio_value);
		DSI_MM_ERR("ESD check failed:%s\n", payload);
		return -EINVAL;
	}

	return 1;

error:
	LCD_ERR("mipi err flag GPIO's are valid, disable mipi err flag check\n");
	if (display->panel->esd_config.status_mode == ESD_MODE_PANEL_MIPI_ERR_FLAG)
		display->panel->esd_config.esd_enabled = false;

	return 1;
}

void oplus_display_esd_check_mode_switch(struct dsi_panel *panel, int cmd_index)
{
	struct drm_panel_esd_config *config;

	if (!panel) {
		LCD_ERR("Invalid params\n");
		return;
	}

	config = &(panel->esd_config);

	if (!strcmp(panel->name, "AC172 P 3 A0023 dsc cmd mode panel") && cmd_index == 0) {
		oplus_sde_early_wakeup(panel);
		oplus_wait_for_vsync(panel);
		if (esd_check_mode == 0) {
			esd_check_mode = 1;
			config->status_value[0] = 0x06;
			config->status_value[1] = 0x00;
			config->status_match_modes = 0x00000000;
			dsi_panel_tx_cmd_set(panel, DSI_CMD_ESD_OFFSET_LOCATION);
		} else if (esd_check_mode == 1) {
			esd_check_mode = 0;
			config->status_value[0] = 0x14;
			config->status_value[1] = 0x14;
			config->status_match_modes = 0x00000001;
			dsi_panel_tx_cmd_set(panel, DSI_CMD_ESD_OFFSET_LOCATION_TWO);
		}
	}
}

bool oplus_display_check_status_pre(struct dsi_panel *panel)
{
	if(!panel) {
		LCD_ERR("Invalid params\n");
		return false;
	}
	if (atomic_read(&panel->esd_pending)) {
		DSI_WARN("Skip the check because esd is pending\n");
		if (!strcmp(panel->name, "AB964 p 1 A0017 dsc video mode panel")) {
			if (panel->oplus_priv.set_backlight_not_do_esd_reg_read_enable
			&& panel->panel_mode == DSI_OP_VIDEO_MODE) {
				atomic_set(&panel->esd_pending, 0);
			}
		} else {
			if (panel->panel_mode == DSI_OP_VIDEO_MODE)
				atomic_set(&panel->esd_pending, 0);
		}
		return true;
	}
	if (panel->power_mode != SDE_MODE_DPMS_ON) {
		DSI_WARN("Skip the check because panel power mode not power on!\n");
		return true;
	}
	return false;
}

