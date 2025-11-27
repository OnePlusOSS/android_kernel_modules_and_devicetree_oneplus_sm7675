/***************************************************************
** Copyright (C), 2022, OPLUS Mobile Comm Corp., Ltd
**
** File : oplus_display_esd.h
** Description : oplus esd feature
** Version : 2.0
** Date : 2021/11/26
** Author : Display
******************************************************************/
#ifndef _OPLUS_ESD_H_
#define _OPLUS_ESD_H_

#include "dsi_panel.h"
#include "dsi_defs.h"
#include "oplus_display_private_api.h"
#include "oplus_display_panel_common.h"

int oplus_panel_parse_esd_reg_read_configs(struct dsi_panel *panel);
bool oplus_panel_validate_reg_read(struct dsi_panel *panel);
int oplus_display_status_check_mipi_err_gpio(struct dsi_display *display);
void oplus_display_esd_check_mode_switch(struct dsi_panel *panel, int cmd_index);
bool oplus_display_check_status_pre(struct dsi_panel *panel);
#endif /* _OPLUS_ESD_H_ */

