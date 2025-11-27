/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2015-2019, The Linux Foundation. All rights reserved.
 * Copyright (C) 2017-2020, Pixelworks, Inc.
 *
 * These files contain modifications made by Pixelworks, Inc., in 2019-2020.
 */
#ifndef _DSI_IRIS_MEMC_I8_
#define _DSI_IRIS_MEMC_I8_


void iris_frc_timing_setting_update_i8(void);
void iris_frc_setting_init_i8(void);
void iris_parse_memc_param0_i8(struct device_node *np);
void iris_parse_memc_param1_i8(void);
int iris_dbgfs_memc_init_i8(struct dsi_display *display);
int iris_low_latency_mode_get_i8(void);

#endif
