// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015-2019, The Linux Foundation. All rights reserved.
 * Copyright (C) 2017-2020, Pixelworks, Inc.
 *
 * These files contain modifications made by Pixelworks, Inc., in 2019-2020.
 */
#include <video/mipi_display.h>
#include <drm/drm_bridge.h>
#include <drm/drm_encoder.h>
#include "dsi_drm.h"
#include <sde_encoder.h>
#include <sde_encoder_phys.h>
#include <sde_trace.h>
#include "dsi_iris_api.h"
#include "dsi_iris_lightup.h"
#include "dsi_iris_lightup_ocp.h"
#include "dsi_iris_lp.h"
#include "dsi_iris_pq.h"
#include "dsi_iris_gpio.h"
#include "dsi_iris_timing_switch.h"
#include "dsi_iris_log.h"
#include "dsi_iris_i3c.h"
#include "dsi_iris_dts_fw.h"
#include <linux/kobject.h>
#include "dsi_iris_reg_i8.h"


void iris_global_var_init_i8(void)
{
	//TODO
}

void iris_dma_gen_ctrl_i8(int channels, int source, bool chain)
{
	//TODO
}

int iris_esd_check_i8(void)
{
	int rc = 1;

	return rc;
}

