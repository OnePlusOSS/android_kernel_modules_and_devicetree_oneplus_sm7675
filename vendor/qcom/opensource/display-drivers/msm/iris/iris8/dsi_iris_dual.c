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
#include <sde_dsc_helper.h>
#include "dsi_display.h"
#include "dsi_panel.h"
#include "dsi_iris.h"
#include "dsi_iris_api.h"
#include "dsi_iris_lightup.h"
#include "dsi_iris_lightup_ocp.h"
#include "dsi_iris_lp.h"
#include "dsi_iris_pq.h"
#include "dsi_iris_log.h"
#include "dsi_iris_reg_i8.h"
#include "dsi_iris_dual_i8.h"
#include "dsi_iris_emv_i8.h"
#include "dsi_iris_memc_i8.h"
#include "dsi_iris_memc_helper.h"
#include "dsi_iris_i3c.h"
#include "dsi_iris_cmpt.h"
#include "dsi_iris_timing_switch.h"


int iris_dual_blending_enable_i8(bool enable)
{
	return 0;
}

void iris_inc_osd_irq_cnt_i8(void)
{
	//TODO
}

void iris_register_osd_irq_i8(void *disp)
{
	//TODO
}

bool iris_is_display1_autorefresh_enabled_i8(void *phys_enc)
{
	return true;
}

