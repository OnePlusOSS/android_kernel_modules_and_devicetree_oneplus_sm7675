// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015-2019, The Linux Foundation. All rights reserved.
 * Copyright (C) 2017-2020, Pixelworks, Inc.
 *
 * These files contain modifications made by Pixelworks, Inc., in 2019-2020.
 */
#include <dsi_drm.h>
#include "dsi_iris_def.h"
#include "dsi_iris_log.h"
#include "dsi_iris_memc_helper.h"
#include "dsi_iris_memc_helper_def.h"
#include "dsi_iris_lightup.h"
#include "dsi_iris_i3c.h"


void iris_dsc_up_format_i8(bool up, uint32_t *payload, uint32_t pps_sel)
{
	//TODO
}

void iris_ioinc_pp_init_i8(void)
{
	//TODO
}

bool iris_ioinc_pp_proc_i8(bool enable, uint32_t ioinc_pos,
		int32_t in_h, int32_t in_v, int32_t out_h, int32_t out_v,
		uint32_t path_sel, uint32_t sel_mode, bool *blend_changed)
{
	bool changed = false;

	return changed;
}

void iris_ioinc_pp_disable_i8(void)
{
	//TODO
}

void iris_ioinc_pp_filter_i8(uint32_t count, uint32_t *values)
{
	//TODO
}
