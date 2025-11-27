// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015-2019, The Linux Foundation. All rights reserved.
 * Copyright (C) 2017-2020, Pixelworks, Inc.
 *
 * These files contain modifications made by Pixelworks, Inc., in 2019-2020.
 */
#include "dsi_iris_api.h"
#include "dsi_iris.h"
#include "dsi_iris_lightup.h"
#include "dsi_iris_lightup_ocp.h"
#include "dsi_iris_lp.h"
#include "dsi_iris_lut.h"
#include "dsi_iris_pq.h"
#include "dsi_iris_ioctl.h"
#include "dsi_iris_i3c.h"
#include "dsi_iris_loop_back.h"
#include "dsi_iris_log.h"
#include "dsi_iris_memc.h"
#include "dsi_iris_memc_helper.h"
#include "dsi_iris_timing_switch.h"
#include "dsi_iris_cmpt.h"


int iris_configure_i8(u32 display, u32 type, u32 value)
{
	int rc = 0;

	return rc;
}

int iris_configure_ex_i8(u32 display, u32 type, u32 count, u32 *values)
{
	int rc = 0;

	return rc;
}

int iris_configure_get_i8(u32 display, u32 type, u32 count, u32 *values)
{
	return 0;
}

int iris_dbgfs_adb_type_init_i8(struct dsi_display *display)
{
	return 0;
}
