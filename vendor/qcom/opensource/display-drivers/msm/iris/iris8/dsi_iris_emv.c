// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015-2021, The Linux Foundation. All rights reserved.
 * Copyright (C) 2017-2021, Pixelworks, Inc.
 *
 * These files contain modifications made by Pixelworks, Inc., in 2019-2020.
 */
#include <linux/gcd.h>

#include <video/mipi_display.h>
#include <drm/drm_mipi_dsi.h>
#include "dsi_iris_api.h"
#include "dsi_iris_lightup.h"
#include "dsi_iris_lightup_ocp.h"
#include "dsi_iris.h"
#include "dsi_iris_pq.h"
#include "dsi_iris_lp.h"
#include "dsi_iris_timing_switch.h"
#include "dsi_iris_log.h"
#include "dsi_iris_reg_i8.h"
#include "dsi_iris_memc_i8.h"
#include "dsi_iris_emv_i8.h"
#include "dsi_iris_dual_i8.h"
#include "dsi_iris_i3c.h"


