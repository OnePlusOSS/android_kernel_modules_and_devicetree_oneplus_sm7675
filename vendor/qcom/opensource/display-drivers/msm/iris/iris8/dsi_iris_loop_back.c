// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015-2019, The Linux Foundation. All rights reserved.
 * Copyright (C) 2017-2020, Pixelworks, Inc.
 *
 * These files contain modifications made by Pixelworks, Inc., in 2019-2020.
 */
#include "dsi_iris_api.h"
#include "dsi_iris_i3c.h"
#include "dsi_iris_loop_back.h"
#include "dsi_iris_lightup.h"
#include "dsi_iris_lightup_ocp.h"
#include "dsi_iris_log.h"
#include "dsi_iris_lp.h"

#define BIT_SMT_EFIFO_PT_SQ		(1 << 0)
#define BIT_DUAL_PT				(1 << 1)
#define BIT_ATSPEED_EFIFO		(1 << 2)
#define BIT_SMT_PMU				(1 << 3)
#define BIT_SMT_EFIFO_PT_SF     (1 << 4)
#define BIT_SMT_EFIFO_PT_UF     (1 << 5)
#define BIT_SRAM_BIST_SQ        (1 << 6)
#define BIT_SRAM_BIST_NPLL      (1 << 7)

//these cases need release to customer
static uint32_t iris_loop_back_flag_i8 = (BIT_SMT_EFIFO_PT_SQ | BIT_DUAL_PT);

void iris_set_loopback_flag_i8(uint32_t val)
{
	iris_loop_back_flag_i8 = val;
}

uint32_t iris_get_loopback_flag_i8(void)
{
	return iris_loop_back_flag_i8;
}

int iris_loop_back_validate_i8(void)
{

	//TODO

	return 0;
}


int iris_mipi_rx0_validate_i8(void)
{
	int ret = 0;

	//TODO

	return ret;
}
