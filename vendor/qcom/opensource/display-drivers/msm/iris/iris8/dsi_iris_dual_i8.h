/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2015-2019, The Linux Foundation. All rights reserved.
 * Copyright (C) 2017-2020, Pixelworks, Inc.
 *
 * These files contain modifications made by Pixelworks, Inc., in 2019-2020.
 */
#ifndef _DSI_IRIS_DUAL_I8_
#define _DSI_IRIS_DUAL_I8_


bool iris_is_display1_autorefresh_enabled_i8(void *phys_enc);
void iris_register_osd_irq_i8(void *disp);
void iris_inc_osd_irq_cnt_i8(void);
int iris_dual_blending_enable_i8(bool enable);
#endif
