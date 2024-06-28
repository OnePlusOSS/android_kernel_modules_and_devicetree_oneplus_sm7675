/* SPDX-License-Identifier: GPL-2.0
 * aw87xxx_dsp.h
 *
 * Copyright (c) 2021 AWINIC Technology CO., LTD
 *
 * Author: Barry <zhaozhongbo@awinic.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#ifndef __AW87XXX_DSP_H__
#define __AW87XXX_DSP_H__

#include "aw87xxx_device.h"

/*#define AW_MTK_OPEN_DSP_PLATFORM*/
#define AW_QCOM_OPEN_DSP_PLATFORM

/*Note: The pord_ID is configured according to different platforms*/
#define AW_DSP_SLEEP_TIME	(10)

#define AW_DSP_MSG_HDR_VER (1)

#define AW_RX_DEFAULT_TOPO_ID		(0x1000FF01)
#define AW_RX_DEFAULT_PORT_ID		(0x4000)

#define AWDSP_RX_SET_ENABLE		(0x10013D11)
#define AWDSP_RX_PARAMS			(0x10013D12)
#define AWDSP_RX_VMAX_0			(0X10013D17)
#define AWDSP_RX_VMAX_1			(0X10013D18)
#define AW_MSG_ID_SPIN			(0x10013D2E)
#define AW_MSG_ID_ALGO_AUTHENTICATION	(0x10013D46)


enum {
	AW_SPIN_0 = 0,
	AW_SPIN_90,
	AW_SPIN_180,
	AW_SPIN_270,
	AW_SPIN_MAX,
};

typedef struct mtk_dsp_msg_header {
	int32_t type;
	int32_t opcode_id;
	int32_t version;
	int32_t reserver[3];
} mtk_dsp_hdr_t;

enum aw_rx_module_enable {
	AW_RX_MODULE_DISENABLE = 0,
	AW_RX_MODULE_ENABLE,
};

enum aw_dsp_msg_type {
	DSP_MSG_TYPE_DATA = 0,
	DSP_MSG_TYPE_CMD = 1,
};

enum aw_dsp_channel {
	AW_DSP_CHANNEL_0 = 0,
	AW_DSP_CHANNEL_1,
	AW_DSP_CHANNEL_MAX,
};

uint8_t aw87xxx_dsp_isEnable(void);
int aw87xxx_dsp_get_rx_module_enable(int *enable);
int aw87xxx_dsp_set_rx_module_enable(int enable);
int aw87xxx_dsp_get_vmax(uint32_t *vmax, int channel);
int aw87xxx_dsp_set_vmax(uint32_t vmax, int channel);
int aw87xxx_dsp_set_spin(uint32_t ctrl_value);
int aw87xxx_dsp_get_spin(void);
int aw87xxx_spin_set_record_val(void);
void aw87xxx_device_parse_port_id_dt(struct aw_device *aw_dev);
void aw87xxx_device_parse_topo_id_dt(struct aw_device *aw_dev);
#ifdef AW_ALGO_AUTH_DSP
int aw87xxx_dsp_get_algo_auth_data(struct aw_device *aw_dev, char *data, unsigned int data_len);
int aw87xxx_dsp_set_algo_auth_data(struct aw_device *aw_dev, char *data, unsigned int data_len);
#endif

#endif
