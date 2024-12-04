/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2015-2019, The Linux Foundation. All rights reserved.
 * Copyright (C) 2017-2020, Pixelworks, Inc.
 *
 * These files contain modifications made by Pixelworks, Inc., in 2019-2020.
 */
#ifndef __DSI_IRIS_MEMC_HELPER_DEF__
#define __DSI_IRIS_MEMC_HELPER_DEF__


#define PROC_INFO(_h, _v) BITS_SET(_v, 16, 16, _h)

enum {
	SCL_1D_ONLY,
	SCL_2D_ONLY,
	SCL_CNN_ONLY,
	SCL_CNN_1D,
	SCL_CNN_2D,
	SCL_STRATEGY_CNT
};

#define SRCNN_CASE(case)[case] = #case
static const char * const srcnn_case_name[] = {
	SRCNN_CASE(SCL_1D_ONLY),
	SRCNN_CASE(SCL_2D_ONLY),
	SRCNN_CASE(SCL_CNN_ONLY),
	SRCNN_CASE(SCL_CNN_1D),
	SRCNN_CASE(SCL_CNN_2D),
};
#undef SRCNN_CASE

enum {
	SCL_DATA_PATH0,
	SCL_DATA_PATH1,
	SCL_DATA_PATH_CNT
};

enum {
	PATH_SEL_META,
	PATH_SEL_REG,
	PATH_SEL_CNT
};

enum {
	SRCNN_MODE_AUTO,
	SRCNN_MODE_DISABLE,
	SRCNN_MODE_ENABLE,
	SRCNN_MODE_CNT,
};

enum {
	IRIS_SCL_IN,
	IRIS_SCL_OUT,
	IRIS_SCL_INOUT,
	IRIS_SCL_PP,
	IRIS_SCL_INOUT_PP,
	IRIS_SCL_TYPE_CNT
};

enum {
	CNN_LOWPOWER_MODEL = 0,
	CNN_NORMAL_MODEL1 = 1, /* Default for Right-Buffer */
	CNN_NORMAL_MODEL2 = 2, /* Default for Left-Buffer */
	CNN_NORMAL_MODEL3,
	CNN_NORMAL_MODEL4,
	CNN_NORMAL_MODEL5,
	CNN_NORMAL_MODEL6,
	CNN_NORMAL_MODEL7,
	/* ... */
	CNN_MODEL_CNT = 16,
	CNN_LAST_MODEL = 0xFF
};

enum { /* scl specific type */
	MV_STRATEGY = 0,
	IOINC_TAP,
	LP_MEMC,
	BLD_SCL_POS,
	SR2D_PRIME,
};

enum { /* ioinc tap */
	IOINC_TAG5 = 5,
	IOINC_TAG9 = 9,
};

enum { /* ioinc filter group */
	FILTER_SOFT = 0,
	FILTER_SHARP,
	FILTER_GROUP_CNT
};

enum { /* ioinc filter type */
	FILTER_HS_Y_LEVEL = 0,
	FILTER_HS_UV_LEVEL,
	FILTER_VS_Y_LEVEL,
	FILTER_VS_UV_LEVEL,
	FILTER_BASE_LEVEL,
	FILTER_TYPE_CNT
};

enum {
	SCL_2D_GF = 0,
	SCL_2D_DETECT,
	SCL_2D_PEAKING,
	SCL_2D_DTI,
	SCL_2D_PQ_CNT
};

enum { /* SCL change type */
	SCL_NO_CHANGE = 0,
	SCL_SWITCH_ONLY,
	SCL_FULL_CHANGE,
	SCL_CHANGE_TYPE_CNT
};

enum { /* ping-pong buffer for CNN model */
	CNN_DMA_BUF_LEFT,
	CNN_DMA_BUF_RIGHT,
	CNN_DMA_BUF_CNT
};

enum { /* PP Scaler1D working type */
	SCL_PP_VIDEO = 0,
	SCL_PP_GRAPHIC = 1,
	SCL_PP_CURSOR = 2,
	SCL_PP_BLD_OUT = 3,
	SCL_PP_POS_CNT
};

#endif //__DSI_IRIS_MEMC_HELPER_DEF__
