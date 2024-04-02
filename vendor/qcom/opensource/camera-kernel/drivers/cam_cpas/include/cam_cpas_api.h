/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2023, Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _CAM_CPAS_API_H_
#define _CAM_CPAS_API_H_

#include <linux/device.h>
#include <linux/platform_device.h>

#include <media/cam_cpas.h>
#include "cam_soc_util.h"
#include "cam_req_mgr_interface.h"

#define CAM_HW_IDENTIFIER_LENGTH 128

/* Default AXI Bandwidth vote */
#define CAM_CPAS_DEFAULT_AXI_BW 1024

/* Default RT AXI Bandwidth vote */
#define CAM_CPAS_DEFAULT_RT_AXI_BW 2000000000L

#define CAM_CPAS_MAX_PATHS_PER_CLIENT 15
#define CAM_CPAS_API_PATH_DATA_STD_START 512

#define CAM_CPAS_VOTE_LEVEL_NONE 0
#define CAM_CPAS_VOTE_LEVEL_MAX 3

/* Qos Selection mask */
#define CAM_CPAS_QOS_DEFAULT_SETTINGS_MASK 0x1
#define CAM_CPAS_QOS_CUSTOM_SETTINGS_MASK  0x2

/**
 * enum cam_cpas_regbase_types - Enum for cpas regbase available for clients
 *                             to read/write
 */
enum cam_cpas_regbase_types {
	CAM_CPAS_REGBASE_CPASTOP,
	CAM_CPAS_REGBASE_MAX
};

/**
 * enum cam_cpas_vote_type - Enum for cpas vote type
 */
enum cam_cpas_vote_type {
	CAM_CPAS_VOTE_TYPE_HLOS,
	CAM_CPAS_VOTE_TYPE_DRV,
	CAM_CPAS_VOTE_TYPE_MAX,
};

/**
 * enum cam_cpas_hw_index  - Enum for identify HW index
 */
enum cam_cpas_hw_index {
	CAM_CPAS_HW_IDX_ANY = 0,
	CAM_CPAS_HW_IDX_0 = 1<<0,
	CAM_CPAS_HW_IDX_1 = 1<<1,
	CAM_CPAS_HW_IDX_2 = 1<<2,
	CAM_CPAS_HW_IDX_3 = 1<<3,
	CAM_CPAS_HW_IDX_4 = 1<<4,
	CAM_CPAS_HW_IDX_5 = 1<<5,
	CAM_CPAS_HW_IDX_6 = 1<<6,
	CAM_CPAS_HW_IDX_7 = 1<<7,
	CAM_CPAS_HW_IDX_MAX = 1<<8
};

/**
 * enum cam_cpas_camera_version Enum for Titan Camera Versions
 */
enum cam_cpas_camera_version {
	CAM_CPAS_CAMERA_VERSION_NONE = 0,
	CAM_CPAS_CAMERA_VERSION_150  = 0x00010500,
	CAM_CPAS_CAMERA_VERSION_170  = 0x00010700,
	CAM_CPAS_CAMERA_VERSION_175  = 0x00010705,
	CAM_CPAS_CAMERA_VERSION_480  = 0x00040800,
	CAM_CPAS_CAMERA_VERSION_520  = 0x00050200,
	CAM_CPAS_CAMERA_VERSION_540  = 0x00050400,
	CAM_CPAS_CAMERA_VERSION_580  = 0x00050800,
	CAM_CPAS_CAMERA_VERSION_545  = 0x00050405,
	CAM_CPAS_CAMERA_VERSION_570  = 0x00050700,
	CAM_CPAS_CAMERA_VERSION_680  = 0x00060800,
	CAM_CPAS_CAMERA_VERSION_165  = 0x00010605,
	CAM_CPAS_CAMERA_VERSION_780  = 0x00070800,
	CAM_CPAS_CAMERA_VERSION_640  = 0x00060400,
	CAM_CPAS_CAMERA_VERSION_880  = 0x00080800,
	CAM_CPAS_CAMERA_VERSION_980  = 0x00090800,
	CAM_CPAS_CAMERA_VERSION_860  = 0x00080600,
	CAM_CPAS_CAMERA_VERSION_770  = 0x00070700,
	CAM_CPAS_CAMERA_VERSION_MAX
};

/**
 * enum cam_cpas_version Enum for Titan CPAS Versions
 */
enum cam_cpas_version {
	CAM_CPAS_VERSION_NONE = 0,
	CAM_CPAS_VERSION_100  = 0x10000000,
	CAM_CPAS_VERSION_101  = 0x10000001,
	CAM_CPAS_VERSION_110  = 0x10010000,
	CAM_CPAS_VERSION_120  = 0x10020000,
	CAM_CPAS_VERSION_130  = 0x10030000,
	CAM_CPAS_VERSION_200  = 0x20000000,
	CAM_CPAS_VERSION_210  = 0x20010000,
	CAM_CPAS_VERSION_MAX
};

/**
 * enum cam_cpas_camera_version_map_id Enum for camera version map id
 * This enum is mapped with cam_cpas_camera_version
 */
enum cam_cpas_camera_version_map_id {
	CAM_CPAS_CAMERA_VERSION_ID_150  = 0x0,
	CAM_CPAS_CAMERA_VERSION_ID_170  = 0x1,
	CAM_CPAS_CAMERA_VERSION_ID_175  = 0x2,
	CAM_CPAS_CAMERA_VERSION_ID_480  = 0x3,
	CAM_CPAS_CAMERA_VERSION_ID_580  = 0x4,
	CAM_CPAS_CAMERA_VERSION_ID_520  = 0x5,
	CAM_CPAS_CAMERA_VERSION_ID_540  = 0x6,
	CAM_CPAS_CAMERA_VERSION_ID_545  = 0x7,
	CAM_CPAS_CAMERA_VERSION_ID_570  = 0x8,
	CAM_CPAS_CAMERA_VERSION_ID_680  = 0x9,
	CAM_CPAS_CAMERA_VERSION_ID_165  = 0xA,
	CAM_CPAS_CAMERA_VERSION_ID_780  = 0xB,
	CAM_CPAS_CAMERA_VERSION_ID_640  = 0xC,
	CAM_CPAS_CAMERA_VERSION_ID_880  = 0xD,
	CAM_CPAS_CAMERA_VERSION_ID_980  = 0xE,
	CAM_CPAS_CAMERA_VERSION_ID_860  = 0xF,
	CAM_CPAS_CAMERA_VERSION_ID_770  = 0x10,
	CAM_CPAS_CAMERA_VERSION_ID_MAX
};

/**
 * enum cam_cpas_version_map_id Enum for cpas version map id
 * This enum is mapped with cam_cpas_version
 */
enum cam_cpas_version_map_id {
	CAM_CPAS_VERSION_ID_100  = 0x0,
	CAM_CPAS_VERSION_ID_101  = 0x1,
	CAM_CPAS_VERSION_ID_110  = 0x2,
	CAM_CPAS_VERSION_ID_120  = 0x3,
	CAM_CPAS_VERSION_ID_130  = 0x4,
	CAM_CPAS_VERSION_ID_200  = 0x5,
	CAM_CPAS_VERSION_ID_210  = 0x6,
	CAM_CPAS_VERSION_ID_MAX
};

/**
 * enum cam_cpas_hw_version - Enum for Titan CPAS HW Versions
 */
enum cam_cpas_hw_version {
	CAM_CPAS_TITAN_NONE = 0,
	CAM_CPAS_TITAN_150_V100 = 0x150100,
	CAM_CPAS_TITAN_165_V100 = 0x165100,
	CAM_CPAS_TITAN_170_V100 = 0x170100,
	CAM_CPAS_TITAN_170_V110 = 0x170110,
	CAM_CPAS_TITAN_170_V120 = 0x170120,
	CAM_CPAS_TITAN_170_V200 = 0x170200,
	CAM_CPAS_TITAN_175_V100 = 0x175100,
	CAM_CPAS_TITAN_175_V101 = 0x175101,
	CAM_CPAS_TITAN_175_V120 = 0x175120,
	CAM_CPAS_TITAN_175_V130 = 0x175130,
	CAM_CPAS_TITAN_480_V100 = 0x480100,
	CAM_CPAS_TITAN_580_V100 = 0x580100,
	CAM_CPAS_TITAN_540_V100 = 0x540100,
	CAM_CPAS_TITAN_520_V100 = 0x520100,
	CAM_CPAS_TITAN_545_V100 = 0x545100,
	CAM_CPAS_TITAN_570_V100 = 0x570100,
	CAM_CPAS_TITAN_570_V200 = 0x570200,
	CAM_CPAS_TITAN_680_V100 = 0x680100,
	CAM_CPAS_TITAN_680_V110 = 0x680110,
	CAM_CPAS_TITAN_780_V100 = 0x780100,
	CAM_CPAS_TITAN_640_V200 = 0x640200,
	CAM_CPAS_TITAN_640_V210 = 0x640210,
	CAM_CPAS_TITAN_880_V100 = 0x880100,
	CAM_CPAS_TITAN_980_V100 = 0x980100,
	CAM_CPAS_TITAN_860_V100 = 0x860100,
	CAM_CPAS_TITAN_770_V100 = 0x770100,
	CAM_CPAS_TITAN_MAX
};

/**
 * enum cam_camnoc_slave_error_codes - Enum for camnoc slave error codes
 *
 */
enum cam_camnoc_slave_error_codes {
	CAM_CAMNOC_TARGET_ERROR,
	CAM_CAMNOC_ADDRESS_DECODE_ERROR,
	CAM_CAMNOC_UNSUPPORTED_REQUEST_ERROR,
	CAM_CAMNOC_DISCONNECTED_TARGET_ERROR,
	CAM_CAMNOC_SECURITY_VIOLATION,
	CAM_CAMNOC_HIDDEN_SECURITY_VIOLATION,
	CAM_CAMNOC_TIME_OUT,
	CAM_CAMNOC_UNUSED,
};

/**
 * enum cam_camnoc_irq_type - Enum for camnoc irq types
 *
 * @CAM_CAMNOC_IRQ_SLAVE_ERROR: Each slave port in CAMNOC (3 QSB ports and
 *                              1 QHB port) has an error logger. The error
 *                              observed at any slave port is logged into
 *                              the error logger register and an IRQ is
 *                              triggered
 * @CAM_CAMNOC_IRQ_IFE_UBWC_ENCODE_ERROR      : Triggered if any error detected
 *                                              in the IFE UBWC encoder instance
 * @CAM_CAMNOC_IRQ_IFE_UBWC_STATS_ENCODE_ERROR: Triggered if any error detected
 *                                              in the IFE UBWC-Stats encoder
 *                                              instance
 * @CAM_CAMNOC_IRQ_IFE02_UBWC_ENCODE_ERROR  : Triggered if any error detected
 *                                            in the IFE0 UBWC encoder instance
 * @CAM_CAMNOC_IRQ_IFE13_UBWC_ENCODE_ERROR  : Triggered if any error detected
 *                                            in the IFE1 or IFE3 UBWC encoder
 *                                            instance
 * @CAM_CAMNOC_IRQ_IFE0_UBWC_ENCODE_ERROR   : Triggered if any error detected
 *                                            in the IFE0 UBWC encoder instance
 * @CAM_CAMNOC_IRQ_IFE1_WR_UBWC_ENCODE_ERROR  : Triggered if any error detected
 *                                            in the IFE1 UBWC encoder
 *                                            instance
 * @CAM_CAMNOC_IRQ_IPE_UBWC_ENCODE_ERROR    : Triggered if any error detected
 *                                            in the IPE write path encoder
 *                                            instance
 * @CAM_CAMNOC_IRQ_BPS_UBWC_ENCODE_ERROR    : Triggered if any error detected
 *                                            in the BPS write path encoder
 *                                            instance
 * @CAM_CAMNOC_IRQ_IPE1_BPS_UBWC_DECODE_ERROR: Triggered if any error detected
 *                                             in the IPE1/BPS read path decoder
 *                                             instance
 * @CAM_CAMNOC_IRQ_IPE0_UBWC_DECODE_ERROR    : Triggered if any error detected
 *                                             in the IPE0 read path decoder
 *                                             instance
 * @CAM_CAMNOC_IRQ_IPE1_UBWC_DECODE_ERROR    : Triggered if any error detected
 *                                             in the IPE1 read path decoder
 *                                             instance
 * @CAM_CAMNOC_IRQ_IPE_BPS_UBWC_DECODE_ERROR: Triggered if any error detected
 *                                            in the IPE/BPS UBWC decoder
 *                                            instance
 * @CAM_CAMNOC_IRQ_IPE_BPS_UBWC_ENCODE_ERROR: Triggered if any error detected
 *                                            in the IPE/BPS UBWC encoder
 *                                            instance
 * @CAM_CAMNOC_IRQ_OFE_WR_UBWC_ENCODE_ERROR : Triggered if any error detected
 *                                            in the OFE write UBWC decoder
 *                                            instance
 * @CAM_CAMNOC_IRQ_OFE_RD_UBWC_DECODE_ERROR : Triggered if any error detected
 *                                            in the OFE read UBWC decoder
 *                                            instance
 * @CAM_CAMNOC_IRQ_TFE_UBWC_ENCODE_ERROR    : Triggered if any error detected
 *                                            in the TFE UBWC encoder
 *                                            instance
 * @CAM_CAMNOC_IRQ_AHB_TIMEOUT              : Triggered when the QHS_ICP slave
 *                                            times out after 4000 AHB cycles
 */
enum cam_camnoc_irq_type {
	CAM_CAMNOC_IRQ_SLAVE_ERROR,
	CAM_CAMNOC_IRQ_IFE_UBWC_ENCODE_ERROR,
	CAM_CAMNOC_IRQ_IFE_UBWC_STATS_ENCODE_ERROR,
	CAM_CAMNOC_IRQ_IFE_UBWC_STATS_1_ENCODE_ERROR,
	CAM_CAMNOC_IRQ_IFE02_UBWC_ENCODE_ERROR,
	CAM_CAMNOC_IRQ_IFE13_UBWC_ENCODE_ERROR,
	CAM_CAMNOC_IRQ_IFE0_UBWC_ENCODE_ERROR,
	CAM_CAMNOC_IRQ_IFE1_WRITE_UBWC_ENCODE_ERROR,
	CAM_CAMNOC_IRQ_IPE_UBWC_ENCODE_ERROR,
	CAM_CAMNOC_IRQ_BPS_UBWC_ENCODE_ERROR,
	CAM_CAMNOC_IRQ_IPE1_BPS_UBWC_DECODE_ERROR,
	CAM_CAMNOC_IRQ_IPE0_UBWC_DECODE_ERROR,
	CAM_CAMNOC_IRQ_IPE1_UBWC_DECODE_ERROR,
	CAM_CAMNOC_IRQ_IPE_BPS_UBWC_DECODE_ERROR,
	CAM_CAMNOC_IRQ_IPE_BPS_UBWC_ENCODE_ERROR,
	CAM_CAMNOC_IRQ_OFE_WR_UBWC_ENCODE_ERROR,
	CAM_CAMNOC_IRQ_OFE_RD_UBWC_DECODE_ERROR,
	CAM_CAMNOC_IRQ_TFE_UBWC_ENCODE_ERROR,
	CAM_CAMNOC_IRQ_AHB_TIMEOUT,
};


/**
 * enum cam_sys_cache_config_types - Enum for camera llc's
 */
enum cam_sys_cache_config_types {
	CAM_LLCC_SMALL_1 = 0,
	CAM_LLCC_SMALL_2 = 1,
	CAM_LLCC_LARGE_1 = 2,
	CAM_LLCC_LARGE_2 = 3,
	CAM_LLCC_LARGE_3 = 4,
	CAM_LLCC_LARGE_4 = 5,
	CAM_LLCC_MAX     = 6,
};

/**
 * enum cam_sys_cache_llcc_staling_mode - Enum for camera llc's stalling mode
 */
enum cam_sys_cache_llcc_staling_mode {
	CAM_LLCC_STALING_MODE_CAPACITY,
	CAM_LLCC_STALING_MODE_NOTIFY,
	CAM_LLCC_STALING_MODE_MAX,
};

/**
 * enum cam_sys_cache_llcc_staling_mode - Enum for camera llc's stalling mode
 */
enum cam_sys_cache_llcc_staling_op_type {
	CAM_LLCC_NOTIFY_STALING_EVICT,
	CAM_LLCC_NOTIFY_STALING_FORGET,
	CAM_LLCC_NOTIFY_STALING_OPS_MAX
};

/**
 * enum cam_subparts_index - Enum for camera subparts indices
 */
enum cam_subparts_index {
	CAM_IFE_HW_IDX,
	CAM_IFE_LITE_HW_IDX,
	CAM_SFE_HW_IDX,
	CAM_CUSTOM_HW_IDX
};

/**
 * struct cam_camnoc_irq_slave_err_data : Data for Slave error.
 *
 * @mainctrl     : Err logger mainctrl info
 * @errvld       : Err logger errvld info
 * @errlog0_low  : Err logger errlog0_low info
 * @errlog0_high : Err logger errlog0_high info
 * @errlog1_low  : Err logger errlog1_low info
 * @errlog1_high : Err logger errlog1_high info
 * @errlog2_low  : Err logger errlog2_low info
 * @errlog2_high : Err logger errlog2_high info
 * @errlog3_low  : Err logger errlog3_low info
 * @errlog3_high : Err logger errlog3_high info
 *
 */
struct cam_camnoc_irq_slave_err_data {
	union {
		struct {
			uint32_t stall_en : 1; /* bit 0 */
			uint32_t fault_en : 1; /* bit 1 */
			uint32_t rsv      : 30; /* bits 2-31 */
		};
		uint32_t value;
	} mainctrl;
	union {
		struct {
			uint32_t err_vld : 1; /* bit 0 */
			uint32_t rsv     : 31; /* bits 1-31 */
		};
		uint32_t value;
	} errvld;
	union {
		struct {
			uint32_t loginfo_vld : 1; /* bit 0 */
			uint32_t word_error  : 1; /* bit 1 */
			uint32_t non_secure  : 1; /* bit 2 */
			uint32_t device      : 1; /* bit 3 */
			uint32_t opc         : 3; /* bits 4 - 6 */
			uint32_t rsv0        : 1; /* bit 7 */
			uint32_t err_code    : 3; /* bits 8 - 10 */
			uint32_t sizef       : 3; /* bits 11 - 13 */
			uint32_t rsv1        : 2; /* bits 14 - 15 */
			uint32_t addr_space  : 6; /* bits 16 - 21 */
			uint32_t rsv2        : 10; /* bits 22 - 31 */
		};
		uint32_t value;
	}  errlog0_low;
	union {
		struct {
			uint32_t len1 : 10; /* bits 0 - 9 */
			uint32_t rsv  : 22; /* bits 10 - 31 */
		};
		uint32_t value;
	} errlog0_high;
	union {
		struct {
			uint32_t path : 16; /* bits 0 - 15 */
			uint32_t rsv  : 16; /* bits 16 - 31 */
		};
		uint32_t value;
	} errlog1_low;
	union {
		struct {
			uint32_t extid : 18; /* bits 0 - 17 */
			uint32_t rsv   : 14; /* bits 18 - 31 */
		};
		uint32_t value;
	} errlog1_high;
	union {
		struct {
			uint32_t errlog2_lsb : 32; /* bits 0 - 31 */
		};
		uint32_t value;
	} errlog2_low;
	union {
		struct {
			uint32_t errlog2_msb : 16; /* bits 0 - 16 */
			uint32_t rsv         : 16; /* bits 16 - 31 */
		};
		uint32_t value;
	} errlog2_high;
	union {
		struct {
			uint32_t errlog3_lsb : 32; /* bits 0 - 31 */
		};
		uint32_t value;
	} errlog3_low;
	union {
		struct {
			uint32_t errlog3_msb : 32; /* bits 0 - 31 */
		};
		uint32_t value;
	} errlog3_high;
};

/**
 * struct cam_camnoc_irq_ubwc_enc_data : Data for UBWC Encode error.
 *
 * @encerr_status : Encode error status
 *
 */
struct cam_camnoc_irq_ubwc_enc_data {
	union {
		struct {
			uint32_t encerrstatus : 3; /* bits 0 - 2 */
			uint32_t rsv          : 29; /* bits 3 - 31 */
		};
		uint32_t value;
	} encerr_status;
};

/**
 * struct cam_camnoc_irq_ubwc_dec_data : Data for UBWC Decode error.
 *
 * @decerr_status : Decoder error status
 * @thr_err       : Set to 1 if
 *                  At least one of the bflc_len fields in the bit steam exceeds
 *                  its threshold value. This error is possible only for
 *                  RGBA1010102, TP10, and RGB565 formats
 * @fcl_err       : Set to 1 if
 *                  Fast clear with a legal non-RGB format
 * @len_md_err    : Set to 1 if
 *                  The calculated burst length does not match burst length
 *                  specified by the metadata value
 * @format_err    : Set to 1 if
 *                  Illegal format
 *                  1. bad format :2,3,6
 *                  2. For 32B MAL, metadata=6
 *                  3. For 32B MAL RGB565, Metadata != 0,1,7
 *                  4. For 64B MAL RGB565, metadata[3:1] == 1,2
 *
 */
struct cam_camnoc_irq_ubwc_dec_data {
	union {
		struct {
			uint32_t thr_err    : 1; /* bit 0 */
			uint32_t fcl_err    : 1; /* bit 1 */
			uint32_t len_md_err : 1; /* bit 2 */
			uint32_t format_err : 1; /* bit 3 */
			uint32_t rsv        : 28; /* bits 4 - 31 */
		};
		uint32_t value;
	} decerr_status;
};

struct cam_camnoc_irq_ahb_timeout_data {
	uint32_t data;
};

/**
 * struct cam_cpas_irq_data : CAMNOC IRQ data
 *
 * @irq_type  : To identify the type of IRQ
 * @u         : Union of irq err data information
 * @slave_err : Data for Slave error.
 *              Valid if type is CAM_CAMNOC_IRQ_SLAVE_ERROR
 * @enc_err   : Data for UBWC Encode error.
 *              Valid if type is one of below:
 *              CAM_CAMNOC_IRQ_IFE02_UBWC_ENCODE_ERROR
 *              CAM_CAMNOC_IRQ_IFE13_UBWC_ENCODE_ERROR
 *              CAM_CAMNOC_IRQ_IPE_BPS_UBWC_ENCODE_ERROR
 * @dec_err   : Data for UBWC Decode error.
 *              Valid if type is CAM_CAMNOC_IRQ_IPE_BPS_UBWC_DECODE_ERROR
 * @ahb_err   : Data for Slave error.
 *              Valid if type is CAM_CAMNOC_IRQ_AHB_TIMEOUT
 *
 */
struct cam_cpas_irq_data {
	enum cam_camnoc_irq_type irq_type;
	union {
		struct cam_camnoc_irq_slave_err_data   slave_err;
		struct cam_camnoc_irq_ubwc_enc_data    enc_err;
		struct cam_camnoc_irq_ubwc_dec_data    dec_err;
		struct cam_camnoc_irq_ahb_timeout_data ahb_err;
	} u;
};

/*
 * CPAS client callback
 *
 * @client_handle : CPAS client handle
 * @userdata      : User data given at the time of register
 * @irq_data      : Event data
 */
typedef bool (*cam_cpas_client_cb_func)(
	uint32_t client_handle, void *userdata,
	struct cam_cpas_irq_data *irq_data);

/**
 * struct cam_cpas_register_params : Register params for cpas client
 *
 * @identifier        : Input identifier string which is the device label
 *                      from dt like vfe, ife, jpeg etc
 * @cell_index        : Input integer identifier pointing to the cell index
 *                      from dt of the device. This can be used to form a
 *                      unique string with @identifier like vfe0, ife1,
 *                      jpeg0, etc
 * @dev               : device handle
 * @userdata          : Input private data which will be passed as
 *                      an argument while callback.
 * @cam_cpas_callback : Input callback pointer for triggering the
 *                      callbacks from CPAS driver.
 * @client_handle     : Output Unique handle generated for this register
 *
 */
struct cam_cpas_register_params {
	char            identifier[CAM_HW_IDENTIFIER_LENGTH];
	uint32_t        cell_index;
	struct device  *dev;
	void           *userdata;
	cam_cpas_client_cb_func cam_cpas_client_cb;
	uint32_t        client_handle;
};

/**
 * enum cam_vote_type - Enum for voting type
 *
 * @CAM_VOTE_ABSOLUTE : Absolute vote
 * @CAM_VOTE_DYNAMIC  : Dynamic vote
 */
enum cam_vote_type {
	CAM_VOTE_ABSOLUTE,
	CAM_VOTE_DYNAMIC,
};

/**
 * struct cam_ahb_vote : AHB vote
 *
 * @type  : AHB voting type.
 *          CAM_VOTE_ABSOLUTE : vote based on the value 'level' is set
 *          CAM_VOTE_DYNAMIC  : vote calculated dynamically using 'freq'
 *                              and 'dev' handle is set
 * @level : AHB vote level
 * @freq  : AHB vote dynamic frequency
 *
 */
struct cam_ahb_vote {
	enum cam_vote_type   type;
	union {
		enum cam_vote_level  level;
		unsigned long        freq;
	} vote;
};

/**
 * struct cam_cpas_axi_per_path_bw_vote - Internal per path bandwidth vote information
 *
 * @usage_data:              client usage data (left/right/rdi)
 * @transac_type:            Transaction type on the path (read/write)
 * @path_data_type:          Path for which vote is given (video, display, rdi)
 * @vote_level:              Vote level for this path
 * @camnoc_bw:               CAMNOC bw for this path
 * @mnoc_ab_bw:              MNOC AB bw for this path
 * @mnoc_ib_bw:              MNOC IB bw for this path
 */
struct cam_cpas_axi_per_path_bw_vote {
	uint32_t                      usage_data;
	uint32_t                      transac_type;
	uint32_t                      path_data_type;
	uint32_t                      vote_level;
	uint64_t                      camnoc_bw;
	uint64_t                      mnoc_ab_bw;
	uint64_t                      mnoc_ib_bw;
};

/**
 * struct cam_axi_vote : AXI vote
 *
 * @num_paths: Number of paths on which BW vote is sent to CPAS
 * @axi_path: Per path BW vote info
 *
 */
struct cam_axi_vote {
	uint32_t num_paths;
	struct cam_cpas_axi_per_path_bw_vote axi_path[CAM_CPAS_MAX_PATHS_PER_CLIENT];
};

/**
 * cam_cpas_prepare_subpart_info()
 *
 * @brief: API to update the number of ifes, ife_lites, sfes and custom
 *         in the struct cam_cpas_private_soc.
 *
 * @idx                   : Camera subpart index
 * @num_subpart_available : Number of available subparts
 * @num_subpart_functional: Number of functional subparts
 *
 * @returns 0 on success & -EINVAL when @subpart_type is invalid.
 *
 */
int cam_cpas_prepare_subpart_info(
	enum cam_subparts_index idx, uint32_t num_subpart_available,
	uint32_t num_subpart_functional);

/**
 * cam_cpas_register_client()
 *
 * @brief: API to register cpas client
 *
 * @register_params: Input params to register as a client to CPAS
 *
 * @return 0 on success.
 *
 */
int cam_cpas_register_client(
	struct cam_cpas_register_params *register_params);

/**
 * cam_cpas_unregister_client()
 *
 * @brief: API to unregister cpas client
 *
 * @client_handle: Client handle to be unregistered
 *
 * @return 0 on success.
 *
 */
int cam_cpas_unregister_client(uint32_t client_handle);

/**
 * cam_cpas_start()
 *
 * @brief: API to start cpas client hw. Clients have to vote for minimal
 *     bandwidth requirements for AHB, AXI. Use cam_cpas_update_ahb_vote
 *     to scale bandwidth after start.
 *
 * @client_handle: client cpas handle
 * @ahb_vote     : Pointer to ahb vote info
 * @axi_vote     : Pointer to axi bandwidth vote info
 *
 * If AXI vote is not applicable to a particular client, use the value exposed
 * by CAM_CPAS_DEFAULT_AXI_BW as the default vote request.
 *
 * @return 0 on success.
 *
 */
int cam_cpas_start(
	uint32_t               client_handle,
	struct cam_ahb_vote   *ahb_vote,
	struct cam_axi_vote   *axi_vote);

/**
 * cam_cpas_stop()
 *
 * @brief: API to stop cpas client hw. Bandwidth for AHB, AXI votes
 *     would be removed for this client on this call. Clients should not
 *     use cam_cpas_update_ahb_vote or cam_cpas_update_axi_vote
 *     to remove their bandwidth vote.
 *
 * @client_handle: client cpas handle
 *
 * @return 0 on success.
 *
 */
int cam_cpas_stop(uint32_t client_handle);

/**
 * cam_cpas_update_ahb_vote()
 *
 * @brief: API to update AHB vote requirement. Use this function only
 *     between cam_cpas_start and cam_cpas_stop in case clients wants
 *     to scale to different vote level. Do not use this function to de-vote,
 *     removing client's vote is implicit on cam_cpas_stop
 *
 * @client_handle : Client cpas handle
 * @ahb_vote      : Pointer to ahb vote info
 *
 * @return 0 on success.
 *
 */
int cam_cpas_update_ahb_vote(
	uint32_t               client_handle,
	struct cam_ahb_vote   *ahb_vote);

/**
 * cam_cpas_update_axi_vote()
 *
 * @brief: API to update AXI vote requirement. Use this function only
 *     between cam_cpas_start and cam_cpas_stop in case clients wants
 *     to scale to different vote level. Do not use this function to de-vote,
 *     removing client's vote is implicit on cam_cpas_stop
 *
 * @client_handle : Client cpas handle
 * @axi_vote      : Pointer to axi bandwidth vote info
 *
 * @return 0 on success.
 *
 */
int cam_cpas_update_axi_vote(
	uint32_t             client_handle,
	struct cam_axi_vote *axi_vote);

/**
 * cam_cpas_reg_write()
 *
 * @brief: API to write a register value in CPAS register space
 *
 * @client_handle : Client cpas handle
 * @reg_base      : Register base identifier
 * @offset        : Offset from the register base address
 * @mb            : Whether to do reg write with memory barrier
 * @value         : Value to be written in register
 *
 * @return 0 on success.
 *
 */
int cam_cpas_reg_write(
	uint32_t                  client_handle,
	enum cam_cpas_regbase_types reg_base,
	uint32_t                  offset,
	bool                      mb,
	uint32_t                  value);

/**
 * cam_cpas_reg_read()
 *
 * @brief: API to read a register value from CPAS register space
 *
 * @client_handle : Client cpas handle
 * @reg_base      : Register base identifier
 * @offset        : Offset from the register base address
 * @mb            : Whether to do reg read with memory barrier
 * @value         : Value to be red from register
 *
 * @return 0 on success.
 *
 */
int cam_cpas_reg_read(
	uint32_t                  client_handle,
	enum cam_cpas_regbase_types reg_base,
	uint32_t                  offset,
	bool                      mb,
	uint32_t                 *value);

/**
 * cam_cpas_get_hw_info()
 *
 * @brief: API to get camera hw information
 *
 * @camera_family  : Camera family type. One of
 *                   CAM_FAMILY_CAMERA_SS
 *                   CAM_FAMILY_CPAS_SS
 * @camera_version : Camera platform version
 * @cpas_version   : Camera cpas version
 * @cam_caps       : Camera capability array
 * @num_cap_mask   : number of capability masks
 * @cam_fuse_info  : Camera fuse info
 * @domain_id_info : Domain id info
 *
 * @return 0 on success.
 *
 */
int cam_cpas_get_hw_info(
	uint32_t                       *camera_family,
	struct cam_hw_version          *camera_version,
	struct cam_hw_version          *cpas_version,
	uint32_t                      **cam_caps,
	uint32_t                       *num_cap_mask,
	struct cam_cpas_fuse_info      *cam_fuse_info,
	struct cam_cpas_domain_id_caps *domain_id_info);

/**
 * cam_cpas_get_cpas_hw_version()
 *
 * @brief: API to get camera cpas hw version
 *
 * @hw_version  : Camera cpas hw version
 *
 * @return 0 on success.
 *
 */
int cam_cpas_get_cpas_hw_version(uint32_t *hw_version);

/**
 * cam_cpas_is_feature_supported()
 *
 * @brief: API to get camera features
 *
 * @flag  : Camera hw features to check
 *
 * @hw_map : To indicate which HWs are supported
 *
 * @fule_val : Return fule value in case of value type feature
 *
 * @return 1 if feature is supported
 *
 */
bool cam_cpas_is_feature_supported(uint32_t flag, uint32_t hw_map,
	uint32_t *fuse_val);

/**
 * cam_cpas_axi_util_path_type_to_string()
 *
 * @brief: API to get string for given path type
 *
 * @path_data_type  : Path type
 *
 * @return string.
 *
 */
const char *cam_cpas_axi_util_path_type_to_string(
	uint32_t path_data_type);

/**
 * cam_cpas_axi_util_trans_type_to_string()
 *
 * @brief: API to get string for given transaction type
 *
 * @path_data_type  : Transaction type
 *
 * @return string.
 *
 */
const char *cam_cpas_axi_util_trans_type_to_string(
	uint32_t path_data_type);

/**
 * cam_cpas_axi_util_drv_vote_lvl_to_string()
 *
 * @brief: API to get string for given DRV vote level
 *
 * @vote_lvl  : DRV vote level
 *
 * @return string.
 *
 */
const char *cam_cpas_axi_util_drv_vote_lvl_to_string(
	uint32_t vote_lvl);

/**
 * cam_cpas_util_vote_type_to_string()
 *
 * @brief: API to get string for given vote type
 *
 * @vote_type  : DRV vote level
 *
 * @return string.
 *
 */
const char *cam_cpas_util_vote_type_to_string(enum cam_cpas_vote_type vote_type);

/**
 * cam_cpas_log_votes()
 *
 * @brief: API to print the all bw votes of axi client. It also print the
 *     applied camnoc axi clock vote value and ahb vote value
 *
 * @ddr_only: Print only DDR info
 *
 * @return 0 on success.
 *
 */
void cam_cpas_log_votes(bool ddr_only);

/**
 * cam_cpas_select_qos_settings()
 *
 * @brief: API to select specific qos settings based on usecase requirements
 *
 * @return 0 on success.
 *
 */
int cam_cpas_select_qos_settings(uint32_t selection_mask);

/**
 * cam_cpas_notify_event()
 *
 * @brief: API that clients can notify about their events. CPAS save the event
 *         and any other useful information related to this event. This will
 *         be printed while cpas state dump - cam_cpas_log_votes.
 *         One such example is IFE notifiying SOF or EPOCH to cpas and cpas
 *         saving axi clock information (camnoc_axi, mnoc_hf) at that point
 *         and printing latest history on IFE overflow.
 *
 * @identifier_string: Identifier string passed by caller
 * @identifier_value: Identifier value passed by caller
 *
 * @return 0 on success.
 *
 */
int cam_cpas_notify_event(const char *identifier_string,
	int32_t identifier_value);

/**
 * cam_cpas_get_scid()
 *
 * @brief: API to obtain slice id for the given type
 *
 * @type: Cache type
 *
 * @return slice id, -1 for invalid id.
 *
 */
int cam_cpas_get_scid(enum cam_sys_cache_config_types  type);

/**
 * cam_cpas_activate_llcc()
 *
 * @brief: API to activate system cache
 *
 * @type: Cache type
 *
 * @return 0 for success.
 *
 */
int cam_cpas_activate_llcc(enum cam_sys_cache_config_types type);

/**
 * cam_cpas_deactivate_llcc()
 *
 * @brief: API to de-activate system cache
 *
 * @type: Cache type
 *
 * @return 0 for success.
 *
 */
int cam_cpas_deactivate_llcc(enum cam_sys_cache_config_types type);

/**
 * cam_cpas_configure_staling_llcc()
 *
 * @brief:  Configure cache staling mode by setting the
 *          staling_mode and corresponding params
 *
 * @type: Cache type
 * @mode_param: llcc stalling mode params
 * @operation_type: cache operation type
 * @stalling_distance: llcc sys cache stalling distance
 *
 * @return 0 for success.
 *
 */
int cam_cpas_configure_staling_llcc(
	enum cam_sys_cache_config_types type,
	enum cam_sys_cache_llcc_staling_mode mode_param,
	enum cam_sys_cache_llcc_staling_op_type operation_type,
	uint32_t staling_distance);

/**
 * cam_cpas_notif_increment_staling_counter()
 *
 * @brief: This will increment the stalling counter
 *         depends on what operation it does.
 *         The operation mode what we have setup in other function.
 *
 * @type: Cache type
 *
 * @return 0 for success.
 *
 */
int cam_cpas_notif_increment_staling_counter(
	enum cam_sys_cache_config_types type);

/**
 * cam_cpas_dump_camnoc_buff_fill_info()
 *
 * @brief: API to dump camnoc buffer fill level info
 *
 * @client_handle : Client cpas handle
 *
 * @return 0 on success
 *
 */
int cam_cpas_dump_camnoc_buff_fill_info(uint32_t client_handle);

/**
 * cam_cpas_csid_input_core_info_update()
 *
 * @brief: API to communicate csid input core info to cpas
 *
 * @csid_idx: csid hw index connected to particular sfe
 * @sfe_idx:  sfe idx to be connected to particular DRV path
 * @set_port: Indicates whether to set or reset DRV port info in dynamic client
 *
 * @return 0 on success
 *
 */
int cam_cpas_csid_input_core_info_update(int csid_idx, int sfe_idx, bool set_port);

/**
 * cam_cpas_csid_process_resume()
 *
 * @brief: API to process csid resume in cpas
 * @csid_idx: CSID idx to notify resume for
 *
 * @return 0 on success
 *
 */
int cam_cpas_csid_process_resume(uint32_t csid_idx);

/**
 * cam_cpas_query_drv_enable()
 *
 * @brief: API to indicate DRV enabled on hw or not
 * @is_ddr_drv_enabled: If DDR DRV enabled
 * @is_clk_drv_enabled: If Clock Cesta DRV enabled
 *
 * @return 0 on success
 *
 */
int cam_cpas_query_drv_enable(bool *is_ddr_drv_enabled, bool *is_clk_drv_enabled);

/**
 * cam_cpas_query_domain_id_security_support()
 * @brief: API to determine if target supports domain id feature
 *         This information is determined by cpas during probe
 *
 * @return true if there's support, false otherwise
 */
bool cam_cpas_query_domain_id_security_support(void);

/**
 * cam_cpas_enable_clks_for_domain_id()
 *
 * @brief: API to enable/disable clocks for domain id support.
 *         All CSIDs including those not in use for a ctxt
 *         needs to be programmed in a secure session.
 * @enable: True to turn on, false otherwise.
 * @return 0 on success
 */
int cam_cpas_enable_clks_for_domain_id(bool enable);

/**
 * cam_cpas_is_notif_staling_supported()
 *
 * @brief: API to check stalling feature is supported or not
 *
 * @return rue if supported
 */
bool cam_cpas_is_notif_staling_supported(void);

/**
 * cam_cpas_dump_state_monitor_info()
 *
 * @brief: API to dump the state monitor info of cpas.
 * @info:  Dump information.
 * @return 0 on success
 */
int cam_cpas_dump_state_monitor_info(struct cam_req_mgr_dump_info *info);

#endif /* _CAM_CPAS_API_H_ */
