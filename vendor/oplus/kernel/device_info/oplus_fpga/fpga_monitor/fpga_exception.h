/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 */

#ifndef _FPGA_EXCEPTION_
#define _FPGA_EXCEPTION_

#include <linux/version.h>

struct fpga_exception_data {
	void  *private_data;
	unsigned int exception_upload_count;
};

typedef enum {
	EXCEP_DEFAULT = 0,
	EXCEP_I2C_READ_ERR,
	EXCEP_SOFT_REST_ERR,
	EXCEP_HARD_REST_ERR,
	EXCEP_FAULT_CODE_RECORD_ERR,
	EXCEP_HARD_RESET_NOT_RECOVERY_ERR,
} fpga_excep_type;

int fpga_exception_report(fpga_excep_type excep_tpye);

#endif /*_FPGA_EXCEPTION_*/
