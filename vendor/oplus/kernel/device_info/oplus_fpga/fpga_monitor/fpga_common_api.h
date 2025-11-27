/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 */

#ifndef _TRIKEY_COMMON_API_
#define _TRIKEY_COMMON_API_

#define FPGA_NAME "oplus_fpga"

/*******Part0:LOG TAG Declear************************/
#define FPGA_INFO(fmt, args...) \
        pr_info("[%s][%s][%d]:" fmt, \
		FPGA_NAME, __func__, __LINE__, ##args)

#define FPGA_WARN(fmt, args...)\
        pr_warn("[%s][%s][%d]:" fmt, \
		FPGA_NAME, __func__, __LINE__, ##args)

#define FPGA_ERR(fmt, args...) \
        pr_err("[%s][%s][%d]:" fmt, \
		FPGA_NAME, __func__, __LINE__, ##args)

#endif /* _TRIKEY_COMMON_API_ */
