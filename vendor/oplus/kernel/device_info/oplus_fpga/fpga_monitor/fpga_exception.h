/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 */

#ifndef _FPGA_EXCEPTION_
#define _FPGA_EXCEPTION_

#include <linux/version.h>

#define SLAVER_ERROR     "slave_error"

#define IO_TX_ERR        "io_tx_error"
#define IO_RX_ERR        "io_rx_error"
#define I2C_TX_ERR       "i2c_tx_error"
#define I2C_RX_ERR       "i2c_rx_error"
#define SPI_TX_ERR       "spi_tx_error"
#define SPI_RX_ERR       "spi_rx_error"
#define GPIO_STAT_ERR    "gpio_status_error"
#define I2C_STAT_ERR     "i2c_status_error"

struct fpga_exception_data {
	void  *private_data;
	unsigned int exception_upload_count;
};

typedef enum {
	EXCEP_DEFAULT = 0,
	EXCEP_IO_TX_ERR,
	EXCEP_IO_RX_ERR,
	EXCEP_I2C_TX_ERR,
	EXCEP_I2C_RX_ERR,
	EXCEP_SPI_TX_ERR,
	EXCEP_SPI_RX_ERR,
	EXCEP_SLAVER_ERR,
	EXCEP_GPIO_STAT_ERR,
	EXCEP_I2C_STAT_ERR,
} fpga_excep_type;

int fpga_exception_report(void *fpga_exception_data, fpga_excep_type excep_tpye, void *summary, unsigned int summary_size);

#endif /*_FPGA_EXCEPTION_*/
