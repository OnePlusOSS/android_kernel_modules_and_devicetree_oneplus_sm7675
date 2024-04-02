// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022-2023 Oplus. All rights reserved.
 */

#ifndef _OPLUS_SC6607_H_
#define _OPLUS_SC6607_H_
#include "../oplus_chg_track.h"

#define UFCS_IC_NAME	"SC6607"

#define SC6607_I2C_ADDR					0x63
#define SC6607_MAX_REG					0x0264
#define SC6607_ENABLE_REG_NUM				4

/* Register 11h */
#define SC6607_REG_11					0x11
#define SC6607_IBUS_POL_H_SHIFT				8
#define SC6607_IBUS_POL_H_MASK				0x0F
#define SC6607_IBUS_ADC_LSB				2500/1000


/* Register 13h */
#define SC6607_REG_13					0x13
#define SC6607_VBUS_POL_H_SHIFT				8
#define SC6607_VBUS_POL_H_MASK				0x0F
#define SC6607_VBUS_ADC_LSB				375/100

/* Register 15h */
#define SC6607_REG_15					0x15
#define SC6607_VAC_POL_H_SHIFT				8

#define SC6607_VAC_POL_H_MASK				0x0F
#define SC6607_VAC_ADC_LSB				5


/* Register 17h */
#define SC6607_REG_17					0x17
#define SC6607_VBAT_POL_H_SHIFT				8
#define SC6607_VBAT_POL_H_MASK				0x0F
#define SC6607_VBAT_ADC_LSB				125/100

/* Register 19h */
#define SC6607_REG_19					0x19
#define SC6607_VBATSNS_POL_H_SHIFT			8
#define SC6607_VBATSNS_POL_H_MASK			0x0F
#define SC6607_VBATSNS_ADC_LSB				125/100


#define SC6607_ADDR_UFCS_CTRL0				0x00
#define SC6607_SEND_SOURCE_HARDRESET			BIT(0)
#define SC6607_SEND_CABLE_HARDRESET			BIT(1)
#define SC6607_CMD_SND_CMP				BIT(2)
#define SC6607_MASK_SND_CMP				BIT(2)
#define SC6607_FLAG_BAUD_RATE_VALUE			(BIT(4) | BIT(3))
#define SC6607_FLAG_BAUD_NUM_SHIFT			3
#define SC6607_CMD_EN_CHIP				0x80
#define SC6607_CMD_DIS_CHIP				0X00
#define SC6607_MASK_EN_HANDSHAKE			BIT(5)
#define SC6607_CMD_EN_HANDSHAKE				BIT(5)

#define SC6607_ADDR_UFCS_CTRL1				0x01
#define SC6607_CMD_CLR_TX_RX				0x30

#define SC6607_ADDR_UFCS_CTRL2				0x02
#define SC6607_CMD_MASK_ACK_DISCARD			0x80

#define SC6607_ADDR_GENERAL_INT_FLAG1			0x03
#define SC6607_FLAG_NUM					3
#define SC6607_FLAG_ACK_RECEIVE_TIMEOUT			BIT(0)
#define SC6607_FLAG_MSG_TRANS_FAIL			BIT(1)
#define SC6607_FLAG_RX_OVERFLOW				BIT(3)
#define SC6607_FLAG_DATA_READY				BIT(4)
#define SC6607_FLAG_SENT_PACKET_COMPLETE		BIT(5)
#define SC6607_FLAG_HANDSHAKE_SUCCESS			BIT(6)
#define SC6607_FLAG_HANDSHAKE_FAIL			BIT(7)


#define SC6607_ADDR_GENERAL_INT_FLAG2			0x04
#define SC6607_FLAG_HARD_RESET				BIT(0)
#define SC6607_FLAG_CRC_ERROR				BIT(1)
#define SC6607_FLAG_STOP_ERROR				BIT(2)
#define SC6607_FLAG_START_FAIL				BIT(3)
#define SC6607_FLAG_LENGTH_ERROR			BIT(4)
#define SC6607_FLAG_DATA_BYTE_TIMEOUT			BIT(5)
#define SC6607_FLAG_TRAINING_BYTE_ERROR			BIT(6)
#define SC6607_FLAG_BAUD_RATE_ERROR			BIT(7)

#define SC6607_ADDR_GENERAL_INT_FLAG3			0x05
#define SC6607_FLAG_BAUD_RATE_CHANGE			BIT(6)
#define SC6607_FLAG_BUS_CONFLICT			BIT(7)



#define SC6607_ADDR_UFCS_INT_MASK1			0x06
#define SC6607_CMD_MASK_ACK_TIMEOUT			0x01

#define SC6607_ADDR_UFCS_INT_MASK2			0x07
#define SC6607_MASK_TRANING_BYTE_ERROR			0x40

#define SC6607_ADDR_UFCS_INT_MASK3			0x08


/*tx_buffer*/
#define SC6607_ADDR_TX_LENGTH				0x09

#define SC6607_ADDR_TX_BUFFER0				0x0A

#define SC6607_ADDR_TX_BUFFER35				0x2D

/*rx_buffer*/
#define SC6607_ADDR_RX_LENGTH				0x2E
#define SC6607_ADDR_RX_BUFFER0				0x2F
#define SC6607_ADDR_RX_BUFFER63				0x6E



/* Register 6Bh */
#define SC6607_REG_6B					0x6B
#define SC6607_SS_TIMEOUT_FLAG_MASK			0x10
#define SC6607_SS_TIMEOUT_FLAG_SHIFT			4
#define SC6607_IBUS_UCP_FALL_FLAG_MASK			0x08
#define SC6607_IBUS_UCP_FALL_FLAG_SHIFT			3
#define SC6607_IBUS_OCP_FLAG_MASK			0x04
#define SC6607_IBUS_OCP_FLAG_SHIFT			2
#define SC6607_VBAT_OVP_FLAG_MASK			0x02
#define SC6607_VBAT_OVP_FLAG_SHIFT			1
#define SC6607_VBATSNS_OVP_FLAG_MASK			0x01
#define SC6607_VBATSNS_OVP_FLAG_SHIFT			0



/* Register 6Ch */
#define SC6607_REG_6C					0x6C
#define SC6607_PMID2OUT_OVP_FLAG_MASK			0x04
#define SC6607_PMID2OUT_OVP_FLAG_SHIFT			2
#define SC6607_PMID2OUT_UCP_FLAG_MASK			0x02
#define SC6607_PMID2OUT_UCP_FLAG_SHIFT			1
#define SC6607_PIN_DIAG_FALL_FLAG_MASK			0x01
#define SC6607_PIN_DIAG_FALL_FLAG_SHIFT			0



#define SC6607_DEVICE_ID				0x67


/****************Message Construction Helper*********/
struct oplus_sc6607 {
	struct device *dev;
	struct i2c_client *client;
	struct regmap *regmap;

	atomic_t suspended;
	bool ufcs_enable;
};
#endif /*_OPLUS_SC6607_H_*/
