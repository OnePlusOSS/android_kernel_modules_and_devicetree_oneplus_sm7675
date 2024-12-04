/****
  include for ak09973
**/
#ifndef __AK09973_H__
#define __AK09973_H__

#include "../abstract/magnetic_cover.h"

#define AK09973_SLAVE_ADDR         (0x11)

#define AK09973_REG_ST_Z           (0x14)
#define AK09973_REG_ST_XYZ         (0x17)
#define AK09973_REG_ST_V           (0x18)

#define AK09973_REG_CNTL1          (0x20)
#define AK09973_REG_CNTL2          (0x21)
#define AK09973_REG_SWX1           (0x22)

#define AK09973_I2C_REG_MAX_SIZE   (8)

#define MAX_I2C_RETRY_TIME 4

/*
true threshold
a. far:  data < 125
b. near: data > 150
BOP: operation threshold
BRP: return threshold
must BOP > BRP
hx: measurement data
OD-INT: irq
L:pull down  H:pull up
-----
when POL = 0
hx > BOP : OD-INT to L
hx < BRP : OD-INT to H
when OPL = 1
hx > BOP : OD-INT to H
hx < BRP : OD-INT to L
-----
BRP < hx < BOP : OD-INT follow last OD-INT
*/


// data status
#define AK_DATA_READY        0x01
#define AK_DEFAULT_DATA      0

#define AK_POLV_SET_1        0x08
#define AK_POLZ_SET_1        0x04
#define AK_POLY_SET_1        0x02
#define AK_POLX_SET_1        0x01
#define AK_POL_SET_0         0x00

#define AK_CNTL1_BYTE1_7_0    1
#define AK_CNTL1_BYTE0_15_8   0

#define AK_CNTL1_SWXEN        0x02
#define AK_CNTL1_SWYEN        0x04
#define AK_CNTL1_SWZEN        0x08
#define AK_CNTL1_SWVEN        0x10
#define AK_CNTL1_ERREN        0x20

#define AK_100HZ_LOWPOWER    0x2a

#define AK_BOP_BRP_X_ADD     0x22
#define AK_BOP_BRP_Y_ADD     0x23
#define AK_BOP_BRP_Z_ADD     0x24
#define AK_BOP_BRP_V_ADD     0x25

#define AK_MAX_SHROT         32767
#define AK_MIN_SHROT         -32767

#define AK_BIT0_ST           0
#define AK_BIT1_HZ_15_8      1
#define AK_BIT2_HZ_7_0       2
#define AK_BIT3_HY_15_8      3
#define AK_BIT4_HY_7_0       4
#define AK_BIT5_HX_15_8      5
#define AK_BIT6_HX_7_0       6

#define AK_BIT_MAX           7

struct ak09973_chip_info {
	struct i2c_client              *client;
	int                            irq;
	struct magnetic_cover_info     *magcvr_info;
	struct mutex                   data_lock;
	short data_x;
	short data_y;
	short data_z;
	long  data_v;
};

#endif  /* __AK09973_H__ */
