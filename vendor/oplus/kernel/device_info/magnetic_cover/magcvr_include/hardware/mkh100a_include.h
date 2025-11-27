/****
  include for mkh110a
**/
#ifndef __MKH100A_H__
#define __MKH100A_H__

#include "../abstract/magnetic_cover.h"

#define SET_NEAR 300
#define SET_FAR    0

struct mkh100a_chip_info {
	struct device                  *dev;
	int                            irq;
	struct magnetic_cover_info     *magcvr_info;
	struct mutex                   data_lock;
	int                            prev_value;
	int                            irq_gpio;
};

#endif  /* __MKH100A_H__ */
