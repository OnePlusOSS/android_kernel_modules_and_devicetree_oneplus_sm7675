// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023-2023 Oplus. All rights reserved.
 */

#ifndef _1WIRE_PROTOCOL_H
#define _1WIRE_PROTOCOL_H

#include <linux/ctype.h>
#include <linux/types.h>

struct onewire_gpio_data {
	void *gpio_out_high_reg;
	void *gpio_out_low_reg;
	void *gpio_cfg_out_reg;
	void *gpio_cfg_in_reg;
	void *gpio_in_reg;
	raw_spinlock_t lock;
	struct pinctrl *ow_gpio_pinctrl;
	struct pinctrl_state *pinctrl_state_active;
	struct pinctrl_state *pinctrl_state_sleep;
	int version;
	int gpio_num;
	unsigned int onewire_gpio_cfg_addr_out;
	unsigned int onewire_gpio_cfg_addr_in;
	unsigned int onewire_gpio_level_addr_high;
	unsigned int onewire_gpio_level_addr_low;
	unsigned int onewire_gpio_in_addr;
	unsigned int gpio_addr_offset;
};

void set_data_gpio_in(void);
void maxim_delay_us(unsigned int delay_us);
void maxim_delay_ms(unsigned int delay_ms);
/* Basic 1-Wire functions */
int  ow_reset(void);
void write_byte(unsigned char byte_value);
void write_bit(unsigned char bit_value);
unsigned char read_bit(void);
unsigned char read_byte(void);
int onewire_init(struct onewire_gpio_data *onewire_data);

#endif /* _1WIRE_PROTOCOL_H */
