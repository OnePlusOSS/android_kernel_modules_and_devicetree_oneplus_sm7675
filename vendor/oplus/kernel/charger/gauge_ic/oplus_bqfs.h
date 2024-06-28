// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2018-2023 Oplus. All rights reserved.
 */

#ifndef __OPLUS_BQFS_H__
#define __OPLUS_BQFS_H__

void bq27426_modify_soc_smooth_parameter(struct chip_bq27541 *chip, bool on);
void bqfs_init(struct chip_bq27541 *chip);
#endif /* __OPLUS_BQFS_H__ */
