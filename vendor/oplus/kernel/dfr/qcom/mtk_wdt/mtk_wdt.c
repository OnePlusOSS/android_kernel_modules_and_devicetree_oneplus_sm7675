// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 */

#include<linux/module.h>
#include<linux/kernel.h>

/*
 *because when virtio_pci.ko is exit, some app use libshell.so,
 *which must need to check sys/modules/mtk_wdt
*/
static int oplus_mtk_wdt_init(void)
{
	printk("enter");
	return 0;
}
static void oplus_mtk_wdt_exit(void)
{
	printk("exit");
}
module_init(oplus_mtk_wdt_init);
module_exit(oplus_mtk_wdt_exit);


MODULE_LICENSE("GPL v2");
