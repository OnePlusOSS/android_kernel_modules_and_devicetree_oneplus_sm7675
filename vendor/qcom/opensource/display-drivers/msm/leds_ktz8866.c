/*
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/i2c.h>
#include <linux/err.h>
#include <linux/of_device.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/backlight.h>
#include "oplus_display_interface.h"
#include "leds_ktz8866.h"

#define KTZ8866_I2C_M_NAME  			"ktz8866-master"
#define KTZ8866_I2C_S_NAME  			"ktz8866-salve"
#define KTZ8866_HW_GPIO_NAME			"ktz8866_hw_en_gpio"
#define KTZ8866_BAIS_ENP_GPIO_NAME		"ktz8866_bais_enp_gpio"
#define KTZ8866_BAIS_ENN_GPIO_NAME		"ktz8866_bais_enn_gpio"

#define KTZ8866_IC_BL_LEVEL_MAX			(2047)
/*****************************************************************************
 * GLobal Variable
 *****************************************************************************/
static struct i2c_client *g_i2c_m_client = NULL;
static struct i2c_client *g_i2c_s_client = NULL;
static int ktz8866_hw_en_gpio_num = -1;
static int ktz8866_bais_enp_gpio_num = -1;
static int ktz8866_bais_enn_gpio_num = -1;
static DEFINE_MUTEX(read_lock);

/*****************************************************************************
 * Extern Area
 *****************************************************************************/

static int ktz8866_ic_write_byte_single(struct i2c_client *i2c_client, unsigned char addr, unsigned char value)
{
	int ret = 0;
	unsigned char write_data[2] = {0};

	if (NULL == i2c_client) {
		pr_err("[LCD][BL] i2c_client is null!!\n");
		return -EINVAL;
	}

	write_data[0] = addr;
	write_data[1] = value;
	ret = i2c_master_send(i2c_client, write_data, 2);

	if (ret < 0)
	pr_err("[LCD][BL] i2c write data fail !!\n");

	return ret;
}

static int ktz8866_ic_write_byte_dual(unsigned char addr, unsigned char value)
{
	int ret = 0;
	unsigned char write_data[2] = {0};

	if ((NULL == g_i2c_m_client)||(NULL == g_i2c_s_client)) {
		pr_err("[LCD][BL] i2c_client is null!!\n");
		return -EINVAL;
	}

	write_data[0] = addr;
	write_data[1] = value;

	ret = i2c_master_send(g_i2c_m_client, write_data, 2);
	if (ret < 0) {
		pr_err("[LCD][BL] i2c write data fail %s !!\n", dev_name(&g_i2c_m_client->dev));
	}

	ret = i2c_master_send(g_i2c_s_client, write_data, 2);
	if (ret < 0) {
		pr_err("[LCD][BL] i2c write data fail %s !!\n", dev_name(&g_i2c_s_client->dev));
	}

	return ret;
}

int ktz8866_ic_read_byte_dual(struct i2c_client *i2c_client_m, unsigned char i2c_client_m_addr, unsigned char *i2c_client_m_buf,
		struct i2c_client *i2c_client_s, unsigned char i2c_client_s_addr, unsigned char *i2c_client_s_buf)
{
	int res = 0;

	mutex_lock(&read_lock);

	if (i2c_client_m) {
		res = i2c_master_send(i2c_client_m, &i2c_client_m_addr, 0x1);
		if (res <= 0) {
			mutex_unlock(&read_lock);
			pr_err("[LCD][BL]read reg send res = %d %s\n", res, dev_name(&i2c_client_m->dev));
			return res;
		}
		res = i2c_master_recv(i2c_client_m, i2c_client_m_buf, 0x1);
		if (res <= 0) {
			mutex_unlock(&read_lock);
			pr_err("[LCD][BL]read reg recv res = %d %s\n", res, dev_name(&i2c_client_m->dev));
			return res;
		}
	} else {
		pr_err("[LCD][BL] i2c_client_m is NULL\n");
	}

	if (i2c_client_s) {
		res = i2c_master_send(i2c_client_s, &i2c_client_s_addr, 0x1);
		if (res <= 0) {
			mutex_unlock(&read_lock);
			pr_err("[LCD][BL]read reg send res = %d %s\n", res, dev_name(&i2c_client_s->dev));
			return res;
		}
		res = i2c_master_recv(i2c_client_s, i2c_client_s_buf, 0x1);
		if (res <= 0) {
			mutex_unlock(&read_lock);
			pr_err("[LCD][BL]read reg recv res = %d %s\n", res, dev_name(&i2c_client_s->dev));
			return res;
		}
	} else {
		pr_err("[LCD][BL] i2c_client_s is NULL\n");
	}

	mutex_unlock(&read_lock);

	return res;
}

static int bl_ic_ktz8866_enable(bool enable)
{
	static bool bl_ic_ktz8866_enabled = false;

	if (enable) {
		if (!bl_ic_ktz8866_enabled) {
			/* config i2c0 and i2c3 */
			/* BL_CFG1；OVP=34.0V，线性调光，PWM Disabled */
			ktz8866_ic_write_byte_dual(0x02, 0XD2);//caba 0ff 0x7A cabc on 0x7B
			/* Current ramp 256ms pwm_hyst 10lsb */
			//ktz8866_ic_write_byte_dual(0x03, 0XCD);
			/* BL_OPTION2；电感4.7uH，BL_CURRENT_LIMIT 2.5A */
			ktz8866_ic_write_byte_dual(0x11, 0x37);
			/* turn on-off ramp */
			ktz8866_ic_write_byte_dual(0x14, 0x44);
			/* Backlight Full-scale LED Current 30.0mA/CH */
			pr_err("[LCD]bl_ic_ktz8866 set LED Current 30.0mA/CH\n");
			ktz8866_ic_write_byte_dual(0x15, 0xF8);

			bl_ic_ktz8866_enabled = true;
			pr_err("[LCD]bl_ic_ktz8866 enable\n");
		}
	} else {
		/* BL disabled and Current sink 1/2/3/4 /5 enabled；*/
		ktz8866_ic_write_byte_dual(0x08, 0x00);

		bl_ic_ktz8866_enabled = false;
		pr_err("[LCD]bl_ic_ktz8866 disable\n");
	}
	return 0;
}

int bl_ic_ktz8866_set_brightness(int bl_lvl)//for set bringhtness
{
	unsigned int mapping_value = 0;
	static bool ktz8866_set_bl_flag = false;

	if (bl_lvl < 0) {
		pr_err("[LCD]%d %s set backlight invalid value=%d, not to set\n", __LINE__, __func__, bl_lvl);
		return 0;
	}

	if (bl_lvl > KTZ8866_IC_BL_LEVEL_MAX) {
		mapping_value = backlight_map[KTZ8866_IC_BL_LEVEL_MAX];
	} else {
		mapping_value = backlight_map[bl_lvl];
	}
	pr_err("[LCD]%s:set backlight lvl= %d, mapping value = %d\n", __func__, bl_lvl, mapping_value);

	if (bl_lvl > 0) {
		bl_ic_ktz8866_enable(true); /* BL enabled and Current sink 1/2/3/4/5 enabled */
		ktz8866_ic_write_byte_dual(0x04, mapping_value & 0x07); /* lsb */
		ktz8866_ic_write_byte_dual(0x05, (mapping_value >> 3) & 0xFF); /* msb */
		if (!ktz8866_set_bl_flag) {
			mdelay(15);
			ktz8866_ic_write_byte_dual(0x08, 0x4F);
			ktz8866_set_bl_flag = true;
		}
	}

	if (bl_lvl == 0) {
		ktz8866_ic_write_byte_dual(0x04, 0x00); /* lsb */
		ktz8866_ic_write_byte_dual(0x05, 0x00); /* msb */
		bl_ic_ktz8866_enable(false); /* BL disabled and Current sink 1/2/3/4/5 disabled */
		ktz8866_set_bl_flag = false;
	}
	return 0;
}

int bl_ic_ktz8866_set_lcd_bias_by_gpio(bool enable)
{
	int  rc = 0;;

	if (enable) {
		pr_err("[LCD]%s:enable lcd_enable_bias by gpio\n", __func__);

		/* only config i2c0*/
		ktz8866_ic_write_byte_dual(0x0C, 0x30);/* LCD_BOOST_CFG */
		ktz8866_ic_write_byte_dual(0x0D, 0x28);/* OUTP_CFG，OUTP = 6.0V */
		ktz8866_ic_write_byte_dual(0x0E, 0x28);/* OUTN_CFG，OUTN = -6.0V */
		ktz8866_ic_write_byte_dual(0x09, 0x9F);/* enable OUTP */
		mdelay(1);
		/* enable bl bais enp */
		if (gpio_is_valid(ktz8866_bais_enp_gpio_num)) {
			rc = gpio_direction_output(ktz8866_bais_enp_gpio_num, true);
			if (rc) {
				pr_err("[LCD]unable to set bl_bais_enp to high rc=%d\n", rc);
				gpio_free(ktz8866_bais_enp_gpio_num);
			}
		}
		mdelay(1);
		/* enable bl bais enn */
		if (gpio_is_valid(ktz8866_bais_enn_gpio_num)) {
			rc = gpio_direction_output(ktz8866_bais_enn_gpio_num, true);
			if (rc) {
				pr_err("[LCD]unable to set bl_bais_enn to high rc=%d\n", rc);
				gpio_free(ktz8866_bais_enn_gpio_num);
			}
		}
		/* ktz8866 bias config master only */
		ktz8866_ic_write_byte_single(g_i2c_m_client, 0x02, 0xD2);//set ovp 34.0v pwm enable
		ktz8866_ic_write_byte_single(g_i2c_m_client, 0x11, 0x37);//4.7uH
		ktz8866_ic_write_byte_single(g_i2c_m_client, 0x15, 0xF8);//30.0mA 900nit limit
	} else {
		pr_err("[LCD]%s:disable lcd_enable_bias by gpio\n", __func__);
		/* disable bl bais enn */
		if (gpio_is_valid(ktz8866_bais_enn_gpio_num)) {
			rc = gpio_direction_output(ktz8866_bais_enn_gpio_num, false);
			if (rc) {
				pr_err("[LCD]unable to set bl_bais_enn to low rc=%d\n", rc);
			}
			gpio_free(ktz8866_bais_enn_gpio_num);
		}
		mdelay(1);
		/* disable bl bais enp */
		if (gpio_is_valid(ktz8866_bais_enp_gpio_num)) {
			rc = gpio_direction_output(ktz8866_bais_enp_gpio_num, false);
			if (rc) {
				pr_err("[LCD]unable to  set bl_bais_enp to low rc=%d\n", rc);
			}
			gpio_free(ktz8866_bais_enp_gpio_num);
		}
	}

	return 0;
}

int bl_ic_ktz8866_set_lcd_bias_by_reg(struct dsi_panel *panel, bool enable)
{
	if (enable) {
		pr_err("[LCD] enable lcd_enable_bias by reg\n");
		/* only config i2c0*/
		ktz8866_ic_write_byte_single(g_i2c_m_client, 0x0C, 0x30);/* LCD_BOOST_CFG */
		ktz8866_ic_write_byte_single(g_i2c_m_client, 0x0D, 0x28);/* OUTP_CFG，OUTP = 6.0V */
		ktz8866_ic_write_byte_single(g_i2c_m_client, 0x0E, 0x28);/* OUTN_CFG，OUTN = -6.0V */
		ktz8866_ic_write_byte_single(g_i2c_m_client, 0x09, 0x9F);/* enable OUTP */
	} else {
		pr_err("[LCD] disable lcd_enable_bias by reg\n");
		ktz8866_ic_write_byte_dual(0x09, 0x9D);/* Disable OUTN */
		mdelay(5);
		ktz8866_ic_write_byte_dual(0x09, 0x99);/* Disable OUTP */
	}
	return 0;
}

int bl_ic_ktz8866_hw_en(bool enable)
{
	int ret;
	u8 value  = enable ? 1 : 0;

	if(gpio_is_valid(ktz8866_hw_en_gpio_num)) {
		ret = gpio_direction_output(ktz8866_hw_en_gpio_num, value);
		if(ret){
			pr_err("[LCD]failed to set %s gpio %d, ret = %d\n", KTZ8866_HW_GPIO_NAME, value, ret);
			return ret;
		} else {
			pr_err("[LCD]%s:set KTZ8866_HW_EN enable=%d succ\n", __func__, enable);
		}
	} else {
		pr_err("[LCD]get KTZ8866_HW_EN gpio(%d) is not vaild\n", ktz8866_hw_en_gpio_num);
	}

	return 0;
}

static int ktz8866_i2c_master_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	if(!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_warn(&client->dev, "[LCD]xx adapter does not support I2C\n");
		return -EIO;
	}

	g_i2c_m_client = client;
	if (client->dev.of_node) {
		ktz8866_hw_en_gpio_num = of_get_named_gpio(client->dev.of_node, KTZ8866_HW_GPIO_NAME, 0);
		if (ktz8866_hw_en_gpio_num < 0) {
			dev_err(&client->dev,"[LCD]failed to get %s\n", KTZ8866_HW_GPIO_NAME);
			return -EINVAL;
		} else {
			pr_err("[LCD]%s:get %s num=%d SUCC!\n", __func__, KTZ8866_HW_GPIO_NAME, ktz8866_hw_en_gpio_num);
			//turn on hw_en
			if(bl_ic_ktz8866_hw_en(true)) {
				pr_err("[LCD]failed to turn on hwen!\n");
			}
		}

		ktz8866_bais_enp_gpio_num = of_get_named_gpio(client->dev.of_node, KTZ8866_BAIS_ENP_GPIO_NAME, 0);
		if (ktz8866_bais_enp_gpio_num < 0) {
			dev_err(&client->dev,"[LCD]failed to get %s\n", KTZ8866_BAIS_ENP_GPIO_NAME);
		} else {
			pr_err("[LCD]%s:get %s num=%d SUCC!\n", __func__, KTZ8866_BAIS_ENP_GPIO_NAME, ktz8866_bais_enp_gpio_num);
		}
		ktz8866_bais_enn_gpio_num = of_get_named_gpio(client->dev.of_node, KTZ8866_BAIS_ENN_GPIO_NAME, 0);
		if (ktz8866_bais_enn_gpio_num < 0) {
			dev_err(&client->dev,"failed to get %s\n", KTZ8866_BAIS_ENN_GPIO_NAME);
		} else {
			pr_err("[LCD]%s:get %s num=%d SUCC!\n", __func__, KTZ8866_BAIS_ENN_GPIO_NAME, ktz8866_bais_enn_gpio_num);
		}
	}
	pr_err("[LCD]%s:get g_i2c_m_client SUCC!\n", __func__);

	return 0;
}

static void ktz8866_i2c_master_remove(struct i2c_client *client)
{
	i2c_unregister_device(client);
	g_i2c_m_client = NULL;
	pr_err("[LCD]%s: dev_name:%s unregister\n", __func__, dev_name(&client->dev));
}

static int ktz8866_i2c_salve_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	if(!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_warn(&client->dev, "[LCD]xx adapter does not support I2C\n");
		return -EIO;
	}

	g_i2c_s_client = client;
	pr_err("[LCD]%s:get g_i2c_s_client SUCC!\n", __func__);

	return 0;
}


static void ktz8866_i2c_salve_remove(struct i2c_client *client)
{
	i2c_unregister_device(client);
	g_i2c_s_client = NULL;
	pr_err("[LCD]%s: dev_name:%s unregister\n", __func__, dev_name(&client->dev));
}


/************************************************************
Attention:
Althouh i2c_bus do not use .id_table to match, but it must be defined,
otherwise the probe function will not be executed!
************************************************************/
static const struct of_device_id ktz8866_m_i2c_of_match[] = {
	{ .compatible = "ktz8866-i2c-master", },
	{},
};

static const struct i2c_device_id ktz8866_m_i2c_id_table[] = {
	{KTZ8866_I2C_M_NAME, 0},
	{},
};

static struct i2c_driver ktz8866_i2c_m_driver = {
	.probe = ktz8866_i2c_master_probe,
	.remove = ktz8866_i2c_master_remove,
	.id_table = ktz8866_m_i2c_id_table,
	.driver = {
		.owner = THIS_MODULE,
		.name = KTZ8866_I2C_M_NAME,
		.of_match_table = ktz8866_m_i2c_of_match,
    },
};

static const struct of_device_id ktz8866_s_i2c_of_match[] = {
	{ .compatible = "ktz8866-i2c-salve", },
	{},
};

static const struct i2c_device_id ktz8866_s_i2c_id_table[] = {
	{KTZ8866_I2C_S_NAME, 0},
	{},
};

static struct i2c_driver ktz8866_i2c_s_driver = {
	.probe = ktz8866_i2c_salve_probe,
	.remove = ktz8866_i2c_salve_remove,
	.id_table = ktz8866_s_i2c_id_table,
	.driver = {
		.owner = THIS_MODULE,
		.name = KTZ8866_I2C_S_NAME,
		.of_match_table = ktz8866_s_i2c_of_match,
    },
};

int __init bl_ic_ktz8866_init(void)
{
	pr_err("[LCD][BL]bl_ic_ktz8866_init +++\n");

	g_i2c_s_client = NULL;
	g_i2c_m_client = NULL;
	if (i2c_add_driver(&ktz8866_i2c_s_driver)) {
		pr_err("[LCD][BL]Failed to register ktz8866_i2c_s_driver!\n");
		return -EINVAL;
	}

	if (i2c_add_driver(&ktz8866_i2c_m_driver)) {
		pr_err("[LCD][BL]Failed to register ktz8866_i2c_m_driver!\n");
		i2c_del_driver(&ktz8866_i2c_s_driver);
		g_i2c_s_client = NULL;
		return -EINVAL;
	}

	pr_err("[LCD][BL]bl_ic_ktz8866_init ---\n");
	return 0;
}

void __exit bl_ic_ktz8866_exit(void)
{
	i2c_del_driver(&ktz8866_i2c_m_driver);
	i2c_del_driver(&ktz8866_i2c_s_driver);
	g_i2c_s_client = NULL;
	g_i2c_m_client = NULL;
}
