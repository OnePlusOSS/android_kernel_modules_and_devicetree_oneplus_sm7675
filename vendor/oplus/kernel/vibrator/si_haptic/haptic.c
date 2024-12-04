/*
 *  Silicon Integrated Co., Ltd haptic sih688x haptic driver file
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/i2c.h>
#include <linux/of_gpio.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/debugfs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/power_supply.h>
#include <linux/vmalloc.h>
#include <linux/pm_qos.h>
#include <linux/mm.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/control.h>
#include <sound/soc.h>
#include <linux/errno.h>
#include <linux/mman.h>
#include <linux/proc_fs.h>
#include "haptic_mid.h"
#include "haptic_regmap.h"
#include "haptic.h"
#include "haptic_misc.h"
#include "sih688x.h"
#include "sih688x_reg.h"
#include "sih688x_func_config.h"
#include "haptic_hv_rtp_key_data.h"
#include "haptic_wave.h"
#include <linux/wait.h>

#ifdef CONFIG_HAPTIC_FEEDBACK_MODULE
#include "../aw8697_haptic/haptic_feedback.h"
#endif

#ifdef OPLUS_FEATURE_CHG_BASIC
#include <soc/oplus/system/boot_mode.h>
#endif

#ifdef CONFIG_OPLUS_CHARGER_MTK
#include <mt-plat/mtk_boot_common.h>
#endif

/* add for DX-2 bringup */
#define FW_ACTION_HOTPLUG 1

/*****************************************************
 *
 * variable
 *
 *****************************************************/
static uint8_t SIH_HAPTIC_MAX_VOL = 95;
static struct aw_vmax_map vmax_map[] = {
	{800, 60, 0x40},//6.0V
	{900, 60, 0x49},
	{1000, 60, 0x51},
	{1100, 60, 0x5A},
	{1200, 60, 0x62},
	{1300, 60, 0x6B},
	{1400, 60, 0x73},
	{1500, 60, 0x7C},
	{1600, 62, 0x80},
	{1700, 66, 0x80},
	{1800, 70, 0x80},
	{1900, 74, 0x80},
	{2000, 79, 0x80},
	{2100, 83, 0x80},
	{2200, 86, 0x80},
	{2300, 90, 0x80},
	{2400, 95, 0x80},
};

struct cdev cdev;
static sih_haptic_ptr_t g_haptic_t;
/*****************************************************
 *
 * parse dts
 *
 *****************************************************/
static int sih_parse_hw_dts(struct device *dev, sih_haptic_t *sih_haptic,
	struct device_node *np)
{
	struct device_node *sih_node = np;

	if (sih_node == NULL) {
		hp_err("%s:haptic device node acquire failed\n", __func__);
		return -EINVAL;
	}

#ifdef SIH_ENABLE_PIN_CONTROL
	sih_haptic->pinctrl = devm_pinctrl_get(dev);
	if(!IS_ERR_OR_NULL(sih_haptic->pinctrl)){
		sih_haptic->pinctrl_state = pinctrl_lookup_state(sih_haptic->pinctrl,
							"irq_active");
		if (!IS_ERR_OR_NULL(sih_haptic->pinctrl_state)){
			pinctrl_select_state(sih_haptic->pinctrl,
						sih_haptic->pinctrl_state);
		} else {
			hp_err("%s: pinctrl_state error!\n", __func__);
		}
	} else {
		hp_err("%s: pinctrl error!\n", __func__);
	}
#endif

	/* acquire reset gpio */
	sih_haptic->chip_attr.reset_gpio =
		of_get_named_gpio(sih_node, "reset-gpio", 0);
	if (sih_haptic->chip_attr.reset_gpio < 0) {
		hp_err("%s:reset gpio acquire failed\n", __func__);
		return -EIO;
	}

	/* acquire irq gpio */
	sih_haptic->chip_attr.irq_gpio =
		of_get_named_gpio(sih_node, "irq-gpio", 0);
	if (sih_haptic->chip_attr.irq_gpio < 0) {
		hp_err("%s:irq gpio acquire failed\n", __func__);
		return -EIO;
	}

	hp_info("%s:reset_gpio = %d, irq_gpio = %d\n", __func__,
		sih_haptic->chip_attr.reset_gpio, sih_haptic->chip_attr.irq_gpio);

	return 0;
}

static int sih_parse_lra_dts(struct device *dev, sih_haptic_t *sih_haptic,
	struct device_node *np)
{
	struct device_node *sih_node = np;
	const char *str = NULL;
	int ret = -1;
	int i = 0;
	uint8_t vmax[VMAX_GAIN_NUM];
	uint8_t gain[VMAX_GAIN_NUM];
	int max_boost_voltage = 0;

	if (sih_node == NULL) {
		hp_err("%s:haptic device node acquire failed\n", __func__);
		return -EINVAL;
	}

	/* acquire lra msg */
	ret = of_property_read_string(sih_node, "lra_name", &str);
	if (ret) {
		hp_err("%s:lra name acquire failed\n", __func__);
	} else {
		strlcpy(sih_haptic->chip_attr.lra_name, str, SIH_LRA_NAME_LEN);
		hp_info("%s:lra_name = %s\n", __func__, sih_haptic->chip_attr.lra_name);
	}
#ifdef OPLUS_FEATURE_CHG_BASIC
	if (of_property_read_u32(np, "qcom,device_id", &sih_haptic->device_id))
		sih_haptic->device_id = 815;
	hp_info("%s: device_id=%d\n", __func__, sih_haptic->device_id);

	sih_haptic->livetap_support = of_property_read_bool(np, "oplus,livetap_support");
	hp_info("%s: oplus,livetap_support = %d\n", __func__, sih_haptic->livetap_support);

	sih_haptic->auto_break_mode_support = of_property_read_bool(np, "oplus,auto_break_mode_support");
	hp_info("oplus,auto_break_mode_support = %d\n", sih_haptic->auto_break_mode_support);

	if (of_property_read_u32(np, "oplus,sih6887_boost_voltage", &max_boost_voltage))
		SIH_HAPTIC_MAX_VOL = SIH_DRIVER_VBOOST_INIT_VALUE;
	else
		SIH_HAPTIC_MAX_VOL = max_boost_voltage;
	sih_haptic->chip_ipara.drv_vboost = SIH_HAPTIC_MAX_VOL;
	hp_info("%s: boost_voltage=%d\n", __func__, SIH_HAPTIC_MAX_VOL);
#endif
	ret = of_property_read_u8_array(np, "haptic_vmax", vmax, ARRAY_SIZE(vmax));
	if (ret != 0) {
		hp_info("%s: haptic_vmax not found", __func__);
	} else {
		for (i = 0; i < ARRAY_SIZE(vmax); i++) {
			vmax_map[i].vmax = vmax[i];
			hp_info("%s: vmax_map vmax: %d vmax: %d\n", __func__, vmax_map[i].vmax, vmax[i]);
		}
	}

	ret = of_property_read_u8_array(np, "haptic_gain", gain, ARRAY_SIZE(gain));
	if (ret != 0) {
		hp_info("%s: haptic_gain not found\n", __func__);
	} else {
		for (i = 0; i < ARRAY_SIZE(gain); i++) {
			vmax_map[i].gain = gain[i];
			hp_info("%s: vmax_map gain: 0x%x gain: 0x%x\n", __func__, vmax_map[i].gain, gain[i]);
		}
	}
	return 0;
}

static int sih_parse_dts(struct device *dev, sih_haptic_t *sih_haptic,
	struct device_node *np)
{
	int ret = -1;

	/* Obtain DTS information and data */
	if (np) {
		ret = sih_parse_hw_dts(dev, sih_haptic, np);
		if (ret) {
			hp_err("%s:dts acquire failed hw\n", __func__);
			return ret;
		}
		ret = sih_parse_lra_dts(dev, sih_haptic, np);
		if (ret) {
			hp_err("%s:dts acquire failed dts\n", __func__);
			return ret;
		}
	} else {
		sih_haptic->chip_attr.reset_gpio = -1;
		sih_haptic->chip_attr.irq_gpio = -1;
	}

	return 0;
}

static int sih_auto_break_config_regs(sih_haptic_t *sih_haptic)
{
	struct device_node *sih_node = sih_haptic->i2c->dev.of_node;
	uint8_t brk_addr_regs[20] = {0};
	uint8_t brk_addr_val[20] = {0};
	int addr_reg_nums = 0;
	int addr_val_nums = 0;
	int ret = -1;
	int i = 0;

	if (sih_node == NULL) {
		hp_err("%s:haptic device node acquire failed\n", __func__);
		return -EINVAL;
	}

	addr_reg_nums = of_property_count_elems_of_size(sih_node, "oplus,brk_addr_regs", sizeof(uint8_t));
	hp_info("%s: brk addr_reg_nums = %d\n", __func__, addr_reg_nums);
	/* read brk regs addr config from dts*/
	ret = of_property_read_u8_array(sih_node, "oplus,brk_addr_regs", brk_addr_regs, addr_reg_nums);
	if (ret != 0) {
		hp_err("%s: brk regs nums acquire failed\n", __func__);
		return -1;
	}

	addr_val_nums = of_property_count_elems_of_size(sih_node, "oplus,brk_addr_val", sizeof(uint8_t));
	hp_info("%s: brk addr_val_nums = %d\n", __func__, addr_val_nums);
	/* read brk regs val config from dts */
	ret = of_property_read_u8_array(sih_node, "oplus,brk_addr_val", brk_addr_val, addr_val_nums);
	if (ret != 0) {
		hp_err("%s: brk regs value acquire failed\n", __func__);
		return -1;
	}
	if (addr_reg_nums != addr_val_nums) {
		hp_err("%s: brk regs nums acquire failed\n", __func__);
		return -1;
	}

	for (i = 0; i < addr_reg_nums; i++) {
		haptic_regmap_write(sih_haptic->regmapp.regmapping, brk_addr_regs[i],
			SIH_I2C_OPERA_BYTE_ONE, &brk_addr_val[i]);
		hp_info("%s: brk write reg = %x, val = %x\n", __func__, brk_addr_regs[i], brk_addr_val[i]);
	}

	return 0;
}

static void sih_hardware_reset(sih_haptic_t *sih_haptic)
{
	if (gpio_is_valid(sih_haptic->chip_attr.reset_gpio)) {
		gpio_set_value(sih_haptic->chip_attr.reset_gpio, SIH_RESET_GPIO_RESET);
		usleep_range(1000, 2000);
		gpio_set_value(sih_haptic->chip_attr.reset_gpio, SIH_RESET_GPIO_SET);
		usleep_range(1000, 2000);
	}
}

static int sih_acquire_gpio_res(struct device *dev,
	sih_haptic_t *sih_haptic)
{
	int ret = -1;

	if (gpio_is_valid(sih_haptic->chip_attr.irq_gpio)) {
		ret = devm_gpio_request_one(dev, sih_haptic->chip_attr.irq_gpio,
			GPIOF_DIR_IN, "sih_haptic_irq");
		if (ret) {
			hp_err("%s:irq gpio request failed\n", __func__);
			return ret;
		}
	}
	if (gpio_is_valid(sih_haptic->chip_attr.reset_gpio)) {
		ret = devm_gpio_request_one(dev, sih_haptic->chip_attr.reset_gpio,
			GPIOF_OUT_INIT_LOW, "sih_haptic_rst");
		if (ret) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0))
			devm_gpio_free(dev, sih_haptic->chip_attr.irq_gpio);
#endif
			hp_err("%s:reset gpio request failed\n", __func__);
			return ret;
		}
	}
	sih_hardware_reset(sih_haptic);
	return ret;
}

static void sih_chip_state_recovery(sih_haptic_t *sih_haptic)
{
	sih_haptic->chip_ipara.state = SIH_STANDBY_MODE;
	sih_haptic->chip_ipara.play_mode = SIH_IDLE_MODE;
}

static void sih_op_clean_status(
	sih_haptic_t *sih_haptic)
{
	sih_haptic->rtp.audio_ready = false;
	sih_haptic->rtp.haptic_ready = false;
	sih_haptic->rtp.pre_haptic_number = 0;
}
/*****************************************************
 *
 * rtp
 *
 *****************************************************/
const struct firmware *sih_old_work_file_load_accord_f0(sih_haptic_t *sih_haptic)
{
	const struct firmware *rtp_file;
	uint32_t f0_file_num = 1024;
	int ret = -1;

	if (sih_haptic->rtp.rtp_file_num == AW8697_WAVEFORM_INDEX_OLD_STEADY //52
		|| sih_haptic->rtp.rtp_file_num == AW8697_WAVEFORM_INDEX_HIGH_TEMP) {//51
		if (DEVICE_ID_0815 == sih_haptic->device_id || DEVICE_ID_0809 == sih_haptic->device_id) {
			if(sih_haptic->detect.tracking_f0 <= 1610)
				f0_file_num = 0;
			else if(sih_haptic->detect.tracking_f0 <= 1630)
				f0_file_num = 1;
			else if(sih_haptic->detect.tracking_f0 <= 1650)
				f0_file_num = 2;
			else if(sih_haptic->detect.tracking_f0 <= 1670)
				f0_file_num = 3;
			else if(sih_haptic->detect.tracking_f0 <= 1690)
				f0_file_num = 4;
			else if(sih_haptic->detect.tracking_f0 <= 1710)
				f0_file_num = 5;
			else if(sih_haptic->detect.tracking_f0 <= 1730)
				f0_file_num = 6;
			else if(sih_haptic->detect.tracking_f0 <= 1750)
				f0_file_num = 7;
			else if(sih_haptic->detect.tracking_f0 <= 1770)
				f0_file_num = 8;
			else if(sih_haptic->detect.tracking_f0 <= 1790)
				f0_file_num = 9;
			else
				f0_file_num = 10;
		} else if (DEVICE_ID_1419 == sih_haptic->device_id) {
			if(sih_haptic->detect.tracking_f0 <= 1960)
				f0_file_num = 0;
			else if (sih_haptic->detect.tracking_f0 <= 1980)
				f0_file_num = 1;
			else if (sih_haptic->detect.tracking_f0 <= 2000)
				f0_file_num = 2;
			else if (sih_haptic->detect.tracking_f0 <= 2020)
				f0_file_num = 3;
			else if (sih_haptic->detect.tracking_f0 <= 2040)
				f0_file_num = 4;
			else if (sih_haptic->detect.tracking_f0 <= 2060)
				f0_file_num = 5;
			else if (sih_haptic->detect.tracking_f0 <= 2080)
				f0_file_num = 6;
			else if (sih_haptic->detect.tracking_f0 <= 2100)
				f0_file_num = 7;
			else if (sih_haptic->detect.tracking_f0 <= 2120)
				f0_file_num = 8;
			else if (sih_haptic->detect.tracking_f0 <= 2140)
				f0_file_num = 9;
			else
				f0_file_num = 10;
		}
	}

	if (sih_haptic->rtp.rtp_file_num == AW8697_WAVEFORM_INDEX_OLD_STEADY) {
		if (DEVICE_ID_0815 == sih_haptic->device_id || DEVICE_ID_0809 == sih_haptic->device_id) {
			ret = request_firmware(&rtp_file,
					sih_old_steady_test_rtp_name_0815[f0_file_num],
					sih_haptic->dev);
			hp_err("%s line %d: rtp_num:%d f0:%d name:%s\n", __func__, __LINE__,
				sih_haptic->rtp.rtp_file_num, f0_file_num, sih_old_steady_test_rtp_name_0815[f0_file_num]);
		} else if (DEVICE_ID_1419 == sih_haptic->device_id) {
			ret = request_firmware(&rtp_file,
					sih_old_steady_test_rtp_name_1419[f0_file_num],
					sih_haptic->dev);
			hp_err("%s line %d: rtp_num:%d f0:%d name:%s\n", __func__, __LINE__,
				sih_haptic->rtp.rtp_file_num, f0_file_num, sih_old_steady_test_rtp_name_1419[f0_file_num]);
		}
	} else {
		if (DEVICE_ID_0815 == sih_haptic->device_id || DEVICE_ID_0809 == sih_haptic->device_id) {
			ret = request_firmware(&rtp_file,
					sih_high_temp_high_humidity_0815[f0_file_num],
					sih_haptic->dev);
			hp_err("%s line %d: rtp_num:%d f0:%d name:%s\n", __func__, __LINE__,
				sih_haptic->rtp.rtp_file_num, f0_file_num, sih_high_temp_high_humidity_0815[f0_file_num]);
		} else if (DEVICE_ID_1419 == sih_haptic->device_id) {
			ret = request_firmware(&rtp_file,
					sih_high_temp_high_humidity_1419[f0_file_num],
					sih_haptic->dev);
			hp_err("%s line %d: rtp_num:%d f0:%d name:%s\n", __func__, __LINE__,
				sih_haptic->rtp.rtp_file_num, f0_file_num, sih_old_steady_test_rtp_name_1419[f0_file_num]);
		}
	}
	if (ret < 0) {
		pr_err("%s line %d: failed to read index[%d]\n", __func__, __LINE__, f0_file_num);
		return NULL;
	}

	return rtp_file;
}

const struct firmware *sih_rtp_load_file_accord_f0(sih_haptic_t *sih_haptic)
{
    if (sih_haptic->rtp.rtp_file_num == AW8697_WAVEFORM_INDEX_OLD_STEADY//52
         || sih_haptic->rtp.rtp_file_num == AW8697_WAVEFORM_INDEX_HIGH_TEMP) {//51
        return sih_old_work_file_load_accord_f0(sih_haptic);
    }

    return NULL;
}

static bool sih_irq_rtp_local_file_handle(sih_haptic_t *sih_haptic)
{
	uint32_t buf_len = 0;
	uint32_t cont_len = 0;
	uint32_t inject_data_cnt;
	int ret = -1;

	/* inject 1/4 fifo size data once max */
	inject_data_cnt = sih_haptic->ram.base_addr >> 2;
	mutex_lock(&sih_haptic->rtp.rtp_lock);

	if (!sih_haptic->rtp.rtp_file_num) {
		hp_err("%s:rtp file num is 0, stop!\n", __func__);
		mutex_unlock(&sih_haptic->rtp.rtp_lock);
		return false;
	}

	if (!sih_haptic->rtp.rtp_cnt) {
		hp_err("%s:rtp_cnt is 0!\n", __func__);
		mutex_unlock(&sih_haptic->rtp.rtp_lock);
		return false;
	}

	if (!sih_haptic->rtp.rtp_cont) {
		hp_err("%s:rtp_container is null, break!\n", __func__);
		mutex_unlock(&sih_haptic->rtp.rtp_lock);
		return false;
	}

	hp_info("%s:rtp_cont->len = %d\n", __func__, sih_haptic->rtp.rtp_cont->len);

	cont_len = sih_haptic->rtp.rtp_cont->len;

	if ((cont_len - sih_haptic->rtp.rtp_cnt) < inject_data_cnt)
		buf_len = cont_len - sih_haptic->rtp.rtp_cnt;
	else
		buf_len = inject_data_cnt;

	hp_info("%s:buf_len:%d\n", __func__, buf_len);
	cpu_latency_qos_add_request(&sih_haptic->pm_qos, CPU_LATENCY_QOC_VALUE);
	if(buf_len > 0) {
		ret = sih_haptic->hp_func->write_rtp_data(sih_haptic,
			&sih_haptic->rtp.rtp_cont->data[sih_haptic->rtp.rtp_cnt], buf_len);

		if (ret < 0) {
			sih_haptic->hp_func->stop(sih_haptic);
			cpu_latency_qos_remove_request(&sih_haptic->pm_qos);
			sih_haptic->hp_func->set_rtp_aei(sih_haptic, false);
			sih_haptic->rtp.rtp_init = false;
			mutex_unlock(&sih_haptic->rtp.rtp_lock);
			hp_err("%s:i2c write rtp data failed\n", __func__);
			return false;
		}

		sih_haptic->rtp.rtp_cnt += buf_len;

		hp_info("%s:rtp cnt:%d\n", __func__, sih_haptic->rtp.rtp_cnt);
	}

	if ((sih_haptic->rtp.rtp_cnt == cont_len) ||
		sih_haptic->hp_func->if_chip_is_mode(sih_haptic, SIH_IDLE_MODE)) {
		if (sih_haptic->rtp.rtp_cnt != cont_len)
			hp_err("%s:rtp play error suspend!\n", __func__);
		else
			hp_info("%s:rtp update complete!\n", __func__);
		sih_haptic->hp_func->set_rtp_aei(sih_haptic, false);
		cpu_latency_qos_remove_request(&sih_haptic->pm_qos);
		sih_haptic->rtp.rtp_init = false;
		sih_chip_state_recovery(sih_haptic);
		mutex_unlock(&sih_haptic->rtp.rtp_lock);
		return false;
	}
	cpu_latency_qos_remove_request(&sih_haptic->pm_qos);
	mutex_unlock(&sih_haptic->rtp.rtp_lock);

	return true;
}

static irqreturn_t sih_irq_isr(int irq, void *data)
{
	sih_haptic_t *sih_haptic = data;

	hp_info("%s:enter! interrupt code number is %d\n", __func__, irq);

	if (sih_haptic->stream_func->is_stream_mode(sih_haptic))
		return IRQ_HANDLED;

	if (sih_haptic->hp_func->get_rtp_fifo_empty_state(sih_haptic)) {
		if (sih_haptic->rtp.rtp_init) {
			while ((!sih_haptic->hp_func->get_rtp_fifo_full_state(sih_haptic)) &&
				(sih_haptic->chip_ipara.play_mode == SIH_RTP_MODE)) {
				if (!sih_irq_rtp_local_file_handle(sih_haptic))
					break;
			}
		} else {
			hp_err("%s: rtp init false\n", __func__);
		}
	}

	if (sih_haptic->chip_ipara.play_mode != SIH_RTP_MODE)
		sih_haptic->hp_func->set_rtp_aei(sih_haptic, false);

	/* detect */
	if ((sih_haptic->detect.trig_detect_en | sih_haptic->detect.ram_detect_en |
		sih_haptic->detect.rtp_detect_en | sih_haptic->detect.cont_detect_en) &&
		(sih_haptic->hp_func->if_chip_is_detect_done(sih_haptic))) {
		hp_info("%s:if chip is detect done\n", __func__);
		sih_haptic->hp_func->ram_init(sih_haptic, true);
		sih_haptic->hp_func->read_detect_fifo(sih_haptic);
		sih_haptic->hp_func->ram_init(sih_haptic, false);
		sih_haptic->hp_func->detect_fifo_ctrl(sih_haptic, false);
		sih_haptic->detect.detect_f0_read_done = true;
	}
	hp_info("%s:exit\n", __func__);
	return IRQ_HANDLED;
}

static int sih_acquire_irq_res(struct device *dev, sih_haptic_t *sih_haptic)
{
	int ret = -1;
	int irq_flags;

	sih_haptic->hp_func->interrupt_state_init(sih_haptic);

	irq_flags = IRQF_TRIGGER_FALLING | IRQF_ONESHOT;

	ret = devm_request_threaded_irq(dev,
		gpio_to_irq(sih_haptic->chip_attr.irq_gpio), NULL, sih_irq_isr,
		irq_flags, sih_haptic->soft_frame.vib_dev.name, sih_haptic);
	return ret;
}

static void sih_vfree_container(sih_haptic_t *sih_haptic,
	haptic_container_t *cont)
{
	if (cont != NULL)
		vfree(cont);
}

static void sih_rtp_play_func(sih_haptic_t *sih_haptic, uint8_t mode)
{
	uint32_t buf_len = 0;
	uint32_t cont_len = 0;
	haptic_container_t *rtp_cont = sih_haptic->rtp.rtp_cont;

	if (!rtp_cont) {
		hp_err("%s:cont is null\n", __func__);
		sih_chip_state_recovery(sih_haptic);
		return;
	}

	hp_info("%s:the rtp cont len is %d\n", __func__, rtp_cont->len);
	sih_haptic->rtp.rtp_cnt = 0;
	mutex_lock(&sih_haptic->rtp.rtp_lock);
	cpu_latency_qos_add_request(&sih_haptic->pm_qos, CPU_LATENCY_QOC_VALUE);
	while (1) {
		if (!sih_haptic->hp_func->get_rtp_fifo_full_state(sih_haptic)) {
			cont_len = rtp_cont->len;
			if (sih_haptic->rtp.rtp_cnt < sih_haptic->ram.base_addr) {
				if ((cont_len - sih_haptic->rtp.rtp_cnt) <
					sih_haptic->ram.base_addr)
					buf_len = cont_len - sih_haptic->rtp.rtp_cnt;
				else
					buf_len = sih_haptic->ram.base_addr;
			} else if ((cont_len - sih_haptic->rtp.rtp_cnt) <
				(sih_haptic->ram.base_addr >> 2)) {
				buf_len = cont_len - sih_haptic->rtp.rtp_cnt;
			} else {
				buf_len = sih_haptic->ram.base_addr >> 2;
			}

			if (sih_haptic->rtp.rtp_cnt != cont_len) {
				if (mode == SIH_RTP_OSC_PLAY) {
					if (sih_haptic->osc_para.start_flag) {
						sih_haptic->osc_para.kstart = ktime_get();
						sih_haptic->osc_para.start_flag = false;
					}
				}
				sih_haptic->hp_func->write_rtp_data(sih_haptic,
					&rtp_cont->data[sih_haptic->rtp.rtp_cnt], buf_len);
				sih_haptic->rtp.rtp_cnt += buf_len;

				hp_info("%s:rtp cnt=%d\n", __func__, sih_haptic->rtp.rtp_cnt);
			}
		}

		if (sih_haptic->hp_func->get_rtp_fifo_full_state(sih_haptic) &&
			mode == SIH_RTP_NORMAL_PLAY) {
			break;
		}
		if ((sih_haptic->rtp.rtp_cnt == cont_len) &&
			sih_haptic->hp_func->if_chip_is_mode(sih_haptic, SIH_IDLE_MODE)) {
			if (sih_haptic->rtp.rtp_cnt != cont_len)
				hp_err("%s:rtp suspend!\n", __func__);
			else
				hp_info("%s:rtp complete!\n", __func__);

			if (mode == SIH_RTP_OSC_PLAY)
				sih_haptic->osc_para.kend = ktime_get();

			sih_chip_state_recovery(sih_haptic);
			break;
		}
	}

	if (mode == SIH_RTP_NORMAL_PLAY &&
		sih_haptic->chip_ipara.play_mode == SIH_RTP_MODE) {
		sih_haptic->hp_func->set_rtp_aei(sih_haptic, true);
	}
	cpu_latency_qos_remove_request(&sih_haptic->pm_qos);
	mutex_unlock(&sih_haptic->rtp.rtp_lock);
}

static void sih_rtp_play(sih_haptic_t *sih_haptic, uint8_t mode)
{
	hp_info("%s:rtp mode:%d\n", __func__, mode);
	if (mode == SIH_RTP_NORMAL_PLAY) {
		sih_rtp_play_func(sih_haptic, mode);
	} else if (mode == SIH_RTP_OSC_PLAY) {
		sih_haptic->osc_para.start_flag = true;
		sih_rtp_play_func(sih_haptic, mode);
		sih_haptic->osc_para.actual_time =
			ktime_to_us(ktime_sub(sih_haptic->osc_para.kend,
			sih_haptic->osc_para.kstart));
		hp_info("%s:actual time:%d\n", __func__,
			sih_haptic->osc_para.actual_time);
	} else {
		hp_err("%s:err mode %d\n", __func__, mode);
	}
}

static void sih_rtp_local_work(sih_haptic_t *sih_haptic, uint8_t mode)
{
	bool rtp_work_flag = false;
	int cnt = SIH_ENTER_RTP_MODE_MAX_TRY;
	int ret = -1;
	const struct firmware *rtp_file;
	uint8_t rtp_file_index = 0;

	hp_info("%s:enter!\n", __func__);

	if (mode == SIH_RTP_OSC_PLAY)
		rtp_file_index = SIH_OSC_PLAY_FILE_INDEX;
	else
		hp_err("%s:err mode:%d\n", __func__, mode);

	mutex_lock(&sih_haptic->rtp.rtp_lock);

	sih_haptic->rtp.rtp_init = false;
	sih_vfree_container(sih_haptic, sih_haptic->rtp.rtp_cont);
	sih_haptic->rtp.rtp_cont = NULL;

	ret = request_firmware(&rtp_file, sih_rtp_name[rtp_file_index],
		sih_haptic->dev);
	if (ret < 0) {
		hp_err("%s:fail to read %s\n", __func__, sih_rtp_name[rtp_file_index]);
		sih_chip_state_recovery(sih_haptic);
		mutex_unlock(&sih_haptic->rtp.rtp_lock);
		return;
	}

	sih_haptic->rtp.rtp_cont = vmalloc(rtp_file->size + sizeof(int));
	if (!sih_haptic->rtp.rtp_cont) {
#ifdef CONFIG_HAPTIC_FEEDBACK_MODULE
		(void)oplus_haptic_track_mem_alloc_err(
				HAPTIC_MEM_ALLOC_TRACK,
				rtp_file->size + sizeof(int), __func__);
#endif
		release_firmware(rtp_file);
		hp_err("%s:error allocating memory\n", __func__);
		sih_chip_state_recovery(sih_haptic);
		mutex_unlock(&sih_haptic->rtp.rtp_lock);
		return;
	}
	sih_haptic->rtp.rtp_cont->len = rtp_file->size;
	if (mode == SIH_RTP_OSC_PLAY)
		sih_haptic->osc_para.osc_rtp_len = rtp_file->size;

	mutex_unlock(&sih_haptic->rtp.rtp_lock);

	memcpy(sih_haptic->rtp.rtp_cont->data, rtp_file->data, rtp_file->size);
	release_firmware(rtp_file);

	hp_info("%s:rtp len is %d\n", __func__, sih_haptic->rtp.rtp_cont->len);

	mutex_lock(&sih_haptic->lock);
	sih_haptic->rtp.rtp_init = true;
	sih_haptic->chip_ipara.state = SIH_ACTIVE_MODE;
	sih_haptic->hp_func->stop(sih_haptic);
	sih_haptic->hp_func->set_rtp_aei(sih_haptic, false);
	sih_haptic->hp_func->set_play_mode(sih_haptic, SIH_RTP_MODE);
	/* osc rtp cali set trim to zero */
	if (mode == SIH_RTP_OSC_PLAY){
		if (sih_haptic->osc_para.set_trim) {
			sih_haptic->hp_func->upload_f0(sih_haptic, SIH_WRITE_ZERO);
		} else {
			sih_haptic->hp_func->upload_f0(sih_haptic, SIH_OSC_CALI_LRA);
		}
	}
	if (mode != SIH_RTP_NORMAL_PLAY)
		disable_irq(gpio_to_irq(sih_haptic->chip_attr.irq_gpio));

	sih_haptic->hp_func->play_go(sih_haptic, true);
	usleep_range(2000, 2500);
	while (cnt--) {
		if (sih_haptic->hp_func->if_chip_is_mode(sih_haptic, SIH_RTP_MODE)) {
			rtp_work_flag = true;
			hp_info("%s:rtp go!\n", __func__);
			break;
		}

		hp_info("%s:wait for rtp go!\n", __func__);
		usleep_range(2000, 2500);
	}
	if (rtp_work_flag) {
		sih_rtp_play(sih_haptic, mode);
	} else {
		/* enter standby mode */
		sih_haptic->hp_func->stop(sih_haptic);
		sih_haptic->chip_ipara.state = SIH_STANDBY_MODE;
		hp_err("%s:failed to enter rtp_go status!\n", __func__);
	}
	/* enable irq */
	if (mode != SIH_RTP_NORMAL_PLAY)
		enable_irq(gpio_to_irq(sih_haptic->chip_attr.irq_gpio));

	mutex_unlock(&sih_haptic->lock);
}

/*****************************************************
 *
 * ram
 *
 *****************************************************/
static void get_ram_num(sih_haptic_t *sih_haptic)
{
	uint8_t wave_addr[2] = {0};
	uint32_t first_wave_addr = 0;

	hp_info("%s:enter\n", __func__);
	if (!sih_haptic->ram.ram_init) {
		hp_err("%s:ram init failed, wave_num = 0!\n", __func__);
		return;
	}

	mutex_lock(&sih_haptic->lock);
	/* RAMINIT Enable */
	sih_haptic->hp_func->ram_init(sih_haptic, true);
	sih_haptic->hp_func->stop(sih_haptic);
	sih_haptic->hp_func->set_ram_addr(sih_haptic);
	sih_haptic->hp_func->get_first_wave_addr(sih_haptic, wave_addr);
	first_wave_addr = (wave_addr[0] << 8 | wave_addr[1]);
	sih_haptic->ram.wave_num = (first_wave_addr -
		sih_haptic->ram.base_addr - 1) / 4;

	hp_info("%s:first wave addr = 0x%04x, wave_num = %d\n", __func__,
		first_wave_addr, sih_haptic->ram.wave_num);

	/* RAMINIT Disable */
	sih_haptic->hp_func->ram_init(sih_haptic, false);
	mutex_unlock(&sih_haptic->lock);
}

static void sih_ram_load(const struct firmware *cont, void *context)
{
	int i;
	int ret = -1;
	uint16_t check_sum = 0;
	sih_haptic_t *sih_haptic = context;
	haptic_container_t *sih_haptic_fw;

	hp_info("%s:enter\n", __func__);

	if (!cont) {
		hp_err("%s:failed to read firmware\n", __func__);
		release_firmware(cont);
		return;
	}

	hp_info("%s:loaded size: %zu\n", __func__, cont ? cont->size : 0);

	/* check sum */
	for (i = 2; i < cont->size; i++)
		check_sum += cont->data[i];
	if (check_sum != (uint16_t)((cont->data[0] << 8) | (cont->data[1]))) {
		hp_err("%s:check sum err: check_sum=0x%04x\n", __func__, check_sum);
		release_firmware(cont);
		return;
	}

	hp_info("%s:check sum pass : 0x%04x\n", __func__, check_sum);

	sih_haptic->ram.check_sum = check_sum;

	/*ram update */
	sih_haptic_fw = kzalloc(cont->size + sizeof(int), GFP_KERNEL);
	if (!sih_haptic_fw) {
		release_firmware(cont);
		hp_err("%s:error allocating memory\n", __func__);
		return;
	}

	sih_haptic_fw->len = cont->size;
	memcpy(sih_haptic_fw->data, cont->data, cont->size);
	release_firmware(cont);
	ret = sih_haptic->hp_func->update_ram_config(sih_haptic, sih_haptic_fw);
	if (ret) {
		hp_err("%s:ram firmware update failed!\n", __func__);
	} else {
		sih_haptic->ram.ram_init = true;
		sih_haptic->ram.len = sih_haptic_fw->len - sih_haptic->ram.ram_shift;
		hp_info("%s:ram firmware update complete!\n", __func__);
		get_ram_num(sih_haptic);
	}
	kfree(sih_haptic_fw);
}

static void sih_ram_play(sih_haptic_t *sih_haptic, uint8_t mode)
{
	hp_info("%s:enter\n", __func__);
	sih_haptic->hp_func->set_play_mode(sih_haptic, mode);
	sih_haptic->hp_func->play_go(sih_haptic, true);
}

sih_haptic_t *get_global_haptic_ptr(void)
{
	return g_haptic_t.g_haptic[SIH_HAPTIC_MMAP_DEV_INDEX];
}

int pointer_prehandle(struct device *dev, const char *buf,
	cdev_t **cdev, sih_haptic_t **sih_haptic)
{
	hp_info("%s:enter\n", __func__);
	null_pointer_err_check(dev);
	null_pointer_err_check(buf);
	*cdev = dev_get_drvdata(dev);
	null_pointer_err_check(*cdev);
	*sih_haptic = container_of(*cdev, sih_haptic_t, soft_frame.vib_dev);
	null_pointer_err_check(*sih_haptic);

	return 0;
}

static int ram_update(sih_haptic_t *sih_haptic)
{
	int len = 0;
	int index = 0;

	hp_info("%s:enter\n", __func__);

	sih_haptic->ram.ram_init = false;

	if (DEVICE_ID_0815 == sih_haptic->device_id || DEVICE_ID_0809 == sih_haptic->device_id) {
		if (sih_haptic->detect.tracking_f0 < F0_VAL_MIN_0815
				|| sih_haptic->detect.tracking_f0 > F0_VAL_MAX_0815) {
			sih_haptic->detect.tracking_f0 = 1700;
		}
	} else if (DEVICE_ID_1419 == sih_haptic->device_id) {
		if (sih_haptic->detect.tracking_f0 < F0_VAL_MIN_1419
				|| sih_haptic->detect.tracking_f0 > F0_VAL_MAX_1419) {
			sih_haptic->detect.tracking_f0 = 2050;
		}
	}

	hp_info("%s: haptic_real_f0 [%d]\n", __func__, (sih_haptic->detect.tracking_f0 / 10));
	if (DEVICE_ID_0815 == sih_haptic->device_id || DEVICE_ID_0809 == sih_haptic->device_id) {
		if (sih_haptic->ram.vibration_style == AW8697_HAPTIC_VIBRATION_CRISP_STYLE) {
			len =  request_firmware_nowait(THIS_MODULE, FW_ACTION_HOTPLUG,
						sih_ram_name[index], sih_haptic->dev, GFP_KERNEL,
						sih_haptic, sih_ram_load);
			hp_err("%s line:%d: haptic bin name %s \n", __func__, __LINE__, sih_ram_name[index]);
		} else if (sih_haptic->ram.vibration_style == AW8697_HAPTIC_VIBRATION_SOFT_STYLE) {
			len =  request_firmware_nowait(THIS_MODULE, FW_ACTION_HOTPLUG,
						sih_ram_name_170_soft[index], sih_haptic->dev, GFP_KERNEL,
						sih_haptic, sih_ram_load);
			hp_err("%s line:%d: haptic bin name %s \n", __func__, __LINE__, sih_ram_name[index]);
		} else {
			len =  request_firmware_nowait(THIS_MODULE, FW_ACTION_HOTPLUG,
						sih_ram_name[index], sih_haptic->dev, GFP_KERNEL,
						sih_haptic, sih_ram_load);
			hp_err("%s line:%d: haptic bin name %s \n", __func__, __LINE__, sih_ram_name[index]);
		}
	} else if (DEVICE_ID_1419 == sih_haptic->device_id) {
		if (sih_haptic->ram.vibration_style == AW8697_HAPTIC_VIBRATION_CRISP_STYLE) {
			len =  request_firmware_nowait(THIS_MODULE, FW_ACTION_HOTPLUG,
						sih_ram_name_205[index], sih_haptic->dev, GFP_KERNEL,
						sih_haptic, sih_ram_load);
			hp_err("%s line:%d: haptic bin name %s \n", __func__, __LINE__, sih_ram_name_205[index]);
		} else if (sih_haptic->ram.vibration_style == AW8697_HAPTIC_VIBRATION_SOFT_STYLE) {
			len =  request_firmware_nowait(THIS_MODULE, FW_ACTION_HOTPLUG,
						 sih_ram_name_205_soft[index], sih_haptic->dev, GFP_KERNEL,
						sih_haptic, sih_ram_load);
			hp_err("%s line:%d: haptic bin name %s \n", __func__, __LINE__,  sih_ram_name_205_soft[index]);
		} else {
			len =  request_firmware_nowait(THIS_MODULE, FW_ACTION_HOTPLUG,
						sih_ram_name_205[index], sih_haptic->dev, GFP_KERNEL,
						sih_haptic, sih_ram_load);
			hp_err("%s line:%d: haptic bin name %s \n", __func__, __LINE__, sih_ram_name_205[index]);
		}
	}
	return len;
}

static void ram_update_work_func(struct work_struct *work) {
	sih_haptic_t *sih_haptic =
		container_of(work, sih_haptic_t, ram.ram_update_work);

	hp_err("%s: enter\n", __func__);
	ram_update(sih_haptic);
}
/*****************************************************
 *
 * vibrator sysfs node
 *
 *****************************************************/
#ifdef OPLUS_FEATURE_CHG_BASIC
static void motor_old_test_work(struct work_struct *work)
{
	struct sih_haptic *sih_haptic =
		container_of(work, struct sih_haptic, motor_old_test_work);

	hp_err("%s: motor_old_test_mode = %d. gain [0x%02x]\n", __func__,
	       sih_haptic->motor_old_test_mode, sih_haptic->chip_ipara.gain);

	if (sih_haptic->motor_old_test_mode == MOTOR_OLD_TEST_TRANSIENT) {
		mutex_lock(&sih_haptic->lock);

		sih_haptic->hp_func->stop(sih_haptic);
		sih_haptic->chip_ipara.gain = 0x80;
		sih_haptic->hp_func->set_gain(sih_haptic, sih_haptic->chip_ipara.gain);
		sih_haptic->hp_func->set_drv_bst_vol(sih_haptic,
					  SIH_HAPTIC_MAX_VOL);
		sih_haptic->hp_func->set_wav_seq(sih_haptic, 0,
					  AW8697_WAVEFORM_INDEX_TRANSIENT);
		sih_haptic->hp_func->set_wav_loop(sih_haptic, 0, 0);
		sih_ram_play(sih_haptic, SIH_RAM_MODE);

		mutex_unlock(&sih_haptic->lock);
	} else if (sih_haptic->motor_old_test_mode == MOTOR_OLD_TEST_STEADY) {
		mutex_lock(&sih_haptic->lock);
		sih_haptic->hp_func->stop(sih_haptic);
		sih_haptic->chip_ipara.gain = 0x80;
		sih_haptic->hp_func->set_gain(sih_haptic, sih_haptic->chip_ipara.gain);
		sih_haptic->hp_func->set_drv_bst_vol(sih_haptic,
					  SIH_HAPTIC_MAX_VOL);
		sih_haptic->hp_func->set_rtp_aei(sih_haptic, false);
		sih_haptic->hp_func->clear_interrupt_state(sih_haptic);
		mutex_unlock(&sih_haptic->lock);
		if (AW8697_WAVEFORM_INDEX_OLD_STEADY < NUM_WAVEFORMS) {
			sih_haptic->rtp.rtp_file_num = AW8697_WAVEFORM_INDEX_OLD_STEADY;
			if (AW8697_WAVEFORM_INDEX_OLD_STEADY) {
				//schedule_work(&sih_haptic->rtp.rtp_work);
				queue_work(system_unbound_wq,
						   &sih_haptic->rtp.rtp_work);
			}
		} else {
			hp_err("%s: rtp_file_num 0x%02x over max value \n",
			       __func__, sih_haptic->rtp.rtp_file_num);
		}
	} else if (sih_haptic->motor_old_test_mode ==
		   MOTOR_OLD_TEST_HIGH_TEMP_HUMIDITY) {
		mutex_lock(&sih_haptic->lock);
		sih_haptic->hp_func->stop(sih_haptic);
		sih_haptic->chip_ipara.gain = 0x80;
		sih_haptic->hp_func->set_gain(sih_haptic, sih_haptic->chip_ipara.gain);
		sih_haptic->hp_func->set_drv_bst_vol(sih_haptic,
					  SIH_HAPTIC_MAX_VOL);
		sih_haptic->hp_func->set_rtp_aei(sih_haptic, false);
		sih_haptic->hp_func->clear_interrupt_state(sih_haptic);
		mutex_unlock(&sih_haptic->lock);
		if (AW8697_WAVEFORM_INDEX_HIGH_TEMP < NUM_WAVEFORMS) {
			sih_haptic->rtp.rtp_file_num = AW8697_WAVEFORM_INDEX_HIGH_TEMP;
			if (AW8697_WAVEFORM_INDEX_HIGH_TEMP) {
				//schedule_work(&sih_haptic->rtp.rtp_work);
				queue_work(system_unbound_wq,
						   &sih_haptic->rtp.rtp_work);
			}
		} else {
			hp_err("%s: rtp_file_num 0x%02x over max value \n",
			       __func__, sih_haptic->rtp.rtp_file_num);
		}
	} else if (sih_haptic->motor_old_test_mode == MOTOR_OLD_TEST_LISTEN_POP) {
		mutex_lock(&sih_haptic->lock);
		sih_haptic->hp_func->stop(sih_haptic);
		sih_haptic->chip_ipara.gain = 0x80;
		sih_haptic->hp_func->set_gain(sih_haptic, sih_haptic->chip_ipara.gain);
		sih_haptic->hp_func->set_drv_bst_vol(sih_haptic,
					  SIH_HAPTIC_MAX_VOL);
		sih_haptic->hp_func->set_rtp_aei(sih_haptic, false);
		sih_haptic->hp_func->clear_interrupt_state(sih_haptic);
		mutex_unlock(&sih_haptic->lock);
		if (AW8697_WAVEFORM_INDEX_LISTEN_POP < NUM_WAVEFORMS) {
			sih_haptic->rtp.rtp_file_num = AW8697_WAVEFORM_INDEX_LISTEN_POP;
			if (AW8697_WAVEFORM_INDEX_LISTEN_POP) {
				//schedule_work(&sih_haptic->rtp.rtp_work);
				queue_work(system_unbound_wq,
						   &sih_haptic->rtp.rtp_work);
			}
		} else {
			hp_err("%s: rtp_file_num 0x%02x over max value \n",
			       __func__, sih_haptic->rtp.rtp_file_num);
		}
	} else {
		sih_haptic->motor_old_test_mode = 0;
		mutex_lock(&sih_haptic->lock);
		sih_haptic->hp_func->stop(sih_haptic);
		//aw8697_haptic_android_stop(aw8697);
		mutex_unlock(&sih_haptic->lock);
	}
}

static ssize_t vmax_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = dev_get_drvdata(dev);
	sih_haptic_t *sih_haptic = container_of(cdev,
		sih_haptic_t, soft_frame.vib_dev);

	return snprintf(buf, PAGE_SIZE, "0x%02x\n", sih_haptic->chip_ipara.vmax);
}

static int convert_level_to_vmax(struct sih_haptic *sih_haptic, int val)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(vmax_map); i++) {
		if (val == vmax_map[i].level) {
			sih_haptic->chip_ipara.vmax = vmax_map[i].vmax;
			sih_haptic->chip_ipara.gain = vmax_map[i].gain;
			break;
		}
	}
	if (i == ARRAY_SIZE(vmax_map)) {
		sih_haptic->chip_ipara.vmax = vmax_map[i - 1].vmax;
		sih_haptic->chip_ipara.gain = vmax_map[i - 1].gain;
	}
	if (sih_haptic->chip_ipara.vmax > SIH_HAPTIC_MAX_VOL)
		sih_haptic->chip_ipara.vmax = SIH_HAPTIC_MAX_VOL;

	return i;
}

static ssize_t vmax_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = dev_get_drvdata(dev);
	sih_haptic_t *sih_haptic = container_of(cdev,
		sih_haptic_t, soft_frame.vib_dev);
	uint32_t val = 0;
	int rc = 0;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;
	hp_info("%s: value=%d\n", __func__, val);
	mutex_lock(&sih_haptic->lock);
#ifdef OPLUS_FEATURE_CHG_BASIC
	if (val <= 255) {
		sih_haptic->chip_ipara.gain = (val * AW_HAPTIC_RAM_VBAT_COMP_GAIN) / 255;
	} else if (val <= 2400) {
		convert_level_to_vmax(sih_haptic, val);
	} else {
		sih_haptic->chip_ipara.vmax = SIH_HAPTIC_MAX_VOL;
		sih_haptic->chip_ipara.gain = 0x80;
	}

	if (val == 2550) {	/* for old test only */
		sih_haptic->chip_ipara.gain = AW_HAPTIC_RAM_VBAT_COMP_GAIN;
	}

	if (sih_haptic->device_id == 833) {
		sih_haptic->chip_ipara.vmax = SIH_HAPTIC_MAX_VOL;
		sih_haptic->chip_ipara.gain = 0x80;
	}

	sih_haptic->hp_func->set_gain(sih_haptic, sih_haptic->chip_ipara.gain);
	sih_haptic->hp_func->set_drv_bst_vol(sih_haptic, sih_haptic->chip_ipara.vmax);
#else
	sih_haptic->chip_ipara.vmax = val;
	sih_haptic->hp_func->set_drv_bst_vol(sih_haptic, sih_haptic->chip_ipara.vmax);
#endif
	mutex_unlock(&sih_haptic->lock);
	hp_info("%s: gain[0x%x], vmax[%d] end\n", __func__,
			sih_haptic->chip_ipara.gain, sih_haptic->chip_ipara.vmax);

	return count;
}

static ssize_t waveform_index_show(struct device *dev,
  	struct device_attribute *attr, char *buf)
{
	return 0;
}

static ssize_t waveform_index_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = dev_get_drvdata(dev);
	sih_haptic_t *sih_haptic = container_of(cdev,
		sih_haptic_t, soft_frame.vib_dev);
	unsigned int databuf[1] = {0};

	if (1 == sscanf(buf, "%d", &databuf[0])) {
		hp_err("%s: waveform_index = %d\n", __func__, databuf[0]);
		mutex_lock(&sih_haptic->lock);
		sih_haptic->ram.seq[0] = (unsigned char)databuf[0];
		sih_haptic->hp_func->set_wav_seq(sih_haptic, 0, sih_haptic->ram.seq[0]);
		sih_haptic->hp_func->set_wav_seq(sih_haptic, 1, 0);
		sih_haptic->hp_func->set_wav_loop(sih_haptic, 0, 0);
		mutex_unlock(&sih_haptic->lock);
	}
	return count;
}

static ssize_t device_id_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = dev_get_drvdata(dev);
	sih_haptic_t *sih_haptic = container_of(cdev,
		sih_haptic_t, soft_frame.vib_dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", sih_haptic->device_id);
}

static ssize_t device_id_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	return count;
}

static ssize_t motor_old_test_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return 0;
}

static ssize_t motor_old_test_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = dev_get_drvdata(dev);
	struct sih_haptic *sih_haptic = container_of(cdev, struct sih_haptic,
						   soft_frame.vib_dev);

	unsigned int databuf[1] = {0};

	hp_info("%s: enter\n", __func__);
	if (1 == sscanf(buf, "%x", &databuf[0])) {
		if (databuf[0] == 0) {
			cancel_work_sync(&sih_haptic->motor_old_test_work);
			mutex_lock(&sih_haptic->lock);
			sih_haptic->hp_func->stop(sih_haptic);
			mutex_unlock(&sih_haptic->lock);
		} else if (databuf[0] <= MOTOR_OLD_TEST_ALL_NUM) {
			cancel_work_sync(&sih_haptic->motor_old_test_work);
			sih_haptic->motor_old_test_mode = databuf[0];
			hp_err("%s: motor_old_test_mode = %d.\n", __func__,
				   sih_haptic->motor_old_test_mode);
			schedule_work(&sih_haptic->motor_old_test_work);
		}
	}

	return count;
}


static ssize_t livetap_support_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	return snprintf(buf, PAGE_SIZE, "%d\n", sih_haptic->livetap_support);
}

static ssize_t livetap_support_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	int val;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (kstrtouint(buf, 0, &val))
		return -EINVAL;

	if (val > 0)
		sih_haptic->livetap_support = true;
	else
		sih_haptic->livetap_support = false;

	return count;
}
#endif

static ssize_t seq_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	uint8_t i;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	sih_haptic->hp_func->get_wav_seq(sih_haptic, SIH_HAPTIC_SEQUENCER_SIZE);

	for (i = 0; i < SIH_HAPTIC_SEQUENCER_SIZE; i++) {
		len += snprintf(buf + len, PAGE_SIZE - len,
			"seq%d = %d\n", i, sih_haptic->ram.seq[i]);
	}

	return len;
}

static ssize_t seq_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	unsigned int databuf[2] = {0, 0};
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x", &databuf[0], &databuf[1]) == 2) {
		if (databuf[0] >= SIH_HAPTIC_SEQUENCER_SIZE) {
			hp_err("%s:input value out of range!\n", __func__);
			return count;
		}
		mutex_lock(&sih_haptic->lock);
		sih_haptic->ram.seq[(uint8_t)databuf[0]] = (uint8_t)databuf[1];
		sih_haptic->hp_func->set_wav_seq(sih_haptic,
			(uint8_t)databuf[0], (uint8_t)databuf[1]);
		mutex_unlock(&sih_haptic->lock);
	}

	return count;
}

static ssize_t reg_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t i;
	ssize_t len = 0;
	uint8_t reg_val = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	for (i = 0; i <= SIH688X_REG_MAX; i++) {
		haptic_regmap_read(sih_haptic->regmapp.regmapping, i,
			SIH_I2C_OPERA_BYTE_ONE, &reg_val);
		len += snprintf(buf + len, PAGE_SIZE - len,
			"0x%02x = 0x%02x\n", i, reg_val);
	}

	return len;
}

static ssize_t reg_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	unsigned int databuf[2] = {0, 0};
	uint8_t val = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x", &databuf[0], &databuf[1]) == 2) {
		val = (uint8_t)databuf[1];
		haptic_regmap_write(sih_haptic->regmapp.regmapping,
			(uint8_t)databuf[0], SIH_I2C_OPERA_BYTE_ONE, &val);
	}

	return count;
}

static ssize_t state_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	sih_haptic->hp_func->update_chip_state(sih_haptic);

	len += snprintf(buf + len, PAGE_SIZE - len, "state = %d, play_mode = %d\n",
		sih_haptic->chip_ipara.state, sih_haptic->chip_ipara.play_mode);

	return len;
}

static ssize_t state_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t val = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;

	if (val == SIH_STANDBY_MODE) {
		sih_haptic->hp_func->stop(sih_haptic);
		sih_haptic->chip_ipara.state = SIH_STANDBY_MODE;
	}

	return count;
}

static ssize_t gain_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len = snprintf(buf, PAGE_SIZE, "gain = 0x%02x\n", sih_haptic->chip_ipara.gain);

	return len;
}

static ssize_t gain_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t val = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;

	if (val > SIH_HAPTIC_MAX_GAIN) {
		hp_err("%s:gain out of range!\n", __func__);
		return count;
	}

	hp_info("%s:gain = 0x%02x\n", __func__, val);

	mutex_lock(&sih_haptic->lock);
	sih_haptic->chip_ipara.gain = val;
	sih_haptic->hp_func->set_gain(sih_haptic, sih_haptic->chip_ipara.gain);
	mutex_unlock(&sih_haptic->lock);

	return count;
}

static ssize_t rtp_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len += snprintf(buf + len, PAGE_SIZE - len, "rtp_cnt = %d\n",
		sih_haptic->rtp.rtp_cnt);

	return len;
}

static ssize_t rtp_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t val = 0;
	int rc = 0;
	int rtp_is_going_on = 0;
	unsigned long audio_delay = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;

	hp_info("%s:input rtp index is :%d\n", __func__, val);

	mutex_lock(&sih_haptic->lock);

	rtp_is_going_on = sih_haptic->hp_func->if_chip_is_mode(sih_haptic, SIH_RTP_MODE);
	if (rtp_is_going_on && (val == AUDIO_READY_STATUS)) {
		hp_err("%s: audio status rtp[%d]\n", __func__, val);
		mutex_unlock(&sih_haptic->lock);
		return count;
	}

	/*OP add for juge rtp on end*/
	if (((val >=  RINGTONES_START_INDEX && val <= RINGTONES_END_INDEX)
		|| (val >=  NEW_RING_START && val <= NEW_RING_END)
		|| (val >=  OS12_NEW_RING_START && val <= OS12_NEW_RING_END)
		|| (val >=  OPLUS_RING_START && val <= OPLUS_RING_END)
		|| (val >=  OS14_NEW_RING_START && val <= OS14_NEW_RING_END)
		|| (val >=  ALCLOUDSCAPE_START && val <= ALCLOUDSCAPE_END)
		|| (val >=  RINGTONE_NOTIF_ALARM_START && val <= RINGTONE_NOTIF_ALARM_END)
		|| val == RINGTONES_SIMPLE_INDEX
		|| val == RINGTONES_PURE_INDEX
		|| val == AUDIO_READY_STATUS)) {
		if (val == AUDIO_READY_STATUS) {
			sih_haptic->rtp.audio_ready = true;
		} else {
			sih_haptic->rtp.haptic_ready = true;
		}

		hp_err("%s:audio[%d] and haptic[%d]\n", __func__,
			sih_haptic->rtp.audio_ready, sih_haptic->rtp.haptic_ready);

		if (sih_haptic->rtp.haptic_ready && !sih_haptic->rtp.audio_ready) {
			sih_haptic->rtp.pre_haptic_number = val;
		}
		if (!sih_haptic->rtp.audio_ready || !sih_haptic->rtp.haptic_ready) {
			mutex_unlock(&sih_haptic->lock);
			return count;
		}
	}

	if (val == AUDIO_READY_STATUS && sih_haptic->rtp.pre_haptic_number) {
		hp_err("%s:pre_haptic_num:%d\n", __func__, sih_haptic->rtp.pre_haptic_number);
		val = sih_haptic->rtp.pre_haptic_number;
		audio_delay = sih_haptic->rtp.audio_delay;
	}

	sih_op_clean_status(sih_haptic);
	sih_haptic->rtp.rtp_file_num = val;
	sih_haptic->hp_func->stop(sih_haptic);
	sih_haptic->hp_func->set_rtp_aei(sih_haptic, false);
	sih_haptic->hp_func->clear_interrupt_state(sih_haptic);

	mutex_unlock(&sih_haptic->lock);

	if (val > 0 && val < NUM_WAVEFORMS) {
		schedule_work(&sih_haptic->rtp.rtp_work);
	} else {
		hp_err("%s: input number err:%d\n", __func__, val);
	}

	return count;
}


static ssize_t auto_pvdd_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len += snprintf(buf + len, PAGE_SIZE - len, "auto_pvdd = %d\n",
		sih_haptic->chip_ipara.auto_pvdd_en);

	return len;
}

static ssize_t auto_pvdd_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	bool val = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = strtobool(buf, &val);
	if (rc < 0)
		return rc;

	mutex_lock(&sih_haptic->lock);
	sih_haptic->hp_func->stop(sih_haptic);
	sih_haptic->hp_func->set_auto_pvdd(sih_haptic, val);
	mutex_unlock(&sih_haptic->lock);

	return count;
}

static ssize_t duration_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	ktime_t time_remain;
	s64 time_ms = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (hrtimer_active(&sih_haptic->timer)) {
		time_remain = hrtimer_get_remaining(&sih_haptic->timer);
		time_ms = ktime_to_ms(time_remain);
	}

	len = snprintf(buf, PAGE_SIZE, "%lldms\n", time_ms);

	return len;
}

static ssize_t duration_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t val = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;

	if (val <= 0) {
		hp_err("%s:duration out of range!\n", __func__);
		return count;
	}
	sih_haptic->chip_ipara.duration = val;
	hp_info("%s: duration = %d\n", __func__, sih_haptic->chip_ipara.duration);
	return count;
}

static ssize_t osc_cali_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len += snprintf(buf + len, PAGE_SIZE - len, "%d\n",
		sih_haptic->osc_para.actual_time);
	return len;
}

static ssize_t osc_cali_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t val = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;
	hp_info("%s: enter, val = %d\n", __func__, val);
	if (val <= 0)
		return count;

	if (val == 3) {
		sih_haptic->osc_para.set_trim = true;
		sih_haptic->chip_ipara.state = SIH_ACTIVE_MODE;
		sih_rtp_local_work(sih_haptic, SIH_RTP_OSC_PLAY);
		sih_haptic->hp_func->osc_cali(sih_haptic);
	} else if (val == 1) {
		sih_haptic->osc_para.set_trim = false;
		sih_haptic->chip_ipara.state = SIH_ACTIVE_MODE;
		sih_rtp_local_work(sih_haptic, SIH_RTP_OSC_PLAY);
	}
	return count;
}



static ssize_t ram_num_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len += snprintf(buf + len, PAGE_SIZE - len, "wave_num = %d\n",
		sih_haptic->ram.wave_num);

	return len;
}

static ssize_t loop_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	uint8_t i;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	sih_haptic->hp_func->get_wav_loop(sih_haptic);

	for (i = 0; i < SIH_HAPTIC_SEQUENCER_SIZE; i++) {
		len += snprintf(buf + len, PAGE_SIZE - len, "seq%d = loop:%d\n",
			i, sih_haptic->ram.loop[i]);
	}

	return len;
}

static ssize_t loop_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	unsigned int databuf[2] = {0, 0};
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x", &databuf[0], &databuf[1]) == 2) {
		if ((databuf[0] >= SIH_HAPTIC_SEQUENCER_SIZE) ||
			(databuf[1] > SIH_HAPTIC_REG_SEQLOOP_MAX)) {
			hp_err("%s:input value out of range!\n", __func__);
			return count;
		}
		mutex_lock(&sih_haptic->lock);
		sih_haptic->ram.loop[(uint8_t)databuf[0]] = (uint8_t)databuf[1];
		sih_haptic->hp_func->set_wav_loop(sih_haptic,
			(uint8_t)databuf[0], (uint8_t)databuf[1]);
		mutex_unlock(&sih_haptic->lock);
	}

	return count;
}

static ssize_t ram_update_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	/* RAMINIT Enable */
	sih_haptic->hp_func->stop(sih_haptic);
	sih_haptic->hp_func->ram_init(sih_haptic, true);
	sih_haptic->hp_func->set_ram_addr(sih_haptic);
	len += snprintf(buf + len, PAGE_SIZE - len, "sih_haptic_ram:\n");
	len += sih_haptic->hp_func->get_ram_data(sih_haptic, buf);

	/* RANINIT Disable */
	sih_haptic->hp_func->ram_init(sih_haptic, false);

	return len;
}

static ssize_t ram_update_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t val = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;

	hp_info("%s:ram update is %d\n", __func__, val);

	if (val) {
		schedule_work(&sih_haptic->ram.ram_update_work);
	}
	return count;
}

static ssize_t ram_vbat_comp_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len += snprintf(buf + len, PAGE_SIZE - len, "ram_vbat_comp = %d\n",
		sih_haptic->ram.ram_vbat_comp);

	return len;
}

static ssize_t ram_vbat_comp_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t val = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;

	mutex_lock(&sih_haptic->lock);

	if (val)
		sih_haptic->ram.ram_vbat_comp = SIH_RAM_VBAT_COMP_ENABLE;
	else
		sih_haptic->ram.ram_vbat_comp = SIH_RAM_VBAT_COMP_DISABLE;

	mutex_unlock(&sih_haptic->lock);

	return count;
}

static ssize_t cont_go_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t val = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;

	if (val <= 0)
		return count;

	mutex_lock(&sih_haptic->lock);
	sih_haptic->hp_func->check_detect_state(sih_haptic, SIH_CONT_MODE);
	sih_haptic->hp_func->set_play_mode(sih_haptic, SIH_CONT_MODE);
	sih_haptic->hp_func->play_go(sih_haptic, true);
	mutex_unlock(&sih_haptic->lock);

	return count;
}

static ssize_t cont_seq0_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len = sih_haptic->hp_func->get_cont_para(sih_haptic,
		SIH688X_CONT_PARA_SEQ0, buf);

	return len;
}

static ssize_t cont_seq0_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	unsigned int databuf[3] = {0};
	uint8_t param[3] = {0};
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x %x", &databuf[0], &databuf[1], &databuf[2]) == 3) {
		param[0] = (uint8_t)databuf[0];
		param[1] = (uint8_t)databuf[1];
		param[2] = (uint8_t)databuf[2];
		mutex_lock(&sih_haptic->lock);
		sih_haptic->hp_func->set_cont_para(sih_haptic,
			SIH688X_CONT_PARA_SEQ0, param);
		mutex_unlock(&sih_haptic->lock);
	}

	return count;
}

static ssize_t cont_seq1_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len = sih_haptic->hp_func->get_cont_para(sih_haptic,
		SIH688X_CONT_PARA_SEQ1, buf);

	return len;
}

static ssize_t cont_seq1_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	unsigned int databuf[3] = {0};
	uint8_t param[3] = {0};
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x %x", &databuf[0], &databuf[1], &databuf[2]) == 3) {
		param[0] = (uint8_t)databuf[0];
		param[1] = (uint8_t)databuf[1];
		param[2] = (uint8_t)databuf[2];
		mutex_lock(&sih_haptic->lock);
		sih_haptic->hp_func->set_cont_para(sih_haptic,
			SIH688X_CONT_PARA_SEQ1, param);
		mutex_unlock(&sih_haptic->lock);
	}

	return count;
}

static ssize_t cont_seq2_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len = sih_haptic->hp_func->get_cont_para(sih_haptic,
		SIH688X_CONT_PARA_SEQ2, buf);

	return len;
}

static ssize_t cont_seq2_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	unsigned int databuf[3] = {0};
	uint8_t param[3] = {0};
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x %x", &databuf[0], &databuf[1], &databuf[2]) == 3) {
		param[0] = (uint8_t)databuf[0];
		param[1] = (uint8_t)databuf[1];
		param[2] = (uint8_t)databuf[2];
		mutex_lock(&sih_haptic->lock);
		sih_haptic->hp_func->set_cont_para(sih_haptic,
			SIH688X_CONT_PARA_SEQ2, param);
		mutex_unlock(&sih_haptic->lock);
	}

	return count;
}

static ssize_t cont_asmooth_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len = sih_haptic->hp_func->get_cont_para(sih_haptic,
		SIH688X_CONT_PARA_ASMOOTH, buf);

	return len;
}

static ssize_t cont_asmooth_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	unsigned int databuf[3] = {0};
	uint8_t param[3] = {0};
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x %x", &databuf[0], &databuf[1], &databuf[2]) == 3) {
		param[0] = (uint8_t)databuf[0];
		param[1] = (uint8_t)databuf[1];
		param[2] = (uint8_t)databuf[2];
		mutex_lock(&sih_haptic->lock);
		sih_haptic->hp_func->set_cont_para(sih_haptic,
			SIH688X_CONT_PARA_ASMOOTH, param);
		mutex_unlock(&sih_haptic->lock);
	}

	return count;
}

static ssize_t cont_th_len_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len = sih_haptic->hp_func->get_cont_para(sih_haptic,
		SIH688X_CONT_PARA_TH_LEN, buf);

	return len;
}

static ssize_t cont_th_len_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	unsigned int databuf[3] = {0};
	uint8_t param[3] = {0};
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x %x", &databuf[0], &databuf[1], &databuf[2]) == 3) {
		param[0] = (uint8_t)databuf[0];
		param[1] = (uint8_t)databuf[1];
		param[2] = (uint8_t)databuf[2];
		mutex_lock(&sih_haptic->lock);
		sih_haptic->hp_func->set_cont_para(sih_haptic,
			SIH688X_CONT_PARA_TH_LEN, param);
		mutex_unlock(&sih_haptic->lock);
	}

	return count;
}

static ssize_t cont_th_num_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len = sih_haptic->hp_func->get_cont_para(sih_haptic,
		SIH688X_CONT_PARA_TH_NUM, buf);

	return len;
}

static ssize_t cont_th_num_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	unsigned int databuf[3] = {0};
	uint8_t param[3] = {0};
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x %x", &databuf[0], &databuf[1], &databuf[2]) == 3) {
		param[0] = (uint8_t)databuf[0];
		param[1] = (uint8_t)databuf[1];
		param[2] = (uint8_t)databuf[2];
		mutex_lock(&sih_haptic->lock);
		sih_haptic->hp_func->set_cont_para(sih_haptic,
			SIH688X_CONT_PARA_TH_NUM, param);
		mutex_unlock(&sih_haptic->lock);
	}

	return count;
}

static ssize_t cont_ampli_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len = sih_haptic->hp_func->get_cont_para(sih_haptic,
		SIH688X_CONT_PARA_AMPLI, buf);

	return len;
}

static ssize_t cont_ampli_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	unsigned int databuf[3] = {0};
	uint8_t param[3] = {0};
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x %x", &databuf[0], &databuf[1], &databuf[2]) == 3) {
		param[0] = (uint8_t)databuf[0];
		param[1] = (uint8_t)databuf[1];
		param[2] = (uint8_t)databuf[2];
		mutex_lock(&sih_haptic->lock);
		sih_haptic->hp_func->set_cont_para(sih_haptic,
			SIH688X_CONT_PARA_AMPLI, param);
		mutex_unlock(&sih_haptic->lock);
	}

	return count;
}

static ssize_t ram_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t databuf[2] = {0, 0};
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x", &databuf[0], &databuf[1]) != 2) {
		hp_err("%s:input parameter error\n", __func__);
		return count;
	}

	if (!sih_haptic->ram.ram_init) {
		hp_err("%s:ram init failed, not allow to play!\n", __func__);
		return count;
	}

	mutex_lock(&sih_haptic->lock);

	/* RAM MODE */
	if (databuf[0] == 1) {
		sih_haptic->hp_func->stop(sih_haptic);
		sih_haptic->ram.action_mode = SIH_RAM_MODE;
	/* LOOPRAM MODE */
	} else if (databuf[0] == 2) {
		sih_haptic->hp_func->stop(sih_haptic);
		sih_haptic->ram.action_mode = SIH_RAM_LOOP_MODE;
	} else {
		mutex_unlock(&sih_haptic->lock);
		hp_err("%s:mode parameter error\n", __func__);
		return count;
	}

	if (databuf[1] == 1) {
		sih_haptic->chip_ipara.state = SIH_ACTIVE_MODE;
	} else {
		sih_haptic->hp_func->stop(sih_haptic);
		sih_haptic->chip_ipara.state = SIH_STANDBY_MODE;
		mutex_unlock(&sih_haptic->lock);
		return count;
	}

	if (hrtimer_active(&sih_haptic->timer))
		hrtimer_cancel(&sih_haptic->timer);

	mutex_unlock(&sih_haptic->lock);
	sih_haptic->hp_func->check_detect_state(sih_haptic, SIH_RAM_MODE);
	schedule_work(&sih_haptic->ram.ram_work);

	return count;
}

static ssize_t lra_resistance_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	mutex_lock(&sih_haptic->lock);
	sih_haptic->hp_func->get_lra_resistance(sih_haptic);
	mutex_unlock(&sih_haptic->lock);

	len += snprintf(buf + len, PAGE_SIZE - len, "%d\n",
				(uint32_t)sih_haptic->detect.resistance);
	return len;
}

static ssize_t lra_resistance_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t val = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtoint(buf, 0 , &val);
	if (rc < 0)
		return rc;

	sih_haptic->detect.rl_offset = val;

	return count;
}




static ssize_t trig_para_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len += sih_haptic->hp_func->get_trig_para(sih_haptic, buf);

	return len;
}

static ssize_t trig_para_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t databuf[7] = {0, 0, 0, 0, 0, 0, 0};
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x %x %x %x %x %x",
		&databuf[0], &databuf[1], &databuf[2], &databuf[3],
		&databuf[4], &databuf[5], &databuf[6]) == 7) {
		mutex_lock(&sih_haptic->lock);
		sih_haptic->hp_func->set_trig_para(sih_haptic, databuf);
		mutex_unlock(&sih_haptic->lock);
	}

	return count;
}

static ssize_t low_power_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len += snprintf(buf + len, PAGE_SIZE - len, "low_power_mode = %d\n",
		(uint8_t)sih_haptic->chip_ipara.low_power);

	return len;
}

static ssize_t low_power_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t val = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;

	mutex_lock(&sih_haptic->lock);
	sih_haptic->hp_func->set_low_power_mode(sih_haptic, val);
	mutex_unlock(&sih_haptic->lock);

	return count;
}

static ssize_t activate_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len += snprintf(buf, PAGE_SIZE, "activate = %d\n",
		sih_haptic->chip_ipara.state);

	return len;
}

static ssize_t activate_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t val = 0;
	int rc = 0;
	int rtp_is_going_on = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;

	if (val < 0)
		return count;

	hp_info("%s:value = %d\n", __func__, val);
	if (val != 0 && val != 1) {
		hp_err("%s: error val, return!\n", __func__);
		return count;
	}
rtp_is_going_on = sih_haptic->hp_func->if_chip_is_mode(sih_haptic, SIH_RTP_MODE);
	if (rtp_is_going_on) {
		hp_info("%s: rtp is going\n", __func__);
		return count;
	}
	if (!sih_haptic->ram.ram_init) {
		hp_err("%s:ram init failed\n", __func__);
		return count;
	}
	mutex_lock(&sih_haptic->lock);
	if (hrtimer_active(&sih_haptic->timer))
		hrtimer_cancel(&sih_haptic->timer);
	sih_haptic->chip_ipara.state = val;
	mutex_unlock(&sih_haptic->lock);

#ifdef OPLUS_FEATURE_CHG_BASIC
	if (sih_haptic->chip_ipara.state) {
		hp_info("%s: gain=0x%02x\n", __func__, sih_haptic->chip_ipara.gain);
		mutex_lock(&sih_haptic->lock);
		sih_haptic->hp_func->stop(sih_haptic);
		sih_haptic->chip_ipara.state = SIH_ACTIVE_MODE;
		sih_haptic->ram.action_mode = SIH_RAM_LOOP_MODE;
#ifdef CONFIG_OPLUS_CHARGER_MTK
		if (get_boot_mode() == META_BOOT || get_boot_mode() == FACTORY_BOOT ||
			get_boot_mode() == ADVMETA_BOOT || get_boot_mode() == ATE_FACTORY_BOOT)
#else
		if (get_boot_mode()== MSM_BOOT_MODE__FACTORY || get_boot_mode() == MSM_BOOT_MODE__RF ||
			get_boot_mode() == MSM_BOOT_MODE__WLAN)
#endif
		{
			sih_haptic->hp_func->set_wav_seq(sih_haptic, 0,
							AW8697_WAVEFORM_INDEX_SINE_CYCLE);
		} else {
			sih_haptic->hp_func->set_wav_seq(sih_haptic, 0,
							AW8697_WAVEFORM_INDEX_SINE_CYCLE);
		}
		if (hrtimer_active(&sih_haptic->timer))
			hrtimer_cancel(&sih_haptic->timer);
		mutex_unlock(&sih_haptic->lock);
		queue_work(system_highpri_wq, &sih_haptic->ram.ram_work);
	} else {
		mutex_lock(&sih_haptic->lock);
		sih_haptic->hp_func->stop(sih_haptic);
		mutex_unlock(&sih_haptic->lock);
	}
#endif

	return count;
}

static ssize_t gun_mode_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	return snprintf(buf, PAGE_SIZE, "0x%02x\n", sih_haptic->gun_mode);
}
static ssize_t gun_mode_store(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	int rc = 0;
	unsigned int val = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;

	hp_info("%s: value=%d\n", __func__, val);

	mutex_lock(&sih_haptic->lock);
	sih_haptic->gun_mode = val;
	mutex_unlock(&sih_haptic->lock);
	return count;
}

static ssize_t gun_type_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	return snprintf(buf, PAGE_SIZE, "0x%02x\n", sih_haptic->gun_type);
}

static ssize_t gun_type_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	int rc = 0;
	unsigned int val = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;

	hp_info("%s: value=%d\n", __func__, val);

	mutex_lock(&sih_haptic->lock);
	sih_haptic->gun_type = val;
	mutex_unlock(&sih_haptic->lock);
	return count;
}

static ssize_t bullet_nr_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	return snprintf(buf, PAGE_SIZE, "0x%02x\n", sih_haptic->bullet_nr);
}

static ssize_t bullet_nr_store(struct device *dev,
			       struct device_attribute *attr,
			       const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	int rc = 0;
	unsigned int val = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;
	hp_info("%s: value=%d\n", __func__, val);
	mutex_lock(&sih_haptic->lock);
	sih_haptic->bullet_nr = val;
	mutex_unlock(&sih_haptic->lock);
	return count;
}

static ssize_t audio_delay_show(
	struct device *dev,
	struct device_attribute *attr,
	char *buf)
{
	ssize_t len = 0;
	cdev_t *cdev = dev_get_drvdata(dev);
	sih_haptic_t *sih_haptic = container_of(cdev,
		sih_haptic_t, soft_frame.vib_dev);

	len += snprintf(buf, PAGE_SIZE, "audio_delay = %d\n",
		sih_haptic->rtp.audio_delay);

	return len;
}

static ssize_t audio_delay_store(
	struct device *dev,
	struct device_attribute *attr,
	const char *buf,
	size_t count)
{
	uint32_t val = 0;
	int ret = 0;
	cdev_t *cdev = dev_get_drvdata(dev);
	sih_haptic_t *sih_haptic = container_of(cdev,
		sih_haptic_t, soft_frame.vib_dev);

	ret = kstrtouint(buf, 0, &val);
	if (ret < 0)
		return ret;
	sih_haptic->rtp.audio_delay = val;

	return count;
}

static ssize_t drv_vboost_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len += snprintf(buf, PAGE_SIZE, "drv_vboost = %d\n",
		sih_haptic->chip_ipara.drv_vboost);

	return len;
}

static ssize_t drv_vboost_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t val = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;

	hp_info("%s:value=%d\n", __func__, val);

	mutex_lock(&sih_haptic->lock);
	sih_haptic->chip_ipara.drv_vboost = val;
	if (val < SIH688X_DRV_VBOOST_MIN * SIH688X_DRV_VBOOST_COEFFICIENT) {
		hp_info("%s:drv_vboost is too low,set to 60:%d", __func__, val);
		sih_haptic->chip_ipara.drv_vboost = SIH688X_DRV_VBOOST_MIN
			* SIH688X_DRV_VBOOST_COEFFICIENT;
	} else if (val > SIH688X_DRV_VBOOST_MAX * SIH688X_DRV_VBOOST_COEFFICIENT) {
		hp_info("%s:drv_vboost is too high,set to 110:%d", __func__, val);
		sih_haptic->chip_ipara.drv_vboost = SIH688X_DRV_VBOOST_MAX
			* SIH688X_DRV_VBOOST_COEFFICIENT;
	}
	sih_haptic->hp_func->set_drv_bst_vol(sih_haptic,
		sih_haptic->chip_ipara.drv_vboost);
	mutex_unlock(&sih_haptic->lock);

	return count;
}

static ssize_t burst_rw_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int i = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sih_haptic->chip_reg.rw_type != SIH_BURST_READ) {
		hp_err("%s:not read mode\n", __func__);
		return -ERANGE;
	}
	if (sih_haptic->chip_reg.reg_addr == NULL) {
		hp_err("%s:no reg_addr parameter\n", __func__);
		return -ERANGE;
	}
	for (i = 0; i < sih_haptic->chip_reg.reg_num; i++) {
		len += snprintf(buf + len, PAGE_SIZE, "0x%02x,",
			sih_haptic->chip_reg.reg_addr[i]);
	}
	len += snprintf(buf + len - 1, PAGE_SIZE, "\n");

	return len;
}

static ssize_t burst_rw_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	uint8_t reg_val = 0;
	uint32_t rw_type = 0;
	uint32_t reg_num = 0;
	uint32_t reg_addr = 0;
	int i = 0;
	int rc = 0;
	char tmp[5] = {0};
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x %x", &rw_type, &reg_num, &reg_addr) == 3) {
		if (!reg_num) {
			hp_err("%s:param error\n", __func__);
			return -ERANGE;
		}
		sih_haptic->chip_reg.rw_type = rw_type;
		sih_haptic->chip_reg.reg_num = reg_num;
		if (sih_haptic->chip_reg.reg_addr != NULL)
			kfree(sih_haptic->chip_reg.reg_addr);

		sih_haptic->chip_reg.reg_addr = kmalloc(reg_num, GFP_KERNEL);
		if (rw_type == SIH_BURST_WRITE) {
			if ((reg_num * 5) != (strlen(buf) - 15)) {
				hp_err("%s:param err, reg_num = %d, strlen = %d\n",
					__func__, reg_num, (int)(strlen(buf) - 15));
				return -ERANGE;
			}
			for (i = 0; i < reg_num; i++) {
				memcpy(tmp, &buf[15 + i * 5], 4);
				tmp[4] = '\0';
				rc = kstrtou8(tmp, 0, &reg_val);
				if (rc < 0) {
					hp_err("%s:reg_val err\n", __func__);
					return -ERANGE;
				}
				sih_haptic->chip_reg.reg_addr[i] = reg_val;
			}
			for (i = 0; i < reg_num; i++) {
				haptic_regmap_write(sih_haptic->regmapp.regmapping,
					(uint8_t)reg_addr + i, SIH_I2C_OPERA_BYTE_ONE,
					&sih_haptic->chip_reg.reg_addr[i]);
			}
		} else if (rw_type == SIH_BURST_READ) {
			for (i = 0; i < reg_num; i++) {
				haptic_regmap_read(sih_haptic->regmapp.regmapping,
					(uint8_t)reg_addr + i, SIH_I2C_OPERA_BYTE_ONE,
					&sih_haptic->chip_reg.reg_addr[i]);
			}
		}
	} else {
		hp_err("%s:param error rw_type err\n", __func__);
		return -ERANGE;
	}

	return count;
}

static ssize_t detect_vbat_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	mutex_lock(&sih_haptic->lock);
	sih_haptic->hp_func->get_vbat(sih_haptic);
	len += snprintf(buf + len, PAGE_SIZE - len, "detect_vbat = %d\n",
		sih_haptic->detect.vbat);
	mutex_unlock(&sih_haptic->lock);

	return len;
}

static ssize_t rtp_file_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len += snprintf(buf + len, PAGE_SIZE - len, "rtp_cnt = %d\n",
		sih_haptic->rtp.rtp_cnt);

	return len;
}

static ssize_t rtp_file_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t rtp_num_max = sizeof(sih_rtp_name) / SIH_RTP_NAME_MAX;
	char databuf[SIH_RTP_NAME_MAX] = {0};
	int buf_len = 0;
	int i = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%s %d", databuf, &buf_len) != 2) {
		hp_err("%s:input parameter error\n", __func__);
		return count;
	}

	if (strlen(databuf) != buf_len) {
		hp_err("%s:input parameter not match\n", __func__);
		return count;
	}

	mutex_lock(&sih_haptic->lock);

	sih_haptic->hp_func->stop(sih_haptic);
	sih_haptic->hp_func->set_rtp_aei(sih_haptic, false);
	sih_haptic->hp_func->clear_interrupt_state(sih_haptic);

	for (i = 0; i < rtp_num_max; i++) {
		if (strncmp(&(sih_rtp_name[i][0]), databuf, buf_len) == 0) {
			sih_haptic->rtp.rtp_file_num = i;
			sih_haptic->chip_ipara.state = SIH_ACTIVE_MODE;
			schedule_work(&sih_haptic->rtp.rtp_work);
			mutex_unlock(&sih_haptic->lock);
			break;
		}
	}

	if (i == rtp_num_max) {
		hp_err("%s:file name %s or length %d err\n",
			__func__, databuf, buf_len);
		mutex_unlock(&sih_haptic->lock);
		return -ERANGE;
	}

	mutex_unlock(&sih_haptic->lock);

	return count;
}

static ssize_t main_loop_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	sih_haptic->hp_func->get_wav_main_loop(sih_haptic);

	len += snprintf(buf + len, PAGE_SIZE - len, "main loop:%d\n",
		sih_haptic->ram.main_loop);

	return len;
}

static ssize_t main_loop_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint8_t val = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtou8(buf, 0, &val);
	if (rc < 0)
		return rc;

	if (val > SIH_RAM_MAIN_LOOP_MAX_TIME) {
		hp_err("%s:input value out of range!\n", __func__);
		return count;
	}

	hp_info("%s:main_loop = %d\n", __func__, val);

	mutex_lock(&sih_haptic->lock);
	sih_haptic->ram.main_loop = val;
	sih_haptic->hp_func->set_wav_main_loop(sih_haptic, val);
	mutex_unlock(&sih_haptic->lock);

	return count;
}

static ssize_t seq_gain_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	ssize_t len = 0;
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;
	len = sih_haptic->hp_func->get_ram_seq_gain(sih_haptic, buf);

	return len;
}

static ssize_t seq_gain_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	unsigned int databuf[2] = {0, 0};
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x", &databuf[0], &databuf[1]) == 2) {
		if (databuf[0] >= SIH_HAPTIC_SEQUENCER_SIZE) {
			hp_err("%s:input value out of range!\n", __func__);
			return count;
		}

		if (databuf[1] > SIH_HAPTIC_GAIN_LIMIT) {
			hp_err("%s:gain out of limit!\n", __func__);
			databuf[1] = SIH_HAPTIC_GAIN_LIMIT;
		}

		mutex_lock(&sih_haptic->lock);
		sih_haptic->ram.gain[(uint8_t)databuf[0]] = (uint8_t)databuf[1];
		sih_haptic->hp_func->set_ram_seq_gain(sih_haptic,
			(uint8_t)databuf[0], sih_haptic->ram.gain[(uint8_t)databuf[0]]);
		mutex_unlock(&sih_haptic->lock);
	}

	return count;
}

static ssize_t pwm_rate_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	ssize_t len = 0;
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len += sih_haptic->hp_func->get_pwm_rate(sih_haptic, buf);

	return len;
}

static ssize_t pwm_rate_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t databuf[2] = {0, 0};
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x", &databuf[0], &databuf[1]) != 2) {
		hp_err("%s:input parameter error\n", __func__);
		return count;
	}
	mutex_lock(&sih_haptic->lock);
	sih_haptic->hp_func->set_pwm_rate(sih_haptic,
		(uint8_t)databuf[0], (uint8_t)databuf[1]);
	mutex_unlock(&sih_haptic->lock);

	return count;
}

static ssize_t brake_ctrl_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len += sih_haptic->hp_func->get_brk_state(sih_haptic, buf);

	return len;
}

static ssize_t brake_ctrl_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	unsigned int databuf[2] = {0, 0};
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x\n", &databuf[0], &databuf[1]) != 2) {
		hp_err("%s:input parameter error\n", __func__);
		return count;
	}

	mutex_lock(&sih_haptic->lock);
	sih_haptic->hp_func->set_brk_state(sih_haptic, (uint8_t)databuf[0],
		(uint8_t)databuf[1]);
	mutex_unlock(&sih_haptic->lock);

	return count;
}

static ssize_t detect_state_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len += sih_haptic->hp_func->get_detect_state(sih_haptic, buf);

	return len;
}

static ssize_t detect_state_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t databuf[2] = {0, 0};
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	if (sscanf(buf, "%x %x\n", &databuf[0], &databuf[1]) != 2) {
		hp_err("%s:input parameter error\n", __func__);
		return count;
	}

	mutex_lock(&sih_haptic->lock);
	sih_haptic->hp_func->set_detect_state(sih_haptic, databuf[0], databuf[1]);
	mutex_unlock(&sih_haptic->lock);

	return count;
}

static ssize_t tracking_f0_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len += snprintf(buf, PAGE_SIZE, "%d\n",
		sih_haptic->detect.tracking_f0);

	return len;
}

static ssize_t tracking_f0_store(struct device *dev,
	struct device_attribute *attr, const char *buf,	size_t count)
{
	cdev_t *cdev = dev_get_drvdata(dev);
	sih_haptic_t *sih_haptic = container_of(cdev,
		sih_haptic_t, soft_frame.vib_dev);
	uint32_t val = 0;
    int rc = 0;

    rc = kstrtouint(buf, 0, &val);
    if (rc < 0) {
        return rc;
    }

	sih_haptic->detect.tracking_f0 = val;
	if (DEVICE_ID_0815 == sih_haptic->device_id || DEVICE_ID_0809 == sih_haptic->device_id) {
		if (sih_haptic->detect.tracking_f0 < F0_VAL_MIN_0815
				|| sih_haptic->detect.tracking_f0 > F0_VAL_MAX_0815) {
			sih_haptic->detect.tracking_f0 = 1700;
		}
	} else if (DEVICE_ID_1419 == sih_haptic->device_id) {
		if (sih_haptic->detect.tracking_f0 < F0_VAL_MIN_1419
				|| sih_haptic->detect.tracking_f0 > F0_VAL_MAX_1419) {
			sih_haptic->detect.tracking_f0 = 2050;
		}
	}
	hp_err("%s:f0 = %d\n", __func__, val);
	schedule_work(&sih_haptic->ram.ram_update_work);

	return count;
}

static ssize_t f0_data_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	int len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;
	len += snprintf(buf + len, PAGE_SIZE - len, "%d\n",
			sih_haptic->detect.f0_cali_data);

	return len;
}

static ssize_t f0_data_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = dev_get_drvdata(dev);
	sih_haptic_t *sih_haptic = container_of(cdev,
		sih_haptic_t, soft_frame.vib_dev);
	uint32_t val = 0;
    int rc = 0;

    rc = kstrtouint(buf, 0, &val);
    if (rc < 0) {
        return rc;
    }
	mutex_lock(&sih_haptic->lock);
	sih_haptic->detect.f0_cali_data = val;
	mutex_unlock(&sih_haptic->lock);
	return count;
}

static ssize_t osc_data_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	int rc = 0;
	int len = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;
	len += snprintf(buf + len, PAGE_SIZE - len, "%d\n",
			sih_haptic->osc_para.osc_data);

	return len;
}

static ssize_t osc_data_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = dev_get_drvdata(dev);
	sih_haptic_t *sih_haptic = container_of(cdev,
		sih_haptic_t, soft_frame.vib_dev);
	uint32_t val = 0;
    int rc = 0;

    rc = kstrtouint(buf, 0, &val);
    if (rc < 0) {
        return rc;
    }
	mutex_lock(&sih_haptic->lock);
	sih_haptic->osc_para.osc_data = val;
	mutex_unlock(&sih_haptic->lock);
	return count;
}

static ssize_t index_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	sih_haptic->hp_func->get_wav_seq(sih_haptic, 1);
	sih_haptic->ram.index = sih_haptic->ram.seq[0];
	len += snprintf(buf, PAGE_SIZE, "index = %d\n", sih_haptic->ram.index);

	return len;
}

static ssize_t index_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t val = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;

	if (val > sih_haptic->ram.wave_num) {
		hp_err("%s:input value out of range!\n", __func__);
		return count;
	}

	hp_info("%s:value = %d\n", __func__, val);

	mutex_lock(&sih_haptic->lock);
	sih_haptic->ram.index = val;
	sih_haptic->hp_func->set_repeat_seq(sih_haptic, sih_haptic->ram.index);
	mutex_unlock(&sih_haptic->lock);

	return count;
}

static ssize_t cali_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	uint32_t val = 0;
	uint8_t i;
	int rc = 0;
	uint32_t sih_f0_min_threshold = 0;
	uint32_t sih_f0_max_threshold = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;

	if (DEVICE_ID_0815 == sih_haptic->device_id || DEVICE_ID_0809 == sih_haptic->device_id) {
		sih_f0_min_threshold = SIH_F0_MIN_THRESHOLD;
		sih_f0_max_threshold = SIH_F0_MAX_THRESHOLD;
	} else if (DEVICE_ID_1419 == sih_haptic->device_id) {
		sih_f0_min_threshold = SIH_F0_MIN_THRESHOLD_1419;
		sih_f0_max_threshold = SIH_F0_MAX_THRESHOLD_1419;
	} else {
		sih_f0_min_threshold = SIH_F0_MIN_THRESHOLD;
		sih_f0_max_threshold = SIH_F0_MAX_THRESHOLD;
	}
	hp_info("%s:value = %d, f0_min = %d, f0_max = %d\n", __func__,
		val, sih_f0_min_threshold, sih_f0_max_threshold);

	if (val == 1) {
		mutex_lock(&sih_haptic->lock);
		for (i = 0; i < SIH_F0_DETECT_TRY; i++) {
			sih_haptic->hp_func->get_tracking_f0(sih_haptic);
			if (sih_haptic->detect.tracking_f0 <= sih_f0_min_threshold &&
				sih_haptic->detect.tracking_f0 >= sih_f0_max_threshold) {
				break;
			}
			msleep(200);
		}
		sih_haptic->hp_func->upload_f0(sih_haptic, SIH_F0_CALI_LRA);
#ifdef CONFIG_HAPTIC_FEEDBACK_MODULE
		if (sih_haptic->detect.f0_cali_data == 0)
			(void)oplus_haptic_track_fre_cail(HAPTIC_F0_CALI_TRACK,
							sih_haptic->detect.tracking_f0,
							-ERANGE, "f0 out of range");
#endif
		mutex_unlock(&sih_haptic->lock);
	}
	return count;
}
static ssize_t f0_save_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	ssize_t len = 0;
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len += snprintf(buf + len, PAGE_SIZE - len, "f0_data = %d\n",
		sih_haptic->detect.tracking_f0);

	return len;
}

static ssize_t f0_save_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	uint32_t val = 0;
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;
	sih_haptic->detect.tracking_f0 = val;

	if (DEVICE_ID_0815 == sih_haptic->device_id || DEVICE_ID_0809 == sih_haptic->device_id) {
		if (sih_haptic->detect.tracking_f0 < F0_VAL_MIN_0815
				|| sih_haptic->detect.tracking_f0 > F0_VAL_MAX_0815) {
			sih_haptic->detect.tracking_f0 = 1700;
		}
	} else if (DEVICE_ID_1419 == sih_haptic->device_id) {
		if (sih_haptic->detect.tracking_f0 < F0_VAL_MIN_1419
				|| sih_haptic->detect.tracking_f0 > F0_VAL_MAX_1419) {
			sih_haptic->detect.tracking_f0 = 2050;
		}
	}
	hp_err("%s:f0 = %d\n", __func__, val);
	return count;
}

static ssize_t detect_f0_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = NULL;
	sih_haptic_t *sih_haptic = NULL;
	ssize_t len = 0;
	int rc = 0;

	rc = pointer_prehandle(dev, buf, &cdev, &sih_haptic);
	if (rc < 0)
		return rc;

	len += snprintf(buf + len, PAGE_SIZE - len, "detect_f0 = %d\n",
		sih_haptic->detect.detect_f0);

	return len;
}

static ssize_t oplus_brightness_show(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	cdev_t *cdev = dev_get_drvdata(dev);
	sih_haptic_t *sih_haptic = container_of(cdev,
			sih_haptic_t, soft_frame.vib_dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", sih_haptic->amplitude);
}

	static ssize_t oplus_brightness_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
	{
	cdev_t *cdev = dev_get_drvdata(dev);
	sih_haptic_t *sih_haptic = container_of(cdev,
		sih_haptic_t, soft_frame.vib_dev);
	uint32_t val = 0;
	int rc = 0;

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;

	hp_err("%s:val = %d\n", __func__, val);
	if (!sih_haptic->ram.ram_init) {
		hp_err("%s:ram init error,not allow to play!\n", __func__);
		return count;
	}

	sih_haptic->amplitude = val;
	mutex_lock(&sih_haptic->lock);
	if (sih_haptic->amplitude > 0) {
		sih_haptic->hp_func->stop(sih_haptic);
		sih_haptic->ram.action_mode = SIH_RAM_MODE;
		sih_haptic->chip_ipara.state = SIH_ACTIVE_MODE;

		sih_ram_play(sih_haptic, sih_haptic->ram.action_mode);
	}
	mutex_unlock(&sih_haptic->lock);
	return count;
}

static ssize_t haptic_ram_test_show(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	cdev_t *cdev = dev_get_drvdata(dev);
	sih_haptic_t *sih_haptic = container_of(cdev,
			sih_haptic_t, soft_frame.vib_dev);
	ssize_t len = 0;
	unsigned int ram_test_result = 0;

	if (sih_haptic->ram_test_flag_0 != 0 ||
	    sih_haptic->ram_test_flag_1 != 0) {
		ram_test_result = 1; /* failed */
		len += snprintf(buf+len, PAGE_SIZE-len, "%d\n", ram_test_result);
	} else {
		ram_test_result = 0; /* pass */
		len += snprintf(buf+len, PAGE_SIZE-len, "%d\n", ram_test_result);
	}
	return len;
}

static ssize_t haptic_ram_test_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	cdev_t *cdev = dev_get_drvdata(dev);
	sih_haptic_t *sih_haptic = container_of(cdev,
			sih_haptic_t, soft_frame.vib_dev);
	struct haptic_container *sh_ramtest;
	int i, j = 0;
	int rc = 0;
	unsigned int val = 0;
	unsigned int start_addr;
	unsigned int tmp_len, retries;
	char *pbuf = NULL;

	hp_err("%s enter\n", __func__);

	rc = kstrtouint(buf, 0, &val);
	if (rc < 0)
		return rc;
	start_addr = 0;
	sih_haptic->ram_test_flag_0 = 0;
	sih_haptic->ram_test_flag_1 = 0;
	tmp_len = 1024 ;  /* 1K */
	retries = 8;  /* tmp_len * retries = 8 * 1024 */
	sh_ramtest = kzalloc(tmp_len * sizeof(char) + sizeof(int), GFP_KERNEL);
	if (!sh_ramtest) {
		hp_err("%s: error allocating memory\n", __func__);
		return count;
	}
	pbuf = kzalloc(tmp_len * sizeof(char), GFP_KERNEL);
	if (!pbuf) {
		hp_err("%s: Error allocating memory\n", __func__);
		kfree(sh_ramtest);
		return count;
	}
	sh_ramtest->len = tmp_len;

	if (val == 1) {
		mutex_lock(&sih_haptic->lock);
		/* RAMINIT Enable */
		sih_haptic->hp_func->ram_init(sih_haptic, true);
		for (j = 0; j < retries; j++) {
			/*test 1-----------start*/
			memset(sh_ramtest->data, 0xff, sh_ramtest->len);
			memset(pbuf, 0x00, sh_ramtest->len);
			/* write ram 1 test */
			sih_haptic->hp_func->si_set_ram_addr(sih_haptic, start_addr);
			sih_haptic->hp_func->set_ram_data(sih_haptic,
						      sh_ramtest->data,
						      sh_ramtest->len);

			/* read ram 1 test */
			sih_haptic->hp_func->si_set_ram_addr(sih_haptic, start_addr);
			sih_haptic->hp_func->si_get_ram_data(sih_haptic, pbuf,
						      sh_ramtest->len);

			for (i = 0; i < sh_ramtest->len; i++) {
				if (pbuf[i] != 0xff)
					sih_haptic->ram_test_flag_1++;
			}
			 /*test 1------------end*/

			/*test 0----------start*/
			memset(sh_ramtest->data, 0x00, sh_ramtest->len);
			memset(pbuf, 0xff, sh_ramtest->len);

			/* write ram 0 test */
			sih_haptic->hp_func->si_set_ram_addr(sih_haptic, start_addr);
			sih_haptic->hp_func->set_ram_data(sih_haptic,
						      sh_ramtest->data,
						      sh_ramtest->len);
			/* read ram 0 test */
			sih_haptic->hp_func->si_set_ram_addr(sih_haptic, start_addr);
			sih_haptic->hp_func->si_get_ram_data(sih_haptic, pbuf,
						      sh_ramtest->len);
			for (i = 0; i < sh_ramtest->len; i++) {
				if (pbuf[i] != 0)
					 sih_haptic->ram_test_flag_0++;
			}
			/*test 0 end*/
			start_addr += tmp_len;
		}
		/* RAMINIT Disable */
		// sih_haptic->hp_func->ram_init(sih_haptic, false);
		schedule_work(&sih_haptic->ram.ram_update_work);
		mutex_unlock(&sih_haptic->lock);
	}
	kfree(sh_ramtest);
	kfree(pbuf);
	pbuf = NULL;
	hp_err("%s exit\n", __func__);
	return count;
}

static ssize_t rtp_going_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	cdev_t *cdev = dev_get_drvdata(dev);
	sih_haptic_t *sih_haptic = container_of(cdev,
			sih_haptic_t, soft_frame.vib_dev);
	ssize_t len = 0;
	int val = -1;

	val = sih_haptic->hp_func->if_chip_is_mode(sih_haptic, SIH_RTP_MODE);
	len += snprintf(buf+len, PAGE_SIZE-len, "%d\n", val);
	return len;
}

static ssize_t rtp_going_store(struct device *dev,
			       struct device_attribute *attr,
			       const char *buf, size_t count)
{
	return count;
}
static DEVICE_ATTR(cali, S_IWUSR | S_IRUGO,
	tracking_f0_show, cali_store);
static DEVICE_ATTR(f0, S_IWUSR | S_IRUGO,
	tracking_f0_show, tracking_f0_store);
static DEVICE_ATTR(seq, S_IWUSR | S_IRUGO,
	seq_show, seq_store);
static DEVICE_ATTR(reg, S_IWUSR | S_IRUGO,
	reg_show, reg_store);
static DEVICE_ATTR(gain, S_IWUSR | S_IRUGO,
	gain_show, gain_store);
static DEVICE_ATTR(state, S_IWUSR | S_IWGRP | S_IRUGO,
	state_show, state_store);
static DEVICE_ATTR(loop, S_IWUSR | S_IRUGO,
	loop_show, loop_store);
static DEVICE_ATTR(rtp, S_IWUSR | S_IRUGO,
	rtp_show, rtp_store);
static DEVICE_ATTR(cont_go, S_IWUSR | S_IRUGO,
	NULL, cont_go_store);
static DEVICE_ATTR(cont_seq0, S_IWUSR | S_IRUGO,
	cont_seq0_show, cont_seq0_store);
static DEVICE_ATTR(cont_seq1, S_IWUSR | S_IRUGO,
	cont_seq1_show, cont_seq1_store);
static DEVICE_ATTR(cont_seq2, S_IWUSR | S_IRUGO,
	cont_seq2_show, cont_seq2_store);
static DEVICE_ATTR(cont_asmooth, S_IWUSR | S_IRUGO,
	cont_asmooth_show, cont_asmooth_store);
static DEVICE_ATTR(cont_th_len, S_IWUSR | S_IRUGO,
	cont_th_len_show, cont_th_len_store);
static DEVICE_ATTR(cont_th_num, S_IWUSR | S_IRUGO,
	cont_th_num_show, cont_th_num_store);
static DEVICE_ATTR(cont_ampli, S_IWUSR | S_IRUGO,
	cont_ampli_show, cont_ampli_store);
static DEVICE_ATTR(ram, S_IWUSR | S_IRUGO,
	NULL, ram_store);
static DEVICE_ATTR(ram_num, S_IWUSR | S_IRUGO,
	ram_num_show, NULL);
static DEVICE_ATTR(detect_vbat, S_IWUSR | S_IRUGO,
	detect_vbat_show, NULL);
static DEVICE_ATTR(tracking_f0, S_IWUSR | S_IRUGO,
	tracking_f0_show, NULL);
static DEVICE_ATTR(detect_f0, S_IWUSR | S_IRUGO,
	detect_f0_show, NULL);
static DEVICE_ATTR(duration, S_IWUSR | S_IWGRP | S_IRUGO,
	duration_show, duration_store);
static DEVICE_ATTR(oplus_duration, S_IWUSR | S_IWGRP | S_IRUGO,
	duration_show, duration_store);
static DEVICE_ATTR(osc_cali, S_IWUSR | S_IRUGO,
	osc_cali_show, osc_cali_store);
static DEVICE_ATTR(auto_pvdd, S_IWUSR | S_IRUGO,
	auto_pvdd_show, auto_pvdd_store);
static DEVICE_ATTR(ram_update, S_IWUSR | S_IRUGO,
	ram_update_show, ram_update_store);
static DEVICE_ATTR(ram_vbat_comp, S_IWUSR | S_IRUGO,
	ram_vbat_comp_show, ram_vbat_comp_store);
static DEVICE_ATTR(lra_resistance, S_IWUSR | S_IRUGO,
	lra_resistance_show, lra_resistance_store);

static DEVICE_ATTR(trig_para, S_IWUSR | S_IRUGO,
	trig_para_show, trig_para_store);
static DEVICE_ATTR(low_power, S_IWUSR | S_IRUGO,
	low_power_show, low_power_store);
static DEVICE_ATTR(activate, S_IWUSR | S_IWGRP | S_IRUGO,
	activate_show, activate_store);
static DEVICE_ATTR(oplus_activate, S_IWUSR | S_IWGRP | S_IRUGO,
	activate_show, activate_store);
static DEVICE_ATTR(drv_vboost, S_IWUSR | S_IRUGO,
	drv_vboost_show, drv_vboost_store);
static DEVICE_ATTR(burst_rw, S_IWUSR | S_IRUGO,
	burst_rw_show, burst_rw_store);
static DEVICE_ATTR(rtp_file, S_IWUSR | S_IRUGO,
	rtp_file_show, rtp_file_store);
static DEVICE_ATTR(main_loop, S_IWUSR | S_IRUGO,
	main_loop_show, main_loop_store);
static DEVICE_ATTR(seq_gain, S_IWUSR | S_IRUGO,
	seq_gain_show, seq_gain_store);
static DEVICE_ATTR(pwm_rate, S_IWUSR | S_IRUGO,
	pwm_rate_show, pwm_rate_store);
static DEVICE_ATTR(brake_ctrl, S_IWUSR | S_IRUGO,
	brake_ctrl_show, brake_ctrl_store);
static DEVICE_ATTR(detect_state, S_IWUSR | S_IRUGO,
	detect_state_show, detect_state_store);
static DEVICE_ATTR(audio_delay, S_IWUSR | S_IRUGO,
	audio_delay_show, audio_delay_store);
static DEVICE_ATTR(osc_data, S_IWUSR | S_IRUGO,
	osc_data_show, osc_data_store);
static DEVICE_ATTR(f0_data, S_IWUSR | S_IRUGO,
	f0_data_show, f0_data_store);
static DEVICE_ATTR(index, S_IWUSR | S_IRUGO,
	index_show, index_store);
static DEVICE_ATTR(f0_save, S_IWUSR | S_IRUGO,
	f0_save_show, f0_save_store);

#ifdef OPLUS_FEATURE_CHG_BASIC
static DEVICE_ATTR(oplus_brightness, S_IWUSR | S_IWGRP | S_IRUGO,
	oplus_brightness_show, oplus_brightness_store);
static DEVICE_ATTR(oplus_state, S_IWUSR | S_IWGRP | S_IRUGO, state_show, state_store);
static DEVICE_ATTR(motor_old, S_IWUSR | S_IRUGO, motor_old_test_show, motor_old_test_store);
static DEVICE_ATTR(waveform_index, S_IWUSR | S_IRUGO, waveform_index_show, waveform_index_store);
static DEVICE_ATTR(device_id, S_IWUSR | S_IRUGO, device_id_show, device_id_store);
static DEVICE_ATTR(vmax, S_IWUSR | S_IRUGO,	vmax_show, vmax_store);
static DEVICE_ATTR(livetap_support, S_IWUSR | S_IRUGO, livetap_support_show, livetap_support_store);
static DEVICE_ATTR(ram_test, S_IWUSR | S_IWGRP | S_IRUGO, haptic_ram_test_show, haptic_ram_test_store);
static DEVICE_ATTR(rtp_going, S_IWUSR | S_IRUGO, rtp_going_show, rtp_going_store);
static DEVICE_ATTR(bullet_nr, S_IWUSR | S_IRUGO, bullet_nr_show, bullet_nr_store);
static DEVICE_ATTR(gun_mode, S_IWUSR | S_IRUGO, gun_mode_show, gun_mode_store);
static DEVICE_ATTR(gun_type, S_IWUSR | S_IRUGO, gun_type_show, gun_type_store);

#endif

static struct attribute *sih_vibra_attribute[] = {
		&dev_attr_cali.attr,
		&dev_attr_f0.attr,
		&dev_attr_seq.attr,
		&dev_attr_reg.attr,
		&dev_attr_gain.attr,
		&dev_attr_state.attr,
		&dev_attr_loop.attr,
		&dev_attr_rtp.attr,
		&dev_attr_cont_go.attr,
		&dev_attr_cont_seq0.attr,
		&dev_attr_cont_seq1.attr,
		&dev_attr_cont_seq2.attr,
		&dev_attr_cont_asmooth.attr,
		&dev_attr_cont_th_len.attr,
		&dev_attr_cont_th_num.attr,
		&dev_attr_cont_ampli.attr,
		&dev_attr_ram.attr,
		&dev_attr_ram_num.attr,
		&dev_attr_duration.attr,
		&dev_attr_osc_cali.attr,
		&dev_attr_auto_pvdd.attr,
		&dev_attr_ram_update.attr,
		&dev_attr_ram_vbat_comp.attr,
		&dev_attr_lra_resistance.attr,
		&dev_attr_f0_save.attr,
		&dev_attr_trig_para.attr,
		&dev_attr_low_power.attr,
		&dev_attr_activate.attr,
		&dev_attr_drv_vboost.attr,
		&dev_attr_burst_rw.attr,
		&dev_attr_detect_vbat.attr,
		&dev_attr_rtp_file.attr,
		&dev_attr_main_loop.attr,
		&dev_attr_seq_gain.attr,
		&dev_attr_pwm_rate.attr,
		&dev_attr_brake_ctrl.attr,
		&dev_attr_detect_state.attr,
		&dev_attr_tracking_f0.attr,
		&dev_attr_detect_f0.attr,
		&dev_attr_audio_delay.attr,
		&dev_attr_osc_data.attr,
		&dev_attr_f0_data.attr,
		&dev_attr_index.attr,
#ifdef OPLUS_FEATURE_CHG_BASIC
		&dev_attr_oplus_brightness.attr,
		&dev_attr_oplus_duration.attr,
		&dev_attr_oplus_activate.attr,
		&dev_attr_oplus_state.attr,
		&dev_attr_vmax.attr,
		&dev_attr_motor_old.attr,
		&dev_attr_waveform_index.attr,
		&dev_attr_device_id.attr,
		&dev_attr_livetap_support.attr,
		&dev_attr_ram_test.attr,
		&dev_attr_rtp_going.attr,
		&dev_attr_gun_type.attr,
		&dev_attr_gun_mode.attr,
		&dev_attr_bullet_nr.attr,
#endif
		NULL,
};

static struct attribute_group sih_vibra_attribute_group = {
		.attrs = sih_vibra_attribute,
};

static enum led_brightness sih_vibra_brightness_get(
	struct led_classdev *cdev)
{
	return LED_OFF;
}

static void sih_vibra_brightness_set(struct led_classdev *cdev,
	enum led_brightness level)
{
	sih_haptic_t *sih_haptic = container_of(cdev,
		sih_haptic_t, soft_frame.vib_dev);

	if (!sih_haptic->ram.ram_init) {
		hp_err("%s:ram init error\n", __func__);
		return;
	}
	hp_info("%s:vibra brightness set\n", __func__);
	mutex_lock(&sih_haptic->lock);
	if (level > 0) {
		sih_haptic->hp_func->stop(sih_haptic);
		sih_haptic->ram.action_mode = SIH_RAM_MODE;
		sih_haptic->chip_ipara.state = SIH_ACTIVE_MODE;

		sih_ram_play(sih_haptic, sih_haptic->ram.action_mode);
	}
	mutex_unlock(&sih_haptic->lock);
}

static int sih_add_node(struct device *dev, sih_haptic_t *sih_haptic)
{
	int ret = -1;

	sih_haptic->soft_frame.vib_dev.name = SIH_HAPTIC_NAME;
	sih_haptic->soft_frame.vib_dev.brightness_get = sih_vibra_brightness_get;
	sih_haptic->soft_frame.vib_dev.brightness_set = sih_vibra_brightness_set;

	/* led sub system register */
	ret = devm_led_classdev_register(sih_haptic->dev,
		&sih_haptic->soft_frame.vib_dev);
	if (ret < 0) {
		hp_err("%s:dev register failed = %d\n", __func__, ret);
		return ret;
	}

	/* vibrator sysfs node create */
	ret = sysfs_create_group(&sih_haptic->soft_frame.vib_dev.dev->kobj,
		&sih_vibra_attribute_group);
	if (ret < 0) {
		hp_err("%s:sysfs node create failed = %d\n ", __func__, ret);
		return ret;
	}

	ret = sih_add_misc_dev();
	if (ret) {
		hp_err("%s:misc fail:%d\n", __func__, ret);
		return ret;
	}
	return 0;
}

static enum hrtimer_restart haptic_timer_func(struct hrtimer *timer)
{
	sih_haptic_t *sih_haptic = container_of(timer, sih_haptic_t, timer);

	hp_info("%s:enter!\n", __func__);
	sih_chip_state_recovery(sih_haptic);
	queue_work(system_highpri_wq, &sih_haptic->ram.ram_work);
	return HRTIMER_NORESTART;
}

static void ram_work_func(struct work_struct *work)
{
	sih_haptic_t *sih_haptic = container_of(work, sih_haptic_t, ram.ram_work);

	hp_info("%s:enter!\n", __func__);
	mutex_lock(&sih_haptic->lock);
	/* Enter standby mode */
	sih_haptic->hp_func->stop(sih_haptic);
	if (sih_haptic->chip_ipara.state == SIH_ACTIVE_MODE) {
		switch (sih_haptic->ram.action_mode) {
		case SIH_RAM_MODE:
			sih_haptic->hp_func->set_boost_mode(sih_haptic, true);
			sih_ram_play(sih_haptic, SIH_RAM_MODE);
			break;
		case SIH_RAM_LOOP_MODE:
			if ((DEVICE_ID_1419 == sih_haptic->device_id) || (sih_haptic->device_id == DEVICE_ID_0809)){
				sih_haptic->hp_func->set_boost_mode(sih_haptic, true);
			} else {
				sih_haptic->hp_func->set_boost_mode(sih_haptic, false);
				sih_haptic->hp_func->vbat_comp(sih_haptic);
			}
			sih_ram_play(sih_haptic, SIH_RAM_LOOP_MODE);
			/* run ms timer */
			hrtimer_start(&sih_haptic->timer,
				ktime_set(sih_haptic->chip_ipara.duration / 1000,
				(sih_haptic->chip_ipara.duration % 1000) * 1000000),
				HRTIMER_MODE_REL);
			break;
		default:
			hp_err("%s:err sta = %d\n", __func__, sih_haptic->chip_ipara.state);
			break;
		}
	}
	mutex_unlock(&sih_haptic->lock);
}

static const char* get_rtp_name(uint32_t id, uint32_t f0) {
	const char* wave_name = NULL;
	const char* f0_suffix = NULL;
	char* rtp_name = NULL;
	size_t len = 0;
	int i = 0;

	hp_info("%s: enter. wave_id = %d, f0 = %d.\n", __func__, id, f0);
	for (i = 0; i < sizeof(f0_suffix_map) / sizeof(f0_suffix_map[0]); i++) {
		if (f0 < f0_suffix_map[i].f0_thre) {
			f0_suffix = f0_suffix_map[i].suffix;
			break;
		}
	}
	if (!f0_suffix) {
		hp_err("%s: f0 is %d, not found suffix.\n", __func__, f0);
		return NULL;
	}
    if (id >= 0 && id < NUM_WAVEFORMS)
        wave_name = rtp_wave_map[id];
    else
        hp_err("%s: id is %d, out of range.\n", __func__, id);
	if (!wave_name) {
		hp_err("%s: id is %d, not found wave name.\n", __func__, id);
		return NULL;
	}
	len = strlen(wave_name) + strlen(f0_suffix) + 1;
	rtp_name = (char*) vmalloc(len);
	if (!rtp_name) {
		hp_err("%s: vmalloc failed.\n", __func__);
#ifdef CONFIG_HAPTIC_FEEDBACK_MODULE
		(void)oplus_haptic_track_mem_alloc_err(HAPTIC_MEM_ALLOC_TRACK,
			len, __func__);
#endif
		return NULL;
	} else {
		snprintf(rtp_name, len, "%s%s", wave_name, f0_suffix);
	}
	return rtp_name;
}
#ifdef OPLUS_FEATURE_CHG_BASIC
//0809 & 08015
#define OPLUS_162HZ_F0 1640
#define OPLUS_166HZ_F0 1680
#define OPLUS_170HZ_F0 1720
#define OPLUS_174HZ_F0 1760
#define OPLUS_178HZ_F0 1800

//1419
#define OPLUS_197HZ_F0 1980
#define OPLUS_201HZ_F0 2020
#define OPLUS_205HZ_F0 2060
#define OPLUS_209HZ_F0 2100
#define OPLUS_213HZ_F0 2150


static uint8_t *custom_0809_rtp_key_file(struct sih_haptic *sih_haptic, uint32_t *data_len)
{
	switch(sih_haptic->rtp.rtp_file_num) {
	case SG_INPUT_DOWN_HIGH:
		if (sih_haptic->detect.tracking_f0 < OPLUS_162HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_302_162Hz);
			return aw_haptic_0809_rtp_302_162Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_166HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_302_166Hz);
			return aw_haptic_0809_rtp_302_166Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_170HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_302_170Hz);
			return aw_haptic_0809_rtp_302_170Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_174HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_302_174Hz);
			return aw_haptic_0809_rtp_302_174Hz;
		} else {
			*data_len = sizeof(aw_haptic_0809_rtp_302_178Hz);
			return aw_haptic_0809_rtp_302_178Hz;
		}
		break;
	case SG_INPUT_UP_HIGH:
		if (sih_haptic->detect.tracking_f0 < OPLUS_162HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_303_162Hz);
			return aw_haptic_0809_rtp_303_162Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_166HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_303_166Hz);
			return aw_haptic_0809_rtp_303_166Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_170HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_303_170Hz);
			return aw_haptic_0809_rtp_303_170Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_174HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_303_174Hz);
			return aw_haptic_0809_rtp_303_174Hz;
		} else {
			*data_len = sizeof(aw_haptic_0809_rtp_303_178Hz);
			return aw_haptic_0809_rtp_303_178Hz;
		}
		break;
	case SG_INPUT_DOWN_LOW:
		if (sih_haptic->detect.tracking_f0 < OPLUS_162HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_304_162Hz);
			return aw_haptic_0809_rtp_304_162Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_166HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_304_166Hz);
			return aw_haptic_0809_rtp_304_166Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_170HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_304_170Hz);
			return aw_haptic_0809_rtp_304_170Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_174HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_304_174Hz);
			return aw_haptic_0809_rtp_304_174Hz;
		} else {
			*data_len = sizeof(aw_haptic_0809_rtp_304_178Hz);
			return aw_haptic_0809_rtp_304_178Hz;
		}
		break;
	case SG_INPUT_UP_LOW:
		if (sih_haptic->detect.tracking_f0 < OPLUS_162HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_305_162Hz);
			return aw_haptic_0809_rtp_305_162Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_166HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_305_166Hz);
			return aw_haptic_0809_rtp_305_166Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_170HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_305_170Hz);
			return aw_haptic_0809_rtp_305_170Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_174HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_305_174Hz);
			return aw_haptic_0809_rtp_305_174Hz;
		} else {
			*data_len = sizeof(aw_haptic_0809_rtp_305_178Hz);
			return aw_haptic_0809_rtp_305_178Hz;
		}
		break;
	case INPUT_LOW:
		if (sih_haptic->detect.tracking_f0 < OPLUS_162HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_110_162Hz);
			return aw_haptic_0809_rtp_110_162Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_166HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_110_166Hz);
			return aw_haptic_0809_rtp_110_166Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_170HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_110_170Hz);
			return aw_haptic_0809_rtp_110_170Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_174HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_110_174Hz);
			return aw_haptic_0809_rtp_110_174Hz;
		} else {
			*data_len = sizeof(aw_haptic_0809_rtp_110_178Hz);
			return aw_haptic_0809_rtp_110_178Hz;
		}
		break;
	case INPUT_MEDI:
		if (sih_haptic->detect.tracking_f0 < OPLUS_162HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_111_162Hz);
			return aw_haptic_0809_rtp_111_162Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_166HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_111_166Hz);
			return aw_haptic_0809_rtp_111_166Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_170HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_111_170Hz);
			return aw_haptic_0809_rtp_111_170Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_174HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_111_174Hz);
			return aw_haptic_0809_rtp_111_174Hz;
		} else {
			*data_len = sizeof(aw_haptic_0809_rtp_111_178Hz);
			return aw_haptic_0809_rtp_111_178Hz;
		}
		break;
	case INPUT_HIGH:
		if (sih_haptic->detect.tracking_f0 < OPLUS_162HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_112_162Hz);
			return aw_haptic_0809_rtp_112_162Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_166HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_112_166Hz);
			return aw_haptic_0809_rtp_112_166Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_170HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_112_170Hz);
			return aw_haptic_0809_rtp_112_170Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_174HZ_F0) {
			*data_len = sizeof(aw_haptic_0809_rtp_112_174Hz);
			return aw_haptic_0809_rtp_112_174Hz;
		} else {
			*data_len = sizeof(aw_haptic_0809_rtp_112_178Hz);
			return aw_haptic_0809_rtp_112_178Hz;
		}
		break;
	default:
		hp_err("%s: can not find rtp file\n", __func__);
		break;
	}

	return NULL;
}

static uint8_t *custom_0815_rtp_key_file(struct sih_haptic *sih_haptic, uint32_t *data_len)
{
	switch(sih_haptic->rtp.rtp_file_num) {
	case SG_INPUT_DOWN_HIGH:
		if (sih_haptic->detect.tracking_f0 < OPLUS_162HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_302_162Hz);
			return aw_haptic_0815_rtp_302_162Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_166HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_302_166Hz);
			return aw_haptic_0815_rtp_302_166Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_170HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_302_170Hz);
			return aw_haptic_0815_rtp_302_170Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_174HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_302_174Hz);
			return aw_haptic_0815_rtp_302_174Hz;
		} else {
			*data_len = sizeof(aw_haptic_0815_rtp_302_178Hz);
			return aw_haptic_0815_rtp_302_178Hz;
		}
		break;
	case SG_INPUT_UP_HIGH:
		if (sih_haptic->detect.tracking_f0 < OPLUS_162HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_303_162Hz);
			return aw_haptic_0815_rtp_303_162Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_166HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_303_166Hz);
			return aw_haptic_0815_rtp_303_166Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_170HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_303_170Hz);
			return aw_haptic_0815_rtp_303_170Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_174HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_303_174Hz);
			return aw_haptic_0815_rtp_303_174Hz;
		} else {
			*data_len = sizeof(aw_haptic_0815_rtp_303_178Hz);
			return aw_haptic_0815_rtp_303_178Hz;
		}
		break;
	case SG_INPUT_DOWN_LOW:
		if (sih_haptic->detect.tracking_f0 < OPLUS_162HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_304_162Hz);
			return aw_haptic_0815_rtp_304_162Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_166HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_304_166Hz);
			return aw_haptic_0815_rtp_304_166Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_170HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_304_170Hz);
			return aw_haptic_0815_rtp_304_170Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_174HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_304_174Hz);
			return aw_haptic_0815_rtp_304_174Hz;
		} else {
			*data_len = sizeof(aw_haptic_0815_rtp_304_178Hz);
			return aw_haptic_0815_rtp_304_178Hz;
		}
		break;
	case SG_INPUT_UP_LOW:
		if (sih_haptic->detect.tracking_f0 < OPLUS_162HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_305_162Hz);
			return aw_haptic_0815_rtp_305_162Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_166HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_305_166Hz);
			return aw_haptic_0815_rtp_305_166Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_170HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_305_170Hz);
			return aw_haptic_0815_rtp_305_170Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_174HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_305_174Hz);
			return aw_haptic_0815_rtp_305_174Hz;
		} else {
			*data_len = sizeof(aw_haptic_0815_rtp_305_178Hz);
			return aw_haptic_0815_rtp_305_178Hz;
		}
		break;
	case INPUT_LOW:
		if (sih_haptic->detect.tracking_f0 < OPLUS_162HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_110_162Hz);
			return aw_haptic_0815_rtp_110_162Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_166HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_110_166Hz);
			return aw_haptic_0815_rtp_110_166Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_170HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_110_170Hz);
			return aw_haptic_0815_rtp_110_170Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_174HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_110_174Hz);
			return aw_haptic_0815_rtp_110_174Hz;
		} else {
			*data_len = sizeof(aw_haptic_0815_rtp_110_178Hz);
			return aw_haptic_0815_rtp_110_178Hz;
		}
		break;
	case INPUT_MEDI:
		if (sih_haptic->detect.tracking_f0 < OPLUS_162HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_111_162Hz);
			return aw_haptic_0815_rtp_111_162Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_166HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_111_166Hz);
			return aw_haptic_0815_rtp_111_166Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_170HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_111_170Hz);
			return aw_haptic_0815_rtp_111_170Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_174HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_111_174Hz);
			return aw_haptic_0815_rtp_111_174Hz;
		} else {
			*data_len = sizeof(aw_haptic_0815_rtp_111_178Hz);
			return aw_haptic_0815_rtp_111_178Hz;
		}
		break;
	case INPUT_HIGH:
		if (sih_haptic->detect.tracking_f0 < OPLUS_162HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_112_162Hz);
			return aw_haptic_0815_rtp_112_162Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_166HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_112_166Hz);
			return aw_haptic_0815_rtp_112_166Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_170HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_112_170Hz);
			return aw_haptic_0815_rtp_112_170Hz;
		} else if (sih_haptic->detect.tracking_f0 < OPLUS_174HZ_F0) {
			*data_len = sizeof(aw_haptic_0815_rtp_112_174Hz);
			return aw_haptic_0815_rtp_112_174Hz;
		} else {
			*data_len = sizeof(aw_haptic_0815_rtp_112_178Hz);
			return aw_haptic_0815_rtp_112_178Hz;
		}
		break;
	default:
		hp_err("%s: can not find rtp file\n", __func__);
		break;
	}

	return NULL;
}
static uint8_t *custom_1419_rtp_key_file(struct sih_haptic *sih_haptic, uint32_t *data_len)
{
	switch(sih_haptic->rtp.rtp_file_num) {
	case SG_INPUT_DOWN_HIGH:
		if (sih_haptic->detect.tracking_f0 <= OPLUS_197HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_302_197Hz);
			return aw_haptic_1419_rtp_302_197Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_201HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_302_201Hz);
			return aw_haptic_1419_rtp_302_201Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_205HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_302_205Hz);
			return aw_haptic_1419_rtp_302_205Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_209HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_302_209Hz);
			return aw_haptic_1419_rtp_302_209Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_213HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_302_213Hz);
			return aw_haptic_1419_rtp_302_213Hz;
		} else {
			*data_len = sizeof(aw_haptic_1419_rtp_302_205Hz);
			return aw_haptic_1419_rtp_302_205Hz;
		}
		break;
	case SG_INPUT_UP_HIGH:
		if (sih_haptic->detect.tracking_f0 <= OPLUS_197HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_303_197Hz);
			return aw_haptic_1419_rtp_303_197Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_201HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_303_201Hz);
			return aw_haptic_1419_rtp_303_201Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_205HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_303_205Hz);
			return aw_haptic_1419_rtp_303_205Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_209HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_303_209Hz);
			return aw_haptic_1419_rtp_303_209Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_213HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_303_213Hz);
			return aw_haptic_1419_rtp_303_213Hz;
		} else {
			*data_len = sizeof(aw_haptic_1419_rtp_303_205Hz);
			return aw_haptic_1419_rtp_303_205Hz;
		}
		break;
	case SG_INPUT_DOWN_LOW:
		if (sih_haptic->detect.tracking_f0 <= OPLUS_197HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_304_197Hz);
			return aw_haptic_1419_rtp_304_197Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_201HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_304_201Hz);
			return aw_haptic_1419_rtp_304_201Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_205HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_304_205Hz);
			return aw_haptic_1419_rtp_304_205Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_209HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_304_209Hz);
			return aw_haptic_1419_rtp_304_209Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_213HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_304_213Hz);
			return aw_haptic_1419_rtp_304_213Hz;
		} else {
			*data_len = sizeof(aw_haptic_1419_rtp_304_205Hz);
			return aw_haptic_1419_rtp_304_205Hz;
		}
		break;
	case SG_INPUT_UP_LOW:
		if (sih_haptic->detect.tracking_f0 <= OPLUS_197HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_305_197Hz);
			return aw_haptic_1419_rtp_305_197Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_201HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_305_201Hz);
			return aw_haptic_1419_rtp_305_201Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_205HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_305_205Hz);
			return aw_haptic_1419_rtp_305_205Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_209HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_305_209Hz);
			return aw_haptic_1419_rtp_305_209Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_213HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_305_213Hz);
			return aw_haptic_1419_rtp_305_213Hz;
		} else {
			*data_len = sizeof(aw_haptic_1419_rtp_305_205Hz);
			return aw_haptic_1419_rtp_305_205Hz;
		}
		break;
	case INPUT_LOW:
		if (sih_haptic->detect.tracking_f0 <= OPLUS_197HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_110_197Hz);
			return aw_haptic_1419_rtp_110_197Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_201HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_110_201Hz);
			return aw_haptic_1419_rtp_110_201Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_205HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_110_205Hz);
			return aw_haptic_1419_rtp_110_205Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_209HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_110_209Hz);
			return aw_haptic_1419_rtp_110_209Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_213HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_110_213Hz);
			return aw_haptic_1419_rtp_110_213Hz;
		} else {
			*data_len = sizeof(aw_haptic_1419_rtp_110_205Hz);
			return aw_haptic_1419_rtp_110_205Hz;
		}
		break;
	case INPUT_MEDI:
		if (sih_haptic->detect.tracking_f0 <= OPLUS_197HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_111_197Hz);
			return aw_haptic_1419_rtp_111_197Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_201HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_111_201Hz);
			return aw_haptic_1419_rtp_111_201Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_205HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_111_205Hz);
			return aw_haptic_1419_rtp_111_205Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_209HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_111_209Hz);
			return aw_haptic_1419_rtp_111_209Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_213HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_111_213Hz);
			return aw_haptic_1419_rtp_111_213Hz;
		} else {
			*data_len = sizeof(aw_haptic_1419_rtp_111_205Hz);
			return aw_haptic_1419_rtp_111_205Hz;
		}
		break;
	case INPUT_HIGH:
		if (sih_haptic->detect.tracking_f0 <= OPLUS_197HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_112_197Hz);
			return aw_haptic_1419_rtp_112_197Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_201HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_112_201Hz);
			return aw_haptic_1419_rtp_112_201Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_205HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_112_205Hz);
			return aw_haptic_1419_rtp_112_205Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_209HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_112_209Hz);
			return aw_haptic_1419_rtp_112_209Hz;
		} else if (sih_haptic->detect.tracking_f0 <= OPLUS_213HZ_F0) {
			*data_len = sizeof(aw_haptic_1419_rtp_112_213Hz);
			return aw_haptic_1419_rtp_112_213Hz;
		} else {
			*data_len = sizeof(aw_haptic_1419_rtp_112_205Hz);
			return aw_haptic_1419_rtp_112_205Hz;
		}
		break;
	default:
		hp_err("%s: can not find rtp file\n", __func__);
		break;
	}

	return NULL;
}
#endif

static void rtp_work_func(struct work_struct *work)
{
	bool rtp_work_flag = false;
	int cnt = SIH_ENTER_RTP_MODE_MAX_TRY;
	int ret = -1;
	const struct firmware *rtp_file;
	uint8_t *haptic_rtp_key_data = NULL;
	uint32_t haptic_rtp_key_data_len = 0;
	const char* rtp_name = NULL;
	sih_haptic_t *sih_haptic = container_of(work, sih_haptic_t, rtp.rtp_work);

	hp_info("%s:enter!\n", __func__);

	mutex_lock(&sih_haptic->rtp.rtp_lock);

	sih_haptic->rtp.rtp_init = false;
	sih_vfree_container(sih_haptic, sih_haptic->rtp.rtp_cont);
	sih_haptic->rtp.rtp_cont = NULL;

	if ((DEVICE_ID_0815 == sih_haptic->device_id || DEVICE_ID_0809 == sih_haptic->device_id
		|| DEVICE_ID_1419 == sih_haptic->device_id) &&
		 ((sih_haptic->rtp.rtp_file_num >= 302 && sih_haptic->rtp.rtp_file_num <= 305) ||
		 (sih_haptic->rtp.rtp_file_num >= 110 && sih_haptic->rtp.rtp_file_num <= 112))) {
		hp_info("%s: key scene, use array data", __func__);

		if (sih_haptic->device_id == DEVICE_ID_0809) {
			haptic_rtp_key_data = custom_0809_rtp_key_file(sih_haptic, &haptic_rtp_key_data_len);
		} else if (sih_haptic->device_id == DEVICE_ID_0815) {
			haptic_rtp_key_data = custom_0815_rtp_key_file(sih_haptic, &haptic_rtp_key_data_len);
		} else if (sih_haptic->device_id == DEVICE_ID_1419) {
			haptic_rtp_key_data = custom_1419_rtp_key_file(sih_haptic, &haptic_rtp_key_data_len);
		} else {
			hp_info("%s: vibrator error, vibrator id: %d \n", __func__, sih_haptic->device_id);
		}
		if (haptic_rtp_key_data == NULL) {
			hp_err("%s: haptic_rtp_key_data is NULL! vibrator id: %d \n", __func__, sih_haptic->device_id);
			mutex_unlock(&sih_haptic->rtp.rtp_lock);
			return;
		}

		sih_haptic->rtp.rtp_cont = vmalloc(haptic_rtp_key_data_len + sizeof(int));
		if (!sih_haptic->rtp.rtp_cont) {
			hp_err("%s:error allocating memory\n", __func__);
			sih_chip_state_recovery(sih_haptic);
			mutex_unlock(&sih_haptic->rtp.rtp_lock);
#ifdef CONFIG_HAPTIC_FEEDBACK_MODULE
			(void)oplus_haptic_track_mem_alloc_err(HAPTIC_MEM_ALLOC_TRACK,
					haptic_rtp_key_data_len + sizeof(int), __func__);
#endif
			return;
		}
		sih_haptic->rtp.rtp_cont->len = haptic_rtp_key_data_len;
		memcpy(sih_haptic->rtp.rtp_cont->data, haptic_rtp_key_data, haptic_rtp_key_data_len);
	} else {
		rtp_file = sih_rtp_load_file_accord_f0(sih_haptic);
		if (!rtp_file) {
			rtp_name = get_rtp_name(sih_haptic->rtp.rtp_file_num, sih_haptic->detect.tracking_f0);
			if (!rtp_name) {
				hp_err("%s: get rtp name failed.\n", __func__);
				sih_chip_state_recovery(sih_haptic);
				mutex_unlock(&sih_haptic->rtp.rtp_lock);
				return;
			}
			ret = request_firmware(&rtp_file, rtp_name, sih_haptic->dev);
			hp_err("%s line:%d: rtp_num:%d name:%s\n", __func__, __LINE__,
					sih_haptic->rtp.rtp_file_num, rtp_name);
			vfree(rtp_name);
			if (ret < 0) {
				hp_err("%s:no this rtp file\n", __func__);
				sih_chip_state_recovery(sih_haptic);
				mutex_unlock(&sih_haptic->rtp.rtp_lock);
				return;
			}
		}

		sih_haptic->rtp.rtp_cont = vmalloc(rtp_file->size + sizeof(int));
		if (!sih_haptic->rtp.rtp_cont) {
#ifdef CONFIG_HAPTIC_FEEDBACK_MODULE
			(void)oplus_haptic_track_mem_alloc_err(HAPTIC_MEM_ALLOC_TRACK,
					rtp_file->size + sizeof(int), __func__);
#endif
			release_firmware(rtp_file);
			hp_err("%s:error allocating memory\n", __func__);
			sih_chip_state_recovery(sih_haptic);
			mutex_unlock(&sih_haptic->rtp.rtp_lock);
			return;
		}
		sih_haptic->rtp.rtp_cont->len = rtp_file->size;
		memcpy(sih_haptic->rtp.rtp_cont->data, rtp_file->data, rtp_file->size);
		release_firmware(rtp_file);
	}

	mutex_unlock(&sih_haptic->rtp.rtp_lock);
	hp_info("%s:rtp len is %d\n", __func__, sih_haptic->rtp.rtp_cont->len);

	mutex_lock(&sih_haptic->lock);

	sih_haptic->rtp.rtp_init = true;
	sih_haptic->chip_ipara.state = SIH_ACTIVE_MODE;
	sih_haptic->hp_func->stop(sih_haptic);
	sih_haptic->hp_func->check_detect_state(sih_haptic, SIH_RTP_MODE);
	sih_haptic->hp_func->set_rtp_aei(sih_haptic, false);
	sih_haptic->hp_func->set_play_mode(sih_haptic, SIH_RTP_MODE);
	sih_haptic->hp_func->play_go(sih_haptic, true);
	usleep_range(2000, 2500);
	while (cnt--) {
		if (sih_haptic->hp_func->if_chip_is_mode(sih_haptic, SIH_RTP_MODE)) {
			rtp_work_flag = true;
			hp_info("%s:rtp go!\n", __func__);
			break;
		}

		hp_info("%s:wait for rtp go!\n", __func__);
		usleep_range(2000, 2500);
	}
	if (rtp_work_flag && sih_haptic->rtp.rtp_file_num != 0) {
		sih_rtp_play(sih_haptic, SIH_RTP_NORMAL_PLAY);
	} else {
		sih_haptic->hp_func->stop(sih_haptic);
		sih_haptic->chip_ipara.state = SIH_STANDBY_MODE;
		sih_op_clean_status(sih_haptic);
		hp_err("%s:rtp go failed! not enter rtp status!\n", __func__);
	}
	mutex_unlock(&sih_haptic->lock);
}

static int vibrator_chip_init(sih_haptic_t *sih_haptic)
{
	int ret = -1;
	ret = sih_haptic->hp_func->efuse_check(sih_haptic);
	if (ret < 0)
		return ret;
	sih_haptic->hp_func->init(sih_haptic);
	sih_haptic->hp_func->stop(sih_haptic);
	/* load lra reg config */
	ret = sih_lra_config_load(sih_haptic);
	if (ret < 0)
		return ret;
	if (sih_haptic->auto_break_mode_support) {
		sih_auto_break_config_regs(sih_haptic);
		sih_haptic->hp_func->set_brk_state(sih_haptic, SIH_RAM_MODE, true);
		sih_haptic->hp_func->set_brk_state(sih_haptic, SIH_RTP_MODE, true);
		hp_info("%s: auto break opened\n", __func__);
	}
	sih_op_clean_status(sih_haptic);
	hp_info("%s:end\n", __func__);
	return ret;
}

static ssize_t proc_vibration_style_read(
	struct file *filp,
	char __user *buf,
	size_t count,
	loff_t *ppos)
{
	sih_haptic_t *sih_haptic = (sih_haptic_t *)filp->private_data;
	uint8_t ret = 0;
	int style = 0;
	char page[10];

	style = sih_haptic->ram.vibration_style;

	hp_err("%s: touch_style=%d\n", __func__, style);
	sprintf(page, "%d\n", style);
	ret = simple_read_from_buffer(buf, count, ppos, page, strlen(page));
	return ret;
}

static ssize_t proc_vibration_style_write(
	struct file *filp,
	const char __user *buf,
	size_t count,
	loff_t *lo)
{
	sih_haptic_t *sih_haptic = (sih_haptic_t *)filp->private_data;
	char buffer[5] = { 0 };
	int val;
	int ret = 0;

	if (count > 5) {
		return -EFAULT;
	}

	if (copy_from_user(buffer, buf, count)) {
		hp_err("%s: error.\n", __func__);
		return -EFAULT;
	}

	hp_err("%s: buffer=%s\n",__func__, buffer);
	ret = kstrtoint(buffer, 0, &val);
	hp_err("%s: val = %d\n",__func__, val);

	if (val == 0) {
		sih_haptic->ram.vibration_style = AW8697_HAPTIC_VIBRATION_CRISP_STYLE;
		schedule_work(&sih_haptic->ram.ram_update_work);
	} else if (val == 1){
		sih_haptic->ram.vibration_style = AW8697_HAPTIC_VIBRATION_SOFT_STYLE;
		schedule_work(&sih_haptic->ram.ram_update_work);
	} else {
		sih_haptic->ram.vibration_style = AW8697_HAPTIC_VIBRATION_CRISP_STYLE;
	}
	return count;
}

static const struct proc_ops proc_vibration_style_ops = {
	.proc_read = proc_vibration_style_read,
	.proc_write = proc_vibration_style_write,
	.proc_open =  memo_file_open,
};

static int __maybe_unused init_vibrator_proc(
	sih_haptic_t *sih_haptic)
{
	int ret = 0;
	struct proc_dir_entry *prEntry_da = NULL;
	struct proc_dir_entry *prEntry_tmp = NULL;

	prEntry_da = proc_mkdir("vibrator", NULL);
	if (prEntry_da == NULL) {
		ret = -ENOMEM;
		hp_err("%s: Couldn't create sih_vibrator proc entry\n",
			  __func__);
	}

	prEntry_tmp = proc_create_data("touch_style", 0664, prEntry_da,
				       &proc_vibration_style_ops, sih_haptic);
	if (prEntry_tmp == NULL) {
		ret = -ENOMEM;
		hp_err("%s: Couldn't create proc entry, %d\n", __func__,
			  __LINE__);
	}
	return 0;
}

static int vibrator_init(sih_haptic_t *sih_haptic)
{
	int ret = -1;
	/* vibrator globle ptr init */
	g_haptic_t.sih_num = SIH_HAPTIC_DEV_NUM;
	g_haptic_t.g_haptic[SIH_HAPTIC_MMAP_DEV_INDEX] = sih_haptic;
	/* timer init */
	hrtimer_init(&sih_haptic->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	sih_haptic->timer.function = haptic_timer_func;
	/* work func init */
	INIT_WORK(&sih_haptic->ram.ram_work, ram_work_func);
	INIT_WORK(&sih_haptic->rtp.rtp_work, rtp_work_func);
	INIT_WORK(&sih_haptic->ram.ram_update_work, ram_update_work_func);
#ifdef OPLUS_FEATURE_CHG_BASIC
	INIT_WORK(&sih_haptic->motor_old_test_work, motor_old_test_work);
	sih_haptic->motor_old_test_mode = 0;
	sih_haptic->gun_type = 0xFF;
	sih_haptic->bullet_nr = 0x00;
	sih_haptic->gun_mode = 0x00;
#endif
	/* mutex init */
	mutex_init(&sih_haptic->lock);
	mutex_init(&sih_haptic->rtp.rtp_lock);

	ret = sih_haptic->stream_func->stream_rtp_work_init(sih_haptic);
	if (ret) {
		hp_err("%s: stream rtp work init failed\n", __func__);
		return ret;
	}
	ret = init_vibrator_proc(sih_haptic);
	if (ret) {
		hp_err("%s: init vibrator proc failed\n", __func__);
		return ret;
	}
	hp_info("%s:end\n", __func__);
	return ret;
}

static int sih_i2c_probe(struct i2c_client *i2c,
	const struct i2c_device_id *id)
{
	sih_haptic_t *sih_haptic;
	struct device_node *np = i2c->dev.of_node;
	int ret = -1;

	hp_info("%s:haptic i2c probe enter\n", __func__);

	/* I2C Adapter capability detection */
	if (!i2c_check_functionality(i2c->adapter, I2C_FUNC_I2C)) {
		hp_err("%s:i2c algorithm ability detect failed\n", __func__);
		return -EIO;
	}
	/* Allocate cache space for haptic device */
	sih_haptic = devm_kzalloc(&i2c->dev, sizeof(sih_haptic_t), GFP_KERNEL);
	if (sih_haptic == NULL) {
		hp_err("%s:sih_haptic is null\n", __func__);
		return -ENOMEM;
	}
	sih_haptic->dev = &i2c->dev;
	sih_haptic->i2c = i2c;
	i2c_set_clientdata(i2c, sih_haptic);
	/* matching dts */
	ret = sih_parse_dts(&i2c->dev, sih_haptic, np);
	if (ret) {
		hp_err("%s:dts parse failed\n", __func__);
		goto err_parse_dts;
	}
	/* acquire gpio resources and hw reset */

	ret = sih_acquire_gpio_res(&i2c->dev, sih_haptic);
	if (ret) {
		hp_err("%s:acquire gpio failed\n", __func__);
		goto err_gpio_res;
	}
	/* Registers chip manipulation functions */
	ret = sih_register_func(sih_haptic);
	if (ret) {
		hp_err("%s:register functions failed\n", __func__);
		goto err_id;
	}
	/* registers regmap */
	sih_haptic->regmapp.regmapping = haptic_regmap_init(i2c,
		sih_haptic->regmapp.config);
	if (sih_haptic->regmapp.regmapping == NULL) {
		hp_err("%s:register regmap failed\n", __func__);
		goto err_regmap;
	}
	/* handle gpio irq */
	ret = sih_acquire_irq_res(&i2c->dev, sih_haptic);
	if (ret) {
		hp_err("%s: irq gpio interrupt request failed\n", __func__);
		goto err_irq;
	}
	/* vibrator chip init */
	ret = vibrator_chip_init(sih_haptic);
	if (ret) {
		hp_err("%s: chip init failed\n", __func__);
		goto err_dev_sysfs;
	}
	/* vibrator init */
	ret = vibrator_init(sih_haptic);
	if (ret) {
		hp_err("%s: add sysfs node failed\n", __func__);
		goto err_dev_sysfs;
	}
	/* add sysfs node */
	ret = sih_add_node(&i2c->dev, sih_haptic);
	if (ret) {
		hp_err("%s: add sysfs node failed\n", __func__);
		goto err_dev_sysfs;
	}
	/* ram work init */
	schedule_work(&sih_haptic->ram.ram_update_work);
	hp_info("%s:end\n", __func__);
	return 0;

err_dev_sysfs:
	sih_haptic->stream_func->stream_rtp_work_release(sih_haptic);
	devm_free_irq(&i2c->dev, gpio_to_irq(sih_haptic->chip_attr.irq_gpio), sih_haptic);
err_irq:
err_regmap:
err_id:
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0))
	devm_gpio_free(&i2c->dev, sih_haptic->chip_attr.irq_gpio);
	devm_gpio_free(&i2c->dev, sih_haptic->chip_attr.reset_gpio);
#endif
err_gpio_res:
err_parse_dts:
	devm_kfree(&i2c->dev, sih_haptic);
	sih_haptic = NULL;
	return ret;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0))
static int sih_i2c_remove(struct i2c_client *i2c)
{
	sih_haptic_t *sih_haptic = i2c_get_clientdata(i2c);

	hp_info("%s:end\n", __func__);
	/* work_struct release */
	cancel_work_sync(&sih_haptic->ram.ram_work);
	cancel_work_sync(&sih_haptic->rtp.rtp_work);
	cancel_work_sync(&sih_haptic->ram.ram_update_work);
	cancel_work_sync(&sih_haptic->motor_old_test_work);
	/* hrtimer release */
	hrtimer_cancel(&sih_haptic->timer);
	/* mutex release */
	mutex_destroy(&sih_haptic->lock);
	mutex_destroy(&sih_haptic->rtp.rtp_lock);
	/* irq release */
	devm_free_irq(&i2c->dev, gpio_to_irq(sih_haptic->chip_attr.irq_gpio),
		sih_haptic);
	/* gpio release */
	if (gpio_is_valid(sih_haptic->chip_attr.irq_gpio))
		devm_gpio_free(&i2c->dev, sih_haptic->chip_attr.irq_gpio);
	if (gpio_is_valid(sih_haptic->chip_attr.reset_gpio))
		devm_gpio_free(&i2c->dev, sih_haptic->chip_attr.reset_gpio);
	/* regmap exit */
	haptic_regmap_remove(sih_haptic->regmapp.regmapping);
	/* container release */
	sih_vfree_container(sih_haptic, sih_haptic->rtp.rtp_cont);
	sih_haptic->rtp.rtp_cont = NULL;

	/* reg addr release */
	if (sih_haptic->chip_reg.reg_addr != NULL)
		kfree(sih_haptic->chip_reg.reg_addr);
	sih_haptic->stream_func->stream_rtp_work_release(sih_haptic);
	return 0;
}
#else
static void sih_i2c_remove(struct i2c_client *i2c)
{
	sih_haptic_t *sih_haptic = i2c_get_clientdata(i2c);

	hp_info("%s:end\n", __func__);
	/* work_struct release */
	cancel_work_sync(&sih_haptic->ram.ram_work);
	cancel_work_sync(&sih_haptic->rtp.rtp_work);
	cancel_work_sync(&sih_haptic->ram.ram_update_work);
	cancel_work_sync(&sih_haptic->motor_old_test_work);
	/* hrtimer release */
	hrtimer_cancel(&sih_haptic->timer);
	/* mutex release */
	mutex_destroy(&sih_haptic->lock);
	mutex_destroy(&sih_haptic->rtp.rtp_lock);
	/* irq release */
	devm_free_irq(&i2c->dev, gpio_to_irq(sih_haptic->chip_attr.irq_gpio),
		sih_haptic);
	/* regmap exit */
	haptic_regmap_remove(sih_haptic->regmapp.regmapping);
	/* container release */
	sih_vfree_container(sih_haptic, sih_haptic->rtp.rtp_cont);
	sih_haptic->rtp.rtp_cont = NULL;

	/* reg addr release */
	if (sih_haptic->chip_reg.reg_addr != NULL)
		kfree(sih_haptic->chip_reg.reg_addr);
	sih_haptic->stream_func->stream_rtp_work_release(sih_haptic);
	return;
}

#endif

static int sih_suspend(struct device *dev)
{
	int ret = 0;
	sih_haptic_t *sih_haptic = dev_get_drvdata(dev);

	mutex_lock(&sih_haptic->lock);
	/* chip stop */
	mutex_unlock(&sih_haptic->lock);

	return ret;
}

static int sih_resume(struct device *dev)
{
	int ret = 0;

	hp_info("%s:resume\n", __func__);

	return ret;
}

static SIMPLE_DEV_PM_OPS(sih_pm_ops, sih_suspend, sih_resume);

static const struct i2c_device_id sih_i2c_id[] = {
	{SIH_HAPTIC_NAME_688X, 0},
	{},
};

static struct of_device_id sih_dt_match[] = {
	{.compatible = SIH_HAPTIC_COMPAT_688X},
	{},
};

static struct i2c_driver sih_i2c_driver = {
	.driver = {
		.name = SIH_HAPTIC_NAME_688X,
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(sih_dt_match),
		.pm = &sih_pm_ops,
	},
	.probe = sih_i2c_probe,
	.remove = sih_i2c_remove,
	.id_table = sih_i2c_id,
};

static int __init sih_i2c_init(void)
{
	int ret = -1;

	ret = i2c_add_driver(&sih_i2c_driver);

	hp_info("%s:i2c_add_driver,ret = %d\n", __func__, ret);

	if (ret) {
		hp_err("%s:fail to add haptic device,ret = %d\n", __func__, ret);
		return ret;
	}

	return 0;
}

static void __exit sih_i2c_exit(void)
{
	i2c_del_driver(&sih_i2c_driver);
}

module_init(sih_i2c_init);
module_exit(sih_i2c_exit);

MODULE_DESCRIPTION("Haptic Driver V1.0.3.691");
MODULE_LICENSE("GPL v2");
#if defined(CONFIG_OPLUS_VIBRATOR_GKI_ENABLE)
MODULE_SOFTDEP("pre: haptic aw8697");
#endif
