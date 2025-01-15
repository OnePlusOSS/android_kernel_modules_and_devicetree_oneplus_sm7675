#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/usb/typec.h>
#include <linux/usb/typec_mux.h>
#include <linux/regulator/consumer.h>
#include <linux/power_supply.h>

#include "../../../../../../drivers/misc/mediatek/typec/tcpc/inc/tcpm.h"
#include "../../../../../../drivers/misc/mediatek/typec/tcpc/inc/tcpci.h"

#include "oplus_discrete_typec_switch.h"

#if IS_ENABLED(CONFIG_OPLUS_FEATURE_MM_FEEDBACK)
/*2022/12/09, Add for oplus_discrete_typec_switch err feedback.*/
#include <soc/oplus/system/oplus_mm_kevent_fb.h>
#endif

//#ifdef OPLUS_ARCH_EXTENDS
/* 2024/1/8, add for supporting type-c headphone detect bypass */
int (*ptypec_ext_eint_handler)(void) = NULL;

int typec_discrete_ext_eint_handler(void)
{
    if (ptypec_ext_eint_handler) {pr_info("ext_eint_handler register");
        ptypec_ext_eint_handler();
        return 0;
    } else {
        pr_info("ext_eint_handler not register");
        return -1;
    }
}

void register_discrete_ext_eint_handler(int (*phandler)(void))
{
    ptypec_ext_eint_handler = phandler;
}
EXPORT_SYMBOL(register_discrete_ext_eint_handler);
//#endif


static struct typec_switch_priv *g_typec_switch_priv = NULL;

static int oplus_discrete_typec_switch_usbc_event_changed(struct notifier_block *nb,
				unsigned long evt, void *ptr)
{
	struct typec_switch_priv *switch_priv =
			container_of(nb, struct typec_switch_priv, pd_nb);
	struct device *dev;
	struct tcp_notify *noti = ptr;

	if (!switch_priv) {
		pr_err("%s, switch_priv is NULL", __func__);
		return -EINVAL;
	}

	dev = switch_priv->dev;
	if (!dev) {
		pr_err("%s, switch_priv->dev is NULL", __func__);
		return -EINVAL;
	}

	if (evt == TCP_NOTIFY_TYPEC_STATE) {
		dev_info(dev, "%s: typeC event = %lu plug_state = %d\n", __func__, evt, switch_priv->plug_state);
	}

	switch (evt) {
	case TCP_NOTIFY_TYPEC_STATE:// 14
		dev_info(dev, "%s: old_state: %d, new_state: %d\n",
			__func__, noti->typec_state.old_state, noti->typec_state.new_state);
		if (noti->typec_state.old_state == TYPEC_UNATTACHED &&
			noti->typec_state.new_state == TYPEC_ATTACHED_SNK) {
			/* SNK plug in */
			dev_err(dev, "%s: SNK  has been plugged in\n", __func__);
			switch_priv->charger_plugged = 1;
		} else if (switch_priv->charger_plugged != 0 && noti->typec_state.old_state == TYPEC_ATTACHED_SNK
			&& noti->typec_state.new_state == TYPEC_UNATTACHED) {
			/* Charger plug out */
			dev_err(dev, "%s: SNK has been plugged out\n", __func__);
			switch_priv->charger_plugged = 0;
		} else if (noti->typec_state.old_state == TYPEC_UNATTACHED &&
			noti->typec_state.new_state == TYPEC_ATTACHED_AUDIO) {
			/* AUDIO plug in */
			dev_info(dev, "%s: audio plug in\n", __func__);
			switch_priv->plug_state = true;
			cancel_work_sync(&switch_priv->usbc_analog_work);
			schedule_work(&switch_priv->usbc_analog_work);
		} else if (switch_priv->plug_state == true
			&& noti->typec_state.new_state == TYPEC_UNATTACHED) {
			/* AUDIO plug out */
			dev_info(dev, "%s: audio plug out\n", __func__);
			switch_priv->plug_state = false;
			cancel_work_sync(&switch_priv->usbc_analog_work);
			schedule_work(&switch_priv->usbc_analog_work);
		}
		break;
	case TCP_NOTIFY_PD_STATE:
		dev_info(dev, "%s, %d, noti->pd_state.connected = %d\n",
			__func__, __LINE__, noti->pd_state.connected);
		switch (noti->pd_state.connected) {
		case PD_CONNECT_NONE:
			break;
		case PD_CONNECT_TYPEC_ONLY_SNK_DFT:
			break;
		case PD_CONNECT_HARD_RESET:
			break;
		default:
			break;
		}
		break;
	case TCP_NOTIFY_PLUG_OUT:
		dev_info(dev, "%s: typec plug out\n", __func__);
		break;
	default:
		break;
	};

	return NOTIFY_OK;
}

static int oplus_discrete_typec_switch_usbc_analog_setup_switches(struct typec_switch_priv *switch_priv)
{
	struct device *dev;
	int state;

	if (!switch_priv) {
		dev_info(dev,"%s, switch_priv is NULL", __func__);

		return -EINVAL;
	}
	dev = switch_priv->dev;
	if (!dev) {
		dev_info(dev,"%s, switch_priv->dev is NULL", __func__);

		return -EINVAL;
	}

	mutex_lock(&switch_priv->notification_lock);
	dev_info(dev, "%s: plug_state %d\n", __func__, switch_priv->plug_state);

	if (switch_priv->plug_state) {
		if (switch_priv->hs_det_bypass) {
			if (gpio_is_valid(switch_priv->switch_enable_pin)) {
				pr_info("%s: switch enable\n", __func__);
				gpio_direction_output(switch_priv->switch_enable_pin, switch_priv->switch_enable_level);
			}
			usleep_range(50*1000, 50*1000+10);
			if (gpio_is_valid(switch_priv->mic_gnd_swh_pin)) {
				pr_info("%s: swap mic gnd pin.\n", __func__);
				gpio_direction_output(switch_priv->mic_gnd_swh_pin, !switch_priv->mic_gnd_swh_level);
			}
			if (gpio_is_valid(switch_priv->mic_gnd_swh_2nd_pin)) {
				pr_info("%s: swap mic gnd 2nd pin.\n", __func__);
				gpio_direction_output(switch_priv->mic_gnd_swh_2nd_pin, !switch_priv->mic_gnd_swh_2nd_level);
			}
			typec_discrete_ext_eint_handler();
		} else {
			if (gpio_is_valid(switch_priv->hs_det_pin)) {
				dev_info(dev, "%s, %d: set hs_det_pin %d to enable.\n", __func__, __LINE__, switch_priv->hs_det_pin);
				state = gpio_get_value(switch_priv->hs_det_pin);
				dev_info(dev, "%s: before hs_det_pin state = %d.\n", __func__, state);
				usleep_range(1000, 1005);
				gpio_direction_output(switch_priv->hs_det_pin, switch_priv->hs_det_level);
				state = gpio_get_value(switch_priv->hs_det_pin);
				dev_info(dev, "%s: after hs_det_pin state = %d.\n", __func__, state);
			}
		}
	} else {
		if (switch_priv->hs_det_bypass) {
			typec_discrete_ext_eint_handler();
		} else {
			if (gpio_is_valid(switch_priv->hs_det_pin)) {
				dev_info(dev, "%s: set hs_det_pin to disable.\n", __func__);
				state = gpio_get_value(switch_priv->hs_det_pin);
				dev_info(dev, "%s: before hs_det_pin state = %d.\n", __func__, state);
				gpio_direction_output(switch_priv->hs_det_pin, !switch_priv->hs_det_level);
				state = gpio_get_value(switch_priv->hs_det_pin);
				dev_info(dev, "%s: after hs_det_pin state = %d.\n", __func__, state);
			}
		}
		//switch to usb mode
		if (gpio_is_valid(switch_priv->lr_sel_pin)) {
			pr_info("%s: disconnect LR.\n", __func__);
			gpio_direction_output(switch_priv->lr_sel_pin, !switch_priv->lr_sel_level);
		}

	}
	mutex_unlock(&switch_priv->notification_lock);
	return 0;
}
int oplus_discrete_typec_switch_get_mic_gnd_status(void)
{
	struct typec_switch_priv *switch_priv = g_typec_switch_priv;
	if (!switch_priv) {
		pr_err("switch_priv is NULL\n");
		return -EINVAL;
	}
	pr_info("%s - mic_gnd_status %d\n", __func__, switch_priv->mic_gnd_status);
	return switch_priv->mic_gnd_status;
}
EXPORT_SYMBOL(oplus_discrete_typec_switch_get_mic_gnd_status);

int oplus_discrete_typec_switch_hs_event(enum audio_switch_hs_event event)
{
	struct typec_switch_priv *switch_priv = g_typec_switch_priv;

	if (!switch_priv) {
		pr_err("switch_priv is NULL\n");
		return -EINVAL;
	}
	pr_info("%s - switch headset event: %d\n", __func__, event);

	switch (event) {
	case HS_MIC_GND_SWAP:
		if ((gpio_is_valid(switch_priv->mic_gnd_swh_pin)) && (gpio_is_valid(switch_priv->mic_gnd_swh_2nd_pin))) {
			if (switch_priv->mic_gnd_status == 0) {
				gpio_direction_output(switch_priv->mic_gnd_swh_pin, switch_priv->mic_gnd_swh_level);
				gpio_direction_output(switch_priv->mic_gnd_swh_2nd_pin, switch_priv->mic_gnd_swh_2nd_level);
				switch_priv->mic_gnd_status = 1;
			} else {
				gpio_direction_output(switch_priv->mic_gnd_swh_pin, !switch_priv->mic_gnd_swh_level);
				gpio_direction_output(switch_priv->mic_gnd_swh_2nd_pin, !switch_priv->mic_gnd_swh_2nd_level);
				switch_priv->mic_gnd_status = 0;
			}
			pr_info("%s: swap mic gnd, set mic_gnd_swh_pin %d\n", \
					__func__, switch_priv->mic_gnd_status);
		}
		break;

	case HS_LR_CONNECT:
		if (gpio_is_valid(switch_priv->lr_sel_pin)) {
			pr_info("%s: connect LR.\n", __func__);
			gpio_direction_output(switch_priv->lr_sel_pin, switch_priv->lr_sel_level);
		}
		break;

	case HS_LR_DISCONNECT:
		if (gpio_is_valid(switch_priv->lr_sel_pin)) {
			pr_info("%s: disconnect LR.\n", __func__);
			gpio_direction_output(switch_priv->lr_sel_pin, !switch_priv->lr_sel_level);
		}
		break;

	case HS_PLUG_OUT:
		if ((gpio_is_valid(switch_priv->mic_gnd_swh_pin)) && (gpio_is_valid(switch_priv->mic_gnd_swh_2nd_pin))) {
			pr_info("%s: set mic_gnd_swh_pin \n", __func__);
			gpio_direction_output(switch_priv->mic_gnd_swh_pin, !switch_priv->mic_gnd_swh_level);
			gpio_direction_output(switch_priv->mic_gnd_swh_2nd_pin, switch_priv->mic_gnd_swh_2nd_level);
			switch_priv->mic_gnd_status = 0;
		}
		if (gpio_is_valid(switch_priv->switch_enable_pin)) {
			pr_info("%s: switch disable\n", __func__);
			gpio_direction_output(switch_priv->switch_enable_pin, !switch_priv->switch_enable_level);
		}

		break;
	default:
		break;
	}

	return 0;
}
EXPORT_SYMBOL(oplus_discrete_typec_switch_hs_event);

static int oplus_discrete_typec_switch_parse_dt(struct typec_switch_priv *switch_priv,
	struct device *dev)
{
	struct device_node *dNode = dev->of_node;
	int ret = 0;
	int hs_det_bypass = 0;

	if (dNode == NULL) {
		return -ENODEV;
	}

	if (!switch_priv) {
		pr_err("%s: swh_priv is NULL\n", __func__);
		return -ENOMEM;
	}

	//hp-det-gpio
	ret = of_property_read_u32(dNode,
			"oplus,hs-det-bypass", &hs_det_bypass);
	if (ret) {
		pr_info("%s: read prop hs-bypass fail\n", __func__);
		switch_priv->hs_det_bypass = false;
	} else {
		switch_priv->hs_det_bypass = hs_det_bypass;
		pr_info("%s: read prop hs-bypass %d\n", __func__, switch_priv->hs_det_bypass);
	}
	switch_priv->hs_det_pin = of_get_named_gpio(dNode,
			"oplus,hs-det-gpio", 0);
	if (!gpio_is_valid(switch_priv->hs_det_pin) || switch_priv->hs_det_bypass) {
		pr_info("%s: hs-det-gpio in dt node is missing\n", __func__);
	} else {
		ret = gpio_request(switch_priv->hs_det_pin, "hs_det_pin");
		if (ret) {
			pr_err("%s exit_hs_det_gpio_request_failed \n", __func__);
			goto exit_hp_det_gpio_request_failed;
		}
	}
	ret = of_property_read_u32(dNode,
			"oplus,hs-det-level", &switch_priv->hs_det_level);
	if (ret) {
		pr_info("%s: read prop hs-det-level fail\n", __func__);
		switch_priv->hs_det_level = 0;
	} else {
		pr_info("%s, hs_det_level = %d\n", __func__, switch_priv->hs_det_level);
	}
	gpio_direction_output(switch_priv->hs_det_pin, !switch_priv->hs_det_level);
	//oplus,lr-sel-gpio
	switch_priv->lr_sel_pin = of_get_named_gpio(dNode,
			"oplus,lr-sel-gpio", 0);
	if (!gpio_is_valid(switch_priv->lr_sel_pin)) {
		pr_info("%s: hp-det-gpio in dt node is missing\n", __func__);
	} else {
		ret = gpio_request(switch_priv->lr_sel_pin, "lr_sel_pin");
		if (ret) {
			pr_err("%s exit_lr_sel_gpio_request_failed \n", __func__);
			goto exit_lr_sel_gpio_request_failed;
		}
	}
	ret = of_property_read_u32(dNode,
			"oplus,lr-sel-level", &switch_priv->lr_sel_level);
	if (ret) {
		pr_info("%s: read prop lr-sel-level fail\n", __func__);
		switch_priv->lr_sel_level = 0;
	} else {
		pr_debug("%s, lr_sel_level = %d\n", __func__, switch_priv->lr_sel_level);
	}
	gpio_direction_output(switch_priv->lr_sel_pin, !switch_priv->lr_sel_level);

	//mic-gnd-swh-gpio
	switch_priv->mic_gnd_swh_pin = of_get_named_gpio(dNode,
			"oplus,mic-gnd-swh-gpio", 0);
	if (!gpio_is_valid(switch_priv->mic_gnd_swh_pin)) {
		pr_info("%s: mic-gnd-swh-gpio in dt node is missing\n", __func__);
	} else {
		ret = gpio_request(switch_priv->mic_gnd_swh_pin, "mic_gnd_swh_pin");
		if (ret) {
			pr_err("%s exit_mic_gnd_swh_gpio_request_failed \n", __func__);
			goto exit_mic_gnd_swh_gpio_request_failed;
		}
	}
	ret = of_property_read_u32(dNode,
			"oplus,mic-gnd-swh-level", &switch_priv->mic_gnd_swh_level);
	if (ret) {
		pr_info("%s: read prop mic-gnd-swh-level fail\n", __func__);
		switch_priv->mic_gnd_swh_level = 0;
	} else {
		pr_debug("%s, mic_gnd_swh_level = %d\n", __func__, switch_priv->mic_gnd_swh_level);
	}
	gpio_direction_output(switch_priv->mic_gnd_swh_pin, !switch_priv->mic_gnd_swh_level); //Default high-level

	//2nd mic-gnd-swh-gpio
	switch_priv->mic_gnd_swh_2nd_pin = of_get_named_gpio(dNode,
			"oplus,mic-gnd-swh-2nd-gpio", 0);
	if (!gpio_is_valid(switch_priv->mic_gnd_swh_2nd_pin)) {
		pr_info("%s: oplus,mic-gnd-swh-2nd-gpio in dt node is missing\n", __func__);
	} else {
		ret = gpio_request(switch_priv->mic_gnd_swh_2nd_pin, "mic_gnd_swh_2nd_pin");
		if (ret) {
			pr_err("%s exit_2nd_mic_gnd_swh_gpio_request_failed \n", __func__);
			goto exit_mic_gnd_swh_2nd_gpio_request_failed;
		}
	}
	ret = of_property_read_u32(dNode,
			"oplus,mic-gnd-swh-2nd-level", &switch_priv->mic_gnd_swh_2nd_level);
	if (ret) {
		pr_info("%s: read prop oplus,mic-gnd-swh-2nd-level fail\n", __func__);
		switch_priv->mic_gnd_swh_2nd_level = 0;
	} else {
		pr_debug("%s, mic_gnd_swh_2nd_level = %d\n", __func__, switch_priv->mic_gnd_swh_2nd_level);
	}
	gpio_direction_output(switch_priv->mic_gnd_swh_2nd_pin, switch_priv->mic_gnd_swh_2nd_level);//Default low-level

	switch_priv->mic_gnd_status = 0;

	//switch-enable-gpio
	switch_priv->switch_enable_pin = of_get_named_gpio(dNode,
			"oplus,switch-enable-gpio", 0);
	if (!gpio_is_valid(switch_priv->switch_enable_pin)) {
		pr_info("%s: oplus, switch-enable-gpio in dt node is missing\n", __func__);
	} else {
		ret = gpio_request(switch_priv->switch_enable_pin, "switch_enable_pin");
		if (ret) {
			pr_err("%s exit_switch_enable_gpio_request_failed \n", __func__);
			goto exit_switch_enable_gpio_request_failed;
		}
	}
	ret = of_property_read_u32(dNode,
			"oplus,switch-enable-level", &switch_priv->switch_enable_level);
	if (ret) {
		pr_info("%s: read prop oplus,switch-enable-level fail\n", __func__);
		switch_priv->switch_enable_level = 0;
	} else {
		pr_debug("%s, switch_enable_level = %d\n", __func__, switch_priv->switch_enable_level);
	}
	gpio_direction_output(switch_priv->switch_enable_pin, !switch_priv->switch_enable_level);//Default high-level

	pr_info("%s exit\n", __func__);

	return 0;
exit_switch_enable_gpio_request_failed:
	if (gpio_is_valid(switch_priv->mic_gnd_swh_2nd_pin)) {
		gpio_free(switch_priv->mic_gnd_swh_2nd_pin);
	}
exit_mic_gnd_swh_2nd_gpio_request_failed:
	if (gpio_is_valid(switch_priv->mic_gnd_swh_pin)) {
		gpio_free(switch_priv->mic_gnd_swh_pin);
	}
exit_mic_gnd_swh_gpio_request_failed:
	if (gpio_is_valid(switch_priv->lr_sel_pin)) {
		gpio_free(switch_priv->lr_sel_pin);
	}
exit_lr_sel_gpio_request_failed:
	if (gpio_is_valid(switch_priv->hs_det_pin)) {
		gpio_free(switch_priv->hs_det_pin);
	}
exit_hp_det_gpio_request_failed:
	return ret;
}

static void oplus_discrete_typec_switch_usbc_analog_work_fn(struct work_struct *work)
{
	struct typec_switch_priv *switch_priv =
		container_of(work, struct typec_switch_priv, usbc_analog_work);

	if (!switch_priv) {
		pr_err("%s: switch_priv is NULL\n", __func__);
		return;
	}
	oplus_discrete_typec_switch_usbc_analog_setup_switches(switch_priv);
}

static void hp_work_callback(struct work_struct *work)
{
	struct typec_switch_priv *switch_priv = g_typec_switch_priv;

	if (switch_priv->plug_state == true) {
		pr_info("%s: headphone is inserted already\n", __func__);
		return;
	}

	if (tcpm_inquire_typec_attach_state(switch_priv->tcpc_dev) == TYPEC_ATTACHED_AUDIO) {
		pr_info("%s: TYPEC_ATTACHED_AUDIO is inserted\n", __func__);
		switch_priv->plug_state = true;
		cancel_work_sync(&switch_priv->usbc_analog_work);
		schedule_work(&switch_priv->usbc_analog_work);
	} else if (tcpm_inquire_typec_attach_state(switch_priv->tcpc_dev) == TYPEC_ATTACHED_SNK) {
		pr_info("%s: SNK has been inserted\n", __func__);
	} else {
		pr_info("%s: TYPEC_ATTACHED_AUDIO is not inserted\n", __func__);
	}
}

static int oplus_discrete_typec_switch_probe(struct platform_device *pdev)
{
	struct typec_switch_priv *switch_priv;
	int ret = 0;

	switch_priv = devm_kzalloc(&pdev->dev, sizeof(*switch_priv),
				GFP_KERNEL);
	if (!switch_priv) {
		pr_err("%s, alloc memory failed!", __func__);
		return -ENOMEM;
	}

	switch_priv->dev = &pdev->dev;
	ret = oplus_discrete_typec_switch_parse_dt(switch_priv, &pdev->dev);
	if (ret != 0) {
		dev_err(switch_priv->dev,"parse dt failed");
		goto parse_dt_failed;
	}

	switch_priv->plug_state = false;
	switch_priv->charger_plugged = 0;
	switch_priv->tcpc_dev = tcpc_dev_get_by_name("type_c_port0");
	if (!switch_priv->tcpc_dev) {
		pr_err("%s get tcpc device type_c_port0 fail\n", __func__);
		ret = -EPROBE_DEFER;
		goto err_data;
	}

	switch_priv->pd_nb.notifier_call = oplus_discrete_typec_switch_usbc_event_changed;
	switch_priv->pd_nb.priority = 0;
	ret = register_tcp_dev_notifier(switch_priv->tcpc_dev, &switch_priv->pd_nb, TCP_NOTIFY_TYPE_ALL);
	if (ret < 0) {
		pr_err("%s: register tcpc notifer fail\n", __func__);
		goto err_data;
	}

	mutex_init(&switch_priv->notification_lock);

	INIT_WORK(&switch_priv->usbc_analog_work, oplus_discrete_typec_switch_usbc_analog_work_fn);

	switch_priv->typec_switch_notifier.rwsem =
		(struct rw_semaphore)__RWSEM_INITIALIZER
		((switch_priv->typec_switch_notifier).rwsem);
	switch_priv->typec_switch_notifier.head = NULL;

	platform_set_drvdata(pdev, switch_priv);
	g_typec_switch_priv = switch_priv;

	INIT_DELAYED_WORK(&switch_priv->hp_work, hp_work_callback);
	schedule_delayed_work(&switch_priv->hp_work, msecs_to_jiffies(4000));

	dev_info(switch_priv->dev, "probed successfully!\n");

	return 0;
parse_dt_failed:
err_data:
	if (switch_priv) {
		pr_info("%s: devm_kfree swh_priv\n", __func__);
		devm_kfree(&pdev->dev, switch_priv);
		platform_set_drvdata(pdev, NULL);
	}

	return ret;
}

static int oplus_discrete_typec_switch_remove(struct platform_device *pdev)
{
	struct  typec_switch_priv *switch_priv = platform_get_drvdata(pdev);

	pr_info("%s enter\n", __func__);

	if (!switch_priv) {
		pr_err("%s switch_priv is NULL!", __func__);
		return -EINVAL;
	}

	cancel_delayed_work(&switch_priv->hp_work);
	cancel_work_sync(&switch_priv->usbc_analog_work);

	mutex_destroy(&switch_priv->notification_lock);

	unregister_tcp_dev_notifier(switch_priv->tcpc_dev, &switch_priv->pd_nb, TCP_NOTIFY_TYPE_ALL);
	if (gpio_is_valid(switch_priv->hs_det_pin)) {
		gpio_free(switch_priv->hs_det_pin);
	}
	if (gpio_is_valid(switch_priv->lr_sel_pin)) {
		gpio_free(switch_priv->lr_sel_pin);
	}
	if (gpio_is_valid(switch_priv->mic_gnd_swh_pin)) {
		gpio_free(switch_priv->mic_gnd_swh_pin);
	}
	if (gpio_is_valid(switch_priv->mic_gnd_swh_2nd_pin)) {
		gpio_free(switch_priv->mic_gnd_swh_2nd_pin);
	}
	if (gpio_is_valid(switch_priv->switch_enable_pin)) {
		gpio_free(switch_priv->switch_enable_pin);
	}
	devm_kfree(&pdev->dev, switch_priv);
	g_typec_switch_priv = NULL;
	platform_set_drvdata(pdev, NULL);

	return 0;
}

static void oplus_discrete_typec_switch_shutdown(struct platform_device *pdev) {
	struct typec_switch_priv *switch_priv = platform_get_drvdata(pdev);

	if (!switch_priv) {
		return;
	}
	//set gpio usb mode
	if ((gpio_is_valid(switch_priv->mic_gnd_swh_pin)) && (gpio_is_valid(switch_priv->mic_gnd_swh_2nd_pin))) {
		pr_info("%s: set mic_gnd_swh_pin \n", __func__);
		gpio_direction_output(switch_priv->mic_gnd_swh_pin, !switch_priv->mic_gnd_swh_level);
		gpio_direction_output(switch_priv->mic_gnd_swh_2nd_pin, switch_priv->mic_gnd_swh_2nd_level);
		switch_priv->mic_gnd_status = 0;
	}
	if (gpio_is_valid(switch_priv->lr_sel_pin)) {
		pr_info("%s: disconnect LR.\n", __func__);
		gpio_direction_output(switch_priv->lr_sel_pin, !switch_priv->lr_sel_level);
	}
	if (gpio_is_valid(switch_priv->switch_enable_pin)) {
		pr_info("%s: switch disable\n", __func__);
		gpio_direction_output(switch_priv->switch_enable_pin, !switch_priv->switch_enable_level);
	}
	return;
}

static const struct of_device_id oplus_discrete_typec_switch_of_match[] = {
	{.compatible = "oplus,discrete_typec_switch"},
	{ }
};

static struct platform_driver oplus_discrete_typec_switch_driver = {
	.probe          = oplus_discrete_typec_switch_probe,
	.remove         = oplus_discrete_typec_switch_remove,
	.shutdown       = oplus_discrete_typec_switch_shutdown,
	.driver         = {
		.name   = OPLUS_DISCRETE_TYPEC_SWITCH_DRIVER_NAME,
		.owner  = THIS_MODULE,
		.of_match_table = oplus_discrete_typec_switch_of_match,
	},
};

static int __init oplus_discrete_typec_switch_init(void)
{
	pr_info("%s: enter\n", __func__);
	return platform_driver_register(&oplus_discrete_typec_switch_driver);
}
module_init(oplus_discrete_typec_switch_init);

static void __exit oplus_discrete_typec_switch_exit(void)
{
	pr_info("%s: enter\n", __func__);
	platform_driver_unregister(&oplus_discrete_typec_switch_driver);
}
module_exit(oplus_discrete_typec_switch_exit);

MODULE_DESCRIPTION("oplus discrete typec switch driver");
MODULE_LICENSE("GPL v2");