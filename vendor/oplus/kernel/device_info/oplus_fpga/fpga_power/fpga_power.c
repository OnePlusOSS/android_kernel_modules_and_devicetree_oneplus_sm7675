#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/i2c.h>
#include <linux/mutex.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>

#include "fpga_power.h"

static int fpga_power_probe(struct platform_device *pdev)
{
#if 0
	int rc;
	struct fpga_power_data *pdata;
	pdata = devm_kzalloc(&pdev->dev, sizeof(struct fpga_power_data), GFP_KERNEL);
	if (!pdata) {
		return -ENOMEM;
	}

	pdata->clk_switch_gpio = of_get_named_gpio(pdev->dev.of_node, "clk-switch-gpio", 0);
	rc = gpio_is_valid(pdata->clk_switch_gpio);
	if (!rc) {
		FPGA_ERR("gpio_is_valid fail clk_switch_gpio[%d]\n", pdata->clk_switch_gpio);
		goto err;
	} else {
		rc = gpio_request(pdata->clk_switch_gpio, "charging-switch1-gpio");
		if (rc) {
			FPGA_ERR("unable to request gpio [%d]\n", pdata->clk_switch_gpio);
		} else {
			gpio_direction_output(pdata->clk_switch_gpio, 0);
		}
	}

	pdata->sleep_en_gpio = of_get_named_gpio(pdev->dev.of_node, "sleep-en-gpio", 0);
	rc = gpio_is_valid(pdata->sleep_en_gpio);
	if (!rc) {
		FPGA_ERR("gpio_is_valid fail sleep_en_gpio[%d]\n", pdata->sleep_en_gpio);
		goto err;
	} else {
		rc = gpio_request(pdata->sleep_en_gpio, "charging-switch1-gpio");
		if (rc) {
			FPGA_ERR("unable to request gpio [%d]\n", pdata->sleep_en_gpio);
		} else {
			gpio_direction_output(pdata->sleep_en_gpio, 0);
		}
	}
	dev_set_drvdata(&pdev->dev, pdata);

	pdata->pinctrl = devm_pinctrl_get(&pdev->dev);
	if (IS_ERR_OR_NULL(pdata->pinctrl)) {
		FPGA_ERR("get pinctrl fail\n");
		return -EINVAL;
	}

	pdata->fpga_ative = pinctrl_lookup_state(pdata->pinctrl, "fpga_ative");
	if (IS_ERR_OR_NULL(pdata->fpga_ative)) {
		FPGA_ERR("Failed to get the state pinctrl handle\n");
		return -EINVAL;
	}

	pdata->fpga_sleep = pinctrl_lookup_state(pdata->pinctrl, "fpga_sleep");
	if (IS_ERR_OR_NULL(pdata->fpga_sleep)) {
		FPGA_ERR("Failed to get the state pinctrl handle\n");
		return -EINVAL;
	}

	pdata->fpga_clk_switch_ative = pinctrl_lookup_state(pdata->pinctrl, "fpga_clk_switch_ative");
	if (IS_ERR_OR_NULL(pdata->fpga_clk_switch_ative)) {
		FPGA_ERR("Failed to get the state pinctrl handle\n");
		return -EINVAL;
	}

	pdata->fpga_clk_switch_sleep = pinctrl_lookup_state(pdata->pinctrl, "fpga_clk_switch_sleep");
	if (IS_ERR_OR_NULL(pdata->fpga_clk_switch_sleep)) {
		FPGA_ERR("Failed to get the state pinctrl handle\n");
		return -EINVAL;
	}
	pinctrl_select_state(pdata->pinctrl, pdata->fpga_ative);
	pinctrl_select_state(pdata->pinctrl, pdata->fpga_clk_switch_ative);

	FPGA_INFO("end\n");
	return 0;
err:
	kfree(pdata);
	return rc;
#endif

	return 0;
}

int fpga_power_remove(struct platform_device *pdev)
{
	return 0;
}

int fpga_power_suspend(struct device *dev)
{
	/*
	struct fpga_power_data *pdata = dev_get_drvdata(dev);
	gpio_direction_output(pdata->clk_switch_gpio, 1);
	gpio_direction_output(pdata->sleep_en_gpio, 1);
	FPGA_INFO("start\n");*/
	return 0;
}

int fpga_power_resume(struct device *dev)
{
	/*

	struct fpga_power_data *pdata = dev_get_drvdata(dev);
	gpio_direction_output(pdata->clk_switch_gpio, 0);
	gpio_direction_output(pdata->sleep_en_gpio, 0);
	FPGA_INFO("start\n");*/
	return 0;
}

static const struct dev_pm_ops fpga_power_dev_pm_ops = {
	.suspend_late = fpga_power_suspend,
	.resume_early = fpga_power_resume,
};


static const struct of_device_id fpga_power_match_table[] = {
	{ .compatible = "oplus,fpga_power" },
	{}
};

static struct platform_driver fpga_power_wdt_driver = {
	.probe     = fpga_power_probe,
	//    .remove = fpga_power_remove,
	.driver = {
		.name = "fpga_power",
		.pm = &fpga_power_dev_pm_ops,
		.of_match_table = fpga_power_match_table,
	},
};

static int __init fpga_power_init(void)
{
	FPGA_INFO("start\n");
	return platform_driver_register(&fpga_power_wdt_driver);
}

static void __exit fpga_power_exit(void)
{
	FPGA_INFO("start\n");
	platform_driver_unregister(&fpga_power_wdt_driver);
}

module_init(fpga_power_init);
module_exit(fpga_power_exit);

MODULE_DESCRIPTION("FPGA POWER driver");
MODULE_LICENSE("GPL v2");

