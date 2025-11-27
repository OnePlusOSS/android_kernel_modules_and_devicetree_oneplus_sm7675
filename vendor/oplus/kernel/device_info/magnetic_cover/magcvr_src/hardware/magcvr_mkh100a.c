/***
  driver for mkh100a
**/

#include "../../magcvr_include/hardware/mkh100a_include.h"

static int mkh100a_get_data(void *chip_data, long *value)
{
	struct mkh100a_chip_info *chip_info = NULL;
	int gpio_value = 0;

	if (chip_data == NULL) {
		MAG_CVR_ERR("g_chip NULL \n");
		return -EINVAL;
	} else {
		MAG_CVR_LOG("called");
		chip_info = (struct mkh100a_chip_info *)chip_data;
	}

	if (chip_info->magcvr_info == NULL) {
		MAG_CVR_LOG("first get gpio irq");
		gpio_value = gpio_get_value(chip_info->irq_gpio);
	} else {
		gpio_value = gpio_get_value(chip_info->magcvr_info->irq_gpio);
	}

	if (gpio_value > 0) {
		*value = SET_FAR;
	} else {
		*value = SET_NEAR;
	}

	chip_info->prev_value = gpio_value;

	MAG_CVR_LOG("get gpio:%d", gpio_value);

	return 0;
}

static struct oplus_magnetic_cover_operations mkh100a_dev_ops = {
	.get_data = mkh100a_get_data,
};

static int magcvr_mkh100a_probe(struct platform_device *pdev)
{
	struct magnetic_cover_info *magcvr_info = NULL;
	struct mkh100a_chip_info *mkh100a_info = NULL;
	int ret = 0;

	MAG_CVR_LOG("call \n");
	// mkh100a private infomation
	mkh100a_info = kzalloc(sizeof(struct mkh100a_chip_info), GFP_KERNEL);
	if (mkh100a_info == NULL) {
		MAG_CVR_ERR("chip info kzalloc error\n");
		return -ENOMEM;
	}

	// abstract platform infomation
	magcvr_info = alloc_for_magcvr();
	if (magcvr_info == NULL) {
		MAG_CVR_ERR("alloc_for_magcvr error\n");
		magcvr_kfree((void **)&mkh100a_info);
		return -ENOMEM;
	}

	ret= platform_get_irq(pdev, 0);
	if (ret < 0) {
		MAG_CVR_ERR("get irq failed\n");
		magcvr_kfree((void **)&mkh100a_info);
		kfree(magcvr_info);
		return ret;
	} else {
		magcvr_info->irq = ret;
	}
	MAG_CVR_LOG("get irq is %d\n", mkh100a_info->irq);
	// private info
	magcvr_info->magcvr_dev = &pdev->dev;
	magcvr_info->iic_client = NULL;
	magcvr_info->irq = mkh100a_info->irq;
	// hardware info
	mkh100a_info->dev = &pdev->dev;
	mkh100a_info->irq_gpio = of_get_named_gpio(magcvr_info->magcvr_dev->of_node, M_IRQ, 0);
	// copy info
	magcvr_info->chip_info = mkh100a_info;
	platform_set_drvdata(pdev, magcvr_info);
	magcvr_info->mc_ops = &mkh100a_dev_ops;

	MAG_CVR_LOG("mutex mkh100a init\n");
	mutex_init(&mkh100a_info->data_lock);

	mkh100a_info->magcvr_info = NULL;

	MAG_CVR_LOG("start to abstract init\n");
	ret = magcvr_core_init(magcvr_info);
	if (ret < 0) {
		MAG_CVR_ERR("mkh100a platform init fail\n");
		magcvr_kfree((void **)&mkh100a_info);
		kfree(magcvr_info);
		platform_set_drvdata(pdev, NULL);
		return 0;
	}

	MAG_CVR_LOG("abstract data init success\n");
	// abstract info
	mkh100a_info->magcvr_info = magcvr_info;

	if (ret == INIT_PROBE_ERR) {
		MAG_CVR_LOG("mkh100a_info some err, continue probe\n");
		ret = after_magcvr_core_init(magcvr_info);
	} else {
		MAG_CVR_LOG("probe end\n");
	}

	return 0;
}

static int magcvr_mkh100a_remove(struct platform_device *pdev)
{
	struct magnetic_cover_info *magcvr_info = platform_get_drvdata(pdev);
	struct mkh100a_chip_info *mkh100a_info = NULL;

	if ((magcvr_info == NULL) || (magcvr_info->chip_info == NULL)) {
		MAG_CVR_ERR("magcvr_info == NULL\n");
		goto EXIT;
	}

	mkh100a_info = (struct mkh100a_chip_info*)magcvr_info->chip_info;

	MAG_CVR_LOG("call\n");

	unregister_magcvr_core(magcvr_info);
	magcvr_kfree((void **)&mkh100a_info);
	platform_set_drvdata(pdev, NULL);

EXIT:
	return 0;
}

static int magcvr_mkh100a_suspend(struct device *dev)
{
	MAG_CVR_LOG("called\n");
	return 0;
}

static int magcvr_mkh100a_resume(struct device *dev)
{
	MAG_CVR_LOG("called\n");
	return 0;
}

static const struct dev_pm_ops magcvr_mkh100a_pm_ops = {
	.suspend = magcvr_mkh100a_suspend,
	.resume = magcvr_mkh100a_resume,
};

static const struct of_device_id magcvr_mkh100a_match[] = {
	{ .compatible = "oplus,magcvr_mkh100a"},
	{},
};

static struct platform_driver magcvr_mkh100a_driver = {
	.driver = {
		.name = "oplus,magcvr_mkh100a",
		.of_match_table =  magcvr_mkh100a_match,
		.pm = &magcvr_mkh100a_pm_ops,
	},
	.probe = magcvr_mkh100a_probe,
	.remove = magcvr_mkh100a_remove,
};

static int __init magcvr_mkh100a_init(void)
{
	int ret = 0;
	MAG_CVR_LOG("call\n");
	ret = platform_driver_register(&magcvr_mkh100a_driver);
	if (ret != 0) {
		MAG_CVR_ERR("devinfo_platform_driver failed, %d\n", ret);
	}
	return 0;
}

device_initcall(magcvr_mkh100a_init);

MODULE_DESCRIPTION("Magcvr ak09973 Driver");
MODULE_LICENSE("GPL");
