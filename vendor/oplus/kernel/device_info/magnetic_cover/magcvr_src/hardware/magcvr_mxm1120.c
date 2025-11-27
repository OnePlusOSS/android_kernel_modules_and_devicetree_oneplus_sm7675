/***
  driver for mxm1120
**/
#include "../../magcvr_include/hardware/mxm1120_include.h"

static int m1120_i2c_read_block(struct mxm1120_chip_info *chip_info,
                                u8 addr,
                                u8 *data,
                                u8 len)
{
	u8 reg_addr = addr;
	int ret = 0;
	int retry = 0;
	struct i2c_client *client = NULL;
	struct i2c_msg msgs[2] = {{0}, {0}};

	if (chip_info == NULL) {
		MAG_CVR_ERR("chip_info == NULL\n");
		return -EINVAL;
	}

	if (len >= M1120_I2C_BUF_SIZE) {
		MAG_CVR_ERR(" length %d exceeds %d\n", len, M1120_I2C_BUF_SIZE);
		return -EINVAL;
	}

	mutex_lock(&chip_info->data_lock);

	client = chip_info->client;

	msgs[0].addr = client->addr;
	msgs[0].flags = 0;
	msgs[0].len = 1;
	msgs[0].buf = &reg_addr;
	msgs[1].addr = client->addr;
	msgs[1].flags = I2C_M_RD;
	msgs[1].len = len;
	msgs[1].buf = data;

	for (retry = 0; retry < MAX_I2C_RETRY_TIME; retry++) {
		ret = i2c_transfer(client->adapter, msgs, (sizeof(msgs) / sizeof(msgs[0])));
		MAG_CVR_DEBUG("----magnetic_cover_i2c_read_block: (0x%02X %p %d)\n",addr, data, len);
		/* dump_stack();*/
		if (ret < 0) {
			MAG_CVR_ERR("i2c_transfer error: (%d %p %d) %d\n", addr, data, len, ret);
			msleep(20);
		} else {
			ret = 0;
			break;
		}
	}

	if (chip_info->magcvr_info != NULL) {
		if (ret < 0 || fault_injection_handle(chip_info->magcvr_info, OPT_IIC_READ)) {
			chip_info->magcvr_info->iic_read_err_cnt++;
			MAG_CVR_ERR("I2C read over retry limit, healthCnt:%d\n",
                chip_info->magcvr_info->iic_read_err_cnt);
		}
	}

	if (retry == MAX_I2C_RETRY_TIME)
		ret = -EIO;

	mutex_unlock(&chip_info->data_lock);

	return ret;
}

static void m1120_short_to_2byte(struct mxm1120_chip_info *chip_info,
                                 short x,
                                 u8 *hbyte,
                                 u8 *lbyte)
{
	if (!chip_info) {
		MAG_CVR_ERR("chip_info == NULL\n");
		return;
	}

	if ((chip_info->reg.map.opf & M1120_VAL_OPF_BIT_8) == M1120_VAL_OPF_BIT_8) {
		/* 8 bit resolution */
		if (x < -128)
			x = -128;
		else if (x > 127)
			x = 127;
		if (x >= 0)
			*lbyte = x & 0x7F;
		else
			*lbyte = ((0x80 - (x * (-1))) & 0x7F) | 0x80;
		*hbyte = 0x00;
	} else {
		/* 10 bit resolution */
		if (x < -512)
			x = -512;
		else if (x > 511)
			x = 511;
		if (x >= 0) {
			*lbyte = x & 0xFF;
			*hbyte = (((x & 0x100) >> 8) & 0x01) << 6;
		} else {
			*lbyte = (0x0200 - (x*(-1))) & 0xFF;
			*hbyte = ((((0x0200 - (x*(-1))) & 0x100) >> 8) << 6) | 0x80;
		}
	}
}

static short m1120_2byte_to_short(struct mxm1120_chip_info *chip_info,
                                  u8 hbyte,
                                  u8 lbyte)
{
	short x = 0;

	if (!chip_info) {
		MAG_CVR_ERR("chip_info == NULL\n");
		return -EINVAL;
	}

	if ((chip_info->reg.map.opf & M1120_VAL_OPF_BIT_8) == M1120_VAL_OPF_BIT_8) {
		MAG_CVR_DEBUG("08bit sample\n");
		/* 8 bit resolution */
		x = lbyte & 0x7F;
		if (lbyte & 0x80)
			x -= 0x80;
	} else {
		/* 10 bit resolution */
		MAG_CVR_DEBUG("10bit sample\n");
		x = (((hbyte & 0x40) >> 6) << 8) | lbyte;
		if (hbyte & 0x80)
			x -= 0x200;
	}
	return x;
}

static int m1120_i2c_write_block(struct mxm1120_chip_info *chip_info,
                                 u8 addr,
                                 u8 *data,
                                 u8 len)
{
	int ret   = 0;
	int retry = 0;
	int idx   = 0;
	int num   = 0;
	char buf[M1120_I2C_BUF_SIZE] = {0};
	struct i2c_client *client = NULL;

	if (chip_info == NULL) {
		MAG_CVR_ERR("chip_info == NULL\n");
		return -EINVAL;
	}

	if (len >= M1120_I2C_BUF_SIZE) {
		MAG_CVR_DEBUG(" length %d exceeds %d\n", len, M1120_I2C_BUF_SIZE);
		return -EINVAL;
	}

	client = chip_info->client;

	mutex_lock(&chip_info->data_lock);

	buf[num++] = addr;
	for (idx = 0; idx < len; idx++) {
		buf[num++] = data[idx];
	}

	for (retry = 0; retry < MAX_I2C_RETRY_TIME; retry++) {
		/*MAG_CVR_LOG("----magnetic_cover_i2c_write_block: (0x%02X %p %d)\n",addr, data, len);
		/dump_stack();*/
		ret = i2c_master_send(client, buf, num);
		if (ret < 0) {
			MAG_CVR_ERR("send command error!! [ret:%d][retry:%d]\n", ret, retry);
			msleep(20);
		} else {
			break;
		}
	}

	if (chip_info->magcvr_info != NULL) {
		if (retry == MAX_I2C_RETRY_TIME || fault_injection_handle(chip_info->magcvr_info, OPT_IIC_WRITE)) {
			chip_info->magcvr_info->iic_write_err_cnt++;
			MAG_CVR_ERR("I2C write over retry limit, healthCnt:%d\n",
                chip_info->magcvr_info->iic_write_err_cnt);
		}
	}

	if (retry == MAX_I2C_RETRY_TIME)
		ret = -EIO;

	/*store reg written*/
	if (len == 1 && ret > 0) {
		switch (addr) {
		case M1120_REG_PERSINT:
			chip_info->reg.map.persint = data[0];
			break;
		case M1120_REG_INTSRS:
			chip_info->reg.map.intsrs = data[0];
			break;
		case M1120_REG_LTHL:
			chip_info->reg.map.lthl = data[0];
			break;
		case M1120_REG_LTHH:
			chip_info->reg.map.lthh = data[0];
			break;
		case M1120_REG_HTHL:
			chip_info->reg.map.hthl = data[0];
			break;
		case M1120_REG_HTHH:
			chip_info->reg.map.hthh = data[0];
			break;
		case M1120_REG_I2CDIS:
			chip_info->reg.map.i2cdis = data[0];
			break;
		case M1120_REG_SRST:
			chip_info->reg.map.srst = data[0];
			break;
		case M1120_REG_OPF:
			chip_info->reg.map.opf = data[0];
			break;
		}
	}

	mutex_unlock(&chip_info->data_lock);
	return ret;
}

static int m1120_clear_interrupt(struct mxm1120_chip_info *chip_info)
{
	int ret = 0;
	u8 data = 0x00;

	if (!chip_info) {
		MAG_CVR_ERR("chip_info is null\n");
		ret = -EINVAL;
		return ret;
	}

	data = chip_info->reg.map.persint | 0x01;
	ret  = m1120_i2c_write_block(chip_info, M1120_REG_PERSINT, &data, 1);
	return ret;
}

static int m1120_update_threshold(void *chip_data,
            int posi, int high_thd, int low_thd)
{
	u8 lthh, lthl, hthh, hthl;
	struct mxm1120_chip_info *chip_info = NULL;
	int ret = 0;
	short lowthd  = M1120_DEF_LOW;
	short highthd = M1120_DEF_HIGH;

	if (chip_data == NULL) {
		MAG_CVR_ERR("chip_data == NULL\n");
		return -EINVAL;
	} else {
		MAG_CVR_LOG("call\n");
		chip_info = (struct mxm1120_chip_info *)chip_data;
	}

	highthd = m_int2short(high_thd);
	lowthd  = m_int2short(low_thd);

	if (chip_info->reg.map.intsrs & M1120_DETECTION_MODE_INTERRUPT) {
		MAG_CVR_LOG("[lowthd=%d, highthd=%d]\n", lowthd, highthd);
		m1120_short_to_2byte(chip_info, highthd, &hthh, &hthl);
		m1120_short_to_2byte(chip_info, lowthd, &lthh, &lthl);
		ret |= m1120_i2c_write_block(chip_info, M1120_REG_HTHH, &hthh, 1);
		ret |= m1120_i2c_write_block(chip_info, M1120_REG_HTHL, &hthl, 1);
		ret |= m1120_i2c_write_block(chip_info, M1120_REG_LTHH, &lthh, 1);
		ret |= m1120_i2c_write_block(chip_info, M1120_REG_LTHL, &lthl, 1);
	}

	if (ret < 0) {
		MAG_CVR_ERR("hallthreshold:fail %d\n", ret);
		return ret;
	} else {
		ret = m1120_clear_interrupt(chip_info);
	}
	return ret;
}

static void m1120_dump_reg(struct seq_file *s, void *chip_data)
{
	int i, err;
	u8 val;
	u8 buffer[512] = {0};
	u8 _buf[20] = {0};

	struct mxm1120_chip_info *chip_info = NULL;
	if (chip_data == NULL) {
		MAG_CVR_ERR("chip_data == NULL");
		return;
	} else {
		chip_info = (struct mxm1120_chip_info *)chip_data;
		MAG_CVR_DEBUG("call ");
	}

	for (i = 0; i <= 0x12; i++) {
		memset(_buf, 0, sizeof(_buf));
		err = m1120_i2c_read_block(chip_info, i, &val, 1);
		if (err < 0) {
			seq_printf(s, "read reg error!\n");
			return;
		}
		snprintf(_buf, sizeof(_buf), "reg 0x%x:0x%x\n", i, val);
		strcat(buffer, _buf);
	}
	seq_printf(s, "%s", buffer);
}

static int m1120_get_data(void *chip_data, long *data)
{
	struct mxm1120_chip_info *chip_info = NULL;

	int ret = 0;
	u8 buf[3] = {0};
	short value = 0;

	if (chip_data == NULL) {
		MAG_CVR_ERR("m1120_get_data == NULL");
		return -EINVAL;
	} else {
		MAG_CVR_LOG("called");
		chip_info = (struct mxm1120_chip_info *)chip_data;
	}

	ret = m1120_i2c_read_block(chip_info, M1120_REG_ST1, buf, sizeof(buf));
	if (ret < 0) {
		MAG_CVR_ERR("fail %d\n", ret);
		return ret;
	}

	if (buf[0] & 0x01) {
		MAG_CVR_DEBUG("buf[0]:%d == 0x01:%d\n", buf[0], ret);
		value = m1120_2byte_to_short(chip_info, buf[2], buf[1]);
	} else {
		MAG_CVR_DEBUG("buf[0]:%d != 0x01:%d\n", buf[0], ret);
		return ret;
	}

	MAG_CVR_LOG("value is %d", value);
	*data = value;
	return 0;
}

static int m1120_set_operation_mode(struct mxm1120_chip_info *chip_info, int mode)
{
	u8 opf = 0;
	int ret = -1;

	if (!chip_info) {
		MAG_CVR_ERR("chip_info is null\n");
		ret = -EINVAL;
		return ret;
	}

	opf = chip_info->reg.map.opf;

	switch (mode) {
	case OPERATION_MODE_POWERDOWN_M:
		opf &= (0xFF - M1120_VAL_OPF_HSSON_ON);
		ret = m1120_i2c_write_block(chip_info, M1120_REG_OPF, &opf, 1);
		MAG_CVR_DEBUG("operation mode was OPERATION_MODE_POWERDOWN_M:%d,opf:0x%2x",
            OPERATION_MODE_POWERDOWN_M,
            opf);
		break;
	case OPERATION_MODE_MEASUREMENT_M:
		opf &= (0xFF - M1120_VAL_OPF_EFRD_ON);
		opf |= M1120_VAL_OPF_HSSON_ON;
		ret = m1120_i2c_write_block(chip_info, M1120_REG_OPF, &opf, 1);
		MAG_CVR_DEBUG("operation mode was OPERATION_MODE_MEASUREMENT_M:%d,opf:0x%2x",
            OPERATION_MODE_MEASUREMENT_M,
            opf);
		break;
	case OPERATION_MODE_FUSEROMACCESS_M:
		opf |= M1120_VAL_OPF_EFRD_ON;
		opf |= M1120_VAL_OPF_HSSON_ON;
		ret = m1120_i2c_write_block(chip_info, M1120_REG_OPF, &opf, 1);
		MAG_CVR_DEBUG("operation mode was OPERATION_MODE_FUSEROMACCESS_M:%d,opf:0x%2x",
            OPERATION_MODE_FUSEROMACCESS_M,
            opf);
		break;
	}

	MAG_CVR_LOG("opf = 0x%x\n", opf);
	return ret;
}

static int m1120_reset_device(struct mxm1120_chip_info *chip_info)
{
	int ret = 0;
	u8  id = 0xFF, data = 0x00;

	if ((chip_info == NULL) || (chip_info->client == NULL))
		return -1;

	/*(1) sw reset*/
	data = M1120_VAL_SRST_RESET;
	ret = m1120_i2c_write_block(chip_info, M1120_REG_SRST, &data, 1);
	if (ret < 0) {
		MAG_CVR_ERR("sw-reset was failed(%d)", ret);
		return ret;
	} else {
		MAG_CVR_LOG("sw-reset was success(%d)", ret);
	}
	msleep(10);

	/*(2) check id*/
	ret = m1120_i2c_read_block(chip_info, M1120_REG_DID, &id, 1);
	if (ret < 0) {
		MAG_CVR_ERR("check id read fail. %d", ret);
		return ret;
	}

	if (id != M1120_VAL_DID) {
		MAG_CVR_ERR("current device id(0x%02X) is not M1120 device id(0x%02X)",
            id, M1120_VAL_DID);
		return -1;
	} else {
		MAG_CVR_LOG("current device id(0x%02X) match M1120 device id(0x%02X)",
            id, M1120_VAL_DID);
	}

	/*(3) init variables*/
	/*(3-1) persint*/
	data = M1120_PERSISTENCE_COUNT;
	ret =   m1120_i2c_write_block(chip_info, M1120_REG_PERSINT, &data, 1);
	if (ret < 0) {
		MAG_CVR_ERR("write M1120_REG_PERSINT error, data : %d", data);
		return ret;
	} else {
		MAG_CVR_LOG("write M1120_REG_PERSIN success, data : %d", data);
	}

	/* (3-2) intsrs */
	data = M1120_DETECTION_MODE | M1120_SENSITIVITY_TYPE;
	if (data & M1120_DETECTION_MODE_INTERRUPT)
		data |= M1120_INTERRUPT_TYPE;

	ret = m1120_i2c_write_block(chip_info, M1120_REG_INTSRS, &data, 1);
	if (ret < 0) {
		MAG_CVR_ERR("write M1120_REG_INTSRS error, data : %d", data);
		return ret;
	} else {
		MAG_CVR_LOG("write M1120_REG_INTSRS success, data : %d", data);
	}

	/*(3-3) opf*/
	data = M1120_OPERATION_FREQUENCY | M1120_OPERATION_RESOLUTION;
	ret = m1120_i2c_write_block(chip_info, M1120_REG_OPF, &data, 1);
	if (ret < 0) {
		MAG_CVR_ERR("write M1120_REG_OPF error, data : %d", data);
		return ret;
	} else {
		MAG_CVR_LOG("write M1120_REG_OPF success, data : %d", data);
	}

	/*(5) set power-on mode*/
	ret = m1120_set_operation_mode(chip_info, OPERATION_MODE_MEASUREMENT_M);
	if (ret < 0) {
		MAG_CVR_ERR("m1120_set_detection_mode was failed(%d)", ret);
		return ret;
	} else {
		MAG_CVR_LOG("m1120_set_detection_mode was success(%d)", ret);
	}

	return ret;
}

static int mxm1120_chip_init(void *chip_data)
{
	int ret = 0;
	struct mxm1120_chip_info *chip_info = (struct mxm1120_chip_info *)chip_data;

	MAG_CVR_LOG("called");

	if (!chip_info) {
		MAG_CVR_ERR("chip_info is null\n");
		ret = -EINVAL;
		return ret;
	}

	chip_info->last_data = 0;
	chip_info->thrhigh = M1120_DETECT_RANGE_HIGH;
	chip_info->thrlow = M1120_DETECT_RANGE_LOW;

	ret = m1120_reset_device(chip_info);
	if (ret < 0) {
		MAG_CVR_ERR("m1120_reset_device was failed (%d)", ret);
		return ret;
	}

	MAG_CVR_DEBUG("success !");
	return ret;
}

static struct oplus_magnetic_cover_operations mxm1120_dev_ops = {
	.chip_init = mxm1120_chip_init,
	.get_data = m1120_get_data,
	.update_threshold = m1120_update_threshold,
	.dump_regsiter = m1120_dump_reg,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int magcvr_mxm1120_probe(struct i2c_client *client)
#else
static int magcvr_mxm1120_probe(struct i2c_client *client, const struct i2c_device_id *id)
#endif
{

	int ret = 0;
	struct magnetic_cover_info *magcvr_info = NULL;
	struct mxm1120_chip_info *mxm1120_info = NULL;

	MAG_CVR_LOG(" call \n");
	// mxm1120 private infomation
	mxm1120_info = kzalloc(sizeof(struct mxm1120_chip_info), GFP_KERNEL);
	if (mxm1120_info == NULL) {
		MAG_CVR_ERR("GT:chip info kzalloc error\n");
		ret = -ENOMEM;
		return ret;
	}

	// abstract platform infomation
	magcvr_info = alloc_for_magcvr();
	if (magcvr_info == NULL) {
		MAG_CVR_ERR("GT:chip info kzalloc error\n");
		magcvr_kfree((void **)&mxm1120_info);
		return -ENOMEM;
	}

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		MAG_CVR_ERR("mxm1120 i2c unsupported\n");
		magcvr_kfree((void **)&mxm1120_info);
		kfree(magcvr_info);
		return 0;
	}

	// private info
	magcvr_info->magcvr_dev = &client->dev;
	magcvr_info->iic_client = client;
	magcvr_info->irq = client->irq;
	// hardware info
	mxm1120_info->client = client;
	mxm1120_info->irq    = client->irq;
	// copy info
	magcvr_info->chip_info = mxm1120_info;
	i2c_set_clientdata(client, magcvr_info);
	magcvr_info->mc_ops = &mxm1120_dev_ops;

	MAG_CVR_DEBUG("mutex mxm1120 init\n");
	mutex_init(&mxm1120_info->data_lock);
	msleep(10);

	mxm1120_info->magcvr_info = NULL;

	MAG_CVR_DEBUG("start to abstract init\n");
	ret = magcvr_core_init(magcvr_info);
	if (ret < 0) {
		MAG_CVR_ERR("mxm1120 i2c init fail\n");
		magcvr_kfree((void **)&mxm1120_info);
		kfree(magcvr_info);
		i2c_set_clientdata(client, NULL);
		return 0;
	}

	// abstract info
	mxm1120_info->magcvr_info = magcvr_info;

	if (ret == INIT_PROBE_ERR) {
		MAG_CVR_LOG("mxm1120 some err, continue probe\n");
		ret = after_magcvr_core_init(magcvr_info);
	} else {
		MAG_CVR_LOG("probe end\n");
	}

	return 0;
}
/**** probe end   ****/

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
static void magcvr_mxm1120_remove(struct i2c_client *client)
#else
static int magcvr_mxm1120_remove(struct i2c_client *client)
#endif
{
	struct magnetic_cover_info *magcvr_info = i2c_get_clientdata(client);
	struct mxm1120_chip_info *mxm1120_info = NULL;

	MAG_CVR_LOG("call\n");
	if (!magcvr_info) {
		MAG_CVR_ERR("magcvr_info is NULL\n");
		goto EXIT;
	}

	mxm1120_info = (struct mxm1120_chip_info*)magcvr_info->chip_info;
	if (!mxm1120_info) {
		MAG_CVR_ERR("mxm1120_info is NULL\n");
		goto EXIT;
	}

	unregister_magcvr_core(magcvr_info);
	magcvr_kfree((void **)&mxm1120_info);
	i2c_set_clientdata(client, NULL);

EXIT:
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
		return;
#else
		return 0;
#endif

}

static int magcvr_mxm1120_i2c_suspend(struct device *dev)
{
	MAG_CVR_LOG(" is called\n");
	return 0;
}

static int magcvr_mxm1120_i2c_resume(struct device *dev)
{
	MAG_CVR_LOG("is called\n");
	return 0;
}

static const struct of_device_id magcvr_mxm1120_match[] = {
	{ .compatible = "oplus,magcvr_mxm1120"},
	{},
};

static const struct i2c_device_id magcvr_mxm1120_id[] = {
	{"oplus,magcvr_mxm1120", 0 },
	{},
};
MODULE_DEVICE_TABLE(i2c, magcvr_mxm1120_id);

static const struct dev_pm_ops magcvr_mxm1120_pm_ops = {
	.suspend = magcvr_mxm1120_i2c_suspend,
	.resume = magcvr_mxm1120_i2c_resume,
};

static struct i2c_driver magcvr_mxm1120_i2c_driver = {
	.driver = {
		.name = "oplus,magcvr_mxm1120",
		.of_match_table = magcvr_mxm1120_match,
		.pm = &magcvr_mxm1120_pm_ops,
	},
	.probe    = magcvr_mxm1120_probe,
	.remove   = magcvr_mxm1120_remove,
	.id_table = magcvr_mxm1120_id,
};

static int __init magcvr_mxm1120_init(void)
{
	int ret = 0;

	MAG_CVR_LOG("call\n");
	ret = i2c_add_driver(&magcvr_mxm1120_i2c_driver);
	if (ret != 0) {
		MAG_CVR_ERR("magcvr_mxm1120_init failed, %d\n", ret);
	}
	return 0;
}

static void __exit magcvr_mxm1120_exit(void)
{
	MAG_CVR_LOG("call\n");
	i2c_del_driver(&magcvr_mxm1120_i2c_driver);
}

module_init(magcvr_mxm1120_init);
module_exit(magcvr_mxm1120_exit);

MODULE_DESCRIPTION("Magcvr mxm1120 Driver");
MODULE_LICENSE("GPL");
