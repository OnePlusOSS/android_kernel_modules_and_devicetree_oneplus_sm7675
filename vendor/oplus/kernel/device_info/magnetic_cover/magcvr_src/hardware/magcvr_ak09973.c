/***
  driver for ak09973
**/

#include "../../magcvr_include/hardware/ak09973_include.h"

static int magnetic_cover_i2c_read_block(struct ak09973_chip_info *chip_info,
                                         u8 addr,
                                         u8 *data,
                                         u8 len)
{
	u8 reg_addr = addr;
	int err = 0;
	int retry = 0;
	struct i2c_client *client = NULL;
	struct i2c_msg msgs[2] = {{0}, {0}};

	if (chip_info == NULL) {
		MAG_CVR_ERR("chip_info null\n");
		return -EINVAL;
	}

	if (len > AK09973_I2C_REG_MAX_SIZE) {
		MAG_CVR_DEBUG(" length %d exceeds %d\n", len, AK09973_I2C_REG_MAX_SIZE);
		return -EINVAL;
	}

	client = chip_info->client;

	mutex_lock(&chip_info->data_lock);
	msgs[0].addr = client->addr;
	msgs[0].flags = 0;
	msgs[0].len = 1;
	msgs[0].buf = &reg_addr;

	msgs[1].addr = client->addr;
	msgs[1].flags = I2C_M_RD;
	msgs[1].len = len;
	msgs[1].buf = data;

	for (retry = 0; retry < MAX_I2C_RETRY_TIME; retry++) {
		err = i2c_transfer(client->adapter, msgs, (sizeof(msgs) / sizeof(msgs[0])));
		MAG_CVR_DEBUG("----magnetic_cover_i2c_read_block: (0x%02X %p %d)\n",addr, data, len);
		/* dump_stack();*/

		if (err < 0) {
			MAG_CVR_ERR("i2c_transfer error: (%d %p %d) %d\n", addr, data, len, err);
			msleep(20);
		} else {
			err = 0;
			break;
		}
	}

	if (chip_info->magcvr_info != NULL) {
		if (err < 0 || fault_injection_handle(chip_info->magcvr_info, OPT_IIC_READ)) {
			chip_info->magcvr_info->iic_read_err_cnt++;
			MAG_CVR_ERR("I2C read over retry limit, healthCnt:%d\n",
                chip_info->magcvr_info->iic_read_err_cnt);
		}
	}

	if (retry == MAX_I2C_RETRY_TIME)
		err = -EIO;

	mutex_unlock(&chip_info->data_lock);

	return err;
}

static int magnetic_cover_i2c_write_block(struct ak09973_chip_info *chip_info,
                                          u8 addr,
                                          u8 *data,
                                          u8 len)
{
	int err = 0, retry = 0;
	int idx = 0;
	int num = 0;
	char buf[AK09973_I2C_REG_MAX_SIZE] = {0};
	struct i2c_client *client = NULL;

	if (chip_info == NULL) {
		MAG_CVR_ERR("client null\n");
		return -EINVAL;
	}

	if (len >= AK09973_I2C_REG_MAX_SIZE) {
		MAG_CVR_DEBUG(" length %d exceeds %d\n", len, AK09973_I2C_REG_MAX_SIZE);
		return -EINVAL;
	}

	client = chip_info->client;

	mutex_lock(&chip_info->data_lock);

	buf[num++] = addr;
	for (idx = 0; idx < len; idx++) {
		buf[num++] = data[idx];
	}

	for (retry = 0; retry < MAX_I2C_RETRY_TIME; retry++) {
		MAG_CVR_DEBUG("----magnetic_cover_i2c_write_block: (0x%02X %p %d)\n",addr, data, len);
		/* dump_stack();*/
		err = i2c_master_send(client, buf, num);
		if (err < 0) {
			MAG_CVR_ERR("send command error!! %d\n", err);
			msleep(20);
		} else {
			break;
		}
	}

	if (chip_info->magcvr_info != NULL) {
		if (err < 0 || fault_injection_handle(chip_info->magcvr_info, OPT_IIC_WRITE)) {
			chip_info->magcvr_info->iic_write_err_cnt++;
			MAG_CVR_ERR("I2C write over retry limit, healthCnt:%d\n",
                chip_info->magcvr_info->iic_write_err_cnt);
		}
	}

	if (retry == MAX_I2C_RETRY_TIME)
		err = -EIO;

	mutex_unlock(&chip_info->data_lock);
	return err;
}

static void ak09973_inttobuff(u8* th, int bop, int brp)
{
	/* 
	BYTE0(th0) BTYE1(th1) BYTE2(th2) BTYE3(th3)
	BOP[15:8]  BOP[7:0]   BRP[15:8]  BRP[7:0]
	*/
	th[0] = (u8)(((u16)bop) >> 8);
	th[1] = (u8)(((u16)bop) & 0xFF);
	th[2] = (u8)(((u16)brp) >> 8);
	th[3] = (u8)(((u16)brp) & 0xFF);
	MAG_CVR_DEBUG("BRP->[th0:%x][th1:%x] BOP->[th2:%x][th3:%x]\n", th[0], th[1], th[2], th[3]);
}

static int mysqrt(long x)
{
	long temp = 0;
	int res = 0;
	int count = 0;
	if (x == 1 || x == 0)
		return x;
	temp = x / 2;
	while (1) {
		long a = temp;
		count++;
		temp = (temp + x / temp) / 2;
		if (count > MAX_SQRT_TIME) {
			res = temp;
			MAG_CVR_DEBUG("count = %d, over the max time\n", count);
			return res;
		}
		if (((a - temp) < 2) && ((a - temp) > -2)) {
			res = temp;
			return res;
		}
	}
}

static int ak09973_chip_init(void *chip_data)
{
	struct ak09973_chip_info *chip_info = (struct ak09973_chip_info *)chip_data;
	int ret = 0;
	u8 data[2] = {0};
	u8 rdata = 0;
	u8 th[4] = {0};

	MAG_CVR_LOG("called");

	if (chip_info == NULL) {
		MAG_CVR_ERR("chip_info is  NULL \n");
		return -EINVAL;
	}

	data[AK_CNTL1_BYTE0_15_8] = AK_POL_SET_0;
	data[AK_CNTL1_BYTE1_7_0]  = AK_CNTL1_SWVEN;
	rdata = AK_100HZ_LOWPOWER; /*low power consumption mode*/

	ret = magnetic_cover_i2c_write_block(chip_info, AK09973_REG_CNTL1, data, 2);
	if (ret < 0) {
		MAG_CVR_ERR("write AK09973_REG_CNTL1 fail %d \n", ret);
		return ret;
	}

	ret = magnetic_cover_i2c_write_block(chip_info, AK09973_REG_CNTL2, &rdata, 1);
	if (ret < 0) {
		MAG_CVR_ERR("write AK09973_REG_CNTL2 fail %d \n", ret);
		return ret;
	}

	ak09973_inttobuff(th, AK_MIN_SHROT, AK_MAX_SHROT);

	ret = magnetic_cover_i2c_write_block(chip_info, AK_BOP_BRP_X_ADD, th, 4);
	if (ret < 0) {
		MAG_CVR_ERR("clear AK09973_REG_SWX1 fail %d \n", ret);
	}

	ret = magnetic_cover_i2c_write_block(chip_info, AK_BOP_BRP_Y_ADD, th, 4);
	if (ret < 0) {
		MAG_CVR_ERR("clear AK09973_REG_SWX1 fail %d \n", ret);
	}

	ret = magnetic_cover_i2c_write_block(chip_info, AK_BOP_BRP_Z_ADD, th, 4);
	if (ret < 0) {
		MAG_CVR_ERR("clear AK09973_REG_SWX1 fail %d \n", ret);
	}

	MAG_CVR_LOG("AK09973_REG_CNTL2:[0x%02X].\n", rdata);

	ret = magnetic_cover_i2c_write_block(chip_info, AK09973_REG_CNTL1, data, 2);
	if (ret < 0) {
		MAG_CVR_ERR("write AK09973_REG_CNTL1 fail %d \n", ret);
		return ret;
	}

	ret = magnetic_cover_i2c_write_block(chip_info, AK09973_REG_CNTL2, &rdata, 1);
	if (ret < 0) {
		MAG_CVR_ERR("write AK09973_REG_CNTL2 fail %d \n", ret);
		return ret;
	}

	MAG_CVR_DEBUG("END sensor mode is %d\n" , rdata);
	return 0;
}

static int ak09973_get_data(void *chip_data, long *value)
{
	struct ak09973_chip_info *chip_info = NULL;
	int ret = -1;
	u8 buf[AK_BIT_MAX] = {0};

	if (chip_data == NULL) {
		MAG_CVR_ERR("g_chip NULL \n");
		return -EINVAL;
	} else {
		MAG_CVR_LOG("called");
		chip_info = (struct ak09973_chip_info *)chip_data;
	}

	ret = magnetic_cover_i2c_read_block(chip_info, AK09973_REG_ST_V, buf, sizeof(buf));
	if (ret < 0) {
		MAG_CVR_ERR(" AK09973_REG_ST_Z fail %d \n", ret);
		return ret;
	}

	if (buf[AK_BIT0_ST] & AK_DATA_READY) {
		// chip_info->data_x = (short)((u16)(buf[AK_BIT5_HX_15_8] << 8) + buf[AK_BIT6_HX_7_0]);
		// chip_info->data_y = (short)((u16)(buf[AK_BIT3_HY_15_8] << 8) + buf[AK_BIT4_HY_7_0]);
		// chip_info->data_z = (short)((u16)(buf[AK_BIT1_HZ_15_8] << 8) + buf[AK_BIT2_HZ_7_0]);
		chip_info->data_v = (long)((u32)(buf[1] << 24) + (u32)(buf[2] << 16) + (u32)(buf[3] << 8) + (u32)buf[4]);
	} else {
		MAG_CVR_DEBUG("magnetic_cover hall: st1(0x%02X%02X) is not DRDY.\n",
            buf[0], buf[1]);
        chip_info->data_v = AK_DEFAULT_DATA;
	}

	MAG_CVR_LOG("[x:%d][y:%d][z:%d][v:%ld,%d]\n",
        chip_info->data_x,
        chip_info->data_y,
        chip_info->data_z,
        chip_info->data_v,
        mysqrt(chip_info->data_v));

	*value = mysqrt(chip_info->data_v);
	return ret;
}

static int ak09973_update_threshold(void *chip_data,
            int posi, int high_thd, int low_thd)
{
	struct ak09973_chip_info *chip_info = NULL;
	u8 th[4] = {0};
	int ret  = 0;
	u8 data[2]   = {0};
	int bop = 0;
	int brp = 0;

	if (chip_data == NULL) {
		MAG_CVR_ERR("chip_data == NULL");
		return -EINVAL;
	} else {
		chip_info = (struct ak09973_chip_info *)chip_data;
		MAG_CVR_DEBUG("call and posi = %d", posi);
	}

	if (posi == MAGNETIC_COVER_INPUT_FAR) {
		data[AK_CNTL1_BYTE0_15_8] = AK_POL_SET_0;
		bop = high_thd;
		brp = high_thd - 1;
	} else if (posi == MAGNETIC_COVER_INPUT_NEAR) {
		data[AK_CNTL1_BYTE0_15_8] = AK_POLV_SET_1;
		bop = low_thd + 1;
		brp = low_thd;
	}

	// data[AK_CNTL1_BYTE1_7_0]  = AK_CNTL1_SWZEN;
	data[AK_CNTL1_BYTE1_7_0]  = AK_CNTL1_SWVEN;

	if (data[AK_CNTL1_BYTE0_15_8] == AK_POLV_SET_1) {
		MAG_CVR_LOG("[h_bopv:%d][l_brpv:%d][value<brp:%d,PullDown]", bop, brp, brp);
	} else {
		MAG_CVR_LOG("[h_bopv:%d][l_brpv:%d][value>bop:%d,PullDown]", bop, brp, bop);
	}

	/* para1:byte[4:0] para2:BRP para3:BOP */
	ak09973_inttobuff(th, bop, brp);

	ret = magnetic_cover_i2c_write_block(chip_info, AK09973_REG_CNTL1, data, 2);
	if (ret < 0) {
		MAG_CVR_ERR("clear AK09973_REG_CNTL1 fail %d \n", ret);
	}

	ret = magnetic_cover_i2c_write_block(chip_info, AK_BOP_BRP_V_ADD, th, 4);
	if (ret < 0) {
		MAG_CVR_ERR("clear AK_BOP_BRP_Z_ADD fail %d \n", ret);
	}

	MAG_CVR_DEBUG("end");
	return ret;
}

static void ak09973_dump_regsiter(struct seq_file *s, void *chip_data)
{
	u8 buf[AK_BIT_MAX] = {0};
	int ret = 0;

	struct ak09973_chip_info *chip_info = NULL;
	if (chip_data == NULL) {
		MAG_CVR_ERR("chip_data == NULL");
		return;
	} else {
		chip_info = (struct ak09973_chip_info *)chip_data;
		MAG_CVR_DEBUG("call ");
	}

	ret = magnetic_cover_i2c_read_block(chip_info, AK09973_REG_CNTL1, buf, sizeof(buf));
	if (ret < 0) {
		MAG_CVR_ERR(" AK09973_REG_ST_Z fail %d \n", ret);
		return;
	} else {
		MAG_CVR_DEBUG("CNTL1->BYTE0[%02X] BYTE1[%02x]\n", buf[0] << 8, buf[1]);
		seq_printf(s, "CNTL1->BYTE0[%02X] BYTE1[%02x]\n", buf[0] << 8, buf[1]);
	}

	ret = magnetic_cover_i2c_read_block(chip_info, AK09973_REG_CNTL2, buf, sizeof(buf));
	if (ret < 0) {
		MAG_CVR_ERR(" AK09973_REG_ST_Z fail %d \n", ret);
		return;
	} else {
		MAG_CVR_DEBUG("CNTL2->BYTE0[%02X]\n", buf[0]);
		seq_printf(s, "CNTL2->BYTE0[%02X]\n", buf[0]);
	}

	ret = magnetic_cover_i2c_read_block(chip_info, AK_BOP_BRP_V_ADD, buf, sizeof(buf));
	if (ret < 0) {
		MAG_CVR_ERR(" AK09973_REG_ST_Z fail %d \n", ret);
		return;
	} else {
		MAG_CVR_DEBUG("25h->bopV[%d] brpV[%d]\n", ((buf[0] << 8) + buf[1]), ((buf[2] << 8) + buf[3]));
		seq_printf(s, "25h->bopV[%d] brpV[%d]\n", ((buf[0] << 8) + buf[1]), ((buf[2] << 8) + buf[3]));
	}
}

static struct oplus_magnetic_cover_operations ak09973_dev_ops = {
	.chip_init = ak09973_chip_init,
	.get_data = ak09973_get_data,
	.update_threshold = ak09973_update_threshold,
	.dump_regsiter = ak09973_dump_regsiter,
};

/**** probe start ****/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int magcvr_ak09973_probe(struct i2c_client *client)
#else
static int magcvr_ak09973_probe(struct i2c_client *client, const struct i2c_device_id *id)
#endif
{
	struct magnetic_cover_info *magcvr_info = NULL;
	struct ak09973_chip_info *ak09973_info = NULL;
	int ret = 0;

	MAG_CVR_LOG("call \n");
	// ak09973 private infomation
	ak09973_info = kzalloc(sizeof(struct ak09973_chip_info), GFP_KERNEL);
	if (ak09973_info == NULL) {
		MAG_CVR_ERR("GT:chip info kzalloc error\n");
		return -ENOMEM;
	}

	// abstract platform infomation
	magcvr_info = alloc_for_magcvr();
	if (magcvr_info == NULL) {
		MAG_CVR_ERR("GT:chip info kzalloc error\n");
		magcvr_kfree((void **)&ak09973_info);
		return -ENOMEM;
	}

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		MAG_CVR_ERR("ak09973 i2c unsupported\n");
		magcvr_kfree((void **)&ak09973_info);
		kfree(magcvr_info);
		return 0;
	}

	// private info
	magcvr_info->magcvr_dev = &client->dev;
	magcvr_info->iic_client = client;
	magcvr_info->irq = client->irq;
	// hardware info
	ak09973_info->client = client;
	ak09973_info->irq    = client->irq;
	// copy info
	magcvr_info->chip_info = ak09973_info;
	i2c_set_clientdata(client, magcvr_info);
	magcvr_info->mc_ops = &ak09973_dev_ops;

	MAG_CVR_LOG("mutex ak09973 init\n");
	mutex_init(&ak09973_info->data_lock);

	ak09973_info->magcvr_info = NULL;
	MAG_CVR_LOG("start to abstract init\n");
	ret = magcvr_core_init(magcvr_info);
	if (ret < 0) {
		MAG_CVR_ERR("ak09973 i2c init fail\n");
		magcvr_kfree((void **)&ak09973_info);
		kfree(magcvr_info);
		i2c_set_clientdata(client, NULL);
		return 0;
	}

	MAG_CVR_LOG("abstract data init success\n");
	// abstract info
	ak09973_info->magcvr_info = magcvr_info;

	if (ret == INIT_PROBE_ERR) {
		MAG_CVR_LOG("ak09973 some err, continue probe\n");
		ret = after_magcvr_core_init(magcvr_info);
	} else {
		MAG_CVR_LOG("probe end\n");
	}

	return 0;
}
/**** probe end   ****/
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
static void magcvr_ak09973_remove(struct i2c_client *client)
#else
static int magcvr_ak09973_remove(struct i2c_client *client)
#endif
{
	struct magnetic_cover_info *magcvr_info = i2c_get_clientdata(client);
	struct ak09973_chip_info *ak09973_info = NULL;

	if (magcvr_info == NULL) {
		MAG_CVR_ERR("magcvr_info == NULL\n");
		goto EXIT;
	}

	ak09973_info = (struct ak09973_chip_info*)magcvr_info->chip_info;
	if (ak09973_info == NULL) {
		MAG_CVR_ERR("ak09973_info == NULL\n");
		goto EXIT;
	}

	MAG_CVR_LOG("call\n");

	unregister_magcvr_core(magcvr_info);
	magcvr_kfree((void **)&ak09973_info);
	i2c_set_clientdata(client, NULL);

EXIT:
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	return;
#else
	return 0;
#endif
}

static int magcvr_ak09973_i2c_suspend(struct device *dev)
{
	MAG_CVR_LOG("called\n");
	return 0;
}

static int magcvr_ak09973_i2c_resume(struct device *dev)
{
	MAG_CVR_LOG("called\n");
	return 0;
}

static const struct of_device_id magcvr_ak09973_match[] = {
	{ .compatible = "oplus,magcvr_ak09973"},
	{},
};

static const struct i2c_device_id magcvr_ak09973_id[] = {
	{"oplus,magcvr_ak09973", 0 },
	{},
};
MODULE_DEVICE_TABLE(i2c, magcvr_ak09973_id);

static const struct dev_pm_ops magcvr_ak09973_pm_ops = {
	.suspend = magcvr_ak09973_i2c_suspend,
	.resume = magcvr_ak09973_i2c_resume,
};

static struct i2c_driver magcvr_ak09973_i2c_driver = {
	.driver = {
		.name = "oplus,magcvr_ak09973",
		.of_match_table =  magcvr_ak09973_match,
		.pm = &magcvr_ak09973_pm_ops,
	},
	.probe    = magcvr_ak09973_probe,
	.remove   = magcvr_ak09973_remove,
	.id_table = magcvr_ak09973_id,
};

static int __init magcvr_ak09973_init(void)
{
	int ret = 0;

	MAG_CVR_LOG("call\n");
	ret = i2c_add_driver(&magcvr_ak09973_i2c_driver);
	if (ret != 0) {
		MAG_CVR_ERR("magcvr_ak09973_init failed, %d\n", ret);
	}
	return 0;
}

static void __exit magcvr_ak09973_exit(void)
{
	MAG_CVR_LOG("call\n");
	i2c_del_driver(&magcvr_ak09973_i2c_driver);
}

module_init(magcvr_ak09973_init);
module_exit(magcvr_ak09973_exit);

MODULE_DESCRIPTION("Magcvr ak09973 Driver");
MODULE_LICENSE("GPL");
