/* SPDX-License-Identifier: GPL-2.0-only  */
/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 */
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/blkdev.h>
#include <linux/sysfs.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/libfdt.h>
#include <linux/suspend.h>
#include "sensor_devinfo.h"
#include <linux/gpio.h>
#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
#include "hf_sensor_type.h"
#include "mtk_nanohub.h"
#ifdef LINUX_KERNEL_VERSION_419
#include "scp.h"
#else /*LINUX_KERNEL_VERSION_419*/
#include "scp_helper.h"
#include "scp_excep.h"
#endif /*LINUX_KERNEL_VERSION_419*/
#else /*CONFIG_OPLUS_SENSOR_MTK68XX*/
#include <SCP_sensorHub.h>
#include <hwmsensor.h>
#include "SCP_power_monitor.h"
#endif /*CONFIG_OPLUS_SENSOR_MTK68XX*/
#include <soc/oplus/system/oplus_project.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
#ifndef PDE_DATA
#define PDE_DATA pde_data
#endif
#endif

#define RETRY_COUNT_FOR_GET_DEVICE 50
#define WAITING_FOR_GET_DEVICE     100

#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
extern int mtk_nanohub_set_cmd_to_hub(uint8_t sensor_id, enum CUST_ACTION action, void *data);
extern int mtk_nanohub_req_send(union SCP_SENSOR_HUB_DATA *data);
extern int mtk_nanohub_cfg_to_hub(uint8_t sensor_id, uint8_t *data, uint8_t count);
#endif

int register_lcdinfo_notifier(struct notifier_block *nb);
int unregister_lcdinfo_notifier(struct notifier_block *nb);
static int oplus_sensor_feature_init(void);
void mag_soft_parameter_init(void);
/* unsigned int get_project(); */

/*
__attribute__((weak)) int register_lcdinfo_notifier() {
	return -1;
}

__attribute__((weak)) int unregister_lcdinfo_notifier() {
	return -1;
}*/

enum panel_id {
	SAMSUNG = 1,
	BOE,
	TIANMA,
	NT36672C,
	HX83112F,
	P_3,
	P_B,
	PANEL_NUM
};

struct panel_node {
        enum panel_id id;
        char *lcm_name;
};

static struct panel_node g_panel_node[PANEL_NUM] = {
	{
		.id = SAMSUNG,
		.lcm_name = "samsung",
	},
	{
		.id = BOE,
		.lcm_name = "boe",
	},
	{
		.id = TIANMA,
		.lcm_name = "tianma",
	},
	{
		.id = NT36672C,
		.lcm_name = "nt36672c",
	},
	{
		.id = HX83112F,
		.lcm_name = "hx83112f",
	},
	{
		.id = P_3,
		.lcm_name = "p_3",
	},
	{
		.id = P_B,
		.lcm_name = "p_B",
	}
};

#define DEV_TAG                     "[sensor_devinfo] "
#define DEVINFO_LOG(fmt, args...)   pr_err(DEV_TAG"%s %d : "fmt, __func__, __LINE__, ##args)

#define UINT2Ptr(n)     (uint32_t *)(n)
#define Ptr2UINT32(p)   (*((uint32_t*)p))
#define MAG_PARA_OFFSET               8
/*#define SOURCE_NUM                    3*/
#define MAG_PARA_NUM                  9

#define OPLUSCUSTOM_FILE "/dev/block/by-name/oplus_custom"
#ifndef ID_REAR_ALS
#define ID_REAR_ALS  97
#endif
#ifndef ID_REAR_CCT
#define ID_REAR_CCT       98
#endif

#ifndef ID_SARS
#define ID_SARS -1
#endif

#ifndef ID_PWM_RGB
#define ID_PWM_RGB 115
#endif

#define SOURCE_NUM 6
#define MAX_SIZE 64

enum {
	IS_SUPPROT_HWCALI = 1,
	IS_IN_FACTORY_MODE,
	IS_SUPPORT_NEW_ARCH,
	GYRO_CALI_VERSION,
	ACC_CALI_RANGE,
	DO_MAG_SELFTEST,
	CONFIG_SAR_REG,
	GOLD_REAR_CCT_3K,
	GOLD_REAR_CCT_6K,
	SAR_NUM,
	GYRO_CALI_ADAPT_Q,
	ACC_CALI_ADAPT_Q,
	IS_SUPPORT_MTK_ORIGIN_CALI,
	GOLD_ALS_FACTOR,
	GOLD_REAR_ALS_FACTOR,
	GOLD_REAR_CCT_FACTOR,
	GYRO_CALI_RANGE,
	GOLD_CCT_3K,
	GOLD_CCT_6K,
	GOLD_CCT_FACTOR,
	CCT_TYPE,
	GOLD_CCT_CHANNELS,
	CCT_GAIN_CALI,
};

enum {
	RED_MAX_LUX = 1,
	GREEN_MAX_LUX,
	BLUE_MAX_LUX,
	WHITE_MAX_LUX,
	CALI_COE,
	ROW_COE,
#ifdef DEBUG_BRIGHTNESS
	BRIGHTNESS,
#endif
};

struct proc_node {
	char *node_name;
	uint32_t id;
};

static struct proc_node sensor_feature_file[] = {
	{"is_support_hwcali", IS_SUPPROT_HWCALI},
	{"is_in_factory_mode", IS_IN_FACTORY_MODE},
	{"is_support_new_arch", IS_SUPPORT_NEW_ARCH},
	{"gyro_cali_version", GYRO_CALI_VERSION},
	{"acc_cali_range", ACC_CALI_RANGE},
	{"do_mag_selftest", DO_MAG_SELFTEST},
	{"config_sar_reg", CONFIG_SAR_REG},
	{"gold_rear_cct_3k", GOLD_REAR_CCT_3K},
	{"gold_rear_cct_6k", GOLD_REAR_CCT_6K},
	{"sar_num", SAR_NUM},
	{"gyro_cali_adapt_q", GYRO_CALI_ADAPT_Q},
	{"acc_cali_adapt_q", ACC_CALI_ADAPT_Q},
	{"is_support_mtk_origin_cali", IS_SUPPORT_MTK_ORIGIN_CALI},
	{"gold_als_factor", GOLD_ALS_FACTOR},
	{"gold_rear_als_factor", GOLD_REAR_ALS_FACTOR},
	{"gold_rear_cct_factor", GOLD_REAR_CCT_FACTOR},
	{"gyro_cali_range", GYRO_CALI_RANGE},
	{"gold_cct_3k", GOLD_CCT_3K},
	{"gold_cct_6k", GOLD_CCT_6K},
	{"gold_cct_factor", GOLD_CCT_FACTOR},
	{"cct_type", CCT_TYPE},
	{"gold_cct_channels", GOLD_CCT_CHANNELS},
	{"cct_gain_cali", CCT_GAIN_CALI},
};

struct proc_node als_cali_file[] = {
	{"red_max_lux", RED_MAX_LUX},
	{"green_max_lux", GREEN_MAX_LUX},
	{"blue_max_lux", BLUE_MAX_LUX},
	{"white_max_lux", WHITE_MAX_LUX},
	{"cali_coe", CALI_COE},
	{"row_coe", ROW_COE},
#ifdef DEBUG_BRIGHTNESS
	{"brightness", BRIGHTNESS},
#endif
};

struct delayed_work parameter_work;
struct delayed_work utc_work;
struct delayed_work lcdinfo_work;

struct cali_data* g_cali_data = NULL;
static bool is_parameter_updated = false;

static char para_buf[3][128] = {"", "", ""};
static bool is_support_new_arch = false;
static bool is_support_mtk_origin_cali = false;
static bool gyro_cali_adapt_q = false;
static bool acc_cali_adapt_q = false;
static struct oplus_als_cali_data *gdata = NULL;
static struct proc_dir_entry *sensor_proc_dir = NULL;
static int gyro_cali_version = 1;
static int gyro_cali_range = 200;
static int g_reg_address = 0;
static int g_reg_value = 0;
static int g_sar_num = ID_SAR;
static char acc_cali_range[64] = {0};
static char gold_rear_cct_3k[64] = {0};
static char gold_rear_cct_6k[64] = {0};
static char gold_rear_cct_factor[64] = {0};
static int gold_als_factor = 1001;
static int gold_rear_als_factor = 1001;
static uint32_t lb_bri_max = 320;
atomic_t utc_suspend;

static char gold_cct_3k[64] = {0};
static char gold_cct_6k[64] = {0};
static char gold_cct_factor[64] = {0};
static int cct_type = CCT_NORMAL;
static int gold_cct_channels = 4;
static int g_cct_gain_cali = 0;
static int support_panel = 0;

static bool g_report_brightness = false;
static bool g_support_bri_to_hal = false;
static bool g_support_bri_to_scp = false;
static bool g_support_pwm_turbo = false;
static bool g_need_to_sync_lcd_rate = false;

enum {
	NONE_TYPE = 0,
	LCM_DC_MODE_TYPE,
	LCM_BRIGHTNESS_TYPE,
	MAX_INFO_TYPE,
	LCM_PWM_TURBO = 0x14,
	LCM_ADFR_MIN_FPS = 0x15,
};
struct sensorlist_info_t {
	char name[16];
};

struct als_info {
	uint16_t brightness;
	uint16_t dc_mode;
	bool use_lb_algo;
	uint16_t pwm_turbo;
	uint16_t rt_bri;
	uint16_t fps;
#if IS_ENABLED(CONFIG_OPLUS_SENSOR_USE_BLANK_MODE)
	uint16_t blank_mode;
#endif
}__packed __aligned(4);

struct als_info g_als_info;


bool is_support_new_arch_func(void)
{
	return is_support_new_arch;
}
bool is_support_mtk_origin_cali_func(void)
{
	return is_support_mtk_origin_cali;
}
enum {
	accel,
	gyro,
	mag,
	als,
	ps,
	baro,
	rear_cct,
	front_cct,
	maxhandle,
};

static struct sensorlist_info_t sensorlist_info[maxhandle];

typedef struct {
	unsigned int        n_magic_num1;
	unsigned int        n_magic_num2;
	unsigned int        nOther1[2];
	unsigned char       nOther2[64];
	unsigned char       Sensor[256];
} sensor_config_info_t;

/*__attribute__((weak)) unsigned int get_project() {
	return -1;
}*/

int oplus_get_dts_feature(int handle, char *node_name, char *feature_name, uint32_t *input)
{
	struct device_node *node;
	int len = 0;
	int ret = 0;
	int index;
	char dnode[16];
	char *device_name = NULL;

	if (handle >= maxhandle) {
		DEVINFO_LOG("ivalid sensor handle %d\n", handle);
		return -1;
	}

	for (index = 1; index <= SOURCE_NUM; index++) {
		sprintf(dnode, "%s_%d", node_name, index);
		node = of_find_node_by_path(dnode);
		if (node == NULL) {
			DEVINFO_LOG("get %s fail", dnode);
			return -1;
		}

		ret = of_property_read_string(node, "device_name", (const char**)&device_name);
		if (!device_name || ret < 0) {
			DEVINFO_LOG("get device_name prop fail \n");
			return -1;
		}

		DEVINFO_LOG("device_name = %s", device_name);
		if (!strcmp(device_name, sensorlist_info[handle].name)) {
			len = of_property_count_elems_of_size(node, feature_name, sizeof(uint32_t));
			if (len < 0) {
				DEVINFO_LOG("get feature_name:%s fail\n", feature_name);
				return -1;
			} else {
				ret = of_property_read_variable_u32_array(node, feature_name, input, len, 0);
				if (ret != len) {
					DEVINFO_LOG("error:read feature_name:%s %d element but length is %d\n", feature_name, ret, len);
					return -1;
				} else {
					DEVINFO_LOG("read %s:%s, len %d, successful\n", device_name, feature_name, len);
					return ret;
				}
			}
		}
	}

	DEVINFO_LOG("oplus_get_dts_feature %s:%s,error\n", node_name, feature_name);
	return -1;
}

static void is_support_lb_algo(void)
{
	uint32_t use_lb_algo;
	int ret;
	g_als_info.use_lb_algo = false;

	ret = oplus_get_dts_feature(als, "/odm/light", "use_lb_algo", &use_lb_algo);
	if (ret < 0) {
		DEVINFO_LOG("get use_lb_algo fail");
		return;
	}

	g_als_info.use_lb_algo = (use_lb_algo == 1) ? true : false;
	DEVINFO_LOG("support lb algo %d", g_als_info.use_lb_algo);
}

static void get_lb_max_brightness(void)
{
	int ret;
	uint32_t val = 0;

	ret = oplus_get_dts_feature(als, "/odm/light", "lb_bri_max", &val);
	if (ret < 0) {
		return;
	}

	lb_bri_max = val;
	DEVINFO_LOG("lb_bri_max %d\n", lb_bri_max);
}

static void get_new_arch_info(void)
{
	struct device_node *node;
        uint32_t is_support = 0;

	node = of_find_node_by_path("/odm/cali_arch");
	if (node == NULL) {
		DEVINFO_LOG("get cali_arch fail");
		return;
	}

	if (of_property_read_u32(node, "new-arch-supported", &is_support)) {
		DEVINFO_LOG("get new-arch-supported fail");
		return;
	}

	if (1 == is_support) {
		is_support_new_arch = true;
	} else {
		is_support_new_arch = false;
	}
}

static void get_mtk_cali_origin_info(void)
{
	struct device_node *node;
	uint8_t mtk_cali_is_support = 0;

	node = of_find_node_by_path("/odm/mtk_cali");
	if (node == NULL) {
		DEVINFO_LOG("get mtk_cali fail");
		return;
	}

	if (of_property_read_u8(node, "new-arch-supported", &mtk_cali_is_support)) {
		DEVINFO_LOG("get new-arch-supported fail");
		return;
	}

	if (1 == mtk_cali_is_support) {
		is_support_mtk_origin_cali = true;
	} else {
		is_support_mtk_origin_cali = false;
	}
}

static void get_acc_gyro_cali_nv_adapt_q_flag(void)
{
	uint8_t is_support = 0;
	struct device_node *node;

	node = of_find_node_by_path("/odm/cali_nv_adapt_q");
	if (node == NULL) {
		DEVINFO_LOG("get cali_nv_adapt_q node fail");
		return;
	}

	if (of_property_read_u8(node, "cali_nv_adapt_q", &is_support)) {
		DEVINFO_LOG("get cali_nv_adapt_q value fail");
		return;
	}

	if (1 == is_support) {
		acc_cali_adapt_q = true;
		if (!strcmp(sensorlist_info[gyro].name, "bmi160")) {
			gyro_cali_adapt_q = false;
		} else {
			gyro_cali_adapt_q = true;
		}
	} else {
		acc_cali_adapt_q = false;
		gyro_cali_adapt_q = false;
	}
}

static inline int handle_to_sensor(int handle)
{
	int sensor = -1;

	switch (handle) {
	case accel:
		sensor = ID_ACCELEROMETER;
		break;
	case gyro:
		sensor = ID_GYROSCOPE;
		break;
#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
	case mag:
		sensor = ID_MAGNETIC_FIELD;
		break;
#else
	case mag:
		sensor = ID_MAGNETIC;
		break;
#endif
	case als:
		sensor = ID_LIGHT;
		break;
	case ps:
		sensor = ID_PROXIMITY;
		break;
	case baro:
		sensor = ID_PRESSURE;
		break;
	case rear_cct:
		sensor = ID_REAR_CCT;
		break;
	case front_cct:
		sensor = ID_CCT;
		break;
	}
	return sensor;
}

struct block_device *get_opluscustom_partition_bdev(void)
{
	struct block_device *bdev = NULL;
	int retry_wait_for_device = RETRY_COUNT_FOR_GET_DEVICE;
	dev_t dev;

	while(retry_wait_for_device--) {
		if (lookup_bdev(OPLUSCUSTOM_FILE, &dev)) {
			printk("failed to get oplus_custom bdev!\n");
			return NULL;
		}
		if(dev != 0) {
			bdev = blkdev_get_by_dev(dev, BLK_OPEN_READ, NULL, NULL);
			if (!IS_ERR(bdev)) {
				printk("success to get dev block\n");
				return bdev;
			}
		}
		printk("Failed to get dev block, retry %d\n", retry_wait_for_device);
		msleep_interruptible(WAITING_FOR_GET_DEVICE);
	}
	printk("Failed to get dev block final\n");
	return NULL;
}

static int read_oplus_custom(void *data)
{
	sensor_config_info_t config_info;
	sensor_cali_file_v1_t *data_v1 = NULL;
	sensor_cali_file_v2_t *data_v2 = NULL;
	struct block_device *bdev = NULL;
	struct file dev_map_file;
	struct kiocb kiocb;
	struct iov_iter iter;
	struct kvec iov;
        int read_size = 0;
	int ret = 0;

	bdev = get_opluscustom_partition_bdev();
	if (!bdev) {
		printk(" %s: bdev get failed\n", __func__);
		return -1;
	}

	memset(&dev_map_file, 0, sizeof(struct file));
	dev_map_file.f_mapping = bdev->bd_inode->i_mapping;
	dev_map_file.f_flags = O_DSYNC | __O_SYNC | O_NOATIME;
	dev_map_file.f_inode = bdev->bd_inode;

	init_sync_kiocb(&kiocb, &dev_map_file);
	kiocb.ki_pos = 0; /* start header offset */
	iov.iov_base = (void *)&config_info;
	iov.iov_len = sizeof(config_info);
	iov_iter_kvec(&iter, READ, &iov, 1, sizeof(config_info));
        read_size = generic_file_read_iter(&kiocb, &iter);

	if (!is_support_new_arch) {
		data_v1 = (sensor_cali_file_v1_t *)data;
		if (!data_v1) {
			DEVINFO_LOG("data_v1 NULL\n");
			ret = -1;
			goto do_bdev_put;
		}

		if (read_size <= 0) {
			DEVINFO_LOG("failed to read file %s\n", OPLUSCUSTOM_FILE);
			ret = -1;
			goto do_bdev_put;
		}

		memcpy(data_v1, config_info.Sensor, 256);
	} else {
		data_v2 = (sensor_cali_file_v2_t *)data;
		if (!data_v2) {
			DEVINFO_LOG("data_v2 NULL\n");
			ret = -1;
			goto do_bdev_put;
		}

		if (read_size <= 0) {
			DEVINFO_LOG("failed to read file %s\n", OPLUSCUSTOM_FILE);
			ret = -1;
			goto do_bdev_put;
		}

		memcpy(data_v2, config_info.Sensor, 256);
	}

	DEVINFO_LOG("read success = %d\n", read_size);

do_bdev_put:
	if(bdev) {
		DEVINFO_LOG("%s: bdev put \n", __func__);
		blkdev_put(bdev, NULL);
		bdev = NULL;
	}


	return ret;
}

static int sensor_read_oplus_custom(struct cali_data *data)
{
	int ret = 0;
	int index = 0;
	sensor_cali_file_v1_t data_v1;
	sensor_cali_file_v2_t data_v2;

	if (!is_support_new_arch) {
		ret = read_oplus_custom(&data_v1);
		if (ret) {
			DEVINFO_LOG("read_oplus_custom error = %d\n", ret);
			return -EINVAL;
		}
		for (index = 0; index < 3; index++) {
			data->acc_data[index] = data_v1.GsensorData[index];
			data->gyro_data[index] = data_v1.GyroData[index];
		}
		for (index = 0; index < 6; index++) {
			data->ps_cali_data[index] = data_v1.ps_data[index];
		}
		data->als_factor = data_v1.gain_als;
		data->baro_cali_offset = data_v1.baro_cali_offset;
	} else {
		ret = read_oplus_custom(&data_v2);
		if (ret) {
			DEVINFO_LOG("read_oplus_custom error = %d\n", ret);
			return -EINVAL;
		}
		for (index = 0; index < 3; index++) {
			data->acc_data[index] = data_v2.gsensor_data[index];
			data->gyro_data[index] = data_v2.gyro_data[index];
		}
		for (index = 0; index < 6; index++) {
			data->ps_cali_data[index] = data_v2.ps_data[index];
			data->cct_cali_data[index] = data_v2.cct_cali_data[index];
		}
		data->als_factor = data_v2.als_gain;
		data->rear_als_factor = data_v2.rear_als_gain;
		data->baro_cali_offset = data_v2.baro_cali_offset;
	}
	DEVINFO_LOG("acc[%d,%d,%d],gyro[%d,%d,%d],ps[%d,%d,%d,%d,%d,%d],als[%d], bar[%d]\n",
		data->acc_data[0], data->acc_data[1], data->acc_data[2],
		data->gyro_data[0], data->gyro_data[1], data->gyro_data[2],
		data->ps_cali_data[0], data->ps_cali_data[1], data->ps_cali_data[2],
		data->ps_cali_data[3], data->ps_cali_data[4], data->ps_cali_data[5],
		data->als_factor, data->baro_cali_offset);
	DEVINFO_LOG("cct_cali_data [%d,%d,%d,%d,%d,%d]\n",
		data->cct_cali_data[0], data->cct_cali_data[1], data->cct_cali_data[2],
		data->cct_cali_data[3], data->cct_cali_data[4], data->cct_cali_data[5]);
	return 0;
}

static void transfer_lcdinfo_to_scp(struct work_struct *dwork)
{
	int err = 0;
	unsigned int len = 0;
	union SCP_SENSOR_HUB_DATA lcdinfo_req;
	lcdinfo_req.req.sensorType = OPLUS_LIGHT;
	lcdinfo_req.req.action = OPLUS_ACTION_SET_LCD_INFO;
	DEVINFO_LOG("send lcd info to scp brightness %d, dc_mode %d, pwm_turbo:%d",
		(uint32_t)g_als_info.brightness, (uint32_t)g_als_info.dc_mode, (uint32_t)g_als_info.pwm_turbo);
	lcdinfo_req.req.data[0] = (uint32_t)g_als_info.brightness << 16 | (uint32_t)g_als_info.dc_mode << 8 | (uint32_t)g_als_info.pwm_turbo;
	DEVINFO_LOG("send lcd info to scp, sensortype:%d, data:%d", lcdinfo_req.req.sensorType, lcdinfo_req.req.data[0]);
	len = sizeof(lcdinfo_req.req);
	#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
	err = mtk_nanohub_req_send(&lcdinfo_req);
	#else
	err = scp_sensorHub_req_send(&lcdinfo_req, &len, 1);
	#endif
	if (err < 0 || lcdinfo_req.rsp.action != OPLUS_ACTION_SET_LCD_INFO) {
		DEVINFO_LOG("fail! err %d\n", err);
		return;
	}
}

static void sync_utc2scp_work(struct work_struct *dwork)
{
	int err = 0;
	unsigned int len = 0;
        struct timespec64 tv = {0};
	struct rtc_time tm;
	union SCP_SENSOR_HUB_DATA rtc_req;
	uint32_t utc_data[6] = {0};

	if (atomic_read(&utc_suspend) == 1) {
		DEVINFO_LOG("Will suspend, stop sync utc \n");
		return;
	}

        ktime_get_real_ts64(&tv);
        rtc_time64_to_tm(tv.tv_sec, &tm);

	utc_data[0] = (uint32_t)tm.tm_mday;
	utc_data[1] = (uint32_t)tm.tm_hour;
	utc_data[2] = (uint32_t)tm.tm_min;
	utc_data[3] = (uint32_t)tm.tm_sec;

	rtc_req.req.sensorType = 0;
	rtc_req.req.action = OPLUS_ACTION_SCP_SYNC_UTC;
	rtc_req.req.data[0] = utc_data[0];
	rtc_req.req.data[1] = utc_data[1];
	rtc_req.req.data[2] = utc_data[2];
	rtc_req.req.data[3] = utc_data[3];
	rtc_req.req.data[4] = tv.tv_sec;
	rtc_req.req.data[5] = tv.tv_nsec/1000;
	DEVINFO_LOG("kernel_ts: %lld.%ld, %u.%u\n",
		tv.tv_sec,
		tv.tv_nsec/1000,
		rtc_req.req.data[4],
		rtc_req.req.data[5]);
	len = sizeof(rtc_req.req);
#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
	err = mtk_nanohub_req_send(&rtc_req);
#else
	err = scp_sensorHub_req_send(&rtc_req, &len, 1);
#endif
	if (err < 0 || rtc_req.rsp.action != OPLUS_ACTION_SCP_SYNC_UTC) {
		DEVINFO_LOG("fail! err %d\n", err);
		return;
	}

	schedule_delayed_work(&utc_work, msecs_to_jiffies(2000));
}

int oplus_send_factory_mode_cmd_to_hub(int sensorType, int mode, void *result)
{
	int err = 0;
	unsigned int len = 0;
	union SCP_SENSOR_HUB_DATA fac_req;

	switch (sensorType) {
	case ID_ACCELEROMETER:
		DEVINFO_LOG("ID_ACCELEROMETER : send_factory_mode_cmd_to_hub");
		fac_req.req.sensorType = OPLUS_ACCEL;
		fac_req.req.action = OPLUS_ACTION_SET_FACTORY_MODE;
		fac_req.req.data[0] = mode;
		len = sizeof(fac_req.req);
#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
		err = mtk_nanohub_req_send(&fac_req);
#else
		err = scp_sensorHub_req_send(&fac_req, &len, 1);
#endif
		if (err < 0 || fac_req.rsp.action != OPLUS_ACTION_SET_FACTORY_MODE) {
			DEVINFO_LOG("fail! err %d\n", err);
			return -1;
		} else {
			*((uint8_t *) result) = fac_req.rsp.reserve[0];
		}
		break;
	case ID_PROXIMITY:
		DEVINFO_LOG("ID_PROXIMITY : send_factory_mode_cmd_to_hub");
		fac_req.req.sensorType = OPLUS_PROXIMITY;
		fac_req.req.action = OPLUS_ACTION_SET_FACTORY_MODE;
		fac_req.req.data[0] = mode;
		len = sizeof(fac_req.req);
#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
		err = mtk_nanohub_req_send(&fac_req);
#else
		err = scp_sensorHub_req_send(&fac_req, &len, 1);
#endif
		if (err < 0 || fac_req.rsp.action != OPLUS_ACTION_SET_FACTORY_MODE) {
			DEVINFO_LOG("fail! err %d\n", err);
			return -1;
		} else {
			*((uint8_t *) result) = fac_req.rsp.reserve[0];
		}
		break;
	case ID_CCT:
		DEVINFO_LOG("ID_CCT : send_factory_mode_cmd_to_hub");
		fac_req.req.sensorType =  OPLUS_CCT;
		fac_req.req.action = OPLUS_ACTION_SET_FACTORY_MODE;
		fac_req.req.data[0] = mode;
		len = sizeof(fac_req.req);
#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
		err = mtk_nanohub_req_send(&fac_req);
#else
		err = scp_sensorHub_req_send(&fac_req, &len, 1);
#endif
		if (err < 0 || fac_req.rsp.action != OPLUS_ACTION_SET_FACTORY_MODE) {
			DEVINFO_LOG("fail! err %d\n", err);
			return -1;
		} else {
			*((uint8_t *) result) = fac_req.rsp.reserve[0];
		}
		break;
	case ID_PWM_RGB:
		DEVINFO_LOG("ID_PWM_RGB : send_factory_mode_cmd_to_hub");
		fac_req.req.sensorType =  OPLUS_LIGHT;
		fac_req.req.action = OPLUS_ACTION_SET_FACTORY_MODE;
		fac_req.req.data[0] = mode;
		len = sizeof(fac_req.req);
#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
		err = mtk_nanohub_req_send(&fac_req);
#else
		err = scp_sensorHub_req_send(&fac_req, &len, 1);
#endif
		if (err < 0 || fac_req.rsp.action != OPLUS_ACTION_SET_FACTORY_MODE) {
			DEVINFO_LOG("fail! err %d\n", err);
			return -1;
		} else {
			*((uint8_t *) result) = fac_req.rsp.reserve[0];
		}
		break;
	default:
		DEVINFO_LOG("invalid sensortype %d\n", err);
	}
	return 1;
}

int oplus_send_selftest_cmd_to_hub(int sensorType, void *testresult)
{
	int err = 0;
	unsigned int len = 0;
	union SCP_SENSOR_HUB_DATA selftest_req;

	switch (sensorType) {
#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
	case ID_MAGNETIC_FIELD:
#else
	case ID_MAGNETIC:
#endif
		DEVINFO_LOG("ID_MAGNETIC : oplus_send_selftest_cmd_to_hub");
		selftest_req.req.sensorType = OPLUS_MAG;
		selftest_req.req.action = OPLUS_ACTION_SELF_TEST;
		len = sizeof(selftest_req.req);
#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
		err = mtk_nanohub_req_send(&selftest_req);
#else
		err = scp_sensorHub_req_send(&selftest_req, &len, 1);
#endif

		if (err < 0 || selftest_req.rsp.action != OPLUS_ACTION_SELF_TEST) {
			DEVINFO_LOG("fail! err %d\n", err);
			return -1;
		} else {
			*((uint8_t *) testresult) = selftest_req.rsp.reserve[0];
		}
		break;
	default:
		DEVINFO_LOG("invalid sensortype %d\n", err);
	}
	return 1;
}

int oplus_send_reg_config_cmd_to_hub(int sensorType)
{
	int ret = 0;
	unsigned int len = 0;
	union SCP_SENSOR_HUB_DATA reg_req;

	reg_req.req.action = OPLUS_ACTION_CONFIG_REG;
	reg_req.req.data[0] = g_reg_address;
	reg_req.req.data[1] = g_reg_value;
	switch (sensorType) {
	case ID_SAR:
		DEVINFO_LOG("ID_SAR : oplus_send_reg_config_cmd_to_hub");
		reg_req.req.sensorType = OPLUS_SAR;
		break;
	case ID_SARS:
		DEVINFO_LOG("ID_SARS : oplus_send_reg_config_cmd_to_hub");
		reg_req.req.sensorType = OPLUS_SARS;
		break;
	default:
		DEVINFO_LOG("invalid sensortype %d\n", sensorType);
		return -1;
	}

	len = sizeof(reg_req.req);
#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
	ret = mtk_nanohub_req_send(&reg_req);
#else
	ret = scp_sensorHub_req_send(&reg_req, &len, 1);
#endif

	if (ret < 0 || reg_req.rsp.action != OPLUS_ACTION_CONFIG_REG) {
		DEVINFO_LOG("fail! ret %d\n", ret);
		return -1;
	}
	return 1;
}

int get_sensor_parameter(struct cali_data *data)
{
	if (!g_cali_data) {
		DEVINFO_LOG("g_cali_data NULL! \n");
		return -EINVAL;
	}

	if (is_parameter_updated) {
		is_parameter_updated = false;
		sensor_read_oplus_custom(g_cali_data);
	}

	if (data) {
		memcpy(data, g_cali_data, sizeof(struct cali_data));
	} else {
		DEVINFO_LOG("data NULL! \n");
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(get_sensor_parameter);

void update_sensor_parameter(void)
{
	is_parameter_updated = true;
}
EXPORT_SYMBOL_GPL(update_sensor_parameter);

int get_sensor_parameter_rear_als(struct cali_data *data)
{
	sensor_read_oplus_custom(data);
	return 0;
}

static int init_sensorlist_info(void)
{
	int err = 0;
	int handle = -1;
	int sensor = -1;
	int ret = -1;
	struct sensorInfo_t devinfo;

	for (handle = accel; handle < maxhandle; ++handle) {
		sensor = handle_to_sensor(handle);
		if (sensor < 0) {
			continue;
		}
#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
		err = mtk_nanohub_set_cmd_to_hub(sensor,
				CUST_ACTION_GET_SENSOR_INFO, &devinfo);
#else
		err = sensor_set_cmd_to_hub(sensor,
				CUST_ACTION_GET_SENSOR_INFO, &devinfo);
#endif
		if (err < 0) {
			DEVINFO_LOG("sensor(%d) not register\n", sensor);
			strlcpy(sensorlist_info[handle].name,
				"NULL",
				sizeof(sensorlist_info[handle].name));
			continue;
		}

		DEVINFO_LOG("sensor(%s) register\n", devinfo.name);
		strlcpy(sensorlist_info[handle].name,
			devinfo.name,
			sizeof(sensorlist_info[handle].name));
		ret = 0;
	}
	return ret;
}

bool is_sensor_available(char *name)
{
	bool find = false;
	int handle = -1;

	for (handle = accel; handle < maxhandle; ++handle) {
		if (name && (!strcmp(sensorlist_info[handle].name, name))) {
			find = true;
			break;
		}
	}

	return find;
}

int get_light_sensor_type(void)
{
	uint32_t type = 1;
	int ret = 0;

	ret = oplus_get_dts_feature(als, "/odm/light", "als_type", &type);
	if (ret < 0) {
		return NORMAL_LIGHT_TYPE;
	}

	DEVINFO_LOG("get_light_sensor_type = %d", (int)type);
	return (int)type;
}
EXPORT_SYMBOL_GPL(get_light_sensor_type);

int oplus_sensor_cfg_to_hub(uint8_t sensor_id, uint8_t *data, uint8_t count)
{
#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
	return mtk_nanohub_cfg_to_hub(sensor_id, data, count);
#else
	return sensor_cfg_to_hub(sensor_id, data, count);
#endif
}

static int als_cali_read_func(struct seq_file *s, void *v)
{
	void *p = s->private;

	DEVINFO_LOG("Ptr2UINT32(p) = %d \n", Ptr2UINT32(p));
	switch (Ptr2UINT32(p)) {
	case RED_MAX_LUX:
		seq_printf(s, "%d", gdata->red_max_lux);
		break;
	case GREEN_MAX_LUX:
		seq_printf(s, "%d", gdata->green_max_lux);
		break;
	case BLUE_MAX_LUX:
		seq_printf(s, "%d", gdata->blue_max_lux);
		break;
	case WHITE_MAX_LUX:
		seq_printf(s, "%d", gdata->white_max_lux);
		break;
	case CALI_COE:
		seq_printf(s, "%d", gdata->cali_coe);
		break;
	case ROW_COE:
		seq_printf(s, "%d", gdata->row_coe);
		break;
	default:
		seq_printf(s, "not support\n");
	}
	return 0;
}

static ssize_t als_cali_write(struct file *filp, const char *ubuf, size_t cnt, loff_t *data)
{
	char buf[64] = {0};
	void *buf_str = buf;
	long val = 0;
	int ret = 0;
	struct seq_file *s = filp->private_data;
	void *p = s->private;
	int node = Ptr2UINT32(p);

	if (cnt >= sizeof(buf)) {
		return -EINVAL;
	} else {
		if (copy_from_user(buf_str, ubuf, cnt)) {
			return -EFAULT;
		}
	}

	ret = kstrtoul(buf, 0, (unsigned long *)&val);
	DEVINFO_LOG("node1 = %d,val = %ld\n", node, val);

	switch (node) {
	case RED_MAX_LUX:
		gdata->red_max_lux = val;
		break;
	case GREEN_MAX_LUX:
		gdata->green_max_lux = val;
		break;
	case BLUE_MAX_LUX:
		gdata->blue_max_lux = val;
		break;
	case WHITE_MAX_LUX:
		gdata->white_max_lux = val;
		break;
	case CALI_COE:
		gdata->cali_coe = val;
		break;
	case ROW_COE:
		gdata->row_coe = val;
		break;
#ifdef DEBUG_BRIGHTNESS
	case BRIGHTNESS:
		if (g_als_info.brightness != val) {
			g_als_info.brightness = val;
			schedule_delayed_work(&lcdinfo_work, msecs_to_jiffies(10));
			DEVINFO_LOG("set brightness %d to scp\n", g_als_info.brightness);
		}
		break;
#endif
	default:
		DEVINFO_LOG("ivalid node type\n");
	}
	return cnt;
}

static int als_cali_open(struct inode *inode, struct file *file)
{
	return single_open(file, als_cali_read_func, PDE_DATA(inode));
}

static loff_t als_cali_llseek(struct file *file, loff_t offset, int whence)
{
	return file->f_pos;
}

static const struct proc_ops als_cali_para_fops = {
	.proc_open  = als_cali_open,
	.proc_write = als_cali_write,
	.proc_read  = seq_read,
	.proc_release = single_release,
	.proc_lseek = als_cali_llseek,
};

static void get_accgyro_cali_version(void)
{
	int ret;
	uint32_t acc_thrd[3];

	ret = oplus_get_dts_feature(accel, "/odm/gsensor", "gyro_cali_version", &gyro_cali_version);
	if (ret < 0) {
		gyro_cali_version = 1;
	}
	DEVINFO_LOG("gyro_cali_version = %d", gyro_cali_version);

	ret = oplus_get_dts_feature(accel, "/odm/gsensor", "gyro_cali_range", &gyro_cali_range);
	if (ret < 0) {
		gyro_cali_range = 200;
	}
	DEVINFO_LOG("gyro range  [%d]", gyro_cali_range);

	ret = oplus_get_dts_feature(accel, "/odm/gsensor", "acc_cali_range", acc_thrd);
	if (ret < 0) {
		return;
	} else {
		DEVINFO_LOG("acc range x y z [%u, %u, %u]", acc_thrd[0], acc_thrd[1], acc_thrd[2]);
		sprintf(acc_cali_range, "%u %u %u", acc_thrd[0], acc_thrd[1], acc_thrd[2]);
	}

	return;
}

static void oplus_als_cali_data_init(void)
{
	struct proc_dir_entry *pentry;
	struct oplus_als_cali_data *data = NULL;
        int ret = 0;
	int i;

	DEVINFO_LOG("call \n");
	if (gdata) {
		DEVINFO_LOG("has been inited\n");
		return;
	}

	data = kzalloc(sizeof(struct oplus_als_cali_data), GFP_KERNEL);
	if (data == NULL) {
		DEVINFO_LOG("kzalloc fail\n");
		return;
	}
	gdata = data;

	ret = oplus_get_dts_feature(als, "/odm/light", "als_ratio", &gdata->row_coe);
	if (ret < 0) {
		gdata->row_coe = 1000;
	}
	DEVINFO_LOG("row_coe = %d\n", gdata->row_coe);

	ret = oplus_get_dts_feature(als, "/odm/light", "gold_als_factor", &gold_als_factor);
	if (ret < 0) {
		gold_als_factor = 1001;
	}
	DEVINFO_LOG("gold_als_factor = %d\n", gold_als_factor);

	ret = oplus_get_dts_feature(als, "/odm/rear_cct", "gold_rear_als_factor", &gold_rear_als_factor);
	if (ret < 0) {
		gold_rear_als_factor = 1001;
	}
	DEVINFO_LOG("gold_rear_als_factor = %d\n", gold_rear_als_factor);

	if (gdata->proc_oplus_als) {
		DEVINFO_LOG("proc_oplus_als has alread inited\n");
		return;
	}

	sensor_proc_dir = proc_mkdir("sensor", NULL);
	if (!sensor_proc_dir) {
		DEVINFO_LOG("can't create proc_sensor proc\n");
		return;
	}

	gdata->proc_oplus_als =  proc_mkdir("als_cali", sensor_proc_dir);
	if (!gdata->proc_oplus_als) {
		DEVINFO_LOG("can't create proc_oplus_als proc\n");
		return;
	}

	for (i = 0; i < ARRAY_SIZE(als_cali_file); i++) {
		if (als_cali_file[i].node_name) {
			pentry = proc_create_data(als_cali_file[i].node_name, S_IRUGO | S_IWUGO,
						 gdata->proc_oplus_als, &als_cali_para_fops,
						 UINT2Ptr(&als_cali_file[i].id));
			if (!pentry) {
				DEVINFO_LOG("can't create %s\n", als_cali_file[i].node_name);
				ret = -ENOMEM;
			}
		}
	}

	return;
}

static void get_gold_rear_cct(void)
{
	int ret = 0;
	uint32_t gold_rear_cct_val[10] = {0};
	uint32_t gold_rear_cct_r = 0;
	uint32_t gold_rear_cct_g = 0;
	uint32_t gold_rear_cct_b = 0;
	uint32_t gold_rear_cct_c = 0;
	uint32_t gold_rear_cct_w = 0;
	uint32_t gold_rear_cct_f = 0;

        /* get 3000k gold ch */
	ret = oplus_get_dts_feature(rear_cct, "/odm/rear_cct", "gold_rear_cct_3k", gold_rear_cct_val);
	if (ret < 0) {
		return;
	} else {
		gold_rear_cct_r = gold_rear_cct_val[0];
		gold_rear_cct_g = gold_rear_cct_val[1];
		gold_rear_cct_b = gold_rear_cct_val[2];
		gold_rear_cct_c = gold_rear_cct_val[3];
		gold_rear_cct_w = gold_rear_cct_val[4];
		gold_rear_cct_f = gold_rear_cct_val[5];
		DEVINFO_LOG("gold_rear_cct_3k [%u, %u, %u, %u, %u, %u]",
				gold_rear_cct_r, gold_rear_cct_g, gold_rear_cct_b,
				gold_rear_cct_c, gold_rear_cct_w, gold_rear_cct_f);

		sprintf(gold_rear_cct_3k, "%u %u %u %u %u %u",
				gold_rear_cct_r, gold_rear_cct_g, gold_rear_cct_b,
				gold_rear_cct_c, gold_rear_cct_w, gold_rear_cct_f);
	}
        /* get 6000k gold ch */
	ret = oplus_get_dts_feature(rear_cct, "/odm/rear_cct", "gold_rear_cct_6k", gold_rear_cct_val);
	if (ret < 0) {
		return;
	} else {
		gold_rear_cct_r = gold_rear_cct_val[0];
		gold_rear_cct_g = gold_rear_cct_val[1];
		gold_rear_cct_b = gold_rear_cct_val[2];
		gold_rear_cct_c = gold_rear_cct_val[3];
		gold_rear_cct_w = gold_rear_cct_val[4];
		gold_rear_cct_f = gold_rear_cct_val[5];
		DEVINFO_LOG("gold_rear_cct_6k [%u, %u, %u, %u, %u, %u]",
				gold_rear_cct_r, gold_rear_cct_g, gold_rear_cct_b,
				gold_rear_cct_c, gold_rear_cct_w, gold_rear_cct_f);

		sprintf(gold_rear_cct_6k, "%u %u %u %u %u %u",
				gold_rear_cct_r, gold_rear_cct_g, gold_rear_cct_b,
				gold_rear_cct_c, gold_rear_cct_w, gold_rear_cct_f);
	}

	ret = oplus_get_dts_feature(rear_cct, "/odm/rear_cct", "gold_rear_cct_factor", gold_rear_cct_val);
	if (ret < 0) {
		sprintf(gold_rear_cct_factor, "1001 1001 1001 1001 1001 1001");
		return;
	} else {
		gold_rear_cct_r = gold_rear_cct_val[0];
		gold_rear_cct_g = gold_rear_cct_val[1];
		gold_rear_cct_b = gold_rear_cct_val[2];
		gold_rear_cct_c = gold_rear_cct_val[3];
		gold_rear_cct_w = gold_rear_cct_val[4];
		gold_rear_cct_f = gold_rear_cct_val[5];
		DEVINFO_LOG("gold_rear_cct_factor [%u, %u, %u, %u, %u, %u]",
			gold_rear_cct_r, gold_rear_cct_g, gold_rear_cct_b,
			gold_rear_cct_c, gold_rear_cct_w, gold_rear_cct_f);

		sprintf(gold_rear_cct_factor, "%u %u %u %u %u %u",
			gold_rear_cct_r, gold_rear_cct_g, gold_rear_cct_b,
			gold_rear_cct_c, gold_rear_cct_w, gold_rear_cct_f);
	}
}

static ssize_t mag_data_int2str(char *buf)
{
	ssize_t pos = 0;
	int jj = 0;
	int symbol = 1;
	int value = 0;
	int offset = 0;
	uint32_t mag_soft_para[18];
	int ret = 0;
	DEVINFO_LOG("%s call\n", __func__);

	ret = oplus_get_dts_feature(mag, "/odm/msensor", "soft-mag-parameter", mag_soft_para);
	if (ret < 0) {
		DEVINFO_LOG("get msensor node failed");
		return 0;
	}

	for (jj = 0; jj < MAG_PARA_NUM; jj++) {
		value = mag_soft_para[2 * jj];
		symbol = mag_soft_para[(2 * jj) + 1] > 0 ? -1 : 1;
		offset = sprintf(buf + pos, "%d", symbol * value);
		if (offset <= 0) {
			DEVINFO_LOG("sprintf fail: %d\n", jj);
			return 0;
		}
		pos += MAG_PARA_OFFSET;
	}

	DEVINFO_LOG("mag_data_int2str success, pos = %zu.\n", pos);
	return pos;
}

static ssize_t mag_para_read_proc(struct file *file, char __user *buf, size_t count, loff_t *off)
{
	char page[256] = {0};
	int len = 0;

	pr_info("%s call\n", __func__);
	len = mag_data_int2str(page);

	if (len > *off) {
		len -= *off;
	} else {
		len = 0;
	}

	if (copy_to_user(buf, page, (len < count ? len : count))) {
		return -EFAULT;
	}

	*off += len < count ? len : count;
	return (len < count ? len : count);
}

static const struct proc_ops mag_para_fops = {
	.proc_read = mag_para_read_proc,
};

static int oplus_mag_para_init(void)
{
	int rc = 0;
	struct proc_dir_entry *pentry = NULL;
	struct proc_dir_entry *proc_mag_para = NULL;

	pr_info("%s call\n", __func__);

	proc_mag_para =  proc_mkdir("mag_para", sensor_proc_dir);

	if (!proc_mag_para) {
		pr_err("can't create proc_mag_para proc\n");
		rc = -EFAULT;
		goto exit;
	}

	pentry = proc_create("soft_para", 0666, proc_mag_para,
			&mag_para_fops);

	if (!pentry) {
		pr_err("create soft_para proc failed.\n");
		rc = -EFAULT;
		goto exit;
	}

exit:
	return rc;
}

static struct panel_node * find_panel(enum panel_id id)
{
	int index = 0;
	for (index = 0; index < PANEL_NUM; ++index) {
		if (g_panel_node[index].id == id) {
			return &g_panel_node[index];
		}
	}
	return NULL;
}

static void choose_special_gold_cct_value(int support_panel)
{
	int ret = 0;
	int len = 0;
	uint32_t gold_cct_val[10] = {0};
	uint32_t gold_cct_r = 0;
	uint32_t gold_cct_g = 0;
	uint32_t gold_cct_b = 0;
	uint32_t gold_cct_c = 0;
	uint32_t gold_cct_w = 0;
	uint32_t gold_cct_f = 0;
	char als_panel[MAX_SIZE] = {0};
	struct panel_node *p_node = NULL;
	struct device_node *node = NULL;

	p_node = find_panel(support_panel);
	if (p_node == NULL) {
		DEVINFO_LOG("find panel fail\n");
		return;
	}

	snprintf(als_panel, MAX_SIZE, "/odm/als_panel_%s_1", p_node->lcm_name);
	DEVINFO_LOG("%s\n", als_panel);
	node = of_find_node_by_path(als_panel);
	if (node == NULL) {
		DEVINFO_LOG("get %s fail", als_panel);
		return;
	}

	/*get 3000k gold ch*/
	len = of_property_count_elems_of_size(node, "gold_cct_3k", sizeof(uint32_t));
	if (len < 0) {
		DEVINFO_LOG("get feature gold_cct_3k fail\n");
		return;
	}

	ret = of_property_read_variable_u32_array(node, "gold_cct_3k", gold_cct_val, len, 0);
	if (ret < 0) {
		DEVINFO_LOG("gold_cct_3k fail\n");
		return;
	} else {
		gold_cct_r = gold_cct_val[0];
		gold_cct_g = gold_cct_val[1];
		gold_cct_b = gold_cct_val[2];
		gold_cct_c = gold_cct_val[3];
		gold_cct_w = gold_cct_val[4];
		gold_cct_f = gold_cct_val[5];
		DEVINFO_LOG("gold_cct_3k [%u, %u, %u, %u, %u, %u]",
			gold_cct_r, gold_cct_g, gold_cct_b,
			gold_cct_c, gold_cct_w, gold_cct_f);

		sprintf(gold_cct_3k, "%u %u %u %u %u %u",
			gold_cct_r, gold_cct_g, gold_cct_b,
			gold_cct_c, gold_cct_w, gold_cct_f);
	}

	/*get 6000k gold ch*/
	len = of_property_count_elems_of_size(node, "gold_cct_6k", sizeof(uint32_t));
	if (len < 0) {
		DEVINFO_LOG("get feature gold_cct_3k fail\n");
		return;
	}

	ret = of_property_read_variable_u32_array(node, "gold_cct_6k", gold_cct_val, len, 0);
	if (ret < 0) {
		DEVINFO_LOG("gold_cct_6k fail\n");
		return;
	} else {
		gold_cct_r = gold_cct_val[0];
		gold_cct_g = gold_cct_val[1];
		gold_cct_b = gold_cct_val[2];
		gold_cct_c = gold_cct_val[3];
		gold_cct_w = gold_cct_val[4];
		gold_cct_f = gold_cct_val[5];
		DEVINFO_LOG("gold_cct_6k [%u, %u, %u, %u, %u, %u]",
			gold_cct_r, gold_cct_g, gold_cct_b,
			gold_cct_c, gold_cct_w, gold_cct_f);

		sprintf(gold_cct_6k, "%u %u %u %u %u %u",
			gold_cct_r, gold_cct_g, gold_cct_b,
			gold_cct_c, gold_cct_w, gold_cct_f);
	}
}

static void get_front_cct_feature(void)
{
	uint32_t gold_front_cct_val[10] = {0};
	int ret = 0;
	uint32_t gold_cct_r = 0;
	uint32_t gold_cct_g = 0;
	uint32_t gold_cct_b = 0;
	uint32_t gold_cct_c = 0;
	uint32_t gold_cct_w = 0;
	uint32_t gold_cct_f = 0;

	ret = oplus_get_dts_feature(front_cct, "/odm/light", "cct_type", &cct_type);
	if (ret < 0) {
		cct_type = CCT_WISE;
	}
	DEVINFO_LOG("cct_type = %d", cct_type);

	ret = oplus_get_dts_feature(front_cct, "/odm/light", "support_panel", &support_panel);
	if (ret < 0) {
		support_panel = 0; /* not support 2 panel */
	}
	DEVINFO_LOG("support_panel = %d", support_panel);

	if (support_panel > 0) {
		DEVINFO_LOG("choose special gold cct");
		choose_special_gold_cct_value(support_panel);
	} else {
		/*get 3000k gold ch*/
		ret = oplus_get_dts_feature(front_cct, "/odm/light", "gold_cct_3k", gold_front_cct_val);
		if (ret < 0) {
			DEVINFO_LOG("gold_cct_3k fail\n");
			return;
		} else {
			gold_cct_r = gold_front_cct_val[0];
			gold_cct_g = gold_front_cct_val[1];
			gold_cct_b = gold_front_cct_val[2];
			gold_cct_c = gold_front_cct_val[3];
			gold_cct_w = gold_front_cct_val[4];
			gold_cct_f = gold_front_cct_val[5];
			DEVINFO_LOG("gold_cct_3k [%u, %u, %u, %u, %u, %u]",
					gold_cct_r, gold_cct_g, gold_cct_b,
					gold_cct_c, gold_cct_w, gold_cct_f);

			sprintf(gold_cct_3k, "%u %u %u %u %u %u",
					gold_cct_r, gold_cct_g, gold_cct_b,
					gold_cct_c, gold_cct_w, gold_cct_f);
		}

		/*get 6000k gold ch*/
		ret = oplus_get_dts_feature(front_cct, "/odm/light", "gold_cct_6k", gold_front_cct_val);
		if (ret < 0) {
			DEVINFO_LOG("gold_cct_6k fail\n");
			return;
		} else {
			gold_cct_r = gold_front_cct_val[0];
			gold_cct_g = gold_front_cct_val[1];
			gold_cct_b = gold_front_cct_val[2];
			gold_cct_c = gold_front_cct_val[3];
			gold_cct_w = gold_front_cct_val[4];
			gold_cct_f = gold_front_cct_val[5];
			DEVINFO_LOG("gold_cct_6k [%u, %u, %u, %u, %u, %u]",
					gold_cct_r, gold_cct_g, gold_cct_b,
					gold_cct_c, gold_cct_w, gold_cct_f);

			sprintf(gold_cct_6k, "%u %u %u %u %u %u",
					gold_cct_r, gold_cct_g, gold_cct_b,
					gold_cct_c, gold_cct_w, gold_cct_f);
		}
	}

	/* get gold_cct_factor */
	ret = oplus_get_dts_feature(front_cct, "/odm/light", "gold_cct_factor", gold_front_cct_val);
	if (ret < 0) {
		DEVINFO_LOG("gold_cct_factor fail, use default\n");
		sprintf(gold_cct_factor, "%d %d %d %d %d %d", 1001, 1001, 1001, 1001, 1001, 1001);
		return;
	} else {
		gold_cct_r = gold_front_cct_val[0];
		gold_cct_g = gold_front_cct_val[1];
		gold_cct_b = gold_front_cct_val[2];
		gold_cct_c = gold_front_cct_val[3];
		gold_cct_w = gold_front_cct_val[4];
		gold_cct_f = gold_front_cct_val[5];
		DEVINFO_LOG("gold_cct_factor [%u, %u, %u, %u, %u, %u]",
				gold_cct_r, gold_cct_g, gold_cct_b,
				gold_cct_c, gold_cct_w, gold_cct_f);

		sprintf(gold_cct_factor, "%u %u %u %u %u %u",
				gold_cct_r, gold_cct_g, gold_cct_b,
				gold_cct_c, gold_cct_w, gold_cct_f);
	}

	ret = oplus_get_dts_feature(front_cct, "/odm/light", "need_gain_cali", &g_cct_gain_cali);
	if (ret < 0) {
		DEVINFO_LOG("g_cct_gain_cali fail, use default\n");
		g_cct_gain_cali = 0;
	}
	DEVINFO_LOG("g_cct_gain_cali = %d", g_cct_gain_cali);
}

static void sensor_devinfo_work(struct work_struct *dwork)
{
	int ret = 0;
	int count = 10;
	int index = 0;
	int cfg_data[12] = {0};

	do {
		ret = sensor_read_oplus_custom(g_cali_data);
		if (ret) {
			DEVINFO_LOG("try %d\n", count);
			count--;
			msleep(1000);
		}
	} while (ret && count > 0);

	if (ret) {
		DEVINFO_LOG("fail!\n");
		return;
	}

	/*to make sure scp is up*/
	count = 5;
	do {
		ret = init_sensorlist_info();
		if (ret < 0) {
			DEVINFO_LOG("scp access err , try %d\n", count);
			count--;
			msleep(1000);
		}
	} while (ret < 0 && count > 0);

	/* send cfg to scp*/
	/* dynamic bias: cfg_data[0] ~ cfg_data[2] */
	/* static bias: cfg_data[3] ~ cfg_data[5], now cfg static bias */
	for (index = 3; index < 6; index++) {
		cfg_data[index] = g_cali_data->acc_data[index-3];
	}
	if (!is_support_mtk_origin_cali) {
		ret = oplus_sensor_cfg_to_hub(ID_ACCELEROMETER, (uint8_t *)cfg_data, sizeof(cfg_data));
		if (ret < 0) {
			DEVINFO_LOG("send acc config fail\n");
		}
	}
	memset(cfg_data, 0, sizeof(int) * 12);

	/*gyro*/
	/* dynamic bias: cfg_data[0] ~ cfg_data[2] */
	/* static bias: cfg_data[3] ~ cfg_data[5], now cfg static bias */
	for (index = 3; index < 6; index++) {
		cfg_data[index] = g_cali_data->gyro_data[index-3];
	}
	if (!is_support_mtk_origin_cali) {
		ret = oplus_sensor_cfg_to_hub(ID_GYROSCOPE, (uint8_t *)cfg_data, sizeof(cfg_data));
		if (ret < 0) {
			DEVINFO_LOG("send gyro config fail\n");
		}
	}
	memset(cfg_data, 0, sizeof(int) * 12);

	/*ps*/
	for (index = 0; index < 6; index++) {
		cfg_data[index] = g_cali_data->ps_cali_data[index];
	}
	if (!is_support_mtk_origin_cali) {
		ret = oplus_sensor_cfg_to_hub(ID_PROXIMITY, (uint8_t *)cfg_data, sizeof(cfg_data));
		if (ret < 0) {
			DEVINFO_LOG("send ps config fail\n");
		}
	}
	memset(cfg_data, 0, sizeof(int) * 12);

	/*light*/
	cfg_data[0] = g_cali_data->als_factor;
	if (!is_support_mtk_origin_cali) {
		ret = oplus_sensor_cfg_to_hub(ID_LIGHT, (uint8_t *)cfg_data, sizeof(cfg_data));
		if (ret < 0) {
			DEVINFO_LOG("send light config fail\n");
		}
	}
	memset(cfg_data, 0, sizeof(int) * 12);

	/*front cct*/
	for (index = 0; index < 6; index++) {
		cfg_data[index] = g_cali_data->cct_cali_data[index];
	}
	ret = oplus_sensor_cfg_to_hub(ID_CCT, (uint8_t *)cfg_data, sizeof(cfg_data));
	if (ret < 0) {
		DEVINFO_LOG("send cct config fail\n");
	}
	memset(cfg_data, 0, sizeof(int) * 12);

	/*rear cct*/
	for (index = 0; index < 6; index++) {
		cfg_data[index] = g_cali_data->cct_cali_data[index];
	}
	ret = oplus_sensor_cfg_to_hub(ID_REAR_CCT, (uint8_t *)cfg_data, sizeof(cfg_data));
	if (ret < 0) {
		DEVINFO_LOG("send light config fail\n");
	}
	memset(cfg_data, 0, sizeof(int) * 12);

	/*rear_als*/
	cfg_data[0] = g_cali_data->rear_als_factor;
	ret = oplus_sensor_cfg_to_hub(ID_REAR_ALS, (uint8_t *)cfg_data, sizeof(cfg_data));
	if (ret < 0) {
		DEVINFO_LOG("send rear als config fail\n");
	}
	memset(cfg_data, 0, sizeof(int) * 12);

	/*baro_cali*/
	cfg_data[0] = g_cali_data->baro_cali_offset;
	ret = oplus_sensor_cfg_to_hub(ID_PRESSURE, (uint8_t *)cfg_data, sizeof(cfg_data));
	if (ret < 0) {
		DEVINFO_LOG("send baro cali config fail\n");
	}
	memset(cfg_data, 0, sizeof(int) * 12);

	oplus_als_cali_data_init();
	get_accgyro_cali_version();
	get_gold_rear_cct();
	get_acc_gyro_cali_nv_adapt_q_flag();
	oplus_mag_para_init();
	get_front_cct_feature();

	DEVINFO_LOG("success \n");
}

static ssize_t parameter_proc_read(struct file *file, char __user *buf,
    size_t count, loff_t *off)
{
	char page[512];
	int len = 0;

	len = sprintf(page, "{%s,\n %s,\n %s}", para_buf[0], para_buf[1], para_buf[2]);

	if ((para_buf[2][0] == '\0') && (para_buf[1][0] == '\0')) {
		page[len - 4] = ' ';
		page[len - 6] = ' ';
		page[len - 7] = ' ';
	} else if (para_buf[2][0] == '\0') {
		page[len - 4] = ' ';
	}

	if (len > *off) {
		len -= *off;
	} else {
		len = 0;
	}

	if (copy_to_user(buf, page, (len < count ?  len : count))) {
		return -EFAULT;
	}
	*off +=  len < count ?  len : count;
	return (len < count ?  len : count);
}

static const struct proc_ops parameter_proc_fops = {
	.proc_read = parameter_proc_read,
	.proc_write = NULL,
};

int get_msensor_parameter(int num)
{
	int elements = 0;
	int index = 0;
	int para_num = 0;
	int ret = 0;
	uint32_t temp_data;
	uint32_t mag_data[30] = {0};
	const char *libname = NULL;
	const char *match_project = NULL;
	char temp_buf[128] = {0}, msensor[16], float_buf[10];
	char project[10] = "0000";
	struct device_node *node = NULL;
	struct device_node *para_ch_node = NULL;

	sprintf(msensor, "/odm/msensor_%d", num + 1);
	node = of_find_node_by_name(NULL, msensor);
	if (!node) {
		DEVINFO_LOG("find /odm/msensor_%d fail\n", num + 1);
		return -ENOMEM;
	}

	ret = of_property_read_string(node, "libname", &libname);
	if (libname == NULL || ret < 0) {
		DEVINFO_LOG("get libname prop fail");
		return -1;
	}
	DEVINFO_LOG(" %s libname is %s\n", msensor, libname);

	ret = of_property_read_u32(node, "para_num", &para_num);
	if (ret < 0) {
		DEVINFO_LOG("para num is null, no need to match project");
		ret = of_property_read_variable_u32_array(node, "soft-mag-parameter", mag_data, 1, 30);
		if (ret < 0) {
			DEVINFO_LOG("get soft-mag-parameter prop fail");
			return -1;
		}
		elements = ret;
	} else {
		DEVINFO_LOG(" %s match project start, para_num = %d\n", msensor, para_num);
		/*sprintf(project, "%u", get_project());
		DEVINFO_LOG("project %s\n", project);*/
		for_each_child_of_node(node, para_ch_node) {
			DEVINFO_LOG("parse %s", para_ch_node->name);
			ret = of_property_read_string(para_ch_node, "match_projects", &match_project);
			if (ret < 0 || match_project == NULL) {
				DEVINFO_LOG("get match_project prop fail");
				return -1;
			}
			DEVINFO_LOG(" match project %s\n", match_project);

			if (strstr(match_project, project) != NULL) {
				ret = of_property_read_variable_u32_array(para_ch_node, "soft-mag-parameter", mag_data, 1, 30);
				if (ret < 0) {
					DEVINFO_LOG("get soft-mag-parameter prop fail");
					return -1;
				}
				elements = ret;

				DEVINFO_LOG("match project success");
				break;
			}
		}
	}

	if (!strcmp(libname, "mmc") || !strcmp(libname, "mxg")) { /*Memsic parameter need analyze*/
		for (index = 0; index < 9; index++) {
			temp_data = mag_data[2 * index];
			sprintf(float_buf, "%c%d.%d%d%d%d", mag_data[2 * index + 1] ? '-' : ' ',
				temp_data / 10000, temp_data % 10000 / 1000, temp_data % 1000 / 100, temp_data % 100 / 10,
				temp_data % 10);
			sprintf(para_buf[num], "%s,%s", temp_buf, float_buf);
			strcpy(temp_buf, para_buf[num]);
		}
		temp_buf[0] = ' ';
		sprintf(para_buf[num], "\"%s\":[%s]", libname, temp_buf);
	} else if (!strcmp(libname, "akm")) {
		for (index = 1; index < elements; index++) {
			sprintf(para_buf[num], "%s,%d", temp_buf, mag_data[index]);
			strcpy(temp_buf, para_buf[num]);
		}
		sprintf(para_buf[num], "\"%s\":[%u%s]", libname, mag_data[0], temp_buf);
	}

	return 0;
}

void  mag_soft_parameter_init(void)
{
	int ret = -1;
	int index = 0;

	for (index = 0; index < 3; index++) {
		ret = get_msensor_parameter(index);
		if (ret == -1) {
			para_buf[index][0] = '\0';
		} else {
			proc_create("mag_soft_parameter.json", 0666, NULL, &parameter_proc_fops);
		}
	}
}

static int sensor_feature_read_func(struct seq_file *s, void *v)
{
	void *p = s->private;
	int ret = 0;
	int selftest_result = 0;

	DEVINFO_LOG("Ptr2UINT32(p) = %d \n", Ptr2UINT32(p));
	switch (Ptr2UINT32(p)) {
	case IS_SUPPROT_HWCALI:
		if (!strcmp(sensorlist_info[ps].name, "tcs3701")) {
			seq_printf(s, "%d", 1);
		} else if (!strcmp(sensorlist_info[ps].name, "tmd2755x12")) {
			seq_printf(s, "%d", 1);
		} else {
			seq_printf(s, "%d", 0);
		}
		break;
	case IS_IN_FACTORY_MODE:
		seq_printf(s, "%d", 1);
		break;
	case IS_SUPPORT_NEW_ARCH:
		seq_printf(s, "%d", is_support_new_arch);
		break;
	case IS_SUPPORT_MTK_ORIGIN_CALI:
		seq_printf(s, "%d", is_support_mtk_origin_cali);
		break;
	case GYRO_CALI_VERSION:
		seq_printf(s, "%d", gyro_cali_version);
		break;
	case ACC_CALI_RANGE:
		seq_printf(s, "%s", acc_cali_range);
		break;
	case CONFIG_SAR_REG:
		seq_printf(s, "0x%x", g_reg_value);
		break;
	case SAR_NUM:
		seq_printf(s, "0x%x", g_sar_num);
		break;
	case DO_MAG_SELFTEST:
#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
		ret = oplus_send_selftest_cmd_to_hub(ID_MAGNETIC_FIELD, &selftest_result);
#else
		ret = oplus_send_selftest_cmd_to_hub(ID_MAGNETIC, &selftest_result);
#endif
		if (ret < 0 || selftest_result < 0) {
			seq_printf(s, "%d", -1);
		} else {
			seq_printf(s, "%d", 0);
		}
		break;
	case GOLD_REAR_CCT_3K:
		seq_printf(s, "%s", gold_rear_cct_3k);
		DEVINFO_LOG("gold_rear_cct_3k = %s \n", gold_rear_cct_3k);
		break;
	case GOLD_REAR_CCT_6K:
		DEVINFO_LOG("gold_rear_cct_6k = %s \n", gold_rear_cct_6k);
		seq_printf(s, "%s", gold_rear_cct_6k);
		break;
	case GYRO_CALI_ADAPT_Q:
		seq_printf(s, "%d", gyro_cali_adapt_q);
		break;
	case ACC_CALI_ADAPT_Q:
		seq_printf(s, "%d", acc_cali_adapt_q);
		break;
	case GOLD_ALS_FACTOR:
		DEVINFO_LOG("gold_als_factor = %d \n", gold_als_factor);
		seq_printf(s, "%d", gold_als_factor);
		break;
	case GOLD_REAR_ALS_FACTOR:
		DEVINFO_LOG("gold_rear_als_factor = %d \n", gold_rear_als_factor);
		seq_printf(s, "%d", gold_rear_als_factor);
		break;
	case GOLD_REAR_CCT_FACTOR:
		DEVINFO_LOG("gold_rear_cct_factor = %s \n", gold_rear_cct_factor);
		seq_printf(s, "%s", gold_rear_cct_factor);
		break;
	case GYRO_CALI_RANGE:
		seq_printf(s, "%d", gyro_cali_range);
		break;
	case GOLD_CCT_3K:
		seq_printf(s, "%s", gold_cct_3k);
		DEVINFO_LOG("gold_cct_3k = %s \n", gold_cct_3k);
		break;
	case GOLD_CCT_6K:
		DEVINFO_LOG("gold_cct_6k = %s \n", gold_cct_6k);
		seq_printf(s, "%s", gold_cct_6k);
		break;
	case GOLD_CCT_FACTOR:
		DEVINFO_LOG("gold_cct_factor = %s \n", gold_cct_factor);
		seq_printf(s, "%s", gold_cct_factor);
		break;
	case CCT_TYPE:
		seq_printf(s, "%d", cct_type);
		break;
	case GOLD_CCT_CHANNELS:
		seq_printf(s, "%d", gold_cct_channels);
		break;
	case CCT_GAIN_CALI:
		DEVINFO_LOG("g_cct_gain_cali = %d \n", g_cct_gain_cali);
		seq_printf(s, "%d", g_cct_gain_cali);
		break;
	default:
		seq_printf(s, "not support chendai\n");
	}
	return 0;
}

static ssize_t sensor_feature_write(struct file *filp, const char *ubuf, size_t cnt, loff_t *data)
{
	char buf[64];
	void *buf_str = buf;
	long val = 0;
	int ret = 0;
	int result = 0;
	int cfg_data[12] = {0};
	int index = 0;
	struct seq_file *s = filp->private_data;
	void *p = s->private;
	int node = Ptr2UINT32(p);

	if (cnt >= sizeof(buf)) {
		return -EINVAL;
	} else {
		if (copy_from_user(buf_str, ubuf, cnt)) {
			return -EFAULT;
		}
	}

	ret = kstrtoul(buf, 0, (unsigned long *)&val);
	DEVINFO_LOG("node1 = %d,val = %ld buf = %s\n", node, val, buf);

	switch (node) {
	case IS_SUPPROT_HWCALI:
		break;
	case IS_IN_FACTORY_MODE:
		switch (val) {
		case PS_FACTORY_MODE:
			ret = oplus_send_factory_mode_cmd_to_hub(ID_PROXIMITY, 1, &result);
			break;
		case PS_NORMAL_MODE:
			ret = oplus_send_factory_mode_cmd_to_hub(ID_PROXIMITY, 0, &result);
			break;
		case GSENSOR_FACTORY_MODE:
			ret = oplus_send_factory_mode_cmd_to_hub(ID_ACCELEROMETER, 1, &result);
			break;
		case GSENSOR_NORMAL_MODE:
			ret = oplus_send_factory_mode_cmd_to_hub(ID_ACCELEROMETER, 0, &result);
			break;
		case CCT_FACTORY_MODE:
			ret = oplus_send_factory_mode_cmd_to_hub(ID_CCT, 1, &result);
			if (result != 9) {
				msleep(300);
				ret = oplus_send_factory_mode_cmd_to_hub(ID_CCT, 1, &result);
			}
			break;
		case CCT_NORMAL_MODE:
			ret = oplus_send_factory_mode_cmd_to_hub(ID_CCT, 0, &result);
			if (result != 9) {
				msleep(300);
				ret = oplus_send_factory_mode_cmd_to_hub(ID_CCT, 0, &result);
			}
			break;
		case CFG_CCT_CALI_DATA_MODE:
			ret = sensor_read_oplus_custom(g_cali_data);
			if (ret) {
				DEVINFO_LOG("try again\n");
				msleep(100);
				sensor_read_oplus_custom(g_cali_data);
			}
			for (index = 0; index < 12; index++) {
				cfg_data[index] = g_cali_data->cct_cali_data[index];
			}
			DEVINFO_LOG("cct_cali_data [%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d]\n",
				cfg_data[0], cfg_data[1], cfg_data[2],
				cfg_data[3], cfg_data[4], cfg_data[5],
				cfg_data[6], cfg_data[7], cfg_data[8],
				cfg_data[9], cfg_data[10], cfg_data[11]);
			ret = oplus_sensor_cfg_to_hub(ID_CCT, (uint8_t *)cfg_data, sizeof(cfg_data));
			if (ret < 0) {
				DEVINFO_LOG("send cct config fail\n");
			}
			break;
		case LEAK_CALI_NORMAL_MODE:
			ret = oplus_send_factory_mode_cmd_to_hub(ID_PWM_RGB, 0, &result);
			break;
		case LEAR_CALI_MODE:
			ret = oplus_send_factory_mode_cmd_to_hub(ID_PWM_RGB, 1, &result);
			break;
		case CCT_FACTORY_512_GAIN:
			ret = oplus_send_factory_mode_cmd_to_hub(ID_PWM_RGB, 2, &result);
			break;
		case CCT_FACTORY_1024_GAIN:
			ret = oplus_send_factory_mode_cmd_to_hub(ID_PWM_RGB, 3, &result);
			break;
		case CCT_FACTORY_2048_GAIN:
			ret = oplus_send_factory_mode_cmd_to_hub(ID_PWM_RGB, 4, &result);
			break;
		case CCT_FACTORY_GAIN_NORMAL:
			ret = oplus_send_factory_mode_cmd_to_hub(ID_PWM_RGB, 5, &result);
			break;
		default:
			DEVINFO_LOG("ivalid sensor mode\n");
		}
		if (ret < 0 || result != 1) {
			DEVINFO_LOG("set_factory_mode fail\n");
		}
		break;
	case CONFIG_SAR_REG:
		sscanf(buf, "%x %x", &g_reg_address, &g_reg_value);
		DEVINFO_LOG("buf %s, g_reg_add = 0x%x g_reg_val = 0x%x,g_sar_num = 0x%x\n", buf, g_reg_address, g_reg_value, g_sar_num);
		ret = oplus_send_reg_config_cmd_to_hub(g_sar_num);
		if (ret < 0) {
			DEVINFO_LOG("send sar config fail\n");
		}
		break;
	case SAR_NUM:
		sscanf(buf, "%ld", &val);
		DEVINFO_LOG("sar_num = %ld\n", val);
		g_sar_num = val;
		break;
	default:
		DEVINFO_LOG("ivalid node type\n");
	}
	return cnt;
}

static int sensor_feature_open(struct inode *inode, struct file *file)
{
	return single_open(file, sensor_feature_read_func, PDE_DATA(inode));
}

static loff_t sensor_llseek(struct file *file, loff_t offset, int whence)
{
	return file->f_pos;
}

static const struct proc_ops sensor_info_fops = {
	.proc_open  = sensor_feature_open,
	.proc_write = sensor_feature_write,
	.proc_read  = seq_read,
        .proc_lseek = sensor_llseek,
	.proc_release = single_release,
};

static int oplus_sensor_feature_init(void)
{
	struct proc_dir_entry *p_entry;
	static struct proc_dir_entry *oplus_sensor = NULL;
	int i;

	oplus_sensor = proc_mkdir("oplusSensorFeature", NULL);
	if (!oplus_sensor) {
		DEVINFO_LOG("proc_mkdir err\n ");
		return -ENOMEM;
	}

	for (i = 0; i < ARRAY_SIZE(sensor_feature_file); i++) {
		if (sensor_feature_file[i].node_name) {
		p_entry = proc_create_data(sensor_feature_file[i].node_name, S_IRUGO | S_IWUGO,
						  oplus_sensor, &sensor_info_fops, UINT2Ptr(&sensor_feature_file[i].id));
			if (!p_entry) {
				DEVINFO_LOG("create %s err\n", sensor_feature_file[i].node_name);
				proc_remove(oplus_sensor);
				oplus_sensor = NULL;
				return -ENOMEM;
			}
		}
	}

	return 0;
}
#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
void __attribute__((weak)) scp_A_register_notify(struct notifier_block *nb)
{
}

void __attribute__((weak)) scp_A_unregister_notify(struct notifier_block *nb)
{
}

static int scp_ready_event(struct notifier_block *this,
    unsigned long event, void *ptr)
{
	if (event == SCP_EVENT_READY) {
		DEVINFO_LOG(" receiver SCP_EVENT_READY event send cfg data\n ");
		schedule_delayed_work(&parameter_work, msecs_to_jiffies(100));
	}

	return NOTIFY_DONE;
}

static struct notifier_block scp_ready_notifier = {
	.notifier_call = scp_ready_event,
};
#endif
static int scp_utc_sync_pm_event(struct notifier_block *notifier,
    unsigned long pm_event, void *unused)
{
	switch (pm_event) {
	case PM_SUSPEND_PREPARE:
	case PM_HIBERNATION_PREPARE:
		atomic_set(&utc_suspend, 1);
		break;
	case PM_POST_RESTORE:
	case PM_POST_SUSPEND:
	case PM_POST_HIBERNATION:
		atomic_set(&utc_suspend, 0);
		schedule_delayed_work(&utc_work, msecs_to_jiffies(100));
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block scp_utc_sync_notifier = {
	.notifier_call = scp_utc_sync_pm_event,
	.priority = 0,
};

static int lcdinfo_callback(struct notifier_block *nb,
    unsigned long event, void *data)
{
	int val = 0;
	if (!data) {
		return 0;
	}
	switch (event) {
	case LCM_DC_MODE_TYPE:
		val = *(bool*)data;
		if (val != g_als_info.dc_mode) {
			g_als_info.dc_mode = val;
			schedule_delayed_work(&lcdinfo_work, 0);
		}
		break;
	case LCM_BRIGHTNESS_TYPE:
		val = *(int*)data;
		if (val <= lb_bri_max) {
			val = val / 20 * 20;
		} else {
			val = 2048;
		}
		if (val != g_als_info.brightness) {
			g_als_info.brightness = val;
			if (g_als_info.use_lb_algo) {
				schedule_delayed_work(&lcdinfo_work, 0);
			}
		}

		break;
	case LCM_PWM_TURBO:
		val = *(bool*)data;
		if (g_support_pwm_turbo) {
			if (val != g_als_info.pwm_turbo) {
				g_als_info.pwm_turbo = val;
				schedule_delayed_work(&lcdinfo_work, 0);
			}
		}
		break;
	case LCM_ADFR_MIN_FPS:
		val = *(int*)data;
		if (g_need_to_sync_lcd_rate) {
			g_als_info.fps = val;
			schedule_delayed_work(&lcdinfo_work, 0);
		}
		break;
	default:
		break;
	}
	return 0;
}
static struct notifier_block lcdinfo_notifier = {
	.notifier_call = lcdinfo_callback,
};

static int ssc_interactive_parse_dts(void)
{
	int ret = 0;
	int report_brightness = 0;
	int support_bri_to_scp = 0;
	int support_pwm_turbo = 0;
	int need_to_sync_lcd_rate = 0;

	struct device_node *node = NULL;

	node = of_find_node_by_name(NULL, "ssc_interactive");
	if (!node) {
		DEVINFO_LOG("find ssc_interactive fail\n");
		return -ENOMEM;
	}

	ret = of_property_read_u32(node, "report_brightness", &report_brightness);
	if (ret != 0) {
		DEVINFO_LOG("read report_brightness fail\n");
	}

	if (report_brightness == 1) {
		g_report_brightness = true;
		DEVINFO_LOG("support brightness report\n");
	}

	ret = of_property_read_u32(node, "support_bri_to_scp", &support_bri_to_scp);
	if (ret != 0) {
		DEVINFO_LOG("read support_bri_to_scp fail\n");
	}

	if (support_bri_to_scp == 1) {
		g_support_bri_to_scp = true;
		DEVINFO_LOG("support bri_to_scp\n");
	}

	g_support_bri_to_hal = true;

	ret = of_property_read_u32(node, "support_pwm_turbo", &support_pwm_turbo);
	if (ret != 0) {
		DEVINFO_LOG("read support_pwm_turbo fail\n");
	}

	support_pwm_turbo = 1;
	if (support_pwm_turbo == 1) {
		g_support_pwm_turbo = true;
		DEVINFO_LOG("support pwm_turbo report\n");
	}


	ret = of_property_read_u32(node, "need_to_sync_lcd_rate", &need_to_sync_lcd_rate);
	if (ret != 0) {
		DEVINFO_LOG("read need_to_sync_lcd_rate fail\n");
	}

	if (need_to_sync_lcd_rate == 1) {
		g_need_to_sync_lcd_rate = true;
		DEVINFO_LOG("need_to_sync_lcd_rate\n");
	}

	return 0;
}

static int __init sensor_devinfo_init(void)
{
	int ret = 0;

	ssc_interactive_parse_dts();
	mag_soft_parameter_init();
	get_new_arch_info();
	is_support_lb_algo();
	get_mtk_cali_origin_info();
	get_lb_max_brightness();

	ret = oplus_sensor_feature_init();
	if (ret != 0) {
		DEVINFO_LOG("oplus_sensor_feature_init err\n ");
		return -ENOMEM;
	}

	g_cali_data = kzalloc(sizeof(struct cali_data), GFP_KERNEL);
	if (!g_cali_data) {
		DEVINFO_LOG("kzalloc err\n ");
		return -ENOMEM;
	}
	g_als_info.brightness = 10000;
	g_als_info.dc_mode = 0;
        /*g_als_info.use_lb_algo = true;*/
	atomic_set(&utc_suspend, 0);
	INIT_DELAYED_WORK(&utc_work, sync_utc2scp_work);
	schedule_delayed_work(&utc_work, msecs_to_jiffies(2000));
	register_pm_notifier(&scp_utc_sync_notifier);
	register_lcdinfo_notifier(&lcdinfo_notifier);
	INIT_DELAYED_WORK(&lcdinfo_work, transfer_lcdinfo_to_scp);
	/*init parameter*/
	INIT_DELAYED_WORK(&parameter_work, sensor_devinfo_work);
	schedule_delayed_work(&parameter_work, msecs_to_jiffies(100));
	#ifdef CONFIG_OPLUS_SENSOR_MTK68XX
	scp_A_register_notify(&scp_ready_notifier);
	#endif

	return 0;
}

late_initcall(sensor_devinfo_init);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Murphy");
