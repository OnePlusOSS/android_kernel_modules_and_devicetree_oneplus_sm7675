#ifndef _HAPTIC_COMMON_H_
#define _HAPTIC_COMMON_H_
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
#include <linux/wait.h>
#include <linux/mutex.h>

#define VMAX_GAIN_NUM							17
#define VMAX_GAIN_NUM_V2						25
#define HAPTIC_NUM								2
#define DEVICE_ID_0815							815
#define DEVICE_ID_0832							832
#define DEVICE_ID_0833							833
#define DEVICE_ID_81538							81538
#define DEVICE_ID_0809							809
#define DEVICE_ID_1419							1419
#define DEVICE_ID_0816							816

#define F0_VAL_MAX_0815							(1800)
#define F0_VAL_MIN_0815							(1600)
#define F0_VAL_MAX_081538						(1600)
#define F0_VAL_MIN_081538						(1400)
#define F0_VAL_MAX_0832							(2350)
#define F0_VAL_MIN_0832							(2250)
#define F0_VAL_MAX_0833							(2380)
#define F0_VAL_MIN_0833							(2260)
#define F0_VAL_MIN_1419							(1950)
#define F0_VAL_MAX_1419							(2150)
#define F0_VAL_MIN_0816							(1200)
#define F0_VAL_MAX_0816							(1400)

//0809 & 08015
#define OPLUS_162HZ_F0							1640
#define OPLUS_166HZ_F0							1680
#define OPLUS_170HZ_F0							1720
#define OPLUS_174HZ_F0							1760
#define OPLUS_178HZ_F0							1800

//1419
#define OPLUS_197HZ_F0							1980
#define OPLUS_201HZ_F0							2020
#define OPLUS_205HZ_F0							2060
#define OPLUS_209HZ_F0							2100
#define OPLUS_213HZ_F0							2150

/* 0816 */
#define OPLUS_124HZ_F0							1240
#define OPLUS_128HZ_F0							1280
#define OPLUS_132HZ_F0							1320
#define OPLUS_136HZ_F0							1360
#define OPLUS_140HZ_F0							1400

#define OPLUS_161HZ_F0							1610
#define OPLUS_163HZ_F0							1630
#define OPLUS_165HZ_F0							1650
#define OPLUS_167HZ_F0							1670
#define OPLUS_169HZ_F0							1690
#define OPLUS_171HZ_F0							1710
#define OPLUS_173HZ_F0							1730
#define OPLUS_175HZ_F0							1750
#define OPLUS_177HZ_F0							1770
#define OPLUS_179HZ_F0							1790

#define OPLUS_196HZ_F0							1960
#define OPLUS_198HZ_F0							1980
#define OPLUS_200HZ_F0							2000
#define OPLUS_202HZ_F0							2020
#define OPLUS_204HZ_F0							2040
#define OPLUS_206HZ_F0							2060
#define OPLUS_208HZ_F0							2080
#define OPLUS_210HZ_F0							2100
#define OPLUS_212HZ_F0							2120
#define OPLUS_214HZ_F0							2140

#define OPLUS_121HZ_F0							1210
#define OPLUS_123HZ_F0							1230
#define OPLUS_125HZ_F0							1250
#define OPLUS_127HZ_F0							1270
#define OPLUS_129HZ_F0							1290
#define OPLUS_131HZ_F0							1310
#define OPLUS_133HZ_F0							1330
#define OPLUS_135HZ_F0							1350
#define OPLUS_137HZ_F0							1370
#define OPLUS_139HZ_F0							1390

#define SG_INPUT_DOWN_HIGH						302
#define SG_INPUT_UP_HIGH						303
#define SG_INPUT_DOWN_LOW						304
#define SG_INPUT_UP_LOW							305
#define INPUT_HIGH								112
#define INPUT_MEDI								111
#define INPUT_LOW								110

#define DEFAULT_BOOST_VOLT						0x4F

#define OPLUS_DEV_HAPTIC_NAME					"awinic_haptic"

#define IOCTL_MMAP_PAGE_ORDER					2
#define IOCTL_MMAP_BUF_SUM						16
#define IOCTL_MMAP_BUF_SIZE						1000
#define IOCTL_HWINFO							0x05

#define IOCTL_IOCTL_GROUP						0x52
#define IOCTL_WAIT_BUFF_VALID_MAX_TRY			100
#define IOCTL_GET_HWINFO						_IO(IOCTL_IOCTL_GROUP, 0x03)
#define IOCTL_SET_FREQ							_IO(IOCTL_IOCTL_GROUP, 0x04)
#define IOCTL_SETTING_GAIN						_IO(IOCTL_IOCTL_GROUP, 0x05)
#define IOCTL_OFF_MODE							_IO(IOCTL_IOCTL_GROUP, 0x06)
#define IOCTL_TIMEOUT_MODE						_IO(IOCTL_IOCTL_GROUP, 0x07)
#define IOCTL_RAM_MODE							_IO(IOCTL_IOCTL_GROUP, 0x08)
#define IOCTL_MODE_RTP_MODE						_IO(IOCTL_IOCTL_GROUP, 0x09)
#define IOCTL_STREAM_MODE						_IO(IOCTL_IOCTL_GROUP, 0x0A)
#define IOCTL_UPDATE_RAM						_IO(IOCTL_IOCTL_GROUP, 0x10)
#define IOCTL_GET_F0							_IO(IOCTL_IOCTL_GROUP, 0x11)
#define IOCTL_STOP_MODE							_IO(IOCTL_IOCTL_GROUP, 0x12)
#define IOCTL_F0_UPDATE							_IO(IOCTL_IOCTL_GROUP, 0x13)

#define HAPTIC_WAVEFORM_INDEX_TRANSIENT			(8)
#define HAPTIC_WAVEFORM_INDEX_SINE_CYCLE		(9)
#define HAPTIC_WAVEFORM_INDEX_HIGH_TEMP			(51)
#define HAPTIC_WAVEFORM_INDEX_OLD_STEADY		(52)
#define HAPTIC_WAVEFORM_INDEX_LISTEN_POP		(53)
#define HAPTIC_WAVEFORM_INDEX_ZERO				(0)

#define AUDIO_READY_STATUS						(1024)
#define RINGTONES_START_INDEX					(1)
#define RINGTONES_END_INDEX						(40)
#define RINGTONES_SIMPLE_INDEX					(48)
#define RINGTONES_PURE_INDEX					(49)
#define NEW_RING_START							(118)
#define NEW_RING_END							(160)
#define OS12_NEW_RING_START						(70)
#define OS12_NEW_RING_END						(89)
#define OPLUS_RING_START						(161)
#define OPLUS_RING_END							(170)

#define OS14_NEW_RING_START						(371)
#define OS14_NEW_RING_END						(410)
#define OS15_ALARM_RING_START						(322)
#define OS15_ALARM_RING_END						(333)
#define OS15_OPERATOR_RING_START					(347)
#define OS15_OPERATOR_RING_END						(354)
#define ALCLOUDSCAPE_START						(94)
#define ALCLOUDSCAPE_END						(99)
#define RINGTONE_NOTIF_ALARM_START				(201)
#define RINGTONE_NOTIF_ALARM_END				(293)

#define HAPTIC_MAX_GAIN							(255)
#define HAPTIC_GAIN_LIMIT						(128)
#define HAPTIC_RAM_VBAT_COMP_GAIN				(0x80)
#define HAPTIC_MAX_LEVEL						(2400)
#define HAPTIC_OLD_TEST_LEVEL					(2550)
#define HAPTIC_MAX_VBAT_SOC						(100)
#define OPLUS_HAPTIC_MAX_VOL					(95)

enum haptic_vibration_style {
	HAPTIC_VIBRATION_CRISP_STYLE = 0,
	HAPTIC_VIBRATION_SOFT_STYLE = 1,
};

typedef enum haptic_buf_status {
	MMAP_BUF_DATA_VALID = 0x55,
	MMAP_BUF_DATA_FINISHED = 0xaa,
	MMAP_BUF_DATA_INVALID = 0xff,
} haptic_buf_status_e;

enum haptic_motor_old_test_mode {
    MOTOR_OLD_TEST_TRANSIENT = 1,
    MOTOR_OLD_TEST_STEADY = 2,
    MOTOR_OLD_TEST_HIGH_TEMP_HUMIDITY = 3,
    MOTOR_OLD_TEST_LISTEN_POP = 4,
    MOTOR_OLD_TEST_ALL_NUM,
};

enum haptic_work_mode {
	HAPTIC_RAM_LOOP_MODE = 0,
	HAPTIC_CONT_MODE = 1,
	HAPTIC_RAM_MODE = 2,
	HAPTIC_RTP_MODE = 3,
	HAPTIC_TRIG_MODE = 4,
	HAPTIC_STANDBY_MODE = 5,
};

#define oh_err(format, ...) \
	pr_err("[oplus_haptic]" format, ##__VA_ARGS__)

#define oh_info(format, ...) \
	pr_info("[oplus_haptic]" format, ##__VA_ARGS__)

#define oh_dbg(format, ...) \
	pr_debug("[oplus_haptic]" format, ##__VA_ARGS__)

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
#ifndef PDE_DATA
#define PDE_DATA pde_data
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#define DECLARE_PROC_OPS(name, open_func, read_func, write_func, release_func) \
					static const struct proc_ops name = { \
						.proc_open	= open_func,	  \
						.proc_write = write_func,	  \
						.proc_read	= read_func,	  \
						.proc_release = release_func, \
						.proc_lseek	= default_llseek, \
					}
#else
#define DECLARE_PROC_OPS(name, open_func, read_func, write_func, release_func) \
					static const struct file_operations name = { \
						.open  = open_func, 	 \
						.write = write_func,	 \
						.read  = read_func, 	 \
						.release = release_func, \
						.owner = THIS_MODULE,	 \
					}
#endif

typedef  struct vmax_map {
	int level;
	int vmax;
	int gain;
}vmax_map_t;

typedef struct haptic_common_data {
	struct i2c_client *i2c;
	struct device *dev;
    struct pinctrl *pinctrl;
	struct pinctrl_state *pinctrl_state;
	struct led_classdev cdev;
    int reset_gpio;
	int irq_gpio;
	uint8_t max_boost_vol;
	unsigned int vbat_low_soc;
	unsigned int vbat_low_soc_cold;
	int vbat_low_temp;
	unsigned int vbat_low_vmax_level;

	struct work_struct  motor_old_test_work;
	unsigned int motor_old_test_mode;
	int gain;
	uint32_t rtp_file_num;
	uint32_t f0;

	int device_id;
	bool livetap_support;
	bool auto_break_mode_support;
	void *chip_data;
	int vibration_style;
	struct oplus_haptic_operations *haptic_common_ops;
	struct proc_dir_entry *prEntry_da;
	struct proc_dir_entry *prEntry_tmp;

	struct mmap_buf_format *start_buf;
	uint8_t *rtp_ptr;
	struct mutex lock;

}haptic_common_data_t;

struct oplus_haptic_operations {
	int (*chip_interface_init)(haptic_common_data_t *pdata);
	int (*chip_interrupt_init)(void *chip_data);
	irqreturn_t (*chip_irq_isr)(int irq, void *data);
	int (*haptic_init)(void *chip_data);
	void (*haptic_brightness_set)(enum led_brightness level, void *chip_data);
	enum led_brightness (*haptic_brightness_get)(void *chip_data);
	int (*add_misc_dev)(void);

	ssize_t (*cali_store)(void *chip_data, const char *buf, uint32_t);
	ssize_t (*cali_show)(void *chip_data, char *buf);
	ssize_t (*f0_store)(void *chip_data, const char *buf, uint32_t);
	ssize_t (*f0_show)(void *chip_data, char *buf);
	ssize_t (*seq_store)(void *chip_data, const char *buf);
	ssize_t (*seq_show)(void *chip_data, char *buf);
	ssize_t (*reg_store)(void *chip_data, const char *buf);
	ssize_t (*reg_show)(void *chip_data, char *buf);
	ssize_t (*gain_store)(void *chip_data, const char *buf,uint32_t);
	ssize_t (*gain_show)(void *chip_data, char *buf);
	ssize_t (*state_store)(void *chip_data, const char *buf);
	ssize_t (*state_show)(void *chip_data, char *buf);
	ssize_t (*rtp_store)(void *chip_data, const char *buf, uint32_t);
	ssize_t (*rtp_show)(void *chip_data, char *buf);
	ssize_t (*ram_store)(void *chip_data, const char *buf);
	ssize_t (*duration_store)(void *chip_data, const char *buf, uint32_t);
	ssize_t (*duration_show)(void *chip_data, char *buf);
	ssize_t (*osc_cali_store)(void *chip_data, const char *buf);
	ssize_t (*osc_cali_show)(void *chip_data, char *buf);
	ssize_t (*ram_update_store)(void *chip_data, const char *buf, uint32_t);
	ssize_t (*ram_update_show)(void *chip_data, char *buf);
	ssize_t (*ram_vbat_comp_store)(void *chip_data, const char *buf, uint32_t);
	ssize_t (*ram_vbat_comp_show)(void *chip_data, char *buf);
	ssize_t (*lra_resistance_store)(void *chip_data, const char *buf);
	ssize_t (*lra_resistance_show)(void *chip_data, char *buf);
	ssize_t (*f0_save_store)(void *chip_data, const char *buf);
	ssize_t (*f0_save_show)(void *chip_data, char *buf);
	ssize_t (*activate_store)(void *chip_data, const char *buf, uint32_t val);
	ssize_t (*activate_show)(void *chip_data, char *buf);
	ssize_t (*drv_vboost_store)(void *chip_data, const char *buf);
	ssize_t (*drv_vboost_show)(void *chip_data, char *buf);
	ssize_t (*detect_vbat_show)(void *chip_data, char *buf);
	ssize_t (*audio_delay_store)(void *chip_data, const char *buf);
	ssize_t (*audio_delay_show)(void *chip_data, char *buf);
	ssize_t (*osc_data_store)(void *chip_data, const char *buf);
	ssize_t (*osc_data_show)(void *chip_data, char *buf);
	ssize_t (*f0_data_store)(void *chip_data, const char *buf);
	ssize_t (*f0_data_show)(void *chip_data, char *buf);
	ssize_t (*oplus_brightness_store)(void *chip_data, const char *buf, uint32_t);
	ssize_t (*oplus_brightness_show)(void *chip_data, char *buf);
	ssize_t (*oplus_duration_store)(void *chip_data, const char *buf, uint32_t);
	ssize_t (*oplus_duration_show)(void *chip_data, char *buf);
	ssize_t (*oplus_activate_store)(void *chip_data, const char *buf, uint32_t);
	ssize_t (*oplus_activate_show)(void *chip_data, char *buf);
	ssize_t (*oplus_state_store)(void *chip_data, const char *buf);
	ssize_t (*oplus_state_show)(void *chip_data, char *buf);
	ssize_t (*vmax_store)(void *chip_data, const char *buf, uint32_t);
	ssize_t (*vmax_show)(void *chip_data, char *buf);
	ssize_t (*waveform_index_store)(void *chip_data, const char *buf);
	ssize_t (*waveform_index_show)(void *chip_data, char *buf);
	ssize_t (*device_id_store)(void *chip_data, const char *buf);
	ssize_t (*device_id_show)(void *chip_data, char *buf);
	ssize_t (*livetap_support_store)(void *chip_data, const char *buf, int);
	ssize_t (*livetap_support_show)(void *chip_data, char *buf);
	ssize_t (*ram_test_store)(void *chip_data, const char *buf);
	ssize_t (*ram_test_show)(void *chip_data, char *buf);
	ssize_t (*rtp_going_store)(void *chip_data, const char *buf);
	ssize_t (*rtp_going_show)(void *chip_data, char *buf);
	ssize_t (*gun_type_store)(void *chip_data, const char *buf);
	ssize_t (*gun_type_show)(void *chip_data, char *buf);
	ssize_t (*gun_mode_store)(void *chip_data, const char *buf);
	ssize_t (*gun_mode_show)(void *chip_data, char *buf);
	ssize_t (*bullet_nr_store)(void *chip_data, const char *buf);
	ssize_t (*bullet_nr_show)(void *chip_data, char *buf);

/*aw*/
	ssize_t (*activate_mode_store)(void *chip_data, const char *buf);
	ssize_t (*activate_mode_show)(void *chip_data, char *buf);
	ssize_t (*index_store)(void *chip_data, const char *buf);
	ssize_t (*index_show)(void *chip_data, char *buf);
	ssize_t (*loop_store)(void *chip_data, const char *buf);
	ssize_t (*loop_show)(void *chip_data, char *buf);

	ssize_t (*proc_vibration_style_write)(void *chip_data,int val);
	ssize_t (*proc_vibration_style_read)(void *chip_data,int style);

	int (*haptic_get_f0)(void *chip_data);
	int (*haptic_get_rtp_file_num)(void *chip_data);
	void (*haptic_play_stop)(void *chip_data);
	void (*haptic_rtp_mode)(void *chip_data,uint32_t val);
	void (*haptic_set_gain)(void *chip_data,unsigned long arg);
	void (*haptic_stream_mode)(void *chip_data);
	void (*haptic_stop_mode)(void *chip_data);
	
	void (*haptic_set_wav_seq)(void *chip_data, uint8_t, uint8_t);
	void (*haptic_set_wav_loop)(void *chip_data, uint8_t, uint8_t);
	void (*haptic_set_drv_bst_vol)(void *chip_data);
	void (*haptic_play_go)(void *chip_data, bool);
	void (*haptic_play_mode)(void *chip_data, uint8_t);
	void (*haptic_set_rtp_aei)(void *chip_data, bool);
	void (*haptic_clear_interrupt_state)(void *chip_data);
	void (*haptic_rtp_work)(void *chip_data, uint32_t);
	unsigned long (*haptic_virt_to_phys)(void *chip_data);
	void (*haptic_mutex_lock)(void *chip_data);
	void (*haptic_mutex_unlock)(void *chip_data);
};

struct haptic_common_data *common_haptic_data_alloc(void);
int register_common_haptic_device(struct haptic_common_data *oh);
void unregister_common_haptic_device(struct haptic_common_data *pdata);
void haptic_set_ftm_wave(void);
int common_haptic_data_free(struct haptic_common_data *pdata);
const char* get_rtp_name(uint32_t id, uint32_t f0);
const struct firmware *rtp_load_file_accord_f0(uint32_t rtp_file_num);
uint32_t haptic_common_get_f0(void);
bool get_ringtone_support(uint32_t val);
bool get_rtp_key_support(uint32_t val);
uint8_t *get_rtp_key_data(uint32_t *haptic_rtp_key_data_len);
int read_batt_soc(int *val);
int read_batt_temp(int *val);
bool vbat_low_soc_flag(void);
extern struct mutex rst_mutex;
int awinic_i2c_init(void);
void awinic_i2c_exit(void);
int sih_i2c_init(void);
void sih_i2c_exit(void);
#endif
