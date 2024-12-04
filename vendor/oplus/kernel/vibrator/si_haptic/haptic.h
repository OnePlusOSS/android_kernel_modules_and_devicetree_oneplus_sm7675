/*
 *  Silicon Integrated Co., Ltd haptic sih688x haptic header file
 *
 *  Copyright (c) 2021 kugua <canzhen.peng@si-in.com>
 *  Copyright (c) 2021 tianchi <tianchi.zheng@si-in.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation
 */

#ifndef _HAPTIC_H_
#define _HAPTIC_H_

#include <linux/regmap.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/hrtimer.h>
#include <linux/mutex.h>
#include <linux/cdev.h>
#include <linux/version.h>
#include <sound/control.h>
#include <sound/soc.h>
#include <../../../drivers/leds/leds.h>
/*********************************************************
 *
 * Conditional Marco
 *
 *********************************************************/
typedef struct led_classdev cdev_t;
#define IOCTL_MMAP_BUF_SIZE                 1000
#define SIH_WAVEFORM_MAX_NUM                20
#define SIH_RAMWAVEFORM_MAX_NUM             3
#define SIH_HAPTIC_MAX_DEV_NUM              4
#define SIH_HAPTIC_MMAP_DEV_INDEX           0
#define SIH_HAPTIC_DEV_NUM                  1
#define SIH_HAPTIC_SEQUENCER_SIZE           8
#define SIH_HAPTIC_MAX_GAIN                 255
#define SIH_HAPTIC_GAIN_LIMIT               128
#define SIH_HAPTIC_REG_SEQLOOP_MAX          15
#define SIH_HAPTIC_SEQUENCER_GAIN_SIZE      4
#define SIH_HAPTIC_RAM_MAX_SIZE             8192
#define SIH_RAMDATA_BUFFER_SIZE             6144
#define SIH_RAMDATA_READ_SIZE               1024
#define CPU_LATENCY_QOC_VALUE               0
#define SIH_PM_QOS_VALUE_VB                 400
#define SIH_RTP_NAME_MAX                    64
#define SIH_RTP_START_DEFAULT_THRES         0x05
#define SIH_TRIG_NUM                        3
#define SIH_F0_PRE_VALUE                    1700
#define SIH_F0_TARGET_VALUE                 1700
#define SIH_F0_PRE_VALUE_1419               2050
#define SIH_F0_TARGET_VALUE_1419            2050
#define SIH_DETECT_FIFO_SIZE                128
#define SIH_RAM_MAIN_LOOP_MAX_TIME          15
#define SIH_RTP_FILE_MAX_NUM                10
#define SIH_RTP_ZERO_MAX_INTERVAL           20
#define SIH_RESET_GPIO_SET                  1
#define SIH_RESET_GPIO_RESET                0
#define SIH_F0_MAX_THRESHOLD                1800
#define SIH_F0_MIN_THRESHOLD                1600
#define SIH_F0_MAX_THRESHOLD_1419           2150
#define SIH_F0_MIN_THRESHOLD_1419           1950
#define SIH_F0_DETECT_TRY                   4
#define SIH_INIT_ZERO_VALUE                 0
#define SIH_DRIVER_VBOOST_INIT_VALUE        80
#define SIH_WAIT_FOR_STANDBY_MAX_TRY        200
#define SIH_ENTER_RTP_MODE_MAX_TRY          200
#define SIH_PROTECTION_TIME                 30000
#define SIH_LRA_NAME_LEN                    10
#define SIH_OSC_PLAY_FILE_INDEX             0
#define SIH_ENABLE_PIN_CONTROL

#ifdef OPLUS_FEATURE_CHG_BASIC
#define F0_VAL_MAX_0815                     1800
#define F0_VAL_MIN_0815                     1600
#define F0_VAL_MAX_081538                   1600
#define F0_VAL_MIN_081538                   1400
#define F0_VAL_MAX_0832                     2350
#define F0_VAL_MIN_0832                     2250
#define F0_VAL_MAX_0833                     2380
#define F0_VAL_MIN_0833                     2260
#define AW8697_RTP_NAME_MAX                 64
#define AW8697_HAPTIC_BASE_VOLTAGE          6000
#define AW8697_HAPTIC_MAX_VOLTAGE           10000
#define AW8697_HAPTIC_LOW_LEVEL_VOL         800
#define AW8697_HAPTIC_LOW_LEVEL_REG_VAL     0
#define AW8697_HAPTIC_MEDIUM_LEVEL_VOL      1600
#define AW8697_HAPTIC_MEDIUM_LEVEL_REG_VAL  0
#define AW8697_WAVEFORM_INDEX_CS_PRESS      16
#define AW8697_WAVEFORM_INDEX_TRANSIENT     8
#define AW8697_WAVEFORM_INDEX_SINE_CYCLE    9
#define AW8697_WAVEFORM_INDEX_HIGH_TEMP     51
#define AW8697_WAVEFORM_INDEX_OLD_STEADY    52
#define AW8697_WAVEFORM_INDEX_LISTEN_POP    53
#define AW_HAPTIC_RAM_VBAT_COMP_GAIN        (0x80)
#define SG_INPUT_DOWN_HIGH                  302
#define SG_INPUT_UP_HIGH                    303
#define SG_INPUT_DOWN_LOW                   304
#define SG_INPUT_UP_LOW                     305
#define INPUT_HIGH                          112
#define INPUT_MEDI                          111
#define INPUT_LOW                           110
#define AW_RTP_LONG_SOUND_INDEX             (44)
#define AUDIO_READY_STATUS                  (1024)
#define RINGTONES_START_INDEX               (1)
#define RINGTONES_END_INDEX                 (40)
#define RINGTONES_SIMPLE_INDEX              (48)
#define RINGTONES_PURE_INDEX                (49)
#define NEW_RING_START                      (118)
#define NEW_RING_END                        (160)
#define OS12_NEW_RING_START                 (70)
#define OS12_NEW_RING_END                   (89)
#define OPLUS_RING_START                    (161)
#define OPLUS_RING_END                      (170)
#define VMAX_GAIN_NUM                       17
#define DEVICE_ID_0809                      809
#define DEVICE_ID_0815                      815
#define DEVICE_ID_1419                      1419
#define F0_VAL_MIN_1419                     1950
#define F0_VAL_MAX_1419                     2150
#define OS14_NEW_RING_START                 (371)
#define OS14_NEW_RING_END                   (410)
#define ALCLOUDSCAPE_START                  (94)
#define ALCLOUDSCAPE_END                    (99)
#define RINGTONE_NOTIF_ALARM_START          (201)
#define RINGTONE_NOTIF_ALARM_END            (293)
enum aw8697_haptic_motor_old_test_mode {
    MOTOR_OLD_TEST_TRANSIENT = 1,
    MOTOR_OLD_TEST_STEADY = 2,
    MOTOR_OLD_TEST_HIGH_TEMP_HUMIDITY = 3,
    MOTOR_OLD_TEST_LISTEN_POP = 4,
    MOTOR_OLD_TEST_ALL_NUM,
};
struct aw_vmax_map {
	int level;
	int vmax;
	int gain;
};
enum aw8697_haptic_vibration_style {
	AW8697_HAPTIC_VIBRATION_CRISP_STYLE = 0,
	AW8697_HAPTIC_VIBRATION_SOFT_STYLE = 1,
};
#endif
/*********************************************************
 *
 * Common enumeration
 *
 *********************************************************/
typedef enum sih_haptic_work_mode {
	SIH_IDLE_MODE = 0,
	SIH_RAM_MODE = 1,
	SIH_RTP_MODE = 2,
	SIH_TRIG_MODE = 3,
	SIH_CONT_MODE = 4,
	SIH_RAM_LOOP_MODE = 5,
} sih_haptic_work_mode_e;

typedef enum sih_haptic_state_status {
	SIH_STANDBY_MODE = 0,
	SIH_ACTIVE_MODE = 1,
} sih_haptic_state_status_e;

typedef enum sih_haptic_rw_type {
	SIH_BURST_WRITE = 0,
	SIH_BURST_READ = 1,
} sih_haptic_rw_type_e;

typedef enum sih_haptic_ram_vbat_comp_mode {
	SIH_RAM_VBAT_COMP_DISABLE = 0,
	SIH_RAM_VBAT_COMP_ENABLE = 1,
} sih_haptic_ram_vbat_comp_mode_e;

typedef enum sih_haptic_cali_lra {
	SIH_WRITE_ZERO = 0,
	SIH_F0_CALI_LRA = 1,
	SIH_OSC_CALI_LRA = 2,
} sih_haptic_cali_lra_e;

typedef enum sih_haptic_pwm_sample_rpt {
	SIH_SAMPLE_RPT_ONE_TIME = 0,
	SIH_SAMPLE_RPT_TWO_TIME = 1,
	SIH_SAMPLE_RPT_FOUR_TIME = 3,
} sih_haptic_sample_rpt_e;

typedef enum sih_haptic_rtp_play_mode {
	SIH_RTP_NORMAL_PLAY = 0,
	SIH_RTP_OSC_PLAY = 1,
	SIH_RTP_POLAR_PLAY = 2,
} sih_haptic_rtp_play_mode_e;

/*********************************************************
 *
 * Common vibrator mode
 *
 *********************************************************/
typedef struct sih_chip_reg {
	uint32_t rw_type;
	uint32_t reg_num;
	uint8_t *reg_addr;
} sih_chip_reg_t;

typedef struct sih_chip_inter_para {
	uint8_t play_mode; /* chip actual state */
	uint8_t gain;
	int vmax;
	bool state; /* software control state */
	bool auto_pvdd_en;
	bool low_power;
	uint32_t duration; /* ram loop play time */
	uint32_t interval_us;
	uint32_t drv_vboost;
	uint32_t brk_vboost;
	ktime_t kcur_time;
	ktime_t kpre_time;
} sih_chip_inter_para_t;

typedef struct sih_rtp_para {
	bool rtp_init;
	uint32_t rtp_cnt_offset;
	uint32_t rtp_cnt;
	uint32_t rtp_file_num;
	uint8_t rtp_start_thres;
	bool haptic_ready;
	bool audio_ready;
	uint32_t pre_haptic_number;
	uint32_t audio_delay;
	struct mutex rtp_lock;
	struct work_struct rtp_work;
	struct haptic_container *rtp_cont;
} sih_rtp_para_t;

typedef struct sih_ram_para {
	unsigned char ram_init;
	uint8_t seq[SIH_HAPTIC_SEQUENCER_SIZE];
	uint8_t loop[SIH_HAPTIC_SEQUENCER_SIZE];
	uint8_t gain[SIH_HAPTIC_SEQUENCER_SIZE];
	uint32_t main_loop;
	uint8_t action_mode; /* ram or ram_loop mode */
	int index;
	uint32_t len;
	uint32_t check_sum;
	uint32_t base_addr;
	uint8_t wave_num; /* ram library's wave num */
	uint8_t lib_index; /* ram library's index */
	uint8_t version;
	uint8_t ram_shift;
	uint8_t baseaddr_shift;
	uint8_t ram_vbat_comp;
	uint8_t vibration_style;
	struct work_struct ram_work;
	struct work_struct ram_update_work;
} sih_ram_para_t;

typedef struct sih_detect_para {
	bool trig_detect_en;
	bool ram_detect_en;
	bool rtp_detect_en;
	bool cont_detect_en;
	bool detect_f0_read_done;
	uint8_t f0_cali_data;
	uint32_t drive_time;
	uint32_t detect_f0;
	uint32_t tracking_f0;
	uint32_t rl_offset;
	uint32_t vbat;
	uint32_t cali_target_value;
	uint64_t resistance;
} sih_detect_para_t;

typedef struct sih_brake_para {
	bool trig_brake_en;
	bool ram_brake_en;
	bool rtp_brake_en;
	bool cont_brake_en;
} sih_brake_para_t;

typedef struct sih_trig_para {
	bool enable;
	bool boost_bypass; /* 0:boost enable 1:boost bypass */
	bool polar; /* 0:high active 1:low active */
	uint8_t mode;
	uint8_t pose_id;
	uint8_t nege_id;
} sih_trig_para_t;

typedef struct sih_frame_core {
	cdev_t vib_dev;
} sih_frame_core_t;

typedef struct sih_chip_attr {
	int reset_gpio;
	int irq_gpio;
	char lra_name[SIH_LRA_NAME_LEN];
} sih_chip_attr_t;

typedef struct sih_osc_para {
	ktime_t kstart;
	ktime_t kend;
	bool start_flag;
	bool set_trim;
	uint8_t osc_data;
	uint32_t actual_time;
	uint32_t osc_rtp_len;
	uint32_t theory_time;
} sih_osc_para_t;

typedef struct haptic_regmap {
	struct regmap *regmapping;
	const struct regmap_config *config;
} haptic_regmap_t;

#pragma pack(4)
typedef struct mmap_buf_format {
	 uint8_t status;
	 uint8_t bit;
	 int16_t length;
	 uint32_t reserve;
	 struct mmap_buf_format *kernel_next;
	 struct mmap_buf_format *user_next;
	 uint8_t data[IOCTL_MMAP_BUF_SIZE];
} mmap_buf_format_t;
#pragma pack()

typedef struct haptic_stream_play_para {
	 bool done_flag;
	 bool stream_mode;
	 uint8_t *rtp_ptr;
	 mmap_buf_format_t *start_buf;
	 struct work_struct stream_work;
} haptic_stream_play_para_t;

typedef struct sih_haptic {
	struct i2c_client *i2c;
	struct device *dev;
	struct mutex lock;
	struct hrtimer timer;
	ktime_t kcurrent_time;
	ktime_t kpre_enter_time;
	unsigned int interval_us;
	struct pm_qos_request pm_qos;
	sih_osc_para_t osc_para;
	sih_chip_reg_t chip_reg;
	sih_chip_attr_t chip_attr;
	sih_chip_inter_para_t chip_ipara;
	sih_detect_para_t detect;
	sih_brake_para_t brake_para;
	sih_frame_core_t soft_frame;
	sih_ram_para_t ram;
	sih_rtp_para_t rtp;
	sih_trig_para_t trig_para[SIH_TRIG_NUM];
	struct haptic_func *hp_func;
	haptic_regmap_t regmapp;
	haptic_stream_play_para_t stream_para;
	struct haptic_stream_func *stream_func;
	struct pinctrl *pinctrl;
	struct pinctrl_state *pinctrl_state;
#ifdef OPLUS_FEATURE_CHG_BASIC
	int device_id;
	int amplitude;
	uint32_t ram_test_flag_0;
	uint32_t ram_test_flag_1;
	bool livetap_support;
	struct work_struct  motor_old_test_work;
	unsigned int motor_old_test_mode;
	uint32_t gun_type;
	uint32_t bullet_nr;
	uint32_t gun_mode;
	bool auto_break_mode_support;
#endif
} sih_haptic_t;

typedef struct haptic_stream_func {
	int (*stream_rtp_work_init)(sih_haptic_t *);
	void (*stream_rtp_work_release)(sih_haptic_t *);
	bool (*is_stream_mode)(sih_haptic_t *);
} haptic_stream_func_t;

typedef struct haptic_container {
	int len;
	uint8_t data[];
} haptic_container_t;

typedef struct haptic_func {
	int (*probe)(sih_haptic_t *);
	void (*get_detect_f0)(sih_haptic_t *);
	int (*update_ram_config)(sih_haptic_t *, haptic_container_t *);
	void (*stop)(sih_haptic_t *);
	void (*get_vbat)(sih_haptic_t *);
	void (*play_go)(sih_haptic_t *, bool);
	void (*ram_init)(sih_haptic_t *, bool);
	void (*detect_fifo_ctrl)(sih_haptic_t *, bool);
	void (*get_lra_resistance)(sih_haptic_t *);
	void (*set_gain)(sih_haptic_t *, uint8_t);
	void (*set_play_mode)(sih_haptic_t *, uint8_t);
	void (*set_drv_bst_vol)(sih_haptic_t *, uint32_t);
	void (*set_brk_bst_vol)(sih_haptic_t *, uint32_t);
	void (*set_repeat_seq)(sih_haptic_t *, uint8_t);
	void (*set_wav_seq)(sih_haptic_t *, uint8_t, uint8_t);
	void (*set_wav_loop)(sih_haptic_t *, uint8_t, uint8_t);
	size_t (*write_rtp_data)(sih_haptic_t *, uint8_t *, uint32_t);
	void (*clear_interrupt_state)(sih_haptic_t *);
	void (*set_ram_addr)(sih_haptic_t *);
	void (*si_set_ram_addr)(sih_haptic_t *, uint32_t);
	void (*set_ram_data)(sih_haptic_t *, uint8_t *, uint32_t);
	void (*interrupt_state_init)(sih_haptic_t *);
	void (*vbat_comp)(sih_haptic_t *);
	void (*set_rtp_aei)(sih_haptic_t *, bool);
	void (*upload_f0)(sih_haptic_t *, uint8_t);
	void (*get_wav_seq)(sih_haptic_t *, uint32_t);
	void (*set_boost_mode)(sih_haptic_t *, bool);
	void (*get_first_wave_addr)(sih_haptic_t *, uint8_t *);
	void (*get_wav_loop)(sih_haptic_t *);
	ssize_t (*get_ram_data)(sih_haptic_t *, char *);
	void (*si_get_ram_data)(sih_haptic_t *, uint8_t *, uint32_t);
	bool (*get_rtp_fifo_full_state)(sih_haptic_t *);
	void (*set_auto_pvdd)(sih_haptic_t *, bool);
	void (*set_wav_main_loop)(sih_haptic_t *, uint8_t);
	void (*get_wav_main_loop)(sih_haptic_t *);
	void (*set_low_power_mode)(sih_haptic_t *, bool);
	bool (*if_chip_is_mode)(sih_haptic_t *, uint8_t);
	void (*set_trig_para)(sih_haptic_t *, uint32_t *);
	size_t (*get_trig_para)(sih_haptic_t *, char *);
	void (*chip_software_reset)(sih_haptic_t *);
	void (*chip_hardware_reset)(sih_haptic_t *);
	void (*set_start_thres)(sih_haptic_t *);
	void (*set_ram_seq_gain)(sih_haptic_t *, uint8_t, uint8_t);
	size_t (*get_ram_seq_gain)(sih_haptic_t *, char *);
	void (*set_brk_state)(sih_haptic_t *, uint8_t, bool);
	size_t (*get_brk_state)(sih_haptic_t *, char *);
	void (*set_detect_state)(sih_haptic_t *, uint8_t, bool);
	size_t (*get_detect_state)(sih_haptic_t *, char *);
	void (*read_detect_fifo)(sih_haptic_t *);
	void (*set_pwm_rate)(sih_haptic_t *, uint8_t, uint8_t);
	size_t (*get_pwm_rate)(sih_haptic_t *, char *);
	void (*init)(sih_haptic_t *);
	void (*update_chip_state)(sih_haptic_t *);
	bool (*get_rtp_fifo_empty_state)(sih_haptic_t *);
	void (*osc_cali)(sih_haptic_t *);
	int (*efuse_check)(sih_haptic_t *);
	void (*get_tracking_f0)(sih_haptic_t *);
	void (*set_cont_para)(sih_haptic_t *, uint8_t, uint8_t *);
	ssize_t (*get_cont_para)(sih_haptic_t *, uint8_t, char *);
	bool (*if_chip_is_detect_done)(sih_haptic_t *);
	void (*check_detect_state)(sih_haptic_t *, uint8_t);
} haptic_func_t;

typedef struct sih_haptic_ptr {
	unsigned char sih_num;
	sih_haptic_t *g_haptic[SIH_HAPTIC_MAX_DEV_NUM];
} sih_haptic_ptr_t;

/*********************************************************
 *
 * Function Call
 *
 *********************************************************/

sih_haptic_t *get_global_haptic_ptr(void);

#endif
