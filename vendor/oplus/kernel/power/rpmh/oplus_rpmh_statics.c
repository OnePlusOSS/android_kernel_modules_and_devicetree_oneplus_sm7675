#include <linux/cdev.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/of.h>
#include <linux/io.h>

#ifdef CONFIG_OPLUS_RPMH_QCOM
// Qcom header file include.
#include <linux/soc/qcom/smem.h>
#endif

#ifdef CONFIG_OPLUS_RPMH_MTK
// Mtk header file include.
#include <linux/arm-smccc.h>
#include "include/mtk_sip_svc.h"
#include <linux/rtc.h>
#endif


MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Faquan.Yao");
MODULE_DESCRIPTION("oplus rpmh statics module.");
MODULE_VERSION("1.0");


#ifdef CONFIG_OPLUS_RPMH_QCOM

#define RPM_DYNAMIC_ADDR	0x14
#define RPM_DYNAMIC_ADDR_MASK	0xFFFF

#define STAT_TYPE_OFFSET	0x0
#define COUNT_OFFSET		0x4
#define LAST_ENTERED_AT_OFFSET	0x8
#define LAST_EXITED_AT_OFFSET	0x10
#define ACCUMULATED_OFFSET	0x18
#define CLIENT_VOTES_OFFSET	0x20

#define DDR_STATS_MAGIC_KEY	0xA1157A75
#define DDR_STATS_MAX_NUM_MODES	0x14
#define MAX_DRV			28
#define MAX_MSG_LEN		64
#define DRV_ABSENT		0xdeaddead
#define DRV_INVALID		0xffffdead
#define VOTE_MASK		0x3fff
#define VOTE_X_SHIFT		14

#define DDR_STATS_MAGIC_KEY_ADDR	0x0
#define DDR_STATS_NUM_MODES_ADDR	0x4
#define DDR_STATS_ENTRY_ADDR		0x8
#define DDR_STATS_NAME_ADDR		0x0
#define DDR_STATS_COUNT_ADDR		0x4
#define DDR_STATS_DURATION_ADDR		0x8

#define MAX_ISLAND_STATS_NAME_LENGTH	16
#define MAX_ISLAND_STATS		6
#define ISLAND_STATS_PID		2 /* ADSP PID */
#define ISLAND_STATS_SMEM_ID		653
#define LLC_ISLAND_STATS_SMEM_ID		661

#define STATS_BASEMINOR				0
#define STATS_MAX_MINOR				1
#define STATS_DEVICE_NAME			"stats"
#define SUBSYSTEM_STATS_MAGIC_NUM		(0x9d)
#define SUBSYSTEM_STATS_OTHERS_NUM		(-2)


struct appended_stats {
	u32 client_votes;
	u32 reserved[3];
};

struct subsystem_data {
	const char *name;
	u32 smem_item;
	u32 pid;
	bool not_present;
};

struct sleep_stats {
	u32 stat_type;
	u32 count;
	u64 last_entered_at;
	u64 last_exited_at;
	u64 accumulated;
};

struct stats_config {
	size_t stats_offset;
	size_t ddr_stats_offset;
	size_t cx_vote_offset;
	size_t num_records;
	bool appended_stats_avail;
	bool dynamic_offset;
	bool subsystem_stats_in_smem;
	bool read_ddr_votes;
	bool read_ddr_his;
	bool read_cx_final_vote;
	bool ddr_freq_update;
	bool island_stats_avail;
	bool llc_island_stats_avail;
};

struct stats_data {
	bool appended_stats_avail;
	void __iomem *base;
};

struct stats_drvdata {
	void __iomem *base;
	const struct stats_config *config;
	struct stats_data *d;
	struct dentry *root;
	dev_t		dev_no;
	struct class	*stats_class;
	struct device	*stats_device;
	struct cdev	stats_cdev;
	struct mutex lock;
	struct qmp *qmp;
	ktime_t ddr_freqsync_msg_time;
};


static struct kobject *soc_sleep_kobj;
static struct kobject *master_stats_kobj;
static struct kobj_attribute ka_stat_oplus;
static struct kobj_attribute ka_master_oplus;


static struct subsystem_data subsystems[] = {
	{ "modem", 605, 1 },
	{ "wpss", 605, 13 },
	{ "adsp", 606, 2 },
	{ "cdsp", 607, 5 },
	{ "cdsp1", 607, 12 },
	{ "gpdsp0", 607, 17 },
	{ "gpdsp1", 607, 18 },
	{ "slpi", 608, 3 },
	{ "gpu", 609, 0 },
	{ "display", 610, 0 },
	{ "adsp_island", 613, 2 },
	{ "slpi_island", 613, 3 },
	{ "apss", 631, -1 },
};


static const struct stats_config rpm_data = {
	.stats_offset = 0,
	.num_records = 2,
	.appended_stats_avail = true,
	.dynamic_offset = true,
	.subsystem_stats_in_smem = false,
};

/* Older RPM firmwares have the stats at a fixed offset instead */
static const struct stats_config rpm_data_dba0 = {
	.stats_offset = 0xdba0,
	.num_records = 2,
	.appended_stats_avail = true,
	.dynamic_offset = false,
	.subsystem_stats_in_smem = false,
};

static const struct stats_config rpmh_data_sdm845 = {
	.stats_offset = 0x48,
	.num_records = 2,
	.appended_stats_avail = false,
	.dynamic_offset = false,
	.subsystem_stats_in_smem = true,
};

static const struct stats_config rpmh_data = {
	.stats_offset = 0x48,
	.ddr_stats_offset = 0xb8,
	.num_records = 3,
	.appended_stats_avail = false,
	.dynamic_offset = false,
	.subsystem_stats_in_smem = true,
};

static const struct stats_config rpmh_v2_data = {
	.stats_offset = 0x48,
	.ddr_stats_offset = 0xb8,
	.cx_vote_offset = 0xb8,
	.num_records = 3,
	.appended_stats_avail = false,
	.dynamic_offset = false,
	.subsystem_stats_in_smem = true,
	.read_ddr_votes = true,
};

static const struct stats_config rpmh_v3_data = {
	.stats_offset = 0x48,
	.ddr_stats_offset = 0xb8,
	.cx_vote_offset = 0xb8,
	.num_records = 3,
	.appended_stats_avail = false,
	.dynamic_offset = false,
	.subsystem_stats_in_smem = true,
	.read_ddr_votes = true,
	.ddr_freq_update = true,
};

static const struct stats_config rpmh_v4_data = {
	.stats_offset = 0x48,
	.ddr_stats_offset = 0xb8,
	.cx_vote_offset = 0xb8,
	.num_records = 3,
	.appended_stats_avail = false,
	.dynamic_offset = false,
	.subsystem_stats_in_smem = true,
	.read_ddr_votes = true,
	.read_ddr_his = true,
	.ddr_freq_update = true,
	.read_cx_final_vote = true,
	.island_stats_avail = true,
	.llc_island_stats_avail = true,
};

static const struct of_device_id qcom_stats_table[] = {
	{ .compatible = "qcom,apq8084-rpm-stats", .data = &rpm_data_dba0 },
	{ .compatible = "qcom,msm8226-rpm-stats", .data = &rpm_data_dba0 },
	{ .compatible = "qcom,msm8916-rpm-stats", .data = &rpm_data_dba0 },
	{ .compatible = "qcom,msm8974-rpm-stats", .data = &rpm_data_dba0 },
	{ .compatible = "qcom,rpm-stats", .data = &rpm_data },
	{ .compatible = "qcom,rpmh-stats", .data = &rpmh_data },
	{ .compatible = "qcom,rpmh-stats-v2", .data = &rpmh_v2_data },
	{ .compatible = "qcom,rpmh-stats-v3", .data = &rpmh_v3_data },
	{ .compatible = "qcom,rpmh-stats-v4", .data = &rpmh_v4_data },
	{ .compatible = "qcom,sdm845-rpmh-stats", .data = &rpmh_data_sdm845 },
	{ }
};

static struct stats_drvdata *drv;
static struct device_node *rpmh_node;

#define MSM_ARCH_TIMER_FREQ 19200000

extern void *get_drvdata(void);

static inline u64 get_time_in_msec(u64 counter)
{
	do_div(counter, (MSM_ARCH_TIMER_FREQ/MSEC_PER_SEC));

	return counter;
}

static inline ssize_t oplus_append_data_to_buf(int index, char *buf, int length,
					 struct sleep_stats *stat)
{
	if (index == 0) {
		//vddlow: aosd: AOSS deep sleep
		return scnprintf(buf, length,
			"vlow:%x:%llx\n",
			stat->count, stat->accumulated);
	} else if (index == 1) {
	  //vddmin: cxsd: cx collapse
		return scnprintf(buf, length,
			"vmin:%x:%llx\r\n",
			stat->count, stat->accumulated);
	} else {
		return 0;
	}
}

static ssize_t oplus_msm_rpmh_master_stats_print_data(char *prvbuf, ssize_t length,
				struct sleep_stats *stat,
				const char *name)
{
	uint64_t accumulated_duration = stat->accumulated;
	if (stat->last_entered_at > stat->last_exited_at)
		accumulated_duration +=
				(__arch_counter_get_cntvct()
				- stat->last_entered_at);

	return scnprintf(prvbuf, length, "%s:%x:%llx\n",
			name, stat->count,
			get_time_in_msec(accumulated_duration));
}

static ssize_t oplus_rpmh_master_stats_show(struct kobject *kobj,
						struct kobj_attribute *attr, char *buf)
{
	ssize_t length = 0;
	int i = 0, j, n_subsystems;
	struct sleep_stats *stat;
	const char *name;

	n_subsystems = of_property_count_strings(rpmh_node, "ss-name");
	if (n_subsystems < 0)
		goto exit;

	for (i = 0; i < n_subsystems; i++) {
		of_property_read_string_index(rpmh_node, "ss-name", i, &name);


		for (j = 0; j < ARRAY_SIZE(subsystems); j++) {
			if (!strcmp(subsystems[j].name, name)) {
				stat = qcom_smem_get(subsystems[j].pid,
						subsystems[j].smem_item, NULL);
				if (IS_ERR(stat))
					return PTR_ERR(stat);

				length += oplus_msm_rpmh_master_stats_print_data(
						buf + length, PAGE_SIZE - length,
						stat,
						subsystems[j].name);
				break;
			}
		}
	}
exit:
	return length;
}

static ssize_t oplus_rpmh_stats_show(struct kobject *kobj,
						struct kobj_attribute *attr, char *buf)
{
	int i;
	ssize_t length = 0, op_length;
	void __iomem *reg = drv->base + drv->config->stats_offset;
	struct sleep_stats stat;
	struct appended_stats app_stat;

	for (i = 0; i < drv->config->num_records; i++) {
		stat.stat_type = le32_to_cpu(readl_relaxed(reg + STAT_TYPE_OFFSET));
		stat.count = le32_to_cpu(readl_relaxed(reg + COUNT_OFFSET));
		stat.last_entered_at = le64_to_cpu(readq(reg + LAST_ENTERED_AT_OFFSET));
		stat.last_exited_at = le64_to_cpu(readq(reg + LAST_EXITED_AT_OFFSET));
		stat.accumulated = le64_to_cpu(readq(reg + ACCUMULATED_OFFSET));

		stat.last_entered_at = get_time_in_msec(stat.last_entered_at);
		stat.last_exited_at = get_time_in_msec(stat.last_exited_at);
		stat.accumulated = get_time_in_msec(stat.accumulated);

		reg += sizeof(struct sleep_stats);

		if (drv->config->appended_stats_avail) {
			app_stat.client_votes = le32_to_cpu(readl_relaxed(reg +
								     CLIENT_VOTES_OFFSET));

			reg += sizeof(struct appended_stats);
		} else {
			app_stat.client_votes = 0;
		}

		op_length = oplus_append_data_to_buf(i, buf + length, PAGE_SIZE - length,
					       &stat);
		if (op_length >= PAGE_SIZE - length)
			goto exit;

		length += op_length;
	}
exit:
	return length;
}
#endif


#ifdef CONFIG_OPLUS_RPMH_MTK
enum MT_SPM_STAT_SCENARIO_TYPE {
	SPM_IDLE_STAT,
	SPM_SUSPEND_STAT,
};

enum MT_SPM_STAT_STATE {
	SPM_STAT_MCUSYS,
	SPM_STAT_F26M,
	SPM_STAT_VCORE,
	NUM_SPM_STAT,
};

enum MT_SPM_STAT_TYPE {
	SPM_SLP_COUNT,
	SPM_SLP_DURATION,
};

enum MT_SPM_DBG_SMC_UID {
	/* spm dbg function ID*/
	MT_SPM_DBG_SMC_UID_IDLE_PWR_CTRL,
	MT_SPM_DBG_SMC_UID_IDLE_CNT,
	MT_SPM_DBG_SMC_UID_SUSPEND_PWR_CTRL,
	MT_SPM_DBG_SMC_UID_SUSPEND_DBG_CTRL,
	MT_SPM_DBG_SMC_UID_FS,
	MT_SPM_DBG_SMC_UID_RC_SWITCH,
	MT_SPM_DBG_SMC_UID_RC_CNT,
	MT_SPM_DBG_SMC_UID_COND_CHECK,
	MT_SPM_DBG_SMC_UID_COND_BLOCK,
	MT_SPM_DBG_SMC_UID_BLOCK_LATCH,
	MT_SPM_DBG_SMC_UID_BLOCK_DETAIL,
	MT_SPM_DBG_SMC_UID_RES_NUM,
	MT_SPM_DBG_SMC_UID_RES_REQ,
	MT_SPM_DBG_SMC_UID_RES_USAGE,
	MT_SPM_DBG_SMC_UID_RES_USER_NUM,
	MT_SPM_DBG_SMC_UID_RES_USER_VALID,
	MT_SPM_DBG_SMC_UID_RES_USER_NAME,
	MT_SPM_DBG_SMC_UID_DOE_RESOURCE_CTRL,
	MT_SPM_DBG_SMC_UID_DOE_RC,
	MT_SPM_DBG_SMC_UID_RC_COND_CTRL,
	MT_SPM_DBG_SMC_UID_RC_RES_CTRL,
	MT_SPM_DBG_SMC_UID_RC_RES_INFO,
	MT_SPM_DBG_SMC_UID_RC_BBLPM,
	MT_SPM_DBG_SMC_UID_RC_TRACE,
	MT_SPM_DBG_SMC_UID_RC_TRACE_TIME,
	MT_SPM_DBG_SMC_UID_RC_DUMP_PLL,
	MT_SPM_DBG_SMC_HWCG_NUM,
	MT_SPM_DBG_SMC_HWCG_STATUS,
	MT_SPM_DBG_SMC_HWCG_SETTING,
	MT_SPM_DBG_SMC_HWCG_DEF_SETTING,
	MT_SPM_DBG_SMC_HWCG_RES_NAME,
	MT_SPM_DBG_SMC_UID_RC_NOTIFY_CTRL,
	MT_SPM_DBG_SMC_VCORE_LP_ENABLE,
	MT_SPM_DBG_SMC_VCORE_LP_VOLT,
	MT_SPM_DBG_SMC_VSRAM_LP_ENABLE,
	MT_SPM_DBG_SMC_VSRAM_LP_VOLT,
	MT_SPM_DBG_SMC_PERI_REQ_NUM,
	MT_SPM_DBG_SMC_PERI_REQ_STATUS,
	MT_SPM_DBG_SMC_PERI_REQ_SETTING,
	MT_SPM_DBG_SMC_PERI_REQ_DEF_SETTING,
	MT_SPM_DBG_SMC_PERI_REQ_RES_NAME,
	MT_SPM_DBG_SMC_PERI_REQ_STATUS_RAW,
	MT_SPM_DBG_SMC_IDLE_PWR_STAT,
	MT_SPM_DBG_SMC_SUSPEND_PWR_STAT,
	MT_SPM_DBG_SMC_LP_REQ_STAT,
	MT_SPM_DBG_SMC_COMMON_SODI5_CTRL,
	MT_SPM_DBG_SMC_SPM_TIMESTAMP,
	MT_SPM_DBG_SMC_SPM_TIMESTAMP_SIZE,
};

enum mt_lpm_smc_user_id {
	mt_lpm_smc_user_cpu_pm = 0,
	mt_lpm_smc_user_spm_dbg,
	mt_lpm_smc_user_spm,
	mt_lpm_smc_user_cpu_pm_lp,
	mt_lpm_smc_user_max,
};

enum MT_SPM_SCENE_STATE {
	MT_SPM_AUDIO_AFE,
	MT_SPM_AUDIO_DSP,
	MT_SPM_USB_HEADSET,
	NUM_SPM_SCENE,
};

enum _sys_res_scene{
	SYS_RES_SCENE_COMMON = 0,
	SYS_RES_SCENE_SUSPEND,
	SYS_RES_SCENE_LAST_SUSPEND_DIFF,
	SYS_RES_SCENE_LAST_DIFF,
	SYS_RES_SCENE_LAST_SYNC,
	SYS_RES_SCENE_TEMP,
	SYS_RES_SCENE_NUM,
};

/* behavior */
#define MT_LPM_SMC_ACT_SET		(1<<0UL)
#define MT_LPM_SMC_ACT_CLR		(1<<1UL)
#define MT_LPM_SMC_ACT_GET		(1<<2UL)
#define MT_LPM_SMC_ACT_PUSH		(1<<3UL)
#define MT_LPM_SMC_ACT_POP		(1<<4UL)
#define MT_LPM_SMC_ACT_SUBMIT		(1<<5UL)

#define MT_LPM_SMC_MAGIC		0xDA000000
#define MT_LPM_SMC_USER_MASK		0xff
#define MT_LPM_SMC_USER_SHIFT		16
#define MT_LPM_SMC_USER_ID_MASK		0x0000ffff

#define PCM_32K_TICKS_PER_SEC		(32768)
#define PCM_TICK_TO_SEC(TICK)	(TICK / PCM_32K_TICKS_PER_SEC)

#define lpm_smc_impl(p1, p2, p3, p4, p5, res) \
			arm_smccc_smc(p1, p2, p3, p4\
			, p5, 0, 0, 0, &res)

#define lpm_smc(_funcid, _lp_id, _act, _val1, _val2) ({\
	struct arm_smccc_res res;\
	lpm_smc_impl(_funcid, _lp_id, _act, _val1\
					, _val2, res);\
	res.a0; })

/* sink user id to smc's user id */
#define MT_LPM_SMC_USER_SINK(user, uid) \
		(((uid & MT_LPM_SMC_USER_ID_MASK)\
		| ((user & MT_LPM_SMC_USER_MASK)\
			<< MT_LPM_SMC_USER_SHIFT))\
		| MT_LPM_SMC_MAGIC)

#define MT_LPM_SMC_USER_ID_SPM_DBG(uid) \
	MT_LPM_SMC_USER_SINK(mt_lpm_smc_user_spm_dbg, uid)

#define MT_LPM_SMC_USER_SPM_DBG(uid)\
			MT_LPM_SMC_USER_ID_SPM_DBG(uid)

#define lpm_smc_spm_dbg(_lp_id, _act, _val1, _val2) ({\
		lpm_smc(MTK_SIP_MTK_LPM_CONTROL,\
				MT_LPM_SMC_USER_SPM_DBG(_lp_id),\
				_act, _val1, _val2); })

#define mtk_dbg_spm_log(fmt, args...) \
	do { \
		int l = scnprintf(p, sz, fmt, ##args); \
		p += l; \
		sz -= l; \
	} while (0)


static const char * const mtk_lp_state_name[NUM_SPM_STAT] = {
	"AP",
	"26M",
	"VCORE",
};


struct lpm_stat_record {
	u64 count;
	u64 duration;
};
struct lpm_dbg_lp_info {
	struct lpm_stat_record record[NUM_SPM_STAT];
};
struct subsys_req {
	char name[15];
	u32 req_addr1;
	u32 req_mask1;
	u32 req_addr2;
	u32 req_mask2;
	u32 on;
};
struct spm_req_sta_list {
	struct subsys_req *spm_req;
	unsigned int spm_req_num;
	unsigned int spm_req_sta_addr;
	unsigned int spm_req_sta_num;
	unsigned int lp_scenario_sta;
	unsigned int is_blocked;
	struct rtc_time *suspend_tm;
};
struct res_sig {
	uint64_t time;
	uint32_t sig_id;
	uint32_t grp_id;
};
struct res_sig_stats {
	struct res_sig *res_sig_tbl;
	uint32_t res_sig_num;
	uint64_t duration_time;
	uint64_t suspend_time;
};
struct sys_res_record {
	struct res_sig_stats *spm_res_sig_stats_ptr;
};


#define SYS_RES_NAME_LEN (10)
struct sys_res_mapping {
	unsigned int id;
	char name[SYS_RES_NAME_LEN];
};

struct lpm_sys_res_ops {
	struct sys_res_record* (*get)(unsigned int scene);
	int (*update)(void);
	uint64_t (*get_detail)(struct sys_res_record *record, int op, unsigned int val);
	unsigned int (*get_threshold)(void);
	void (*set_threshold)(unsigned int val);
	void (*enable_common_log)(int en);
	int (*get_log_enable)(void);
	void (*log)(unsigned int scene);
	spinlock_t *lock;
	int (*get_id_name)(struct sys_res_mapping **map, unsigned int *size);
};

#if IS_ENABLED(CONFIG_MTK_ECCCI_DRIVER)
struct md_sleep_status {
	u64 guard_sleep_cnt1;
	u64 sleep_utc;
	u64 sleep_wall_clk;
	u64 sleep_cnt;
	u64 sleep_cnt_reserve;
	u64 sleep_time;
	u64 sleep_time_reserve;
	u64 md_sleep_time; // uS
	u64 gsm_sleep_time; // uS
	u64 wcdma_sleep_time; //uS
	u64 lte_sleep_time; // uS
	u64 nr_sleep_time; // uS
	u64 reserved[51]; //0x60~0x1F0
	u64 guard_sleep_cnt2;
};

extern void get_md_sleep_time(struct md_sleep_status *md_data);
extern int is_md_sleep_info_valid(struct md_sleep_status *md_data);
extern void log_md_sleep_info(void);
extern struct md_sleep_status cur_md_sleep_status;
#endif

static void mtk_get_lp_info(struct lpm_dbg_lp_info *info, int type)
{
	unsigned int smc_id;
	int i;

	if (type == SPM_IDLE_STAT)
		smc_id = MT_SPM_DBG_SMC_IDLE_PWR_STAT;
	else
		smc_id = MT_SPM_DBG_SMC_SUSPEND_PWR_STAT;

	for (i = 0; i < NUM_SPM_STAT; i++) {
		info->record[i].count = lpm_smc_spm_dbg(smc_id,
			MT_LPM_SMC_ACT_GET, i, SPM_SLP_COUNT);
		info->record[i].duration = lpm_smc_spm_dbg(smc_id,
			MT_LPM_SMC_ACT_GET, i, SPM_SLP_DURATION);
	}
}

static char *spm_scenario_str[NUM_SPM_SCENE] = {
	[MT_SPM_AUDIO_AFE] = "AUDIO_AFE",
	[MT_SPM_AUDIO_DSP] = "AUDIO_DSP",
	[MT_SPM_USB_HEADSET] = "USB_HEADSET",
};

char *get_spm_scenario_str(unsigned int index)
{
	if (index >= NUM_SPM_SCENE)
		return NULL;
	return spm_scenario_str[index];
}

extern struct spm_req_sta_list *spm_get_req_sta_list(void);
extern struct lpm_sys_res_ops *get_lpm_sys_res_ops(void);
static struct kobject *lpm_kobj;
static struct kobj_attribute ka_system_stats;

static ssize_t oplus_system_stats_show(struct kobject *kobj,
						struct kobj_attribute *attr, char *buf)
{
	char *p = buf;
	size_t sz = PAGE_SIZE;

#if IS_ENABLED(CONFIG_MTK_ECCCI_DRIVER)
	struct md_sleep_status tmp_md_data;
#endif
	struct lpm_dbg_lp_info info;
	unsigned int i;
	struct spm_req_sta_list *sta_list;
	struct sys_res_record *sys_res_record;
	struct lpm_sys_res_ops *sys_res_ops;
	struct sys_res_mapping *map = NULL;
	unsigned int res_mapping_len, tmp_active_time, tmp_id;

	mtk_get_lp_info(&info, SPM_IDLE_STAT);
	for (i = 0; i < NUM_SPM_STAT; i++) {
		mtk_dbg_spm_log("Idle %s:%lld:%lld.%03lld\n",
			mtk_lp_state_name[i], info.record[i].count,
			PCM_TICK_TO_SEC(info.record[i].duration),
			PCM_TICK_TO_SEC((info.record[i].duration % PCM_32K_TICKS_PER_SEC) * 1000));
	}

	mtk_get_lp_info(&info, SPM_SUSPEND_STAT);
	for (i = 0; i < NUM_SPM_STAT; i++) {
		mtk_dbg_spm_log("Suspend %s:%lld:%lld.%03lld\n",
			mtk_lp_state_name[i], info.record[i].count,
			PCM_TICK_TO_SEC(info.record[i].duration),
			PCM_TICK_TO_SEC((info.record[i].duration % PCM_32K_TICKS_PER_SEC) * 1000));
	}

#if IS_ENABLED(CONFIG_MTK_ECCCI_DRIVER)
	/* get MD data */
	get_md_sleep_time(&tmp_md_data);
	if (is_md_sleep_info_valid(&tmp_md_data))
		cur_md_sleep_status = tmp_md_data;

	mtk_dbg_spm_log("MD:%lld.%03lld\nMD_2G:%lld.%03lld\nMD_3G:%lld.%03lld\n",
		cur_md_sleep_status.md_sleep_time / 1000000,
		(cur_md_sleep_status.md_sleep_time % 1000000) / 1000,
		cur_md_sleep_status.gsm_sleep_time / 1000000,
		(cur_md_sleep_status.gsm_sleep_time % 1000000) / 1000,
		cur_md_sleep_status.wcdma_sleep_time / 1000000,
		(cur_md_sleep_status.wcdma_sleep_time % 1000000) / 1000);

	mtk_dbg_spm_log("MD_4G:%lld.%03lld\nMD_5G:%lld.%03lld\n",
		cur_md_sleep_status.lte_sleep_time / 1000000,
		(cur_md_sleep_status.lte_sleep_time % 1000000) / 1000,
		cur_md_sleep_status.nr_sleep_time / 1000000,
		(cur_md_sleep_status.nr_sleep_time % 1000000) / 1000);
#endif

	/* dump last suspend blocking request */
	sta_list = spm_get_req_sta_list();
	if (!sta_list || sta_list->is_blocked == 0) {
		mtk_dbg_spm_log("Last Suspend is not blocked\n");
		goto SKIP_REQ_DUMP;
	}

	mtk_dbg_spm_log("Last Suspend %d-%02d-%02d %02d:%02d:%02d (UTC) blocked by ",
		sta_list->suspend_tm->tm_year + 1900, sta_list->suspend_tm->tm_mon + 1,
		sta_list->suspend_tm->tm_mday, sta_list->suspend_tm->tm_hour,
		sta_list->suspend_tm->tm_min, sta_list->suspend_tm->tm_sec);

	for (i = 0; i < sta_list->spm_req_num; i++) {
		if (sta_list->spm_req[i].on)
			mtk_dbg_spm_log("%s ", sta_list->spm_req[i].name);
	}

	for (i = 0; i < NUM_SPM_SCENE; i++) {
		if ((sta_list->lp_scenario_sta & (1 << i)))
			mtk_dbg_spm_log("%s ", get_spm_scenario_str(i));
	}
	mtk_dbg_spm_log("\n");

SKIP_REQ_DUMP:

	sys_res_ops = get_lpm_sys_res_ops();
	if (!sys_res_ops || !sys_res_ops->get || !sys_res_ops->get_id_name || !sys_res_ops->update)
		goto SKIP_DUMP;

	if(sys_res_ops->get_id_name(&map, &res_mapping_len) != 0)
		goto SKIP_DUMP;

	sys_res_ops->update();

	mtk_dbg_spm_log("Subsys accumulated active time\n");
	sys_res_record = sys_res_ops->get(SYS_RES_SCENE_COMMON);
	for (i = 0; i < res_mapping_len; i++) {
		tmp_id = map[i].id;
		tmp_active_time = sys_res_record->spm_res_sig_stats_ptr->res_sig_tbl[tmp_id].time;
		mtk_dbg_spm_log("common(active) %s: %u.%03u\n",
				map[i].name, tmp_active_time / 1000, tmp_active_time % 1000);
	}

	sys_res_record = sys_res_ops->get(SYS_RES_SCENE_SUSPEND);
	for (i = 0; i < res_mapping_len; i++) {
		tmp_id = map[i].id;
		tmp_active_time = sys_res_record->spm_res_sig_stats_ptr->res_sig_tbl[tmp_id].time;
		mtk_dbg_spm_log("Suspend(active) %s: %u.%03u\n",
				map[i].name, tmp_active_time / 1000, tmp_active_time % 1000);
	}

SKIP_DUMP:
	return p - buf;
}
#endif

static int __init oplus_rpmh_statics_init(void) {
	int res = 0;
	#ifdef CONFIG_OPLUS_RPMH_QCOM
	const struct of_device_id *match_ptr;
	#endif

	pr_info("%s oplus_rpmh_statics_init...\n", __func__);

	#ifdef CONFIG_OPLUS_RPMH_QCOM
	rpmh_node = of_find_matching_node_and_match(NULL, qcom_stats_table, &match_ptr);
	if (!rpmh_node) {
		pr_err("%s rpmh_node is null\n", __func__);
		return -ENODEV;
	}

	drv = (struct stats_drvdata *)get_drvdata();
	if (!drv) {
		pr_err("%s drv is null\n", __func__);
		of_node_put(rpmh_node);
		return -ENODEV;
	}

	soc_sleep_kobj = kobject_create_and_add("soc_sleep", &THIS_MODULE->mkobj.kobj);
	if (!soc_sleep_kobj) {
		pr_err("%s soc_sleep_kobj is null\n", __func__);
		of_node_put(rpmh_node);
		return -ENOMEM;
	}
	sysfs_attr_init(&ka_stat_oplus.attr);
	ka_stat_oplus.attr.name = "oplus_rpmh_stats";
	ka_stat_oplus.attr.mode = 0444;
	ka_stat_oplus.show = oplus_rpmh_stats_show;

	res = sysfs_create_file(soc_sleep_kobj, &ka_stat_oplus.attr);
	if (res) {
		pr_err("%s sysfs_create_file failed\n", __func__);
		of_node_put(rpmh_node);
		return res;
	}


	master_stats_kobj = kobject_create_and_add("rpmh_stats",  &THIS_MODULE->mkobj.kobj);
	if (!master_stats_kobj) {
		pr_err("%s master_stats_kobj is null\n", __func__);
		of_node_put(rpmh_node);
		return -ENOMEM;
	}
	sysfs_attr_init(&ka_master_oplus.attr);
	ka_master_oplus.attr.name = "oplus_rpmh_master_stats";
	ka_master_oplus.attr.mode = 0444;
	ka_master_oplus.show = oplus_rpmh_master_stats_show;

	res = sysfs_create_file(master_stats_kobj, &ka_master_oplus.attr);
	if (res) {
		pr_err("%s sysfs_create_file failed\n", __func__);
		of_node_put(rpmh_node);
		return res;
	}

	of_node_put(rpmh_node);
	#endif

	#ifdef CONFIG_OPLUS_RPMH_MTK
	lpm_kobj = kobject_create_and_add("lpm", &THIS_MODULE->mkobj.kobj);
	if (!lpm_kobj) {
		pr_err("%s lpm_kobj is null\n", __func__);
		return -ENOMEM;
	}
	sysfs_attr_init(&ka_system_stats.attr);
	ka_system_stats.attr.name = "system_stats";
	ka_system_stats.attr.mode = 0444;
	ka_system_stats.show = oplus_system_stats_show;

	res = sysfs_create_file(lpm_kobj, &ka_system_stats.attr);
	if (res) {
		pr_err("%s sysfs_create_file failed\n", __func__);
		return res;
	}
	#endif
	return res;
}

static void __exit oplus_rpmh_statics_exit(void) {
	#ifdef CONFIG_OPLUS_RPMH_QCOM
	sysfs_remove_file(soc_sleep_kobj, &ka_stat_oplus.attr);
	kobject_del(soc_sleep_kobj);

	sysfs_remove_file(master_stats_kobj, &ka_master_oplus.attr);
	kobject_del(master_stats_kobj);

	of_node_put(rpmh_node);
	#endif

	#ifdef CONFIG_OPLUS_RPMH_MTK
	sysfs_remove_file(lpm_kobj, &ka_system_stats.attr);
	kobject_del(lpm_kobj);
	#endif
}

module_init(oplus_rpmh_statics_init);
module_exit(oplus_rpmh_statics_exit);