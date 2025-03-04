#ifndef _UFS_OPLUS_DBG_H
#define _UFS_OPLUS_DBG_H

#include <linux/reset-controller.h>
#include <linux/reset.h>
#include <linux/phy/phy.h>
#include <linux/pm_qos.h>
#include <linux/notifier.h>
#include <linux/panic_notifier.h>
#include <linux/version.h>
#include <ufs/ufshcd.h>
#include <ufs/unipro.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) || defined(CONFIG_OPLUS_QCOM_UFS_DRIVER)
#define UFS_IOCTL_QUERY			0x5388
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) || defined(CONFIG_OPLUS_QCOM_UFS_DRIVER) */
#define UFS_IOCTL_MONITOR               0x5392  /* For monitor access */

/*define ufs uic error code*/
enum unipro_pa_errCode {
	UNIPRO_PA_LANE0_ERR_CNT,
	UNIPRO_PA_LANE1_ERR_CNT,
	UNIPRO_PA_LANE2_ERR_CNT,
	UNIPRO_PA_LANE3_ERR_CNT,
	UNIPRO_PA_LINE_RESET,
	UNIPRO_PA_ERR_MAX
};

enum unipro_dl_errCode {
	UNIPRO_DL_NAC_RECEIVED,
	UNIPRO_DL_TCX_REPLAY_TIMER_EXPIRED,
	UNIPRO_DL_AFCX_REQUEST_TIMER_EXPIRED,
	UNIPRO_DL_FCX_PROTECTION_TIMER_EXPIRED,
	UNIPRO_DL_CRC_ERROR,
	UNIPRO_DL_RX_BUFFER_OVERFLOW,
	UNIPRO_DL_MAX_FRAME_LENGTH_EXCEEDED,
	UNIPRO_DL_WRONG_SEQUENCE_NUMBER,
	UNIPRO_DL_AFC_FRAME_SYNTAX_ERROR,
	UNIPRO_DL_NAC_FRAME_SYNTAX_ERROR,
	UNIPRO_DL_EOF_SYNTAX_ERROR,
	UNIPRO_DL_FRAME_SYNTAX_ERROR,
	UNIPRO_DL_BAD_CTRL_SYMBOL_TYPE,
	UNIPRO_DL_PA_INIT_ERROR,
	UNIPRO_DL_PA_ERROR_IND_RECEIVED,
	UNIPRO_DL_PA_INIT,
	UNIPRO_DL_ERR_MAX
};

enum unipro_nl_errCode {
	UNIPRO_NL_UNSUPPORTED_HEADER_TYPE,
	UNIPRO_NL_BAD_DEVICEID_ENC,
	UNIPRO_NL_LHDR_TRAP_PACKET_DROPPING,
	UNIPRO_NL_ERR_MAX
};

enum unipro_tl_errCode {
	UNIPRO_TL_UNSUPPORTED_HEADER_TYPE,
	UNIPRO_TL_UNKNOWN_CPORTID,
	UNIPRO_TL_NO_CONNECTION_RX,
	UNIPRO_TL_CONTROLLED_SEGMENT_DROPPING,
	UNIPRO_TL_BAD_TC,
	UNIPRO_TL_E2E_CREDIT_OVERFLOW,
	UNIPRO_TL_SAFETY_VALVE_DROPPING,
	UNIPRO_TL_ERR_MAX
};

enum unipro_dme_errCode {
	UNIPRO_DME_GENERIC,
	UNIPRO_DME_TX_QOS,
	UNIPRO_DME_RX_QOS,
	UNIPRO_DME_PA_INIT_QOS,
	UNIPRO_DME_ERR_MAX
};

enum unipro_err_time_stamp {
	UNIPRO_0_STAMP,
	UNIPRO_1_STAMP,
	UNIPRO_2_STAMP,
	UNIPRO_3_STAMP,
	UNIPRO_4_STAMP,
	UNIPRO_5_STAMP,
	UNIPRO_6_STAMP,
	UNIPRO_7_STAMP,
	UNIPRO_8_STAMP,
	UNIPRO_9_STAMP,
	STAMP_RECORD_MAX
};
#define STAMP_MIN_INTERVAL ((ktime_t)600000000000) /*ns, 10min*/

struct signal_quality {
	u32 ufs_device_err_cnt;
	u32 ufs_host_err_cnt;
	u32 ufs_bus_err_cnt;
	u32 ufs_crypto_err_cnt;
	u32 ufs_link_lost_cnt;
	u32 task_abort_cnt;
	u32 host_reset_cnt;
	u32 dev_reset_cnt;
	u32 unipro_PA_err_total_cnt;
	u32 unipro_PA_err_cnt[UNIPRO_PA_ERR_MAX];
	u32 unipro_DL_err_total_cnt;
	u32 unipro_DL_err_cnt[UNIPRO_DL_ERR_MAX];
	u32 unipro_NL_err_total_cnt;
	u32 unipro_NL_err_cnt[UNIPRO_NL_ERR_MAX];
	u32 unipro_TL_err_total_cnt;
	u32 unipro_TL_err_cnt[UNIPRO_TL_ERR_MAX];
	u32 unipro_DME_err_total_cnt;
	u32 unipro_DME_err_cnt[UNIPRO_DME_ERR_MAX];
	u32 gear_err_cnt[UFS_HS_G5 + 1];
	/* first 10 error cnt, interval is 10min at least */
	ktime_t stamp[STAMP_RECORD_MAX];
	int stamp_pos;
};

struct unipro_signal_quality_ctrl {
	struct proc_dir_entry *ctrl_dir;
	struct signal_quality record;
	struct signal_quality record_upload;
};

struct ufs_transmission_status_t
{
	u8  transmission_status_enable;

	u64 gear_min_write_sec;
	u64 gear_max_write_sec;
	u64 gear_min_read_sec;
	u64 gear_max_read_sec;

	u64 gear_min_write_us;
	u64 gear_max_write_us;
	u64 gear_min_read_us;
	u64 gear_max_read_us;

	u64 gear_min_dev_us;
	u64 gear_max_dev_us;

	u64 gear_min_other_sec;
	u64 gear_max_other_sec;
	u64 gear_min_other_us;
	u64 gear_max_other_us;

	u64 scsi_send_count;
	u64 dev_cmd_count;

	u64 active_count;
	u64 active_time;
	u64 resume_timing;

	u64 sleep_count;
	u64 sleep_time;
	u64 suspend_timing;

	u64 powerdown_count;
	u64 powerdown_time;

	u64 power_total_count;
	u32 current_pwr_mode;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#ifndef CONFIG_OPLUS_QCOM_UFS_DRIVER
struct ufs_ioctl_query_data {
 	/*
	 * User should select one of the opcode defined in "enum query_opcode".
	 * Please check include/uapi/scsi/ufs/ufs.h for the definition of it.
	 * Note that only UPIU_QUERY_OPCODE_READ_DESC,
	 * UPIU_QUERY_OPCODE_READ_ATTR & UPIU_QUERY_OPCODE_READ_FLAG are
	 * supported as of now. All other query_opcode would be considered
	 * invalid.
 	 * As of now only read query operations are supported.
	 */
	__u32 opcode;
	/*
	 * User should select one of the idn from "enum flag_idn" or "enum
	 * attr_idn" or "enum desc_idn" based on whether opcode above is
	 * attribute, flag or descriptor.
	 * Please check include/uapi/scsi/ufs/ufs.h for the definition of it.
	 */
	__u8 idn;
	/*
	 * User should specify the size of the buffer (buffer[0] below) where
	 * it wants to read the query data (attribute/flag/descriptor).
 	 * As we might end up reading less data then what is specified in
	 * buf_size. So we are updating buf_size to what exactly we have read.
	 */
	__u16 buf_size;
	/*
	 * placeholder for the start of the data buffer where kernel will copy
	 * the query data (attribute/flag/descriptor) read from the UFS device
	 * Note:
	 * For Read/Write Attribute you will have to allocate 4 bytes
	 * For Read/Write Flag you will have to allocate 1 byte
	 */
	__u8 buffer[0];
};
#endif
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) */

void ufs_active_time_get(struct ufs_hba *hba);
void ufs_sleep_time_get(struct ufs_hba *hba);
void recordSignalerr(struct ufs_hba *hba, unsigned int val, enum ufs_event_type evt);
void ufs_init_oplus_dbg(struct ufs_hba *hba);
void ufs_remove_oplus_dbg(void);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
void ufs_oplus_init_sdev(struct scsi_device *sdev);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) */

#endif /* !_UFS_OPLUS_DBG_H */
