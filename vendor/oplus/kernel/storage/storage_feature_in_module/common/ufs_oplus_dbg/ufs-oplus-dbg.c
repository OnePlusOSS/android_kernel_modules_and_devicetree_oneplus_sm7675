#include <scsi/scsi.h>
#include <scsi/scsi_ioctl.h>
#include <scsi/scsi_cmnd.h>
#include <ufs/ufs_quirks.h>
#include <ufs/ufshcd.h>
#include <ufs/unipro.h>
#include <trace/hooks/ufshcd.h>
#include <linux/tracepoint.h>
#include <linux/proc_fs.h>
#include <linux/rtc.h>
#include <linux/async.h>

#include <soc/oplus/device_info.h>

#include "ufs-oplus-dbg.h"
#ifdef CONFIG_OPLUS_QCOM_UFS_DRIVER
#include "../../../../../ufs/host/ufs-qcom.h"
#endif /* CONFIG_OPLUS_QCOM_UFS_DRIVER */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0))
#ifdef CONFIG_OPLUS_QCOM_UFS_DRIVER
#include "../../../../../ufs/core/ufshcd-priv.h"
#endif /* CONFIG_OPLUS_QCOM_UFS_DRIVER */
#include "ufshcd-priv.h"
#else
#ifdef CONFIG_OPLUS_QCOM_UFS_DRIVER
#include <ufs/ufshcd-priv.h>
#endif /* CONFIG_OPLUS_QCOM_UFS_DRIVER */
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) */


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0))
#define UFS_OPLUS_IOCTL_MAGIC 0xF5
#define UFS_OPLUS_QUERY_IOCTL _IOWR(UFS_OPLUS_IOCTL_MAGIC, 0, int)
#define UFS_OPLUS_MONITOR_IOCTL _IOWR(UFS_OPLUS_IOCTL_MAGIC, 1, int)
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) */

struct unipro_signal_quality_ctrl signalCtrl;

struct ufs_transmission_status_t ufs_transmission_status;
struct device_attribute ufs_transmission_status_attr;

#define ONE_DAY_SEC 86400
static const char *ufs_null_device_strs = "nullnullnullnull";
atomic_t ufs_init_done;

int ufsplus_wb_status = 0;
int ufsplus_hpb_status = 0;

#ifdef CONFIG_OPLUS_QCOM_UFS_DRIVER
extern int ufshcd_query_descriptor_retry(struct ufs_hba *hba,
  				  enum query_opcode opcode,
  				  enum desc_idn idn, u8 index,
  				  u8 selector,
  				  u8 *desc_buf, int *buf_len);
#endif
static void recordTimeStamp(
	struct signal_quality *record,
	enum ufs_event_type type
) {
	ktime_t cur_time = ktime_get();
	switch (type)
	{
	case UFS_EVT_PA_ERR:
	case UFS_EVT_DL_ERR:
	case UFS_EVT_NL_ERR:
	case UFS_EVT_TL_ERR:
	case UFS_EVT_DME_ERR:
		if (STAMP_RECORD_MAX <= record->stamp_pos)
			return;
		if (0 == record->stamp_pos)
			record->stamp[0] = cur_time;
		else if (cur_time > (record->stamp[record->stamp_pos - 1] +
				STAMP_MIN_INTERVAL))
			record->stamp[record->stamp_pos++] = cur_time;
		return;
	default:
		return;
	}
}

void recordUniproErr(
	struct unipro_signal_quality_ctrl *signalCtrl,
	u32 reg,
	enum ufs_event_type type
) {
	unsigned long err_bits;
	int ec;
	struct signal_quality *rec = &signalCtrl->record;
	recordTimeStamp(rec, type);
	switch (type)
	{
	case UFS_EVT_FATAL_ERR:
		if (DEVICE_FATAL_ERROR & reg)
			rec->ufs_device_err_cnt++;
		if (CONTROLLER_FATAL_ERROR & reg)
			rec->ufs_host_err_cnt++;
		if (SYSTEM_BUS_FATAL_ERROR & reg)
			rec->ufs_bus_err_cnt++;
		if (CRYPTO_ENGINE_FATAL_ERROR & reg)
			rec->ufs_crypto_err_cnt++;
		break;
	case UFS_EVT_LINK_STARTUP_FAIL:
		if (UIC_LINK_LOST & reg)
			rec->ufs_link_lost_cnt++;
		break;
	case UFS_EVT_PA_ERR:
		err_bits = reg & UIC_PHY_ADAPTER_LAYER_ERROR_CODE_MASK;
		for_each_set_bit(ec, &err_bits, UNIPRO_PA_ERR_MAX) {
			rec->unipro_PA_err_total_cnt++;
			rec->unipro_PA_err_cnt[ec]++;
		}
		break;
	case UFS_EVT_DL_ERR:
		err_bits = reg & UIC_DATA_LINK_LAYER_ERROR_CODE_MASK;
		for_each_set_bit(ec, &err_bits, UNIPRO_DL_ERR_MAX) {
			rec->unipro_DL_err_total_cnt++;
			rec->unipro_DL_err_cnt[ec]++;
		}
		break;
	case UFS_EVT_NL_ERR:
		err_bits = reg & UIC_NETWORK_LAYER_ERROR_CODE_MASK;
		for_each_set_bit(ec, &err_bits, UNIPRO_NL_ERR_MAX) {
			rec->unipro_NL_err_total_cnt++;
			rec->unipro_NL_err_cnt[ec]++;
		}
		break;
	case UFS_EVT_TL_ERR:
		err_bits = reg & UIC_TRANSPORT_LAYER_ERROR_CODE_MASK;
		for_each_set_bit(ec, &err_bits, UNIPRO_TL_ERR_MAX) {
			rec->unipro_TL_err_total_cnt++;
			rec->unipro_TL_err_cnt[ec]++;
		}
		break;
	case UFS_EVT_DME_ERR:
		err_bits = reg & UIC_DME_ERROR_CODE_MASK;
		for_each_set_bit(ec, &err_bits, UNIPRO_DME_ERR_MAX) {
			rec->unipro_DME_err_total_cnt++;
			rec->unipro_DME_err_cnt[ec]++;
		}
		break;
	default:
		break;
	}
}

#define SEQ_EASY_PRINT(x)   seq_printf(s, #x"\t%d\n", signalCtrl->record.x)
#define SEQ_PA_PRINT(x)     \
	seq_printf(s, #x"\t%d\n", signalCtrl->record.unipro_PA_err_cnt[x])
#define SEQ_DL_PRINT(x)     \
	seq_printf(s, #x"\t%d\n", signalCtrl->record.unipro_DL_err_cnt[x])
#define SEQ_NL_PRINT(x)     \
	seq_printf(s, #x"\t%d\n", signalCtrl->record.unipro_NL_err_cnt[x])
#define SEQ_TL_PRINT(x)     \
	seq_printf(s, #x"\t%d\n", signalCtrl->record.unipro_TL_err_cnt[x])
#define SEQ_DME_PRINT(x)    \
	seq_printf(s, #x"\t%d\n", signalCtrl->record.unipro_DME_err_cnt[x])
#define SEQ_STAMP_PRINT(x)  \
	seq_printf(s, #x"\t%lld\n", signalCtrl->record.stamp[x])

#define SEQ_GEAR_PRINT(x)  \
	seq_printf(s, #x"\t%d\n", signalCtrl->record.gear_err_cnt[x])

static int record_read_func(struct seq_file *s, void *v)
{
	struct unipro_signal_quality_ctrl *signalCtrl =
		(struct unipro_signal_quality_ctrl *)(s->private);
	if (!signalCtrl)
		return -EINVAL;
	SEQ_EASY_PRINT(ufs_device_err_cnt);
	SEQ_EASY_PRINT(ufs_host_err_cnt);
	SEQ_EASY_PRINT(ufs_bus_err_cnt);
	SEQ_EASY_PRINT(ufs_crypto_err_cnt);
	SEQ_EASY_PRINT(ufs_link_lost_cnt);
	SEQ_EASY_PRINT(unipro_PA_err_total_cnt);
	SEQ_PA_PRINT(UNIPRO_PA_LANE0_ERR_CNT);
	SEQ_PA_PRINT(UNIPRO_PA_LANE1_ERR_CNT);
	SEQ_PA_PRINT(UNIPRO_PA_LANE2_ERR_CNT);
	SEQ_PA_PRINT(UNIPRO_PA_LANE3_ERR_CNT);
	SEQ_PA_PRINT(UNIPRO_PA_LINE_RESET);
	SEQ_EASY_PRINT(unipro_DL_err_total_cnt);
	SEQ_DL_PRINT(UNIPRO_DL_NAC_RECEIVED);
	SEQ_DL_PRINT(UNIPRO_DL_TCX_REPLAY_TIMER_EXPIRED);
	SEQ_DL_PRINT(UNIPRO_DL_AFCX_REQUEST_TIMER_EXPIRED);
	SEQ_DL_PRINT(UNIPRO_DL_FCX_PROTECTION_TIMER_EXPIRED);
	SEQ_DL_PRINT(UNIPRO_DL_CRC_ERROR);
	SEQ_DL_PRINT(UNIPRO_DL_RX_BUFFER_OVERFLOW);
	SEQ_DL_PRINT(UNIPRO_DL_MAX_FRAME_LENGTH_EXCEEDED);
	SEQ_DL_PRINT(UNIPRO_DL_WRONG_SEQUENCE_NUMBER);
	SEQ_DL_PRINT(UNIPRO_DL_AFC_FRAME_SYNTAX_ERROR);
	SEQ_DL_PRINT(UNIPRO_DL_NAC_FRAME_SYNTAX_ERROR);
	SEQ_DL_PRINT(UNIPRO_DL_EOF_SYNTAX_ERROR);
	SEQ_DL_PRINT(UNIPRO_DL_FRAME_SYNTAX_ERROR);
	SEQ_DL_PRINT(UNIPRO_DL_BAD_CTRL_SYMBOL_TYPE);
	SEQ_DL_PRINT(UNIPRO_DL_PA_INIT_ERROR);
	SEQ_DL_PRINT(UNIPRO_DL_PA_ERROR_IND_RECEIVED);
	SEQ_DL_PRINT(UNIPRO_DL_PA_INIT);
	SEQ_EASY_PRINT(unipro_NL_err_total_cnt);
	SEQ_NL_PRINT(UNIPRO_NL_UNSUPPORTED_HEADER_TYPE);
	SEQ_NL_PRINT(UNIPRO_NL_BAD_DEVICEID_ENC);
	SEQ_NL_PRINT(UNIPRO_NL_LHDR_TRAP_PACKET_DROPPING);
	SEQ_EASY_PRINT(unipro_TL_err_total_cnt);
	SEQ_TL_PRINT(UNIPRO_TL_UNSUPPORTED_HEADER_TYPE);
	SEQ_TL_PRINT(UNIPRO_TL_UNKNOWN_CPORTID);
	SEQ_TL_PRINT(UNIPRO_TL_NO_CONNECTION_RX);
	SEQ_TL_PRINT(UNIPRO_TL_CONTROLLED_SEGMENT_DROPPING);
	SEQ_TL_PRINT(UNIPRO_TL_BAD_TC);
	SEQ_TL_PRINT(UNIPRO_TL_E2E_CREDIT_OVERFLOW);
	SEQ_TL_PRINT(UNIPRO_TL_SAFETY_VALVE_DROPPING);
	SEQ_EASY_PRINT(unipro_DME_err_total_cnt);
	SEQ_DME_PRINT(UNIPRO_DME_GENERIC);
	SEQ_DME_PRINT(UNIPRO_DME_TX_QOS);
	SEQ_DME_PRINT(UNIPRO_DME_RX_QOS);
	SEQ_DME_PRINT(UNIPRO_DME_PA_INIT_QOS);
	SEQ_GEAR_PRINT(UFS_HS_G1);
	SEQ_GEAR_PRINT(UFS_HS_G2);
	SEQ_GEAR_PRINT(UFS_HS_G3);
	SEQ_GEAR_PRINT(UFS_HS_G4);
	SEQ_GEAR_PRINT(UFS_HS_G5);
	return 0;
}

static int record_open(struct inode *inode, struct file *file)
{
	return single_open(file, record_read_func, pde_data(inode));
}

static const struct proc_ops record_fops = {
	.proc_open = record_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};

#define SEQ_UPLOAD_PRINT(x) \
	seq_printf(s, #x": %d\n", signalCtrl->record.x \
		-signalCtrl->record_upload.x);\
	signalCtrl->record_upload.x = signalCtrl->record.x;
#define SEQ_UPLOAD_STAMP_PRINT(x) \
	seq_printf(s, #x": %lld\n", signalCtrl->record.stamp[x] \
		-signalCtrl->record_upload.stamp[x]);\
	signalCtrl->record_upload.stamp[x] = signalCtrl->record.stamp[x];

#define SEQ_PA_UPLOAD_PRINT(x) \
	seq_printf(s, #x": %d\n", signalCtrl->record.unipro_PA_err_cnt[x] \
		-signalCtrl->record_upload.unipro_PA_err_cnt[x]);\
	signalCtrl->record_upload.unipro_PA_err_cnt[x] = signalCtrl->record.unipro_PA_err_cnt[x];

#define SEQ_DL_UPLOAD_PRINT(x) \
		seq_printf(s, #x": %d\n", signalCtrl->record.unipro_DL_err_cnt[x] \
			-signalCtrl->record_upload.unipro_DL_err_cnt[x]);\
		signalCtrl->record_upload.unipro_DL_err_cnt[x] = signalCtrl->record.unipro_DL_err_cnt[x];

#define SEQ_DL_UPLOAD_PRINT(x) \
			seq_printf(s, #x": %d\n", signalCtrl->record.unipro_DL_err_cnt[x] \
				-signalCtrl->record_upload.unipro_DL_err_cnt[x]);\
			signalCtrl->record_upload.unipro_DL_err_cnt[x] = signalCtrl->record.unipro_DL_err_cnt[x];

#define SEQ_NL_UPLOAD_PRINT(x) \
				seq_printf(s, #x": %d\n", signalCtrl->record.unipro_NL_err_cnt[x] \
					-signalCtrl->record_upload.unipro_NL_err_cnt[x]);\
				signalCtrl->record_upload.unipro_NL_err_cnt[x] = signalCtrl->record.unipro_NL_err_cnt[x];

#define SEQ_TL_UPLOAD_PRINT(x) \
					seq_printf(s, #x": %d\n", signalCtrl->record.unipro_TL_err_cnt[x] \
						-signalCtrl->record_upload.unipro_TL_err_cnt[x]);\
					signalCtrl->record_upload.unipro_TL_err_cnt[x] = signalCtrl->record.unipro_TL_err_cnt[x];

#define SEQ_DME_UPLOAD_PRINT(x) \
						seq_printf(s, #x": %d\n", signalCtrl->record.unipro_DME_err_cnt[x] \
							-signalCtrl->record_upload.unipro_DME_err_cnt[x]);\
						signalCtrl->record_upload.unipro_DME_err_cnt[x] = signalCtrl->record.unipro_DME_err_cnt[x];

#define SEQ_GEAR_UPLOAD_PRINT(x) \
						seq_printf(s, #x": %d\n", signalCtrl->record.gear_err_cnt[x] \
							-signalCtrl->record_upload.gear_err_cnt[x]);\
						signalCtrl->record_upload.gear_err_cnt[x] = signalCtrl->record.gear_err_cnt[x];

static int record_upload_read_func(struct seq_file *s, void *v)
{
	struct unipro_signal_quality_ctrl *signalCtrl =
		(struct unipro_signal_quality_ctrl *)(s->private);
	if (!signalCtrl)
		return -EINVAL;
	SEQ_UPLOAD_PRINT(ufs_device_err_cnt);
	SEQ_UPLOAD_PRINT(ufs_host_err_cnt);
	SEQ_UPLOAD_PRINT(ufs_bus_err_cnt);
	SEQ_UPLOAD_PRINT(ufs_crypto_err_cnt);
	SEQ_UPLOAD_PRINT(ufs_link_lost_cnt);
	SEQ_UPLOAD_PRINT(unipro_PA_err_total_cnt);
	SEQ_UPLOAD_PRINT(unipro_DL_err_total_cnt);
	SEQ_UPLOAD_PRINT(unipro_NL_err_total_cnt);
	SEQ_UPLOAD_PRINT(unipro_TL_err_total_cnt);
	SEQ_UPLOAD_PRINT(unipro_DME_err_total_cnt);
	SEQ_PA_UPLOAD_PRINT(UNIPRO_PA_LANE0_ERR_CNT);
	SEQ_PA_UPLOAD_PRINT(UNIPRO_PA_LANE1_ERR_CNT);
	SEQ_PA_UPLOAD_PRINT(UNIPRO_PA_LANE2_ERR_CNT);
	SEQ_PA_UPLOAD_PRINT(UNIPRO_PA_LANE3_ERR_CNT);
	SEQ_PA_UPLOAD_PRINT(UNIPRO_PA_LINE_RESET);

	SEQ_DL_UPLOAD_PRINT(UNIPRO_DL_NAC_RECEIVED);
	SEQ_DL_UPLOAD_PRINT(UNIPRO_DL_TCX_REPLAY_TIMER_EXPIRED);
	SEQ_DL_UPLOAD_PRINT(UNIPRO_DL_AFCX_REQUEST_TIMER_EXPIRED);
	SEQ_DL_UPLOAD_PRINT(UNIPRO_DL_FCX_PROTECTION_TIMER_EXPIRED);
	SEQ_DL_UPLOAD_PRINT(UNIPRO_DL_CRC_ERROR);
	SEQ_DL_UPLOAD_PRINT(UNIPRO_DL_RX_BUFFER_OVERFLOW);
	SEQ_DL_UPLOAD_PRINT(UNIPRO_DL_MAX_FRAME_LENGTH_EXCEEDED);
	SEQ_DL_UPLOAD_PRINT(UNIPRO_DL_WRONG_SEQUENCE_NUMBER);
	SEQ_DL_UPLOAD_PRINT(UNIPRO_DL_AFC_FRAME_SYNTAX_ERROR);
	SEQ_DL_UPLOAD_PRINT(UNIPRO_DL_NAC_FRAME_SYNTAX_ERROR);
	SEQ_DL_UPLOAD_PRINT(UNIPRO_DL_EOF_SYNTAX_ERROR);
	SEQ_DL_UPLOAD_PRINT(UNIPRO_DL_FRAME_SYNTAX_ERROR);
	SEQ_DL_UPLOAD_PRINT(UNIPRO_DL_BAD_CTRL_SYMBOL_TYPE);
	SEQ_DL_UPLOAD_PRINT(UNIPRO_DL_PA_INIT_ERROR);
	SEQ_DL_UPLOAD_PRINT(UNIPRO_DL_PA_ERROR_IND_RECEIVED);
	SEQ_DL_UPLOAD_PRINT(UNIPRO_DL_PA_INIT);

	SEQ_NL_UPLOAD_PRINT(UNIPRO_NL_UNSUPPORTED_HEADER_TYPE);
	SEQ_NL_UPLOAD_PRINT(UNIPRO_NL_BAD_DEVICEID_ENC);
	SEQ_NL_UPLOAD_PRINT(UNIPRO_NL_LHDR_TRAP_PACKET_DROPPING);

	SEQ_TL_UPLOAD_PRINT(UNIPRO_TL_UNSUPPORTED_HEADER_TYPE);
	SEQ_TL_UPLOAD_PRINT(UNIPRO_TL_UNKNOWN_CPORTID);
	SEQ_TL_UPLOAD_PRINT(UNIPRO_TL_NO_CONNECTION_RX);
	SEQ_TL_UPLOAD_PRINT(UNIPRO_TL_CONTROLLED_SEGMENT_DROPPING);
	SEQ_TL_UPLOAD_PRINT(UNIPRO_TL_BAD_TC);
	SEQ_TL_UPLOAD_PRINT(UNIPRO_TL_E2E_CREDIT_OVERFLOW);
	SEQ_TL_UPLOAD_PRINT(UNIPRO_TL_SAFETY_VALVE_DROPPING);

	SEQ_DME_UPLOAD_PRINT(UNIPRO_DME_GENERIC);
	SEQ_DME_UPLOAD_PRINT(UNIPRO_DME_TX_QOS);
	SEQ_DME_UPLOAD_PRINT(UNIPRO_DME_RX_QOS);
	SEQ_DME_UPLOAD_PRINT(UNIPRO_DME_PA_INIT_QOS);

	SEQ_GEAR_UPLOAD_PRINT(UFS_HS_G1);
	SEQ_GEAR_UPLOAD_PRINT(UFS_HS_G2);
	SEQ_GEAR_UPLOAD_PRINT(UFS_HS_G3);
	SEQ_GEAR_UPLOAD_PRINT(UFS_HS_G4);
	SEQ_GEAR_UPLOAD_PRINT(UFS_HS_G5);
	return 0;
}

static int record_upload_open(struct inode *inode, struct file *file)
{
	return single_open(file, record_upload_read_func, pde_data(inode));
}

static const struct proc_ops record_upload_fops = {
	.proc_open = record_upload_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};

int create_signal_quality_proc(struct unipro_signal_quality_ctrl *signalCtrl)
{
	struct proc_dir_entry *d_entry;
	signalCtrl->ctrl_dir = proc_mkdir("ufs_signalShow", NULL);
	if (!signalCtrl->ctrl_dir)
		return -ENOMEM;
	d_entry = proc_create_data("record", S_IRUGO, signalCtrl->ctrl_dir,
			&record_fops, signalCtrl);
	if (!d_entry)
		return -ENOMEM;
	d_entry = proc_create_data("record_upload", S_IRUGO, signalCtrl->ctrl_dir,
			&record_upload_fops, signalCtrl);
	if (!d_entry)
		return -ENOMEM;
	return 0;
}

void remove_signal_quality_proc(struct unipro_signal_quality_ctrl *signalCtrl)
{
	if (signalCtrl->ctrl_dir) {
		remove_proc_entry("record", signalCtrl->ctrl_dir);
		remove_proc_entry("record_upload", signalCtrl->ctrl_dir);
	}
	return;
}

void recordGearErr(struct unipro_signal_quality_ctrl *signalCtrl, struct ufs_hba *hba)
{
	struct ufs_pa_layer_attr *pwr_info = &hba->pwr_info;
	u32 dev_gear = min_t(u32, pwr_info->gear_rx, pwr_info->gear_tx);

	if (dev_gear > UFS_HS_G5)
		return;

	signalCtrl->record.gear_err_cnt[dev_gear]++;
}

void recordSignalerr(struct ufs_hba *hba, unsigned int val, enum ufs_event_type evt)
{
	recordUniproErr(&signalCtrl, val, evt);
	recordGearErr(&signalCtrl, hba);
}
EXPORT_SYMBOL_GPL(recordSignalerr);

int get_rtc_time(struct rtc_time *tm)
{
	struct rtc_device *rtc;
	int rc = 0;

	rtc = rtc_class_open("rtc0");
	if (rtc == NULL)
		return -1;

	rc = rtc_read_time(rtc, tm);
	if (rc)
		goto close_time;

	rc = rtc_valid_tm(tm);
	if (rc)
		goto close_time;

close_time:
	rtc_class_close(rtc);

	return rc;
}

void ufs_active_time_get(struct ufs_hba *hba)
{
	struct rtc_time tm;
	int rc = 0;
	ufs_transmission_status.active_count++;
	rc = get_rtc_time(&tm);
	if (rc != 0) {
		dev_err(hba->dev,"ufs_transmission_status: get_rtc_time failed\n");
		return;
	}
	ufs_transmission_status.resume_timing = (tm.tm_hour * 3600 + tm.tm_min * 60 + tm.tm_sec);
	if (ufs_transmission_status.resume_timing < ufs_transmission_status.suspend_timing) {
		ufs_transmission_status.sleep_time += ((ufs_transmission_status.resume_timing
			+ ONE_DAY_SEC) - ufs_transmission_status.suspend_timing);
		return;
	}
	if(ufs_transmission_status.suspend_timing == 0)
		return;

	ufs_transmission_status.sleep_time += (ufs_transmission_status.resume_timing
		- ufs_transmission_status.suspend_timing);
	return;
}
EXPORT_SYMBOL_GPL(ufs_active_time_get);


void ufs_sleep_time_get(struct ufs_hba *hba)
{
	struct rtc_time tm;
	int rc = 0;
	ufs_transmission_status.sleep_count++;
	rc = get_rtc_time(&tm);
	if (rc != 0) {
		dev_err(hba->dev,"ufs_transmission_status: get_rtc_time failed\n");
		return;
	}
	ufs_transmission_status.suspend_timing = (tm.tm_hour * 3600 + tm.tm_min * 60 + tm.tm_sec);
	if (ufs_transmission_status.suspend_timing < ufs_transmission_status.resume_timing) {
		ufs_transmission_status.active_time += ((ufs_transmission_status.suspend_timing
			+ ONE_DAY_SEC) - ufs_transmission_status.resume_timing);
		return;
	}
	if(ufs_transmission_status.resume_timing == 0)
		return;

	ufs_transmission_status.active_time += (ufs_transmission_status.suspend_timing
		- ufs_transmission_status.resume_timing);
	return;
}
EXPORT_SYMBOL_GPL(ufs_sleep_time_get);

static void ufshcd_lrb_scsicmd_time_statistics(struct ufs_hba *hba, struct ufshcd_lrb *lrbp)
{
	if (lrbp->cmd->cmnd[0] == WRITE_10 || lrbp->cmd->cmnd[0] == WRITE_16) {
		if (hba->pwr_info.gear_tx == 1) {
			ufs_transmission_status.gear_min_write_sec += blk_rq_sectors(scsi_cmd_to_rq(lrbp->cmd));
			ufs_transmission_status.gear_min_write_us +=
				ktime_us_delta(lrbp->compl_time_stamp, lrbp->issue_time_stamp);
		}

		if (hba->pwr_info.gear_tx == 3 || hba->pwr_info.gear_tx == 4) {
			ufs_transmission_status.gear_max_write_sec += blk_rq_sectors(scsi_cmd_to_rq(lrbp->cmd));
			ufs_transmission_status.gear_max_write_us +=
				ktime_us_delta(lrbp->compl_time_stamp, lrbp->issue_time_stamp);
		}
	} else if (lrbp->cmd->cmnd[0] == READ_10 || lrbp->cmd->cmnd[0] == READ_16) {
		if (hba->pwr_info.gear_rx == 1) {
			ufs_transmission_status.gear_min_read_sec += blk_rq_sectors(scsi_cmd_to_rq(lrbp->cmd));
			ufs_transmission_status.gear_min_read_us +=
				ktime_us_delta(lrbp->compl_time_stamp, lrbp->issue_time_stamp);
		}

		if (hba->pwr_info.gear_rx == 3 || hba->pwr_info.gear_rx == 4) {
			ufs_transmission_status.gear_max_read_sec += blk_rq_sectors(scsi_cmd_to_rq(lrbp->cmd));
			ufs_transmission_status.gear_max_read_us +=
				ktime_us_delta(lrbp->compl_time_stamp, lrbp->issue_time_stamp);
		}
	} else {
		if (hba->pwr_info.gear_rx == 1) {
			ufs_transmission_status.gear_min_other_sec += blk_rq_sectors(scsi_cmd_to_rq(lrbp->cmd));
			ufs_transmission_status.gear_min_other_us += ktime_us_delta(lrbp->compl_time_stamp, lrbp->issue_time_stamp);
		}

		if (hba->pwr_info.gear_rx == 3 || hba->pwr_info.gear_rx == 4) {
			ufs_transmission_status.gear_max_other_sec += blk_rq_sectors(scsi_cmd_to_rq(lrbp->cmd));
			ufs_transmission_status.gear_max_other_us += ktime_us_delta(lrbp->compl_time_stamp, lrbp->issue_time_stamp);
		}
	}

	return;
}

static void ufshcd_lrb_devcmd_time_statistics(struct ufs_hba *hba, struct ufshcd_lrb *lrbp)
{
	if (hba->pwr_info.gear_tx == 1) {
		ufs_transmission_status.gear_min_dev_us +=
			ktime_us_delta(lrbp->compl_time_stamp, lrbp->issue_time_stamp);
	}

	if (hba->pwr_info.gear_tx == 3 || hba->pwr_info.gear_tx == 4) {
		ufs_transmission_status.gear_max_dev_us +=
			ktime_us_delta(lrbp->compl_time_stamp, lrbp->issue_time_stamp);
	}
}

void ufs_send_cmd_handle(void *data, struct ufs_hba *hba, struct ufshcd_lrb *lrbp)
{
	if (ufs_transmission_status.transmission_status_enable) {
		if(lrbp->cmd) {
			ufs_transmission_status.scsi_send_count++;
		} else {
			ufs_transmission_status.dev_cmd_count++;
		}
	}
}

void ufs_compl_cmd_handle(void *data, struct ufs_hba *hba, struct ufshcd_lrb *lrbp)
{
	if (lrbp->cmd) {
		if (ufs_transmission_status.transmission_status_enable) {
			lrbp->compl_time_stamp = ktime_get();
			ufshcd_lrb_scsicmd_time_statistics(hba, lrbp);
		}
	} else if (lrbp->command_type == UTP_CMD_TYPE_DEV_MANAGE ||
			lrbp->command_type == UTP_CMD_TYPE_UFS_STORAGE) {
		if (ufs_transmission_status.transmission_status_enable) {
			ufshcd_lrb_devcmd_time_statistics(hba, lrbp);
		}
	}
}

static ssize_t ufshcd_transmission_status_data_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE,
					"transmission_status_enable:%u\n"
					"gear_min_write_sec:%llu\n"
					"gear_max_write_sec:%llu\n"
					"gear_min_read_sec:%llu\n"
					"gear_max_read_sec:%llu\n"
					"gear_min_write_us:%llu\n"
					"gear_max_write_us:%llu\n"
					"gear_min_read_us:%llu\n"
					"gear_max_read_us:%llu\n"
					"gear_min_dev_us:%llu\n"
					"gear_max_dev_us:%llu\n"
					"gear_min_other_sec:%llu\n"
					"gear_max_other_sec:%llu\n"
					"gear_min_other_us:%llu\n"
					"gear_max_other_us:%llu\n"
					"scsi_send_count:%llu\n"
					"dev_cmd_count:%llu\n"
					"active_count:%llu\n"
					"active_time:%llu\n"
					"sleep_count:%llu\n"
					"sleep_time:%llu\n"
					"powerdown_count:%llu\n"
					"powerdown_time:%llu\n"
					"power_total_count:%llu\n"
					"current_pwr_mode:%u\n",
					ufs_transmission_status.transmission_status_enable,
					ufs_transmission_status.gear_min_write_sec,
					ufs_transmission_status.gear_max_write_sec,
					ufs_transmission_status.gear_min_read_sec,
					ufs_transmission_status.gear_max_read_sec,
					ufs_transmission_status.gear_min_write_us,
					ufs_transmission_status.gear_max_write_us,
					ufs_transmission_status.gear_min_read_us,
					ufs_transmission_status.gear_max_read_us,
					ufs_transmission_status.gear_min_dev_us,
					ufs_transmission_status.gear_max_dev_us,
					ufs_transmission_status.gear_min_other_sec,
					ufs_transmission_status.gear_max_other_sec,
					ufs_transmission_status.gear_min_other_us,
					ufs_transmission_status.gear_max_other_us,
					ufs_transmission_status.scsi_send_count,
					ufs_transmission_status.dev_cmd_count,
					ufs_transmission_status.active_count,
					ufs_transmission_status.active_time,
					ufs_transmission_status.sleep_count,
					ufs_transmission_status.sleep_time,
					ufs_transmission_status.powerdown_count,
					ufs_transmission_status.powerdown_time,
					ufs_transmission_status.power_total_count,
					ufs_transmission_status.current_pwr_mode);
}

static ssize_t ufshcd_transmission_status_data_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 value;

	if (kstrtou32(buf, 0, &value))
		return -EINVAL;

	value = !!value;

	if (value) {
		ufs_transmission_status.transmission_status_enable = 1;
	} else {
		ufs_transmission_status.transmission_status_enable = 0;
		memset(&ufs_transmission_status, 0, sizeof(struct ufs_transmission_status_t));
	}

	return count;
}

static void ufshcd_transmission_status_init_sysfs(struct ufs_hba *hba)
{
	printk("tianwen: ufshcd_transmission_status_init_sysfs start\n");
	ufs_transmission_status_attr.show = ufshcd_transmission_status_data_show;
	ufs_transmission_status_attr.store = ufshcd_transmission_status_data_store;
	sysfs_attr_init(&ufs_transmission_status_attr.attr);
	ufs_transmission_status_attr.attr.name = "ufs_transmission_status";
	ufs_transmission_status_attr.attr.mode = 0644;
	if (device_create_file(hba->dev, &ufs_transmission_status_attr))
		dev_err(hba->dev, "Failed to create sysfs for ufs_transmission_status_attr\n");

	/*init the struct ufs_transmission_status*/
	memset(&ufs_transmission_status, 0, sizeof(struct ufs_transmission_status_t));
	ufs_transmission_status.transmission_status_enable = 1;
}

#ifdef CONFIG_SCSI_UFS_HPB
static bool is_ufshpb_allowed(struct ufs_hba *hba)
{
	return !(hba->ufshpb_dev.hpb_disabled);
}
#else
static bool is_ufshpb_allowed(struct ufs_hba *hba)
{
	pr_warn("ufshpb macro definition is not opened\n");
	return false;
}
#endif /* CONFIG_SCSI_UFS_HPB */

static void create_devinfo_ufs(void *data, async_cookie_t c)
{
	struct scsi_device *sdev = data;
	static char temp_version[5] = {0};
	static char vendor[9] = {0};
	static char model[17] = {0};
	int ret = 0;
	struct ufs_hba *hba = NULL;

	pr_info("get ufs device vendor/model/rev\n");
	WARN_ON(!sdev);
	strncpy(temp_version, sdev->rev, 4);
	strncpy(vendor, sdev->vendor, 8);
	strncpy(model, sdev->model, 16);

	ret = register_device_proc("ufs_version", temp_version, vendor);

	if (ret) {
		pr_err("%s create ufs_version fail, ret=%d",__func__,ret);
		return;
	}

	ret = register_device_proc("ufs", model, vendor);

	if (ret) {
		pr_err("%s create ufs fail, ret=%d",__func__,ret);
	}

	hba = shost_priv(sdev->host);
	if (hba && ufshcd_is_wb_allowed(hba)) {
		ufsplus_wb_status = 1;
	}
	if (hba && is_ufshpb_allowed(hba)) {
		ufsplus_hpb_status = 1;
	}
	ret = register_device_proc_for_ufsplus("ufsplus_status", &ufsplus_hpb_status, &ufsplus_wb_status);
	if (ret) {
		pr_err("%s create , ret=%d",__func__,ret);
	}

}

static int monitor_verify_command(unsigned char *cmd)
{
    if (cmd[0] != 0x3B && cmd[0] != 0x3C && cmd[0] != 0xC0)
        return false;

    return true;
}

/**
 * ufs_ioctl_monitor - special cmd for memory monitor
 * @hba: per-adapter instance
 * @buf_user: user space buffer for ioctl data
 * @return: 0 for success negative error code otherwise
 *
 */
int ufs_ioctl_monitor(struct scsi_device *dev, void __user *buf_user)
{
	struct request_queue *q = dev->request_queue;
	struct request *rq;
	struct scsi_cmnd *req;
	struct scsi_ioctl_command __user *sic = (struct scsi_ioctl_command __user *)buf_user;
	int err;
	unsigned int in_len, out_len, bytes, opcode, cmdlen;
	char *buffer = NULL;

	/*
	 * get in an out lengths, verify they don't exceed a page worth of data
	 */
	if (get_user(in_len, &sic->inlen))
		return -EFAULT;
	if (get_user(out_len, &sic->outlen))
		return -EFAULT;
	if (in_len > PAGE_SIZE || out_len > PAGE_SIZE)
		return -EINVAL;
	if (get_user(opcode, sic->data))
		return -EFAULT;

	bytes = max(in_len, out_len);
	if (bytes) {
		buffer = kzalloc(bytes, GFP_NOIO | GFP_USER| __GFP_NOWARN);
		if (!buffer)
			return -ENOMEM;

	}

	rq = scsi_alloc_request(q, in_len ? REQ_OP_DRV_OUT : REQ_OP_DRV_IN, 0);
	if (IS_ERR(rq)) {
		err = PTR_ERR(rq);
		goto error_free_buffer;
	}
	req = blk_mq_rq_to_pdu(rq);

	cmdlen = COMMAND_SIZE(opcode);
	if ((VENDOR_SPECIFIC_CDB == opcode) &&(0 == strncmp(dev->vendor, "SAMSUNG ", 8)))
		cmdlen = 16;

	/*
	 * get command and data to send to device, if any
	 */
	err = -EFAULT;
	req->cmd_len = cmdlen;
	if (copy_from_user(req->cmnd, sic->data, cmdlen))
		goto error;

	if (in_len && copy_from_user(buffer, sic->data + cmdlen, in_len))
		goto error;

	if (!monitor_verify_command(req->cmnd))
		goto error;

	/* default.  possible overriden later */
	req->retries = 5;

	if (bytes) {
		err = blk_rq_map_kern(q, rq, buffer, bytes, GFP_NOIO);
		if (err)
			goto error;
	}
	blk_execute_rq(rq, 0);

#define OMAX_SB_LEN 16          /* For backward compatibility */
	err = req->result & 0xff;	/* only 8 bit SCSI status */
	if (err) {
		if (req->sense_len && req->sense_buffer) {
			bytes = (OMAX_SB_LEN > req->sense_len) ?
				req->sense_len : OMAX_SB_LEN;
			if (copy_to_user(sic->data, req->sense_buffer, bytes))
				err = -EFAULT;
		}
	} else {
		if (copy_to_user(sic->data, buffer, out_len))
			err = -EFAULT;
	}

error:
	blk_mq_free_request(rq);

error_free_buffer:
	kfree(buffer);

	return err;
}

static void probe_android_vh_ufs_update_sdev(void *data, struct scsi_device *sdev)
{
	if (strcmp(sdev->model, ufs_null_device_strs) && atomic_inc_return(&ufs_init_done) == 1) {
		async_schedule(create_devinfo_ufs, sdev);
	}

}

static int oplus_ufs_regist_tracepoint(void)
{
	int rc;
	printk("oplus ufs trace point init");
	rc = register_trace_android_vh_ufs_send_command(ufs_send_cmd_handle, NULL);
	if (rc != 0)
		pr_err("register_trace_android_vh_ufs_send_command failed! rc=%d\n", rc);

	rc = register_trace_android_vh_ufs_compl_command(ufs_compl_cmd_handle, NULL);
	if (rc != 0)
		pr_err("register_trace_android_vh_ufs_compl_command failed! rc=%d\n", rc);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	rc = register_trace_android_vh_ufs_update_sdev(probe_android_vh_ufs_update_sdev, NULL);
	if (rc != 0)
		pr_err("register_trace_android_vh_ufs_update_sdev failed! rc=%d\n", rc);
#endif /*  */
	return rc;
}

static void oplus_ufs_unregist_tracepoint(void)
{
	unregister_trace_android_vh_ufs_send_command(ufs_send_cmd_handle, NULL);
	unregister_trace_android_vh_ufs_compl_command(ufs_compl_cmd_handle, NULL);
	unregister_trace_android_vh_ufs_update_sdev(probe_android_vh_ufs_update_sdev, NULL);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)) || defined(CONFIG_OPLUS_QCOM_UFS_DRIVER)
/**
 * ufs_oplus_query_ioctl - perform user read queries
 * @hba: per-adapter instance
 * @lun: used for lun specific queries
 * @buffer: user space buffer for reading and submitting query data and params
 * @return: 0 for success negative error code otherwise
 *
 * Expected/Submitted buffer structure is struct ufs_ioctl_query_data.
 * It will read the opcode, idn and buf_length parameters, and, put the
 * response in the buffer field while updating the used size in buf_length.
 */
static int
ufs_oplus_query_ioctl(struct ufs_hba *hba, u8 lun, void __user *buffer)
{
	struct ufs_ioctl_query_data *ioctl_data;
	int err = 0;
	int length = 0;
	void *data_ptr;
	bool flag;
	u32 att;
	u8 index;
	u8 *desc = NULL;

	ioctl_data = kzalloc(sizeof(*ioctl_data), GFP_KERNEL);
	if (!ioctl_data) {
		err = -ENOMEM;
		goto out;
	}

	/* extract params from user buffer */
	err = copy_from_user(ioctl_data, buffer,
			     sizeof(struct ufs_ioctl_query_data));
	if (err) {
		dev_err(hba->dev,
			"%s: Failed copying buffer from user, err %d\n",
			__func__, err);
		goto out_release_mem;
	}

	/* verify legal parameters & send query */
	switch (ioctl_data->opcode) {
	case UPIU_QUERY_OPCODE_READ_DESC:
		switch (ioctl_data->idn) {
		case QUERY_DESC_IDN_DEVICE:
		case QUERY_DESC_IDN_CONFIGURATION:
		case QUERY_DESC_IDN_INTERCONNECT:
		case QUERY_DESC_IDN_GEOMETRY:
		case QUERY_DESC_IDN_POWER:
		case QUERY_DESC_IDN_HEALTH:
			index = 0;
			break;
		case QUERY_DESC_IDN_UNIT:
			if (!ufs_is_valid_unit_desc_lun(&hba->dev_info, lun)) {
				dev_err(hba->dev,
					"%s: No unit descriptor for lun 0x%x\n",
					__func__, lun);
				err = -EINVAL;
				goto out_release_mem;
			}
			index = lun;
			break;
		default:
			goto out_einval;
		}
		length = min_t(int, QUERY_DESC_MAX_SIZE,
			       ioctl_data->buf_size);
		desc = kzalloc(length, GFP_KERNEL);
		if (!desc) {
			dev_err(hba->dev, "%s: Failed allocating %d bytes\n",
				__func__, length);
			err = -ENOMEM;
			goto out_release_mem;
		}
		err = ufshcd_query_descriptor_retry(hba, ioctl_data->opcode,
						    ioctl_data->idn, index, 0,
						    desc, &length);
		break;
	case UPIU_QUERY_OPCODE_READ_ATTR:
		switch (ioctl_data->idn) {
		case QUERY_ATTR_IDN_BOOT_LU_EN:
		case QUERY_ATTR_IDN_POWER_MODE:
		case QUERY_ATTR_IDN_ACTIVE_ICC_LVL:
		case QUERY_ATTR_IDN_OOO_DATA_EN:
		case QUERY_ATTR_IDN_BKOPS_STATUS:
		case QUERY_ATTR_IDN_PURGE_STATUS:
		case QUERY_ATTR_IDN_MAX_DATA_IN:
		case QUERY_ATTR_IDN_MAX_DATA_OUT:
		case QUERY_ATTR_IDN_REF_CLK_FREQ:
		case QUERY_ATTR_IDN_CONF_DESC_LOCK:
		case QUERY_ATTR_IDN_MAX_NUM_OF_RTT:
		case QUERY_ATTR_IDN_EE_CONTROL:
		case QUERY_ATTR_IDN_EE_STATUS:
		case QUERY_ATTR_IDN_SECONDS_PASSED:
			index = 0;
			break;
		case QUERY_ATTR_IDN_DYN_CAP_NEEDED:
		case QUERY_ATTR_IDN_CORR_PRG_BLK_NUM:
			index = lun;
			break;
		default:
			goto out_einval;
		}
		err = ufshcd_query_attr(hba, ioctl_data->opcode,
					ioctl_data->idn, index, 0, &att);
		break;

	case UPIU_QUERY_OPCODE_WRITE_ATTR:
		err = copy_from_user(&att,
				     buffer +
				     sizeof(struct ufs_ioctl_query_data),
				     sizeof(u32));
		if (err) {
			dev_err(hba->dev,
				"%s: Failed copying buffer from user, err %d\n",
				__func__, err);
			goto out_release_mem;
		}

		switch (ioctl_data->idn) {
		case QUERY_ATTR_IDN_BOOT_LU_EN:
			index = 0;
			if (!att) {
				dev_err(hba->dev,
					"%s: Illegal ufs query ioctl data, opcode 0x%x, idn 0x%x, att 0x%x\n",
					__func__, ioctl_data->opcode,
					(unsigned int)ioctl_data->idn, att);
				err = -EINVAL;
				goto out_release_mem;
			}
			break;
		default:
			goto out_einval;
		}
		err = ufshcd_query_attr(hba, ioctl_data->opcode,
					ioctl_data->idn, index, 0, &att);
		break;

	case UPIU_QUERY_OPCODE_READ_FLAG:
		switch (ioctl_data->idn) {
		case QUERY_FLAG_IDN_FDEVICEINIT:
		case QUERY_FLAG_IDN_PERMANENT_WPE:
		case QUERY_FLAG_IDN_PWR_ON_WPE:
		case QUERY_FLAG_IDN_BKOPS_EN:
		case QUERY_FLAG_IDN_PURGE_ENABLE:
		case QUERY_FLAG_IDN_FPHYRESOURCEREMOVAL:
		case QUERY_FLAG_IDN_BUSY_RTC:
			break;
		default:
			goto out_einval;
		}
		err = ufshcd_query_flag(hba, ioctl_data->opcode,
					ioctl_data->idn, 0, &flag);
		break;
	default:
		goto out_einval;
	}

	if (err) {
		dev_err(hba->dev, "%s: Query for idn %d failed\n", __func__,
			ioctl_data->idn);
		goto out_release_mem;
	}

	/*
	 * copy response data
	 * As we might end up reading less data than what is specified in
	 * "ioctl_data->buf_size". So we are updating "ioctl_data->
	 * buf_size" to what exactly we have read.
	 */
	switch (ioctl_data->opcode) {
	case UPIU_QUERY_OPCODE_READ_DESC:
		ioctl_data->buf_size = min_t(int, ioctl_data->buf_size, length);
		data_ptr = desc;
		break;
	case UPIU_QUERY_OPCODE_READ_ATTR:
		ioctl_data->buf_size = sizeof(u32);
		data_ptr = &att;
		break;
	case UPIU_QUERY_OPCODE_READ_FLAG:
		ioctl_data->buf_size = 1;
		data_ptr = &flag;
		break;
	case UPIU_QUERY_OPCODE_WRITE_ATTR:
		goto out_release_mem;
	default:
		goto out_einval;
	}

	/* copy to user */
	err = copy_to_user(buffer, ioctl_data,
			   sizeof(struct ufs_ioctl_query_data));
	if (err)
		dev_err(hba->dev, "%s: Failed copying back to user.\n",
			__func__);
	err = copy_to_user(buffer + sizeof(struct ufs_ioctl_query_data),
			   data_ptr, ioctl_data->buf_size);
	if (err)
		dev_err(hba->dev, "%s: err %d copying back to user.\n",
			__func__, err);
	goto out_release_mem;

out_einval:
	dev_err(hba->dev,
		"%s: illegal ufs query ioctl data, opcode 0x%x, idn 0x%x\n",
		__func__, ioctl_data->opcode, (unsigned int)ioctl_data->idn);
	err = -EINVAL;
out_release_mem:
	kfree(ioctl_data);
	kfree(desc);
out:
	return err;
}


static int
ufs_oplus_ioctl(struct scsi_device *dev, unsigned int cmd, void __user *buffer)
{
	struct ufs_hba *hba = shost_priv(dev->host);
	int err = 0;

	if (!hba)
		return -ENOTTY;
	if (!buffer) {
		dev_err(hba->dev, "%s: User buffer is NULL!\n", __func__);
		return -EINVAL;
	}

	switch (cmd) {
	case UFS_IOCTL_QUERY:
		down(&hba->host_sem);
		if (!ufshcd_is_user_access_allowed(hba)) {
			up(&hba->host_sem);
			err = -EBUSY;
			goto err_out;
		}
		ufshcd_rpm_get_sync(hba);
		err = ufs_oplus_query_ioctl(hba,
					   ufshcd_scsi_to_upiu_lun(dev->lun),
					   buffer);
		ufshcd_rpm_put_sync(hba);
		up(&hba->host_sem);
	break;
	case UFS_IOCTL_MONITOR:
		ufshcd_rpm_get_sync(hba);
		err = ufs_ioctl_monitor(dev, buffer);
		ufshcd_rpm_put_sync(hba);
	break;
	default:
		err = -ENOIOCTLCMD;
		dev_err(hba->dev, "%s: Unsupported ioctl cmd %d\n", __func__,
			cmd);
	break;
	}

err_out:
	return err;
}
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) || defined(CONFIG_OPLUS_QCOM_UFS_DRIVER) */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0))
static void ufs_update_sdev(struct scsi_device *sdev)
{
	async_schedule(create_devinfo_ufs, sdev);
}

static long ufs_common_oplus_ioctl (struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct scsi_device *dev = pde_data(file_inode(filp));
	long err = 0;

	if (dev == NULL)
		return -ENOTTY;

	if (_IOC_TYPE(cmd) != UFS_OPLUS_IOCTL_MAGIC)
		return -ENOTTY;

	switch (cmd)
	{
		case UFS_OPLUS_QUERY_IOCTL:
			err = ufs_oplus_ioctl(dev, UFS_IOCTL_QUERY, (void *)arg);
		break;
		case UFS_OPLUS_MONITOR_IOCTL:
			err = ufs_oplus_ioctl(dev, UFS_IOCTL_MONITOR, (void *)arg);
		break;
	}
	return err;
}

static struct proc_ops proc_ioctl_fops = {
	.proc_ioctl = ufs_common_oplus_ioctl,
};

static void ufs_oplus_ioctl_init(struct scsi_device *sdev) {
	struct proc_dir_entry *oplus_ufs_proc_dir = proc_mkdir("ufs_oplus_dir", NULL);
	struct proc_dir_entry *d_entry;

	if (!oplus_ufs_proc_dir)
		return;

	d_entry = proc_create_data("ufs_oplus_ioctl", 0644, oplus_ufs_proc_dir, &proc_ioctl_fops, sdev);
	if (!d_entry)
		return;
	return;
}

void ufs_oplus_init_sdev(struct scsi_device *sdev) {
	if (atomic_inc_return(&ufs_init_done) == 1) {
        	ufs_update_sdev(sdev);
		ufs_oplus_ioctl_init(sdev);
	}
}
EXPORT_SYMBOL_GPL(ufs_oplus_init_sdev);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) */

void ufs_init_oplus_dbg(struct ufs_hba *hba)
{
	oplus_ufs_regist_tracepoint();
	ufshcd_transmission_status_init_sysfs(hba);
	create_signal_quality_proc(&signalCtrl);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
#ifdef CONFIG_OPLUS_QCOM_UFS_DRIVER
	hba->host->hostt->ioctl = (int (*)(struct scsi_device *, unsigned int,
				   void __user *))ufs_oplus_ioctl;
#ifdef CONFIG_COMPAT
	hba->host->hostt->compat_ioctl = (int (*)(struct scsi_device *,
					  unsigned int,
					  void __user *))ufs_oplus_ioctl;
#endif /* CONFIG_COMPAT */
#endif /* CONFIG_OPLUS_QCOM_UFS_DRIVER */
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) */
}
EXPORT_SYMBOL_GPL(ufs_init_oplus_dbg);

void ufs_remove_oplus_dbg(void)
{
	oplus_ufs_unregist_tracepoint();
	remove_signal_quality_proc(&signalCtrl);
}
EXPORT_SYMBOL_GPL(ufs_remove_oplus_dbg);


static void __exit ufs_oplus_dbg_exit(void)
{
	return;
}

static int __init ufs_oplus_dbg_init(void)
{
	atomic_set(&ufs_init_done, 0);
	return 0;
}

module_init(ufs_oplus_dbg_init)
module_exit(ufs_oplus_dbg_exit)

MODULE_DESCRIPTION("Oplus UFS Debugging Facility");
MODULE_AUTHOR("oplus");
MODULE_LICENSE("GPL v2");


