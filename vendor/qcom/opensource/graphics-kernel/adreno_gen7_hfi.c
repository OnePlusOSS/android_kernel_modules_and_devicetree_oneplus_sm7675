// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/delay.h>
#include <linux/nvmem-consumer.h>

#include "adreno.h"
#include "adreno_gen7.h"
#include "adreno_gen7_gmu.h"
#include "adreno_gen7_hfi.h"
#include "kgsl_device.h"
#include "kgsl_trace.h"

/* Below section is for all structures related to HFI queues */
#define HFI_QUEUE_MAX HFI_QUEUE_DEFAULT_CNT

/* Total header sizes + queue sizes + 16 for alignment */
#define HFIMEM_SIZE (sizeof(struct hfi_queue_table) + 16 + \
		(HFI_QUEUE_SIZE * HFI_QUEUE_MAX))

#define HOST_QUEUE_START_ADDR(hfi_mem, i) \
	((hfi_mem)->hostptr + HFI_QUEUE_OFFSET(i))

struct gen7_hfi *to_gen7_hfi(struct adreno_device *adreno_dev)
{
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);

	return &gmu->hfi;
}

/* Size in below functions are in unit of dwords */
int gen7_hfi_queue_read(struct gen7_gmu_device *gmu, u32 queue_idx,
		unsigned int *output, unsigned int max_size)
{
	struct kgsl_memdesc *mem_addr = gmu->hfi.hfi_mem;
	struct hfi_queue_table *tbl = mem_addr->hostptr;
	struct hfi_queue_header *hdr = &tbl->qhdr[queue_idx];
	u32 *queue;
	u32 msg_hdr;
	u32 i, read;
	u32 size;
	int result = 0;

	if (hdr->status == HFI_QUEUE_STATUS_DISABLED)
		return -EINVAL;

	if (hdr->read_index == hdr->write_index)
		return -ENODATA;

	/* Clear the output data before populating */
	memset(output, 0, max_size);

	queue = HOST_QUEUE_START_ADDR(mem_addr, queue_idx);
	msg_hdr = queue[hdr->read_index];
	size = MSG_HDR_GET_SIZE(msg_hdr);

	if (size > (max_size >> 2)) {
		dev_err(&gmu->pdev->dev,
		"HFI message too big: hdr:0x%x rd idx=%d\n",
			msg_hdr, hdr->read_index);
		result = -EMSGSIZE;
		goto done;
	}

	read = hdr->read_index;

	if (read < hdr->queue_size) {
		for (i = 0; i < size && i < (max_size >> 2); i++) {
			output[i] = queue[read];
			read = (read + 1)%hdr->queue_size;
		}
		result = size;
	} else {
		/* In case FW messed up */
		dev_err(&gmu->pdev->dev,
			"Read index %d greater than queue size %d\n",
			hdr->read_index, hdr->queue_size);
		result = -ENODATA;
	}

	read = ALIGN(read, SZ_4) % hdr->queue_size;

	hfi_update_read_idx(hdr, read);

	/* For acks, trace the packet for which this ack was sent */
	if (MSG_HDR_GET_TYPE(msg_hdr) == HFI_MSG_ACK)
		trace_kgsl_hfi_receive(MSG_HDR_GET_ID(output[1]),
			MSG_HDR_GET_SIZE(output[1]),
			MSG_HDR_GET_SEQNUM(output[1]));
	else
		trace_kgsl_hfi_receive(MSG_HDR_GET_ID(msg_hdr),
			MSG_HDR_GET_SIZE(msg_hdr), MSG_HDR_GET_SEQNUM(msg_hdr));

done:
	return result;
}

int gen7_hfi_queue_write(struct adreno_device *adreno_dev, u32 queue_idx,
		u32 *msg, u32 size_bytes)
{
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);
	struct hfi_queue_table *tbl = gmu->hfi.hfi_mem->hostptr;
	struct hfi_queue_header *hdr = &tbl->qhdr[queue_idx];
	u32 *queue;
	u32 i, write_idx, read_idx, empty_space;
	u32 size_dwords = size_bytes >> 2;
	u32 align_size = ALIGN(size_dwords, SZ_4);
	u32 id = MSG_HDR_GET_ID(*msg);

	if (hdr->status == HFI_QUEUE_STATUS_DISABLED || !IS_ALIGNED(size_bytes, sizeof(u32)))
		return -EINVAL;

	queue = HOST_QUEUE_START_ADDR(gmu->hfi.hfi_mem, queue_idx);

	write_idx = hdr->write_index;
	read_idx = hdr->read_index;

	empty_space = (write_idx >= read_idx) ?
			(hdr->queue_size - (write_idx - read_idx))
			: (read_idx - write_idx);

	if (empty_space <= align_size)
		return -ENOSPC;

	for (i = 0; i < size_dwords; i++) {
		queue[write_idx] = msg[i];
		write_idx = (write_idx + 1) % hdr->queue_size;
	}

	/* Cookify any non used data at the end of the write buffer */
	for (; i < align_size; i++) {
		queue[write_idx] = 0xfafafafa;
		write_idx = (write_idx + 1) % hdr->queue_size;
	}

	trace_kgsl_hfi_send(id, size_dwords, MSG_HDR_GET_SEQNUM(*msg));

	hfi_update_write_idx(&hdr->write_index, write_idx);

	return 0;
}

int gen7_hfi_cmdq_write(struct adreno_device *adreno_dev, u32 *msg, u32 size_bytes)
{
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);
	struct gen7_hfi *hfi = &gmu->hfi;
	int ret;

	spin_lock(&hfi->cmdq_lock);

	if (test_bit(MSG_HDR_GET_ID(msg[0]), hfi->wb_set_record_bitmask))
		*msg = RECORD_MSG_HDR(*msg);

	ret = gen7_hfi_queue_write(adreno_dev, HFI_CMD_ID, msg, size_bytes);

	/*
	 * Some messages like ACD table and perf table are saved in memory, so we need
	 * to reset the header to make sure we do not send a record enabled bit incase
	 * we change the warmboot setting from debugfs
	 */
	*msg = CLEAR_RECORD_MSG_HDR(*msg);
	/*
	 * Memory barrier to make sure packet and write index are written before
	 * an interrupt is raised
	 */
	wmb();

	/* Send interrupt to GMU to receive the message */
	if (!ret)
		gmu_core_regwrite(KGSL_DEVICE(adreno_dev),
			GEN7_GMU_HOST2GMU_INTR_SET, 0x1);

	spin_unlock(&hfi->cmdq_lock);

	return ret;
}

/* Sizes of the queue and message are in unit of dwords */
static void init_queues(struct adreno_device *adreno_dev)
{
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);
	struct kgsl_memdesc *mem_addr = gmu->hfi.hfi_mem;
	int i;
	struct hfi_queue_table *tbl;
	struct hfi_queue_header *hdr;
	struct {
		unsigned int idx;
		unsigned int pri;
		unsigned int status;
	} queue[HFI_QUEUE_MAX] = {
		{ HFI_CMD_ID, HFI_CMD_PRI, HFI_QUEUE_STATUS_ENABLED },
		{ HFI_MSG_ID, HFI_MSG_PRI, HFI_QUEUE_STATUS_ENABLED },
		{ HFI_DBG_ID, HFI_DBG_PRI, HFI_QUEUE_STATUS_ENABLED },
	};

	/* Fill Table Header */
	tbl = mem_addr->hostptr;
	tbl->qtbl_hdr.version = 0;
	tbl->qtbl_hdr.size = sizeof(struct hfi_queue_table) >> 2;
	tbl->qtbl_hdr.qhdr0_offset = sizeof(struct hfi_queue_table_header) >> 2;
	tbl->qtbl_hdr.qhdr_size = sizeof(struct hfi_queue_header) >> 2;
	tbl->qtbl_hdr.num_q = HFI_QUEUE_MAX;
	tbl->qtbl_hdr.num_active_q = HFI_QUEUE_MAX;

	memset(&tbl->qhdr[0], 0, sizeof(tbl->qhdr));

	/* Fill Individual Queue Headers */
	for (i = 0; i < HFI_QUEUE_MAX; i++) {
		hdr = &tbl->qhdr[i];
		hdr->start_addr = GMU_QUEUE_START_ADDR(mem_addr->gmuaddr, i);
		hdr->type = QUEUE_HDR_TYPE(queue[i].idx, queue[i].pri, 0, 0);
		hdr->status = queue[i].status;
		hdr->queue_size = HFI_QUEUE_SIZE >> 2; /* convert to dwords */
	}
}

int gen7_hfi_init(struct adreno_device *adreno_dev)
{
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);
	struct gen7_hfi *hfi = &gmu->hfi;

	/* Allocates & maps memory for HFI */
	if (IS_ERR_OR_NULL(hfi->hfi_mem)) {
		hfi->hfi_mem = gen7_reserve_gmu_kernel_block(gmu, 0,
				HFIMEM_SIZE, GMU_NONCACHED_KERNEL, 0);
		if (!IS_ERR(hfi->hfi_mem))
			init_queues(adreno_dev);
	}

	return PTR_ERR_OR_ZERO(hfi->hfi_mem);
}

int gen7_receive_ack_cmd(struct gen7_gmu_device *gmu, void *rcvd,
	struct pending_cmd *ret_cmd)
{
	struct adreno_device *adreno_dev = gen7_gmu_to_adreno(gmu);
	struct kgsl_device *device = KGSL_DEVICE(adreno_dev);
	u32 *ack = rcvd;
	u32 hdr = ack[0];
	u32 req_hdr = ack[1];

	if (ret_cmd == NULL)
		return -EINVAL;

	if (CMP_HFI_ACK_HDR(ret_cmd->sent_hdr, req_hdr)) {
		memcpy(&ret_cmd->results, ack, MSG_HDR_GET_SIZE(hdr) << 2);
		return 0;
	}

	/* Didn't find the sender, list the waiter */
	dev_err_ratelimited(&gmu->pdev->dev,
		"HFI ACK: Cannot find sender for 0x%8.8x Waiter: 0x%8.8x\n",
		req_hdr, ret_cmd->sent_hdr);

	gmu_core_fault_snapshot(device);

	return -ENODEV;
}

static int poll_gmu_reg(struct adreno_device *adreno_dev,
	u32 offsetdwords, unsigned int expected_val,
	unsigned int mask, unsigned int timeout_ms)
{
	unsigned int val;
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);
	struct kgsl_device *device = KGSL_DEVICE(adreno_dev);
	unsigned long timeout = jiffies + msecs_to_jiffies(timeout_ms);
	bool nmi = false;

	while (time_is_after_jiffies(timeout)) {
		gmu_core_regread(device, offsetdwords, &val);
		if ((val & mask) == expected_val)
			return 0;

		/*
		 * If GMU firmware fails any assertion, error message is sent
		 * to KMD and NMI is triggered. So check if GMU is in NMI and
		 * timeout early. Bits [11:9] of A6XX_GMU_CM3_FW_INIT_RESULT
		 * contain GMU reset status. Non zero value here indicates that
		 * GMU reset is active, NMI handler would eventually complete
		 * and GMU would wait for recovery.
		 */
		gmu_core_regread(device, GEN7_GMU_CM3_FW_INIT_RESULT, &val);
		if (val & 0xE00) {
			nmi = true;
			break;
		}

		usleep_range(10, 100);
	}

	/* Check one last time */
	gmu_core_regread(device, offsetdwords, &val);
	if ((val & mask) == expected_val)
		return 0;

	dev_err(&gmu->pdev->dev,
		"Reg poll %s: offset 0x%x, want 0x%x, got 0x%x\n",
		nmi ? "abort" : "timeout", offsetdwords, expected_val,
		val & mask);

	return -ETIMEDOUT;
}

static int gen7_hfi_send_cmd_wait_inline(struct adreno_device *adreno_dev,
	void *data, u32 size_bytes, struct pending_cmd *ret_cmd)
{
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);
	struct kgsl_device *device = KGSL_DEVICE(adreno_dev);
	int rc;
	u32 *cmd = data;
	struct gen7_hfi *hfi = &gmu->hfi;
	unsigned int seqnum = atomic_inc_return(&hfi->seqnum);

	*cmd = MSG_HDR_SET_SEQNUM_SIZE(*cmd, seqnum, size_bytes >> 2);

	if (ret_cmd == NULL)
		return gen7_hfi_cmdq_write(adreno_dev, cmd, size_bytes);

	ret_cmd->sent_hdr = cmd[0];

	rc = gen7_hfi_cmdq_write(adreno_dev, cmd, size_bytes);
	if (rc)
		return rc;

	rc = poll_gmu_reg(adreno_dev, GEN7_GMU_GMU2HOST_INTR_INFO,
		HFI_IRQ_MSGQ_MASK, HFI_IRQ_MSGQ_MASK, HFI_RSP_TIMEOUT);

	if (rc) {
		gmu_core_fault_snapshot(device);
		dev_err(&gmu->pdev->dev,
		"Timed out waiting on ack for 0x%8.8x (id %d, sequence %d)\n",
		cmd[0], MSG_HDR_GET_ID(*cmd), MSG_HDR_GET_SEQNUM(*cmd));
		return rc;
	}

	/* Clear the interrupt */
	gmu_core_regwrite(device, GEN7_GMU_GMU2HOST_INTR_CLR,
		HFI_IRQ_MSGQ_MASK);

	rc = gen7_hfi_process_queue(gmu, HFI_MSG_ID, ret_cmd);

	return rc;
}

int gen7_hfi_send_generic_req(struct adreno_device *adreno_dev, void *cmd, u32 size_bytes)
{
	struct pending_cmd ret_cmd;
	int rc;

	memset(&ret_cmd, 0, sizeof(ret_cmd));

	rc = gen7_hfi_send_cmd_wait_inline(adreno_dev, cmd, size_bytes, &ret_cmd);
	if (rc)
		return rc;

	if (ret_cmd.results[2]) {
		struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);
		struct kgsl_device *device = KGSL_DEVICE(adreno_dev);

		gmu_core_fault_snapshot(device);
		dev_err(&gmu->pdev->dev,
				"HFI ACK failure: Req=0x%8.8X, Result=0x%8.8X\n",
				ret_cmd.results[1],
				ret_cmd.results[2]);
		return -EINVAL;
	}

	return 0;
}

int gen7_hfi_send_core_fw_start(struct adreno_device *adreno_dev)
{
	struct hfi_core_fw_start_cmd cmd = {
		.handle = 0x0,
	};
	int ret;

	ret = CMD_MSG_HDR(cmd, H2F_MSG_CORE_FW_START);
	if (ret)
		return ret;

	return gen7_hfi_send_generic_req(adreno_dev, &cmd, sizeof(cmd));
}

static const char *feature_to_string(u32 feature)
{
	if (feature == HFI_FEATURE_ACD)
		return "ACD";
	else if (feature == HFI_FEATURE_LM)
		return "LM";

	return "unknown";
}

/* For sending hfi message inline to handle GMU return type error */
int gen7_hfi_send_generic_req_v5(struct adreno_device *adreno_dev, void *cmd,
		struct pending_cmd *ret_cmd, u32 size_bytes)
{
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);
	int rc;

	if (GMU_VER_MINOR(gmu->ver.hfi) <= 4)
		return gen7_hfi_send_generic_req(adreno_dev, cmd, size_bytes);

	rc = gen7_hfi_send_cmd_wait_inline(adreno_dev, cmd, size_bytes, ret_cmd);
	if (rc)
		return rc;

	switch (ret_cmd->results[3]) {
	case GMU_SUCCESS:
		rc = ret_cmd->results[2];
		break;
	case GMU_ERROR_NO_ENTRY:
		/* Unique error to handle undefined HFI msgs by caller */
		rc = -ENOENT;
		break;
	case GMU_ERROR_TIMEOUT:
		rc = -EINVAL;
		break;
	default:
		gmu_core_fault_snapshot(KGSL_DEVICE(adreno_dev));
		dev_err(&gmu->pdev->dev,
			"HFI ACK: Req=0x%8.8X, Result=0x%8.8X Error:0x%8.8X\n",
			ret_cmd->results[1], ret_cmd->results[2], ret_cmd->results[3]);
		rc = -EINVAL;
		break;
	}

	return rc;
}

int gen7_hfi_send_feature_ctrl(struct adreno_device *adreno_dev,
	u32 feature, u32 enable, u32 data)
{
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);
	struct pending_cmd ret_cmd = {0};
	struct hfi_feature_ctrl_cmd cmd = {
		.feature = feature,
		.enable = enable,
		.data = data,
	};
	int ret;

	ret = CMD_MSG_HDR(cmd, H2F_MSG_FEATURE_CTRL);
	if (ret)
		return ret;

	ret = gen7_hfi_send_generic_req_v5(adreno_dev, &cmd, &ret_cmd, sizeof(cmd));
	if (ret < 0)
		dev_err(&gmu->pdev->dev,
				"Unable to %s feature %s (%d)\n",
				enable ? "enable" : "disable",
				feature_to_string(feature),
				feature);
	return ret;
}

int gen7_hfi_send_get_value(struct adreno_device *adreno_dev, u32 type, u32 subtype)
{
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);
	struct pending_cmd ret_cmd = {0};
	struct hfi_get_value_cmd cmd = {
		.type = type,
		.subtype = subtype,
	};
	int ret;

	ret = CMD_MSG_HDR(cmd, H2F_MSG_GET_VALUE);
	if (ret)
		return ret;

	ret = gen7_hfi_send_generic_req_v5(adreno_dev, &cmd, &ret_cmd, sizeof(cmd));
	if (ret < 0)
		dev_err(&gmu->pdev->dev,
			"Unable to get HFI Value type: %d, subtype: %d, error = %d\n",
			type, subtype, ret);

	return ret;
}

int gen7_hfi_send_set_value(struct adreno_device *adreno_dev,
		u32 type, u32 subtype, u32 data)
{
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);
	struct pending_cmd ret_cmd = {0};
	struct hfi_set_value_cmd cmd = {
		.type = type,
		.subtype = subtype,
		.data = data,
	};
	int ret;

	ret = CMD_MSG_HDR(cmd, H2F_MSG_SET_VALUE);
	if (ret)
		return ret;

	ret = gen7_hfi_send_generic_req_v5(adreno_dev, &cmd, &ret_cmd, sizeof(cmd));
	if (ret < 0)
		dev_err(&gmu->pdev->dev,
			"Unable to set HFI Value %d, %d to %d, error = %d\n",
			type, subtype, data, ret);
	return ret;
}

void adreno_gen7_receive_err_req(struct gen7_gmu_device *gmu, void *rcvd)
{
	struct hfi_err_cmd *cmd = rcvd;

	dev_err(&gmu->pdev->dev, "HFI Error Received: %d %d %.16s\n",
			((cmd->error_code >> 16) & 0xffff),
			(cmd->error_code & 0xffff),
			(char *) cmd->data);
}

void adreno_gen7_receive_debug_req(struct gen7_gmu_device *gmu, void *rcvd)
{
	struct hfi_debug_cmd *cmd = rcvd;

	dev_dbg(&gmu->pdev->dev, "HFI Debug Received: %d %d %d\n",
			cmd->type, cmd->timestamp, cmd->data);
}

int gen7_hfi_process_queue(struct gen7_gmu_device *gmu,
		u32 queue_idx, struct pending_cmd *ret_cmd)
{
	u32 rcvd[MAX_RCVD_SIZE];

	while (gen7_hfi_queue_read(gmu, queue_idx, rcvd, sizeof(rcvd)) > 0) {
		/* ACK Handler */
		if (MSG_HDR_GET_TYPE(rcvd[0]) == HFI_MSG_ACK) {
			int ret = gen7_receive_ack_cmd(gmu, rcvd, ret_cmd);

			if (ret)
				return ret;
			continue;
		}

		/* Request Handler */
		switch (MSG_HDR_GET_ID(rcvd[0])) {
		case F2H_MSG_ERR: /* No Reply */
			adreno_gen7_receive_err_req(gmu, rcvd);
			break;
		case F2H_MSG_DEBUG: /* No Reply */
			adreno_gen7_receive_debug_req(gmu, rcvd);
			break;
		default: /* No Reply */
			dev_err(&gmu->pdev->dev,
				"HFI request %d not supported\n",
				MSG_HDR_GET_ID(rcvd[0]));
			break;
		}
	}

	return 0;
}

int gen7_hfi_send_bcl_feature_ctrl(struct adreno_device *adreno_dev)
{
	if (!adreno_dev->bcl_enabled)
		return 0;

	/*
	 * BCL data is expected by gmu in below format
	 * BIT[0] - response type
	 * BIT[1:7] - Throttle level 1 (optional)
	 * BIT[8:14] - Throttle level 2 (optional)
	 * BIT[15:21] - Throttle level 3 (optional)
	 */
	return gen7_hfi_send_feature_ctrl(adreno_dev, HFI_FEATURE_BCL, 1, adreno_dev->bcl_data);
}

static int gen7_hfi_send_clx_v1_feature_ctrl(struct adreno_device *adreno_dev)
{
	int ret;
	struct hfi_clx_table_v1_cmd cmd = {0};

	/* Make sure the table is valid before enabling feature */
	ret = CMD_MSG_HDR(cmd, H2F_MSG_CLX_TBL);
	if (ret)
		return ret;

	ret = gen7_hfi_send_feature_ctrl(adreno_dev, HFI_FEATURE_CLX, 1, 0);
	if (ret)
		return ret;

	/* GMU supports HW CLX V2 only with both HFI V1 and V2 data formats */
	cmd.data0 = FIELD_PREP(GENMASK(31, 16), 0x2) | FIELD_PREP(GENMASK(15, 0), 0x1);
	cmd.data1 = FIELD_PREP(GENMASK(31, 29), 1) |
				FIELD_PREP(GENMASK(28, 28), 1) |
				FIELD_PREP(GENMASK(27, 22), 1) |
				FIELD_PREP(GENMASK(21, 16), 40) |
				FIELD_PREP(GENMASK(15, 0), 0);
	cmd.clxt = 0;
	cmd.clxh = 0;
	cmd.urgmode = 1;
	cmd.lkgen = 0;

	return gen7_hfi_send_generic_req(adreno_dev, &cmd, sizeof(cmd));
}

static int gen7_hfi_send_clx_v2_feature_ctrl(struct adreno_device *adreno_dev)
{
	int ret = 0;
	struct hfi_clx_table_v2_cmd cmd = {0};

	/* Make sure the table is valid before enabling feature */
	ret = CMD_MSG_HDR(cmd, H2F_MSG_CLX_TBL);
	if (ret)
		return ret;

	ret = gen7_hfi_send_feature_ctrl(adreno_dev, HFI_FEATURE_CLX, 1, 0);
	if (ret)
		return ret;

	cmd.version = FIELD_PREP(GENMASK(31, 16), 0x2) | FIELD_PREP(GENMASK(15, 0), 0x1);
	/* cmd.domain[0] is never used but needed per hfi spec */
	cmd.domain[1].data0 = FIELD_PREP(GENMASK(31, 29), 1) |
				FIELD_PREP(GENMASK(28, 28), 1) |
				FIELD_PREP(GENMASK(27, 22), 1) |
				FIELD_PREP(GENMASK(21, 16), 40) |
				FIELD_PREP(GENMASK(15, 0), 0);
	cmd.domain[1].clxt = 0;
	cmd.domain[1].clxh = 0;
	cmd.domain[1].urgmode = 1;
	cmd.domain[1].lkgen = 0;
	cmd.domain[1].currbudget = 50;

	return gen7_hfi_send_generic_req(adreno_dev, &cmd, sizeof(cmd));
}

int gen7_hfi_send_clx_feature_ctrl(struct adreno_device *adreno_dev)
{
	if (!adreno_dev->clx_enabled)
		return 0;

	/* gen7_11_0 GPU uses HFI CLX data version 1 */
	if (adreno_is_gen7_11_0(adreno_dev))
		return gen7_hfi_send_clx_v1_feature_ctrl(adreno_dev);

	return gen7_hfi_send_clx_v2_feature_ctrl(adreno_dev);
}

#define EVENT_PWR_ACD_THROTTLE_PROF 44

int gen7_hfi_send_acd_feature_ctrl(struct adreno_device *adreno_dev)
{
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);
	int ret = 0;

	if (adreno_dev->acd_enabled) {
		ret = gen7_hfi_send_feature_ctrl(adreno_dev,
			HFI_FEATURE_ACD, 1, 0);
		if (ret)
			return ret;

		ret = gen7_hfi_send_generic_req(adreno_dev,
				&gmu->hfi.acd_table, sizeof(gmu->hfi.acd_table));
		if (ret)
			return ret;

		gen7_hfi_send_set_value(adreno_dev, HFI_VALUE_LOG_EVENT_ON,
				EVENT_PWR_ACD_THROTTLE_PROF, 0);
	}

	return 0;
}

int gen7_hfi_send_ifpc_feature_ctrl(struct adreno_device *adreno_dev)
{
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);

	if (gmu->idle_level == GPU_HW_IFPC)
		return gen7_hfi_send_feature_ctrl(adreno_dev,
				HFI_FEATURE_IFPC, 1, adreno_dev->ifpc_hyst);
	return 0;
}

static void reset_hfi_queues(struct adreno_device *adreno_dev)
{
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);
	struct kgsl_memdesc *mem_addr = gmu->hfi.hfi_mem;
	struct hfi_queue_table *tbl = mem_addr->hostptr;
	struct hfi_queue_header *hdr;
	unsigned int i;

	/* Flush HFI queues */
	for (i = 0; i < HFI_QUEUE_MAX; i++) {
		hdr = &tbl->qhdr[i];
		if (hdr->status == HFI_QUEUE_STATUS_DISABLED)
			continue;

		hdr->read_index = hdr->write_index;
	}
}

/* Fill the entry and return the dword count written */
static u32 _fill_table_entry(struct hfi_table_entry *entry, u32 count,
		u32 stride_bytes, u32 *data)
{
	entry->count = count;
	entry->stride = stride_bytes >> 2; /* entry->stride is in dwords */
	memcpy(entry->data, data, stride_bytes * count);

	/* Return total dword count of entry + data */
	return (sizeof(*entry) >> 2) + (entry->count * entry->stride);
}

int gen7_hfi_send_gpu_perf_table(struct adreno_device *adreno_dev)
{
	/*
	 * Buffer to store either hfi_table_cmd or hfi_dcvstable_cmd.
	 * Current max size for either is 165 dwords.
	 */
	static u32 cmd_buf[200];
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);
	struct gen7_dcvs_table *tbl = &gmu->dcvs_table;
	int ret = 0;

	/* Starting with GMU HFI Version 2.6.1, use H2F_MSG_TABLE */
	if (gmu->ver.hfi >= HFI_VERSION(2, 6, 1)) {
		struct hfi_table_cmd *cmd = (struct hfi_table_cmd *)&cmd_buf[0];
		u32 dword_off;

		/* Already setup, so just send cmd */
		if (cmd->hdr)
			return gen7_hfi_send_generic_req(adreno_dev, cmd,
					MSG_HDR_GET_SIZE(cmd->hdr) << 2);

		if (tbl->gpu_level_num > MAX_GX_LEVELS || tbl->gmu_level_num > MAX_CX_LEVELS)
			return -EINVAL;

		/* CMD starts with struct hfi_table_cmd data */
		cmd->type = HFI_TABLE_GPU_PERF;
		dword_off = sizeof(*cmd) >> 2;

		/* Fill in the table entry and data starting at dword_off */
		dword_off += _fill_table_entry((struct hfi_table_entry *)&cmd_buf[dword_off],
				tbl->gpu_level_num, sizeof(struct opp_gx_desc),
				(u32 *)tbl->gx_votes);

		/* Fill in the table entry and data starting at dword_off */
		dword_off += _fill_table_entry((struct hfi_table_entry *)&cmd_buf[dword_off],
				tbl->gmu_level_num, sizeof(struct opp_desc),
				(u32 *)tbl->cx_votes);

		cmd->hdr = CREATE_MSG_HDR(H2F_MSG_TABLE, HFI_MSG_CMD);
		cmd->hdr = MSG_HDR_SET_SIZE(cmd->hdr, dword_off);

		ret = gen7_hfi_send_generic_req(adreno_dev, cmd, dword_off << 2);
	} else {
		struct hfi_dcvstable_cmd *cmd = (struct hfi_dcvstable_cmd *)&cmd_buf[0];

		/* Already setup, so just send cmd */
		if (cmd->hdr)
			return gen7_hfi_send_generic_req(adreno_dev, cmd, sizeof(*cmd));

		if (tbl->gpu_level_num > MAX_GX_LEVELS_LEGACY || tbl->gmu_level_num > MAX_CX_LEVELS)
			return -EINVAL;

		ret = CMD_MSG_HDR(*cmd, H2F_MSG_PERF_TBL);
		if (ret)
			return ret;

		cmd->gpu_level_num = tbl->gpu_level_num;
		cmd->gmu_level_num = tbl->gmu_level_num;
		memcpy(&cmd->gx_votes, tbl->gx_votes,
				sizeof(struct opp_gx_desc) * cmd->gpu_level_num);
		memcpy(&cmd->cx_votes, tbl->cx_votes,
				sizeof(struct opp_desc) * cmd->gmu_level_num);

		ret = gen7_hfi_send_generic_req(adreno_dev, cmd, sizeof(*cmd));
	}

	return ret;
}

int gen7_hfi_start(struct adreno_device *adreno_dev)
{
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);
	struct kgsl_device *device = KGSL_DEVICE(adreno_dev);
	int result;

	reset_hfi_queues(adreno_dev);

	result = gen7_hfi_send_gpu_perf_table(adreno_dev);
	if (result)
		goto err;

	result = gen7_hfi_send_generic_req(adreno_dev, &gmu->hfi.bw_table,
			sizeof(gmu->hfi.bw_table));
	if (result)
		goto err;

	result = gen7_hfi_send_acd_feature_ctrl(adreno_dev);
	if (result)
		goto err;

	result = gen7_hfi_send_bcl_feature_ctrl(adreno_dev);
	if (result)
		goto err;

	result = gen7_hfi_send_clx_feature_ctrl(adreno_dev);
	if (result)
		goto err;

	result = gen7_hfi_send_ifpc_feature_ctrl(adreno_dev);
	if (result)
		goto err;

	result = gen7_hfi_send_core_fw_start(adreno_dev);
	if (result)
		goto err;

	set_bit(GMU_PRIV_HFI_STARTED, &gmu->flags);

	/* Request default DCVS level */
	result = kgsl_pwrctrl_set_default_gpu_pwrlevel(device);
	if (result)
		goto err;

	/* Request default BW vote */
	result = kgsl_pwrctrl_axi(device, true);

err:
	if (result)
		gen7_hfi_stop(adreno_dev);

	return result;

}

void gen7_hfi_stop(struct adreno_device *adreno_dev)
{
	struct gen7_gmu_device *gmu = to_gen7_gmu(adreno_dev);
	struct kgsl_device *device = KGSL_DEVICE(adreno_dev);

	kgsl_pwrctrl_axi(device, false);

	clear_bit(GMU_PRIV_HFI_STARTED, &gmu->flags);
}

/* HFI interrupt handler */
irqreturn_t gen7_hfi_irq_handler(int irq, void *data)
{
	struct kgsl_device *device = data;
	struct gen7_gmu_device *gmu = to_gen7_gmu(ADRENO_DEVICE(device));
	unsigned int status = 0;

	gmu_core_regread(device, GEN7_GMU_GMU2HOST_INTR_INFO, &status);
	gmu_core_regwrite(device, GEN7_GMU_GMU2HOST_INTR_CLR, HFI_IRQ_MASK);

	if (status & HFI_IRQ_DBGQ_MASK)
		gen7_hfi_process_queue(gmu, HFI_DBG_ID, NULL);
	if (status & HFI_IRQ_CM3_FAULT_MASK) {
		dev_err_ratelimited(&gmu->pdev->dev,
				"GMU CM3 fault interrupt received\n");
		atomic_set(&gmu->cm3_fault, 1);

		/* make sure other CPUs see the update */
		smp_wmb();
	}
	if (status & ~HFI_IRQ_MASK)
		dev_err_ratelimited(&gmu->pdev->dev,
				"Unhandled HFI interrupts 0x%lx\n",
				status & ~HFI_IRQ_MASK);

	return IRQ_HANDLED;
}
