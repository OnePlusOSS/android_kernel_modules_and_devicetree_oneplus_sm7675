// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2017-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2023, Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/module.h>
#include "cam_cci_core.h"
#include "cam_cci_dev.h"
#include "cam_req_mgr_workq.h"
#include "cam_common_util.h"
#define DUMP_CCI_REGISTERS
#ifdef OPLUS_FEATURE_CAMERA_COMMON
//#define DUMP_CCI_REGISTERS 1
#include "cam_cci_ctrl_interface.h"
#endif

static int32_t cam_cci_convert_type_to_num_bytes(
	enum camera_sensor_i2c_type type)
{
	int32_t num_bytes;

	switch (type) {
	case CAMERA_SENSOR_I2C_TYPE_BYTE:
		num_bytes = 1;
		break;
	case CAMERA_SENSOR_I2C_TYPE_WORD:
		num_bytes = 2;
		break;
	case CAMERA_SENSOR_I2C_TYPE_3B:
		num_bytes = 3;
		break;
	case CAMERA_SENSOR_I2C_TYPE_DWORD:
		num_bytes = 4;
		break;
	default:
		CAM_ERR(CAM_CCI, "Wrong Sensor I2c Type: %d", type);
		num_bytes = 0;
		break;
	}
	return num_bytes;
}

static void cam_cci_flush_queue(struct cci_device *cci_dev,
	enum cci_i2c_master_t master)
{
	int32_t rc = 0;
	struct cam_hw_soc_info *soc_info =
		&cci_dev->soc_info;
	void __iomem *base = soc_info->reg_map[0].mem_base;

	cam_io_w_mb(1 << master, base + CCI_HALT_REQ_ADDR);
	if (!cci_dev->cci_master_info[master].status)
		reinit_completion(&cci_dev->cci_master_info[master]
			.reset_complete);
	if (!cam_common_wait_for_completion_timeout(
		&cci_dev->cci_master_info[master].reset_complete,
		CCI_TIMEOUT)) {
		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d wait timeout for reset complete",
			cci_dev->soc_info.index, master);

		/* Set reset pending flag to true */
		cci_dev->cci_master_info[master].reset_pending = true;
		cci_dev->cci_master_info[master].status = 0;

		/* Set proper mask to RESET CMD address based on MASTER */
		if (master == MASTER_0)
			cam_io_w_mb(CCI_M0_RESET_RMSK,
				base + CCI_RESET_CMD_ADDR);
		else
			cam_io_w_mb(CCI_M1_RESET_RMSK,
				base + CCI_RESET_CMD_ADDR);

		/* wait for reset done irq */
		if (!cam_common_wait_for_completion_timeout(
			&cci_dev->cci_master_info[master].reset_complete,
			CCI_TIMEOUT)) {
			rc = -EINVAL;
			CAM_ERR(CAM_CCI,
				"CCI%d_I2C_M%d Retry:: wait timeout for reset complete",
				cci_dev->soc_info.index, master);
		}
		cci_dev->cci_master_info[master].status = 0;
	}

	if (!rc)
		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d Success: Reset complete",
			cci_dev->soc_info.index, master);
}

static int32_t cam_cci_validate_queue(struct cci_device *cci_dev,
	uint32_t len,
	enum cci_i2c_master_t master,
	enum cci_i2c_queue_t queue)
{
	int32_t rc = 0;
	uint32_t read_val = 0;
	uint32_t reg_offset = master * 0x200 + queue * 0x100;
	struct cam_hw_soc_info *soc_info =
		&cci_dev->soc_info;
	void __iomem *base = soc_info->reg_map[0].mem_base;
	unsigned long flags;

	read_val = cam_io_r_mb(base +
		CCI_I2C_M0_Q0_CUR_WORD_CNT_ADDR + reg_offset);
	CAM_DBG(CAM_CCI,
		"CCI%d_I2C_M%d_Q%d_CUR_WORD_CNT_ADDR %d len %d max %d",
		cci_dev->soc_info.index, master, queue, read_val, len,
		cci_dev->cci_i2c_queue_info[master][queue].max_queue_size);
	if ((read_val + len + 1) >
		cci_dev->cci_i2c_queue_info[master][queue].max_queue_size) {
		uint32_t reg_val = 0;
		uint32_t report_id =
			cci_dev->cci_i2c_queue_info[master][queue].report_id;
		uint32_t report_val = CCI_I2C_REPORT_CMD | (1 << 8) |
			(1 << 9) | (report_id << 4);

		CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d_REPORT_CMD",
			cci_dev->soc_info.index, master, queue);
		cam_io_w_mb(report_val,
			base + CCI_I2C_M0_Q0_LOAD_DATA_ADDR +
			reg_offset);
		read_val++;
		cci_dev->cci_i2c_queue_info[master][queue].report_id++;
		if (cci_dev->cci_i2c_queue_info[master][queue].report_id == REPORT_IDSIZE)
			cci_dev->cci_i2c_queue_info[master][queue].report_id = 0;

		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d_EXEC_WORD_CNT_ADDR %d",
			cci_dev->soc_info.index, master, queue, read_val);
		cam_io_w_mb(read_val, base +
			CCI_I2C_M0_Q0_EXEC_WORD_CNT_ADDR + reg_offset);
		reg_val = 1 << ((master * 2) + queue);
		CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d_START_ADDR", cci_dev->soc_info.index, master, queue);
		spin_lock_irqsave(
			&cci_dev->cci_master_info[master].lock_q[queue], flags);
		atomic_set(
			&cci_dev->cci_master_info[master].done_pending[queue],
			1);
		cam_io_w_mb(reg_val, base + CCI_QUEUE_START_ADDR);
		atomic_set(&cci_dev->cci_master_info[master].q_free[queue], 1);
		spin_unlock_irqrestore(
			&cci_dev->cci_master_info[master].lock_q[queue], flags);
		if (!cam_common_wait_for_completion_timeout(
			&cci_dev->cci_master_info[master].report_q[queue],
			CCI_TIMEOUT)) {
			CAM_ERR(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d wait timeout, rc:%d",
				cci_dev->soc_info.index, master, queue, rc);
			cam_cci_flush_queue(cci_dev, master);
			return -EINVAL;
		}
		rc = cci_dev->cci_master_info[master].status;
		if (rc < 0) {
			CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d is in error state",
				cci_dev->soc_info.index, master, queue);
			cci_dev->cci_master_info[master].status = 0;
		}
	}

	return rc;
}

static int32_t cam_cci_write_i2c_queue(struct cci_device *cci_dev,
	uint32_t val,
	enum cci_i2c_master_t master,
	enum cci_i2c_queue_t queue)
{
	int32_t rc = 0;
	uint32_t reg_offset = master * 0x200 + queue * 0x100;
	struct cam_hw_soc_info *soc_info = NULL;
	void __iomem *base = NULL;

	if (!cci_dev) {
		CAM_ERR(CAM_CCI, "cci_dev NULL");
		return -EINVAL;
	}

	soc_info = &cci_dev->soc_info;
	base = soc_info->reg_map[0].mem_base;

	rc = cam_cci_validate_queue(cci_dev, 1, master, queue);
	if (rc < 0) {
		CAM_ERR(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d Failed to validate:: rc: %d",
			cci_dev->soc_info.index, master, queue, rc);
		return rc;
	}
	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d_LOAD_DATA_ADDR:val 0x%x:0x%x ",
		cci_dev->soc_info.index, master, queue,
		CCI_I2C_M0_Q0_LOAD_DATA_ADDR +
		reg_offset, val);
	cam_io_w_mb(val, base + CCI_I2C_M0_Q0_LOAD_DATA_ADDR +
		reg_offset);

	return rc;
}

static void cam_cci_lock_queue(struct cci_device *cci_dev,
	enum cci_i2c_master_t master,
	enum cci_i2c_queue_t queue, uint32_t en)
{
	uint32_t                val = 0;
	uint32_t                read_val = 0;
	struct cam_hw_soc_info *soc_info =
		&cci_dev->soc_info;
	void __iomem           *base =
		soc_info->reg_map[0].mem_base;
	uint32_t                reg_offset =
		master * 0x200 + queue * 0x100;

	if (queue != PRIORITY_QUEUE)
		return;

	val = en ? CCI_I2C_LOCK_CMD : CCI_I2C_UNLOCK_CMD;

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d_LOAD_DATA_ADDR:val 0x%x:0x%x ",
		cci_dev->soc_info.index, master, queue,
		CCI_I2C_M0_Q0_LOAD_DATA_ADDR +
		reg_offset, val);
	cam_io_w_mb(val, base + CCI_I2C_M0_Q0_LOAD_DATA_ADDR +
		reg_offset);

	if (cci_dev->cci_master_info[master].is_burst_enable[queue] == true) {
		cci_dev->cci_master_info[master].num_words_exec[queue]++;
		read_val = cci_dev->cci_master_info[master].num_words_exec[queue];
	} else {
		read_val = cam_io_r_mb(base +
			CCI_I2C_M0_Q0_CUR_WORD_CNT_ADDR + reg_offset);
	}

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d_EXEC_WORD_CNT_ADDR %d",
		cci_dev->soc_info.index, master, queue, read_val);
	cam_io_w_mb(read_val, base +
		CCI_I2C_M0_Q0_EXEC_WORD_CNT_ADDR + reg_offset);
}

void cam_cci_dump_registers(struct cci_device *cci_dev,
	enum cci_i2c_master_t master, enum cci_i2c_queue_t queue)
{
	uint32_t dump_en = 0;
	uint32_t read_val = 0;
	uint32_t i = 0;
	uint32_t reg_offset = 0;
	void __iomem *base = cci_dev->soc_info.reg_map[0].mem_base;

	dump_en = cci_dev->dump_en;
	if (!(dump_en & CAM_CCI_NACK_DUMP_EN) &&
		!(dump_en & CAM_CCI_TIMEOUT_DUMP_EN)) {
		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d Nack and Timeout dump is not enabled",
			cci_dev->soc_info.index, master, queue);
		return;
	}

	CAM_INFO(CAM_CCI, "**** CCI%d_I2C_M%d_Q%d register dump ****",
		cci_dev->soc_info.index, master, queue);

	/* CCI Top Registers */
	CAM_INFO(CAM_CCI, "**** CCI TOP Registers ****");
	for (i = 0; i < DEBUG_TOP_REG_COUNT; i++) {
		reg_offset = DEBUG_TOP_REG_START + i * 4;
		read_val = cam_io_r_mb(base + reg_offset);
		CAM_INFO(CAM_CCI, "offset = 0x%X value = 0x%X",
			reg_offset, read_val);
	}

	/* CCI Master registers */
	CAM_INFO(CAM_CCI, "**** CCI%d_I2C_M%d Registers ****",
		cci_dev->soc_info.index, master);
	for (i = 0; i < DEBUG_MASTER_REG_COUNT; i++) {
		if ((i * 4) == 0x18)
			continue;

		reg_offset = DEBUG_MASTER_REG_START + master*0x100 + i * 4;
		read_val = cam_io_r_mb(base + reg_offset);
		CAM_INFO(CAM_CCI, "offset = 0x%X value = 0x%X",
			reg_offset, read_val);
	}

	/* CCI Master Queue registers */
	CAM_INFO(CAM_CCI, " **** CCI%d_I2C_M%d_Q%d Registers ****",
		cci_dev->soc_info.index, master, queue);
	for (i = 0; i < DEBUG_MASTER_QUEUE_REG_COUNT; i++) {
		reg_offset = DEBUG_MASTER_QUEUE_REG_START +  master*0x200 +
			queue*0x100 + i * 4;
		read_val = cam_io_r_mb(base + reg_offset);
		CAM_INFO(CAM_CCI, "offset = 0x%X value = 0x%X",
			reg_offset, read_val);
	}

	/* CCI Interrupt registers */
	CAM_INFO(CAM_CCI, " ****CCI Interrupt Registers****");
	for (i = 0; i < DEBUG_INTR_REG_COUNT; i++) {
		reg_offset = DEBUG_INTR_REG_START + i * 4;
		read_val = cam_io_r_mb(base + reg_offset);
		CAM_INFO(CAM_CCI, "offset = 0x%X value = 0x%X",
			reg_offset, read_val);
	}
}
EXPORT_SYMBOL(cam_cci_dump_registers);

static uint32_t cam_cci_wait(struct cci_device *cci_dev,
	enum cci_i2c_master_t master,
	enum cci_i2c_queue_t queue)
{
	int32_t rc = 0;

	if (!cci_dev) {
		CAM_ERR(CAM_CCI, "cci_dev pointer is NULL");
		return -EINVAL;
	}

	if (!cam_common_wait_for_completion_timeout(
		&cci_dev->cci_master_info[master].report_q[queue],
		CCI_TIMEOUT)) {
		cam_cci_dump_registers(cci_dev, master, queue);

		CAM_ERR(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d wait timeout, rc: %d",
			cci_dev->soc_info.index, master, queue, rc);
		rc = -ETIMEDOUT;
		cam_cci_flush_queue(cci_dev, master);
		CAM_INFO(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d dump register after reset",
			cci_dev->soc_info.index, master, queue);
		cam_cci_dump_registers(cci_dev, master, queue);
		return rc;
	}

	rc = cci_dev->cci_master_info[master].status;
	if (rc < 0) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q% is in error state",
			cci_dev->soc_info.index, master, queue);
		cci_dev->cci_master_info[master].status = 0;
		return rc;
	}

	return 0;
}

static void cam_cci_load_report_cmd(struct cci_device *cci_dev,
	enum cci_i2c_master_t master,
	enum cci_i2c_queue_t queue)
{
	struct cam_hw_soc_info *soc_info =
		&cci_dev->soc_info;
	void __iomem *base = soc_info->reg_map[0].mem_base;

	uint32_t reg_offset = master * 0x200 + queue * 0x100;
	uint32_t read_val = cam_io_r_mb(base +
		CCI_I2C_M0_Q0_CUR_WORD_CNT_ADDR + reg_offset);
	uint32_t report_id =
		cci_dev->cci_i2c_queue_info[master][queue].report_id;
	uint32_t report_val = CCI_I2C_REPORT_CMD | (1 << 8) |
		(1 << 9) | (report_id << 4);

	CAM_DBG(CAM_CCI,
		"CCI%d_I2C_M%d_Q%d_REPORT_CMD curr_w_cnt: %d report_id %d",
		cci_dev->soc_info.index, master, queue, read_val, report_id);
	cam_io_w_mb(report_val,
		base + CCI_I2C_M0_Q0_LOAD_DATA_ADDR +
		reg_offset);
	if (cci_dev->cci_master_info[master].is_burst_enable[queue] == true) {
		cci_dev->cci_master_info[master].num_words_exec[queue]++;
		read_val = cci_dev->cci_master_info[master].num_words_exec[queue];
	} else {
		read_val++;
	}
	cci_dev->cci_i2c_queue_info[master][queue].report_id++;
	if (cci_dev->cci_i2c_queue_info[master][queue].report_id == REPORT_IDSIZE)
		cci_dev->cci_i2c_queue_info[master][queue].report_id = 0;

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d_EXEC_WORD_CNT_ADDR %d (ReadValue: %u)",
		cci_dev->soc_info.index, master, queue, read_val,
		cam_io_r_mb(base + CCI_I2C_M0_Q0_EXEC_WORD_CNT_ADDR + reg_offset));
	cam_io_w_mb(read_val, base +
		CCI_I2C_M0_Q0_EXEC_WORD_CNT_ADDR + reg_offset);
}

static int32_t cam_cci_wait_report_cmd(struct cci_device *cci_dev,
	enum cci_i2c_master_t master,
	enum cci_i2c_queue_t queue)
{
	unsigned long flags;
	struct cam_hw_soc_info *soc_info =
		&cci_dev->soc_info;
	void __iomem *base = soc_info->reg_map[0].mem_base;

	uint32_t reg_val = 1 << ((master * 2) + queue);

	spin_lock_irqsave(
		&cci_dev->cci_master_info[master].lock_q[queue], flags);
	atomic_set(&cci_dev->cci_master_info[master].q_free[queue], 1);
	atomic_set(&cci_dev->cci_master_info[master].done_pending[queue], 1);
	spin_unlock_irqrestore(
		&cci_dev->cci_master_info[master].lock_q[queue], flags);
	cam_io_w_mb(reg_val, base + CCI_QUEUE_START_ADDR);

	return cam_cci_wait(cci_dev, master, queue);
}

static int32_t cam_cci_transfer_end(struct cci_device *cci_dev,
	enum cci_i2c_master_t master,
	enum cci_i2c_queue_t queue)
{
	int32_t rc = 0;
	unsigned long flags;

	spin_lock_irqsave(
		&cci_dev->cci_master_info[master].lock_q[queue], flags);
	if (atomic_read(&cci_dev->cci_master_info[master].q_free[queue]) == 0) {
		spin_unlock_irqrestore(
			&cci_dev->cci_master_info[master].lock_q[queue], flags);
		cam_cci_load_report_cmd(cci_dev, master, queue);
		cam_cci_lock_queue(cci_dev, master, queue, 0);

		rc = cam_cci_wait_report_cmd(cci_dev, master, queue);
		if (rc < 0) {
			CAM_ERR(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d Failed for wait_report_cmd for rc: %d",
				cci_dev->soc_info.index, master, queue, rc);
			return rc;
		}
	} else {
		atomic_set(
			&cci_dev->cci_master_info[master].done_pending[queue],
			1);
		spin_unlock_irqrestore(
			&cci_dev->cci_master_info[master].lock_q[queue], flags);
		rc = cam_cci_wait(cci_dev, master, queue);
		if (rc < 0) {
			CAM_ERR(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d Failed with cci_wait for rc: %d",
				cci_dev->soc_info.index, master, queue, rc);
			return rc;
		}
		cam_cci_load_report_cmd(cci_dev, master, queue);
		cam_cci_lock_queue(cci_dev, master, queue, 0);

		rc = cam_cci_wait_report_cmd(cci_dev, master, queue);
		if (rc < 0) {
			CAM_ERR(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d Failed in wait_report_cmd for rc: %d",
				cci_dev->soc_info.index, master, queue, rc);
			return rc;
		}
	}

	return rc;
}

static int32_t cam_cci_get_queue_free_size(struct cci_device *cci_dev,
	enum cci_i2c_master_t master,
	enum cci_i2c_queue_t queue)
{
	uint32_t read_val = 0;
	uint32_t reg_offset = master * 0x200 + queue * 0x100;
	struct cam_hw_soc_info *soc_info =
		&cci_dev->soc_info;
	void __iomem *base = soc_info->reg_map[0].mem_base;

	read_val = cam_io_r_mb(base +
		CCI_I2C_M0_Q0_CUR_WORD_CNT_ADDR + reg_offset);
	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d_CUR_WORD_CNT_ADDR %d max %d",
		cci_dev->soc_info.index, master, queue, read_val,
		cci_dev->cci_i2c_queue_info[master][queue].max_queue_size);
	return ((cci_dev->cci_i2c_queue_info[master][queue].max_queue_size) -
			read_val);
}

static void cam_cci_process_half_q(struct cci_device *cci_dev,
	enum cci_i2c_master_t master,
	enum cci_i2c_queue_t queue)
{
	unsigned long flags;
	struct cam_hw_soc_info *soc_info =
		&cci_dev->soc_info;
	void __iomem *base = soc_info->reg_map[0].mem_base;
	uint32_t reg_val = 1 << ((master * 2) + queue);

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d ENTER", cci_dev->soc_info.index, master, queue);

	spin_lock_irqsave(&cci_dev->cci_master_info[master].lock_q[queue],
		flags);
	if (atomic_read(&cci_dev->cci_master_info[master].q_free[queue]) == 0) {
		CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d is free", cci_dev->soc_info.index, master, queue);
		cam_cci_load_report_cmd(cci_dev, master, queue);
		atomic_set(&cci_dev->cci_master_info[master].q_free[queue], 1);
		cam_io_w_mb(reg_val, base +
			CCI_QUEUE_START_ADDR);
	}
	spin_unlock_irqrestore(&cci_dev->cci_master_info[master].lock_q[queue],
		flags);
}

static int32_t cam_cci_process_full_q(struct cci_device *cci_dev,
	enum cci_i2c_master_t master,
	enum cci_i2c_queue_t queue)
{
	int32_t rc = 0;
	unsigned long flags;

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d ENTER", cci_dev->soc_info.index, master, queue);
	spin_lock_irqsave(&cci_dev->cci_master_info[master].lock_q[queue],
		flags);
	if (atomic_read(&cci_dev->cci_master_info[master].q_free[queue]) == 1) {
		atomic_set(
			&cci_dev->cci_master_info[master].done_pending[queue],
			1);
		spin_unlock_irqrestore(
			&cci_dev->cci_master_info[master].lock_q[queue], flags);
		CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d is set to 1", cci_dev->soc_info.index, master, queue);
		rc = cam_cci_wait(cci_dev, master, queue);
		if (rc < 0) {
			CAM_ERR(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d cci_wait failed for rc: %d",
				cci_dev->soc_info.index, master, queue, rc);
			return rc;
		}
	} else {
		spin_unlock_irqrestore(
			&cci_dev->cci_master_info[master].lock_q[queue], flags);
		CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d is set to 0", cci_dev->soc_info.index, master, queue);
		cam_cci_load_report_cmd(cci_dev, master, queue);
		rc = cam_cci_wait_report_cmd(cci_dev, master, queue);
		if (rc < 0) {
			CAM_ERR(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d Failed in wait_report for rc: %d",
				cci_dev->soc_info.index, master, queue, rc);
			return rc;
		}
	}

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d EXIT", cci_dev->soc_info.index, master, queue);

	return rc;
}

static int32_t cam_cci_calc_cmd_len(struct cci_device *cci_dev,
	struct cam_cci_ctrl *c_ctrl, uint32_t cmd_size,
	 struct cam_sensor_i2c_reg_array *i2c_cmd, uint32_t *pack)
{
	uint8_t i;
	uint32_t len = 0;
	uint8_t data_len = 0, addr_len = 0;
	uint8_t pack_max_len;
	struct cam_sensor_i2c_reg_setting *msg;
	struct cam_sensor_i2c_reg_array *cmd = i2c_cmd;
	uint32_t size = cmd_size;

	if (!cci_dev || !c_ctrl) {
		CAM_ERR(CAM_CCI, "Invalid arguments cci_dev:%p, c_ctrl:%p",
			cci_dev, c_ctrl);
		return -EINVAL;
	}

	msg = &c_ctrl->cfg.cci_i2c_write_cfg;
	*pack = 0;

	if (c_ctrl->cmd == MSM_CCI_I2C_WRITE_SEQ ||
		c_ctrl->cmd == MSM_CCI_I2C_WRITE_BURST) {
		addr_len = cam_cci_convert_type_to_num_bytes(msg->addr_type);
		len = (size + addr_len) <= (cci_dev->payload_size) ?
			(size + addr_len):cci_dev->payload_size;
	} else {
		addr_len = cam_cci_convert_type_to_num_bytes(msg->addr_type);
		data_len = cam_cci_convert_type_to_num_bytes(msg->data_type);
		len = data_len + addr_len;
		pack_max_len = size < (cci_dev->payload_size-len) ?
			size : (cci_dev->payload_size-len);
		for (i = 0; i < pack_max_len;) {
			if (cmd->delay || ((cmd - i2c_cmd) >= (cmd_size - 1)))
				break;
			if (cmd->reg_addr + 1 ==
				(cmd+1)->reg_addr) {
				len += data_len;
				if (len > cci_dev->payload_size) {
					len = len - data_len;
					break;
				}
				(*pack)++;
			} else {
				break;
			}
			i += data_len;
			cmd++;
		}
	}

	if (len > cci_dev->payload_size) {
		CAM_ERR(CAM_CCI, "Len error: len: %u expected_len: %u",
			len, cci_dev->payload_size);
		return -EINVAL;
	}

	len += 1; /*add i2c WR command*/
	len = len/4 + 1;

	return len;
}

static uint32_t cam_cci_cycles_per_ms(unsigned long clk)
{
	uint32_t cycles_per_us;

	if (clk) {
		cycles_per_us = ((clk/1000)*256)/1000;
	} else {
		CAM_ERR(CAM_CCI, "Failed: Can use default: %d",
			CYCLES_PER_MICRO_SEC_DEFAULT);
		cycles_per_us = CYCLES_PER_MICRO_SEC_DEFAULT;
	}

	return cycles_per_us;
}

void cam_cci_get_clk_rates(struct cci_device *cci_dev,
	struct cam_cci_ctrl *c_ctrl)

{
	int32_t src_clk_idx, j;
	uint32_t cci_clk_src;
	unsigned long clk;
	struct cam_cci_clk_params_t *clk_params = NULL;

	enum i2c_freq_mode i2c_freq_mode = c_ctrl->cci_info->i2c_freq_mode;
	struct cam_hw_soc_info *soc_info = &cci_dev->soc_info;

	if (i2c_freq_mode >= I2C_MAX_MODES ||
		i2c_freq_mode < I2C_STANDARD_MODE) {
		CAM_ERR(CAM_CCI, "Invalid frequency mode: %d",
			(int32_t)i2c_freq_mode);
		cci_dev->clk_level_index = -1;
		return;
	}

	clk_params = &cci_dev->cci_clk_params[i2c_freq_mode];
	cci_clk_src = clk_params->cci_clk_src;

	src_clk_idx = soc_info->src_clk_idx;

	if (src_clk_idx < 0) {
		cci_dev->cycles_per_us = CYCLES_PER_MICRO_SEC_DEFAULT;
		cci_dev->clk_level_index = 0;
		return;
	}

	if (cci_clk_src == 0) {
		clk = soc_info->clk_rate[0][src_clk_idx];
		cci_dev->cycles_per_us = cam_cci_cycles_per_ms(clk);
		cci_dev->clk_level_index = 0;
		return;
	}

	for (j = 0; j < CAM_MAX_VOTE; j++) {
		clk = soc_info->clk_rate[j][src_clk_idx];
		if (clk == cci_clk_src) {
			cci_dev->cycles_per_us = cam_cci_cycles_per_ms(clk);
			cci_dev->clk_level_index = j;
			return;
		}
	}
}

static int32_t cam_cci_set_clk_param(struct cci_device *cci_dev,
	struct cam_cci_ctrl *c_ctrl)
{
	struct cam_cci_clk_params_t *clk_params = NULL;
	enum cci_i2c_master_t master = c_ctrl->cci_info->cci_i2c_master;
	enum i2c_freq_mode i2c_freq_mode = c_ctrl->cci_info->i2c_freq_mode;
	void __iomem *base = cci_dev->soc_info.reg_map[0].mem_base;
	struct cam_cci_master_info *cci_master =
		&cci_dev->cci_master_info[master];

	if ((i2c_freq_mode >= I2C_MAX_MODES) || (i2c_freq_mode < 0)) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d invalid i2c_freq_mode = %d",
			cci_dev->soc_info.index, master, i2c_freq_mode);
		return -EINVAL;
	}
	/*
	 * If no change in i2c freq, then acquire semaphore only for the first
	 * i2c transaction to indicate I2C transaction is in progress, else
	 * always try to acquire semaphore, to make sure that no other I2C
	 * transaction is in progress.
	 */
	mutex_lock(&cci_master->mutex);
	if (i2c_freq_mode == cci_dev->i2c_freq_mode[master]) {
		CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d, curr_freq: %d", cci_dev->soc_info.index, master,
			i2c_freq_mode);
		mutex_lock(&cci_master->freq_cnt_lock);
		if (cci_master->freq_ref_cnt == 0)
			down(&cci_master->master_sem);
		cci_master->freq_ref_cnt++;
		mutex_unlock(&cci_master->freq_cnt_lock);
		mutex_unlock(&cci_master->mutex);
		return 0;
	}
	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d, curr_freq: %d, req_freq: %d",
		cci_dev->soc_info.index, master, cci_dev->i2c_freq_mode[master], i2c_freq_mode);
	down(&cci_master->master_sem);

	mutex_lock(&cci_master->freq_cnt_lock);
	cci_master->freq_ref_cnt++;
	mutex_unlock(&cci_master->freq_cnt_lock);

	clk_params = &cci_dev->cci_clk_params[i2c_freq_mode];

	if (master == MASTER_0) {
		cam_io_w_mb(clk_params->hw_thigh << 16 |
			clk_params->hw_tlow,
			base + CCI_I2C_M0_SCL_CTL_ADDR);
		cam_io_w_mb(clk_params->hw_tsu_sto << 16 |
			clk_params->hw_tsu_sta,
			base + CCI_I2C_M0_SDA_CTL_0_ADDR);
		cam_io_w_mb(clk_params->hw_thd_dat << 16 |
			clk_params->hw_thd_sta,
			base + CCI_I2C_M0_SDA_CTL_1_ADDR);
		cam_io_w_mb(clk_params->hw_tbuf,
			base + CCI_I2C_M0_SDA_CTL_2_ADDR);
		cam_io_w_mb(clk_params->hw_scl_stretch_en << 8 |
			clk_params->hw_trdhld << 4 | clk_params->hw_tsp,
			base + CCI_I2C_M0_MISC_CTL_ADDR);
	} else if (master == MASTER_1) {
		cam_io_w_mb(clk_params->hw_thigh << 16 |
			clk_params->hw_tlow,
			base + CCI_I2C_M1_SCL_CTL_ADDR);
		cam_io_w_mb(clk_params->hw_tsu_sto << 16 |
			clk_params->hw_tsu_sta,
			base + CCI_I2C_M1_SDA_CTL_0_ADDR);
		cam_io_w_mb(clk_params->hw_thd_dat << 16 |
			clk_params->hw_thd_sta,
			base + CCI_I2C_M1_SDA_CTL_1_ADDR);
		cam_io_w_mb(clk_params->hw_tbuf,
			base + CCI_I2C_M1_SDA_CTL_2_ADDR);
		cam_io_w_mb(clk_params->hw_scl_stretch_en << 8 |
			clk_params->hw_trdhld << 4 | clk_params->hw_tsp,
			base + CCI_I2C_M1_MISC_CTL_ADDR);
	}
	cci_dev->i2c_freq_mode[master] = i2c_freq_mode;

	mutex_unlock(&cci_master->mutex);
	return 0;
}

int32_t cam_cci_data_queue_burst_apply(struct cci_device *cci_dev,
	enum cci_i2c_master_t master, enum cci_i2c_queue_t queue,
	uint32_t triggerHalfQueue)
{
	struct cam_hw_soc_info *soc_info =
		&cci_dev->soc_info;
	void __iomem *base = soc_info->reg_map[0].mem_base;
	uint32_t reg_val = 1 << ((master * 2) + queue);
	uint32_t iterate = 0;
	uint32_t numBytes = 0;
	bool condition = false;
	uint32_t num_word_written_to_queue = 0;
	uint32_t *data_queue = NULL;
	uint32_t index = 0;
	uint32_t reg_offset;
	uint32_t queue_size = cci_dev->cci_i2c_queue_info[master][queue].max_queue_size;
	uint32_t numWordsInQueue = 0, queueStartThreshold = 0;

	reg_offset = master * 0x200 + queue * 0x100;
	data_queue = cci_dev->cci_master_info[master].data_queue[queue];
	num_word_written_to_queue = cci_dev->cci_master_info[master].num_words_in_data_queue[queue];
	index = cci_dev->cci_master_info[master].data_queue_start_index[queue];
	queueStartThreshold = cci_dev->cci_master_info[master].half_queue_mark[queue];

	if (data_queue == NULL)	{
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d data_queue is NULL",
			cci_dev->soc_info.index, master, queue);
		return -EINVAL;
	}

	/* At First this routine is called from process context with FULL QUEUE
	 * Execution. and next iteration will be called from IRQ Context to process
	 * only HALF QUEUE size decided by precomputed value "queueStartThreshold"
	 * */
	if (triggerHalfQueue == 1) {
		// Apply HALF QUEUE
		trace_cam_cci_burst(cci_dev->soc_info.index, master, queue,
			"thirq raised Buflvl",
			cci_dev->cci_master_info[master].th_irq_ref_cnt[queue]);
		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d Threshold IRQ Raised, BufferLevel: %d",
			cci_dev->soc_info.index, master, queue,
			cam_io_r_mb(base + CCI_I2C_M0_Q0_CUR_WORD_CNT_ADDR + reg_offset));
	} else {
		// Apply FULL QUEUE
		numWordsInQueue = cam_io_r_mb(base +
			CCI_I2C_M0_Q0_CUR_WORD_CNT_ADDR + reg_offset);
	}

	while (index < num_word_written_to_queue) {
		numBytes = (data_queue[index] & 0xF0) >> 4;
		if ((numBytes == 0xF) || (numBytes == 0xE)) {
		       iterate = 3;
		} else {
			numBytes = (numBytes + 4) & ~0x03;
			iterate = numBytes / 4;
		}
		if (numBytes == 0xE) {
			CAM_DBG(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d THRESHOLD IRQ Enabled; data_queue[%d]: 0x%x refcnt: %d",
				cci_dev->soc_info.index, master, queue, index, data_queue[index],
				cci_dev->cci_master_info[master].th_irq_ref_cnt[queue]);
		}
		if (triggerHalfQueue == 0) {
			condition = ((numWordsInQueue + iterate + 1) > queue_size);
		} else {
			condition = (cci_dev->cci_master_info[master].th_irq_ref_cnt[queue] > 0) ?
				(numWordsInQueue >= queueStartThreshold) : 0;
		}

		if (condition == true) {
			CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d CUR_WORD_CNT_ADDR %d len %d max %d",
				cci_dev->soc_info.index, master, queue, numWordsInQueue, iterate, queue_size);
			if ((cci_dev->cci_master_info[master].th_irq_ref_cnt[queue]) > 0) {
				cam_io_w_mb(numWordsInQueue, base +
					CCI_I2C_M0_Q0_EXEC_WORD_CNT_ADDR + reg_offset);
				cam_io_w_mb(reg_val, base + CCI_QUEUE_START_ADDR);
				triggerHalfQueue = 1;
				numWordsInQueue = 0;
				CAM_INFO(CAM_CCI,
					"CCI%d_I2C_M%d_Q%d Issued QUEUE_START, "
					"wait for Threshold_IRQ, th_irq_ref_cnt[%d]:%d",
					cci_dev->soc_info.index, master, queue, queue,
					cci_dev->cci_master_info[master].th_irq_ref_cnt[queue]);
				trace_cam_cci_burst(cci_dev->soc_info.index, master, queue,
					"Q_START thirq_cnt",
					cci_dev->cci_master_info[master].th_irq_ref_cnt[queue]);

				return 0;
			}
		} else {
			while (iterate > 0) {
				cam_io_w_mb(data_queue[index], base +
					CCI_I2C_M0_Q0_LOAD_DATA_ADDR +
					master * 0x200 + queue * 0x100);
				CAM_DBG(CAM_CCI,
					"CCI%d_I2C_M%d_Q%d LOAD_DATA_ADDR 0x%x, "
					"index: %d trig: %d numWordsInQueue: %d",
					cci_dev->soc_info.index, master, queue,
					data_queue[index], (index + 1),
					triggerHalfQueue, (numWordsInQueue + 1));
				numWordsInQueue++;
				index++;
				cci_dev->cci_master_info[master].data_queue_start_index[queue] = index;
				iterate--;
			}
		}
	}

	if ((numWordsInQueue > 0) && (cci_dev->cci_master_info[master].th_irq_ref_cnt[queue] > 0)) {
		cam_io_w_mb(numWordsInQueue, base +
			CCI_I2C_M0_Q0_EXEC_WORD_CNT_ADDR + reg_offset);
		cam_io_w_mb(reg_val, base + CCI_QUEUE_START_ADDR);
		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d Issued ****** FINAL QUEUE_START********, "
			"numWordsInQueue: %d, th_irq_ref_cnt[%d]:%d",
			cci_dev->soc_info.index, master, queue, queue, numWordsInQueue,
			cci_dev->cci_master_info[master].th_irq_ref_cnt[queue]);
		numWordsInQueue = 0;
	}

	return 0;
}

static int32_t cam_cci_data_queue_burst(struct cci_device *cci_dev,
	struct cam_cci_ctrl *c_ctrl, enum cci_i2c_queue_t queue,
	enum cci_i2c_sync sync_en)
{
	uint16_t i = 0, j = 0, len = 0;
	int32_t rc = 0, en_seq_write = 0;
	struct cam_sensor_i2c_reg_setting *i2c_msg =
		&c_ctrl->cfg.cci_i2c_write_cfg;
	struct cam_sensor_i2c_reg_array *i2c_cmd = i2c_msg->reg_setting;
	enum cci_i2c_master_t master = c_ctrl->cci_info->cci_i2c_master;
	uint16_t reg_addr = 0, cmd_size = i2c_msg->size;
	uint32_t reg_offset, val, delay = 0;
	uint32_t max_queue_size, queue_size = 0;
	struct cam_hw_soc_info *soc_info =
		&cci_dev->soc_info;
	void __iomem *base = soc_info->reg_map[0].mem_base;
	unsigned long flags;
	uint8_t next_position = i2c_msg->data_type;
	uint32_t half_queue_mark = 0, full_queue_mark = 0, num_payload = 0;
	uint32_t num_word_written_to_queue = 0;
	uint32_t *data_queue = NULL;
	uint8_t data_len = 0, addr_len = 0;
	uint32_t index = 0;
	uint8_t *buf = NULL;
	uint32_t last_i2c_full_payload = 0;
	uint32_t trigger_half_queue = 0, queue_start_threshold = 0;
	uint32_t en_threshold_irq = 0, cci_enable_th_irq = 0;

	if (i2c_cmd == NULL) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d Failed: i2c cmd is NULL",
			cci_dev->soc_info.index, master, queue);
		return -EINVAL;
	}

	if ((!cmd_size) || (cmd_size > CCI_I2C_MAX_WRITE)) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d failed: invalid cmd_size %d",
			cci_dev->soc_info.index, master, queue, cmd_size);
		return -EINVAL;
	}

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d addr type %d data type %d cmd_size %d",
		cci_dev->soc_info.index, master, queue, i2c_msg->addr_type, i2c_msg->data_type, cmd_size);

	if (i2c_msg->addr_type >= CAMERA_SENSOR_I2C_TYPE_MAX) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d failed: invalid addr_type 0x%X",
			cci_dev->soc_info.index, master, queue, i2c_msg->addr_type);
		return -EINVAL;
	}
	if (i2c_msg->data_type >= CAMERA_SENSOR_I2C_TYPE_MAX) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d failed: invalid data_type 0x%X",
			cci_dev->soc_info.index, master, queue, i2c_msg->data_type);
		return -EINVAL;
	}

	trace_cam_cci_burst(cci_dev->soc_info.index, master, queue,
		"cci burst write START for sid",
		c_ctrl->cci_info->sid);
	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d : START for sid: 0x%x size: %d",
		cci_dev->soc_info.index, master, queue, c_ctrl->cci_info->sid, i2c_msg->size);

	cci_dev->cci_master_info[master].is_burst_enable[queue] = false;
	cci_dev->cci_master_info[master].num_words_exec[queue] = 0;

	addr_len = cam_cci_convert_type_to_num_bytes(i2c_msg->addr_type);
	data_len = cam_cci_convert_type_to_num_bytes(i2c_msg->data_type);
	len = (cmd_size * data_len + addr_len);
	last_i2c_full_payload = len/MSM_CCI_WRITE_DATA_PAYLOAD_SIZE_11;
	/*
	 * For every 11 Bytes of Data 1 Byte of data is Control cmd: 0xF9 or 0xE9 or {0x19 to 0xB9}
	 * Hence compute will account for "len/PAYLOAD_SIZE_11"
	 */
	len = len + len/MSM_CCI_WRITE_DATA_PAYLOAD_SIZE_11 +
		(((len % MSM_CCI_WRITE_DATA_PAYLOAD_SIZE_11) == 0) ? 0 : 1);
	if (len % 4) {
		len = len/4 + 1;
	} else {
		len = len/4;
	}
	/*
	 * Its possible that 8 number of CCI cmds, each 32-bit
	 * can co-exisist in QUEUE along with I2C Data
	 */
	len = len + 8;

	data_queue = kzalloc((len * sizeof(uint32_t)),
			GFP_KERNEL);
	if (!data_queue) {
		CAM_ERR(CAM_CCI, "Unable to allocate memory, BUF is NULL");
		return -ENOMEM;
	}

	reg_offset = master * 0x200 + queue * 0x100;

	cam_io_w_mb(cci_dev->cci_wait_sync_cfg.cid,
		base + CCI_SET_CID_SYNC_TIMER_ADDR +
		cci_dev->cci_wait_sync_cfg.csid *
		CCI_SET_CID_SYNC_TIMER_OFFSET);

	/* Retry count is not supported in BURST MODE */
	c_ctrl->cci_info->retries = 0;

	/* 
	 * 1. Configure Slave ID through SET_PARAM_CMD
	 *    For Burst Mode retries are not supported.
	 *    Record the number of words written to QUEUE
	*/
	val = CCI_I2C_SET_PARAM_CMD | c_ctrl->cci_info->sid << 4 |
		c_ctrl->cci_info->retries << 16 |
		c_ctrl->cci_info->id_map << 18;

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d_LOAD_DATA_ADDR:val 0x%x:0x%x",
		cci_dev->soc_info.index, master, queue, CCI_I2C_M0_Q0_LOAD_DATA_ADDR +
		reg_offset, val);
	cam_io_w_mb(val, base + CCI_I2C_M0_Q0_LOAD_DATA_ADDR +
		reg_offset);
	index++;

	/* 
	 * 2. Initialize the variables used for synchronizing between
	 *    process context and CCI IRQ Context
	 */
	spin_lock_irqsave(&cci_dev->cci_master_info[master].lock_q[queue],
		flags);
	atomic_set(&cci_dev->cci_master_info[master].q_free[queue], 0);
	// atomic_set(&cci_dev->cci_master_info[master].th_irq_ref_cnt[queue], 0);
	reinit_completion(&cci_dev->cci_master_info[master].th_burst_complete[queue]);
	spin_unlock_irqrestore(&cci_dev->cci_master_info[master].lock_q[queue],
		flags);
	cci_dev->cci_master_info[master].th_irq_ref_cnt[queue] = 0;

	max_queue_size =
		cci_dev->cci_i2c_queue_info[master][queue].max_queue_size;

	if ((c_ctrl->cmd == MSM_CCI_I2C_WRITE_SEQ) ||
		(c_ctrl->cmd == MSM_CCI_I2C_WRITE_BURST))
		queue_size = max_queue_size;
	else
		queue_size = max_queue_size / 2;
	reg_addr = i2c_cmd->reg_addr;

	if (len < queue_size) {
		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d: len: %d < QueueSize: %d "
			"No need of threshold IRQ",
			cci_dev->soc_info.index, master, queue, len, queue_size);
		cci_enable_th_irq = 0;
	} else {
		cci_enable_th_irq = CCI_ENABLE_THRESHOLD_IRQ;
	}

	if (sync_en == MSM_SYNC_ENABLE && cci_dev->valid_sync &&
		cmd_size < max_queue_size) {
		val = CCI_I2C_WAIT_SYNC_CMD |
			((cci_dev->cci_wait_sync_cfg.line) << 4);
		cam_io_w_mb(val,
			base + CCI_I2C_M0_Q0_LOAD_DATA_ADDR +
			reg_offset);
		index++;
	}

	/* 3. LOCK the QUEUE So that we can start BURST WRITE*/
	cam_cci_lock_queue(cci_dev, master, queue, 1);
	index++;

	/*
	 * 4. Need to place 0xE0 marker in middle and end of the QUEUE to trigger
	 *    Thresold Interrupt
	 */
	full_queue_mark = (queue_size - index - 1) / MSM_CCI_WRITE_DATA_PAYLOAD_SIZE_WORDS;
	half_queue_mark = full_queue_mark / 2;
	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d queue_size: %d full_queue_mark: %d half_queue_mark: %d",
		cci_dev->soc_info.index, master, queue, queue_size, full_queue_mark, half_queue_mark);

	/*
	 * 5. Iterate through entire size of settings ==> {reg_addr, reg_data}
	 *    and formulate in QUEUE0 like below
	 *            D2 A1 A2 F9  ==> 0xF9: Hold the BUS for I2C WRITE; {0xA2A1, 0xD2D1,
	 *            D6 D3 D4 D1  ==> 0xD4D3, 0xD6D5, 0xD8D7, 0xD10D9.......}
	 *           D10 D7 D8 D5
	 */

	index = 0;
	buf = (uint8_t *) &data_queue[index];
	while (cmd_size) {
		delay = i2c_cmd->delay;
		i = 0;
		buf[i++] = CCI_I2C_WRITE_CMD;

		if (en_seq_write == 0) {
			for (j = 0; j < i2c_msg->addr_type; j++) {
				buf[i2c_msg->addr_type - j] = (reg_addr >> (j * 8)) & 0xFF;
				i++;
			}
		}
		do {
			if (i2c_msg->data_type == CAMERA_SENSOR_I2C_TYPE_BYTE) {
				buf[i++] = i2c_cmd->reg_data;
				if (c_ctrl->cmd == MSM_CCI_I2C_WRITE_SEQ ||
					c_ctrl->cmd == MSM_CCI_I2C_WRITE_BURST)
					reg_addr++;
			} else {
				if (i <= cci_dev->payload_size) {
					/*
					 * this logic fill reg data to buf[] array
					 * which has a max index value 11,
					 * and the sensor reg data type can be DWORD/3B/WORD,
					 * next_position records the split position or the
					 * position in the reg data where will be filled into
					 * next buf[] array slot.
					 */
					if (next_position >= CAMERA_SENSOR_I2C_TYPE_DWORD) {
						buf[i++] = (i2c_cmd->reg_data &
							0xFF000000) >> 24;
						if ((i-1) == MSM_CCI_WRITE_DATA_PAYLOAD_SIZE_11) {
							next_position = CAMERA_SENSOR_I2C_TYPE_3B;
							break;
						}
					}
					/* fill highest byte of 3B type sensor reg data */
					if (next_position >= CAMERA_SENSOR_I2C_TYPE_3B) {
						buf[i++] = (i2c_cmd->reg_data &
							0x00FF0000) >> 16;
						if ((i-1) == MSM_CCI_WRITE_DATA_PAYLOAD_SIZE_11) {
							next_position = CAMERA_SENSOR_I2C_TYPE_WORD;
							break;
						}
					}
					/* fill high byte of WORD type sensor reg data */
					if (next_position >= CAMERA_SENSOR_I2C_TYPE_WORD) {
						buf[i++] = (i2c_cmd->reg_data &
							0x0000FF00) >> 8;
						if ((i-1) == MSM_CCI_WRITE_DATA_PAYLOAD_SIZE_11) {
							next_position = CAMERA_SENSOR_I2C_TYPE_BYTE;
							break;
						}
					}
					/* fill lowest byte of sensor reg data */
					buf[i++] = i2c_cmd->reg_data & 0x000000FF;
					next_position = i2c_msg->data_type;

					if (c_ctrl->cmd == MSM_CCI_I2C_WRITE_SEQ ||
						c_ctrl->cmd == MSM_CCI_I2C_WRITE_BURST)
						reg_addr += i2c_msg->data_type;
				}
			}
			/* move to next cmd while all reg data bytes are filled */
			if (next_position == i2c_msg->data_type) {
				i2c_cmd++;
				--cmd_size;
			}
		} while ((cmd_size > 0) && (i <= cci_dev->payload_size));

		num_payload++;
		en_threshold_irq = cci_enable_th_irq &&
			(((num_payload % half_queue_mark) == 0) || (num_payload == last_i2c_full_payload));
		if (cmd_size > 0) {
			if (en_threshold_irq) {
				buf[0] |= 0xE0;
				cci_dev->cci_master_info[master].th_irq_ref_cnt[queue]++;
				CAM_DBG(CAM_CCI,
					"CCI%d_I2C_M%d_Q%d Th IRQ enabled for index: %d "
					"num_payld: %d th_irq_ref_cnt: %d",
					cci_dev->soc_info.index, master, queue, num_word_written_to_queue,
					num_payload, cci_dev->cci_master_info[master].th_irq_ref_cnt[queue]);
			} else {
				buf[0] |= 0xF0;
			}
		} else {
			buf[0] |= ((i-1) << 4);
			CAM_DBG(CAM_CCI, "End of register Write............ ");
		}
		en_seq_write = 1;
		len = ((i-1)/4) + 1;
		/* increment pointer to next multiple of 4; which is a word in CCI QUEUE */
		buf = buf + ((i+3) & ~0x03);
		num_word_written_to_queue += len;
	}

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d num words to Queue: %d th_irq_ref_cnt: %d cci_dev: %p",
		cci_dev->soc_info.index, master, queue, num_word_written_to_queue,
		cci_dev->cci_master_info[master].th_irq_ref_cnt[queue], cci_dev);

	trace_cam_cci_burst(cci_dev->soc_info.index, master, queue,
		"thirq_cnt",
		cci_dev->cci_master_info[master].th_irq_ref_cnt[queue]);

	index = 0;
	queue_start_threshold = half_queue_mark * MSM_CCI_WRITE_DATA_PAYLOAD_SIZE_WORDS;

	cci_dev->cci_master_info[master].data_queue[queue] = data_queue;
	cci_dev->cci_master_info[master].num_words_in_data_queue[queue] = num_word_written_to_queue;
	cci_dev->cci_master_info[master].data_queue_start_index[queue] = index;
	cci_dev->cci_master_info[master].half_queue_mark[queue] = queue_start_threshold;

	cam_cci_data_queue_burst_apply(cci_dev, master, queue, trigger_half_queue);

	while ((cci_dev->cci_master_info[master].th_irq_ref_cnt[queue]) > 0) {
		if (!cam_common_wait_for_completion_timeout(
			&cci_dev->cci_master_info[master].th_burst_complete[queue],
			CCI_TIMEOUT)) {
			cam_cci_dump_registers(cci_dev, master, queue);

			CAM_ERR(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d wait timeout, rc: %d",
				cci_dev->soc_info.index, master, queue, rc);
			rc = -ETIMEDOUT;
			cam_cci_flush_queue(cci_dev, master);
			CAM_INFO(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d dump register after reset",
				cci_dev->soc_info.index, master, queue);
			cam_cci_dump_registers(cci_dev, master, queue);
			goto ERROR;
		}
		cci_dev->cci_master_info[master].th_irq_ref_cnt[queue]--;
		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d Threshold IRQ Raised, BufferLevel: %d",
			cci_dev->soc_info.index, master, queue,
			cam_io_r_mb(base + CCI_I2C_M0_Q0_CUR_WORD_CNT_ADDR + reg_offset));
	}

	if (cci_dev->cci_master_info[master].th_irq_ref_cnt[queue] > 0) {
		cci_dev->cci_master_info[master].is_burst_enable[queue] = true;
		cci_dev->cci_master_info[master].num_words_exec[queue] = 0;
	}

	rc = cam_cci_transfer_end(cci_dev, master, queue);
	if (rc < 0) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d Slave: 0x%x failed rc %d",
			cci_dev->soc_info.index, master, queue, (c_ctrl->cci_info->sid << 1), rc);
		goto ERROR;
	}
	trace_cam_cci_burst(cci_dev->soc_info.index, master, queue,
		"cci burst write Done for sid",
		c_ctrl->cci_info->sid);
	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d : completed ....for sid: 0x%x size: %d",
		cci_dev->soc_info.index, master, queue, c_ctrl->cci_info->sid, i2c_msg->size);

ERROR:
	kfree(data_queue);
	cci_dev->cci_master_info[master].data_queue[queue] = NULL;
	return rc;
}

static int32_t cam_cci_data_queue(struct cci_device *cci_dev,
	struct cam_cci_ctrl *c_ctrl, enum cci_i2c_queue_t queue,
	enum cci_i2c_sync sync_en)
{
	uint16_t i = 0, j = 0, k = 0, h = 0, len = 0;
	int32_t rc = 0, free_size = 0, en_seq_write = 0;
	uint8_t write_data[CAM_MAX_NUM_CCI_PAYLOAD_BYTES + 1] = {0};
	struct cam_sensor_i2c_reg_setting *i2c_msg =
		&c_ctrl->cfg.cci_i2c_write_cfg;
	struct cam_sensor_i2c_reg_array *i2c_cmd = i2c_msg->reg_setting;
	enum cci_i2c_master_t master = c_ctrl->cci_info->cci_i2c_master;
	uint16_t reg_addr = 0, cmd_size = i2c_msg->size;
	uint32_t read_val = 0, reg_offset, val, delay = 0;
	uint32_t max_queue_size, queue_size = 0, cmd = 0;
	struct cam_hw_soc_info *soc_info =
		&cci_dev->soc_info;
	void __iomem *base = soc_info->reg_map[0].mem_base;
	unsigned long flags;
	uint8_t next_position = i2c_msg->data_type;

	if (i2c_cmd == NULL) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d Failed: i2c cmd is NULL",
			cci_dev->soc_info.index, master, queue);
		return -EINVAL;
	}

	if ((!cmd_size) || (cmd_size > CCI_I2C_MAX_WRITE)) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d failed: invalid cmd_size %d",
			cci_dev->soc_info.index, master, queue, cmd_size);
		return -EINVAL;
	}

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d addr type %d data type %d cmd_size %d",
		cci_dev->soc_info.index, master, queue, i2c_msg->addr_type, i2c_msg->data_type, cmd_size);

	if (i2c_msg->addr_type >= CAMERA_SENSOR_I2C_TYPE_MAX) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d failed: invalid addr_type 0x%X",
			cci_dev->soc_info.index, master, queue, i2c_msg->addr_type);
		return -EINVAL;
	}
	if (i2c_msg->data_type >= CAMERA_SENSOR_I2C_TYPE_MAX) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d failed: invalid data_type 0x%X",
			cci_dev->soc_info.index, master, queue, i2c_msg->data_type);
		return -EINVAL;
	}
	reg_offset = master * 0x200 + queue * 0x100;

	cci_dev->cci_master_info[master].is_burst_enable[queue] = false;
	cci_dev->cci_master_info[master].num_words_exec[queue] = 0;
	cam_io_w_mb(cci_dev->cci_wait_sync_cfg.cid,
		base + CCI_SET_CID_SYNC_TIMER_ADDR +
		cci_dev->cci_wait_sync_cfg.csid *
		CCI_SET_CID_SYNC_TIMER_OFFSET);

	cam_cci_lock_queue(cci_dev, master, queue, 1);

	val = CCI_I2C_SET_PARAM_CMD | c_ctrl->cci_info->sid << 4 |
		c_ctrl->cci_info->retries << 16 |
		c_ctrl->cci_info->id_map << 18;

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d_LOAD_DATA_ADDR:val 0x%x:0x%x",
		cci_dev->soc_info.index, master, queue, CCI_I2C_M0_Q0_LOAD_DATA_ADDR +
		reg_offset, val);
	cam_io_w_mb(val, base + CCI_I2C_M0_Q0_LOAD_DATA_ADDR +
		reg_offset);

	spin_lock_irqsave(&cci_dev->cci_master_info[master].lock_q[queue],
		flags);
	atomic_set(&cci_dev->cci_master_info[master].q_free[queue], 0);
	spin_unlock_irqrestore(&cci_dev->cci_master_info[master].lock_q[queue],
		flags);

	max_queue_size =
		cci_dev->cci_i2c_queue_info[master][queue].max_queue_size;

	if ((c_ctrl->cmd == MSM_CCI_I2C_WRITE_SEQ) ||
		(c_ctrl->cmd == MSM_CCI_I2C_WRITE_BURST))
		queue_size = max_queue_size;
	else
		queue_size = max_queue_size / 2;
	reg_addr = i2c_cmd->reg_addr;

	if (sync_en == MSM_SYNC_ENABLE && cci_dev->valid_sync &&
		cmd_size < max_queue_size) {
		val = CCI_I2C_WAIT_SYNC_CMD |
			((cci_dev->cci_wait_sync_cfg.line) << 4);
		cam_io_w_mb(val,
			base + CCI_I2C_M0_Q0_LOAD_DATA_ADDR +
			reg_offset);
	}

	while (cmd_size) {
		uint32_t pack = 0;

		len = cam_cci_calc_cmd_len(cci_dev, c_ctrl, cmd_size,
			i2c_cmd, &pack);
		if (len <= 0) {
			CAM_ERR(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d Calculate command len failed, len: %d",
				cci_dev->soc_info.index, master, queue, len);
			return -EINVAL;
		}

		read_val = cam_io_r_mb(base +
			CCI_I2C_M0_Q0_CUR_WORD_CNT_ADDR + reg_offset);
		CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d CUR_WORD_CNT_ADDR %d len %d max %d",
			cci_dev->soc_info.index, master, queue, read_val, len, max_queue_size);
		/* + 2 - space alocation for Report and Unlock CMD */
		if ((read_val + len + 2) > queue_size) {
			if ((read_val + len + 2) > max_queue_size) {
				rc = cam_cci_process_full_q(cci_dev,
					master, queue);
				if (rc < 0) {
					CAM_ERR(CAM_CCI,
						"CCI%d_I2C_M%d_Q%d Failed to process full queue rc: %d",
						cci_dev->soc_info.index, master, queue, rc);
					return rc;
				}
				continue;
			}
			cam_cci_process_half_q(cci_dev, master, queue);
		}

		CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d cmd_size %d addr 0x%x data 0x%x",
			cci_dev->soc_info.index, master, queue, cmd_size, i2c_cmd->reg_addr, i2c_cmd->reg_data);
		delay = i2c_cmd->delay;
		i = 0;
		write_data[i++] = CCI_I2C_WRITE_CMD;

		/*
		 * in case of multiple command
		 * MSM_CCI_I2C_WRITE : address is not continuous, so update
		 *	address for a new packet.
		 * MSM_CCI_I2C_WRITE_SEQ : address is continuous, need to keep
		 *	the incremented address for a
		 *	new packet
		 */
		if (c_ctrl->cmd == MSM_CCI_I2C_WRITE ||
			c_ctrl->cmd == MSM_CCI_I2C_WRITE_ASYNC ||
			c_ctrl->cmd == MSM_CCI_I2C_WRITE_SYNC ||
			c_ctrl->cmd == MSM_CCI_I2C_WRITE_SYNC_BLOCK)
			reg_addr = i2c_cmd->reg_addr;

		if (en_seq_write == 0) {
			for (j = 0; j < i2c_msg->addr_type; j++) {
				write_data[i2c_msg->addr_type - j] = (reg_addr >> (j * 8)) & 0xFF;
				i++;
			}
		}

		do {
			if (i2c_msg->data_type == CAMERA_SENSOR_I2C_TYPE_BYTE) {
				write_data[i++] = i2c_cmd->reg_data;
				if (c_ctrl->cmd == MSM_CCI_I2C_WRITE_SEQ)
					reg_addr++;
			} else {
				if (i <= cci_dev->payload_size) {
					/*
					 * this logic fill reg data to write_data[] array
					 * which has a max index value 11,
					 * and the sensor reg data type can be DWORD/3B/WORD,
					 * next_position records the split position or the
					 * position in the reg data where will be filled into
					 * next write_data[] array slot.
					 */
					if (next_position >= CAMERA_SENSOR_I2C_TYPE_DWORD) {
						write_data[i++] = (i2c_cmd->reg_data &
							0xFF000000) >> 24;
						if ((i-1) == MSM_CCI_WRITE_DATA_PAYLOAD_SIZE_11) {
							next_position = CAMERA_SENSOR_I2C_TYPE_3B;
							break;
						}
					}
					/* fill highest byte of 3B type sensor reg data */
					if (next_position >= CAMERA_SENSOR_I2C_TYPE_3B) {
						write_data[i++] = (i2c_cmd->reg_data &
							0x00FF0000) >> 16;
						if ((i-1) == MSM_CCI_WRITE_DATA_PAYLOAD_SIZE_11) {
							next_position = CAMERA_SENSOR_I2C_TYPE_WORD;
							break;
						}
					}
					/* fill high byte of WORD type sensor reg data */
					if (next_position >= CAMERA_SENSOR_I2C_TYPE_WORD) {
						write_data[i++] = (i2c_cmd->reg_data &
							0x0000FF00) >> 8;
						if ((i-1) == MSM_CCI_WRITE_DATA_PAYLOAD_SIZE_11) {
							next_position = CAMERA_SENSOR_I2C_TYPE_BYTE;
							break;
						}
					}
					/* fill lowest byte of sensor reg data */
					write_data[i++] = i2c_cmd->reg_data & 0x000000FF;
					next_position = i2c_msg->data_type;

					if (c_ctrl->cmd == MSM_CCI_I2C_WRITE_SEQ)
						reg_addr += i2c_msg->data_type;
				}
			}
			/* move to next cmd while all reg data bytes are filled */
			if (next_position == i2c_msg->data_type) {
				i2c_cmd++;
				--cmd_size;
			}
		} while (((c_ctrl->cmd == MSM_CCI_I2C_WRITE_SEQ ||
			c_ctrl->cmd == MSM_CCI_I2C_WRITE_BURST) || pack--) &&
				(cmd_size > 0) && (i <= cci_dev->payload_size));
		free_size = cam_cci_get_queue_free_size(cci_dev, master,
				queue);
		if ((c_ctrl->cmd == MSM_CCI_I2C_WRITE_SEQ ||
			c_ctrl->cmd == MSM_CCI_I2C_WRITE_BURST) &&
			((i-1) == MSM_CCI_WRITE_DATA_PAYLOAD_SIZE_11) &&
			cci_dev->support_seq_write && cmd_size > 0 &&
			free_size > BURST_MIN_FREE_SIZE) {
			write_data[0] |= 0xF0;
			en_seq_write = 1;
		} else {
			write_data[0] |= ((i-1) << 4);
			en_seq_write = 0;
		}
		len = ((i-1)/4) + 1;

		CAM_DBG(CAM_CCI, "free_size %d, en_seq_write %d i: %d len: %d ",
			free_size, en_seq_write, i, len);
		read_val = cam_io_r_mb(base +
			CCI_I2C_M0_Q0_CUR_WORD_CNT_ADDR + reg_offset);
		for (h = 0, k = 0; h < len; h++) {
			cmd = 0;
			for (j = 0; (j < 4 && k < i); j++)
				cmd |= (write_data[k++] << (j * 8));
			CAM_DBG(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d LOAD_DATA_ADDR 0x%x, len:%d, cnt: %d",
				cci_dev->soc_info.index, master, queue, cmd, len, read_val);
			cam_io_w_mb(cmd, base +
				CCI_I2C_M0_Q0_LOAD_DATA_ADDR +
				master * 0x200 + queue * 0x100);

			read_val += 1;

		}

		cam_io_w_mb(read_val, base +
			CCI_I2C_M0_Q0_EXEC_WORD_CNT_ADDR + reg_offset);

		if ((delay > 0) && (delay < CCI_MAX_DELAY) &&
			en_seq_write == 0) {
			cmd = (uint32_t)((delay * cci_dev->cycles_per_us) /
				0x100);
			cmd <<= 4;
			cmd |= CCI_I2C_WAIT_CMD;
			CAM_DBG(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d_LOAD_DATA_ADDR 0x%x",
				cci_dev->soc_info.index, master, queue, cmd);
			cam_io_w_mb(cmd, base +
				CCI_I2C_M0_Q0_LOAD_DATA_ADDR +
				master * 0x200 + queue * 0x100);
			read_val += 1;
			cam_io_w_mb(read_val, base +
				CCI_I2C_M0_Q0_EXEC_WORD_CNT_ADDR + reg_offset);
		}
	}

	rc = cam_cci_transfer_end(cci_dev, master, queue);
	if (rc < 0) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d Slave: 0x%x failed rc %d",
			cci_dev->soc_info.index, master, queue, (c_ctrl->cci_info->sid << 1), rc);
		return rc;
	}

	return rc;
}

static int32_t cam_cci_burst_read(struct v4l2_subdev *sd,
	struct cam_cci_ctrl *c_ctrl)
{
	int32_t rc = 0;
	uint32_t val = 0, i = 0, j = 0, irq_mask_update = 0;
	unsigned long rem_jiffies, flags;
	int32_t read_words = 0, exp_words = 0;
	int32_t index = 0, first_byte = 0, total_read_words = 0;
	enum cci_i2c_master_t master;
	enum cci_i2c_queue_t queue = QUEUE_1;
	struct cci_device                  *cci_dev = NULL;
	struct cam_cci_read_cfg            *read_cfg = NULL;
	struct cam_hw_soc_info             *soc_info = NULL;
	void __iomem                       *base = NULL;

	cci_dev = v4l2_get_subdevdata(sd);
	if (!cci_dev) {
		CAM_ERR(CAM_CCI, "cci_dev NULL");
		return -EINVAL;
	}
	master = c_ctrl->cci_info->cci_i2c_master;
	read_cfg = &c_ctrl->cfg.cci_i2c_read_cfg;

	if (c_ctrl->cci_info->cci_i2c_master >= MASTER_MAX
		|| c_ctrl->cci_info->cci_i2c_master < 0) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d Invalid I2C master addr",
			cci_dev->soc_info.index, master, queue);
		return -EINVAL;
	}

	/* Set the I2C Frequency */
	rc = cam_cci_set_clk_param(cci_dev, c_ctrl);
	if (rc < 0) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d cam_cci_set_clk_param failed rc: %d",
			cci_dev->soc_info.index, master, queue, rc);
		return rc;
	}

	mutex_lock(&cci_dev->cci_master_info[master].mutex_q[queue]);
	cci_dev->is_burst_read[master] = true;
	reinit_completion(&cci_dev->cci_master_info[master].report_q[queue]);

	soc_info = &cci_dev->soc_info;
	base = soc_info->reg_map[0].mem_base;

	/*
	 * Call validate queue to make sure queue is empty before starting.
	 * If this call fails, don't proceed with i2c_read call. This is to
	 * avoid overflow / underflow of queue
	 */
	rc = cam_cci_validate_queue(cci_dev,
		cci_dev->cci_i2c_queue_info[master][queue].max_queue_size - 1,
		master, queue);
	if (rc < 0) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d Initial validataion failed rc:%d",
			cci_dev->soc_info.index, master, queue, rc);
		goto rel_mutex_q;
	}

	if (c_ctrl->cci_info->retries > CCI_I2C_READ_MAX_RETRIES) {
		CAM_ERR(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d Invalid read retries info retries from slave: %d, max retries: %d",
			cci_dev->soc_info.index, master, queue, c_ctrl->cci_info->retries, CCI_I2C_READ_MAX_RETRIES);
		goto rel_mutex_q;
	}

	if (read_cfg->data == NULL) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d Data ptr is NULL",
			cci_dev->soc_info.index, master, queue);
		goto rel_mutex_q;
	}

	if (read_cfg->addr_type >= CAMERA_SENSOR_I2C_TYPE_MAX) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d failed : Invalid addr type: %u",
			cci_dev->soc_info.index, master, queue, read_cfg->addr_type);
		rc = -EINVAL;
		goto rel_mutex_q;
	}

	val = CCI_I2C_LOCK_CMD;
	rc = cam_cci_write_i2c_queue(cci_dev, val, master, queue);
	if (rc < 0) {
		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d failed to write lock_cmd for rc: %d",
			cci_dev->soc_info.index, master, queue, rc);
		goto rel_mutex_q;
	}

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d set param sid 0x%x retries %d id_map %d",
		cci_dev->soc_info.index, master, queue,
		c_ctrl->cci_info->sid, c_ctrl->cci_info->retries,
		c_ctrl->cci_info->id_map);
	val = CCI_I2C_SET_PARAM_CMD | c_ctrl->cci_info->sid << 4 |
		c_ctrl->cci_info->retries << 16 |
		c_ctrl->cci_info->id_map << 18;
	rc = cam_cci_write_i2c_queue(cci_dev, val, master, queue);
	if (rc < 0) {
		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d Failed to write param_cmd for rc: %d",
			cci_dev->soc_info.index, master, queue, rc);
		goto rel_mutex_q;
	}

	val = CCI_I2C_WRITE_DISABLE_P_CMD | (read_cfg->addr_type << 4);
	for (i = 0; i < read_cfg->addr_type; i++) {
		val |= ((read_cfg->addr >> (i << 3)) & 0xFF)  <<
		((read_cfg->addr_type - i) << 3);
	}

	rc = cam_cci_write_i2c_queue(cci_dev, val, master, queue);
	if (rc < 0) {
		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d Failed to write disable cmd for rc: %d",
			cci_dev->soc_info.index, master, queue, rc);
		goto rel_mutex_q;
	}

	val = CCI_I2C_READ_CMD | (read_cfg->num_byte << 4);
	rc = cam_cci_write_i2c_queue(cci_dev, val, master, queue);
	if (rc < 0) {
		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d Failed to write read_cmd for rc: %d",
			cci_dev->soc_info.index, master, queue, rc);
		goto rel_mutex_q;
	}

	val = CCI_I2C_UNLOCK_CMD;
	rc = cam_cci_write_i2c_queue(cci_dev, val, master, queue);
	if (rc < 0) {
		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d failed to write unlock_cmd for rc: %d",
			cci_dev->soc_info.index, master, queue, rc);
		goto rel_mutex_q;
	}

	val = cam_io_r_mb(base + CCI_I2C_M0_Q0_CUR_WORD_CNT_ADDR
			+ master * 0x200 + queue * 0x100);
	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d cur word cnt 0x%x",
		cci_dev->soc_info.index, master, queue, val);
	cam_io_w_mb(val, base + CCI_I2C_M0_Q0_EXEC_WORD_CNT_ADDR
			+ master * 0x200 + queue * 0x100);

	val = 1 << ((master * 2) + queue);
	cam_io_w_mb(val, base + CCI_QUEUE_START_ADDR);

	exp_words = ((read_cfg->num_byte / 4) + 1);
	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d waiting for threshold [exp_words %d]",
		cci_dev->soc_info.index, master, queue, exp_words);

	while (total_read_words != exp_words) {
		rem_jiffies = cam_common_wait_for_completion_timeout(
			&cci_dev->cci_master_info[master].th_complete,
			CCI_TIMEOUT);
		if (!rem_jiffies) {
			rc = -ETIMEDOUT;
			val = cam_io_r_mb(base +
				CCI_I2C_M0_READ_BUF_LEVEL_ADDR +
				master * 0x100);
			CAM_ERR(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d wait timeout for th_complete, FIFO buf_lvl:0x%x, rc: %d",
				cci_dev->soc_info.index, master, queue, val, rc);
			cam_cci_dump_registers(cci_dev, master, queue);

			cam_cci_flush_queue(cci_dev, master);
			goto rel_mutex_q;
		}

		if (cci_dev->cci_master_info[master].status) {
			CAM_ERR(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d Error with Slave: 0x%x",
				cci_dev->soc_info.index, master, queue, (c_ctrl->cci_info->sid << 1));
			rc = -EINVAL;
			cci_dev->cci_master_info[master].status = 0;
			goto rel_mutex_q;
		}

		read_words = cam_io_r_mb(base +
			CCI_I2C_M0_READ_BUF_LEVEL_ADDR + master * 0x100);
		if (read_words <= 0) {
			CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d FIFO Buffer lvl is 0",
				cci_dev->soc_info.index, master, queue);
			goto enable_irq;
		}

read_again:
		j++;
		CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d Iteration: %u read_words %d",
			cci_dev->soc_info.index, master, queue, j, read_words);

		total_read_words += read_words;
		while (read_words > 0) {
			val = cam_io_r_mb(base +
				CCI_I2C_M0_READ_DATA_ADDR + master * 0x100);
			for (i = 0; (i < 4) &&
				(index < read_cfg->num_byte); i++) {
				CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d i:%d index:%d",
					cci_dev->soc_info.index, master, queue, i, index);
				if (!first_byte) {
					CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d sid 0x%x",
						cci_dev->soc_info.index, master, queue, val & 0xFF);
					first_byte++;
				} else {
					read_cfg->data[index] =
						(val  >> (i * 8)) & 0xFF;
					CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d data[%d] 0x%x",
						cci_dev->soc_info.index, master, queue, index,
						read_cfg->data[index]);
					index++;
				}
			}
			read_words--;
		}

		CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d Iteration:%u total_read_words %d",
			cci_dev->soc_info.index, master, queue, j, total_read_words);

		read_words = cam_io_r_mb(base +
			CCI_I2C_M0_READ_BUF_LEVEL_ADDR + master * 0x100);
		if (read_words > 0) {
			CAM_DBG(CAM_CCI, "FIFO Buffer lvl is %d", read_words);
			goto read_again;
		}

enable_irq:
		spin_lock_irqsave(&cci_dev->lock_status, flags);
		if (cci_dev->irqs_disabled) {
			irq_mask_update =
				cam_io_r_mb(base + CCI_IRQ_MASK_1_ADDR);
			if (master == MASTER_0 && cci_dev->irqs_disabled &
				CCI_IRQ_STATUS_1_I2C_M0_RD_THRESHOLD)
				irq_mask_update |=
					CCI_IRQ_STATUS_1_I2C_M0_RD_THRESHOLD;
			else if (master == MASTER_1 && cci_dev->irqs_disabled &
				CCI_IRQ_STATUS_1_I2C_M1_RD_THRESHOLD)
				irq_mask_update |=
					CCI_IRQ_STATUS_1_I2C_M1_RD_THRESHOLD;
			cam_io_w_mb(irq_mask_update,
				base + CCI_IRQ_MASK_1_ADDR);
		}
		spin_unlock_irqrestore(&cci_dev->lock_status, flags);

		if (total_read_words == exp_words) {
		   /*
		    * This wait is for RD_DONE irq, if RD_DONE is
		    * triggered we will call complete on both threshold
		    * & read done waits. As part of the threshold wait
		    * we will be draining the entire buffer out. This
		    * wait is to compensate for the complete invoked for
		    * RD_DONE exclusively.
		    */
			rem_jiffies = cam_common_wait_for_completion_timeout(
			&cci_dev->cci_master_info[master].rd_done,
			CCI_TIMEOUT);
			if (!rem_jiffies) {
				rc = -ETIMEDOUT;
				val = cam_io_r_mb(base +
					CCI_I2C_M0_READ_BUF_LEVEL_ADDR +
					master * 0x100);
				CAM_ERR(CAM_CCI,
					"CCI%d_I2C_M%d_Q%d wait timeout for RD_DONE irq for rc = %d FIFO buf_lvl:0x%x, rc: %d",
					cci_dev->soc_info.index, master, queue,
					val, rc);
				cam_cci_dump_registers(cci_dev,
						master, queue);

				cam_cci_flush_queue(cci_dev, master);
				goto rel_mutex_q;
			}

			if (cci_dev->cci_master_info[master].status) {
				CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d Error with Slave 0x%x",
					cci_dev->soc_info.index, master, queue, (c_ctrl->cci_info->sid << 1));
				rc = -EINVAL;
				cci_dev->cci_master_info[master].status = 0;
				goto rel_mutex_q;
			}
			break;
		}
	}

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d Burst read successful words_read %d",
		cci_dev->soc_info.index, master, queue, total_read_words);

rel_mutex_q:
	mutex_unlock(&cci_dev->cci_master_info[master].mutex_q[queue]);

	mutex_lock(&cci_dev->cci_master_info[master].freq_cnt_lock);
	if (--cci_dev->cci_master_info[master].freq_ref_cnt == 0)
		up(&cci_dev->cci_master_info[master].master_sem);
	mutex_unlock(&cci_dev->cci_master_info[master].freq_cnt_lock);
	return rc;
}

static int32_t cam_cci_read(struct v4l2_subdev *sd,
	struct cam_cci_ctrl *c_ctrl)
{
	int32_t rc = 0;
	uint32_t val = 0;
	uint8_t read_data_byte[CAM_MAX_NUM_CCI_PAYLOAD_BYTES + 1] = {0};
	uint32_t *reg_addr;
	int32_t read_words = 0, exp_words = 0;
	int32_t index = 0, first_byte = 0;
	uint32_t i = 0;
	enum cci_i2c_master_t master;
	enum cci_i2c_queue_t queue = QUEUE_1;
	struct cci_device *cci_dev = NULL;
	struct cam_cci_read_cfg *read_cfg = NULL;
	struct cam_hw_soc_info *soc_info = NULL;
	void __iomem *base = NULL;

	cci_dev = v4l2_get_subdevdata(sd);
	if (!cci_dev) {
		CAM_ERR(CAM_CCI, "cci_dev NULL");
		return -EINVAL;
	}
	master = c_ctrl->cci_info->cci_i2c_master;
	read_cfg = &c_ctrl->cfg.cci_i2c_read_cfg;

	if (c_ctrl->cci_info->cci_i2c_master >= MASTER_MAX
		|| c_ctrl->cci_info->cci_i2c_master < 0) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d Invalid I2C master addr:%d",
			cci_dev->soc_info.index, master, queue, c_ctrl->cci_info->cci_i2c_master);
		return -EINVAL;
	}

	/* Set the I2C Frequency */
	rc = cam_cci_set_clk_param(cci_dev, c_ctrl);
	if (rc < 0) {
		CAM_ERR(CAM_CCI, "cam_cci_set_clk_param failed rc = %d", rc);
		return rc;
	}

	mutex_lock(&cci_dev->cci_master_info[master].mutex_q[queue]);
	cci_dev->is_burst_read[master] = false;
	reinit_completion(&cci_dev->cci_master_info[master].report_q[queue]);

	soc_info = &cci_dev->soc_info;
	base = soc_info->reg_map[0].mem_base;

	/*
	 * Call validate queue to make sure queue is empty before starting.
	 * If this call fails, don't proceed with i2c_read call. This is to
	 * avoid overflow / underflow of queue
	 */
	rc = cam_cci_validate_queue(cci_dev,
		cci_dev->cci_i2c_queue_info[master][queue].max_queue_size - 1,
		master, queue);
	if (rc < 0) {
		val = cam_io_r_mb(base + CCI_I2C_M0_Q0_CUR_CMD_ADDR +
			master * 0x200 + queue * 0x100);
		CAM_ERR(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d Initial validataion failed rc: %d, CUR_CMD:0x%x",
			cci_dev->soc_info.index, master, queue, rc, val);
		goto rel_mutex_q;
	}

	if (c_ctrl->cci_info->retries > CCI_I2C_READ_MAX_RETRIES) {
		CAM_ERR(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d Invalid read retries info retries from slave: %d, max retries: %d",
			cci_dev->soc_info.index, master, queue, c_ctrl->cci_info->retries, CCI_I2C_READ_MAX_RETRIES);
		goto rel_mutex_q;
	}

	if (read_cfg->data == NULL) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d Data ptr is NULL",
			cci_dev->soc_info.index, master, queue);
		goto rel_mutex_q;
	}

	val = CCI_I2C_LOCK_CMD;
	rc = cam_cci_write_i2c_queue(cci_dev, val, master, queue);
	if (rc < 0) {
		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d failed to write lock_cmd for rc: %d",
			cci_dev->soc_info.index, master, queue, rc);
		goto rel_mutex_q;
	}

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d set param sid 0x%x retries %d id_map %d",
		cci_dev->soc_info.index, master, queue,
		c_ctrl->cci_info->sid, c_ctrl->cci_info->retries,
		c_ctrl->cci_info->id_map);
	val = CCI_I2C_SET_PARAM_CMD | c_ctrl->cci_info->sid << 4 |
		c_ctrl->cci_info->retries << 16 |
		c_ctrl->cci_info->id_map << 18;
	rc = cam_cci_write_i2c_queue(cci_dev, val, master, queue);
	if (rc < 0) {
		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d Failed to write param_cmd for rc: %d",
			cci_dev->soc_info.index, master, queue, rc);
		goto rel_mutex_q;
	}

	if (read_cfg->addr_type >= CAMERA_SENSOR_I2C_TYPE_MAX) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d Failed : Invalid addr type: %u",
			cci_dev->soc_info.index, master, queue, read_cfg->addr_type);
		rc = -EINVAL;
		goto rel_mutex_q;
	}

	read_data_byte[0] = CCI_I2C_WRITE_DISABLE_P_CMD | (read_cfg->addr_type << 4);
	for (i = 0; i < read_cfg->addr_type; i++) {
		read_data_byte[read_cfg->addr_type - i] = (read_cfg->addr >> (i * 8)) & 0xFF;
	}

	reg_addr = (uint32_t *)&read_data_byte[0];
	read_words = DIV_ROUND_UP(read_cfg->addr_type + 1, 4);

	for (i = 0; i < read_words; i++) {
		rc = cam_cci_write_i2c_queue(cci_dev, *reg_addr, master, queue);
		if (rc < 0) {
			CAM_DBG(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d Failed to write disable_cmd for rc: %d",
				cci_dev->soc_info.index, master, queue, rc);
			goto rel_mutex_q;
		}
		reg_addr++;
	}

	val = CCI_I2C_READ_CMD | (read_cfg->num_byte << 4);
	rc = cam_cci_write_i2c_queue(cci_dev, val, master, queue);
	if (rc < 0) {
		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d Failed to write read_cmd for rc: %d",
			cci_dev->soc_info.index, master, queue, rc);
		goto rel_mutex_q;
	}

	val = CCI_I2C_UNLOCK_CMD;
	rc = cam_cci_write_i2c_queue(cci_dev, val, master, queue);
	if (rc < 0) {
		CAM_DBG(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d failed to write unlock_cmd for rc: %d",
			cci_dev->soc_info.index, master, queue, rc);
		goto rel_mutex_q;
	}

	val = cam_io_r_mb(base + CCI_I2C_M0_Q0_CUR_WORD_CNT_ADDR
			+ master * 0x200 + queue * 0x100);
	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d_CUR_WORD_CNT 0x%x",
		cci_dev->soc_info.index, master, queue, val);
	cam_io_w_mb(val, base + CCI_I2C_M0_Q0_EXEC_WORD_CNT_ADDR
			+ master * 0x200 + queue * 0x100);

	val = 1 << ((master * 2) + queue);
	cam_io_w_mb(val, base + CCI_QUEUE_START_ADDR);
	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d exp_words to be read: %d",
		cci_dev->soc_info.index, master, queue, ((read_cfg->num_byte / 4) + 1));

	if (!cam_common_wait_for_completion_timeout(
		&cci_dev->cci_master_info[master].rd_done, CCI_TIMEOUT)) {
		cam_cci_dump_registers(cci_dev, master, queue);

		rc = -ETIMEDOUT;
		val = cam_io_r_mb(base +
			CCI_I2C_M0_READ_BUF_LEVEL_ADDR + master * 0x100);
		CAM_ERR(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d rd_done wait timeout FIFO buf_lvl: 0x%x, rc: %d",
			cci_dev->soc_info.index, master, queue, val, rc);
		cam_cci_flush_queue(cci_dev, master);
		goto rel_mutex_q;
	}

	if (cci_dev->cci_master_info[master].status) {
		if (cci_dev->is_probing)
			CAM_INFO(CAM_CCI, "CCI%d_I2C_M%d_Q%d ERROR with Slave 0x%x",
				cci_dev->soc_info.index, master, queue,
				(c_ctrl->cci_info->sid << 1));
		else
			CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d ERROR with Slave 0x%x",
				cci_dev->soc_info.index, master, queue,
				(c_ctrl->cci_info->sid << 1));
		rc = -EINVAL;
		cci_dev->cci_master_info[master].status = 0;
		goto rel_mutex_q;
	}

	read_words = cam_io_r_mb(base +
		CCI_I2C_M0_READ_BUF_LEVEL_ADDR + master * 0x100);
	exp_words = ((read_cfg->num_byte / 4) + 1);
	if (read_words != exp_words) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d read_words: %d, exp words: %d",
			cci_dev->soc_info.index, master, queue, read_words, exp_words);
		memset(read_cfg->data, 0, read_cfg->num_byte);
		rc = -EINVAL;
		goto rel_mutex_q;
	}
	index = 0;
	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d index: %d, num_type: %d",
		cci_dev->soc_info.index, master, queue, index, read_cfg->num_byte);
	first_byte = 0;
	while (read_words > 0) {
		val = cam_io_r_mb(base +
			CCI_I2C_M0_READ_DATA_ADDR + master * 0x100);
		CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d read val: 0x%x",
			cci_dev->soc_info.index, master, queue, val);
		for (i = 0; (i < 4) && (index < read_cfg->num_byte); i++) {
			CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d i: %d, index: %d",
				cci_dev->soc_info.index, master, queue, i, index);
			if (!first_byte) {
				CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d sid: 0x%x",
					cci_dev->soc_info.index, master, queue, val & 0xFF);
				first_byte++;
			} else {
				read_cfg->data[index] =
					(val  >> (i * 8)) & 0xFF;
				CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d data[%d] 0x%x",
					cci_dev->soc_info.index, master, queue, index,
					read_cfg->data[index]);
				index++;
			}
		}
		read_words--;
	}
rel_mutex_q:
	mutex_unlock(&cci_dev->cci_master_info[master].mutex_q[queue]);

	mutex_lock(&cci_dev->cci_master_info[master].freq_cnt_lock);
	if (--cci_dev->cci_master_info[master].freq_ref_cnt == 0)
		up(&cci_dev->cci_master_info[master].master_sem);
	mutex_unlock(&cci_dev->cci_master_info[master].freq_cnt_lock);
	return rc;
}

static int32_t cam_cci_i2c_write(struct v4l2_subdev *sd,
	struct cam_cci_ctrl *c_ctrl, enum cci_i2c_queue_t queue,
	enum cci_i2c_sync sync_en)
{
	int32_t rc = 0;
	struct cci_device *cci_dev;
	enum cci_i2c_master_t master;

	cci_dev = v4l2_get_subdevdata(sd);
	if (!cci_dev) {
		CAM_ERR(CAM_CCI, "cci_dev NULL");
		return -EINVAL;
	}

	if (cci_dev->cci_state != CCI_STATE_ENABLED) {
		CAM_ERR(CAM_CCI, "invalid cci: %d state: %d",
			cci_dev->soc_info.index, cci_dev->cci_state);
		return -EINVAL;
	}
	master = c_ctrl->cci_info->cci_i2c_master;
	if (master >= MASTER_MAX || master < 0) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d Invalid I2C master addr",
			cci_dev->soc_info.index,
			master);
		return -EINVAL;
	}

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d_Q%d set param sid 0x%x retries %d id_map %d",
		cci_dev->soc_info.index, master, queue, c_ctrl->cci_info->sid, c_ctrl->cci_info->retries,
		c_ctrl->cci_info->id_map);

	/* Set the I2C Frequency */
	rc = cam_cci_set_clk_param(cci_dev, c_ctrl);
	if (rc < 0) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d cam_cci_set_clk_param failed rc %d",
			cci_dev->soc_info.index, master, queue, rc);
		return rc;
	}
	reinit_completion(&cci_dev->cci_master_info[master].report_q[queue]);
	reinit_completion(&cci_dev->cci_master_info[master].th_burst_complete[queue]);
	/*
	 * Call validate queue to make sure queue is empty before starting.
	 * If this call fails, don't proceed with i2c_write call. This is to
	 * avoid overflow / underflow of queue
	 */
	rc = cam_cci_validate_queue(cci_dev,
		cci_dev->cci_i2c_queue_info[master][queue].max_queue_size-1,
		master, queue);
	if (rc < 0) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d Initial validataion failed rc %d",
			cci_dev->soc_info.index, master, queue, rc);
		goto ERROR;
	}
	if (c_ctrl->cci_info->retries > CCI_I2C_READ_MAX_RETRIES) {
		CAM_ERR(CAM_CCI,
			"CCI%d_I2C_M%d_Q%d Invalid read retries info retries from slave: %d, max retries: %d",
			cci_dev->soc_info.index, master, queue, c_ctrl->cci_info->retries, CCI_I2C_READ_MAX_RETRIES);
		goto ERROR;
	}
	if (c_ctrl->cmd == MSM_CCI_I2C_WRITE_BURST) {
		rc = cam_cci_data_queue_burst(cci_dev, c_ctrl, queue, sync_en);
		if (rc < 0) {
			CAM_ERR(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d Failed in queueing i2c Burst write data for rc: %d",
				cci_dev->soc_info.index, master, queue, rc);
			goto ERROR;
		}
	} else {
		rc = cam_cci_data_queue(cci_dev, c_ctrl, queue, sync_en);
		if (rc < 0) {
			CAM_ERR(CAM_CCI,
				"CCI%d_I2C_M%d_Q%d Failed in queueing the data for rc: %d",
				cci_dev->soc_info.index, master, queue, rc);
			goto ERROR;
		}
	}

ERROR:
	mutex_lock(&cci_dev->cci_master_info[master].freq_cnt_lock);
	if (--cci_dev->cci_master_info[master].freq_ref_cnt == 0)
		up(&cci_dev->cci_master_info[master].master_sem);
	mutex_unlock(&cci_dev->cci_master_info[master].freq_cnt_lock);
	return rc;
}

static void cam_cci_write_async_helper(struct work_struct *work)
{
	int rc;
	struct cci_device *cci_dev;
	struct cci_write_async *write_async =
		container_of(work, struct cci_write_async, work);
	enum cci_i2c_master_t master;
	struct cam_cci_master_info *cci_master_info;

	cam_common_util_thread_switch_delay_detect(
		"cam_cci_workq", "schedule", cam_cci_write_async_helper,
		write_async->workq_scheduled_ts,
		CAM_WORKQ_SCHEDULE_TIME_THRESHOLD);
	cci_dev = write_async->cci_dev;
	master = write_async->c_ctrl.cci_info->cci_i2c_master;
	cci_master_info = &cci_dev->cci_master_info[master];

	mutex_lock(&cci_master_info->mutex_q[write_async->queue]);
	rc = cam_cci_i2c_write(&(cci_dev->v4l2_dev_str.sd),
		&write_async->c_ctrl, write_async->queue, write_async->sync_en);
	mutex_unlock(&cci_master_info->mutex_q[write_async->queue]);
	if (rc < 0)
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d Failed rc: %d",
		cci_dev->soc_info.index, master, write_async->queue, rc);

	kfree(write_async->c_ctrl.cfg.cci_i2c_write_cfg.reg_setting);
	kfree(write_async);
}

static int32_t cam_cci_i2c_write_async(struct v4l2_subdev *sd,
	struct cam_cci_ctrl *c_ctrl, enum cci_i2c_queue_t queue,
	enum cci_i2c_sync sync_en)
{
	int32_t rc = 0;
	struct cci_write_async *write_async;
	struct cci_device *cci_dev;
	struct cam_sensor_i2c_reg_setting *cci_i2c_write_cfg;
	struct cam_sensor_i2c_reg_setting *cci_i2c_write_cfg_w;

	cci_dev = v4l2_get_subdevdata(sd);
	if (!cci_dev) {
		CAM_ERR(CAM_CCI, "cci_dev NULL");
		return -EINVAL;
	}

	write_async = kzalloc(sizeof(*write_async), GFP_KERNEL);
	if (!write_async) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d Memory allocation failed for write_async",
			cci_dev->soc_info.index, c_ctrl->cci_info->cci_i2c_master, queue);
		return -ENOMEM;
	}


	INIT_WORK(&write_async->work, cam_cci_write_async_helper);
	write_async->cci_dev = cci_dev;
	write_async->c_ctrl = *c_ctrl;
	write_async->queue = queue;
	write_async->sync_en = sync_en;

	cci_i2c_write_cfg = &c_ctrl->cfg.cci_i2c_write_cfg;
	cci_i2c_write_cfg_w = &write_async->c_ctrl.cfg.cci_i2c_write_cfg;

	if (cci_i2c_write_cfg->size == 0) {
		kfree(write_async);
		return -EINVAL;
	}

	cci_i2c_write_cfg_w->reg_setting =
		kzalloc(sizeof(struct cam_sensor_i2c_reg_array)*
		cci_i2c_write_cfg->size, GFP_KERNEL);
	if (!cci_i2c_write_cfg_w->reg_setting) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d_Q%d Couldn't allocate memory for reg_setting",
			cci_dev->soc_info.index, c_ctrl->cci_info->cci_i2c_master, queue);
		kfree(write_async);
		return -ENOMEM;
	}
	memcpy(cci_i2c_write_cfg_w->reg_setting,
		cci_i2c_write_cfg->reg_setting,
		(sizeof(struct cam_sensor_i2c_reg_array)*
						cci_i2c_write_cfg->size));

	cci_i2c_write_cfg_w->addr_type = cci_i2c_write_cfg->addr_type;
	cci_i2c_write_cfg_w->addr_type = cci_i2c_write_cfg->addr_type;
	cci_i2c_write_cfg_w->data_type = cci_i2c_write_cfg->data_type;
	cci_i2c_write_cfg_w->size = cci_i2c_write_cfg->size;
	cci_i2c_write_cfg_w->delay = cci_i2c_write_cfg->delay;

	write_async->workq_scheduled_ts = ktime_get();
	queue_work(cci_dev->write_wq[write_async->queue], &write_async->work);

	return rc;
}

static int32_t cam_cci_read_bytes_v_1_2(struct v4l2_subdev *sd,
	struct cam_cci_ctrl *c_ctrl)
{
	int32_t rc = 0;
	struct cci_device *cci_dev = NULL;
	enum cci_i2c_master_t master;
	struct cam_cci_read_cfg *read_cfg = NULL;
	uint16_t read_bytes = 0;

	if (!sd || !c_ctrl) {
		CAM_ERR(CAM_CCI, "sd %pK c_ctrl %pK",
			sd, c_ctrl);
		return -EINVAL;
	}
	if (!c_ctrl->cci_info) {
		CAM_ERR(CAM_CCI, "cci_info NULL");
		return -EINVAL;
	}
	cci_dev = v4l2_get_subdevdata(sd);
	if (!cci_dev) {
		CAM_ERR(CAM_CCI, "cci_dev NULL");
		return -EINVAL;
	}
	if (cci_dev->cci_state != CCI_STATE_ENABLED) {
		CAM_ERR(CAM_CCI, "invalid CCI:%d state %d",
			cci_dev->soc_info.index, cci_dev->cci_state);
		return -EINVAL;
	}

	if (c_ctrl->cci_info->cci_i2c_master >= MASTER_MAX
			|| c_ctrl->cci_info->cci_i2c_master < 0) {
		CAM_ERR(CAM_CCI, "Invalid I2C master addr");
		return -EINVAL;
	}

	master = c_ctrl->cci_info->cci_i2c_master;
	read_cfg = &c_ctrl->cfg.cci_i2c_read_cfg;
	if ((!read_cfg->num_byte) || (read_cfg->num_byte > CCI_I2C_MAX_READ)) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d read num bytes 0",
			cci_dev->soc_info.index, master);
		rc = -EINVAL;
		goto ERROR;
	}

	reinit_completion(&cci_dev->cci_master_info[master].rd_done);
	read_bytes = read_cfg->num_byte;
	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d Bytes to read %u",
		cci_dev->soc_info.index, master, read_bytes);
	do {
		if (read_bytes >= CCI_READ_MAX_V_1_2)
			read_cfg->num_byte = CCI_READ_MAX_V_1_2;
		else
			read_cfg->num_byte = read_bytes;

		cci_dev->is_burst_read[master] = false;
		rc = cam_cci_read(sd, c_ctrl);
		if (rc) {
			if (cci_dev->is_probing)
				CAM_INFO(CAM_CCI, "CCI%d_I2C_M%d failed to read rc: %d",
					cci_dev->soc_info.index, master, rc);
			else
				CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d failed to read rc: %d",
					cci_dev->soc_info.index, master, rc);
			goto ERROR;
		}

		if (read_bytes >= CCI_READ_MAX_V_1_2) {
			read_cfg->addr += CCI_READ_MAX_V_1_2;
			read_cfg->data += CCI_READ_MAX_V_1_2;
			read_bytes -= CCI_READ_MAX_V_1_2;
		} else {
			read_bytes = 0;
		}
	} while (read_bytes);

ERROR:
	return rc;
}

static int32_t cam_cci_read_bytes(struct v4l2_subdev *sd,
	struct cam_cci_ctrl *c_ctrl)
{
	int32_t rc = 0;
	struct cci_device *cci_dev = NULL;
	enum cci_i2c_master_t master;
	struct cam_cci_read_cfg *read_cfg = NULL;
	uint16_t read_bytes = 0;

	if (!sd || !c_ctrl) {
		CAM_ERR(CAM_CCI, "Invalid arg sd %pK c_ctrl %pK",
			sd, c_ctrl);
		return -EINVAL;
	}
	if (!c_ctrl->cci_info) {
		CAM_ERR(CAM_CCI, "cci_info NULL");
		return -EINVAL;
	}
	cci_dev = v4l2_get_subdevdata(sd);
	if (!cci_dev) {
		CAM_ERR(CAM_CCI, "cci_dev NULL");
		return -EINVAL;
	}
	if (cci_dev->cci_state != CCI_STATE_ENABLED) {
		CAM_ERR(CAM_CCI, "invalid CCI:%d state %d",
			cci_dev->soc_info.index, cci_dev->cci_state);
		return -EINVAL;
	}

	if (c_ctrl->cci_info->cci_i2c_master >= MASTER_MAX
			|| c_ctrl->cci_info->cci_i2c_master < 0) {
		CAM_ERR(CAM_CCI, "Invalid I2C master addr");
		return -EINVAL;
	}

	cci_dev->is_probing = c_ctrl->is_probing;

	master = c_ctrl->cci_info->cci_i2c_master;
	read_cfg = &c_ctrl->cfg.cci_i2c_read_cfg;
	if ((!read_cfg->num_byte) || (read_cfg->num_byte > CCI_I2C_MAX_READ)) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d read num bytes 0",
			cci_dev->soc_info.index, master);
		rc = -EINVAL;
		goto ERROR;
	}

	read_bytes = read_cfg->num_byte;

	/*
	 * To avoid any conflicts due to back to back trigger of
	 * THRESHOLD irq's, we reinit the threshold wait before
	 * we load the burst read cmd.
	 */
	mutex_lock(&cci_dev->cci_master_info[master].mutex_q[QUEUE_1]);
	reinit_completion(&cci_dev->cci_master_info[master].rd_done);
	reinit_completion(&cci_dev->cci_master_info[master].th_complete);
	mutex_unlock(&cci_dev->cci_master_info[master].mutex_q[QUEUE_1]);

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d Bytes to read %u",
		cci_dev->soc_info.index, master, read_bytes);
	do {
		if (read_bytes >= CCI_I2C_MAX_BYTE_COUNT)
			read_cfg->num_byte = CCI_I2C_MAX_BYTE_COUNT;
		else
			read_cfg->num_byte = read_bytes;

		if (read_cfg->num_byte >= CCI_READ_MAX) {
			rc = cam_cci_burst_read(sd, c_ctrl);
		} else {
			rc = cam_cci_read(sd, c_ctrl);
		}
		if (rc) {
			if (cci_dev->is_probing)
				CAM_INFO(CAM_CCI, "CCI%d_I2C_M%d Failed to read rc:%d",
					cci_dev->soc_info.index, master, rc);
			else
				CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d Failed to read rc:%d",
					cci_dev->soc_info.index, master, rc);
			goto ERROR;
		}

		if (read_bytes >= CCI_I2C_MAX_BYTE_COUNT) {
			read_cfg->addr += (CCI_I2C_MAX_BYTE_COUNT /
				read_cfg->data_type);
			read_cfg->data += CCI_I2C_MAX_BYTE_COUNT;
			read_bytes -= CCI_I2C_MAX_BYTE_COUNT;
		} else {
			read_bytes = 0;
		}
	} while (read_bytes);

ERROR:
	return rc;
}

static int32_t cam_cci_i2c_set_sync_prms(struct v4l2_subdev *sd,
	struct cam_cci_ctrl *c_ctrl)
{
	int32_t rc = 0;
	struct cci_device *cci_dev;

	cci_dev = v4l2_get_subdevdata(sd);
	if (!cci_dev || !c_ctrl) {
		CAM_ERR(CAM_CCI,
			"Failed: invalid params cci_dev:%pK, c_ctrl:%pK",
			cci_dev, c_ctrl);
		rc = -EINVAL;
		return rc;
	}
	cci_dev->cci_wait_sync_cfg = c_ctrl->cfg.cci_wait_sync_cfg;
	cci_dev->valid_sync = cci_dev->cci_wait_sync_cfg.csid < 0 ? 0 : 1;

	return rc;
}

static int32_t cam_cci_release(struct v4l2_subdev *sd,
	enum cci_i2c_master_t master)
{
	uint8_t rc = 0;
	struct cci_device *cci_dev;

	cci_dev = v4l2_get_subdevdata(sd);
	if (!cci_dev) {
		CAM_ERR(CAM_CCI, "cci_dev NULL");
		return -EINVAL;
	}

	rc = cam_cci_soc_release(cci_dev, master);
	if (rc < 0) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d Failed in releasing the rc: %d",
			cci_dev->soc_info.index, master, rc);
		return rc;
	}

	return rc;
}

static int32_t cam_cci_write(struct v4l2_subdev *sd,
	struct cam_cci_ctrl *c_ctrl)
{
	int32_t rc = 0;
	struct cci_device *cci_dev;
	enum cci_i2c_master_t master;
	struct cam_cci_master_info *cci_master_info;
	uint32_t i;

	cci_dev = v4l2_get_subdevdata(sd);
	if (!cci_dev || !c_ctrl) {
		CAM_ERR(CAM_CCI,
			"Failed: invalid params cci_dev:%pK, c_ctrl:%pK",
			cci_dev, c_ctrl);
		rc = -EINVAL;
		return rc;
	}

	master = c_ctrl->cci_info->cci_i2c_master;

	if (c_ctrl->cci_info->cci_i2c_master >= MASTER_MAX
		|| c_ctrl->cci_info->cci_i2c_master < 0) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d Invalid I2C master addr", cci_dev->soc_info.index, master);
		return -EINVAL;
	}

	cci_master_info = &cci_dev->cci_master_info[master];

	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d ctrl_cmd = %d", cci_dev->soc_info.index, master, c_ctrl->cmd);

	switch (c_ctrl->cmd) {
	case MSM_CCI_I2C_WRITE_SYNC_BLOCK:
		mutex_lock(&cci_master_info->mutex_q[SYNC_QUEUE]);
		rc = cam_cci_i2c_write(sd, c_ctrl,
			SYNC_QUEUE, MSM_SYNC_ENABLE);
		mutex_unlock(&cci_master_info->mutex_q[SYNC_QUEUE]);
		break;
	case MSM_CCI_I2C_WRITE_SYNC:
		rc = cam_cci_i2c_write_async(sd, c_ctrl,
			SYNC_QUEUE, MSM_SYNC_ENABLE);
		break;
	case MSM_CCI_I2C_WRITE:
		for (i = 0; i < NUM_QUEUES; i++) {
			if (mutex_trylock(&cci_master_info->mutex_q[i])) {
				rc = cam_cci_i2c_write(sd, c_ctrl, i,
					MSM_SYNC_DISABLE);
				mutex_unlock(&cci_master_info->mutex_q[i]);
				return rc;
			}
		}
		mutex_lock(&cci_master_info->mutex_q[PRIORITY_QUEUE]);
		rc = cam_cci_i2c_write(sd, c_ctrl,
			PRIORITY_QUEUE, MSM_SYNC_DISABLE);
		mutex_unlock(&cci_master_info->mutex_q[PRIORITY_QUEUE]);
		break;
	case MSM_CCI_I2C_WRITE_SEQ:
	case MSM_CCI_I2C_WRITE_BURST:
		mutex_lock(&cci_master_info->mutex_q[PRIORITY_QUEUE]);
		rc = cam_cci_i2c_write(sd, c_ctrl,
			PRIORITY_QUEUE, MSM_SYNC_DISABLE);
		mutex_unlock(&cci_master_info->mutex_q[PRIORITY_QUEUE]);
		break;
	case MSM_CCI_I2C_WRITE_ASYNC:
		rc = cam_cci_i2c_write_async(sd, c_ctrl,
			PRIORITY_QUEUE, MSM_SYNC_DISABLE);
		break;
	default:
		rc = -ENOIOCTLCMD;
	}

	return rc;
}

int32_t cam_cci_core_cfg(struct v4l2_subdev *sd,
	struct cam_cci_ctrl *cci_ctrl)
{
	int32_t rc = 0;
	struct cci_device *cci_dev = v4l2_get_subdevdata(sd);
	enum cci_i2c_master_t master = MASTER_MAX;

	if (!cci_dev) {
		CAM_ERR(CAM_CCI, "CCI_DEV is null");
		return -EINVAL;
	}

	if (!cci_ctrl || !cci_ctrl->cci_info) {
		CAM_ERR(CAM_CCI, "CCI%d_I2C_M%d CCI_CTRL OR CCI_INFO IS NULL",
			cci_dev->soc_info.index, master);
		return -EINVAL;
	}

	master = cci_ctrl->cci_info->cci_i2c_master;
	if (master >= MASTER_MAX) {
		CAM_ERR(CAM_CCI, "INVALID MASTER: %d", master);
		return -EINVAL;
	}

	if ((cci_dev->cci_master_info[master].status < 0) && (cci_ctrl->cmd != MSM_CCI_RELEASE)) {
		CAM_WARN(CAM_CCI, "CCI hardware is resetting");
		return -EAGAIN;
	}
	cci_dev->is_probing = false;
	CAM_DBG(CAM_CCI, "CCI%d_I2C_M%d cmd = %d", cci_dev->soc_info.index, master, cci_ctrl->cmd);

	switch (cci_ctrl->cmd) {
	case MSM_CCI_INIT:
		mutex_lock(&cci_dev->init_mutex);
		rc = cam_cci_init(sd, cci_ctrl);
		mutex_unlock(&cci_dev->init_mutex);
		break;
	case MSM_CCI_RELEASE:
		mutex_lock(&cci_dev->init_mutex);
		rc = cam_cci_release(sd, master);
		mutex_unlock(&cci_dev->init_mutex);
		break;
	case MSM_CCI_I2C_READ:
		/*
		 * CCI version 1.2 does not support burst read
		 * due to the absence of the read threshold register
		 */
		if (cci_dev->hw_version == CCI_VERSION_1_2_9) {
			CAM_DBG(CAM_CCI, "cci-v1.2 no burst read");
			rc = cam_cci_read_bytes_v_1_2(sd, cci_ctrl);
		} else {
			rc = cam_cci_read_bytes(sd, cci_ctrl);
		}
		break;
	case MSM_CCI_I2C_WRITE:
	case MSM_CCI_I2C_WRITE_SEQ:
	case MSM_CCI_I2C_WRITE_BURST:
	case MSM_CCI_I2C_WRITE_SYNC:
	case MSM_CCI_I2C_WRITE_ASYNC:
	case MSM_CCI_I2C_WRITE_SYNC_BLOCK:
		rc = cam_cci_write(sd, cci_ctrl);
		break;
	case MSM_CCI_GPIO_WRITE:
		break;
	case MSM_CCI_SET_SYNC_CID:
		rc = cam_cci_i2c_set_sync_prms(sd, cci_ctrl);
		break;

	default:
		rc = -ENOIOCTLCMD;
	}

	cci_ctrl->status = rc;

	return rc;
}

#ifdef OPLUS_FEATURE_CAMERA_COMMON
#define MAX_WRITE_ARRAY_SIZE   300
static struct cam_cci_ctrl cci_ctrl_interface;
static struct cam_sensor_cci_client cci_ctrl_interface_info;
static struct cam_sensor_i2c_reg_array write_regarray[MAX_WRITE_ARRAY_SIZE];
extern bool dump_tof_registers;

int32_t cam_cci_read_packet(struct cam_cci_ctrl *cci_ctrl,
	uint32_t addr, uint8_t *data,uint32_t count)
{
	int32_t rc = -EINVAL;

	cci_ctrl->cmd = MSM_CCI_I2C_READ;
	cci_ctrl->cfg.cci_i2c_read_cfg.addr = addr;
	cci_ctrl->cfg.cci_i2c_read_cfg.addr_type = CAMERA_SENSOR_I2C_TYPE_BYTE;
	cci_ctrl->cfg.cci_i2c_read_cfg.data_type = CAMERA_SENSOR_I2C_TYPE_BYTE;
	cci_ctrl->cfg.cci_i2c_read_cfg.data = data;
	cci_ctrl->cfg.cci_i2c_read_cfg.num_byte = count;

	rc = cci_ctrl->status;
	return rc;
}

static int32_t cam_cci_write_packet(
	struct cam_cci_ctrl *cci_ctrl,
	int addr,
	uint8_t *data,
	uint16_t count)
{
	int32_t rc = 0;
	int i;
	memset(write_regarray,0,sizeof(write_regarray));
	if (!cci_ctrl || !data)
		return rc;
	if(count > MAX_WRITE_ARRAY_SIZE){
		CAM_ERR(CAM_SENSOR, "fatal error!!count exceeds 300,count=%d",
			count);
		count = MAX_WRITE_ARRAY_SIZE;
	}
	for(i=0; i<count; i++){
		write_regarray[i].reg_addr = addr+i;
		write_regarray[i].reg_data = data[i];
	}
	cci_ctrl->cfg.cci_i2c_write_cfg.reg_setting =
		write_regarray;
	cci_ctrl->cfg.cci_i2c_write_cfg.data_type = CAMERA_SENSOR_I2C_TYPE_BYTE;
	cci_ctrl->cfg.cci_i2c_write_cfg.addr_type = CAMERA_SENSOR_I2C_TYPE_BYTE;
	cci_ctrl->cfg.cci_i2c_write_cfg.size = count;

	if (rc < 0) {
		CAM_ERR(CAM_SENSOR, "Failed rc = %d", rc);
		return rc;
	}
	rc = cci_ctrl->status;
	//if (write_setting->delay > 20)
	//	  msleep(write_setting->delay);
	//else if (write_setting->delay)
	//	  usleep_range(write_setting->delay * 1000, (write_setting->delay
	//		  * 1000) + 1000);

	return rc;
}

int32_t cam_cci_control_interface(void* control)
{

	int32_t rc = 0,exp_byte;
	struct v4l2_subdev *sd = cam_cci_get_subdev(CCI_DEVICE_1);
	struct cci_device *cci_dev = v4l2_get_subdevdata(sd);
	struct camera_cci_transfer* pControl = (struct camera_cci_transfer*)control;
        int i=0;

	switch (pControl->cmd) {
	case CAMERA_CCI_INIT:
		memset(&cci_ctrl_interface,0,sizeof(cci_ctrl_interface));
		memset(&cci_ctrl_interface_info,0,sizeof(cci_ctrl_interface_info));
		cci_ctrl_interface.cci_info = &cci_ctrl_interface_info;
		cci_ctrl_interface.cci_info->cci_i2c_master = MASTER_1;
		cci_ctrl_interface.cci_info->i2c_freq_mode = I2C_FAST_PLUS_MODE;
		cci_ctrl_interface.cci_info->sid = (0x82 >> 1);
		cci_ctrl_interface.cci_info->retries = 3;
                cci_ctrl_interface.cci_info->cci_device = CCI_DEVICE_1;
		mutex_lock(&cci_dev->init_mutex);
		rc = cam_cci_init(sd, &cci_ctrl_interface);
		mutex_unlock(&cci_dev->init_mutex);
		CAM_INFO(CAM_CCI, "cci init cmd,rc=%d",rc);
		break;
	case CAMERA_CCI_RELEASE:
		mutex_lock(&cci_dev->init_mutex);
		rc = cam_cci_release(sd, cci_ctrl_interface.cci_info->cci_i2c_master);
		mutex_unlock(&cci_dev->init_mutex);
		CAM_INFO(CAM_CCI, "cci release cmd,rc=%d",rc);
		break;
	case CAMERA_CCI_READ:
		cci_ctrl_interface.cmd = MSM_CCI_I2C_READ;
		//pack read data
		cam_cci_read_packet(&cci_ctrl_interface,
							pControl->addr,
							pControl->data,
							pControl->count);
		mutex_lock(&cci_dev->init_mutex);
                cci_ctrl_interface.cci_info->cci_device=CCI_DEVICE_1;
		rc = cam_cci_read_bytes(sd, &cci_ctrl_interface);
		mutex_unlock(&cci_dev->init_mutex);
                if(dump_tof_registers){
		        CAM_ERR(CAM_CCI, "tof_registers %d,rc=%d", pControl->cmd,rc);
		        exp_byte = cci_ctrl_interface.cfg.cci_i2c_read_cfg.num_byte;//((cci_ctrl_interface.cfg.cci_i2c_read_cfg.num_byte / 2) + 1);
		        CAM_ERR(CAM_CCI, "tof_registers read exp byte=%d", exp_byte);
		        for(i=0; i<exp_byte; i++){
			        CAM_ERR(CAM_CCI, "tof_registers read addr =0x%x byte=0x%x,index=%d",
				        cci_ctrl_interface.cfg.cci_i2c_read_cfg.addr,cci_ctrl_interface.cfg.cci_i2c_read_cfg.data[i],i);
		        }
                }
		break;
	case CAMERA_CCI_WRITE:
		//if(pControl->count>1)
		//	  cci_ctrl_interface.cmd = MSM_CCI_I2C_WRITE_SEQ;
		//else
		//	  cci_ctrl_interface.cmd = MSM_CCI_I2C_WRITE_SYNC_BLOCK;
		cci_ctrl_interface.cmd = MSM_CCI_I2C_WRITE;
		//pack write data
		cam_cci_write_packet(&cci_ctrl_interface,
							pControl->addr,
							pControl->data,
							pControl->count);
		mutex_lock(&cci_dev->init_mutex);
		rc = cam_cci_write(sd, &cci_ctrl_interface);
		mutex_unlock(&cci_dev->init_mutex);
                if(dump_tof_registers){
		        exp_byte = cci_ctrl_interface.cfg.cci_i2c_write_cfg.size;
		        CAM_ERR(CAM_CCI, "tof_registers write exp byte=%d", exp_byte);
		        for(i=0; i<exp_byte; i++){
			        CAM_ERR(CAM_CCI, "tof_registers write i=%d,addr=0x%x data=0x%x",i,
				        cci_ctrl_interface.cfg.cci_i2c_write_cfg.reg_setting[i].reg_addr,
				        cci_ctrl_interface.cfg.cci_i2c_write_cfg.reg_setting[i].reg_data);
		        }
                }
		if(rc < 0){
			CAM_ERR(CAM_CCI, "cmd %d,rc=%d",pControl->cmd,rc);
		}
		break;
	default:
		rc = -ENOIOCTLCMD;
	}

	cci_ctrl_interface.status = rc;
	return rc;
}
#endif
