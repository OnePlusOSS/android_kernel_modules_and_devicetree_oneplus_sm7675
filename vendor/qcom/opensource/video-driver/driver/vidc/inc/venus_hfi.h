/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _VENUS_HFI_H_
#define _VENUS_HFI_H_

#include <linux/irqreturn.h>
#include <linux/clk.h>
#include <linux/regulator/consumer.h>
#include <linux/clk-provider.h>

#include "msm_vidc_internal.h"
#include "msm_vidc_inst.h"
#include "msm_vidc_core.h"

#define VIDC_MAX_PC_SKIP_COUNT	10

struct vidc_buffer_addr_info {
	enum msm_vidc_buffer_type buffer_type;
	u32 buffer_size;
	u32 num_buffers;
	u32 align_device_addr;
	u32 extradata_addr;
	u32 extradata_size;
	u32 response_required;
};

struct hfi_pending_packet {
	struct list_head       list;
	void                  *data;
};

int __strict_check(struct msm_vidc_core *core,
		   const char *function);
int venus_hfi_session_property(struct msm_vidc_inst *inst,
			       u32 pkt_type, u32 flags, u32 port,
			       u32 payload_type, void *payload,
			       u32 payload_size);
int venus_hfi_session_command(struct msm_vidc_inst *inst,
			      u32 cmd, enum msm_vidc_port_type port,
			      u32 payload_type,
			      void *payload, u32 payload_size);
int venus_hfi_queue_buffer(struct msm_vidc_inst *inst,
			   struct msm_vidc_buffer *buffer,
			   struct msm_vidc_buffer *metabuf);
int venus_hfi_queue_super_buffer(struct msm_vidc_inst *inst,
				 struct msm_vidc_buffer *buffer,
				 struct msm_vidc_buffer *metabuf);
int venus_hfi_release_buffer(struct msm_vidc_inst *inst,
			     struct msm_vidc_buffer *buffer);
int venus_hfi_start(struct msm_vidc_inst *inst, enum msm_vidc_port_type port);
int venus_hfi_stop(struct msm_vidc_inst *inst, enum msm_vidc_port_type port);
int venus_hfi_session_close(struct msm_vidc_inst *inst);
int venus_hfi_session_open(struct msm_vidc_inst *inst);
int venus_hfi_session_pause(struct msm_vidc_inst *inst, enum msm_vidc_port_type port);
int venus_hfi_session_resume(struct msm_vidc_inst *inst,
			     enum msm_vidc_port_type port, u32 payload);
int venus_hfi_session_drain(struct msm_vidc_inst *inst, enum msm_vidc_port_type port);
int venus_hfi_session_set_codec(struct msm_vidc_inst *inst);
int venus_hfi_session_set_secure_mode(struct msm_vidc_inst *inst);
int venus_hfi_core_init(struct msm_vidc_core *core);
int venus_hfi_core_deinit(struct msm_vidc_core *core, bool force);
int venus_hfi_noc_error_info(struct msm_vidc_core *core);
int venus_hfi_suspend(struct msm_vidc_core *core);
bool is_ssr_type_allowed(struct msm_vidc_core *core, u32 type);
int venus_hfi_trigger_ssr(struct msm_vidc_core *core, u32 type,
			  u32 client_id, u32 addr);
int venus_hfi_trigger_stability(struct msm_vidc_inst *inst, u32 type,
				u32 client_id, u32 val);
int venus_hfi_reserve_hardware(struct msm_vidc_inst *inst, u32 duration);
int venus_hfi_scale_clocks(struct msm_vidc_inst *inst, u64 freq);
int venus_hfi_scale_buses(struct msm_vidc_inst *inst, u64 bw_ddr, u64 bw_llcc);
int venus_hfi_set_ir_period(struct msm_vidc_inst *inst, u32 ir_type,
			    enum msm_vidc_inst_capability_type cap_id);
void venus_hfi_pm_work_handler(struct work_struct *work);
irqreturn_t venus_hfi_isr(int irq, void *data);
irqreturn_t venus_hfi_isr_handler(int irq, void *data);
int __prepare_pc(struct msm_vidc_core *core);
struct device_region_info
	*venus_hfi_get_device_region_info(struct msm_vidc_core *core,
					  enum msm_vidc_device_region region);

#endif // _VENUS_HFI_H_
