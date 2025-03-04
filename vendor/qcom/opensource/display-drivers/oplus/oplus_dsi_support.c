/***************************************************************
** Copyright (C), 2022, OPLUS Mobile Comm Corp., Ltd
**
** File : oplus_dsi_support.c
** Description : display driver private management
** Version : 1.1
** Date : 2020/09/06
** Author : Display
******************************************************************/
#include "oplus_dsi_support.h"
#include "oplus_display_interface.h"
#include <soc/oplus/system/boot_mode.h>
#include <soc/oplus/system/oplus_project.h>
#include <soc/oplus/device_info.h>
#include <linux/notifier.h>
#include <linux/module.h>
#include "dsi_display.h"

#ifdef OPLUS_FEATURE_DISPLAY_ADFR
#include "oplus_adfr.h"
#endif /* OPLUS_FEATURE_DISPLAY_ADFR */

#ifdef OPLUS_FEATURE_DISPLAY_ONSCREENFINGERPRINT
#include "oplus_onscreenfingerprint.h"
#endif /* OPLUS_FEATURE_DISPLAY_ONSCREENFINGERPRINT */

/* log level config */
unsigned int oplus_lcd_log_level = OPLUS_LOG_LEVEL_DEBUG;
EXPORT_SYMBOL(oplus_lcd_log_level);

static enum oplus_display_support_list  oplus_display_vendor =
		OPLUS_DISPLAY_UNKNOW;
static enum oplus_display_power_status oplus_display_status =
		OPLUS_DISPLAY_POWER_OFF;
static BLOCKING_NOTIFIER_HEAD(oplus_display_notifier_list);
/* add for dual panel */
static struct dsi_display *current_display = NULL;

int oplus_display_register_client(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&oplus_display_notifier_list, nb);
}
EXPORT_SYMBOL(oplus_display_register_client);


int oplus_display_unregister_client(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&oplus_display_notifier_list,
			nb);
}
EXPORT_SYMBOL(oplus_display_unregister_client);

static int oplus_display_notifier_call_chain(unsigned long val, void *v)
{
	return blocking_notifier_call_chain(&oplus_display_notifier_list, val, v);
}

bool oplus_is_correct_display(enum oplus_display_support_list lcd_name)
{
	return (oplus_display_vendor == lcd_name ? true : false);
}

bool oplus_is_silence_reboot(void)
{
	LCD_INFO("get_boot_mode = %d\n", get_boot_mode());
	if ((MSM_BOOT_MODE__SILENCE == get_boot_mode())
			|| (MSM_BOOT_MODE__SAU == get_boot_mode())) {
		return true;

	} else {
		return false;
	}
	return false;
}
EXPORT_SYMBOL(oplus_is_silence_reboot);

bool oplus_is_factory_boot(void)
{
	LCD_INFO("get_boot_mode = %d\n", get_boot_mode());
	if ((MSM_BOOT_MODE__FACTORY == get_boot_mode())
			|| (MSM_BOOT_MODE__RF == get_boot_mode())
			|| (MSM_BOOT_MODE__WLAN == get_boot_mode())
			|| (MSM_BOOT_MODE__MOS == get_boot_mode())) {
		return true;
	} else {
		return false;
	}
	return false;
}
EXPORT_SYMBOL(oplus_is_factory_boot);

void oplus_display_notifier_early_status(enum oplus_display_power_status
					power_status)
{
	int blank;
	OPLUS_DISPLAY_NOTIFIER_EVENT oplus_notifier_data;

	switch (power_status) {
	case OPLUS_DISPLAY_POWER_ON:
		blank = OPLUS_DISPLAY_POWER_ON;
		oplus_notifier_data.data = &blank;
		oplus_notifier_data.status = OPLUS_DISPLAY_POWER_ON;
		oplus_display_notifier_call_chain(OPLUS_DISPLAY_EARLY_EVENT_BLANK,
				&oplus_notifier_data);
		break;
	case OPLUS_DISPLAY_POWER_DOZE:
		blank = OPLUS_DISPLAY_POWER_DOZE;
		oplus_notifier_data.data = &blank;
		oplus_notifier_data.status = OPLUS_DISPLAY_POWER_DOZE;
		oplus_display_notifier_call_chain(OPLUS_DISPLAY_EARLY_EVENT_BLANK,
				&oplus_notifier_data);
		break;
	case OPLUS_DISPLAY_POWER_DOZE_SUSPEND:
		blank = OPLUS_DISPLAY_POWER_DOZE_SUSPEND;
		oplus_notifier_data.data = &blank;
		oplus_notifier_data.status = OPLUS_DISPLAY_POWER_DOZE_SUSPEND;
		oplus_display_notifier_call_chain(OPLUS_DISPLAY_EARLY_EVENT_BLANK,
				&oplus_notifier_data);
		break;
	case OPLUS_DISPLAY_POWER_OFF:
		blank = OPLUS_DISPLAY_POWER_OFF;
		oplus_notifier_data.data = &blank;
		oplus_notifier_data.status = OPLUS_DISPLAY_POWER_OFF;
		oplus_display_notifier_call_chain(OPLUS_DISPLAY_EARLY_EVENT_BLANK,
				&oplus_notifier_data);
		break;
	default:
		break;
	}
}

void oplus_display_notifier_status(enum oplus_display_power_status power_status)
{
	int blank;
	OPLUS_DISPLAY_NOTIFIER_EVENT oplus_notifier_data;

	switch (power_status) {
	case OPLUS_DISPLAY_POWER_ON:
		blank = OPLUS_DISPLAY_POWER_ON;
		oplus_notifier_data.data = &blank;
		oplus_notifier_data.status = OPLUS_DISPLAY_POWER_ON;
		oplus_display_notifier_call_chain(OPLUS_DISPLAY_EVENT_BLANK,
				&oplus_notifier_data);
		break;
	case OPLUS_DISPLAY_POWER_DOZE:
		blank = OPLUS_DISPLAY_POWER_DOZE;
		oplus_notifier_data.data = &blank;
		oplus_notifier_data.status = OPLUS_DISPLAY_POWER_DOZE;
		oplus_display_notifier_call_chain(OPLUS_DISPLAY_EVENT_BLANK,
				&oplus_notifier_data);
		break;
	case OPLUS_DISPLAY_POWER_DOZE_SUSPEND:
		blank = OPLUS_DISPLAY_POWER_DOZE_SUSPEND;
		oplus_notifier_data.data = &blank;
		oplus_notifier_data.status = OPLUS_DISPLAY_POWER_DOZE_SUSPEND;
		oplus_display_notifier_call_chain(OPLUS_DISPLAY_EVENT_BLANK,
				&oplus_notifier_data);
		break;
	case OPLUS_DISPLAY_POWER_OFF:
		blank = OPLUS_DISPLAY_POWER_OFF;
		oplus_notifier_data.data = &blank;
		oplus_notifier_data.status = OPLUS_DISPLAY_POWER_OFF;
		oplus_display_notifier_call_chain(OPLUS_DISPLAY_EVENT_BLANK,
				&oplus_notifier_data);
		break;
	default:
		break;
	}
}

void __oplus_set_power_status(enum oplus_display_power_status power_status)
{
	oplus_display_status = power_status;
}
EXPORT_SYMBOL(__oplus_set_power_status);

enum oplus_display_power_status __oplus_get_power_status(void)
{
	return oplus_display_status;
}
EXPORT_SYMBOL(__oplus_get_power_status);

bool oplus_display_is_support_feature(enum oplus_display_feature feature_name)
{
	bool ret = false;

	switch (feature_name) {
	case OPLUS_DISPLAY_HDR:
		ret = false;
		break;
	case OPLUS_DISPLAY_SEED:
		ret = true;
		break;
	case OPLUS_DISPLAY_HBM:
		ret = true;
		break;
	case OPLUS_DISPLAY_LBR:
		ret = true;
		break;
	case OPLUS_DISPLAY_AOD:
		ret = true;
		break;
	case OPLUS_DISPLAY_ULPS:
		ret = false;
		break;
	case OPLUS_DISPLAY_ESD_CHECK:
		ret = true;
		break;
	case OPLUS_DISPLAY_DYNAMIC_MIPI:
		ret = true;
		break;
	case OPLUS_DISPLAY_PARTIAL_UPDATE:
		ret = false;
		break;
	default:
		break;
	}

	return ret;
}

/* add for dual panel */
void oplus_display_set_current_display(void *dsi_display)
{
	struct dsi_display *display = dsi_display;
	current_display = display;
}

/* update current display when panel is enabled and disabled */
void oplus_display_update_current_display(void)
{
	struct dsi_display *primary_display = get_main_display();
	struct dsi_display *secondary_display = get_sec_display();

	LCD_DEBUG("start\n");

	if ((!primary_display && !secondary_display) || (!primary_display->panel && !secondary_display->panel)) {
		current_display = NULL;
	} else if ((primary_display && !secondary_display) || (primary_display->panel && !secondary_display->panel)) {
		current_display = primary_display;
	} else if ((!primary_display && secondary_display) || (!primary_display->panel && secondary_display->panel)) {
		current_display = secondary_display;
	} else if (primary_display->panel->panel_initialized && !secondary_display->panel->panel_initialized) {
		current_display = primary_display;
	} else if (!primary_display->panel->panel_initialized && secondary_display->panel->panel_initialized) {
		current_display = secondary_display;
	} else if (primary_display->panel->panel_initialized && secondary_display->panel->panel_initialized) {
		current_display = primary_display;
	}

#ifdef OPLUS_FEATURE_DISPLAY_ADFR
	oplus_adfr_update_display_id();
#endif /* OPLUS_FEATURE_DISPLAY_ADFR */

#ifdef OPLUS_FEATURE_DISPLAY_ONSCREENFINGERPRINT
	if (oplus_ofp_is_supported()) {
		oplus_ofp_update_display_id();
	}
#endif /* OPLUS_FEATURE_DISPLAY_ONSCREENFINGERPRINT */

	LCD_DEBUG("end\n");

	return;
}

struct dsi_display *oplus_display_get_current_display(void)
{
	return current_display;
}

#define A0020_GAMMA_COMPENSATION_READ_RETRY_MAX 5
#define A0020_GAMMA_COMPENSATION_PERCENTAGE1 70/100
#define REG_SIZE 256
#define OPLUS_DSI_CMD_PRINT_BUF_SIZE 1024
#define A0020_GAMMA_COMPENSATION_READ_LENGTH 6
#define A0020_GAMMA_COMPENSATION_READ_REG 0x82
#define A0020_GAMMA_COMPENSATION_BAND_REG 0x99

#define A0020_GAMMA_COMPENSATION_BAND_VALUE1 0x97
#define A0020_GAMMA_COMPENSATION_BAND_VALUE2 0xBB

static int oplus_panel_gamma_compensation_read_reg(struct dsi_panel *panel, struct dsi_display_ctrl *m_ctrl, char *regs, u8 page_value)
{
	int rc = 0;
	u32 cnt = 0;
	int index = 0;
	u8 cmd = A0020_GAMMA_COMPENSATION_BAND_REG;
	size_t replace_reg_len = 1;
	char replace_reg[REG_SIZE] = {0};
	char print_buf[OPLUS_DSI_CMD_PRINT_BUF_SIZE] = {0};

	memset(replace_reg, 0, sizeof(replace_reg));
	replace_reg[0] = page_value;
	rc = oplus_panel_cmd_reg_replace(panel, DSI_CMD_GAMMA_COMPENSATION_PAGE1, cmd, replace_reg, replace_reg_len);
	if (rc) {
		DSI_ERR("oplus panel cmd reg replace failed, retry\n");
		return rc;
	}
	rc = dsi_panel_tx_cmd_set(panel, DSI_CMD_GAMMA_COMPENSATION_PAGE1);
	if (rc) {
		DSI_ERR("send DSI_CMD_GAMMA_COMPENSATION_PAGE1 failed, retry\n");
		return rc;
	}

	/* Read back the A0020_GAMMA_COMPENSATION_READ_REG register, A0020_GAMMA_COMPENSATION_READ_LENGTH*/
	rc = dsi_panel_read_panel_reg_unlock(m_ctrl, panel, A0020_GAMMA_COMPENSATION_READ_REG,
			regs, A0020_GAMMA_COMPENSATION_READ_LENGTH);
	if (rc < 0) {
		DSI_ERR("failed to read A0020_GAMMA_COMPENSATION_READ_REG rc=%d\n", rc);
		return rc;
	}

	cnt = 0;
	memset(print_buf, 0, OPLUS_DSI_CMD_PRINT_BUF_SIZE);
	for (index = 0; index < A0020_GAMMA_COMPENSATION_READ_LENGTH; index++) {
		cnt += snprintf(print_buf + cnt, OPLUS_DSI_CMD_PRINT_BUF_SIZE - cnt, "%02X ", regs[index]);
	}
	LCD_INFO("read regs0x%02X len=%d, buf=[%s]\n", page_value, A0020_GAMMA_COMPENSATION_READ_LENGTH, print_buf);

	return 0;
}

bool g_gamma_regs_read_done = false;
EXPORT_SYMBOL(g_gamma_regs_read_done);
int oplus_display_panel_A0020_gamma_compensation(struct dsi_display *display)
{
	u32 retry_count = 0;
	u32 index = 0;
	int rc = 0;
	u32 cnt = 0;
	u32 reg_tmp = 0;
	struct dsi_display_mode *mode = NULL;
	char print_buf[OPLUS_DSI_CMD_PRINT_BUF_SIZE] = {0};
	struct dsi_display_ctrl *m_ctrl = NULL;
	struct dsi_panel *panel = display->panel;
	char regs1[A0020_GAMMA_COMPENSATION_READ_LENGTH] = {0};
	char regs2[A0020_GAMMA_COMPENSATION_READ_LENGTH] = {0};

	char regs1_last[A0020_GAMMA_COMPENSATION_READ_LENGTH] = {0};
	char regs2_last[A0020_GAMMA_COMPENSATION_READ_LENGTH] = {0};

	const char reg_base[A0020_GAMMA_COMPENSATION_READ_LENGTH] = {0};

	if (!panel) {
		DSI_ERR("panel is null\n");
		return  -EINVAL;
	}

	m_ctrl = &display->ctrl[display->cmd_master_idx];

	if (!m_ctrl) {
		DSI_ERR("ctrl is null\n");
		return -EINVAL;
	}

	if (!panel->oplus_priv.gamma_compensation_support) {
		LCD_INFO("panel gamma compensation isn't supported\n");
		return rc;
	}

	if (display->panel->power_mode != SDE_MODE_DPMS_ON) {
		DSI_ERR("display panel in off status / compensation\n");
		return -EINVAL;
	}
	if (!display->panel->panel_initialized) {
		DSI_ERR("panel initialized = false\n");
		return -EINVAL;
	}

	mutex_lock(&display->display_lock);
	mutex_lock(&display->panel->panel_lock);
	while(!g_gamma_regs_read_done && retry_count < A0020_GAMMA_COMPENSATION_READ_RETRY_MAX) {
		LCD_INFO("read gamma compensation regs, retry_count=%d\n", retry_count);
		memset(regs1, 0, A0020_GAMMA_COMPENSATION_READ_LENGTH);

		rc = oplus_panel_gamma_compensation_read_reg(panel, m_ctrl, regs1, A0020_GAMMA_COMPENSATION_BAND_VALUE1);
		if (rc) {
			DSI_ERR("panel read reg1 failed\n");
			retry_count++;
			continue;
		}

		rc = oplus_panel_gamma_compensation_read_reg(panel, m_ctrl, regs2, A0020_GAMMA_COMPENSATION_BAND_VALUE2);
		if (rc) {
			DSI_ERR("panel read reg1 failed\n");
			retry_count++;
			continue;
		}

		if (!memcmp(regs1, reg_base, sizeof(reg_base)) || memcmp(regs1, regs1_last, sizeof(regs1_last))||
			!memcmp(regs2, reg_base, sizeof(reg_base)) || memcmp(regs2, regs2_last, sizeof(regs2_last))) {
			DSI_WARN("gamma compensation regs is invalid, retry\n");
			memcpy(regs1_last, regs1, A0020_GAMMA_COMPENSATION_READ_LENGTH);
			retry_count++;
			memcpy(regs2_last, regs2, A0020_GAMMA_COMPENSATION_READ_LENGTH);
			retry_count++;
			continue;
		}

		rc = dsi_panel_tx_cmd_set(panel, DSI_CMD_GAMMA_COMPENSATION_PAGE0);
		if (rc) {
			DSI_ERR("send DSI_CMD_GAMMA_COMPENSATION_PAGE0 failed\n");
		}

		g_gamma_regs_read_done = true;
		LCD_INFO("gamma compensation read success");
		break;
	}
	mutex_unlock(&display->panel->panel_lock);
	mutex_unlock(&display->display_lock);

	if (!g_gamma_regs_read_done) {
		return -EFAULT;
	}

	for (index = 0; index < (A0020_GAMMA_COMPENSATION_READ_LENGTH - 1); index = index+2) {
		if(index == 2) {
			reg_tmp = regs1[index] << 8 | regs1[index+1];
			regs1[index] = (reg_tmp*A0020_GAMMA_COMPENSATION_PERCENTAGE1) >> 8 & 0xFF;
			regs1[index+1] = (reg_tmp*A0020_GAMMA_COMPENSATION_PERCENTAGE1) & 0xFF;

			reg_tmp = regs2[index] << 8 | regs2[index+1];
			regs2[index] = (reg_tmp*A0020_GAMMA_COMPENSATION_PERCENTAGE1) >> 8 & 0xFF;
			regs2[index+1] = (reg_tmp*A0020_GAMMA_COMPENSATION_PERCENTAGE1) & 0xFF;
		} else {
			reg_tmp = regs1[index] << 8 | regs1[index+1];
			regs1[index] = (reg_tmp * 0) >> 8 & 0xFF;
			regs1[index+1] = (reg_tmp * 0) & 0xFF;

			reg_tmp = regs2[index] << 8 | regs2[index+1];
			regs2[index] = (reg_tmp * 0) >> 8 & 0xFF;
			regs2[index+1] = (reg_tmp * 0) & 0xFF;
		}
	}
	memset(print_buf, 0, OPLUS_DSI_CMD_PRINT_BUF_SIZE);

	cnt = 0;
	for (index = 0; index < A0020_GAMMA_COMPENSATION_READ_LENGTH; index++) {
		cnt += snprintf(print_buf + cnt, OPLUS_DSI_CMD_PRINT_BUF_SIZE - cnt, "%02X ", regs1[index]);
	}
	LCD_INFO("after switch page 0x97 compensation regs0x%02X len=%d, buf=[%s]\n",
			A0020_GAMMA_COMPENSATION_BAND_VALUE1, A0020_GAMMA_COMPENSATION_READ_LENGTH, print_buf);

	cnt = 0;
	for (index = 0; index < A0020_GAMMA_COMPENSATION_READ_LENGTH; index++) {
		cnt += snprintf(print_buf + cnt, OPLUS_DSI_CMD_PRINT_BUF_SIZE - cnt, "%02X ", regs2[index]);
	}
	LCD_INFO("after switch page 0xBB compensation regs0x%02X len=%d, buf=[%s]\n",
			A0020_GAMMA_COMPENSATION_BAND_VALUE2, A0020_GAMMA_COMPENSATION_READ_LENGTH, print_buf);

	mutex_lock(&display->display_lock);
	mutex_lock(&display->panel->panel_lock);
	for (index = 0; index < display->panel->num_display_modes; index++) {
		mode = &display->modes[index];
		if (!mode) {
			LCD_INFO("mode is null\n");
			continue;
		}
		rc = oplus_panel_cmd_reg_replace_specific_row(panel, mode, DSI_CMD_GAMMA_COMPENSATION, regs1,
		A0020_GAMMA_COMPENSATION_READ_LENGTH, 3/* rows of cmd */);
		if (rc) {
			DSI_ERR("DSI_CMD_GAMMA_COMPENSATION reg1 replace failed\n");
			g_gamma_regs_read_done = false;
			return -EFAULT;
		}

		rc = oplus_panel_cmd_reg_replace_specific_row(panel, mode, DSI_CMD_GAMMA_COMPENSATION, regs2,
		A0020_GAMMA_COMPENSATION_READ_LENGTH, 7/* rows of cmd */);
		if (rc) {
			DSI_ERR("DSI_CMD_GAMMA_COMPENSATION reg2 replace failed\n");
			g_gamma_regs_read_done = false;
			return -EFAULT;
		}
		LCD_INFO("display mode%d had completed gamma compensation\n", index);
	}
	mutex_unlock(&display->panel->panel_lock);
	mutex_unlock(&display->display_lock);

	return rc;
}
