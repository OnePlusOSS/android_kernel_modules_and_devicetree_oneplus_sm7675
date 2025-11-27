#ifndef __OPLUS_TYPEC_SWITCH_H__
#define __OPLUS_TYPEC_SWITCH_H__
//-----------------------------------------------------------------------------

#define OPLUS_DISCRETE_TYPEC_SWITCH_DRIVER_NAME	"oplus-discrete-typec-switch-driver"

enum audio_switch_hs_event {
	HS_MIC_GND_SWAP = 0,
	HS_LR_CONNECT,
	HS_LR_DISCONNECT,
	HS_PLUG_OUT,
	HS_SWITCH_EVENT_MAX
};
struct typec_switch_priv {
	struct device *dev;
	struct tcpc_device *tcpc_dev;
	struct notifier_block pd_nb;
	struct work_struct usbc_analog_work;
	struct blocking_notifier_head typec_switch_notifier;
	struct mutex notification_lock;
	unsigned int mic_gnd_status;
	unsigned int mic_gnd_swh_pin;
	unsigned int mic_gnd_swh_2nd_pin;
	unsigned int lr_sel_pin;
	unsigned int hs_det_pin;
	unsigned int switch_enable_pin;
	unsigned int hs_det_level;
	unsigned int lr_sel_level;
	unsigned int mic_gnd_swh_level;
	unsigned int mic_gnd_swh_2nd_level;
	unsigned int switch_enable_level;
	bool plug_state;
	struct delayed_work hp_work;
	int charger_plugged;
	bool hs_det_bypass;
};
//-----------------------------------------------------------------------------
#endif
