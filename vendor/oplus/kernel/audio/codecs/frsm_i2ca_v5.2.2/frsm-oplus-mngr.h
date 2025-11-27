/**
 * Copyright (C) Fourier Semiconductor Inc. 2016-2020. All rights reserved.
 * 2024-04-27 File created.
 */
#include "internal.h"

#if IS_ENABLED(CONFIG_SND_SOC_OPLUS_PA_MANAGER)
struct frsm_oplus_manager {
	char spkr_switch[FRSM_DEV_MAX];
	char spkr_mode[FRSM_DEV_MAX];
};

enum {
	FRSM_SPKR_LEFT = 1,
	FRSM_SPKR_RIGHT = 2,
};

enum {
	FRSM_MUSIC_MODE,
	FRSM_VOICE_MODE,
	FRSM_FM_MODE,
	FRSM_RCV_MODE,
	FRSM_MODE_NUM,
};

static DEFINE_MUTEX(frsm_oplus_mutex);
static struct frsm_oplus_manager frsm_spkr_mngr;

extern int frsm_i2ca_set_scene(int spkid, int scene);
extern int frsm_i2ca_spk_switch(int spkid, bool on);

void frsm_spkr_enable(int id, int enable, int mode)
{
	int ret = 0;
	int next_mode;

	pr_info("%s: id -> %d  enable -> %d  mode -> %d spkr_mode -> %d",
			__func__, id, enable, mode, frsm_spkr_mngr.spkr_mode[id - 1]);
	mutex_lock(&frsm_oplus_mutex);
	if (RECV_MODE == mode)
		next_mode = FRSM_RCV_MODE;
	else
		next_mode = frsm_spkr_mngr.spkr_mode[id - 1];

	if (next_mode < 0 || next_mode >= FRSM_MODE_NUM) {
		pr_err("invaild next_mode: %d", next_mode);
		mutex_unlock(&frsm_oplus_mutex);
		return;
	}

	if (enable) {
		if (frsm_spkr_mngr.spkr_switch[id - 1])
			ret = frsm_i2ca_spk_switch(id, 0);

		ret |= frsm_i2ca_set_scene(id, next_mode);
		ret |= frsm_i2ca_spk_switch(id, enable);
	} else {
		ret = frsm_i2ca_spk_switch(id, enable);
		ret |= frsm_i2ca_set_scene(id, next_mode);
	}
	if (ret)
		pr_err("%s: set failed ret = %d\n", __func__, ret);
	else {
		//frsm_spkr_mngr.spkr_mode[id - 1] = next_mode;
		frsm_spkr_mngr.spkr_switch[id - 1] = enable;
	}
	mutex_unlock(&frsm_oplus_mutex);

	return;
}

void frsm_left_spkr_enable(int enable, int mode)
{
	frsm_spkr_enable(FRSM_SPKR_LEFT, enable, mode);
	return;
}

void frsm_right_spkr_enable(int enable, int mode)
{
	frsm_spkr_enable(FRSM_SPKR_RIGHT, enable, mode);
	return;
}

int frsm_left_spkr_mode_get(struct snd_kcontrol *kcontrol,
			struct snd_ctl_elem_value *uc)
{
	char spkr_mode;

	mutex_lock(&frsm_oplus_mutex);
	spkr_mode = frsm_spkr_mngr.spkr_mode[FRSM_SPKR_LEFT - 1];
	uc->value.integer.value[0] = spkr_mode;
	mutex_unlock(&frsm_oplus_mutex);

	return 0;
}

int frsm_left_spkr_mode_put(struct snd_kcontrol *kcontrol,
			struct snd_ctl_elem_value *uc)
{
	char spkr_mode;
	int ret;

	mutex_lock(&frsm_oplus_mutex);
	spkr_mode = (char)uc->value.integer.value[0];
	ret = frsm_i2ca_set_scene(FRSM_SPKR_LEFT, spkr_mode);
	if (ret) {
		pr_err("%s: Failed to set to %d\n", __func__, spkr_mode);
		mutex_unlock(&frsm_oplus_mutex);
		return ret;
	}
	frsm_spkr_mngr.spkr_mode[FRSM_SPKR_LEFT - 1] = spkr_mode;
	mutex_unlock(&frsm_oplus_mutex);

	return 0;
}

int frsm_right_spkr_mode_get(struct snd_kcontrol *kcontrol,
			struct snd_ctl_elem_value *uc)
{
	char spkr_mode;

	mutex_lock(&frsm_oplus_mutex);
	spkr_mode = frsm_spkr_mngr.spkr_mode[FRSM_SPKR_RIGHT - 1];
	uc->value.integer.value[0] = spkr_mode;
	mutex_unlock(&frsm_oplus_mutex);

	return 0;
}

int frsm_right_spkr_mode_put(struct snd_kcontrol *kcontrol,
			struct snd_ctl_elem_value *uc)
{
	char spkr_mode;
	int ret;

	mutex_lock(&frsm_oplus_mutex);
	spkr_mode = (char)uc->value.integer.value[0];
	ret = frsm_i2ca_set_scene(FRSM_SPKR_RIGHT, spkr_mode);
	if (ret) {
		pr_err("%s: Failed to set to %d\n", __func__, spkr_mode);
		mutex_unlock(&frsm_oplus_mutex);
		return ret;
	}
	frsm_spkr_mngr.spkr_mode[FRSM_SPKR_RIGHT - 1] = spkr_mode;
	mutex_unlock(&frsm_oplus_mutex);

	return 0;
}

int frsm_left_spkr_switch_get(struct snd_kcontrol *kcontrol,
			struct snd_ctl_elem_value *uc)
{
	char spkr_switch;

	mutex_lock(&frsm_oplus_mutex);
	spkr_switch = frsm_spkr_mngr.spkr_switch[FRSM_SPKR_LEFT - 1];
	uc->value.integer.value[0] = spkr_switch;
	mutex_unlock(&frsm_oplus_mutex);

	return 0;
}

int frsm_left_spkr_switch_put(struct snd_kcontrol *kcontrol,
			struct snd_ctl_elem_value *uc)
{
	bool spkr_switch;
	int ret;

	mutex_lock(&frsm_oplus_mutex);
	spkr_switch = !!uc->value.integer.value[0];
	ret = frsm_i2ca_spk_switch(FRSM_SPKR_LEFT, spkr_switch);
	if (ret) {
		pr_err("%s: Failed to set to %d\n", __func__, spkr_switch);
		mutex_unlock(&frsm_oplus_mutex);
		return ret;
	}
	frsm_spkr_mngr.spkr_switch[FRSM_SPKR_LEFT - 1] = spkr_switch;
	mutex_unlock(&frsm_oplus_mutex);

	return 0;
}

int frsm_right_spkr_switch_get(struct snd_kcontrol *kcontrol,
			struct snd_ctl_elem_value *uc)
{
	char spkr_switch;

	mutex_lock(&frsm_oplus_mutex);
	spkr_switch = frsm_spkr_mngr.spkr_switch[FRSM_SPKR_RIGHT - 1];
	uc->value.integer.value[0] = spkr_switch;
	mutex_unlock(&frsm_oplus_mutex);

	return 0;
}

int frsm_right_spkr_switch_put(struct snd_kcontrol *kcontrol,
			struct snd_ctl_elem_value *uc)
{
	bool spkr_switch;
	int ret;

	mutex_lock(&frsm_oplus_mutex);
	spkr_switch = !!uc->value.integer.value[0];
	ret = frsm_i2ca_spk_switch(FRSM_SPKR_RIGHT, spkr_switch);
	if (ret) {
		pr_err("%s: Failed to set to %d\n", __func__, spkr_switch);
		mutex_unlock(&frsm_oplus_mutex);
		return ret;
	}
	frsm_spkr_mngr.spkr_switch[FRSM_SPKR_RIGHT - 1] = spkr_switch;
	mutex_unlock(&frsm_oplus_mutex);

	return 0;
}

void frsm_oplus_pa_mngr_init(struct frsm_dev *frsm_dev)
{
	struct oplus_spk_dev_node *spk_dev_node = NULL;
	struct oplus_speaker_device *speaker_device = NULL;

	if (NULL == frsm_dev) {
		pr_err("bad parameter");
		return;
	}

	pr_info("%s(): speaker_device == null, oplus_register start\n", __func__);
	speaker_device = kzalloc(sizeof(struct oplus_speaker_device), GFP_KERNEL);
	if ((frsm_dev->pdata->spkr_id == FRSM_SPKR_LEFT) && (speaker_device != NULL)) {
		speaker_device->chipset = MFR_FSM;
		speaker_device->type = L_SPK;
		speaker_device->vdd_need = 0;
		// PA RECV_MODE -> 1 and switch set
		speaker_device->speaker_enable_set = frsm_left_spkr_enable;
		// PA SPK_MODE -> 0 and switch set
		speaker_device->spk_mode_set = frsm_left_spkr_mode_put;
		speaker_device->spk_mode_get = frsm_left_spkr_mode_get;
		speaker_device->speaker_mute_set = frsm_left_spkr_switch_put;
		speaker_device->speaker_mute_get = frsm_left_spkr_switch_get;
		spk_dev_node = oplus_speaker_pa_register(speaker_device);
		frsm_dev->oplus_dev_node = spk_dev_node;
		pr_info("%s: oplus_register end\n", __func__);
	} else if ((frsm_dev->pdata->spkr_id == FRSM_SPKR_RIGHT) && (speaker_device != NULL)) {
		speaker_device->chipset = MFR_FSM;
		speaker_device->type = R_SPK;
		speaker_device->vdd_need = 0;
		// PA RECV_MODE and switch set
		speaker_device->speaker_enable_set = frsm_right_spkr_enable;
		// PA SPK_MODE -> 0 and switch set
		speaker_device->spk_mode_set = frsm_right_spkr_mode_put;
		speaker_device->spk_mode_get = frsm_right_spkr_mode_get;
		speaker_device->speaker_mute_set = frsm_right_spkr_switch_put;
		speaker_device->speaker_mute_get = frsm_right_spkr_switch_get;
		spk_dev_node = oplus_speaker_pa_register(speaker_device);
		frsm_dev->oplus_dev_node = spk_dev_node;
		pr_info("%s: oplus_register end\n", __func__);
	}
}

void frsm_oplus_pa_mngr_uninit(struct frsm_dev *frsm_dev)
{
	struct oplus_spk_dev_node* spk_dev_node = NULL;

	if (NULL == frsm_dev) {
		pr_err("bad parameter");
		return;
	}

	spk_dev_node = frsm_dev->oplus_dev_node;
	oplus_speaker_pa_remove(spk_dev_node);

	pr_info("%s(): oplus_deinit done\n", __func__);
}
#endif