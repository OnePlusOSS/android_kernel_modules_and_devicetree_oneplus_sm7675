/************************************************************************************
** File: - OplusAudioDaemon.h
**
** Copyright (C), 2024-2028, OPLUS Mobile Comm Corp., Ltd
**
** Description:
**     Implementation of OPLUS audio driver Daemon system.
**
** Version: 1.0
************************************************************************************/

#ifndef OPLUS_AUDIO_DAEMON_H
#define OPLUS_AUDIO_DAEMON_H

enum {
	FEEDBACK_EVENT_RESERVE1 = 0,
	FEEDBACK_EVENT_RESERVE2,
	FEEDBACK_EVENT_RESERVE3,
	DAEMON_TYPE_ALL_MAX,
};

void oplus_audio_daemon_record(unsigned int type);
bool oplus_audio_daemon_check(unsigned int type);
bool oplus_audio_daemon_trigger(unsigned int type);
void oplus_audio_daemon_clear_record(unsigned int type);
bool oplus_audio_daemon_record_check_trigger(unsigned int type);
bool oplus_audio_daemon_record_or_clear(bool is_err, unsigned int type);
bool oplus_is_daemon_event_id(unsigned int event_id);
bool oplus_audio_daemon_feedback_event(unsigned int event_id, char *fb_info);
#endif /* OPLUS_AUDIO_DAEMON_H */
