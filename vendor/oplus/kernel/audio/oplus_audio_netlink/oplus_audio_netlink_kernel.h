/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * oplus_kernel_audio.h - for audio kernel action upload to user layer
 *
 */
#ifndef _OPLUS_MM_KNL_NT_
#define _OPLUS_MM_KNL_NT_

#include <linux/sched.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <linux/version.h>

#define MAX_PAYLOAD_DATASIZE		 (512)
#define MM_KNL_NT_MODULE_SIZE_MAX	 (16)
#define MM_KNL_NT_MODULE_LEN_MAX	 (64)

#define MM_KNL_NT_BAD_VALUE 		 (-1)
#define MM_KNL_NT_NO_ERROR			 (0)
#define OPLUS_MM_MSG_TO_NATIVE_BUF_LEN			256

#define AUDIO_KERNEL_NATIVE_COM					"knl_nt_com"
#define OPLUS_KNL_NT_GENL_VERSION				0x01
#define OPLUS_NETLINK_KNL_NT_LV2 0x2
#define KNL_NT_CMD_ATTR_MAX 	(__KNL_NT_CMD_ATTR_MAX - 1)

enum {
	KNL_NT_CMD_ATTR_UNSPEC = 0,
	KNL_NT_CMD_ATTR_MS,
	KNL_NT_CMD_ATTR_OPT,
	__KNL_NT_CMD_ATTR_MAX,
};

enum {
	KNL_NT_GENL_UNSPE = 0,
	KNL_NT_GENL_SEND_MODULE,
	KNL_NT_GENL_UPLOAD,
	KNL_NT_GENL_TEST_UPLOAD,
};

enum knl_nt_msg_cmd_type {
    MSG_CMD_MIC_BLOCK = 0x0,
    MSG_CMD_MAX,
};

struct mm_knl_nt_module {
	u32 pid;
	char modl[MM_KNL_NT_MODULE_LEN_MAX];
};

int mm_knl_nt_kevent_send_to_user(char* nt_module, char *data, int len);
#endif  //_OPLUS_MM_KNL_NT_


