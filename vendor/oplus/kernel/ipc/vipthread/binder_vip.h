/***********************************************************
** Copyright (C), 2008-2019, OPLUS Mobile Comm Corp., Ltd.
** File: vip_binder.h
** Description: Add for vip thread policy for binder
**
** Version: 1.0
** Date : 2023/10/07
** Author: #, 2023/10/07, add for vip thread policy
**
** ------------------ Revision History:------------------------
** <author>      <data>      <version >       <desc>
** Feng Song    2023/10/07      1.0       VIP BINDER THREAD POLICY
****************************************************************/


#ifndef _LINUX_VIP_BINDER_H
#define _LINUX_VIP_BINDER_H

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/uidgid.h>
#include <uapi/linux/android/binderfs.h>
#include <drivers/android/binder_internal.h>

#define BINDER_ENABLE_VIP_THREAD_POLICY	_IOW('b', 31, __u32)
#define BINDER_SWITCH_VIP_THREAD_POLICY	_IOW('b', 32, __u32)

/*
 * NOTE: Two special error codes you should check for when calling
 * in to the driver are:
 *
 * EINTR -- The operation has been interupted.  This should be
 * handled by retrying the ioctl() until a different error code
 * is returned.
 *
 * ECONNREFUSED -- The driver is no longer accepting operations
 * from your process.  That is, the process is being destroyed.
 * You should handle this by exiting from your process.  Note
 * that once this error code is returned, all further calls to
 * the driver from any thread will return this same code.
 */
/*COPY UAIP binder.h*/
enum binder_vip_transaction_flags {
	TF_TAXI_THREAD_WAY = 0x1000, /*request vip thread */
	TF_TAXI_UX_WAY = 0x2000, /*request ux thread */
};

/*TAXI thread: copy from hans_help*/
#define MIN_USERAPP_UID (10000)
#define MAX_OTHER_USERAPP_UID (19999)

#define MAX_SYSTEM_UID  (2000)
#define HANS_SYSTEM_UID (1000)
#define INTERFACETOKEN_BUFF_SIZE (140)
#define PARCEL_OFFSET (16) /* sync with the writeInterfaceToken */

#define MAX_TAXI_THREAD_RPC_NAME_LEN (300)
#define MAX_TRANS_CODES_CNT (4)

enum e_vip_policy_group {
        e_vip_policy_group_default = 0,
        e_vip_policy_group_app_switch,
};

struct binder_proc_vip_policy {
	struct list_head self_node;
	int vip_thread_policy_max_threads;
};

struct binder_vip_device {
	struct miscdevice miscdev;
};

struct binder_vip_policy_info {
	char interface_token[140];
        uint16_t tr_code_size;
        uint32_t* tr_code;
	/*int tr_code[MAX_TRANS_CODES_CNT];*/
	/*char tr_name[140];*/
	char client_proc_name[16];
	char server_proc_name[16];
	uint8_t policy_type; /*0: not limit; 1: check :tr->code ; 2: check flag 3: check client proc*/
	int handle;
	int index; /*debug index: for file node*/
};

struct binder_vip_policy {
	struct list_head vip_entry;
	struct binder_vip_policy_info *info;
};

/*note: */
#define MAX_BINDER_VIP_WHITE_LIST_CNT 2
struct binder_vip_policy_summary
{
	int vip_white_list_cnt;
	int cur_vip_policy_type_group;
	struct list_head vip_white_list[MAX_BINDER_VIP_WHITE_LIST_CNT];
};

#define binder_vip_for_each_debugfs_entry(entry)	\
	for ((entry) = binder_vip_debugfs_entries;	\
	     (entry)->name;			\
	     (entry)++)

/*for /dev/oplus_vip_binder ioctl*/
struct vip_token {
        char interface_token[INTERFACETOKEN_BUFF_SIZE];
        uint16_t tr_code_size;
        uint32_t* tr_codes;
        char server_proc_name[TASK_COMM_LEN];
        char client_proc_name[TASK_COMM_LEN];
        uint8_t type;
};

struct vip_token_group {
        /*    char group_name[GROUP_NAME_LEN];*/
        /*    uint8_t group_id;*/
        uint32_t token_size;
        struct vip_token* tokens_head;
};


#ifndef VIP_BINDER_SUBMIT_VIP_TOKENS
#define VIP_BINDER_SUBMIT_VIP_TOKENS _IOW('b', 100, struct vip_token_group)
#endif

#ifndef VIP_BINDER_CLEAR_TOKENS
#define VIP_BINDER_CLEAR_TOKENS _IO('b', 101)
#endif

/*TODO: SWICH GROUP WILL BE REMOVED*/
#ifndef VIP_BINDER_SWITCH_GROUP_ID
#define VIP_BINDER_SWITCH_GROUP_ID _IOW('b', 102, __u32)
#endif

#ifndef VIP_BINDER_SET_ENABLE_STATE
#define VIP_BINDER_SET_ENABLE_STATE _IOW('b', 103, __u8)
#endif

#ifndef VIP_BINDER_GET_ENABLE_STATE
#define VIP_BINDER_GET_ENABLE_STATE _IOR('b', 104, __u8)
#endif

#ifndef VIP_BINDER_SET_DEBUG_TRACE_STATE
#define VIP_BINDER_SET_DEBUG_TRACE_STATE _IOW('b', 105, __u8)
#endif

#ifndef VIP_BINDER_GET_DEBUG_TRACE_STATE
#define VIP_BINDER_GET_DEBUG_TRACE_STATE _IOR('b', 106, __u8)
#endif


bool binder_look_for_proc_work_on_vip_thread(struct list_head **list,
						struct binder_proc *proc,
						struct binder_thread *thread,
						int wait_for_proc_work);
bool binder_has_vip_work_ilocked(struct binder_thread *thread, bool do_proc_work, int *ret);
void binder_vip_clear_vip_token_group_ilocked(int group_id);
int binder_vip_update_vip_token_group_ilocked(int group_id,  struct vip_token_group *in_group);

#endif /* _LINUX_VIP_BINDER_H */
