// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Oplus. All rights reserved.
 *
 * secure harden: heapspary check and selinux policy reload check.
 */
#include <linux/pgtable.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/bootconfig.h>
#include <linux/device.h>
#include <linux/version.h>

#include <linux/cred.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/async.h>
#include <linux/sysctl.h>
#include <linux/uio.h>

#include <linux/capability.h>
#include "oplus_secure_harden.h"
#include "oplus_guard_general.h"
#include "oplus_kevent.h"
#include <../kernel/oplus_cpu/sched/sched_assist/sa_common.h>
#define SECUREGUARD_NEW    "[secureguard_new][root_check]"
#define OPLUS_ANDROID_ROOT_UID			0
#define OPLUS_ANDROID_THIRD_PART_APK_UID	10000
#define OPLUS_AID_SHELL_UID			2000

#define SYS_CALL_EXECVE			18
#define SYS_CALL_CAPSET			91
#define SYS_CALL_SETREGID			143
#define SYS_CALL_SETGID			144
#define SYS_CALL_SETREUID			145
#define SYS_CALL_SETUID			146
#define SYS_CALL_SETRESUID			147
#define SYS_CALL_SETRESGID			149
#define SYS_CALL_SETFSUID			151
#define SYS_CALL_SETFSGID			152

#define SYS_CALL_FUTEX			98
#define SYS_CALL_PPOLL			73
#define SYS_CALL_EPOLL_PWAIT			22
#define SYS_CALL_IOCTL			29
#define SYS_CALL_RT_TGSIGQUEUEINFO			240
#define SYS_CALL_NONOSLEEP			101
#define SYS_CALL_RT_SIGTIMEDWAIT			137

/* secureguard sub-module string for print */
#define SG_MIX_HARDEN    "[secureguard][secure_harden]"
#define arg0(pt_regs)	((pt_regs)->regs[0])
#define arg1(pt_regs)	((pt_regs)->regs[1])
#define arg2(pt_regs)	((pt_regs)->regs[2])
#define arg3(pt_regs)	((pt_regs)->regs[3])
#define arg4(pt_regs)	((pt_regs)->regs[4])
#define arg5(pt_regs)	((pt_regs)->regs[5])
#define arg6(pt_regs)	((pt_regs)->regs[6])
#define arg7(pt_regs)	((pt_regs)->regs[7])
static int selinux_enabled = 1;
unsigned int temp_uid = 0;
struct selinux_state {
#ifdef CONFIG_SECURITY_SELINUX_DISABLE
	bool disabled;
#endif
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
	bool enforcing;
#endif
	bool checkreqprot;
	bool initialized;
	bool policycap[7];
	/* __POLICYDB_CAPABILITY_MAX == 7  */
	/*bool policycap[__POLICYDB_CAPABILITY_MAX];*/
	bool android_netlink_route;
	bool android_netlink_getneigh;

	struct page *status_page;
	struct mutex status_lock;

	struct selinux_avc *avc;
	struct selinux_policy __rcu *policy;
	struct mutex policy_mutex;
} __randomize_layout;

/* Heapspary layout[x]: PPID, COUNT, TIME */
/* pid type is int, count can use int, tv.tv_sec type is time64_t = long */
/* using int will be better, or using struct NOT array */
unsigned int heapspary_ip4[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
unsigned int heapspary_cpuinfo[3] = {0, 0, 0};
unsigned int heapspary_xttr[3] = {0, 0, 0};
unsigned int heapspary_ip6[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0};

/*Used for hook function name by Kprobe.*/
static char func_name_sepolicy_reload[NAME_MAX] = "sel_write_load";
static char func_name_socket[NAME_MAX]		= "ip_setsockopt";	/* ipv4 */
static char func_name_socket_ip6[NAME_MAX]	= "do_ipv6_setsockopt";	/* ipv6 */
static char func_name_cpu_info[NAME_MAX]	= "cpuinfo_open";
static char func_name_setxattr[NAME_MAX]	= "setxattr";

static char func_name_execve[NAME_MAX] = "do_execveat_common";
static char func_name_capset[NAME_MAX] = "cap_capset"; /* __arm64_sys_capset */

static char func_name_setregid[NAME_MAX] = "__sys_setregid";   /* setregid */
static char func_name_setgid[NAME_MAX] = "__sys_setgid";       /* setgid */
static char func_name_setreuid[NAME_MAX] = "__sys_setreuid";   /* setreuid */
static char func_name_setuid[NAME_MAX] = "__sys_setuid";   /* setreuid */
static char func_name_setresuid[NAME_MAX] = "__sys_setresuid"; /* setresuid */
static char func_name_setresgid[NAME_MAX] = "__sys_setresgid"; /* setresgid */
static char func_name_setfsuid[NAME_MAX] = "__sys_setfsuid";   /* setfsuid */
static char func_name_setfsgid[NAME_MAX] = "__sys_setfsgid";   /* setfsgid */

static char func_name_futex[NAME_MAX] = "__arm64_sys_futex";   /* futex */
static char func_name_ppoll[NAME_MAX] = "__arm64_sys_ppoll";   /* ppoll */
static char func_name_epoll_pwait[NAME_MAX] = "__arm64_sys_epoll_pwait";   /* epoll_pwait */
static char func_name_ioctl[NAME_MAX] = "__arm64_sys_ioctl";   /* ioctl */
static char func_name_rt_tgsigqueueinfo[NAME_MAX] = "__arm64_sys_rt_tgsigqueueinfo"; /* rt_tgsigqueueinfo */
static char func_name_nanosleep[NAME_MAX] = "__arm64_sys_nanosleep"; /* nanosleep */
static char func_name_sigtimedwait[NAME_MAX] = "__arm64_sys_rt_sigtimedwait"; /* sigtimedwait */




/*
 * oplus_heapspray_check:
 * By detecting how often the function is called by the same process, judge whether is a heapspary.
 * If an exception is detected, exception handling it.(e.g.. kill process)
 * @type: Type of entered
 * @Return: Void type, non-return.
 */
void oplus_heapspray_check(unsigned int type)
{
	struct timespec64 ts;
	const char *event_type = "heapspray";
	unsigned int new_ppid = current->real_parent->pid;

	/*bypass if root process */
	if ((!current_uid().val))
		return;

	ktime_get_real_ts64(&ts);
	/*
	 * task_ppid_nr() calls init_ppid_ns. But init_ppid_ns is not include into whilelist by Android R + K5.4.
	 * May support Android S + Kernel 5.10.
	 * unsigned int new_ppid = task_ppid_nr(current);
	 */
	switch (type) {
	case CPU_INFO:
		/* Only detect the same caller. */
		if (new_ppid == heapspary_cpuinfo[0]) {
			/* The time interval greater than 10s, then count again to avoid normal process being intercepted. */
			if ((ts.tv_sec - heapspary_cpuinfo[2]) >= HEAPSPARY_TIME_LIMIT) {
				heapspary_cpuinfo[1] = 0;
				heapspary_cpuinfo[2] = ts.tv_sec;
			/*For the first record, the initial value needs to be set.*/
			} else if (!heapspary_cpuinfo[2]) {
				heapspary_cpuinfo[2] = ts.tv_sec;
			/*Detect abnormal process: 1.Exceed the limit of 200 times within 10s of time intercal.*/
			} else if (heapspary_cpuinfo[1] > HEAPSPART_COUNT_LIMIT) {
				pr_err(SG_MIX_HARDEN "%s:CPU_INFO may be abnormal! (tiem diff: %lld)\n", __func__, ts.tv_sec - heapspary_cpuinfo[2]);
				heapspary_cpuinfo[1] = 0;
				heapspary_cpuinfo[2] = 0;
				/*force_sig is not include in whilelist*/
				report_security_event(event_type, type, "");
			}
			heapspary_cpuinfo[1]++;
		} else {
			/*Record the first call of different process.*/
			heapspary_cpuinfo[0] = new_ppid;
			heapspary_cpuinfo[1] = 0;
			heapspary_cpuinfo[2] = 0;
		}
		break;

	case SET_XATTR:
		if (new_ppid == heapspary_xttr[0]) {
			if ((ts.tv_sec - heapspary_xttr[2]) >= HEAPSPARY_TIME_LIMIT) {
				heapspary_xttr[1] = 0;
				heapspary_xttr[2] = ts.tv_sec;
			} else if (!heapspary_xttr[2]) {
				heapspary_xttr[2] = ts.tv_sec;
			} else if (heapspary_xttr[1] > HEAPSPART_COUNT_LIMIT) {
				pr_err(SG_MIX_HARDEN "%s:SET_XATTR may be abnormal! (tiem diff: %lld)\n", __func__, ts.tv_sec - heapspary_xttr[2]);
				heapspary_xttr[1] = 0;
				heapspary_xttr[2] = 0;
				report_security_event(event_type, type, "");
			}
			heapspary_xttr[1]++;
		} else {
			heapspary_xttr[0] = new_ppid;
			heapspary_xttr[1] = 0;
			heapspary_xttr[2] = 0;
		}
		break;

	case MCAST_MSFILTER_IP4:
		if (new_ppid == heapspary_ip4[0]) {
			if ((ts.tv_sec - heapspary_ip4[2]) >= HEAPSPARY_TIME_LIMIT) {
				heapspary_ip4[1] = 0;
				heapspary_ip4[2] = ts.tv_sec;
			} else if (!heapspary_ip4[2]) {
				heapspary_ip4[2] = ts.tv_sec;
			} else if (heapspary_ip4[1] > HEAPSPART_COUNT_LIMIT) {
				pr_err(SG_MIX_HARDEN "%s:MCAST_MSFILTER_IP4 may be abnormal! (tiem diff: %lld)\n", __func__, ts.tv_sec - heapspary_ip4[2]);
				heapspary_ip4[1] = 0;
				heapspary_ip4[2] = 0;
				/* do_exit(SIGKILL); */
				report_security_event(event_type, type, "");
			}
			heapspary_ip4[1]++;
		} else {
			heapspary_ip4[0] = new_ppid;
			heapspary_ip4[1] = 0;
			heapspary_ip4[2] = 0;
		}
		break;

	case MCAST_JOIN_GROUP_IP4:
		if (new_ppid == heapspary_ip4[3]) {
			if ((ts.tv_sec - heapspary_ip4[5]) >= HEAPSPARY_TIME_LIMIT) {
				heapspary_ip4[4] = 0;
				heapspary_ip4[5] = ts.tv_sec;
			} else if (!heapspary_ip4[5]) {
				heapspary_ip4[5] = ts.tv_sec;
			} else if (heapspary_ip4[4] > HEAPSPART_COUNT_LIMIT) {
				pr_err(SG_MIX_HARDEN "%s:MCAST_JOIN_GROUP_IP4 may be abnormal! (tiem diff: %lld)\n", __func__, ts.tv_sec - heapspary_ip4[5]);
				heapspary_ip4[4] = 0;
				heapspary_ip4[5] = 0;
				/* do_exit(SIGKILL); */
				report_security_event(event_type, type, "");
			}
			heapspary_ip4[4]++;
		} else {
			heapspary_ip4[3] = new_ppid;
			heapspary_ip4[4] = 0;
			heapspary_ip4[5] = 0;
		}
		break;

	case IP_MSFILTER_IP4:
		if (new_ppid == heapspary_ip4[6]) {
			if ((ts.tv_sec - heapspary_ip4[8]) >= HEAPSPARY_TIME_LIMIT) {
				heapspary_ip4[7] = 0;
				heapspary_ip4[8] = ts.tv_sec;
			} else if (!heapspary_ip4[8]) {
				heapspary_ip4[8] = ts.tv_sec;
			} else if (heapspary_ip4[7] > HEAPSPART_COUNT_LIMIT) {
				pr_err(SG_MIX_HARDEN "%s:IP_MSFILTER_IP4 may be abnormal! (tiem diff: %lld)\n", __func__, ts.tv_sec - heapspary_ip4[8]);
				heapspary_ip4[7] = 0;
				heapspary_ip4[8] = 0;
				/* do_exit(SIGKILL); */
				report_security_event(event_type, type, "");
			}
			heapspary_ip4[7]++;
		} else {
			heapspary_ip4[6] = new_ppid;
			heapspary_ip4[7] = 0;
			heapspary_ip4[8] = 0;
		}
		break;

	case MCAST_JOIN_GROUP_IP6:
		if (new_ppid == heapspary_ip6[0]) {
			if ((ts.tv_sec - heapspary_ip6[2]) >= HEAPSPARY_TIME_LIMIT) {
				heapspary_ip6[1] = 0;
				heapspary_ip6[2] = ts.tv_sec;
			} else if (!heapspary_ip6[2]) {
				heapspary_ip6[2] = ts.tv_sec;
			} else if (heapspary_ip6[1] > HEAPSPART_COUNT_LIMIT) {
				pr_err(SG_MIX_HARDEN "%s:MCAST_JOIN_GROUP_IP6 may be abnormal! (tiem diff: %lld)\n", __func__, ts.tv_sec - heapspary_ip6[2]);
				heapspary_ip6[1] = 0;
				heapspary_ip6[2] = 0;
				/* do_exit(SIGKILL); */
				report_security_event(event_type, type, "");
			}
			heapspary_ip6[1]++;
		} else {
			heapspary_ip6[0] = new_ppid;
			heapspary_ip6[1] = 0;
			heapspary_ip6[2] = 0;
		}
		break;

	case MCAST_MSFILTER_IP6:
		if (new_ppid == heapspary_ip6[3]) {
			if ((ts.tv_sec - heapspary_ip6[5]) >= HEAPSPARY_TIME_LIMIT) {
				heapspary_ip6[4] = 0;
				heapspary_ip6[5] = ts.tv_sec;
			} else if (!heapspary_ip6[5]) {
				heapspary_ip6[5] = ts.tv_sec;
			} else if (heapspary_ip6[4] > HEAPSPART_COUNT_LIMIT) {
				pr_err(SG_MIX_HARDEN "%s:MCAST_MSFILTER_IP6 may be abnormal! (tiem diff: %lld)\n", __func__, ts.tv_sec - heapspary_ip6[5]);
				heapspary_ip6[4] = 0;
				heapspary_ip6[5] = 0;
				report_security_event(event_type, type, "");
			}
			heapspary_ip6[4]++;
		} else {
			heapspary_ip6[3] = new_ppid;
			heapspary_ip6[4] = 0;
			heapspary_ip6[5] = 0;
		}
		break;
	} /*switch(type)*/
}

/*
 * oplus_sepolicy_reload:
 * Only the init process is allowed to load sepolicy, and the other process calls will be bolcked.
 * @type: Void
 * @Return: Void type, non-return.
 */
void oplus_sepolicy_reload(void)
{
	const char *event_type = "spolicy_reload";

	if (!is_global_init(current)) {
		pr_err(SG_MIX_HARDEN "%s:Detected illegal porcess reload policy!!!\n", __func__);
		/* do_exit(SIGKILL); */
		report_security_event(event_type, SEPOLICY_RL, "");
	}
}

static int entry_handler_socket(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int socket_type = regs->regs[2];

	if (socket_type == MCAST_MSFILTER) {
		pr_info("[SECUREGUARD_NEW]:MCAST_MSFILTER\n");
		oplus_heapspray_check(MCAST_MSFILTER_IP4);
	} else if (socket_type == MCAST_JOIN_GROUP) {
		pr_info("[SECUREGUARD_NEW]:MCAST_JOIN_GROUP\n");
		oplus_heapspray_check(MCAST_JOIN_GROUP_IP4);
	} else if (socket_type == IP_MSFILTER) {
		pr_info("[SECUREGUARD_NEW]:IP_MSFILTER\n");
		oplus_heapspray_check(IP_MSFILTER_IP4);
	}
	return 0;
}

static int entry_handler_socket_ip6(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int socket_type = regs->regs[2];

	if (socket_type == MCAST_JOIN_GROUP) {
		pr_info("[SECUREGUARD_NEW]:MCAST_JOIN_GROUP\n");
		oplus_heapspray_check(MCAST_JOIN_GROUP_IP4);
	} else if (socket_type == IP_MSFILTER) {
		pr_info("[SECUREGUARD_NEW]:IP_MSFILTER\n");
		oplus_heapspray_check(IP_MSFILTER_IP4);
	}
	return 0;
}

static int entry_handler_cpuinfo(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	oplus_heapspray_check(CPU_INFO);
	return 0;
}

static int entry_handler_setxattr(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	oplus_heapspray_check(SET_XATTR);
	return 0;
}

static int entry_handler_sepolicy_reload(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	oplus_sepolicy_reload();
	return 0;
}

static void oplus_report_execveat_new(const char *path, const char *dcs_event_id)
{
	struct kernel_packet_info *dcs_event;
	char dcs_stack[sizeof(struct kernel_packet_info) + 256];
	const char *dcs_event_tag = "kernel_event";
	/* const char* dcs_event_id = "execve_report"; */
	char *dcs_event_payload = NULL;
	int uid = current_uid().val;
	/*const struct cred *cred = current_cred();*/
	struct kernel_packet_info *dcs_event_h = kmalloc(sizeof(struct kernel_packet_info) + 256, GFP_ATOMIC);
	dcs_event = (struct kernel_packet_info *)dcs_stack;
	dcs_event_payload = dcs_stack +
		sizeof(struct kernel_packet_info);

	dcs_event->type = 3;

	strncpy(dcs_event->log_tag, dcs_event_tag,
		sizeof(dcs_event->log_tag));
	strncpy(dcs_event->event_id, dcs_event_id,
		sizeof(dcs_event->event_id));

	dcs_event->payload_length = snprintf(dcs_event_payload, 256,
		"%d,path@@%s", uid, path);
	if (dcs_event->payload_length < 256)
		dcs_event->payload_length += 1;

	memcpy(dcs_event_h, dcs_event, sizeof(struct kernel_packet_info) + 256);
	async_schedule(kevent_send_to_user, dcs_event_h);
	pr_err(SECUREGUARD_NEW "%s, common %s result %s\n", __func__, path, dcs_event_id);
}

static int oplus_RWO_root_check(struct task_struct *p)
{
	struct task_struct *tgid_task, *parent_task = NULL;
	char data_buff[128];
	const char *event_type = "exec2";

	if (!p || p->pid == 1)
		return 0;

	if (CHECK_ROOT_CREDS(p)) {
		if (p->tgid != p->pid) {
			/* get tgid's task and cred */
			tgid_task = find_task_by_vpid(p->tgid);
			get_task_struct(tgid_task);
			/* get tgid's uid */
			if (!CHECK_ROOT_CREDS(tgid_task)) {
				pr_err(SECUREGUARD_NEW "%s, Found task process %s, uid:%d, tgid_uid: %d.\n", __func__,
					p->comm, p->cred->uid.val, tgid_task->cred->uid.val);
				report_security_event(event_type, EXEC2_EVENT, "");
				return 1;
			}
		} else {
			parent_task = rcu_dereference(p->real_parent);
			if (!CHECK_ROOT_CREDS(parent_task)) {
				sprintf(data_buff, "parent(%s),comm(%s)", parent_task->comm, p->comm);
				pr_err(SECUREGUARD_NEW "%s, Detect curr process %s(%d), parent process %s(%d).\n", __func__,
					p->comm, p->cred->uid.val, parent_task->comm, parent_task->cred->uid.val);
				report_security_event(event_type, EXEC2_EVENT, data_buff);
				return 1;
			}
		}
	}
	return 0;
}

static int do_execveat_common_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	char *absolute_path_buf = NULL;
	char *absolute_path = NULL;
	struct path *p_f_path = &(current->mm->exe_file->f_path);

	if (p_f_path == NULL) {
		goto out_ret;
	}
	absolute_path_buf = (char *)__get_free_page(GFP_ATOMIC);
	if(absolute_path_buf == NULL) {
		goto out_ret;
	}
	absolute_path = d_path(p_f_path, absolute_path_buf, PAGE_SIZE);
	if (IS_ERR(absolute_path)) {
		goto out_free;
	}
	/*pr_info(SECUREGUARD_NEW "LIKE:guard: abs_path:%s.\n", absolute_path);*/
	if (strncmp(absolute_path, "/data", 5)) {/* not /data then exempt */
		goto out_free;
	}
	if ((!strncmp(absolute_path, "/data/local/tmp", 15))
		|| (!strncmp(absolute_path, "/data/nativetest", 16))
		|| (!strncmp(absolute_path, "/data/nativetest64", 18))) {/* exempt three data */
		if (oplus_RWO_root_check(current)) {
			/*Note: Do not block execve now*/
		}
		goto out_free;
	}

	if(!uid_eq(current_uid(), GLOBAL_ROOT_UID)) {
		pr_err(SECUREGUARD_NEW "LIKE:guard: detect abnormal ROOT exec (%s).\n", absolute_path);
		oplus_report_execveat_new(absolute_path, "execve_report");
	} else {
		oplus_report_execveat_new(absolute_path, "execve_block");
		pr_err(SECUREGUARD_NEW "LIKE:guard: detect abnormal current_uid not 0 so need kill! (%s).\n", absolute_path);
		/*send_sig(SIGKILL, current, 0);*/
		goto out_free;
	}

out_free:
	if(absolute_path_buf != NULL) {
		free_page((unsigned long)absolute_path_buf);
	}

out_ret:
	return 0;
}
#if 1
static void oplus_root_check_succ_upload(uid_t uid, uid_t euid, gid_t egid, int callnum)
{
	struct kernel_packet_info *dcs_event;
	char dcs_stack[sizeof(struct kernel_packet_info) + 256];
	const char *dcs_event_tag = "kernel_event";
	const char *dcs_event_id = "root_check";
	char *dcs_event_payload = NULL;

	char comm[TASK_COMM_LEN], nameofppid[TASK_COMM_LEN];
	struct task_struct *parent_task = NULL;
	int ppid = -1;

	struct kernel_packet_info *dcs_event_h = kmalloc(sizeof(struct kernel_packet_info) + 256, GFP_ATOMIC);

	pr_info(SECUREGUARD_NEW "%s, oplus_root_check_succ_upload enter.\n", __func__);
	memset(comm, 0, TASK_COMM_LEN);
	memset(nameofppid, 0, TASK_COMM_LEN);

	if (uid < 0 || uid > 65536 || euid < 0 || euid > 65536 || egid < 0 || egid > 65536) {
		return;
	}
	/*ppid = task_ppid_nr(current);*/
	parent_task = rcu_dereference(current->real_parent);
	if (parent_task) {
		get_task_comm(nameofppid, parent_task);
		ppid = parent_task->pid;
	}

	dcs_event = (struct kernel_packet_info *)dcs_stack;
	dcs_event->type = 0;
	strncpy(dcs_event->log_tag, dcs_event_tag, sizeof(dcs_event->log_tag));
	strncpy(dcs_event->event_id, dcs_event_id, sizeof(dcs_event->event_id));
	dcs_event_payload = kmalloc(256, GFP_ATOMIC);
	if (dcs_event_payload == NULL) {
		return;
	}

	memset(dcs_event_payload, 0, 256);

	dcs_event->payload_length = snprintf(dcs_event_payload, 256,
		"%d$$old_euid@@%d$$old_egid@@%d$$sys_call_number@@%d$$addr_limit@@%lx$$curr_uid@@%d$$"
		"curr_euid@@%d$$curr_egid@@%d$$curr_name@@%s$$ppid@@%d$$ppidname@@%s$$enforce@@%d\n",
		uid, euid, egid, callnum, get_fs(), current_uid().val, current_euid().val, current_egid().val,
		get_task_comm(comm, current), ppid, nameofppid, selinux_enabled);

	memcpy(dcs_event->payload, dcs_event_payload, strlen(dcs_event_payload));

	memcpy(dcs_event_h, dcs_event, sizeof(struct kernel_packet_info) + 256);
	pr_info(SECUREGUARD_NEW "%s, payload:%s.\n", __func__, dcs_event_h->payload);
	async_schedule(kevent_send_to_user, dcs_event_h);

	kfree(dcs_event_payload);
}
#endif

static int uid_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct oplus_task_struct *ots_cur;
	int symbol_name_len = strlen(ri->rph->rp->kp.symbol_name);
	int syscallno = 0;
	ots_cur = get_oplus_task_struct(current);
	/* pr_info(SECUREGUARD_NEW "uid_entry_handler!!!!!!!!!! %s",ri->rph->rp->kp.symbol_name); */
	if (IS_ERR_OR_NULL(ots_cur))
		return 1;
	if (!(memcmp(ri->rph->rp->kp.symbol_name, func_name_capset, symbol_name_len))) {
		syscallno = SYS_CALL_CAPSET;
	} else if (!(memcmp(ri->rph->rp->kp.symbol_name, func_name_futex, symbol_name_len))) {
		syscallno = SYS_CALL_FUTEX;
	} else if (!(memcmp(ri->rph->rp->kp.symbol_name, func_name_ppoll, symbol_name_len))) {
		syscallno = SYS_CALL_PPOLL;
	} else if (!(memcmp(ri->rph->rp->kp.symbol_name, func_name_epoll_pwait, symbol_name_len))) {
		syscallno = SYS_CALL_EPOLL_PWAIT;
	} else if (!(memcmp(ri->rph->rp->kp.symbol_name, func_name_ioctl, symbol_name_len))) {
		syscallno = SYS_CALL_IOCTL;
	} else if (!(memcmp(ri->rph->rp->kp.symbol_name, func_name_rt_tgsigqueueinfo, symbol_name_len))) {
		syscallno = SYS_CALL_RT_TGSIGQUEUEINFO;
	} else if (!(memcmp(ri->rph->rp->kp.symbol_name, func_name_nanosleep, symbol_name_len))) {
		syscallno = SYS_CALL_NONOSLEEP;
	} else if (!(memcmp(ri->rph->rp->kp.symbol_name, func_name_sigtimedwait, symbol_name_len))) {
		syscallno = SYS_CALL_RT_SIGTIMEDWAIT;
	} else {
		return 1;
	}
	ots_cur->sg_scno = syscallno;
	ots_cur->sg_uid = current_uid().val;
	ots_cur->sg_euid = current_euid().val;
	ots_cur->sg_gid = current_gid().val;
	ots_cur->sg_egid = current_egid().val;

	return 0;
}

static int uid_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
	struct oplus_task_struct *ots_cur;
	ots_cur = get_oplus_task_struct(current);
	if (IS_ERR_OR_NULL(ots_cur))
		return 1;
	if ((ots_cur->sg_uid > current_uid().val) || (ots_cur->sg_euid > current_euid().val)
		 || (ots_cur->sg_gid > current_gid().val) || (ots_cur->sg_egid > current_egid().val)) {
			oplus_root_check_succ_upload(ots_cur->sg_uid, ots_cur->sg_euid, current_uid().val, ots_cur->sg_scno);
			pr_err(SECUREGUARD_NEW "uid_ret_handler\n");
		 }

	return 0;
}


	static struct kretprobe do_execveat_common_kretprobe = {
		/* .handler = ret_handler, */
		.entry_handler = do_execveat_common_entry_handler,
		.data_size = sizeof(struct pt_regs),
		.maxactive = 40,
	};
	static struct kretprobe capset_kretprobe = {
		.handler = uid_ret_handler,
		.entry_handler = uid_entry_handler,
		.data_size = sizeof(struct pt_regs),
		.maxactive = 40,
	};
	static struct kretprobe futex_kretprobe = {
		.handler = uid_ret_handler,
		.entry_handler = uid_entry_handler,
		.data_size = sizeof(struct pt_regs),
		.maxactive = 40,
	};
	static struct kretprobe ppoll_kretprobe = {
		.handler = uid_ret_handler,
		.entry_handler = uid_entry_handler,
		.data_size = sizeof(struct pt_regs),
		.maxactive = 40,
	};
	static struct kretprobe epoll_pwait_kretprobe = {
		.handler = uid_ret_handler,
		.entry_handler = uid_entry_handler,
		.data_size = sizeof(struct pt_regs),
		.maxactive = 40,
	};
	static struct kretprobe ioctl_kretprobe = {
		.handler = uid_ret_handler,
		.entry_handler = uid_entry_handler,
		.data_size = sizeof(struct pt_regs),
		.maxactive = 40,
	};
	static struct kretprobe rt_tgsigqueueinfo_kretprobe = {
		.handler = uid_ret_handler,
		.entry_handler = uid_entry_handler,
		.data_size = sizeof(struct pt_regs),
		.maxactive = 40,
	};
	static struct kretprobe nanosleep_kretprobe = {
		.handler = uid_ret_handler,
		.entry_handler = uid_entry_handler,
		.data_size = sizeof(struct pt_regs),
		.maxactive = 40,
	};
	static struct kretprobe sigtimedwait_kretprobe = {
		.handler = uid_ret_handler,
		.entry_handler = uid_entry_handler,
		.data_size = sizeof(struct pt_regs),
		.maxactive = 40,
	};

/* ---CONFIG_OPLUS_SEPOLICY_RELOAD --- */
static struct kretprobe sepolicy_reload_kretprobe = {
	.entry_handler  = entry_handler_sepolicy_reload,
	.maxactive	= 20,
};

static struct kretprobe socket_kretprobe = {
	.entry_handler  = entry_handler_socket,
	.data_size	= sizeof(struct pt_regs),
	.maxactive	= 300,
};
static struct kretprobe socket_ip6_kretprobe = {
	.entry_handler  = entry_handler_socket_ip6,
	.data_size	= sizeof(struct pt_regs),
	.maxactive	= 300,
};
static struct kretprobe cpuinfo_kretprobe = {
	.entry_handler  = entry_handler_cpuinfo,
	.data_size	= sizeof(struct pt_regs),
	.maxactive	= 300,
};
static struct kretprobe setxattr_kretprobe = {
	.entry_handler  = entry_handler_setxattr,
	.data_size	= sizeof(struct pt_regs),
	.maxactive	= 300,
};

static int oplus_harden_init_succeed = 0;
#if 1
static struct kprobe kp_setregid = {
	.symbol_name    = func_name_setregid,
};
static struct kprobe kp_setgid = {
	.symbol_name    = func_name_setgid,
};
static struct kprobe kp_setreuid = {
	.symbol_name    = func_name_setreuid,
};
static struct kprobe kp_setesuid = {
	.symbol_name    = func_name_setuid,
};
static struct kprobe kp_setresuid = {
	.symbol_name    = func_name_setresuid,
};
static struct kprobe kp_setresgid = {
	.symbol_name    = func_name_setresgid,
};
static struct kprobe kp_setfsuid = {
	.symbol_name    = func_name_setfsuid,
};
static struct kprobe kp_setfsgid = {
	.symbol_name    = func_name_setfsgid,
};

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned int new_gid = 0;
	unsigned int new_uid = 0;
	unsigned int new_ruid = 0;
	unsigned int new_euid = 0;
	unsigned int new_suid = 0;
	unsigned int new_rgid = 0;
	unsigned int new_egid = 0;
	unsigned int new_sgid = 0;
	unsigned int new_fsuid = 0;
	unsigned int new_fsgid = 0;
/* current_cred */
	const struct cred *cred = current_cred();
	unsigned int cur_uid = cred->uid.val;
	unsigned int cur_gid = cred->gid.val;
	/* unsigned int cur_suid = cred->suid.val; */
	/* unsigned int cur_sgid = cred->sgid.val; */
	unsigned int cur_euid = cred->euid.val;
	unsigned int cur_egid = cred->egid.val;
	unsigned int cur_fsuid = cred->fsuid.val;
	unsigned int cur_fsgid = cred->fsgid.val;
	unsigned int callnum = 0;
	int symbol_name_len = strlen(p->symbol_name);
	enum COMMAND { __sys_setresuid, CLOSE, QUERY };
	if (!(memcmp(p->symbol_name, func_name_setregid, symbol_name_len))) {
		callnum = SYS_CALL_SETREGID;
		new_rgid = regs->regs[0];
		new_egid = regs->regs[1];
		if (capable(CAP_SETGID) == true) {
			pr_err(SECUREGUARD_NEW "11 There is func_name_setregid new_rgid %d new_egid %d \n", new_rgid, new_egid);
			if (cur_gid == OPLUS_AID_SHELL_UID || cur_gid >= OPLUS_ANDROID_THIRD_PART_APK_UID) {
				pr_err(SECUREGUARD_NEW "22 There is func_name_setregid new_rgid %d new_egid %d \n", new_rgid, new_egid);
				if ((new_rgid == OPLUS_ANDROID_ROOT_UID) || (new_egid == OPLUS_ANDROID_ROOT_UID)) {
					pr_err(SECUREGUARD_NEW "There is func_name_setregid new_rgid %d new_egid %d \n", new_rgid, new_egid);
					oplus_root_check_succ_upload(cur_uid, cur_euid, new_egid, callnum);
				}
			}
		}
	} else if (!(memcmp(p->symbol_name, func_name_setgid, symbol_name_len))) {
		callnum = SYS_CALL_SETGID;
		new_gid = regs->regs[0];
		if (capable(CAP_SETGID) == true) {
			if (cur_gid == OPLUS_AID_SHELL_UID || cur_gid >= OPLUS_ANDROID_THIRD_PART_APK_UID) {
				if (new_gid == OPLUS_ANDROID_ROOT_UID) {
					pr_err(SECUREGUARD_NEW "There is func_name_setgid \n");
					oplus_root_check_succ_upload(cur_uid, cur_euid, new_gid, callnum);
				}
			}
		}
	} else if (!(memcmp(p->symbol_name, func_name_setreuid, symbol_name_len))) {
		callnum = SYS_CALL_SETREUID;
		new_ruid = regs->regs[0];
		new_euid = regs->regs[1];
		if (capable(CAP_SETUID) == true) {
			if (cur_uid == OPLUS_AID_SHELL_UID || cur_uid >= OPLUS_ANDROID_THIRD_PART_APK_UID) {
				if ((new_ruid == OPLUS_ANDROID_ROOT_UID) || (new_euid == OPLUS_ANDROID_ROOT_UID)) {
					pr_err(SECUREGUARD_NEW "There is func_name_setreuid new_ruid %d new_euid %d \n", new_ruid, new_euid);
					oplus_root_check_succ_upload(cur_uid, new_euid, cur_egid, callnum);
				}
			}
		}
	} else if (!(memcmp(p->symbol_name, func_name_setuid, symbol_name_len))) {
		callnum = SYS_CALL_SETUID;
		new_uid = regs->regs[0];
		if (capable(CAP_SETUID) == true) {
			if (cur_uid == OPLUS_AID_SHELL_UID || cur_uid >= OPLUS_ANDROID_THIRD_PART_APK_UID) {
				pr_err(SECUREGUARD_NEW "33There is func_name_setuid new_uid %d \n", new_uid);
				if (new_uid == OPLUS_ANDROID_ROOT_UID) {
					pr_err(SECUREGUARD_NEW "There is func_name_setuid new_uid %d \n", new_uid);
					oplus_root_check_succ_upload(new_uid, cur_euid, cur_egid, callnum);
				}
			}
		}
	} else if (!(memcmp(p->symbol_name, func_name_setresuid, symbol_name_len))) {
		callnum = SYS_CALL_SETRESUID;
		new_ruid = regs->regs[0];
		new_euid = regs->regs[1];
		new_suid = regs->regs[2];
		if (capable(CAP_SETUID) == true) {
			if (cur_uid == OPLUS_AID_SHELL_UID || cur_uid >= OPLUS_ANDROID_THIRD_PART_APK_UID) {
				if ((new_ruid == OPLUS_ANDROID_ROOT_UID) || (new_euid == OPLUS_ANDROID_ROOT_UID) || (new_suid == OPLUS_ANDROID_ROOT_UID)) {
					pr_err(SECUREGUARD_NEW "There is func_name_setresuid new_ruid %d new_euid %d new_suid %d \n", new_ruid, new_euid, new_suid);
					oplus_root_check_succ_upload(cur_uid, new_euid, cur_egid, callnum);
				}
			}
		}
	} else if (!(memcmp(p->symbol_name, func_name_setresgid, symbol_name_len))) {
		callnum = SYS_CALL_SETRESGID;
		new_rgid = regs->regs[0];
		new_egid = regs->regs[1];
		new_sgid = regs->regs[2];
		if (capable(CAP_SETGID) == true) {
			if (cur_gid == OPLUS_AID_SHELL_UID || cur_gid >= OPLUS_ANDROID_THIRD_PART_APK_UID) {
				if ((new_rgid == OPLUS_ANDROID_ROOT_UID) || (new_egid == OPLUS_ANDROID_ROOT_UID) || (new_sgid == OPLUS_ANDROID_ROOT_UID)) {
					pr_err(SECUREGUARD_NEW "There is func_name_setresgid new_rgid %d new_egid %d new_sgid %d \n", new_rgid, new_egid, new_sgid);
					oplus_root_check_succ_upload(cur_uid, cur_euid, new_egid, callnum);
				}
			}
		}
	} else if (!(memcmp(p->symbol_name, func_name_setfsuid, symbol_name_len))) {
		callnum = SYS_CALL_SETFSUID;
		new_fsuid = regs->regs[0];
		if (capable(CAP_SETUID) == true) {
			if (cur_uid == OPLUS_AID_SHELL_UID || cur_uid >= OPLUS_ANDROID_THIRD_PART_APK_UID) {
				if(new_fsuid == OPLUS_ANDROID_ROOT_UID) {
					pr_err(SECUREGUARD_NEW "There is func_name_setfsuid new_fsuid %d \n", new_fsuid);
					oplus_root_check_succ_upload(new_fsuid, cur_fsuid, cur_egid, callnum);
				}
			}
		}
	} else if (!(memcmp(p->symbol_name, func_name_setfsgid, symbol_name_len))) {
		callnum = SYS_CALL_SETFSGID;
		new_fsgid = regs->regs[0];
		if (capable(CAP_SETGID) == true) {
			if (cur_gid == OPLUS_AID_SHELL_UID || cur_gid >= OPLUS_ANDROID_THIRD_PART_APK_UID) {
				if(new_fsgid == OPLUS_ANDROID_ROOT_UID) {
					pr_err(SECUREGUARD_NEW "There is func_name_setfsgid new_fsgid %d \n", new_fsgid);
					oplus_root_check_succ_upload(new_fsgid, cur_fsgid, cur_egid, callnum);
				}
			}
		}
	} else {
		pr_info(SECUREGUARD_NEW "There default \n");
	}
	return 0;
}
#endif

int oplus_harden_init(void)
{
	int ret = 0;

	sepolicy_reload_kretprobe.kp.symbol_name = func_name_sepolicy_reload;
	socket_kretprobe.kp.symbol_name = func_name_socket;
	socket_ip6_kretprobe.kp.symbol_name = func_name_socket_ip6;
	cpuinfo_kretprobe.kp.symbol_name = func_name_cpu_info;
	setxattr_kretprobe.kp.symbol_name = func_name_setxattr;

	do_execveat_common_kretprobe.kp.symbol_name = func_name_execve;
	capset_kretprobe.kp.symbol_name = func_name_capset;

	futex_kretprobe.kp.symbol_name = func_name_futex;
	ppoll_kretprobe.kp.symbol_name = func_name_ppoll;
	epoll_pwait_kretprobe.kp.symbol_name = func_name_epoll_pwait;
	ioctl_kretprobe.kp.symbol_name = func_name_ioctl;
	rt_tgsigqueueinfo_kretprobe.kp.symbol_name = func_name_rt_tgsigqueueinfo;
	nanosleep_kretprobe.kp.symbol_name = func_name_nanosleep;
	sigtimedwait_kretprobe.kp.symbol_name = func_name_sigtimedwait;

	kp_setregid.pre_handler = handler_pre;
	kp_setgid.pre_handler = handler_pre;
	kp_setreuid.pre_handler = handler_pre;
	kp_setesuid.pre_handler = handler_pre;
	kp_setresuid.pre_handler = handler_pre;
	kp_setresgid.pre_handler = handler_pre;
	kp_setfsuid.pre_handler = handler_pre;
	kp_setfsgid.pre_handler = handler_pre;
	pr_err(SECUREGUARD_NEW "register_kprobe sigtimedwait_kretprobe init ok  \n");
	ret = register_kprobe(&kp_setregid);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe kp_setregid error \n");
	}
	ret = register_kprobe(&kp_setgid);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe kp_setgid error \n");
	}
	ret = register_kprobe(&kp_setreuid);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe kp_setreuid error \n");
	}
	ret = register_kprobe(&kp_setesuid);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe kp_setesuid error \n");
	}
	ret = register_kprobe(&kp_setresuid);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe kp_setresuid error \n");
	}
	ret = register_kprobe(&kp_setresgid);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe kp_setresgid error \n");
	}
	ret = register_kprobe(&kp_setfsuid);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe kp_setfsuid error \n");
	}
	ret = register_kprobe(&kp_setfsgid);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe kp_setfsgid error \n");
	}
	ret = register_kretprobe(&do_execveat_common_kretprobe);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe do_execveat_common_kretprobe error \n");
	}
	ret = register_kretprobe(&capset_kretprobe);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe capset_kretprobe error \n");
	}
	ret = register_kretprobe(&futex_kretprobe);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe futex_kretprobe error \n");
	}
	ret = register_kretprobe(&ppoll_kretprobe);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe ppoll_kretprobe error \n");
	}
	ret = register_kretprobe(&epoll_pwait_kretprobe);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe epoll_pwait_kretprobe error \n");
	}
	ret = register_kretprobe(&ioctl_kretprobe);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe ioctl_kretprobe error \n");
	}
	ret = register_kretprobe(&rt_tgsigqueueinfo_kretprobe);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe rt_tgsigqueueinfo_kretprobe error \n");
	}
	ret = register_kretprobe(&nanosleep_kretprobe);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe nanosleep_kretprobe error \n");
	}
	ret = register_kretprobe(&sigtimedwait_kretprobe);
	if (ret < 0) {
		pr_err(SECUREGUARD_NEW "register_kprobe sigtimedwait_kretprobe error \n");
	}

#ifdef CONFIG_OPLUS_FEATURE_SECURE_SRGUARD
	ret = register_kretprobe(&sepolicy_reload_kretprobe);
	if (ret < 0) {
		pr_err(SG_MIX_HARDEN "%s:register sepolicy_write_load FAILED! ret %d.\n", __func__, ret);
		goto sepolicy_reload_kretprobe_failed;
	}
#endif

#ifdef CONFIG_OPLUS_FEATURE_SECURE_SOCKETGUARD
	ret = register_kretprobe(&socket_kretprobe);
	if (ret < 0) {
		pr_err(SG_MIX_HARDEN "%s:register do_setsocket_opt FAILED! ret %d.\n", __func__, ret);
		goto socket_kretprobe_failed;
	}
	ret = register_kretprobe(&socket_ip6_kretprobe);
	if (ret < 0) {
		pr_err(SG_MIX_HARDEN "%s:register do_ip6_setsocket_opt FAILED! ret %d.\n", __func__, ret);
		goto socket_ip6_kretprobe_failed;
	}
	ret = register_kretprobe(&cpuinfo_kretprobe);
	if (ret < 0) {
		pr_err(SG_MIX_HARDEN "%s:register func_name_cpu_info FAILED! ret %d.\n", __func__, ret);
		goto cpuinfo_kretprobe_failed;
	}

	ret = register_kretprobe(&setxattr_kretprobe);
	if (ret < 0) {
		pr_err(SG_MIX_HARDEN "%s:register func_name_setxattr FAILED! ret %d.\n", __func__, ret);
		goto setxattr_kretprobe_failed;
	}
#endif

	pr_info(SG_MIX_HARDEN "%s:secure_harden has been register.\n", __func__);
	oplus_harden_init_succeed = 1;
	return 0;

#ifdef CONFIG_OPLUS_FEATURE_SECURE_SOCKETGUARD
setxattr_kretprobe_failed:
	unregister_kretprobe(&cpuinfo_kretprobe);
cpuinfo_kretprobe_failed:
	unregister_kretprobe(&socket_ip6_kretprobe);
socket_ip6_kretprobe_failed:
	unregister_kretprobe(&socket_kretprobe);
socket_kretprobe_failed:
#endif
#ifdef CONFIG_OPLUS_FEATURE_SECURE_SRGUARD
	unregister_kretprobe(&sepolicy_reload_kretprobe);
sepolicy_reload_kretprobe_failed:
#endif

	unregister_kretprobe(&capset_kretprobe);
	unregister_kretprobe(&do_execveat_common_kretprobe);
	return ret;
}

void oplus_harden_exit(void)
{
	if (oplus_harden_init_succeed != 1)
		return;
	unregister_kprobe(&kp_setregid);
	unregister_kprobe(&kp_setgid);
	unregister_kprobe(&kp_setreuid);
	unregister_kprobe(&kp_setesuid);
	unregister_kprobe(&kp_setresuid);
	unregister_kprobe(&kp_setresgid);
	unregister_kprobe(&kp_setfsuid);
	unregister_kprobe(&kp_setfsgid);

	unregister_kretprobe(&do_execveat_common_kretprobe);
	unregister_kretprobe(&capset_kretprobe);

	unregister_kretprobe(&futex_kretprobe);
	unregister_kretprobe(&ppoll_kretprobe);
	unregister_kretprobe(&epoll_pwait_kretprobe);
	unregister_kretprobe(&ioctl_kretprobe);
	unregister_kretprobe(&rt_tgsigqueueinfo_kretprobe);
	unregister_kretprobe(&nanosleep_kretprobe);
	unregister_kretprobe(&sigtimedwait_kretprobe);

#ifdef CONFIG_OPLUS_FEATURE_SECURE_SRGUARD
	unregister_kretprobe(&sepolicy_reload_kretprobe);
#endif

#ifdef CONFIG_OPLUS_FEATURE_SECURE_SOCKETGUARD
	unregister_kretprobe(&socket_kretprobe);
	unregister_kretprobe(&socket_ip6_kretprobe);
	unregister_kretprobe(&cpuinfo_kretprobe);
	unregister_kretprobe(&setxattr_kretprobe);
#endif
	pr_info(SG_MIX_HARDEN "%s:secure_harden has been unregister.\n", __func__);
}
