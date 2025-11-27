// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023-2025 Oplus. All rights reserved.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/genetlink.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include "oplus_audio_netlink_kernel.h"

#define KNL_NT_FAMILY_VERSION	1
#define KNL_NT_FAMILY "aud_knl_nt"
#define GENL_ID_GENERATE	0

static struct mm_knl_nt_module knl_modules[MM_KNL_NT_MODULE_SIZE_MAX];
static volatile bool knl_nt_init_flag = false;
static spinlock_t knl_lock;
static DEFINE_MUTEX(mm_kevent_lock);

/* record connect pid and modules */
static void mm_knl_nt_add_module(u32 pid, char *module)
{
	int i = 0x0;
	int len = 0x0;

	if (!module) {
		return;
	}

	len = strlen(module);
	if (len > (MM_KNL_NT_MODULE_LEN_MAX - 1)) {
		pr_err("knl_nt: nt_module len is larger than %d error\n", MM_KNL_NT_MODULE_LEN_MAX);
		return;
	}

	for (i = 0; i < MM_KNL_NT_MODULE_SIZE_MAX; i++) {
		if ((!knl_modules[i].pid) || (!strcmp(knl_modules[i].modl, module))) {
			spin_lock(&knl_lock);
			knl_modules[i].pid = pid;
			memcpy(knl_modules[i].modl, module, len);
			knl_modules[i].modl[len] = 0x0;
			spin_unlock(&knl_lock);
			return;
		}
	}

	return;
}

/* record connect pid and modules */
static int mm_knl_nt_get_pid(char *module)
{
	int i = 0;

	if (!module) {
		return MM_KNL_NT_BAD_VALUE;
	}

	for (i = 0; i < MM_KNL_NT_MODULE_SIZE_MAX; i++) {
		if (!strcmp(knl_modules[i].modl, module)) {
			return knl_modules[i].pid;
		}
	}

	return MM_KNL_NT_BAD_VALUE;
}

static int mm_knl_nt_send_module(struct sk_buff *skb,
	struct genl_info *info)
{
	struct sk_buff *skbu = NULL;
	struct nlmsghdr *nlh;
	struct nlattr *na = NULL;
	char *pmesg = NULL;

	if (!knl_nt_init_flag) {
		pr_err("%s: knl_nt: not init error\n", __func__);
		return -1;
	}

	skbu = skb_get(skb);
	if (!skbu) {
		pr_err("knl_nt: skb_get result is null error\n");
		return -1;
	}

	if (info->attrs[KNL_NT_CMD_ATTR_MS]) {
		na = info->attrs[KNL_NT_CMD_ATTR_MS];
		nlh = nlmsg_hdr(skbu);
		pmesg = (char*)kmalloc(nla_len(na) + 0x10, GFP_KERNEL);
		if (pmesg) {
			memcpy(pmesg, nla_data(na), nla_len(na));
			pmesg[nla_len(na)] = 0x0;
			pr_info("knl_nt: nla_len(na) %d, pid %d, module: %s\n",
					nla_len(na), nlh->nlmsg_pid, pmesg);
			mm_knl_nt_add_module(nlh->nlmsg_pid, pmesg);
		}
	}

	if (pmesg) {
		kfree(pmesg);
	}
	if (skbu) {
		kfree_skb(skbu);
	}

	return 0;
}

static ssize_t audio_msg_state_write(struct file *file,
				const char __user *buf,
				size_t count,
				loff_t *off)
{
	char *r_buf = NULL;
	unsigned int len = 0;

	if (!knl_nt_init_flag) {
		pr_err("%s: knl_nt: error, module not init\n", __func__);
		return -EINVAL;
	}

	r_buf = (char *)kzalloc(MAX_PAYLOAD_DATASIZE, GFP_KERNEL);
	if (!r_buf) {
		pr_err("%s: knl_nt: kzalloc failed\n", __func__);
		return count;
	}

	if (count > *off) {
		count -= *off;
	} else {
		count = 0;
	}

	*off += count;
	len = MAX_PAYLOAD_DATASIZE > count ? count : MAX_PAYLOAD_DATASIZE;
	if (copy_from_user(r_buf, buf, len)) {
		goto exit;
	}

	pr_info("knl_nt: %s: len = %u\n", __func__, len);
	mutex_lock(&mm_kevent_lock);
	mm_knl_nt_kevent_send_to_user(AUDIO_KERNEL_NATIVE_COM, r_buf, len);
	mutex_unlock(&mm_kevent_lock);

exit:
	kfree(r_buf);
	return count;
}

static ssize_t audio_msg_state_read(struct file *file,
				char __user *buf,
				size_t count,
				loff_t *off)
{
	if (!knl_nt_init_flag) {
		pr_err("%s: knl_nt: error, module not init\n", __func__);
		return -EINVAL;
	}

	return count;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
static struct nla_policy mm_knl_genl_policy[KNL_NT_CMD_ATTR_MAX + 1] = {
	[KNL_NT_CMD_ATTR_MS] = { .type = NLA_NUL_STRING },
	[KNL_NT_CMD_ATTR_OPT] = { .type = NLA_U32 },
};

static const struct genl_ops mm_knl_genl_ops[] = {
	{
		.cmd		= KNL_NT_GENL_SEND_MODULE,
		.doit		= mm_knl_nt_send_module,
		.policy		= mm_knl_genl_policy,
	},
};

static struct genl_family knl_nt_genl_family __ro_after_init = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = KNL_NT_FAMILY,
	.version = KNL_NT_FAMILY_VERSION,
	.maxattr = KNL_NT_CMD_ATTR_MAX,
	.module = THIS_MODULE,
	.policy = mm_knl_genl_policy,
	.ops = mm_knl_genl_ops,
	.n_ops = ARRAY_SIZE(mm_knl_genl_ops),
};

static const struct proc_ops audio_msg_state_fops = {
	.proc_write = audio_msg_state_write,
	.proc_read = audio_msg_state_read,
	.proc_lseek = default_llseek,
	.proc_open = simple_open,
};
#else
static const struct genl_ops mm_knl_genl_ops[] = {
	{
		.cmd		= KNL_NT_GENL_SEND_MODULE,
		.doit		= mm_knl_nt_send_module,
	},
};

static struct genl_family knl_nt_genl_family __ro_after_init = {
	.id = GENL_ID_GENERATE,
	.name = KNL_NT_FAMILY,
	.version = KNL_NT_FAMILY_VERSION,
	.maxattr = KNL_NT_CMD_ATTR_MAX,
	.module = THIS_MODULE,
	.ops = mm_knl_genl_ops,
	.n_ops = ARRAY_SIZE(mm_knl_genl_ops),
};

static const struct file_operations audio_msg_state_fops = {
	.write = audio_msg_state_write,
	.read = audio_msg_state_read,
	.open = simple_open,
	.owner = THIS_MODULE,
};
#endif

static inline int genl_msg_prepare_usr_msg(unsigned char cmd, size_t size,
	pid_t pid, struct sk_buff **skbp)
{
	struct sk_buff *skb;

	/* create a new netlink msg */
	skb = genlmsg_new(size, GFP_KERNEL);

	if (skb == NULL) {
		pr_err("knl_nt: genlmsg_new failed\n");
		return -ENOMEM;
	}

	/* Add a new netlink message to an skb */
	genlmsg_put(skb, pid, 0, &knl_nt_genl_family, 0, cmd);

	*skbp = skb;
	return 0;
}

static inline int genl_msg_mk_usr_msg(struct sk_buff *skb, int type, void *data,
	int len)
{
	int ret = 0;

	/* add a netlink attribute to a socket buffer */
	ret = nla_put(skb, type, len, data);

	return ret;
}

/* send to user space */
int mm_knl_nt_kevent_send_to_user(char *module, char *data, int len)
{
	int ret;
	int size_use;
	int payload_size;
	struct sk_buff *skbuff;
	void * head;
	int pid;

	if (!knl_nt_init_flag) {
		pr_err("%s: knl_nt: not init error\n", __func__);
		return MM_KNL_NT_BAD_VALUE;
	}

	/* protect payload too long problem*/
	if (len >= MAX_PAYLOAD_DATASIZE) {
		pr_err("knl_nt: payload_length out of range error\n");
		return MM_KNL_NT_BAD_VALUE;
	}

	pid = mm_knl_nt_get_pid(module);
	if (pid == MM_KNL_NT_BAD_VALUE) {
		pr_err("knl_nt: module = %s get pid error\n", module);
		return MM_KNL_NT_BAD_VALUE;
	}

	payload_size = len;
	size_use = nla_total_size(payload_size);
	ret = genl_msg_prepare_usr_msg(KNL_NT_GENL_UPLOAD, size_use, pid, &skbuff);
	if (ret) {
		pr_err("knl_nt: genl_msg_prepare_usr_msg error, ret is %d \n", ret);
		return ret;
	}

	ret = genl_msg_mk_usr_msg(skbuff, KNL_NT_CMD_ATTR_MS, data, payload_size);
	if (ret) {
		pr_err("knl_nt: genl_msg_mk_usr_msg error, ret is %d \n", ret);
		kfree_skb(skbuff);
		return ret;
	}

	head = genlmsg_data(nlmsg_data(nlmsg_hdr(skbuff)));
	genlmsg_end(skbuff, head);

	ret = genlmsg_unicast(&init_net, skbuff, pid);
	pr_info("knl_nt: genlmsg_unicast: pid = %d, module = %s\n", pid, module);
	if (ret < 0) {
		pr_err("knl_nt: genlmsg_unicast fail = %d \n", ret);
		return MM_KNL_NT_BAD_VALUE;
	}

	return MM_KNL_NT_NO_ERROR;
}
EXPORT_SYMBOL(mm_knl_nt_kevent_send_to_user);

int __init mm_knl_nt_module_init(void) {
	int ret;

	struct proc_dir_entry *d_entry = NULL;
	ret = genl_register_family(&knl_nt_genl_family);
	if (ret) {
		pr_err("knl_nt: genl_register_family:%s error,ret = %d\n", KNL_NT_FAMILY, ret);
		return ret;
	} else {
		pr_info("knl_nt: genl_register_family complete, id = %d!\n", knl_nt_genl_family.id);
	}

	spin_lock_init(&knl_lock);
	memset(knl_modules, 0x0, sizeof(knl_modules));

	/* create /proc/audio_msg_kel file node */
	d_entry = proc_create_data("audio_msg_kel", 0666, NULL, &audio_msg_state_fops, NULL);
	if (!d_entry) {
		pr_err("%s: knl_nt failed to create file node\n", __func__);
		ret = -ENODEV;
		return ret;
	}

	knl_nt_init_flag = true;
	pr_info("knl_nt: init ok\n");
	return MM_KNL_NT_NO_ERROR;
}

void __exit mm_knl_nt_module_exit(void) {
	genl_unregister_family(&knl_nt_genl_family);
	remove_proc_entry("audio_msg_kel", NULL);

	knl_nt_init_flag = false;
	pr_info("knl_nt: exit\n");
}

module_init(mm_knl_nt_module_init);
module_exit(mm_knl_nt_module_exit);

MODULE_DESCRIPTION("knl_nt@1.0");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL v2");


