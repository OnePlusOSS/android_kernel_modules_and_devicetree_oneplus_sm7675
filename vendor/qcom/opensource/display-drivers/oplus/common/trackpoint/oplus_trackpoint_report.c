// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023-2023 Oplus. All rights reserved.
 */


#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/err.h>
#include <linux/string.h>
#include <net/genetlink.h>

#include "oplus_trackpoint_report.h"

#define GENL_FAMILY_TRACKPOINT_NAME "trackpoint"
#define GENL_FAMILY_TRACKPOINT_VERSION 1
#define SERVER_TOKEN "DTLM"

enum trackpoint_cmd {
	TRACKPOINT_CMD_UNSPEC = 0,
	TRACKPOINT_CMD_REGISTER,	/* user->kernel cmd */
	TRACKPOINT_CMD_UPLOAD,		/* kernel->user cmd */
};

enum register_cmd_attr {
	REGISTER_CMD_ATTR_UNSPEC = 0,
	REGISTER_CMD_ATTR_TOKEN,

		/* keep last */
	__REGISTER_CMD_ATTR_MAX,
	REGISTER_CMD_ATTR_MAX = __REGISTER_CMD_ATTR_MAX -1 ,
};

enum upload_cmd_attr{
	UPLOAD_CMD_ATTR_UNSPEC = 0,
	UPLOAD_CMD_ATTR_TYPE,
	UPLOAD_CMD_ATTR_EVENT_ID,
	UPLOAD_CMD_ATTR_SUB_EVENT_ID,
	UPLOAD_CMD_ATTR_MESSAGE,
	UPLOAD_CMD_ATTR_FUNC_LINE,

	/* keep last */
	__UPLOAD_CMD_ATTR_MAX,
	UPLOAD_CMD_ATTR_MAX = __UPLOAD_CMD_ATTR_MAX -1 ,
};

static struct genl_family trackpoint_genl_family;
static struct workqueue_struct *trackpoint_wq;
static bool trackpoint_init;
static int server_pid = 0;

struct trackpoint_event {
	struct work_struct work;
	struct trackpoint tp;
};

static int trackpoint_register_pid(struct sk_buff *skb, struct genl_info *info)
{
	char *token = NULL;

	if (!trackpoint_init) {
		pr_err("%s: trackpoint_report not init\n", __func__);
		return -1;
	}

	token = nla_data(info->attrs[REGISTER_CMD_ATTR_TOKEN]);
	if (!strcmp(SERVER_TOKEN, token)) {
		server_pid = nlmsg_hdr(skb)->nlmsg_pid;
	}

	pr_info("%s: sucess\n", __func__);
	return 0;
}

static void trackpoint_event_work(struct work_struct *work)
{
	struct trackpoint_event *event = container_of(work, struct trackpoint_event, work);
	struct sk_buff *skb;
	int ret = 0;

	pr_info("%s: the trackpoint report work start\n", __func__);

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb) {
		pr_err("%s: genlmsg_new failed\n", __func__);
		return;
	}

	genlmsg_put(skb, server_pid, 0, &trackpoint_genl_family, 0, TRACKPOINT_CMD_UPLOAD);
	nla_put_s32(skb, UPLOAD_CMD_ATTR_TYPE, event->tp.type);
	nla_put_s32(skb, UPLOAD_CMD_ATTR_EVENT_ID, event->tp.event_id);
	nla_put_s32(skb, UPLOAD_CMD_ATTR_SUB_EVENT_ID, event->tp.sub_event_id);
	nla_put_string(skb, UPLOAD_CMD_ATTR_MESSAGE, event->tp.message);
	nla_put_string(skb, UPLOAD_CMD_ATTR_FUNC_LINE, event->tp.func_line);
	kfree(event);

	genlmsg_end(skb, genlmsg_data(nlmsg_data(nlmsg_hdr(skb))));
	ret = genlmsg_unicast(&init_net, skb, server_pid);

	if (ret) {
		pr_err("%s: the trackpoint report work failed\n", __func__);
	} else {
		pr_info("%s: the trackpoint report work success\n", __func__);
	}
}

int trackpoint_report(struct trackpoint *tp)
{
	struct trackpoint_event *event = NULL;
	char buf[4] = {};

	if (!trackpoint_init) {
		pr_err("%s: trackpoint_report not init\n", __func__);
		return -1;
	}
	pr_info("%s: event_id=%d, message:%s\n", __func__, tp->event_id, tp->message);

	event = kzalloc(sizeof(*event), GFP_ATOMIC);
	if (!event) {
		pr_info("%s: kzalloc trackpoint_event failed\n", __func__);
		return -ENOMEM;
	}

	/* extract sub_event_id from str like this: DisplayDriverID@@425$$... */
	memcpy(buf, tp->message + 17, 3);
	(void)kstrtoint(buf, 10, &tp->sub_event_id);

	INIT_WORK(&event->work, trackpoint_event_work);
	memcpy(&event->tp, tp, sizeof(*tp));
	pr_info("%s: queue the trackpoint report work to trackpoint_wq\n", __func__);
	queue_work(trackpoint_wq, &event->work);

	return 0;
}
EXPORT_SYMBOL(trackpoint_report);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
static struct nla_policy register_cmd_policy[REGISTER_CMD_ATTR_MAX + 1] = {
	[REGISTER_CMD_ATTR_TOKEN]	= { .type = NLA_NUL_STRING },
};

static const struct genl_ops trackpoint_genl_ops[] = {
	{
		.cmd		= TRACKPOINT_CMD_REGISTER,
		.doit		= trackpoint_register_pid,
		.policy		= register_cmd_policy,
		.maxattr	= ARRAY_SIZE(register_cmd_policy) - 1,
	},
};

static struct genl_family trackpoint_genl_family __ro_after_init = {
	.name		= GENL_FAMILY_TRACKPOINT_NAME,
	.version	= GENL_FAMILY_TRACKPOINT_VERSION,
	.module		= THIS_MODULE,
	.ops		= trackpoint_genl_ops,
	.n_ops		= ARRAY_SIZE(trackpoint_genl_ops),
};
#else
static const struct genl_ops trackpoint_genl_ops[] = {
	{
		.cmd		= TRACKPOINT_CMD_REGISTER,
		.doit		= trackpoint_register_pid,
	},
};

static struct genl_family trackpoint_genl_family __ro_after_init = {
	.name		= GENL_FAMILY_TRACKPOINT_NAME,
	.version	= GENL_FAMILY_TRACKPOINT_VERSION,
	.module		= THIS_MODULE,
	.ops		= trackpoint_genl_ops,
	.n_ops		= ARRAY_SIZE(trackpoint_genl_ops),
};
#endif

static int __init trackpoint_report_init(void)
{
	int ret = 0;

	ret = genl_register_family(&trackpoint_genl_family);
	if (ret) {
		pr_err("%s: genl_register_family error:%d\n", __func__, ret);
		return ret;
	}

	trackpoint_wq = create_singlethread_workqueue("trackpoint_wq");
	if (!trackpoint_wq) {
		pr_err("%s: create trackpoint_wq failed\n", __func__);
		return -1;
	}

	trackpoint_init = true;
	pr_info("%s: success, family id:%d\n", __func__, trackpoint_genl_family.id);
	return 0;
}

static void __exit trackpoint_report_exit(void)
{
	destroy_workqueue(trackpoint_wq);
	genl_unregister_family(&trackpoint_genl_family);
	pr_info("%s: success\n", __func__);
}

module_init(trackpoint_report_init);
module_exit(trackpoint_report_exit);

MODULE_DESCRIPTION("trackpoint_report");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL v2");
