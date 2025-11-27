#include "standby_netlink.h"
#include "standby_netlink_deps.h"

// default close all info switch
static u32 info_switch = 0;

/**
 * struct info_handler - Netlink information handler descriptor
 * @type: The info type (STANDBY_NETLINK_INFO_TYPE enum)
 * @handler: Callback function to process this info type
 *
 * Maps specific netlink info types to their handler functions.
 * Used to dispatch different info requests to proper handlers.
 */
struct info_handler {
    STANDBY_NETLINK_INFO_TYPE type;
    info_handler_t handler;
};

/**
 * handlers - Static registry of netlink info type handlers
 *
 * This array defines all supported netlink information types and their
 * corresponding handler functions.
 */
static const struct info_handler handlers[] = {
// add Qcom platform related info
#ifdef CONFIG_OPLUS_STANDBY_NETLINK_QCOM
    {STANDBY_GENL_INFO_SMP2P, handle_smp2p_info},
    {STANDBY_GENL_INFO_CLOCK, handle_clock_info},
    {STANDBY_GENL_INFO_REGS, handle_regs_info},
#endif

// add MTK platform related info here
#ifdef CONFIG_OPLUS_STANDBY_NETLINK_MTK
#endif
};

int get_info_handler_size(void)
{
    return ARRAY_SIZE(handlers);
}

static int process_info(struct sk_buff *reply_skb, u32 types)
{
    char *buf = NULL;
    int ret;
    u32 type;

    for (int i = 0; i < ARRAY_SIZE(handlers); i++) {
        ret = -1;

        type = handlers[i].type;
        if (!(info_switch & type)) {
            pr_warn("[standby_netlink]: type %d not enabled\n", type);
            continue;
        }

        if (!(types & type))
            continue;

        ret = handlers[i].handler(&buf);
        pr_info("[standby_netlink]: type:%d, len:%d\n", handlers[i].type, ret);
        if (!buf) {
            pr_err("[standby_netlink]: buf mem error.\n");
            continue;
        }

        if (ret <= 0)
            continue;

        ret = nla_put_string(reply_skb, type, buf);
        kfree(buf);
        buf = NULL;
        if (ret) {
            pr_err("[standby_netlink]: put attribute %d error. ret=%d\n", type, ret);
            return ret;
        }
    }
    return 0;
}

/* Send Generic Netlink reply for given info type */
static int reply_info(struct genl_info *info, u32 types)
{
    struct sk_buff *reply_skb;
    void *reply_head;
    int ret;

    // Allocate reply buffer
    reply_skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!reply_skb)
        return -ENOMEM;

    // Setup message header
    reply_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq,
                     &standby_netlink_genl_family, 0, (u8)STANDBY_GENL_CMD_REPLY);
    if (!reply_head) {
        nlmsg_free(reply_skb);
        return -ENOBUFS;
    }

    // Add payload and send
    ret = process_info(reply_skb, types);
    if (ret) {
        nlmsg_free(reply_skb);
        return ret;
    }

    // Finalize message (calculates length and checks validity)
    genlmsg_end(reply_skb, reply_head);

    // Transmit reply and automatically free SKB
    ret = genlmsg_reply(reply_skb, info);
    pr_info("[standby_netlink]: send info len %d bytes. ret %d\n", reply_skb->len, ret);

    return ret;
}

int netlink_handler_request(struct sk_buff *skb, struct genl_info *info)
{
    u32 types, sanitized_type;

    // 1. Validate required attributes exist
    if (!info->attrs[STANDBY_GENL_ATTR_INFO_TYPE]) {
        pr_err("[standby_netlink]: Missing required attributes.\n");
        return -EINVAL;
    }

    // 2. Extract values from netlink attributes
    types = nla_get_u32(info->attrs[STANDBY_GENL_ATTR_INFO_TYPE]);

    // 3. Validate types range
    sanitized_type = types & FUNC_TYPE_MASK;
    if (types == STANDBY_GENL_INFO_UNSPEC) {
        pr_err("[standby_netlink]: Invalid type 0 (UNSPEC), valid range: 1-0x%x\n", FUNC_TYPE_MASK);
        return -EINVAL;
    }

    if (types & ~FUNC_TYPE_MASK)
        pr_warn("[standby_netlink]: type 0x%x are out of range (max allowed: 0x%x), truncated to 0x%x\n",
            types, FUNC_TYPE_MASK, sanitized_type);

    // 3. Send formatted info back using the received attr types
    return reply_info(info, types);
}

static void on_switch_change(int switch_type, int changed_type)
{
    if (changed_type & STANDBY_GENL_INFO_SMP2P)
        reset_smp2p_switch(switch_type);
}

int netlink_handler_switch_state(struct sk_buff *skb, struct genl_info *info)
{
    u32 option, type, sanitized_type, changed_type, origin_switch = info_switch;

    // 1. Validate required attributes exist
    if (!info->attrs[STANDBY_GENL_ATTR_OPTION_TYPE] || !info->attrs[STANDBY_GENL_ATTR_INFO_TYPE]) {
        pr_err("[standby_netlink]: Missing required attributes.\n");
        return -EINVAL;
    }

    // 2. Extract values from netlink attributes
    option = nla_get_u32(info->attrs[STANDBY_GENL_ATTR_OPTION_TYPE]);
    type = nla_get_u32(info->attrs[STANDBY_GENL_ATTR_INFO_TYPE]);

    // 3. Validate type range
    sanitized_type = type & FUNC_TYPE_MASK;
    if (type == STANDBY_GENL_INFO_UNSPEC) {
        pr_err("[standby_netlink]: Invalid type 0 (UNSPEC), valid range: 1-0x%x\n", FUNC_TYPE_MASK);
        return -EINVAL;
    }

    if (type & ~FUNC_TYPE_MASK)
        pr_warn("[standby_netlink]: type 0x%x are out of range (max allowed: 0x%x), truncated to 0x%x\n",
               type, FUNC_TYPE_MASK, sanitized_type);

    // 4. Safely update switch state using bit operations
    if (option == OPTION_OPEN_SWITCH) {
        info_switch |= sanitized_type;
        changed_type = ~origin_switch & info_switch;
    } else if (option == OPTION_CLOSE_SWITCH) {
        info_switch &= ~sanitized_type;
        changed_type = ~info_switch & origin_switch;
    } else {
        pr_err("[standby_netlink]: Invalid option.\n");
        return -EINVAL;
    }
    pr_info("[standby_netlink]: info_switch change from %u to %u, changed type: %d.\n",
        origin_switch, info_switch, changed_type);

    // 5. Call switch change handler
    on_switch_change(option, changed_type);

    return 0;
}
