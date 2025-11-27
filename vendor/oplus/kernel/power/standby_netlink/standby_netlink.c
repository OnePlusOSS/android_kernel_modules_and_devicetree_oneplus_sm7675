#include <linux/module.h>
#include <linux/init.h>

#include "standby_netlink.h"

static const struct nla_policy standby_genl_policy[STANDBY_GENL_ATTR_MAX + 1] = {
    [STANDBY_GENL_ATTR_OPTION_TYPE] = { .type = NLA_U32},     // Using 32-bit unsigned integer for 4-byte alignment
    [STANDBY_GENL_ATTR_INFO_TYPE] = { .type = NLA_U32 },       // Using 32-bit unsigned integer for 4-byte alignment
};

static const struct genl_ops standby_netlink_genl_ops[] = {
    {
        .cmd = STANDBY_GENL_CMD_REQUEST,
        .doit = netlink_handler_request,
        .policy = standby_genl_policy,
    },
    {
        .cmd = STANDBY_GENL_CMD_CHANGE_SWITCH,
        .doit = netlink_handler_switch_state,
        .policy = standby_genl_policy,
    },
};

struct genl_family standby_netlink_genl_family = {
    /* The unique identifier of the genl family, assigned by the kernel upon registration. */
    .id = 0,

    /* The name of the genl family, used for identification. */
    .name = STANDBY_NETLINK_FAMILY,

    /* The version of the genl family, used for versioning purposes. */
    .version = STANDBY_NETLINK_FAMILY_VERSION,

    /* The maximum number of attributes this genl family can handle. */
    .maxattr = STANDBY_GENL_ATTR_MAX,

    /* Pointer to the array of genl operations (genl_ops) supported by this family. */
    .ops = standby_netlink_genl_ops,

    /* The number of operations (genl_ops) in the array pointed to by .ops. */
    .n_ops = ARRAY_SIZE(standby_netlink_genl_ops),
};

static int __init standby_netlink_init(void)
{
    int ret = -1;
    if (get_info_handler_size() <= 0) {
        pr_info("[standby_netlink]: No available info on current platform.\n");
        return -EINVAL;
    }

    ret = genl_register_family(&standby_netlink_genl_family);
    if (ret) {
        pr_info("[standby_netlink]: genl_register_family:%s error,ret = %d\n", STANDBY_NETLINK_FAMILY, ret);
        return ret;
    } else {
        pr_info("[standby_netlink]: genl_register_family complete, id = %d!\n", standby_netlink_genl_family.id);
    }

    return 0;
}

static void __exit standby_netlink_exit(void)
{
    genl_unregister_family(&standby_netlink_genl_family);
    pr_info("[standby_netlink]: exit successfully!");
}

module_init(standby_netlink_init);
module_exit(standby_netlink_exit);

MODULE_AUTHOR("Lofam.Wu");
MODULE_DESCRIPTION("Oplus standby netlink module");
MODULE_LICENSE("GPL v2");