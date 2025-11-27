#ifndef _STANDBY_NETLINK_H
#define _STANDBY_NETLINK_H

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/genetlink.h>

#define STANDBY_NETLINK_FAMILY_VERSION	1
#define STANDBY_NETLINK_FAMILY "standby_netlink"

/* commands */
enum standby_genl_commands {
    STANDBY_GENL_CMD_UNSPEC = 0,
    STANDBY_GENL_CMD_CHANGE_SWITCH,
    STANDBY_GENL_CMD_REQUEST,
    STANDBY_GENL_CMD_REPLY,
    __STANDBY_GENL_CMD_MAX,
};
#define STANDBY_GENL_CMD_MAX (__STANDBY_GENL_CMD_MAX - 1)

/* options */
typedef enum {
    OPTION_CLOSE_SWITCH,  // close one info switch
    OPTION_OPEN_SWITCH,  // open one info switch
    OPTION_REQUEST_INFO,  // request info
} OPTION_TYPE;

/* attributes */
enum {
    STANDBY_GENL_ATTR_UNSPEC = 0,
    STANDBY_GENL_ATTR_OPTION_TYPE,           // OPTION TYPE
    STANDBY_GENL_ATTR_INFO_TYPE,          // INFO TYPE
    __STANDBY_GENL_ATTR_MAX,
};
#define STANDBY_GENL_ATTR_MAX (__STANDBY_GENL_ATTR_MAX - 1)

/* info types. WARNNING!!! : Max attr value must less than 1 << 32. */
typedef enum {
    STANDBY_GENL_INFO_UNSPEC = 0,
    STANDBY_GENL_INFO_SMP2P = 1 << 0,      // smp2p info
    STANDBY_GENL_INFO_CLOCK = 1 << 1,    // clock info
    STANDBY_GENL_INFO_REGS = 1 << 2,     // regs info
    __STANDBY_GENL_INFO_MAX = 1 << 3,
} STANDBY_NETLINK_INFO_TYPE;
#define FUNC_TYPE_MASK (__STANDBY_GENL_INFO_MAX - 1)

extern struct genl_family standby_netlink_genl_family;

int netlink_handler_request(struct sk_buff *skb, struct genl_info *info);
int netlink_handler_switch_state(struct sk_buff *skb, struct genl_info *info);
int get_info_handler_size(void);

#endif  /* _STANDBY_NETLINK_H */