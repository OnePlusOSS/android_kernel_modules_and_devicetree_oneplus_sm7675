#ifndef FRK_NETLINK_H
#define FRK_NETLINK_H



#include <linux/version.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/genetlink.h>


#define MSG_START_IDX 2


enum event_no {
	THREAD_WATCHER_EVENT = 1,
	LOWMEM_WATCHER_EVENT = 2,
};

#define OPLUS_FRK_FAMILY_NAME			"oplus_frk_nl"
#define OPLUS_FRK_FAMILY_VER			1
#define OPLUS_FRK_GENL_ID_GENERATE		0


/* cmd type */
enum {
	OPLUS_FRK_CMD_UNDEFINE = 0,
	OPLUS_FRK_CMD_RECV,				/* recv_from_user */
	OPLUS_FRK_CMD_SEND,				/* send_to_frk */
	__OPLUS_FRK_CMD_MAX,
};
#define OPLUS_FRK_CMD_MAX (__OPLUS_FRK_CMD_MAX - 1)

/* attribute type */
enum {
	OPLUS_FRK_ATTR_MSG_UNDEFINE = 0,
	OPLUS_FRK_ATTR_MSG_GENL,
	__OPLUS_FRK_ATTR_MSG_MAX
};
#define OPLUS_FRK_ATTR_MSG_MAX (__OPLUS_FRK_ATTR_MSG_MAX - 1)

int send_to_frk(int event_type, size_t len, const int *data);
void create_frk_netlink(int socket_no);
void destroy_frk_netlink(void);

#endif	/* FRK_NETLINK_H */
