#ifndef _STANDBY_NETLINK_DEPS_H
#define _STANDBY_NETLINK_DEPS_H

/**
 * info_handler_t - Function pointer type for info handling callbacks
 *
 * The handler populates a buffer with information and returns the length of the
 * buffer.
 */
typedef int (*info_handler_t)(char **buf);

int handle_smp2p_info(char **buf);
int handle_regs_info(char **buf);
int handle_clock_info(char **buf);
void reset_smp2p_switch(int switch_state);
#endif  /* _STANDBY_NETLINK_DEPS_H */
