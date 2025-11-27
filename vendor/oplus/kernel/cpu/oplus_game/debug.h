#ifndef _OPLUS_GAME_DEBUG_H_
#define _OPLUS_GAME_DEBUG_H_

#define debug_tprintk(fmt, ...)                                                \
	do {                                                                   \
		trace_printk("[oplus_bsp_cpu_game] " fmt, ##__VA_ARGS__);          \
	} while (0)

int debug_init(void);
void systrace_c_printk(const char *msg, unsigned long val);

#endif