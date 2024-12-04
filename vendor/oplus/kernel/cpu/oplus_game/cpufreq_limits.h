#ifndef _OPLUS_GAME_CPUFREQ_LIMITS_H_
#define _OPLUS_GAME_CPUFREQ_LIMITS_H_

typedef void (*oplus_game_update_cpu_freq_cb_t)(void);
int oplus_game_get_max_freq(int policy);
void do_ed_freq_boost_request(unsigned int boost_type);
int cpufreq_limits_init(void);
void cpufreq_limits_exit(void);

extern oplus_game_update_cpu_freq_cb_t oplus_game_update_cpu_freq_cb;

#endif