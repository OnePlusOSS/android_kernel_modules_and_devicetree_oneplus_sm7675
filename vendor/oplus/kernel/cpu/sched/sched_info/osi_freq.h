/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2022 Oplus. All rights reserved.
 */

#ifndef __OPLUS_CPU_OSI_FREQ_H__
#define __OPLUS_CPU_OSI_FREQ_H__


#define DO_CLAMP		BIT(0)
#define DO_INCREASE		BIT(1)

void osi_opp_init(struct cpufreq_policy *policy);
int  osi_freq_init(struct proc_dir_entry *pde);
void osi_freq_exit(struct proc_dir_entry *pde);
void osi_cpufreq_transition_handler(struct cpufreq_policy *policy,
		unsigned int new_freq);
void get_cpufreq_info(bool *is_sample);

void jank_curr_freq_show(struct seq_file *m,
			u32 win_idx, u64 now);
void jank_burst_freq_show(struct seq_file *m,
			u32 win_idx, u64 now);
void jank_increase_freq_show(struct seq_file *m,
			u32 win_idx, u64 now);
#endif  /* endif */
