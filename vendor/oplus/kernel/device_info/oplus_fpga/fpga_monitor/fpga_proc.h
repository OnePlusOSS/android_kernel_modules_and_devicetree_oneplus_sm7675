#ifndef _FPGA_PROC_H
#define _FPGA_PROC_H
int fpga_proc_create(struct fpga_mnt_pri *mnt_pri);
void fpga_gen_errcode(struct fpga_mnt_pri *mnt_pri);
void fpga_poll_wakeup(struct fpga_mnt_pri *mnt_pri, uint64_t type);
#endif /* _FPGA_PROC_H */