#ifndef _FPGA_MID_H
#define _FPGA_MID_H

int fpga_i2c_write(struct fpga_mnt_pri *mnt_pri,
		   u8 reg, u8 *data, size_t len);
int fpga_i2c_read(struct fpga_mnt_pri *mnt_pri,
		  u8 reg, u8 *data, size_t len);
#endif /* _FPGA_MID_H */