#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/timex.h>

#include <clocksource/arm_arch_timer.h>

#include "gw_fpgadown.h"

#define VERSION "v091606"

volatile int buflen_v = 0;

unsigned char program = 1; // 0: No program flash, 1: program flash
unsigned char refresh = 1; // 0: No refresh, 1: REPROGRAM
u8 g_load_path = 1;
struct fpga_dw_pri fpga_dw;


#define ns2cycles(ns) ((ns) / 50)// 19.2MHZ
//#define delay_xxx(a)
void runtest_xxus(uint32_t xxus, uint32_t freq_hz, uint32_t cycle);

#if 0
void delay_xxx(u32 nsecs)
{
	// __ndelay(250);

	// ndelay(200);
	// volatile u32 t;
	// for(t = 0; t < delay; t++);
	/* cycles_t target = get_cycles();

	 target += ns2cycles(250);
	 while (get_cycles() < target)8、
	   cpu_relax();*/
	/* u64 target = get_cycles();
	 target += 5;
	 while (get_cycles() < target)*/

	// hrtimer_nanosleep(200, HRTIMER_MODE_REL, CLOCK_MONOTONIC);


}
#endif

#ifdef ADJ_TCK_FREQ //如果打开了频率自动调整
void test_tck_loop(int dely_t, int loop_t)
{
	int i = 0;

#ifdef ON_PROTRCT_TCK
	local_irq_disable();
#endif
	for (i = 0; i < loop_t; i++) {
		/*//gpio_set_value(PIN_TCK, 1);
		TCK_1;
		// FPGA_INFO("o");
		for (t = 0; t < dely_t; t++)
		    ;
		//gpio_set_value(PIN_TCK, 0);
		TCK_0;
		// FPGA_INFO(".");
		for (t = 0; t < dely_t; t++);*/
		GW_TCK(0);
		delay_xxx(dely_t);
		GW_TCK(1);
		delay_xxx(dely_t);
	}
#ifdef ON_PROTRCT_TCK
	local_irq_enable();
#endif

}

int cal_clk_clycle(int tohz, u32 set_timeus)
{
	u64 start, end;
	struct timespec64 tv_1, tv_2;
	int tick_2 = 0;
	u32 clk = 0;
	int set_delay_cle = 1;//SET_DELAY_CYLE_S;
	// 1.输入数据:set_timeus:测量时间以us为单位 , to_hz：目标是调整到xxhz
	// 2.由设置的测量时间大概算出要循环的次数即clk; // tohz: 1mhz  settime: 100,000us --> clk = settime * (to_hz/1000,000)
	// clk= 时间 / 周期（1/f）; 周期是以s为单位需要 换成us 1us = （1/1000000） s
	// clk = set_timeus * (tohz/1000000.0); //内核不支持浮点运算SSE register return with SSE disabled
	clk = set_timeus * (tohz / 1000000);
	FPGA_INFO("set_timeus:%d tohz:%dhz clk:%d", set_timeus, tohz, clk);
	while (1) {
		ktime_get_real_ts64(&tv_1); //开始前获取timeval_1值
		start = ktime_get_ns();
		test_tck_loop(set_delay_cle, clk);
		end = ktime_get_ns();
		ktime_get_real_ts64(&tv_2); //结束后获取 timeval_2
		tick_2 = ((tv_2.tv_sec - tv_1.tv_sec) * 1000000) + (tv_2.tv_nsec - tv_1.tv_nsec) / 1000;
		// FPGA_INFO("tick2:%dus set_delay_cle: %d sched_clock %ld\n", tick_2, set_delay_cle, end - start);
#if 0
		FPGA_INFO(" tv_1.tv_sec  :%lds ---tv_2.tv_sec  :%lds \n", tv_1.tv_sec, tv_2.tv_sec);
		FPGA_INFO(" tv_1.tv_usec :%ldus---tv_2.tv_usec :%ldus \n", tv_1.tv_usec, tv_2.tv_usec);
#endif
		/* if (tick_2 >= set_timeus)
		     break;*/
		set_delay_cle++;
		if (set_delay_cle > 100) {
			break;
		}
	}
	FPGA_INFO("--->set_delay_cle: %d \n", set_delay_cle);
	return set_delay_cle;
}

#endif

unsigned int readPort(void)
{
	unsigned int val = *(const volatile u32 __force *)tdo_mem_base;
	//unsigned int val = readl(tdo_mem_base);
	if (val) {
		return 0x01;
	} else {
		return 0x00;
	}

	/*  if (gpio_get_value(PIN_TDO))
	       return 0x01;
	   else
	       return 0x00;*/
}

void jtag_tap_move_oneclock(char tms_value)
{
	if (tms_value) {
		GW_TMS(1);
	} else {
		GW_TMS(0);
	}

	GW_TCK(0);
	delay_xxx(DELAY_LEN);
	GW_TCK(1);
	delay_xxx(DELAY_LEN);
}

void jtag_move_tap(tap_def TAP_From, tap_def TAP_To)
{
	int i = 0;
	if ((TAP_From == TAP_UNKNOWN) && (TAP_To == TAP_IDLE)) {
		for (i = 0; i < 8; i++) {
			jtag_tap_move_oneclock(1);
		}
		jtag_tap_move_oneclock(0);
		jtag_tap_move_oneclock(0);
	}

	else if ((TAP_From == TAP_IDLE) && (TAP_To == TAP_IDLE)) {
		for (i = 0; i < 3; i++) {
			jtag_tap_move_oneclock(0);
		}
	}

	else if ((TAP_From == TAP_IDLE) && (TAP_To == TAP_IRSHIFT)) {
		jtag_tap_move_oneclock(1);
		jtag_tap_move_oneclock(1);
		jtag_tap_move_oneclock(0);
		jtag_tap_move_oneclock(0);
	}

	else if ((TAP_From == TAP_IDLE) && (TAP_To == TAP_DRSHIFT)) {

		jtag_tap_move_oneclock(1);
		jtag_tap_move_oneclock(0);
		jtag_tap_move_oneclock(0);
	}

	else if ((TAP_From == TAP_IREXIT1) && (TAP_To == TAP_IDLE)) {

		jtag_tap_move_oneclock(1);
		jtag_tap_move_oneclock(0);
		jtag_tap_move_oneclock(0);
	}

	else if ((TAP_From == TAP_DREXIT1) && (TAP_To == TAP_IDLE)) {

		jtag_tap_move_oneclock(1);
		jtag_tap_move_oneclock(0);
		jtag_tap_move_oneclock(0);
	}

	else {
		FPGA_INFO("error tap walking.\r\n");
	}
}

void jtag_reset(void)
{
	jtag_move_tap(TAP_UNKNOWN, TAP_IDLE);
}

void jtag_run_test(int cycles)
{
	int i = 0;
	for (i = 0; i < cycles; i++) {
		jtag_tap_move_oneclock(0);
	}
}

uint32_t jtag_write(uint8_t din, uint8_t dout, uint8_t tms, int LSB)
{

	int i = 0;
	int tmp = 0;
	uint32_t dout_new = 0;

	if (LSB == 0) {
		// MSB
		uint8_t _tmp_din = 0;
		uint8_t sign = 1;
		for (i = 0; i <= 7; i++) {
			_tmp_din |= ((din & (sign << i)) >> i) << (7 - i);
		}

		din = _tmp_din;
	}

	GW_TMS(0);

	for (i = 0; i < 8; i++) {
		if (i == 7) {
			if (tms & 1) {
				GW_TMS(1);
			} else {
				GW_TMS(0);
			}
		}

		tmp = din >> i;
		if (1 & tmp) {
			GW_TDI(1);
		} else {
			GW_TDI(0);
		}

		GW_TCK(0);
		delay_xxx(DELAY_LEN);
		GW_TCK(1);
		delay_xxx(DELAY_LEN);

		dout_new <<= 1;
		dout_new |= (GW_TDO & 1);
	}

	return dout_new;
}

void jtag_write_inst(uint8_t inst)
{

	jtag_move_tap(TAP_IDLE, TAP_IRSHIFT);
	jtag_write(inst, 0x0, 0x1, 0x1); // LSB, true  LSB / false  MSB
	jtag_move_tap(TAP_IREXIT1, TAP_IDLE);

	jtag_move_tap(TAP_IDLE, TAP_IDLE);
	jtag_move_tap(TAP_IDLE, TAP_IDLE);
	jtag_move_tap(TAP_IDLE, TAP_IDLE);
}

uint8_t lock_IO(void)
{
	jtag_move_tap(TAP_IDLE, TAP_IDLE);
	jtag_move_tap(TAP_IDLE, TAP_IDLE);

	jtag_move_tap(TAP_IDLE, TAP_IRSHIFT);
	jtag_write(0x01, 0x0, 0x1, 0x1); // inst: 0x01  Exit1-IR

	jtag_tap_move_oneclock(1); // updata-IR
	jtag_tap_move_oneclock(1); // Select-DR-scan
	jtag_tap_move_oneclock(0); // Capture-DR
	jtag_tap_move_oneclock(1); // Exit1-DR
	jtag_tap_move_oneclock(1); // Updata-DR
	jtag_tap_move_oneclock(1); // Select-DR-scan
	jtag_tap_move_oneclock(1); // Select-IR-scan
	jtag_tap_move_oneclock(0); // Capture-IR
	jtag_tap_move_oneclock(0); // Shirft-IR

	jtag_write(0x04, 0x0, 0x1, 0x1); // inset:04  Exit1-IR
	jtag_tap_move_oneclock(1);       // updata-IR

	jtag_tap_move_oneclock(0); // IDLE
	jtag_move_tap(TAP_IDLE, TAP_IDLE);
	jtag_move_tap(TAP_IDLE, TAP_IDLE);
	jtag_move_tap(TAP_IDLE, TAP_IDLE);
	return 0;
}

void hotboot_mode(uint32_t chain_len, uint8_t cmd)
{
	int i = 0;
	int c_len = chain_len;
	char rd_data[525] = {0};

#if 1 // read bsdl
	jtag_write_inst(0x01);

	jtag_move_tap(TAP_IDLE, TAP_DRSHIFT);

	//  c_len = 244; //

	for (i = 0; i < (c_len - 1); i++) {
		jtag_tap_move_oneclock(0);
		GW_TDI(0);
		rd_data[i] = GW_TDO;
		GW_TCK(0);
	}
	jtag_tap_move_oneclock(1); // Exit1-DR //c_len - 1
	rd_data[i] = GW_TDO;
	GW_TCK(0);

	jtag_move_tap(TAP_DREXIT1, TAP_IDLE);
	jtag_move_tap(TAP_IDLE, TAP_IDLE);
	jtag_move_tap(TAP_IDLE, TAP_IDLE);

#endif // read end

#if 0
	//if (lockio == 1)
	lock_IO();
#endif

	rd_data[196] = 1; // IOT6B
	rd_data[197] = 0;

	if (cmd == 1) { // write data
		jtag_write_inst(0x01); // IN_TEST

		jtag_move_tap(TAP_IDLE, TAP_DRSHIFT);

		for (i = 0; i < c_len - 1; i++) {
			if (rd_data[i]) {
				GW_TDI(1);
			} else {
				GW_TDI(0);
			}
			jtag_tap_move_oneclock(0);
		}

		if (rd_data[i]) { // c_len - 1
			GW_TDI(1);
		} else {
			GW_TDI(0);
		}
		jtag_tap_move_oneclock(1);

		jtag_move_tap(TAP_DREXIT1, TAP_IDLE);
		jtag_move_tap(TAP_IDLE, TAP_IDLE);
		jtag_move_tap(TAP_IDLE, TAP_IDLE);
		jtag_move_tap(TAP_IDLE, TAP_IDLE);
		jtag_write_inst(0x04); // EXIT_TEST
	}

	delay_ms(1);

#if 1
	rd_data[196] = 1; // IOT6B
	rd_data[197] = 1;

	if (cmd == 1) { // write data
		jtag_move_tap(TAP_IDLE, TAP_DRSHIFT);

		for (i = 0; i < c_len - 1; i++) {
			if (rd_data[i]) {
				GW_TDI(1);
			} else {
				GW_TDI(0);
			}
			jtag_tap_move_oneclock(0);
		}

		if (rd_data[i]) { // c_len - 1
			GW_TDI(1);
		} else {
			GW_TDI(0);
		}
		jtag_tap_move_oneclock(1);

		jtag_move_tap(TAP_DREXIT1, TAP_IDLE);
		jtag_move_tap(TAP_IDLE, TAP_IDLE);
		jtag_move_tap(TAP_IDLE, TAP_IDLE);
		jtag_move_tap(TAP_IDLE, TAP_IDLE);
		jtag_write_inst(0x04); // EXIT_TEST
	}
#endif
}

uint8_t revert_one_byte(uint8_t in)
{
	int i = 0;
	uint8_t _tmp_din = 0;
	uint8_t sign = 1;
	for (i = 0; i < 8; i++) {
		_tmp_din |= ((in & (sign << i)) >> i) << (7 - i);
	}

	return _tmp_din;
}

uint32_t jtag_transmit(uint32_t tdi, uint32_t tms, int length, int lsb)
{
	// lsb=1, lsb is true
	// lsb=0, msb is true

	// int j = 0;
	int i = 0;
	uint32_t out = 0;

	if (lsb == 0) {
		tdi = revert_one_byte(tdi & 0xff);
	}

	for (i = 0; i < length; i++) {

		if ((tms >> i) & 0x01) {
			GW_TMS(1);
		} else {
			GW_TMS(0);
		}

		if ((tdi >> i) & 0x01) {
			GW_TDI(1);
		} else {
			GW_TDI(0);
		}

		GW_TCK(0);
		delay_xxx(DELAY_LEN);
		GW_TCK(1);
		delay_xxx(DELAY_LEN);

		if (lsb) {
			out |= GW_TDO ? 1 << i : 0;
		} else {
			out <<= 1;
			out |= GW_TDO ? 0x1 : 0;
		}
	}

	return out;
}

#if 0
void clear_sram(void)
{
	jtag_write_inst(0x11);
	jtag_write_inst(0x15);
	jtag_write_inst(0x05);

	jtag_write_inst(0x02);

	jtag_run_test(0xE00);

	jtag_write_inst(0x09);
	jtag_write_inst(0x3A);

	jtag_write_inst(0x02);
	jtag_write_inst(0x11);
}
#endif

void jtag_ef_prog_write_one_X_address(uint32_t address_index)
{
	int i = 0;
	int tmp = 0;

	jtag_move_tap(TAP_IDLE, TAP_DRSHIFT);

	for (i = 0; i < 6; i++) {
		GW_TDI(0);

		GW_TCK(0);
		delay_xxx(DELAY_LEN);
		GW_TCK(1);
		delay_xxx(DELAY_LEN);
	}

	for (i = 0; i < 26; i++) {
		if (i == 25) {
			GW_TMS(1);
		}

		tmp = address_index >> i;
		if (1 & tmp) {
			GW_TDI(1);
		} else {
			GW_TDI(0);
		}

		GW_TCK(0);
		delay_xxx(DELAY_LEN);
		GW_TCK(1);
		delay_xxx(DELAY_LEN);
	}

	jtag_move_tap(TAP_DREXIT1, TAP_IDLE);
}

void jtag_ef_prog_one_Y(uint8_t data_array[4])
{
	int i = 3;
	uint8_t tms;

	// FPGA_INFO("%02X%02X%02X%02X   ", data_array[3], data_array[2],data_array[1],data_array[0]);

	jtag_move_tap(TAP_IDLE, TAP_DRSHIFT);

	for (i = 3; i >= 0; i--) {
		tms = (i == 0) ? 1 : 0;
		jtag_write(data_array[i], 0x0, tms, 1);
	}

	jtag_move_tap(TAP_DREXIT1, TAP_IDLE);
	jtag_move_tap(TAP_IDLE, TAP_IDLE);
	jtag_move_tap(TAP_IDLE, TAP_IDLE);
	jtag_move_tap(TAP_IDLE, TAP_IDLE);
}

void jtag_ef_prog_one_X_TSMC(uint8_t data_array[256], uint32_t address_index)
{
	int i = 0;
	uint8_t y_page[4] = {0};

#ifdef LOWRATE
	// programming for low rate
	jtag_write(0x03, 0x00, 0x00, 1);
	jtag_write(0xfe, 0x00, 0x00, 1);
	jtag_write(0xcd, 0x00, 0x00, 1);
	jtag_write(0xab, 0x00, 0x00, 1);
#endif

	jtag_write_inst(READ_ID_CODE);
	jtag_write_inst(ISC_ENABLE);
	jtag_write_inst(JTAG_EF_PROGRAM);

	if (address_index > 0) { // 12us - 16 us
#ifdef LOWRATE
		jtag_run_test(35);
#else
		runtest_xxus(16, USE_FREQ_XHZ, g_tck_delay_len); // 12us - 16 us
#endif
	}

	jtag_ef_prog_write_one_X_address(address_index);

#ifdef LOWRATE
	jtag_run_test(35);
#else
	runtest_xxus(12, USE_FREQ_XHZ, g_tck_delay_len);     // 12us - 16 us
#endif

	for (i = 0; i < 256; i += 4) {

		y_page[0] = data_array[i];
		y_page[1] = data_array[i + 1];
		y_page[2] = data_array[i + 2];
		y_page[3] = data_array[i + 3];

		jtag_ef_prog_one_Y(y_page);

#ifdef LOWRATE
		jtag_run_test(35);
#else
		runtest_xxus(13, USE_FREQ_XHZ, g_tck_delay_len); // after one y-page delay 13-15 us
#endif
	}


#ifdef LOWRATE
	jtag_run_test(15);
#else
	runtest_xxus(6, USE_FREQ_XHZ, g_tck_delay_len);      // after one x-page delay 6us
#endif

	jtag_write_inst(ISC_DISABLE);
	jtag_write_inst(ISC_NOOP);

#ifdef LOWRATE
	// programming for low rate
	jtag_write(0x04, 0x00, 0x00, 1);
	jtag_write(0xfe, 0x00, 0x00, 1);
	jtag_write(0xcd, 0x00, 0x00, 1);
	jtag_write(0xab, 0x00, 0x00, 1);
	// FPGA_INFO("send abcdfe04 \n");
	delay_ms(6); // wait x-page send ok again next x-page
#endif
}

uint8_t jtag_ef_verify_y(uint8_t data_array[4])
{

	int i = 0;
	uint8_t data_temp[4] = {0};
	uint32_t out = 0;

	jtag_move_tap(TAP_IDLE, TAP_DRSHIFT);

	GW_TMS(0);

	for (i = 0; i < 32; i++) {
		if (i == 31) {
			GW_TMS(1);
		}

		GW_TCK(0);
		delay_xxx(DELAY_LEN);
		GW_TCK(1);
		delay_xxx(DELAY_LEN);
		out |= GW_TDO ? 1 << i : 0;
	}

	jtag_move_tap(TAP_DREXIT1, TAP_IDLE);

	data_temp[0] = (out >> 24) & 0xff;
	data_temp[1] = (out >> 16) & 0xff;
	data_temp[2] = (out >> 8) & 0xff;
	data_temp[3] = (out >> 0) & 0xff;

	for (i = 3; i >= 0; i--) {
		if (data_array[i] != data_temp[i]) {
			FPGA_INFO("%d--wr:%x re:%x \n", i, data_array[i], data_temp[i]);
			return 0x0;
		}
	}
	return 0x1;
}

uint32_t jtag_read_code(uint8_t inst)
{
	uint8_t i = 0;
	uint32_t out = 0;
	uint32_t code = 0;

	jtag_write_inst(inst);
	jtag_move_tap(TAP_IDLE, TAP_DRSHIFT);

	GW_TMS(0);
	for (i = 0; i < 32; i++) {
		if (i == 31) {
			GW_TMS(1);
		}

		GW_TCK(0);
		delay_xxx(DELAY_LEN);
		GW_TCK(1);
		// delay_xxx(DELAY_LEN);

		out |= GW_TDO << i;
	}

	code = out;

	jtag_move_tap(TAP_DREXIT1, TAP_IDLE);
	jtag_run_test(10);

	return code;
}

uint8_t jtag_ef_erase_TSMC(uint8_t type)
{

#ifdef LOWRATE
	// uint32_t _code;
	FPGA_INFO("\n ------ low rate ----\n");
	// programming for low rate
	jtag_write(0x01, 0x00, 0x00, 1);
	jtag_write(0xfe, 0x00, 0x00, 1);
	jtag_write(0xcd, 0x00, 0x00, 1);
	jtag_write(0xab, 0x00, 0x00, 1);

	delay_ms(130);

	jtag_write(0x02, 0x00, 0x00, 1);
	jtag_write(0xfe, 0x00, 0x00, 1);
	jtag_write(0xcd, 0x00, 0x00, 1);
	jtag_write(0xab, 0x00, 0x00, 1);

	jtag_write_inst(ISC_DISABLE);
	jtag_write_inst(ISC_NOOP);

	jtag_run_test(20000);

	return 0x1;

#else
	/***EF_ERASE****/
	jtag_write_inst(READ_ID_CODE);
	jtag_write_inst(ISC_ENABLE);
	jtag_write_inst(JTAG_EF_ERASE);
	//  runtest_xxus(500, USE_FREQ_XHZ, g_tck_delay_len); // 500us

	jtag_move_tap(TAP_IDLE, TAP_DRSHIFT);
	jtag_run_test(6);

	jtag_tap_move_oneclock(0); // Shift-DR
	jtag_tap_move_oneclock(1); // Exit1-DR
	jtag_tap_move_oneclock(0); // Pause-DR

	jtag_run_test(16);
	jtag_tap_move_oneclock(1); // Exit2-DR
	jtag_tap_move_oneclock(0); // Shift-DR
	jtag_tap_move_oneclock(1); // Exit1-DR
	jtag_tap_move_oneclock(1); // Update-DR
	jtag_tap_move_oneclock(0); // Run-Test/Idle
	jtag_tap_move_oneclock(0);
	jtag_tap_move_oneclock(0);
	jtag_tap_move_oneclock(0);

	runtest_xxus(140000, USE_FREQ_XHZ, g_tck_delay_len); // 120ms

	jtag_write_inst(ISC_DISABLE);
	jtag_write_inst(ISC_NOOP);

	delay_ms(200);

#endif

	jtag_write_inst(READ_ID_CODE);

	if (type == PROG_GENERAL) {
		jtag_write_inst(REPROGRAM);
		jtag_write_inst(ISC_NOOP);
		runtest_xxus(100000, USE_FREQ_XHZ, g_tck_delay_len);
	}

	return 0x0;
}

void refresh_two(void)
{
#if 0
	hotboot_mode(244, 1);
	delay_ms(300);
	jtag_write_inst(0xFF);
	delay_ms(200);
#else
	jtag_read_code(0x11);

	jtag_write_inst(REPROGRAM);
	jtag_write_inst(ISC_NOOP); // 200ms
	delay_ms(200);
#endif
}

uint8_t jtag_ef_prog_TSMC(char *fs_p, uint32_t len, uint8_t verify, uint8_t background_prog)
{
	uint32_t i = 0, t = 0;
	uint32_t code = 0;
	int page_index = 0;
	uint8_t ret_verify = 1;
	uint8_t data_array[256] = {0};
	uint8_t y_data_array[4] = {0};

	code = jtag_read_code(READ_STATUS_CODE);
	FPGA_INFO("erase flash begin code: %08X\n", code);
	local_irq_disable();
	jtag_ef_erase_TSMC(background_prog);
	local_irq_enable();
	code = jtag_read_code(READ_STATUS_CODE);
	FPGA_INFO("erase flash finish code: %08X\n", code);


	for (i = 0; i < len; i += 256) {
		memcpy(data_array, &fs_p[i], 256);

		if (page_index == 0) {
			if (verify == 0x1) {
				data_array[0] = 0xF7;
				data_array[1] = 0xF7;
				data_array[2] = 0x3F;
				data_array[3] = 0x4F;
			} else {
				// autoboot
				data_array[0] = 0x47;
				data_array[1] = 0x57;
				data_array[2] = 0x31;
				data_array[3] = 0x4E;
			}
		}

		local_irq_disable();
		jtag_ef_prog_one_X_TSMC(data_array, page_index);
		local_irq_enable();

		page_index++;
	}

	delay_ms(200);

	if (verify == 0x1) {
		if (background_prog != PROG_BACKGROUND) {
			jtag_write_inst(REPROGRAM);
			jtag_write_inst(ISC_NOOP);
			delay_ms(1000);
		}
		jtag_write_inst(ISC_ENABLE);
		jtag_write_inst(JTAG_EF_READ);
		jtag_run_test(100);

		jtag_ef_prog_write_one_X_address(0);
		runtest_xxus(16, 500000, g_tck_delay_len); // 16us

		page_index = 0;
		for (i = 0; i < len; i += 256) {
			memcpy(data_array, &fs_p[i], 256);

			if (page_index == 0) {
				data_array[0] = 0xF7;
				data_array[1] = 0xF7;
				data_array[2] = 0x3F;
				data_array[3] = 0x4F;
			}

			for (t = 0; t < 256; t += 4) {
				y_data_array[0] = data_array[t + 0];
				y_data_array[1] = data_array[t + 1];
				y_data_array[2] = data_array[t + 2];
				y_data_array[3] = data_array[t + 3];
				if (jtag_ef_verify_y(y_data_array) == 0x0) {
					ret_verify = 0x0;
					FPGA_INFO("verify fail :%d \n", i);
					// break;
					return ret_verify;
				}
			}
			page_index++;
		}

		jtag_write_inst(ISC_DISABLE);
		jtag_write_inst(ISC_NOOP);

		// autoboot
		data_array[0] = 0x47;
		data_array[1] = 0x57;
		data_array[2] = 0x31;
		data_array[3] = 0x4E;

		for (i = 4; i < 256; i++) {
			data_array[i] = 0xFF;
		}

		jtag_write_inst(ISC_ENABLE);
#ifdef ON_PROTRCT_TCK
		local_irq_disable();
#endif
		jtag_ef_prog_one_X_TSMC(data_array, 0);
#ifdef ON_PROTRCT_TCK
		local_irq_enable();
#endif
		jtag_run_test(20);

		jtag_write_inst(ISC_DISABLE);
		jtag_write_inst(ISC_NOOP);
		jtag_run_test(20);
	}

	jtag_write_inst(READ_ID_CODE);

	delay_ms(2000);
	jtag_reset();
	code = jtag_read_code(READ_STATUS_CODE);
	FPGA_INFO("\n jtag_ef_prog_TSMC() finish, status code: %08X \n", code);

#if 0
	if (refresh == 1) {
		refresh_two();
	}
#endif
	return ret_verify;
}

/**
 * @brief   check  DONE final bit of status code
 * @param   uint32_t status-code
 * @return  uint8_t
 */
uint8_t done_final_is_low(uint32_t code)
{
	code >>= 13;
	if (code & 0x01) {
		return 0x0;
	} else {
		return 0x1;
	}
}

void runtest_xxus(uint32_t xxus, uint32_t freq_hz, uint32_t cycle)
{

	//   unsigned long count = 0;
	//   uint32_t count_t = 2;
	u64 start;
	start = sched_clock();

	//  count = (unsigned long)(xxus * freq_hz / 1000000);
	//  count_t = (uint32_t)(count + 1); // Use double count directly after for loop error

	//  FPGA_INFO("rentest:%dus, %dhz count:%lu\n", xxus, freq_hz, count);

	do {
		GW_TCK(0);
		delay_xxx(DELAY_LEN);
		//wmb();
		GW_TCK(1);
		delay_xxx(DELAY_LEN);
		//wmb();
	} while ((sched_clock() - start) < (xxus * 1000));


	return;
}

void adj_tckfreq(int cycle)
{
	uint32_t count_t = 1000;
	for (; count_t > 1; count_t--) {
		GW_TCK(0);
		delay_xxx(DELAY_LEN);
		GW_TCK(1);
		delay_xxx(DELAY_LEN);
	}
}

void chip_reinit(void)
{
	FPGA_INFO("chip_reinit\n");
	jtag_reset();
	jtag_write_inst(0x3a);
	jtag_write_inst(0x02);
	jtag_write_inst(0x41);
	delay_ms(500);
	jtag_write_inst(0x15);
	jtag_write_inst(0x3f);
	jtag_write_inst(0x02);
	delay_ms(1000);
}

void reconfig(void)
{
	delay_ms(1000);
	jtag_write_inst(ISC_ENABLE);
	jtag_write_inst(REPROGRAM);
	jtag_write_inst(ISC_DISABLE);
	jtag_write_inst(ISC_NOOP);
}

uint8_t jtag_erase_sram(void)
{
	uint32_t code = 0;

	jtag_reset();

	jtag_write_inst(ISC_ENABLE); // 0x15
	jtag_write_inst(ISC_ERASE);  // 0x05
	jtag_write_inst(ISC_NOOP);   // 0x02

	runtest_xxus(6000, 500000, g_tck_delay_len); // 6ms

	jtag_write_inst(ERASE_DONE);  // 0x09
	jtag_write_inst(ISC_NOOP);    // 0x02
	jtag_write_inst(ISC_DISABLE); // 0x3a
	jtag_write_inst(ISC_NOOP);
	runtest_xxus(10000, 500000, g_tck_delay_len);

	code = jtag_read_code(READ_STATUS_CODE);

	if (done_final_is_low(code)) {
		FPGA_INFO("done is low, STATUS_CODE: %x\n", code);
		return 0x1;
	}

	return 0x0;
}
void sram_clear_1(void)
{

	FPGA_INFO("clear sram 1\n");
	jtag_write_inst(0x15);
	jtag_write_inst(0x3a);
	jtag_write_inst(0x02);
	jtag_write_inst(0x11);
	jtag_reset();
	jtag_write_inst(0x3c);
	jtag_reset();
	jtag_write_inst(0x15);
	jtag_write_inst(0x3a);
	jtag_write_inst(0x11);
	delay_ms(500);
	jtag_write_inst(0x11);
	jtag_write_inst(0x15);
	jtag_write_inst(0x3a);
	jtag_write_inst(0x11);
	jtag_write_inst(0x11);
}
int jtag_prog_sram(char *fs_p, uint32_t len, uint8_t type)
{
	// uint8_t res;
	uint32_t i = 0;

	jtag_reset();

	// sram sram
	jtag_erase_sram();

	// send config Enable inst
	jtag_write_inst(ISC_ENABLE);
	jtag_write_inst(INIT_ADDRESS); // 0x12
	// send Write SRAM inst
	jtag_write_inst(FAST_PROGRAM);

	// TAP move from TAP_IDLE to TAP_DRSHIFT
	jtag_move_tap(TAP_IDLE, TAP_DRSHIFT);

	for (i = 0; i < len; i++) {
		jtag_write(fs_p[i], 0, 0, 0);
	}

	jtag_write(0xFF, 0x0, 0x1, 0);

	// TAP move from TAP_DREXIT1 to TAP_IDLE
	jtag_move_tap(TAP_DREXIT1, TAP_IDLE);

	// send config disable inst
	jtag_write_inst(ISC_DISABLE);

	// send Noop AND play over.
	jtag_write_inst(ISC_NOOP);

	return 1;
}

extern u8 *dbg_buf;
extern u64 dbg_buf_len;
int gowin_main(u8 *data_buf, uint32_t fssize)
{
	int ret = 0;
	int i = 0;
	uint32_t code = 0;
	//    u64 start;

#if 1//ADJ_TCK_FREQ
	/* local_irq_disable();
	 g_tck_delay_len = cal_clk_clycle(TO_2_0MHZ, SET_1MS);
	 FPGA_INFO(" to_hz:%dhz set_time:%dus g_tck_delay_len %d; end the test\n", TO_2_0MHZ, SET_1MS, g_tck_delay_len);
	 local_irq_enable();*/

	unsigned long flag;

	local_irq_save(flag);
	runtest_xxus(120000, USE_FREQ_XHZ, g_tck_delay_len); // 120ms
	delay_ms(100);
	runtest_xxus(120000, USE_FREQ_XHZ, g_tck_delay_len); // 120ms
	delay_ms(100);
	runtest_xxus(120000, USE_FREQ_XHZ, g_tck_delay_len); // 120ms
	local_irq_restore(flag);

	FPGA_INFO("dbg_buf_len %ld \n", dbg_buf_len);
	for (i = 0; i < dbg_buf_len; i++) {
		trace_printk("fpga_download total len %ld, dbg_buf[%d] %d\n", dbg_buf_len, i, dbg_buf[i]);
	}
	dbg_buf_len = 0;

	return 0;
#endif

#if 0
	adj_tckfreq(DELAY_LEN); // TCK frequency adjustment requires setting DELAY_LEN
#endif
	jtag_reset();
	jtag_write_inst(0x3A);
	jtag_write_inst(0x02);
	delay_ms(100);

	code = jtag_read_code(0x11);
	FPGA_INFO("025 jtag id code: %08X, %08X \n", code, ID_GW1N2);
	FPGA_INFO("start jtag id code: %08X, %08X \n", code, ID_GW1N2);
	runtest_xxus(120000, USE_FREQ_XHZ, g_tck_delay_len); // 120ms
	FPGA_INFO("end jtag id code: %08X, %08X \n", code, ID_GW1N2);
	delay_ms(100);
#if 0
	delay_ms(100);
	local_irq_disable();
	FPGA_INFO("start jtag id code: %08X, %08X \n", code, ID_GW1N2);
	// runtest_xxus(120000, USE_FREQ_XHZ, g_tck_delay_len); // 120ms
	runtest_xxus(120000, USE_FREQ_XHZ, g_tck_delay_len); // 120ms
	FPGA_INFO("end jtag id code: %08X, %08X \n", code, ID_GW1N2);
	local_irq_enable();
	FPGA_INFO("start jtag id code");
	start = ktime_get_ns();
	FPGA_INFO("end jtag id code %ld", start);
	FPGA_INFO("1 start jtag id code");
	start = local_clock();
	FPGA_INFO("1 end jtag id code %ld", start);

	return 0;
#endif
	code = jtag_read_code(READ_STATUS_CODE);
	FPGA_INFO("jtag_befor prog_sram--code: %08x, %08X\n", code, (code & 0xffff));
	FPGA_INFO("-------\n");
	for (i = 16; i < 32; i++) {
		FPGA_INFO("%02x ", data_buf[i]);
	}
	FPGA_INFO("-------\n");

	if (g_load_path == 0) { //(code & 0xffff) != 0xF020 &&
		// clear_sram();
		if ((code & 0xffff) != 0x9020) {
			sram_clear_1();
			code = jtag_read_code(READ_STATUS_CODE);
			FPGA_INFO("clear_sram code: %08x, %08X\n", code, (code & 0xffff));
		}
		jtag_prog_sram(data_buf, fssize, (uint8_t)0);
	}


	FPGA_INFO("id code: %08X", jtag_read_code(0x11));
	FPGA_INFO("user code: %08X", jtag_read_code(0x13));
	FPGA_INFO("status code: %08X", jtag_read_code(0x41));

#if 0
	if (program == 0) {
		if (refresh == 1) {
			refresh_two();
			FPGA_INFO("refresh_two()\n");
			return 0;
		}
	}
#endif

	code = jtag_read_code(0x11);

	if (g_load_path == 1) { //code == FPGA_DEV_IDCODE
		FPGA_INFO("jtag_ef_prog_TSMC() begin status code: %08X\n", jtag_read_code(0x41));

		ret = jtag_ef_prog_TSMC(data_buf, fssize, VERIFY, (uint8_t)PROG_GENERAL); // PROG_BACKGROUND

		if (ret == 1) {
			refresh_two();
		}

		FPGA_INFO("jtag_ef_prog_TSMC() finish status code: %08X\n", jtag_read_code(0x41));
	}

	FPGA_INFO("Program finish\n");

	/**xxx**/
	jtag_reset();
	jtag_write_inst(0x3A);
	jtag_write_inst(0x02);
	delay_ms(100);


	FPGA_INFO("id code: %08X", jtag_read_code(0x11));
	FPGA_INFO("user code: %08X", jtag_read_code(0x13));
	FPGA_INFO("status code: %08X", jtag_read_code(0x41));

	FPGA_INFO("end \n");

	return 0;
}

/*static int test_TCK(int s)
{
    int i = 0;

    for (i = 0; i < s; i++)
    {
        gpio_set_value(PIN_TCK, 1);
        gpio_set_value(PIN_TCK, 0);
    }
    return i;
}

static int test_TCKMSDI(int s)
{
    int i = 0;

    for (i = 0; i < s; i++)
    {
        gpio_set_value(PIN_TCK, 1);
        gpio_set_value(PIN_TMS, 1);
        gpio_set_value(PIN_TDI, 1);

        gpio_set_value(PIN_TCK, 0);
        gpio_set_value(PIN_TMS, 0);
        gpio_set_value(PIN_TDI, 0);
    }
    return i;
}*/

static int jtag_io_init(void)
{
	int i = 0;
	int ret = 0;

	FPGA_INFO("\t  match successed %s \n", VERSION);
	/*获取jtga_pins的设备树节点*/
	jtag_io_device_node = of_find_node_by_path("/soc/jtag_pins");
	if (jtag_io_device_node == NULL) {
		FPGA_INFO(KERN_EMERG "\t  lihongmao get jtag_pins failed!22  \n");
	}
	g_tck_io = of_get_named_gpio(jtag_io_device_node, "g_tck_io", 0);
	g_tms_io = of_get_named_gpio(jtag_io_device_node, "g_tms_io", 0);
	g_tdi_io = of_get_named_gpio(jtag_io_device_node, "g_tdi_io", 0);
	g_tdo_io = of_get_named_gpio(jtag_io_device_node, "g_tdo_io", 0);

	g_mode_io = of_get_named_gpio(jtag_io_device_node, "g_mode_io", 0);
	g_vccx_io = of_get_named_gpio(jtag_io_device_node, "g_vccx_io", 0);
	g_vcco_io = of_get_named_gpio(jtag_io_device_node, "g_vcco_io", 0);
	g_vcc_io = of_get_named_gpio(jtag_io_device_node, "g_vcc_io", 0);

	FPGA_INFO("g_tck_io = %d, g_tms_io = %d, g_tdi_io = %d, g_mode_io = %d, g_vccx_io = %d, g_vcco_io = %d, g_vcc_io=%d\n",
		  g_tck_io, g_tms_io, g_tdi_io, g_mode_io, g_vccx_io, g_vcco_io, g_vcc_io);
	ret = gpio_direction_output(g_tck_io, 1);
	if (ret) {
		FPGA_INFO("%s Set the g_tck_io fail\n", __FUNCTION__);
	}
	ret = gpio_direction_output(g_tms_io, 1);
	if (ret) {
		FPGA_INFO("%s Set the g_tms_io fail\n", __FUNCTION__);
	}
	ret = gpio_direction_output(g_tdi_io, 1);
	if (ret) {
		FPGA_INFO("%s Set the g_tdi_io fail\n", __FUNCTION__);
	}
	ret = gpio_direction_input(g_tdo_io); //设置引脚为输入模式
	if (ret) {
		FPGA_INFO("%s Set the g_tdo_io fail\n", __FUNCTION__);
	}

	ret = gpio_direction_output(g_mode_io, 0);
	if (ret) {
		FPGA_INFO("%s Set the g_mode_io fail\n", __FUNCTION__);
	}
	ret = gpio_direction_output(g_vccx_io, 1);
	if (ret) {
		FPGA_INFO("%s Set the g_vccx_io fail\n", __FUNCTION__);
	}
	ret = gpio_direction_output(g_vcco_io, 1);
	if (ret) {
		FPGA_INFO("%s Set the g_vcco_io fail\n", __FUNCTION__);
	}
	ret = gpio_direction_output(g_vcc_io, 1);
	if (ret) {
		FPGA_INFO("%s Set the g_vcc_io fail\n", __FUNCTION__);
	}

#ifdef ON_PROTRCT_TCK
	local_irq_disable();
#endif
	for (i = 0; i < 10; i++) {
		// 引脚输出clk
		gpio_set_value(PIN_TCK, 1);
		gpio_set_value(PIN_TCK, 0);
	}
	for (i = 0; i < 10; i++) {
		// 引脚输出clk
		gpio_set_value(PIN_TDI, 1);
		gpio_set_value(PIN_TDI, 0);
	}
#ifdef ON_PROTRCT_TCK
	local_irq_enable();
#endif

	tck_mem_base = ioremap(0xF136004, 4);
	if (!tck_mem_base) {
		FPGA_INFO("tck_mem_base is NULL, ioremap failed\n");
	}
	tms_mem_base = ioremap(0xF137004, 4);
	if (!tms_mem_base) {
		FPGA_INFO("tck_mem_base is NULL, ioremap failed\n");
	}

	tdi_mem_base = ioremap(0xF135004, 4);
	if (!tdi_mem_base) {
		FPGA_INFO("tck_mem_base is NULL, ioremap failed\n");
	}

	tdo_mem_base = ioremap(0xF134004, 4);
	if (!tdo_mem_base) {
		FPGA_INFO("tck_mem_base is NULL, ioremap failed\n");
	}


	return 0;
}
static int gowinJtag_open(struct inode *inode, struct file *file)
{
	uint32_t _code;
	u8 *data_buf = NULL;

	if (first_configgpio == 0) {
		jtag_io_init();

#if 0//ADJ_TCK_FREQ
		g_tck_delay_len = cal_clk_clycle(TO_2_0MHZ, SET_1MS);
		FPGA_INFO(" to_hz:%dhz set_time:%dus g_tck_delay_len %d; end the test\n", TO_2_0MHZ, SET_1MS, g_tck_delay_len);
#endif
		first_configgpio = 1;

		jtag_reset();
		_code = jtag_read_code(READ_ID_CODE);
		FPGA_INFO("code:%x-%x\n", _code, FPGA_DEV_IDCODE);
	}

	data_buf = vmalloc(BUFSIZE);
	if (data_buf == NULL) {
		FPGA_INFO("vmalloc failed ,sizei %d \n", BUFSIZE);
	}
	memset(data_buf, 0xfe, BUFSIZE);

	buflen_v = 0;
	FPGA_INFO("delay_10us start.");
	delay_xxx(10000);
	FPGA_INFO("delay_10us end.");
	file->private_data = data_buf;
	fpga_dw.data_buf = data_buf;

	FPGA_INFO("%s: data_buf %p open.\n", __FUNCTION__, data_buf);
	return 0;
}

static int gowinJtag_release(struct inode *inode, struct file *file)
{
	//  u8 *data_buf = file->private_data;

	//  vfree(data_buf);
	//  data_buf = NULL;

	FPGA_INFO("%s: release.\n", __FUNCTION__);
	return 0;
}

static ssize_t gowinJtag_read(struct file *file, char __user *data, size_t len, loff_t *ppos)
{
#if 0
	r = test_TCK(1000);
	FPGA_INFO("%s: read. %d\n", __FUNCTION__, r);

	r = test_TCKMSDI(1000);
	FPGA_INFO("%s: read. %d\n", __FUNCTION__, r);

	adj_tckfreq(DELAY_LEN); // TCK frequency adjustment requires setting DELAY_LEN

	code = jtag_read_code(0x11);
	FPGA_INFO("jtag id code: %08X, %08X \n", code, ID_GW1N2);
#else
	jtag_write_inst(0x3A);
	jtag_write_inst(0x02);

	delay_ms(100);

	jtag_write_inst(0x3C);
	jtag_write_inst(0x02);

	delay_ms(200);

	FPGA_INFO("id code: %08X", jtag_read_code(0x11));
	FPGA_INFO("user code: %08X", jtag_read_code(0x13));
	FPGA_INFO("status code: %08X\n", jtag_read_code(0x41));
#endif
	FPGA_INFO("%s: read.\n", __FUNCTION__);
	return 0;
}

static int jtag_flash_mode_enable(u8 op)
{
	gpio_set_value(g_mode_io, op);

	msleep(5);

	gpio_set_value(g_vcc_io, 0);
	gpio_set_value(g_vcco_io, 0);
	gpio_set_value(g_vccx_io, 0);

	msleep(50);

	gpio_set_value(g_vcc_io, 1);
	gpio_set_value(g_vcco_io, 1);
	gpio_set_value(g_vccx_io, 1);

	FPGA_INFO("%s: g_mode_io op %d.\n", __FUNCTION__, op);
	return 0;
}

static ssize_t gowinJtag_write(struct file *file, const char __user *data, size_t len, loff_t *ppos)
{
	char cmd[8] = {0};
	int page_index = 0;
	u8 *data_buf = file->private_data;

	if (len == 2) {
		if (copy_from_user(cmd, data, len)) {
			FPGA_INFO("copy faile \n");
			return -EFAULT;
		} else {
			switch (cmd[0]) {
			case '0':
				program = 1;
				refresh = 1;
				break;

			case '1':
				program = 1;
				refresh = 0;
				break;

			case '2':
				program = 0;
				refresh = 1;
				refresh_two();
				FPGA_INFO("cmd2:refresh_two()\n");
				// for (i = 0; i < buflen_v; i++)
				//     FPGA_INFO("[%d]-%x", i, g_data_buff[i]);
				break;

			default:
				program = 1;
				refresh = 1;
			}
			FPGA_INFO("%s %d. prog: %d, ref: %d\n", cmd, len, program, refresh);
		}
	} else {
		// FPGA_INFO("len %d\n", len);
		if (len == PAGESIZE) { // 4096
			page_index++;
			if (copy_from_user(data_buf + buflen_v, data, len)) {
				FPGA_INFO("%s:  error write.\n", __FUNCTION__);
				return -EFAULT;
			} else {
				buflen_v += len;
				// FPGA_INFO("len %d buflen_v %d \n", len, buflen_v);
			}
		} else {
			page_index++;
			// ret_t = copy_from_user(g_data_buff + buflen_v, data, len);
			// FPGA_INFO("--len %d, fsize %d ret_t %d page_index %d--\n", len, buflen_v, ret_t, page_index);
			if (copy_from_user(data_buf + buflen_v, data, len)) {
				FPGA_INFO("%s:  error write.\n", __FUNCTION__);
				return -EFAULT;
			} else {
				FPGA_INFO("%s:  gowin_main write.\n", __FUNCTION__);
				buflen_v += len;
				FPGA_INFO("len %d, fsize %d\n", len, buflen_v);

				fpga_dw.data_len = buflen_v;

				FPGA_INFO("*****data_buf %p data_len %u*****\n", fpga_dw.data_buf, fpga_dw.data_len);
				//queue_work_on(4, fpga_dw.dw_workqueue, &fpga_dw.dw_work); //smp_processor_id()
				kthread_bind(fpga_dw.kworker->task, 7);
				kthread_queue_work(fpga_dw.kworker, &fpga_dw.pump_messages);
				//gowin_main(fpga_dw.data_buf, fpga_dw.data_len);
			}
		}
	}

	return len;
}

static long gowinJtag_misc_ioctl(struct file *filp,
				 unsigned int cmd,
				 unsigned long arg)
{
	int ret = 0;
	u8 op_flag = 0;

	switch (cmd) {
	case GW_IOC_EN:
		if (copy_from_user(&op_flag, (u8 *)arg, sizeof(u8))) {
			ret = -EFAULT;
		}
		if (op_flag == 0 || op_flag == 1) {
			jtag_flash_mode_enable(op_flag);
		}
		FPGA_INFO("%s: g_mode_io op %d.\n", __FUNCTION__, op_flag);
		break;
	case GW_IOC_LOAD_PATH:
		if (copy_from_user(&g_load_path, (u8 *)arg, sizeof(u8))) {
			ret = -EFAULT;
		}
		FPGA_INFO("%s: g_load_path %d.\n", __FUNCTION__, g_load_path);
		break;

	default:
		ret = -1;
		FPGA_INFO("cmd not support:0x%x, GW_IOC_EN 0x%x GW_IOC_LOAD_PATH 0x%x\n", cmd, GW_IOC_EN, GW_IOC_LOAD_PATH);
		break;
	}

	return ret;
}
static const struct file_operations miscgowinJtag_fops = {
	.owner = THIS_MODULE,
	.open = gowinJtag_open,
	.read = gowinJtag_read,
	.write = gowinJtag_write,
	.unlocked_ioctl = gowinJtag_misc_ioctl,
	.release = gowinJtag_release
};

static struct miscdevice miscgowinJtag_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = MISC_NAME,
	.fops = &miscgowinJtag_fops,
};

void fpga_download_work(struct kthread_work *work)
{
	struct fpga_dw_pri *mnt_pri = container_of(work, struct fpga_dw_pri, pump_messages);
	int ret;
	struct sched_param param = {.sched_priority = 1};

	sched_setscheduler(current, SCHED_FIFO, &param);
	FPGA_INFO("*****data_buf %p data_len %u *****\n",
		  mnt_pri->data_buf, mnt_pri->data_len);
	ret = gowin_main(fpga_dw.data_buf, fpga_dw.data_len);
	if (ret != 0) {
		FPGA_INFO("*****download failed %d*****\n", ret);
		return;
	}
	FPGA_INFO("*****download success!*****\n");
}


static int __init cpldGowin_init(void)
{
	int ret;

	FPGA_INFO("=====3 cpldGowin-init ======\n");
	FPGA_INFO("=====2 cpldGowin-v:%s ======\n", VERSION);
	ret = misc_register(&miscgowinJtag_dev);
	if (ret) {
		FPGA_INFO("*****cpldGowin init error*****\n");
		return ret;
	}

	fpga_dw.kworker = kthread_create_worker(0, "fpga_download");
	if (IS_ERR(fpga_dw.kworker)) {
		FPGA_INFO("failed to create message pump kworker\n");
		return 0;
	}

	kthread_init_work(&fpga_dw.pump_messages, fpga_download_work);
	// sched_set_fifo(fpga_dw.kworker->task);

	init_waitqueue_head(&fpga_dw.waiter);

	fpga_dw.wakeup_flag = false;

	dbg_buf = kzalloc(1024 * 1024, GFP_KERNEL);
	if (dbg_buf == NULL) {
		misc_deregister(&miscgowinJtag_dev);
		return 0;
	}

	FPGA_INFO("%s: init success.\n", __FUNCTION__);
	return 0;
}

static void __exit cpldGowin_exit(void)
{
	FPGA_INFO("%s: exit.\n", __FUNCTION__);
	misc_deregister(&miscgowinJtag_dev);
	FPGA_INFO("=====cpldGowin-exit======\n");
}

module_init(cpldGowin_init);
module_exit(cpldGowin_exit);
MODULE_LICENSE("GPL");
