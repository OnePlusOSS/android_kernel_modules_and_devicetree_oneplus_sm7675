// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023-2023 Oplus. All rights reserved.
 */

#ifndef _DS28E30_H
#define _DS28E30_H

#include <linux/types.h>

/* define 1-wire ROM command  */
#define READ_ROM              0x33
#define SKIP_ROM              0xCC

/* DS28E30 commands */
#define XPC_COMMAND				0x66
#define CMD_WRITE_MEM				0x96
#define CMD_READ_MEM				0x44
#define CMD_READ_STATUS				0xAA
#define CMD_SET_PAGE_PROT			0xC3
#define CMD_COMP_READ_AUTH			0xA5
#define CMD_DECREMENT_CNT			0xC9
#define CMD_DISABLE_DEVICE			0x33
#define CMD_READ_DEVICE_PUBLIC_KEY		0xCB
#define CMD_AUTHENTICATE_PUBLIC_KEY		0x59
#define CMD_AUTHENTICATE_WRITE			0x89

/* Test Mode sub-commands */
#define CMD_TM_ENABLE_DISABLE			0xDD
#define CMD_TM_WRITE_BLOCK			0xBB
#define CMD_TM_READ_BLOCK			0x66

/* Result bytes */
#define RESULT_SUCCESS				0xAA
#define RESULT_FAIL_PROTECTION			0x55
#define RESULT_FAIL_PARAMETETER			0x77
#define RESULT_FAIL_INVALID_SEQUENCE		0x33
#define RESULT_FAIL_ECDSA			0x22
#define RESULT_DEVICE_DISABLED			0x88
#define RESULT_FAIL_VERIFY			0x00

#define RESULT_FAIL_COMMUNICATION		0xFF

#define STRONG_PULL_UP				0xAA
#define SKIP_CRC_CHECK				0xB001
#define OW_SKIP_ROM				0xCC

/* Pages */
#define PG_USER_EEPROM_0		0
#define PG_USER_EEPROM_1		1
#define PG_USER_EEPROM_2		2
#define PG_USER_EEPROM_3		3
#define PG_CERTIFICATE_R		4
#define PG_CERTIFICATE_S		5
#define PG_AUTHORITY_PUB_KEY_X		6
#define PG_AUTHORITY_PUB_KEY_Y		7
#define PG_DS28E30_PUB_KEY_X		28
#define PG_DS28E30_PUB_KEY_Y		29
#define PG_DS28E30_PRIVATE_KEY		36

#define PG_DEC_COUNTER			106

/* delays */
#define DELAY_DS28E30_EE_WRITE_TWM	100       /* maximal 100ms */
#define DELAY_DS28E30_EE_READ_TRM	50       /* maximal 100ms */
#define DELAY_DS28E30_ECDSA_GEN_TGES	200      /* maximal 130ms (tGFS) */
#define DELAY_DS28E30_VERIFY_ECDSA_SIGNATURE_TEVS	200         /* maximal 130ms (tGFS) */
#define DELAY_DS28E30_ECDSA_WRITE	350          /* for ECDSA write EEPROM */

/* Protection bit fields */
#define PROT_RP			0x01  /* Read Protection */
#define PROT_WP			0x02  /* Write Protection  */
#define PROT_EM			0x04  /* EPROM Emulation Mode  */
#define PROT_DC			0x08  /* Decrement Counter mode (only page 4) */
#define PROT_AUTH		0x20  /* AUTH mode for authority public key X&Y */
#define PROT_ECH		0x40  /* Encrypted read and write using shared key from ECDH */
#define PROT_ECW		0x80  /* Authentication Write Protection ECDSA (not applicable to KEY_PAGES) */

/* Generate key flags */
#define ECDSA_KEY_LOCK		0x80
#define ECDSA_USE_PUF		0x01

/*define expected read length in DS28E30 function commands  */
#define EXPECTED_READ_LENGTH_1   1
#define EXPECTED_READ_LENGTH_2   2
#define EXPECTED_READ_LENGTH_5   5
#define EXPECTED_READ_LENGTH_33  33
#define EXPECTED_READ_LENGTH_65  65

/*check a bit logic in a byte  */
#define MSB_CHECK        0x80

/* 1-Wire selection methods */
#define SELECT_SKIP	0
#define SELECT_RESUME	1
#define SELECT_MATCH	2
#define SELECT_ODMATCH	3
#define SELECT_SEARCH	4
#define SELECT_READROM	5
#define SELECT_ODSKIP	6

/* constants */
#define DS28E30_FAM	0x5B       /* 0xDB for custom DS28E30 */
#define OP_CID		0x061

#define BATT_SN_NUM_LEN		12
#define MAX_SN_NUM_NUMBER	3
#define MAX_SN_NUM_SIZE		36
struct maxim_sn_num_info {
	unsigned char sn_num[MAX_SN_NUM_NUMBER][BATT_SN_NUM_LEN];
	int sn_num_number;
};

/* Command Functions (no high level verification) */
int ds28e30_cmd_write_memory(int pg, u8 *data);
bool ds28e30_cmd_read_memory(int pg, u8 *data);
int ds28e30_cmd_read_status(int pg, u8 *pr_data, u8 *manid, u8 *hardware_version);
int ds28e30_cmd_set_page_protection(int pg, u8 prot);
int ds28e30_cmd_compute_read_page_authentication(int pg, int anon, u8 *challenge, u8 *sig);
int ds28e30_cmd_decrement_counter(void);
int ds28e30_cmd_device_disable(u8 *release_sequence);
int ds28e30_cmd_verify_ecdsa_signature(u8 *sig_r, u8 *sig_s, u8 *custom_cert_fields, int cert_len);
int ds28e30_cmd_authendicated_ecdsa_write_memory(int pg, u8 *data, u8 *sig_r, u8 *sig_s);

/* High level functions */
int ds28e30_cmd_read_device_public_key(u8 *data);
int ds28e30_compute_verify_ecdsa(int pg, int anon, u8 *mempage, u8 *challenge, u8 *sig_r, u8 *sig_s);
int ds28e30_compute_verify_ecdsa_no_read(int pg, int anon, u8 *mempage, u8 *challenge, u8 *sig_r, u8 *sig_s);

/* DS28E30 application functions */
int verify_ecdsa_certificate_device(u8 *sig_r, u8 *sig_s, u8 *pub_key_x, u8 *pub_key_y,
				   u8 *slave_romid, u8 *slave_manid, u8 *system_level_pub_key_x,
				   u8 *system_level_pub_key_y);
int authenticate_ds28e30(struct maxim_sn_num_info *sn_num_info, int page_number);
int ds28e30_write_memory_page_with_ecw(int pg, u8 *new_data);

/* Helper functions */
int ds28e30_detect(u8 addr);
u8 ds28e30_get_last_result_byte(void);
int standard_cmd_flow(u8 *write_buf, int write_len, int delayms, int expect_read_len,
		      u8 *read_buf, int *read_len);
void ds28e30_set_public_key(u8 *px, u8 *py);
void ds28e30_set_private_key(u8 *priv);
int ds28e30_read_romno_manid_hardware_version(void);

/* ECDSA algorithm achieved by software */
int sw_compute_ecdsa_signature(u8 *message, int msg_len,  u8 *sig_r, u8 *sig_s);

int ow_read_rom(void);
int ow_skip_rom(void);

#endif /* _DS28E30_H */
