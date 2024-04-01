/*
 * Copyright (c) 2023-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#ifndef _MACTX_HT_SIG_H_
#define _MACTX_HT_SIG_H_

#include "ht_sig_info.h"
#define NUM_OF_DWORDS_MACTX_HT_SIG 2

struct mactx_ht_sig {
#ifndef WIFI_BIT_ORDER_BIG_ENDIAN
             struct   ht_sig_info                                               mactx_ht_sig_info_details;
#else
             struct   ht_sig_info                                               mactx_ht_sig_info_details;
#endif
};

#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_MCS_OFFSET                           0x00000000
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_MCS_LSB                              0
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_MCS_MSB                              6
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_MCS_MASK                             0x0000007f

#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_CBW_OFFSET                           0x00000000
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_CBW_LSB                              7
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_CBW_MSB                              7
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_CBW_MASK                             0x00000080

#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_LENGTH_OFFSET                        0x00000000
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_LENGTH_LSB                           8
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_LENGTH_MSB                           23
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_LENGTH_MASK                          0x00ffff00

#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_RESERVED_0_OFFSET                    0x00000000
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_RESERVED_0_LSB                       24
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_RESERVED_0_MSB                       31
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_RESERVED_0_MASK                      0xff000000

#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_SMOOTHING_OFFSET                     0x00000004
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_SMOOTHING_LSB                        0
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_SMOOTHING_MSB                        0
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_SMOOTHING_MASK                       0x00000001

#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_NOT_SOUNDING_OFFSET                  0x00000004
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_NOT_SOUNDING_LSB                     1
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_NOT_SOUNDING_MSB                     1
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_NOT_SOUNDING_MASK                    0x00000002

#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_HT_RESERVED_OFFSET                   0x00000004
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_HT_RESERVED_LSB                      2
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_HT_RESERVED_MSB                      2
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_HT_RESERVED_MASK                     0x00000004

#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_AGGREGATION_OFFSET                   0x00000004
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_AGGREGATION_LSB                      3
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_AGGREGATION_MSB                      3
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_AGGREGATION_MASK                     0x00000008

#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_STBC_OFFSET                          0x00000004
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_STBC_LSB                             4
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_STBC_MSB                             5
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_STBC_MASK                            0x00000030

#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_FEC_CODING_OFFSET                    0x00000004
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_FEC_CODING_LSB                       6
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_FEC_CODING_MSB                       6
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_FEC_CODING_MASK                      0x00000040

#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_SHORT_GI_OFFSET                      0x00000004
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_SHORT_GI_LSB                         7
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_SHORT_GI_MSB                         7
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_SHORT_GI_MASK                        0x00000080

#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_NUM_EXT_SP_STR_OFFSET                0x00000004
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_NUM_EXT_SP_STR_LSB                   8
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_NUM_EXT_SP_STR_MSB                   9
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_NUM_EXT_SP_STR_MASK                  0x00000300

#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_CRC_OFFSET                           0x00000004
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_CRC_LSB                              10
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_CRC_MSB                              17
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_CRC_MASK                             0x0003fc00

#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_SIGNAL_TAIL_OFFSET                   0x00000004
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_SIGNAL_TAIL_LSB                      18
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_SIGNAL_TAIL_MSB                      23
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_SIGNAL_TAIL_MASK                     0x00fc0000

#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_RESERVED_1_OFFSET                    0x00000004
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_RESERVED_1_LSB                       24
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_RESERVED_1_MSB                       30
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_RESERVED_1_MASK                      0x7f000000

#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_RX_INTEGRITY_CHECK_PASSED_OFFSET     0x00000004
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_RX_INTEGRITY_CHECK_PASSED_LSB        31
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_RX_INTEGRITY_CHECK_PASSED_MSB        31
#define MACTX_HT_SIG_MACTX_HT_SIG_INFO_DETAILS_RX_INTEGRITY_CHECK_PASSED_MASK       0x80000000

#endif
