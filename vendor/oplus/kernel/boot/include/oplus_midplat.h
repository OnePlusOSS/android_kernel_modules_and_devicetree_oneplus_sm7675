/*
 *  * Copyright (C) 2024-2025 Oplus. All rights reserved.
 *   */
#ifndef __OPLUS_MID_PLAT_EXPORT_H__
#define  __OPLUS_MID_PLAT_EXPORT_H__

#define OPLUS_OMPDT_DATA_SIZE_MAX (OPLUS_FEAUTRE_MAX + 8)
#define MIDPLAT_INFO_NORMAL 0
#define MIDPLAT_INFO_CRC_ERR 0XFFFFFFFF
#define MIDPLAT_INFO_UNSUPPORTED 0XFFFFFFFE

typedef enum {
    OPLUS_FEATURE_SKU_SUPPORTED,
    OPLUS_FEATURE_BAROMETER_INFO,
    OPLUS_FEAUTRE_MAX
} OPLUS_MID_PLAT_FEATURE_T;

typedef struct {
    u32 nMagic;
    u32 nVersion;
    u32 nEncryption_offset;
    u32 nEncryption_len;
    u32 data_len;
    u32 nCrc;
    u8 infoMidPlat[OPLUS_OMPDT_DATA_SIZE_MAX];
} ImageInfoMidPlat;

typedef enum {
    OPLUS_ACK_VERSION_GKI = 0,
    OPLUS_ACK_VERSION_OKI,
    OPLUS_ACK_VERSION_OGKI,
    OPLUS_ACK_VERSION_UNKNOWN,
    OPLUS_ACK_VERSION_MAX,
} OPLUS_ACK_VERSION_TYPE;

#endif /*end of __OPLUS_MID_PLAT_EXPORT_H__*/
