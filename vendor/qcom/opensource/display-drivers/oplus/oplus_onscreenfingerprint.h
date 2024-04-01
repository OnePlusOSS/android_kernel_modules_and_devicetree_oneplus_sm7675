/***************************************************************
** Copyright (C), 2022, OPLUS Mobile Comm Corp., Ltd
** File : oplus_onscreenfingerprint.h
** Description : oplus_onscreenfingerprint header
** Version : 2.0
** Date : 2022/08/01
** Author : Display
***************************************************************/

#ifndef _OPLUS_ONSCREENFINGERPRINT_H_
#define _OPLUS_ONSCREENFINGERPRINT_H_

/* please just only include linux common head file to keep me pure */
#include "oplus_display_private_api.h"

const static uint16_t audi_lhbm_alpha[] = {
	811, 811, 812, 812, 812, 813, 816, 816, 816, 818, 818, 818, 819, 822, 822, 822, 823, 824, 825, 825, 825, 828, 828, 830, 830, 831, 832, 833, 834,
    835, 836, 838, 837, 838, 841, 840, 841, 842, 844, 844, 844, 845, 846, 845, 848, 848, 848, 849, 850, 851, 851, 852, 853, 854, 854, 855, 857, 860,
    861, 862, 863, 863, 864, 865, 865, 866, 867, 867, 868, 869, 870, 870, 871, 871, 873, 872, 874, 876, 875, 876, 876, 879, 878, 879, 881, 880, 884,
    885, 885, 887, 888, 888, 889, 888, 891, 891, 893, 893, 895, 895, 895, 897, 897, 898, 898, 900, 900, 901, 901, 901, 903, 904, 904, 904, 909, 910,
    909, 910, 913, 913, 913, 914, 914, 916, 916, 917, 916, 917, 920, 919, 920, 920, 923, 924, 923, 925, 927, 926, 929, 928, 929, 930, 930, 935, 935,
    935, 936, 935, 938, 939, 938, 939, 940, 942, 941, 943, 944, 944, 945, 945, 947, 948, 948, 949, 950, 951, 950, 952, 954, 952, 956, 960, 960, 962,
    962, 964, 963, 964, 966, 965, 968, 967, 969, 971, 971, 972, 972, 973, 973, 974, 975, 975, 976, 976, 980, 982, 984, 986, 984, 990, 990, 991, 992,
    994, 998, 1000, 1000, 1002, 1002, 1004, 1006, 1006, 1012, 1012, 1014, 1015, 1015, 1019, 1019, 1021, 1023, 1030, 1030, 1030, 1032, 1033, 1034, 1035,
    1035, 1037, 1043, 1044, 1045, 1047, 1049, 1050, 1052, 1053, 1055, 1061, 1065, 1065, 1067, 1067, 1069, 1071, 1072, 1073, 1080, 1081, 1083, 1086, 1088,
    1089, 1090, 1092, 1092, 1099, 1101, 1102, 1106, 1107, 1108, 1110, 1112, 1112, 1122, 1122, 1124, 1126, 1128, 1130, 1131, 1132, 1138, 1140, 1141, 1144,
    1146, 1148, 1149, 1150, 1152, 1158, 1160, 1161, 1164, 1165, 1167, 1168, 1171, 1173, 1179, 1182, 1183, 1186, 1187, 1189, 1192, 1193, 1195, 1201, 1202,
    1205, 1206, 1207, 1209, 1212, 1215, 1215, 1223, 1225, 1227, 1229, 1229, 1233, 1234, 1233, 1238, 1241, 1242, 1243, 1243, 1251, 1254, 1255, 1254, 1258,
    1260, 1263, 1266, 1265, 1267, 1273, 1275, 1275, 1278, 1278, 1287, 1288, 1288, 1291, 1291, 1296, 1297, 1299, 1302, 1302, 1305, 1308, 1312, 1311, 1316,
    1316, 1323, 1324, 1323, 1325, 1327, 1334, 1334, 1336, 1336, 1339, 1347, 1349, 1350, 1351, 1352, 1359, 1360, 1361, 1362, 1365, 1373, 1374, 1376, 1376,
    1377, 1384, 1385, 1387, 1389, 1389, 1397, 1396, 1398, 1400, 1400, 1410, 1411, 1413, 1414, 1415, 1417, 1423, 1426, 1426, 1428, 1430, 1438, 1438, 1439,
    1441, 1443, 1451, 1451, 1454, 1454, 1454, 1463, 1463, 1466, 1468, 1469, 1476, 1479, 1479, 1481, 1483, 1490, 1492, 1492, 1493, 1496, 1504, 1505, 1505,
    1508, 1509, 1517, 1518, 1519, 1519, 1522, 1524, 1531, 1532, 1536, 1537, 1538, 1544, 1546, 1547, 1550, 1550, 1557, 1559, 1560, 1563, 1566, 1572, 1573,
    1575, 1576, 1579, 1587, 1588, 1590, 1591, 1591, 1601, 1601, 1604, 1605, 1607, 1614, 1617, 1617, 1619, 1622, 1630, 1631, 1632, 1633, 1638, 1638, 1645,
    1646, 1649, 1650, 1652, 1661, 1662, 1664, 1665, 1668, 1675, 1679, 1679, 1680, 1683, 1690, 1693, 1692, 1692, 1699, 1698, 1701, 1708, 1705, 1709, 1716,
    1716, 1715, 1719, 1726, 1725, 1728, 1734, 1735, 1735, 1742, 1744, 1743, 1751, 1753, 1753, 1761, 1762, 1762, 1768, 1770, 1770, 1778, 1776, 1779, 1780,
    1787, 1788, 1789, 1797, 1796, 1797, 1804, 1806, 1807, 1814, 1814, 1814, 1823, 1823, 1825, 1830, 1830, 1833, 1838, 1840, 1841, 1842, 1848, 1849, 1851,
    1859, 1859, 1860, 1869, 1869, 1870, 1878, 1880, 1881, 1886, 1891, 1891, 1897, 1899, 1892, 1894, 1898, 1904, 1903, 1910, 1911, 1913, 1918, 1919, 1921,
    1929, 1930, 1932, 1938, 1938, 1942, 1947, 1950, 1951, 1958, 1960, 1961, 1962, 1968, 1971, 1971, 1977, 1980, 1982, 1988, 1990, 1991, 1998, 1997, 2001,
    2006, 2009, 2009, 2017, 2017, 2018, 2021, 2026, 2027, 2029, 2035, 2037, 2038, 2048, 2047, 2049, 2056, 2057, 2058, 2065, 2066, 2068, 2075, 2076, 2077,
    2084, 2085, 2086, 2088, 2093, 2094, 2095, 2103, 2104, 2105, 2114, 2114, 2109, 2112, 2119, 2116, 2124, 2125, 2124, 2132, 2133, 2138, 2143, 2144, 2145,
    2145, 2150, 2155, 2156, 2160, 2162, 2164, 2169, 2172, 2172, 2179, 2181, 2181, 2189, 2189, 2191, 2198, 2199, 2200, 2200, 2207, 2210, 2211, 2217, 2218,
    2217, 2227, 2226, 2227, 2234, 2238, 2237, 2244, 2246, 2248, 2252, 2252, 2254, 2263, 2264, 2264, 2266, 2273, 2273, 2275, 2281, 2281, 2283, 2288, 2290,
    2293, 2298, 2300, 2299, 2310, 2310, 2308, 2318, 2319, 2318, 2323, 2321, 2321, 2327, 2328, 2333, 2332, 2337, 2338, 2346, 2345, 2350, 2350, 2356, 2355,
    2361, 2361, 2371, 2370, 2377, 2376, 2382, 2384, 2388, 2388, 2396, 2398, 2403, 2403, 2403, 2410, 2411, 2416, 2418, 2425, 2426, 2431, 2432, 2437, 2438,
    2444, 2446, 2451, 2451, 2460, 2459, 2464, 2464, 2471, 2474, 2479, 2479, 2485, 2485, 2493, 2493, 2491, 2499, 2502, 2505, 2506, 2512, 2512, 2517, 2516,
    2526, 2525, 2532, 2533, 2537, 2539, 2545, 2544, 2552, 2550, 2558, 2558, 2565, 2565, 2571, 2571, 2578, 2576, 2580, 2587, 2586, 2592, 2591, 2598, 2599,
    2604, 2605, 2611, 2612, 2617, 2618, 2623, 2624, 2630, 2631, 2636, 2637, 2642, 2641, 2648, 2647, 2654, 2654, 2661, 2662, 2667, 2667, 2667, 2672, 2673,
    2679, 2680, 2685, 2685, 2693, 2691, 2698, 2697, 2702, 2704, 2710, 2710, 2715, 2716, 2721, 2723, 2727, 2726, 2735, 2733, 2738, 2737, 2747, 2748, 2746,
    2751, 2753, 2758, 2757, 2764, 2759, 2762, 2763, 2768, 2770, 2776, 2774, 2778, 2782, 2789, 2786, 2792, 2795, 2798, 2796, 2802, 2807, 2812, 2810, 2817,
    2816, 2817, 2824, 2823, 2831, 2830, 2834, 2834, 2840, 2840, 2846, 2847, 2852, 2852, 2858, 2856, 2862, 2864, 2870, 2869, 2877, 2873, 2879, 2879, 2883,
    2887, 2891, 2893, 2894, 2895, 2898, 2903, 2902, 2910, 2911, 2915, 2917, 2924, 2921, 2928, 2927, 2933, 2934, 2940, 2942, 2947, 2947, 2951, 2953, 2958,
    2960, 2966, 2966, 2970, 2970, 2977, 2978, 2978, 2982, 2984, 2988, 2988, 2995, 2996, 3001, 3002, 3005, 3009, 3015, 3014, 3020, 3021, 3024, 3025, 3031,
    3034, 3035, 3038, 3043, 3044, 3048, 3048, 3051, 3055, 3056, 3061, 3064, 3069, 3067, 3071, 3071, 3078, 3081, 3084, 3086, 3090, 3090, 3096, 3095, 3100,
    3104, 3109, 3110, 3114, 3116, 3117, 3117, 3123, 3127, 3133, 3132, 3133, 3136, 3139, 3142, 3141, 3149, 3150, 3156, 3156, 3161, 3161, 3165, 3164, 3169,
    3169, 3173, 3177, 3180, 3180, 3185, 3190, 3189, 3194, 3197, 3199, 3201, 3207, 3206, 3211, 3219, 3220, 3225, 3229, 3231, 3231, 3236, 3241, 3239, 3243,
    3248, 3246, 3254, 3257, 3259, 3263, 3269, 3270, 3275, 3278, 3283, 3283, 3287, 3290, 3292, 3296, 3298, 3296, 3304, 3307, 3311, 3313, 3320, 3323, 3321,
    3328, 3331, 3332, 3337, 3342, 3341, 3343, 3349, 3350, 3353, 3358, 3357, 3363, 3368, 3371, 3372, 3374, 3382, 3379, 3386, 3389, 3389, 3393, 3398, 3398,
    3403, 3408, 3407, 3411, 3414, 3420, 3421, 3421, 3427, 3427, 3432, 3437, 3437, 3439, 3446, 3450, 3450, 3457, 3462, 3462, 3466, 3471, 3471, 3473, 3480,
    3482, 3486, 3490, 3489, 3494, 3496, 3502, 3506, 3510, 3515, 3513, 3520, 3521, 3522, 3527, 3533, 3534, 3539, 3543, 3543, 3548, 3554, 3552, 3558, 3564,
    3567, 3568, 3572, 3576, 3577, 3584, 3586, 3585, 3590, 3597, 3595, 3602, 3609, 3612, 3611, 3616, 3617, 3620, 3626, 3631, 3630, 3633, 3638, 3640, 3641,
    3647, 3644, 3648, 3652, 3657, 3656, 3660, 3667, 3668, 3671, 3676, 3677, 3679, 3683, 3684, 3686, 3692, 3693, 3699, 3701, 3708, 3705, 3712, 3716, 3716,
    3719, 3725, 3723, 3729, 3732, 3732, 3740, 3744, 3747, 3748, 3753, 3756, 3757, 3763, 3763, 3764, 3771, 3772, 3772, 3777, 3780, 3784, 3789, 3792, 3797,
    3795, 3804, 3806, 3808, 3810, 3813, 3813, 3819, 3823, 3820, 3826, 3829, 3832, 3836, 3841, 3844, 3847, 3848, 3857, 3858, 3858, 3861, 3863, 3867, 3873,
    3873, 3874, 3881, 3886, 3886, 3892, 3894, 3894, 3897, 3902, 3901, 3906, 3911, 3909, 3915, 3920, 3919, 3926, 3926, 3932, 3936, 3936, 3939, 3938, 3945,
    3947, 3947, 3951, 3955, 3955, 3962, 3964, 3965, 3971, 3975, 3979, 3981, 3983, 3985, 3988, 3991, 3992, 3994, 3996, 4002, 4001, 4008, 4013, 4016, 4020,
    4022, 4027, 4025, 4031, 4032, 4033, 4038, 4041, 4038, 4046, 4048, 4050, 4058, 4062, 4064, 4066, 4068, 4071, 4071, 4074, 4078, 4079, 4082, 4087, 4086,
    4087, 4091, 4094,
};

enum oplus_ofp_log_level {
	OPLUS_OFP_LOG_LEVEL_NONE = 0,
	OPLUS_OFP_LOG_LEVEL_ERR,
	OPLUS_OFP_LOG_LEVEL_WARN,
	OPLUS_OFP_LOG_LEVEL_INFO,
	OPLUS_OFP_LOG_LEVEL_DEBUG,
};

enum oplus_ofp_display_id {
	OPLUS_OFP_PRIMARY_DISPLAY = 0,
	OPLUS_OFP_SECONDARY_DISPLAY = 1,
};

enum oplus_ofp_property_value {
	OPLUS_OFP_PROPERTY_NONE = 0,
	OPLUS_OFP_PROPERTY_DIM_LAYER = BIT(0),
	OPLUS_OFP_PROPERTY_FINGERPRESS_LAYER = BIT(1),
	OPLUS_OFP_PROPERTY_ICON_LAYER = BIT(2),
	OPLUS_OFP_PROPERTY_AOD_LAYER = BIT(3),
};

enum oplus_ofp_irq_type {
	OPLUS_OFP_RD_PTR = 0,
	OPLUS_OFP_WD_PTR = 1,
	OPLUS_OFP_PP_DONE = 2,
};

enum oplus_ofp_pressed_icon_status {
	OPLUS_OFP_PRESSED_ICON_OFF_WR_PTR = 0,			/* the data scanning without pressed icon has started */
	OPLUS_OFP_PRESSED_ICON_OFF_PP_DONE = 1,			/* the data without pressed icon has been flush to DDIC ram */
	OPLUS_OFP_PRESSED_ICON_OFF = 2,					/* the data without pressed icon has been displayed in panel */
	OPLUS_OFP_PRESSED_ICON_ON_WR_PTR = 3,			/* pressed icon scanning has started */
	OPLUS_OFP_PRESSED_ICON_ON_PP_DONE = 4,			/* pressed icon has been flush to DDIC ram */
	OPLUS_OFP_PRESSED_ICON_ON = 5,					/* pressed icon has been displayed in panel */
};

enum oplus_ofp_ui_status {
	OPLUS_OFP_UI_DISAPPEAR = 0,
	OPLUS_OFP_UI_READY = 1,
};

/* remember to initialize params */
struct oplus_ofp_params {
	unsigned int fp_type;							/*
													 bit(0):lcd capacitive fingerprint(aod/fod aren't supported)
													 bit(1):oled capacitive fingerprint(only support aod)
													 bit(2):optical fingerprint old solution(dim layer && pressed icon are controlled by kernel)
													 bit(3):optical fingerprint new solution(dim layer && pressed icon aren't controlled by kernel)
													 bit(4):local hbm
													 bit(5):pressed icon brightness adaptation
													 bit(6):ultrasonic fingerprint
													 bit(7):ultra low power aod
													 bit(8):fod color feature flag
													 bit(9):video mode aod && fod
													*/
	bool fp_type_compatible_mode;					/* indicates whether fp type compatible mode is set or not */
	bool need_to_bypass_gamut;						/* indicates whether gamut needs to be bypassed in aod/fod scenarios or not */
	/* fod */
	unsigned int hbm_mode;							/* a node value used for fingerprint calibration */
	unsigned int aor_mode;							/* a node value used for aor change setting */
	unsigned int dimlayer_hbm;						/* indicates whether the dimlayer and hbm should enable or not(reserved) */
	uint64_t hbm_enable;							/* HBM_ENABLE property value */
	bool need_to_update_lhbm_vdc;	                    /* indicates whether lhbm vdc params needs to be updated or not */
	bool need_to_update_lhbm_pressed_icon_gamma;	/* indicates whether lhbm pressed icon gamma needs to be read and updated or not */
	bool hbm_state;									/* indicates whether panel is hbm state or not */
	bool panel_hbm_status;							/* indicates whether hbm cmds are taking effect in panel module or not */
	bool fp_press;									/* indicates whether pressed icon layer is ready or not */
	unsigned int pressed_icon_status;				/* indicates whether pressed icon has been displayed in panel module or not */
	unsigned int notifier_chain_value;				/* ui ready notifier chain value */
	struct workqueue_struct *uiready_event_wq;		/* a workqueue used to send uiready event */
	struct work_struct uiready_event_work;			/* a work struct used to send uiready event */
	/* aod */
	bool doze_active;								/* indicates whether the current power mode is doze/doze suspend or not */
	bool aod_state;									/* indicates whether panel is aod state or not */
	bool need_to_wait_data_before_aod_on;			/* indicates whether display on cmd(29h) needs to be sent after image data write before aod on or not */
	bool wait_data_before_aod_on;					/* indicates whether to start waiting image data before aod on or not */
	bool aod_unlocking;								/* indicates whether the fingerprint unlocking is in aod state or not */
	unsigned int aod_off_hbm_on_delay;				/* indicates that how many frames need to wait to separate aod off cmds and hbm on cmds */
	ktime_t aod_off_cmd_timestamp;					/* record aod off cmds timestamp for aod off hbm on delay judgment */
	unsigned int aod_light_mode;					/* aod brightness setting, 0:50nit, 1:10nit */
	bool ultra_low_power_aod_state;					/* indicates whether panel is ultra low power aod state or not */
	unsigned int ultra_low_power_aod_mode;			/* indicates whether ultra low power aod mode needs to be entered or not */
	struct workqueue_struct *aod_display_on_set_wq;	/* a workqueue used to send display on(29) cmd after image data write before aod on */
	struct work_struct aod_display_on_set_work;		/* a work struct used to send display on(29) cmd after image data write before aod on */
	struct workqueue_struct *aod_off_set_wq;		/* a workqueue used to send aod off cmds to speed up aod unlocking */
	struct work_struct aod_off_set_work;			/* a work struct used to send aod off cmds to speed up aod unlocking */
	struct notifier_block touchpanel_event_notifier;/* add for touchpanel event notifier */
};

/* log level config */
extern unsigned int oplus_ofp_log_level;
/* dual display id */
extern unsigned int oplus_ofp_display_id;
/* debug log switch */
extern unsigned int oplus_dsi_log_type;
/* dynamic trace enable */
extern unsigned int oplus_display_trace_enable;

/* debug log */
#define OFP_ERR(fmt, arg...)	\
	do {	\
		if (oplus_ofp_log_level >= OPLUS_OFP_LOG_LEVEL_ERR)	\
			pr_err("[OFP][%u][ERR][%s:%d]"pr_fmt(fmt), oplus_ofp_display_id, __func__, __LINE__, ##arg);	\
	} while (0)

#define OFP_WARN(fmt, arg...)	\
	do {	\
		if (oplus_ofp_log_level >= OPLUS_OFP_LOG_LEVEL_WARN)	\
			pr_warn("[OFP][%u][WARN][%s:%d]"pr_fmt(fmt), oplus_ofp_display_id, __func__, __LINE__, ##arg);	\
	} while (0)

#define OFP_INFO(fmt, arg...)	\
	do {	\
		if (oplus_ofp_log_level >= OPLUS_OFP_LOG_LEVEL_INFO)	\
			pr_info("[OFP][%u][INFO][%s:%d]"pr_fmt(fmt), oplus_ofp_display_id, __func__, __LINE__, ##arg);	\
	} while (0)

#define OFP_DEBUG(fmt, arg...)	\
	do {	\
		if ((oplus_ofp_log_level >= OPLUS_OFP_LOG_LEVEL_DEBUG) && (oplus_dsi_log_type & OPLUS_DEBUG_LOG_OFP))	\
			pr_info("[OFP][%u][DEBUG][%s:%d]"pr_fmt(fmt), oplus_ofp_display_id, __func__, __LINE__, ##arg);	\
	} while (0)

/* debug trace */
#define OPLUS_OFP_TRACE_BEGIN(name)	\
	do {	\
		if (oplus_display_trace_enable & OPLUS_DISPLAY_OFP_TRACE_ENABLE)	\
			SDE_ATRACE_BEGIN(name);	\
	} while (0)

#define OPLUS_OFP_TRACE_END(name)	\
	do {	\
		if (oplus_display_trace_enable & OPLUS_DISPLAY_OFP_TRACE_ENABLE)	\
			SDE_ATRACE_END(name);	\
	} while (0)

#define OPLUS_OFP_TRACE_INT(name, value)	\
	do {	\
		if (oplus_display_trace_enable & OPLUS_DISPLAY_OFP_TRACE_ENABLE)	\
			SDE_ATRACE_INT(name, value);	\
	} while (0)

/* -------------------- oplus_ofp_params -------------------- */
int oplus_ofp_update_display_id(void);
int oplus_ofp_init(void *dsi_panel);
bool oplus_ofp_is_supported(void);
bool oplus_ofp_oled_capacitive_is_enabled(void);
bool oplus_ofp_optical_new_solution_is_enabled(void);
bool oplus_ofp_local_hbm_is_enabled(void);
bool oplus_ofp_ultrasonic_is_enabled(void);
bool oplus_ofp_video_mode_aod_fod_is_enabled(void);
bool oplus_ofp_get_hbm_state(void);
int oplus_ofp_property_update(void *sde_connector, void *sde_connector_state, int prop_id, uint64_t prop_val);

/* -------------------- fod -------------------- */
int oplus_ofp_parse_dtsi_config(void *dsi_display_mode, void *dsi_parser_utils);
int oplus_ofp_lhbm_pressed_icon_gamma_update(void *dsi_display);
int oplus_ofp_lhbm_backlight_update(void *sde_encoder_virt, void *dsi_panel, unsigned int *bl_level);
int oplus_ofp_send_hbm_state_event(unsigned int hbm_state);
int oplus_ofp_hbm_handle(void *sde_encoder_virt);
int oplus_ofp_cmd_post_wait(void *dsi_display_mode, void *dsi_cmd_desc, enum dsi_cmd_set_type type);
int oplus_ofp_panel_hbm_status_update(void *sde_encoder_phys);
int oplus_ofp_pressed_icon_status_update(void *sde_encoder_phys, unsigned int irq_type);
void oplus_ofp_uiready_event_work_handler(struct work_struct *work_item);
int oplus_ofp_notify_uiready(void *sde_encoder_phys);
bool oplus_ofp_backlight_filter(void *dsi_panel, unsigned int bl_level);
bool oplus_ofp_need_pcc_change(void *s_crtc);
int oplus_ofp_set_dspp_pcc_feature(void *sde_hw_cp_cfg, void *s_crtc, bool before_setup_pcc);
int oplus_ofp_bypass_dspp_gamut(void *sde_hw_cp_cfg, void *s_crtc);
int oplus_ofp_lhbm_dbv_vdc_update(void *dsi_panel, unsigned int bl_level, bool entering_lhbm);
int oplus_ofp_lhbm_dbv_alpha_update(void *dsi_panel, unsigned int bl_level, bool entering_lhbm);

/* -------------------- aod -------------------- */
void oplus_ofp_aod_display_on_set_work_handler(struct work_struct *work_item);
int oplus_ofp_aod_display_on_set(void *sde_encoder_phys);
int oplus_ofp_aod_off_handle(void *dsi_display);
int oplus_ofp_power_mode_handle(void *dsi_display, int power_mode);
int oplus_ofp_video_mode_aod_handle(void *dsi_display, void *dsi_display_mode);
void oplus_ofp_aod_off_set_work_handler(struct work_struct *work_item);
int oplus_ofp_touchpanel_event_notifier_call(struct notifier_block *nb, unsigned long action, void *data);
int oplus_ofp_aod_off_hbm_on_delay_check(void *sde_encoder_phys);
int oplus_ofp_aod_off_backlight_recovery(void *sde_encoder_virt);
int oplus_ofp_ultra_low_power_aod_update(void *sde_encoder_virt);

/* -------------------- node -------------------- */
/* fp_type */
int oplus_ofp_set_fp_type(void *buf);
int oplus_ofp_get_fp_type(void *buf);
ssize_t oplus_ofp_set_fp_type_attr(struct kobject *obj,
	struct kobj_attribute *attr, const char *buf, size_t count);
ssize_t oplus_ofp_get_fp_type_attr(struct kobject *obj,
	struct kobj_attribute *attr, char *buf);
/* ----- fod part ----- */
/* hbm */
int oplus_ofp_set_hbm(void *buf);
int oplus_ofp_get_hbm(void *buf);
ssize_t oplus_ofp_set_hbm_attr(struct kobject *obj,
	struct kobj_attribute *attr, const char *buf, size_t count);
ssize_t oplus_ofp_get_hbm_attr(struct kobject *obj,
	struct kobj_attribute *attr, char *buf);
/* aor */
ssize_t oplus_ofp_set_aor_attr(struct kobject *obj,
	struct kobj_attribute *attr, const char *buf, size_t count);
ssize_t oplus_ofp_get_aor_attr(struct kobject *obj,
	struct kobj_attribute *attr, char *buf);
/* dimlayer_hbm */
int oplus_ofp_set_dimlayer_hbm(void *buf);
int oplus_ofp_get_dimlayer_hbm(void *buf);
ssize_t oplus_ofp_set_dimlayer_hbm_attr(struct kobject *obj,
	struct kobj_attribute *attr, const char *buf, size_t count);
ssize_t oplus_ofp_get_dimlayer_hbm_attr(struct kobject *obj,
	struct kobj_attribute *attr, char *buf);
/* notify_fppress */
int oplus_ofp_notify_fp_press(void *buf);
ssize_t oplus_ofp_notify_fp_press_attr(struct kobject *obj,
	struct kobj_attribute *attr, const char *buf, size_t count);
/* ----- aod part ----- */
/* aod_light_mode_set */
int oplus_ofp_set_aod_light_mode(void *buf);
int oplus_ofp_get_aod_light_mode(void *buf);
ssize_t oplus_ofp_set_aod_light_mode_attr(struct kobject *obj,
	struct kobj_attribute *attr, const char *buf, size_t count);
ssize_t oplus_ofp_get_aod_light_mode_attr(struct kobject *obj,
	struct kobj_attribute *attr, char *buf);
/* ultra_low_power_aod_mode */
int oplus_ofp_set_ultra_low_power_aod_mode(void *buf);
int oplus_ofp_get_ultra_low_power_aod_mode(void *buf);
ssize_t oplus_ofp_set_ultra_low_power_aod_mode_attr(struct kobject *obj,
	struct kobj_attribute *attr, const char *buf, size_t count);
ssize_t oplus_ofp_get_ultra_low_power_aod_mode_attr(struct kobject *obj,
	struct kobj_attribute *attr, char *buf);

#endif /*_OPLUS_ONSCREENFINGERPRINT_H_*/
