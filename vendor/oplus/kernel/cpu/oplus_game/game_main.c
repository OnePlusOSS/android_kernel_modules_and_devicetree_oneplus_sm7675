#include <linux/module.h>

#include "early_detect.h"
#include "cpufreq_limits.h"
#include "debug.h"

#define OPLUS_GAME_VERSION_MODULE "1.0"

static void __exit oplus_game_exit(void)
{
	early_detect_exit();
	cpufreq_limits_exit();
}

static int __init oplus_game_init(void)
{
	early_detect_init();
	cpufreq_limits_init();
	debug_init();

	return 0;
}

module_init(oplus_game_init);
module_exit(oplus_game_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("OPLUS GAME");
MODULE_AUTHOR("Oplus Inc.");
MODULE_VERSION(OPLUS_GAME_VERSION_MODULE);