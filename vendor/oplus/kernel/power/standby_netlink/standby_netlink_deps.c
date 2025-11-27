#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/compiler.h>
#include <linux/mm.h>

#include "standby_netlink_deps.h"

struct suspend_enabled_clk {
	struct list_head list;
	const char *clk_name;
	unsigned int clk_rate;
};

struct consumer_regulator {
	struct list_head list;
	const char *supply_name;
	unsigned int enabled_count;
	int min_uV;
	int max_uV;
	int uA_load;
};

struct suspend_enabled_regulator {
	const char *regulator_name;
	struct list_head enabled_regulator_list;
	struct list_head enabled_consumer_list;
};

struct oplus_smp2p_state {
	struct list_head list;
	unsigned local_pid;
	unsigned remote_pid;
	unsigned val;
	u32 count;
};

#ifdef CONFIG_OPLUS_FEATURE_STANDBY_NETLINK_CLOCK
extern struct list_head *get_suspend_clk_list(void);
#else
static struct list_head *get_suspend_clk_list(void)
{
    pr_err("[standby_netlink]: unsupport get_suspend_clk_list.");
    return NULL;
}
#endif

#ifdef CONFIG_OPLUS_FEATURE_STANDBY_NETLINK_REGULATOR
extern struct list_head *get_suspend_regulator_list(void);
#else
static struct list_head *get_suspend_regulator_list(void)
{
    pr_err("[standby_netlink]: unsupport get_suspend_regulator_list.");
    return NULL;
}
#endif

#ifdef CONFIG_OPLUS_FEATURE_STANDBY_NETLINK_SMP2P
extern struct list_head *get_oplus_smp2p_state_list(void);
extern void reset_oplus_smp2p_state(int switch_state);
#else
static struct list_head *get_oplus_smp2p_state_list(void)
{
    pr_err("[standby_netlink]: unsupport get_oplus_smp2p_state_list.");
    return NULL;
}

void reset_oplus_smp2p_state(int switch_state)
{
    pr_err("[standby_netlink]: unsupport reset_oplus_smp2p_state. switch %d.\n", switch_state);
}
#endif

static DEFINE_SPINLOCK(suspend_clk_lock);
static DEFINE_SPINLOCK(suspend_regulator_lock);

void reset_smp2p_switch(int switch_state)
{
    reset_oplus_smp2p_state(switch_state);
}

static int calculate_smp2p_info_size(struct list_head *smp2p_list)
{
    int total_len = 0;
    struct oplus_smp2p_state *entry;

    if (!smp2p_list)
        return snprintf(NULL, 0, "Unsupport");

    list_for_each_entry(entry, smp2p_list, list) {
        total_len += snprintf(NULL, 0, "%d_%d_%d_%d\n",
                            entry->local_pid, entry->remote_pid, entry->val, entry->count);
    }

    return total_len ? total_len : snprintf(NULL, 0, "Empty");
}

static int fill_smp2p_info(struct list_head *smp2p_list, char *buf, int len)
{
    int pos = 0;
    struct oplus_smp2p_state *entry;

    if (!smp2p_list)
        return scnprintf(buf, len, "Unsupport");

    if (list_empty(smp2p_list))
        return scnprintf(buf, len, "Empty");

    list_for_each_entry(entry, smp2p_list, list) {
        pos += scnprintf(buf + pos, len - pos, "%d_%d_%d_%d\n",
                            entry->local_pid, entry->remote_pid, entry->val, entry->count);
        if (pos >= len)
            break;
    }

    return pos;
}

int handle_smp2p_info(char **buf)
{
    struct list_head *smp2p_info;
    int needed, actual;

    smp2p_info = get_oplus_smp2p_state_list();
    // Phase 1: Calculate required size
    needed = calculate_smp2p_info_size(smp2p_info);
    if (needed <= 0)
        return needed;

    // Phase 2: Allocate memory of exact size
    *buf = kmalloc(needed + 1, GFP_KERNEL);
    if (!*buf)
        return -ENOMEM;

    // Phase 3: Fill data into the buffer
    actual = fill_smp2p_info(smp2p_info, *buf, needed + 1);
    if (actual < 0) {
        kfree(*buf);
        *buf = NULL;
    }

    return actual;
}

static int calculate_regs_info_size(struct list_head *regs_list)
{
    int total_len = 0;
    unsigned long flags;
    struct suspend_enabled_regulator *suspend_reg;
    struct consumer_regulator *suspend_consumer;

    if (!regs_list)
        return snprintf(NULL, 0, "Unsupport");

    spin_lock_irqsave(&suspend_regulator_lock, flags);
    list_for_each_entry(suspend_reg, regs_list, enabled_regulator_list) {
        total_len += snprintf(NULL, 0, "%s\n", suspend_reg->regulator_name);
        total_len += snprintf(NULL, 0, "  %-32s EN    Min_uV   Max_uV  load_uA\n", "Device-Supply");
        list_for_each_entry(suspend_consumer, &suspend_reg->enabled_consumer_list, list) {
            total_len += snprintf(NULL, 0, "  %-32s %d   %8d %8d %8d\n", suspend_consumer->supply_name,
                suspend_consumer->enabled_count,
                suspend_consumer->min_uV,
                suspend_consumer->max_uV,
                suspend_consumer->uA_load);
        }
    }
    spin_unlock_irqrestore(&suspend_regulator_lock, flags);

    return total_len ? total_len : snprintf(NULL, 0, "Empty");
}

static int fill_regs_info(struct list_head *regs_list, char *buf, int len)
{
    int pos = 0;
    unsigned long flags;
    struct suspend_enabled_regulator *suspend_reg;
    struct consumer_regulator *suspend_consumer;

    if (!regs_list)
        return scnprintf(buf, len, "Unsupport");

    if (list_empty(regs_list))
        return scnprintf(buf, len, "Empty");

    spin_lock_irqsave(&suspend_regulator_lock, flags);
    list_for_each_entry(suspend_reg, regs_list, enabled_regulator_list) {
        pos += scnprintf(buf + pos, len - pos, "%s\n", suspend_reg->regulator_name);
        pos += scnprintf(buf + pos, len - pos, "  %-32s EN    Min_uV   Max_uV  load_uA\n", "Device-Supply");
        list_for_each_entry(suspend_consumer, &suspend_reg->enabled_consumer_list, list) {
            pos += scnprintf(buf + pos, len - pos, "  %-32s %d   %8d %8d %8d\n", suspend_consumer->supply_name,
                suspend_consumer->enabled_count,
                suspend_consumer->min_uV,
                suspend_consumer->max_uV,
                suspend_consumer->uA_load);
        }
        if (pos >= len)
            break;
    }
    spin_unlock_irqrestore(&suspend_regulator_lock, flags);

    return pos;
}

int handle_regs_info(char **buf)
{
    int needed, actual;
    struct list_head *suspend_regs;

    suspend_regs = get_suspend_regulator_list();
    // Phase 1: Calculate required size
    needed = calculate_regs_info_size(suspend_regs);
    if (needed <= 0)
        return needed;

    // Phase 2: Allocate memory of exact size
    *buf = kmalloc(needed + 1, GFP_KERNEL);
    if (!*buf)
        return -ENOMEM;

    // Phase 3: Fill data into the buffer
    actual = fill_regs_info(suspend_regs, *buf, needed + 1);
    if (actual < 0) {
        kfree(*buf);
        *buf = NULL;
    }

    return actual;
}

static int calculate_clocks_info_size(struct list_head *clocks_list)
{
    int total_len = 0;
    unsigned long flags;
    struct suspend_enabled_clk *entry;

    if (!clocks_list)
        return snprintf(NULL, 0, "Unsupport");

    spin_lock_irqsave(&suspend_clk_lock, flags);
    list_for_each_entry(entry, clocks_list, list) {
        total_len += snprintf(NULL, 0, "%s: [%u]\n", entry->clk_name ?: "null", entry->clk_rate);
    }
    spin_unlock_irqrestore(&suspend_clk_lock, flags);

    return total_len ? total_len : snprintf(NULL, 0, "Empty");
}

static int fill_clocks_info(struct list_head *clocks_list, char *buf, int len)
{
    int pos = 0;
    unsigned long flags;
    struct suspend_enabled_clk *entry;

    if (!clocks_list)
        return scnprintf(NULL, 0, "Unsupport");

    if (list_empty(clocks_list))
        return scnprintf(buf, len, "Empty");

    spin_lock_irqsave(&suspend_clk_lock, flags);
    list_for_each_entry(entry, clocks_list, list) {
        pos += scnprintf(buf + pos, len - pos, "%s: [%u]\n", entry->clk_name ?: "null", entry->clk_rate);
        if (pos >= len)
            break;
    }
    spin_unlock_irqrestore(&suspend_clk_lock, flags);

    return pos;
}

int handle_clock_info(char **buf)
{
    int needed, actual;
    struct list_head *suspend_clk_list;

    suspend_clk_list = get_suspend_clk_list();
    // Phase 1: Calculate required size
    needed = calculate_clocks_info_size(suspend_clk_list);
    if (needed <= 0)
        return needed;

    // Phase 2: Allocate memory of exact size
    *buf = kmalloc(needed + 1, GFP_KERNEL);
    if (!*buf)
        return -ENOMEM;

    // Phase 3: Fill data into the buffer
    actual = fill_clocks_info(suspend_clk_list, *buf, needed + 1);
    if (actual < 0) {
        kfree(*buf);
        *buf = NULL;
    }

    return actual;
}