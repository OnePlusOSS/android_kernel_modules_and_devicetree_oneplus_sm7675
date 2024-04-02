// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020-2022 Oplus. All rights reserved.
 */

#define pr_fmt(fmt) "[HYB_ZRAM]" fmt

#include <linux/slab.h>
#include <linux/cpu.h>
#include <trace/hooks/mm.h>
#include <trace/hooks/vmscan.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/swap.h>
#include <linux/blkdev.h>
#include <linux/cred.h>
#include <linux/mm_inline.h>

#include "../zram_drv.h"
#include "../zram_drv_internal.h"
#include "internal.h"
#include "hybridswap.h"

#ifdef CONFIG_OPLUS_FEATURE_UXMEM_OPT
#include <../kernel/oplus_cpu/sched/sched_assist/sa_common.h>
#endif

static const char *swapd_text[NR_EVENT_ITEMS] = {
#ifdef CONFIG_HYBRIDSWAP_SWAPD
	"swapd_wakeup",
	"swapd_hit_refaults",
	"swapd_medium_press",
	"swapd_critical_press",
	"swapd_memcg_ratio_skip",
	"swapd_memcg_refault_skip",
	"swapd_shrink_anon",
	"swapd_swapout",
	"swapd_skip_swapout",
	"swapd_empty_round",
	"swapd_over_min_buffer_skip_times",
	"swapd_empty_round_skip_times",
	"swapd_snapshot_times",
	"swapd_skip_shrink_of_window",
	"swapd_manual_pause",
#ifdef CONFIG_OPLUS_JANK
	"swapd_cpu_busy_skip_times",
	"swapd_cpu_busy_break_times",
#endif
#endif
};

static int log_level = HYB_MAX;
static struct kmem_cache *hybridswap_cache;
static struct list_head score_head;
static DEFINE_SPINLOCK(score_list_lock);
static DEFINE_MUTEX(hybridswap_enable_lock);
static bool hybridswap_enabled = false;
struct hybridswapd_operations *hybridswapd_ops;

DEFINE_MUTEX(reclaim_para_lock);
DEFINE_PER_CPU(struct swapd_event_state, swapd_event_states);

extern unsigned long try_to_free_mem_cgroup_pages(struct mem_cgroup *memcg,
		unsigned long nr_pages,
		gfp_t gfp_mask,
		unsigned int reclaim_options);

extern int folio_referenced(struct folio *folio, int is_locked,
				struct mem_cgroup *memcg, unsigned long *vm_flags);

void hybridswap_loglevel_set(int level)
{
	log_level = level;
}

int hybridswap_loglevel(void)
{
	return log_level;
}

void __put_memcg_cache(memcg_hybs_t *hybs)
{
	kmem_cache_free(hybridswap_cache, (void *)hybs);
}

static inline void sum_hybridswap_vm_events(unsigned long *ret)
{
	int cpu;
	int i;

	memset(ret, 0, NR_EVENT_ITEMS * sizeof(unsigned long));

	for_each_online_cpu(cpu) {
		struct swapd_event_state *this =
			&per_cpu(swapd_event_states, cpu);

		for (i = 0; i < NR_EVENT_ITEMS; i++)
			ret[i] += this->event[i];
	}
}

static inline void all_hybridswap_vm_events(unsigned long *ret)
{
	cpus_read_lock();
	sum_hybridswap_vm_events(ret);
	cpus_read_unlock();
}

ssize_t hybridswap_vmstat_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned long *vm_buf = NULL;
	int len = 0;
	int i = 0;

	vm_buf = kzalloc(sizeof(struct swapd_event_state), GFP_KERNEL);
	if (!vm_buf)
		return -ENOMEM;
	all_hybridswap_vm_events(vm_buf);

#ifdef CONFIG_HYBRIDSWAP_SWAPD
	len += snprintf(buf + len, PAGE_SIZE - len, "%-32s %12lu\n",
			"fault_out_pause", atomic_long_read(hybridswapd_ops->fault_out_pause));
	len += snprintf(buf + len, PAGE_SIZE - len, "%-32s %12lu\n",
			"fault_out_pause_cnt", atomic_long_read(hybridswapd_ops->fault_out_pause_cnt));
#endif

	for (;i < NR_EVENT_ITEMS; i++) {
		len += snprintf(buf + len, PAGE_SIZE - len, "%-32s %12lu\n",
				swapd_text[i], vm_buf[i]);
		if (len == PAGE_SIZE)
			break;
	}
	kfree(vm_buf);

	return len;
}

ssize_t hybridswap_loglevel_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	char *type_buf = NULL;
	unsigned long val;

	type_buf = strstrip((char *)buf);
	if (kstrtoul(type_buf, 0, &val))
		return -EINVAL;

	if (val >= HYB_MAX) {
		log_err("val %lu is not valid\n", val);
		return -EINVAL;
	}
	hybridswap_loglevel_set((int)val);

	return len;
}

ssize_t hybridswap_loglevel_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	ssize_t size = 0;

	size += scnprintf(buf + size, PAGE_SIZE - size,
			"Hybridswap log level: %d\n", hybridswap_loglevel());

	return size;
}

/* Make sure the memcg is not NULL in caller */
memcg_hybs_t *hybridswap_cache_alloc(struct mem_cgroup *memcg, bool atomic)
{
	memcg_hybs_t *hybs;
	u64 ret;
	gfp_t flags = GFP_KERNEL;

	if (memcg->android_oem_data1[0])
		BUG();

	if (atomic)
		flags &= ~__GFP_DIRECT_RECLAIM;

	hybs = (memcg_hybs_t *)kmem_cache_zalloc(hybridswap_cache, flags);
	if (!hybs)
		return NULL;

	INIT_LIST_HEAD(&hybs->score_node);
#ifdef CONFIG_HYBRIDSWAP_CORE
	spin_lock_init(&hybs->zram_init_lock);
#endif
	atomic64_set(&hybs->app_score, 300);
	atomic64_set(&hybs->ub_ufs2zram_ratio, 100);
#ifdef CONFIG_HYBRIDSWAP_SWAPD
	atomic_set(&hybs->ub_mem2zram_ratio, 80);
	atomic_set(&hybs->ub_zram2ufs_ratio, 50);
	atomic_set(&hybs->refault_threshold, 50);
#endif
	hybs->memcg = memcg;
	refcount_set(&hybs->usage, 1);

	ret = atomic64_cmpxchg((atomic64_t *)&memcg->android_oem_data1[0], 0, (u64)hybs);
	if (ret != 0) {
		put_memcg_cache(hybs);
		return (memcg_hybs_t *)ret;
	}

	return hybs;
}

#ifdef CONFIG_HYBRIDSWAP_SWAPD
static void tune_scan_type_hook(void *data, enum scan_balance *s_balance)
{
	hybridswapd_ops->vh_tune_scan_type(NULL , s_balance);
}
#endif

static void mem_cgroup_alloc_hook(void *data, struct mem_cgroup *memcg)
{
	if (memcg->android_oem_data1[0])
		BUG();

	hybridswap_cache_alloc(memcg, true);
}

static void mem_cgroup_free_hook(void *data, struct mem_cgroup *memcg)
{
	memcg_hybs_t *hybs;

	if (!memcg->android_oem_data1[0])
		return;

	hybs = (memcg_hybs_t *)memcg->android_oem_data1[0];
	memcg->android_oem_data1[0] = 0;
	put_memcg_cache(hybs);
}

void memcg_app_score_update(struct mem_cgroup *target)
{
	struct list_head *pos = NULL;
	unsigned long flags;

#ifdef CONFIG_HYBRIDSWAP_SWAPD
	hybridswapd_ops->update_memcg_param(target);
#endif
	spin_lock_irqsave(&score_list_lock, flags);
	list_for_each(pos, &score_head) {
		memcg_hybs_t *hybs = list_entry(pos, memcg_hybs_t, score_node);
		if (atomic64_read(&hybs->app_score) <
				atomic64_read(&MEMCGRP_ITEM(target, app_score)))
			break;
	}
	list_move_tail(&MEMCGRP_ITEM(target, score_node), pos);
	spin_unlock_irqrestore(&score_list_lock, flags);
}

static void mem_cgroup_css_online_hook(void *data,
		struct cgroup_subsys_state *css, struct mem_cgroup *memcg)
{
	if (memcg->android_oem_data1[0])
		memcg_app_score_update(memcg);

	css_get(css);
}

static void mem_cgroup_css_offline_hook(void *data,
		struct cgroup_subsys_state *css, struct mem_cgroup *memcg)
{
	unsigned long flags;

	if (memcg->android_oem_data1[0]) {
		spin_lock_irqsave(&score_list_lock, flags);
		list_del_init(&MEMCGRP_ITEM(memcg, score_node));
		spin_unlock_irqrestore(&score_list_lock, flags);
	}

	css_put(css);
}

#ifdef CONFIG_CONT_PTE_HUGEPAGE
#if IS_ENABLED(CONFIG_OPLUS_FEATURE_SCHED_ASSIST)
extern bool test_task_ux(struct task_struct *task);
#else
static inline bool test_task_ux(struct task_struct *task)
{
	return false;
}
#endif /* CONFIG_OPLUS_FEATURE_SCHED_ASSIST */

#ifdef CONFIG_OPLUS_FEATURE_UXMEM_OPT
extern bool is_fg(int uid);
inline int task_is_fg(struct task_struct *tsk)
{
	int cur_uid;

	cur_uid = task_uid(tsk).val;
	if (is_fg(cur_uid))
		return 1;
	return 0;
}

static inline bool current_is_key_task(void)
{
	return test_task_ux(current) || rt_task(current)
		|| (oplus_get_im_flag(current) == IM_FLAG_SURFACEFLINGER)
		|| (oplus_get_im_flag(current) == IM_FLAG_SYSTEMSERVER_PID)
		|| task_is_fg(current);
}
#endif /* CONFIG_OPLUS_FEATURE_UXMEM_OPT */

static void oplus_mm_common_hook(void *unused, unsigned long *behavior, unsigned long *output)
{
	switch ((unsigned long)behavior) {
	case OPLUS_MM_VH_CURRENT_IS_UX:
		*output = test_task_ux(current);
		break;
	case OPLUS_MM_VH_FREE_ZRAM_IS_OK:
		*output = hybridswapd_ops->free_zram_is_ok();
		break;
#ifdef CONFIG_OPLUS_FEATURE_UXMEM_OPT
	case OPLUS_MM_VH_CURRENT_IS_KEY:
		*output = current_is_key_task();
		break;
#endif
	default:
		break;
	}
}
#endif /* CONFIG_CONT_PTE_HUGEPAGE */

#define REGISTER_HOOK(name) do {\
	rc = register_trace_android_vh_##name(name##_hook, NULL);\
	if (rc) {\
		log_err("%s:%d register hook %s failed", __FILE__, __LINE__, #name);\
		goto err_out_##name;\
	}\
} while (0)

#define UNREGISTER_HOOK(name) do {\
	unregister_trace_android_vh_##name(name##_hook, NULL);\
} while (0)

#define ERROR_OUT(name) err_out_##name

static int register_all_hooks(void)
{
	int rc;

	/* mem_cgroup_alloc_hook */
	REGISTER_HOOK(mem_cgroup_alloc);
	/* mem_cgroup_free_hook */
	REGISTER_HOOK(mem_cgroup_free);
	/* mem_cgroup_css_online_hook */
	REGISTER_HOOK(mem_cgroup_css_online);
	/* mem_cgroup_css_offline_hook */
	REGISTER_HOOK(mem_cgroup_css_offline);
#ifdef CONFIG_CONT_PTE_HUGEPAGE
	rc = register_trace_android_vh_si_meminfo_adjust(oplus_mm_common_hook, NULL);
	if (rc) {
		log_err("register_trace_android_vh_si_meminfo_adjust failed\n");
		goto err_out_si_meminfo_adjust;
	}
#endif
#ifdef CONFIG_HYBRIDSWAP_SWAPD
	/* For GKI reason we use get_page_wmark_hook rather than rmqueue_hook. Both are fine. */
	/* rmqueue_hook */
	/* REGISTER_HOOK(rmqueue); */
	/* get_page_wmark_hook */
	rc = register_trace_android_vh_get_page_wmark(hybridswapd_ops->vh_get_page_wmark, NULL);
	if (rc) {
		log_err("register get_page_wmark_hook failed\n");
		goto err_out_get_page_wmark;
	}
	/* tune_scan_type_hook */
	REGISTER_HOOK(tune_scan_type);

	rc = register_trace_android_vh_shrink_slab_bypass(hybridswapd_ops->vh_shrink_slab_bypass, NULL);
	if (rc) {
		log_err("register shrink_slab_bypass failed\n");
		goto err_out_shrink_slab_bypass;
	}
#endif
#ifdef CONFIG_HYBRIDSWAP_CORE
	/* mem_cgroup_id_remove_hook */
	REGISTER_HOOK(mem_cgroup_id_remove);
#endif
	return 0;

#ifdef CONFIG_HYBRIDSWAP_CORE
	UNREGISTER_HOOK(mem_cgroup_id_remove);
ERROR_OUT(mem_cgroup_id_remove):
#endif
#ifdef CONFIG_HYBRIDSWAP_SWAPD
	unregister_trace_android_vh_shrink_slab_bypass(hybridswapd_ops->vh_shrink_slab_bypass, NULL);
err_out_shrink_slab_bypass:
	UNREGISTER_HOOK(tune_scan_type);
ERROR_OUT(tune_scan_type):
	/* UNREGISTER_HOOK(rmqueue);
ERROR_OUT(rmqueue): */
	unregister_trace_android_vh_get_page_wmark(hybridswapd_ops->vh_get_page_wmark, NULL);
err_out_get_page_wmark:
#endif
#ifdef CONFIG_CONT_PTE_HUGEPAGE
	unregister_trace_android_vh_si_meminfo_adjust(oplus_mm_common_hook, NULL);
err_out_si_meminfo_adjust:
#endif
	UNREGISTER_HOOK(mem_cgroup_css_offline);
ERROR_OUT(mem_cgroup_css_offline):
	UNREGISTER_HOOK(mem_cgroup_css_online);
ERROR_OUT(mem_cgroup_css_online):
	UNREGISTER_HOOK(mem_cgroup_free);
ERROR_OUT(mem_cgroup_free):
	UNREGISTER_HOOK(mem_cgroup_alloc);
ERROR_OUT(mem_cgroup_alloc):
	return rc;
}

static void unregister_all_hook(void)
{
	UNREGISTER_HOOK(mem_cgroup_alloc);
	UNREGISTER_HOOK(mem_cgroup_free);
	UNREGISTER_HOOK(mem_cgroup_css_offline);
	UNREGISTER_HOOK(mem_cgroup_css_online);
#ifdef CONFIG_HYBRIDSWAP_CORE
	UNREGISTER_HOOK(mem_cgroup_id_remove);
#endif
#ifdef CONFIG_HYBRIDSWAP_SWAPD
	/* UNREGISTER_HOOK(rmqueue); */
	unregister_trace_android_vh_get_page_wmark(hybridswapd_ops->vh_get_page_wmark, NULL);
	UNREGISTER_HOOK(tune_scan_type);
#endif
}

/*
 * FIXME : memcg->vmstats_percpu pointer to incomplete type ‘struct memcg_vmstats_percpu‘
 * Copy from memcontrol.c,The memcg_vmstats_percpu must be the same as memcontrol.c
 */
const unsigned int memcg_vm_event_stat[] = {
	PGPGIN,
	PGPGOUT,
	PGSCAN_KSWAPD,
	PGSCAN_DIRECT,
	PGSTEAL_KSWAPD,
	PGSTEAL_DIRECT,
	PGFAULT,
	PGMAJFAULT,
	PGREFILL,
	PGACTIVATE,
	PGDEACTIVATE,
	PGLAZYFREE,
	PGLAZYFREED,
#if defined(CONFIG_MEMCG_KMEM) && defined(CONFIG_ZSWAP)
	ZSWPIN,
	ZSWPOUT,
#endif
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	THP_FAULT_ALLOC,
	THP_COLLAPSE_ALLOC,
#endif
};
#define NR_MEMCG_EVENTS ARRAY_SIZE(memcg_vm_event_stat)
struct memcg_vmstats_percpu {
	/* Local (CPU and cgroup) page state & events */
	long			state[MEMCG_NR_STAT];
	unsigned long		events[NR_MEMCG_EVENTS];
	/* Delta calculation for lockless upward propagation */
	long			state_prev[MEMCG_NR_STAT];
	unsigned long		events_prev[NR_MEMCG_EVENTS];
	/* Cgroup1: threshold notifications & softlimit tree updates */
	unsigned long		nr_page_events;
	unsigned long		targets[MEM_CGROUP_NTARGETS];
};


/* idx can be of type enum memcg_stat_item or node_stat_item. */
static unsigned long memcg_page_state_local(struct mem_cgroup *memcg, int idx)
{
	long x = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		x += per_cpu(memcg->vmstats_percpu->state[idx], cpu);
#ifdef CONFIG_SMP
	if (x < 0)
		x = 0;
#endif
	return x;
}

unsigned long memcg_anon_pages(struct mem_cgroup *memcg)
{
	if (unlikely(!memcg))
		return 0;


	return (memcg_page_state_local(memcg, NR_ACTIVE_ANON) +
			memcg_page_state_local(memcg, NR_INACTIVE_ANON));
}

static unsigned long memcg_lru_pages(struct mem_cgroup *memcg,
				     enum lru_list lru, bool chp)
{
	int zid;
	unsigned long nr = 0;
	struct mem_cgroup_per_node *mz;

	if (!memcg)
		return 0;

	if (!chp) {
		mz = memcg->nodeinfo[0];
		for (zid = 0; zid < MAX_NR_ZONES; zid++)
			nr += READ_ONCE(mz->lru_zone_size[zid][lru]);
	}
#ifdef CONFIG_CONT_PTE_HUGEPAGE_64K_ZRAM
	if (chp) {
		struct chp_lruvec *lruvec;
		lruvec = (struct chp_lruvec *)memcg->deferred_split_queue.split_queue_len;
		for (zid = 0; zid < MAX_NR_ZONES; zid++)
			nr += READ_ONCE(lruvec->lru_zone_size[zid][lru]);
	}
#endif

	return nr;
}

/* Shrink by free a batch of pages */
static int force_shrink_batch(struct mem_cgroup * memcg,
			      unsigned long nr_need_reclaim,
			      unsigned long *nr_reclaimed,
			      unsigned long batch,
			      bool may_swap, bool chp)
{
	int ret = 0;
	gfp_t gfp_mask = GFP_KERNEL;
#ifdef CONFIG_CONT_PTE_HUGEPAGE_64K_ZRAM
	if (chp)
		gfp_mask |= POOL_USER_ALLOC;
#endif

	while (*nr_reclaimed < nr_need_reclaim) {
		unsigned long reclaimed;
		reclaimed = try_to_free_mem_cgroup_pages(memcg,
			batch, gfp_mask, may_swap);

		if (reclaimed == 0)
			break;

		*nr_reclaimed += reclaimed;

		/* Abort shrink when receive SIGUSR2 */
		if (unlikely(sigismember(&current->pending.signal, SIGUSR2) ||
			sigismember(&current->signal->shared_pending.signal, SIGUSR2))) {
			log_info("abort shrink while shrinking\n");
			ret = -EINTR;
			break;
		}
	}

	log_info("%s try to reclaim %lu %s pages and reclaim %lu pages\n",
		 MEMCGRP_ITEM(memcg, name), nr_need_reclaim,
		 chp ? "chp" : "normal", *nr_reclaimed);
	return ret;
}

#define	BATCH_4M	(1 << 10)
#define	RECLAIM_INACTIVE	0
#define	RECLAIM_ALL		1
unsigned long get_reclaim_pages(struct mem_cgroup *memcg, bool file,
				char *buf, unsigned long *batch,
				unsigned long *nr_reclaimed, bool chp)
{
	unsigned long nr_need_reclaim = 0;
	unsigned long reclaim_flag = 0;
	unsigned long reclaim_batch = 0;
	int lru = LRU_BASE + (file ? LRU_FILE : 0);
	int ret;

	buf = strstrip(buf);
	ret = sscanf(buf, "%lu %lu", &reclaim_flag, &reclaim_batch);
	if (ret != 1 && ret != 2) {
		log_err("reclaim_flag %s value is error!\n",  buf);
		return 0;
	}

	if (reclaim_flag == RECLAIM_INACTIVE)
		nr_need_reclaim = memcg_lru_pages(memcg, lru, chp);
	else if (reclaim_flag == RECLAIM_ALL)
		nr_need_reclaim = memcg_lru_pages(memcg, lru, chp) +
			memcg_lru_pages(memcg, lru + LRU_ACTIVE, chp);
	else if (!chp)
		nr_need_reclaim = reclaim_flag;
	else if (reclaim_flag > *nr_reclaimed)
		/* Try to reclaim a nr of chp */
		nr_need_reclaim = reclaim_flag - *nr_reclaimed;

	if (reclaim_batch > 0 && batch)
		*batch = reclaim_batch;

	log_info("%s batch %lu, nr_need_reclaim %lu, file %d\n",
		 chp ? "chp" : "normal page",
		 *batch, nr_need_reclaim, file);
	return nr_need_reclaim;
}

static ssize_t mem_cgroup_force_shrink(struct kernfs_open_file *of,
		char *buf, size_t nbytes, bool file)
{
	int ret;
	struct mem_cgroup *memcg;
	unsigned long nr_need_reclaim;
	unsigned long nr_reclaimed = 0;
	unsigned long batch = BATCH_4M;

	memcg = mem_cgroup_from_css(of_css(of));
	nr_need_reclaim = get_reclaim_pages(memcg, file, buf,
				&batch, &nr_reclaimed, false);
	if (!file)
		/* In the hook of scan_type, only reclaim anon */
		current->flags |= PF_SHRINK_ANON;

	/* Set may_swap as false to only reclaim file */
	ret = force_shrink_batch(memcg, nr_need_reclaim, &nr_reclaimed,
					  batch, !file, false);
	if (ret == -EINTR)
		goto out;
#ifdef CONFIG_CONT_PTE_HUGEPAGE_64K_ZRAM
	/* Shrink normal page as above, and then shrink chp */
	if (chp_supported && chp_pool && !file) {
		nr_need_reclaim = get_reclaim_pages(memcg, file, buf,
				&batch, &nr_reclaimed, true);
		nr_reclaimed = 0;
		ret = force_shrink_batch(memcg, nr_need_reclaim,
				&nr_reclaimed, batch, !file, true);
		if (ret == -EINTR)
			goto out;
	}
#endif

out:
	if (!file)
		current->flags &= ~PF_SHRINK_ANON;

	return nbytes;
}

static ssize_t mem_cgroup_force_shrink_anon(struct kernfs_open_file *of,
		char *buf, size_t nbytes, loff_t off)
{
	return mem_cgroup_force_shrink(of, buf, nbytes, false);
}

static ssize_t mem_cgroup_force_shrink_file(struct kernfs_open_file *of,
		char *buf, size_t nbytes, loff_t off)
{
	return mem_cgroup_force_shrink(of, buf, nbytes, true);
}

static inline bool folio_evictable(struct folio *folio)
{
	bool ret;

	/* Prevent address_space of inode and swap cache from being freed */
	rcu_read_lock();
	ret = !mapping_unevictable(folio_mapping(folio)) &&
			!folio_test_mlocked(folio);
	rcu_read_unlock();
	return ret;
}

/**
 * isolate_folio_from_lru - a copy of folio_isolate_lru
 * Context:
 * (1) Must be called with an elevated refcount on the folio. This is a
 *     fundamental difference from isolate_lru_folios() (which is called
 *     without a stable reference).
 * (2) The lru_lock must not be held.
 * (3) Interrupts must be enabled.
 */
static int isolate_folio_from_lru(struct folio *folio, struct lruvec *lruvec)
{
	int ret = -EBUSY;

	VM_BUG_ON_FOLIO(!folio_ref_count(folio), folio);

	if (folio_test_clear_lru(folio)) {
		folio_get(folio);
		spin_lock_irq(&lruvec->lru_lock);
		lruvec_del_folio(lruvec, folio);
		spin_unlock_irq(&lruvec->lru_lock);
		ret = 0;
	}

	return ret;
}

/**
 * putback_folio_to_lru - a copy of folio_putback_lru
 *
 * lru_lock must not be held, interrupts must be enabled.
 */
static void putback_folio_to_lru(struct folio *folio)
{
	folio_add_lru(folio);
	folio_put(folio);		/* drop ref from isolate */
}

static unsigned long isolate_folios_to_folio_list(struct lruvec *lruvec,
		enum lru_list lru, struct list_head *folio_list,
		unsigned long nr_to_isolate)
{
	unsigned long nr_isolated = 0, nr_scanned = 0, nr_pages;
	struct folio *folio = NULL;
	struct list_head *src = &lruvec->lists[lru];

	while (!list_empty(src) && nr_scanned < nr_to_isolate) {
		folio = lru_to_folio(src);
		nr_pages = folio_nr_pages(folio);
		nr_scanned += nr_pages;

		if (unlikely(!folio_evictable(folio)))
			continue;

		if (likely(folio_try_get(folio))) {
			if (isolate_folio_from_lru(folio, lruvec)) {
				folio_put(folio);
				continue;
			}
			folio_put(folio);
		} else
			continue;

		if (unlikely(!folio_evictable(folio))) {
			putback_folio_to_lru(folio);
			continue;
		}

		/*
		 * MADV_FREE clears pte dirty bit and then marks the folio
		 * lazyfree (clear SwapBacked). Inbetween if this lazyfreed folio
		 * is touched by user then it becomes dirty.  PPR in
		 * shrink_folio_list in try_to_unmap finds the folio dirty, marks
		 * it back as SwapBacked and skips reclaim. This can cause
		 * isolated count mismatch.
		 */
		if (folio_test_anon(folio) && !folio_test_swapbacked(folio)) {
			putback_folio_to_lru(folio);
			continue;
		}

		list_add(&folio->lru, folio_list);
		nr_isolated += nr_pages;
	}
	return nr_isolated;
}

static void seperate_list(struct list_head *src,
			  struct list_head *active,
			  struct list_head *inactive,
			  struct mem_cgroup *memcg)
{
	struct folio *folio;
	unsigned long vm_flags;

	while (!list_empty(src)) {
		folio = lru_to_folio(src);
		list_del(&folio->lru);

		if (unlikely(!folio_evictable(folio))) {
			putback_folio_to_lru(folio);
			continue;
		}

		if (folio_referenced(folio, 0, memcg, &vm_flags)) {
			folio_set_active(folio);
			list_add(&folio->lru, active);
		} else {
			folio_clear_active(folio);
			list_add(&folio->lru, inactive);
		}
		cond_resched();
	}
}

/*
 * move_folios_into_lru(), a copy of move_folios_to_lru(), but keep zero ref folios in lru
 * Moves folios from private @list to appropriate LRU list.
 *
 * Returns the number of pages moved to the given lruvec.
 */
static unsigned int move_folios_into_lru(struct lruvec *lruvec,
		struct list_head *list)
{
	int nr_pages, nr_moved = 0;
	LIST_HEAD(folios_to_free);

	while (!list_empty(list)) {
		struct folio *folio = lru_to_folio(list);

		VM_BUG_ON_FOLIO(folio_test_lru(folio), folio);
		list_del(&folio->lru);
		if (unlikely(!folio_evictable(folio))) {
			spin_unlock_irq(&lruvec->lru_lock);
			putback_folio_to_lru(folio);
			spin_lock_irq(&lruvec->lru_lock);
			continue;
		}

		/*
		 * The folio_set_lru needs to be kept here for list integrity.
		 * Otherwise:
		 *   #0 move_folios_to_lru             #1 release_pages
		 *   if (!folio_put_testzero())
		 *				      if (folio_put_testzero())
		 *				        !lru //skip lru_lock
		 *     folio_set_lru()
		 *     list_add(&folio->lru,)
		 *                                        list_add(&folio->lru,)
		 */
		folio_set_lru(folio);

		if (unlikely(folio_ref_count(folio) == 1)) {
			__folio_clear_lru_flags(folio);
			list_add(&folio->lru, &folios_to_free);
			continue;
		}

		folio_put(folio);

		/*
		 * All pages were isolated from the same lruvec (and isolation
		 * inhibits memcg migration).
		 */
		VM_BUG_ON_FOLIO(!folio_matches_lruvec(folio, lruvec), folio);
		lruvec_add_folio(lruvec, folio);
		nr_pages = folio_nr_pages(folio);
		nr_moved += nr_pages;
	}

	/*
	 * To save our caller's stack, now use input list for pages to free.
	 */
	list_splice(&folios_to_free, list);

	return nr_moved;
}

static void mem_cgroup_aging_anon_lruvec(struct mem_cgroup *memcg,
		struct lruvec *lruvec, unsigned long lru_mask, bool is_chp)
{
	pg_data_t *pgdat = NODE_DATA(0);
	unsigned long nr_to_scan = 0;

	LIST_HEAD(l_hold);
	LIST_HEAD(l_active);
	LIST_HEAD(l_inactive);

	if (BIT(LRU_INACTIVE_ANON) & lru_mask) {
		unsigned long nr_to_isolate = memcg_lru_pages(memcg, LRU_INACTIVE_ANON, is_chp);
		nr_to_scan +=
			isolate_folios_to_folio_list(lruvec, LRU_INACTIVE_ANON, &l_hold, nr_to_isolate);
		log_info("nr_to_isolate from %s inactive anon: %lu",
			 is_chp ? "chp" : "normal", nr_to_isolate);
	}

	if (BIT(LRU_ACTIVE_ANON) & lru_mask) {
		unsigned long nr_to_isolate = memcg_lru_pages(memcg, LRU_ACTIVE_ANON, is_chp);
		nr_to_scan +=
			isolate_folios_to_folio_list(lruvec, LRU_ACTIVE_ANON, &l_hold, nr_to_isolate);
		log_info("nr_to_isolate from %s active anon: %lu",
			 is_chp ? "chp" : "normal", nr_to_isolate);
	}

	mod_node_page_state(pgdat, NR_ISOLATED_ANON, nr_to_scan);

	log_info("nr_isolated: %lu %s pages", nr_to_scan, is_chp ? "chp" : "normal");

	/* Seperate the isolated list to active list and inactive list */
	seperate_list(&l_hold, &l_active, &l_inactive, memcg);

	/* Move folios to the active list */
	spin_lock_irq(&lruvec->lru_lock);
	move_folios_into_lru(lruvec, &l_active);
	spin_unlock_irq(&lruvec->lru_lock);
	put_pages_list(&l_active);

	/* Move folios to the inactive list */
	spin_lock_irq(&lruvec->lru_lock);
	move_folios_into_lru(lruvec, &l_inactive);
	spin_unlock_irq(&lruvec->lru_lock);
	put_pages_list(&l_inactive);

	mod_node_page_state(pgdat, NR_ISOLATED_ANON, -nr_to_scan);
}

static ssize_t mem_cgroup_aging_anon(struct kernfs_open_file *of,
		char *buf, size_t nbytes, loff_t off)
{
	unsigned long lru_mask = 0;
	struct lruvec *lruvec;
	pg_data_t *pgdat = NODE_DATA(0);
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));

	if (kstrtoul(strstrip(buf), 0, &lru_mask))
		return -EINVAL;

	lruvec = mem_cgroup_lruvec(memcg, pgdat);
	mem_cgroup_aging_anon_lruvec(memcg, lruvec, lru_mask, false);

#ifdef CONFIG_CONT_PTE_HUGEPAGE_64K_ZRAM
	if (chp_supported && chp_pool) {
		struct chp_lruvec *chp_lruvec =
			(struct chp_lruvec *)memcg->deferred_split_queue.split_queue_len;
		mem_cgroup_aging_anon_lruvec(memcg, &chp_lruvec->lruvec, lru_mask, true);
	}
#endif
	return nbytes;
}

static int memcg_total_info_per_app_show(struct seq_file *m, void *v)
{
	struct mem_cgroup *memcg = NULL;
	unsigned long anon_size;
	unsigned long zram_compress_size;
	unsigned long eswap_compress_size;
	unsigned long zram_page_size;
	unsigned long eswap_page_size;

	seq_printf(m, "%-8s %-8s %-8s %-8s %-8s %s \n",
			"anon", "zram_c", "zram_p", "eswap_c", "eswap_p",
			"memcg_n");
	while ((memcg = get_next_memcg(memcg))) {
		if (!MEMCGRP_ITEM_DATA(memcg))
			continue;

		anon_size = memcg_anon_pages(memcg);
		zram_compress_size = hybridswap_read_memcg_stats(memcg,
				MCG_ZRAM_STORED_SZ);
		eswap_compress_size = hybridswap_read_memcg_stats(memcg,
				MCG_DISK_STORED_SZ);
		zram_page_size = hybridswap_read_memcg_stats(memcg,
				MCG_ZRAM_STORED_PG_SZ);
		eswap_page_size = hybridswap_read_memcg_stats(memcg,
				MCG_DISK_STORED_PG_SZ);

		anon_size *= PAGE_SIZE / SZ_1K;
		zram_compress_size /= SZ_1K;
		eswap_compress_size /= SZ_1K;
		zram_page_size *= PAGE_SIZE / SZ_1K;
		eswap_page_size *= PAGE_SIZE / SZ_1K;

		seq_printf(m, "%-8lu %-8lu %-8lu %-8lu %-8lu %s \n",
				anon_size, zram_compress_size, zram_page_size,
				eswap_compress_size, eswap_page_size,
				MEMCGRP_ITEM(memcg, name));
	}

	return 0;
}

static int memcg_swap_stat_show(struct seq_file *m, void *v)
{
	struct mem_cgroup *memcg = NULL;
	unsigned long eswap_out_cnt;
	unsigned long eswap_out_size;
	unsigned long eswap_in_size;
	unsigned long eswap_in_cnt;
	unsigned long page_fault_cnt;
	unsigned long cur_eswap_size;
	unsigned long max_eswap_size;
	unsigned long zram_compress_size, zram_page_size;
	unsigned long eswap_compress_size, eswap_page_size;

	memcg = mem_cgroup_from_css(seq_css(m));

	zram_compress_size = hybridswap_read_memcg_stats(memcg, MCG_ZRAM_STORED_SZ);
	zram_page_size = hybridswap_read_memcg_stats(memcg, MCG_ZRAM_STORED_PG_SZ);
	eswap_compress_size = hybridswap_read_memcg_stats(memcg, MCG_DISK_STORED_SZ);
	eswap_page_size = hybridswap_read_memcg_stats(memcg, MCG_DISK_STORED_PG_SZ);

	eswap_out_cnt = hybridswap_read_memcg_stats(memcg, MCG_ESWAPOUT_CNT);
	eswap_out_size = hybridswap_read_memcg_stats(memcg, MCG_ESWAPOUT_SZ);
	eswap_in_size = hybridswap_read_memcg_stats(memcg, MCG_ESWAPIN_SZ);
	eswap_in_cnt = hybridswap_read_memcg_stats(memcg, MCG_ESWAPIN_CNT);
	page_fault_cnt = hybridswap_read_memcg_stats(memcg, MCG_DISK_FAULT_CNT);
	cur_eswap_size = hybridswap_read_memcg_stats(memcg, MCG_DISK_SPACE);
	max_eswap_size = hybridswap_read_memcg_stats(memcg, MCG_DISK_SPACE_PEAK);

	seq_printf(m, "%-32s %12lu KB\n", "zramCompressedSize:",
			zram_compress_size / SZ_1K);
	seq_printf(m, "%-32s %12lu KB\n", "zramOrignalSize:",
			zram_page_size << (PAGE_SHIFT - 10));
	seq_printf(m, "%-32s %12lu KB\n", "eswapCompressedSize:",
			eswap_compress_size / SZ_1K);
	seq_printf(m, "%-32s %12lu KB\n", "eswapOrignalSize:",
			eswap_page_size << (PAGE_SHIFT - 10));
	seq_printf(m, "%-32s %12lu \n", "eswapOutTotal:", eswap_out_cnt);
	seq_printf(m, "%-32s %12lu KB\n", "eswapOutSize:", eswap_out_size / SZ_1K);
	seq_printf(m, "%-32s %12lu\n", "eswapInTotal:", eswap_in_cnt);
	seq_printf(m, "%-32s %12lu KB\n", "eswapInSize:", eswap_in_size / SZ_1K);
	seq_printf(m, "%-32s %12lu\n", "pageInTotal:", page_fault_cnt);
	seq_printf(m, "%-32s %12lu KB\n", "eswapSizeCur:", cur_eswap_size / SZ_1K);
	seq_printf(m, "%-32s %12lu KB\n", "eswapSizeMax:", max_eswap_size / SZ_1K);

	return 0;
}

static ssize_t mem_cgroup_name_write(struct kernfs_open_file *of, char *buf,
		size_t nbytes, loff_t off)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));
	memcg_hybs_t *hybp = MEMCGRP_ITEM_DATA(memcg);
	int len, w_len;

	if (!hybp)
		return -EINVAL;

	buf = strstrip(buf);
	len = strlen(buf) + 1;
	if (len > MEM_CGROUP_NAME_MAX_LEN)
		len = MEM_CGROUP_NAME_MAX_LEN;

	w_len = snprintf(hybp->name, len, "%s", buf);
	if (w_len > len)
		hybp->name[len - 1] = '\0';

	return nbytes;
}

static int mem_cgroup_name_show(struct seq_file *m, void *v)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(seq_css(m));

	if (!MEMCGRP_ITEM_DATA(memcg))
		return -EPERM;

	seq_printf(m, "%s\n", MEMCGRP_ITEM(memcg, name));

	return 0;
}

static int mem_cgroup_app_score_write(struct cgroup_subsys_state *css,
		struct cftype *cft, s64 val)
{
	struct mem_cgroup *memcg;
	memcg_hybs_t *hybs;

	if (val > MAX_APP_SCORE || val < 0)
		return -EINVAL;

	memcg = mem_cgroup_from_css(css);
	hybs = MEMCGRP_ITEM_DATA(memcg);
	if (!hybs) {
		hybs = hybridswap_cache_alloc(memcg, false);
		if (!hybs)
			return -EINVAL;
	}

	if (atomic64_read(&MEMCGRP_ITEM(memcg, app_score)) != val)
		atomic64_set(&MEMCGRP_ITEM(memcg, app_score), val);
	memcg_app_score_update(memcg);

	return 0;
}

static s64 mem_cgroup_app_score_read(struct cgroup_subsys_state *css,
		struct cftype *cft)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);

	if (!MEMCGRP_ITEM_DATA(memcg))
		return -EPERM;

	return atomic64_read(&MEMCGRP_ITEM(memcg, app_score));
}

int mem_cgroup_app_uid_write(struct cgroup_subsys_state *css,
		struct cftype *cft, s64 val)
{
	struct mem_cgroup *memcg;
	memcg_hybs_t *hybs;

	if (val < 0)
		return -EINVAL;

	memcg = mem_cgroup_from_css(css);
	hybs = MEMCGRP_ITEM_DATA(memcg);
	if (!hybs) {
		return -EINVAL;
	}

	if (atomic64_read(&MEMCGRP_ITEM(memcg, app_uid)) != val)
		atomic64_set(&MEMCGRP_ITEM(memcg, app_uid), val);

	return 0;
}

static s64 mem_cgroup_app_uid_read(struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);

	if (!MEMCGRP_ITEM_DATA(memcg))
		return -EPERM;

	return atomic64_read(&MEMCGRP_ITEM(memcg, app_uid));
}

static int mem_cgroup_ub_ufs2zram_ratio_write(struct cgroup_subsys_state *css,
		struct cftype *cft, s64 val)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);

	if (!MEMCGRP_ITEM_DATA(memcg))
		return -EPERM;

	if (val > MAX_RATIO || val < MIN_RATIO)
		return -EINVAL;

	atomic64_set(&MEMCGRP_ITEM(memcg, ub_ufs2zram_ratio), val);

	return 0;
}

static s64 mem_cgroup_ub_ufs2zram_ratio_read(struct cgroup_subsys_state *css,
		struct cftype *cft)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);

	if (!MEMCGRP_ITEM_DATA(memcg))
		return -EPERM;

	return atomic64_read(&MEMCGRP_ITEM(memcg, ub_ufs2zram_ratio));
}

static int mem_cgroup_force_swapin_write(struct cgroup_subsys_state *css,
		struct cftype *cft, s64 val)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);
	memcg_hybs_t *hybs;
	unsigned long size = 0;
	const unsigned int ratio = 100;

	hybs = MEMCGRP_ITEM_DATA(memcg);
	if (!hybs)
		return -EPERM;

#ifdef	CONFIG_HYBRIDSWAP_CORE
	size = atomic64_read(&hybs->hybridswap_stored_size);
#endif
	size = atomic64_read(&hybs->ub_ufs2zram_ratio) * size / ratio;
	size = EXTENT_ALIGN_UP(size);

#ifdef CONFIG_HYBRIDSWAP_CORE
	hybridswap_batch_out(memcg, size, val ? true : false);
#endif

	return 0;
}

static int mem_cgroup_force_swapout_write(struct cgroup_subsys_state *css,
		struct cftype *cft, s64 val)
{
#ifdef CONFIG_HYBRIDSWAP_CORE
	hybridswap_force_reclaim(mem_cgroup_from_css(css));
#endif
	return 0;
}

struct mem_cgroup *get_next_memcg(struct mem_cgroup *prev)
{
	memcg_hybs_t *hybs = NULL;
	struct mem_cgroup *memcg = NULL;
	struct list_head *pos = NULL;
	unsigned long flags;
	bool prev_got = true;

	spin_lock_irqsave(&score_list_lock, flags);
find_again:
	if (unlikely(!prev))
		pos = &score_head;
	else
		pos = &MEMCGRP_ITEM(prev, score_node);

	if (list_empty(pos)) /* deleted node */
		goto unlock;

	if (pos->next == &score_head)
		goto unlock;

	hybs = list_entry(pos->next, struct mem_cgroup_hybridswap, score_node);
	memcg = hybs->memcg;
	if (unlikely(!memcg))
		goto unlock;

	if (!css_tryget(&memcg->css)) {
		if (prev && prev_got)
			css_put(&prev->css);
		prev = memcg;
		prev_got = false;
		goto find_again;
	}

unlock:
	spin_unlock_irqrestore(&score_list_lock, flags);
	if (prev && prev_got)
		css_put(&prev->css);

	return memcg;
}

void get_next_memcg_break(struct mem_cgroup *memcg)
{
	if (memcg)
		css_put(&memcg->css);
}

static struct cftype mem_cgroup_hybridswap_legacy_files[] = {
	{
		.name = "force_shrink_anon",
		.write = mem_cgroup_force_shrink_anon,
	},
	{
		.name = "force_shrink_file",
		.write = mem_cgroup_force_shrink_file,
	},
	{
		.name = "total_info_per_app",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.seq_show = memcg_total_info_per_app_show,
	},
	{
		.name = "aging_anon",
		.write = mem_cgroup_aging_anon,
	},
	{
		.name = "swap_stat",
		.seq_show = memcg_swap_stat_show,
	},
	{
		.name = "name",
		.write = mem_cgroup_name_write,
		.seq_show = mem_cgroup_name_show,
	},
	{
		.name = "app_score",
		.write_s64 = mem_cgroup_app_score_write,
		.read_s64 = mem_cgroup_app_score_read,
	},
	{
		.name = "app_uid",
		.write_s64 = mem_cgroup_app_uid_write,
		.read_s64 = mem_cgroup_app_uid_read,
	},
	{
		.name = "ub_ufs2zram_ratio",
		.write_s64 = mem_cgroup_ub_ufs2zram_ratio_write,
		.read_s64 = mem_cgroup_ub_ufs2zram_ratio_read,
	},
	{
		.name = "force_swapin",
		.write_s64 = mem_cgroup_force_swapin_write,
	},
	{
		.name = "force_swapout",
		.write_s64 = mem_cgroup_force_swapout_write,
	},
#ifdef CONFIG_HYBRIDSWAP_CORE
	{
		.name = "psi",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.seq_show = hybridswap_psi_show,
	},
	{
		.name = "stored_wm_ratio",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.write_s64 = mem_cgroup_stored_wm_ratio_write,
		.read_s64 = mem_cgroup_stored_wm_ratio_read,
	},
#endif
	{ }, /* terminate */
};

static int hybridswap_enable(struct zram **zram_arr)
{
	int ret = 0;

	if (hybridswap_enabled) {
		log_warn("enabled is true\n");
		return ret;
	}

#ifdef CONFIG_HYBRIDSWAP_SWAPD
	ret = hybridswapd_ops->init(zram_arr);
	if (ret)
		return ret;
#endif

#ifdef CONFIG_HYBRIDSWAP_CORE
	if (!chp_supported) {
		ret = hybridswap_core_enable();
		if (ret)
			goto hybridswap_core_enable_fail;
	}
#endif
	hybridswap_enabled = true;

	return 0;

#ifdef CONFIG_HYBRIDSWAP_CORE
hybridswap_core_enable_fail:
#endif
#ifdef CONFIG_HYBRIDSWAP_SWAPD
	hybridswapd_ops->deinit();
#endif
	return ret;
}

static void hybridswap_disable(struct zram **zram)
{
	if (!hybridswap_enabled) {
		log_warn("enabled is false\n");
		return;
	}

#ifdef CONFIG_HYBRIDSWAP_CORE
	hybridswap_core_disable();
#endif

#ifdef CONFIG_HYBRIDSWAP_SWAPD
	hybridswapd_ops->deinit();
#endif
	hybridswap_enabled = false;
}

ssize_t hybridswap_enable_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int len = snprintf(buf, PAGE_SIZE, "hybridswap %s reclaim_in %s swapd %s\n",
			hybridswap_core_enabled() ? "enable" : "disable",
			hybridswap_reclaim_in_enable() ? "enable" : "disable",
			hybridswapd_ops->enabled() ? "enable" : "disable");

	return len;
}

ssize_t hybridswap_swapd_pause_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t len)
{
	char *type_buf = NULL;
	bool val;

	type_buf = strstrip((char *)buf);
	if (kstrtobool(type_buf, &val))
		return -EINVAL;
	atomic_set(hybridswapd_ops->swapd_pause, val);
	return len;
}

ssize_t hybridswap_swapd_pause_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	ssize_t size = 0;

	size += scnprintf(buf + size, PAGE_SIZE - size,
			  "%d\n", atomic_read(hybridswapd_ops->swapd_pause));
	return size;
}

ssize_t hybridswap_enable_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	int ret;
	unsigned long val;
	char *kbuf;
	struct zram *zram;

	kbuf = strstrip((char *)buf);
	ret = kstrtoul(kbuf, 0, &val);
	if (unlikely(ret)) {
		log_err("val %s is invalid!\n", kbuf);

		return -EINVAL;
	}

	mutex_lock(&hybridswap_enable_lock);
	zram = dev_to_zram(dev);
	if (val == 0)
		hybridswap_disable(zram_arr);
	else
		ret = hybridswap_enable(zram_arr);
	mutex_unlock(&hybridswap_enable_lock);

	if (ret == 0)
		ret = len;
	return ret;
}

int __init hybridswap_pre_init(void)
{
	int ret;

	INIT_LIST_HEAD(&score_head);
	log_level = HS_LOG_INFO;

	hybridswap_cache = kmem_cache_create("mem_cgroup_hybridswap",
			sizeof(struct mem_cgroup_hybridswap),
			0, SLAB_PANIC, NULL);
	if (!hybridswap_cache) {
		log_err("create hybridswap_cache failed\n");
		ret = -ENOMEM;
		return ret;
	}

	ret = cgroup_add_legacy_cftypes(&memory_cgrp_subsys,
			mem_cgroup_hybridswap_legacy_files);
	if (ret) {
		log_info("add mem_cgroup_hybridswap_legacy_files failed\n");
		goto error_out;
	}

#ifdef CONFIG_HYBRIDSWAP_SWAPD
	hybridswapd_ops = kzalloc(sizeof(struct hybridswapd_operations),
				  GFP_KERNEL);
	if (!hybridswapd_ops)
		goto error_out;

#ifdef CONFIG_CONT_PTE_HUGEPAGE_64K_ZRAM
	if (chp_supported && chp_pool) {
		log_info("init for hybridswapd_chp_ops");
		hybridswapd_chp_ops_init(hybridswapd_ops);
	} else {
		log_info("init for hybridswapd_ops");
		hybridswapd_ops_init(hybridswapd_ops);
	}
#else
	hybridswapd_ops_init(hybridswapd_ops);
#endif
	hybridswapd_ops->pre_init();

	ret = cgroup_add_legacy_cftypes(&memory_cgrp_subsys,
			hybridswapd_ops->memcg_legacy_files);
	if (ret) {
		log_info("add mem_cgroup_swapd_legacy_files failed!\n");
		goto fail_out;
	}
#endif
	ret = register_all_hooks();
	if (ret)
		goto fail_out;

	log_info("hybridswap inited success!\n");
	return 0;

fail_out:
#ifdef CONFIG_HYBRIDSWAP_SWAPD
	hybridswapd_ops->pre_deinit();
	kfree(hybridswapd_ops);
#endif
error_out:
	if (hybridswap_cache) {
		kmem_cache_destroy(hybridswap_cache);
		hybridswap_cache = NULL;
	}
	return ret;
}

void __exit hybridswap_exit(void)
{
	unregister_all_hook();

#ifdef CONFIG_HYBRIDSWAP_SWAPD
	hybridswapd_ops->pre_deinit();
#endif

	if (hybridswap_cache) {
		kmem_cache_destroy(hybridswap_cache);
		hybridswap_cache = NULL;
	}
}
