/*
 * Copyright (c) 2014-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2023 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * DOC: qdf_mc_timer
 * QCA driver framework timer APIs serialized to MC thread
 */

/* Include Files */
#include <qdf_debug_domain.h>
#include <qdf_mc_timer.h>
#include <qdf_lock.h>
#include "qdf_lock.h"
#include "qdf_list.h"
#include "qdf_mem.h"
#include <qdf_module.h>
#include "qdf_timer.h"
#include <linux/time64.h>

/* Preprocessor definitions and constants */
#define LINUX_TIMER_COOKIE 0x12341234
#define LINUX_INVALID_TIMER_COOKIE 0xfeedface
#define TMR_INVALID_ID (0)

#ifdef QDF_TIMER_MULTIPLIER_FRAC
static uint32_t g_qdf_timer_multiplier = QDF_TIMER_MULTIPLIER_FRAC;
#else
static uint32_t g_qdf_timer_multiplier = 1;
#endif

inline void qdf_timer_set_multiplier(uint32_t multiplier)
{
	g_qdf_timer_multiplier = multiplier;
}
qdf_export_symbol(qdf_timer_set_multiplier);

inline uint32_t qdf_timer_get_multiplier(void)
{
	return g_qdf_timer_multiplier;
}
qdf_export_symbol(qdf_timer_get_multiplier);

/* Type declarations */

/* Static Variable Definitions */
static unsigned int persistent_timer_count;
static qdf_mutex_t persistent_timer_count_lock;

static void (*scheduler_timer_callback)(qdf_mc_timer_t *);
void qdf_register_mc_timer_callback(void (*callback) (qdf_mc_timer_t *))
{
	scheduler_timer_callback = callback;
}

qdf_export_symbol(qdf_register_mc_timer_callback);

/* Function declarations and documentation */

void qdf_try_allowing_sleep(QDF_TIMER_TYPE type)
{
	if (QDF_TIMER_TYPE_WAKE_APPS == type) {

		persistent_timer_count--;
		if (0 == persistent_timer_count) {
			/* since the number of persistent timers has
			 * decreased from 1 to 0, the timer should allow
			 * sleep
			 */
		}
	}
}
qdf_export_symbol(qdf_try_allowing_sleep);

QDF_TIMER_STATE qdf_mc_timer_get_current_state(qdf_mc_timer_t *timer)
{
	QDF_TIMER_STATE timer_state = QDF_TIMER_STATE_UNUSED;

	if (!timer) {
		QDF_ASSERT(0);
		return timer_state;
	}

	qdf_spin_lock_irqsave(&timer->platform_info.spinlock);

	switch (timer->state) {
	case QDF_TIMER_STATE_STOPPED:
	case QDF_TIMER_STATE_STARTING:
	case QDF_TIMER_STATE_RUNNING:
	case QDF_TIMER_STATE_UNUSED:
		timer_state = timer->state;
		break;
	default:
		QDF_ASSERT(0);
	}
	qdf_spin_unlock_irqrestore(&timer->platform_info.spinlock);
	return timer_state;
}
qdf_export_symbol(qdf_mc_timer_get_current_state);

void qdf_timer_module_init(void)
{
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "Initializing the QDF MC timer module");
	qdf_mutex_create(&persistent_timer_count_lock);
}
qdf_export_symbol(qdf_timer_module_init);

#ifdef TIMER_MANAGER

static qdf_list_t qdf_timer_domains[QDF_DEBUG_DOMAIN_COUNT];
static qdf_spinlock_t qdf_timer_list_lock;

static inline qdf_list_t *qdf_timer_list_get(enum qdf_debug_domain domain)
{
	return &qdf_timer_domains[domain];
}

void qdf_mc_timer_manager_init(void)
{
	int i;

	for (i = 0; i < QDF_DEBUG_DOMAIN_COUNT; ++i)
		qdf_list_create(&qdf_timer_domains[i], 1000);
	qdf_spinlock_create(&qdf_timer_list_lock);
}
qdf_export_symbol(qdf_mc_timer_manager_init);

static void qdf_mc_timer_print_list(qdf_list_t *timers)
{
	QDF_STATUS status;
	qdf_list_node_t *node;

	qdf_spin_lock_irqsave(&qdf_timer_list_lock);
	status = qdf_list_peek_front(timers, &node);
	while (QDF_IS_STATUS_SUCCESS(status)) {
		qdf_mc_timer_node_t *timer_node = (qdf_mc_timer_node_t *)node;
		const char *filename = kbasename(timer_node->file_name);
		uint32_t line = timer_node->line_num;

		qdf_spin_unlock_irqrestore(&qdf_timer_list_lock);
		qdf_err("timer Leak@ File %s, @Line %u", filename, line);
		qdf_spin_lock_irqsave(&qdf_timer_list_lock);

		status = qdf_list_peek_next(timers, node, &node);
	}
	qdf_spin_unlock_irqrestore(&qdf_timer_list_lock);
}

void qdf_mc_timer_check_for_leaks(void)
{
	enum qdf_debug_domain current_domain = qdf_debug_domain_get();
	qdf_list_t *timers = qdf_timer_list_get(current_domain);

	if (qdf_list_empty(timers))
		return;

	qdf_err("Timer leaks detected in %s domain!",
		qdf_debug_domain_name(current_domain));
	qdf_mc_timer_print_list(timers);
	QDF_DEBUG_PANIC("Previously reported timer leaks detected");
}

static void qdf_mc_timer_free_leaked_timers(qdf_list_t *timers)
{
	QDF_STATUS status;
	qdf_list_node_t *node;

	qdf_spin_lock_irqsave(&qdf_timer_list_lock);
	status = qdf_list_remove_front(timers, &node);
	while (QDF_IS_STATUS_SUCCESS(status)) {
		qdf_mem_free(node);
		status = qdf_list_remove_front(timers, &node);
	}
	qdf_spin_unlock_irqrestore(&qdf_timer_list_lock);
}

/**
 * qdf_timer_clean() - clean up QDF timer debug functionality
 *
 * This API cleans up QDF timer debug functionality and prints which QDF timers
 * are leaked. This is called during driver unload.
 *
 * Return: none
 */
static void qdf_timer_clean(void)
{
	bool leaks_detected = false;
	int i;

	/* detect and print leaks */
	for (i = 0; i < QDF_DEBUG_DOMAIN_COUNT; ++i) {
		qdf_list_t *timers = &qdf_timer_domains[i];

		if (qdf_list_empty(timers))
			continue;

		leaks_detected = true;

		qdf_err("\nTimer leaks detected in the %s (Id %d) domain!",
			qdf_debug_domain_name(i), i);
		qdf_mc_timer_print_list(timers);
	}

	/* we're done if there were no leaks */
	if (!leaks_detected)
		return;

	/* panic, if enabled */
	QDF_DEBUG_PANIC("Previously reported timer leaks detected");

	/* if we didn't crash, release the leaked timers */
	for (i = 0; i < QDF_DEBUG_DOMAIN_COUNT; ++i)
		qdf_mc_timer_free_leaked_timers(&qdf_timer_domains[i]);
}

void qdf_mc_timer_manager_exit(void)
{
	int i;

	qdf_timer_clean();

	for (i = 0; i < QDF_DEBUG_DOMAIN_COUNT; ++i)
		qdf_list_destroy(&qdf_timer_domains[i]);

	qdf_spinlock_destroy(&qdf_timer_list_lock);
}
qdf_export_symbol(qdf_mc_timer_manager_exit);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
static void __os_mc_timer_shim(struct timer_list *os_timer)
{
	qdf_mc_timer_platform_t *platform_info_ptr =
				qdf_container_of(os_timer,
						 qdf_mc_timer_platform_t,
						 timer);
	qdf_mc_timer_t *timer = qdf_container_of(platform_info_ptr,
						 qdf_mc_timer_t,
						 platform_info);

	scheduler_timer_callback(timer);
}

static void qdf_mc_timer_setup(qdf_mc_timer_t *timer,
			       QDF_TIMER_TYPE timer_type)
{
	uint32_t flags = 0;

	if (QDF_TIMER_TYPE_SW == timer_type)
		flags |= TIMER_DEFERRABLE;

	timer_setup(&timer->platform_info.timer,
		    __os_mc_timer_shim, flags);
}
#else
static void __os_mc_timer_shim(unsigned long data)
{
	qdf_mc_timer_t *timer = (qdf_mc_timer_t *)data;

	scheduler_timer_callback(timer);
}

static void qdf_mc_timer_setup(qdf_mc_timer_t *timer,
			       QDF_TIMER_TYPE timer_type)
{
	if (QDF_TIMER_TYPE_SW == timer_type)
		init_timer_deferrable(&timer->platform_info.timer);
	else
		init_timer(&timer->platform_info.timer);

	timer->platform_info.timer.function = __os_mc_timer_shim;
	timer->platform_info.timer.data = (unsigned long)timer;
}
#endif
#ifdef TIMER_MANAGER
QDF_STATUS qdf_mc_timer_init_debug(qdf_mc_timer_t *timer,
				   QDF_TIMER_TYPE timer_type,
				   qdf_mc_timer_callback_t callback,
				   void *user_data, char *file_name,
				   uint32_t line_num)
{
	enum qdf_debug_domain current_domain = qdf_debug_domain_get();
	qdf_list_t *active_timers = qdf_timer_list_get(current_domain);
	QDF_STATUS qdf_status;

	/* check for invalid pointer */
	if ((!timer) || (!callback)) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Null params being passed", __func__);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAULT;
	}

	timer->timer_node = qdf_mem_malloc(sizeof(qdf_mc_timer_node_t));

	if (!timer->timer_node) {
		QDF_ASSERT(0);
		return QDF_STATUS_E_NOMEM;
	}

	timer->timer_node->file_name = file_name;
	timer->timer_node->line_num = line_num;
	timer->timer_node->qdf_timer = timer;

	qdf_spin_lock_irqsave(&qdf_timer_list_lock);
	qdf_status = qdf_list_insert_front(active_timers,
					   &timer->timer_node->node);
	qdf_spin_unlock_irqrestore(&qdf_timer_list_lock);
	if (QDF_STATUS_SUCCESS != qdf_status) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Unable to insert node into List qdf_status %d",
			  __func__, qdf_status);
	}

	/* set the various members of the timer structure
	 * with arguments passed or with default values
	 */
	qdf_spinlock_create(&timer->platform_info.spinlock);
	qdf_mc_timer_setup(timer, timer_type);
	timer->callback = callback;
	timer->user_data = user_data;
	timer->type = timer_type;
	timer->platform_info.cookie = LINUX_TIMER_COOKIE;
	timer->platform_info.thread_id = 0;
	timer->state = QDF_TIMER_STATE_STOPPED;

	return QDF_STATUS_SUCCESS;
}
qdf_export_symbol(qdf_mc_timer_init_debug);
#else
QDF_STATUS qdf_mc_timer_init(qdf_mc_timer_t *timer, QDF_TIMER_TYPE timer_type,
			     qdf_mc_timer_callback_t callback,
			     void *user_data)
{
	/* check for invalid pointer */
	if ((!timer) || (!callback)) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Null params being passed", __func__);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAULT;
	}

	/* set the various members of the timer structure
	 * with arguments passed or with default values
	 */
	qdf_spinlock_create(&timer->platform_info.spinlock);
	qdf_mc_timer_setup(timer, timer_type);
	timer->callback = callback;
	timer->user_data = user_data;
	timer->type = timer_type;
	timer->platform_info.cookie = LINUX_TIMER_COOKIE;
	timer->platform_info.thread_id = 0;
	timer->state = QDF_TIMER_STATE_STOPPED;

	return QDF_STATUS_SUCCESS;
}
qdf_export_symbol(qdf_mc_timer_init);
#endif

#ifdef TIMER_MANAGER
QDF_STATUS qdf_mc_timer_destroy(qdf_mc_timer_t *timer)
{
	enum qdf_debug_domain current_domain = qdf_debug_domain_get();
	qdf_list_t *active_timers = qdf_timer_list_get(current_domain);
	QDF_STATUS v_status = QDF_STATUS_SUCCESS;

	/* check for invalid pointer */
	if (!timer) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Null timer pointer being passed", __func__);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAULT;
	}

	/* Check if timer refers to an uninitialized object */
	if (LINUX_TIMER_COOKIE != timer->platform_info.cookie) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Cannot destroy uninitialized timer", __func__);
		QDF_ASSERT(0);
		return QDF_STATUS_E_INVAL;
	}

	qdf_spin_lock_irqsave(&qdf_timer_list_lock);
	v_status = qdf_list_remove_node(active_timers,
					&timer->timer_node->node);
	qdf_spin_unlock_irqrestore(&qdf_timer_list_lock);
	if (v_status != QDF_STATUS_SUCCESS) {
		QDF_ASSERT(0);
		return QDF_STATUS_E_INVAL;
	}
	qdf_mem_free(timer->timer_node);

	qdf_spin_lock_irqsave(&timer->platform_info.spinlock);

	switch (timer->state) {

	case QDF_TIMER_STATE_STARTING:
		v_status = QDF_STATUS_E_BUSY;
		break;

	case QDF_TIMER_STATE_RUNNING:
		/* Stop the timer first */
		del_timer(&(timer->platform_info.timer));
		v_status = QDF_STATUS_SUCCESS;
		break;
	case QDF_TIMER_STATE_STOPPED:
		v_status = QDF_STATUS_SUCCESS;
		break;

	case QDF_TIMER_STATE_UNUSED:
		v_status = QDF_STATUS_E_ALREADY;
		break;

	default:
		v_status = QDF_STATUS_E_FAULT;
		break;
	}

	if (QDF_STATUS_SUCCESS == v_status) {
		timer->platform_info.cookie = LINUX_INVALID_TIMER_COOKIE;
		timer->state = QDF_TIMER_STATE_UNUSED;
		qdf_spin_unlock_irqrestore(&timer->platform_info.spinlock);
		qdf_spinlock_destroy(&timer->platform_info.spinlock);
		return v_status;
	}

	qdf_spin_unlock_irqrestore(&timer->platform_info.spinlock);

	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: Cannot destroy timer in state = %d", __func__,
		  timer->state);
	QDF_ASSERT(0);

	return v_status;
}
qdf_export_symbol(qdf_mc_timer_destroy);

#else

QDF_STATUS qdf_mc_timer_destroy(qdf_mc_timer_t *timer)
{
	QDF_STATUS v_status = QDF_STATUS_SUCCESS;

	/* check for invalid pointer */
	if (!timer) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Null timer pointer being passed", __func__);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAULT;
	}

	/* check if timer refers to an uninitialized object */
	if (LINUX_TIMER_COOKIE != timer->platform_info.cookie) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Cannot destroy uninitialized timer", __func__);
		QDF_ASSERT(0);
		return QDF_STATUS_E_INVAL;
	}
	qdf_spin_lock_irqsave(&timer->platform_info.spinlock);

	switch (timer->state) {

	case QDF_TIMER_STATE_STARTING:
		v_status = QDF_STATUS_E_BUSY;
		break;

	case QDF_TIMER_STATE_RUNNING:
		/* Stop the timer first */
		del_timer(&(timer->platform_info.timer));
		v_status = QDF_STATUS_SUCCESS;
		break;

	case QDF_TIMER_STATE_STOPPED:
		v_status = QDF_STATUS_SUCCESS;
		break;

	case QDF_TIMER_STATE_UNUSED:
		v_status = QDF_STATUS_E_ALREADY;
		break;

	default:
		v_status = QDF_STATUS_E_FAULT;
		break;
	}

	if (QDF_STATUS_SUCCESS == v_status) {
		timer->platform_info.cookie = LINUX_INVALID_TIMER_COOKIE;
		timer->state = QDF_TIMER_STATE_UNUSED;
		qdf_spin_unlock_irqrestore(&timer->platform_info.spinlock);
		return v_status;
	}

	qdf_spin_unlock_irqrestore(&timer->platform_info.spinlock);

	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: Cannot destroy timer in state = %d", __func__,
		  timer->state);
	QDF_ASSERT(0);

	return v_status;
}
qdf_export_symbol(qdf_mc_timer_destroy);
#endif

QDF_STATUS qdf_mc_timer_start(qdf_mc_timer_t *timer, uint32_t expiration_time)
{
	/* check for invalid pointer */
	if (!timer) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s Null timer pointer being passed", __func__);
		QDF_ASSERT(0);
		return QDF_STATUS_E_INVAL;
	}

	/* check if timer refers to an uninitialized object */
	if (LINUX_TIMER_COOKIE != timer->platform_info.cookie) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Cannot start uninitialized timer", __func__);
		QDF_ASSERT(0);

		return QDF_STATUS_E_INVAL;
	}

	/* check if timer has expiration time less than 10 ms */
	if (expiration_time < 10) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Cannot start a timer with expiration less than 10 ms",
			  __func__);
		return QDF_STATUS_E_INVAL;
	}

	/* make sure the remainder of the logic isn't interrupted */
	qdf_spin_lock_irqsave(&timer->platform_info.spinlock);

	/* ensure if the timer can be started */
	if (QDF_TIMER_STATE_STOPPED != timer->state) {
		qdf_spin_unlock_irqrestore(&timer->platform_info.spinlock);
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Cannot start timer in state = %d %ps",
			  __func__, timer->state, (void *)timer->callback);
		return QDF_STATUS_E_ALREADY;
	}

	/* start the timer */
	mod_timer(&(timer->platform_info.timer),
		  jiffies + __qdf_scaled_msecs_to_jiffies(expiration_time));

	timer->state = QDF_TIMER_STATE_RUNNING;

	/* Save the jiffies value in a per-timer context in qdf_mc_timer_t
	 * It will help the debugger to know the exact time at which the host
	 * starts the QDF timer.
	 */
	timer->timer_start_jiffies = jiffies;

	/* get the thread ID on which the timer is being started */
	timer->platform_info.thread_id = current->pid;

	if (QDF_TIMER_TYPE_WAKE_APPS == timer->type) {
		persistent_timer_count++;
		if (1 == persistent_timer_count) {
			/* since we now have one persistent timer,
			 * we need to disallow sleep
			 * sleep_negate_okts(sleep_client_handle);
			 */
		}
	}

	qdf_spin_unlock_irqrestore(&timer->platform_info.spinlock);

	return QDF_STATUS_SUCCESS;
}
qdf_export_symbol(qdf_mc_timer_start);

QDF_STATUS qdf_mc_timer_stop(qdf_mc_timer_t *timer)
{
	/* check for invalid pointer */
	if (!timer) {
		QDF_TRACE_DEBUG_RL(QDF_MODULE_ID_QDF,
				   "%s Null timer pointer", __func__);
		QDF_ASSERT(0);
		return QDF_STATUS_E_INVAL;
	}

	/* check if timer refers to an uninitialized object */
	if (LINUX_TIMER_COOKIE != timer->platform_info.cookie) {
		QDF_TRACE_DEBUG_RL(QDF_MODULE_ID_QDF,
				   "%s: Cannot stop uninit timer", __func__);
		QDF_ASSERT(0);

		return QDF_STATUS_E_INVAL;
	}

	/* ensure the timer state is correct */
	qdf_spin_lock_irqsave(&timer->platform_info.spinlock);

	if (QDF_TIMER_STATE_RUNNING != timer->state) {
		qdf_spin_unlock_irqrestore(&timer->platform_info.spinlock);
		return QDF_STATUS_SUCCESS;
	}

	qdf_spin_unlock_irqrestore(&timer->platform_info.spinlock);

	del_timer(&(timer->platform_info.timer));

	qdf_spin_lock_irqsave(&timer->platform_info.spinlock);
	timer->state = QDF_TIMER_STATE_STOPPED;
	qdf_spin_unlock_irqrestore(&timer->platform_info.spinlock);

	qdf_try_allowing_sleep(timer->type);

	return QDF_STATUS_SUCCESS;
}
qdf_export_symbol(qdf_mc_timer_stop);

QDF_STATUS qdf_mc_timer_stop_sync(qdf_mc_timer_t *timer)
{
	/* check for invalid pointer */
	if (!timer) {
		QDF_TRACE_DEBUG_RL(QDF_MODULE_ID_QDF,
				   "%s Null timer pointer", __func__);
		QDF_ASSERT(0);
		return QDF_STATUS_E_INVAL;
	}

	/* check if timer refers to an uninitialized object */
	if (LINUX_TIMER_COOKIE != timer->platform_info.cookie) {
		QDF_TRACE_DEBUG_RL(QDF_MODULE_ID_QDF,
				   "%s: Cannot stop uninit timer", __func__);
		QDF_ASSERT(0);

		return QDF_STATUS_E_INVAL;
	}

	/* ensure the timer state is correct */
	qdf_spin_lock_irqsave(&timer->platform_info.spinlock);

	if (QDF_TIMER_STATE_RUNNING != timer->state) {
		qdf_spin_unlock_irqrestore(&timer->platform_info.spinlock);
		return QDF_STATUS_SUCCESS;
	}

	timer->state = QDF_TIMER_STATE_STOPPED;

	qdf_spin_unlock_irqrestore(&timer->platform_info.spinlock);
	del_timer_sync(&(timer->platform_info.timer));

	qdf_try_allowing_sleep(timer->type);

	return QDF_STATUS_SUCCESS;
}
qdf_export_symbol(qdf_mc_timer_stop_sync);

unsigned long qdf_mc_timer_get_system_ticks(void)
{
	return jiffies_to_msecs(jiffies) / 10;
}
qdf_export_symbol(qdf_mc_timer_get_system_ticks);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0))
unsigned long qdf_mc_timer_get_system_time(void)
{
	struct timespec64 tv;

	ktime_get_real_ts64(&tv);
	return tv.tv_sec * 1000 + tv.tv_nsec / 1000000;
}
qdf_export_symbol(qdf_mc_timer_get_system_time);

#else
unsigned long qdf_mc_timer_get_system_time(void)
{
	struct timeval tv;

	do_gettimeofday(&tv);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}
qdf_export_symbol(qdf_mc_timer_get_system_time);
#endif

s64 qdf_get_monotonic_boottime_ns(void)
{
	return ktime_to_ns(ktime_get_boottime());
}
qdf_export_symbol(qdf_get_monotonic_boottime_ns);

void qdf_timer_module_deinit(void)
{
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "De-Initializing the QDF MC timer module");
	qdf_mutex_destroy(&persistent_timer_count_lock);
}
qdf_export_symbol(qdf_timer_module_deinit);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0))
void qdf_get_time_of_the_day_in_hr_min_sec_usec(char *tbuf, int len)
{
	struct timespec64 tv;
	struct rtc_time tm;
	unsigned long local_time;

	/* Format the Log time R#: [hr:min:sec.microsec] */
	ktime_get_real_ts64(&tv);
	/* Convert rtc to local time */
	local_time = (u32)(tv.tv_sec - (sys_tz.tz_minuteswest * 60));
	rtc_time64_to_tm(local_time, &tm);
	scnprintf(tbuf, len,
		  "[%02d:%02d:%02d.%06lu]",
		  tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_nsec / 1000);
}

qdf_export_symbol(qdf_get_time_of_the_day_in_hr_min_sec_usec);

uint64_t qdf_get_time_of_the_day_us(void)
{
	struct timespec64 tv;
	struct rtc_time tm;
	unsigned long local_time;
	uint64_t time_of_day_us = 0;

	ktime_get_real_ts64(&tv);
	/* Convert rtc to local time */
	local_time = (u32)(tv.tv_sec - (sys_tz.tz_minuteswest * 60));
	rtc_time64_to_tm(local_time, &tm);

	time_of_day_us += (uint64_t)tm.tm_hour * 60 * 60 * 1000 * 1000;
	time_of_day_us += (uint64_t)tm.tm_min * 60 * 1000 * 1000;
	time_of_day_us += (uint64_t)tm.tm_sec * 1000 * 1000;
	time_of_day_us += qdf_do_div((uint64_t)tv.tv_nsec,  1000);

	return time_of_day_us;
}

qdf_export_symbol(qdf_get_time_of_the_day_us);
#else
void qdf_get_time_of_the_day_in_hr_min_sec_usec(char *tbuf, int len)
{
	struct timeval tv;
	struct rtc_time tm;
	unsigned long local_time;

	/* Format the Log time R#: [hr:min:sec.microsec] */
	do_gettimeofday(&tv);
	/* Convert rtc to local time */
	local_time = (u32)(tv.tv_sec - (sys_tz.tz_minuteswest * 60));
	rtc_time_to_tm(local_time, &tm);
	scnprintf(tbuf, len,
		"[%02d:%02d:%02d.%06lu]",
		tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);
}
qdf_export_symbol(qdf_get_time_of_the_day_in_hr_min_sec_usec);

uint64_t qdf_get_time_of_the_day_us(void)
{
	struct timeval tv;
	struct rtc_time tm;
	unsigned long local_time;
	uint64_t time_of_day_us = 0;

	do_gettimeofday(&tv);
	/* Convert rtc to local time */
	local_time = (u32)(tv.tv_sec - (sys_tz.tz_minuteswest * 60));
	rtc_time_to_tm(local_time, &tm);

	time_of_day_us += (uint64_t)tm.tm_hour * 60 * 60 * 1000 * 1000;
	time_of_day_us += (uint64_t)tm.tm_min * 60 * 1000 * 1000;
	time_of_day_us += (uint64_t)tm.tm_sec * 1000 * 1000;
	time_of_day_us += (uint64_t)tv.tv_usec;

	return time_of_day_us;
}

qdf_export_symbol(qdf_get_time_of_the_day_us);
#endif

qdf_time_t qdf_get_time_of_the_day_ms(void)
{
	qdf_time_t time_of_the_day_ms;

	time_of_the_day_ms = qdf_do_div(qdf_get_time_of_the_day_us(), 1000);

	return time_of_the_day_ms;
}

qdf_export_symbol(qdf_get_time_of_the_day_ms);
