#ifndef _OPLUS_ALARMTIMER_HOOK_H
#define _OPLUS_ALARMTIMER_HOOK_H

struct tracepoints_table {
    const char *name;
    void *func;
    struct tracepoint *tp;
    bool registered;
};

int alarmtimer_hook_init(void);
void alarmtimer_hook_exit(void);

#endif /* _OPLUS_ALARMTIMER_HOOK_H */
