
#include <trace/hooks/binder.h>
#include <drivers/android/binder_alloc.h>
#include <drivers/android/binder_internal.h>


void binder_buffer_watcher(void *ignore, int is_async, size_t *free_async_space, 
							int pid,  bool *should_fail);
