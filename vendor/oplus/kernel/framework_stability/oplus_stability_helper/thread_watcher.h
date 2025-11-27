
#include "frk_stability.h"
#include "frk_netlink.h"

#define THREAD_HIGH_WATER_MARK 30000
#define PROCESS_THREAD_THRESHOLD 5000
#define THREAD_REPORT_INTERVAL 60 

struct thread_watcher_args {
	pid_t pid;
	int nr_threads;
	int current_signal_nr_threads;
	struct work_struct thread_watcher_work;
};
extern struct workqueue_struct *thread_watcher_wq;
extern struct thread_watcher_args  *work_args;
extern struct  kmem_cache *thread_watcher_struct_cachep;
void thread_watcher_do_work(struct work_struct *work);
void thread_watcher(void *ignore, struct task_struct *task, int nr_threads, 
							int current_signal_nr_threads);
