#include "thread_watcher.h"

void thread_watcher_do_work(struct work_struct *work)
{
	struct thread_watcher_args *args= container_of(work, struct thread_watcher_args, thread_watcher_work);
	if (args) {
		int thread_count_array[3] = { 0 };
		//binder_watcher_debug("system thread counts: %d, %d:%s is creating way too much threads,thread counts: %d \n",args->nr_threads,args->tsk->tgid, args->tsk->comm,args->current_signal_nr_threads);
		thread_watcher_debug("running thread: %s, system thread counts: %d, %d is creating way too much threads,thread counts: %d \n",current->comm,args->nr_threads,args->pid,args->current_signal_nr_threads);
		//kfree(args);
		thread_count_array[0] = args->nr_threads; //system thread count
		thread_count_array[1] = args->pid;  //current process pid
		thread_count_array[2] = args->current_signal_nr_threads; //thread count under this particular process
		thread_watcher_debug("frk_netlink running thread: %s, system thread counts: %d, %d is creating way too much threads,thread counts: %d \n",current->comm,thread_count_array[0],thread_count_array[1],thread_count_array[2]);
		send_to_frk(THREAD_WATCHER_EVENT,ARRAY_SIZE(thread_count_array),thread_count_array);
		kmem_cache_free(thread_watcher_struct_cachep,args);
	}

}
		
void thread_watcher(void *ignore, struct task_struct *task, int nr_threads, 
							int current_signal_nr_threads)
{
	static u64 last_report_jiffies = 0;

	int current_nr_threads = current->signal->nr_threads;

	if (nr_threads > THREAD_HIGH_WATER_MARK || current_nr_threads >= PROCESS_THREAD_THRESHOLD) {
		u64 now = get_jiffies_64();
		u64 interval = THREAD_REPORT_INTERVAL * HZ;

		//if the system total thread count is above 30000
		//report the events every 100 threads increments, such as 30100/30200/30300....
		if (nr_threads > THREAD_HIGH_WATER_MARK && nr_threads % 100 == 0)
			interval = 0;
		//any process whose total thread count gets to PROCESS_THREAD_THRESHOLD 
                //or the total thread count is divisable by 1000,say 4000,5000,6000...
		//get a chance to report
		if (current_nr_threads == PROCESS_THREAD_THRESHOLD || current_nr_threads % 1000 == 0)
			interval = 0;

		if (last_report_jiffies > 0 && time_before64(now, (last_report_jiffies + interval)))
			goto done;
		//if current the system thread is high abovte 25000,check every seconds
		thread_watcher_debug("%d:%s is frk creating way too much threads,thread counts: %d \n",current->tgid, current->comm,current->signal->nr_threads);
               	//work_args = kzalloc(sizeof(struct thread_watcher_args), GFP_KERNEL);
		work_args = kmem_cache_alloc(thread_watcher_struct_cachep, GFP_KERNEL);
		if (!work_args)
			return;
		work_args->pid = current->tgid;
		work_args->nr_threads = nr_threads;
		work_args->current_signal_nr_threads = current->signal->nr_threads;
		INIT_WORK(&work_args->thread_watcher_work, thread_watcher_do_work);
		queue_work(thread_watcher_wq,&work_args->thread_watcher_work);
		last_report_jiffies = now;
	}
done:
	return;
}

