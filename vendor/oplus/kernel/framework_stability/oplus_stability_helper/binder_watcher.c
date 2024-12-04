#include "frk_stability.h"
#include "binder_watcher.h"

static bool is_system_server(struct task_struct *t)
{
	if (!t)
		return false;

  	if (task_uid(t).val == SYSTEM_UID) {
  		if (!strcmp(t->comm, "system_server"))
  			return true;
  	}
  	return false;
}
static bool is_surface_flinger(struct task_struct *t)
{
	if (!t)
		return false;

  	if (task_uid(t).val == SYSTEM_UID) {
  		if (!strcmp(t->comm, "surfaceflinger"))
  			return true;
  	}
  	return false;
}
static struct binder_buffer *binder_buffer_next(struct binder_buffer *buffer)
{
	return list_entry(buffer->entry.next, struct binder_buffer, entry);
}


static size_t binder_alloc_buffer_size(struct binder_alloc *alloc,
				       struct binder_buffer *buffer)
{
	if (list_is_last(&buffer->entry, &alloc->buffers))
		return alloc->buffer + alloc->buffer_size - buffer->user_data;
	return binder_buffer_next(buffer)->user_data - buffer->user_data;
}


void binder_buffer_watcher(void *ignore, int is_async, size_t *free_async_space, 
							int pid,  bool *should_fail)
{
	struct task_struct *task = NULL;
	struct binder_alloc *alloc = NULL;
	
	//first, check if it is async binder transaction
	if (is_async) {
		alloc = container_of(free_async_space, struct binder_alloc, free_async_space);
		if (alloc == NULL) {
			//This should not happen, if it does, do nothing
			goto watcher_done;
		}
		if (alloc->free_async_space > alloc->buffer_size / 5)
			//if there is still 40% free async space left, do nothing
			goto watcher_done;

	 	//if this async transaction is from surfaceflinger backgroud thread or main thread, do nothing.		
  		if (is_surface_flinger(current)) {
			//binder_watcher_debug("%d:%s is calling alloc binder buffer  %d\n",current->tgid, current->comm,alloc->pid);
  			goto watcher_done;
		}
		
		// first check this target allocation is aiming at system_server
		task = get_pid_task(find_vpid(alloc->pid), PIDTYPE_PID);
		if(is_system_server(task)) {
			//now system_server async space is lower than 40%, try to calculate the binder buffer usage of this pid
			struct rb_node *n;
			struct binder_buffer *buffer;
			size_t total_alloc_size = 0;
			size_t num_buffers = 0;
		
			//binder_watcher_debug("%d is calling alloc binder buffer to system_server: %d:%s \n",current->tgid, task->pid, task->comm);
			for (n = rb_first(&alloc->allocated_buffers); n != NULL;
				 n = rb_next(n)) {
				buffer = rb_entry(n, struct binder_buffer, rb_node);
				if (buffer->pid != current->tgid)
					continue;
				if (!buffer->async_transaction)
					continue;
				total_alloc_size += binder_alloc_buffer_size(alloc, buffer)
					+ sizeof(struct binder_buffer);
				num_buffers++;
			}
		
			/*
			 * Warn if this pid has more than 50 transactions, or more than 50% of
			 * async space (which is 25% of total buffer size). Oneway spam is only
			 * detected when the threshold is exceeded.
			 */
			if (total_alloc_size > alloc->buffer_size / 4) {
				binder_watcher_debug("%d: pid %d spamming oneway? %zd buffers allocated for a total size of %zd\n",
		        			      alloc->pid, pid, num_buffers, total_alloc_size);
				binder_watcher_debug("%d: pid %d spamming oneway? should fail\n",
		        			      alloc->pid, pid);
				*should_fail = true;
			}
			
		}
	}
watcher_done:
	return;
}
