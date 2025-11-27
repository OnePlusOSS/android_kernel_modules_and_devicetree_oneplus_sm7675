#include <linux/cgroup.h>
#include <linux/proc_fs.h>
#include <linux/sched/cputime.h>
#include <kernel/sched/sched.h>
#include <trace/hooks/cgroup.h>
#include "sa_group.h"

LIST_HEAD(css_tg_map_list);

int bg_cgrp, fg_cgrp, fgwd_cgrp, ta_cgrp;

static inline int task_cpu_cgroup(struct task_struct *p)
{
	if (IS_ERR_OR_NULL(p))
		return -1;

	struct cgroup_subsys_state *css = task_css(p, cpu_cgrp_id);
	return css ? css->id : -1;
}

bool fg_task(struct task_struct *p)
{
	int cpu_cgrp_id = task_cpu_cgroup(p);
	if (-1 == cpu_cgrp_id)
		return false;

	if ((fg_cgrp && cpu_cgrp_id == fg_cgrp)
		|| (fgwd_cgrp && cpu_cgrp_id == fgwd_cgrp))
		return true;

	return false;
}
EXPORT_SYMBOL_GPL(fg_task);

bool bg_task(struct task_struct *p)
{
	int cpu_cgrp_id = task_cpu_cgroup(p);
	if (-1 == cpu_cgrp_id)
		return false;

	if (bg_cgrp && cpu_cgrp_id == bg_cgrp)
		return true;

	return false;
}
EXPORT_SYMBOL_GPL(bg_task);

bool ta_task(struct task_struct *p)
{
	int cpu_cgrp_id = task_cpu_cgroup(p);
	if (-1 == cpu_cgrp_id)
		return false;

	if (ta_cgrp && cpu_cgrp_id == ta_cgrp)
		return true;

	return false;
}
EXPORT_SYMBOL_GPL(ta_task);

bool rootcg_task(struct task_struct *p)
{
	int cpu_cgrp_id = task_cpu_cgroup(p);
	if (-1 == cpu_cgrp_id)
		return false;

	if (1 == cpu_cgrp_id)
		return true;

	return false;
}
EXPORT_SYMBOL_GPL(rootcg_task);

static ssize_t tg_map_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	char buffer[MAX_OUTPUT];
	size_t len = 0;
	struct css_tg_map *iter = NULL;

	memset(buffer, 0, sizeof(buffer));

	rcu_read_lock();
	list_for_each_entry_rcu(iter, &css_tg_map_list, map_list) {
		len += snprintf(buffer + len, sizeof(buffer) - len, "%s:%d ",
			iter->tg_name, iter->id);
		if (len > MAX_GUARD_SIZE) {
			len += snprintf(buffer + len, sizeof(buffer) - len, "... ");
			break;
		}
	}
	rcu_read_unlock();

	buffer[len-1] = '\n';

	return simple_read_from_buffer(buf, count, ppos, buffer, len);
};

bool same_cgrp(const char *s1, const char *s2)
{
	if (strlen(s1) != strlen(s2))
		return false;

	if (!strncmp(s1, s2, strlen(s1)))
		return true;

	return false;
}

struct css_tg_map *get_tg_map(const char *tg_name)
{
	struct css_tg_map *iter = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(iter, &css_tg_map_list, map_list) {
		if (!same_cgrp(iter->tg_name, tg_name))
			continue;
		rcu_read_unlock();
		return iter;
	}
	rcu_read_unlock();

	return NULL;
}

static const struct proc_ops tg_map_fops = {
	.proc_read		= tg_map_read,
};

void save_oplus_sg_info(struct css_tg_map *map)
{
	if (IS_ERR_OR_NULL(map))
		return;

	if (same_cgrp(map->tg_name, "foreground"))
		fg_cgrp = map->id;
	else if (same_cgrp(map->tg_name, "foreground_window"))
		fgwd_cgrp = map->id;
	else if (same_cgrp(map->tg_name, "background"))
		bg_cgrp = map->id;
	else if (same_cgrp(map->tg_name, "top-app"))
		ta_cgrp = map->id;
}

struct css_tg_map *map_node_init(struct cgroup_subsys_state *css)
{
	struct cgroup *cgrp = NULL;
	struct css_tg_map *map = NULL;

	map = kzalloc(sizeof(struct css_tg_map), GFP_ATOMIC);
	if (!map || !css)
		return NULL;

	cgrp = css->cgroup;
	if (cgrp && cgrp->kn) {
		map->tg_name = kstrdup_const(cgrp->kn->name, GFP_ATOMIC);
		map->id = css->id;

		save_oplus_sg_info(map);

		return map;
	}
	return NULL;
}

void oplus_update_tg_map(struct cgroup_subsys_state *css)
{
	struct cgroup *cgrp = css->cgroup;
	struct css_tg_map *map = NULL, *iter = NULL;

	if (!(map = map_node_init(css)))
		return;

	if (cgrp && cgrp->kn) {
		iter = get_tg_map(cgrp->kn->name);
		if (iter) {
			list_replace_rcu(&iter->map_list, &map->map_list);
			kfree_const(iter->tg_name);
			kfree(iter);
			return;
		}
		list_add_tail_rcu(&map->map_list, &css_tg_map_list);
	}
}

void oplus_sg_map_init(void)
{
	struct cgroup_subsys_state *css = &root_task_group.css;
	struct cgroup_subsys_state *top_css = css;

	rcu_read_lock();
	css_for_each_child(css, top_css)
		oplus_update_tg_map(css);
	rcu_read_unlock();
}

void oplus_sched_group_init(struct proc_dir_entry *pde)
{
	struct proc_dir_entry *proc_node;

	proc_node = proc_create("tg_map", 0666, pde, &tg_map_fops);
	if (!proc_node) {
		pr_err("failed to create proc node tg_css_map\n");
		remove_proc_entry("tg_map", pde);
	}
}
