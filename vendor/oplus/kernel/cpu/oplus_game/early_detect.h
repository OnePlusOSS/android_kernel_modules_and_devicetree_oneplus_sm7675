#ifndef _OPLUS_GAME_EARLY_DETECT_H_
#define _OPLUS_GAME_EARLY_DETECT_H_

extern struct proc_dir_entry *early_detect_dir;

enum ED_BOOST_TYPE { ED_BOOST_NONE = 0, ED_BOOST_EDB = 1 };

void early_detect_set_render_task(int pid);
void early_detect_init(void);
void early_detect_exit(void);

#endif