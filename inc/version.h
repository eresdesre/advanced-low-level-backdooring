#ifndef VERSION_H
#define VERSION_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_LOOKUP 1
#endif

#endif /* VERSION_H */
