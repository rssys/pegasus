#pragma once
#include <vector>
#include <string>
#include <sys/time.h>
#include <linux/time_types.h>

namespace pegasus {
void init_vdso();
void *get_vdso_base();
}

extern int (*pegasus_vdso_clock_gettime)(clockid_t, struct __kernel_timespec *);
extern int (*pegasus_vdso_gettimeofday)(struct timeval *, struct timezone *);
extern __kernel_old_time_t (*pegasus_vdso_time)(__kernel_old_time_t *);
extern int (*pegasus_vdso_clock_getres)(clockid_t, struct __kernel_timespec *);
