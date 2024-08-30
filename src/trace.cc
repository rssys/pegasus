#include <seccomp.h>
#include "pegasus/sched.h"
#include "pegasus/trace.h"

using namespace pegasus;

static SyscallLogger logger(256);

SyscallLogger::SyscallLogger(size_t n_) : n(n_), p(0) {
    log.resize(n);
}

void SyscallLogger::add(const SyscallLogEntry &entry) {
    std::lock_guard lock(mutex);
    log[p] = entry;
    p = (p + 1) % n;
}

void SyscallLogger::print_recent() {
    std::lock_guard lock(mutex);
    for (int i = p; i < p + n; ++i) {
        int j = i % n;
        SyscallLogEntry &entry = log[j];
        const long *args = entry.args;
        char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_X86_64, entry.sysno);
        printf("sysno  %d\ttgid   %d\ttid    %d\ttime %lu\t%s(%lx, %lx, %lx, %lx, %lx, %lx)=%lx\n",
               entry.sysno, entry.tgid, entry.tid, entry.time,
               name, args[0], args[1], args[2], args[3], args[4], args[5], entry.res);
        free(name);
    }
}

#ifdef CONFIG_ENABLE_TRACE
void pegasus::trace_syscall(int sysno, int tgid, int tid, const long *args, long res) {
    logger.add(SyscallLogEntry{
        sysno, tgid, tid,
        {args[0], args[1], args[2], args[3], args[4], args[5]},
        res, time_nanosec()
    });
}

void pegasus::print_recent_log() {
    logger.print_recent();
}
#endif
