#pragma once
#include <functional>
#include <unordered_set>
#include <csignal>
#include <cinttypes>
#include "exception.h"
#include "types.h"

namespace pegasus {
struct SyscallInfo {
    enum class SyscallSource {
        Signal = 0,
        MonitorCall = 1,
        SyscallRewrite = 2,
    };
    SyscallSource source;
    uintptr_t *gregs;
    siginfo_t *si;
    uintptr_t frame;
};

class VThread;
using SyscallHandler = long (*)(VThread *, int, const long *, SyscallInfo *);
//using SyscallHandler = std::function<long (VThread *, int, const long *, SyscallInfo *)>;
template <int MaxSyscall = 512>
struct SyscallTable {
    static constexpr int NumSyscalls = MaxSyscall;
    SyscallHandler handlers[MaxSyscall];
    inline const SyscallHandler &get(int sysno) const {
        if (sysno >= 0 && sysno < MaxSyscall && handlers[sysno]) {
            return handlers[sysno];
        }
        return default_syscall_handler;
    }
    inline SyscallHandler &operator[](size_t i) {
        return handlers[i];
    }
    inline const SyscallHandler &operator[](size_t i) const {
        return handlers[i];
    }
    SyscallHandler default_syscall_handler;
};

inline static long raw_syscall(int sysno) {
    long res = sysno;
    asm volatile (
        "syscall"
        : "+a" (res)
        :: "rcx", "r11", "memory"
    );
    return res;
}

inline static long raw_syscall(int sysno, long arg1) {
    long res = sysno;
    asm volatile (
        "syscall"
        : "+a" (res)
        : "D" (arg1)
        : "rcx", "r11", "memory"
    );
    return res;
}
inline static long raw_syscall(int sysno, long arg1, long arg2) {
    long res = sysno;
    asm volatile (
        "syscall"
        : "+a" (res)
        : "D" (arg1), "S" (arg2)
        : "rcx", "r11", "memory"
    );
    return res;
}

inline static long raw_syscall(int sysno, long arg1, long arg2, long arg3) {
    long res = sysno;
    asm volatile (
        "syscall"
        : "+a" (res)
        : "D" (arg1), "S" (arg2), "d" (arg3)
        : "rcx", "r11", "memory"
    );
    return res;
}

inline static long raw_syscall(int sysno, long arg1, long arg2, long arg3,
                               long arg4) {
    long res = sysno;
    register long r10 asm ("r10") = arg4;
    asm volatile (
        "syscall"
        : "+a" (res)
        : "D" (arg1), "S" (arg2), "d" (arg3), "r" (r10)
        : "rcx", "r11", "memory"
    );
    return res;
}

inline static long raw_syscall(int sysno, long arg1, long arg2, long arg3,
                               long arg4, long arg5) {
    long res = sysno;
    register long r10 asm ("r10") = arg4;
    register long r8 asm ("r8") = arg5;
    asm volatile (
        "syscall"
        : "+a" (res)
        : "D" (arg1), "S" (arg2), "d" (arg3), "r" (r10), "r" (r8)
        : "rcx", "r11", "memory"
    );
    return res;
}

inline static long raw_syscall(int sysno, long arg1, long arg2, long arg3,
                               long arg4, long arg5, long arg6) {
    long res = sysno;
    register long r10 asm ("r10") = arg4;
    register long r8 asm ("r8") = arg5;
    register long r9 asm ("r9") = arg6;
    asm volatile (
        "syscall"
        : "+a" (res)
        : "D" (arg1), "S" (arg2), "d" (arg3), "r" (r10), "r" (r8), "r" (r9)
        : "rcx", "r11", "memory"
    );
    return res;
}

template <typename... T>
inline static long raw_syscall(int sysno, T... args) {
    return raw_syscall(sysno, ((long)args)...);
}

struct SyscallHandlers {
    // Memory management
    static long brk(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long mmap(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long munmap(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long mprotect(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long mremap(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long madvise(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long mlock(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long munlock(VThread *vthread, int sysno, const long *args, SyscallInfo *info);

    // Signal
    static long sigaction(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sigreturn(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sigprocmask(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sigsuspend(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sigaltstack(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sigtimedwait(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sigpending(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sigqueueinfo(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long tgsigqueueinfo(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long tgkill(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long tkill(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long kill(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long restart_syscall(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long signalfd(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long signalfd4(VThread *vthread, int sysno, const long *args, SyscallInfo *info);

    // Timer
    static long clock_nanosleep(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long clock_gettime(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long gettimeofday(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long nanosleep(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sched_yield(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long pause(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long setitimer(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long getitimer(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long timer_create(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long timer_settime(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long timer_gettime(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long timer_getoverrun(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long timer_delete(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long alarm(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long timerfd_create(VThread *vthread, int sysno, const long *args, SyscallInfo *info);

    // Process
    static long arch_prctl(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long exit_group(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long exit(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long gettid(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long getpid(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long getpgid(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long getpgrp(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long setpgid(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long getppid(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long getsid(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long prlimit64(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long getrlimit(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long setrlimit(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sched_getaffinity(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sched_setaffinity(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long set_tid_address(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long setpriorty(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sched_setparam(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sched_getparam(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sched_getscheduler(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sched_setscheduler(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sched_get_priority_max(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sched_get_priority_min(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sched_rr_get_interval(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long wait4(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long waitid(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long getcpu(VThread *vthread, int sysno, const long *args, SyscallInfo *info);

    // futex
    static long futex(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long set_robust_list(VThread *vthread, int sysno, const long *args, SyscallInfo *info);

    // clone
    static long clone(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long clone3(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long vfork(VThread *vthread, int sysno, const long *args, SyscallInfo *info);

    // execve
    static long execve(VThread *vthread, int sysno, const long *args, SyscallInfo *info);

    // file
    static long open(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long openat(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long read(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long write(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long close(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long readv(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long writev(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long fcntl(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long ioctl(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sendfile(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long socket(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long recvfrom(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sendto(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long recvmsg(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long sendmsg(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long listen(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long bind(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long accept4(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long accept(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long connect(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long shutdown(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long getsockopt(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long setsockopt(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long getsockname(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long getpeername(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long socketpair(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long pipe(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long pipe2(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long dup(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long dup2(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long dup3(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long eventfd(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long eventfd2(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long stat(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long newfstatat(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long readlink(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long close_range(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long inotify_init(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long inotify_init1(VThread *vthread, int sysno, const long *args, SyscallInfo *info);

    // epoll
    static long epoll_create(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long epoll_create1(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long epoll_ctl(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long epoll_wait(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long epoll_pwait(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long epoll_pwait2(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long poll(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long ppoll(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long select(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long pselect6(VThread *vthread, int sysno, const long *args, SyscallInfo *info);

    // Helpers
    template <long res>
    static long stub_handler(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
        return res;
    }
    static long raise_exception(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
        printf("unhandled syscall: %d, source: %d\n", sysno, (int)info->source);
        throw SyscallException(sysno);
    }
    static long passthrough(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    static long passthrough_with_fd(VThread *vthread, int sysno, const long *args, SyscallInfo *info);
    template <typename T>
    static long raise_custom_exception(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
        throw T();
    }
    static const std::unordered_map<int, SyscallHandler> Handlers;
};

extern const std::unordered_set<int> PassthroughSyscalls;
extern const std::unordered_set<unsigned int> SchedulePointSyscalls;
extern const SyscallTable<512> SyscallHandlerTable;
}