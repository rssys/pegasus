#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/syscall.h>
#include "pegasus/event.h"
#include "pegasus/exception.h"
#include "pegasus/file.h"
#include "pegasus/mm.h"
#include "pegasus/monitor.h"
#include "pegasus/runtime.h"
#include "pegasus/sched.h"
#include "pegasus/stat.h"
#include "pegasus/syscall.h"
#include "pegasus/timer.h"
#include "pegasus/wait_queue.h"

using namespace pegasus;

TimerContext::TimerContext() : max_timerid(TimerOther) {
    epfd = epoll_create1(0);
}

TimerContext::~TimerContext() {
    close(epfd);
    for (auto &&t : timers) {
        close(t.second.fd);
    }
}

intptr_t TimerContext::add_timer(const TimerData &data, intptr_t timerid, bool set_sev_val) {
    {
        std::lock_guard lock(mutex);
        if (timerid == -1) {
            timerid = max_timerid++;
        } else {
            timers[timerid] = data;
        }
        TimerData &new_data = timers[timerid];
        new_data = data;
        if (set_sev_val) {
            new_data.event.sigev_value.sival_int = (int)timerid;
        }
    }
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.u64 = timerid;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, data.fd, &event) == -1) {
        intptr_t res = -errno;
        std::lock_guard lock(mutex);
        timers.erase(timerid);
        return res;
    }
    return timerid;
}

bool TimerContext::del_timer(intptr_t timerid) {
    int fd;
    {
        std::lock_guard lock(mutex);
        auto it = timers.find(timerid);
        if (it == timers.end()) {
            return false;
        }
        fd = it->second.fd;
    }
    close(fd);
    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
    return true;
}

int TimerContext::get_timer_fd(intptr_t timerid) {
    std::lock_guard lock(mutex);
    auto it = timers.find(timerid);
    if (it == timers.end()) {
        return -1;
    }
    return it->second.fd;
}

bool TimerContext::handle() {
    static constexpr int MaxEvents = 16;
    struct epoll_event events[MaxEvents];
    int n = epoll_wait(epfd, events, MaxEvents, 0);
    if (n < 0) {
        return false;
    } else if (n == 0) {
        return true;
    }
    std::lock_guard lock(mutex);
    for (int i = 0; i < n; ++i) {
        intptr_t timerid = events[i].data.u64;
        auto it = timers.find(timerid);
        if (it == timers.end()) {
            continue;
        }
        TimerData &data = it->second;
        uint64_t expires;
        if (read(data.fd, &expires, 8) < 0) {
            expires = 0;
        }
        int notify = data.event.sigev_notify;
        siginfo_t si = {};
        si.si_signo = data.event.sigev_signo;
        si.si_code = timerid >= TimerOther ? SI_TIMER : SI_KERNEL;
        si.si_overrun = expires;
        si.si_timerid = (int)timerid;
        if (notify == SIGEV_SIGNAL) {
            std::shared_ptr<VProcess> vprocess = data.vprocess.lock();
            if (vprocess) {
                vprocess->send_signal(data.event.sigev_signo, &si);
            } else {
                timers.erase(it);
            }
        } else if (notify == SIGEV_THREAD_ID) {
            std::shared_ptr<VThread> vthread = data.vthread.lock();
            if (vthread) {
                vthread->send_signal(data.event.sigev_signo, &si);
            } else {
                timers.erase(it);
            }
        }
    }
    return true;
}

void TimerContext::reset() {
    std::lock_guard lock(mutex);
    for (auto &&timer : timers) {
        int fd = timer.second.fd;
        close(fd);
        epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
    }
    timers.clear();
}

struct ClockNanosleepRestartFunction {
    clockid_t clockid;
    struct __kernel_timespec *rem;
    long operator()(VThread *vthread) {
        const long args[6] = {clockid, 0, (long)rem, (long)rem};
        return SyscallHandlers::clock_nanosleep(vthread, SYS_clock_nanosleep, args, nullptr);
    }
};

long SyscallHandlers::clock_nanosleep(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    clockid_t clockid = args[0];
    int flags = args[1];
    const struct __kernel_timespec *req = (const struct __kernel_timespec *)args[2];
    struct __kernel_timespec *rem = (struct __kernel_timespec *)args[3];
    struct __kernel_timespec req_host;
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();

    int timeout_flags;
    switch (clockid) {
    case CLOCK_MONOTONIC:   timeout_flags = 0; break;
    case CLOCK_REALTIME:    timeout_flags = IORING_TIMEOUT_REALTIME; break;
    case CLOCK_BOOTTIME:    timeout_flags = IORING_TIMEOUT_BOOTTIME; break;
    case CLOCK_TAI:
    case CLOCK_PROCESS_CPUTIME_ID:
        return -ENOTSUP;
    default:
        return -EINVAL;
    }
    if (flags == TIMER_ABSTIME) {
        rem = NULL;
        timeout_flags |= IORING_TIMEOUT_ABS;
    } else if (flags != 0) {
        return -EINVAL;
    }

    try {
        mm->copy_from_sandbox(&req_host, req, sizeof(struct __kernel_timespec));
    } catch (FaultException &e) {
        return -EFAULT;
    }
    if (req_host.tv_nsec > 999999999) {
        return -EINVAL;
    }
    std::shared_ptr<Task> task = Executor::get_current_task();

    struct timespec start_ts, end_ts;
    if (rem) {
        ::clock_gettime(clockid, &start_ts);
    }

    Executor::get_current_executor()->get_eq().add_task_timeout(task, &req_host, timeout_flags);
    Executor::block();
    Task::WaitResult wq_res = task->wq_res;

    if (wq_res.from_signal) {
        if (rem) {
            ::clock_gettime(clockid, &end_ts);
            uint64_t t1 = end_ts.tv_sec * 1000000000 + end_ts.tv_nsec -
                (start_ts.tv_sec * 1000000000 + start_ts.tv_nsec);
            uint64_t t2 = req_host.tv_sec * 1000000000 + req_host.tv_nsec;
            if (t1 >= t2) {
                return 0;
            }
            uint64_t diff = t2 - t1;
            struct __kernel_timespec rem_host;
            rem_host.tv_sec = diff / 1000000000;
            rem_host.tv_nsec = diff % 1000000000;
            try {
                mm->copy_to_sandbox(rem, &rem_host, sizeof(struct __kernel_timespec));
            } catch (FaultException &e) {
                return -EFAULT;
            }
            //ClockNanosleepRestartFunction func;
            //func.clockid = clockid;
            //func.rem = rem;
            //thread->set_restart(func);
        } else {
            //thread->set_restart();
        }
        return -EINTR;
    }

    return 0;
}

long SyscallHandlers::clock_gettime(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    //printf("%d\n", info->source);
    clockid_t clk_id = args[0];
    struct timespec *ptp = (struct timespec *)args[1];
    struct timespec tp;
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    int res = ::clock_gettime(clk_id, &tp);
    if (res == -1) {
        res = -errno;
    }
    try {
        mm->copy_to_sandbox(ptp, &tp, sizeof(tp));
    } catch (FaultException &e) {
        return -EFAULT;
    }
    return res;
}

long SyscallHandlers::gettimeofday(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    struct timeval *ptv = (struct timeval *)args[0];
    struct timezone *ptz = (struct timezone *)args[1];
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    struct timeval tv;
    struct timezone tz;
    int res = ::gettimeofday(&tv, ptz ? &tz : nullptr);
    if (res == -1) {
        res = -errno;
    }
    try {
        mm->copy_to_sandbox(ptv, &tv, sizeof(tv));
        if (ptz) {
            mm->copy_to_sandbox(ptz, &tz, sizeof(tz));
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }
    return res;
}

long SyscallHandlers::nanosleep(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    const struct __kernel_timespec *req = (const struct __kernel_timespec *)args[0];
    struct __kernel_timespec *rem = (struct __kernel_timespec *)args[1];
    struct __kernel_timespec req_host;
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();
    try {
        mm->copy_from_sandbox(&req_host, req, sizeof(struct __kernel_timespec));
    } catch (FaultException &e) {
        return -EFAULT;
    }
    if (req_host.tv_nsec > 999999999) {
        return -EINVAL;
    }
    //Stat::get().add(0, req_host.tv_sec * 1000000000 + req_host.tv_nsec);
    std::shared_ptr<Task> task = Executor::get_current_task();

    struct timespec start_ts, end_ts;
    if (rem) {
        ::clock_gettime(CLOCK_MONOTONIC, &start_ts);
    }

    Executor::get_current_executor()->get_eq().add_task_timeout(task, &req_host);
    Executor::block();
    Task::WaitResult wq_res = task->wq_res;

    if (wq_res.from_signal) {
        if (rem) {
            ::clock_gettime(CLOCK_MONOTONIC, &end_ts);
            uint64_t t1 = end_ts.tv_sec * 1000000000 + end_ts.tv_nsec -
                (start_ts.tv_sec * 1000000000 + start_ts.tv_nsec);
            uint64_t t2 = req_host.tv_sec * 1000000000 + req_host.tv_nsec;
            if (t1 >= t2) {
                return 0;
            }
            uint64_t diff = t2 - t1;
            struct __kernel_timespec rem_host;
            rem_host.tv_sec = diff / 1000000000;
            rem_host.tv_nsec = diff % 1000000000;
            try {
                mm->copy_to_sandbox(rem, &rem_host, sizeof(struct __kernel_timespec));
            } catch (FaultException &e) {
                return -EFAULT;
            }
            //ClockNanosleepRestartFunction func;
            //func.clockid = CLOCK_MONOTONIC;
            //func.rem = rem;
            //thread->set_restart(func);
        } else {
            //thread->set_restart();
        }
        return -EINTR;
    }

    return 0;
}

long SyscallHandlers::sched_yield(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    ReadyQueue &rq = Executor::get_current_executor()->get_rq();
    {
        std::lock_guard lock(rq.get_mutex());
        rq.yield_task();
    }
    Executor::schedule(0);
    return 0;
}

long SyscallHandlers::pause(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    std::shared_ptr<Task> task = Executor::get_current_task();
    Executor::get_current_executor()->get_eq().get_wq()->add_task(task);
    Executor::block();
    return -EINTR;
}

long SyscallHandlers::setitimer(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    int which = args[0];
    const struct itimerval *pnewval = (const struct itimerval *)args[1];
    struct itimerval *poldval = (struct itimerval *)args[2];
    struct itimerval newval, oldval;
    struct itimerspec newits = {}, oldits;
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();
    intptr_t timerid = TimerContext::TimerReal;
    int sig = SIGALRM;
    if (which != ITIMER_REAL) {
        return -EINVAL;
    }
    if (pnewval) {
        try {
            mm->copy_from_sandbox(&newval, pnewval, sizeof(struct itimerval));
        } catch (FaultException &e) {
            return -EFAULT;
        }
    }
    int fd = vprocess->get_timer_context()->get_timer_fd(timerid);
    bool has_timer = true;
    if (fd == -1) {
        has_timer = false;
        fd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (fd == -1) {
            return -errno;
        }
    }
    if (pnewval) {
        newits.it_interval.tv_sec = newval.it_interval.tv_sec;
        newits.it_interval.tv_nsec = newval.it_interval.tv_usec * 1000;
        newits.it_value.tv_sec = newval.it_value.tv_sec;
        newits.it_value.tv_nsec = newval.it_value.tv_usec * 1000;
        if (newval.it_interval.tv_usec > 999999 || newval.it_value.tv_usec > 999999) {
            return -EINVAL;
        }
    }
    if (!has_timer) {
        TimerData data;
        data.fd = fd;
        data.vprocess = thread->get_vprocess()->shared_from_this();
        data.event.sigev_notify = SIGEV_SIGNAL;
        data.event.sigev_signo = sig;
        vprocess->get_timer_context()->add_timer(data, timerid);
    }
    if (timerfd_settime(fd, 0, &newits, poldval ? &oldits : nullptr) == -1) {
        return -errno;
    }
    if (poldval) {
        oldval.it_interval.tv_sec = oldits.it_interval.tv_sec;
        oldval.it_interval.tv_usec = oldits.it_interval.tv_nsec * 1000;
        oldval.it_value.tv_sec = oldits.it_value.tv_sec;
        oldval.it_value.tv_usec = oldits.it_value.tv_nsec * 1000;
        try {
            mm->copy_to_sandbox(poldval, &oldval, sizeof(struct itimerval));
        } catch (FaultException &e) {
            return -EFAULT;
        }
    }
    return 0;
}

long SyscallHandlers::getitimer(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    int which = args[0];
    struct itimerval *pval = (struct itimerval *)args[1];
    intptr_t timerid;
    if (which == ITIMER_REAL) {
        timerid = TimerContext::TimerReal;
    } else if (which == ITIMER_VIRTUAL) {
        timerid = TimerContext::TimerVirtual;
    } else if (which == ITIMER_PROF) {
        timerid = TimerContext::TimerProf;
    } else {
        return -EINVAL;
    }
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();
    struct itimerval val;
    struct itimerspec its = {};
    int fd = vprocess->get_timer_context()->get_timer_fd(timerid);
    if (fd != -1) {
        timerfd_gettime(fd, &its);
    }
    val.it_interval.tv_sec = its.it_interval.tv_sec;
    val.it_interval.tv_usec = its.it_interval.tv_nsec / 1000;
    val.it_value.tv_sec = its.it_value.tv_sec;
    val.it_value.tv_usec = its.it_value.tv_nsec / 1000;
    try {
        mm->copy_to_sandbox(pval, &val, sizeof(struct itimerval));
    } catch (FaultException &e) {
        return -EFAULT;
    }
    return 0;
}


long SyscallHandlers::timer_create(VThread *thread, int sysno,
                                   const long *args, SyscallInfo *info) {
    clockid_t clockid = args[0];
    struct sigevent *sevp = (struct sigevent *)args[1];
    timer_t *ptimerid = (timer_t *)args[2];
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();
    TaskManager *tm = Runtime::get()->get_tm();
    struct sigevent sev = {};
    switch (clockid) {
    case CLOCK_REALTIME:
    case CLOCK_MONOTONIC:
    case CLOCK_BOOTTIME:
    case CLOCK_REALTIME_ALARM:
    case CLOCK_BOOTTIME_ALARM:
        break;
    default:
        return -EINVAL;
    }
    if (sevp) {
        try {
            mm->copy_from_sandbox(&sev, sevp, sizeof(struct sigevent));
        } catch (FaultException &e) {
            return -EFAULT;
        }
    } else {
        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = SIGALRM;
    }
    TimerData data;
    data.event = sev;
    if (sev.sigev_notify == SIGEV_SIGNAL) {
        data.vprocess = thread->get_vprocess()->shared_from_this();
    } else if (sev.sigev_notify == SIGEV_THREAD_ID) {
        std::shared_ptr<Task> task = tm->get_task(sev._sigev_un._tid);
        if (!task || !task->vthread) {
            return -EINVAL;
        }
        std::shared_ptr<VThread> th = task->vthread;
        if (th->get_vprocess() != thread->get_vprocess()) {
            return -EINVAL;
        }
        data.vthread = th;
    } else if (sev.sigev_notify != SIGEV_NONE) {
        return -EINVAL;
    }
    int fd = ::timerfd_create(clockid, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd == -1) {
        return -errno;
    }
    data.fd = fd;
    intptr_t timerid = vprocess->get_timer_context()->add_timer(data, -1, !sevp);
    if (timerid < 0) {
        return timerid;
    }
    try {
        mm->put_sandbox<timer_t>((timer_t)timerid, ptimerid);
    } catch (FaultException &e) {
        return -EFAULT;
    }
    return 0;
}

long SyscallHandlers::timer_settime(VThread *thread, int sysno,
                                    const long *args, SyscallInfo *info) {
    timer_t timerid = (timer_t)args[0];
    int flags = args[1];
    const struct itimerspec *pnewval = (const struct itimerspec *)args[2];
    struct itimerspec *poldval = (struct itimerspec *)args[3];
    int tfd_flags;
    if ((uintptr_t)timerid < TimerContext::TimerOther) {
        return -EINVAL;
    }
    if (flags == 0) {
        tfd_flags = 0;
    } else if (flags == TIMER_ABSTIME) {
        tfd_flags = TFD_TIMER_ABSTIME;
    } else {
        return -EINVAL;
    }
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();
    int fd = vprocess->get_timer_context()->get_timer_fd((intptr_t)timerid);
    if (fd == -1) {
        return -EINVAL;
    }
    struct itimerspec newval, oldval;
    if (pnewval) {
        try {
            mm->copy_from_sandbox(&newval, pnewval, sizeof(struct itimerspec));
        } catch (FaultException &e) {
            return -EFAULT;
        }
    }
    if (timerfd_settime(fd, tfd_flags, pnewval ? &newval : nullptr, poldval ? &oldval : nullptr) == -1) {
        return -errno;
    }
    if (poldval) {
        try {
             mm->copy_to_sandbox(poldval, &oldval, sizeof(struct itimerspec));
        } catch (FaultException &e) {
            return -EFAULT;
        }
    }
    return 0;
}

long SyscallHandlers::timer_gettime(VThread *thread, int sysno,
                                    const long *args, SyscallInfo *info) {
    timer_t timerid = (timer_t)args[0];
    struct itimerspec *pval = (struct itimerspec *)args[1];
    if ((uintptr_t)timerid < TimerContext::TimerOther) {
        return -EINVAL;
    }
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();
    int fd = vprocess->get_timer_context()->get_timer_fd((intptr_t)timerid);
    if (fd == -1) {
        return -EINVAL;
    }
    struct itimerspec val;
    if (timerfd_gettime(fd, &val) == -1) {
        return -errno;
    }
    try {
         mm->copy_to_sandbox(pval, &val, sizeof(struct itimerspec));
    } catch (FaultException &e) {
        return -EFAULT;
    }
    return 0;
}

long SyscallHandlers::timer_getoverrun(VThread *thread, int sysno,
                                       const long *args, SyscallInfo *info) {
    timer_t timerid = (timer_t)args[0];
    if ((uintptr_t)timerid < TimerContext::TimerOther) {
        return -EINVAL;
    }
    VProcess *vprocess = thread->get_vprocess();
    int fd = vprocess->get_timer_context()->get_timer_fd((intptr_t)timerid);
    if (fd == -1) {
        return -EINVAL;
    }
    uint64_t overrun;
    ssize_t res = ::read(fd, &overrun, 8);
    if (res > 0) {
        return overrun;
    }
    return 0;
}

long SyscallHandlers::timer_delete(VThread *thread, int sysno,
                                   const long *args, SyscallInfo *info) {
    timer_t timerid = (timer_t)args[0];
    if ((uintptr_t)timerid < TimerContext::TimerOther) {
        return -EINVAL;
    }
    VProcess *vprocess = thread->get_vprocess();
    if (!vprocess->get_timer_context()->del_timer((intptr_t)timerid)) {
        return -EINVAL;
    }
    return 0;
}

long SyscallHandlers::alarm(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    unsigned int seconds = args[0];
    VProcess *vprocess = thread->get_vprocess();
    int fd = vprocess->get_timer_context()->get_timer_fd(TimerContext::TimerReal);
    bool has_timer = true;
    if (fd == -1) {
        has_timer = false;
        fd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (fd == -1) {
            return -errno;
        }
    }
    struct itimerspec newits, oldits;
    newits.it_interval.tv_sec = 0;
    newits.it_interval.tv_nsec = 0;
    newits.it_value.tv_sec = seconds;
    newits.it_value.tv_nsec = 0;
    if (!has_timer) {
        if (!seconds) {
            return 0;
        }
        TimerData data;
        data.fd = fd;
        data.vprocess = thread->get_vprocess()->shared_from_this();
        data.event.sigev_notify = SIGEV_SIGNAL;
        data.event.sigev_signo = SIGALRM;
        vprocess->get_timer_context()->add_timer(data, TimerContext::TimerReal);
    }
    if (timerfd_settime(fd, 0, &newits, &oldits) == -1) {
        return 0;
    }
    return oldits.it_value.tv_sec;
}

long SyscallHandlers::timerfd_create(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    clockid_t clockid = args[0];
    int flags = args[1];
    bool nonblock = flags & TFD_NONBLOCK;
    flags |= TFD_NONBLOCK;
    long new_args[6] = {clockid, flags};
    int res = vthread->invoke_syscall(SYS_timerfd_create, new_args);
    if (res < 0) {
        return res;
    }
    VProcess *vprocess = vthread->get_vprocess();
    USwitchContext *ucontext = vprocess->get_ucontext();
    FileTable *ft = vprocess->get_file_table();
    FileDescriptor fd(ucontext, res);
    std::shared_ptr<NonblockingFile> file = std::make_shared<NonblockingFile>(ucontext, res, nonblock);
    try {
        ft->add_file(vthread, fd, file);
    } catch (std::bad_alloc &e) {
        return -ENOMEM;
    }
    return res;
}
