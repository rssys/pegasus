#include <unordered_map>
#include <unordered_set>
#include <condition_variable>
#include <thread>
#include <mutex>
#include <climits>
#include <ctime>
#include <csignal>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/ioctl.h>
#include <linux/time_types.h>
#include "pegasus/event.h"
#include "pegasus/file.h"
#include "pegasus/monitor.h"
#include "pegasus/mm.h"
#include "pegasus/runtime.h"
#include "pegasus/sched.h"
#include "pegasus/syscall.h"
#include "pegasus/wait_queue.h"

using namespace pegasus;

#define SS_AUTODISARM (1 << 31)

long SyscallHandlers::sigaction(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    int sig = (int)args[0];
    if (sig == SIGKILL || sig == SIGSTOP || sig < 1 || sig > NumSignals) {
        return -EINVAL;
    }
    const KernelSigAction *pact = (const KernelSigAction *)args[1];
    KernelSigAction *poldact = (KernelSigAction *)args[2];
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();
    KernelSigAction act, oldact;
    try {
        if (pact) {
            mm->copy_from_sandbox(&act, pact, sizeof(KernelSigAction));
        }
        vprocess->sigaction(sig, pact ? &act : nullptr, poldact ? &oldact : nullptr);
        if (poldact) {
            mm->copy_to_sandbox(poldact, &oldact, sizeof(KernelSigAction));
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }
    
    return 0;
}

long SyscallHandlers::sigreturn(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    thread->sigreturn();
    return 0;
}

long SyscallHandlers::sigprocmask(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    int how = (int)args[0];
    const uint64_t *set = (const uint64_t *)args[1];
    uint64_t *oldset = (uint64_t *)args[2];
    size_t size = (size_t)args[3];
    if (size != sizeof(uint64_t) || (how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK)) {
        return -EINVAL;
    }
    MM *mm = thread->get_vprocess()->get_mm();
    try {
        uint64_t old = 0;
        uint64_t new_set = 0;
        if (set) {
            new_set = mm->get_sandbox<uint64_t>(set);
        }
        thread->sigprocmask(how, set ? &new_set : nullptr, oldset ? &old : nullptr);
        if (oldset) {
            mm->put_sandbox(old, oldset);
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }
    return 0;
}

long SyscallHandlers::sigsuspend(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    uint64_t mask;
    try {
        mask = thread->get_vprocess()->get_mm()->get_sandbox<uint64_t>((void *)args[0]);
    } catch (FaultException &e) {
        return -EFAULT;
    }
    uint64_t old_mask;
    thread->sigprocmask(SIG_SETMASK, &mask, &old_mask);

    std::shared_ptr<Task> task = Executor::get_current_task();
    Executor::get_current_executor()->get_eq().get_wq()->add_task(task);
    Executor::block();

    thread->sigprocmask(SIG_SETMASK, &old_mask, nullptr);
    return -EINTR;
}

long SyscallHandlers::sigtimedwait(VThread *thread, int sysno, const long *args,
                                   SyscallInfo *info) {
    const uint64_t *pset = (const uint64_t *)args[0];
    siginfo_t *si = (siginfo_t *)args[1];
    const struct __kernel_timespec *timeout = (const struct __kernel_timespec *)args[2];
    struct __kernel_timespec ts;
    size_t size = args[3];
    if (size != sizeof(uint64_t)) {
        return -EINVAL;
    }
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();
    uint64_t set;
    try {
        set = mm->get_sandbox<uint64_t>(pset);
        if (timeout) {
            mm->copy_from_sandbox(&ts, timeout, sizeof(struct __kernel_timespec));
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }

    if (timeout && ts.tv_nsec > 999999999) {
        return -EINVAL;
    }

    set &= ~build_signal_mask(SIGKILL, SIGSTOP);

    std::unique_lock lock(vprocess->get_signal_mutex());

    int res = thread->pop_pending_signal(set, si, true);
    if (res != -EAGAIN || (timeout && ts.tv_sec == 0 && ts.tv_nsec == 0)) {
        return res;
    }

    uint64_t old_mask;
    thread->sigprocmask(SIG_UNBLOCK, &set, &old_mask);

    try {
        std::shared_ptr<Task> task = Executor::get_current_task();
        if (!timeout) {
            Executor::get_current_executor()->get_eq().get_wq()->add_task(task);
        } else {
            Executor::get_current_executor()->get_eq().add_task_timeout(task, &ts);
        }

        lock.unlock();
        Executor::block();
        lock.lock();

        Task::WaitResult wq_res = task->wq_res;
        if (wq_res.timeout) {
            thread->sigprocmask(SIG_SETMASK, &old_mask, nullptr);
            return -EAGAIN;
        }
        thread->sigprocmask(SIG_SETMASK, &old_mask, nullptr);
        int res = thread->pop_pending_signal(set, si, true);
        if (res == -EAGAIN) {
            return -EINTR;
        }
        return res;
    } catch (...) {
        thread->sigprocmask(SIG_SETMASK, &old_mask, nullptr);
        throw;
    }
}

long SyscallHandlers::sigpending(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    uint64_t *pset = (uint64_t *)args[0];
    size_t size = args[1];
    if (size != sizeof(uint64_t)) {
        return -EINVAL;
    }
    uint64_t set = 0;
    thread->sigpending(&set);
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();
    try {
        mm->put_sandbox<uint64_t>(set, pset);
    } catch (FaultException &e) {
        return -EFAULT;
    }
    return 0;
}

long SyscallHandlers::sigqueueinfo(VThread *thread, int sysno,
                                   const long *args, SyscallInfo *info) {
    pid_t tgid = args[0];
    int sig = args[1];
    siginfo_t *puinfo = (siginfo_t *)args[2];
    siginfo_t uinfo;
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();
    if (sig < 1 || sig > NumSignals) {
        return -EINVAL;
    }
    try {
        mm->copy_from_sandbox(&uinfo, puinfo, sizeof(siginfo_t));
    } catch (FaultException &e) {
        return -EFAULT;
    }
    uinfo.si_signo = sig;
    if ((uinfo.si_code >= 0 || uinfo.si_code == SI_TKILL) && tgid != vprocess->get_tgid()) {
        return -EPERM;
    }
    if (tgid == vprocess->get_tgid()) {
        if (!vprocess->send_signal(sig, &uinfo)) {
            return -EAGAIN;
        }
        return 0;
    }
    if (!(vprocess->cap & VProcess::CapKill)) {
        return -EPERM;
    }
    TaskManager *tm = Runtime::get()->get_tm();
    std::shared_ptr<Task> task = tm->get_task(tgid);
    if (!task || !task->vthread) {
        return -ESRCH;
    }
    VProcess *target_vprocess = task->vthread->get_vprocess();
    if (!target_vprocess->send_signal(sig, &uinfo)) {
        return -EAGAIN;
    }
    return 0;
}

long SyscallHandlers::tgsigqueueinfo(VThread *thread, int sysno,
                                     const long *args, SyscallInfo *info) {
    pid_t tgid = args[0];
    pid_t tid = args[1];
    int sig = args[2];
    siginfo_t *puinfo = (siginfo_t *)args[3];
    siginfo_t uinfo;
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();
    if (sig < 1 || sig > 64) {
        return -EINVAL;
    }
    try {
        mm->copy_from_sandbox(&uinfo, puinfo, sizeof(siginfo_t));
    } catch (FaultException &e) {
        return -EFAULT;
    }
    uinfo.si_signo = sig;
    if ((uinfo.si_code >= 0 || uinfo.si_code == SI_TKILL) && tgid != vprocess->get_tgid()) {
        return -EPERM;
    }
    if (tgid != vprocess->get_tgid() && !(vprocess->cap & VProcess::CapKill)) {
        return -EPERM;
    }
    TaskManager *tm = Runtime::get()->get_tm();
    std::shared_ptr<Task> task = tm->get_task(tid);
    if (!task || !task->vthread || task->vthread->get_vprocess()->get_tgid() != tgid) {
        return -ESRCH;
    }
    if (!task->vthread->send_signal(sig, &uinfo)) {
        return -EAGAIN;
    }
    return 0;
}

long SyscallHandlers::sigaltstack(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    const stack_t *ss = (const stack_t *)args[0];
    stack_t *old_ss = (stack_t *)args[1];
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();
    try {
        stack_t new_stack, old_stack;
        if (ss) {
            mm->copy_from_sandbox(&new_stack, ss, sizeof(stack_t));
        }
        int res = thread->sigaltstack(ss ? &new_stack : nullptr, old_ss ? &old_stack : nullptr);
        if (res < 0) {
            return res;
        }
        if (old_ss) {
            mm->copy_to_sandbox(old_ss, &old_stack, sizeof(stack_t));
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }
    return 0;
}

long SyscallHandlers::tgkill(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    int tgid = (int)args[0];
    int tid = (int)args[1];
    int sig = (int)args[2];
    VProcess *vprocess = thread->get_vprocess();
    TaskManager *tm = Runtime::get()->get_tm();
    std::shared_ptr<Task> task = tm->get_task(tid);
    if (!task || !task->vthread) {
        if (tgid == -1 || tgid == vprocess->get_tgid() || (vprocess->cap & VProcess::CapKill)) {
            return -ESRCH;
        } else {
            return -EPERM;
        }
    }
    if (tgid == -1) {
        tgid = task->vthread->get_vprocess()->get_tgid();
    }
    if (tgid != vprocess->get_tgid() && !(vprocess->cap & VProcess::CapKill)) {
        return -EPERM;
    }
    if (task->vthread->get_vprocess()->get_tgid() != tgid) {
        return -ESRCH;
    }
    siginfo_t si = {};
    si.si_signo = sig;
    si.si_code = SI_TKILL;
    task->vthread->send_signal(sig, &si);
    return 0;
}

long SyscallHandlers::tkill(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    long new_args[6] = {-1, args[1], args[2]};
    return tgkill(thread, sysno, new_args, info);
}

long SyscallHandlers::kill(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    pid_t pid = args[0];
    int sig = args[1];
    if (sig < 1 || sig > 64) {
        return -EINVAL;
    }
    VProcess *vprocess = thread->get_vprocess();
    siginfo_t si = {};
    si.si_signo = sig;
    si.si_code = SI_USER;
    si.si_pid = vprocess->get_tgid();
    if (vprocess->get_tgid() == pid) {
        vprocess->send_signal(sig, &si);
        return 0;
    }
    if (!(vprocess->cap & VProcess::CapKill)) {
        return -EPERM;
    }
    TaskManager *tm = Runtime::get()->get_tm();
    std::shared_ptr<Task> task = tm->get_task(pid);
    if (!task) {
        return -ESRCH;
    }
    if (task->vthread) {
        task->vthread->get_vprocess()->send_signal(sig, &si);
        return 0;
    }
    //if (task->proxy) {
    //    return task->proxy->send_signal(sig);
    //}
    return -ESRCH;
}

long SyscallHandlers::restart_syscall(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    return thread->restart_syscall();
}

long SyscallHandlers::signalfd(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    long new_args[6] = {args[0], args[1], args[3], 0};
    return signalfd4(thread, SYS_signalfd4, new_args, info);
}

long SyscallHandlers::signalfd4(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    int fd = args[0];
    const uint64_t *pmask = (const uint64_t *)args[1];
    size_t sizemask = args[2];
    int flags = args[3];
    if (sizemask != sizeof(uint64_t)) {
        return -EINVAL;
    }
    if (flags & ~(SFD_NONBLOCK | SFD_CLOEXEC)) {
        return -EINVAL;
    }
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();
    uint64_t mask;
    try {
        mm->copy_from_sandbox(&mask, pmask, sizeof(uint64_t));
    } catch (FaultException &e) {
        return -EFAULT;
    }
    FileTable *files = vprocess->get_file_table();
    std::shared_ptr<File> f;
    std::shared_ptr<SignalFdFile> file;
    if (fd != -1) {
        f = files->get_file(fd);
        if (!f) {
            return -EBADF;
        }
        file = std::dynamic_pointer_cast<SignalFdFile>(f);
        if (!file) {
            return -EINVAL;
        }
    } else {
        file = std::make_shared<SignalFdFile>(vprocess);
    }
    file->set_mask_nonblock(mask, flags & SFD_NONBLOCK);
    if (fd != -1) {
        return fd;
    }
    file->activate();
    FileDescriptor fd_(vprocess->get_ucontext(), -1);
    return files->add_file(thread, fd_, file);
}

void VProcess::sigaction(int sig, const KernelSigAction *act, KernelSigAction *oldact) {
    if (sig < 1 || sig > NumSignals) {
        return;
    }
    if (oldact) {
        memcpy(oldact, &signal_handlers[sig - 1], sizeof(KernelSigAction));
    }
    if (act) {
        memcpy(&signal_handlers[sig - 1], act, sizeof(KernelSigAction));
    }
}

bool VProcess::send_signal(int sig, siginfo_t *info) {
    {
        std::unique_lock lock(vthread_mutex);
        for (auto it = vthreads.begin(); it != vthreads.end(); ) {
            auto next = std::next(it);
            std::shared_ptr<VThread> vthread = it->second.lock();
            if (!vthread) {
                vthreads.erase(it);
                it = next;
                continue;
            }
            uint64_t mask = __atomic_load_n(&vthread->signal_mask, __ATOMIC_RELAXED);
            if (!(mask & build_signal_mask(sig))) {
                siginfo_t si = {};
                si.si_signo = sig;
                si.si_code = SI_USER;
                return vthread->send_signal(sig, info ? info : &si);
            }
            it = next;
        }
    }
    std::lock_guard lock(signal_mutex);
    if (info) {
        pending_signals.push_front(*info);
    } else {
        siginfo_t si = {};
        si.si_signo = sig;
        si.si_code = SI_USER;
        pending_signals.push_front(si);
    }
    for (auto it = signal_fds.begin(); it != signal_fds.end(); ) {
        auto next = std::next(it);
        std::shared_ptr<SignalFdFile> f = it->second.lock();
        if (!f) {
            signal_fds.erase(it);
            it = next;
            continue;
        }
        uint64_t mask = f->get_mask();
        if (build_signal_mask(sig) & mask) {
            f->notify();
        }
        it = next;
    }
    return false;
}

void VProcess::send_signal_all(int sig) {
    send_signal(sig, nullptr);
    {
        std::lock_guard lock(vthread_mutex);
        for (auto &&c : children) {
            c.second->send_signal_all(sig);
        }
    }
}

void VProcess::kill(int retval_) {
    if (exited) {
        return;
    }
    retval_ = (int8_t)retval_;
    retval = retval_;
    exited = true;
    std::lock_guard lock(vthread_mutex);
    for (auto &&th : vthreads) {
        std::shared_ptr<VThread> thread = th.second.lock();
        if (!thread) {
            continue;
        }
        std::shared_ptr<Task> task = thread->task.lock();
        if (!task) {
            continue;
        }
        task->signal();
    }
}

int VThread::sigaltstack(const stack_t *ss, stack_t *old_ss) {
    if (old_ss) {
        KernelStack s = alternative_signal_stack;
        if (s.ss_flags != SS_DISABLE && check_bound(s.ss_sp, s.ss_size, get_rsp(), 1)) {
            s.ss_flags = SS_ONSTACK;
        }
        memcpy(old_ss, &s, sizeof(stack_t));
    }
    if (ss) {
        if (ss->ss_flags & SS_DISABLE) {
            alternative_signal_stack.ss_sp = nullptr;
            alternative_signal_stack.ss_flags = SS_DISABLE;
            alternative_signal_stack.ss_size = 0;
        } else if (ss->ss_flags != 0 && ss->ss_flags != SS_AUTODISARM) {
            return -EINVAL;
        }
        memcpy(&alternative_signal_stack, ss, sizeof(KernelStack));
    }
    return 0;
}

void VThread::sigprocmask(int how, const uint64_t *set, uint64_t *old_set) {
    if (old_set) {
        *old_set = signal_mask;
    }
    if (!set) {
        return;
    }
    uint64_t new_mask = signal_mask;
    uint64_t new_set = *set;
    if (how == SIG_BLOCK) {
        new_mask |= new_set;
    } else if (how == SIG_UNBLOCK) {
        new_mask &= ~new_set;
    } else if (how == SIG_SETMASK) {
        new_mask = new_set;
    }
    new_mask &= ~build_signal_mask(SIGKILL, SIGSTOP);
    signal_mask = new_mask;
}

void VThread::sigpending(uint64_t *pset) {
    std::lock_guard lock(vprocess->signal_mutex);
    uint64_t set = 0;
    for (auto &&s : pending_signals) {
        set |= build_signal_mask(s.si_signo);
    }
    for (auto &&s : vprocess->pending_signals) {
        set |= build_signal_mask(s.si_signo);
    }
    *pset = set;
}

// assume vprocess->signal_mutex is locked
int VThread::pop_pending_signal(uint64_t set, siginfo_t *info, bool sandbox_mem) {
    for (auto it = pending_signals.begin(); it != pending_signals.end(); ++it) {
        int sig = it->si_signo;
        if (set & build_signal_mask(sig)) {
            siginfo_t si = *it;
            if (sandbox_mem) {
                try {
                    vprocess->mm->copy_to_sandbox(info, &si, sizeof(siginfo_t));
                } catch (FaultException &e) {
                    return -EFAULT;
                }
            } else {
                memcpy(info, &si, sizeof(siginfo_t));
            }
            pending_signals.erase(it);
            return sig;
        }
    }
    for (auto it = vprocess->pending_signals.begin(); it != vprocess->pending_signals.end(); ++it) {
        int sig = it->si_signo;
        if (set & build_signal_mask(sig)) {
            siginfo_t si = *it;
            if (sandbox_mem) {
                try {
                    vprocess->mm->copy_to_sandbox(info, &si, sizeof(siginfo_t));
                } catch (FaultException &e) {
                    return -EFAULT;
                }
            } else {
                memcpy(info, &si, sizeof(siginfo_t));
            }
            vprocess->pending_signals.erase(it);
            return sig;
        }
    }
    return -EAGAIN;
}

bool VThread::send_signal(int sig, siginfo_t *info) {
    if (sig < 1 || sig > NumSignals) {
        return false;
    }
    bool queued = false;
    bool blocked = false;
    {
        std::unique_lock lock(vprocess->signal_mutex);
        if (pending_signals.size() >= MaxPendingSignals) {
            return false;
        }
        bool has_sig = false;
        for (auto &&s : pending_signals) {
            if (s.si_signo == sig) {
                has_sig = true;
                break;
            }
        }
        if (!has_sig) {
            if (info) {
                pending_signals.push_front(*info);
            } else {
                siginfo_t si = {};
                si.si_signo = sig;
                si.si_code = SI_TKILL;
                pending_signals.push_front(si);
            }
        }
        if (signal_mask & build_signal_mask(sig)) {
            blocked = true;
        }
        queued = true;

        if (queued) {
            for (auto it = vprocess->signal_fds.begin(); it != vprocess->signal_fds.end(); ) {
                auto next = std::next(it);
                std::shared_ptr<SignalFdFile> f = it->second.lock();
                if (!f) {
                    vprocess->signal_fds.erase(it);
                    it = next;
                    continue;
                }
                uint64_t mask = f->get_mask();
                if (build_signal_mask(sig) & mask) {
                    f->notify();
                }
                it = next;
            }
        }
        if (blocked) {
            return true;
        }
        KernelSigAction act = vprocess->signal_handlers[sig - 1];
        lock.unlock();
        if (act.sa_handler_ == SIG_IGN) {
            return true;
        }
        if (act.sa_handler_ == SIG_DFL &&
            (sig == SIGCHLD || sig == SIGURG || sig == SIGWINCH || sig == SIGCONT)) {
            return true;
        }
    }

    std::shared_ptr<Task> task_ = task.lock();
    if (task_) {
        task_->signal();
    }
    return true;
}

void VThread::force_signal(int sig, siginfo_t *info) {
    KernelSigAction act;
    {
        std::lock_guard lock(vprocess->signal_mutex);
        act = vprocess->signal_handlers[sig - 1];
        if (act.sa_flags &  SA_RESETHAND) {
            vprocess->signal_handlers[sig - 1].sa_handler_ = SIG_DFL;
        }
    }
    if (act.sa_handler_ == SIG_IGN || (signal_mask & build_signal_mask(sig))) {
        act.sa_handler_ = SIG_DFL;
    }
    if (act.sa_handler_ == SIG_DFL) {
        throw SignalException(sig);
    }
    siginfo_t si;
    if (!info) {
        memset(&si, 0, sizeof(siginfo_t));
        si.si_signo = sig;
        si.si_code = SI_KERNEL;
    }
    handle_vsignal(sig, info ? info : &si, act);
}

SignalFdFile::SignalFdFile(VProcess *vprocess_)
    : File(nullptr, -1), mask(0), nonblock(false), vprocess(vprocess_->shared_from_this()) {
}

SignalFdFile::~SignalFdFile() {
    std::shared_ptr<VProcess> p = vprocess.lock();
    if (p) {
        std::lock_guard lock(p->signal_mutex);
        p->signal_fds.erase(this);
    }
}

void SignalFdFile::activate() {
    std::shared_ptr<VProcess> p = vprocess.lock();
    if (p) {
        std::lock_guard lock(p->signal_mutex);
        std::shared_ptr<SignalFdFile> self = std::static_pointer_cast<SignalFdFile>(shared_from_this());
        p->signal_fds.emplace(this, self);
    }
}

ssize_t SignalFdFile::read(VThread *vthread, int fd, void *buf, size_t len) {
    VProcess *vprocess = vthread->get_vprocess();
    std::unique_lock lock(vprocess->signal_mutex);
    ssize_t res = read_once(vthread, buf, len);
    if (get_nonblock() || res != -EAGAIN) {
        return res;
    }
    std::shared_ptr<Task> task = Executor::get_current_task();
    while (res == -EAGAIN) {
        wq->add_task(task);
        lock.unlock();
        Executor::block();
        if (task->wq_res.from_signal) {
            res = -EINTR;
            break;
        }
        lock.lock();
        res = read_once(vthread, buf, len);
        if (res != -EAGAIN) {
            break;
        }
    }
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

static void copy_signal_fd_info(struct signalfd_siginfo &dst, const siginfo_t &src) {
    memset(&dst, 0, sizeof(struct signalfd_siginfo));
    dst.ssi_signo      = src.si_signo;
    dst.ssi_errno      = src.si_errno;
    dst.ssi_code       = src.si_code;
    dst.ssi_pid        = src.si_pid;
    dst.ssi_uid        = src.si_uid;
    dst.ssi_fd         = src.si_fd;
    dst.ssi_tid        = src.si_timerid;
    dst.ssi_band       = src.si_band;
    dst.ssi_overrun    = src.si_overrun;
    dst.ssi_trapno     = *(int *)&src.si_addr_lsb;
    dst.ssi_status     = src.si_status;
    dst.ssi_int        = src.si_int;
    dst.ssi_ptr        = (uint64_t)src.si_ptr;
    dst.ssi_utime      = src.si_utime;
    dst.ssi_stime      = src.si_stime;
    dst.ssi_addr       = (uint64_t)src.si_addr;
    dst.ssi_addr_lsb   = src.si_addr_lsb;
    dst.ssi_syscall    = src.si_syscall;
    dst.ssi_call_addr  = (uint64_t)src.si_call_addr;
    dst.ssi_arch       = src.si_arch;
}

ssize_t SignalFdFile::read_once(VThread *vthread, void *buf, size_t len) {
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    size_t n = len / sizeof(struct signalfd_siginfo);
    struct signalfd_siginfo *si = (struct signalfd_siginfo *)buf;
    ssize_t i = 0;
    struct signalfd_siginfo info;
    for (auto it = vthread->pending_signals.begin(); it != vthread->pending_signals.end() && i < n; ) {
        auto next = std::next(it);
        if (!(build_signal_mask(it->si_signo) & mask)) {
            it = next;
            continue;
        }
        copy_signal_fd_info(info, *it);
        try {
            mm->copy_to_sandbox(si, &info, sizeof(struct signalfd_siginfo));
        } catch (FaultException &e) {
            return -EFAULT;
        }
        ++i;
        ++si;
        vthread->pending_signals.erase(it);
        it = next;
    }
    for (auto it = vprocess->pending_signals.begin(); it != vprocess->pending_signals.end() && i < n; ) {
        auto next = std::next(it);
        if (!(build_signal_mask(it->si_signo) & mask)) {
            it = next;
            continue;
        }
        copy_signal_fd_info(info, *it);
        try {
            mm->copy_to_sandbox(si, &info, sizeof(struct signalfd_siginfo));
        } catch (FaultException &e) {
            return -EFAULT;
        }
        ++i;
        ++si;
        vprocess->pending_signals.erase(it);
        it = next;
    }
    if (i == 0) {
        return -EAGAIN;
    }
    return i * sizeof(struct signalfd_siginfo);
}

uint32_t SignalFdFile::poll(VThread *vthread, uint32_t events) {
    VProcess *vprocess = vthread->get_vprocess();
    std::lock_guard lock(vprocess->signal_mutex);
    if (vprocess->pending_signals.size() || vthread->pending_signals.size()) {
        return EPOLLIN;
    }
    return 0;
}

int SignalFdFile::fcntl(VThread *vthread, int fd, const long *args) {
    int cmd = args[1];
    USwitchContext *ucontext = vthread->get_vprocess()->get_ucontext();
    if (cmd == F_GETFL) {
        int flags;
        ucontext->run_on_behalf_of([&] {
            flags = ::fcntl(fd, F_GETFL);
            if (flags == -1) {
                flags = -errno;
            }
        });
        if (flags < 0) {
            return flags;
        }
        flags &= ~O_NONBLOCK;
        if (nonblock.load(std::memory_order_acquire)) {
            flags |= O_NONBLOCK;
        }
        return flags;
    } else if (cmd == F_SETFL) {
        int flags = args[2];
        bool nonblock_ = flags & O_NONBLOCK;
        flags |= O_NONBLOCK;
        ucontext->run_on_behalf_of([&] {
            flags = ::fcntl(fd, F_SETFL, flags);
            if (flags == -1) {
                flags = -errno;
            }
        });
        if (flags < 0) {
            return flags;
        }
        nonblock.store(nonblock_, std::memory_order_release);
        return 0;
    }
    return 0;
}

int SignalFdFile::ioctl(VThread *vthread, int fd, const long *args) {
    if (args[1] == FIONBIO) {
        MM *mm = vthread->get_vprocess()->get_mm();
        int on;
        try {
            on = mm->get_sandbox<int>((void *)args[2]);
        } catch (FaultException &e) {
            return -EFAULT;
        }
        nonblock.store(on, std::memory_order_release);
        return 0;
    }
    return 0;
}

uint32_t SignalFdFile::get_cap() {
    return Pollable;
}

void SignalFdFile::notify() {
    std::unique_lock lock(mutex);
    wq->wake_all();
    File::notify(EPOLLIN, lock);
}
