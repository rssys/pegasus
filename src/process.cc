#include <unistd.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <asm/prctl.h>
#include "pegasus/mm.h"
#include "pegasus/monitor.h"
#include "pegasus/runtime.h"
#include "pegasus/sched.h"
#include "pegasus/syscall.h"

using namespace pegasus;

long SyscallHandlers::arch_prctl(VThread *thread, int sysno, const long *args, SyscallInfo *info){
    int code = (int)args[0];
    uintptr_t addr = (uintptr_t)args[1];
    if (code == ARCH_GET_FS) {
        try {
            thread->get_vprocess()->get_mm()->put_sandbox(thread->get_saved_state().cpu_state.fs, (void *)addr);
        } catch (FaultException&) {
            return -EFAULT;
        }
        return 0;
    } else if (code == ARCH_SET_FS) {
        thread->get_saved_state().cpu_state.fs = addr;
        return 0;
    }
    return -EINVAL;
}

long SyscallHandlers::exit_group(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    int status = (int)args[0];
    thread->get_vprocess()->kill(status);
    return 0;
}

long SyscallHandlers::exit(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    thread->set_exit(args[0]);
    return 0;
}

long SyscallHandlers::gettid(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    return thread->get_tid();
}

long SyscallHandlers::getpid(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    return thread->get_vprocess()->get_tgid();
}

long SyscallHandlers::getpgid(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    return -ESRCH;
}

long SyscallHandlers::getpgrp(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    return -ESRCH;
}

long SyscallHandlers::setpgid(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    return -ESRCH;
}

long SyscallHandlers::getppid(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    return thread->get_vprocess()->get_ppid();
}

long SyscallHandlers::getsid(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    return -ESRCH;
}

long SyscallHandlers::prlimit64(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    pid_t pid = (pid_t)args[0];
    (void)pid;
    int resource = (int)args[1];
    const struct rlimit *new_limit = (const struct rlimit *)args[2];
    struct rlimit *old_limit = (struct rlimit *)args[3];
    struct rlimit nl, ol;
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();
    try {
        if (new_limit) {
            mm->copy_from_sandbox(&nl, new_limit, sizeof(struct rlimit));
        }
        if (old_limit) {
            switch (resource) {
            case RLIMIT_STACK:
                ol.rlim_cur = 8192 * 1024;
                ol.rlim_max = 8192 * 1024;
                break;
            case RLIMIT_AS:
            case RLIMIT_DATA:
                ol.rlim_cur = mm->get_size();
                ol.rlim_max = mm->get_size();
                break;
            case RLIMIT_NOFILE:
                ol.rlim_cur = 1048576;
                ol.rlim_max = 1048576;
                break;
            default:
                ol.rlim_cur = RLIM_INFINITY;
                ol.rlim_max = RLIM_INFINITY;
                break;
            }
            mm->copy_to_sandbox(old_limit, &ol, sizeof(struct rlimit));
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }
    return 0;
}

long SyscallHandlers::getrlimit(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    long new_args[6] = {0, args[0], 0, args[1]};
    return prlimit64(thread, SYS_prlimit64, new_args, info);
}

long SyscallHandlers::setrlimit(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    long new_args[6] = {0, args[0], args[1], 0};
    return prlimit64(thread, SYS_prlimit64, new_args, info);
}

long SyscallHandlers::sched_getaffinity(VThread *thread, int sysno,
                                        const long *args, SyscallInfo *info) {
    pid_t pid = args[0];
    size_t cpusetsize = args[1];
    cpu_set_t *pmask = (cpu_set_t *)args[2];
    cpu_set_t mask;
    CPU_ZERO(&mask);
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();
    TaskManager *tm = Runtime::get()->get_tm();
    if (cpusetsize < sizeof(mask)) {
        return -EINVAL;
    }
    cpusetsize = sizeof(mask);
    int maxcpu = cpusetsize * 8;

    std::shared_ptr<Task> task;
    if (pid == 0) {
        task = Executor::get_current_task();
    } else {
        task = tm->get_task(pid);
        if (!task || !task->vthread) {
            return -ESRCH;
        }
        if (task->vthread->get_vprocess() != vprocess) {
            return -EPERM;
        }
    }
    {
        std::lock_guard lock(task->mutex);
        task->affinity.for_each(tm->get_num_executors(), [&] (int e) {
            if (e <= maxcpu) {
                CPU_SET(e, &mask);
            }
            return true;
        });
    }
    try {
        mm->copy_to_sandbox(pmask, &mask, cpusetsize);
    } catch (FaultException &e) {
        return -EFAULT;
    }
    return cpusetsize;
}

long SyscallHandlers::sched_setaffinity(VThread *thread, int sysno,
                                        const long *args, SyscallInfo *info) {
    pid_t pid = args[0];
    size_t cpusetsize = args[1];
    const cpu_set_t *pmask = (const cpu_set_t *)args[2];
    cpu_set_t mask;
    VProcess *vprocess = thread->get_vprocess();
    MM *mm = vprocess->get_mm();
    TaskManager *tm = Runtime::get()->get_tm();
    if (cpusetsize <= 0) {
        return -EINVAL;
    }
    if (cpusetsize > sizeof(mask)) {
        cpusetsize = sizeof(mask);
    }
    try {
        mm->copy_from_sandbox(&mask, pmask, cpusetsize);
    } catch (FaultException &e) {
        return -EFAULT;
    }

    std::shared_ptr<Task> task;
    bool is_current_thread = false;
    if (pid == 0) {
        is_current_thread = true;
        task = Executor::get_current_task();
    } else {
        task = tm->get_task(pid);
        if (!task || !task->vthread) {
            return -ESRCH;
        }
        if (task == Executor::get_current_task()) {
            is_current_thread = true;
        }
        if (task->vthread->get_vprocess() != vprocess) {
            return -EPERM;
        }
    }
    CPUSet affinity;
    size_t num_executors = tm->get_num_executors();
    int n = 0;
    for (size_t i = 0; i < cpusetsize * 8; i++) {
        if (!CPU_ISSET(i, &mask)) {
            continue;
        }
        if (i >= num_executors) {
            return -EINVAL;
        }
        affinity.insert((int)i);
        ++n;
    }
    if (n == 0) {
        return -EINVAL;
    }
    {
        std::lock_guard lock(task->mutex);
        task->affinity = affinity;
    }
    if (is_current_thread) {
        int current_eid = Executor::get_current_executor()->get_eid();
        Executor *new_executor = tm->get_scheduler()->select_task_rq(task, current_eid, 0);
        new_executor->migrate_to();
    }
    return 0;
}

long SyscallHandlers::set_tid_address(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    thread->set_child_tid((int *)args[0]);
    return thread->get_tid();
}

long SyscallHandlers::sched_setparam(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    return 0;
}

long SyscallHandlers::sched_getparam(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    return 0;
}

long SyscallHandlers::sched_getscheduler(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    return SCHED_OTHER;
}

long SyscallHandlers::sched_setscheduler(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    return 0;
}

long SyscallHandlers::sched_get_priority_max(VThread *thread, int sysno,
                                             const long *args, SyscallInfo *info) {
    return 0;
}

long SyscallHandlers::sched_get_priority_min(VThread *thread, int sysno,
                                             const long *args, SyscallInfo *info) {
    return 0;
}

long SyscallHandlers::sched_rr_get_interval(VThread *thread, int sysno,
                                            const long *args, SyscallInfo *info) {
    return -ESRCH;
}

long SyscallHandlers::wait4(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    pid_t pid = args[0];
    int *pwstatus = (int *)args[1];
    int options = args[2];
    struct rusage *rusage = (struct rusage *)args[3];
    (void)rusage;
    int status;
    VProcess *vprocess = vthread->get_vprocess();
    pid_t res = vprocess->wait(pid, &status, options);
    if (res >= 0 && pwstatus) {
        try {
            vprocess->get_mm()->put_sandbox(status, pwstatus);
        } catch (FaultException &e) {
            return -EFAULT;
        }
    }
    return res;
}

long SyscallHandlers::waitid(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int idtype = args[0];
    id_t id = args[1];
    siginfo_t *infop = (siginfo_t *)args[2];
    int options = args[3];
    pid_t pid;
    if (idtype == P_PID) {
        pid = id;
    } else if (idtype == P_PGID) {
        pid = -id;
    } else if (idtype == P_ALL) {
        pid = -1;
    } else {
        return -EINVAL;
    }

    int status;
    VProcess *vprocess = vthread->get_vprocess();
    pid_t res = vprocess->wait(pid, &status, options);
    if (res >= 0 && infop) {
        siginfo_t si = {};
        si.si_pid = res;
        si.si_signo = SIGCHLD;
        if (WIFEXITED(status)) {
            si.si_status = WEXITSTATUS(status);
            si.si_code = CLD_EXITED;
        } else {
            si.si_status = WSTOPSIG(status);
            si.si_code = CLD_KILLED;
        }
         
        try {
            vprocess->get_mm()->copy_to_sandbox(infop, &si, sizeof(si));
        } catch (FaultException &e) {
            return -EFAULT;
        }
    }
    return res;
}

long SyscallHandlers::getcpu(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    unsigned int *pcpu = (unsigned int *)args[0];
    unsigned int *pnode = (unsigned int *)args[1];
    MM *mm = vthread->get_vprocess()->get_mm();
    unsigned int cpu = Executor::get_current_eid();
    unsigned int node = 0;
    try {
        if (pcpu) {
            mm->put_sandbox(cpu, pcpu);
        }
        if (pnode) {
            mm->put_sandbox(node, pnode);
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }
    return 0;
}
