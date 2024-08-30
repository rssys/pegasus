#include <cstring>
#include <sys/mman.h>
#include <linux/sched.h>
#include <sched.h>
#include "pegasus/exception.h"
#include "pegasus/file.h"
#include "pegasus/loader.h"
#include "pegasus/monitor.h"
#include "pegasus/mm.h"
#include "pegasus/runtime.h"
#include "pegasus/sched.h"
#include "pegasus/syscall.h"
#include "pegasus/timer.h"
#include "pegasus/types.h"
#include "pegasus/uswitch.h"

using namespace pegasus;

static constexpr uint64_t SupportedFlags = CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID | CLONE_VM |
    CLONE_FILES | CLONE_FS | CLONE_PARENT | CLONE_PARENT_SETTID  |
    CLONE_SETTLS | CLONE_SIGHAND | CLONE_THREAD | CLONE_VFORK;
static constexpr uint64_t UnsupportedFlags = CLONE_CLEAR_SIGHAND | CLONE_INTO_CGROUP |
    CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWUTS |
    CLONE_PIDFD | CLONE_PTRACE | CLONE_UNTRACED;
static constexpr uint64_t IgnoredFlags = CLONE_DETACHED | CLONE_IO | CLONE_SYSVSEM;
static constexpr uint64_t RequiredFlags = CLONE_VM;
static constexpr uint64_t ThreadFlags = CLONE_FILES | CLONE_FS | CLONE_SIGHAND | CLONE_THREAD;
static constexpr uint64_t RecognizedFlags = SupportedFlags | IgnoredFlags | UnsupportedFlags | CSIGNAL;

long SyscallHandlers::clone(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    uint64_t flags = (uint64_t)args[0];
    uint64_t newsp = (uintptr_t)args[1];
    uint64_t parent_tidptr = (uint64_t)args[2];
    uint64_t child_tidptr = (uint64_t)args[3];
    uint64_t tls = (uint64_t)args[4];
    struct clone_args clone_args;
    clone_args.flags = flags;
    clone_args.stack = newsp;
    clone_args.stack_size = 0;
    clone_args.parent_tid = parent_tidptr;
    clone_args.child_tid = child_tidptr;
    clone_args.tls = tls;
    if ((flags & ~RecognizedFlags) || (flags & UnsupportedFlags)) {
        return -EINVAL;
    }
    if ((flags & RequiredFlags) != RequiredFlags) {
        return -EINVAL;
    }
    int f = flags & ThreadFlags;
    if (f != ThreadFlags && f != 0) {
        return -EINVAL;
    }
    if ((flags & ThreadFlags) && (flags & CLONE_VFORK)) {
        return -EINVAL;
    }
    return vthread->clone(clone_args);
}

long SyscallHandlers::clone3(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    size_t size = args[1];
    struct clone_args clone_args;
    try {
        vthread->get_vprocess()->get_mm()->copy_from_sandbox(&clone_args, (void *)args[0], size);
    } catch (FaultException &e) {
        return -EFAULT;
    }
    uint64_t flags = clone_args.flags;
    if ((flags & ~RecognizedFlags) || (flags & UnsupportedFlags)) {
        return -EINVAL;
    }
    if ((flags & RequiredFlags) != RequiredFlags) {
        return -EINVAL;
    }
    int f = flags & ThreadFlags;
    if (f != ThreadFlags && f != 0) {
        return -EINVAL;
    }
    if ((flags & ThreadFlags) && (flags & CLONE_VFORK)) {
        return -EINVAL;
    }
    return vthread->clone(clone_args);
}

long SyscallHandlers::execve(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    if (!(vprocess->cap & VProcess::CapExec)) {
        return -EPERM;
    }
    using T = const char *;
    T filename = (T)args[0];
    const T *argv = (const T *)args[1];
    const T *envp = (const T *)args[2];
    std::string path;
    std::vector<std::string> cmd_args, envs;
    if (mm->copy_str_from_sandbox(path, filename, PATH_MAX) == -1ull) {
        return -EFAULT;
    }
    std::string buffer;
    static constexpr size_t ArgMax = 1024 * 1024;
    size_t total_size = 0;
    try {
        if (argv) {
            for (size_t i = 0; total_size < ArgMax; ++i) {
                T arg = mm->get_sandbox<T>(&argv[i]);
                if (!arg) {
                    break;
                }
                size_t n = mm->copy_str_from_sandbox(buffer, arg, ArgMax - total_size);
                if (n == -1ull) {
                    return -EFAULT;
                }
                total_size += n;
                cmd_args.push_back(buffer);
            }
        }
        if (envp) {
            for (size_t i = 0; total_size < ArgMax; ++i) {
                T env = mm->get_sandbox<T>(&envp[i]);
                if (!env) {
                    break;
                }
                size_t n = mm->copy_str_from_sandbox(buffer, env, ArgMax - total_size);
                if (n == -1ull) {
                    return -EFAULT;
                }
                total_size += n;
                envs.push_back(buffer);
            }
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }
    try {
        vprocess->execve(path.c_str(), cmd_args, envs);
    } catch(std::bad_alloc &e) {
        return -ENOMEM;
    } catch (std::exception &e) {
        return -ENOENT;
    }
    return 0;
}

long SyscallHandlers::vfork(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    struct clone_args clone_args {};
    clone_args.flags = CLONE_VM | CLONE_VFORK | SIGCHLD;
    return vthread->clone(clone_args);
}

std::shared_ptr<VProcess> VProcess::clone(uint64_t flags) {
    int uswitch_flags = 0;
    std::shared_ptr<FileTable> new_file_table;
    if (flags & CLONE_FILES) {
        uswitch_flags |= USWITCH_CLONE_FD_SHARE;
    } else {
        uswitch_flags |= USWITCH_CLONE_FD_COPY;
    }
    if (flags & CLONE_FS) {
        uswitch_flags |= USWITCH_CLONE_FS_SHARE;
    } else {
        uswitch_flags |= USWITCH_CLONE_FS_COPY;
    }
    std::shared_ptr<USwitchContext> new_ucontext = ucontext->clone(uswitch_flags);
    if (flags & CLONE_FILES) {
        new_file_table = file_table;
    } else {
        new_file_table = file_table->clone(new_ucontext.get());
    }

    std::shared_ptr<VProcess> new_vprocess =
        std::shared_ptr<VProcess>(new VProcess(mm, new_ucontext, ref, network_context, true));
    new_vprocess->cap = cap;
    new_vprocess->rewrite_context = rewrite_context;
    new_vprocess->futex_context = futex_context;
    new_vprocess->file_table = new_file_table;
    new_vprocess->exe_file = exe_file;
    std::weak_ptr<VProcess> new_vp = new_vprocess;
    Executor::get_current_executor()->get_eq().add_event_poll_multishot([new_vp] (int res) {
        std::shared_ptr<VProcess> vprocess = new_vp.lock();
        if (!vprocess) {
            return false;
        }
        return vprocess->get_timer_context()->handle();
    }, new_vprocess->timer_context->get_epfd(), EPOLLIN);
    return new_vprocess;
}

int VThread::clone(struct clone_args &args) {
    if (!(vprocess->cap & VProcess::CapClone)) {
        return -EPERM;
    }
    if (saved_state.enter_type != EnterMonitorType::Signal) {
        return -EINVAL;
    }
    uint64_t flags = args.flags;
    int *child_tid = (int *)args.child_tid;
    std::shared_ptr<VProcess> new_vprocess;
    std::shared_ptr<VThread> vthread;
    std::shared_ptr<Task> task;
    std::shared_ptr<Task> current_task = Executor::get_current_task();
    TaskManager *tm;
    int tid;
    bool is_creating_thread = (flags & ThreadFlags) == ThreadFlags;
    if (!is_creating_thread && (flags & CSIGNAL) != SIGCHLD) {
        return -EINVAL;
    }

    std::unique_lock lock(vprocess->vthread_mutex, std::defer_lock);
    try {
        if (is_creating_thread) {
            vthread = vprocess->create_vthread();
        } else {
            new_vprocess = vprocess->clone(flags);
            vthread = new_vprocess->create_vthread();
            new_vprocess->main_thread = vthread;
        }

        if (!vthread) {
            return -EINVAL;
        }

        if (flags & CLONE_CHILD_CLEARTID) {
            vthread->child_tid = child_tid;
        }

        VThreadEntrypoint entry;
        entry.type = EnterSandboxType::SignalProtected;
        if (flags & CLONE_SETTLS) {
            entry.registers.fs = args.tls;
        } else {
            entry.registers.fs = saved_state.cpu_state.fs;
        }
        uintptr_t frame = copy_signal_frame(vthread->protected_signal_buffer, signal_buffer);
        KernelUContext *uc = (KernelUContext *)frame;
        if (args.stack) {
            uc->uc_mcontext.rsp = args.stack + args.stack_size;
        } else {
            uc->uc_mcontext.rsp = get_rsp();
        }
        uc->uc_mcontext.rax = 0;

        tm = Runtime::get()->get_tm();
        task = tm->create_task([entry] {
            Executor::get_current_task()->vthread->run(entry);
        });
        if (!task) {
            throw std::bad_alloc();
        }
        {
            std::lock_guard lock(current_task->mutex);
            task->affinity = current_task->affinity;
        }
        vthread->set_task(task);
        task->vthread = vthread;
        tid = task->tid;
        if (new_vprocess) {
            new_vprocess->tgid = tid;
            new_vprocess->parent = vprocess;
            std::lock_guard lock(vprocess->vthread_mutex);
            vprocess->children.emplace(tid, new_vprocess);
        }
        if (flags & CLONE_PARENT_SETTID) {
            vprocess->mm->put_sandbox(tid, (void *)args.parent_tid);
        }
        if (flags & CLONE_CHILD_SETTID) {
            vprocess->mm->put_sandbox(tid, (void *)args.child_tid);
        }
        Executor::get_current_executor()->get_rq().task_fork(task);
    } catch (FaultException &e) {
        return -EFAULT;
    } catch (std::bad_alloc &e) {
        return -ENOMEM;
    }
    if ((flags & CLONE_VFORK) && new_vprocess) {
        std::unique_lock lock(new_vprocess->vthread_mutex);
        tm->wake_up_new_task(task);
        new_vprocess->exit_wq->add_task(current_task, VProcess::VProcessVfork, false);
        lock.unlock();
        Executor::block();
    } else {
        tm->wake_up_new_task(task);
        //set_work(WorkResched);
    }
    return tid;
}
