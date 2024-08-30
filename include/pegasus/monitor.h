#pragma once
#include <memory>
#include <list>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <condition_variable>
#include <seccomp.h>
#include <linux/time_types.h>
#include "def.h"
#include "lock.h"
#include "rewrite.h"
#include "sched.h"
#include "syscall.h"
#include "types.h"

namespace pegasus {
void init_global();
void init_cpu();

class VThread;
class MM;
struct USwitchContext;
class FutexContext;
struct TaskManagerReference;
class NetworkContext;
class FileTable;
class TimerContext;
class SignalFdFile;
struct MonitorFile;
struct ExecveState {
    std::shared_ptr<MM> mm;
    uintptr_t entry;
    uintptr_t rsp;
};
struct ProxyThread : public std::enable_shared_from_this<ProxyThread> {
    ProxyThread(const std::shared_ptr<USwitchContext> &ucontext_);
    void init();
    void routine();
    void exit();
    std::shared_ptr<USwitchContext> ucontext;
    pid_t tid;
    std::mutex mutex;
    std::condition_variable cv;
    std::unique_ptr<Exception> exception;
    bool ready;
    bool stopped;
    bool exited;
};
class VProcess : public std::enable_shared_from_this<VProcess> {
public:
    static std::shared_ptr<VProcess> create(const std::shared_ptr<MM> &mm_,
                                            const std::shared_ptr<USwitchContext> &ucontext_,
                                            const std::shared_ptr<TaskManagerReference> &ref_,
                                            const std::shared_ptr<NetworkContext> &network_);
    ~VProcess();

    std::shared_ptr<VThread> create_vthread();
    
    std::shared_ptr<Task> load_program(const char *filename,
                                       const std::vector<std::string> &args,
                                       const std::vector<std::string> &envs,
                                       const std::unordered_set<int> &affinity = {});
    void start(struct __kernel_timespec *timeout);
    inline MM *get_mm() {
        return mm.get();
    }
    inline USwitchContext *get_ucontext() {
        return ucontext.get();
    }
    inline int get_tgid() {
        return tgid;
    }
    int get_ppid();
    inline bool is_stopped() {
        return stopped;
    }
    inline void enable_dynamic_syscall_rewriting() {
        rewrite_context->enable();
    }
    inline FutexContext *get_futex_context() {
        return futex_context.get();
    }
    inline FileTable *get_file_table() {
        return file_table.get();
    }
    inline NetworkContext *get_network_context() {
        return network_context.get();
    }
    inline TimerContext *get_timer_context() {
        return timer_context.get();
    }
    inline MonitorFile *get_exe_file() {
        return exe_file.get();
    }
    inline std::string &get_exe_path() {
        return exe_path;
    }

    inline SpinLock &get_signal_mutex() {
        return signal_mutex;
    }
    void sigaction(int sig, const KernelSigAction *act, KernelSigAction *oldact);
    bool send_signal(int sig, siginfo_t *info);
    void send_signal_all(int sig);
    void kill(int retval);

    // child processes
    std::shared_ptr<VProcess> clone(uint64_t flags);
    void execve(const char *filename,
                const std::vector<std::string> &args,
                const std::vector<std::string> &env);
    pid_t wait(pid_t pid, int *wstatus, int options);
    void waitall();

    void stop_and_run(const Tasklet &tasklet, bool immediate = false);

    inline pid_t get_proxy_tid() {
        return proxy_thread->tid;
    }

    enum {
        CapClone        = 0x1lu,
        CapFork         = 0x2lu,
        CapKill         = 0x4lu,
        CapExec         = 0x8lu,
        CapVTCPAccept   = 0x10lu,
        CapVTCPConnect  = 0x20lu,
        CapDSocket      = 0x40lu,
        CapVDSO         = 0x80lu,
        CapVSocketPair  = 0x100lu,
        DefaultCap      = 0x315u,
        AllCap          = -1lu,
    };
    uint64_t cap;
    std::function<void (int, int)> on_exit;
    
private:
    friend class VThread;
    friend class SyscallRewriteContext;
    friend class SignalFdFile;

    enum {
        VProcessExit = 1,
        VProcessVfork = 2,
        VProcessWait = 4,
    };

    VProcess(const std::shared_ptr<MM> &mm_,
             const std::shared_ptr<USwitchContext> &ucontext_,
             const std::shared_ptr<TaskManagerReference> &ref_,
             const std::shared_ptr<NetworkContext> &network_,
             bool from_clone = false);
    VProcess(const VProcess &) = delete;
    VProcess &operator=(const VProcess &) = delete;
    void start_task(const std::shared_ptr<Task> &task, struct __kernel_timespec *timeout);
    void init_seccomp();
    void exit();

    std::shared_ptr<MM> mm;
    std::shared_ptr<USwitchContext> ucontext;
    std::shared_ptr<TaskManagerReference> ref;
    std::shared_ptr<MonitorFile> exe_file;
    std::string exe_path;

    scmp_filter_ctx seccomp_ctx;

    SpinLock vthread_mutex;
    std::unordered_map<VThread *, std::weak_ptr<VThread>> vthreads;
    std::weak_ptr<VThread> main_thread;
    std::vector<Tasklet> stop_tasklets;
    std::shared_ptr<WaitQueue> stop_wq;
    std::shared_ptr<WaitQueue> exit_wq;
    std::shared_ptr<ExecveState> execve_state;
    std::unordered_map<pid_t, std::shared_ptr<VProcess>> children;
    std::unordered_map<pid_t, std::shared_ptr<VProcess>> zombie_children;
    std::weak_ptr<VProcess> parent;
    std::shared_ptr<ProxyThread> proxy_thread;
    
    int tgid;
    int retval;
    int retsig;
    bool exited;
    std::atomic_bool stopped;

    // allocator
    SlabAllocator vthread_buffer_allocator;
    SlabAllocator signal_frame_buffer_allocator;

    // signal
    SpinLock signal_mutex;
    KernelSigAction signal_handlers[NumSignals];
    std::list<siginfo_t> pending_signals;
    std::unordered_map<SignalFdFile *, std::weak_ptr<SignalFdFile>> signal_fds;

    // syscall rewrite
    std::shared_ptr<SyscallRewriteContext> rewrite_context;

    // futex
    std::shared_ptr<FutexContext> futex_context;

    // file
    std::shared_ptr<FileTable> file_table;

    // network
    std::shared_ptr<NetworkContext> network_context;

    // timer
    std::shared_ptr<TimerContext> timer_context;
};

struct Task;
class VThread {
public:
    VThread(const std::shared_ptr<VProcess> &vprocess_);
    VThread(const VThread &thread) = delete;
    VThread &operator=(const VThread &) = delete;
    ~VThread();
    void run(const VThreadEntrypoint &entry);
    long invoke_syscall_may_interrupted(int sysno, const long *args, int &sig);
    long invoke_syscall(int sysno, const long *args, bool handle_restart = true);
    void set_task(const std::shared_ptr<Task> &task_);
    inline int get_tid() {
        return tid;
    }
    inline void set_exit(int retval_) {
        retval_ = retval;
        exited = true;
    }
    inline void set_child_tid(int *tid) {
        child_tid = tid;
    }
    enum {
        WorkResched = 0x1u,
        WorkFixSignalFrame = 0x2u,
        WorkSyscallRestart = 0x4u,
    };
    inline void set_work(uint32_t work_) {
        work |= work_;
    }
    inline void clear_work(uint32_t work_) {
        work &= ~work_;
    }
    inline bool has_work(uint32_t work_) {
        return work & work_;
    }

    // signal handling
    inline void sigreturn() {
        saved_state.resume_type = EnterSandboxType::VSignalReturn;
    }
    int sigaltstack(const stack_t *ss, stack_t *old_ss);
    void sigprocmask(int how, const uint64_t *set, uint64_t *old_set);
    void sigpending(uint64_t *set);
    int pop_pending_signal(uint64_t set, siginfo_t *info, bool sandbox_mem = true);
    bool send_signal(int sig, siginfo_t *info);
    void force_signal(int sig, siginfo_t *info);
    inline void set_restart(const std::function<long (VThread *)> &func = nullptr) {
        set_work(WorkSyscallRestart);
        restart_syscall_func = func;
    }
    inline long restart_syscall() {
        if (restart_syscall_func) {
            return restart_syscall_func(this);
        }
        return -EINTR;
    }

    // clone
    int clone(struct clone_args &args);

    bool check_stop(const std::shared_ptr<Task> &task);

    inline VProcess *get_vprocess() {
        return vprocess.get();
    }
    inline VThreadState &get_saved_state() {
        return saved_state;
    }

private:
    friend class VProcess;
    friend class SyscallRewriteContext;
    friend class SignalFdFile;

    void run_vthread(const VThreadEntrypoint &entry);
    void exit();
    void execve();
    void on_signal();
    long on_signal_syscall(VThreadState &state);
    void validate_signal(uintptr_t new_rsp, uintptr_t new_fpstate,
                         size_t fpstate_size, uintptr_t xfeatures);
    uintptr_t copy_signal_frame(const MemoryRegion &to, const MemoryRegion &from);
    uintptr_t copy_vsignal_frame(const MemoryRegion &to, uintptr_t frame);
    uintptr_t copy_protected_signal_frame();
    bool replace_signal_frame_xstate(uintptr_t xstate, uint64_t mask);
    inline uintptr_t get_rsp() {
        if (saved_state.enter_type == EnterMonitorType::MonitorCall) {
            return saved_state.cpu_state.rsp;
        } else if (saved_state.enter_type == EnterMonitorType::SyscallRewrite) {
            return saved_state.rewrite_state.gregs->rsp;
        }
        KernelUContext *ctx = saved_state.signal_state.get_uc();
        return ctx->uc_mcontext.rsp;
    }
    uintptr_t get_signal_rsp(bool onstack);
    SignalState write_vsignal_frame_from_signal(const siginfo_t *alt_info,
                                                bool restartable, bool onstack);
    SignalState write_vsignal_frame_from_monitor_call(int sig, const siginfo_t *info,
                                                      bool restartable, bool onstack);
    SignalState write_vsignal_frame_from_syscall_rewrite(int sig, const siginfo_t *info,
                                                         bool restartable, bool onstack);

    void resume_sandbox_call(CPUState *registers);
    void resume_signal(CPUState *registers, uintptr_t frame);

    void handle_monitor_call();
    void handle_signal();
    void handle_sigsys();
    void handle_sigsegv();
    void handle_sigtrap();
    void handle_signal_syscall(int sig);
    void handle_signal_race(int sig);
    void pass_signal();
    void check_vsignal();
    void handle_vsignal(int sig, const siginfo_t *info, const KernelSigAction &act);
    long handle_syscall(int sysno, const long *args, SyscallInfo *info);

    // saved CPU and signal state
    VThreadState saved_state;
    MemoryRegion buffer;
    MemoryRegion signal_buffer;
    MemoryRegion syscall_signal_buffer;
    MemoryRegion syscall_rewrite_buffer;
    MemoryRegion protected_signal_buffer;
    std::function<long (VThread *)> restart_syscall_func;

    std::shared_ptr<VProcess> vprocess;
    std::weak_ptr<Task> task;
    int *child_tid;
    int tid;
    int retval;
    bool exited;
    uint32_t work;

    // signal handling
    KernelStack alternative_signal_stack;
    uint64_t signal_mask;
    std::list<siginfo_t> pending_signals;
};
}