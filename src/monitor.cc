#include <thread>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <csignal>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <asm/prctl.h>
#include <linux/uswitch.h>
#include <seccomp.h>
#include "pegasus/breakpoint.h"
#include "pegasus/decode.h"
#include "pegasus/def.h"
#include "pegasus/exception.h"
#include "pegasus/futex.h"
#include "pegasus/gate.h"
#include "pegasus/loader.h"
#include "pegasus/mm.h"
#include "pegasus/monitor.h"
#include "pegasus/rewrite.h"
#include "pegasus/runtime.h"
#include "pegasus/sched.h"
#include "pegasus/sigframe.h"
#include "pegasus/stat.h"
#include "pegasus/syscall.h"
#include "pegasus/trace.h"
#include "pegasus/timer.h"
#include "pegasus/uswitch.h"
#include "pegasus/vdso.h"
#include "pegasus/wait_queue.h"
#include "pegasus/network/network.h"

#if defined(__GLIBC__) && __GLIBC_MINOR__ >= 34
#include <sys/rseq.h>
#endif

#define SA_RESTORER 0x04000000
#define SS_AUTODISARM (1 << 31)

using namespace pegasus;

static struct CPUProfile {
    size_t xstate_pkru_offset;
    size_t xstate_xmm_offset;
    uint64_t xcr0;
    uint32_t mxcsr_mask;
    std::vector<size_t> xstate_offsets;
    std::vector<size_t> xstate_sizes;
} cpu_profile;

static void init_cpu_profile() {
    int offset;
    uint64_t xcr0;
#ifndef CONFIG_DISABLE_MPK
    asm volatile (
        "movl $0x0d, %%eax\n"
        "movl $9, %%ecx\n"
        "cpuid\n"
        : "=b" (offset) :: "eax", "ecx", "edx"
    );
#else
    asm volatile (
        "movl $0x0d, %%eax\n"
        "movl $2, %%ecx\n"
        "cpuid\n"
        : "=b" (offset) :: "eax", "ecx", "edx"
    );
    offset += 256 - 8;
#endif
    cpu_profile.xstate_pkru_offset = offset;
    asm volatile (
        "movl $0x0d, %%eax\n"
        "movl $1, %%ecx\n"
        "cpuid\n"
        : "=b" (offset) :: "eax", "ecx", "edx"
    );
    cpu_profile.xstate_xmm_offset = offset;
    asm volatile (
        "xorl %%ecx, %%ecx\n"
        "xgetbv\n"
        : "=A" (xcr0) :: "ecx"
    );
    cpu_profile.xcr0 = xcr0;
    uint8_t buf[512 + 16];
    uintptr_t p = (uintptr_t)&buf;
    p = (p + 16) & (~15ull);
    asm volatile ("fsave %0" : "+m"(*(uint8_t *)p));
    uint32_t mxcsr_mask = *(uint32_t *)(p + 28);
    if (mxcsr_mask == 0) {
        mxcsr_mask = 0xffbf;
    }
    cpu_profile.mxcsr_mask = mxcsr_mask;

    cpu_profile.xstate_offsets.resize(64);
    cpu_profile.xstate_sizes.resize(64);
    for (int i = 0; i < 64; ++i) {
        if (!(xcr0 & (1ul << i))) {
            continue;
        }
        int offset;
        int size = 0x0d;
        asm volatile (
            "movl %0, %%ecx\n"
            "cpuid\n"
            : "=b" (offset), "+a" (size) : "r" (i) : "ecx", "edx"
        );
        cpu_profile.xstate_offsets[i] = offset;
        cpu_profile.xstate_sizes[i] = offset;
    }
}

// we need to hook pthread_create to clear gs base address when creating new thread
// so we can know whether TCB is initialized
extern "C" int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*routine)(void *), void *arg) {
    static int (*real_pthread_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *) = nullptr;
    if (!real_pthread_create) {
        real_pthread_create = (decltype(real_pthread_create))dlsym(RTLD_NEXT, "pthread_create");
        if (!real_pthread_create) {
            return EOPNOTSUPP;
        }
    }

    uintptr_t gs = get_gsbase();
    if (syscall(SYS_arch_prctl, ARCH_SET_GS, nullptr) < 0) {
        return errno;
    }
    int res = real_pthread_create(thread, attr, routine, arg);
    if (syscall(SYS_arch_prctl, ARCH_SET_GS, gs) < 0) {
        return errno;
    }
    return res;
}

#ifdef CONFIG_DISABLE_MPK
int pkey_mprotect(void *addr, size_t len, int prot, int pkey) {
    return mprotect(addr, len, prot);
}
#endif

static void init_per_cpu_data() {
    if (per_cpu_initialized()) {
        return;
    }
    void *tcb_mem = mmap(nullptr, PAGE_SIZE * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tcb_mem == MAP_FAILED) {
        throw Exception("failed to reserve memory for per-CPU data");
    }
    if (mmap(tcb_mem, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != tcb_mem) {
        throw Exception("failed to allocate memory for public per-CPU data");
    }
    void *shared_pub_percpu = (void *)((uintptr_t)tcb_mem + PAGE_SIZE * 2);
    if (mremap(tcb_mem, 0, PAGE_SIZE, MREMAP_FIXED | MREMAP_MAYMOVE, shared_pub_percpu) != shared_pub_percpu) {
        throw Exception("failed to share public per-CPU data");
    }
    if (pkey_mprotect(tcb_mem, PAGE_SIZE, PROT_READ | PROT_WRITE, PkeyReadonly) == -1) {
        throw Exception("failed to set pkey for private per-CPU data");
    }

    void *p = mmap(nullptr, PAGE_SIZE * 2, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) {
        throw Exception("failed to allocate per-CPU signal buffer");
    }
    if (pkey_mprotect(p, PAGE_SIZE, PROT_READ | PROT_WRITE, PkeyReadonly) == -1) {
        throw Exception("failed to allocate per-CPU signal buffer");
    }

    size_t fast_call_stack_size = PAGE_SIZE * 4;
    uint8_t *fast_call_stack = (uint8_t *)mmap(nullptr, fast_call_stack_size,PROT_READ | PROT_WRITE,
                                            MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if (fast_call_stack == MAP_FAILED) {
        throw Exception("failed to allocate per-CPU fast call stack");
    }

    new (tcb_mem) PerCPUPublicData;
    uintptr_t priv_addr = (uintptr_t)tcb_mem + PAGE_SIZE;
    new ((void *)priv_addr) PerCPUPrivateData;

    PerCPUPrivateData *priv = (PerCPUPrivateData *)priv_addr;
    priv->signal_buffer.base = (uint8_t *)p;
    priv->signal_buffer.size = PAGE_SIZE * 2;
    priv->fast_call_rsp = fast_call_stack + fast_call_stack_size - 8;
    priv->fast_call_handler = pegasus_handle_fast_call;
    priv->cwm = new CleanupWorkManager;
    PerCPUPublicData *pub = (PerCPUPublicData *)tcb_mem;
    pub->monitor_call_entry = (uintptr_t)pegasus_gate_monitor_call;
    pub->syscall_rewrite_entry = (uintptr_t)pegasus_gate_syscall_rewrite;
    pub->fast_call_entry = (uintptr_t)pegasus_gate_fast_call;

#ifdef CONFIG_ENABLE_TIME_TRACE
    const MemoryRegion &trace_buffer = Runtime::get()->get_trace_buffer();
    pub->tracer_entry = (uintptr_t)pegasus_gate_trace_time;
    pub->trace_buffer = trace_buffer.base;
    pub->trace_buffer_size = trace_buffer.size;
#endif

    if (syscall(SYS_arch_prctl, ARCH_SET_GS, tcb_mem) == -1) {
        throw Exception("failed to set gs base address");
    }
}

static void init_global_mpk() {
#ifndef CONFIG_DISABLE_MPK
    for (int i = 1; i < 16; ++i) {
        if (pkey_alloc(0, 0) == -1) {
            throw Exception("failed to allocate pkey");
        }
    }
#endif
}

static void raise_signal(int sig) {
    fprintf(stderr, "priv signal: %d\n", sig);
    struct sigaction act;
    act.sa_flags = 0;
    act.sa_handler = SIG_DFL;
    sigaction(sig, &act, nullptr);
    sigset_t set;
    sigemptyset(&set);
    sigprocmask(SIG_SETMASK, &set, nullptr);
    if (sig == SIGABRT || sig == SIGSEGV) {
        return;
    }
    raise(sig);
    exit(sig + 128);
}

extern "C" void pegasus_signal_trampoline(int sig, void *info, void *ucontext);

extern "C" void pegasus_handle_monitor_signal(int sig, siginfo_t *info, void *ucontext) {
    if (per_cpu_initialized()) {
        if (GET_PER_CPU_PRIV(signal_fixup_mask) & build_signal_mask(sig)) {
            ucontext_t *uc = (ucontext_t *)ucontext;
            uc->uc_mcontext.gregs[REG_RIP] = GET_PER_CPU_PRIV(signal_fixup_rip);
            uc->uc_mcontext.gregs[REG_RSP] = GET_PER_CPU_PRIV(signal_fixup_rsp);
        } else if (GET_PER_CPU_PRIV(signal_exception_mask) & build_signal_mask(sig)) {
            if (sig == SIGSEGV) {
                uintptr_t addr = (uintptr_t)info->si_addr;
                throw FaultException(addr, addr);
            } else {
                throw SignalException(sig);
            }
        }
    }
    if (sig == SIGURG || sig == SIGPIPE || sig == SIGWINCH || sig == SIGCONT || sig == SIGCHLD) {
        return;
    }
    if (sig == SIGALRM) {
        SET_PER_CPU_PRIV(alarmed, 1);
        return;
    }
    if (sig == SIGFPE) {
        uintptr_t fpstate = (uintptr_t)(((ucontext_t *)ucontext)->uc_mcontext.fpregs);
        reset_mxcsr(fpstate);
        return;
    }
    if (sig == SIGUSR1) {
        Stat::get().show_and_reset(0);
        Stat::get().show_and_reset(1);
        return;
    }
    if (sig == SIGUSR2) {
        print_recent_log();
#ifdef CONFIG_ENABLE_TIME_TRACE
        const RuntimeConfiguration &config = Runtime::get()->get_config();
        if (config.enable_time_trace) {
            int fd = open(config.trace_output_file.c_str(), O_CREAT | O_WRONLY, 0644);
            if (fd == -1) {
                return;
            }
            const MemoryRegion &buffer = Runtime::get()->get_trace_buffer();
            ssize_t size = write(fd, buffer.base, buffer.size);
            int err = errno;
            close(fd);
            printf("write trace %lu %ld %d\n", buffer.size, size, size == -1 ? err : 0);
        }
#endif
        return;
    }
    raise_signal(sig);
    return;
}

/*
bool debug_syscalls = true;
struct SyscallStatInfo {
    double time;
    uint64_t n;
    SpinLock mutex;
} syscall_stats[512];

static void print_syscall_stats() {
    for (int i = 0; i < 512; ++i) {
        std::unique_lock lock(syscall_stats[i].mutex);
        if (syscall_stats[i].n == 0) {
            continue;
        }
        double t = syscall_stats[i].time;
        uint64_t n = syscall_stats[i].n;
        double avg_time = t / n;
        syscall_stats[i].time = 0;
        syscall_stats[i].n = 0;
        lock.unlock();
        char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_X86_64, i);
        printf("%ld\t%ld\t\t%s\n", (long)avg_time, (long)(t / 1000000), name);
        free(name);
    }
}
*/
static void init_global_signal() {
    for (int sig = 1; sig <= NumSignals; ++sig) {
        if (sig == SIGKILL || sig == SIGSTOP/* || sig == SIGSEGV*/) {
            continue;
        }
        KernelSigAction action, old_action;
        if (sig == SIGPIPE) {
            action.sa_flags = 0;
            action.sa_handler_ = SIG_IGN;
            action.sa_mask = 0;
        } else {
            action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTORER | SA_RESTART | SA_NOCLDWAIT;
            action.sa_mask = -1ul;
            action.sa_sigaction_ = pegasus_signal_trampoline;
            action.sa_restorer = (void *)pegasus_sig_restorer;
        }
        if (syscall(SYS_rt_sigaction, sig, &action, &old_action, sizeof(action.sa_mask)) != 0) {
            throw Exception("failed to set signal handler for sig " + std::to_string(sig));
        }
    }
}

void pegasus::init_global() {
    static bool has_init;
    if (has_init) {
        return;
    }

    init_decoder();
    init_global_mpk();
    init_per_cpu_data();
    init_global_uswitch();
    SyscallRewriteContext::init_global();

    // we create a thread to ensure glibc initializes signal handler for SIG_RT1
    std::thread th([] {});
    th.join();

    init_global_signal();
    init_cpu_profile();
    init_vdso();
    
}

void pegasus::init_cpu() {
    init_per_cpu_data();
    init_cpu_uswitch();
    BreakpointManager *bpm = Runtime::get()->get_bpm();
    if (bpm) {
        bpm->init_cpu();
    }
    IOWorker *iow = Runtime::get()->get_tm()->get_ioworker();
    if (iow) {
        iow->init_cpu();
    }

#ifdef __GLIBC_HAVE_KERNEL_RSEQ
    uintptr_t thread_pointer = (uintptr_t)__builtin_thread_pointer();
    uintptr_t rseq_addr = thread_pointer + __rseq_offset;
    struct rseq *rseq = (struct rseq *)rseq_addr;
    syscall(SYS_rseq, rseq, sizeof(struct rseq), RSEQ_FLAG_UNREGISTER, RSEQ_SIG);
#endif

    pegasus_safe_wrpkru(0);
}

// ================================ vprocess =================================

static constexpr size_t VThreadBufferSize = PAGE_SIZE * 6;
static constexpr size_t ProtectedSignalBufferSize = PAGE_SIZE * 2;

VProcess::VProcess(const std::shared_ptr<MM> &mm_,
                   const std::shared_ptr<USwitchContext> &ucontext_,
                   const std::shared_ptr<TaskManagerReference> &ref_,
                   const std::shared_ptr<NetworkContext> &network_,
                   bool from_clone)
    : mm(mm_), ucontext(ucontext_), ref(ref_),
      stop_wq(new WaitQueue()), exit_wq(new WaitQueue()),
      tgid(-1), retval(0), retsig(0), exited(false), stopped(false),
      vthread_buffer_allocator(VThreadBufferSize, 512),
      signal_frame_buffer_allocator(ProtectedSignalBufferSize, 512),
      rewrite_context(from_clone ? nullptr : std::make_shared<SyscallRewriteContext>()),
      futex_context(from_clone ? nullptr : std::make_shared<FutexContext>()),
      file_table(from_clone ? nullptr : std::make_shared<FileTable>()),
      network_context(network_),
      timer_context(std::make_shared<TimerContext>()) {
    seccomp_ctx = seccomp_init(SCMP_ACT_TRAP);
    if (!seccomp_ctx) {
        throw Exception("failed to init seccomp");
    }
    memset(signal_handlers, 0, sizeof(signal_handlers));
    for (int i = 0; i < NumSignals; ++i) {
        signal_handlers[i].sa_handler_ = SIG_DFL;
    }

    vthread_buffer_allocator.page_allocator = [this] (size_t num_pages) {
        intptr_t res = mm->mmap(0, num_pages * PAGE_SIZE, PROT_READ | PROT_WRITE,
                                MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, true, true);
        if (res < 0 && res >= -4096) {
            return MAP_FAILED;
        }
        return (void *)res;
    };
    vthread_buffer_allocator.page_deallocator = [this] (void *ptr, size_t num_pages) {
        mm->munmap((uintptr_t)ptr, num_pages * PAGE_SIZE, true);
    };
    proxy_thread = std::make_shared<ProxyThread>(ucontext);
    proxy_thread->init();
}

VProcess::~VProcess() {
    proxy_thread->exit();
    seccomp_release(seccomp_ctx);
}

std::shared_ptr<VProcess> VProcess::create(const std::shared_ptr<MM> &mm_,
                                           const std::shared_ptr<USwitchContext> &ucontext_,
                                           const std::shared_ptr<TaskManagerReference> &ref_,
                                           const std::shared_ptr<NetworkContext> &network_) {
    return std::shared_ptr<VProcess>(new VProcess(mm_, ucontext_, ref_, network_));
}

std::shared_ptr<VThread> VProcess::create_vthread() {
    std::shared_ptr<VThread> vthread(new VThread(shared_from_this()));
    std::lock_guard lock(vthread_mutex);
    vthreads[vthread.get()] = vthread;
    return vthread;
}

std::shared_ptr<Task> VProcess::load_program(const char *filename,
                                             const std::vector<std::string> &args,
                                             const std::vector<std::string> &envs,
                                             const std::unordered_set<int> &affinity) {
    init_seccomp();
    std::shared_ptr<VThread> vthread = create_vthread();
    main_thread = vthread;
    ELFLoader loader;
    loader.mm = mm.get();
    uintptr_t program_entry, rsp;
    FileDescriptor exe_fd;
    ucontext->run_on_behalf_of([&] {
        MonitorFile file;
        program_entry = loader.load_program(filename, args, envs, file, exe_path, nullptr, 0, cap & CapVDSO);
        exe_fd.fd = file.fd;
        file.fd = -1;
        exe_fd.ucontext = ucontext.get();
    });
    std::shared_ptr<MonitorFile> exe_file_ = std::make_shared<MonitorFile>();
    exe_file_->fd = ucontext->get_file(exe_fd.fd);
    if (exe_file_->fd == -1) {
        throw Exception("failed to get exe file\n");
    }
    exe_file = std::move(exe_file_);
    rsp = loader.stack;
    TaskManager *tm = Runtime::get()->get_tm();
    std::shared_ptr<Task> task = tm->create_task([this, vthread, program_entry, rsp] {
        VThreadEntrypoint entry;
        memset(&entry, 0, sizeof(VThreadEntrypoint));
        entry.type = EnterSandboxType::SandboxCall;
        entry.registers.rip = program_entry;
        entry.registers.rsp = rsp;
        vthread->run(entry);
    });
    if (!affinity.empty()) {
        CPUSet aff;
        for (int i : affinity) {
            if ((size_t)i >= tm->get_num_executors()) {
                throw Exception("invalid executor id");
            }
            aff.insert(i);
        }
        task->affinity = aff;
    }
    vthread->set_task(task);
    tgid = task->tid;
    task->vthread = vthread;
    return task;
}

void VProcess::stop_and_run(const Tasklet &tasklet, bool immediate) {
    struct StopVProcessTasklet {
        std::atomic_int n;
        int num_executors;
        std::weak_ptr<VProcess> vprocess;
        void operator()() {
            if (++n != num_executors) {
                return;
            }
            std::shared_ptr<VProcess> p = vprocess.lock();
            if (!p) {
                return;
            }
            std::lock_guard lock(p->vthread_mutex);
            for (auto &t : p->stop_tasklets) {
                t();
            }
            p->stop_tasklets.clear();
            p->stopped.store(false, std::memory_order_release);
            p->stop_wq->wake_all();
        }
    };
    std::unique_lock lock(vthread_mutex);
    if (!stop_tasklets.empty()) {
        stop_tasklets.push_back(tasklet);
        return;
    }
    stop_tasklets.push_back(tasklet);
    lock.unlock();

    stopped.store(true, std::memory_order_release);
    // from this point no new task of current vprocess will be scheduled in

    TaskManager *tm = Runtime::get()->get_tm();
    std::shared_ptr<StopVProcessTasklet> stop_tasklet = std::make_shared<StopVProcessTasklet>();
    int n = tm->get_num_executors();
    std::vector<int> executors_running;
    for (int i = 0; i < n; ++i) {
        Executor *executor = tm->get_executor(i);
        ReadyQueue &rq = executor->get_rq();
        std::lock_guard lock(rq.get_mutex());
        std::shared_ptr<Task> curr = rq.get_curr();
        if (curr && curr->vthread && curr->vthread->vprocess.get() == this) {
            executors_running.push_back(i);
        }
    }

    if (executors_running.empty()) {
        executors_running.push_back(Executor::get_current_eid());
    }

    stop_tasklet->n.store(0, std::memory_order_release);
    stop_tasklet->num_executors = (int)executors_running.size();
    stop_tasklet->vprocess = weak_from_this();
    for (int &e : executors_running) {
        Executor *executor = tm->get_executor(e);
        executor->add_tasklet([stop_tasklet] {
            (*stop_tasklet)();
        });
        if (immediate) {
            executor->send_reschedule();
        }
    }

    if (immediate) {
        Executor::schedule();
    }
}

void VProcess::start(struct __kernel_timespec *timeout) {
    std::shared_ptr<VThread> mt = main_thread.lock();
    std::shared_ptr<Task> task = mt->task.lock();
    
    int current_eid = 0;
    if (Executor::get_current_executor()) {
        current_eid = Executor::get_current_executor()->get_eid();
    }

    TaskManager *tm = Runtime::get()->get_tm();
    Executor *executor = tm->get_scheduler()->select_task_rq(task, current_eid, 0);
    if (!timeout) {
        tm->wake_up_new_task(task);
    } else {
        task->executor = executor;
        executor->get_eq().add_task_timeout(task, timeout);
        task->mutex.unlock();
    }
    std::weak_ptr<VProcess> self = shared_from_this();
    executor->get_eq().add_event_poll_multishot([self] (int res) {
        std::shared_ptr<VProcess> vprocess = self.lock();
        if (!vprocess) {
            return false;
        }
        return vprocess->get_timer_context()->handle();
    }, timer_context->get_epfd(), EPOLLIN);
}

void VProcess::init_seccomp() {
    for (int s : PassthroughSyscalls) {
        int res = seccomp_rule_add(seccomp_ctx, SCMP_ACT_ALLOW, s, 0);
        if (res != 0) {
            throw SystemException(-res);
        }
    }

    int res = seccomp_attr_set(seccomp_ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_TRAP);
    if (res != 0) {
        throw SystemException(-res);
    }
    res = seccomp_attr_set(seccomp_ctx, SCMP_FLTATR_CTL_OPTIMIZE, 2);
    if (res != 0) {
        throw SystemException(-res);
    }
    res = seccomp_attr_set(seccomp_ctx, SCMP_FLTATR_CTL_SSB, 1);
    if (res != 0) {
        throw SystemException(-res);
    }
    ucontext->run_on_behalf_of([&] {
        res = seccomp_load(seccomp_ctx);
    });
    if (res != 0) {
        throw SystemException(-res);
    }
}

void VProcess::exit() {
    uid_t uid = 0;
    ucontext->run_on_behalf_of([&] {
        uid = getuid();
    });
    proxy_thread->exit();
    timer_context.reset();
    network_context.reset();
    file_table.reset();
    futex_context.reset();
    ucontext.reset();
    std::shared_ptr<VProcess> p;
    {
        std::lock_guard lock(vthread_mutex);
        exit_wq->wake_all(VProcessVfork);
        p = parent.lock();
    }
    if (p) {
        {
            std::lock_guard lock1(p->vthread_mutex);
            std::unique_lock lock2(vthread_mutex);
            auto it = p->children.find(tgid);
            if (it != p->children.end()) {
                p->zombie_children.emplace(tgid, it->second);
                p->children.erase(it);
            }
            for (auto &&c : children) {
                std::shared_ptr<VProcess> child = c.second;
                {
                    std::lock_guard lock3(child->vthread_mutex);
                    child->parent = p;
                }
                p->children.emplace(c.first, child);
            }
            for (auto &&c : zombie_children) {
                std::shared_ptr<VProcess> child = c.second;
                {
                    std::lock_guard lock3(child->vthread_mutex);
                    child->parent = p;
                }
                p->zombie_children.emplace(c.first, child);
            }
            lock2.unlock();
            p->exit_wq->wake_all(VProcessWait);
        }
        siginfo_t si = {};
        si.si_signo = SIGCHLD;
        si.si_code = retval >= 128 ? CLD_KILLED : CLD_EXITED;
        si.si_pid = tgid;
        si.si_status = retval;
        si.si_uid = uid;
        p->send_signal(SIGCHLD, &si);
    } else {
        // init process
        send_signal_all(SIGKILL);
        waitall();
    }
    if (on_exit) {
        on_exit(retval, retsig);
    }
}

int VProcess::get_ppid() {
    std::lock_guard lock(vthread_mutex);
    std::shared_ptr<VProcess> p = parent.lock();
    if (!p) {
        return 0;
    }
    return p->tgid;
}

void VProcess::execve(const char *filename,
                      const std::vector<std::string> &args,
                      const std::vector<std::string> &env) {
    std::shared_ptr<MM> new_mm = std::make_shared<MM>(mm->get_size(), mm->get_pkey(), mm->cap);
    std::shared_ptr<ExecveState> state = std::make_shared<ExecveState>();
    ELFLoader loader;
    loader.mm = new_mm.get();
    FileDescriptor exe_fd;
    ucontext->run_on_behalf_of([&] {
        MonitorFile file;
        state->entry = loader.load_program(filename, args, env, file, exe_path, nullptr, 0, cap & CapVDSO);
        exe_fd.fd = file.fd;
        file.fd = -1;
        exe_fd.ucontext = ucontext.get();
    });
    std::shared_ptr<MonitorFile> exe_file_ = std::make_shared<MonitorFile>();
    exe_file_->fd = ucontext->get_file(exe_fd.fd);
    if (exe_file_->fd == -1) {
        throw Exception("failed to get exe file\n");
    }
    exe_file = std::move(exe_file_);

    state->mm = new_mm;
    state->rsp = loader.stack;
    std::lock_guard lock(vthread_mutex);
    if (execve_state) {
        throw Exception("concurrent execve");
    }
    execve_state = state;
    exited = true;
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

pid_t VProcess::wait(pid_t pid, int *wstatus, int options) {
    std::unique_lock lock(vthread_mutex);
    std::shared_ptr<VProcess> vprocess;
    std::shared_ptr<Task> task = Executor::get_current_task();
    while (true) {
        if (pid <= 0) {
            // TODO: pgid
            if (zombie_children.size()) {
                vprocess = zombie_children.begin()->second;
                zombie_children.erase(zombie_children.begin());
                break;
            }
            if (children.empty()) {
                return -ECHILD;
            }
        } else {
            auto it = zombie_children.find(tgid);
            if (it != zombie_children.end()) {
                vprocess = it->second;
                zombie_children.erase(it);
                break;
            }
            if (!children.count(pid)) {
                return -ECHILD;
            }
        }
        if (options & WNOHANG) {
            return 0;
        }
        exit_wq->add_task(task, VProcessWait);
        lock.unlock();
        Executor::block();
        lock.lock();
        if (task->wq_res.from_signal) {
            return -EINTR;
        }
    }
    if (wstatus) {
        int status = 0;
        if (vprocess->retval < 128) {
            uint8_t ret = (int8_t)vprocess->retval;
            status = ret << 8;
        } else {
            status = retval - 128;
        }
        *wstatus = status;
    }
    return vprocess->tgid;
}

void VProcess::waitall() {
    std::unique_lock lock(vthread_mutex);
    std::shared_ptr<Task> task = Executor::get_current_task();
    while (children.size()) {
        zombie_children.clear();
        exit_wq->add_task(task, VProcessWait);
        lock.unlock();
        Executor::block();
        lock.lock();
    }
    zombie_children.clear();
}

// ================================= vthread =================================

inline static int *read_pkru_from_xsave(const struct _xstate *xstate) {
    return (int *)((uintptr_t)xstate + cpu_profile.xstate_pkru_offset);
}

VThread::VThread(const std::shared_ptr<VProcess> &vprocess_)
    : vprocess(vprocess_), child_tid(nullptr), tid(-1), retval(0), exited(false),
      alternative_signal_stack{nullptr, SS_DISABLE, 0}, signal_mask(0) {
    memset(&saved_state, 0, sizeof(VThreadState));
    void *monitor_mem = vprocess->signal_frame_buffer_allocator.allocate();
    if (!monitor_mem) {
        throw std::bad_alloc();
    }
    void *mem = vprocess->vthread_buffer_allocator.allocate();
    if (!mem) {
        vprocess->signal_frame_buffer_allocator.deallocate(monitor_mem);
        throw std::bad_alloc();
    }
    buffer.base = (uint8_t *)mem;
    buffer.size = VThreadBufferSize;
    signal_buffer.base = buffer.base;
    signal_buffer.size = PAGE_SIZE * 2;
    syscall_signal_buffer.base = buffer.base + PAGE_SIZE * 2;
    syscall_signal_buffer.size = PAGE_SIZE * 2;
    syscall_rewrite_buffer.base = buffer.base + PAGE_SIZE * 4;
    syscall_rewrite_buffer.size = PAGE_SIZE * 2;
    protected_signal_buffer.base = (uint8_t *)monitor_mem;
    protected_signal_buffer.size = ProtectedSignalBufferSize;
}

VThread::~VThread() {
    if (buffer.base) {
        vprocess->vthread_buffer_allocator.deallocate(buffer.base);
    }
    if (protected_signal_buffer.base) {
        vprocess->signal_frame_buffer_allocator.deallocate(protected_signal_buffer.base);
    }
}

void VThread::run(const VThreadEntrypoint &entry) {
    VThreadEntrypoint new_entry;
    const VThreadEntrypoint *e = &entry;
    while (true) {
        try {
            run_vthread(*e);
        } catch (SignalException &e) {
            printf("exception: %d %d %s\n", vprocess->get_tgid(), tid, e.what());
            print_recent_log();
            vprocess->retsig = e.sig;
            vprocess->kill(e.ret);
        } catch (Exception &e) {
            printf("exception: %d %d %s\n", vprocess->get_tgid(), tid, e.what());
            vprocess->kill(e.ret);
        } catch (std::exception &e) {
            printf("exception: %d %d %s\n", vprocess->get_tgid(), tid, e.what());
            vprocess->kill(128);
        } catch (...) {
        }
        exit();
        if (vprocess->tgid != tid || !vprocess->execve_state) {
            break;
        }

        // execve
        try {
            execve();
        } catch (...) {
            vprocess->exit();
            break;
        }
        memset(&new_entry, 0, sizeof(VThreadEntrypoint));
        new_entry.type = EnterSandboxType::SandboxCall;
        new_entry.registers.rip = vprocess->execve_state->entry;
        new_entry.registers.rsp = vprocess->execve_state->rsp;
        vprocess->execve_state.reset();
        e = &new_entry;
    }
}

long VThread::invoke_syscall_may_interrupted(int sysno, const long *args, int &sig) {
    sig = -1;
    CPUState registers;
    VThreadState state;
    state.cpu_state.rax = sysno;
    state.cpu_state.rdi = args[0];
    state.cpu_state.rsi = args[1];
    state.cpu_state.rdx = args[2];
    state.cpu_state.r10 = args[3];
    state.cpu_state.r8  = args[4];
    state.cpu_state.r9  = args[5];
    USwitchContext *ucontext = vprocess->ucontext.get();

    ucontext->block_signals();
    SET_PER_CPU_PUB(pkru, vprocess->mm->get_pkru());
    SET_PER_CPU_PRIV(monitor_entry, &registers);
    SET_PER_CPU_PRIV(current, &state);    
    SET_PER_CPU_PRIV(mode, ExecutionMode::Syscall);
    ucontext->set_signal_stack((unsigned long)syscall_signal_buffer.base, syscall_signal_buffer.size, SS_AUTODISARM);
    ucontext->switch_to();
    ucontext->use_priv_seccomp();
    EnterMonitorType enter_type = pegasus_gate_resume_syscall(&registers, &state);
    ucontext->use_self_seccomp();
    ucontext->switch_to_priv();
    SET_PER_CPU_PRIV(mode, ExecutionMode::Monitor);
    ucontext->clear_signal_stack();
    ucontext->unblock_signals();

    if (enter_type == EnterMonitorType::Signal) {
        sig = state.signal_state.sig;
        return on_signal_syscall(state);
    }
    return state.cpu_state.rax;
}

long VThread::invoke_syscall(int sysno, const long *args, bool handle_restart) {
    long res;
    int sig;
    while (true) {
        res = invoke_syscall_may_interrupted(sysno, args, sig);
        if (res != -EINTR && res != -ERESTART) {
            break;
        }
        if (pending_signals.size() || exited || vprocess->exited) {
            break;
        }
        handle_signal_syscall(sig);
    }
    if (res == -ERESTART) {
        res = -EINTR;
        set_restart();
    }
    return res;
}

void VThread::set_task(const std::shared_ptr<Task> &task_) {
    task = task_;
    tid = task_->tid;
}

bool VThread::check_stop(const std::shared_ptr<Task> &task) {
    if (vprocess->stopped.load(std::memory_order_acquire)) {
        std::lock_guard lock(vprocess->vthread_mutex);
        if (!vprocess->stopped.load(std::memory_order_acquire)) {
            return false;
        }
        vprocess->stop_wq->add_task(task, -1, false);
        return true;
    }
    return false;
}

static void print_signal_frame(uintptr_t frame) {
    KernelUContext *uc = (KernelUContext *)frame;
    printf("rax: %lx\nrbx: %lx\nrcx: %lx\nrdx: %lx\nrsi: %lx\nrdi: %lx\nrbp: %lx\nrsp: %lx\n"
           "r8:  %lx\nr9:  %lx\nr10: %lx\nr11: %lx\nr12: %lx\nr13: %lx\nr14: %lx\nr15: %lx\n"
           "rip: %lx\nrflags: %lx\n",
           uc->uc_mcontext.rax, uc->uc_mcontext.rbx, uc->uc_mcontext.rcx, uc->uc_mcontext.rdx,
           uc->uc_mcontext.rsi, uc->uc_mcontext.rdi, uc->uc_mcontext.rbp, uc->uc_mcontext.rsp,
           uc->uc_mcontext.r8, uc->uc_mcontext.r9, uc->uc_mcontext.r10, uc->uc_mcontext.r11,
           uc->uc_mcontext.r12, uc->uc_mcontext.r13, uc->uc_mcontext.r14, uc->uc_mcontext.r15,
           uc->uc_mcontext.rip, uc->uc_mcontext.eflags);
}

void VThread::run_vthread(const VThreadEntrypoint &entry) {
    CPUState registers;
    EnterMonitorType enter_type;
    EnterSandboxType resume_type = entry.type;
    if (resume_type == EnterSandboxType::SandboxCall) {
        memcpy(&saved_state.cpu_state, &entry.registers, sizeof(MonitorCallCPUState));
    } else if (resume_type == EnterSandboxType::SignalProtected) {
        memset(&saved_state.cpu_state, 0, sizeof(MonitorCallCPUState));
        saved_state.cpu_state.fs = entry.registers.fs;
    }
    while (true) {
        uintptr_t frame;
        bool resume_from_signal = false;
        //Executor::get_current_executor()->poll_fast();
        //Stat::get().add(0, has_work(WorkResched));
        if (has_work(WorkResched)) {
            Executor::schedule();
        }
        if (exited || vprocess->exited) {
            break;
        }
        switch(resume_type) {
        case EnterSandboxType::SandboxCall:
        case EnterSandboxType::VSignalEnter:
            resume_from_signal = false;
            break;
        case EnterSandboxType::VSignalReturn:
            frame = copy_vsignal_frame(PER_CPU_PRIV_REF(signal_buffer), get_rsp() - 8);
            resume_from_signal = true;
            break;
        case EnterSandboxType::Signal:
            frame = copy_signal_frame(PER_CPU_PRIV_REF(signal_buffer), signal_buffer);
            resume_from_signal = true;
            break;
        case EnterSandboxType::SignalProtected:
            frame = copy_protected_signal_frame();
            resume_from_signal = true;
            break;
        }

        if (resume_from_signal) {
            if (has_work(WorkFixSignalFrame)) {
                KernelUContext *uc = (KernelUContext *)frame;
                vprocess->rewrite_context->fix_signal_frame(this, &uc->uc_mcontext);
            }
        }

        // WorkFixSignalFrame cannot be clear once set
        work &= WorkFixSignalFrame;

        if (resume_from_signal) {
            resume_signal(&registers, frame);
        } else {
            resume_sandbox_call(&registers);
        }

        if (int cpu_work = GET_PER_CPU_PRIV(work)) {
            if (cpu_work & PerCPUPrivateData::WorkCleanup) {
                GET_PER_CPU_PRIV(cwm)->check();
            }
        }

        enter_type = saved_state.enter_type;

        if (enter_type == EnterMonitorType::MonitorCall) {
            handle_monitor_call();
        } else if (enter_type == EnterMonitorType::Signal) {
            handle_signal();
        } else if (enter_type == EnterMonitorType::Race) {
            handle_signal_race(saved_state.signal_state.sig);
            resume_type = EnterSandboxType::Signal;
            continue;
        }

        check_vsignal();

        resume_type = saved_state.resume_type;
    }
}

void VThread::exit() {
    if (buffer.base) {
        vprocess->vthread_buffer_allocator.deallocate(buffer.base);
        buffer.base = nullptr;
    }
    std::unique_lock lock(vprocess->vthread_mutex);
    vprocess->vthreads.erase(this);
    lock.unlock();
    if (child_tid) {
        try {
            vprocess->mm->put_sandbox<int>(0, child_tid);
            vprocess->futex_context->wake(this, (uint32_t *)child_tid, 1, -1u);
        } catch (...) {
        }
    }
    exited = true;
    lock.lock();
    if (vprocess->vthreads.empty()) {
        vprocess->exit_wq->wake_all(VProcess::VProcessExit);
    }
    if (tid == vprocess->tgid) {
        std::shared_ptr<Task> task = Executor::get_current_task();
        while (!vprocess->vthreads.empty()) {
            vprocess->exit_wq->add_task(task, VProcess::VProcessExit, false);
            lock.unlock();
            Executor::block();
            lock.lock();
        }
        if (!vprocess->execve_state) {
            lock.unlock();
            vprocess->exit();
        } else {
            vprocess->vthreads.emplace(this, vprocess->main_thread);
            vprocess->exit_wq->wake_all(VProcess::VProcessVfork);
            lock.unlock();
        }
    }
}

void VThread::execve() {
    if (buffer.base) {
        vprocess->vthread_buffer_allocator.deallocate(buffer.base);
        buffer.base = nullptr;
    }
    vprocess->vthread_buffer_allocator.reset();
    vprocess->mm = vprocess->execve_state->mm;
    MM *mm = vprocess->get_mm();
    vprocess->vthread_buffer_allocator.page_allocator = [mm] (size_t num_pages) {
        intptr_t res = mm->mmap(0, num_pages * PAGE_SIZE, PROT_READ | PROT_WRITE,
                                MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, true, true);
        if (res < 0 && res >= -4096) {
            return MAP_FAILED;
        }
        return (void *)res;
    };
    vprocess->vthread_buffer_allocator.page_deallocator = [mm] (void *ptr, size_t num_pages) {
        mm->munmap((uintptr_t)ptr, num_pages * PAGE_SIZE, true);
    };
    void *mem = vprocess->vthread_buffer_allocator.allocate();
    if (!mem) {
        throw std::bad_alloc();
    }
    buffer.base = (uint8_t *)mem;
    buffer.size = VThreadBufferSize;
    signal_buffer.base = buffer.base;
    signal_buffer.size = PAGE_SIZE * 2;
    syscall_signal_buffer.base = buffer.base + PAGE_SIZE * 2;
    syscall_signal_buffer.size = PAGE_SIZE * 2;
    syscall_rewrite_buffer.base = buffer.base + PAGE_SIZE * 4;
    syscall_rewrite_buffer.size = PAGE_SIZE * 2;
    child_tid = nullptr;

    restart_syscall_func = nullptr;
    work = 0;

    {
        std::lock_guard lock(vprocess->signal_mutex);
        memset(vprocess->signal_handlers, 0, sizeof(vprocess->signal_handlers));
        for (int i = 0; i < NumSignals; ++i) {
            vprocess->signal_handlers[i].sa_handler_ = SIG_DFL;
        }
        alternative_signal_stack.ss_sp = nullptr;
        alternative_signal_stack.ss_size = 0;
        alternative_signal_stack.ss_flags = SS_DISABLE;
    }
    {
        std::lock_guard lock(vprocess->vthread_mutex);
        vprocess->stop_tasklets.clear();
    }

    vprocess->rewrite_context = std::make_shared<SyscallRewriteContext>();
    vprocess->futex_context = std::make_shared<FutexContext>();
    vprocess->timer_context->reset();
    exited = false;
    vprocess->exited = false;
}


extern uint8_t pegasus_gate_monitor_call_race_start;
extern uint8_t pegasus_gate_monitor_call_race_end;
extern uint8_t pegasus_gate_monitor_call_race_restart;
extern uint8_t pegasus_gate_resume_sandbox_call_race_start;
extern uint8_t pegasus_gate_resume_sandbox_call_race_end;
extern uint8_t pegasus_gate_fast_call_race1_start;
extern uint8_t pegasus_gate_fast_call_race1_end;
extern uint8_t pegasus_gate_fast_call_race2_start;
extern uint8_t pegasus_gate_fast_call_race2_end;
extern uint8_t __start_pegasus_trusted_code;
extern uint8_t __stop_pegasus_trusted_code;
extern uint8_t pegasus_gate_resume_syscall_race_point;

void VThread::on_signal() {
    KernelUContext *uc = saved_state.signal_state.get_uc();
    uint64_t sigset = 0;
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, &sigset, nullptr, sizeof(sigset));
    if (!check_bound(signal_buffer.base, signal_buffer.size, uc, sizeof(KernelUContext))) {
        throw CorruptedSignalFrameException();
    }
    // detect race conditions
    uintptr_t rip = uc->uc_mcontext.rip;
    if (rip >= (uintptr_t)&__start_pegasus_trusted_code && rip < (uintptr_t)&__stop_pegasus_trusted_code) {
        saved_state.enter_type = EnterMonitorType::Race;
    }
}

long VThread::on_signal_syscall(VThreadState &state) {
    KernelUContext *ucontext = state.signal_state.get_uc();
    if (!check_bound(syscall_signal_buffer.base, syscall_signal_buffer.size, ucontext, sizeof(KernelUContext))) {
        uint64_t sigset = 0;
        syscall(SYS_rt_sigprocmask, SIG_SETMASK, &sigset, nullptr, sizeof(sigset));
        return -EINTR;
    }
    uint64_t sigset = 0;
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, &sigset, nullptr, sizeof(sigset));
    uintptr_t rip = ucontext->uc_mcontext.rip;
    long rax;
    if (rip < (uintptr_t)&pegasus_gate_resume_syscall_race_point) {
        rax = -ERESTART;
    } else if (rip == (uintptr_t)&pegasus_gate_resume_syscall_race_point) {
        rax = ucontext->uc_mcontext.rax;
    } else {
        rax = ucontext->uc_mcontext.r12;
    }
    return rax;
}

void VThread::validate_signal(uintptr_t new_rsp, uintptr_t new_fpstate,
                              size_t fpstate_size, uintptr_t xfeatures) {
    uint32_t fpstate_size_new;
    uint64_t xfeatures_new;
    bool has_extended_fpstate = get_fpstate_size(new_fpstate, &fpstate_size_new, &xfeatures_new);
    if (!has_extended_fpstate || fpstate_size_new != fpstate_size || xfeatures_new != xfeatures) {
        throw CorruptedSignalFrameException();
    }
    if (!sanitize_fpstate(new_fpstate, fpstate_size, cpu_profile.xcr0, cpu_profile.mxcsr_mask)) {
        throw CorruptedSignalFrameException();
    }

    KernelUContext *new_uc = (KernelUContext *)(new_rsp + 8);
    new_uc->uc_mcontext.fpstate = (void *)new_fpstate;
    new_uc->uc_link = nullptr;
    new_uc->uc_stack.ss_flags = SS_DISABLE;
    new_uc->uc_stack.ss_sp = 0;
    new_uc->uc_stack.ss_flags = 0;
    new_uc->uc_sigmask = 0;

#ifndef CONFIG_DISABLE_MPK
    struct _xstate *xstate = (struct _xstate *)new_fpstate;
    int *pkru_ptr = read_pkru_from_xsave(xstate);
    if (!pkru_ptr || (uintptr_t)pkru_ptr + 4 > (uintptr_t)xstate + fpstate_size) {
        throw CorruptedSignalFrameException();
    }
    int real_pkru = vprocess->mm->get_pkru();
#endif

    // Handle race conditions
    uint8_t *rip = (uint8_t *)new_uc->uc_mcontext.rip;
    if (rip >= &pegasus_gate_monitor_call_race_start && rip < &pegasus_gate_monitor_call_race_end) {
#ifndef CONFIG_DISABLE_MPK
        *pkru_ptr = real_pkru;
#endif
        new_uc->uc_mcontext.rip = (uintptr_t)&pegasus_gate_monitor_call_race_restart;
    } else if (rip >= &pegasus_gate_resume_sandbox_call_race_start && rip < &pegasus_gate_resume_sandbox_call_race_end) {
#ifndef CONFIG_DISABLE_MPK
        *pkru_ptr = real_pkru;
#endif
        new_uc->uc_mcontext.rip = (uintptr_t)&pegasus_gate_resume_sandbox_call_race_end;
    } else if (rip >= &pegasus_gate_fast_call_race1_start && rip < &pegasus_gate_fast_call_race1_end) {
#ifndef CONFIG_DISABLE_MPK
        *pkru_ptr = real_pkru;
#endif
        new_uc->uc_mcontext.rip = (uintptr_t)pegasus_gate_fast_call;
    } else if (rip >= &pegasus_gate_fast_call_race2_start && rip < &pegasus_gate_fast_call_race2_end) {
#ifndef CONFIG_DISABLE_MPK
        *pkru_ptr = real_pkru;
#endif
        new_uc->uc_mcontext.rip = (uintptr_t)&pegasus_gate_fast_call_race2_end;
    }

#ifndef CONFIG_DISABLE_MPK
    if (*pkru_ptr != real_pkru) {
        throw CorruptedSignalFrameException();
    }
#endif

    // clear RF flag to prevent breakpoint escaping
    new_uc->uc_mcontext.eflags &= ~(1ul << 16);
}

uintptr_t VThread::copy_signal_frame(const MemoryRegion &to, const MemoryRegion &from) {
    uintptr_t info = saved_state.signal_state.info;
    uintptr_t frame = saved_state.signal_state.rsp;

    uintptr_t signal_stack_start = (uintptr_t)from.base;
    uintptr_t signal_stack_end = (uintptr_t)from.base + from.size;

    KernelUContext *uc = (KernelUContext *)(frame + 8);
    void *fpstate;

#define CHECK_SIGNAL_BUFFER(addr, s) \
    if (!check_bound(from.base, from.size, addr, s)) { \
        throw CorruptedSignalFrameException(); \
    }

    CHECK_SIGNAL_BUFFER(uc, sizeof(KernelUContext));
    fpstate = uc->uc_mcontext.fpstate;
    intptr_t siginfo_offset = info - frame;
    intptr_t fpstate_offset = (uintptr_t)fpstate - frame;
    if (siginfo_offset < 0 || fpstate_offset < 0) {
        throw CorruptedSignalFrameException();
    }

    uint32_t fpstate_size;
    uint64_t xfeatures;
    bool has_extended_fpstate = get_fpstate_size(frame + fpstate_offset, &fpstate_size, &xfeatures,
                                                 signal_stack_start, signal_stack_end);
    if (!has_extended_fpstate) {
        throw CorruptedSignalFrameException();
    }

    uintptr_t new_rsp;
    uintptr_t new_fpstate;
    uintptr_t stack = (uintptr_t)to.base;

    constexpr int offset_mcontext = offsetof(KernelUContext, uc_mcontext) + 8; //48
    new_rsp = stack + PAGE_SIZE - offset_mcontext;
    new_fpstate = new_rsp + fpstate_offset + 64;
    new_fpstate = new_fpstate & ~(0x3full);
    if (new_fpstate + fpstate_size > stack + PAGE_SIZE * 2) {
        throw CorruptedSignalFrameException();
    }

    CHECK_SIGNAL_BUFFER(frame, fpstate_offset);
    CHECK_SIGNAL_BUFFER(frame + fpstate_offset, fpstate_size);
    memcpy((void *)new_rsp, (void *)frame, fpstate_offset);
    memcpy((void *)new_fpstate, (void *)(frame + fpstate_offset), fpstate_size);

    validate_signal(new_rsp, new_fpstate, fpstate_size, xfeatures);

    return new_rsp + 8;
#undef CHECK_SIGNAL_BUFFER
}

uintptr_t VThread::copy_vsignal_frame(const MemoryRegion &to, uintptr_t rsp) {
    MM *mm = vprocess->mm.get();
    try {
        KernelUContext *uc = (KernelUContext *)(rsp + 8);
        mm->copy_from_sandbox(&alternative_signal_stack, &uc->uc_stack, sizeof(stack_t));
        signal_mask = mm->get_sandbox<uint64_t>(&uc->uc_sigmask);
        void *fpstate = mm->get_sandbox<void *>(&uc->uc_mcontext.fpstate);
        uintptr_t fpstate_offset = (uintptr_t)fpstate - rsp;
        uint32_t fpstate_size;
        uint64_t xfeatures;
        bool has_extended_fpstate = get_fpstate_size(mm, (uintptr_t)fpstate, &fpstate_size, &xfeatures);
        if (!mm->check_memory_range(rsp, fpstate_offset) || !has_extended_fpstate) {
            throw CorruptedSignalFrameException();
        }
        uintptr_t new_rsp;
        uintptr_t new_fpstate;
        uintptr_t stack = (uintptr_t)to.base;

        constexpr int offset_mcontext = offsetof(KernelUContext, uc_mcontext) + 8; //48
        new_rsp = stack + PAGE_SIZE - offset_mcontext;
        new_fpstate = new_rsp + fpstate_offset + 64;
        new_fpstate = new_fpstate & ~(0x3full);
        if (new_fpstate + fpstate_size > stack + PAGE_SIZE * 2) {
            throw CorruptedSignalFrameException();
        }

        mm->copy_from_sandbox((void *)new_rsp, (void *)rsp, fpstate_offset);
        mm->copy_from_sandbox((void *)new_fpstate, (void *)(rsp + fpstate_offset), fpstate_size);

        validate_signal(new_rsp, new_fpstate, fpstate_size, xfeatures);
        return new_rsp + 8;
    } catch (FaultException &e) {
        throw CorruptedSignalFrameException();
    }
}

uintptr_t VThread::copy_protected_signal_frame() {
    constexpr int offset_mcontext = offsetof(KernelUContext, uc_mcontext) + 8;
    uintptr_t rsp = (uintptr_t)protected_signal_buffer.base + PAGE_SIZE - offset_mcontext;
    uintptr_t new_rsp = (uintptr_t)PER_CPU_PRIV_REF(signal_buffer).base + PAGE_SIZE - offset_mcontext;
    size_t frame_size = PAGE_SIZE + offset_mcontext;
    memcpy((void *)new_rsp, (void *)rsp, frame_size);
    KernelUContext *uc1 = (KernelUContext *)(rsp + 8);
    void *fpstate = uc1->uc_mcontext.fpstate;
    size_t offset = (uintptr_t)fpstate - rsp;
    KernelUContext *uc2 = (KernelUContext *)(new_rsp + 8);
    uc2->uc_mcontext.fpstate = (void *)(new_rsp + offset);
    return new_rsp + 8;
}

bool VThread::replace_signal_frame_xstate(uintptr_t xstate, uint64_t mask) {
    MM *mm = vprocess->get_mm();
    mask &= cpu_profile.xcr0;
    KernelUContext *uc = saved_state.signal_state.get_uc();
    uint8_t *signal_xstate = (uint8_t *)uc->uc_mcontext.fpstate;
    uint8_t *x = (uint8_t *)xstate;

    for (int i = 0; i < 63; ++i) {
        if (!(mask & (1ul << i))) {
            continue;
        }
        if (i == 9) {
            return false;
        }
        size_t offset = cpu_profile.xstate_offsets[i];
        size_t size = cpu_profile.xstate_sizes[i];
        try {
            mm->copy_in_sandbox(signal_xstate + offset, x + offset, size);
        } catch (FaultException &e) {
            return false;
        }
    }
    return true;
}

uintptr_t VThread::get_signal_rsp(bool onstack) {
    uintptr_t rsp;
    if (onstack && alternative_signal_stack.ss_flags != SS_DISABLE) {
        if (alternative_signal_stack.ss_flags == SS_AUTODISARM) {
            alternative_signal_stack.ss_flags = SS_DISABLE;
        }
        rsp = (uintptr_t)alternative_signal_stack.ss_sp + alternative_signal_stack.ss_size;
    } else {
        rsp = get_rsp() - 128;
    }
    return rsp;
}

SignalState VThread::write_vsignal_frame_from_signal(const siginfo_t *alt_info,
                                                     bool restartable, bool onstack) {
    uintptr_t info = saved_state.signal_state.info;
    uintptr_t frame = saved_state.signal_state.rsp;

    uintptr_t signal_stack_start = (uintptr_t)signal_buffer.base;
    uintptr_t signal_stack_end = (uintptr_t)signal_buffer.base + signal_buffer.size;

    KernelUContext *uc = (KernelUContext *)(frame + 8);
    void *fpstate;

#define CHECK_SIGNAL_BUFFER(addr, s) \
    if (!check_bound(signal_buffer.base, signal_buffer.size, addr, s)) { \
        throw CorruptedSignalFrameException(); \
    }

    CHECK_SIGNAL_BUFFER(uc, sizeof(KernelUContext));
    CHECK_SIGNAL_BUFFER(info, sizeof(siginfo_t));
    fpstate = uc->uc_mcontext.fpstate;
    intptr_t siginfo_offset = info - frame;
    intptr_t fpstate_offset = (uintptr_t)fpstate - frame;
    if (siginfo_offset < 0 || fpstate_offset < 0) {
        throw CorruptedSignalFrameException();
    }

    uint32_t fpstate_size;
    uint64_t xfeatures;
    bool has_extended_fpstate = get_fpstate_size(frame + fpstate_offset, &fpstate_size, &xfeatures,
                                                 signal_stack_start, signal_stack_end);
    if (!has_extended_fpstate) {
        throw CorruptedSignalFrameException();
    }
    CHECK_SIGNAL_BUFFER(fpstate, fpstate_size);

    uintptr_t rsp = get_signal_rsp(onstack);
    uintptr_t old_rsp = rsp;

    rsp = (rsp - fpstate_size) & ~(0x3full);
    uintptr_t new_fpstate = rsp;
    rsp -= sizeof(siginfo_t);
    uintptr_t new_siginfo = rsp;
    rsp = (rsp - sizeof(KernelUContext)) & (~0xfull);
    KernelUContext *new_uc = (KernelUContext *)rsp;
    rsp -= 8;
    uintptr_t new_rsp = rsp;
    MM *mm = vprocess->get_mm();

    if (restartable && has_work(WorkSyscallRestart)) {
        uc->uc_mcontext.rip -= 2;
        if (restart_syscall_func) {
            uc->uc_mcontext.rax = SYS_restart_syscall;
        } else {
            uc->uc_mcontext.rax = (uint32_t)saved_state.orig_sysno;
        }
    }
    uc->uc_stack = alternative_signal_stack;
    uc->uc_sigmask = signal_mask;

    try {
        mm->copy_to_sandbox((void *)new_fpstate, fpstate, fpstate_size);
        if (alt_info) {
            mm->copy_to_sandbox((void *)new_siginfo, alt_info, sizeof(siginfo_t));
        } else {
            mm->copy_to_sandbox((void *)new_siginfo, (void *)info, sizeof(siginfo_t));
        }
        mm->copy_to_sandbox(new_uc, uc, sizeof(KernelUContext));
        mm->put_sandbox(new_fpstate, &new_uc->uc_mcontext.fpstate);
        mm->put_sandbox(pegasus_vsig_restorer, (void *)new_rsp);
    } catch (FaultException &e) {
        throw CorruptedSignalFrameException();
    }

    SignalState res = {saved_state.signal_state.sig, new_siginfo, new_rsp};
    return res;
#undef CHECK_SIGNAL_BUFFER
}

SignalState VThread::write_vsignal_frame_from_monitor_call(int sig, const siginfo_t *info,
                                                           bool restartable, bool onstack) {
    uintptr_t rsp = get_signal_rsp(onstack);
    size_t non_compact_xstate_size = cpu_profile.xstate_pkru_offset + 12;
    rsp = (rsp - non_compact_xstate_size) & (~0x3full);
    uintptr_t xstate = rsp;
    if (!vprocess->mm->run_catch_fault_noexcept((void *)xstate, non_compact_xstate_size, [&] {
        write_xstate(xstate, vprocess->mm->get_pkru(),
                 true, cpu_profile.xstate_pkru_offset, cpu_profile.xcr0);
    })) {
        throw CorruptedSignalFrameException();
    }
    rsp -= sizeof(siginfo_t);
    siginfo_t *si = (siginfo_t *)rsp;
    rsp = (rsp - sizeof(KernelUContext)) & (~0xfull);
    KernelUContext *ctx = (KernelUContext *)rsp;
    rsp -= 8;
    KernelUContext uc;
    uc.uc_flags = 0;
    uc.uc_link = nullptr;
    uc.uc_sigmask = signal_mask;
    uc.uc_stack = alternative_signal_stack;
    memset(&uc.uc_mcontext, 0, sizeof(KernelSigContext));
    uc.uc_mcontext.r8 = saved_state.cpu_state.r8;
    uc.uc_mcontext.r9 = saved_state.cpu_state.r9;
    uc.uc_mcontext.r10 = saved_state.cpu_state.r10;
    uc.uc_mcontext.rdi = saved_state.cpu_state.rdi;
    uc.uc_mcontext.rsi = saved_state.cpu_state.rsi;
    uc.uc_mcontext.rbp = saved_state.cpu_state.rbp;
    uc.uc_mcontext.rbx = saved_state.cpu_state.rbx;
    uc.uc_mcontext.rdx = saved_state.cpu_state.rdx;
    uc.uc_mcontext.rax = saved_state.cpu_state.rax;
    uc.uc_mcontext.rcx = saved_state.cpu_state.rcx;
    try {
        uc.uc_mcontext.rip = vprocess->mm->get_sandbox<uintptr_t>((void *)saved_state.cpu_state.rsp);
        uc.uc_mcontext.rsp = saved_state.cpu_state.rsp + 8;
    } catch (FaultException &e) {
        uc.uc_mcontext.rip = saved_state.cpu_state.rip;
        uc.uc_mcontext.rsp = saved_state.cpu_state.rsp;
    }
    uc.uc_mcontext.fpstate = (void *)xstate;
    uc.uc_mcontext.cs = 0x33;
    uc.uc_mcontext.ss = 0x2b;
    if (restartable && has_work(WorkSyscallRestart)) {
        uc.uc_mcontext.rip -= 8; // sizeof call *%gs:8
        uc.uc_mcontext.rax = MonitorCallSyscall;
        if (restart_syscall_func) {
            uc.uc_mcontext.rcx = SYS_restart_syscall;
        } else {
            uc.uc_mcontext.rcx = (uint32_t)saved_state.orig_sysno;
        }
    }
    try {
        vprocess->mm->copy_to_sandbox(si, info, sizeof(siginfo_t));
        vprocess->mm->copy_to_sandbox(ctx, &uc, sizeof(KernelUContext));
        vprocess->mm->put_sandbox(pegasus_vsig_restorer, (void *)rsp);
    } catch (FaultException &e) {
        throw CorruptedSignalFrameException();
    }
    SignalState res = {sig, (uintptr_t)si, rsp};
    return res;
}

SignalState VThread::write_vsignal_frame_from_syscall_rewrite(int sig, const siginfo_t *info,
                                                              bool restartable, bool onstack) {
    uintptr_t rsp = get_signal_rsp(onstack);
    size_t non_compact_xstate_size = cpu_profile.xstate_pkru_offset + 12;
    rsp = (rsp - non_compact_xstate_size) & (~0x3full);
    uintptr_t xstate = rsp;
    bool save_fpu = saved_state.rewrite_state.fpstate;
    if (!vprocess->mm->run_catch_fault_noexcept((void *)xstate, non_compact_xstate_size, [&] {
        if (save_fpu) {
            memcpy((void *)xstate, saved_state.rewrite_state.fpstate, non_compact_xstate_size);
        }
        write_xstate(xstate, vprocess->mm->get_pkru(),
                     !save_fpu, cpu_profile.xstate_pkru_offset, cpu_profile.xcr0);
        if (!save_fpu) {
            void *fpstate_small = saved_state.rewrite_state.fpstate_small;
            memcpy((void *)(xstate + cpu_profile.xstate_xmm_offset), fpstate_small, 128);
        }
    })) {
        throw CorruptedSignalFrameException();
    }
    rsp -= sizeof(siginfo_t);
    siginfo_t *si = (siginfo_t *)rsp;
    rsp = (rsp - sizeof(KernelUContext)) & (~0xfull);
    KernelUContext *ctx = (KernelUContext *)rsp;
    rsp -= 8;
    KernelUContext uc;
    uc.uc_flags = 0;
    uc.uc_link = nullptr;
    uc.uc_sigmask = signal_mask;
    uc.uc_stack = alternative_signal_stack;
    memset(&uc.uc_mcontext, 0, sizeof(KernelSigContext));
    memcpy(&uc.uc_mcontext, saved_state.rewrite_state.gregs, sizeof(SyscallRewriteCPUState));
    uc.uc_mcontext.fpstate = (void *)xstate;
    uc.uc_mcontext.cs = 0x33;
    uc.uc_mcontext.ss = 0x2b;
    if (restartable && has_work(WorkSyscallRestart)) {
        if (restart_syscall_func) {
            if (save_fpu) {
                uc.uc_mcontext.rip = (uintptr_t)pegasus_gate_syscall_rewrite_restart;
            } else {
                uc.uc_mcontext.rip = (uintptr_t)pegasus_gate_syscall_rewrite_nofpu_restart;
            }
        } else {
            if (saved_state.rewrite_state.restart_rewrite_rax) {
                uc.uc_mcontext.rax = saved_state.orig_sysno;
            }
            uc.uc_mcontext.rip = saved_state.rewrite_state.restart_rip;
        }
    }
    try {
        vprocess->mm->copy_to_sandbox(si, info, sizeof(siginfo_t));
        vprocess->mm->copy_to_sandbox(ctx, &uc, sizeof(KernelUContext));
        vprocess->mm->put_sandbox(pegasus_vsig_restorer, (void *)rsp);
    } catch (FaultException &e) {
        throw CorruptedSignalFrameException();
    }
    SignalState res = {sig, (uintptr_t)si, rsp};
    return res;
}

void VThread::resume_sandbox_call(CPUState *registers) {
    if (!is_canonical_addr(saved_state.cpu_state.fs)) {
        throw Exception("fs is not canonical");
    }

    USwitchContext *ucontext = vprocess->ucontext.get();

    volatile struct uswitch_data *u = USwitchContext::get();
    //ucontext->block_signals();
    u->block_signals = 1;
    asm volatile ("" ::: "memory");
    SET_PER_CPU_PUB(pkru, vprocess->mm->get_pkru());
    SET_PER_CPU_PUB(syscall_rewrite_rsp,
                    (uintptr_t)syscall_rewrite_buffer.base + syscall_rewrite_buffer.size);
    SET_PER_CPU_PRIV(monitor_entry, registers);
    SET_PER_CPU_PRIV(current, &saved_state);    
    SET_PER_CPU_PRIV(mode, ExecutionMode::Sandbox);
    //ucontext->set_signal_stack((unsigned long)signal_buffer.base, signal_buffer.size);
    u->ss_sp = (unsigned long)signal_buffer.base;
    u->ss_size = signal_buffer.size;
    u->ss_flags = 0;
    u->ss_control = USWITCH_SIGNAL_STACK_USE_SHARED;
    u->next_block_signals = -1;
    //ucontext->switch_to();
    u->shared_descriptor = ucontext->cid;
    saved_state.enter_type = pegasus_gate_resume_sandbox_call(registers, &saved_state);
    //ucontext->switch_to_priv();
    u->shared_descriptor = 0;
    SET_PER_CPU_PRIV(mode, ExecutionMode::Monitor);
    //ucontext->clear_signal_stack();
    u->ss_control = USWITCH_SIGNAL_STACK_USE_RSP;
    //ucontext->unblock_signals();
    asm volatile ("" ::: "memory");
    u->block_signals = 0;

    if (saved_state.enter_type == EnterMonitorType::Signal) {
        on_signal();
    }
}

void VThread::resume_signal(CPUState *registers, uintptr_t frame) {
    if (!is_canonical_addr(saved_state.cpu_state.fs)) {
        throw Exception("fs is not canonical");
    }

    USwitchContext *ucontext = vprocess->ucontext.get();

    ucontext->block_signals();
    SET_PER_CPU_PUB(pkru, vprocess->mm->get_pkru());
    SET_PER_CPU_PUB(syscall_rewrite_rsp,
                    (uintptr_t)syscall_rewrite_buffer.base + syscall_rewrite_buffer.size);
    SET_PER_CPU_PRIV(monitor_entry, registers);
    SET_PER_CPU_PRIV(current, &saved_state);    
    SET_PER_CPU_PRIV(mode, ExecutionMode::Sandbox);
    ucontext->set_signal_stack((unsigned long)signal_buffer.base, signal_buffer.size, SS_AUTODISARM, 0);
    ucontext->set_next_descriptor();
    ucontext->switch_to_priv();
    saved_state.enter_type = pegasus_gate_resume_signal(registers, frame, saved_state.cpu_state.fs);
    ucontext->switch_to_priv();
    SET_PER_CPU_PRIV(mode, ExecutionMode::Monitor);
    ucontext->clear_signal_stack();
    ucontext->unblock_signals();

    if (saved_state.enter_type == EnterMonitorType::Signal) {
        on_signal();
    }
}

void VThread::handle_monitor_call() {
    saved_state.resume_type = EnterSandboxType::SandboxCall;
    uintptr_t mcid = saved_state.cpu_state.rax;
    if (mcid == MonitorCallSyscall) {
        int sysno = (int)saved_state.cpu_state.rcx;
        long args[6] = {
            (long)saved_state.cpu_state.rdi,
            (long)saved_state.cpu_state.rsi,
            (long)saved_state.cpu_state.rdx,
            (long)saved_state.cpu_state.r10,
            (long)saved_state.cpu_state.r8,
            (long)saved_state.cpu_state.r9,
        };
        SyscallInfo sysinfo;
        sysinfo.source = SyscallInfo::SyscallSource::MonitorCall;
        long res = handle_syscall(sysno, args, &sysinfo);
        saved_state.cpu_state.rax = res;
    } else if (mcid == MonitorCallSyscallRewrite) {
        uintptr_t rbx = saved_state.cpu_state.rbx;
        uintptr_t rbp = saved_state.cpu_state.rbp;
        
        if (!check_bound(syscall_rewrite_buffer.base, syscall_rewrite_buffer.size,
                         rbp, sizeof(SyscallRewriteCPUState))) {
            throw CorruptedSignalFrameException();
        }
        if (rbx) {
            size_t non_compact_xstate_size = cpu_profile.xstate_pkru_offset + 12;
            if (!check_bound(syscall_rewrite_buffer.base, syscall_rewrite_buffer.size,
                             rbx, non_compact_xstate_size)) {
                throw CorruptedSignalFrameException();
            }
        } else {
            uintptr_t rsp = saved_state.cpu_state.rsp;
            if (!check_bound(syscall_rewrite_buffer.base, syscall_rewrite_buffer.size,
                             rsp, 128)) {
                throw CorruptedSignalFrameException();
            }
            saved_state.rewrite_state.fpstate_small = (void *)rsp;
        }
        SyscallRewriteCPUState *gregs = (SyscallRewriteCPUState *)rbp;
        saved_state.enter_type = EnterMonitorType::SyscallRewrite;
        saved_state.rewrite_state.gregs = gregs;
        saved_state.rewrite_state.fpstate = (void *)rbx;

        //uintptr_t rsp = saved_state.cpu_state.rsp;
        vprocess->rewrite_context->handle_syscall(this, gregs);
        //uintptr_t rip = vprocess->mm->get_sandbox<uintptr_t>((void *)saved_state.cpu_state.rsp);
    }
}

void VThread::handle_signal() {
    int sig = saved_state.signal_state.sig;
    saved_state.resume_type = EnterSandboxType::Signal;

    switch (sig) {
    case SIGSYS:    handle_sigsys();    return;
    case SIGSEGV:   handle_sigsegv();   return;
    case SIGTRAP:   handle_sigtrap();   return;
    case SIGALRM:
        SET_PER_CPU_PRIV(alarmed, 1);
    case SIGURG:
        set_work(WorkResched);
        return;
    }
}

void VThread::handle_sigsys() {
    siginfo_t *si = (siginfo_t *)saved_state.signal_state.info;
    uintptr_t frame = saved_state.signal_state.rsp + 8;
    ucontext_t *uc = (ucontext_t *)frame;
    gregset_t gregs;
    memcpy(gregs, uc->uc_mcontext.gregs, sizeof(gregs));
    static constexpr int SysSeccomp = 1;
    if (si->si_signo != SIGSYS || si->si_code != SysSeccomp || si->si_arch != AUDIT_ARCH_X86_64) {
        throw SignalException(SIGSYS);
    }
    int sysno = si->si_syscall;
    uintptr_t rip = gregs[REG_RIP];
    long args[6] = {
        gregs[REG_RDI], gregs[REG_RSI], gregs[REG_RDX],
        gregs[REG_R10], gregs[REG_R8], gregs[REG_R9]
    };
    SyscallInfo sysinfo;
    sysinfo.source = SyscallInfo::SyscallSource::Signal;
    sysinfo.gregs = (uintptr_t *)gregs;
    sysinfo.si = si;
    sysinfo.frame = frame;
    long rax = handle_syscall(sysno, args, &sysinfo);
    gregs[REG_RAX] = rax;
    memcpy(uc->uc_mcontext.gregs, &gregs, sizeof(gregs));

    vprocess->rewrite_context->try_rewrite(this, sysno, rip - 2);
}

void VThread::handle_sigsegv() {
    //throw SignalException(SIGSEGV);
    if (vprocess->mm->handle_fault(this)) {
        return;
    }
    pass_signal();
}

void VThread::handle_sigtrap() {
    KernelUContext *uc = saved_state.signal_state.get_uc();
    siginfo_t *si = (siginfo_t *)saved_state.signal_state.info;
    uintptr_t rip = uc->uc_mcontext.rip;
    uint64_t eax = (uint32_t)uc->uc_mcontext.rax;
    uint64_t edx = (uint32_t)uc->uc_mcontext.rdx;
    uint64_t mask = (edx << 32) | eax;
    uint8_t buf[3];
    vprocess->mm->copy_from_sandbox(buf, (void *)rip, 3);
    if (si->si_signo != SIGTRAP || si->si_code != TRAP_HWBKPT) {
        pass_signal();
        return;
    }
    if (!vprocess->mm->has_breakpoint(rip)) {
        pass_signal();
        return;
    }

    uint8_t inst_buf[15];
    size_t n = vprocess->mm->copy_from_sandbox_atmost(inst_buf, (void *)rip, sizeof(inst_buf));
    if (n == 0) {
        throw SignalException(SIGTRAP);
    }

    // handle xrstor

    AddressGenerationContext ctx;
    ctx.gregs = (uintptr_t *)&uc->uc_mcontext;
    ctx.fs = saved_state.cpu_state.fs;
    ctx.gs = get_gsbase();
    uint64_t addr;
    if ((eax & (1ul << 9)) || !get_xrstor_address(&ctx, inst_buf, n, &addr)) {
        throw SignalException(SIGTRAP);
    }

    if (!replace_signal_frame_xstate(addr, mask)) {
        force_signal(SIGSEGV, nullptr);
    }
}

void VThread::handle_signal_syscall(int sig) {
    switch (sig) {
    case SIGALRM:
        SET_PER_CPU_PRIV(alarmed, 1);
    case SIGURG:
        Executor::schedule();
    case SIGCHLD:
        return;
    }
}

void VThread::handle_signal_race(int sig) {
    switch (sig) {
    case SIGALRM:
        SET_PER_CPU_PRIV(alarmed, 1);
    case SIGURG:
        set_work(WorkResched);
    case SIGCHLD:
        return;
    }
}

void VThread::pass_signal() {
    int sig = saved_state.signal_state.sig;
    if (sig < 1 || sig > NumSignals) {
        return;
    }
    siginfo_t *si = (siginfo_t *)saved_state.signal_state.info;
    KernelSigAction act;
    {
        std::lock_guard lock(vprocess->signal_mutex);
        act = vprocess->signal_handlers[sig - 1];
        if (act.sa_flags &  SA_RESETHAND) {
            vprocess->signal_handlers[sig - 1].sa_handler_ = SIG_DFL;
        }
    }

    bool use_altstack = alternative_signal_stack.ss_flags != SS_DISABLE && (act.sa_flags & SA_ONSTACK);
    if (act.sa_handler_ == SIG_IGN) {
        return;
    }
    if (sig == SIGCHLD && (act.sa_flags & SA_NOCLDWAIT)) {
        std::lock_guard lock(vprocess->vthread_mutex);
        vprocess->zombie_children.clear();
    }
    if (act.sa_handler_ == SIG_DFL) {
        if (sig == SIGCHLD || sig == SIGURG || sig == SIGWINCH || sig == SIGCONT) {
            return;
        }
        throw SignalException(sig);
    }

    bool restartable = act.sa_flags & SA_RESTART;
    SignalState vsignal;
    try {
        vsignal = write_vsignal_frame_from_signal(si, restartable, use_altstack);;
    } catch (CorruptedSignalFrameException &e) {
        if (sig == SIGSEGV) {
            throw;
        }
        force_signal(SIGSEGV, nullptr);
        return;
    }
    signal_mask |= act.sa_mask;
    if (!(act.sa_flags & SA_NODEFER)) {
        signal_mask |= build_signal_mask(sig);
    }
    uintptr_t rip = (uintptr_t)act.sa_sigaction_;

    saved_state.resume_type = EnterSandboxType::VSignalEnter;
    saved_state.cpu_state.rip = rip;
    saved_state.cpu_state.rsp = vsignal.rsp;
    saved_state.cpu_state.rbp = 0;
    saved_state.cpu_state.rbx = 0;
    saved_state.cpu_state.rdi = vsignal.sig;
    saved_state.cpu_state.rsi = vsignal.info;
    saved_state.cpu_state.rdx = vsignal.rsp + 8;

}

void VThread::check_vsignal() {
    if (pending_signals.empty() && vprocess->pending_signals.empty()) {
        return;
    }
    siginfo_t si;
    KernelSigAction act;
    int sig;
    {
        std::lock_guard lock(vprocess->signal_mutex);
        sig = pop_pending_signal(~signal_mask, &si, false);
        if (sig == -EAGAIN) {
            return;
        }
        if (sig < 1 || sig > NumSignals) {
            return;
        }
        act = vprocess->signal_handlers[sig - 1];
        if (act.sa_flags &  SA_RESETHAND) {
            vprocess->signal_handlers[sig - 1].sa_handler_ = SIG_DFL;
        }
    }
    handle_vsignal(sig, &si, act);
}

void VThread::handle_vsignal(int sig, const siginfo_t *info, const KernelSigAction &act) {
    uintptr_t handler = (uintptr_t)act.sa_sigaction_;
    bool restartable = act.sa_flags & SA_RESTART;
    bool use_altstack = alternative_signal_stack.ss_flags != SS_DISABLE && (act.sa_flags & SA_ONSTACK);
    if (act.sa_handler_ == SIG_IGN) {
        return;
    }
    if (act.sa_handler_ == SIG_DFL) {
        if (sig == SIGCHLD || sig == SIGURG || sig == SIGWINCH || sig == SIGCONT) {
            return;
        }
        throw SignalException(sig);
    }
    SignalState vsignal{};
    try {
        if (saved_state.resume_type == EnterSandboxType::Signal) {
            vsignal = write_vsignal_frame_from_signal(info, restartable, use_altstack);
            vsignal.sig = sig;
        } else if (saved_state.resume_type == EnterSandboxType::SandboxCall) {
            if (saved_state.enter_type == EnterMonitorType::SyscallRewrite) {
                vsignal = write_vsignal_frame_from_syscall_rewrite(sig, info, restartable, use_altstack);
            } else {
                vsignal = write_vsignal_frame_from_monitor_call(sig, info, restartable, use_altstack);
            }
        }
    } catch (CorruptedSignalFrameException &e) {
        if (sig == SIGSEGV) {
            throw;
        }
        force_signal(SIGSEGV, nullptr);
        return;
    }
    signal_mask |= act.sa_mask;
    if (!(act.sa_flags & SA_NODEFER)) {
        signal_mask |= build_signal_mask(sig);
    }

    saved_state.resume_type = EnterSandboxType::VSignalEnter;
    saved_state.cpu_state.rip = handler;
    saved_state.cpu_state.rsp = vsignal.rsp;
    saved_state.cpu_state.rbp = 0;
    saved_state.cpu_state.rbx = 0;
    saved_state.cpu_state.rdi = vsignal.sig;
    saved_state.cpu_state.rsi = vsignal.info;
    saved_state.cpu_state.rdx = vsignal.rsp + 8;
}

//bool debug_syscalls = true;
long VThread::handle_syscall(int sysno, const long *args, SyscallInfo *info) {
    SyscallHandler handler = SyscallHandlerTable.get(sysno);
    saved_state.orig_sysno = sysno;
//#define DEBUG_SYSCALL
    //bool debug_syscalls = vprocess->tgid == 13;
#ifdef DEBUG_SYSCALL
    if (debug_syscalls) {
        char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_X86_64, sysno);
        printf("s tgid=%d tid=%d sysno=%d %s(%lx, %lx, %lx, %lx, %lx, %lx)\n", vprocess->tgid, tid, sysno, name,
               args[0], args[1], args[2], args[3], args[4], args[5]);
        free(name);
    }
#endif
//#define STAT_SYSCALL
#ifdef STAT_SYSCALL
    std::shared_ptr<Task> task = Executor::get_current_task();
    uint64_t start = time_nanosec();
    //task->sys_time = 0;
    //task->last_sys_time = start;
#endif
    long res = handler(this, sysno, args, info);

#ifdef STAT_SYSCALL
    uint64_t end = time_nanosec();
    //uint64_t time = task->sys_time + end - task->last_sys_time;
    if (sysno < 512) {
        auto &stat = syscall_stats[sysno];
        std::lock_guard lock(stat.mutex);
        ++stat.n;
        stat.time += end - start;
    }
#endif

#ifdef DEBUG_SYSCALL
    if (debug_syscalls) {
        char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_X86_64, sysno);
        //printf("s %d %d %d %s %ld\n", tgid, thread->tid, sysno, name, rax);
        printf("s tgid=%d tid=%d sysno=%d %s(%lx, %lx, %lx, %lx, %lx, %lx)=%lx\n", vprocess->tgid, tid, sysno, name,
               args[0], args[1], args[2], args[3], args[4], args[5], res);
        free(name);
    }
#endif
    //if (res < 0 && res > -4096) {
    //    char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_X86_64, sysno);
    //    //printf("%s %d %d %d %ld\n", name, sysno, vprocess->tgid, tid, res);
    //    printf("s tgid=%d tid=%d sysno=%d %s(%lx, %lx, %lx, %lx, %lx, %lx)=%lx\n", vprocess->tgid, tid, sysno, name,
    //           args[0], args[1], args[2], args[3], args[4], args[5], res);
    //    free(name);
    //}

    trace_syscall(sysno, vprocess->tgid, tid, args, res);
    //if (SchedulePointSyscalls.count(sysno)) {
    //    set_work(WorkResched);
    //}
    return res;
}

ProxyThread::ProxyThread(const std::shared_ptr<USwitchContext> &ucontext_)
    : ucontext(ucontext_), ready(false), stopped(false), exited(false) {
}

void ProxyThread::init() {
    sigset_t newset, oldset;
    sigfillset(&newset);
    pthread_sigmask(SIG_SETMASK, &newset, &oldset);
    try {
        std::thread th([self = shared_from_this()] {
            self->routine();
        });
        th.detach();
    } catch (...) {
        pthread_sigmask(SIG_SETMASK, &oldset, nullptr);
        throw;
    }
    pthread_sigmask(SIG_SETMASK, &oldset, nullptr);
    std::unique_lock lock(mutex);
    cv.wait(lock, [&] {
        return ready;
    });
    if (exception) {
        throw *exception;
    }
}

void ProxyThread::routine() {
    tid = gettid();
    struct uswitch_data *data;
    int res = syscall(__NR_uswitch_cntl, USWITCH_CNTL_GET_CID, &data);
    if (res < 0) {
        exception.reset(new Exception("failed to init uswitch thread"));
    }
    data->shared_descriptor = ucontext->cid;
    data->seccomp_descriptor = 0;
    getpid(); // ensure switch

    std::unique_lock lock(mutex);
    ready = true;
    lock.unlock();
    cv.notify_one();

    if (exception) {
        return;
    }

    lock.lock();
    cv.wait(lock, [&] {
        return stopped;
    });
    data->shared_descriptor = 0;
    ucontext.reset();
    exited = true;
    lock.unlock();
    cv.notify_one();
}

void ProxyThread::exit() {
    std::unique_lock lock(mutex);
    if (stopped) {
        return;
    }
    stopped = true;
    lock.unlock();
    cv.notify_one();
    lock.lock();
    cv.wait(lock, [&] {
        return exited;
    });
}