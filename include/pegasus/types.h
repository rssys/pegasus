#pragma once
#include <string>
#include <cinttypes>

namespace pegasus {
struct CompactCPUState {
    uintptr_t rip, rsp, rbp, rbx, r12, r13, r14, r15;
};

struct CPUState {
    uintptr_t rip, rsp, rbp, rbx, r12, r13, r14, r15, fs;
};

struct MemoryRegion {
    uint8_t *base = nullptr;
    size_t size = 0;
};

// Saved registers: r8, r9, r10, rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip
struct MonitorCallCPUState {
    uintptr_t r8, r9, r10, rdi;
    uintptr_t rsi, rbp, rbx, rdx;
    uintptr_t rax, rcx, rsp, rip;
    uintptr_t fs;
};

struct SyscallRewriteCPUState {
    uintptr_t r8, r9, r10, r11, r12, r13, r14, r15;
    uintptr_t rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp;
    uintptr_t rip, eflags;
};

struct SyscallRewriteState {
    SyscallRewriteCPUState *gregs;
    void *fpstate;
    void *fpstate_small;
    uint64_t restart_rip;
    bool restart_rewrite_rax;
};

struct KernelSigAction {
    union {
	    void (*sa_handler_)(int);
	    void (*sa_sigaction_) (int, void *, void *);
    };
    unsigned long sa_flags;
    void *sa_restorer;
    uint64_t sa_mask;
};

struct KernelSigContext {
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp;
    uint64_t rip, eflags;
    uint16_t cs, gs, fs;
    union {
        uint16_t ss;
        uint16_t __pad[0];
    };
    uint64_t err, trapno, oldmask, cr2;
    void *fpstate;
    uint64_t reserved1[8];
};

struct KernelStack {
    void *ss_sp;
    int ss_flags;
    size_t ss_size;
};

struct KernelUContext {
    unsigned long uc_flags;
    KernelUContext *uc_link;
    KernelStack uc_stack;
    KernelSigContext uc_mcontext;
    uint64_t uc_sigmask;
};

struct SignalState {
    int sig;
    uintptr_t info;
    uintptr_t rsp;
    inline KernelUContext *get_uc() {
        return (KernelUContext *)(rsp + 8);
    }
};

enum class EnterMonitorType : uint32_t {
    MonitorCall = 0,
    Signal = 1,
    SyscallRewrite = 2,
    Race = 3,
};

enum class EnterSandboxType : uint32_t {
    SandboxCall = 0,
    Signal = 1,
    SignalProtected = 2,
    VSignalEnter = 3,
    VSignalReturn = 4,
};

struct VThreadState {
    MonitorCallCPUState cpu_state;
    SignalState signal_state;
    SyscallRewriteState rewrite_state;
    EnterMonitorType enter_type;
    EnterSandboxType resume_type;
    int orig_sysno;
};

struct VThreadEntrypoint {
    EnterSandboxType type;
    MonitorCallCPUState registers;
};

static_assert(offsetof(VThreadState, signal_state) == 104, "");

enum class ExecutionMode : uint32_t {
    Monitor = 0,
    Sandbox = 1,
    Syscall = 2,
};

struct CPUSet {
    CPUSet() : mask{} {}
    inline void insert(int i) {
        if (i >= MaxCPU) {
            return;
        }
        mask[i / 64] |= 1ull << (i % 64);
    }
    inline void erase(int i) {
        if (i >= MaxCPU) {
            return;
        }
        mask[i / 64] &= ~(1ull << (i % 64));
    }
    inline int count(int i) const {
        if (i >= MaxCPU) {
            return 0;
        }
        if ((mask[i / 64] >> (i % 64)) & 1) {
            return 1;
        }
        return 0;
    }
    inline int find_first(int max) const {
        for (int i = 0; i < max; ++i) {
            uint64_t m = mask[i / 64];
            if ((m >> (i % 64)) & 1) {
                return i;
            }
        }
        return -1;
    }
    inline bool empty(int max) const {
        int n = (max + 63) / 64;
        for (int i = 0; i < n; ++i) {
            if (mask[i] != 0) {
                return false;
            }
        }
        return true;
    }
    template <typename T>
    inline void for_each(int max, T func) const {
        for (int i = 0; i < max; ++i) {
            uint64_t m = mask[i / 64];
            if ((m >> (i % 64)) & 1) {
                if (!func(i)) {
                    return;
                }
            }
        }
    }

    template <typename T>
    inline void for_each_from(int max, int from, T func) const {
        for (int i = from; i < max; ++i) {
            uint64_t m = mask[i / 64];
            if ((m >> (i % 64)) & 1) {
                if (!func(i)) {
                    return;
                }
            }
        }
    }

    template <typename T>
    inline void for_each_wrap(int max, int from, T func) const {
        for (int i = from; i < max; ++i) {
            uint64_t m = mask[i / 64];
            if ((m >> (i % 64)) & 1) {
                if (!func(i)) {
                    return;
                }
            }
        }
        for (int i = 0; i < from; ++i) {
            uint64_t m = mask[i / 64];
            if ((m >> (i % 64)) & 1) {
                if (!func(i)) {
                    return;
                }
            }
        }
    }
    inline void print() {
        std::string out;
        for (int i = 0; i < MaxCPU; ++i) {
            if (count(i)) {
                out += std::to_string(i) + " ";
            }
        }
        printf("affinity: %s\n", out.c_str());
    }

    static constexpr int MaxCPU = 512;
    static_assert(MaxCPU % 64 == 0, "");
    uint64_t mask[MaxCPU / 64];
};
}