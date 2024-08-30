#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <cstring>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include "pegasus/decode.h"
#include "pegasus/exception.h"
#include "pegasus/gate.h"
#include "pegasus/mm.h"
#include "pegasus/monitor.h"
#include "pegasus/rewrite.h"
#include "pegasus/types.h"

using namespace pegasus;

static const std::unordered_set<int> NonRewritableSyscalls = {SYS_clone, SYS_clone3, SYS_fork, SYS_vfork, SYS_execve};

struct SyscallRewriteTrampoline {
    static constexpr size_t MaxSize = 1024 * 1024 * 16;
    static constexpr size_t AddrSize = sizeof(void *);
    static constexpr size_t ItemsPerPage = PAGE_SIZE / AddrSize;
    SpinLock mutex;
    MemoryRegion memory;
    uint32_t num_idx;
    SyscallRewriteTrampoline(uintptr_t entry) : num_idx(ItemsPerPage) {
        void *mem = mmap(nullptr, MaxSize, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
        if (mem == MAP_FAILED) {
            throw Exception("failed to init syscall rewrite");
        }
        if (pkey_mprotect(mem, MaxSize, PROT_READ | PROT_WRITE, PkeyReadonly) == -1) {
            throw Exception("failed to init syscall rewrite");
        }
        memory.base = (uint8_t *)mem;
        memory.size = MaxSize;
        for (size_t i = 0; i < ItemsPerPage; ++i) {
            uintptr_t *ecx = (uintptr_t *)(memory.base + i * AddrSize);
            *ecx = entry;
        }
    }
    inline uint32_t ecx_to_idx(uint32_t ecx) {
        return (ecx - (uint32_t)(uintptr_t)memory.base) / AddrSize;
    }
    inline uint32_t idx_to_ecx(uint32_t idx) {
        return (uint32_t)(uintptr_t)memory.base + idx * AddrSize;
    }
    uint32_t add_trampoline(size_t idx) {
        std::lock_guard lock(mutex);
        if (idx < num_idx) {
            return idx_to_ecx(idx);
        }
        if (num_idx * AddrSize == memory.size) {
            return -1;
        }
        uint32_t next_num = num_idx + ItemsPerPage;
        memcpy(memory.base + num_idx * AddrSize, memory.base, PAGE_SIZE);
        num_idx = next_num;
        return idx_to_ecx(idx);
    }
};

static std::unique_ptr<SyscallRewriteTrampoline> trampoline;
static std::unique_ptr<SyscallRewriteTrampoline> trampoline_nofpu;

static inline long get_cmp_rflags(long rflags, long op1, long op2) {
    long f = op1;
    asm volatile (
        "cmpq %0, %1\n"
        "pushfq\n"
        "popq %0\n" : "+r" (f) : "r" (op2) : "memory"
    );
    rflags &= ~0x8d5l;
    rflags |= f & 0x8d5l;
    return rflags;
}

static constexpr size_t MaxInstToAnalyze = 1000;
static constexpr size_t MaxInstLength = 15;

struct FPUAnalysisState {
    MM *mm;
    std::unordered_set<uintptr_t> visited;
    size_t max_insts;
    enum {
        Success = 0,
        TooManyInstructions = 1,
        Fetch = 2,
        Decode = 3,
        JMP = 4,
        SIMD = 5,
    } reason;
};

static bool need_save_fpu(uintptr_t rip, FPUAnalysisState &state);

inline static bool need_save_fpu_jmp(xed_decoded_inst_t *inst, uintptr_t rip, size_t n,
                                     FPUAnalysisState &state) {
    xed_iform_enum_t iform = xed_decoded_inst_get_iform_enum(inst);
    if (iform == XED_IFORM_JMP_GPRv || iform == XED_IFORM_JMP_MEMv) {
        state.reason = FPUAnalysisState::JMP;
        return true;
    }
    int64_t displacement = xed_decoded_inst_get_branch_displacement(inst);
    uintptr_t jmp_rip = rip + n + displacement;
    return need_save_fpu(jmp_rip, state);
}

static bool need_save_fpu(uintptr_t rip, FPUAnalysisState &state) {
    if (state.visited.size() > state.max_insts) {
        state.reason = FPUAnalysisState::TooManyInstructions;
        return true;
    }
    if (state.visited.count(rip)) {
        return false;
    }
    uint8_t buf[MaxInstLength];
    size_t n = state.mm->copy_from_sandbox_atmost(buf, (void *)rip, MaxInstLength);
    if (n == 0) {
        state.reason = FPUAnalysisState::Fetch;
        return true;
    }
    xed_decoded_inst_t inst;
    xed_decoded_inst_zero(&inst);
    xed_decoded_inst_set_mode(&inst, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
    if (xed_decode(&inst, buf, n) != XED_ERROR_NONE) {
        state.reason = FPUAnalysisState::Decode;
        return true;
    }
    n = xed_decoded_inst_get_length(&inst);
    if (xed_classify_sse(&inst) || xed_classify_avx(&inst) ||
        xed_classify_avx512(&inst) || xed_classify_avx512_maskop(&inst)) {
        state.reason = FPUAnalysisState::SIMD;
        return true;
    }
    xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(&inst);
    state.visited.insert(rip);
    switch (iclass) {
    case XED_ICLASS_RET_NEAR:
    case XED_ICLASS_RET_FAR:
    case XED_ICLASS_CALL_NEAR:
    case XED_ICLASS_CALL_FAR:
        return false;
    case XED_ICLASS_JMP_FAR:
        state.reason = FPUAnalysisState::JMP;
        return true;
    case XED_ICLASS_JMP:
        return need_save_fpu_jmp(&inst, rip, n, state);
    case XED_ICLASS_JB:
    case XED_ICLASS_JBE:
    case XED_ICLASS_JCXZ:
    case XED_ICLASS_JECXZ:
    case XED_ICLASS_JL:
    case XED_ICLASS_JLE:
    case XED_ICLASS_JNB:
    case XED_ICLASS_JNBE:
    case XED_ICLASS_JNL:
    case XED_ICLASS_JNLE:
    case XED_ICLASS_JNO:
    case XED_ICLASS_JNP:
    case XED_ICLASS_JNS:
    case XED_ICLASS_JNZ:
    case XED_ICLASS_JO:
    case XED_ICLASS_JP:
    case XED_ICLASS_JRCXZ:
    case XED_ICLASS_JS:
    case XED_ICLASS_JZ:
        int64_t displacement = xed_decoded_inst_get_branch_displacement(&inst);
        uintptr_t br_rip = rip + n + displacement;
        if (need_save_fpu(br_rip, state)) {
            return true;
        }
    }
    return need_save_fpu(rip + n, state);
}

static bool need_save_fpu(MM *mm, uintptr_t rip) {
    
    FPUAnalysisState state;
    state.mm = mm;
    state.max_insts = MaxInstToAnalyze;
    state.reason = FPUAnalysisState::Success;
    return need_save_fpu(rip, state);
}

SyscallRewriteContext::SyscallRewriteContext()
    : enabled(false), num_idx(0) {
}

SyscallRewriteContext::~SyscallRewriteContext() {

}

void SyscallRewriteContext::init_global() {
    trampoline.reset(new SyscallRewriteTrampoline((uintptr_t)pegasus_gate_syscall_rewrite));
    trampoline_nofpu.reset(new SyscallRewriteTrampoline((uintptr_t)pegasus_gate_syscall_rewrite_nofpu));
}

void SyscallRewriteContext::try_rewrite(VThread *vthread, int sysno, uintptr_t rip) {
    if (!enabled || NonRewritableSyscalls.count(sysno)) {
        return;
    }
    {
        std::shared_lock lock(mutex);
        if (failed_rip.count(rip) || rip_ecx_map.count(rip)) {
            return;
        }
    }
    std::unique_lock lock(mutex);
    if (failed_rip.count(rip) || rip_ecx_map.count(rip)) {
        return;
    }
    if (try_rewrite_type0(vthread->vprocess, rip, lock)) {
        return;
    }
    if (try_rewrite_type1(vthread->vprocess, rip, lock)) {
        return;
    }
    if (try_rewrite_type2(vthread->vprocess, rip, lock)) {
        return;
    }
    if (try_rewrite_type3(vthread->vprocess, rip, lock)) {
        return;
    }
    failed_rip.emplace(rip);
}

void SyscallRewriteContext::handle_syscall(VThread *vthread, SyscallRewriteCPUState *state) {
    Data data;
    {
        std::shared_lock lock(mutex);
        uint32_t ecx = (uint32_t)state->rcx;
        auto it = ecx_rewrite_map.find(ecx);
        if (it == ecx_rewrite_map.end()) {
            return;
        }
        data = it->second;
    }
    int sysno = 0;
    uintptr_t restart_rip = 0;
    bool is_restart = state->rip;
    bool restart_rewrite_rax = false;
    switch (data.type) {
    case 0:
        state->rax = (uint32_t)data.eax;
        sysno = data.eax;
        restart_rip = data.rip - 7;
        break;
    case 1:
        state->rax = (uint32_t)data.eax;
        sysno = data.eax;
        restart_rip = data.rip - 9;
        break;
    case 2:
        sysno = (int)state->rax;
        restart_rip = data.rip - 8;
        restart_rewrite_rax = true;
        break;
    case 3:
        sysno = (int)state->rax;
        restart_rip = data.rip - 11;
        restart_rewrite_rax = true;
        break;
    }
    if (is_restart) {
        sysno = SYS_restart_syscall;
    }
    state->rip = data.rip;
    vthread->saved_state.rewrite_state.restart_rip = restart_rip;
    vthread->saved_state.rewrite_state.restart_rewrite_rax = restart_rewrite_rax;

    long args[6] = {
        (long)state->rdi,
        (long)state->rsi,
        (long)state->rdx,
        (long)state->r10,
        (long)state->r8,
        (long)state->r9,
    };
    SyscallInfo sysinfo;
    sysinfo.source = SyscallInfo::SyscallSource::SyscallRewrite;
    long res = vthread->handle_syscall(sysno, args, &sysinfo);
    state->rax = res;

    if (data.type == 2 || data.type == 3) {
        state->eflags = get_cmp_rflags(state->eflags, data.cmp, res);
    }
}

void SyscallRewriteContext::fix_signal_frame(VThread *vthread, KernelSigContext *ctx) {
    std::shared_lock lock(mutex);
    uintptr_t rip = ctx->rip;
    auto it = race_rip.find(rip);
    if (it == race_rip.end()) {
        return;
    }
    auto it2 = ecx_rewrite_map.find(it->second);
    if (it2 == ecx_rewrite_map.end()) {
        return;
    }
    Data data = it2->second;
    lock.unlock();
    switch (data.type) {
    case 0:
    case 1:
        fix_signal_frame_type0_type1(vthread, rip, ctx, data);
        break;
    case 2:
        fix_signal_frame_type2(vthread, rip, ctx, data);
        break;
    case 3:
        fix_signal_frame_type3(vthread, rip, ctx, data);
        break;
    }
}

void SyscallRewriteContext::set_fix_signal_frame(const std::shared_ptr<VProcess> &vprocess) {
    for (auto &&it : vprocess->vthreads) {
        std::shared_ptr<VThread> th = it.second.lock();
        if (!th) {
            continue;
        }
        th->set_work(VThread::WorkFixSignalFrame);
    }
}

// ==================== Type0 ====================

static inline bool check_type0(MM *mm, uintptr_t rip, int32_t &eax) {
    uint8_t buf[7];
    try {
        mm->copy_from_sandbox(buf, (void *)(rip - 5), 7);
    } catch (FaultException &e) {
        return false;
    }
    if (!(buf[0] == 0xb8 && buf[5] == 0x0f && buf[6] == 0x05)) {
        return false;
    }
    eax = *(int32_t *)(buf + 1);
    return true;
}

bool SyscallRewriteContext::try_rewrite_type0(const std::shared_ptr<VProcess> &vprocess,
                                              uintptr_t rip, std::unique_lock<RWSpinLock> &lock) {
    int32_t eax;
    if (!check_type0(vprocess->get_mm(), rip, eax)) {
        return false;
    }
    lock.unlock();
    vprocess->stop_and_run([vprocess = std::weak_ptr<VProcess>(vprocess), rip] {
        std::shared_ptr<VProcess> p = vprocess.lock();
        if (p) {
            p->rewrite_context->rewrite_type0(p, rip);
        }
    }, true);
    return true;
}

void SyscallRewriteContext::rewrite_type0(const std::shared_ptr<VProcess> &vprocess, uintptr_t rip) {
    std::unique_lock lock(mutex);
    if (failed_rip.count(rip) || rip_ecx_map.count(rip)) {
        return;
    }
    int32_t eax;
    MM *mm = vprocess->get_mm();
    if (!check_type0(mm, rip, eax)) {
        return;
    }
    bool save_fpu = need_save_fpu(mm, rip + 2);
    uint32_t idx = num_idx;
    uint32_t ecx = (save_fpu ? trampoline : trampoline_nofpu)->add_trampoline(idx);
    if (ecx == -1u) {
        return;
    }
    try {
        Data data;
        data.rip = rip + 2;
        data.ecx = ecx;
        data.type = 0;
        data.eax = eax;
        ecx_rewrite_map.emplace(ecx, data);
        rip_ecx_map[rip] = ecx;
        race_rip[rip] = ecx;
    } catch (std::bad_alloc &e) {
        return;
    }
    uintptr_t rewrite_rip = rip - 5;
    uint8_t buf[7];
    buf[0] = 0xb9;
    *(int32_t *)(buf + 1) = ecx;
    buf[5] = 0xff;
    buf[6] = 0x21;
    if (!vprocess->mm->rewrite_code(rewrite_rip, buf, 7)) {
        ecx_rewrite_map.erase(ecx);
        rip_ecx_map.erase(rip);
        race_rip.erase(rip);
        failed_rip.emplace(rip);
        return;
    }
    ++num_idx;
    lock.unlock();
    set_fix_signal_frame(vprocess);
}

void SyscallRewriteContext::fix_signal_frame_type0_type1(VThread *vthread, uintptr_t rip,
                                                         KernelSigContext *ctx, Data &data) {
    if (rip == data.rip - 2) { 
        ctx->rcx = (uint32_t)data.ecx;
    }
}

// ==================== Type1 ====================

static inline bool check_type1(MM *mm, uintptr_t rip, int32_t &eax) {
    uint8_t buf[9];
    try {
        mm->copy_from_sandbox(buf, (void *)(rip - 7), 9);
    } catch (FaultException &e) {
        return false;
    }
    if (!(buf[0] == 0x48 && buf[1] == 0xc7 && buf[2] == 0xc0 &&
          buf[7] == 0x0f && buf[8] == 0x05)) {
        return false;
    }
    eax = *(int32_t *)(buf + 3);
    return true;
}

bool SyscallRewriteContext::try_rewrite_type1(const std::shared_ptr<VProcess> &vprocess,
                                              uintptr_t rip, std::unique_lock<RWSpinLock> &lock) {
    int32_t eax;
    if (!check_type1(vprocess->get_mm(), rip, eax)) {
        return false;
    }
    lock.unlock();
    vprocess->stop_and_run([vprocess = std::weak_ptr<VProcess>(vprocess), rip] {
        std::shared_ptr<VProcess> p = vprocess.lock();
        if (p) {
            p->rewrite_context->rewrite_type1(p, rip);
        }
    }, true);
    return true;
}

void SyscallRewriteContext::rewrite_type1(const std::shared_ptr<VProcess> &vprocess, uintptr_t rip) {
    std::unique_lock lock(mutex);
    if (failed_rip.count(rip) || rip_ecx_map.count(rip)) {
        return;
    }
    int32_t eax;
    MM *mm = vprocess->get_mm();
    if (!check_type1(mm, rip, eax)) {
        return;
    }
    bool save_fpu = need_save_fpu(mm, rip + 2);
    uint32_t idx = num_idx;
    uint32_t ecx = (save_fpu ? trampoline : trampoline_nofpu)->add_trampoline(idx);
    if (ecx == -1u) {
        return;
    }
    try {
        Data data;
        data.rip = rip + 2;
        data.ecx = ecx;
        data.type = 1;
        data.eax = eax;
        ecx_rewrite_map.emplace(ecx, data);
        rip_ecx_map[rip] = ecx;
        race_rip[rip] = ecx;
    } catch (std::bad_alloc &e) {
        return;
    }
    uintptr_t rewrite_rip = rip - 7;
    uint8_t buf[9];
    buf[0] = 0x48;
    buf[1] = 0xc7;
    buf[2] = 0xc1;
    *(int32_t *)(buf + 3) = ecx;
    buf[7] = 0xff;
    buf[8] = 0x21;
    if (!vprocess->mm->rewrite_code(rewrite_rip, buf, 9)) {
        ecx_rewrite_map.erase(ecx);
        rip_ecx_map.erase(rip);
        race_rip.erase(rip);
        failed_rip.emplace(rip);
        return;
    }
    ++num_idx;
    lock.unlock();
    set_fix_signal_frame(vprocess);
}

// ==================== Type2 ====================

static inline bool check_type2(MM *mm, uintptr_t rip, int32_t &cmp) {
    uint8_t buf[8];
    try {
        mm->copy_from_sandbox(buf, (void *)rip, 8);
    } catch (FaultException &e) {
        return false;
    }
    if (memcmp(buf, "\x0f\x05\x48\x3d", 4) != 0) {
        return false;
    }
    cmp = *(int32_t *)(buf + 4);
    return true;
}

bool SyscallRewriteContext::try_rewrite_type2(const std::shared_ptr<VProcess> &vprocess,
                                              uintptr_t rip, std::unique_lock<RWSpinLock> &lock) {
    int32_t cmp;
    if (!check_type2(vprocess->get_mm(), rip, cmp)) {
        return false;
    }
    lock.unlock();
    vprocess->stop_and_run([vprocess = std::weak_ptr<VProcess>(vprocess), rip] {
        std::shared_ptr<VProcess> p = vprocess.lock();
        if (p) {
            p->rewrite_context->rewrite_type2(p, rip);
        }
    }, true);
    return true;
}

void SyscallRewriteContext::rewrite_type2(const std::shared_ptr<VProcess> &vprocess, uintptr_t rip) {
    std::unique_lock lock(mutex);
    if (failed_rip.count(rip) || rip_ecx_map.count(rip)) {
        return;
    }
    int32_t cmp;
    MM *mm = vprocess->get_mm();
    if (!check_type2(mm, rip, cmp)) {
        return;
    }
    bool save_fpu = need_save_fpu(mm, rip + 8);
    uint32_t idx = num_idx;
    uint32_t ecx = (save_fpu ? trampoline : trampoline_nofpu)->add_trampoline(idx);
    if (ecx == -1u) {
        return;
    }
    try {
        Data data;
        data.rip = rip + 8;
        data.ecx = ecx;
        data.type = 2;
        data.cmp = cmp;
        ecx_rewrite_map.emplace(ecx, data);
        rip_ecx_map[rip] = ecx;
        race_rip[rip + 2] = ecx;
    } catch (std::bad_alloc &e) {
        return;
    }
    uintptr_t rewrite_rip = rip;
    uint8_t buf[8];
    buf[0] = 0xb9;
    *(int32_t *)(buf + 1) = ecx;
    buf[5] = 0xff;
    buf[6] = 0x21;
    buf[7] = 0x90;
    if (!vprocess->mm->rewrite_code(rewrite_rip, buf, 8)) {
        ecx_rewrite_map.erase(ecx);
        rip_ecx_map.erase(rip);
        race_rip.erase(rip + 2);
        failed_rip.emplace(rip);
        return;
    }
    ++num_idx;
    lock.unlock();
    set_fix_signal_frame(vprocess);
}

void SyscallRewriteContext::fix_signal_frame_type2(VThread *vthread, uintptr_t rip,
                                                   KernelSigContext *ctx, Data &data) {
    if (rip == data.rip - 6) {
        ctx->rip = data.rip;
        ctx->eflags = get_cmp_rflags(ctx->eflags, data.cmp, ctx->rax);
    }
}

// ==================== Type3 ====================

static inline bool check_type3(MM *mm, uintptr_t rip, int32_t &cmp) {
    uint8_t buf[11];
    try {
        mm->copy_from_sandbox(buf, (void *)rip, 11);
    } catch (FaultException &e) {
        return false;
    }
    if (memcmp(buf, "\x0f\x05\x48\x89\xc3\x48\x3d", 7) != 0) {
        return false;
    }
    cmp = *(int32_t *)(buf + 7);
    return true;
}

bool SyscallRewriteContext::try_rewrite_type3(const std::shared_ptr<VProcess> &vprocess,
                                              uintptr_t rip, std::unique_lock<RWSpinLock> &lock) {
    int32_t cmp;
    if (!check_type3(vprocess->get_mm(), rip, cmp)) {
        return false;
    }
    lock.unlock();
    vprocess->stop_and_run([vprocess = std::weak_ptr<VProcess>(vprocess), rip] {
        std::shared_ptr<VProcess> p = vprocess.lock();
        if (p) {
            p->rewrite_context->rewrite_type3(p, rip);
        }
    }, true);
    return true;
}


void SyscallRewriteContext::rewrite_type3(const std::shared_ptr<VProcess> &vprocess, uintptr_t rip) {
    std::unique_lock lock(mutex);
    if (failed_rip.count(rip) || rip_ecx_map.count(rip)) {
        return;
    }
    int32_t cmp;
    MM *mm = vprocess->get_mm();
    if (!check_type3(mm, rip, cmp)) {
        return;
    }
    bool save_fpu = need_save_fpu(mm, rip + 11);
    uint32_t idx = num_idx;
    uint32_t ecx = (save_fpu ? trampoline : trampoline_nofpu)->add_trampoline(idx);
    if (ecx == -1u) {
        return;
    }
    try {
        Data data;
        data.rip = rip + 11;
        data.ecx = ecx;
        data.type = 3;
        data.cmp = cmp;
        ecx_rewrite_map.emplace(ecx, data);
        rip_ecx_map[rip] = ecx;
        race_rip[rip + 2] = ecx;
        race_rip[rip + 5] = ecx;
    } catch (std::bad_alloc &e) {
        return;
    }
    uintptr_t rewrite_rip = rip;
    uint8_t buf[11];
    buf[0] = 0x90;
    buf[1] = 0xb9;
    *(int32_t *)(buf + 2) = ecx;
    buf[6] = 0xff;
    buf[7] = 0x21;
    buf[8] = 0x0f;
    buf[9] = 0x1f;
    buf[10] = 0x00;
    if (!vprocess->mm->rewrite_code(rewrite_rip, buf, 11)) {
        ecx_rewrite_map.erase(ecx);
        rip_ecx_map.erase(rip);
        race_rip.erase(rip + 2);
        race_rip.erase(rip + 5);
        failed_rip.emplace(rip);
        return;
    }
    ++num_idx;
    lock.unlock();
    set_fix_signal_frame(vprocess);
}

void SyscallRewriteContext::fix_signal_frame_type3(VThread *vthread, uintptr_t rip,
                                                   KernelSigContext *ctx, Data &data) {
    if (rip == data.rip - 6 || rip == data.rip - 9) {
        ctx->rip = data.rip;
        ctx->rbx = ctx->rax;
        ctx->eflags = get_cmp_rflags(ctx->eflags, data.cmp, ctx->rax);
    }
}
