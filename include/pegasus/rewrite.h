#pragma once
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <cinttypes>
#include "lock.h"
#include "mm.h"
#include "types.h"

namespace pegasus {

/*
 *  Rewrite syscall instruction sequeunces to monitor calls.
 *
 *  We add a rewrite trampoline in the first 2 GiB virtual address. So it is
 *  possible to jump there with 7 bytes of instructions:
 *      b9 XX XX XX XX  movl $addr, %ecx
 *      ff e1           jmpq *(%rcx)
 *  %rcx can be clobbered according to the SysV ABI.
 *
 *  When rewriting, we first switch the page permission to PAGE_READ | PAGE_WRITE
 *  and set its pkey to the monitor domain. Afte rewriting we set it back.
 *
 *  To prevent race conditions, we use a stop tasklet to rewrite only after stopping
 *  all vthreads of the current vprocess. After rewriting we check the signal frames
 *  of all the vthreads and fix them if necessary.
 *
 *  Pattern0:
 *      b8 XX XX 00 00  movl $XXXX, %eax
 *      0f 05           syscall
 *  Rewrite to:
 *      b9 AA AA AA AA  movl $AAAAAAAA, %ecx
 *      ff e1           jmpq *(%rcx)
 * 
 *  Pattern1:
 *      48 c7 c0 XX XX 00 00    movq $XXXX, %rax
 *      0f 05                   sycall
 *  Rewrite to:
 *      48 c7 c1 AA AA AA AA    movq $AAAAAAAA, %rcx
 *      ff e1                   jmpq *(%rcx)
 * 
 *  Pattern2:
 *      0f 05               syscall
 *      48 3d XX XX XX XX   cmpq $XXXXXXXX, %rax
 *  Rewrite to:
 *      b9 AA AA AA AA      movl $AAAAAAAA, %ecx
 *      ff e1               jmpq *(%rcx)
 *      90                  nop
 * 
 *  Pattern3:
 *      0f 05               syscall
 *      48 89 c3            movq %rax, %rbx
 *      48 3d XX XX XX XX   cmpq $XXXXXXXX, %rax
 *  Rewrite to:
 *      90                  nop
 *      b9 AA AA AA AA      movl $AAAAAAAA, %ecx
 *      ff e1               jmpq *(%rcx)
 *      0f 1f 00            nopl (%rax)
 */

class VThread;
class VProcess;
class SyscallRewriteContext {
public:
    SyscallRewriteContext();
    SyscallRewriteContext(const SyscallRewriteContext &) = delete;
    SyscallRewriteContext &operator=(const SyscallRewriteContext &) = delete;
    ~SyscallRewriteContext();
    inline void enable() {
        enabled = true;
    }
    static void init_global();
    void try_rewrite(VThread *vthread, int sysno, uintptr_t rip);
    void handle_syscall(VThread *vthread, SyscallRewriteCPUState *state);
    void fix_signal_frame(VThread *vthread, KernelSigContext *ctx);
private:
    struct Data {
        uintptr_t rip;
        int32_t ecx;
        int type;
        union {
            int32_t eax;
            int32_t cmp;
        };
    };
    void set_fix_signal_frame(const std::shared_ptr<VProcess> &vprocess);
    bool try_rewrite_type0(const std::shared_ptr<VProcess> &vprocess, uintptr_t rip,
                           std::unique_lock<RWSpinLock> &lock);
    bool try_rewrite_type1(const std::shared_ptr<VProcess> &vprocess, uintptr_t rip,
                           std::unique_lock<RWSpinLock> &lock);
    bool try_rewrite_type2(const std::shared_ptr<VProcess> &vprocess, uintptr_t rip,
                           std::unique_lock<RWSpinLock> &lock);
    bool try_rewrite_type3(const std::shared_ptr<VProcess> &vprocess, uintptr_t rip,
                           std::unique_lock<RWSpinLock> &lock);
    void rewrite_type0(const std::shared_ptr<VProcess> &vprocess, uintptr_t rip);
    void rewrite_type1(const std::shared_ptr<VProcess> &vprocess, uintptr_t rip);
    void rewrite_type2(const std::shared_ptr<VProcess> &vprocess, uintptr_t rip);
    void rewrite_type3(const std::shared_ptr<VProcess> &vprocess, uintptr_t rip);
    void fix_signal_frame_type0_type1(VThread *vthread, uintptr_t rip, KernelSigContext *ctx, Data &data);
    void fix_signal_frame_type2(VThread *vthread, uintptr_t rip, KernelSigContext *ctx, Data &data);
    void fix_signal_frame_type3(VThread *vthread, uintptr_t rip, KernelSigContext *ctx, Data &data);

    RWSpinLock mutex;
    bool enabled;
    uint32_t num_idx;
    std::unordered_map<uint32_t, Data> ecx_rewrite_map;
    std::unordered_map<uintptr_t, uint32_t> rip_ecx_map;
    std::unordered_map<uintptr_t, uint32_t> race_rip;
    std::unordered_set<uintptr_t> failed_rip;
};
}