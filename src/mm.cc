#include <thread>
#include <mutex>
#include <set>
#include <map>
#include <vector>
#include <string>
#include <memory>
#include <algorithm>
#include <random>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <ucontext.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <linux/mman.h>
#include "pegasus/breakpoint.h"
#include "pegasus/code_inspect.h"
#include "pegasus/decode.h"
#include "pegasus/def.h"
#include "pegasus/mm.h"
#include "pegasus/monitor.h"
#include "pegasus/percpu.h"
#include "pegasus/runtime.h"
#include "pegasus/syscall.h"
#include "pegasus/uswitch.h"

using namespace pegasus;

static constexpr uintptr_t BadAddress = -1;

enum {
    FlagPriv = 0x1,
    FlagGrowsDown = 0x2,
    FlagPrivate = 0x4,
    FlagShared = 0x8,
    FlagAnonymous = 0x10,
};
static constexpr size_t WriteExecPageSegmentSize = PAGE_SIZE * 32;

int MM::pkey_ref[16] = {1, 1, 0};
SpinLock MM::pkey_ref_mutex;

inline static void *real_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    //uint64_t t1 = time_nanosec();
    return mmap(addr, len, prot, flags, fd, offset);
}

inline static int real_munmap(void *addr, size_t len) {
    return munmap(addr, len);
}

inline static int real_pkey_mprotect(void *addr, size_t len, int prot, int pkey) {
    return pkey_mprotect(addr, len, prot, pkey);
}

MM::MM(size_t size_, int pkey_, uint64_t cap_)
    : cap(cap_), pkey(pkey_), base(0), heap(0), size(size_), num_vmas(0), max_vmas(261244) {
    if (pkey != -1 && (pkey > 16 || pkey < 3) && pkey != 0) {
        throw NoPKeyException();
    }
    if (pkey == -1) {
        pkey = get_unused_pkey();
    } else {
        std::lock_guard lock(pkey_ref_mutex);
        ++pkey_ref[pkey];
    }
    pkru = ::get_pkru(pkey);
    init();
}

MM::~MM() {
    void *entry;
    uintptr_t index = 0;
    mt_for_each(&mm_mt, entry, index, ULONG_MAX) {
        VMA *vma = (VMA *)entry;
        delete vma;
    }
    mtree_destroy(&mm_mt);
    if (base != (uintptr_t)MAP_FAILED) {
        ::munmap((void *)base, size);
    }
    {
        std::lock_guard lock(pkey_ref_mutex);
        --pkey_ref[pkey];
    }
}

int MM::get_unused_pkey() {
    std::lock_guard lock(pkey_ref_mutex);
    for (int i = PkeySandbox; i < 16; ++i) {
        if (pkey_ref[i] == 0) {
            ++pkey_ref[i];
            return i;
        }
    }
    throw NoPKeyException();
}

extern uint8_t __start__trusted_code;
extern uint8_t __stop__trusted_code;

void MM::init() {
    void *addr = real_mmap(nullptr, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    base = (uintptr_t)addr;
    if (addr == MAP_FAILED) {
        throw std::bad_alloc();
    }
    mt_init_flags(&mm_mt, MT_FLAGS_ALLOC_RANGE);
}

void MM::init_heap(size_t size) {
    if (heap) {
        return;
    }
    intptr_t new_heap = mmap(base, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, true, false);
    if (new_heap < 0 && new_heap > -4096) {
        throw Exception("failed to allocate heap");
    }
    heap = new_heap;
}

uintptr_t MM::mmap_internal(uintptr_t addr, size_t len, size_t real_len,
                                  int prot, int real_prot, int flags, int vma_flags,
                                  int fd, off_t offset, bool priv, bool remove_old, bool need_mmap) {
    bool need_set_breakpoint = false;
    std::vector<uintptr_t> bp;
    if (real_prot & PROT_EXEC) {
        if (fd == -1 || (cap & CapMapExecFile)) {
            int temp_prot = real_prot & (~PROT_EXEC);
            temp_prot |= PROT_READ; // we need to inspect the code
            if (real_mmap((void *)addr, len, temp_prot, flags, -1, 0) == MAP_FAILED) {
                return -errno;
            }
            uintptr_t s, e;
            if (!inspect_code(addr, len, fd, false, &s, &e)) {
                real_mmap((void *)addr, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
                return -EPERM;
            }
        } else if (flags & MAP_PRIVATE) {
            int err;
            if (!fake_mmap_exec_file(addr, len, real_len, real_prot, flags, fd, offset, err)) {
                return -err;
            }
            vma_flags |= FlagAnonymous;
            uintptr_t s, e;
            if (!inspect_code(addr, len, fd, true, &s, &e)) {
                if (Runtime::get()->get_bpm()) {
                    need_set_breakpoint = true;
                    Runtime::get()->get_ci()->find_unsafe_instructions((const uint8_t *)s, e - s, bp);
                } else {
                    remove_vma_range(addr, addr + len, priv, false, nullptr);
                    real_mmap((void *)addr, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
                    return -EPERM;
                }
            }
        } else {
            return -EPERM;
        }
    } else {
        if (need_mmap && real_mmap((void *)addr, len, real_prot, flags, fd, offset) == MAP_FAILED) {
            return -errno;
        }
    }
    if (need_set_breakpoint) {
        std::lock_guard lock(Runtime::get()->get_bpm()->mutex);
        for (auto it = breakpoints.begin(); it != breakpoints.end(); ) {
            auto next = std::next(it);
            if (*it >= addr && *it < addr + len) {
                breakpoints.erase(it);
            }
            it = next;
        }
        for (uintptr_t b : bp) {
            breakpoints.insert(b);
        }
        int err;
        // todo: error handling
        if (!pkey_mprotect_with_holes(addr, len, real_prot, pkey, bp, err)) {
            remove_vma_range(addr, addr + len, priv, false, nullptr);
            real_mmap((void *)addr, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            return -err;
        }
        update_breakpoints();
    } else {
        if (real_pkey_mprotect((void *)addr, len, real_prot, pkey) == -1) {
            remove_vma_range(addr, addr + len, priv, false, nullptr);
            real_mmap((void *)addr, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            return -errno;
        }
    }
    if (remove_old) {
        remove_vma_range(addr, addr + len, priv, false, nullptr);
    }
    if (WriteExecPageSegmentSize != -1lu && prot == (PROT_READ | PROT_WRITE | PROT_EXEC) && real_prot != prot) {
        VMA vma;
        for (uintptr_t i = addr; i < addr + len; i += WriteExecPageSegmentSize) {
            vma.start = i;
            vma.end = i + WriteExecPageSegmentSize > addr + len ? addr + len : i + WriteExecPageSegmentSize;
            vma.prot = prot;
            vma.real_prot = real_prot;
            vma.flags = vma_flags;
            vma.refcount = 0;
            insert_vma(vma);
        }
    } else {
        VMA vma;
        vma.start = addr;
        vma.end = addr + len;
        vma.prot = prot;
        vma.real_prot = real_prot;
        vma.flags = vma_flags;
        vma.refcount = 0;
        insert_vma(vma);
    }
    return addr;
}

uintptr_t MM::mmap(uintptr_t addr, size_t len, int prot, int flags,
                   int fd, off_t offset, bool priv, bool topdown) {
    size_t real_len = len;
    len = page_round_up(len);
    prot = prot & (PROT_READ | PROT_WRITE | PROT_EXEC | PROT_NONE);
    if (!is_page_aligned(addr) || !is_page_aligned(len) || !len) {
        return -EINVAL;
    }
    if (!(cap & CapMap) ||
        ((flags & MAP_SHARED) && !(cap & CapMapShared)) ||
        (fd != -1 && !(cap & CapMapFile)) ||
        ((prot & PROT_EXEC) && !(cap & CapMapExec)) ||
        (((flags & MAP_FIXED) || (flags & MAP_FIXED_NOREPLACE)) && !(cap & CapMapFixed))) {
        return -EPERM;
    }
    if (prot & PROT_WRITE) {
        prot |= PROT_READ;
    }
    int real_prot = prot;
    // no W+X
    if ((prot & PROT_WRITE) && (prot & PROT_EXEC)) {
        if (!(cap & CapMapWriteExec)) {
            return -EPERM;
        }
        if (!(cap & CapMapWriteExecReal)) {
            real_prot = PROT_READ | PROT_EXEC;
        }
    }
    //  no X only (which involves MPK)
    if ((prot & PROT_EXEC) && !(prot & PROT_READ)) {
        return -EPERM;
    }
    if (!(flags & MAP_SHARED) && !(flags & MAP_SHARED_VALIDATE) && !(flags & MAP_PRIVATE)) {
        return -EINVAL;
    }
    constexpr int IgnoredFlags = MAP_32BIT | MAP_GROWSDOWN | MAP_STACK;
    int vma_flags = priv ? FlagPriv : 0;
    if (flags & MAP_GROWSDOWN) {
        vma_flags |= FlagGrowsDown;
    }
    if (flags & MAP_PRIVATE) {
        vma_flags |= FlagPrivate;
    } else {
        vma_flags |= FlagShared;
    }
    if (flags & MAP_ANONYMOUS) {
        vma_flags |= FlagAnonymous;
    }
    constexpr int UnsupportedFlags = MAP_HUGETLB;
    flags &= ~IgnoredFlags;
    if (flags & UnsupportedFlags) {
        return -EOPNOTSUPP;
    }
    std::lock_guard lock(mutex);
    if ((flags & MAP_FIXED) && !(flags & MAP_FIXED_NOREPLACE)) {
        if (!check_memory_range(addr, len)) {
            return -ENOMEM;
        }
        size_t num_new_vmas;
        if (!remove_vma_range(addr, addr + len, priv, true, &num_new_vmas) || num_new_vmas + 1 > max_vmas) {
            return -ENOMEM;
        }
        return mmap_internal(addr, len, real_len, prot, real_prot, flags, vma_flags, fd, offset, priv, true, true);
    } else {
        if (num_vmas + 1 > max_vmas) {
            return -ENOMEM;
        }
        uintptr_t start = get_unmap_area(addr, len, topdown);
        if (start == BadAddress) {
            return -ENOMEM;
        }
        if (flags & MAP_FIXED_NOREPLACE) {
            if (start != addr) {
                return -EEXIST;
            }
        }
        flags = (flags & (~MAP_FIXED_NOREPLACE)) | MAP_FIXED;
        bool need_mmap = true;
        if (flags == (MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED) && prot == (PROT_READ | PROT_WRITE) && fd == -1) {
            need_mmap = false;
        }
        return mmap_internal(start, len, real_len, prot, real_prot, flags,
                             vma_flags, fd, offset, priv, false, need_mmap);
    }
}

bool MM::inspect_code(uintptr_t addr, size_t len, int fd, bool may_rewrite, uintptr_t *ps, uintptr_t *pe) {
    CodeInspector *ci = Runtime::get()->get_ci();
    if (!ci) {
        return true;
    }
    if (cap & CapMapExecNoInspect) {
        return true;
    }
    bool has_prev;
    VMA *vma = find_vma(addr - PAGE_SIZE, addr);
    if (!vma) {
        has_prev = false;
    } else {
        has_prev = vma->prot & PROT_EXEC;
    }
    bool has_next;
    vma = find_vma(addr + len, addr + len + PAGE_SIZE);
    if (!vma) {
        has_next = false;
    } else {
        has_next = vma->prot & PROT_EXEC;
    }
    uintptr_t start = addr;
    uintptr_t end = addr + len;
    if (has_prev) {
        start -= PAGE_SIZE;
    }
    if (has_next) {
        end += PAGE_SIZE;
    }
    *ps = start;
    *pe = end;
    return ci->inspect((const uint8_t *)start, end - start, (uint8_t *)addr, len, fd, may_rewrite);
}

bool MM::fake_mmap_exec_file(uintptr_t addr, size_t len, size_t real_len,
                                   int prot, int flags, int fd, off_t offset, int &err) {
    if (!is_page_aligned(offset)) {
        err = EINVAL;
        return false;
    }
    void *start = real_mmap((void *)addr, len, PROT_READ | PROT_WRITE, flags | MAP_ANONYMOUS, -1, 0);
    if (start == MAP_FAILED) {
        err = errno;
        return false;
    }
    ssize_t res = pread(fd, start, real_len, offset);
    if (res == -1) {
        real_mmap(start, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        err = errno;
        return false;
    }
    if (real_pkey_mprotect(start, len, PROT_WRITE | PROT_READ, 0) == -1) {
        err = EPERM;
        real_mmap(start, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        return false;
    }
    return true;
}

bool MM::pkey_mprotect_with_holes(uintptr_t addr, size_t len, int prot, int pk,
                                        const std::vector<uintptr_t> &breakpoints, int &err) {
    std::set<uintptr_t> hole_pages;
    bool has_prev = false;
    bool has_next = false;
    for (uintptr_t bp : breakpoints) {
        uintptr_t p = page_round_down(bp);
        if (p == addr - PAGE_SIZE) {
            has_prev = true;
        } else if (p == addr + len) {
            has_next = true;
        } else {
            hole_pages.insert(p);
        }
    }
    if (has_prev) {
        if (real_pkey_mprotect((void *)(addr - PAGE_SIZE), PAGE_SIZE, PROT_READ, pk) == -1) {
            err = errno;
            return false;
        }
    }
    if (has_next) {
        if (real_pkey_mprotect((void *)(addr + len), PAGE_SIZE, PROT_READ, pk) == -1) {
            err = errno;
            return false;
        }
    }
    uintptr_t i = addr;
    for (uintptr_t hole : hole_pages) {
        if (real_pkey_mprotect((void *)hole, PAGE_SIZE, PROT_READ, pk) == -1) {
            err = errno;
            return false;
        }
        if (hole > i) {
            if (real_pkey_mprotect((void *)i, hole - i, prot, pk) == -1) {
                err = errno;
                return false;
            }
        }
        i = hole + PAGE_SIZE;
    }
    if (addr + len > i) {
        if (real_pkey_mprotect((void *)i, addr + len - i, prot, pk) == -1) {
            err = errno;
            return false;
        }
    }
    return true;
}

int MM::munmap(uintptr_t addr, size_t len, bool priv) {
    len = page_round_up(len);
    if (!is_page_aligned(addr) || !is_page_aligned(len) || !len) {
        return -EINVAL;
    }
    if (!check_memory_range(addr, len)) {
        return -EINVAL;
    }
    if (!(cap & CapUnmap)) {
        return -EPERM;
    }
    std::lock_guard lock(mutex);
    size_t size;
    if (!remove_vma_range(addr, addr + len, priv, true, &size) || size + 1 > max_vmas) {
        return -ENOMEM;
    }
    if (real_mmap((void *)addr, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED) {
        return -errno;
    }
    remove_vma_range(addr, addr + len, priv, false, nullptr);
    return 0;
}

bool MM::rewrite_code(uintptr_t rip, const uint8_t *buf, size_t size) {
    std::lock_guard lock(mutex);
    VMA *p = find_cover_vma(rip);
    if (!p) {
        return false;
    }
    VMA &vma = *p;
    if (!check_bound(vma.start, vma.end - vma.start, rip, size)) {
        return false;
    }
    if (vma.prot == (PROT_READ | PROT_WRITE | PROT_EXEC)) {
        return false;
    }
    if (real_pkey_mprotect((void *)vma.start, vma.end - vma.start, PROT_READ | PROT_WRITE, 0) == -1) {
        return false;
    }
    std::basic_string<uint8_t> old_buf((const uint8_t *)rip, size);
    memcpy((void *)rip, buf, size);
    if (set_vma_executable(vma) != 0) {
        memcpy((void *)rip, old_buf.data(), size);
        if (set_vma_executable(vma) != 0) {
            // very unlikely
            remove_vma_range(vma.start, vma.end, false, false, nullptr);
            real_mmap((void *)vma.start, vma.end - vma.start, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            return false;
        }
        return false;
    }
    return true;
}

bool MM::handle_fault(VThread *vthread) {
    VThreadState &saved_state = vthread->get_saved_state();
    KernelUContext *uc = saved_state.signal_state.get_uc();
    siginfo_t *si = (siginfo_t *)(saved_state.signal_state.info);
    uintptr_t addr = (uintptr_t)si->si_addr;
    int trapno = uc->uc_mcontext.trapno;
    int error_code = uc->uc_mcontext.err;

    if (trapno != 14) {
        return false;
    }

    std::lock_guard lock(mutex);

    bool should_try_again;
    bool should_handle;
    AddressGenerationContext ctx;
    ctx.gregs = (uintptr_t *)(&uc->uc_mcontext);
    ctx.fs = saved_state.cpu_state.fs;
    uintptr_t gs;
    asm volatile (
        "rdgsbase %0\n" : "=r" (gs)
    );
    ctx.gs = gs;
    check_permission(&ctx, addr, error_code, should_try_again, should_handle);
    if (should_try_again) {
        return true;
    } else if (!should_handle) {
        return false;
    }

    int fault_reason;
    if (error_code & 0x10) {
        fault_reason = FaultExecute;
    } else if (error_code & 0x2) {
        fault_reason = FaultWrite;
    } else {
        fault_reason = FaultRead;
    }

    if (fault_reason == FaultExecute) {
        int res = handle_fault_breakpoint(addr);
        if (res == 0) {
            return true;
        } else if (res == 2) {
            return false;
        }
    }

    VMA *p = find_cover_vma(addr);
    if (!p) {
        return false;
    }
    VMA &vma = *p;

    if (fault_reason == FaultExecute && (vma.real_prot & PROT_EXEC)) {
        return true;
    }

    if (vma.prot != (PROT_READ | PROT_WRITE | PROT_EXEC)) {
        return false;
    }
    if (fault_reason == FaultExecute) {
        if (vma.real_prot != (PROT_READ | PROT_WRITE)) {
            return true;
        }
        if (set_vma_executable(vma) != 0) {
            return false;
        }
        return true;
    } else if (fault_reason == FaultWrite) {
        if (vma.real_prot != (PROT_READ | PROT_EXEC)) {
            return true;
        }
        if (real_pkey_mprotect((void *)vma.start, vma.end - vma.start, PROT_READ | PROT_WRITE, pkey) == -1) {
            return false;
        }
        vma.real_prot = PROT_READ | PROT_WRITE;
        return true;
    }

    return false;
}

void MM::check_permission(AddressGenerationContext *ctx, uintptr_t fault_addr, int error_code,
                          bool &should_try_again, bool &should_handle) {
    if (error_code & 0x10) {
        should_try_again = false;
        should_handle = true;
        return;
    }
    uint8_t inst_buf[15];
    uintptr_t rip = ctx->gregs[REG_RIP];
    size_t n = copy_from_sandbox_atmost(inst_buf, (void *)rip, sizeof(inst_buf));

    should_try_again = false;
    should_handle = false;

    MemoryOperand operands[2];
    int num_operands;
    if (!get_memory_operands(ctx, inst_buf, n, operands, &num_operands)) {
        return;
    }

    bool sufficient_real_prot = true;
    bool sufficient_prot = true;
    for (int i = 0; i < num_operands; ++i) {
        MemoryOperand &op = operands[i];
        int mp, mrp;
        get_min_prot(op.addr, op.addr + op.size, mp, mrp);
        if (op.write) {
            if (!(mp & PROT_WRITE)) {
                sufficient_prot = false;
            }
            if (!(mrp & PROT_WRITE)) {
                sufficient_real_prot = false;
            }
        } else if (op.read) {
            if (!(mp & PROT_READ)) {
                sufficient_prot = false;
            }
            if (!(mrp & PROT_READ)) {
                sufficient_real_prot = false;
            }
        }
    }

    if (sufficient_real_prot) {
        should_try_again = true;
    }
    if (sufficient_prot) {
        should_handle = true;
    }
}

int MM::set_vma_executable(VMA &vma) {
    bool need_set_breakpoint = false;
    std::vector<uintptr_t> bp;
    uintptr_t addr = vma.start;
    size_t len = vma.end - vma.start;
    if (real_pkey_mprotect((void *)addr, len, PROT_READ | PROT_WRITE, 0) == -1) {
        return -errno;
    }
    uintptr_t s, e;
    BreakpointManager *bpm;
    if (!inspect_code(addr, len, -1, true, &s, &e)) {
        bpm = Runtime::get()->get_bpm();
        if (bpm) {
            need_set_breakpoint = true;
            Runtime::get()->get_ci()->find_unsafe_instructions((const uint8_t *)s, e - s, bp);
        } else {
            return -EPERM;
        }
    }
    if (need_set_breakpoint) {
        std::lock_guard lock(bpm->mutex);
        for (auto it = breakpoints.begin(); it != breakpoints.end(); ) {
            auto next = std::next(it);
            if (*it >= addr && *it < addr + len) {
                breakpoints.erase(it);
            }
            it = next;
        }
        for (uintptr_t b : bp) {
            breakpoints.insert(b);
        }
        int err;
        if (!pkey_mprotect_with_holes(addr, len, PROT_READ | PROT_EXEC, pkey, bp, err)) {
            remove_vma_range(addr, addr + len, false, false, nullptr);
            real_mmap((void *)addr, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            return -err;
        }
        update_breakpoints();
    } else {
        if (real_pkey_mprotect((void *)addr, len, PROT_READ | PROT_EXEC, pkey) == -1) {
            return -errno;
        }
    }
    vma.real_prot = PROT_READ | PROT_EXEC;
    return 0;
}

void MM::update_breakpoints() {
    std::map<uintptr_t, int> new_breakpoints;
    BreakpointManager *bpm = Runtime::get()->get_bpm();
    // exclude the breakpoints that were in the current mm but are not now
    for (auto &&it : bpm->breakpoints) {
        uintptr_t b = it.first;
        if (b < base || b >= base + size) {
            new_breakpoints[b] = it.second;
            continue;
        }
        if (breakpoints.count(b)) {
            new_breakpoints[it.first] = pkey;
        }
    }
    if (new_breakpoints != bpm->breakpoints) {
        bpm->breakpoints = new_breakpoints;
        bpm->set_breakpoint();
    }
    
}

int MM::handle_fault_breakpoint(uintptr_t addr) {
    BreakpointManager *bpm = Runtime::get()->get_bpm();
    if (!bpm) {
        return 1;
    }
    uintptr_t page = page_round_down(addr);
    VMA *vma = find_cover_vma(addr);
    if (!vma) {
        return 1;
    }
    if (!(vma->real_prot & (PROT_READ | PROT_EXEC))) {
        return 1;
    }
    std::lock_guard lock(bpm->mutex);
    std::set<uintptr_t> required_breakpoints;
    bool has_cur_page = false;
    bool has_next_page = false;
    for (uintptr_t b : breakpoints) {
        if (page_round_down(b) == page) {
            required_breakpoints.insert(b);
            has_cur_page = true;
        }
        if (page_round_down(b) == page + 1) {
            required_breakpoints.insert(b);
            has_next_page = true;
        }
    }
    if (!required_breakpoints.size()) {
        return 1;
    }
    static constexpr size_t MaxRegisters = 4;
    // it's impossible to set more than 4 hardware breakpoints
    if (required_breakpoints.size() > MaxRegisters) {
        return 2;
    }

    bool has_set_breakpoint = true;

    for (uintptr_t bp : required_breakpoints) {
        if (!bpm->breakpoints.count(bp)) {
            has_set_breakpoint = false;
            break;
        }
    }

    if (has_set_breakpoint) {
        return 0;
    }

    std::map<uintptr_t, int> may_evict_breakpoints;
    for (auto &&it : bpm->breakpoints) {
        if (!required_breakpoints.count(it.first)) {
            may_evict_breakpoints.insert(it);
        }
    }
    ssize_t num_to_evict = may_evict_breakpoints.size() + required_breakpoints.size() - MaxRegisters;
    while (num_to_evict > 0) {
        std::pair<uintptr_t, int> b;
        std::sample(may_evict_breakpoints.begin(), may_evict_breakpoints.end(), &b, 1,
                    std::mt19937{std::random_device{}()});
        uintptr_t page_evict = page_round_down(b.first);
        int pk = -1;
        for (auto it = may_evict_breakpoints.begin(); it != may_evict_breakpoints.end(); ) {
            auto next = std::next(it);
            if (page_round_down(it->first) == page_evict) {
                pk = it->second;
                may_evict_breakpoints.erase(it);
            }
            it = next;
        }
        if (real_pkey_mprotect((void *)page_evict, PAGE_SIZE, PROT_READ, pk) == -1) {
            return 2;
        }
        num_to_evict = may_evict_breakpoints.size() + required_breakpoints.size() - MaxRegisters;
    }
    bpm->breakpoints = may_evict_breakpoints;
    for (uintptr_t b : required_breakpoints) {
        bpm->breakpoints[b] = pkey;
    }
    bpm->set_breakpoint();
    if (has_cur_page &&
        real_pkey_mprotect((void *)page, PAGE_SIZE, PROT_READ | PROT_EXEC, pkey) == -1) {
        return 2;
    }
    if (has_next_page &&
        real_pkey_mprotect((void *)(page + PAGE_SIZE), PAGE_SIZE, PROT_READ | PROT_EXEC, pkey) == -1) {
        return 2;
    }
    return 0;
}

int MM::mprotect(uintptr_t addr, size_t len, int prot, bool priv) {
    len = page_round_up(len);
    prot = prot & (PROT_READ | PROT_WRITE | PROT_EXEC | PROT_NONE);
    if (!is_page_aligned(addr) || !is_page_aligned(len) || !len) {
        return -EINVAL;
    }
    if (!check_memory_range(addr, len)) {
        return -EINVAL;
    }
    if (!(cap & CapProtect) ||
        ((prot & PROT_EXEC) && !(cap & CapMapExec))) {
        return -EPERM;
    }
    if (prot & PROT_WRITE) {
        prot |= PROT_READ;
    }
    int real_prot = prot;
    if ((prot & PROT_WRITE) && (prot & PROT_EXEC)) {
        if (!(cap & CapMapWriteExec)) {
            return -EPERM;
        }
        if (!(cap & CapMapWriteExecReal)) {
            real_prot = PROT_READ | PROT_EXEC;
        }
    }
    if ((prot & PROT_EXEC) && !(prot & PROT_READ)) {
        return -EPERM;
    }
    std::lock_guard lock(mutex);
    uintptr_t start = addr;
    uintptr_t end = addr + len;
    ssize_t diff = 0;

    void *entry;
    uintptr_t index = start;
    uintptr_t p = start;
    mt_for_each(&mm_mt, entry, index, end - 1) {
        VMA &vma = *(VMA *)entry;
        if (vma.start > p) {
            return -ENOMEM;
        }
        p = vma.end;
        if (!priv && (vma.flags & FlagPriv) && vma.prot != prot) {
            return -EACCES;
        }
        if ((prot & PROT_EXEC) && !(vma.flags & FlagAnonymous) && !(cap & CapMapExecFile)) {
            return -EPERM;
        }
        if ((prot & PROT_EXEC) && (vma.flags & FlagShared)) {
            return -EPERM;
        }
        if (vma.start >= start && vma.end <= end) {
            continue;
        } else if (vma.start < start && vma.end > end) {
            if (vma.prot != prot || vma.real_prot != real_prot) {
                diff += 2;
            }
        } else if (vma.start < start) {
            if (vma.prot != prot || vma.real_prot != real_prot) {
                ++diff;
            }
        } else if (vma.end > end) {
            if (vma.prot != prot || vma.real_prot != real_prot) {
                ++diff;
            }
        }
    }

    if (p < end) {
        return -ENOMEM;
    }

    if (num_vmas + diff > max_vmas) {
        return -ENOMEM;
    }
    bool need_set_breakpoint = false;
    std::vector<uintptr_t> bp;
    if (prot & PROT_EXEC) {
        if (real_pkey_mprotect((void *)addr, len, PROT_READ | PROT_WRITE, 0) == -1) {
            return -errno;
        }
        uintptr_t s, e;
        if (!inspect_code(addr, len, -1, true, &s, &e)) {
            if (Runtime::get()->get_bpm()) {
                need_set_breakpoint = true;
                Runtime::get()->get_ci()->find_unsafe_instructions((const uint8_t *)s, e - s, bp);
            } else {
                return -EPERM;
            }
        }
    }
    if (need_set_breakpoint) {
        std::lock_guard lock(Runtime::get()->get_bpm()->mutex);
        for (auto it = breakpoints.begin(); it != breakpoints.end(); ) {
            auto next = std::next(it);
            if (*it >= addr && *it < addr + len) {
                breakpoints.erase(it);
            }
            it = next;
        }
        for (uintptr_t b : bp) {
            breakpoints.insert(b);
        }
        int err;
        // todo: error handling
        if (!pkey_mprotect_with_holes(addr, len, real_prot, pkey, bp, err)) {
            remove_vma_range(addr, addr + len, priv, false, nullptr);
            real_mmap((void *)addr, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            return -err;
        }
        update_breakpoints();
    } else {
        if (real_pkey_mprotect((void *)addr, len, real_prot, pkey) == -1) {
            return -errno;
        }
    }

    index = start;
    mt_for_each(&mm_mt, entry, index, end - 1) {
        VMA &vma = *(VMA *)entry;
        if (vma.start >= start && vma.end <= end) {
            vma.prot = prot;
            vma.real_prot = real_prot;
        } else if (vma.start < start && vma.end > end) {
            //     |          |       |       |
            // vma.start    start    end  vma.end
            if (vma.prot != prot || vma.real_prot != real_prot) {
                VMA new_vma = vma;
                vma.end = start;
                update_vma(vma);
                new_vma.start = end;
                insert_vma(new_vma);
                new_vma.start = start;
                new_vma.end = end;
                new_vma.prot = prot;
                new_vma.real_prot = real_prot;
                insert_vma(new_vma);
                break;
            }
        } else if (vma.start < start) {
            //     |          |        |     |
            // vma.start    start   vma.end end
            // start != vma.end, otherwise they don't overlap
            if (vma.prot != prot || vma.real_prot != real_prot) {
                index = vma.end;
                VMA new_vma = vma;
                vma.end = start;
                update_vma(vma);
                new_vma.start = start;
                new_vma.prot = prot;
                new_vma.real_prot = real_prot;
                insert_vma(new_vma);
            }
        } else if (vma.end > end) {
            //   |          |       |        |
            // start   vma.start   end    vma.end
            if (vma.prot != prot || vma.real_prot != real_prot) {
                //index = vma.end;
                VMA new_vma = vma;
                vma.end = end;
                vma.prot = prot;
                vma.real_prot = real_prot;
                update_vma(vma);
                new_vma.start = end;
                insert_vma(new_vma);
                break;
            }
        }
    }
    return 0;
}

uintptr_t MM::mremap(uintptr_t old_addr, size_t old_size,
                     size_t new_size, int flags, uintptr_t new_addr, bool priv) {
    old_size = page_round_up(old_size);
    new_size = page_round_up(new_size);
    if (!is_page_aligned(old_addr) || !is_page_aligned(old_size) ||
        !is_page_aligned(new_size) || !new_size) {
        return -EINVAL;
    }
    if (!check_memory_range(old_addr, old_size)) {
        return -EFAULT;
    }
    if (!(cap & CapRemap)) {
        return -EPERM;
    }
    if (flags & MREMAP_DONTUNMAP) {
        return -EINVAL;
    }
    if (flags & MREMAP_FIXED) {
        if (!(flags & MREMAP_MAYMOVE)) {
            return -EINVAL;
        }
        if (!check_memory_range(new_addr, new_size)) {
            return -ENOMEM;
        }
        if (!(new_addr + new_size <= old_addr || new_addr >= old_addr + old_size)) {
            return -EINVAL;
        }
    }
    if (!(flags & MREMAP_MAYMOVE)) {
        if (!check_memory_range(old_addr, new_size)) {
            return -ENOMEM;
        }
    }
    std::lock_guard lock(mutex);
    void *entry = mtree_load(&mm_mt, old_addr);
    if (!entry) {
        return -EFAULT;
    }
    VMA &vma = *(VMA *)entry;
    if (old_addr < vma.start) {
        return -EFAULT;
    }
    if (old_size == 0 && (vma.flags & FlagShared) && (flags & MREMAP_MAYMOVE)) {
        return dup_shm(old_addr, new_size, vma.flags, vma.prot, flags, new_addr);
    } else if (!old_size) {
        return -EINVAL;
    }
    if ((vma.flags & FlagPriv) && !priv) {
        return -ENOMEM;
    }
    uintptr_t offset = old_addr - vma.start;
    if (old_size + offset != vma.end - vma.start) {
        return -ENOMEM;
    }
    bool try_old_addr = !(flags & MREMAP_FIXED);
    while (try_old_addr) {
        uintptr_t max_avail_addr;
        
        VMA *next = find_next_vma(vma);
        if (!next) {
            max_avail_addr = base + size;
        } else {
            max_avail_addr = next->start;
        }
        uintptr_t new_end = old_addr + new_size;
        uintptr_t old_end = vma.end;
        if (new_end > max_avail_addr) {
            if (flags & MREMAP_MAYMOVE) {
                break;
            }
            return -ENOMEM;
        }
        if (new_end == old_end) {
            return old_addr;
        } else if (new_end > old_end) {
            // we fill the "unmapped" area with actually PROT_NONE mappings,
            // so we need to clean them to reserve the space
            if (::munmap((void *)old_end, new_end - old_end) == -1) {
                return -errno;
            }
            if (::mremap((void *)old_addr, old_size, new_size, 0) == MAP_FAILED ||
                real_pkey_mprotect((void *)old_end, new_end - old_end, vma.prot, pkey) == -1) {
                return -errno;
            }
            vma.end = new_end;
            update_vma(vma);
            return old_addr;
        } else {
            // we simply map PROT_NONE pages to clobber the old ones
            if (real_mmap((void *)new_end, old_end - new_end, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED) {
                return -errno;
            }
        }
    }
    uintptr_t new_start;
    if (flags & MREMAP_FIXED) {
        new_start = new_addr;
    } else {
        new_start = old_addr;
    }
    new_start = get_unmap_area(new_start, new_size);
    if (new_start == BadAddress || ((flags & MREMAP_FIXED) && new_start != new_addr)) {
        return -ENOMEM;
    }
    if (::munmap((void *)new_start, new_size) == -1) {
        return -errno;
    }
    if (::mremap((void *)old_addr, old_size, new_size, MREMAP_FIXED | MREMAP_MAYMOVE, new_start) == MAP_FAILED) {
        real_mmap((void *)new_start, new_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        return -errno;
    }
    if (real_pkey_mprotect((void *)new_start, new_size, vma.prot, pkey) == -1) {
        real_mmap((void *)old_addr, old_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        real_mmap((void *)new_start, new_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        return -errno;
    }
    real_mmap((void *)old_addr, old_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (offset) {
        vma.end = old_addr;
        update_vma(vma);
    } else {
        remove_vma(vma);
    }
    VMA new_vma = vma;
    new_vma.start = new_start;
    new_vma.end = new_start + new_size;
    insert_vma(new_vma);
    return new_start;
}

int MM::madvise(uintptr_t addr, size_t len, int advice) {
    if (!is_page_aligned(addr)) {
        return -EINVAL;
    }
    if (!(cap & CapAdvise)) {
        return -EPERM;
    }
    len = page_round_up(len);
    if (!check_memory_range(addr, len)) {
        return -EINVAL;
    }
    if (::madvise((void *)addr, len, advice) == -1) {
        return -errno;
    }
    return 0;
}

int MM::mlock(uintptr_t addr, size_t len) {
    if (!is_page_aligned(addr)) {
        return -EINVAL;
    }
    if (!(cap & CapLock)) {
        return -EPERM;
    }
    len = page_round_up(len);
    if (!check_memory_range(addr, len)) {
        return -EINVAL;
    }
    std::lock_guard lock(mutex);
    if (!is_mapped(addr, addr + len)) {
        return -ENOMEM;
    }
    if (::mlock((void *)addr, len) == -1) {
        return -errno;
    }
    return 0;
}

int MM::munlock(uintptr_t addr, size_t len) {
    if (!is_page_aligned(addr)) {
        return -EINVAL;
    }
    if (!(cap & CapLock)) {
        return -EPERM;
    }
    len = page_round_up(len);
    if (!check_memory_range(addr, len)) {
        return -EINVAL;
    }
    std::lock_guard lock(mutex);
    if (!is_mapped(addr, addr + len)) {
        return -ENOMEM;
    }
    if (::munlock((void *)addr, len) == -1) {
        return -errno;
    }
    return 0;
}

int MM::mlockall(int flags) {
    // TODO
    if (flags & MCL_FUTURE) {
        return -EPERM;
    }
    if (!(cap & CapLock)) {
        return -EPERM;
    }
    return -EPERM;
}

int MM::munlockall() {
    if (!(cap & CapLock)) {
        return -EPERM;
    }
    return -EPERM;;
}

int MM::msync(uintptr_t addr, size_t len, int flags) {
    if (!is_page_aligned(addr)) {
        return -EINVAL;
    }
    if (!(cap & CapFlush)) {
        return -EPERM;
    }
    len = page_round_up(len);
    if (!check_memory_range(addr, len)) {
        return -EINVAL;
    }
    std::lock_guard lock(mutex);
    if (!is_mapped(addr, addr + len)) {
        return -ENOMEM;
    }
    if (::msync((void *)addr, len, flags) == -1) {
        return -errno;
    }
    return 0;
}

uintptr_t MM::brk(uintptr_t addr) {
    if (!(cap & CapBrk) || !heap) {
        return 0;
    }
    addr = page_round_up(addr);
    std::lock_guard lock(mutex);

    VMA *vma = find_exact_vma(heap);
    if (!vma) {
        return 0;
    }
    if (addr <= heap) {
        return vma->end;
    }
    uintptr_t max_avail_addr;
    VMA *next = find_next_vma(*vma);
    if (!next) {
        max_avail_addr = base + size;
    } else {
        max_avail_addr = next->start;
    }
    if (addr > max_avail_addr) {
        return vma->end;
    }
    if (addr > vma->end) {
        void *res = real_mmap((void *)vma->end, addr - vma->end, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (res == MAP_FAILED) {
            return vma->end;
        }
        if (real_pkey_mprotect((void *)vma->end, addr - vma->end, PROT_READ | PROT_WRITE, pkey) == -1) {
            real_mmap((void *)vma->end, addr - vma->end, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            return vma->end;
        }
        vma->end = addr;
        update_vma(*vma);
        return addr;
    } else if (addr < vma->end) {
        real_mmap((void *)addr, vma->end - addr, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        vma->end = addr;
        update_vma(*vma);
        return addr;
    }
    return addr;
}

uintptr_t MM::dup_shm(uintptr_t old_addr, size_t new_size, int vma_flags, int prot, int flags, uintptr_t new_addr) {
    if (!(cap & CapDupShare)) {
        return -EPERM;
    }
    if (prot & PROT_EXEC) {
        return -EPERM;
    }
    if (!(flags & MREMAP_FIXED)) {
        new_addr = 0;
    }
    uintptr_t start = get_unmap_area(new_addr, new_size);
    if (start == BadAddress) {
        return -ENOMEM;
    }
    if ((flags & MREMAP_FIXED) && start != new_addr) {
        return -ENOMEM;
    }
    if (::mremap((void *)old_addr, 0, new_size, MREMAP_FIXED | MREMAP_MAYMOVE, start) == MAP_FAILED) {
        return -errno;
    }
    if (real_pkey_mprotect((void *)start, new_size, prot, pkey) == -1) {
        real_mmap((void *)start, new_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        return -errno;
    }
    VMA vma;
    vma.start = start;
    vma.end = start + new_size;
    vma.flags = vma_flags;
    vma.prot = prot;
    vma.real_prot = prot;
    insert_vma(vma);
    return start;
}

uintptr_t MM::dup_shm(MM &mm, uintptr_t old_addr, size_t new_size, bool fixed, uintptr_t new_addr) {
    if (!is_page_aligned(old_addr) || !is_page_aligned(new_size) || (fixed && !is_page_aligned(new_addr))) {
        return -EINVAL;
    }
    if (&mm == this) {
        int flags = fixed ? (MREMAP_MAYMOVE | MREMAP_FIXED) : MREMAP_MAYMOVE;
        return mremap(old_addr, 0, new_size, flags, new_addr, false);
    }
    std::scoped_lock lock(mutex, mm.mutex);
    VMA *vma = find_cover_vma(old_addr);
    if (!vma) {
        return -EFAULT;
    }
    int flags = fixed ? (MREMAP_MAYMOVE | MREMAP_FIXED) : MREMAP_MAYMOVE;
    return dup_shm((uintptr_t)old_addr, new_size, vma->flags, vma->prot, flags, new_addr);
}

void MM::copy_from_sandbox(void *to, const void *from, size_t n) {
    if (!check_memory_range((uintptr_t)from, n)) {
        throw FaultException((uintptr_t)from, (uintptr_t)from + n);
    }
    SET_PER_CPU_PRIV(signal_exception_mask, build_signal_mask(SigSegv));
    try {
        memcpy(to, from, n);
    } catch (...) {
        SET_PER_CPU_PRIV(signal_exception_mask, 0);
        throw;
    }
    SET_PER_CPU_PRIV(signal_exception_mask, 0);
}

size_t MM::copy_from_sandbox_atmost(void *to, const void *from, size_t n) {
    uintptr_t p_src = (uintptr_t)from;
    uint8_t *p_dst = (uint8_t *)to;
    size_t len = n;
    size_t copied = 0;
    while (len > 0) {
        uintptr_t end = (p_src + PAGE_SIZE) / PAGE_SIZE * PAGE_SIZE;
        uintptr_t page_len = end - p_src;
        if (page_len > len) {
            page_len = len;
        }
        if (run_catch_fault_noexcept((void *)p_src, page_len, [&] {
            memcpy(p_dst, (void *)p_src, page_len);
        })) {
            p_src += page_len;
            p_dst += page_len;
            len -= page_len;
            copied += page_len;
        } else {
            break;
        }
    }
    return copied;
}

size_t MM::copy_str_from_sandbox(std::string &to, const void *from, size_t n) {
    uintptr_t from_ = (uintptr_t)from;
    uintptr_t end = from_ + n;
    intptr_t diff = (uintptr_t)get_base() + get_size() - end;
    if (diff < 0) {
        n += diff;
    }
    to.resize(n);
    char *p;
    if (!run_catch_fault_noexcept((void *)from, n, [&] {
        p = stpncpy(to.data(), (const char *)from, n);
    })) {
        return -1;
    }
    size_t len = p - to.data();
    to.resize(len);
    return len;
}

size_t MM::copy_str_from_sandbox(char *to, const void *from, size_t n) {
    uintptr_t from_ = (uintptr_t)from;
    uintptr_t end = from_ + n;
    intptr_t diff = (uintptr_t)get_base() + get_size() - end;
    if (diff < 0) {
        n += diff;
    }
    char *p;
    if (!run_catch_fault_noexcept((void *)from, n, [&] {
        p = stpncpy(to, (const char *)from, n);
    })) {
        return -1;
    }
    size_t len = p - to;
    return len;
}

void MM::copy_to_sandbox(void *to, const void *from, size_t n) {
    if (!check_memory_range((uintptr_t)to, n)) {
        throw FaultException((uintptr_t)to, (uintptr_t)to + n);
    }
    SET_PER_CPU_PRIV(signal_exception_mask, build_signal_mask(SigSegv));
    try {
        memcpy(to, from, n);
    } catch (...) {
        SET_PER_CPU_PRIV(signal_exception_mask, 0);
        throw;
    }
    SET_PER_CPU_PRIV(signal_exception_mask, 0);
}

void MM::copy_in_sandbox(void *to, const void *from, size_t n) {
    if (!check_memory_range((uintptr_t)from, n)) {
        throw FaultException((uintptr_t)from, (uintptr_t)from + n);
    }
    run_catch_fault(to, n, [&] {
        memcpy(to, from, n);
    });
}

bool MM::is_mapped(uintptr_t start, uintptr_t end) {
    uintptr_t p = start;
    void *entry;
    uintptr_t index = start;
    mt_for_each(&mm_mt, entry, index, end - 1) {
        VMA *vma = (VMA *)entry;
        if (vma->start <= p) {
            p = vma->end;
        } else {
            return false;
        }
    }
    return p >= end;
}

bool MM::is_accessible(uintptr_t start, uintptr_t end, int prot) {
    if (!check_memory_range(start, end - start)) {
        return false;
    }
    uintptr_t p = start;
    void *entry;
    uintptr_t index = start;
    mt_for_each(&mm_mt, entry, index, end - 1) {
        VMA *vma = (VMA *)entry;
        if (vma->start <= p && (vma->real_prot & prot)) {
            p = vma->end;
        } else {
            return false;
        }
    }
    return p >= end;
}

void MM::get_min_prot(uintptr_t start, uintptr_t end, int &min_prot, int &min_real_prot) {
    int mp = -1;
    int mrp = -1;
    uintptr_t p = start;
    void *entry;
    uintptr_t index = start;
    mt_for_each(&mm_mt, entry, index, end - 1) {
        VMA *vma = (VMA *)entry;
        if (vma->start <= p) {
            p = vma->end;
            mp &= vma->prot;
            mrp &= vma->real_prot;
        } else {
            break;
        }
    }
    if (p < end || mp == -1) {
        min_prot = 0;
        min_real_prot = 0;
        return;
    }
    min_prot = mp;
    min_real_prot = mrp;
}

uintptr_t MM::get_unmap_area(uintptr_t addr, size_t len, bool topdown) {
    if (addr) {
        if (check_memory_range(addr, len)) {
            VMA *vma = find_vma(addr);
            if (!vma || (addr + len <= vma->start)) {
                return addr;
            }
        }
    }
    MA_STATE(mas, &mm_mt, 0, 0);
    if (topdown) {
        if (!mm_mt.ma_root) {
            return base + size - len;
        }
        if (mas_empty_area_rev(&mas, base, base + size - 1, len)) {
            return BadAddress;
        }
        return mas.last + 1 - len;
    }
    if (!mm_mt.ma_root) {
        return base;
    }
    if (mas_empty_area(&mas, base, base + size - 1, len)) {
        return BadAddress;
    }
    return mas.index;
}

// look up the first vma such that addr < end
VMA *MM::find_vma(uintptr_t addr) {
    auto res = (VMA *)mt_find(&mm_mt, &addr, base + size - 1);
    return res;
}

VMA *MM::find_cover_vma(uintptr_t addr) {
    return (VMA *)mtree_load(&mm_mt, addr);
}

VMA *MM::find_exact_vma(uintptr_t addr) {
    VMA *vma = (VMA *)mtree_load(&mm_mt, addr);
    if (!vma || vma->start != addr) {
        return nullptr;
    }
    return vma;
}

VMA *MM::find_next_vma(const VMA &vma) {
    uintptr_t index = vma.end;
    return (VMA *)mt_find(&mm_mt, &index, base + size);
}

VMA *MM::find_vma(uintptr_t addr, uintptr_t end) {
    VMA *vma = (VMA *)mtree_load(&mm_mt, addr);
    if (!vma) {
        return nullptr;
    }
    if (vma->end < end) {
        return nullptr;
    }
    return vma;
}

void MM::insert_vma(const VMA &vma) {
    VMA *v = new VMA(vma);
    uintptr_t start = vma.start;
    uintptr_t end = vma.end;
    int res = mtree_store_range(&mm_mt, start, end - 1, v, 0);
    if (res != 0) {
        delete v;
        throw MapleTreeException(res);
    }
    ++num_vmas;
}

void MM::update_vma(const VMA &vma) {
    uintptr_t start = vma.start;
    uintptr_t end = vma.end;
    void *entry = mtree_erase(&mm_mt, start);
    mtree_store_range(&mm_mt, start, end - 1, entry, 0);
}

void MM::remove_vma(const VMA &vma) {
    VMA *v = (VMA *)mtree_erase(&mm_mt, vma.start);
    if (v) {
        delete v;
        --num_vmas;
    }
}

bool MM::remove_vma_range(uintptr_t start, uintptr_t end, bool priv, bool only_validate, size_t *size) {
    void *entry;
    uintptr_t index = start;
    if (only_validate) {
        ssize_t diff = 0;
        mt_for_each(&mm_mt, entry, index, end - 1) {
            VMA &vma = *(VMA *)entry;
            if (!priv && (vma.flags & FlagPriv)) {
                return false;
            }
            if (vma.start >= start && vma.end <= end) {
                --diff;
            } else if (vma.start < start && vma.end > end) {
                ++diff;
            }
        }
        if (*size) {
            *size = num_vmas + diff;
        }
        return true;
    }
    mt_for_each(&mm_mt, entry, index, end - 1) {
        VMA &vma = *(VMA *)entry;
        if (vma.start >= start && vma.end <= end) {
            index = vma.end;
            remove_vma(vma);
        } else if (vma.start < start && vma.end > end) {
            //index = vma.end;
            VMA new_vma = vma;
            vma.end = start;
            update_vma(vma);
            new_vma.start = end;
            insert_vma(new_vma);
            break;
        } else if (vma.start < start) {
            index = vma.end;
            vma.end = start;
            update_vma(vma);
        } else if (vma.end > end) {
            //index = vma.end;
            VMA new_vma = vma;
            remove_vma(vma);
            new_vma.start = end;
            insert_vma(new_vma);
            break;
        }
    }
    return true;
}

long SyscallHandlers::brk(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    return (long)thread->get_vprocess()->get_mm()->brk((uintptr_t)args[0]);
}

long SyscallHandlers::mmap(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    uintptr_t addr = (uintptr_t)args[0];
    size_t length = (size_t)args[1];
    int prot = (int)args[2];
    int flags = (int)args[3];
    int fd = (int)args[4];
    off_t offset = (off_t)args[5];
    USwitchContext *ucontext = thread->get_vprocess()->get_ucontext();
    uintptr_t res;
    if (fd != -1) {
        ucontext->run_on_behalf_of([&] {
            res = thread->get_vprocess()->get_mm()->mmap(addr, length, prot, flags, fd, offset, false, true);
        });
    } else {
        res = thread->get_vprocess()->get_mm()->mmap(addr, length, prot, flags, fd, offset, false, true);
    }
    return res;
}

long SyscallHandlers::munmap(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    uintptr_t addr = (uintptr_t)args[0];
    size_t length = (size_t)args[1];
    int res = thread->get_vprocess()->get_mm()->munmap(addr, length, false);
    return res;
}

long SyscallHandlers::mprotect(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    uintptr_t addr = (uintptr_t)args[0];
    size_t length = (size_t)args[1];
    int prot = (int)args[2];
    int res = thread->get_vprocess()->get_mm()->mprotect(addr, length, prot, false);
    return res;
}

long SyscallHandlers::mremap(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    uintptr_t old_addr = (uintptr_t)args[0];
    size_t old_size = (size_t)args[1];
    size_t new_size = (size_t)args[2];
    int flags = (int)args[3];
    uintptr_t new_addr = (uintptr_t)args[4];
    MM *mm = thread->get_vprocess()->get_mm();
    uintptr_t res = mm->mremap(old_addr, old_size, new_size, flags, new_addr, false);
    return (long)res;
}

long SyscallHandlers::madvise(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    uintptr_t addr = (uintptr_t)args[0];
    size_t length = (size_t)args[1];
    int advice = (int)args[2];
    int res = thread->get_vprocess()->get_mm()->madvise(addr, length, advice);
    return res;
}

long SyscallHandlers::mlock(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    uintptr_t addr = (uintptr_t)args[0];
    size_t length = (size_t)args[1];
    int res = thread->get_vprocess()->get_mm()->mlock(addr, length);
    return res;
}

long SyscallHandlers::munlock(VThread *thread, int sysno, const long *args, SyscallInfo *info) {
    uintptr_t addr = (uintptr_t)args[0];
    size_t length = (size_t)args[1];
    int res = thread->get_vprocess()->get_mm()->munlock(addr, length);
    return res;
}
