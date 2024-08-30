#pragma once
#include <shared_mutex>
#include <map>
#include <vector>
#include <set>
#include <memory>
#include <functional>
#include <cinttypes>
#include <sys/uio.h>
#include "def.h"
#include "exception.h"
#include "lock.h"
#include "percpu.h"
#include "maple_tree.h"

namespace pegasus {

template <typename T>
static T page_round_down(T addr) {
    return (T)((uintptr_t)addr / PAGE_SIZE * PAGE_SIZE);
}

template <typename T>
static T page_round_up(T addr) {
    return (T)(((uintptr_t)addr + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE);
}

template <typename T>
static inline bool is_page_aligned(T addr) {
    return ((uintptr_t)addr & (PAGE_SIZE - 1)) == 0;
}

template <typename T, typename S>
static inline bool check_bound(T bound_base, size_t bound_size, S ptr, size_t size) {
    uintptr_t b = (uintptr_t)bound_base;
    uintptr_t p = (uintptr_t)ptr;
    return b < b + bound_size &&
        p < p + size &&
        p >= b &&
        p + size <= b + bound_size;
}

static inline bool is_fail_address(uintptr_t addr) {
    intptr_t a = (intptr_t)addr;
    return a < 0 && a >= -4096;
}

inline static bool is_canonical_addr(uintptr_t addr) {
    return addr < 0x7ffffffffffful || addr > 0xffff800000000000ul;
}

inline static uint32_t get_pkru(int pkey) {
    if (pkey == 0) {
        return 0;
    } else {
        return ~(0x4 | (1 << (2 * pkey)) | (1 << (2 * pkey + 1)));
    }
}

struct VMA {
    uintptr_t start;
    uintptr_t end;
    int flags;
    int prot;
    int real_prot;
    int refcount;
};

class VThread;
struct AddressGenerationContext;
class MM {
public:
    MM(size_t size,
       int pkey = -1, uint64_t cap_ = DefaultCap);
    MM(MM &) = delete;
    MM &operator=(const MM &) = delete;
    ~MM();
    static int get_unused_pkey();
    void init_heap(size_t size);
    inline void *get_base() const {
        return (void *)base;
    }
    inline size_t get_size() const {
        return size;
    }
    inline void *get_heap() const {
        return (void *)heap;
    }
    inline int get_pkey() const {
        return pkey;
    }
    inline uint32_t get_pkru() const {
        return pkru;
    }

    uintptr_t mmap(uintptr_t addr, size_t len, int prot, int flags, int fd,
                   off_t offset, bool priv, bool topdown);
    bool inspect_code(uintptr_t addr, size_t len, int fd, bool may_rewrite, uintptr_t *ps, uintptr_t *pe);
    int munmap(uintptr_t addr, size_t len, bool priv);
    int mprotect(uintptr_t addr, size_t len, int prot, bool priv);
    uintptr_t mremap(uintptr_t old_addr, size_t old_size, size_t new_size,
                     int flags, uintptr_t new_addr, bool priv);
    int madvise(uintptr_t addr, size_t len, int advice);
    int mlock(uintptr_t addr, size_t len);
    int munlock(uintptr_t addr, size_t len);
    int mlockall(int flags);
    int munlockall();
    int msync(uintptr_t addr, size_t len, int flags);
    uintptr_t brk(uintptr_t addr);

    inline bool check_memory_range(uintptr_t addr, uintptr_t len) {
        return addr >= base && addr + len <= base + size && addr < addr + len;
    }
    template <typename T>
    inline void run_catch_fault(void *addr, size_t len, T &&func) {
        if (!check_memory_range((uintptr_t)addr, len)) {
            throw FaultException((uintptr_t)addr, (uintptr_t)addr + len);
        }
        SET_PER_CPU_PRIV(signal_exception_mask, build_signal_mask(SigSegv));
        try {
            func();
        } catch (...) {
            SET_PER_CPU_PRIV(signal_exception_mask, 0);
            throw;
        }
        SET_PER_CPU_PRIV(signal_exception_mask, 0);
    }
    template <typename T>
    inline bool run_catch_fault_noexcept(void *addr, size_t len, T &&func) {
        if (!check_memory_range((uintptr_t)addr, len)) {
            return false;
        }
        SET_PER_CPU_PRIV(signal_exception_mask, build_signal_mask(SigSegv));
        try {
            func();
        } catch (...) {
            SET_PER_CPU_PRIV(signal_exception_mask, 0);
            return false;
        }
        SET_PER_CPU_PRIV(signal_exception_mask, 0);
        return true;
    }
    void copy_from_sandbox(void *to, const void *from, size_t n);
    size_t copy_from_sandbox_atmost(void *to, const void *from, size_t n);
    size_t copy_str_from_sandbox(std::string &to, const void *from, size_t n);
    size_t copy_str_from_sandbox(char *to, const void *from, size_t n);
    void copy_to_sandbox(void *to, const void *from, size_t n);
    void copy_in_sandbox(void *to, const void *from, size_t n);
    bool rewrite_code(uintptr_t rip, const uint8_t *buf, size_t size);
    bool handle_fault(VThread *vthread);
    bool has_breakpoint(uintptr_t rip) {
        std::shared_lock lock(mutex);
        return breakpoints.count(rip);
    }
    void check_permission(AddressGenerationContext *ctx, uintptr_t fault_addr, int error_code,
                          bool &should_try_again, bool &should_handle);

    template <typename T>
    inline T get_sandbox(const void *ptr) {
        T buf;
        copy_from_sandbox(&buf, ptr, sizeof(T));
        return buf;
    }

    template <typename T>
    inline void put_sandbox(T x, void *ptr) {
        copy_to_sandbox(ptr, &x, sizeof(T));
    }

    enum {
        CapMap          = 0x1lu,
        CapUnmap        = 0x2lu,
        CapProtect      = 0x4lu,
        CapRemap        = 0x8lu,
        CapMapShared    = 0x10lu,
        CapMapFile      = 0x20lu,
        CapMapExec      = 0x40lu,
        CapMapExecFile  = 0x80lu,
        CapMapFixed     = 0x100lu,
        CapDupShare     = 0x200lu,
        CapBrk          = 0x400lu,
        CapLock         = 0x800lu,
        CapFlush        = 0x1000lu,
        CapAdvise       = 0x2000lu,
        CapMapWriteExec = 0x4000lu,
        CapFork         = 0x8000lu,
        CapMapWriteExecReal = 0x10000lu,
        CapMapExecNoInspect = 0x20000lu,
        DefaultCap      = 0x777flu,
        AllCap          = -1lu,
    };
    uint64_t cap;
private:
    enum {
        FaultRead,
        FaultWrite,
        FaultExecute,
        FaultUnknown,
    };
    static constexpr int SigSegv = 11;

    void init();
    bool is_accessible(uintptr_t start, uintptr_t end, int prot);
    void get_min_prot(uintptr_t start, uintptr_t end, int &min_prot, int &min_real_prot);
    uintptr_t get_unmap_area(uintptr_t addr, size_t len, bool topdown = true);
    VMA *find_vma(uintptr_t addr);
    VMA *find_cover_vma(uintptr_t addr);
    VMA *find_exact_vma(uintptr_t addr);
    VMA *find_next_vma(const VMA &vma);
    VMA *find_vma(uintptr_t addr, uintptr_t end);
    void insert_vma(const VMA &vma);
    void update_vma(const VMA &vma);
    void remove_vma(const VMA &vma);
    bool is_mapped(uintptr_t start, uintptr_t end);
    bool remove_vma_range(uintptr_t start, uintptr_t end, bool priv, bool only_validate, size_t *size);
    bool fake_mmap_exec_file(uintptr_t addr, size_t len, size_t real_len, int prot, int flags,
                             int fd, off_t offset, int &err);
    bool pkey_mprotect_with_holes(uintptr_t addr, size_t len, int prot, int pk,
                                  const std::vector<uintptr_t> &breakpoints, int &err);
    uintptr_t mmap_internal(uintptr_t addr, size_t len, size_t real_len,
                            int prot, int real_prot, int flags, int vma_flags,
                            int fd, off_t offset, bool priv, bool remove_old, bool need_mmap);
    uintptr_t dup_shm(uintptr_t old_addr, size_t new_size, int vma_flags, int prot, int flags, uintptr_t new_addr);
    uintptr_t dup_shm(MM &mm, uintptr_t old_addr, size_t new_size, bool fixed, uintptr_t new_addr);
    int set_vma_executable(VMA &vma);
    void update_breakpoints();
    int handle_fault_breakpoint(uintptr_t addr);

    static int pkey_ref[16];
    static SpinLock pkey_ref_mutex;
    RWSpinLock mutex;
    int pkey;
    uint32_t pkru;
    uintptr_t base;
    uintptr_t heap;
    size_t size;

    struct maple_tree mm_mt;
    size_t num_vmas;
    size_t max_vmas;

    std::set<uintptr_t> breakpoints;
};
}