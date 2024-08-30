#pragma once
#include <type_traits>
#include <memory>
#include <cinttypes>
#include <cstddef>
#include "def.h"
#include "types.h"

struct uswitch_data;

namespace pegasus {
template <int Offset>
struct PerCPUData {
    inline static PerCPUData *get() {
        uintptr_t gs;
        asm volatile (
            "rdgsbase %0\n" : "=r" (gs)
        );
        return (PerCPUData *)(gs + Offset);
    }
    template <typename T, int Off>
    inline static T get_field() {
        T res;
        asm volatile (
            "mov %%gs:(%c[offset]), %[res]\n"
            : [res] "=r" (res)
            : [offset] "i" (Offset + Off)
        );
        return res;
    }
    template <typename T, int Off>
    inline static void set_field(T val) {
        asm volatile (
            "mov %[val], %%gs:(%c[offset])\n"
            :: [offset] "i" (Offset + Off), [val] "r" (val)
            : "memory"
        );
    }
};

struct Task;
class Executor;
struct ClusterCPUData;
class CleanupWorkManager;

// per-cpu protected data
struct PerCPUPrivateData : public PerCPUData<PAGE_SIZE> {
    inline static PerCPUPrivateData *get() {
        return (PerCPUPrivateData *)PerCPUData::get();
    }
    enum {
        WorkCleanup = 1,
    };
    CPUState *monitor_entry;
    VThreadState *current;
    struct uswitch_data *uswitch_data;
    ExecutionMode mode;
    void *fast_call_rsp;
    uintptr_t (*fast_call_handler)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
    MemoryRegion signal_buffer;

    CompactCPUState executor_registers;
    Executor *current_executor;
    int current_eid;

    uint64_t signal_exception_mask;
    uintptr_t signal_fixup_rsp;
    uintptr_t signal_fixup_rip;

    std::shared_ptr<Task> current_task;
    ClusterCPUData *cluster_cpu_data;
    CleanupWorkManager *cwm;

    uint64_t signal_fixup_mask;
    int alarmed;
    int work;
};

#define PER_CPU_PRIV_OFFSET(name, offset) static_assert(offsetof(PerCPUPrivateData, name) == offset, "")
#define GET_PER_CPU_PRIV(field) \
    (PerCPUPrivateData::get_field \
        <decltype(PerCPUPrivateData::field), offsetof(PerCPUPrivateData, field)>())
#define SET_PER_CPU_PRIV(field, value) \
    PerCPUPrivateData::set_field \
        <decltype(PerCPUPrivateData::field), offsetof(PerCPUPrivateData, field)>(value)
#define PER_CPU_PRIV_PTR(field) (&(PerCPUPrivateData::get()->field))
#define PER_CPU_PRIV_REF(field) (PerCPUPrivateData::get()->field)

PER_CPU_PRIV_OFFSET(monitor_entry, 0);
PER_CPU_PRIV_OFFSET(current, 8);
PER_CPU_PRIV_OFFSET(uswitch_data, 16);
PER_CPU_PRIV_OFFSET(mode, 24);
PER_CPU_PRIV_OFFSET(fast_call_rsp, 32);
PER_CPU_PRIV_OFFSET(fast_call_handler, 40);
PER_CPU_PRIV_OFFSET(executor_registers, 64);
PER_CPU_PRIV_OFFSET(current_eid, 136);
PER_CPU_PRIV_OFFSET(signal_exception_mask, 144);
PER_CPU_PRIV_OFFSET(signal_fixup_rsp, 152);
PER_CPU_PRIV_OFFSET(signal_fixup_rip, 160);

// per-cpu public data that is readable in the app mode
struct PerCPUPublicData : public PerCPUData<0> {
    inline static PerCPUPublicData *get() {
        return (PerCPUPublicData *)PerCPUData::get();
    }
    uint32_t pkru;
    uintptr_t monitor_call_entry;
    uintptr_t syscall_rewrite_entry;
    uintptr_t syscall_rewrite_rsp;
    uintptr_t fast_call_entry;
    uintptr_t tracer_entry;
    void *trace_buffer;
    size_t trace_buffer_size;
};

#define PER_CPU_PUB_OFFSET(name, offset) static_assert(offsetof(PerCPUPublicData, name) == offset, "")
#define GET_PER_CPU_PUB(field) \
    PerCPUPublicData::get_field \
        <decltype(PerCPUPublicData::field), offsetof(PerCPUPublicData, field)>()
#define SET_PER_CPU_PUB(field, value) \
    PerCPUPublicData::set_field \
        <decltype(PerCPUPublicData::field), offsetof(PerCPUPublicData, field)>(value)

PER_CPU_PUB_OFFSET(monitor_call_entry, 8);
PER_CPU_PUB_OFFSET(syscall_rewrite_entry, 16);
PER_CPU_PUB_OFFSET(tracer_entry, 40);

static inline bool per_cpu_initialized() {
    uintptr_t gs;
    asm volatile (
        "rdgsbase %0\n" : "=r" (gs)
    );
    return gs;
}

static inline uintptr_t get_gsbase() {
    uintptr_t gs;
    asm volatile (
        "rdgsbase %0\n" : "=r" (gs)
    );
    return gs;
}
}