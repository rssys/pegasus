#pragma once
#include <cinttypes>

namespace pegasus {
static constexpr unsigned int PAGE_SIZE = 4096;
static constexpr int NumSignals = 64;
static constexpr int MaxPendingSignals = 65536;
enum {
    PkeyPrivileged = 0,
    PkeyReadonly = 1,
    PkeySandbox = 2,
};

enum {
    MonitorCallSyscall = 0,
    MonitorCallSyscallRewrite = 1,
};

template <typename... T>
uint64_t build_signal_mask(T... args) {
    return (((1 << (args - 1))) | ...);
}
}