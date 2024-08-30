#pragma once
#include <vector>
#include <cstddef>
#include "pegasus/lock.h"

//#define CONFIG_ENABLE_TRACE

namespace pegasus {
struct SyscallLogEntry {
    int sysno;
    int tgid;
    int tid;
    long args[6];
    long res;
    uint64_t time;
};

class SyscallLogger {
public:
    SyscallLogger(size_t n);
    void add(const SyscallLogEntry &entry);
    void print_recent();
private:
    size_t n;
    size_t p;
    SpinLock mutex;
    std::vector<SyscallLogEntry> log;
};

#ifdef CONFIG_ENABLE_TRACE
void trace_syscall(int sysno, int tgid, int tid, const long *args, long res);
void print_recent_log();
#else
inline void trace_syscall(int sysno, int tgid, int tid, const long *args, long res) {}
inline void print_recent_log() {}
#endif
}