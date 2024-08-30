#pragma once
#include <mutex>
#include <unordered_set>
#include <set>
#include <map>
#include <cinttypes>
#include <sys/types.h>

namespace pegasus {
struct BreakpointManager {
public:
    BreakpointManager();
    BreakpointManager(const BreakpointManager &) = delete;
    BreakpointManager &operator=(const BreakpointManager &) = delete;
    void init_global();
    void init_cpu();
    void set_breakpoint();
    void handle_sigchld();
private:
    friend class MM;
    void handle_breakpoint_requests();
    void send_breakpoint_request(const std::unordered_set<pid_t> &pids);

    bool exited;
    pid_t tracer_pid;
    int to_tracer_fds[2];
    int from_tracer_fds[2];
    std::mutex mutex;
    std::unordered_set<pid_t> tids;
    std::map<uintptr_t, int> breakpoints;
};
}