#include <mutex>
#include <thread>
#include <vector>
#include <set>
#include <map>
#include <cinttypes>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include "pegasus/types.h"
#include "pegasus/breakpoint.h"
#include "pegasus/exception.h"

using namespace pegasus;

static void read_all(int fd, void *buf, size_t len) {
    size_t has_read = 0;
    while (has_read < len) {
        ssize_t res = read(fd, (uint8_t *)buf + has_read, len - has_read);
        if (res == -1) {
            throw SystemException(errno);
        }
        has_read += res;
    }
}

static void write_all(int fd, const void *buf, size_t len) {
    size_t has_written = 0;
    while (has_written < len) {
        ssize_t res = write(fd, (const uint8_t *)buf + has_written, len - has_written);
        if (res == -1) {
            throw SystemException(errno);
        }
        has_written += res;
    }
}

BreakpointManager::BreakpointManager() : exited(false) {
}

void BreakpointManager::init_global() {
    if (pipe(to_tracer_fds) == -1 || pipe(from_tracer_fds) == -1) {
        throw Exception("failed to create pipes");
    }
    pid_t pid = fork();
    if (pid == -1) {
        throw Exception("failed to fork");
    }
    if (pid == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1) {
            exit(1);
        }
        for (int i = 1; i <= 64; ++i) {
            struct sigaction act;
            act.sa_flags = 0;
            act.sa_handler = SIG_DFL;
            sigaction(i, &act, nullptr);
        }
        char ready = 0;
        read_all(to_tracer_fds[0], &ready, 1);
        int ppid = getppid();
        if (ready != 1) {
            kill(ppid, SIGKILL);
            wait(nullptr);
            exit(1);
        }
        try {
            handle_breakpoint_requests();
        } catch (std::exception &e) {
            kill(ppid, SIGKILL);
            wait(nullptr);
            exit(1);
        }
    } else {
        tracer_pid = pid;
        prctl(PR_SET_PTRACER, pid);
        char ready = 1;
        write_all(to_tracer_fds[1], &ready, 1);
    }
}

void BreakpointManager::init_cpu() {
    std::lock_guard<std::mutex> lock(mutex);
    pid_t tid = gettid();
    tids.insert(tid);
    if (breakpoints.empty()) {
        return;
    }
    send_breakpoint_request({tid});
}

void BreakpointManager::set_breakpoint() {
    send_breakpoint_request(tids);
}

void BreakpointManager::handle_sigchld() {
    pid_t pid;
    int status;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (pid == tracer_pid && (WIFEXITED(status) || WIFSIGNALED(status))) {
            //printf("exited %d\n", gettid());
            exited = true;
        }
    }
}

void BreakpointManager::send_breakpoint_request(const std::unordered_set<pid_t> &pids) {
    if (exited) {
        throw Exception("failed to set breakpoint");
    }
    std::vector<uint8_t> buf(6 * sizeof(uintptr_t) + sizeof(size_t) + sizeof(pid_t) * pids.size());
    uint8_t *p = buf.data();
    *(size_t *)(p + 6 * sizeof(uintptr_t)) = pids.size();
    auto it = pids.begin();
    for (size_t i = 0; i < pids.size(); ++i) {
        *(pid_t *)(p + 6 * sizeof(uintptr_t) + sizeof(size_t) + sizeof(pid_t) * i) = *it;
        ++it;
    }
    uintptr_t *pdr = (uintptr_t *)p;
    auto it2 = breakpoints.begin();
    for (size_t i = 0; i < breakpoints.size(); ++i) {
        pdr[i] = it2->first;
        ++it2;
    }
    pdr[4] = 0;
    uint32_t dr7 = 0x700;
    for (size_t i = 0; i < breakpoints.size(); ++i) {
        dr7 |= 1 << (i * 2);
    }
    pdr[5] = dr7;
    write_all(to_tracer_fds[1], buf.data(), buf.size());
    char ready = 0;
    read_all(from_tracer_fds[0], &ready, 1);
    if (ready != 1) {
        throw Exception("failed to set breakpoint");
    }
}

static inline size_t dr_offset(int i) {
    return offsetof(struct user, u_debugreg[0]) + i * sizeof(uintptr_t);
}

void BreakpointManager::handle_breakpoint_requests() {
    while (true) {
        uintptr_t dr[6];
        read_all(to_tracer_fds[0], dr, 6 * sizeof(uintptr_t));
        size_t num_threads;
        read_all(to_tracer_fds[0], &num_threads, sizeof(num_threads));
        char ready = 1;
        for (size_t i = 0; i < num_threads; ++i) {
            pid_t tid;
            read_all(to_tracer_fds[0], &tid, sizeof(tid));
            if (ptrace(PTRACE_ATTACH, tid) == -1) {
                ready = 0;
                continue;
            }
            bool cont = false;
            while (true) {
                int status;
                if (waitpid(tid, &status, 0) != tid || !WIFSTOPPED(status)) {
                    ready = 0;
                    cont = true;
                    break;
                }
                if (WSTOPSIG(status) == SIGSTOP) {
                    break;
                }
                ptrace(PTRACE_CONT, tid, 0, 0);
            }
            if (cont) {
                continue;
            }

            for (int j = 0; j < 4; ++j) {
                if (ptrace(PTRACE_POKEUSER, tid, dr_offset(j), dr[j]) == -1) {
                    ready = 0;
                    continue;
                }
            }
            for (int j = 6; j < 8; ++j) {
                if (ptrace(PTRACE_POKEUSER, tid, dr_offset(j), dr[j - 2]) == -1) {
                    ready = 0;
                    continue;
                }
            }
            if (ptrace(PTRACE_DETACH, tid, 0, 0) == -1) {
                ready = 0;
                continue;
            }
        }
        write_all(from_tracer_fds[1], &ready, 1);
    }
}