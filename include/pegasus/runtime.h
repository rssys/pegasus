#pragma once
#include <memory>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <string>
#include <thread>
#include <cstdio>
#include "ioworker.h"
#include "monitor.h"
#include "types.h"
#include "json.hpp"

namespace pegasus {
struct ClusterData;
struct RuntimeConfiguration {
    RuntimeConfiguration();
    int num_threads;
    std::vector<int> cores;
    std::string rewrite_rule_filename;
    std::string hook_so;
    bool enable_code_inspection;
    bool log_code_inspection;
    bool enable_breakpoint;
    bool enable_fork;
    bool enable_vtcp;
    bool enable_poll;
    bool enable_vdso;
    double poll_threshold;
    bool enable_vsocketpair;
    bool enable_perf_map;
    bool send_ready_signal;
    bool cluster_mode;
    bool cluster_sched;
    ClusterData *cluster_data;
    IOWorkerConfiguration ioworker_config;

    std::string api_uds_path;

#ifdef CONFIG_ENABLE_TIME_TRACE
    bool enable_time_trace;
    size_t trace_buffer_size;
    int trace_buffer_pkey;
    std::string trace_output_file;
#endif
};

#ifdef CONFIG_ENABLE_TIME_TRACE
extern "C" void pegasus_trace_time(int tag);
#else
inline void pegasus_trace_time(int tag) {}
#endif

struct Mount {
    std::string type;
    std::string destination;
    std::string source;
    std::vector<std::string> options;
};

struct Namespace {
    int flag;
    std::string path;
};

struct ProgramConfiguration {
    ProgramConfiguration();
    ~ProgramConfiguration();
    std::string id;
    std::string bundle;
    std::string rootfs;
    bool rootfs_ro;
    std::string program;
    std::string working_directory;
    std::vector<std::string> args;
    std::vector<std::string> envs;
    std::vector<int> fds;
    std::vector<std::pair<std::string, std::string>> bind_mounts;
    std::unordered_set<int> affinity;

    std::vector<Mount> mounts;
    int rootfs_propagation;
    std::vector<std::string> masked_paths;
    std::vector<std::string> readonly_paths;

    nlohmann::json prestart_hooks;
    std::vector<Namespace> namespaces;
    uid_t uid;
    gid_t gid;
    bool terminal;
    pid_t proxy_pid;
    std::string console_socket;
    size_t vmem;
    int mpk_domain;
    uint64_t start_delay;
    bool enable_dynamic_syscall_rewrite;
    bool enable_clone;
    bool enable_fork;
    bool enable_execve;
    bool enable_vtcp_accept;
    bool enable_vtcp_connect;
    bool enable_ioworker;
    bool enable_vdso;
    bool enable_vsocketpair;
    bool enable_write_exec;
    bool enable_exec_noinspect;
    bool enable_hook;
    bool drop_ref;
    void *plugin;
    nlohmann::json plugin_config;
};

struct NamespaceFiles {
    NamespaceFiles() : netns_fd(-1), utsns_fd(-1) {}
    ~NamespaceFiles();
    int netns_fd;
    int utsns_fd;
};

struct ProxyProcess {
    ProxyProcess() : pid(-1) {}
    ~ProxyProcess();
    void exit(int ret, int sig);
    pid_t pid;
};

struct Program {
    enum Status {
        Creating = 0,
        Created = 1,
        Started = 2,
        Terminated = 3,
    };
    Program() : status(Created) {}
    ~Program();
    std::shared_ptr<Task> task;
    std::unique_ptr<NamespaceFiles> ns_files;
    std::unique_ptr<ProxyProcess> proxy_process;
    nlohmann::json prestart_hooks;
    Status status;
};

struct BreakpointManager;
class CodeInspector;
class TaskManager;
struct TaskManagerReference;
class VirtualNetwork;
class Runtime {
public:
    inline static Runtime *get() {
        return runtime;
    }
    static void create(const RuntimeConfiguration &config);
    void load_program(const RuntimeConfiguration &runtime_config,
                      const ProgramConfiguration &config, int sock);
    void start();
    TaskManager *get_tm() {
        return tm.get();
    }
    BreakpointManager *get_bpm() {
        return bpm.get();
    }
    CodeInspector *get_ci() {
        return ci.get();
    }
    void *get_vdso_base() {
        return vdso_base;
    }
    const RuntimeConfiguration &get_config() {
        return config;
    }
    int get_placeholder_fd() {
        return placeholder_fd;
    }
#ifdef CONFIG_ENABLE_TIME_TRACE
    const MemoryRegion &get_trace_buffer() {
        return trace_buffer;
    }
#endif
    //void add_symbol(uintptr_t ptr, size_t size, const std::string &name);
private:
    Runtime(const RuntimeConfiguration &config_);
    void init();
    void handle_api();
    void handle_cmd_create(int fd, nlohmann::json &args);
    void handle_cmd_start(int fd, nlohmann::json &args);
    void handle_cmd_delete(int fd, nlohmann::json &args);
    void handle_cmd_kill(int fd, nlohmann::json &args);
    static Runtime *runtime;
    RuntimeConfiguration config;

    std::unique_ptr<TaskManager> tm;
    std::unique_ptr<BreakpointManager> bpm;
    std::unique_ptr<CodeInspector> ci;
    std::shared_ptr<TaskManagerReference> ref;
    std::weak_ptr<TaskManagerReference> ref_weak;
    std::unique_ptr<std::thread> api_thread;
    std::mutex mutex;
    std::unordered_map<std::string, std::shared_ptr<Program>> programs;
    MemoryRegion trace_buffer;
    void *vdso_base;
    int placeholder_fd;
    int api_fd;
    //FILE *file_perf_map;
    //std::mutex mutex_perf_map;
};
}