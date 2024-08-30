#include <memory>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <fstream>
#include <iostream>
#include <dlfcn.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/fsuid.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <linux/time_types.h>
#include "json.hpp"
#include "pegasus/breakpoint.h"
#include "pegasus/code_inspect.h"
#include "pegasus/exception.h"
#include "pegasus/file.h"
#include "pegasus/mm.h"
#include "pegasus/monitor.h"
#include "pegasus/mount.h"
#include "pegasus/runtime.h"
#include "pegasus/sched.h"
#include "pegasus/syscall.h"
#include "pegasus/uswitch.h"
#include "pegasus/util.h"
#include "pegasus/vdso.h"
#include "pegasus/network/network.h"

using namespace nlohmann;
using namespace pegasus;

Runtime *Runtime::runtime;

RuntimeConfiguration::RuntimeConfiguration()
    : num_threads(1), rewrite_rule_filename(),
      enable_code_inspection(true), log_code_inspection(false),
      enable_breakpoint(true), enable_fork(false),
      enable_vtcp(false), enable_poll(false), enable_vdso(true),
      poll_threshold(0.0), enable_vsocketpair(false),
      enable_perf_map(false), send_ready_signal(false), cluster_mode(false),
      cluster_sched(false), cluster_data(nullptr)
#ifdef CONFIG_ENABLE_TIME_TRACE
      , enable_time_trace(false), trace_buffer_size(1024 * 1024), trace_buffer_pkey(0),
      trace_output_file("trace.data")
#endif
{
}

ProgramConfiguration::ProgramConfiguration()
    : rootfs_ro(false), fds{}, rootfs_propagation(0),
      uid(0), gid(0), terminal(false), proxy_pid(-1),
      vmem(1ul << 40), mpk_domain(-1), start_delay(0),
      enable_dynamic_syscall_rewrite(true), enable_clone(true), enable_fork(false), enable_execve(false),
      enable_vtcp_accept(false), enable_vtcp_connect(false), enable_ioworker(false), enable_vdso(true),
      enable_vsocketpair(false), enable_write_exec(false), enable_exec_noinspect(false),
      enable_hook(false), drop_ref(false), plugin(nullptr)
      {
    
}

ProgramConfiguration::~ProgramConfiguration() {
    for (int fd : fds) {
        close(fd);
    }
}

void Runtime::create(const RuntimeConfiguration &config) {
    if (runtime) {
        return;
    }
    runtime = new Runtime(config);
    runtime->init();
}

Runtime::Runtime(const RuntimeConfiguration &config_) :
    config(config_), api_fd(-1), vdso_base(nullptr) /*, file_perf_map(nullptr)*/ {
}

extern unsigned char linux_vdso_so_1_so[];
extern unsigned int linux_vdso_so_1_so_len;

void Runtime::init() {
    //if (config.ioworker_config.enabled) {
    //    IOWorker::global_init(config.ioworker_config);
    //}
    if (config.enable_breakpoint) {
        bpm.reset(new BreakpointManager);
        bpm->init_global();
    }
    placeholder_fd = open("/dev/null", O_RDONLY);
    if (placeholder_fd == -1) {
        throw Exception("cannot open placeholder fd /dev/null");
    }
    init_global();
    if (config.enable_code_inspection) {
        ci.reset(new CodeInspector(config.rewrite_rule_filename));
        if (!ci->inspect_process()) {
            printf("failed to inspect code\n");
            //throw Exception("failed to inspect code");
        }
    }
#ifdef CONFIG_ENABLE_TIME_TRACE
    size_t page_size = page_round_up(config.trace_buffer_size);
    void *buffer = mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (buffer == MAP_FAILED) {
        throw Exception("failed to allocate trace buffer");
    }
    if (pkey_mprotect(buffer, page_size, PROT_READ | PROT_WRITE,
                      config.trace_buffer_pkey) == -1) {
        throw Exception("failed to set pkey for trace buffer"); 
    }
    trace_buffer.base = (uint8_t *)buffer;
    trace_buffer.size = config.trace_buffer_size;
    *(uint64_t *)buffer = 16;
#endif
    tm.reset(new TaskManager(config.num_threads, config.ioworker_config.enabled,
                             !config.cores.empty(), config.cores));
    ref = std::make_shared<TaskManagerReference>(tm.get());
    ref_weak = ref;

    if (config.enable_vdso) {
        //size_t size = linux_vdso_so_1_so_len;
        //size_t size_aligned = page_round_up(size);
        //void *addr = ::mmap(nullptr, size_aligned, PROT_READ | PROT_WRITE,
        //                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        //if (addr == MAP_FAILED) {
        //    throw Exception("failed to allocate page for vDSO");
        //}
        //memcpy(addr, linux_vdso_so_1_so, size);
        //if (pkey_mprotect(addr, size_aligned, PROT_READ | PROT_EXEC, PkeyReadonly) == -1) {
        //    throw Exception("failed to set permission for vDSO page");
        //}
        //vdso_base = addr;
        vdso_base = ::get_vdso_base();
    }

    api_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (api_fd == -1) {
        throw Exception("cannot create api socket");
    }
    struct sockaddr_un name;
    name.sun_family = AF_UNIX;
    unlink(config.api_uds_path.c_str());
    strncpy(name.sun_path, config.api_uds_path.c_str(), sizeof(name.sun_path) - 1);
    if (bind(api_fd, (struct sockaddr *)&name, sizeof(struct sockaddr_un)) == -1) {
        throw Exception("cannot bind api socket");
    }
    if (listen(api_fd, 4) == -1) {
        throw Exception("cannot listen api socket");
    }
    printf("ready\n");
    if (config.send_ready_signal) {
        pid_t ppid = getppid();
        kill(ppid, SIGUSR1);
    }

    //if (config.enable_perf_map) {
    //    const std::string &filename = "/tmp/perf-" + std::to_string(getpid()) + ".map";
    //    file_perf_map = fopen(filename.c_str(), "w");
    //    if (!file_perf_map) {
    //        throw Exception("failed to open perf map file");
    //    }
    //}
}

static void dup_files(const std::shared_ptr<USwitchContext> &ucontext, const std::vector<int> &fds) {
    for (int i = 0; i < (int)fds.size(); ++i) {
        if (ucontext->get_file_from_priv(fds[i]) != i) {
            throw Exception("failed to dup file");
        }
    }
}

static void send_fd(int sock, int fd) {
    struct msghdr msgh;
    struct iovec iov;
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg;
    msgh.msg_name = nullptr;
    msgh.msg_namelen = 0;
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    int data = 0;
    iov.iov_base = &data;
    iov.iov_len = sizeof(int);
    msgh.msg_control = cmsg.buf;
    msgh.msg_controllen = sizeof(cmsg.buf);
    struct cmsghdr *cmsgp = CMSG_FIRSTHDR(&msgh);
    cmsgp->cmsg_level = SOL_SOCKET;
    cmsgp->cmsg_type = SCM_RIGHTS;
    cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsgp), &fd, sizeof(int));
    if (sendmsg(sock, &msgh, 0) == -1) {
        throw Exception("failed to send fd to console sock: " + std::string(strerror(errno)));
    }
}

static void send_fd(const std::string &path, int fd) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        throw Exception("failed to open console socket (" + path + "): " + strerror(errno));
    }
    struct sockaddr_un name;
    name.sun_family = AF_UNIX;
    strncpy(name.sun_path, path.c_str(), sizeof(name.sun_path) - 1);
    if (connect(sock, (struct sockaddr *)&name, sizeof(name)) == -1) {
        close(sock);
        throw Exception("failed to connect to console socket: " + std::string(strerror(errno)));
    }
    try {
        send_fd(sock, fd);
    } catch (...) {
        close(sock);
        throw;
    }
    close(sock);
}

void send_fds(int sock, const std::vector<int> &fds) {
    struct msghdr msgh;
    struct iovec iov;
    size_t len = sizeof(int) * fds.size();
    size_t len_buf = CMSG_SPACE(len);
    std::vector<uint8_t> buf(len_buf);

    msgh.msg_name = nullptr;
    msgh.msg_namelen = 0;
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    int data = 0;
    iov.iov_base = &data;
    iov.iov_len = sizeof(int);
    msgh.msg_control = buf.data();
    msgh.msg_controllen = len_buf;
    struct cmsghdr *cmsgp = CMSG_FIRSTHDR(&msgh);
    cmsgp->cmsg_level = SOL_SOCKET;
    cmsgp->cmsg_type = SCM_RIGHTS;
    cmsgp->cmsg_len = CMSG_LEN(len);
    memcpy(CMSG_DATA(cmsgp), fds.data(), len);
    if (sendmsg(sock, &msgh, 0) == -1) {
        throw Exception("failed to send fds: " + std::string(strerror(errno)));
    }
}

static void recv_fd(int sock, int num_fds, std::vector<int> &fds) {
    struct msghdr msgh;
    struct iovec iov;
    int data;
    ssize_t nr;
    size_t len_buf = CMSG_SPACE(sizeof(int) * num_fds);

    std::vector<uint8_t> buf(len_buf);
    msgh.msg_name = nullptr;
    msgh.msg_namelen = 0;
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    iov.iov_base = &data;
    iov.iov_len = sizeof(int);
    msgh.msg_control = buf.data();
    msgh.msg_controllen = len_buf;
    nr = recvmsg(sock, &msgh, 0);
    if (nr == -1) {
        throw Exception("failed to recvmsg for preserve-fds: " + std::string(strerror(errno)));
    }
    struct cmsghdr *cmsgp = CMSG_FIRSTHDR(&msgh);
    if (!cmsgp || cmsgp->cmsg_len != CMSG_LEN(sizeof(int) * num_fds) ||
        cmsgp->cmsg_level != SOL_SOCKET || cmsgp->cmsg_type != SCM_RIGHTS) {
        throw Exception("corrupted msg for preserve-fds");
    }
    fds.resize(num_fds);
    memcpy(fds.data(), CMSG_DATA(cmsgp), sizeof(int) * num_fds);
}

static void init_terminal(const std::shared_ptr<USwitchContext> &ucontext,
                          const ProgramConfiguration &pc,
                          int *terminal_fds) {
    int fd_master = terminal_fds[0];
    int fd_slave = terminal_fds[1];
    ucontext->run_on_behalf_of([&] {
        int fd0 = fd_slave;
        int fd1 = dup(fd_slave);
        int fd2 = dup(fd_slave);
        dup2(fd0, 0);
        dup2(fd1, 1);
        dup2(fd2, 2);
        close(fd0);
        close(fd1);
        close(fd2);
    });
    int fd_master_priv = ucontext->get_file(fd_master);
    if (fd_master_priv == -1) {
        throw Exception("failed to get master pty: " + std::string(strerror(errno)));
    }
    ucontext->run_on_behalf_of([&] {
        close(fd_master);
    });
    send_fd(pc.console_socket, fd_master_priv);
    close(fd_master_priv);
}

static void init_namespaces(const std::shared_ptr<USwitchContext> &ucontext,
                            const ProgramConfiguration &pc,
                            NamespaceFiles *ns_files) {
    int ns_flags = 0;
    int unshare_flags = 0;
    for (const Namespace &ns : pc.namespaces) {
        ns_flags |= ns.flag;
        if (ns.path.empty()) {
            unshare_flags |= ns.flag;
        }
    }
    ucontext->run_on_behalf_of([&] {
        if (unshare(unshare_flags) == -1) {
            throw Exception("failed to create new namespaces: " + std::string(strerror(errno)));
        }
        for (const Namespace &ns : pc.namespaces) {
            if (!ns.path.empty()) {
                int fd = open(ns.path.c_str(), O_RDONLY);
                if (fd == -1) {
                    throw Exception("failed to open nanmespace file (" +
                        ns.path + "): " + std::string(strerror(errno)));
                }
                if (setns(fd, ns.flag) == -1) {
                    close(fd);
                    throw Exception("failed to setns (" +
                        ns.path + "): " + std::string(strerror(errno)));
                }
                close(fd);
            }
        }
    });
    int fd;
    ucontext->run_on_behalf_of([&] {
        fd = open("/proc/thread-self/ns/net", O_RDONLY);
        if (fd == -1) {
            throw Exception("failed to open net ns file: " + std::string(strerror(errno)));
        }
    });
    ns_files->netns_fd = ucontext->get_file(fd);
    if (ns_files->netns_fd == -1) {
        throw Exception("failed to get net ns fd: " + std::string(strerror(errno)));
    }
    ucontext->run_on_behalf_of([&] {
        if (close(fd) == -1) {
            throw Exception("failed to close net ns file: " + std::string(strerror(errno)));
        }
    });

    ucontext->run_on_behalf_of([&] {
        fd = open("/proc/thread-self/ns/uts", O_RDONLY);
        if (fd == -1) {
            throw Exception("failed to open utsns ns file: " + std::string(strerror(errno)));
        }
    });
    ns_files->utsns_fd = ucontext->get_file(fd);
    if (ns_files->utsns_fd == -1) {
        throw Exception("failed to get net ns fd: " + std::string(strerror(errno)));
    }
    ucontext->run_on_behalf_of([&] {
        if (close(fd) == -1) {
            throw Exception("failed to close uts ns file: " + std::string(strerror(errno)));
        }
    });
}

static void init_uid_gid(const std::shared_ptr<USwitchContext> &ucontext, int uid, int gid) {
    int err = 0;
    ucontext->run_on_behalf_of([&] {
        if (syscall(SYS_setgid, gid) == -1) {
            err = errno;
        }
    });
    if (err) {
        throw Exception("failed to setgid");
    }
    ucontext->run_on_behalf_of([&] {
        if (syscall(SYS_setuid, uid) == -1) {
            err = errno;
        }
    });
    if (err) {
        throw Exception("failed to setuid");
    }
    //prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
}

static void init_close_fd(const std::shared_ptr<USwitchContext> &ucontext, int num_fds) {
    int err = 0;
    ucontext->run_on_behalf_of([&] {
        err = close_range(num_fds, INT_MAX, 0);
    });
    if (err) {
        throw Exception("failed to close fds");
    }
}

static void write_msg(int fd, const std::string &msg) {
    ssize_t res = write(fd, msg.c_str(), msg.length());
    (void)res;
    return;
}

static void read_dummy_msg(int fd) {
    char buf[1] = {};
    ssize_t res = read(fd, &buf, sizeof(buf));
    if (res < 0) {
        throw Exception(strerror(errno));
    }
}

static void send_response(int fd, const std::string &status) {
    json resp;
    resp["status"] = status;
    const std::string &msg = resp.dump();
    write_msg(fd, msg);
}

static json get_container_state(const ProgramConfiguration &config, int status) {
    json res;
    const char *s = "";
    switch (status) {
    case Program::Creating: s = "creating"; break;
    case Program::Created: s = "created"; break;
    case Program::Started: s = "running"; break;
    case Program::Terminated: s = "stopped"; break;
    }
    res["ociVersion"] = "0.2.0";
    res["status"] = s;
    res["id"] = config.id;
    res["pid"] = config.proxy_pid;
    res["bundle"] = config.bundle;
    return res;
}

void Runtime::load_program(const RuntimeConfiguration &runtime_config,
                           const ProgramConfiguration &config, int sock) {
    uint64_t mmcap = MM::DefaultCap;
    uint64_t cap = 0;
    if (config.enable_clone) {
        cap |= VProcess::CapClone;
    }
    if (config.enable_fork) {
        cap |= VProcess::CapFork;
        mmcap |= MM::CapFork;
    }
    if (config.enable_execve) {
        cap |= VProcess::CapExec;
    }
    if (config.enable_vtcp_accept) {
        cap |= VProcess::CapVTCPAccept;
    }
    if (config.enable_vtcp_connect) {
        cap |= VProcess::CapVTCPConnect;
    }
    if (config.enable_ioworker) {
        cap |= VProcess::CapDSocket;
    }
    if (config.enable_vdso) {
        cap |= VProcess::CapVDSO;
    }
    if (config.enable_vsocketpair) {
        cap |= VProcess::CapVSocketPair;
    }
    if (config.enable_write_exec) {
        mmcap |= MM::CapMapWriteExecReal;
    }
    if (config.enable_exec_noinspect) {
        mmcap |= MM::CapMapExecNoInspect;
    }

    std::lock_guard lock(mutex);
    auto it = programs.find(config.id);
    if (it != programs.end()) {
        throw Exception("id already exist");
    }
    std::shared_ptr<MM> mm = std::make_shared<MM>(config.vmem, config.mpk_domain, mmcap);
    std::shared_ptr<USwitchContext> ucontext = std::make_shared<USwitchContext>();

    dup_files(ucontext, config.fds);
    std::unique_ptr<NamespaceFiles> ns_files(new NamespaceFiles);
    std::unique_ptr<ProxyProcess> proxy_process(new ProxyProcess);
    init_namespaces(ucontext, config, ns_files.get());

    proxy_process->pid = config.proxy_pid;
    json resp;
    resp["status"] = "ok";
    resp["state"] = get_container_state(config, Program::Creating);
    resp["hook"] = config.prestart_hooks;
    write_msg(sock, resp.dump());
    send_fds(sock, {ns_files->netns_fd, ns_files->utsns_fd});
    // wait for hooks
    read_dummy_msg(sock);

    int terminal_fds[2];
    init_mount(ucontext, config, config.terminal ? terminal_fds : nullptr);
    if (config.terminal) {
        init_terminal(ucontext, config, terminal_fds);
    }
    //init_default_devices(ucontext, config);
    init_uid_gid(ucontext, config.uid, config.gid);
    init_close_fd(ucontext, (int)config.fds.size());
    ucontext->run_on_behalf_of([&] {
        if (chdir(config.working_directory.c_str()) == -1) {
            throw Exception("failed to chdir: " + std::string(strerror(errno)));
        }
    });

    std::shared_ptr<NetworkContext> network =
        NetworkContext::get_network_context(ucontext.get(), ns_files->netns_fd);
    std::shared_ptr<VProcess> vprocess = VProcess::create(mm, ucontext, ref, network);
    vprocess->cap = cap;

    if (config.enable_dynamic_syscall_rewrite) {
        vprocess->enable_dynamic_syscall_rewriting();
    }
    std::shared_ptr<Task> task =
        vprocess->load_program(config.program.c_str(), config.args, config.envs, config.affinity);
    std::shared_ptr<Program> program = std::make_shared<Program>();
    program->task = task;
    program->ns_files = std::move(ns_files);
    program->proxy_process = std::move(proxy_process);
    program->prestart_hooks = std::move(config.prestart_hooks);
    vprocess->on_exit = [p = std::weak_ptr<Program>(program)] (int retval, int sig) {
        std::shared_ptr<Program> prog = p.lock();
        if (!prog) {
            return;
        }
        prog->proxy_process->exit(retval, sig);
    };
    programs[config.id] = program;
}

void Runtime::start() {
    api_thread.reset(new std::thread([this] {
        handle_api();
    }));
    tm->run();
    unlink(config.api_uds_path.c_str());
}

void Runtime::handle_api() {
    static constexpr size_t CommandBufferSize = 8192;
    std::vector<uint8_t> buf(CommandBufferSize);
    init_cpu();
    while (true) {
        int fd = accept(api_fd, nullptr, nullptr);
        if (fd == -1) {
            break;
        }
        ssize_t len = read(fd, buf.data(), CommandBufferSize);
        if (len == -1) {
            break;
        }
        json payload;
        try {
            payload = json::parse(buf.data(), buf.data() + len);
        } catch (...) {
            continue;
        }
        auto it = payload.find("command");
        if (it == payload.end()) {
            continue;
        }
        std::string cmd = it->get<std::string>();
        try {
            if (cmd == "create") {
                handle_cmd_create(fd, payload);
            } else if (cmd == "start") {
                handle_cmd_start(fd, payload);
            } else if (cmd == "delete") {
                handle_cmd_delete(fd, payload);
            } else if (cmd == "kill") {
                handle_cmd_kill(fd, payload);
            }
        } catch (std::exception &e) {
            printf("err: %s\n", e.what());
            send_response(fd, e.what());
        }
        close(fd);

    }
    printf("daemon exited");
}

void Runtime::handle_cmd_create(int fd, nlohmann::json &args) {
    std::string bundle = args["bundle"].get<std::string>();
    std::string container_id = args["container-id"].get<std::string>();
    std::string console_socket;
    bool drop_ref = false;
    pid_t proxy_pid = -1;
    auto it = args.find("console-socket");
    if (it != args.end()) {
        console_socket = it->get<std::string>();
    }
    it = args.find("pid");
    if (it != args.end()) {
        proxy_pid = it->get<pid_t>();
    }
    it = args.find("drop_ref");
    if (it != args.end()) {
        drop_ref = it->get<bool>();
    }
    int preserve_fds = 0;
    it = args.find("preserve-fds");
    if (it != args.end()) {
        preserve_fds = it->get<int>();
    }
    if (preserve_fds < 0) {
        throw Exception("preserve-fds is less than 0");
    }
    preserve_fds += 3;

    std::ifstream ifs(bundle + "/config.json");
    if (!ifs) {
        throw Exception("failed to open config file");
    }
    json config = json::parse(ifs);
    auto process = config["process"];
    auto user = process["user"];
    std::vector<std::string> argv = process["args"].get<std::vector<std::string>>();
    std::vector<std::string> env = process["env"].get<std::vector<std::string>>();
    uid_t uid = user["uid"].get<uid_t>();
    gid_t gid = user["gid"].get<gid_t>();
    std::string cwd = process["cwd"].get<std::string>();
    bool terminal = false;
    it = process.find("terminal");
    if (it != process.end()) {
        terminal = it->get<bool>();
    }
    auto rootfs = config["root"];
    std::string rootfs_path = rootfs["path"].get<std::string>();
    it = rootfs.find("readonly");
    bool rootfs_readonly = false;
    if (it != rootfs.end()) {
        rootfs_readonly = it->get<bool>();
    }
    std::string bin;
    if (argv.size() >= 1) {
        bin = argv[0];
    }

    ProgramConfiguration pc;
    pc.bundle = bundle;
    pc.args = argv;
    if (!rootfs_path.empty() && rootfs_path[0] != '/') {
        pc.rootfs = bundle + "/" + rootfs_path;
    } else {
        pc.rootfs = rootfs_path;
    }
    pc.rootfs_ro = rootfs_readonly;
    pc.envs = env;
    pc.program = bin;
    pc.enable_dynamic_syscall_rewrite = true;
    pc.enable_clone = true;
    pc.enable_execve = true;
    pc.enable_vdso = true;
    pc.enable_write_exec = true;
    if (!get_config().hook_so.empty()) {
        pc.enable_hook = true;
    }
    pc.working_directory = cwd;
    pc.id = container_id;
    pc.uid = uid;
    pc.gid = gid;
    pc.terminal = terminal;
    pc.console_socket = console_socket;
    pc.proxy_pid = proxy_pid;
    pc.drop_ref = drop_ref;
    recv_fd(fd, preserve_fds, pc.fds);

    auto mounts = config.find("mounts");
    if (mounts != config.end()) {
        for (auto &&m : *mounts) {
            std::string dest = m["destination"].get<std::string>();
            std::string type = m["type"].get<std::string>();
            std::string source;
            std::vector<std::string> options;
            it = m.find("source");
            if (it != m.end()) {
                source = it->get<std::string>();
            }
            it = m.find("options");
            if (it != m.end()) {
                options = it->get<std::vector<std::string>>();
            }
            Mount mount;
            mount.destination = dest;
            mount.type = type;
            mount.source = source;
            mount.options = options;
            pc.mounts.push_back(mount);
        }
    }
    it = config.find("rootfsPropagation");
    if (it != config.end()) {
        std::string rp = it->get<std::string>();
        if (rp == "shared") {
            pc.rootfs_propagation = MS_SHARED;
        } else if (rp == "private") {
            pc.rootfs_propagation = MS_PRIVATE;
        } else if (rp == "slave") {
            pc.rootfs_propagation = MS_SLAVE;
        } else if (rp == "unbindable") {
            pc.rootfs_propagation = MS_UNBINDABLE;
        } else {
            throw Exception("invalid rootPropagation: " + rp);
        }
    }
    it = config.find("maskedPaths");
    if (it != config.end()) {
        pc.masked_paths = it->get<std::vector<std::string>>();
    }
    it = config.find("readonlyPaths");
    if (it != config.end()) {
        pc.readonly_paths = it->get<std::vector<std::string>>();
    }
    if (pc.enable_hook) {
        Mount mount;
        mount.destination = "/lib/libpegasus_hook.so";
        mount.source = get_config().hook_so;
        mount.type = "bind";
        mount.options.push_back("ro");
        mount.options.push_back("bind");
        pc.mounts.push_back(mount);
        bool has_ld_preload = false;
        for (std::string &s : pc.envs) {
            if (startswith(s, "LD_PRELOAD=")) {
                has_ld_preload = true;
                s += ":" + mount.destination;
                break;
            }
        }
        if (!has_ld_preload) {
            pc.envs.push_back("LD_PRELOAD=" + mount.destination);
        }
    }
    it = config.find("linux");
    pc.namespaces.emplace_back(Namespace {CLONE_NEWNS, ""});
    if (it != config.end()) {
        auto linux_config = *it;
        auto namespaces = linux_config.find("namespaces");
        if (namespaces != linux_config.end()) {
            for (auto &&n : *namespaces) {
                std::string type = n["type"].get<std::string>();
                std::string path;
                auto it2 = n.find("path");
                if (it2 != n.end()) {
                    path = it2->get<std::string>();
                }
                int ns_flags = 0;
                if (type == "network") {
                    ns_flags = CLONE_NEWNET;
                } else if (type == "uts") {
                    ns_flags = CLONE_NEWUTS;
                }
                if (ns_flags != 0) {
                    pc.namespaces.emplace_back(Namespace {ns_flags, path});
                }
            }
        }
    }
    auto hooks = config.find("hooks");
    if (hooks != config.end()) {
        auto it = hooks->find("prestart");
        if (it != hooks->end()) {
            pc.prestart_hooks = *it;
        }
    }
    load_program(get_config(), pc, fd);
    if (drop_ref) {
        ref.reset();
    }
    send_response(fd, "ok");
    printf("container %s created\n", pc.id.c_str());
}

void Runtime::handle_cmd_start(int fd, nlohmann::json &args) {
    std::string container_id = args["container-id"].get<std::string>();
    std::shared_ptr<Task> task;
    {
        std::lock_guard lock(mutex);
        auto it = programs.find(container_id);
        if (it == programs.end()) {
            throw Exception("container not found");
        }
        task = it->second->task;
        if (it->second->status != Program::Created) {
            throw Exception("container already started");
        }
        it->second->status = Program::Started;
    }
    VProcess *vprocess = task->vthread->get_vprocess();
    vprocess->start(nullptr);
    send_response(fd, "ok");
    printf("container %s started tgid %d\n", container_id.c_str(), vprocess->get_tgid());
}

void Runtime::handle_cmd_delete(int fd, nlohmann::json &args) {
    std::string container_id = args["container-id"].get<std::string>();
    std::shared_ptr<Task> task;
    {
        std::lock_guard lock(mutex);
        auto it = programs.find(container_id);
        if (it == programs.end()) {
            throw Exception("container not found");
        }
        programs.erase(it);
    }
    send_response(fd, "ok");
    printf("container %s deleted\n", container_id.c_str());
}

void Runtime::handle_cmd_kill(int fd, nlohmann::json &args) {
    std::string container_id = args["container-id"].get<std::string>();
    int sig = args["signal"].get<int>();
    bool all = false;
    auto it = args.find("all");
    if (it != args.end()) {
        all = it->get<bool>();
    }
    std::shared_ptr<Task> task;
    {
        std::lock_guard lock(mutex);
        auto it = programs.find(container_id);
        if (it == programs.end()) {
            throw Exception("container not found");
        }
        if (it->second->status != Program::Started) {
            throw Exception("container not started");
        }
        task = it->second->task;
    }
    if (sig < 1 || sig > 64) {
        throw Exception("invalid signal: " + std::to_string(sig));
    }
    VProcess *vprocess = task->vthread->get_vprocess();
    if (all) {
        vprocess->send_signal_all(sig);
    } else {
        vprocess->send_signal(sig, nullptr);
    }
    send_response(fd, "ok");
    printf("container %s killed with signal %d\n", container_id.c_str(), sig);
}

Program::~Program() {
}

NamespaceFiles::~NamespaceFiles() {
    if (netns_fd != -1) {
        close(netns_fd);
    }
    if (utsns_fd != -1) {
        close(utsns_fd);
    }
}

ProxyProcess::~ProxyProcess() {
}

void ProxyProcess::exit(int ret, int sig) {
    if (pid == -1) {
        return;
    }
    if (sig) {
        kill(pid, sig);
    } else {
        //kill(pid, SIGURG);
        union sigval val;
        val.sival_int = ret;
        sigqueue(pid, SIGURG, val);
    }
}

#ifdef CONFIG_ENABLE_TIME_TRACE
void pegasus::pegasus_trace_time(int tag) {
    const MemoryRegion &buffer = Runtime::get()->get_trace_buffer();
    uint64_t *buf = (uint64_t *)buffer.base;
    uint64_t idx = __atomic_fetch_add(buf, 16, __ATOMIC_RELAXED);
    if (idx < buffer.size) {
        uint64_t *p = (uint64_t *)(buffer.base + idx);
        p[0] = tag;
        p[1] = __rdtsc();
    }
}
#endif

//void Runtime::add_symbol(uintptr_t ptr, size_t size, const std::string &name) {
//    if (!file_perf_map) {
//        return;
//    }
//    std::lock_guard lock(mutex_perf_map);
//    fprintf(file_perf_map, "%lx %lx %s\n", ptr, size, name.c_str());
//}

//Plugin::~Plugin() {
//}
