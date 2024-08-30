#include <string>
#include <cstdio>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <climits>
#include <fstream>
#include <unistd.h>
#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sched.h>
#include <CLI/CLI.hpp>
#include <json.hpp>
#include "pegasus/exception.h"

using namespace nlohmann;
using namespace pegasus;

static std::string sock = "/var/run/pegasus.sock";
static std::string log_file;
static std::string log_format;
static std::string root = "/var/run/pegasus/";
static bool systemd_cgroup;

static std::string bundle = ".";
static std::string console_socket;
static std::string pid_file;
static int preserve_fds;
static std::string container_id;

static int kill_signal = SIGTERM;
static bool kill_all;
static bool force;

int argc;
char **argv;

static void write_log(const std::string &line) {
    std::string log_line;
    char buf[64];
    time_t now;
    time(&now);
    strftime(buf, sizeof(buf), "%FT%TZ", gmtime(&now));
    json log;
    log["log"] = line + "\n";
    log["stream"] = "stdout";
    log["time"] = buf;
    log_line = log.dump();
    if (!log_file.empty()) {
        std::ofstream ofs(log_file);
        if (!ofs) {
            return;
        }
        ofs << log_line << "\n";
    }
}

struct UDSConn {
    UDSConn(int sock);
    UDSConn(const std::string &path);
    ~UDSConn();
    void send(int msg);
    void send(const std::string &msg);
    void send(const json &msg);
    void send_fds(const std::vector<int> &fds);
    void send_dummy_msg();
    int recv_int();
    json recv_json();
    void recv_fds(int num_fds, std::vector<int> &fds);
    void recv_dummy_msg();
    int sock;
};

UDSConn::UDSConn(int sock_) : sock(sock_) {
}

UDSConn::UDSConn(const std::string &path) {
    sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (sock == -1) {
        throw Exception("failed to open daemon socket: " + std::string(strerror(errno)));
    }
    struct sockaddr_un name;
    name.sun_family = AF_UNIX;
    strncpy(name.sun_path, path.c_str(), sizeof(name.sun_path) - 1);
    if (connect(sock, (struct sockaddr *)&name, sizeof(name)) == -1) {
        close(sock);
        throw Exception("failed to connect to daemon socket: " + std::string(strerror(errno)));
    }
}

UDSConn::~UDSConn() {
    if (sock != -1) {
        close(sock);
    }
}

void UDSConn::send(int msg) {
    ssize_t res = write(sock, &msg, sizeof(msg));
    if (res <= 0) {
        throw Exception("failed to send");
    }
}

void UDSConn::send(const std::string &msg) {
    ssize_t res = write(sock, msg.c_str(), msg.length());
    if (res <= 0) {
        throw Exception("failed to send");
    }
}

void UDSConn::send(const json &msg) {
    const std::string &str = msg.dump();
    send(str);
}

void UDSConn::send_fds(const std::vector<int> &fds) {
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

void UDSConn::send_dummy_msg() {
    char buf[1] = {};
    ssize_t len = write(sock, buf, sizeof(buf));
    if (len <= 0) {
        throw Exception(strerror(errno));
    }
}

int UDSConn::recv_int() {
    int buf;
    ssize_t res = read(sock, &buf, sizeof(buf));
    if (res <= 0) {
        throw Exception(strerror(errno));
    }
    return buf;
}

json UDSConn::recv_json() {
    static constexpr size_t BufferSize = 8192;
    std::vector<uint8_t> buf(BufferSize);
    ssize_t res = read(sock, buf.data(), buf.size());
    if (res == -1) {
        throw Exception("failed to receive: " + std::string(strerror(errno)));
    }
    json resp = json::parse(buf.data(), buf.data() + res);
    if (resp["status"] != "ok") {
        throw Exception(resp["status"].get<std::string>());
    }
    return resp;
}

void UDSConn::recv_fds(int num_fds, std::vector<int> &fds) {
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

void UDSConn::recv_dummy_msg() {
    char buf[1];
    ssize_t len = read(sock, buf, sizeof(buf));
    if (len <= 0) {
        throw Exception(strerror(errno));
    }
}

void handler_sigurg(int sig, siginfo_t *info, void *ucontext) {
    exit(info->si_value.sival_int);
}

static void run_proxy_process(int &fd) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == -1) {
        throw Exception("failed to create sockpair for proxy process: " + std::string(strerror(errno)));
    }
    pid_t p = fork();
    if (p == -1) {
        throw Exception("failed to fork proxy process: " + std::string(strerror(errno)));
    }
    if (p > 0) {
        fd = fds[0];
        close(fds[1]);
        return;
    }
    close(fds[0]);

    struct sigaction act = {};
    act.sa_sigaction = handler_sigurg;
    sigaction(SIGURG, &act, nullptr);

    UDSConn conn(fds[1]);
    //setsid();
    p = fork();
    if (p == -1) {
        conn.send(-errno);
        exit(1);
    } else if (p > 0) {
        conn.send(p);
        exit(0);
    }
    std::vector<int> ns_fds(2);
    conn.recv_fds(ns_fds.size(), ns_fds);
    int netns_fd = ns_fds[0];
    if (setns(netns_fd, CLONE_NEWNET) == -1) {
        conn.send(errno);
        exit(1);
    }
    int utsns_fd = ns_fds[1];
    if (setns(utsns_fd, CLONE_NEWUTS) == -1) {
        conn.send(errno);
        exit(1);
    }
    conn.send(0);
    close_range(0, INT_MAX, 0);
    conn.sock = -1;
    pause();
    exit(0);
}

static void write_all(int fd, const std::string &msg) {
    const char *p = msg.data();
    size_t size = msg.size();
    size_t written = 0;
    while (written < size) {
        ssize_t res = write(fd, p, size - written);
        if (res <= 0) {
            throw Exception("error to write to pipe: " + std::string(strerror(errno)));
        }
        written += res;
        p += res;
    }
}

static void run_hook(const std::string &path, const std::vector<std::string> &args,
                     const std::vector<std::string> &env, int timeout,
                     const std::string &state) {
    pid_t pid;
    std::vector<const char *> argv, envp;
    for (const std::string &a : args) {
        argv.push_back(a.data());
    }
    argv.push_back(nullptr);
    for (const std::string &e : env) {
        envp.push_back(e.data());
    }
    envp.push_back(nullptr);
    int fds[2];
    if (pipe(fds) == -1) {
        close(fds[0]);
        close(fds[1]);
        throw Exception("failed to create pipe: " + std::string(strerror(errno)));
    }
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    int res = posix_spawn_file_actions_adddup2(&fa, fds[0], 0);
    if (res != 0) {
        close(fds[0]);
        close(fds[1]);
        throw Exception("failed to add file action: " + std::string(strerror(res)));
    }
    res = posix_spawn(&pid, path.c_str(), &fa, nullptr,
        (char * const *)argv.data(), (char * const *)envp.data());
    close(fds[0]);
    if (res) {
        close(fds[1]);
        throw Exception("failed to posix_spawn: " + std::string(strerror(errno)));
    }
    int ws;
    write_all(fds[1], state);
    close(fds[1]);
    waitpid(res, &ws, 0);
    if (!(WIFEXITED(ws) && WEXITSTATUS(ws) == 0)) {
        throw Exception("hook error: return " + std::to_string(WEXITSTATUS(ws)));
    }
}

static void get_cores(std::vector<int> &cores) {
    cpu_set_t set;
    CPU_ZERO(&set);
    sched_getaffinity(0, sizeof(set), &set);
    for (int i = 0; i < CPU_SETSIZE; ++i) {
        if (CPU_ISSET(i, &set)) {
            cores.push_back(i);
        }
    } 
}

static void create_uvisor_instance(const std::string &uid) {
    std::string sock_path = root + "/" + uid + ".sock";
    if (access(sock_path.c_str(), F_OK) == 0) {
        sock = sock_path;
        return;
    }
    json req;
    req["command"] = "create";
    req["path"] = sock_path;

    UDSConn conn_daemon(sock);
    conn_daemon.send(req);
    conn_daemon.recv_json();
    sock = sock_path;
    /*
    std::string config_path = root + "/" + uid + ".conf";
    json config;
    std::vector<int> cores;
    get_cores(cores);
    config["num_threads"] = cores.size();
    config["cores"] = cores;
    config["enable_breakpoint"] = false;
    config["enable_code_inspection"] = false;
    config["enable_vtcp"] = true;
    config["send_ready_signal"] = true;
    config["api"] = sock_path;
    config["hook_so"] = "/usr/local/share/pegasus/libhook.so";
    {
        std::ofstream ofs(config_path);
        if (!ofs) {
            throw Exception("failed to create temporary config file");
        }
        ofs << config.dump();
    }
    pid_t pid;
    const char *argv[] = {"pegasus", config_path.data(), nullptr};
    int fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        throw Exception("failed to open /dev/null" + std::string(strerror(errno)));
    }
    posix_spawn_file_actions_t act;
    posix_spawn_file_actions_init(&act);
    posix_spawn_file_actions_adddup2(&act, fd, 0);
    posix_spawn_file_actions_adddup2(&act, fd, 1);
    posix_spawn_file_actions_adddup2(&act, fd, 2);
    posix_spawn_file_actions_addclose(&act, fd);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, nullptr);
    if (posix_spawnp(&pid, "pegasus", nullptr, nullptr, (char **)argv, nullptr) == -1) {
        throw Exception("failed to create pegasus instance: " + std::string(strerror(errno)));
    }
    siginfo_t info;
    if (sigwaitinfo(&set, &info) != SIGUSR1) {
        throw Exception("failed to wait pegasus instance: " + std::string(strerror(errno)));
    }
    unlink(config_path.c_str());
    sock = sock_path;
    */
}

static void create_check_pass_to(const json &bundle_obj) {
    static const std::string pattern = "RUNUC_PASS_TO=";
    bool is_native = false;
    std::string pass_to;
    json process = bundle_obj["process"];
    auto it = process.find("env");
    if (it != process.end()) {
        std::vector<std::string> envs = it->get<std::vector<std::string>>();
        for (const std::string &s : envs) {
            if (s.length() > pattern.length() && s.substr(0, pattern.length()) == pattern) {
                pass_to = s.substr(pattern.length());
                is_native = true;
                break;
            }
        }
    }

    if (is_native) {
        std::vector<char *> args;
        args.push_back(pass_to.data());
        for (int i = 1; i < argc; ++i) {
            args.push_back(argv[i]);
        }
        args.push_back(nullptr);
        {
            std::string container_sock_path = root + "/" + container_id + ".sock";
            std::ofstream ofs(container_sock_path);
            if (!ofs) {
                throw Exception("failed to create container data");
            }
            ofs << pass_to;
        }
        if (execvp(pass_to.c_str(), args.data()) == -1) {
            throw Exception("failed to pass to another runtime " + pass_to + ": " + strerror(errno));
        }
    }
}

static void check_pass_to() {
    std::string container_path = root + "/" + container_id + ".sock";
    int fd = open(container_path.c_str(), O_RDONLY);
    if (fd == -1) {
        return;
        //throw Exception("failed to open " + container_path + ": " + strerror(errno));
    }
    size_t size = lseek64(fd, 0, SEEK_END);
    lseek64(fd, 0, SEEK_SET);
    std::string path;
    path.resize(size);
    if (read(fd, path.data(), size) != size) {
        close(fd);
        throw Exception("failed to read runtime name: " + std::string(strerror(errno)));
    }
    std::vector<char *> args;
    args.push_back(path.data());
    for (int i = 1; i < argc; ++i) {
        args.push_back(argv[i]);
    }
    close(fd);
    if (execvp(path.c_str(), args.data()) == -1) {
        throw Exception("failed to pass to another runtime " + path + ": " + strerror(errno));
    }
}

void mkdirp(std::string path, mode_t mode) {
    char *s = path.data();
    for (char *p = strchr(s + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = 0;
        int res = mkdir(s, mode);
        int err = errno;
        if (res == -1) {
            if (err != EEXIST) {
                *p = '/';
                return;
            }
        }
        *p = '/';
    }
}

static void handle_create() {
    std::ifstream ifs(bundle + "/config.json");
    if (!ifs) {
        throw Exception("failed to open bundle config.json");
    }
    json bundle_obj = json::parse(ifs);
    ifs.close();

    json req;
    req["command"] = "create";
    req["bundle"] = bundle;

    create_check_pass_to(bundle_obj);

    auto it = bundle_obj.find("annotations");
    if (it != bundle_obj.end()) {
        auto it2 = it->find("io.kubernetes.cri.sandbox-uid");
        if (it2 != it->end()) {
            create_uvisor_instance(it2->get<std::string>());
            //create_uvisor_instance(container_id + "-uid");
            req["drop_ref"] = true;
        }
    }

    if (preserve_fds != 0) {
        req["preserve-fds"] = preserve_fds;
    }
    preserve_fds += 3;
    std::vector<int> fds;
    for (int i = 0; i < preserve_fds; ++i) {
        fds.push_back(i);
    }
    if (!console_socket.empty()) {
        req["console-socket"] = console_socket;
    }
    req["container-id"] = container_id;

    mkdirp(root + "/", 0755);
    std::ofstream ofs(pid_file);
    if (!ofs) {
        throw Exception("failed to open pid file");
    }
    UDSConn conn_daemon(sock);

    std::string container_sock_path = root + "/" + container_id + ".sock";
    if (symlink(sock.c_str(), container_sock_path.c_str()) == -1) {
        throw Exception("failed to create container sock: " + std::string(strerror(errno)));
    }

    int proxy_fd;
    run_proxy_process(proxy_fd);
    UDSConn conn_proxy(proxy_fd);
    pid_t pid = conn_proxy.recv_int();
    if (pid < 0) {
        throw Exception("failed to create proxy process");
    }
    ofs << pid;
    ofs.close();
    req["pid"] = pid;
    conn_daemon.send(req);
    conn_daemon.send_fds(fds);
    json resp = conn_daemon.recv_json();
    std::vector<int> ns_fds(2);
    conn_daemon.recv_fds(ns_fds.size(), ns_fds);
    conn_proxy.send_fds(ns_fds);
    int res = conn_proxy.recv_int();
    if (res != 0) {
        throw Exception("failed to set proxy process: " + std::string(strerror(res)));
    }

    // prestart hook
    std::string state = resp["state"].dump();
    for (auto &&hook : resp["hook"]) {
        std::string path = hook["path"].get<std::string>();
        std::vector<std::string> args;
        std::vector<std::string> env;
        int timeout = -1;
        auto it = hook.find("args");
        if (it != hook.end()) {
            args = it->get<std::vector<std::string>>();
        }
        it = hook.find("env");
        if (it != hook.end()) {
            env = it->get<std::vector<std::string>>();
        }
        it = hook.find("timeout");
        if (it != hook.end()) {
            timeout = it->get<int>();
        }
        run_hook(path, args, env, timeout, state);
    }

    conn_daemon.send_dummy_msg();
    conn_daemon.recv_json();
    //write_log("create container");
}

static void handle_start() {
    check_pass_to();
    json req;
    req["command"] = "start";
    req["container-id"] = container_id;

    std::string container_sock_path = root + "/" + container_id + ".sock";

    UDSConn conn_daemon(container_sock_path);
    conn_daemon.send(req);
    conn_daemon.recv_json();
}

static void handle_kill() {
    check_pass_to();
    json req;
    req["command"] = "kill";
    req["container-id"] = container_id;
    req["signal"] = kill_signal;
    req["all"] = kill_all;

    std::string container_sock_path = root + "/" + container_id + ".sock";

    UDSConn conn_daemon(container_sock_path);
    conn_daemon.send(req);
    conn_daemon.recv_json();
}

static void handle_delete() {
    check_pass_to();
    json req;
    req["command"] = "delete";
    req["container-id"] = container_id;

    std::string container_sock_path = root + "/" + container_id + ".sock";

    try {
        UDSConn conn_daemon(container_sock_path);
        conn_daemon.send(req);
        conn_daemon.recv_json();
    } catch (...) {
        if (force) {
            unlink(container_sock_path.c_str());
        }
        return;
    }
    unlink(container_sock_path.c_str());
}

int main(int argc, char **argv) {
    ::argc = argc;
    ::argv = argv;
    std::string line;
    for (int i = 0; i < argc; ++i) {
        line += argv[i];
        line += ' ';
    }
    CLI::App app("runpc");
    app.add_option("-s,--sock", sock, "pegasus daemon socket");
    app.add_option("--log", log_file);
    app.add_option("--log-format", log_format);
    app.add_option("--root", root);
    app.add_flag("--systemd-cgroup", systemd_cgroup);
    app.add_flag("--force", force);
    CLI::App *create = app.add_subcommand("create", "create a container");
    CLI::App *start = app.add_subcommand("start", "start a container");
    CLI::App *delete_ = app.add_subcommand("delete", "delete a container");
    CLI::App *kill_ = app.add_subcommand("kill", "kill a container");
    app.require_subcommand();
    create->add_option("-b,--bundle", bundle);
    create->add_option("--console-socket", console_socket);
    create->add_option("--pid-file", pid_file);
    create->add_option("--preserve-fds", preserve_fds);
    create->add_option("container-id", container_id)->required();
    create->final_callback(handle_create);

    start->add_option("container-id", container_id)->required();
    start->final_callback(handle_start);

    delete_->add_option("container-id", container_id)->required();
    delete_->add_flag("--force", force);
    delete_->final_callback(handle_delete);

    kill_->add_flag("--all", kill_all);
    kill_->add_option("container-id", container_id)->required();
    kill_->add_option("signal", kill_signal);
    kill_->final_callback(handle_kill);
    try {
        CLI11_PARSE(app, argc, argv);
    } catch (std::exception &e) {
        //write_log(e.what());
        //fprintf(stderr, "%s\n", e.what());
    }
    return 0;
}
