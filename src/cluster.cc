#include <string>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include "json.hpp"
#include "pegasus/cluster.h"
#include "pegasus/mm.h"
#include "pegasus/runtime.h"
#include "pegasus/stat.h"

using namespace nlohmann;
using namespace pegasus;

Cluster::Cluster(RuntimeConfiguration &config_) : config(config_) {
    api_fd.fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (api_fd.fd == -1) {
        throw Exception("cannot create api socket");
    }
    struct sockaddr_un name;
    name.sun_family = AF_UNIX;
    unlink(config.api_uds_path.c_str());
    strncpy(name.sun_path, config.api_uds_path.c_str(), sizeof(name.sun_path) - 1);
    if (bind(api_fd.fd, (struct sockaddr *)&name, sizeof(struct sockaddr_un)) == -1) {
        throw Exception("cannot bind api socket");
    }
    if (listen(api_fd.fd, 128) == -1) {
        throw Exception("cannot listen api socket");
    }
    size_t size = sizeof(ClusterData) + sizeof(ClusterCPUData) * config.num_threads;
    size_t num_pages = page_round_up(size);
    void *buf = mmap(nullptr, num_pages, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (buf == MAP_FAILED) {
        throw Exception("cannot mmap: " + std::string(strerror(errno)));
    }
    cluster_data = (ClusterData *)buf;
    cluster_data->ncpus = config.num_threads;
    cluster_data->cpu_data = (ClusterCPUData *)((uintptr_t)buf + sizeof(ClusterData));
    for (int i = 0; i < cluster_data->ncpus; ++i) {
        new (&cluster_data->cpu_data[i]) ClusterCPUData;
    }
}

static void write_msg(int fd, const std::string &msg) {
    ssize_t res = write(fd, msg.c_str(), msg.length());
    (void)res;
    return;
}

static void send_response(int fd, const std::string &status) {
    json resp;
    resp["status"] = status;
    const std::string &msg = resp.dump();
    write_msg(fd, msg);
}

void Cluster::run() {
    static constexpr size_t CommandBufferSize = 8192;
    std::vector<uint8_t> buf(CommandBufferSize);
    while (true) {
        MonitorFile fd;
        fd.fd = accept(api_fd.fd, nullptr, nullptr);
        if (fd.fd == -1) {
            break;
        }
        ssize_t len = read(fd.fd, buf.data(), CommandBufferSize);
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
                std::string path = payload["path"].get<std::string>();
                create_node(path);
                send_response(fd.fd, "ok");
            }
        } catch (std::exception &e) {
            printf("err: %s\n", e.what());
            send_response(fd.fd, e.what());
        }
    }
}

void Cluster::create_node(const std::string &path) {
    //current_core += 6;
    pid_t pid = fork();
    if (pid == -1) {
        throw Exception("failed to fork: " + std::string(strerror(errno)));
    }
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, nullptr);
    if (pid > 0) {
        siginfo_t info;
        if (sigwaitinfo(&set, &info) != SIGUSR1) {
            throw Exception("failed to wait pegasus instance: " + std::string(strerror(errno)));
        }
        return;
    }
    api_fd.fd = -1;
    RuntimeConfiguration new_config = config;
    new_config.api_uds_path = path;
    new_config.send_ready_signal = true;
    if (config.cores.size()) {
        new_config.cluster_sched = true;
    }
    new_config.cluster_data = cluster_data;
    Runtime::create(new_config);
    Runtime *runtime = Runtime::get();
    runtime->start();
    Stat::get().show_and_reset(0);
    Stat::get().show_and_reset(1);
    Stat::get().show_and_reset(2);
    Stat::get().show_and_reset(3);
    //Stat::get().show_and_reset(4);
}
