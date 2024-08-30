#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <arpa/inet.h>
#include <dlfcn.h>
#include "json.hpp"
#include "pegasus/runtime.h"
#include "pegasus/exception.h"

using namespace nlohmann;
using namespace pegasus;

static void load_config(const std::string &filename,
                        RuntimeConfiguration &runtime_config,
                        std::vector<ProgramConfiguration> &program_config) {
    std::ifstream ifs(filename);
    json config = json::parse(ifs, nullptr, true, true);
    auto it = config.find("num_threads");
    if (it != config.end()) {
        runtime_config.num_threads = it->get<int>();
    }
    it = config.find("cores");
    if (it != config.end()) {
        for (int core : *it) {
            runtime_config.cores.push_back(core);
        }
    }
    it = config.find("enable_breakpoint");
    if (it != config.end()) {
        runtime_config.enable_breakpoint = it->get<bool>();
    }
    it = config.find("enable_code_inspection");
    if (it != config.end()) {
        runtime_config.enable_code_inspection = it->get<bool>();
    }
    it = config.find("log_code_inspection");
    if (it != config.end()) {
        runtime_config.log_code_inspection = it->get<bool>();
    }
    it = config.find("enable_fork");
    if (it != config.end()) {
        runtime_config.enable_fork = it->get<bool>();
    }
    it = config.find("enable_vtcp");
    if (it != config.end()) {
        runtime_config.enable_vtcp = it->get<bool>();
        struct in_addr a;
        a.s_addr = htonl(INADDR_LOOPBACK);
        runtime_config.vtcp_addr_in.insert(a);
        a.s_addr = htonl(INADDR_ANY);
        runtime_config.vtcp_addr_in.insert(a);
        runtime_config.vtcp_addr_in6.insert(in6addr_loopback);
        runtime_config.vtcp_addr_in6.insert(in6addr_any);
    }
    it = config.find("vtcp_addr_v4");
    if (it != config.end()) {
        json addr = *it;
        struct in_addr a;
        for (auto &&s : addr) {
            const std::string &ip = s.get<std::string>();
            if (inet_aton(ip.c_str(), &a) == 0) {
                throw Exception("Invalid VTCP address: " + ip);
            }
            runtime_config.vtcp_addr_in.insert(a);
        }
    }
    it = config.find("vtcp_addr_v6");
    if (it != config.end()) {
        json addr = *it;
        struct in6_addr a;
        for (auto &&s : addr) {
            const std::string &ip = s.get<std::string>();
            if (inet_pton(AF_INET6, ip.c_str(), &a) == 0) {
                throw Exception("Invalid VTCP v6 address: " + ip);
            }
            runtime_config.vtcp_addr_in6.insert(a);
        }
    }
    it = config.find("enable_vsocketpair");
    if (it != config.end()) {
        runtime_config.enable_vsocketpair = it->get<bool>();
    }
    it = config.find("enable_perf_map");
    if (it != config.end()) {
        runtime_config.enable_perf_map = it->get<bool>();
    }
    it = config.find("enable_poll");
    if (it != config.end()) {
        runtime_config.enable_poll = it->get<bool>();
    }
    it = config.find("poll_threshold");
    if (it != config.end()) {
        runtime_config.poll_threshold = it->get<double>();
    }
    it = config.find("rewrite_rule");
    if (it != config.end()) {
        runtime_config.rewrite_rule_filename = it->get<std::string>();
    }
    it = config.find("use_user_ns");
    if (it != config.end()) {
        runtime_config.use_user_ns = it->get<bool>();
    }
    it = config.find("vdso");
    if (it != config.end()) {
        runtime_config.vdso = it->get<std::string>();
    }
    it = config.find("set_fsuid_fsgid");
    if (it != config.end()) {
        runtime_config.set_fsuid_fsgid = true;
        runtime_config.fsuid = (*it)["fsuid"].get<int>();
        runtime_config.fsgid = (*it)["fsgid"].get<int>();
    }
    it = config.find("ioworker");
    if (it != config.end()) {
        runtime_config.ioworker_config.enabled = true;
        json ioworker_config = *it;
        auto it2 = ioworker_config.find("config_file");
        if (it2 != ioworker_config.end()) {
            runtime_config.ioworker_config.config_file = it2->get<std::string>();
        }
        it2 = ioworker_config.find("ip");
        if (it2 != ioworker_config.end()) {
            runtime_config.ioworker_config.ip = it2->get<std::string>();
        }
        runtime_config.ioworker_config.args = ioworker_config["args"].get<std::vector<std::string>>();
    }
    auto programs = config["programs"];
    for (auto &&program : programs) {
        ProgramConfiguration pconfig;
        pconfig.rootfs = program["rootfs"].get<std::string>();
        pconfig.program = program["cmd"][0].get<std::string>();
        for (auto &&s : program["cmd"]) {
            pconfig.args.push_back(s.get<std::string>());
        }
        for (auto &&s : program["env"]) {
            pconfig.envs.push_back(s.get<std::string>());
        }
        auto it = program.find("affinity");
        if (it != program.end()) {
            for (auto &&s : *it) {
                pconfig.affinity.insert(s.get<int>());
            }
        }
        it = program.find("mem_bits");
        if (it != program.end()) {
            pconfig.vmem = 1ul << it->get<int>() ;
        }
        it = program.find("mpk_domain");
        if (it != program.end()) {
            pconfig.mpk_domain = it->get<uint64_t>();
        }
        it = program.find("start_delay");
        if (it != program.end()) {
            pconfig.start_delay = it->get<uint64_t>();
        }
        it = program.find("working_directory");
        if (it != program.end()) {
            pconfig.working_directory = it->get<std::string>();
        }
        it = program.find("plugin");
        if (it != program.end()) {
            auto plugin_config = *it;
            const std::string &so = plugin_config["so"].get<std::string>();
            auto config = plugin_config["config"];
            void *plugin = dlopen(so.c_str(), RTLD_NOW | RTLD_LOCAL);
            if (!plugin) {
                std::string msg = "failed to load plugin ";
                msg += dlerror();
                throw Exception(msg);
            }
            pconfig.plugin = plugin;
            pconfig.plugin_config = config;
        }
        it = program.find("features");
        if (it != program.end()) {
            pconfig.enable_dynamic_syscall_rewrite = false;
            pconfig.enable_clone = false;
            pconfig.enable_fork = false;
            pconfig.enable_vtcp_accept = false;
            pconfig.enable_vtcp_connect = false;
            for (auto &&s : *it) {
                if (s == "dynamic_syscall_rewrite") {
                    pconfig.enable_dynamic_syscall_rewrite = true;
                } else if (s == "clone") {
                    pconfig.enable_clone = true;
                } else if (s == "fork") {
                    pconfig.enable_fork = true;
                } else if (s == "execve") {
                    pconfig.enable_execve = true;
                } else if (s == "vtcp_accept" && runtime_config.enable_vtcp) {
                    pconfig.enable_vtcp_accept = true;
                } else if (s == "vtcp_connect" && runtime_config.enable_vtcp) {
                    pconfig.enable_vtcp_connect = true;
                } else if (s == "ioworker" && runtime_config.ioworker_config.enabled) {
                    pconfig.enable_ioworker = true;
                } else if (s == "vdso" && !runtime_config.vdso.empty()) {
                    pconfig.enable_vdso = true;
                } else if (s == "vsocketpair" && runtime_config.enable_vsocketpair) {
                    pconfig.enable_vsocketpair = true;
                } else if (s == "write_exec") {
                    pconfig.enable_write_exec = true;
                } else if (s == "no_inspect_code") {
                    pconfig.enable_exec_noinspect = true;
                }
            }
        }
        it = program.find("bind_mounts");
        if (it != program.end()) {
            for (auto &&s : *it) {
                pconfig.bind_mounts.emplace_back(s[0].get<std::string>(), s[1].get<std::string>());
            }
        }
        program_config.push_back(pconfig);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: pegasus <config>\n");
        return 1;
    }
    //signal(SIGUSR1, [] (int sig) {
    //    Stat::get().show();
    //});
    //signal(SIGUSR2, [] (int sig) {
    //    Stat::get().enabled = !Stat::get().enabled;
    //});
    RuntimeConfiguration runtime_config;
    std::vector<ProgramConfiguration> program_config;
    try {
        load_config(argv[1], runtime_config, program_config);
    } catch (std::exception &e) {
        printf("Failed to load configuration: %s\n", e.what());
        return 1;
    }
    try {
        Runtime::create(runtime_config);
    } catch (std::exception &e) {
        printf("Failed to create runtime: %s\n", e.what());
        return 1;
    }
    Runtime *runtime = Runtime::get();
    //Stat::get().resize(program_config.size() + 1, 10);
    for (auto &&program : program_config) {
        try {
            runtime->run_program(runtime_config, program);
        } catch (std::exception &e) {
            printf("Failed to load program %s: %s\n", program.program.c_str(), e.what());
            return 1;
        }
    }
    //Stat::get().show();
    try {
        runtime->start();
    } catch (std::exception &e) {
        printf("Failed to start runtime: %s\n", e.what());
        return 1;
    }
    //Stat::get().show();
    return 0;
}