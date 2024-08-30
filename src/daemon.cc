#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <arpa/inet.h>
#include <dlfcn.h>
#include "json.hpp"
#include "pegasus/cluster.h"
#include "pegasus/runtime.h"
#include "pegasus/exception.h"

using namespace nlohmann;
using namespace pegasus;

static void load_config(const std::string &filename,
                        RuntimeConfiguration &runtime_config) {
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
    it = config.find("enable_vdso");
    if (it != config.end()) {
        runtime_config.enable_vdso = it->get<bool>();
    }
    it = config.find("poll_threshold");
    if (it != config.end()) {
        runtime_config.poll_threshold = it->get<double>();
    }
    it = config.find("rewrite_rule");
    if (it != config.end()) {
        runtime_config.rewrite_rule_filename = it->get<std::string>();
    }
    it = config.find("hook_so");
    if (it != config.end()) {
        runtime_config.hook_so = it->get<std::string>();
    }
    it = config.find("cluster_mode");
    if (it != config.end()) {
        runtime_config.cluster_mode = it->get<bool>();
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
        it2 = ioworker_config.find("enable_linux_lo");
        if (it2 != ioworker_config.end()) {
            runtime_config.ioworker_config.enable_linux_lo = it2->get<bool>();
        }
        runtime_config.ioworker_config.args = ioworker_config["args"].get<std::vector<std::string>>();
    }
    it = config.find("send_ready_signal");
    if (it != config.end()) {
        runtime_config.send_ready_signal = it->get<bool>();
    }
    it = config.find("api");
    if (it != config.end()) {
        runtime_config.api_uds_path = it->get<std::string>();
    } else {
        runtime_config.api_uds_path = "/var/run/pegasus.sock";
    }
#ifdef CONFIG_ENABLE_TIME_TRACE
    it = config.find("enable_time_trace");
    if (it != config.end()) {
        runtime_config.enable_time_trace = it->get<bool>();
        if (runtime_config.enable_time_trace) {
            it = config.find("trace_buffer_size");
            if (it != config.end()) {
                runtime_config.trace_buffer_size = it->get<size_t>();
            }
            it = config.find("trace_buffer_pkey");
            if (it != config.end()) {
                runtime_config.trace_buffer_pkey = it->get<int>();
            }
            it = config.find("trace_output_file");
            if (it != config.end()) {
                runtime_config.trace_output_file = it->get<std::string>();
            }
        }
    }
#endif
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: pegasus <config>\n");
        return 1;
    }
    RuntimeConfiguration runtime_config;
    try {
        load_config(argv[1], runtime_config);
    } catch (std::exception &e) {
        printf("Failed to load configuration: %s\n", e.what());
        return 1;
    }
    if (runtime_config.cluster_mode) {
        Cluster cluster(runtime_config);
        cluster.run();
        return 0;
    }
    try {
        Runtime::create(runtime_config);
    } catch (std::exception &e) {
        printf("Failed to create runtime: %s\n", e.what());
        return 1;
    }
    Runtime *runtime = Runtime::get();
    try {
        runtime->start();
    } catch (std::exception &e) {
        printf("Failed to start runtime: %s\n", e.what());
        return 1;
    }
    //Stat::get().show();
    return 0;
}