#pragma once
#include "pegasus/file.h"
#include "pegasus/lock.h"
#include "pegasus/runtime.h"
#include "pegasus/sched.h"

namespace pegasus {
struct ClusterCPUData {
    SpinLock lock;
    int nr_running;
    int active;
};

struct ClusterData {
    int ncpus;
    ClusterCPUData *cpu_data;
};

class Cluster {
public:
    Cluster(RuntimeConfiguration &config);
    void run();
private:
    void create_node(const std::string &path);
    RuntimeConfiguration config;
    MonitorFile api_fd;
    ClusterData *cluster_data;
};
}