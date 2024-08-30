#pragma once
#ifdef CONFIG_ENABLE_FSTACK
#include "ioworker_fstack.h"
#else
#include <string>
#include <vector>

namespace pegasus {
struct IOWorkerConfiguration {
    IOWorkerConfiguration() : enabled(false) {}
    bool enabled;
    std::string config_file;
    std::vector<std::string> args;
    std::string ip;
};

class VThread;
struct FDFilePair;
class IOWorker {
public:
    IOWorker(TaskManager *tm, int core) {
        throw Exception("No IOWorker backend.");
    }
    inline void init_global(IOWorkerConfiguration &config) {
        throw Exception("No IOWorker backend.");
    }
    inline void init_cpu(IOWorkerConfiguration &config) {
        throw Exception("No IOWorker backend.");
    }
    inline static create(VThread *vthread, FDFilePair &out, bool local, int domain, int type, int protocol) {
        return false;
    }
    inline void start() {}
    inline void wait() {}
};
}
#endif