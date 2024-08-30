#pragma once
#include <memory>
#include <unordered_map>
#include <csignal>
#include <cinttypes>
#include "monitor.h"

namespace pegasus {
struct TimerData {
    int fd;
    struct sigevent event;
    std::weak_ptr<VProcess> vprocess;
    std::weak_ptr<VThread> vthread;
};

class TimerContext {
public:
    enum {
        TimerReal = 1l,
        TimerVirtual = 2l,
        TimerProf = 3l,
        TimerOther = 4l,
    };
    TimerContext();
    ~TimerContext();
    intptr_t add_timer(const TimerData &data, intptr_t timerid = -1, bool set_sev_val = false);
    bool del_timer(intptr_t timerid);
    int get_timer_fd(intptr_t timerid);
    bool handle();
    inline int get_epfd() {
        return epfd;
    }
    void reset();
private:
    SpinLock mutex;
    int epfd;
    std::unordered_map<intptr_t, TimerData> timers;
    int max_timerid;
};
}