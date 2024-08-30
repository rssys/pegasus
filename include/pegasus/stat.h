#pragma once
#include "lock.h"

namespace pegasus {
struct StatData {
    SpinLock lock;
    double sum;
    uint64_t count;
    uint64_t max;
    uint64_t buckets[65];
};

class Stat {
public:
    static constexpr size_t NumData = 32;
    Stat();
    ~Stat();
    inline static Stat &get() {
        return stat;
    }
    void add(int idx, uint64_t data);
    void show_and_reset(int idx);
private:
    static Stat stat;
    StatData data[NumData];
};
}