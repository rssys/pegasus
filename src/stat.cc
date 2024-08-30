#include <thread>
#include <mutex>
#include <cstring>
#include "pegasus/lock.h"
#include "pegasus/stat.h"

using namespace pegasus;

Stat Stat::stat;

Stat::Stat() {

}

Stat::~Stat() {

}

void Stat::add(int idx, uint64_t x) {
    StatData &d = data[idx];
    uint64_t n = 64 - __builtin_clzll(x);
    std::lock_guard lock(d.lock);
    ++d.count;
    if (x > d.max) {
        d.max = x;
    }
    d.sum += x;
    ++d.buckets[n];
}

void Stat::show_and_reset(int idx) {
    StatData &d = data[idx];
    uint64_t max;
    double sum;
    uint64_t count;
    uint64_t buckets[65];
    {
        std::lock_guard lock(d.lock);
        max = d.max;
        sum = d.sum;
        count = d.count;
        memcpy(buckets, d.buckets, sizeof(buckets));
        d.count = 0;
        d.sum = 0;
        d.max = 0;
        memset(d.buckets, 0, sizeof(d.buckets));
    }
    if (!count) {
        return;
    }
    printf("Stat %d: avg %f max %lu count %lu, distribution:\n", idx, sum / count, max, count);
    for (uint64_t i = 0; i < 64; ++i) {
        printf("%lu to %lu: %lu\n", i == 0 ? 0 : (1ull << (i - 1)), 1ull << i, buckets[i]);
    }
}