#pragma once
#include <unordered_map>
#include <linux/time_types.h>
#include "pegasus/lock.h"
#include "pegasus/types.h"

namespace pegasus {
class WaitQueue;
class VThread;
class FutexContext {
public:
    FutexContext();
    FutexContext(const FutexContext &) = delete;
    FutexContext &operator=(const FutexContext &) = delete;
    ~FutexContext();
    int wait(VThread *vthread, uint32_t *uaddr, uint32_t val,
             const struct __kernel_timespec *timeout, int timeout_flags, uint32_t mask);
    int wake(VThread *vthread, uint32_t *uaddr, int max_tasks, uint32_t mask);
    int wake_op(VThread *vthread, uint32_t *uaddr, uint32_t val,
                uint32_t val2, uint32_t *uaddr2, uint32_t val3);
    int requeue(VThread *vthread, bool cmp, uint32_t *uaddr, uint32_t val,
                uint32_t val2, uint32_t *uaddr2, uint32_t val3);
private:
    SpinLock mutex;
    std::unordered_map<uintptr_t, std::weak_ptr<WaitQueue>> futexes;
};
}