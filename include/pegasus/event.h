#pragma once
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <functional>
#include <unordered_map>
#include <vector>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <linux/time_types.h>
#include <liburing.h>
#include "lock.h"

namespace pegasus {
inline static uint64_t time_nanosec(clockid_t cid = CLOCK_MONOTONIC_RAW) {
    struct timespec t;
    clock_gettime(cid, &t);
    return t.tv_sec * 1000000000ull + t.tv_nsec;
}

inline static void spin_nanosec(uint64_t ns) {
    uint64_t start = time_nanosec();
    while (time_nanosec() - start < ns);
}
struct Task;
struct File;
struct FileDescriptorReference;
class ReadyQueue;
class WaitQueue;
class TaskManager;
class EventQueue {
public:
    struct Data {
        std::function<void (int)> callback;
        uint32_t type;
        bool cancellable;
        bool is_poll;
        clockid_t clock;
        uint64_t time;
        int fd;
    };
    struct Res {
        Res() {}
        Res(const std::function<void (int)> &callback_, int res_) : callback(callback_), res(res_) {}
        std::function<void (int)> callback;
        int res;
    };
    struct CQEBuffer {
        CQEBuffer();
        std::vector<struct io_uring_cqe *> cqes;
        std::vector<Res> finished_events;
    };
    EventQueue(TaskManager *tm_, timer_t &monotonic_timer_);
    EventQueue(const EventQueue &) = delete;
    EventQueue &operator=(const EventQueue &) = delete;
    ~EventQueue();
    inline uintptr_t add_task_timeout(const std::shared_ptr<Task> &task,
                                      struct __kernel_timespec *timeout,
                                      int timeout_flags = 0,
                                      uint32_t mask = -1) {
        return add_task_timeout(wq, task, timeout, timeout_flags, mask);
    }
    inline uintptr_t add_task_poll_timeout(const std::shared_ptr<Task> &task,
                                           const FileDescriptorReference &fd,
                                           uint32_t events = POLLIN,
                                           struct __kernel_timespec *timeout = nullptr,
                                           int timeout_flags = 0,
                                           uint32_t mask = -1) {
        return add_task_poll_timeout(wq, task, fd, events, timeout, timeout_flags, mask);
    }
    inline uintptr_t add_task_poll_timeout(const std::shared_ptr<Task> &task,
                                           int fd,
                                           uint32_t events = POLLIN,
                                           struct __kernel_timespec *timeout = nullptr,
                                           int timeout_flags = 0,
                                           uint32_t mask = -1) {
        return add_task_poll_timeout(wq, task, fd, events, timeout, timeout_flags, mask);
    }
    uintptr_t add_task_timeout(const std::shared_ptr<WaitQueue> &wq_,
                               const std::shared_ptr<Task> &task,
                               struct __kernel_timespec *timeout,
                               int timeout_flags = 0,
                               uint32_t mask = -1);
    uintptr_t add_task_poll_timeout(const std::shared_ptr<WaitQueue> &wq_,
                                    const std::shared_ptr<Task> &task,
                                    const FileDescriptorReference &fd,
                                    uint32_t events = POLLIN,
                                    struct __kernel_timespec *timeout = nullptr,
                                    int timeout_flags = 0,
                                    uint32_t mask = -1);
    uintptr_t add_task_poll_timeout(const std::shared_ptr<WaitQueue> &wq_,
                                    const std::shared_ptr<Task> &task,
                                    int fd,
                                    uint32_t events = POLLIN,
                                    struct __kernel_timespec *timeout = nullptr,
                                    int timeout_flags = 0,
                                    uint32_t mask = -1);
    bool add_event_poll_multishot(const std::function<bool (int)> &callback, int fd, uint32_t events);
    inline struct io_uring_sqe *get_sqe() {
        return io_uring_get_sqe(&ring);
    }
    bool cancel(uintptr_t key);
    void update(uintptr_t key, const std::function<void (int)> &callback);
    inline void poll() {
        std::unique_lock lock(mutex);
        poll(cqe_buffer, lock);
    }
    inline void poll(CQEBuffer &buffer) {
        std::unique_lock lock(mutex);
        poll(buffer, lock);
    }
    void sleep(CQEBuffer &buffer);
    void interrupt();
    inline const std::shared_ptr<WaitQueue> &get_wq() {
        return wq;
    }
    inline SpinLock &get_mutex() {
        return mutex;
    }
    bool ready();
    //inline bool ready() {
    //    return io_uring_cq_ready(&ring) || (time_nanosec(CLOCK_MONOTONIC) >= next_time_event);
    //}
private:
    enum {
        IOUringEvent = 1,
        TimerEvent = 2,
    };
    enum {
        NotifyKey = 1ull,
        NOPKey = 2ull,
        InitialKey = 3ull,
    };
    friend class ReadyQueue;
    friend class EventQueuePoller;
    friend struct EventQueueCQEBuffer;
    int poll(CQEBuffer &buffer, std::unique_lock<SpinLock> &lock);
    int handle_events(unsigned int n, CQEBuffer &buffer, std::unique_lock<SpinLock> &lock);
    void cancel_io_uring(uintptr_t key, const Data &data);
    void cancel_internal(uintptr_t key, const Data &data, uint32_t from);
    void handle_timer(clockid_t clock, std::multimap<uint64_t, uintptr_t> &timeline,
                      CQEBuffer &buffer);
    void cancel_other_event(uintptr_t key, const Data &data, uint32_t from);
    uintptr_t add_event(const std::function<void (int)> &callback,
                        struct io_uring_sqe **sqes, size_t nsqe, bool cancellable, bool is_poll);
    uintptr_t add_event_timeout(const std::function<void (int)> &callback,
                                struct __kernel_timespec *timeout,
                                int timeout_flags = 0);
    uintptr_t add_event_poll_timeout(const std::function<void (int)> &callback,
                                     int fd,
                                     uint32_t events,
                                     struct __kernel_timespec *timeout = nullptr,
                                     int timeout_flags = 0);

    uintptr_t current_key;
    struct io_uring ring;
    SpinLock mutex;
    TaskManager *tm;
    std::shared_ptr<WaitQueue> wq;
    CQEBuffer cqe_buffer;
    std::unordered_map<uintptr_t, Data> events;
    
    std::multimap<uint64_t, uintptr_t> monotonic_timeline;
    std::multimap<uint64_t, uintptr_t> realtime_timeline;
    std::multimap<uint64_t, uintptr_t> boottime_timeline;
    timer_t &monotonic_timer;
};
}