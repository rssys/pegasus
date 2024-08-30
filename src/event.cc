#include <memory>
#include <functional>
#include <unordered_map>
#include <vector>
#include <sys/eventfd.h>
#include "pegasus/event.h"
#include "pegasus/exception.h"
#include "pegasus/file.h"
#include "pegasus/runtime.h"
#include "pegasus/sched.h"
#include "pegasus/stat.h"
#include "pegasus/wait_queue.h"

using namespace pegasus;
static constexpr unsigned int QueueDepth = 4096;

EventQueue::CQEBuffer::CQEBuffer() : cqes(QueueDepth * 4) {

}

EventQueue::EventQueue(TaskManager *tm_, timer_t &monotonic_timer_)
    : current_key(InitialKey), tm(tm_), wq(std::make_shared<WaitQueue>()),
      monotonic_timer(monotonic_timer_) {
    std::unique_ptr<Data> data = std::make_unique<Data>();

    struct io_uring_params params{};
    params.sq_entries = QueueDepth;
    params.cq_entries = QueueDepth * 4;
    params.flags = IORING_SETUP_CQSIZE;
    int res = io_uring_queue_init_params(QueueDepth, &ring, &params);

    if (res < 0) {
        throw SystemException(-res);
    }
}

EventQueue::~EventQueue() {
    io_uring_queue_exit(&ring);
}

uintptr_t EventQueue::add_task_timeout(const std::shared_ptr<WaitQueue> &wq_,
                                       const std::shared_ptr<Task> &task,
                                       struct __kernel_timespec *timeout,
                                       int timeout_flags,
                                       uint32_t mask) {
    std::scoped_lock lock(mutex, wq_->mutex);
    uintptr_t key = add_event_timeout([wq = wq_, ptask = task.get()] (int res) {
        int flags = Task::WaitResult::FromEventQueue | Task::WaitResult::Timeout;
        wq->wake_internal(ptask, Task::WaitResult(flags, res));
    }, timeout, timeout_flags);
    wq_->add_task_internal(task, this, key, mask, true);
    return key;
}

uintptr_t EventQueue::add_task_poll_timeout(const std::shared_ptr<WaitQueue> &wq_,
                                            const std::shared_ptr<Task> &task,
                                            const FileDescriptorReference &fd,
                                            uint32_t events,
                                            struct __kernel_timespec *timeout,
                                            int timeout_flags,
                                            uint32_t mask) {
    uintptr_t res;
    fd.ucontext->run_on_behalf_of([&] {
        res = add_task_poll_timeout(wq_, task, fd.fd, events, timeout, timeout_flags, mask);
    });
    return res;
}

uintptr_t EventQueue::add_task_poll_timeout(const std::shared_ptr<WaitQueue> &wq_,
                                            const std::shared_ptr<Task> &task,
                                            int fd,
                                            uint32_t events,
                                            struct __kernel_timespec *timeout,
                                            int timeout_flags,
                                            uint32_t mask) {
    if (fd == -1 && !timeout) {
        wq_->add_task(task);
        return NOPKey;
    }
    if (fd == -1) {
        return add_task_timeout(wq_, task, timeout, timeout_flags, mask);
    }
    std::scoped_lock lock(mutex, wq_->mutex);
    uintptr_t key = add_event_poll_timeout([wq = wq_, ptask = task.get()] (int res) {
        int flags = Task::WaitResult::FromEventQueue;
        if (res == -ETIME) {
            flags |= Task::WaitResult::Timeout;
        }
        wq->wake_internal(ptask, Task::WaitResult(flags, res));
    }, fd, events, timeout, timeout_flags);
    wq_->add_task_internal(task, this, key, mask, true);
    return key;
}

bool EventQueue::add_event_poll_multishot(const std::function<bool (int)> &callback,
                                                int fd, uint32_t events) {
    std::lock_guard lock(mutex);
    uintptr_t key = add_event_poll_timeout([this, callback, fd, events] (int res) {
        if (callback(res)) {
            add_event_poll_multishot(callback, fd, events);
        }
    }, fd, events);
    return key;
}

uintptr_t EventQueue::add_event(const std::function<void (int)> &callback,
                                struct io_uring_sqe **sqes, size_t nsqe, bool cancellable, bool is_poll) {
    uintptr_t key;

    if (current_key == -1u) {
        current_key = InitialKey;
    }
    key = current_key++;
    Data data;
    data.type = IOUringEvent;
    data.callback = callback;
    data.cancellable = cancellable;
    data.is_poll = is_poll;
    events[key] = data;

    for (size_t i = 0; i < nsqe; ++i) {
        io_uring_sqe_set_data(sqes[i], (void *)key);
    }

    io_uring_submit(&ring);
    return key;
}

static inline void get_expire_time(int timeout_flags, const struct __kernel_timespec &timeout,
                                   clockid_t &clock,
                                   uint64_t &expire_time) {
    if (timeout_flags & IORING_TIMEOUT_REALTIME) {
        clock = CLOCK_REALTIME;
    } else if (timeout_flags & IORING_TIMEOUT_BOOTTIME) {
        clock = CLOCK_BOOTTIME;
    } else {
        clock = CLOCK_MONOTONIC;
    }
    if (timeout_flags & IORING_TIMEOUT_ABS) {
        expire_time = timeout.tv_sec * 1000000000 + timeout.tv_nsec;
    } else {
        expire_time = time_nanosec(clock) + timeout.tv_sec * 1000000000 + timeout.tv_nsec;
    }
}

uintptr_t EventQueue::add_event_timeout(const std::function<void (int)> &callback,
                                        struct __kernel_timespec *timeout,
                                        int timeout_flags) {
    uintptr_t key;

    if (current_key == -1u) {
        current_key = InitialKey;
    }
    key = current_key++;
    Data data;
    data.callback = callback;
    data.type = TimerEvent;
    data.cancellable = true;
    data.is_poll = false;
    clockid_t clock;
    uint64_t expire_time;
    get_expire_time(timeout_flags, *timeout, clock, expire_time);
    data.clock = clock;
    data.time = expire_time;
    events[key] = data;
    auto &timeline = clock == CLOCK_REALTIME ? realtime_timeline :
        (clock == CLOCK_BOOTTIME ? boottime_timeline : monotonic_timeline);
    timeline.emplace(expire_time, key);
    //if (clock == CLOCK_MONOTONIC && !timeline.empty() && timeline.begin()->first == expire_time) {
    //    struct itimerspec its;
    //    its.it_value.tv_sec = expire_time / 1000000000;
    //    its.it_value.tv_nsec = expire_time % 1000000000;
    //    its.it_interval.tv_sec = 0;
    //    its.it_interval.tv_nsec = 0;
    //    timer_settime(monotonic_timer, TIMER_ABSTIME, &its, nullptr);
    //} 
    //if (clock == CLOCK_REALTIME) {
    //    realtime_timeline.emplace(expire_time, key);
    //} else if (clock == CLOCK_BOOTTIME) {
    //    boottime_timeline.emplace(expire_time, key);
    //} else {
    //    monotonic_timeline.emplace(expire_time, key);
    //}

    return key;
}

uintptr_t EventQueue::add_event_poll_timeout(const std::function<void (int)> &callback,
                                             int fd,
                                             uint32_t events_,
                                             struct __kernel_timespec *timeout,
                                             int timeout_flags) {
    struct io_uring_sqe *sqes[2];
    sqes[0] = io_uring_get_sqe(&ring);
    if (!sqes[0]) {
        throw Exception("ring is full");
    }
    io_uring_prep_poll_add(sqes[0], fd, events_);
    if (timeout) {
        sqes[1] = io_uring_get_sqe(&ring);
        if (!sqes[1]) {
            throw Exception("ring is full");
        }
        sqes[0]->flags |= IOSQE_IO_LINK;
        io_uring_prep_link_timeout(sqes[1], timeout, timeout_flags);
    }
    return add_event(callback, sqes, timeout ? 2 : 1, true, true);
/*
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        throw Exception("ring is full");
    }
    io_uring_prep_poll_add(sqe, fd, events_);

    uintptr_t key;
    if (current_key == -1u) {
        current_key = InitialKey;
    }
    key = current_key++;
    Data data;
    data.type = IOUringEvent | (timeout ? TimerEvent : 0);
    data.callback = callback;
    data.cancellable = true;
    data.is_poll = true;
    events[key] = data;
    io_uring_sqe_set_data(sqe, (void *)key);
    io_uring_submit(&ring);
    if (timeout) {
        clockid_t clock;
        uint64_t expire_time = get_expire_time(timeout_flags, *timeout, clock);
        data.clock = clock;
        data.time = expire_time;
        if (clock == CLOCK_REALTIME) {
            realtime_timeline.emplace(expire_time, key);
        } else if (clock == CLOCK_BOOTTIME) {
            boottime_timeline.emplace(expire_time, key);
        } else {
            monotonic_timeline.emplace(expire_time, key);
        }
    }
    return key;
*/
}

void EventQueue::cancel_io_uring(uintptr_t key, const EventQueue::Data &data) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        return;
    }
    if (data.is_poll) {
        io_uring_prep_poll_remove(sqe, key);
    } else {
        io_uring_prep_cancel(sqe, (void *)key, 0);
    }
    io_uring_sqe_set_data(sqe, nullptr);
}

void EventQueue::cancel_internal(uintptr_t key, const EventQueue::Data &data, uint32_t from) {
    if (from & IOUringEvent) {
        cancel_io_uring(key, data);
    }
    if (from & TimerEvent) {
        auto &timeline = data.clock == CLOCK_REALTIME ? realtime_timeline :
            (data.clock == CLOCK_BOOTTIME ? boottime_timeline : monotonic_timeline);
        auto range = timeline.equal_range(data.time);
        for (auto it2 = range.first; it2 != range.second; ++it2) {
            if (it2->second == key) {
                timeline.erase(it2);
                break;
            }
        }
        //if (data.clock == CLOCK_MONOTONIC) {
        //    struct itimerspec its;
        //    if (timeline.empty()) {
        //        its.it_value.tv_sec = 0;
        //        its.it_value.tv_nsec = 0;
        //    } else {
        //        uint64_t first = timeline.begin()->first;
        //        its.it_value.tv_sec = first / 1000000000;
        //        its.it_value.tv_nsec = first % 1000000000;
        //    }
        //    its.it_interval.tv_sec = 0;
        //    its.it_interval.tv_nsec = 0;
        //    timer_settime(monotonic_timer, TIMER_ABSTIME, &its, nullptr);
        //}
    }
}

bool EventQueue::cancel(uintptr_t key) {
    std::lock_guard lock(mutex);
    auto it = events.find(key);
    if (it == events.end()) {
        return false;
    }
    cancel_internal(key, it->second, it->second.type);
    events.erase(it);
    return true;
}

void EventQueue::update(uintptr_t key, const std::function<void (int)> &callback) {
    std::lock_guard lock(mutex);
    auto it = events.find(key);
    if (it == events.end()) {
        return;
    }
    it->second.callback = callback;
}

int EventQueue::poll(CQEBuffer &buffer, std::unique_lock<SpinLock> &lock) {
    unsigned int n = io_uring_peek_batch_cqe(&ring, buffer.cqes.data(), buffer.cqes.size());
    return handle_events(n, buffer, lock);
}

void EventQueue::sleep(CQEBuffer &buffer) {
    uint64_t timeout = -1ull;
    int64_t t;
    std::unique_lock lock(mutex);
    {
        if (!monotonic_timeline.empty()) {
            t = monotonic_timeline.begin()->first - time_nanosec(CLOCK_MONOTONIC);
            if (t < 0) {
                t = 0;
            }
            if ((uintptr_t)t < timeout) {
                timeout = t;
            }
        }
        if (timeout != 0 && !realtime_timeline.empty()) {
            t = realtime_timeline.begin()->first - time_nanosec(CLOCK_REALTIME);
            if (t < 0) {
                t = 0;
            }
            if ((uintptr_t)t < timeout) {
                timeout = t;
            }
        }
        if (timeout != 0 && !boottime_timeline.empty()) {
            t = boottime_timeline.begin()->first - time_nanosec(CLOCK_BOOTTIME);
            if (t < 0) {
                t = 0;
            }
            if ((uintptr_t)t < timeout) {
                timeout = t;
            }
        }
    }

    struct __kernel_timespec ts;
    if (timeout != -1ull) {
        ts.tv_sec = timeout / 1000000000;
        ts.tv_nsec = timeout % 1000000000;
    }

    unsigned int n = poll(buffer, lock);
    if (n > 0 || timeout == 0) {
        return;
    }

    struct io_uring_getevents_arg arg = {
        .sigmask = 0,
        .sigmask_sz = _NSIG / 8,
        .ts = timeout == -1ull ? 0 : (uint64_t)&ts
    };
    lock.unlock();
    io_uring_enter2(ring.enter_ring_fd, 0, 1, IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG,
                    (sigset_t *)&arg, sizeof(arg));
    lock.lock();
    poll(buffer, lock);
}

void EventQueue::interrupt() {
    std::unique_lock lock(mutex);
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        throw Exception("ring is full");
    }
    io_uring_prep_nop(sqe);
    io_uring_sqe_set_data(sqe, (void *)NOPKey);
    io_uring_submit(&ring);
}

int EventQueue::handle_events(unsigned int n, CQEBuffer &buffer, std::unique_lock<SpinLock> &lock) {
    unsigned int j = 0;

    {
        //std::lock_guard lock(mutex);
        buffer.finished_events.resize(n);
        if (n > 0) {
            for (unsigned int i = 0; i < n; ++i) {
                struct io_uring_cqe *cqe = buffer.cqes[i];
                uintptr_t key = (uintptr_t)io_uring_cqe_get_data(cqe);
                if (!key) {
                    io_uring_cqe_seen(&ring, cqe);
                    continue;
                }
                int res = cqe->res;
                auto it = events.find(key);
                if (it == events.end()) {
                    io_uring_cqe_seen(&ring, cqe);
                    continue;
                }
                buffer.finished_events[j].callback = it->second.callback;
                buffer.finished_events[j].res = res;
                cancel_other_event(key, it->second, IOUringEvent);
                events.erase(it);
                io_uring_cqe_seen(&ring, cqe);
                ++j;
            }
            buffer.finished_events.resize(j);
        }
        handle_timer(CLOCK_MONOTONIC, monotonic_timeline, buffer);
        handle_timer(CLOCK_REALTIME, realtime_timeline, buffer);
        handle_timer(CLOCK_BOOTTIME, boottime_timeline, buffer);
        
    }
    if (buffer.finished_events.empty()) {
        return 0;
    }
    lock.unlock();

    for (size_t i = 0; i < buffer.finished_events.size(); ++i) {
        if (buffer.finished_events[i].callback) {
            buffer.finished_events[i].callback(buffer.finished_events[i].res);
        }
    }
    return buffer.finished_events.size();
}

void EventQueue::handle_timer(clockid_t clock, std::multimap<uint64_t, uintptr_t> &timeline,
                              CQEBuffer &buffer) {
    if (timeline.empty()) {
        return;
    }
    uint64_t now = time_nanosec(clock);
    uint64_t first = -1;
    for (auto it = timeline.begin(); it != timeline.end(); ) {
        auto next = std::next(it);
        int64_t diff = it->first - now;
        if (diff > 0) {
            first = it->first;
            break;
        }
        //Stat::get().add(1, -diff);
        uintptr_t key = it->second;
        auto it2 = events.find(key);
        if (it2 != events.end()) {
            buffer.finished_events.emplace_back(it2->second.callback, -ETIME);
            cancel_other_event(key, it2->second, TimerEvent);
            events.erase(it2);
        }

        timeline.erase(it);
        it = next;
    }
    //if (clock == CLOCK_MONOTONIC) {
    //    struct itimerspec its;
    //    if (first == -1) {
    //        its.it_value.tv_sec = 0;
    //        its.it_value.tv_nsec = 0;
    //    } else {
    //        its.it_value.tv_sec = first / 1000000000;
    //        its.it_value.tv_nsec = first % 1000000000;
    //    }
    //    its.it_interval.tv_sec = 0;
    //    its.it_interval.tv_nsec = 0;
    //    timer_settime(monotonic_timer, TIMER_ABSTIME, &its, nullptr);
    //}
}

inline void EventQueue::cancel_other_event(uintptr_t key, const Data &data, uint32_t from) {
    uint32_t other_sources = data.type & (~from);
    if (other_sources) {
        cancel_internal(key, data, other_sources);
    }
}

bool EventQueue::ready() {
    return io_uring_cq_ready(&ring);
}
