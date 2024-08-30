#pragma once
#include <memory>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <cstdio>
#include "lock.h"
#include "sched.h"

namespace pegasus {

class WaitQueue : public std::enable_shared_from_this<WaitQueue> {
public:
    enum {
        WakeWQ = 0x1u,
        WakeMigrated = 0x2u,
        WakeFork = 0x4u,
        WakeEQ = 0x8u,
    };
    WaitQueue(uintptr_t key_ = 0);
    WaitQueue(const WaitQueue &) = delete;
    WaitQueue &operator=(const WaitQueue &) = delete;
    ~WaitQueue();

    void add_task(const std::shared_ptr<Task> &task, uint32_t mask = -1u, bool interruptible = true);
    inline size_t wake(Task *task, Task::WaitResult res) {
        return wake_internal(task, res);
    }
    inline size_t wake(Task *task) {
        return wake_internal(task, Task::WaitResult(0, 0));
    }
    size_t wake_one(uint32_t mask = -1u, Task::WaitResult res = {});
    size_t wake_all(uint32_t mask = -1u, Task::WaitResult res = {});
    size_t wake_some(size_t max_tasks, uint32_t mask = -1u, Task::WaitResult res = {});
    size_t requeue_one(std::shared_ptr<WaitQueue> wq);
    size_t requeue(std::shared_ptr<WaitQueue> wq, size_t max_wake_tasks, size_t max_requeue_tasks);
    inline uintptr_t get_key() const {
        return key;
    }
    inline SpinLock &get_mutex() {
        return mutex;
    }
    inline size_t get_num_tasks() {
        std::lock_guard lock(mutex);
        return tasks.size();
    }
private:
    friend class EventQueue;
    struct Data {
        std::shared_ptr<Task> task;
        EventQueue *eq;
        uintptr_t key;
        uint32_t mask;
    };
    void add_task_internal(const std::shared_ptr<Task> &task,
                           EventQueue *eq, uintptr_t key, uint32_t mask, bool interruptible);
    size_t wake_internal(Task *task, Task::WaitResult res);
    size_t wake_task(const std::shared_ptr<Task> &task, Task::WaitResult res);
    size_t get_tasks(size_t max_tasks, std::vector<Data> &wake_tasks, uint32_t mask = -1u);
    void wake_tasks(const std::vector<Data> &wake_tasks, Task::WaitResult res);

    uintptr_t key;
    SpinLock mutex;
    std::unordered_map<Task *, Data> tasks;
};
}