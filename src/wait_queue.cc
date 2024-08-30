#include <memory>
#include <thread>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <linux/time_types.h>
#include <liburing.h>
#include "pegasus/event.h"
#include "pegasus/runtime.h"
#include "pegasus/sched.h"
#include "pegasus/stat.h"
#include "pegasus/wait_queue.h"

using namespace pegasus;

WaitQueue::WaitQueue(uintptr_t key_)
    : key(key_) {
}

WaitQueue::~WaitQueue() {
}

void WaitQueue::add_task(const std::shared_ptr<Task> &task, uint32_t mask, bool interruptible) {
    std::lock_guard lock(mutex);
    add_task_internal(task, nullptr, 0, mask, interruptible);
}

void WaitQueue::add_task_internal(const std::shared_ptr<Task> &task,
                                  EventQueue *eq, uintptr_t key, uint32_t mask, bool interruptible) {
    task->mutex.lock();
    Data data;
    data.task = task;
    data.eq = eq;
    data.key = key;
    data.mask = mask;
    try {
        tasks[task.get()] = data;
    } catch (std::bad_alloc &e) {
        task->mutex.unlock();
        throw;
    }
    task->wq_res = Task::WaitResult(0, -1);
    task->wq = shared_from_this();
    task->state = interruptible ? Task::Interruptible : Task::Uninterruptible;
}

size_t WaitQueue::wake_task(const std::shared_ptr<Task> &task, Task::WaitResult res) {
    ReadyQueue *rq;
    Executor *wake_executor;
    Executor *executor;
    {
        std::lock_guard lock(task->mutex);
        wake_executor = task->executor;
        int eid = wake_executor->get_eid();
        executor = Runtime::get()->get_tm()->get_scheduler()->select_task_rq(task, eid, WakeWQ);
        rq = &executor->get_rq();
        task->state = Task::Waking;
        task->executor = executor;
        task->wq = nullptr;
        task->wq_key = this->key;
        task->wq_res = res;
    }
    int wake_flags = WakeWQ;
    if (res.from_eq) {
        wake_flags |= WakeEQ;
    }
    //if (res.from_eq) {
    //    Stat::get().add(1, Executor::get_current_executor() == executor);
    //} else {
    //    Stat::get().add(2, Executor::get_current_executor() == executor);
    //}
    int enqueue_flags = ReadyQueue::EnqueueWakeup | ReadyQueue::EnqueueNoClock;
    if (executor != wake_executor) {
        wake_flags |= WakeMigrated;
        enqueue_flags |= ReadyQueue::EnqueueMigrated;
        ReadyQueue &prev_rq = wake_executor->get_rq();
        std::lock_guard lock(prev_rq.get_mutex());
        prev_rq.migrate_task_rq(task);
    }
    {
        std::lock_guard lock(rq->get_mutex());
        rq->update_clock();
        rq->activate_task(task, enqueue_flags);
        rq->check_preempt_curr(task, wake_flags);
        task->state = Task::Running;
    }
    return 1;
}

void WaitQueue::wake_tasks(const std::vector<Data> &wake_tasks,
                           Task::WaitResult res) {
    for (auto &t : wake_tasks) {
        if (t.eq) {
            t.eq->cancel(t.key);
        }
        wake_task(t.task, res);
    }
}

size_t WaitQueue::wake_internal(Task *task_, Task::WaitResult res) {
    std::shared_ptr<Task> task;
    EventQueue *eq;
    uintptr_t key;
    {
        std::lock_guard lock(mutex);
        auto it = tasks.find(task_);
        if (it == tasks.end()) {
            return 0;
        }
        task = it->second.task;
        eq = it->second.eq;
        key = it->second.key;
        tasks.erase(it);
    }
    if (!res.from_eq && eq) {
        eq->cancel(key);
    }
    return wake_task(task, res);
}

size_t WaitQueue::get_tasks(size_t max_tasks, std::vector<Data> &wake_tasks, uint32_t mask) {
    std::lock_guard lock(mutex);
    if (tasks.empty()) {
        return 0;
    }
    size_t n = 0;
    for (auto it = tasks.begin(); it != tasks.end(); ) {
        auto next = std::next(it);
        if (it->second.mask & mask) {
            wake_tasks.push_back(it->second);
            tasks.erase(it);
            ++n;
            if (n >= max_tasks) {
                break;
            }
        }
        it = next;
    }
    return n;
}

size_t WaitQueue::wake_one(uint32_t mask, Task::WaitResult res) {
    std::shared_ptr<Task> task;
    EventQueue *eq;
    uintptr_t key;
    {
        std::lock_guard lock(mutex);
        if (tasks.empty()) {
            return 0;
        }
        if (mask == -1u) {
            auto it = tasks.begin();
            task = it->second.task;
            eq = it->second.eq;
            key = it->second.key;
            tasks.erase(it);
        } else {
            for (auto it = tasks.begin(); it != tasks.end(); ++it) {
                if (!(it->second.mask & mask)) {
                    continue;
                }
                task = it->second.task;
                eq = it->second.eq;
                key = it->second.key;
                tasks.erase(it);
                goto out;
            }
            return 0;
        }
    }
out:
    if (eq) {
        eq->cancel(key);
    }
    return wake_task(task, res);
}

size_t WaitQueue::wake_all(uint32_t mask, Task::WaitResult res) {
    return wake_some(-1, mask, res);
}

size_t WaitQueue::wake_some(size_t max_tasks, uint32_t mask, Task::WaitResult res) {
    static thread_local std::vector<Data> wake_tasks_;
    wake_tasks_.clear();
    size_t n = get_tasks(max_tasks, wake_tasks_, mask);
    wake_tasks(wake_tasks_, res);
    return n;
}

size_t WaitQueue::requeue_one(std::shared_ptr<WaitQueue> wq) {
    std::shared_ptr<Task> task;
    EventQueue *eq;
    uintptr_t key;
    {
        std::lock_guard lock(mutex);
        if (tasks.empty()) {
            return 0;
        }
        auto it = tasks.begin();
        task = it->second.task;
        eq = it->second.eq;
        key = it->second.key;
    }
    if (eq) {
        eq->update(key, [wq1 = shared_from_this(), wq2 = wq, ptask = task.get()] (int) {
            int flags = Task::WaitResult::Timeout | Task::WaitResult::Interrupted;
            wq1->wake_internal(ptask, Task::WaitResult(flags, 0));
            wq2->wake_internal(ptask, Task::WaitResult(flags, 0));
        });
    }
    {
        std::scoped_lock lock(mutex, wq->mutex);
        if (tasks.empty()) {
            return 0;
        }
        auto it = tasks.find(task.get());
        if (it == tasks.end()) {
            // has waken
            return 0;
        }
        {
            std::lock_guard lock(task->mutex);
            task->wq = wq;
        }
        wq->tasks[task.get()] = it->second;
        tasks.erase(it);
    }
    if (eq) {
        eq->update(key, [wq, ptask = task.get()] (int) {
            int flags = Task::WaitResult::Timeout | Task::WaitResult::Interrupted;
            wq->wake_internal(ptask, Task::WaitResult(flags, 0));
        });
    }
    return 1;
}

size_t WaitQueue::requeue(std::shared_ptr<WaitQueue> wq, size_t max_wake_tasks, size_t max_requeue_tasks) {
    size_t n = 0;
    for (; n < max_wake_tasks && wake_one(); ++n);
    if (n < max_wake_tasks || !max_requeue_tasks || !wq) {
        return n;
    }
    size_t m = 0;
    for (; m < max_requeue_tasks && requeue_one(wq); ++m);
    return m + n;
}