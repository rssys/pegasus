#pragma once

#include <thread>
#include <condition_variable>
#include <memory>
#include <vector>
#include <list>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <map>
#include <functional>
#include <atomic>
#include <x86intrin.h>
#include "allocator.h"
#include "event.h"
#include "lock.h"
#include "percpu.h"
#include "types.h"

namespace pegasus {

extern "C" long pegasus_executor_context_switch(CompactCPUState *old_reg,
                                               const CompactCPUState *new_reg, long res = 0);

class VThread;
struct Executor;
class WaitQueue;
struct SchedAvg {
    uint64_t last_update_time;
    double load_sum;
    double runnable_sum;
    //double util_sum;
    double period_contrib;
    double load_avg;
    double runnable_avg;
    //double util_avg;
};
struct Task {
    struct WaitResult {
        enum {
            Timeout = 0x1,
            Interrupted = 0x2,
            FromEventQueue = 0x4,
            FromIOWorker = 0x8,
            FromSignal = 0x10,
        };
        WaitResult() : timeout(0), interrupted(0), from_eq(0), from_iow(0), from_signal(0), data(0) {}
        WaitResult(int flags, uintptr_t data_)
            : timeout(!!(flags & Timeout)),
              interrupted(!!(flags & Interrupted)),
              from_eq(!!(flags & FromEventQueue)),
              from_iow(!!(flags & FromIOWorker)),
              from_signal(!!(flags & FromSignal)),
              data(data_) {}
        WaitResult(int flags, int cqe_res_)
            : timeout(!!(flags & Timeout)),
              interrupted(!!(flags & Interrupted)),
              from_eq(!!(flags & FromEventQueue)),
              from_iow(!!(flags & FromIOWorker)),
              from_signal(!!(flags & FromSignal)),
              cqe_res(cqe_res_) {}
        unsigned int timeout        : 1;
        unsigned int interrupted    : 1;
        unsigned int from_eq        : 1;
        unsigned int from_iow       : 1;
        unsigned int from_signal    : 1;
        unsigned int                : 3;
        union {
            int cqe_res;
            uintptr_t data;
            pid_t pid;
        };
    };
    enum {
        Initializing = -1,
        Running = 0,
        Interruptible = 1,
        Uninterruptible = 2,
        Waking = 3,
        Stopped = 4,
    };
    enum {
        FlagNeedResched = 0x1u,
    };
    Task(TaskManager *tm_);
    Task(const Task &) = delete;
    Task &operator=(const Task &) = delete;
    ~Task();
    void signal();
    //inline void set_need_resched() {
    //    flags |= FlagNeedResched;
    //}
    //inline void clear_need_resched() {
    //    flags &= ~FlagNeedResched;
    //}
    //inline bool need_resched() {
    //    return flags & FlagNeedResched;
    //}
    void set_need_resched();
    void clear_need_resched();
    bool need_resched();
    CompactCPUState registers;
    uint8_t *stack;
    size_t stack_size;
    int state;

    uint64_t vruntime;
    uint64_t exec_start;
    uint64_t sum_exec_runtime;
    uint64_t prev_sum_exec_runtime;

    uint64_t sys_time;
    uint64_t last_sys_time;

    double load_weight;
    SchedAvg avg;
    bool on_rq;

    uint64_t wake_time = -1;

    int tid;
    std::shared_ptr<VThread> vthread;
    SpinLock mutex;
    std::function<void (void)> routine;

    TaskManager *tm;
    Executor *executor;
    Executor *wake_executor;
    Executor *recent_executor;
    std::shared_ptr<WaitQueue> wq;

    uintptr_t wq_key;
    WaitResult wq_res;
    CPUSet affinity;
    uint32_t flags;
};

using Tasklet = std::function<void ()>;

class TaskManager;

class ReadyQueue {
public:
    enum {
        EnqueueWakeup = 0x1u,
        EnqueueKeepTaskLocked = 0x2u,
        EnqueueNew = 0x4u,
        EnqueueMigrated = 0x8u,
        EnqueueRestore = 0x10u,
        EnqueueMove = 0x20u,
        EnqueueNoClock = 0x40u,
    };
    enum {
        DequeueSleep = 0x1u,
        DequeueSave = 0x2u,
        DequeueMove = 0x4u,
        DequeueNoClock = 0x8u,
    };
    ReadyQueue(TaskManager *tm_, Executor *executor_);
    virtual ~ReadyQueue();
    void activate_task(const std::shared_ptr<Task> &task, int flags = 0);
    void deactivate_task(const std::shared_ptr<Task> &task, int flags = 0);
    virtual void dequeue_task(const std::shared_ptr<Task> &task, int flags = 0) = 0;
    virtual void enqueue_task(const std::shared_ptr<Task> &task, int flags = 0) = 0;
    virtual std::shared_ptr<Task> pick_next_task(std::shared_ptr<Task> &prev) = 0;
    virtual void put_prev_task(std::shared_ptr<Task> &prev) = 0;
    virtual void set_next_task(const std::shared_ptr<Task> &task, bool first = false) = 0;
    virtual void migrate_task_rq(const std::shared_ptr<Task> &task) = 0;
    virtual void task_tick() = 0;
    virtual void check_preempt_curr(const std::shared_ptr<Task> &task, int flags = 0) = 0;
    virtual void task_fork(const std::shared_ptr<Task> &task) = 0;
    virtual void task_dead(const std::shared_ptr<Task> &task) = 0;
    virtual void resched_curr() = 0;
    virtual void yield_task() = 0;
    virtual void update_curr() = 0;
    virtual int get_num_tasks() = 0;
    virtual void trigger_load_balance() = 0;
    virtual uint64_t get_last_idle_stamp() = 0;
    inline void update_clock() {
        now = time_nanosec();
    }
    inline SpinLock &get_mutex() {
        return mutex;
    }
    virtual std::shared_ptr<Task> &get_curr() = 0;
    virtual bool is_idle() = 0;
    virtual void set_idle() = 0;
    virtual double get_load_avg() = 0;
protected:
    SpinLock mutex;
    TaskManager *tm;
    Executor *executor;
    uint64_t now;
};

class Executor {
public:
    enum {
        YieldSleep = 0x1,
        YieldDying = 0x2,
        YieldTaskLocked = 0x4,
        YieldMigrate = 0x8,
    };
    Executor(TaskManager *tm_, int eid_, int core_ = -1);
    Executor(const Executor &) = delete;
    Executor &operator=(const Executor &) = delete;
    static void schedule(int flags = 0);
    static void cond_schedule();
    static void yield();
    static void block();
    static void fail();
    void migrate_to();
    void start();
    void wait();
    void send_reschedule(bool from_eq = false);
    inline ReadyQueue &get_rq() {
        return *rq;
    }
    inline EventQueue &get_eq() {
        return eq;
    }
    inline static Executor *get_current_executor() {
        return PER_CPU_PRIV_REF(current_executor);
    }
    inline static int get_current_eid() {
        return GET_PER_CPU_PRIV(current_eid);
    }
    inline static const std::shared_ptr<Task> &get_current_task() {
        return PER_CPU_PRIV_REF(current_task);
    }
    inline TaskManager *get_tm() {
        return tm;
    }
    inline pid_t get_tid() {
        return tid;
    }
    inline int get_eid() {
        return eid;
    }
    //inline bool is_idle() {
    //    return curr == idle_task;
    //}
    bool is_idle();
    inline bool is_sleeping() {
        return eq_state.load(std::memory_order_acquire) & Sleeping;
    }
    inline EventQueue::CQEBuffer &get_cqe_buffer() {
        return cqe_buffer;
    }
    inline void poll_fast() {
        if (get_eq().ready()) {
            get_eq().poll(cqe_buffer);
        }
    }
    void add_tasklet(const Tasklet &tasklet);
private:
    friend class TaskManager;
    enum {
        Sleeping = 0x1,
        Polling = 0x2,
        Interrupted = 0x3,
        Scheduling = 0x4,
    };
    static void task_routine();
    int run_task(const std::shared_ptr<Task> &task);
    void executor_routine();
    bool handle_timer();
    void idle_routine();

    std::unique_ptr<std::thread> thread;
    std::unique_ptr<ReadyQueue> rq;
    std::shared_ptr<Task> idle_task;
    std::shared_ptr<Task> curr;

    TaskManager *tm;
    EventQueue eq;
    EventQueue::CQEBuffer cqe_buffer;
    std::vector<Tasklet> tasklets;

    pid_t tid;
    int eid;
    int core;
    std::atomic_int eq_state;

    uint64_t eq_interrupt_time;

    timer_t monotonic_timer;
};

class Scheduler {
public:
    Scheduler(TaskManager *tm_) : tm(tm_) {}
    Scheduler(const Scheduler &) = delete;
    Scheduler &operator=(const Scheduler &) = delete;
    virtual ~Scheduler() {}
    virtual std::unique_ptr<ReadyQueue> create_rq(Executor *executor) = 0;
    virtual Executor *select_task_rq(const std::shared_ptr<Task> &task, int prev, int flags) = 0;
protected:
    TaskManager *tm;
};

class IOWorker;
class TaskManager {
public:
    TaskManager(size_t num_threads, bool has_ioworker = true,
                bool pin = true, const std::vector<int> &cores = {});
    TaskManager(const TaskManager &) = delete;
    TaskManager &operator=(const TaskManager &) = delete;
    ~TaskManager();
    void run();
    std::shared_ptr<Task> create_task(const std::function<void (void)> &routine, bool alloc_tid = true);
    void remove_task(int tid);
    void broadcast_signal(int sig);
    inline pid_t get_pid() {
        return pid;
    }
    inline IOWorker *get_ioworker() {
        return ioworker.get();
    }
    inline size_t get_num_executors() {
        return executors.size();
    }
    inline Executor *get_executor(int eid) {
        return executors[eid].get();
    }
    inline SlabAllocator &get_stack_allocator() {
        return stack_allocator;
    }
    inline Scheduler *get_scheduler() {
        return scheduler.get();
    }
    inline CPUSet get_full_affinity() {
        return full_affinity;
    }
    void wake_up_new_task(const std::shared_ptr<Task> &task);
    std::shared_ptr<Task> get_task(int tid);
    void add_task(int tid, const std::shared_ptr<Task> &task);
    void wait_barrier();
    void add_tasklet(const Tasklet &tasklet);
private:
    int find_unused_tid();
    SpinLock mutex;
    std::unique_ptr<Scheduler> scheduler;
    std::vector<std::unique_ptr<Executor>> executors;
    std::unique_ptr<IOWorker> ioworker;
    std::map<int, std::weak_ptr<Task>> tid_task_map;
    pid_t pid;
    int num_started;
    int max_tid;
    pthread_barrier_t barrier;
    SlabAllocator stack_allocator;
    CPUSet full_affinity;
public:
    bool stopped;
    uint64_t jiffies;
};

class CleanupWorkManager {
public:
    void add(const Tasklet &tasklet);
    void check();
private:
    std::vector<Tasklet> tasklets;
};

struct TaskManagerReference {
    TaskManagerReference(TaskManager *tm_) : tm(tm_) {}
    ~TaskManagerReference() {
        tm->stopped = true;
        try {
            tm->broadcast_signal(SIGALRM);
        } catch (...) {
        }
    }
    TaskManager *tm;
};
}
