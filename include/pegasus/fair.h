#pragma once
#include <memory>
#include <map>
#include "sched.h"

namespace pegasus {
class FairReadyQueue;
class FairScheduler : public Scheduler {
public:
    FairScheduler(TaskManager *tm_);
    virtual ~FairScheduler();
    virtual std::unique_ptr<ReadyQueue> create_rq(Executor *executor);
    virtual Executor *select_task_rq(const std::shared_ptr<Task> &task, int prev, int flags);
private:
    friend class FairReadyQueue;
    inline FairReadyQueue &get_rq(int eid) {
        return (FairReadyQueue &)(tm->get_executor(eid)->get_rq());
    }
    int find_idlest_executor(const std::shared_ptr<Task> &task, int eid, int prev, int flags);
    int select_idle_executor(const std::shared_ptr<Task> &task, int prev, int target);
    int select_idle_executor(const std::shared_ptr<Task> &task, int target);
    static void sync_task_load_avg(const std::shared_ptr<Task> &task);
};

class FairReadyQueue : public ReadyQueue {
public:
    FairReadyQueue(TaskManager *tm_, Executor *executor_);
    virtual ~FairReadyQueue();
    virtual void dequeue_task(const std::shared_ptr<Task> &task, int flags = 0);
    virtual void enqueue_task(const std::shared_ptr<Task> &task, int flags = 0);
    virtual std::shared_ptr<Task> pick_next_task(std::shared_ptr<Task> &prev);
    virtual void put_prev_task(std::shared_ptr<Task> &prev);
    virtual void set_next_task(const std::shared_ptr<Task> &task, bool first = false);
    virtual void migrate_task_rq(const std::shared_ptr<Task> &task);
    virtual void task_tick();
    virtual void check_preempt_curr(const std::shared_ptr<Task> &task, int flags = 0);
    virtual void task_fork(const std::shared_ptr<Task> &task);
    virtual void task_dead(const std::shared_ptr<Task> &task);
    virtual void resched_curr();
    virtual void yield_task();
    virtual void update_curr();
    virtual int get_num_tasks();
    virtual void trigger_load_balance();
    virtual uint64_t get_last_idle_stamp();
    virtual std::shared_ptr<Task> &get_curr();
    virtual bool is_idle();
    virtual void set_idle();
    virtual double get_load_avg() {
        return avg.load_avg;
    }
private:
    friend class FairScheduler;
    friend class Executor;
    struct LBEnv;
    enum IdleType {
        Idle = 0,
        NotIdle = 1,
        NewlyIdle = 2,
    };
    enum MigrationType {
        MigrateLoad = 0,
        MigrateUtil = 1,
        MigrateTask = 2,
    };
    enum {
        DoAttach = 0x1u,
        DoDetach = 0x2u,
        SkipAgeLoad = 0x4u,
    };
    enum {
        StartDebit = 0x1ull,
        BaseSlice = 0x2ull,
        GentleFairSleepers = 0x4ull,
        NextBuddy = 0x8ull,
        LastBuddy = 0x10ull,
        WakeupPreemption = 0x20ull,
    };
    void update_min_vruntime();
    void update_load_avg(const std::shared_ptr<Task> &task, int flags);
    bool update_load_avg_task(const std::shared_ptr<Task> &task);
    bool update_load_avg();
    void place_task(const std::shared_ptr<Task> task, bool initial);
    uint64_t sched_slice(const std::shared_ptr<Task> task);
    uint64_t sched_vslice(const std::shared_ptr<Task> task);
    void clear_buddies(const std::shared_ptr<Task> &task);
    void account_enqueue(const std::shared_ptr<Task> task);
    void account_dequeue(const std::shared_ptr<Task> task);
    std::shared_ptr<Task> pick_first();
    std::shared_ptr<Task> pick_next(const std::shared_ptr<Task> &task);
    void rebalance(IdleType idle);
    int load_balance(IdleType idle, bool &continue_balancing);
    bool should_we_balance(const LBEnv &env);
    FairReadyQueue *find_busiest_queue(LBEnv &env);
    int detach_tasks(LBEnv &env);
    bool can_migrate_task(const std::shared_ptr<Task> &p, LBEnv &env);
    void attach_tasks(LBEnv &env);
    std::shared_ptr<Task> pick_next_task_internal(std::shared_ptr<Task> curr_);
    int newidle_balance();
    void remove_task_load_avg(const std::shared_ptr<Task> &task);

    inline bool has_feature(uint64_t feature) {
        return features & feature;
    }
    uint64_t features;
    unsigned int nr_running;
    double load_weight;
    uint64_t min_vruntime;
    uint64_t idle_stamp;
    SchedAvg avg;

    bool idle_balance;
    uint64_t next_balance;

    struct Compare {
        inline bool operator()(const Task *t1, const Task *t2) const {
            int64_t diff = int64_t(t1->vruntime - t2->vruntime);
            if (diff < 0) {
                return true;
            } else if (diff > 0) {
                return false;
            }
            return t1 < t2;
        }
    };
    std::map<Task *, std::shared_ptr<Task>, Compare> tasks_timeline;

    std::shared_ptr<Task> curr;

    std::shared_ptr<Task> next;
    std::shared_ptr<Task> skip;
    std::shared_ptr<Task> last;

    struct {
        int nr;
        double load_avg;
        double runnable_avg;
        SpinLock mutex;
    } removed;
};
}