#include <algorithm>
#include <climits>
#include <cassert>
#include <cmath>
#include "pegasus/cluster.h"
#include "pegasus/fair.h"
#include "pegasus/percpu.h"
#include "pegasus/sched.h"
#include "pegasus/stat.h"
#include "pegasus/wait_queue.h"

using namespace pegasus;

static constexpr unsigned int SchedLatency = 6000000ul;
static constexpr unsigned int SchedMinGranularity = 750000ul;
static constexpr unsigned int SchedWakeupGranularity = 1000000ul;
static constexpr unsigned int SchedNRLatency = 8;
static constexpr unsigned int SchedNRMigrateBreak = 32;
static constexpr unsigned int SchedNRMigrate = SchedNRMigrateBreak;
static constexpr double LoadAvgMax = 47742.0 / 1024;
static constexpr uint64_t LoadAvgPeriod = 32;

#define DEBUG_SCHED(...)
#define CHECK_VRUNTIME(x)

static inline uint64_t min_vruntime(uint64_t min_vruntime, uint64_t vruntime) {
    int64_t delta = (int64_t)(vruntime - min_vruntime);
    if (delta < 0) {
        min_vruntime = vruntime;
    }
    return min_vruntime;
}

static inline uint64_t max_vruntime(uint64_t max_vruntime, uint64_t vruntime) {
    int64_t delta = (int64_t)(vruntime - max_vruntime);
    if (delta > 0) {
        max_vruntime = vruntime;
    }
    return max_vruntime;
}

static inline uint64_t calc_delta_fair(uint64_t delta, const std::shared_ptr<Task> &task) {
    return delta / task->load_weight;
}

static inline bool entity_before(const std::shared_ptr<Task> &t1, const std::shared_ptr<Task> &t2) {
    return int64_t(t1->vruntime - t2->vruntime) < 0;
}

static uint64_t wakeup_gran(const std::shared_ptr<Task> &task) {
    uint64_t gran = SchedWakeupGranularity;
    return calc_delta_fair(gran, task);
}

static inline int wakeup_preempt_entity(const std::shared_ptr<Task> &curr,
                                        const std::shared_ptr<Task> &task) {
    int64_t vdiff = curr->vruntime - task->vruntime;
    if (vdiff <= 0) {
        return -1;
    }
    int64_t gran = wakeup_gran(task);
    if (vdiff > gran) {
        return 1;
    }
    return 0;
}

static inline uint64_t sched_period(unsigned long nr_running) {
    if (nr_running > SchedNRLatency) {
        return nr_running * SchedMinGranularity;
    } else {
        return SchedLatency;
    }
}

static double decay_load(double val, uint64_t n) {
    return val * powf(0.97857206208770, n);
}

static void sub_positive(double &x, double y) {
    double z = x - y;
    x = z >= 0 ? z : 0;
}

static bool update_load_sum(uint64_t now, SchedAvg &sa, double load, uint64_t runnable, bool running) {
    uint64_t delta = now - sa.last_update_time;
    if ((int64_t)delta < 0) {
        sa.last_update_time = now;
        return false;
    }

    delta >>= 10;
    if (!delta)
        return 0;

    sa.last_update_time += delta << 10;
    if (!load)
        runnable = running = 0;
    
    double contrib = delta;
    delta += sa.period_contrib;
    uint64_t periods = delta / 1;

    if (periods) {
        //printf("before decay: %f %d\n", sa.load_sum, periods);
        sa.load_sum = decay_load(sa.load_sum, periods);
        sa.runnable_sum = decay_load(sa.runnable_sum, periods);
        //sa.util_sum = decay_load(sa.util_sum, periods);
        delta %= 1;
        if (load) {
            double d1 = 1 - sa.period_contrib;
            double d3 = delta;
            double c1 = decay_load(d1, periods);
            double c2 = LoadAvgMax - decay_load(LoadAvgMax, periods) - 1;
            contrib = c1 + c2 + d3;
        }
        //printf("after decay: %f\n", sa.load_sum);
    }
    sa.period_contrib = delta;
    if (load) {
        sa.load_sum += load * contrib;
    }
    if (runnable) {
        sa.runnable_sum += runnable * contrib;
    }
    if (running) {
        //sa.util_sum += contrib;
    }
    //printf("return: %f %f\n", sa.load_sum, contrib);
    return periods;
}

static inline void update_load_avg(SchedAvg &sa, double load) {
    double divider = (LoadAvgMax - 1) + sa.period_contrib;
    sa.load_avg = load * sa.load_sum / divider;
    sa.runnable_avg = sa.runnable_sum / divider;
    //sa.util_avg = sa.util_sum / divider;
}

FairScheduler::FairScheduler(TaskManager *tm_)
    : Scheduler(tm_) {

}

FairScheduler::~FairScheduler() {

}

std::unique_ptr<ReadyQueue> FairScheduler::create_rq(Executor *executor) {
    return std::make_unique<FairReadyQueue>(tm, executor);
}

Executor *FairScheduler::select_task_rq(const std::shared_ptr<Task> &task, int prev, int flags) {
    if (tm->get_num_executors() == 1) {
        return tm->get_executor(0);
    }
    int cpu = Executor::get_current_eid();
    int new_cpu = prev;
    bool use_fast_path = flags == WaitQueue::WakeWQ;
    if (use_fast_path) {
        new_cpu = select_idle_executor(task, prev, new_cpu);
    } else {
        new_cpu = find_idlest_executor(task, cpu, prev, flags);
    }
    DEBUG_SCHED(printf("select_task_rq task %d prev %d flags %x new %d\n", task->tid, prev, flags, new_eid));
    return tm->get_executor(new_cpu);
}

int FairScheduler::find_idlest_executor(const std::shared_ptr<Task> &task, int eid, int prev, int flags) {
    if (!(flags & WaitQueue::WakeFork)) {
        sync_task_load_avg(task);
    }
    double min_load = std::numeric_limits<double>::max();
    int least_loaded = eid;
    int shallowset_idle = -1;
    uint64_t latest_idle_timestamp = 0;
    task->affinity.for_each(tm->get_num_executors(), [&, this] (int e) {
        FairReadyQueue &rq = get_rq(e);
        if (rq.is_idle()) {
            uint64_t stamp = rq.idle_stamp;
            if (stamp > latest_idle_timestamp) {
                shallowset_idle = e;
                latest_idle_timestamp = stamp;
            }
        } else if (shallowset_idle == -1) {
            double load = rq.avg.load_avg;
            if (load < min_load) {
                min_load = load;
                least_loaded = e;
            }
        }
        return true;
    });
    return shallowset_idle != -1 ? shallowset_idle : least_loaded;
}

void FairScheduler::sync_task_load_avg(const std::shared_ptr<Task> &task) {
    Executor *executor = task->executor;
    if (!executor) {
        return;
    }
    FairReadyQueue &rq = (FairReadyQueue &)executor->get_rq();
    uint64_t load_update_time = rq.avg.last_update_time;
    if (update_load_sum(load_update_time, task->avg, 0, 0, false)) {
        update_load_avg(task->avg, task->load_weight);
    }
}

int FairScheduler::select_idle_executor(const std::shared_ptr<Task> &task, int prev, int target) {
    if (task->affinity.count(target)) {
        return target;
    }
    if (tm->get_executor(target)->is_idle() && task->affinity.count(target)) {
        return target;
    }
    if (prev != target && tm->get_executor(prev)->is_idle() && task->affinity.count(prev)) {
        return prev;
    }
    Executor *recent_executor = task->recent_executor;
    task->recent_executor = tm->get_executor(prev);
    int recent_cpu = recent_executor ? recent_executor->get_eid() : -1;
    if (recent_cpu != -1 &&
        recent_cpu != prev &&
        recent_cpu != target &&
        task->affinity.count(recent_cpu) &&
        recent_executor->is_idle()) {
        return recent_cpu;
    }
    int eid = select_idle_executor(task, target);
    if (eid != -1) {
        return eid;
    }
    return target;
}

int FairScheduler::select_idle_executor(const std::shared_ptr<Task> &task, int target) {
    int nr = INT_MAX;
    int res = -2;
    task->affinity.for_each_wrap(tm->get_num_executors(), target + 1, [&] (int e) {
        if (!--nr) {
            res = -1;
            return false;
        }
        if (tm->get_executor(e)->is_idle()) {
            res = e;
            return false;
        }
        return true;
    });
    if (res != -2) {
        return res;
    }
    
    return -1;
}

FairReadyQueue::FairReadyQueue(TaskManager *tm_, Executor *executor_)
    : ReadyQueue(tm_, executor_),
      features(StartDebit | BaseSlice | GentleFairSleepers | WakeupPreemption),
      nr_running(0), load_weight(0.0), min_vruntime(0), avg{},
      idle_balance(false), next_balance(5),
      removed{0, 0.0, 0.0} {

}

FairReadyQueue::~FairReadyQueue() {

}

void FairReadyQueue::dequeue_task(const std::shared_ptr<Task> &task, int flags) {
    int action = 0;

    if (!(flags & DequeueNoClock)) {
        update_clock();
    }
    update_curr();
    update_load_avg(task, action);
    clear_buddies(task);
    if (task != curr) {
        tasks_timeline.erase(task.get());
    }
    task->on_rq = false;

    account_dequeue(task);

    if (!(flags & DequeueSleep)) {
        task->vruntime -= min_vruntime;
    }

    if ((flags & (DequeueSave | DequeueMove)) != DequeueSave) {
        update_min_vruntime();
    }
    DEBUG_SCHED(printf("dequeue_task rq %d task %d flags %x vruntime %ld min_vruntime %ld\n",
                       executor->get_eid(), task->tid, flags, task->vruntime, min_vruntime));
    CHECK_VRUNTIME(task);
}

void FairReadyQueue::enqueue_task(const std::shared_ptr<Task> &task, int flags) {
    if (!(flags & EnqueueNoClock)) {
        update_clock();
    }
    if (task->on_rq) {
        return;
    }
    bool renorm = !(flags & EnqueueWakeup) || (flags & EnqueueMigrated);
    bool is_curr = curr == task;

    if (renorm && is_curr) {
        task->vruntime += min_vruntime;
        //DEBUG_SCHED(printf("renorm is_curr rq %d task %d vruntime %ld min_vruntime %ld\n",
        //                   executor->get_eid(), task->tid, task->vruntime, min_vruntime));
    }

    update_curr();

    if (renorm && !is_curr) {
        task->vruntime += min_vruntime;
        //DEBUG_SCHED(printf("renorm !is_curr rq %d task %d vruntime %ld %f min_vruntime %ld %f\n",
        //                   executor->get_eid(), task->tid, task->vruntime, task->vruntime / 1000000000.0, min_vruntime, min_vruntime / 1000000000.0));
    }

    update_load_avg(task, DoAttach);
    account_enqueue(task);
    if (flags & EnqueueWakeup) {
        place_task(task, false);
    }
    if (!is_curr) {
        tasks_timeline.emplace(task.get(), task);
    }
    task->on_rq = true;
    DEBUG_SCHED(printf("enqueue_task rq %d task %d flags %x vruntime %ld min_vruntime %ld\n",
                       executor->get_eid(), task->tid, flags, task->vruntime, min_vruntime));
    CHECK_VRUNTIME(task);
}

std::shared_ptr<Task> FairReadyQueue::pick_next_task(std::shared_ptr<Task> &prev) {
    std::shared_ptr<Task> task;
    if (prev) {
        put_prev_task(prev);
    }
again:
    if (nr_running == 0) {
        goto idle;
    }
    task = pick_next_task_internal(nullptr);
    DEBUG_SCHED(printf("pick_next_task rq %d prev %d task %d vruntime %ld min_vruntime %ld\n", executor->get_eid(),
                       prev ? prev->tid : -1, task ? task->tid : -1, task ? task->vruntime : -1, min_vruntime));
    return task;
idle:
    int new_tasks = newidle_balance();
    if (new_tasks > 0) {
        goto again;
    }
    update_clock();
    set_idle();
    return nullptr;
}

std::shared_ptr<Task> FairReadyQueue::pick_next_task_internal(std::shared_ptr<Task> curr_) {
    std::shared_ptr<Task> left, task, second;
    left = pick_first();
    if (!left || (curr_ && entity_before(curr_, left))) {
        left = curr;
    }

    task = left;

    if (skip && skip == task) {
        if (task == curr_) {
            second = pick_first();
        } else {
            second = pick_next(task);
            if (!second || (curr_ && entity_before(curr_, second))) {
                second = curr_;
            }
        }
        if (second && wakeup_preempt_entity(second, left) < 1) {
            task = second;
        }
    }

    if (next && wakeup_preempt_entity(next, left) < 1) {
        task = next;
    } else if (last && wakeup_preempt_entity(last, left) < 1) {
        task = last;
    }
    return task;
}

void FairReadyQueue::put_prev_task(std::shared_ptr<Task> &prev) {
    if (prev->on_rq) {
        update_curr();
    }
    if (prev->on_rq) {
        tasks_timeline.emplace(prev.get(), prev);
        update_load_avg(prev, 0);
    }
    curr.reset();
}

void FairReadyQueue::set_next_task(const std::shared_ptr<Task> &task, bool first) {
    assert(!(curr && !curr->on_rq));
    if (!task) {
        curr.reset();
        return;
    }
    clear_buddies(task);
    if (task->on_rq) {
        tasks_timeline.erase(task.get());
        update_load_avg(task, 0);
    }
    DEBUG_SCHED(printf("set_next_task: rq %d task %d exec_start %f\n", executor->get_eid(), task->tid, task->exec_start / 1000000000.0));
    task->exec_start = now;
    curr = task;
    task->prev_sum_exec_runtime = task->sum_exec_runtime;
}

void FairReadyQueue::migrate_task_rq(const std::shared_ptr<Task> &task) {
    if (task->state == Task::Waking) {
        task->vruntime -= min_vruntime;
        //CHECK_VRUNTIME(task);
    }
    remove_task_load_avg(task);
    task->avg.last_update_time = 0;
    task->exec_start = 0;
    DEBUG_SCHED(printf("migrate_task_rq rq %d task %d vruntime %ld min_vruntime %ld\n",
                       executor->get_eid(), task ? task->tid : -1, task ? task->vruntime : -1, min_vruntime));
}

void FairReadyQueue::task_tick() {
    if (curr) {
        update_curr();
        update_load_avg(curr, 0);
    }
    //printf("%d %f %f\n", executor->get_eid(), avg.load_avg, load_weight);
}

void FairReadyQueue::check_preempt_curr(const std::shared_ptr<Task> &task, int flags) {
    int scale = false;
    bool next_buddy_marked;
    //if (Executor::get_current_executor() == executor) {
    //    goto nopreempt;
    //}
    if (is_idle()) {
        if (Executor::get_current_executor() == executor) {
            goto nopreempt;
        }
        goto preempt;
    }
    if (curr == task || !curr) {
        goto nopreempt;
    }
    scale = nr_running >= SchedNRLatency;
    next_buddy_marked = false;
    if (has_feature(NextBuddy) && scale && !(flags & WaitQueue::WakeFork)) {
        next = task;
        next_buddy_marked = true;
    }
    if (curr->need_resched()) {
        goto nopreempt;
    }
    if (!has_feature(WakeupPreemption)) {
        goto nopreempt;
    }
    update_curr();
    if (wakeup_preempt_entity(curr, task) == 1) {
        if (!next_buddy_marked) {
            next = task;
        }
        goto preempt;
    }
    goto nopreempt;
preempt:
    resched_curr();
    if (!task->on_rq || !curr) {
        return;
    }
    if (has_feature(LastBuddy) && scale) {
        last = curr;
    }
    return;
nopreempt:
    return;
}

void FairReadyQueue::task_fork(const std::shared_ptr<Task> &task) {
    std::lock_guard lock(mutex);
    update_clock();
    if (curr) {
        update_curr();
        task->vruntime = curr->vruntime;
    }
    place_task(task, true);
    task->vruntime -= min_vruntime;
}

void FairReadyQueue::task_dead(const std::shared_ptr<Task> &task) {
    remove_task_load_avg(task);
}

void FairReadyQueue::resched_curr() {
    if (is_idle()) {
        if (Executor::get_current_executor() != executor) {
            executor->send_reschedule();
        }
        return;
    }
    if (curr && curr->need_resched()) {
        return;
    }
    if (Executor::get_current_executor() == executor) {
        if (curr) {
            curr->set_need_resched();
        }
        return;
    }
    executor->send_reschedule();
}

void FairReadyQueue::yield_task() {
    if (nr_running == 1 || !curr) {
        return;
    }
    clear_buddies(curr);
    update_clock();
    update_curr();
    skip = curr;
}

void FairReadyQueue::place_task(const std::shared_ptr<Task> task, bool initial) {
    uint64_t vruntime = min_vruntime;
    if (initial && has_feature(StartDebit)) {
        vruntime += sched_vslice(task);
    }
    if (!initial) {
        unsigned long thresh = SchedLatency;
        if (has_feature(GentleFairSleepers)) {
            thresh >>= 1;
        }
        vruntime -= thresh;
    }
    task->vruntime = ::max_vruntime(task->vruntime, vruntime);
    DEBUG_SCHED(printf("place_task: rq %d task %d initla %d vruntime %ld min_vruntime %ld\n",
                       executor->get_eid(), task->tid, initial, task->vruntime, min_vruntime));
    CHECK_VRUNTIME(task);
}

uint64_t FairReadyQueue::sched_slice(const std::shared_ptr<Task> task) {
    unsigned int nrr = nr_running;
    uint64_t slice = sched_period(nrr + !task->on_rq);
    double lw = load_weight;

    if (!task->on_rq) {
        lw += task->load_weight;
    }
    slice = slice * task->load_weight / lw;

    if (has_feature(BaseSlice)) {
        uint64_t min_gran = SchedMinGranularity;
        slice = std::max(slice, min_gran);
    }
    return slice;
}

uint64_t FairReadyQueue::sched_vslice(const std::shared_ptr<Task> task) {
    return calc_delta_fair(sched_slice(task), task);
}

void FairReadyQueue::clear_buddies(const std::shared_ptr<Task> &task) {
    if (last == task) {
        last.reset();
    }
    if (next == task) {
        next.reset();
    }
    if (skip == task) {
        skip.reset();
    }
}

void FairReadyQueue::account_enqueue(const std::shared_ptr<Task> task) {
    load_weight += task->load_weight;
    ++nr_running;
}

void FairReadyQueue::account_dequeue(const std::shared_ptr<Task> task) {
    load_weight -= task->load_weight;
    --nr_running;
}

inline std::shared_ptr<Task> FairReadyQueue::pick_first() {
    auto it = tasks_timeline.begin();
    if (it == tasks_timeline.end()) {
        return nullptr;
    }
    return it->second;
}

inline std::shared_ptr<Task> FairReadyQueue::pick_next(const std::shared_ptr<Task> &task) {
    auto it = tasks_timeline.find(task.get());
    if (it == tasks_timeline.end()) {
        return nullptr;
    }
    it = std::next(it);
    if (it == tasks_timeline.end()) {
        return nullptr;
    }
    return it->second;
}

void FairReadyQueue::update_curr() {
    if (!curr) {
        return;
    }

    uint64_t delta_exec = now - curr->exec_start;

    if ((int64_t)delta_exec <= 0) {
        return;
    }

    curr->exec_start = now;
    curr->sum_exec_runtime += delta_exec;

    curr->vruntime += calc_delta_fair(delta_exec, curr);
    //printf("delta_exec: %d %f\n", curr->tid, delta_exec / 1000000000.0);
    //if (delta_exec > 100000000000) {
    //    printf("invalid delta %d %d\n", executor->get_eid(), curr->tid);
    //    fflush(stdout);
    //    abort();
    //    volatile int loop = 1;
    //    while(loop);
    //}
    //if (executor->get_eid() == 0) {
    //    printf("delta_exec: %f\n", delta_exec / 1000000000.0);
    //}
    CHECK_VRUNTIME(curr);
    update_min_vruntime();
}

inline void FairReadyQueue::update_min_vruntime() {
    auto leftmost = tasks_timeline.begin();
    uint64_t vruntime = min_vruntime;
    Task *curr_ = curr.get();
    if (curr_) {
        if (curr_->on_rq) {
            vruntime = curr->vruntime;
        } else {
            curr_ = nullptr;
        }
    }
    if (leftmost != tasks_timeline.end()) {
        Task *task = leftmost->first;
        if (!curr_) {
            vruntime = task->vruntime;
        } else {
            vruntime = ::min_vruntime(vruntime, task->vruntime);
        }
    }
    min_vruntime = ::max_vruntime(min_vruntime, vruntime);
    DEBUG_SCHED(printf("update_min_vruntime rq %d min_vruntime %lu\n", executor->get_eid(), min_vruntime););
}

void FairReadyQueue::update_load_avg(const std::shared_ptr<Task> &task, int flags) {
    if (task && task->avg.last_update_time && !(flags & SkipAgeLoad)) {
        update_load_avg_task(task);
    }
    bool decayed = update_load_avg();
    if (task && !task->avg.last_update_time && (flags & DoAttach)) {
        
    } else if (flags & DoDetach) {

    }
}

bool FairReadyQueue::update_load_avg_task(const std::shared_ptr<Task> &task) {
    if (update_load_sum(now, task->avg, task->on_rq != 0, task->on_rq != 0, curr == task)) {
        ::update_load_avg(task->avg, task->load_weight);
        return true;
    }
    return false;
}

bool FairReadyQueue::update_load_avg() {
    bool decayed = false;
    if (removed.nr) {
        double divider = (LoadAvgMax - 1) + avg.period_contrib;
        double removed_load, removed_runnable;
        {
            std::lock_guard lock(removed.mutex);
            removed_load = removed.load_avg;
            removed_runnable = removed.runnable_avg;
            removed.load_avg = 0;
            removed.runnable_avg = 0;
            removed.nr = 0;
        }
        double r = removed_load;
        sub_positive(avg.load_avg, r);
        sub_positive(avg.load_sum, r * divider);
        avg.load_sum = std::max(avg.load_sum, avg.load_avg * (LoadAvgMax - 1));
        r = removed_runnable;
        sub_positive(avg.runnable_avg, r);
        sub_positive(avg.runnable_sum, r * divider);
        avg.runnable_sum = std::max(avg.runnable_sum, avg.runnable_avg * (LoadAvgMax - 1));
        decayed = true;
    }
    if (update_load_sum(now, avg, load_weight, nr_running, curr != nullptr)) {
        ::update_load_avg(avg, 1);
        decayed = true;
    }
    return decayed;
}

int FairReadyQueue::get_num_tasks() {
    return nr_running;
}

void FairReadyQueue::trigger_load_balance() {
    if (tm->get_num_executors() == 1) {
        return;
    }
    idle_balance = is_idle();
    if (tm->jiffies > next_balance) {
        rebalance(idle_balance ? Idle : NotIdle);
        next_balance = tm->jiffies + 5;
    }
}

uint64_t FairReadyQueue::get_last_idle_stamp() {
    return idle_stamp;
}

std::shared_ptr<Task> &FairReadyQueue::get_curr() {
    return curr;
}

bool FairReadyQueue::is_idle() {
    if (!executor->is_idle()) {
        return false;
    }
    //if (nr_running) {
    //    return false;
    //}
    return true;
}

void FairReadyQueue::set_idle() {
    idle_stamp = now;
}

void FairReadyQueue::rebalance(IdleType idle) {
    bool continue_balancing;
    load_balance(idle, continue_balancing);
}

struct FairReadyQueue::LBEnv {
    enum {
        AllPinned = 0x1,
        NeedBreak = 0x2,
        DstPinned = 0x4,
        SomePinned = 0x8,
        ActiveLB = 0x10,
    };
    int flags;
    int dst_cpu;
    FairReadyQueue *dst_rq;
    int src_cpu;
    FairReadyQueue *src_rq;
    IdleType idle;
    MigrationType migration_type;
    double imbalance;
    int new_dst_cpu;

    int loop;
    int loop_break;
    int loop_max;

    CPUSet cpus;
    std::vector<std::shared_ptr<Task>> tasks;
};

int FairReadyQueue::load_balance(IdleType idle, bool &continue_balancing) {
    int ld_moved = 0, cur_ld_moved;
    CPUSet cpus = tm->get_full_affinity();
    LBEnv env;
    FairReadyQueue *busiest;
    env.flags = 0;
    env.dst_cpu = executor->get_eid();
    env.dst_rq = this;
    env.src_cpu = 0;
    env.src_rq = nullptr;
    env.idle = idle;
    env.migration_type = MigrateLoad;
    env.imbalance = 0;
    env.loop = 0;
    env.loop_break = SchedNRMigrateBreak;
    env.cpus = cpus;

redo:
    if (!should_we_balance(env)) {
        continue_balancing = false;
        goto out_balanced;
    }
    //printf("should balance\n");

    busiest = find_busiest_queue(env);
    //printf("busiest: %p\n", busiest);
    if (!busiest) {
        goto out_balanced;
    }
    env.src_cpu = busiest->executor->get_eid();
    env.src_rq = busiest;
    ld_moved = 0;
    env.flags |= LBEnv::AllPinned;
    if (busiest->nr_running > 1) {
        env.loop_max = std::min(SchedNRMigrate, busiest->nr_running);
more_balance:
        {
            std::lock_guard lock(busiest->mutex);
            busiest->update_clock();
            cur_ld_moved = detach_tasks(env);
        }
        if (cur_ld_moved) {
            attach_tasks(env);
            ld_moved += cur_ld_moved;
        }
        if (env.flags & LBEnv::NeedBreak) {
            env.flags &= ~LBEnv::NeedBreak;
            if ((unsigned int)env.loop < busiest->nr_running) {
                goto more_balance;
            }
        }
        if ((env.flags & LBEnv::DstPinned) && env.imbalance > 0) {
            env.cpus.erase(env.dst_cpu);
            env.dst_rq = (FairReadyQueue *)&(tm->get_executor(env.new_dst_cpu)->get_rq());
            env.dst_cpu = env.new_dst_cpu;
            env.flags &= ~LBEnv::DstPinned;
            env.loop = 0;
            env.loop_break = SchedNRMigrateBreak;
            goto more_balance;
        }
        if (env.flags & LBEnv::AllPinned) {
            goto out_all_pinned;
        }
    }
    goto out;
out_balanced:
out_all_pinned:
out_one_pinned:
    if (env.idle == NewlyIdle) {
        goto out;
    }
out:
    if (ld_moved) {
        //printf("ld_moved: %d\n", ld_moved);
    }
    return ld_moved;
}

bool FairReadyQueue::should_we_balance(const LBEnv &env) {
    if (env.idle == NewlyIdle) {
        if (env.dst_rq->nr_running > 0) {
            return false;
        }
        return true;
    }
    bool return_func = false;
    bool found_idle_cpu;
    env.cpus.for_each(tm->get_num_executors(), [&] (int e) {
        FairReadyQueue &rq = (FairReadyQueue &)tm->get_executor(e)->get_rq();
        if (!rq.is_idle()) {
            return true;
        }
        return_func = true;
        found_idle_cpu = e == env.dst_cpu;
        return false;
    });
    if (return_func) {
        return found_idle_cpu;
    }
    return env.dst_cpu == 0;
}

FairReadyQueue *FairReadyQueue::find_busiest_queue(LBEnv &env) {
    FairReadyQueue *busiest = NULL;
    double busiest_load = 0;
    unsigned int busiest_nr = 0;
    env.migration_type = MigrateLoad;
    double sum_load = 0;
    int ncpus = 0;
    env.cpus.for_each(tm->get_num_executors(), [&] (int e) {
        ++ncpus;
        FairReadyQueue &rq = (FairReadyQueue &)tm->get_executor(e)->get_rq();
        int nr_running = rq.nr_running;
        if (!nr_running) {
            return true;
        }
        double load;
        switch (env.migration_type) {
        case MigrateLoad:
            load = rq.avg.load_avg;
            sum_load += load;
            if (nr_running == 1 && load > env.imbalance) {
                break;
            }
            if (load > busiest_load) {
                busiest_load = load;
                busiest = &rq;
            }
            break;
        case MigrateTask:
            if (busiest_nr < nr_running) {
                busiest_nr = (unsigned int)nr_running;
                busiest = &rq;
            }
            break;
        }
        return true;
    });
    double avg_load = sum_load / ncpus;
    double imbalance = busiest_load - avg_load;
    //double imbalance = std::min(busiest_load - avg_load, avg_load - env.dst_rq->avg.load_avg);
    if (imbalance <= 0) {
        env.imbalance = 0;
        return nullptr;
    }
    env.imbalance = imbalance;
    return busiest;
}

int FairReadyQueue::detach_tasks(LBEnv &env) {
    std::shared_ptr<Task> p;
    double load;
    int detached = 0;

    if (env.src_rq->nr_running <= 1) {
        env.flags &= ~LBEnv::AllPinned;
        return 0;
    }
    if (env.imbalance <= 0) {
        return 0;
    }
    while (!env.src_rq->tasks_timeline.empty()) {
        if (env.idle != NotIdle && env.src_rq->nr_running <= 1) {
            break;
        }
        ++env.loop;
        if (env.loop > env.loop_max && !(env.flags & LBEnv::AllPinned)) {
            break;
        }
        if (env.loop > env.loop_break) {
            env.loop_break += SchedNRMigrateBreak;
            env.flags |= LBEnv::NeedBreak;
            break;
        }
        p = env.src_rq->tasks_timeline.rbegin()->second;
        if (!can_migrate_task(p, env)) {
            continue;
        }
        switch (env.migration_type) {
        case MigrateLoad:
            load = std::max(p->avg.load_avg, 1.0);
            env.imbalance -= load;
            break;
        case MigrateTask:
            --env.imbalance;
            break;
        }
        env.src_rq->deactivate_task(p, DequeueNoClock);
        env.src_rq->migrate_task_rq(p);
        p->executor = tm->get_executor(env.dst_cpu);
        env.tasks.push_back(p);
        ++detached;
        if (env.imbalance <= 0) {
            break;
        }
        continue;
    }
    return detached;
}

bool FairReadyQueue::can_migrate_task(const std::shared_ptr<Task> &p, LBEnv &env) {
    if (!p->affinity.count(env.dst_cpu)) {
        env.flags |= LBEnv::SomePinned;
        if (env.idle == NewlyIdle || (env.flags & (LBEnv::DstPinned | LBEnv::ActiveLB))) {
            return false;
        }
        env.cpus.for_each(tm->get_num_executors(), [&] (int cpu) {
            if (p->affinity.count(cpu)) {
                env.flags |= LBEnv::DstPinned;
                env.new_dst_cpu = cpu;
                return false;
            }
            return true;
        });
        return false;
    }
    env.flags &= ~LBEnv::AllPinned;
    if (env.src_rq->curr == p) {
        return false;
    }
    if (env.flags & LBEnv::ActiveLB) {
        return true;
    }
    //TODO: hot task
    return true;
}

void FairReadyQueue::attach_tasks(LBEnv &env) {
    {
        std::lock_guard lock(env.dst_rq->mutex);
        env.dst_rq->update_clock();
        for (auto &&task : env.tasks) {
            env.dst_rq->activate_task(task, EnqueueNoClock);
            env.dst_rq->check_preempt_curr(task, 0);
        }
    }
    env.tasks.clear();
}

int FairReadyQueue::newidle_balance() {
    /*
    FairReadyQueue *src = nullptr;
    tm->get_full_affinity().for_each_wrap(tm->get_num_executors(), executor->get_eid(), [&] (int e) {
        FairReadyQueue &rq = (FairReadyQueue &)(tm->get_executor(e)->get_rq());
        if (rq.nr_running > 1) {
            src = &rq;
            return false;
        }
        return true;
    });
    if (!src) {
        return 0;
    }
    mutex.unlock();
    int n = 0;
    std::shared_ptr<Task> p;
    {
        std::lock_guard lock(src->mutex);
        if (src->tasks_timeline.empty()) {
            goto out;
        }
        p = src->tasks_timeline.rbegin()->second;
        src->deactivate_task(p, DequeueNoClock);
        src->migrate_task_rq(p);
        p->executor = executor;
        n = 1;
    }
out:
    mutex.lock();
    if (p) {
        update_clock();
        activate_task(p, EnqueueNoClock);
    }
    return n;
    */
    if (tm->get_num_executors() == 1) {
        return 0;
    }
    set_idle();
    mutex.unlock();
    bool continue_balancing;
    int n = load_balance(NewlyIdle, continue_balancing);
    mutex.lock();
    return n;
}

void FairReadyQueue::remove_task_load_avg(const std::shared_ptr<Task> &task) {
    FairScheduler::sync_task_load_avg(task);
    std::lock_guard lock(removed.mutex);
    ++removed.nr;
    removed.load_avg += task->avg.load_avg;
    removed.runnable_avg += task->avg.runnable_avg;
}
