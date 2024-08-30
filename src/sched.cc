#include <set>
#include <cstdio>
#include <ctime>
#include <csignal>
#include <climits>
#include <cstdlib>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <linux/time_types.h>
#include <poll.h>
#include <x86intrin.h>
#include <liburing.h>

#include "pegasus/cluster.h"
#include "pegasus/event.h"
#include "pegasus/exception.h"
#include "pegasus/fair.h"
#include "pegasus/ioworker.h"
#include "pegasus/monitor.h"
#include "pegasus/percpu.h"
#include "pegasus/runtime.h"
#include "pegasus/sched.h"
#include "pegasus/stat.h"
#include "pegasus/uswitch.h"
#include "pegasus/wait_queue.h"

using namespace pegasus;

static constexpr size_t StackSize = 128 * 1024;
static constexpr int TimerHertz = 100;

Task::Task(TaskManager *tm_) :
    stack(nullptr), stack_size(StackSize),
    state(Initializing),
    vruntime(0), exec_start(0), sum_exec_runtime(0), prev_sum_exec_runtime(0),
    load_weight(1.0), avg{}, on_rq(false),
    tm(tm_), executor(nullptr), wake_executor(nullptr), recent_executor(nullptr), flags(0) {
    void *s = tm->get_stack_allocator().allocate();
    if (!s) {
        throw std::bad_alloc();
    }
    stack = (uint8_t *)s;
}

Task::~Task() {
    tm->remove_task(tid);
    if (stack) {
        tm->get_stack_allocator().deallocate(stack);
    }
}

void Task::signal() {
    std::shared_ptr<WaitQueue> wq_;
    int s;
    {
        std::lock_guard lock(mutex);
        s = state;
        if (s == Interruptible) {
            wq_ = wq;
        }
    }
    size_t n = 0;
    if (s == Interruptible) {
        if (wq_) {
            n = wq_->wake(this, WaitResult(WaitResult::Interrupted | WaitResult::FromSignal, 0));
        }
    }
    if (n == 0) {
        std::lock_guard lock(mutex);
        if (executor && executor != Executor::get_current_executor()) {
            executor->send_reschedule();
        }
    }
}

void Task::set_need_resched() {
    //return;
    if (vthread) {
        vthread->set_work(VThread::WorkResched);
    }
}

void Task::clear_need_resched() {
    //return;
    if (vthread) {
        vthread->clear_work(VThread::WorkResched);
    }
}

bool Task::need_resched() {
    //return false;
    if (vthread) {
        return vthread->has_work(VThread::WorkResched);
    }
    return false;
}

ReadyQueue::ReadyQueue(TaskManager *tm_, Executor *executor_)
    : tm(tm_), executor(executor_) {

}

ReadyQueue::~ReadyQueue() {

}

void ReadyQueue::activate_task(const std::shared_ptr<Task> &task, int flags) {
    enqueue_task(task, flags);
    task->on_rq = true;
}

void ReadyQueue::deactivate_task(const std::shared_ptr<Task> &task, int flags) {
    task->on_rq = false;
    dequeue_task(task, flags);
}

Executor::Executor(TaskManager *tm_, int eid_, int core_)
    : tm(tm_), eq(tm_, monotonic_timer),
      tid(-1), eid(eid_), core(core_), eq_state(0) {
    rq = std::move(tm->get_scheduler()->create_rq(this));
}

void Executor::schedule(int flags) {
    //std::shared_ptr<Task> task = PER_CPU_PRIV_REF(current_task);
    //task->sys_time = time_nanosec() - task->last_sys_time;
    pegasus_executor_context_switch(&PER_CPU_PRIV_REF(current_task)->registers,
                                   PER_CPU_PRIV_PTR(executor_registers), flags);
    //task->last_sys_time = time_nanosec();
}

void Executor::cond_schedule() {
    if (PER_CPU_PRIV_REF(current_task)->need_resched()) {
        schedule();
        PER_CPU_PRIV_REF(current_task)->clear_need_resched();
    }
}

void Executor::yield() {
    schedule(0);
}

void Executor::block() {
    schedule(YieldSleep | YieldTaskLocked);
}

void Executor::migrate_to() {
    if (Executor::get_current_executor() == this) {
        return;
    }
    std::shared_ptr<Task> task = Executor::get_current_task();
    {
        std::lock_guard lock(task->mutex);
        task->state = Task::Waking;
        task->executor = this;
    }
    schedule(YieldMigrate);
}

void Executor::fail() {
    schedule(0);
}

void Executor::start() {
    thread.reset(new std::thread([this] {
        executor_routine();
    }));
}

void Executor::wait() {
    thread->join();
}

bool Executor::is_idle() {
    if (curr != idle_task) {
        return false;
    }
    //ClusterData *cluster_data = Runtime::get()->get_config().cluster_data;
    //if (cluster_data) {
    //    if (cluster_data->cpu_data[eid].active) {
    //        return false;
    //    }
    //}
    return true;
}

void Executor::send_reschedule(bool from_eq) {
    //if (curr == idle_task) {
    //    if (sleeping) {
    //        //uint64_t t1 = time_nanosec();
    //        //if (from_eq) {
    //        //    eq_interrupt_time = t1;
    //        //}
    //        get_eq().interrupt();
    //        //uint64_t t2 = time_nanosec();
    //        //Stat::get().add(1, t2 - t1);
    //        //++count;
    //        //if (t1 - last_time > 1000000000) {
    //        //    printf("Resched/sec: %lu\n", count * 1000000000 / (t1 - last_time));
    //        //    count = 0;
    //        //    last_time = t1;
    //        //}
    //        //tgkill(tm->get_pid(), tid, SIGURG);
    //    } else {
    //    }
    //} else if (tid != -1) {
    //    USwitchContext::run_current([this] {
    //        tgkill(tm->get_pid(), tid, SIGURG);
    //    });
    //}
    //if (tid != -1 && !(curr == idle_task && !sleeping)) {
    //    USwitchContext::run_current([this] {
    //        tgkill(tm->get_pid(), tid, SIGURG);
    //    });
    //}

    int state = eq_state.exchange(Interrupted);
    if (state == Sleeping) {
        get_eq().interrupt();
    } else if (state != Polling && tid != -1) {
        USwitchContext::run_current([this] {
            tgkill(tm->get_pid(), tid, SIGURG);
        });
    }
}

void Executor::add_tasklet(const Tasklet &tasklet) {
    std::lock_guard lock(rq->get_mutex());
    tasklets.push_back(tasklet);
}

void Executor::idle_routine() {
    int state;
    while (true) {
        if (rq->get_num_tasks()) {
            goto next;
        }
        state = eq_state.exchange(Sleeping);
        if (state == Interrupted) {
            eq_state.store(0, std::memory_order_release);
            goto next;
        }
        get_eq().sleep(cqe_buffer);
        eq_state.store(0, std::memory_order_release);
next:
        Executor::schedule(0);
    }
}

//void Executor::idle_routine() {
//    bool enable_poll = Runtime::get()->get_config().enable_poll;
//    //double poll_threshold = config.poll_threshold;
//    //bool enable_poll = false;
//    double poll_threshold = 0;
//    int state;
//    while (true) {
//        if (enable_poll && (!poll_threshold || rq->get_load_avg() >= poll_threshold)) {
//            //state = eq_state.exchange(Polling);
//            //if (state == Interrupted) {
//            //    eq_state.store(0, std::memory_order_release);
//            //    goto next;
//            //}
//            //while (true) {
//            //    get_eq().poll(cqe_buffer);
//            //    if (rq->get_num_tasks() || GET_PER_CPU_PRIV(alarmed)) {
//            //        eq_state.store(0, std::memory_order_release);
//            //        goto next;
//            //    }
//            //    state = Interrupted;
//            //    if (eq_state.compare_exchange_strong(state, 0)) {
//            //        goto next;
//            //    }
//            //}
//            goto next;
//        } else {
//            if (rq->get_num_tasks()) {
//                goto next;
//            }
//            //eq_interrupt_time = -1ull;
//            state = eq_state.exchange(Sleeping);
//            if (state == Interrupted) {
//                eq_state.store(0, std::memory_order_release);
//                goto next;
//            }
//            get_eq().sleep(cqe_buffer);
//            eq_state.store(0, std::memory_order_release);
//            //if (eq_interrupt_time != -1ull) {
//            //    Stat::get().add(0, time_nanosec() - eq_interrupt_time);
//            //}
//        }
//next:
//        Executor::schedule(0);
//    }
//}

void Executor::executor_routine() {
    // must set affinity before initializing DPDK
    tid = gettid();
    if (core != -1) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(core, &set);
        int res = pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
        if (res) {
            throw SystemException(res);
        }
    }
    init_cpu();
    SET_PER_CPU_PRIV(current_executor, this);
    SET_PER_CPU_PRIV(current_eid, eid);
    //ClusterData *cluster_data = Runtime::get()->get_config().cluster_data;
    //bool cluster_sched = Runtime::get()->get_config().cluster_sched;
    //if (cluster_data && cluster_sched) {
    //    SET_PER_CPU_PRIV(cluster_cpu_data, &cluster_data->cpu_data[eid]);
    //}

    timer_t timerid;
    struct sigevent sevp;
    sevp.sigev_notify = SIGEV_THREAD_ID;
    sevp.sigev_signo = SIGALRM;
    sevp._sigev_un._tid = tid;
    if (timer_create(CLOCK_MONOTONIC, &sevp, &timerid) != 0) {
        throw SystemException(errno);
    }
    struct itimerspec its;
    its.it_value.tv_sec = 0;
    its.it_value.tv_nsec = 1000000000 / TimerHertz;
    its.it_interval.tv_sec = its.it_value.tv_sec;
    its.it_interval.tv_nsec = its.it_value.tv_nsec;
    if (timer_settime(timerid, 0, &its, nullptr) != 0)  {
        throw SystemException(errno);
    }

    //sevp.sigev_notify = SIGEV_THREAD_ID;
    //sevp.sigev_signo = SIGURG;
    //sevp._sigev_un._tid = tid;
    //if (timer_create(CLOCK_MONOTONIC, &sevp, &timerid) != 0) {
    //    throw SystemException(errno);
    //}
    //monotonic_timer = timerid;

    idle_task = tm->create_task([this] {
        idle_routine();
    }, false);
    idle_task->state = Task::Running;
    idle_task->on_rq = true;
    idle_task->executor = this;
    tm->wait_barrier();
    //ClusterCPUData *cluster_cpu_data = GET_PER_CPU_PRIV(cluster_cpu_data);
    std::shared_ptr<Task> migrate_task;

    int flags = 0;
    bool enable_poll = Runtime::get()->get_config().enable_poll;
    bool polling = false;
    std::vector<Tasklet> tasklets_;
    try {
        while (true) {
            if (tm->stopped) {
                break;
            }

            bool tick = GET_PER_CPU_PRIV(alarmed);
            if (tick) {
                SET_PER_CPU_PRIV(alarmed, 0);
                if (eid == 0) {
                    ++tm->jiffies;
                }
            }

            //if (!polling) {
            //    eq_state.store(Scheduling, std::memory_order_release);
            //}

            if (tick) {
                rq->trigger_load_balance();
            }
            {
                std::unique_lock lock(rq->get_mutex());
                if (flags & (YieldSleep | YieldDying | YieldMigrate)) {
                    rq->dequeue_task(curr, ReadyQueue::DequeueSleep | ReadyQueue::DequeueNoClock);
                }
                if (flags & YieldDying) {
                    rq->task_dead(curr);
                }
                if (flags & YieldTaskLocked) {
                    curr->mutex.unlock();
                }
                if (flags & YieldMigrate) {
                    migrate_task = curr;
                    rq->migrate_task_rq(migrate_task);
                }

                rq->update_clock();
                std::shared_ptr<Task> prev = rq->get_curr();
                std::shared_ptr<Task> next = rq->pick_next_task(prev);
                rq->set_next_task(next);
                if (!next) {
                    if (enable_poll && !polling) {
                        int state = eq_state.exchange(Polling);
                        if (state == Interrupted) {
                            eq_state.store(0, std::memory_order_release);
                        }
                        polling = true;
                    }
                    curr = idle_task;
                } else {
                    if (enable_poll && polling) {
                        eq_state.store(0, std::memory_order_release);
                        polling = false;
                    }
                    curr = rq->get_curr();
                }
                if (tick) {
                    rq->task_tick();
                }
                std::swap(tasklets_, tasklets);
            }

            if (flags & YieldMigrate) {
                ReadyQueue &rq = migrate_task->executor->get_rq();
                {
                    std::lock_guard lock(rq.get_mutex());
                    rq.update_clock();
                    rq.activate_task(migrate_task, ReadyQueue::EnqueueWakeup |
                                                   ReadyQueue::EnqueueNoClock |
                                                   ReadyQueue::EnqueueMigrated);
                    rq.check_preempt_curr(migrate_task, WaitQueue::WakeWQ | WaitQueue::WakeMigrated);
                    migrate_task->state = Task::Running;
                }
            }

            get_eq().poll(cqe_buffer);

            if (curr->vthread && curr->vthread->check_stop(curr)) {
                flags = YieldSleep | YieldTaskLocked;
                continue;
            }

            if (tasklets_.size()) {
                for (Tasklet &tasklet : tasklets_) {
                    tasklet();
                }
                tasklets_.clear();
            }
            GET_PER_CPU_PRIV(cwm)->check();

            //if (cluster_cpu_data && curr != idle_task) {
            //    ++cluster_cpu_data->active;
            //}
            if (polling) {
                flags = 0;
            } else {
                //int state = eq_state.exchange(0);
                //if (state == Interrupted && curr == idle_task) {
                //    flags = 0;
                //    continue;
                //}
                flags = run_task(curr);
            }
            //if (cluster_cpu_data && curr != idle_task) {
            //    --cluster_cpu_data->active;
            //}
        }
    } catch (ExecutorException &e) {
        printf("executor exception: %s\n", e.what());
    }

    timer_delete(timerid);
    printf("uswitch count %d: %d\n", eid, USwitchContext::get()->switch_count);
    tm->wait_barrier();
}

inline bool Executor::handle_timer() {
    return false;
}

void Executor::task_routine() {
    std::shared_ptr<Task> current = PER_CPU_PRIV_REF(current_task);
    current->routine();
    current->mutex.lock();
    current->state = Task::Stopped;
    current.reset();
    CompactCPUState regs;
    pegasus_executor_context_switch(&regs, PER_CPU_PRIV_PTR(executor_registers),
                                   YieldDying | YieldTaskLocked);
}

inline int Executor::run_task(const std::shared_ptr<Task> &task) {
    PER_CPU_PRIV_REF(current_task) = task;
    long res = pegasus_executor_context_switch(PER_CPU_PRIV_PTR(executor_registers),
                                              &PER_CPU_PRIV_REF(current_task)->registers);
    PER_CPU_PRIV_REF(current_task) = nullptr;
    return res;
}

TaskManager::TaskManager(size_t num_threads, bool has_ioworker,
                         bool pin, const std::vector<int> &cores)
    : max_tid(1),
      stack_allocator(StackSize, 256),
      stopped(false), jiffies(0) {
    scheduler.reset(new FairScheduler(this));
    for (size_t i = 0; i < num_threads; ++i) {
        int core = -1;
        if (pin) {
            if (cores.size() > i) {
                core = cores[i];
            } else {
                core = i;
            }
        }
        executors.push_back(std::make_unique<Executor>(this, i, core));
        full_affinity.insert(i);
    }
    if (has_ioworker) {
        ioworker.reset(new IOWorker(this, num_threads < cores.size() ? cores[num_threads] : -1));
        ioworker->init_global(Runtime::get()->get_config().ioworker_config);
    }
    //if (allow_fork) {
    //    cm.reset(new ChildProcessManager(this));
    //}
    pid = getpid();
    int barrier_size = executors.size();// + 1;
    //if (cm) {
    //    ++barrier_size;
    //}
    if (ioworker) {
        ++barrier_size;
    }
    pthread_barrier_init(&barrier, nullptr, barrier_size);
}

TaskManager::~TaskManager() {
    pthread_barrier_destroy(&barrier);
}

void TaskManager::run() {
    //if (cm) {
    //    cm->start();
    //}
    for (auto &&e : executors) {
        e->start();
    }
    if (ioworker) {
        ioworker->start();
    }
    //eq_poller->start();
    for (auto &&e : executors) {
        e->wait();
    }
    //eq_poller->wait();
    //if (cm) {
    //    cm->join();
    //}
    if (ioworker) {
        ioworker->wait();
    }
}

int TaskManager::find_unused_tid() {
    if (max_tid == INT_MAX) {
        return -1;
    }
    return max_tid++;
}

std::shared_ptr<Task> TaskManager::create_task(const std::function<void (void)> &routine, 
                                                            bool alloc_tid) {
    std::shared_ptr<Task> task = std::make_shared<Task>(this);
    task->routine = routine;
    uintptr_t rsp = (uintptr_t)task->stack + task->stack_size;
    rsp = (rsp & ~0xfl) - 8;
    task->registers.rsp = rsp;
    task->registers.rip = (uintptr_t)Executor::task_routine;
    int t = 0;
    if (alloc_tid) {
        std::lock_guard lock(mutex);
        t = find_unused_tid();
        if (t == -1) {
            return nullptr;
        }
        tid_task_map[t] = task;
    }
    task->tid = t;
    task->affinity = get_full_affinity();
    return task;
}

void TaskManager::wake_up_new_task(const std::shared_ptr<Task> &task) {
    int eid;
    if (Executor::get_current_executor()) {
        eid = Executor::get_current_executor()->get_eid();
    } else {
        eid = 0;
    }
    Executor *executor = scheduler->select_task_rq(task, eid, WaitQueue::WakeFork);
    ReadyQueue &rq = executor->get_rq();
    task->state = Task::Running;
    task->executor = executor;
    {
        std::lock_guard lock(rq.get_mutex());
        rq.update_clock();
        rq.activate_task(task, ReadyQueue::EnqueueNew | ReadyQueue::EnqueueNoClock);
        rq.check_preempt_curr(task, WaitQueue::WakeFork);
    }
}

std::shared_ptr<Task> TaskManager::get_task(int tid) {
    std::shared_ptr<Task> task;
    {
        std::lock_guard lock(mutex);
        auto it = tid_task_map.find(tid);
        if (it == tid_task_map.end()) {
            return nullptr;
        }
        task = it->second.lock();
    }
    if (!task) {
        return nullptr;
    }
    std::lock_guard lock(task->mutex);
    if (task->state == Task::Initializing || task->state == Task::Stopped) {
        return nullptr;
    }
    return task;
}

void TaskManager::add_task(int tid, const std::shared_ptr<Task> &task) {
    std::lock_guard lock(mutex);
    task->tid = tid;
    tid_task_map[tid] = task;
}

void TaskManager::remove_task(int tid) {
    std::lock_guard lock(mutex);
    tid_task_map.erase(tid);
}

void TaskManager::broadcast_signal(int sig) {
    std::lock_guard lock(mutex);
    for (auto &&e : executors) {
        tgkill(pid, e->tid, sig);
    }
    //if (cm) {
    //    tgkill(pid, cm->tid, sig);
    //}
}

void TaskManager::wait_barrier() {
    pthread_barrier_wait(&barrier);
}

void TaskManager::add_tasklet(const Tasklet &tasklet) {
    Executor *executor = Executor::get_current_executor();
    if (!executor) {
        executor = get_executor(0);
    }
    executor->add_tasklet(tasklet);
}

void CleanupWorkManager::add(const Tasklet &tasklet) {
    tasklets.push_back(tasklet);
    PER_CPU_PRIV_REF(work) |= PerCPUPrivateData::WorkCleanup;
}

void CleanupWorkManager::check() {
    if (tasklets.empty()) {
        return;
    }
    for (auto &t : tasklets) {
        if (t) {
            t();
        }
    }
    tasklets.clear();
    PER_CPU_PRIV_REF(work) &= ~PerCPUPrivateData::WorkCleanup;
}
