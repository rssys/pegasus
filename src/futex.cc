#include <unordered_map>
#include <linux/futex.h>
#include <linux/time_types.h>
#include "pegasus/event.h"
#include "pegasus/exception.h"
#include "pegasus/futex.h"
#include "pegasus/mm.h"
#include "pegasus/monitor.h"
#include "pegasus/sched.h"
#include "pegasus/stat.h"
#include "pegasus/wait_queue.h"

using namespace pegasus;

FutexContext::FutexContext() {

}

FutexContext::~FutexContext() {

}

struct FutexWaitRestartFunction {
    uint32_t *uaddr;
    uint32_t val;
    struct __kernel_timespec timeout;
    int timeout_flags;
    uint32_t mask;
    long operator()(VThread *vthread) {
        FutexContext *fc = vthread->get_vprocess()->get_futex_context();
        return fc->wait(vthread, uaddr, val, &timeout, timeout_flags, mask);
    }
};

int FutexContext::wait(VThread *vthread, uint32_t *uaddr, uint32_t val,
                       const struct __kernel_timespec *timeout, int timeout_flags, uint32_t mask) {
    //uint64_t t1 = time_nanosec();
    if ((uintptr_t)uaddr % sizeof(uint32_t) != 0) {
        return -EINVAL;
    }
    MM *mm = vthread->get_vprocess()->get_mm();
    EventQueue &eq = Executor::get_current_executor()->get_eq();
    std::shared_ptr<Task> task = Executor::get_current_task();

    bool is_absolute_timeout = timeout_flags & IORING_TIMEOUT_ABS;
    struct __kernel_timespec end;
    if (timeout) {
        if (is_absolute_timeout) {
            end = *timeout;
        } else {
            struct timespec now;
            clock_gettime((timeout_flags & IORING_TIMEOUT_REALTIME) ? CLOCK_REALTIME : CLOCK_MONOTONIC, &now);
            long ns = now.tv_nsec + timeout->tv_nsec;
            end.tv_nsec = ns % 1000000000;
            end.tv_sec = now.tv_sec + timeout->tv_sec + ns / 1000000000;
        }
    }

    int res;
    {
        std::lock_guard lock(mutex);
        bool is_same;
        try {
            uint32_t x;
            mm->run_catch_fault(uaddr, sizeof(uint32_t), [&] {
                x = __atomic_load_n(uaddr, __ATOMIC_SEQ_CST);
            });
            is_same = x == val;
        } catch (FaultException &e) {
            return -EFAULT;
        }
        if (!is_same) {
            return -EAGAIN;
        }
        std::shared_ptr<WaitQueue> wq;
        auto it = futexes.find((uintptr_t)uaddr);
        if (it == futexes.end()) {
            wq.reset(new WaitQueue((uintptr_t)uaddr));
            futexes[(uintptr_t)uaddr] = wq;
        } else {
            wq = it->second.lock();
            if (!wq) {
                wq.reset(new WaitQueue((uintptr_t)uaddr));
                futexes[(uintptr_t)uaddr] = wq;
            }
        }
        if (timeout) {
            eq.add_task_timeout(wq, task, (struct __kernel_timespec *)timeout, timeout_flags, mask);
        } else {
            wq->add_task(task, mask);
        }
    }
    //uint64_t t2 = time_nanosec();
    Executor::block();
    //uint64_t t3 = time_nanosec();
    Task::WaitResult wq_res = task->wq_res;

    if (wq_res.timeout) {
        res = -ETIMEDOUT;
    } else if (wq_res.from_signal) {
        res = -EINTR;
    } else {
        res = 0;
    }
    uintptr_t wq_key = task->wq_key;
    {
        std::lock_guard lock(mutex);
        auto it = futexes.find(wq_key);
        if (it == futexes.end()) {
            goto out;
        }
        if (it->second.expired()) {
            futexes.erase(it);
        }
    }
out:
    //uint64_t t4 = time_nanosec();
    //Stat::get().add(1, t2 - t1);
    //Stat::get().add(2, t3 - t2);
    //Stat::get().add(3, t4 - t3);
    if (res != -EINTR) {
        return res;
    }
    if (!timeout) {
        vthread->set_restart();
        return -EINTR;
    }
    FutexWaitRestartFunction func;
    func.uaddr = uaddr;
    func.val = val;
    func.timeout = end;
    func.timeout_flags = timeout_flags | IORING_TIMEOUT_ABS;
    func.mask = mask;
    vthread->set_restart(func);
    return -EINTR;
}

int FutexContext::wake(VThread *vthread, uint32_t *uaddr, int max_tasks, uint32_t mask) {
    //uint64_t t1 = time_nanosec();
    std::shared_ptr<WaitQueue> wq;
    size_t n;
    {
        std::lock_guard lock(mutex);
        auto it = futexes.find((uintptr_t)uaddr);
        if (it == futexes.end()) {
            return 0;
        }
        wq = it->second.lock();
        if (!wq) {
            futexes.erase(it);
            return 0;
        }
        n = wq->wake_some(max_tasks, mask);
    }
    if (n) {
        //vthread->set_work(VThread::WorkResched);
    }
    //uint64_t t2 = time_nanosec();
    //Stat::get().add(0, t2 - t1);
    return n;
}

int FutexContext::wake_op(VThread *vthread, uint32_t *uaddr, uint32_t val,
                          uint32_t val2, uint32_t *uaddr2, uint32_t val3) {
    if ((uintptr_t)uaddr % sizeof(uint32_t) != 0) {
        return -EINVAL;
    }
    if ((uintptr_t)uaddr2 % sizeof(uint32_t) != 0) {
        return -EINVAL;
    }
    MM *mm = vthread->get_vprocess()->get_mm();
    size_t n = 0;
    {
        std::lock_guard lock(mutex);
        uint32_t op = (val3 >> 28) & 0xf;
        uint32_t cmp = (val3 >> 24) & 0xf;
        uint32_t oparg = (val3 >> 12) & 0xfff;
        uint32_t cmparg = val3 & 0xfff;
        if (op & FUTEX_OP_OPARG_SHIFT) {
            oparg = 1 << oparg;
            op &= ~FUTEX_OP_OPARG_SHIFT;
        }
        if (op > 4 || cmp > 5) {
            return -EINVAL;
        }
        uint32_t oldval = 0;
        try {
            mm->run_catch_fault(uaddr2, sizeof(uint32_t), [&] {
                switch (op) {
                case FUTEX_OP_SET:  oldval = __atomic_exchange_n(uaddr2, oparg, __ATOMIC_SEQ_CST); break;
                case FUTEX_OP_ADD:  oldval = __atomic_fetch_add(uaddr2, oparg, __ATOMIC_SEQ_CST); break;
                case FUTEX_OP_OR:   oldval = __atomic_fetch_or(uaddr2, oparg, __ATOMIC_SEQ_CST); break;
                case FUTEX_OP_ANDN: oldval = __atomic_fetch_and(uaddr2, ~oparg, __ATOMIC_SEQ_CST); break;
                case FUTEX_OP_XOR:  oldval = __atomic_fetch_xor(uaddr2, oparg, __ATOMIC_SEQ_CST); break;
                }
            });
        } catch (FaultException &e) {
            return -EFAULT;
        }

        do {
            auto it = futexes.find((uintptr_t)uaddr);
            if (it == futexes.end()) {
                break;
            }
            std::shared_ptr<WaitQueue> wq = it->second.lock();
            if (!wq) {
                futexes.erase(it);
                break;
            }
            n += wq->wake_some(val);
        } while (0);

        bool condition = false;
        switch (cmp) {
        case FUTEX_OP_CMP_EQ:   condition = oldval == cmparg;   break;
        case FUTEX_OP_CMP_NE:   condition = oldval != cmparg;   break;
        case FUTEX_OP_CMP_LT:   condition = oldval <  cmparg;   break;
        case FUTEX_OP_CMP_LE:   condition = oldval <= cmparg;   break;
        case FUTEX_OP_CMP_GT:   condition = oldval >  cmparg;   break;
        case FUTEX_OP_CMP_GE:   condition = oldval >= cmparg;   break;
        }
        if (condition) {
            do {
                auto it = futexes.find((uintptr_t)uaddr2);
                if (it == futexes.end()) {
                    break;
                }
                std::shared_ptr<WaitQueue> wq = it->second.lock();
                if (!wq) {
                    futexes.erase(it);
                    break;
                }
                n += wq->wake_some(val2);
            } while (0);
        }
    }
    if (n) {
        //vthread->set_work(VThread::WorkResched);
    }
    return n;
}

int FutexContext::requeue(VThread *vthread, bool cmp, uint32_t *uaddr, uint32_t val,
                          uint32_t val2, uint32_t *uaddr2, uint32_t val3) {
    if ((uintptr_t)uaddr % sizeof(uint32_t) != 0) {
        return -EINVAL;
    }
    MM *mm = vthread->get_vprocess()->get_mm();
    std::shared_ptr<Task> task = Executor::get_current_task();
    size_t n = 0;
    {
        std::lock_guard lock(mutex);
        if (cmp) {
            uint32_t x;
            mm->run_catch_fault(uaddr, sizeof(uint32_t), [&] {
                x = __atomic_load_n(uaddr, __ATOMIC_SEQ_CST);
            });
            if (x != val3) {
                return -EAGAIN;
            }
        }
        std::shared_ptr<WaitQueue> wq1, wq2;
        auto it = futexes.find((uintptr_t)uaddr);
        if (it == futexes.end()) {
            return 0;
        }
        wq1 = it->second.lock();
        if (!wq1) {
            return 0;
        }
        it = futexes.find((uintptr_t)uaddr2);
        if (it == futexes.end()) {
            wq2.reset(new WaitQueue((uintptr_t)uaddr2));
            futexes[(uintptr_t)uaddr2] = wq2;
        } else {
            wq2 = it->second.lock();
            if (!wq2) {
                wq2.reset(new WaitQueue((uintptr_t)uaddr2));
                futexes[(uintptr_t)uaddr2] = wq2;
            }
        }
        n = wq1->requeue(wq2, val, val2);
    }
    if (n) {
        //vthread->set_work(VThread::WorkResched);
    }
    return n;
}

long SyscallHandlers::futex(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    //Stat::get().add(1, 1);
    int op = args[1];
    bool is_private = false;
    if (op & FUTEX_PRIVATE_FLAG) {
        is_private = true;
        op &= ~FUTEX_PRIVATE_FLAG;
    }
    (void)is_private;
    int timeout_flags = 0;
    struct __kernel_timespec *ptimeout = (struct __kernel_timespec *)args[3];
    struct __kernel_timespec timeout;
    MM *mm = vthread->get_vprocess()->get_mm();
    FutexContext *fc = vthread->get_vprocess()->get_futex_context();
    if (op & FUTEX_CLOCK_REALTIME) {
        timeout_flags = IORING_TIMEOUT_REALTIME;
        op &= ~FUTEX_CLOCK_REALTIME;
        if (op != FUTEX_WAIT && op != FUTEX_WAIT_BITSET && op != FUTEX_WAIT_REQUEUE_PI && op != FUTEX_LOCK_PI2) {
            return -ENOSYS;
        }
    }
    if ((op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET) && ptimeout) {
        try {
            mm->copy_from_sandbox(&timeout, ptimeout, sizeof(struct __kernel_timespec));
        } catch (FaultException &e) {
            return -EFAULT;
        }
    }

    if (op != FUTEX_WAIT) {
        timeout_flags |= IORING_TIMEOUT_ABS;
    }
    uint32_t *uaddr = (uint32_t *)args[0];
    uint32_t *uaddr2 = (uint32_t *)args[4];
    uint32_t val = args[2];
    uint32_t val2 = args[3];
    uint32_t val3 = args[5];
    switch (op) {
    case FUTEX_WAIT:
        return fc->wait(vthread, uaddr, val, ptimeout ? &timeout : nullptr, timeout_flags, -1u);
    case FUTEX_WAKE:
        return fc->wake(vthread, uaddr, val, -1u);
    case FUTEX_WAIT_BITSET:
        return fc->wait(vthread, uaddr, val, ptimeout ? &timeout : nullptr, timeout_flags, val3);
    case FUTEX_WAKE_BITSET:
        return fc->wake(vthread, uaddr, val, val3);
    case FUTEX_WAKE_OP:
        return fc->wake_op(vthread, uaddr, val, val2, uaddr2, val3);
    case FUTEX_CMP_REQUEUE:
        return fc->requeue(vthread, true, uaddr, val, val2, uaddr2, val3);
    case FUTEX_REQUEUE:
        return fc->requeue(vthread, false, uaddr, val, val2, uaddr2, val3);
    default:
        return -ENOTSUP;
    }
}

long SyscallHandlers::set_robust_list(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    return 0;
}
