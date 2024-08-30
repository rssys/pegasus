#pragma once
#include <memory>
#include <vector>
#include <string>
#include <thread>
#include <functional>
#include <mutex>
#include <unordered_set>
#include <unordered_map>
#include <map>
#include <csetjmp>
#include <sys/socket.h>
#include <sys/epoll.h>
#include "file.h"
#include "lock.h"

namespace pegasus {
struct IOWorkerConfiguration {
    IOWorkerConfiguration();
    bool enabled;
    std::string config_file;
    std::vector<std::string> args;
    std::string ip;
    bool enable_linux_lo;
};

struct IOWorkerFd {
    IOWorkerFd() : iow(nullptr), fp(nullptr), fd(-1) {}
    IOWorkerFd(const IOWorkerFd &) = delete;
    IOWorkerFd(IOWorkerFd &&f) {
        iow = f.iow;
        fp = f.fp;
        fd = f.fd;
        f.iow = nullptr;
        f.fp = nullptr;
        f.fd = -1;
    }
    IOWorkerFd &operator=(const IOWorkerFd &f) = delete;
    IOWorkerFd &operator=(IOWorkerFd &&f) {
        reset();
        iow = f.iow;
        fp = f.fp;
        fd = f.fd;
        f.iow = nullptr;
        f.fp = nullptr;
        f.fd = -1;
        return *this;
    }
    ~IOWorkerFd() {
        reset();
    }
    void reset();
    IOWorker *iow;
    void *fp;
    int fd;
};

struct IOWorkerEpollFd : IOWorkerFd {
    IOWorkerEpollFd() : IOWorkerFd(), kq(nullptr) {}
    IOWorkerEpollFd(const IOWorkerEpollFd &) = delete;
    IOWorkerEpollFd(IOWorkerEpollFd &&f) {
        iow = f.iow;
        fp = f.fp;
        kq = f.kq;
        fd = f.fd;
        f.iow = nullptr;
        f.fp = nullptr;
        f.kq = nullptr;
        f.fd = -1;
    }
    IOWorkerEpollFd &operator=(const IOWorkerEpollFd &f) = delete;
    IOWorkerEpollFd &operator=(IOWorkerEpollFd &&f) {
        reset();
        iow = f.iow;
        fp = f.fp;
        kq = f.kq;
        fd = f.fd;
        f.iow = nullptr;
        f.fp = nullptr;
        f.kq = nullptr;
        f.fd = -1;
        return *this;
    }
    ~IOWorkerEpollFd() {
        reset();
    }
    void reset();
    void *kq;
};

class DPDKSocket;
class TaskManager;
class VThread;
struct FDFilePair;
class WaitQueue;
struct Task;

class IOWorker {
public:
    using SyscallMutexType = FakeLock;
    IOWorker(TaskManager *tm_, int core_);
    void init_global(const IOWorkerConfiguration &config);
    void init_cpu();
    void start();
    void wait();
    static bool create(VThread *vthread, FDFilePair &out, bool local, int domain, int type, int protocol);
    //void add_file(const std::shared_ptr<DPDKSocket> &file);
    void remove_file(IOWorkerFd &dfd);
    int create_epoll(IOWorkerEpollFd &dfd);
    int epoll_get_events(VThread *vthread, const IOWorkerEpollFd &fd, struct epoll_event *ev, int n);
    int epoll_ctl(VThread *vthread, const IOWorkerFd &fd, int op, File *file, struct epoll_event *ev);
    uintptr_t poll_file(const IOWorkerFd &fd, const std::shared_ptr<WaitQueue> &wq,
                        const std::shared_ptr<Task> &task, uint32_t events);
    void cancel_poll_file(const IOWorkerFd &fd, uintptr_t key);
    void poll_file(const IOWorkerEpollFd &fd, const std::shared_ptr<File> &file);
    void cancel_poll_file(const IOWorkerEpollFd &fd);
private:
    friend class DPDKSocket;
    enum {
        InitialKey = 1ull,
    };
    static constexpr int MaxEvents = 32;
    //struct Poll {
    //    std::shared_ptr<WaitQueue> wq;
    //    std::shared_ptr<Task> task;
    //    uint32_t events;
    //};
    //struct Item {
    //    Item() : current_key(0) {}
    //    uintptr_t current_key;
    //    std::unordered_map<uintptr_t, Poll> polls;
    //};
    struct Item {
        std::shared_ptr<WaitQueue> wq;
        std::shared_ptr<Task> task;
        void *fp;
        uint32_t events;
    };
    struct ItemEpoll {
        std::shared_ptr<File> file;
        int ref;
        uint32_t events;
    };
    struct AvailItem {
        std::shared_ptr<WaitQueue> wq;
        std::shared_ptr<Task> task;
    };
    void ioworker_routine();
    int loop_func();

    SpinLock file_mutex;
    TaskManager *tm;
    int core;
    //int epfd;
    //void *kq;
    pid_t tid;
    uintptr_t current_key;
    bool started;

    //std::unordered_map<int, Item> watching_files;
    std::unordered_map<uintptr_t, Item> watching_files;
    std::unordered_map<void *, ItemEpoll> watching_epfiles;
    jmp_buf jbuf;

    std::vector<struct epoll_event> blocking_file_events;
    std::vector<AvailItem> avail_events;
    std::vector<std::shared_ptr<File>> avail_epevents;
    //BatchNotifyState batch_notify_state;
};
}
