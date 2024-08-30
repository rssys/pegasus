#include <vector>
#include <string>
#include <thread>
#include <memory>
#include <cassert>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <rte_lcore.h>
#include <ff_api.h>
#include <ff_epoll.h>
#include "pegasus/event.h"
#include "pegasus/exception.h"
#include "pegasus/gate.h"
#include "pegasus/ioworker.h"
#include "pegasus/mm.h"
#include "pegasus/runtime.h"
#include "pegasus/sched.h"
#include "pegasus/stat.h"
#include "pegasus/wait_queue.h"
#include "pegasus/network/dpdk.h"
#include "pegasus/network/network.h"

using namespace pegasus;

#define FREEBSD_SOCK_NONBLOCK 0x20000000

IOWorkerConfiguration::IOWorkerConfiguration() : enabled(false), enable_linux_lo(false) {}

void IOWorker::init_global(const IOWorkerConfiguration &config) {
    std::vector<char *> args;
    args.push_back((char *)"pegasus");
    for (auto &&s : config.args) {
        args.push_back((char *)s.data());
    }

    int res = ff_init(args.size(), args.data());
    if (res != 0) {
        printf("failed to init f-stack\n");
        throw SystemException(res);
    }
}

void IOWorker::init_cpu() {
    if (rte_lcore_id() == LCORE_ID_ANY) {
        if (rte_thread_register() || rte_lcore_id() == LCORE_ID_ANY) {
            throw Exception("failed to register thread for DPDK");
        }
    }
    int res = ff_init_thread();
    if (res < 0) {
        throw SystemException(-res);
    }
}

IOWorker::IOWorker(TaskManager *tm_, int core_ = -1)
    : tm(tm_), core(core_), /*epfd(-1),*/ tid(-1), current_key(0), started(false),
      blocking_file_events(MaxEvents) {
}

void IOWorker::start() {
    ioworker_routine();
}

void IOWorker::wait() {
}

void IOWorker::ioworker_routine() {
    tid = gettid();
    //if (core != -1) {
    //    cpu_set_t set;
    //    CPU_ZERO(&set);
    //    CPU_SET(core, &set);
    //    pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    //}
    ::init_cpu();
    printf("fstack starting\n");

    if (setjmp(jbuf)) {
        Runtime::get()->get_tm()->wait_barrier();
        return;
    }
    //epfd = ff_epoll_create(0);
    //if (epfd == -1) {
    //    throw Exception("failed to create ff epfd");
    //}
    //void *fp = ff_fget(epfd);
    //if (!fp) {
    //    throw Exception("failed to create ff ep fp");
    //}
    //kq = ff_kqueue_acquire(fp);
    //if (!kq) {
    //    throw Exception("failed to create ff ep kq");
    //}
    ff_run([] (void *arg) {
        IOWorker *iokernel = (IOWorker *)arg;
        int res = iokernel->loop_func();
        return res;
    }, this);
    Runtime::get()->get_tm()->wait_barrier();
}

bool IOWorker::create(VThread *vthread, FDFilePair &out, bool local, int domain, int type, int protocol) {
    IOWorker *iow = Runtime::get()->get_tm()->get_ioworker();
    if ((domain != AF_INET && domain != AF_INET6)) {
        return false;
    }
    bool nonblock = type & SOCK_NONBLOCK;
    bool no_local = type & NoFastPath;
    type &= ~NoFastPath;
    type &= ~(SOCK_CLOEXEC | SOCK_NONBLOCK);
    IOWorkerFd dfd;
    int fd = ff_socket(domain, type | FREEBSD_SOCK_NONBLOCK, protocol);
    if (fd < 0) {
        return false;
    }
    void *fp = ff_fget(fd);
    if (!fp) {
        ff_close(fd);
        return false;
    }
    dfd.iow = iow;
    dfd.fd = fd;
    dfd.fp = fp;
    std::shared_ptr<DPDKSocket> sock;
    if (local && !no_local) {
        sock = std::make_shared<SocketWrapper<DPDKSocket>>(
            nullptr, -1, domain, type, protocol, dfd, domain, nonblock
        );
    } else {
        if (Runtime::get()->get_config().ioworker_config.enable_linux_lo) {
            FileDescriptor lfd;
            USwitchContext *ucontext = vthread->get_vprocess()->get_ucontext();
            ucontext->run_on_behalf_of([&] {
                lfd.fd = socket(domain, type | SOCK_NONBLOCK, protocol);
            });
            if (lfd.fd != -1) {
                lfd.ucontext = ucontext;
                out.fd = std::move(lfd);
                sock = std::make_shared<DPDKSocketWithLO>(ucontext, out.fd.fd, dfd, domain, nonblock);
            }
        }
        if (!sock) {
            sock = std::make_shared<DPDKSocket>(dfd, domain, nonblock);
        }
    }
    //iow->add_file(sock);
    out.file = sock;
    return true;
}

void IOWorker::remove_file(IOWorkerFd &dfd) {
    //std::lock_guard lock(file_mutex);
    //ff_epoll_ctl(epfd, EPOLL_CTL_DEL, dfd.fd, nullptr);
    //watching_files.erase(dfd.fd);
}

int IOWorker::create_epoll(IOWorkerEpollFd &dfd) {
    int fd;
    fd = ff_epoll_create(0);
    if (fd < 0) {
        return -errno;
    }
    dfd.iow = this;
    dfd.fd = fd;
    dfd.fp = ff_fget(fd);
    if (!dfd.fp) {
        return -EBADF;
    }
    dfd.kq = ff_kqueue_acquire(dfd.fp);
    if (!dfd.kq) {
        return -EBADF;
    }
    return 0;
}

int IOWorker::epoll_get_events(VThread *vthread, const IOWorkerEpollFd &fd,
                               struct epoll_event *ev, int n) {
    int res;
    res = ff_epoll_scan(fd.kq, ev, n);
    if (res < 0) {
        res = -errno;
    }
    return res;
}

int IOWorker::epoll_ctl(VThread *vthread, const IOWorkerFd &fd, int op,
                        File *file, struct epoll_event *ev) {
    DPDKSocket *sock = dynamic_cast<DPDKSocket *>(file);
    if (!sock) {
        return -EINVAL;
    }
    int res;
    res = ff_epoll_ctl(fd.fd, op, sock->fd.fd, ev);
    if (res < 0) {
        res = -errno;
    }
    return res;
}

uintptr_t IOWorker::poll_file(const IOWorkerFd &fd, const std::shared_ptr<WaitQueue> &wq,
                              const std::shared_ptr<Task> &task, uint32_t events) {
    std::lock_guard lock(file_mutex);
    //Item &item = watching_files[fd.fd];
    //uint32_t old_events = 0;
    //uintptr_t key = item.current_key++;
    //bool has_event = item.polls.size();
    //if (has_event) {
    //    for (auto &&it : item.polls) {
    //        old_events |= it.second.events;
    //    }
    //}
    //uint32_t all_events = old_events | events;
    //item.polls.emplace(key, Poll {wq, task, events});
    //if (old_events != all_events) {
    //    struct epoll_event ev;
    //    ev.events = all_events;
    //    ev.data.fd = fd.fd;
    //    if (has_event) {
    //        ff_epoll_ctl(epfd, EPOLL_CTL_MOD, fd.fd, &ev);
    //    } else {
    //        ff_epoll_ctl(epfd, EPOLL_CTL_ADD, fd.fd, &ev);
    //    }
    //}
    //return key;
    uintptr_t key = current_key++;
    watching_files.emplace(key, Item {wq, task, fd.fp, events});
    return key;
}

void IOWorker::cancel_poll_file(const IOWorkerFd &fd, uintptr_t key) {
    std::lock_guard lock(file_mutex);
    watching_files.erase(key);
    //auto it = watching_files.find(fd.fd);
    //if (it == watching_files.end()) {
    //    return;
    //}
    //Item &item = it->second;
    //item.polls.erase(key);
    //uint32_t events = 0;
    //for (auto &&it : item.polls) {
    //    events |= it.second.events;
    //}
    //if (events == 0) {
    //    ff_epoll_ctl(epfd, EPOLL_CTL_DEL, fd.fd, nullptr);
    //} else {
    //    struct epoll_event ev;
    //    ev.events = events;
    //    ev.data.fd = fd.fd;
    //    ff_epoll_ctl(epfd, EPOLL_CTL_MOD, fd.fd, &ev);
    //}
}

void IOWorker::poll_file(const IOWorkerEpollFd &fd, const std::shared_ptr<File> &file) {
    std::lock_guard lock(file_mutex);
    auto it = watching_epfiles.find(fd.kq);
    if (it == watching_epfiles.end()) {
        watching_epfiles.emplace(fd.kq, ItemEpoll {file, 1, EPOLLIN});
    } else {
        ++it->second.ref;
    }
}

void IOWorker::cancel_poll_file(const IOWorkerEpollFd &fd) {
    std::lock_guard lock(file_mutex);
    auto it = watching_epfiles.find(fd.kq);
    if (it == watching_epfiles.end()) {
        return;
    }
    if (!--it->second.ref) {
        watching_epfiles.erase(it);
    }
}

int IOWorker::loop_func() {
    if (!started) {
        Runtime::get()->get_tm()->wait_barrier();
        printf("ioworker initialized\n");
        started = true;
    }
    if (Runtime::get()->get_tm()->stopped) {
        longjmp(jbuf, 1);
    }
    {
        std::lock_guard lock(file_mutex);
        //if (watching_files.size()) {
        //    int n = ff_epoll_scan(kq, blocking_file_events.data(), MaxEvents);
        //    if (n > 0) {
        //        //pegasus_trace_time(3);
        //    }
        //    for (int i = 0; i < n; ++i) {
        //        int fd = blocking_file_events[i].data.fd;
        //        uint32_t events = blocking_file_events[i].events;
        //        auto it = watching_files.find(fd);
        //        if (it != watching_files.end()) {
        //            Item &item = it->second;
        //            uint32_t new_events = 0;
        //            uint32_t old_events = 0;
        //            for (auto it2 = item.polls.begin(); it2 != item.polls.end(); ) {
        //                auto next = std::next(it2);
        //                old_events |= it2->second.events;
        //                if (events & it2->second.events) {
        //                    avail_events.emplace_back(AvailItem {it2->second.wq, it2->second.task});
        //                    item.polls.erase(it2);
        //                } else {
        //                    new_events |= it2->second.events;
        //                }
        //                it2 = next;
        //            }
        //            if (new_events != old_events) {
        //                if (new_events == 0) {
        //                    ff_epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
        //                } else {
        //                    struct epoll_event ev;
        //                    ev.events = new_events;
        //                    ev.data.fd = fd;
        //                    ff_epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
        //                }
        //            }
        //        }
        //    }
        //}
        for (auto it = watching_files.begin(); it != watching_files.end(); ) {
            auto next = std::next(it);
            Item &item = it->second;
            uint32_t revents = ff_poll_fp(item.fp, item.events);
            if (revents) {
                avail_events.push_back(AvailItem {item.wq, item.task});
                watching_files.erase(it);
            }
            it = next;
        }
        for (auto &&it : watching_epfiles) {
            uint32_t revents = ff_kqueue_poll(it.first);
            if (revents) {
                avail_epevents.push_back(it.second.file);
            }
        }
    }
    if (avail_events.size()) {
        for (auto &&ev : avail_events) {
            Task::WaitResult res(Task::WaitResult::FromIOWorker, 0);
            pegasus_trace_time(3);
            ev.wq->wake(ev.task.get(), res);
        }
        avail_events.clear();
    }
    if (avail_epevents.size()){
        for (auto &&ev : avail_epevents) {
            std::unique_lock lock(ev->get_mutex());
            ev->notify(EPOLLIN, lock);
        }
        avail_epevents.clear();
    }
    GET_PER_CPU_PRIV(cwm)->check();

    return 0;
}
