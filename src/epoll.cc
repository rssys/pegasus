#include <memory>
#include <unordered_map>
#include <cstring>
#include "pegasus/epoll.h"
#include "pegasus/file.h"
#include "pegasus/ioworker.h"
#include "pegasus/lock.h"
#include "pegasus/mm.h"
#include "pegasus/monitor.h"
#include "pegasus/runtime.h"
#include "pegasus/stat.h"
#include "pegasus/uswitch.h"
#include "pegasus/wait_queue.h"

using namespace pegasus;

// protects epoll files' watching_epfiles and exclusive_epfiles
// to handle nested epoll files
static SpinLock global_epoll_mutex;

struct PollFileEntry {
    std::shared_ptr<File> file;
    int events = 0;
};

static int
epoll_from_poll_select(VThread *vthread,
                       const std::unordered_map<int, PollFileEntry> &files,
                       int num_real_file,
                       int num_unmanaged_file,
                       int num_iow_file,
                       std::shared_ptr<EpollFile> &epoll_file,
                       std::shared_ptr<File> &only_real_file,
                       int &only_real_file_fd,
                       uint32_t &only_real_file_events) {
    VProcess *vprocess = vthread->get_vprocess();
    USwitchContext *ucontext = vprocess->get_ucontext();
    int fd = -1;
    bool need_create_epoll = num_real_file > 1 || num_unmanaged_file;
    if (need_create_epoll) {
        fd = ::epoll_create1(0);
        if (fd == -1) {
            return -errno;
        }
    }
    std::shared_ptr<EpollFile> epfile = std::make_shared<EpollFile>(nullptr, -1);
    if (need_create_epoll) {
        epfile->set_monitor_fd(fd);
    }
    if (num_iow_file) {
        IOWorker *iow = Runtime::get()->get_tm()->get_ioworker();
        IOWorkerEpollFd iow_fd;
        int res = iow->create_epoll(iow_fd);
        if (res < 0) {
            return res;
        }
        epfile->set_iow_fd(iow_fd);
    }

    for (auto &&f : files) {
        int ffd = f.first;
        struct epoll_event event;
        event.events = f.second.events;
        event.data.fd = ffd;
        std::shared_ptr<File> file = f.second.file;
        
        int res1 = 0;
        int res2 = 0;
        if (num_real_file) {
            int pfd = -1;
            if (!file) {
                pfd = ucontext->get_file(ffd);
                if (pfd < 0) {
                    res1 = -errno;
                }
                res1 = ::epoll_ctl(fd, EPOLL_CTL_ADD, pfd, &event);
                if (res1 < 0) {
                    res1 = -errno;
                }
                ::close(pfd);
            } else if (file->get_cap() & File::Real) {
                FileDescriptorReference fdr;
                fdr.fd = ffd;
                fdr.ucontext = ucontext;
                pfd = file->create_monitor_fd(fdr);
                if (!need_create_epoll && pfd != -1 && num_real_file == 1 && num_unmanaged_file == 0) {
                    only_real_file = file;
                    only_real_file_fd = ffd;
                    only_real_file_events = event.events;
                }
            }
        }
        if (file) {
            std::unique_lock lock(epfile->get_mutex());
            res2 = epfile->add_file(vthread, file, &event, lock);
        }
        if (res1 < 0 && res2 < 0) {
            return res1;
        }
    }

    epoll_file = epfile;
    return 0;
}

static int epoll_from_poll(VThread *vthread, struct pollfd *fds, int nfds,
                           std::shared_ptr<EpollFile> &epoll_file,
                           std::shared_ptr<File> &only_real_file,
                           int &only_real_file_fd,
                           uint32_t &only_real_file_events) {
    int num_real_file = 0;
    int num_unmanaged_file = 0;
    int num_iow_file = 0;
    static thread_local std::unordered_map<int, PollFileEntry> files;
    files.clear();
    FileTable *ft = vthread->get_vprocess()->get_file_table();
    for (int i = 0; i < nfds; ++i) {
        int fd = fds[i].fd;
        auto it = files.find(fd);
        if (it == files.end()) {
            PollFileEntry f;
            f.file = ft->get_file(fd);
            f.events = fds[i].events;
            if (!f.file) {
                ++num_unmanaged_file;
                ++num_real_file;
            } else {
                uint32_t cap = f.file->get_cap();
                if (cap & File::Real) {
                    ++num_real_file;
                }
                if (cap & File::FromIOWorker) {
                    ++num_iow_file;
                }
            }
            files.emplace(fd, f);
        } else {
            it->second.events |= fds[i].events;
        }
    }
    int res = epoll_from_poll_select(vthread, files, num_real_file, num_unmanaged_file, num_iow_file,
                                     epoll_file, only_real_file, only_real_file_fd, only_real_file_events);
    return res;
}

static int epoll_from_select(VThread *vthread, int nfds, const fd_set *rfds,
                             const fd_set *wfds, const fd_set *efds,
                             std::shared_ptr<EpollFile> &epoll_file,
                             std::shared_ptr<File> &only_real_file,
                             int &only_real_file_fd,
                             uint32_t &only_real_file_events) {
    int num_real_file = 0;
    int num_unmanaged_file = 0;
    int num_iow_file = 0;
    static thread_local std::unordered_map<int, PollFileEntry> files;
    FileTable *ft = vthread->get_vprocess()->get_file_table();
    if (nfds > FD_SETSIZE) {
        nfds = FD_SETSIZE;
    }
    files.clear();
    if (rfds) {
        for (int i = 0; i < nfds; ++i) {
            if (FD_ISSET(i, rfds)) {
                auto it = files.find(i);
                if (it == files.end()) {
                    PollFileEntry f;
                    f.file = ft->get_file(i);
                    f.events = EPOLLIN;
                    if (!f.file) {
                        ++num_unmanaged_file;
                        ++num_real_file;
                    } else {
                        uint32_t cap = f.file->get_cap();
                        if (cap & File::Real) {
                            ++num_real_file;
                        }
                        if (cap & File::FromIOWorker) {
                            ++num_iow_file;
                        }
                    }
                    files.emplace(i, f);
                } else {
                    it->second.events |= EPOLLIN;
                }
            }
        }
    }
    if (wfds) {
        for (int i = 0; i < nfds; ++i) {
            if (FD_ISSET(i, wfds)) {
                auto it = files.find(i);
                if (it == files.end()) {
                    PollFileEntry f;
                    f.file = ft->get_file(i);
                    f.events = EPOLLOUT;
                    if (!f.file) {
                        ++num_unmanaged_file;
                        ++num_real_file;
                    } else {
                        uint32_t cap = f.file->get_cap();
                        if (cap & File::Real) {
                            ++num_real_file;
                        }
                        if (cap & File::FromIOWorker) {
                            ++num_iow_file;
                        }
                    }
                    files.emplace(i, f);
                } else {
                    it->second.events |= EPOLLOUT;
                }
            }
        }
    }
    (void)efds;
    
    return epoll_from_poll_select(vthread, files, num_real_file, num_unmanaged_file, num_iow_file,
                                  epoll_file, only_real_file, only_real_file_fd, only_real_file_events);
}

EpollFile::EpollFile(USwitchContext *ucontext, int fd)
    : File(ucontext, fd), wq(std::make_shared<WaitQueue>()) {
}

EpollFile::~EpollFile() {
}

uint32_t EpollFile::poll(VThread *vthread, uint32_t events) {
    std::lock_guard lock(mutex);
    return pending_events.empty() ? 0 : EPOLLIN;
}

void EpollFile::notify(uint32_t events, std::unique_lock<SpinLock> &lock) {
    if (watching_epfiles.empty() && exclusive_epfiles.empty()) {
        wq->wake_all();
        return;
    }
    lock.unlock();
    if (events & EPOLLIN) {
        std::lock_guard lock(global_epoll_mutex);
        notify_epoll();
    }
}

uint32_t EpollFile::get_cap() {
    return Real | Pollable;
}

void EpollFile::notify(File *f, uint32_t events) {
    std::unique_lock lock(mutex);
    auto it = files.find(f);
    if (it == files.end()) {
        return;
    }
    std::shared_ptr<File> file = it->second.file.lock();
    if (!file) {
        files.erase(it);
        return;
    }
    if (!(it->second.event.events & events)) {
        return;
    }
    it->second.revents |= it->second.event.events & events;
    pending_events.insert(f);
    notify(EPOLLIN, lock);
}

void EpollFile::notify(const std::unordered_map<File *, uint32_t> &notify_files) {
    std::unique_lock lock(mutex);
    for (auto &&f : notify_files) {
        auto it = files.find(f.first);
        if (it == files.end()) {
            continue;
        }
        std::shared_ptr<File> file = it->second.file.lock();
        if (!file) {
            files.erase(it);
            return;
        }
        uint32_t events = f.second;
        if (!(it->second.event.events & events)) {
            return;
        }
        it->second.revents |= it->second.event.events & events;
        pending_events.insert(f.first);
    }
    notify(EPOLLIN, lock);
}

int EpollFile::add_file(VThread *vthread, const std::shared_ptr<File> &file,
                        const struct epoll_event *event, std::unique_lock<SpinLock> &lock1) {
    if (file.get() == this) {
        return -EBADF;
    }
    if (is_epoll_file(file.get())) {
        lock1.unlock();
        return add_epoll_file(vthread, file, event);
    }
    auto it = find_files(file.get());
    if (it != files.end()) {
        return -EEXIST;
    }
    struct epoll_event ev = *event;
    ev.events |= EPOLLERR | EPOLLHUP;
    if (file->get_cap() & File::Real) {
        if (::epoll_ctl(monitor_file.fd, EPOLL_CTL_ADD, file->get_monitor_fd(), &ev) == -1) {
            return -errno;
        }
        real_files.insert(file.get());
    }
    if (file->get_cap() & File::FromIOWorker) {
        int res = iow_fd.iow->epoll_ctl(vthread, iow_fd, EPOLL_CTL_ADD, file.get(), &ev);
        if (res < 0) {
            return res;
        }
        iow_files.insert(file.get());
    }
    {
        std::lock_guard lock2(file->mutex);
        if (ev.events & EPOLLEXCLUSIVE) {
            file->exclusive_epfiles.emplace(this, std::static_pointer_cast<EpollFile>(shared_from_this()));
        } else {
            file->watching_epfiles.emplace(this, std::static_pointer_cast<EpollFile>(shared_from_this()));
        }
    }
    uint32_t revents = file->poll(vthread, ev.events);
    Entry entry = {file, ev, revents};
    files[file.get()] = entry;
    if (revents) {
        pending_events.insert(file.get());
    }
    return 0;
}

int EpollFile::mod_file(VThread *vthread, const std::shared_ptr<File> &file,
                        const struct epoll_event *event, std::unique_lock<SpinLock> &lock)  {
    if (is_epoll_file(file.get())) {
        lock.unlock();
        return mod_epoll_file(vthread, file, event);
    }
    auto it = find_files(file.get());
    if (it == files.end()) {
        return -ENOENT;
    }
    if (event->events & EPOLLEXCLUSIVE) {
        return -EINVAL;
    }
    if (it->second.event.events & EPOLLEXCLUSIVE) {
        return -EINVAL;
    }
    struct epoll_event ev = *event;
    ev.events |= EPOLLERR | EPOLLHUP;
    if (file->get_cap() & File::Real) {
        if (::epoll_ctl(monitor_file.fd, EPOLL_CTL_MOD, file->get_monitor_fd(), &ev) == -1) {
            return -errno;
        }
    }
    if (file->get_cap() & File::FromIOWorker) {
        int res = iow_fd.iow->epoll_ctl(vthread, iow_fd, EPOLL_CTL_MOD, file.get(), &ev);
        if (res < 0) {
            return res;
        }
    }
    it->second.event = ev;
    uint32_t revents = file->poll(vthread, it->second.event.events);
    it->second.revents = revents;
    if (revents) {
        pending_events.insert(file.get());
    }
    return 0;
}

int EpollFile::del_file(VThread *vthread, const std::shared_ptr<File> &file,
                        std::unique_lock<SpinLock> &lock1) {
    if (is_epoll_file(file.get())) {
        lock1.unlock();
        return del_epoll_file(file.get());
    }
    auto it = find_files(file.get());
    if (it == files.end()) {
        return -ENOENT;
    }
    if (file->get_cap() & File::Real) {
        if (::epoll_ctl(monitor_file.fd, EPOLL_CTL_DEL, file->get_monitor_fd(), nullptr) == -1) {
            return -errno;
        }
        real_files.erase(file.get());
    }
    if (file->get_cap() & File::FromIOWorker) {
        int res = iow_fd.iow->epoll_ctl(vthread, iow_fd, EPOLL_CTL_DEL, file.get(), nullptr);
        if (res < 0) {
            return res;
        }
        iow_files.erase(file.get());
    }
    {
        std::lock_guard lock2(file->mutex);
        if (it->second.event.events & EPOLLEXCLUSIVE) {
            file->exclusive_epfiles.erase(this);
        } else {
            file->watching_epfiles.erase(this);
        }
    }
    files.erase(it);
    return 0;
}

void EpollFile::del_file_on_close(File *file) {
    std::unique_lock<SpinLock> lock(mutex);
    files.erase(file);
}

int EpollFile::wait(VThread *vthread, int epfd, struct epoll_event *events,
                    int maxevents, struct __kernel_timespec *ts) {
    //uint64_t t1 = time_nanosec();
    std::unique_lock lock(mutex);
    bool has_zero_timeout = ts && ts->tv_sec == 0 && ts->tv_nsec == 0;
    int res = get_events(vthread, events, maxevents);
    if (res != 0 || has_zero_timeout) {
        return res;
    }
    //uint64_t t2 = time_nanosec();
    std::shared_ptr<Task> task = Executor::get_current_task();
    if (real_files.size()) {
        Executor::get_current_executor()->get_eq().
            add_task_poll_timeout(wq, task, monitor_file.fd, EPOLLIN, ts, 0, -1);
    } else if (ts) {
        Executor::get_current_executor()->get_eq().
            add_task_timeout(wq, task, ts, 0, -1);
    } else {
        wq->add_task(task);
    }
    bool has_iow_files = iow_files.size();
    if (has_iow_files) {
        iow_fd.iow->poll_file(iow_fd, shared_from_this());
    }
    lock.unlock();
    //uint64_t t3 = time_nanosec();
    Executor::block();
    //uint64_t t4 = time_nanosec();
    lock.lock();
    if (has_iow_files) {
        iow_fd.iow->cancel_poll_file(iow_fd);
    }
    if (task->wq_res.from_signal) {
        res = -EINTR;
    } else {
        res = get_events(vthread, events, maxevents);
    }
    //uint64_t t5 = time_nanosec();
    //Stat::get().add(0, t2 - t1);
    //Stat::get().add(1, t3 - t2);
    //Stat::get().add(2, t5 - t4);
    return res;
}

void EpollFile::handle_overlay_real_file(VThread *vthread, int epfd, int fd, const std::shared_ptr<File> &file) {
    if (overlay_real_files.count(fd)) {
        return;
    }
    auto it = find_files(file.get());
    if (it == files.end()) {
        return;
    }
    long args[6] = {epfd, EPOLL_CTL_DEL, fd};
    vthread->invoke_syscall(SYS_epoll_ctl, args);
    overlay_real_files.insert(fd);
}

void EpollFile::handle_overlay_iow_file(VThread *vthread, int epfd, int fd, const std::shared_ptr<File> &file) {
    if (overlay_iow_files.count(fd)) {
        return;
    }
    auto it = find_files(file.get());
    if (it == files.end()) {
        return;
    }
    iow_fd.iow->epoll_ctl(vthread, iow_fd, EPOLL_CTL_DEL, file.get(), nullptr);
    overlay_iow_files.insert(fd);
}

int EpollFile::add_epoll_file(VThread *vthread, const std::shared_ptr<File> &file, const struct epoll_event *event) {
    static constexpr int MaxDepth = 5;
    std::lock_guard lock1(global_epoll_mutex);
    if (has_loop((EpollFile *)file.get(), MaxDepth)) {
        return -ELOOP;
    }
    struct epoll_event ev = *event;
    uint32_t revents = file->poll(vthread, ev.events);
    std::lock_guard lock2(mutex);
    auto it = find_files(file.get());
    if (it != files.end()) {
        return -EEXIST;
    }
    if (::epoll_ctl(monitor_file.fd, EPOLL_CTL_ADD, file->get_monitor_fd(), &ev) == -1) {
        return -errno;
    }
    real_files.insert(file.get());
    ev.events |= EPOLLERR | EPOLLHUP;
    if (ev.events & EPOLLEXCLUSIVE) {
        file->exclusive_epfiles.emplace(this, std::static_pointer_cast<EpollFile>(shared_from_this()));
    } else {
        file->watching_epfiles.emplace(this, std::static_pointer_cast<EpollFile>(shared_from_this()));
    }
    Entry entry = {file, ev, revents};
    files[file.get()] = entry;
    if (revents) {
        pending_events.insert(file.get());
    }
    return 0;
}

int EpollFile::mod_epoll_file(VThread *vthread, const std::shared_ptr<File> &file, const struct epoll_event *event) {
    std::lock_guard lock1(global_epoll_mutex);
    uint32_t revents = file->poll(vthread, EPOLLIN);
    std::lock_guard lock2(mutex);
    auto it = find_files(file.get());
    if (it == files.end()) {
        return -ENOENT;
    }
    if (event->events & EPOLLEXCLUSIVE) {
        return -EINVAL;
    }
    if (it->second.event.events & EPOLLEXCLUSIVE) {
        return -EINVAL;
    }
    struct epoll_event ev = *event;
    ev.events |= EPOLLERR | EPOLLHUP;
    if (::epoll_ctl(monitor_file.fd, EPOLL_CTL_MOD, file->get_monitor_fd(), &ev) == -1) {
        return -errno;
    }
    it->second.event = ev;
    it->second.revents = revents;
    if (revents) {
        pending_events.insert(file.get());
    }
    return 0;
}

int EpollFile::del_epoll_file(File *file) {
    std::lock_guard lock1(global_epoll_mutex);
    std::lock_guard lock2(mutex);
    auto it = find_files(file);
    if (it == files.end()) {
        return -ENOENT;
    }
    if (::epoll_ctl(monitor_file.fd, EPOLL_CTL_DEL, file->get_monitor_fd(), nullptr) == -1) {
        return -errno;
    }
    real_files.erase(file);
    if (it->second.event.events & EPOLLEXCLUSIVE) {
        file->exclusive_epfiles.erase(this);
    } else {
        file->watching_epfiles.erase(this);
    }
    files.erase(it);
    return 0;
}

bool EpollFile::has_loop(EpollFile *f, int max_depth) {
    if (this == f) {
        return true;
    }
    if (max_depth == 0) {
        return watching_epfiles.size() || exclusive_epfiles.size();
    }
    for (auto it = watching_epfiles.begin(); it != watching_epfiles.end(); ) {
        auto next = std::next(it);
        std::shared_ptr<EpollFile> file = it->second.lock();
        if (!file) {
            watching_epfiles.erase(it);
            it = next;
            continue;
        }
        if (file->has_loop(f, max_depth - 1)) {
            return true;
        }
        it = next;
        continue;
    }
    for (auto it = exclusive_epfiles.begin(); it != exclusive_epfiles.end(); ) {
        auto next = std::next(it);
        std::shared_ptr<EpollFile> file = it->second.lock();
        if (!file) {
            exclusive_epfiles.erase(it);
            it = next;
            continue;
        }
        if (file->has_loop(f, max_depth - 1)) {
            return true;
        }
        break;
    }
    return false;
}

void EpollFile::notify_epoll() {
    wq->wake_all();
    for (auto it = watching_epfiles.begin(); it != watching_epfiles.end(); ) {
        auto next = std::next(it);
        std::shared_ptr<EpollFile> file = it->second.lock();
        if (!file) {
            watching_epfiles.erase(it);
            it = next;
            continue;
        }
        file->notify_epoll();
        it = next;
        continue;
    }
    for (auto it = exclusive_epfiles.begin(); it != exclusive_epfiles.end(); ) {
        auto next = std::next(it);
        std::shared_ptr<EpollFile> file = it->second.lock();
        if (!file) {
            exclusive_epfiles.erase(it);
            it = next;
            continue;
        }
        file->notify_epoll();
        break;
    }
}

int EpollFile::get_events(VThread *vthread, struct epoll_event *events, int maxevents) {
    /*
    MM *mm = vthread->get_vprocess()->get_mm();
    static thread_local std::vector<struct epoll_event> events_;
    try {
        events_.resize(maxevents);
    } catch (std::bad_alloc &e) {
        return -ENOMEM;
    }
    int n = ::epoll_wait(monitor_file.fd, events_.data(), maxevents, 0);
    if (n == -1) {
        return -errno;
    }
    int m = 0;
    if (n < maxevents) {
        m = get_virtual_events(vthread, events_.data() + n, maxevents - n);
    }
    //if (n > 0 && m > 0) {
    //    std::sort(events_.begin(), events_.begin() + n,
    //        [] (const struct epoll_event &ev1, const struct epoll_event &ev2) {
    //            return ev1.data.u64 < ev2.data.u64;
    //        });
    //    std::sort(events_.begin() + n, events_.begin() + n + m,
    //        [] (const struct epoll_event &ev1, const struct epoll_event &ev2) {
    //            return ev1.data.u64 < ev2.data.u64;
    //        });
    //    int i = 0, j = 0, k = 0;
    //    while (i < n && j < m) {
    //        uint64_t d1 = events_[i].data.u64;
    //        uint64_t d2 = events_[n + j].data.u64;
    //        if (d2 < d1) {
    //            events_[n + k] = events_[n + j];
    //            ++k;
    //            ++j;
    //        } else if (d2 == d1) {
    //            events_[i].events |= events_[n + j].events;
    //            ++j;
    //        } else {
    //            ++i;
    //        }
    //    }
    //    if (j < m) {
    //        int remain = m - j;
    //        memmove(&events_[n + k], &events_[n + j], remain * sizeof(struct epoll_event));
    //        k += remain;
    //    }
    //    n += k;
    //} else if (m > 0) {
    //    n = m;
    //}
    n += m;
    if (n > 0) {
        try {
            mm->copy_to_sandbox(events, events_.data(), sizeof(struct epoll_event) * n);
        } catch (FaultException &e) {
            return -EFAULT;
        }
    }
    return n;
    */

    MM *mm = vthread->get_vprocess()->get_mm();
    if (maxevents < 0) {
        return -EINVAL;
    } else if (maxevents == 0) {
        return 0;
    }
    if (!mm->check_memory_range((uintptr_t)events, sizeof(struct epoll_event) * maxevents)) {
        return -EFAULT;
    }
    int n = 0;
    if (real_files.size()) {
        n = ::epoll_wait(monitor_file.fd, events, maxevents, 0);
    }
    if (n == -1) {
        return -errno;
    }
    int m = 0;
    if (n < maxevents && iow_files.size()) {
        m = iow_fd.iow->epoll_get_events(vthread, iow_fd, events + n, maxevents - n);
        if (m < 0) {
            return m;
        }
    }
    n += m;
    m = 0;
    if (n < maxevents && !pending_events.empty()) {
        try {
            mm->run_catch_fault(events, sizeof(struct epoll_event) * maxevents, [&] {
                m = get_virtual_events(vthread, events + n, maxevents - n);
            });
        } catch (FaultException &e) {
            return -EFAULT;
        }
    }
    n += m;
    return n;
}

int EpollFile::get_virtual_events(VThread *vthread, struct epoll_event *events, int maxevents) {
    if (pending_events.empty()) {
        return 0;
    }
    int n = 0;
    for (auto it = pending_events.begin(); it != pending_events.end() && n < maxevents; ) {
        auto next = std::next(it);
        File *f = *it;
        auto it2 = files.find(f);
        if (it2 == files.end()) {
            pending_events.erase(it);
            it = next;
            continue;
        }
        Entry &e = it2->second;
        std::shared_ptr<File> file = e.file.lock();
        if (!file) {
            files.erase(it2);
            pending_events.erase(it);
            it = next;
            continue;
        }
        uint32_t revents = 0;
        if (e.event.events & EPOLLET) {
            revents = e.revents;
            e.revents = 0;
        } else {
            revents = file->poll(vthread, e.event.events);
            e.revents = revents;
        }
        //printf("revents: %lx %x %x\n", e.event.data.u64, revents, e.event.events);
        if (revents) {
            events[n].data = e.event.data;
            events[n].events = revents;
            ++n;
        }
        if (e.event.events & EPOLLONESHOT) {
            files.erase(it2);
            pending_events.erase(it);
            it = next;
            continue;
        }
        if (e.revents == 0) {
            pending_events.erase(it);
        }
        it = next;
    }
    return n;
}

int EpollFile::epoll_wait(VThread *vthread, int epfd, struct epoll_event *events,
                          int maxevents, struct __kernel_timespec *ts) {
    VProcess *vprocess = vthread->get_vprocess();
    std::shared_ptr<File> file = vprocess->get_file_table()->get_file(epfd);
    if (!file) {
        return -EBADF;
    }
    EpollFile *epfile = dynamic_cast<EpollFile *>(file.get());
    if (!epfile) {
        return -EINVAL;
    }
    return epfile->wait(vthread, epfd, events, maxevents, ts);
}

int EpollFile::poll_once(VThread *vthread,
                         struct pollfd *fds, int nfds,
                         const std::shared_ptr<File> &only_real_file,
                         int only_real_file_fd,
                         uint32_t only_real_file_events) {
    static thread_local std::vector<struct epoll_event> events;
    static thread_local std::unordered_map<int, int> evmap;
    try {
        events.resize(nfds);
    } catch (std::bad_alloc &e) {
        return -ENOMEM;
    }
    int n = 0;
    if (monitor_file.fd != -1) {
        n = ::epoll_wait(monitor_file.fd, events.data(), nfds, 0);
    } else if (only_real_file) {
        struct pollfd fd;
        fd.fd = only_real_file->get_monitor_fd();
        fd.events = only_real_file_events;
        n = ::poll(&fd, 1, 0);
        if (n < 0) {
            n = 0;
        } else if (n > 0) {
            events[0].data.fd = only_real_file_fd;
            events[0].events = fd.revents;
        }
    }
    if (n == -1) {
        return -errno;
    }
    int m = 0;
    if (n < nfds && iow_files.size()) {
        m = iow_fd.iow->epoll_get_events(vthread, iow_fd, events.data() + n, nfds - n);
        if (m < 0) {
            return m;
        }
    }
    n += m;
    m = 0;
    if (n < nfds && !pending_events.empty()) {
        m = get_virtual_events(vthread, events.data() + n, nfds - n);
    }
    n += m;
    if (n == 0) {
        return 0;
    }
    evmap.clear();
    try {
        for (int i = 0; i < n; ++i) {
            evmap[events[i].data.fd] = events[i].events;
        }
    } catch (std::bad_alloc &e) {
        return -ENOMEM;
    }
    int count = 0;
    for (int i = 0; i < nfds; ++i) {
        int ffd = fds[i].fd;
        auto it = evmap.find(ffd);
        if (it != evmap.end()) {
            fds[i].revents = it->second;
            ++count;
        } else {
            fds[i].revents = 0;
        }
    }
    return count;

}

int EpollFile::poll(VThread *vthread, struct pollfd *fds, nfds_t nfds, struct __kernel_timespec *ts) {
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    std::vector<struct pollfd> fds_;
    std::shared_ptr<Task> task = Executor::get_current_task();
    Task::WaitResult wq_res;

    struct timespec start_ts, end_ts;
    bool has_zero_timeout = ts && ts->tv_sec == 0 && ts->tv_nsec == 0;
    bool has_nonzero_timeout = ts && (ts->tv_sec != 0 || ts->tv_nsec != 0);
    if (has_nonzero_timeout) {
        ::clock_gettime(CLOCK_MONOTONIC, &start_ts);
    }

    try {
        fds_.resize(nfds);
        mm->copy_from_sandbox(fds_.data(), fds, sizeof(struct pollfd) * nfds);
    } catch (std::bad_alloc &e) {
        return -ENOMEM;
    } catch (FaultException &e) {
        return -EFAULT;
    }

    std::shared_ptr<EpollFile> epfile;
    std::shared_ptr<File> only_real_file;
    int only_real_file_fd;
    uint32_t only_real_file_events = 0;
    int res = epoll_from_poll(vthread, fds_.data(), nfds, epfile,
                              only_real_file, only_real_file_fd, only_real_file_events);
    if (res < 0) {
        return res;
    }

    std::unique_lock lock(epfile->mutex);

    res = epfile->poll_once(vthread, fds_.data(),
                            nfds, only_real_file, only_real_file_fd, only_real_file_events);

    if (res != 0 || has_zero_timeout) {
        goto final;
    }

    if (only_real_file) {
        Executor::get_current_executor()->get_eq().
            add_task_poll_timeout(epfile->wq, task, only_real_file->get_monitor_fd(),
                                  only_real_file_events, ts, 0, -1);
    } else {
        Executor::get_current_executor()->get_eq().
            add_task_poll_timeout(epfile->wq, task, epfile->get_monitor_fd(), EPOLLIN, ts, 0, -1);
    }
    lock.unlock();
    Executor::block();
    lock.lock();
    wq_res = task->wq_res;
    if (wq_res.from_signal) {
        res = -EINTR;
    } else {
        res = epfile->poll_once(vthread, fds_.data(), nfds, only_real_file, only_real_file_fd,
                                only_real_file_events);
    }

    if (has_nonzero_timeout) {
        ::clock_gettime(CLOCK_MONOTONIC, &end_ts);
        uint64_t t1 = end_ts.tv_sec * 1000000000 + end_ts.tv_nsec -
            (start_ts.tv_sec * 1000000000 + start_ts.tv_nsec);
        uint64_t t2 = ts->tv_sec * 1000000000 + ts->tv_nsec;
        uint64_t diff = t1 >= t2 ? 0 : t2 - t1;
        ts->tv_sec = diff / 1000000000;
        ts->tv_nsec = diff % 1000000000;
    }
final:
    if (res > 0) {
        try {
            mm->copy_to_sandbox(fds, fds_.data(), sizeof(struct pollfd) * res);
        } catch (FaultException &e) {
            return -EFAULT;
        }
    }
    return res;
}

int EpollFile::select_once(VThread *vthread, int nfds,
                            fd_set *rfds, fd_set *wfds, fd_set *efds,
                            const fd_set *orfds, const fd_set *owfds, const fd_set *oefds,
                            const std::shared_ptr<File> &only_real_file, uint32_t only_real_file_events) {
    static thread_local std::vector<struct epoll_event> events;
    try {
        events.resize(nfds);
    } catch (std::bad_alloc &e) {
        return -ENOMEM;
    }
    int n = 0;
    if (monitor_file.fd != -1) {
        n = ::epoll_wait(monitor_file.fd, events.data(), nfds, 0);
    } else if (only_real_file) {
        struct pollfd fd;
        fd.fd = only_real_file->get_monitor_fd();
        fd.events = only_real_file_events;
        n = ::poll(&fd, 1, 0);
        if (n < 0) {
            n = 0;
        } else if (n > 0) {
            events[0].data.fd = fd.fd;
            events[0].events = fd.revents;
        }
    }
    if (n == -1) {
        return -errno;
    }
    int m = 0;
    if (n < nfds && iow_files.size()) {
        m = iow_fd.iow->epoll_get_events(vthread, iow_fd, events.data() + n, nfds - n);
        if (m < 0) {
            return m;
        }
    }
    n += m;
    m = 0;
    if (n < nfds && !pending_events.empty()) {
        m = get_virtual_events(vthread, events.data() + n, nfds - n);
    }
    n += m;
    if (n == 0) {
        return 0;
    }
    int count = 0;
    if (rfds) {
        memset(rfds, 0, sizeof(fd_set));
    }
    if (wfds) {
        memset(wfds, 0, sizeof(fd_set));
    }
    if (efds) {
        memset(efds, 0, sizeof(fd_set));
    }
    for (int i = 0; i < n; ++i) {
        int ffd = events[i].data.fd;
        int ev = events[i].events;
        if (rfds && FD_ISSET(ffd, orfds) && (ev & EPOLLIN)) {
            FD_SET(ffd, rfds);
            ++count;
        }
        if (wfds && FD_ISSET(ffd, owfds) && (ev & EPOLLOUT)) {
            FD_SET(ffd, wfds);
            ++count;
        }
        if (efds && FD_ISSET(ffd, oefds) && (ev & EPOLLERR)) {
            FD_SET(ffd, efds);
            ++count;
        }
    }
    return count;
}

int EpollFile::select(VThread *vthread, int nfds, fd_set *rfds, fd_set *wfds,
                      fd_set *efds, struct __kernel_timespec *ts) {
    MM *mm = vthread->get_vprocess()->get_mm();
    std::shared_ptr<Task> task = Executor::get_current_task();
    Task::WaitResult wq_res;

    struct timespec start_ts, end_ts;
    bool has_nonzero_timeout = ts && (ts->tv_sec != 0 || ts->tv_nsec != 0);
    if (has_nonzero_timeout) {
        ::clock_gettime(CLOCK_MONOTONIC, &start_ts);
    }

    fd_set rfds_, wfds_, efds_;
    fd_set *prfds = nullptr, *pwfds = nullptr, *pefds = nullptr;
    try {
        if (rfds) {
            mm->copy_from_sandbox(&rfds_, rfds, sizeof(fd_set));
            prfds = &rfds_;
        }
        if (wfds) {
            mm->copy_from_sandbox(&wfds_, wfds, sizeof(fd_set));
            pwfds = &wfds_;
        }
        if (efds) {
            mm->copy_from_sandbox(&efds_, efds, sizeof(fd_set));
            pefds = &efds_;
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }

    std::shared_ptr<EpollFile> epfile;
    std::shared_ptr<File> only_real_file;
    int only_real_file_fd;
    uint32_t only_real_file_events = 0;
    int res = epoll_from_select(vthread, nfds, prfds, pwfds, pefds, epfile,
                                only_real_file, only_real_file_fd, only_real_file_events);
    if (res < 0) {
        return res;
    }

    std::unique_lock lock(epfile->mutex);
    fd_set orfds, owfds, oefds; 
    if (prfds) {
        memcpy(&orfds, prfds, sizeof(fd_set));
    }
    if (pwfds) {
        memcpy(&owfds, pwfds, sizeof(fd_set));
    }
    if (pefds) {
        memcpy(&oefds, pefds, sizeof(fd_set));
    }
    res = epfile->select_once(vthread, nfds, prfds, pwfds, pefds, &orfds, &owfds, &oefds,
                           only_real_file, only_real_file_events);
    if (res != 0 || (ts && !has_nonzero_timeout)) {
        goto final;
    }

    if (only_real_file) {
        Executor::get_current_executor()->get_eq().
            add_task_poll_timeout(epfile->wq, task, only_real_file->get_monitor_fd(),
                                  only_real_file_events, ts, 0, -1);
    } else {
        Executor::get_current_executor()->get_eq().
            add_task_poll_timeout(epfile->wq, task, epfile->get_monitor_fd(), EPOLLIN, ts, 0, -1);
    }
    lock.unlock();
    Executor::block();
    lock.lock();
    wq_res = task->wq_res;
    if (wq_res.from_signal) {
        res = -EINTR;
    } else {
        res = epfile->select_once(vthread,nfds, prfds, pwfds, pefds, &orfds, &owfds, &oefds,
                                  only_real_file, only_real_file_events);
    }
    if (has_nonzero_timeout) {
        ::clock_gettime(CLOCK_MONOTONIC, &end_ts);
        uint64_t t1 = end_ts.tv_sec * 1000000000 + end_ts.tv_nsec -
            (start_ts.tv_sec * 1000000000 + start_ts.tv_nsec);
        uint64_t t2 = ts->tv_sec * 1000000000 + ts->tv_nsec;
        uint64_t diff = t1 >= t2 ? 0 : t2 - t1;
        ts->tv_sec = diff / 1000000000;
        ts->tv_nsec = diff % 1000000000;
    }
final:
    if (res > 0) {
        try {
            if (rfds) {
                mm->copy_to_sandbox(rfds, prfds, sizeof(fd_set));
            }
            if (wfds) {
                mm->copy_to_sandbox(wfds, pwfds, sizeof(fd_set));
            }
            if (efds) {
                mm->copy_from_sandbox(efds, pefds, sizeof(fd_set));
            }
        } catch (FaultException &e) {
            return -EFAULT;
        }
    }
    return res;
}

long SyscallHandlers::epoll_create(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    long new_args[6] = {0};
    return epoll_create1(vthread, sysno, new_args, info);
}

long SyscallHandlers::epoll_create1(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    VProcess *vprocess = vthread->get_vprocess();
    USwitchContext *ucontext = vprocess->get_ucontext();
    int res;
    ucontext->run_on_behalf_of([&] {
        res = ::epoll_create1(0);
        if (res == -1) {
            res = -errno;
        }
    });
    if (res < 0) {
        return res;
    }
    FileDescriptor fd(ucontext, res);
    MonitorFile mf;
    mf.fd = ucontext->get_file(fd.fd);
    if (mf.fd == -1) {
        return -errno;
    }
    std::shared_ptr<EpollFile> file = std::make_shared<EpollFile>(ucontext, fd.fd);
    file->set_monitor_fd(mf);
    IOWorker *iow = Runtime::get()->get_tm()->get_ioworker();
    if (iow) {
        IOWorkerEpollFd iowfd;
        int res = iow->create_epoll(iowfd);
        if (res < 0) {
            return res;
        }
        file->set_iow_fd(iowfd);
    }
    return vprocess->get_file_table()->add_file(vthread, fd, file);
}

long SyscallHandlers::epoll_ctl(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int epfd = args[0];
    int op = args[1];
    int fd = args[2];
    if (op != EPOLL_CTL_ADD && op != EPOLL_CTL_MOD && op != EPOLL_CTL_DEL) {
        return -EINVAL;
    }
    struct epoll_event *pevent = (struct epoll_event *)args[3];
    struct epoll_event event;
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    FileTable *files = vprocess->get_file_table();
    if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) {
        try {
            mm->copy_from_sandbox(&event, pevent, sizeof(struct epoll_event));
        } catch (FaultException &e) {
            return -EFAULT;
        }
    }
    std::shared_ptr<File> epf = files->get_file(epfd);
    std::shared_ptr<File> file = files->get_file(fd);
    if (!epf) {
        return -EBADF;
    }
    EpollFile *epfile = dynamic_cast<EpollFile *>(epf.get());
    if (!epfile) {
        return -EINVAL;
    }
    if (!file) {
        return vthread->invoke_syscall(sysno, args);
    }
    //int res1 = 0;
    //if (file->get_cap() & File::Real) {
    //    res1 = vthread->invoke_syscall(sysno, args);
    //}
    //if (res1 < 0) {
    //    return res1;
    //}
    std::unique_lock lock(epfile->get_mutex());
    uint32_t cap = file->get_cap();
    if (cap & File::OverlayReal) {
        epfile->handle_overlay_real_file(vthread, epfd, fd, file);
    }
    if (cap & File::OverlayIOW) {
        epfile->handle_overlay_iow_file(vthread, epfd, fd, file);
    }
    int res2;
    if (op == EPOLL_CTL_ADD) {
        res2 = epfile->add_file(vthread, file, &event, lock);
    } else if (op == EPOLL_CTL_MOD) {
        res2 = epfile->mod_file(vthread, file, &event, lock);
    } else {
        res2 = epfile->del_file(vthread, file, lock);
    }

    return res2;
}

long SyscallHandlers::epoll_wait(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int epfd = args[0];
    struct epoll_event *events = (struct epoll_event *)args[1];
    int maxevents = args[2];
    long timeout = args[3];
    struct __kernel_timespec ts;
    if (timeout != -1) {
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000000;
    }
    return EpollFile::epoll_wait(vthread, epfd, events, maxevents, timeout == -1 ? nullptr : &ts);
}

long SyscallHandlers::epoll_pwait(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    uint64_t *pmask = (uint64_t *)args[4];
    if (!pmask) {
        return epoll_wait(vthread, SYS_epoll_wait, args, info);
    }
    uint64_t mask;
    try {
        mask = vthread->get_vprocess()->get_mm()->get_sandbox<uint64_t>(pmask);
    } catch (FaultException &e) {
        return -EFAULT;
    }
    uint64_t old_mask;
    vthread->sigprocmask(SIG_SETMASK, &mask, &old_mask);
    long res = epoll_wait(vthread, SYS_epoll_wait, args, info);
    vthread->sigprocmask(SIG_SETMASK, &old_mask, nullptr);
    return res;
}

long SyscallHandlers::epoll_pwait2(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int epfd = args[0];
    struct epoll_event *events = (struct epoll_event *)args[1];
    int maxevents = args[2];
    const struct __kernel_timespec *pts = (const struct __kernel_timespec *)args[3];
    uint64_t *pmask = (uint64_t *)args[4];
    struct __kernel_timespec ts;
    uint64_t mask;
    MM *mm  = vthread->get_vprocess()->get_mm();

    try {
        if (pmask) {
            mask = mm->get_sandbox<uint64_t>(pmask);
        }
        if (pts) {
            mm->copy_from_sandbox(&ts, pts, sizeof(struct __kernel_timespec));
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }
    if (pts && (ts.tv_nsec > 999999999 || ts.tv_nsec < 0)) {
        return -EINVAL;
    }
    uint64_t old_mask;
    if (pmask) {
        vthread->sigprocmask(SIG_SETMASK, &mask, &old_mask);
    }
    int res = EpollFile::epoll_wait(vthread, epfd, events, maxevents, pts ? &ts : nullptr);
    if (pmask) {
        vthread->sigprocmask(SIG_SETMASK, &old_mask, nullptr);
    }
    return res;
}

struct PollRestartFunction {
    struct pollfd *fds;
    nfds_t nfds;
    int timeout;
    long operator()(VThread *vthread) {
        const long args[6] = {(long)fds, (long)nfds, timeout};
        return SyscallHandlers::poll(vthread, SYS_poll, args, nullptr);
    }
};

long SyscallHandlers::poll(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    struct pollfd *fds = (struct pollfd *)args[0];
    nfds_t nfds = args[1];
    int timeout = args[2];

    struct __kernel_timespec ts;
    if (timeout != -1) {
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000000;
    }
    int res;
    try {
        res = EpollFile::poll(vthread, fds, nfds, timeout == -1 ? nullptr : &ts);
    } catch (std::bad_alloc &e) {
        return -ENOMEM;
    }
    if (res == -EINTR) {
        if (timeout == -1) {
            vthread->set_restart();
        } else {
            PollRestartFunction func;
            func.fds = fds;
            func.nfds = nfds;
            func.timeout = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
            vthread->set_restart(func);
        }
    }

    return res;
}

long SyscallHandlers::ppoll(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    MM *mm = vthread->get_vprocess()->get_mm();
    struct pollfd *fds = (struct pollfd *)args[0];
    nfds_t nfds = args[1];
    struct __kernel_timespec *pts = (struct __kernel_timespec *)args[2];
    uint64_t *pmask = (uint64_t *)args[3];
    struct __kernel_timespec ts;
    uint64_t mask;
    try {
        if (pmask) {
            mask = mm->get_sandbox<uint64_t>(pmask);
        }
        if (pts) {
            mm->copy_from_sandbox(&ts, pts, sizeof(struct __kernel_timespec));
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }

    uint64_t old_mask;
    if (pmask) {
        vthread->sigprocmask(SIG_SETMASK, &mask, &old_mask);
    }

    if (pts && (ts.tv_nsec > 999999999 || ts.tv_nsec < 0)) {
        return -EINVAL;
    }

    int res;
    try {
        res = EpollFile::poll(vthread, fds, nfds, pts ? &ts : nullptr);
    } catch (std::bad_alloc &e) {
        res = -ENOMEM;
    }

    if (pmask) {
        vthread->sigprocmask(SIG_SETMASK, &old_mask, nullptr);
    }
    try {
        if (pts) {
            mm->copy_to_sandbox(pts, &ts, sizeof(struct __kernel_timespec));
        }
    } catch (FaultException &e) {
        return res;
    }
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

long SyscallHandlers::select(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    MM *mm = vthread->get_vprocess()->get_mm();
    int nfds = args[0];
    fd_set *rfds = (fd_set *)args[1];
    fd_set *wfds = (fd_set *)args[2];
    fd_set *efds = (fd_set *)args[3];
    struct __kernel_old_timeval *ptv = (struct __kernel_old_timeval *)args[4];
    struct __kernel_old_timeval tv;
    struct __kernel_timespec ts;
    try {
        if (ptv) {
            mm->copy_from_sandbox(&tv, ptv, sizeof(struct __kernel_old_timeval));
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }
    if (ptv && (tv.tv_usec > 999999 || tv.tv_usec < 0)) {
        return -EINVAL;
    }
    if (ptv) {
        ts.tv_sec = tv.tv_sec;
        ts.tv_nsec = tv.tv_usec * 1000;
    }

    int res;
    try {
        res = EpollFile::select(vthread, nfds, rfds, wfds, efds, ptv ? &ts : nullptr);
    } catch (std::bad_alloc &e) {
        res = -ENOMEM;
    }

    try {
        if (ptv) {
            tv.tv_sec = ts.tv_sec;
            tv.tv_usec = ts.tv_nsec / 1000;
            mm->copy_to_sandbox(ptv, &tv, sizeof(struct __kernel_old_timeval));
        }
    } catch (FaultException &e) {
        return res;
    }
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

long SyscallHandlers::pselect6(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    MM *mm = vthread->get_vprocess()->get_mm();
    int nfds = args[0];
    fd_set *rfds = (fd_set *)args[1];
    fd_set *wfds = (fd_set *)args[2];
    fd_set *efds = (fd_set *)args[3];
    struct __kernel_timespec *pts = (struct __kernel_timespec *)args[4];
    uint64_t *pmask = (uint64_t *)args[5];
    struct __kernel_timespec ts;
    uint64_t mask;
    try {
        if (pmask) {
            mask = mm->get_sandbox<uint64_t>(pmask);
        }
        if (pts) {
            mm->copy_from_sandbox(&ts, pts, sizeof(struct __kernel_timespec));
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }
    if (pts && (ts.tv_nsec > 999999999 || ts.tv_nsec < 0)) {
        return -EINVAL;
    }

    uint64_t old_mask;
    if (pmask) {
        vthread->sigprocmask(SIG_SETMASK, &mask, &old_mask);
    }

    int res;
    try {
        res = EpollFile::select(vthread, nfds, rfds, wfds, efds, pts ? &ts : nullptr);
    } catch (std::bad_alloc &e) {
        res = -ENOMEM;
    }

    if (pmask) {
        vthread->sigprocmask(SIG_SETMASK, &old_mask, nullptr);
    }
    try {
        if (pts) {
            mm->copy_to_sandbox(pts, &ts, sizeof(struct __kernel_timespec));
        }
    } catch (FaultException &e) {
        return res;
    }
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}
