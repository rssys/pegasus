#pragma once
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <sys/epoll.h>
#include "file.h"
#include "ioworker.h"
#include "lock.h"
#include "monitor.h"
#include "ucontext.h"

namespace pegasus {
class EpollFile : public File {
public:
    EpollFile(USwitchContext *ucontext, int fd);
    virtual ~EpollFile();
    virtual uint32_t poll(VThread *vthread, uint32_t events);
    virtual void notify(uint32_t events, std::unique_lock<SpinLock> &lock);
    virtual uint32_t get_cap();
    void notify(File *file, uint32_t events);
    void notify(const std::unordered_map<File *, uint32_t> &notify_files);
    int add_file(VThread *vthread, const std::shared_ptr<File> &file,
                 const struct epoll_event *event, std::unique_lock<SpinLock> &lock);
    int mod_file(VThread *vthread, const std::shared_ptr<File> &file,
                 const struct epoll_event *event, std::unique_lock<SpinLock> &lock);
    int del_file(VThread *vthread, const std::shared_ptr<File> &file,
                 std::unique_lock<SpinLock> &lock);
    void del_file_on_close(File *file);
    int wait(VThread *vthread, int epfd, struct epoll_event *events, int maxevents, struct __kernel_timespec *ts);
    void handle_overlay_real_file(VThread *vthread, int epfd, int fd, const std::shared_ptr<File> &file);
    void handle_overlay_iow_file(VThread *vthread, int epfd, int fd, const std::shared_ptr<File> &file);
    static int epoll_wait(VThread *vthread, int epfd, struct epoll_event *events,
                          int maxevents, struct __kernel_timespec *ts);
    static int poll(VThread *vthread, struct pollfd *fds, nfds_t nfds, struct __kernel_timespec *ts);
    static int select(VThread *vthread, int nfds, fd_set *rfds, fd_set *wfds,
                      fd_set *efds, struct __kernel_timespec *ts);
    inline void set_iow_fd(IOWorkerEpollFd &iow_fd_) {
        iow_fd = std::move(iow_fd_);
    }
private:
    struct Entry {
        std::weak_ptr<File> file;
        struct epoll_event event;
        uint32_t revents;
    };
    int add_epoll_file(VThread *vthread, const std::shared_ptr<File> &file, const struct epoll_event *event);
    int mod_epoll_file(VThread *vthread, const std::shared_ptr<File> &file, const struct epoll_event *event);
    int del_epoll_file(File *file);
    bool has_loop(EpollFile *file, int max_depth);
    void notify_epoll();
    int get_events(VThread *vthread, struct epoll_event *events, int maxevents);
    int get_virtual_events(VThread *vthread, struct epoll_event *events, int maxevents);
    int poll_once(VThread *vthread, struct pollfd *fds, int nfds,
                  const std::shared_ptr<File> &only_real_file, int only_real_file_fd,
                  uint32_t only_real_file_events);
    int select_once(VThread *vthread, int nfds,
                    fd_set *rfds, fd_set *wfds, fd_set *efds,
                    const fd_set *orfds, const fd_set *owfds, const fd_set *oefds,
                    const std::shared_ptr<File> &only_real_file, uint32_t only_real_file_events);
    inline bool is_epoll_file(File *file) {
        return dynamic_cast<EpollFile *>(file);
    }
    inline std::unordered_map<File *, Entry>::iterator find_files(File *f) {
        auto it = files.find(f);
        if (it == files.end()) {
            return it;
        }
        if (it->second.file.expired()) {
            files.erase(it);
            return files.end();
        }
        return it;
    }

    std::shared_ptr<WaitQueue> wq;
    std::unordered_map<File *, Entry> files;
    std::unordered_set<File *> pending_events;
    std::unordered_set<File *> real_files;
    std::unordered_set<File *> iow_files;
    std::unordered_set<int> overlay_real_files;
    std::unordered_set<int> overlay_iow_files;
    IOWorkerEpollFd iow_fd;
};
}
