#include <mutex>
#include <shared_mutex>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <sys/sendfile.h>
#include "pegasus/epoll.h"
#include "pegasus/event.h"
#include "pegasus/file.h"
#include "pegasus/lock.h"
#include "pegasus/mm.h"
#include "pegasus/monitor.h"
#include "pegasus/runtime.h"
#include "pegasus/sched.h"
#include "pegasus/stat.h"
#include "pegasus/syscall.h"
#include "pegasus/uswitch.h"
#include "pegasus/util.h"
#include "pegasus/network/network.h"
#include "pegasus/network/socket.h"

using namespace pegasus;

struct FileCloseTasklet {
    std::unordered_map<EpollFile *, std::weak_ptr<EpollFile>> watching_epfiles;
    std::unordered_map<EpollFile *, std::weak_ptr<EpollFile>> exclusive_epfiles;
    File *file;
    void operator()() {
        for (auto &&f : watching_epfiles) {
            std::shared_ptr<EpollFile> epfile = f.second.lock();
            if (epfile) {
                epfile->del_file_on_close(file);
            }
        }
        for (auto &&f : exclusive_epfiles) {
            std::shared_ptr<EpollFile> epfile = f.second.lock();
            if (epfile) {
                epfile->del_file_on_close(file);
            }
        }
    }
};

File::File(USwitchContext *ucontext, int fd) {
}

File::~File() {
    if (watching_epfiles.size() || exclusive_epfiles.size()) {
        try {
            GET_PER_CPU_PRIV(cwm)->add(FileCloseTasklet{
                std::move(watching_epfiles), std::move(exclusive_epfiles), this
            });
        } catch (...) {
        }
    }
    
}

ssize_t File::read(VThread *vthread, int fd, void *buf, size_t len) {
    return -EBADF;
}

ssize_t File::write(VThread *vthread, int fd, const void *buf, size_t len) {
    return -EBADF;
}

ssize_t File::readv(VThread *vthread, int fd, const struct iovec *iov, int iovcnt) {
    return -EBADF;
}

ssize_t File::writev(VThread *vthread, int fd, const struct iovec *iov, int iovcnt) {
    return -EBADF;
}

int File::fcntl(VThread *vthread, int fd, const long *args) {
    return -EBADF;
}

int File::ioctl(VThread *vthread, int fd, const long *args) {
    return -EBADF;
}

ssize_t File::sendfile(VThread *vthread, int fd, int in_fd, off_t *offset, size_t len) {
    return -EBADF;
}

uint32_t File::poll(VThread *vthread, uint32_t events) {
    return 0;
}

void File::notify(uint32_t events, std::unique_lock<SpinLock> &lock) {
    static thread_local std::vector<std::shared_ptr<EpollFile>> epfiles;
    epfiles.clear();
    for (auto it = watching_epfiles.begin(); it != watching_epfiles.end(); ) {
        auto next = std::next(it);
        std::shared_ptr<EpollFile> file = it->second.lock();
        if (!file) {
            watching_epfiles.erase(it);
            it = next;
            continue;
        }
        epfiles.push_back(file);
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
        epfiles.push_back(file);
        break;
    }

    lock.unlock();

    for (auto &&file : epfiles) {
        file->notify(this, events);
    }
}

void File::notify_batch(uint32_t events, std::unique_lock<SpinLock> &lock,
                        BatchNotifyState &state) {
    for (auto it = watching_epfiles.begin(); it != watching_epfiles.end(); ) {
        auto next = std::next(it);
        std::shared_ptr<EpollFile> file = it->second.lock();
        if (!file) {
            watching_epfiles.erase(it);
            it = next;
            continue;
        }
        state.add(file, this, events);
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
        state.add(file, this, events);
        break;
    }

    lock.unlock();
}

uint32_t File::get_cap() {
    return 0;
}

std::shared_ptr<File> File::clone(const FileDescriptorReference &fdr) {
    return shared_from_this();
}

int File::create_monitor_fd(const FileDescriptorReference &fd) {
    std::lock_guard lock(mutex);
    if (fd.fd == -1) {
        return -1;
    }
    if (monitor_file.fd != -1) {
        return monitor_file.fd;
    }
    if (!fd.ucontext) {
        return -1;
    }
    int pfd = fd.ucontext->get_file(fd.fd);
    if (pfd < 0) {
        return -1;
    }
    monitor_file.fd = pfd;
    return pfd;
}

void BatchNotifyState::add(const std::shared_ptr<EpollFile> &epfile, File *file, uint32_t events) {
    auto it = epfiles.find(epfile.get());
    if (it == epfiles.end()) {
        epfiles.emplace(epfile.get(), Item {epfile, {{file, events}}});
    } else {
        it->second.events[file] |= events;
    }
}

void BatchNotifyState::finish() {
    for (auto &&it : epfiles) {
        it.first->notify(it.second.events);
    }
    clear();
}

void BatchNotifyState::clear() {
    epfiles.clear();
}

PassthroughFile::PassthroughFile(USwitchContext *ucontext, int fd)
    : File(ucontext, fd) {

}

PassthroughFile::~PassthroughFile() {

}

ssize_t PassthroughFile::read(VThread *vthread, int fd, void *buf, size_t len) {
    long args[6] = {fd, (long)buf, (long)len};
    return vthread->invoke_syscall(SYS_read, args);
}

ssize_t PassthroughFile::write(VThread *vthread, int fd, const void *buf, size_t len) {
    long args[6] = {fd, (long)buf, (long)len};
    return vthread->invoke_syscall(SYS_write, args);
}

ssize_t PassthroughFile::readv(VThread *vthread, int fd, const struct iovec *iov, int iovcnt) {
    long args[6] = {fd, (long)iov, iovcnt};
    return vthread->invoke_syscall(SYS_readv, args);
}

ssize_t PassthroughFile::writev(VThread *vthread, int fd, const struct iovec *iov, int iovcnt) {
    long args[6] = {fd, (long)iov, iovcnt};
    return vthread->invoke_syscall(SYS_writev, args);
}

int PassthroughFile::fcntl(VThread *vthread, int fd, const long *args) {
    return vthread->invoke_syscall(SYS_fcntl, args);
}

int PassthroughFile::ioctl(VThread *vthread, int fd, const long *args) {
    return vthread->invoke_syscall(SYS_ioctl, args);
}

ssize_t PassthroughFile::sendfile(VThread *vthread, int fd, int in_fd, off_t *offset, size_t len) {
    long args[6] = {fd, in_fd, (long)offset, (long)len};
    return vthread->invoke_syscall(SYS_sendfile, args);
}

uint32_t PassthroughFile::get_cap() {
    return Real;
}

NonblockingFile::NonblockingFile(USwitchContext *ucontext, int fd, bool nonblock_)
    : File(ucontext, fd), nonblock(nonblock_) {
    FileDescriptorReference fdr(ucontext, fd);
    create_monitor_fd(fdr);
}

NonblockingFile::~NonblockingFile() {

}

ssize_t NonblockingFile::read(VThread *vthread, int fd, void *buf, size_t len) {
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    USwitchContext *ucontext = vprocess->get_ucontext();
    if (!mm->check_memory_range((uintptr_t)buf, len)) {
        return -EFAULT;
    }
    ssize_t res = ucontext->invoke_fd_syscall(::read, fd, get_monitor_fd(), buf, len);
    if (nonblock_ || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLIN)) {
            res = -EINTR;
            break;
        }
        res = ucontext->invoke_fd_syscall(::read, fd, get_monitor_fd(), buf, len);
        if (res != -EAGAIN && res != -EWOULDBLOCK) {
            break;
        }
    }
out:
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

ssize_t NonblockingFile::write(VThread *vthread, int fd, const void *buf, size_t len) {
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    USwitchContext *ucontext = vprocess->get_ucontext();
    if (!mm->check_memory_range((uintptr_t)buf, len)) {
        return -EFAULT;
    }
    ssize_t res = ucontext->invoke_fd_syscall(::write, fd, get_monitor_fd(), buf, len);
    if (nonblock_ || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLOUT)) {
            res = -EINTR;
            break;
        }
        res = ucontext->invoke_fd_syscall(::write, fd, get_monitor_fd(), buf, len);
        if (res != -EAGAIN && res != -EWOULDBLOCK) {
            break;
        }
    }
out:
    if (res == -EPIPE) {
        siginfo_t si = {};
        si.si_code = SI_KERNEL;
        vthread->send_signal(SIGPIPE, &si);
    }
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

ssize_t NonblockingFile::readv(VThread *vthread, int fd, const struct iovec *iov, int iovcnt) {
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    long args[6] = {fd, (long)iov, iovcnt};
    ssize_t res = vthread->invoke_syscall(SYS_readv, args);
    if (nonblock_ || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLIN)) {
            res = -EINTR;
            break;
        }
        res = vthread->invoke_syscall(SYS_readv, args);
        if (res != -EAGAIN && res != -EWOULDBLOCK) {
            break;
        }
    }
out:
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

ssize_t NonblockingFile::writev(VThread *vthread, int fd, const struct iovec *iov, int iovcnt) {
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    long args[6] = {fd, (long)iov, iovcnt};
    ssize_t res = vthread->invoke_syscall(SYS_writev, args);
    if (nonblock_ || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLOUT)) {
            res = -EINTR;
            break;
        }
        res = vthread->invoke_syscall(SYS_writev, args);
        if (res != -EAGAIN && res != -EWOULDBLOCK) {
            break;
        }
    }
out:
    if (res == -EPIPE) {
        siginfo_t si = {};
        si.si_code = SI_KERNEL;
        vthread->send_signal(SIGPIPE, &si);
    }
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

int NonblockingFile::fcntl(VThread *vthread, int fd, const long *args) {
    int cmd = args[1];
    USwitchContext *ucontext = vthread->get_vprocess()->get_ucontext();
    if (cmd == F_GETFL) {
        int flags;
        ucontext->run_on_behalf_of([&] {
            flags = ::fcntl(fd, F_GETFL);
            if (flags == -1) {
                flags = -errno;
            }
        });
        if (flags < 0) {
            return flags;
        }
        flags &= ~O_NONBLOCK;
        if (nonblock.load(std::memory_order_acquire)) {
            flags |= O_NONBLOCK;
        }
        return flags;
    } else if (cmd == F_SETFL) {
        int flags = args[2];
        bool nonblock_ = flags & O_NONBLOCK;
        flags |= O_NONBLOCK;
        ucontext->run_on_behalf_of([&] {
            flags = ::fcntl(fd, F_SETFL, flags);
            if (flags == -1) {
                flags = -errno;
            }
        });
        if (flags < 0) {
            return flags;
        }
        nonblock.store(nonblock_, std::memory_order_release);
        return 0;
    }
    return vthread->invoke_syscall(SYS_fcntl, args);
}

int NonblockingFile::ioctl(VThread *vthread, int fd, const long *args) {
    if (args[1] == FIONBIO) {
        MM *mm = vthread->get_vprocess()->get_mm();
        int on;
        try {
            on = mm->get_sandbox<int>((void *)args[2]);
        } catch (FaultException &e) {
            return -EFAULT;
        }
        nonblock.store(on, std::memory_order_release);
        return 0;
    }
    return vthread->invoke_syscall(SYS_ioctl, args);
}

ssize_t NonblockingFile::sendfile(VThread *vthread, int fd, int in_fd, off_t *offset, size_t len) {
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    USwitchContext *ucontext = vprocess->get_ucontext();
    FileTable *ft = vprocess->get_file_table();
    if (offset && !mm->check_memory_range((uintptr_t)offset, sizeof(*offset))) {
        return -EFAULT;
    }
    std::shared_ptr<File> in_file = ft->get_file(in_fd);
    int in_fd_m = -1;
    if (in_file) {
        in_fd_m = in_file->get_monitor_fd();
    }
    ssize_t res;
    if (in_fd_m == -1 || ucontext->is_current()) {
        ucontext->run_on_behalf_of([&] {
            res = ::sendfile(fd, in_fd, offset, len);
            if (res < 0) {
                res = -errno;
            }
        });
    } else {
        res = ::sendfile(get_monitor_fd(), in_fd_m, offset, len);
        if (res < 0) {
            res = -errno;
        }
    }
    if (nonblock_ || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLOUT)) {
            res = -EINTR;
            break;
        }
        if (in_fd_m == -1 || ucontext->is_current()) {
            ucontext->run_on_behalf_of([&] {
                res = ::sendfile(fd, in_fd, offset, len);
                if (res < 0) {
                    res = -errno;
                }
            });
        } else {
            res = ::sendfile(get_monitor_fd(), in_fd_m, offset, len);
            if (res < 0) {
                res = -errno;
            }
        }
        if (res != -EAGAIN && res != -EWOULDBLOCK) {
            break;
        }
    }
out:
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;    
}

uint32_t NonblockingFile::get_cap() {
    return Real;
}

bool NonblockingFile::block_until_event(uint32_t events) {
    std::shared_ptr<Task> task = Executor::get_current_task();
    Executor::get_current_executor()->get_eq().add_task_poll_timeout(task, monitor_file.fd, events);
    Executor::block();
    return task->wq_res.from_signal;
}

bool NonblockingFile::block_until_event(uint32_t events, const std::shared_ptr<WaitQueue> &wq,
                                        std::unique_lock<SpinLock> &lock) {
    std::shared_ptr<Task> task = Executor::get_current_task();
    Executor::get_current_executor()->get_eq().add_task_poll_timeout(wq, task, monitor_file.fd, events);
    lock.unlock();
    Executor::block();
    lock.lock();
    return task->wq_res.from_signal;
}

FileTable::FileTable() {
    
}

int FileTable::add_file(VThread *vthread, FileDescriptor &fd, const std::shared_ptr<File> &file) {
    if (fd.fd != -1) {
        std::lock_guard lock(mutex);
        FDFilePair item;
        item.fd = std::move(fd);
        int tmp = item.fd.fd;
        item.file = file;
        FDFilePair *fdp = get_or_alloc(tmp);
        if (!fdp) {
            return -ENOMEM;
        }
        *fdp = std::move(item);
        return tmp;
    }

    USwitchContext *ucontext = vthread->get_vprocess()->get_ucontext();
    fd.ucontext = ucontext;
    fd.fd = ucontext->get_file_from_priv(Runtime::get()->get_placeholder_fd());
    if (fd.fd == -1) {
        return -EMFILE;
    }
    std::lock_guard lock(mutex);
    FDFilePair item;
    item.fd = std::move(fd);
    int tmp = item.fd.fd;
    item.file = file;
    FDFilePair *fdp = get_or_alloc(tmp);
    if (!fdp) {
        return -ENOMEM;
    }
    *fdp = std::move(item);
    return tmp;
}

int FileTable::add_files(VThread *vthread, FDFilePair *new_files, size_t n) {
    USwitchContext *ucontext = vthread->get_vprocess()->get_ucontext();
    for (size_t i = 0; i < n; ++i) {
        FDFilePair &f = new_files[i];
        if (f.fd.fd == -1) {
            f.fd.fd = ucontext->get_file_from_priv(Runtime::get()->get_placeholder_fd());
            if (f.fd.fd == -1) {
                return -EMFILE;
            }
        }
    }
    std::lock_guard lock(mutex);
    size_t i = 0;
    for (i = 0; i < n; ++i) {
        int fd = new_files[i].fd.fd;
        FDFilePair *fdp = get_or_alloc(fd);
        if (!fdp) {
            for (size_t j = 0; j < i; ++j) {
                int fd = files[j].fd.fd;
                std::swap(files[fd], new_files[j]);
            }
            return -ENOMEM;
        }
        std::swap(*fdp, new_files[i]);
    }
    return 0;
}

std::shared_ptr<FileTable> FileTable::clone(USwitchContext *ucontext) {
    std::shared_ptr<FileTable> table = std::make_shared<FileTable>();
    std::shared_lock lock(mutex);
    int nfiles = (int)files.size();
    table->files.resize(nfiles);
    for (int fd = 0; fd < nfiles; ++fd) {
        FDFilePair *fdp = &files[fd];
        if (!fdp || !fdp->file) {
            continue;
        }
        FileDescriptorReference fdr(ucontext, fd);
        std::shared_ptr<File> file_clone = fdp->file->clone(fdr);
        if (!file_clone) {
            ucontext->run_on_behalf_of([&] {
                ::close(fd);
            });
            continue;
        }
        FDFilePair ffp;
        ffp.fd.ucontext = ucontext;
        ffp.fd.fd = fd;
        ffp.file = file_clone;
        table->files[fd] = std::move(ffp);
    }
    return table;
}

int FileTable::dup(VThread *vthread, int oldfd, int newfd, int flags) {
    VProcess *vprocess = vthread->get_vprocess();
    USwitchContext *ucontext = vprocess->get_ucontext();
    std::lock_guard lock(mutex);
    std::shared_ptr<File> oldfile;
    std::shared_ptr<File> newfile;
    if (oldfd < 0 || newfd < 0 || (size_t)oldfd >= files.size()) {
        return -EBADF;
    }
    if ((size_t)oldfd < files.size()) {
        oldfile = files[oldfd].file;
    }
    FDFilePair *new_ffp = nullptr;
    if ((size_t)newfd < files.size()) {
        new_ffp = &files[newfd];
        newfile = new_ffp->file;
    }
    long args[6] = {oldfd, newfd};
    if (!oldfile && !newfile) {
        return vthread->invoke_syscall(SYS_dup2, args);
    }
    if (!oldfile && newfile) {
        int res = vthread->invoke_syscall(SYS_dup2, args);
        if (res < 0) {
            return res;
        }
        new_ffp->reset();
        return newfd;
    }
    if (newfile) {
        int res = vthread->invoke_syscall(SYS_dup2, args);
        if (res < 0) {
            return res;
        }
        new_ffp->file = oldfile;
        return newfd;
    }
    if (!new_ffp) {
        new_ffp = get_or_alloc(newfd);
    }
    if (!new_ffp) {
        return -ENOMEM;
    }
    int res = vthread->invoke_syscall(SYS_dup2, args);
    if (res < 0) {
        new_ffp->reset();
        return res;
    }
    new_ffp->fd.fd = newfd;
    new_ffp->fd.ucontext = ucontext;
    new_ffp->file = oldfile;
    return newfd;
}

int FileTable::close(VThread *vthread, int fd) {
    std::unique_lock lock(mutex);
    if (fd < 0 || (size_t)fd >= files.size()) {
        return -EBADF;
    }
    FDFilePair &ffp = files[fd];
    if (!ffp.file) {
        return -EBADF;
    }
    ffp.reset();
    return 0;
}

int FileTable::close_range(VThread *vthread, int first, int last, int flags) {
    if (last < first || first < 0 || last < 0) {
        return -EINVAL;
    }
    if (flags & CLOSE_RANGE_CLOEXEC) {
        return 0;
    }
    std::unique_lock lock(mutex);
    int begin = first;
    int nfiles = (int)files.size();
    int end = last < nfiles ? last : nfiles;
    for (int fd = begin; fd < end; ++fd) {
        files[fd].reset();
    }
    //if (last - first < files.size()) {
    //    for (int fd = first; fd <= last; ++fd) {
    //        files.erase(fd);
    //    }
    //} else {
    //    for (auto it = files.begin(); it != files.end(); ) {
    //        auto next = std::next(it);
    //        if (it->first >= first && it->first <= last) {
    //            files.erase(it);
    //        }
    //        it = next;
    //    }
    //}
    return 0;
}

static int open_special_stdio(VThread *vthread, const std::string &path, int flags, mode_t mode) {
    int fd = -1;
    if (path == "/dev/stdin") {
        fd = 0;
    } else if (path == "/dev/stdout") {
        fd = 1;
    } else if (path == "/dev/stderr") {
        fd = 2;
    } else {
        return -ENOENT;
    }
    VProcess *vprocess = vthread->get_vprocess();
    USwitchContext *ucontext = vprocess->get_ucontext();
    pid_t tid = vprocess->get_proxy_tid();
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd/%d", tid, fd);
    int proc_fd = open(proc_path, flags, mode);
    if (proc_fd == -1) {
        return -errno;
    }
    fd = ucontext->get_file_from_priv(proc_fd);
    int err = errno;
    close(proc_fd);
    return fd == -1 ? -err : fd;
}

static int open_proc_self_exe(VThread *vthread, int flags, mode_t mode) {
    return -ENOENT;
    //VProcess *vprocess = vthread->get_vprocess();
    //USwitchContext *ucontext = vprocess->get_ucontext();
    //int exe_fd = vprocess->get_exe_file()->fd;
    //std::string path = "/proc/thread-self/fd/" + std::to_string(exe_fd);
    //int new_fd;
    //ucontext->run_with_euidguid([&] {
    //    new_fd = open(path.c_str(), flags, mode);
    //    if (new_fd == -1) {
    //        new_fd = -errno;
    //    }
    //});
    //if (new_fd < 0) {
    //    return new_fd;
    //}
    //int res = ucontext->get_file_from_priv(new_fd);
    //if (res == -1) {
    //    res = -errno;
    //}
    //close(new_fd);
    //return res;
}

static int open_special_procfs(VThread *vthread, const std::string &path, int flags, mode_t mode) {
    if (path == "/proc/self/exe") {
        return open_proc_self_exe(vthread, flags, mode);
    }
    return -ENOENT;
}

static int stat_special_err(VThread *vthread, const std::string &path, struct stat *buf) {
    return -ENOENT;
}

static int stat_proc_self_exe(VThread *vthread, struct stat *pbuf) {
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    int exe_fd = vprocess->get_exe_file()->fd;
    std::string path = "/proc/thread-self/fd/" + std::to_string(exe_fd);
    struct stat buf = {};
    if (stat(path.c_str(), &buf) == -1) {
        return -errno;
    }
    try {
        mm->copy_to_sandbox(pbuf, &buf, sizeof(buf));
    } catch (FaultException &e) {
        return -EFAULT;
    }
    return 0;
}

static int stat_special_procfs(VThread *vthread, const std::string &path, struct stat *pbuf) {
    if (path == "/proc/self/exe") {
        return stat_proc_self_exe(vthread, pbuf);
    }
    return -ENOENT;
}

static ssize_t readlink_special_err(VThread *vthread, const std::string &path, char *buf, size_t size) {
    return -ENOENT;
}

static ssize_t readlink_with_str(VThread *vthread, const std::string &str, char *buf, size_t size) {
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    if (size > str.length()) {
        size = str.length();
    }
    try {
        mm->copy_to_sandbox(buf, str.c_str(), size);
    } catch (FaultException &e) {
        return -EFAULT;
    }
    return size;
}

static ssize_t readlink_special_procfs(VThread *vthread, const std::string &path, char *buf, size_t size) {
    std::string tgid = std::to_string(vthread->get_vprocess()->get_tgid());
    std::string tgid_path = "/proc/" + tgid;
    if (path == "/proc") {
        return -EINVAL;
    } else if (path == "/proc/self") {
        return readlink_with_str(vthread, tgid_path, buf, size);
    } else if (path == tgid_path) {
        return -EINVAL;
    } else if (path == "/proc/self/exe" || path == tgid_path + "/exe") {
        return readlink_with_str(vthread, vthread->get_vprocess()->get_exe_path(), buf, size);
    }
    return -ENOENT;
}

using SpecialFileOpenHandler = std::function<int (VThread *, const std::string &, int, mode_t)>;
using SpecialFileStatHandler = std::function<int (VThread *, const std::string &, struct stat *)>;
using SpecialFileReadlinkHandler = std::function<ssize_t (VThread *, const std::string &, char *, size_t)>;

struct SpecialFile {
    std::string prefix;
    SpecialFileOpenHandler open;
    SpecialFileStatHandler stat;
    SpecialFileReadlinkHandler readlink;
};

static const std::vector<SpecialFile> SpecialFileHandlers = {
    {"/dev/std",        open_special_stdio,     stat_special_err,       readlink_special_err},
    {"/proc",           open_special_procfs,    stat_special_procfs,    readlink_special_procfs}
};

long SyscallHandlers::open(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    long new_args[6] = {AT_FDCWD, args[0], args[1], args[2]};
    return openat(vthread, SYS_openat, new_args, info);
}

static int openat_getfd(VThread *vthread, const long *args) {
    int dirfd = args[0];
    if (dirfd != AT_FDCWD) {
        return vthread->invoke_syscall(SYS_openat, args);
    }
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    const char *ppath = (const char *)args[1];
    int flags = args[2];
    mode_t mode = args[3];
    std::string path;
    if (mm->copy_str_from_sandbox(path, ppath, PATH_MAX) == -1ull) {
        return -EFAULT;
    }
    for (const SpecialFile &f : SpecialFileHandlers) {
        if (startswith(path, f.prefix)) {
            int fd = f.open(vthread, path, flags, mode);
            if (fd != -ENOENT) {
                return fd;
            }
        }
    }
    return vthread->invoke_syscall(SYS_openat, args);
}

long SyscallHandlers::openat(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    USwitchContext *ucontext = vprocess->get_ucontext();
    FileTable *ft = vprocess->get_file_table();
    //printf("openat: %s\n", args[1]);
    int res = openat_getfd(vthread, args);
    if (res < 0) {
        return res;
    }
    FileDescriptor fd;
    fd.fd = res;
    fd.ucontext = ucontext;
    std::shared_ptr<PassthroughFile> file;
    try {
        file = std::make_shared<PassthroughFile>(ucontext, fd.fd);
    } catch (std::bad_alloc &e) {
        return -ENOMEM;
    }
    file->create_monitor_fd(fd);
    return ft->add_file(vthread, fd, file);
}

long SyscallHandlers::read(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int fd = args[0];
    void *buf = (void *)args[1];
    size_t len = args[2];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(fd);
    if (!file) {
        return vthread->invoke_syscall(SYS_read, args);
    }
    return file->read(vthread, fd, buf, len);
}

long SyscallHandlers::write(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int fd = args[0];
    const void *buf = (void *)args[1];
    size_t len = args[2];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(fd);
    if (!file) {
        
        long res = vthread->invoke_syscall(SYS_write, args);
        return res;
    }
    return file->write(vthread, fd, buf, len);
}

long SyscallHandlers::close(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int fd = args[0];
    return vthread->get_vprocess()->get_file_table()->close(vthread, fd);
}

long SyscallHandlers::readv(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int fd = args[0];
    const struct iovec *iov = (const struct iovec *)args[1];
    int iovcnt = args[2];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(fd);
    if (!file) {
        return vthread->invoke_syscall(SYS_readv, args);
    }
    return file->readv(vthread, fd, iov, iovcnt);
}

long SyscallHandlers::writev(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int fd = args[0];
    const struct iovec *iov = (const struct iovec *)args[1];
    int iovcnt = args[2];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(fd);
    if (!file) {
        return vthread->invoke_syscall(SYS_writev, args);
    }
    return file->writev(vthread, fd, iov, iovcnt);
}

long SyscallHandlers::fcntl(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int fd = args[0];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(fd);
    if (!file) {
        return vthread->invoke_syscall(SYS_fcntl, args);
    }

    int cmd = args[1];
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        VProcess *vprocess = vthread->get_vprocess();
        USwitchContext *ucontext = vprocess->get_ucontext();
        FileTable *ft = vprocess->get_file_table();
        int newfd = vthread->invoke_syscall(sysno, args);
        if (newfd < 0) {
            return newfd;
        }
        FileDescriptor fd;
        fd.ucontext = ucontext;
        fd.fd = newfd;
        return ft->add_file(vthread, fd, file);
    }
    return file->fcntl(vthread, fd, args);
}

long SyscallHandlers::ioctl(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int fd = args[0];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(fd);
    if (!file) {
        return vthread->invoke_syscall(SYS_ioctl, args);
    }
    return file->ioctl(vthread, fd, args);
}

long SyscallHandlers::sendfile(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int out_fd = args[0];
    int in_fd = args[1];
    off_t *offset = (off_t *)args[2];
    size_t len = args[3];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(out_fd);
    if (!file) {
        return vthread->invoke_syscall(SYS_sendfile, args);
    }
    return file->sendfile(vthread, out_fd, in_fd, offset, len);
}

long SyscallHandlers::socket(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int domain = args[0];
    int type = args[1];
    int protocol = args[2];
    VProcess *vprocess = vthread->get_vprocess();
    NetworkContext *nc = vprocess->get_network_context();
    FileTable *ft = vprocess->get_file_table();
    FDFilePair ffp;
    bool allow_local = Runtime::get()->get_config().enable_vtcp;
    if (!nc->create_socket(vthread, ffp, allow_local, domain, type, protocol)) {
        return -EINVAL;
    }
    return ft->add_file(vthread, ffp.fd, ffp.file);
}

long SyscallHandlers::recvfrom(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int sockfd = args[0];
    void *buf = (void *)args[1];
    size_t len = args[2];
    int flags = args[3];
    struct sockaddr *addr = (struct sockaddr *)args[4];
    socklen_t *addrlen = (socklen_t *)args[5];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(sockfd);
    if (!file) {
        return -EBADF;
    }
    return file->recvfrom(vthread, sockfd, buf, len, flags, addr, addrlen);
}

long SyscallHandlers::sendto(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int sockfd = args[0];
    void *buf = (void *)args[1];
    size_t len = args[2];
    int flags = args[3];
    const struct sockaddr *addr = (const struct sockaddr *)args[4];
    socklen_t addrlen = args[5];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(sockfd);
    if (!file) {
        return -EBADF;
    }
    return file->sendto(vthread, sockfd, buf, len, flags, addr, addrlen);
}

long SyscallHandlers::recvmsg(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int sockfd = args[0];
    struct msghdr *msg = (struct msghdr *)args[1];
    int flags = args[2];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(sockfd);
    if (!file) {
        return -EBADF;
    }
    return file->recvmsg(vthread, sockfd, msg, flags);
}

long SyscallHandlers::sendmsg(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int sockfd = args[0];
    const struct msghdr *msg = (const struct msghdr *)args[1];
    int flags = args[2];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(sockfd);
    if (!file) {
        return -EBADF;
    }
    return file->sendmsg(vthread, sockfd, msg, flags);
}

long SyscallHandlers::listen(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int sockfd = args[0];
    int backlog = args[1];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(sockfd);
    if (!file) {
        return -EBADF;
    }
    return file->listen(vthread, sockfd, backlog);
}

long SyscallHandlers::bind(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int sockfd = args[0];
    const struct sockaddr *addr = (const struct sockaddr *)args[1];
    socklen_t addrlen = args[2];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(sockfd);
    if (!file) {
        return -EBADF;
    }
    return file->bind(vthread, sockfd, addr, addrlen);
}

long SyscallHandlers::accept4(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int sockfd = args[0];
    struct sockaddr *addr = (struct sockaddr *)args[1];
    socklen_t *addrlen = (socklen_t *)args[2];
    int flags = args[3];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(sockfd);
    if (!file) {
        return -EBADF;
    }
    return file->accept4(vthread, sockfd, addr, addrlen, flags, nullptr);
}

long SyscallHandlers::accept(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int sockfd = args[0];
    struct sockaddr *addr = (struct sockaddr *)args[1];
    socklen_t *addrlen = (socklen_t *)args[2];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(sockfd);
    if (!file) {
        return -EBADF;
    }
    return file->accept4(vthread, sockfd, addr, addrlen, 0);
}

long SyscallHandlers::connect(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int sockfd = args[0];
    const struct sockaddr *addr = (const struct sockaddr *)args[1];
    socklen_t addrlen = args[2];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(sockfd);
    if (!file) {
        return -EBADF;
    }
    return file->connect(vthread, sockfd, addr, addrlen);
}

long SyscallHandlers::shutdown(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int sockfd = args[0];
    int how = args[1];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(sockfd);
    if (!file) {
        return -EBADF;
    }
    return file->shutdown(vthread, sockfd, how);
}

long SyscallHandlers::getsockopt(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int sockfd = args[0];
    int level = args[1];
    int optname = args[2];
    void *optval = (void *)args[3];
    socklen_t *optlen = (socklen_t *)args[4];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(sockfd);
    if (!file) {
        return -EBADF;
    }
    return file->getsockopt(vthread, sockfd, level, optname, optval, optlen);
}

long SyscallHandlers::setsockopt(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int sockfd = args[0];
    int level = args[1];
    int optname = args[2];
    const void *optval = (const void *)args[3];
    socklen_t optlen = args[4];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(sockfd);
    if (!file) {
        return -EBADF;
    }
    return file->setsockopt(vthread, sockfd, level, optname, optval, optlen);
}

long SyscallHandlers::getsockname(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int sockfd = args[0];
    struct sockaddr *addr = (struct sockaddr *)args[1];
    socklen_t *addrlen = (socklen_t *)args[2];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(sockfd);
    if (!file) {
        return -EBADF;
    }
    return file->getsockname(vthread, sockfd, addr, addrlen);
}

long SyscallHandlers::getpeername(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int sockfd = args[0];
    struct sockaddr *addr = (struct sockaddr *)args[1];
    socklen_t *addrlen = (socklen_t *)args[2];

    std::shared_ptr<File> file = vthread->get_vprocess()->get_file_table()->get_file(sockfd);
    if (!file) {
        return -EBADF;
    }
    return file->getpeername(vthread, sockfd, addr, addrlen);
}

long SyscallHandlers::socketpair(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int domain = args[0];
    int type = args[1];
    int protocol = args[2];
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    FileTable *ft = vprocess->get_file_table();
    int res;
    FDFilePair ffps[2];
    res = LinuxSocket::socketpair(vthread, domain, type, protocol, ffps);
    if (res < 0) {
        return res;
    }
    int sv[2] = {ffps[0].fd.fd, ffps[1].fd.fd};
    try {
        mm->copy_to_sandbox((void *)args[3], sv, sizeof(int) * 2);
    } catch (FaultException &e) {
        return -EFAULT;
    }
    return ft->add_files(vthread, ffps, 2);
}

long SyscallHandlers::pipe(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    long new_args[6] = {args[0], 0};
    return pipe2(vthread, SYS_pipe2, new_args, info);
}

long SyscallHandlers::pipe2(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int *pfds = (int *)args[0];
    int flags = args[1];
    bool nonblock = flags & O_NONBLOCK;
    flags |= O_NONBLOCK;
    int fds[2];
    FDFilePair ffps[2];
    VProcess *vprocess = vthread->get_vprocess();
    USwitchContext *ucontext = vprocess->get_ucontext();
    MM *mm = vprocess->get_mm();
    FileTable *ft = vprocess->get_file_table();
    int res;
    ucontext->run_on_behalf_of([&] {
        res = ::pipe2(fds, flags);
        if (res == -1) {
            res = -errno;
        }
    });
    if (res < 0) {
        return res;
    }
    ffps[0].fd.ucontext = ucontext;
    ffps[0].fd.fd = fds[0];
    ffps[1].fd.ucontext = ucontext;
    ffps[1].fd.fd = fds[1];
    ffps[0].file = std::make_shared<NonblockingFile>(ucontext, fds[0], nonblock);
    ffps[1].file = std::make_shared<NonblockingFile>(ucontext, fds[1], nonblock);
    try {
        mm->copy_to_sandbox(pfds, fds, sizeof(fds));
    } catch (FaultException &e) {
        return -EFAULT;
    }
    return ft->add_files(vthread, ffps, 2);
}

long SyscallHandlers::dup(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int oldfd = args[0];
    int newfd = vthread->invoke_syscall(sysno, args);
    if (newfd < 0) {
        return newfd;
    }
    VProcess *vprocess = vthread->get_vprocess();
    USwitchContext *ucontext = vprocess->get_ucontext();
    FileTable *ft = vprocess->get_file_table();
    FileDescriptor fd;
    fd.ucontext = ucontext;
    fd.fd = newfd;
    std::shared_ptr<File> old_file = ft->get_file(oldfd);
    if (!old_file) {
        return fd.move();
    }
    return ft->add_file(vthread, fd, old_file);
}

long SyscallHandlers::dup2(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int oldfd = args[0];
    int newfd = args[1];
    if (oldfd == newfd) {
        return vthread->invoke_syscall(sysno, args);
    }
    VProcess *vprocess = vthread->get_vprocess();
    FileTable *ft = vprocess->get_file_table();
    return ft->dup(vthread, oldfd, newfd, 0);
}

long SyscallHandlers::dup3(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int oldfd = args[0];
    int newfd = args[1];
    int flags = args[2];
    if (oldfd == newfd) {
        return -EINVAL;
    }
    VProcess *vprocess = vthread->get_vprocess();
    FileTable *ft = vprocess->get_file_table();
    return ft->dup(vthread, oldfd, newfd, flags);
}

long SyscallHandlers::eventfd(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    long new_args[6] = {args[0], 0};
    return eventfd2(vthread, SYS_eventfd2, new_args, info);
}

long SyscallHandlers::eventfd2(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int initial = args[0];
    int flags = args[1];
    bool nonblock = flags & EFD_NONBLOCK;
    flags |= EFD_NONBLOCK;
    long new_args[6] = {initial, flags};
    int res = vthread->invoke_syscall(SYS_eventfd2, new_args);
    if (res < 0) {
        return res;
    }
    VProcess *vprocess = vthread->get_vprocess();
    USwitchContext *ucontext = vprocess->get_ucontext();
    FileTable *ft = vprocess->get_file_table();
    FileDescriptor fd(ucontext, res);
    std::shared_ptr<NonblockingFile> file = std::make_shared<NonblockingFile>(ucontext, res, nonblock);
    return ft->add_file(vthread, fd, file);
}

long SyscallHandlers::stat(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {    
    const char *ppath = (const char *)args[0];
    struct stat *pbuf = (struct stat *)args[1];
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    std::string path;
    if (mm->copy_str_from_sandbox(path, ppath, PATH_MAX) == -1ull) {
        return -EFAULT;
    }
    for (const SpecialFile &f : SpecialFileHandlers) {
        if (startswith(path, f.prefix)) {
            int res = f.stat(vthread, path, pbuf);
            if (res != -ENOENT) {
                return res;
            }
        }
    }
    return vthread->invoke_syscall(SYS_stat, args);
}

long SyscallHandlers::newfstatat(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int fd = args[0];
    const char *ppath = (const char *)args[1];
    struct stat *pbuf = (struct stat *)args[2];
    if (fd != AT_FDCWD) {
        return vthread->invoke_syscall(SYS_newfstatat, args);
    }
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    std::string path;
    if (mm->copy_str_from_sandbox(path, ppath, PATH_MAX) == -1ull) {
        return -EFAULT;
    }
    for (const SpecialFile &f : SpecialFileHandlers) {
        if (startswith(path, f.prefix)) {
            int res = f.stat(vthread, path, pbuf);
            if (res != -ENOENT) {
                return res;
            }
        }
    }
    return vthread->invoke_syscall(SYS_newfstatat, args);
}

long SyscallHandlers::readlink(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    const char *ppath = (const char *)args[0];
    char *buf = (char *)args[1];
    size_t size = args[2];
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    std::string path;
    if (mm->copy_str_from_sandbox(path, ppath, PATH_MAX) == -1ull) {
        return -EFAULT;
    }
    for (const SpecialFile &f : SpecialFileHandlers) {
        if (startswith(path, f.prefix)) {
            ssize_t res = f.readlink(vthread, path, buf, size);
            if (res != -ENOENT) {
                return res;
            }
        }
    }
    return vthread->invoke_syscall(SYS_readlink, args);
}

long SyscallHandlers::close_range(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int first = args[0];
    int last = args[1];
    int flags = args[2];
    return vthread->get_vprocess()->get_file_table()->close_range(vthread, first, last, flags);
}

long SyscallHandlers::inotify_init(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    long new_args[6] = {};
    return inotify_init1(vthread, SYS_inotify_init1, new_args, info);
}

long SyscallHandlers::inotify_init1(VThread *vthread, int sysno, const long *args, SyscallInfo *info) {
    int flags = args[1];
    bool nonblock = flags & IN_NONBLOCK;
    flags = IN_NONBLOCK;
    long new_args[6] = {flags};
    int res = vthread->invoke_syscall(SYS_inotify_init1, new_args);
    if (res < 0) {
        return res;
    }
    VProcess *vprocess = vthread->get_vprocess();
    USwitchContext *ucontext = vprocess->get_ucontext();
    FileTable *ft = vprocess->get_file_table();
    FileDescriptor fd(ucontext, res);
    std::shared_ptr<NonblockingFile> file = std::make_shared<NonblockingFile>(ucontext, res, nonblock);
    return ft->add_file(vthread, fd, file);
}

long SyscallHandlers::passthrough_with_fd(VThread *vthread, int sysno,
                                  const long *args, SyscallInfo *info) {
    int res = vthread->invoke_syscall(sysno, args);
    if (res < 0) {
        return res;
    }
    VProcess *vprocess = vthread->get_vprocess();
    USwitchContext *ucontext = vprocess->get_ucontext();
    FileTable *ft = vprocess->get_file_table();
    FileDescriptor fd(ucontext, res);
    std::shared_ptr<PassthroughFile> file = std::make_shared<PassthroughFile>(ucontext, res);
    file->create_monitor_fd(fd);
    return ft->add_file(vthread, fd, file);
}

struct iovec *pegasus::load_iovec(MM *mm, const struct iovec *piov, int iovcnt,
                                 std::unique_ptr<struct iovec[]> &iov_slow, struct iovec *iov_fast, int &err) {
    if (iovcnt <= 0 || iovcnt > MaxIovecSize) {
        err = -EINVAL;
        return nullptr;
    }
    struct iovec *iov;
    if (iovcnt <= MaxStackIovecSize) {
        iov = iov_fast;
    } else {
        try {
            iov_slow.reset(new struct iovec[iovcnt]);
        } catch (std::bad_alloc &e) {
            err = -ENOMEM;
            return nullptr;
        }
        iov = iov_slow.get();
    }
    try {
        mm->copy_from_sandbox(iov, piov, sizeof(struct iovec) * iovcnt);
    } catch (FaultException &e) {
        err = -EFAULT;
        return nullptr;
    }
    return iov;
}
