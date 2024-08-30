#pragma once
#include <map>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <cstddef>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include "lock.h"
#include "uswitch.h"
#include "wait_queue.h"

namespace pegasus {
struct MonitorFile {
    MonitorFile() : fd(-1) {}
    MonitorFile(const MonitorFile &) = delete;
    MonitorFile(MonitorFile &&f) {
        if (fd != -1) {
            close(fd);
        }
        fd = f.fd;
        f.fd = -1;
    }
    MonitorFile &operator=(const MonitorFile &f) = delete;
    MonitorFile &operator=(MonitorFile &&f) {
        if (fd != -1) {
            close(fd);
        }
        fd = f.fd;
        f.fd = -1;
        return *this;
    }
    ~MonitorFile() {
        if (fd != -1) {
            close(fd);
        }
    }
    int fd;
};

struct FileDescriptorReference {
    FileDescriptorReference() : ucontext(nullptr), fd(-1) {}
    FileDescriptorReference(USwitchContext *ucontext_, int fd_) : ucontext(ucontext_), fd(fd_) {}
    USwitchContext *ucontext;
    int fd;
};

struct FileDescriptor : public FileDescriptorReference {
    FileDescriptor() : FileDescriptorReference(nullptr, -1) {}
    FileDescriptor(const FileDescriptor &) = delete;
    FileDescriptor(FileDescriptor &&f) {
        reset();
        ucontext = f.ucontext;
        fd = f.fd;
        f.ucontext = nullptr;
        f.fd = -1;
    }
    FileDescriptor(USwitchContext *ucontext_, int fd_) : FileDescriptorReference(ucontext_, fd_) {}
    FileDescriptor &operator=(const FileDescriptor &) = delete;
    FileDescriptor &operator=(FileDescriptor &&f) {
        reset();
        ucontext = f.ucontext;
        fd = f.fd;
        f.ucontext = nullptr;
        f.fd = -1;
        return *this;
    }
    inline void reset() {
        if (fd != -1 && ucontext) {
            ucontext->run_on_behalf_of([&] {
                close(fd);
            });
        }
        ucontext = nullptr;
        fd = -1;
    }
    inline int move() {
        int f = fd;
        ucontext = nullptr;
        fd = -1;
        return f;
    }
    ~FileDescriptor() {
        reset();
    }
};

struct FDFilePair {
    FileDescriptor fd;
    std::shared_ptr<File> file;
    void reset() {
        file.reset();
        fd.reset();
    }
};

class Socket {
public:
    using AcceptHook = const std::function<int (std::shared_ptr<WaitQueue> &wq, std::unique_lock<SpinLock> &lock)>;
    virtual ssize_t recvfrom(VThread *vthread, int fd, void *buf, size_t len, int flags,
                             struct sockaddr *addr, socklen_t *addrlen);
    virtual ssize_t sendto(VThread *vthread, int fd, const void *buf, size_t len, int flags,
                           const struct sockaddr *addr, socklen_t addrlen);
    virtual ssize_t recvmsg(VThread *vthread, int fd, struct msghdr *msg, int flags);
    virtual ssize_t sendmsg(VThread *vthread, int fd, const struct msghdr *msg, int flags);
    virtual int listen(VThread *vthread, int fd, int backlog);
    virtual int bind(VThread *vthread, int fd, const sockaddr *addr, socklen_t len);
    virtual int accept4(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *len, int flags,
                        AcceptHook &hook = nullptr);
    virtual int connect(VThread *vthread, int fd, const struct sockaddr *addr, socklen_t len);
    virtual int shutdown(VThread *vthread, int fd, int how);
    virtual int getsockopt(VThread *vthread, int fd, int level, int optname, void *optval, socklen_t *optlen);
    virtual int setsockopt(VThread *vthread, int fd, int level, int optname, const void *optval, socklen_t optlen);
    virtual int getsockname(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *addrlen);
    virtual int getpeername(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *addrlen);
    virtual bool is_nonblock();
    virtual int get_domain();
    static constexpr int BogusPortNumber = 1;
};

class VProcess;
class VThread;
class EpollFile;
class BatchNotifyState;

class File : public std::enable_shared_from_this<File>, public Socket {
public:
    enum {
        Real = 1u,
        Seekable = 2u,
        Pollable = 4u,
        OverlayReal = 8u,
        FromIOWorker = 16u,
        OverlayIOW = 32u,
    };

    File(USwitchContext *ucontext, int fd);
    virtual ~File();
    virtual ssize_t read(VThread *vthread, int fd, void *buf, size_t len);
    virtual ssize_t write(VThread *vthread, int fd, const void *buf, size_t len);
    virtual ssize_t readv(VThread *vthread, int fd, const struct iovec *iov, int iovcnt);
    virtual ssize_t writev(VThread *vthread, int fd, const struct iovec *iov, int iovcnt);
    virtual int fcntl(VThread *vthread, int fd, const long *args);
    virtual int ioctl(VThread *vthread, int fd, const long *args);
    virtual ssize_t sendfile(VThread *vthread, int fd, int in_fd, off_t *offset, size_t len);
    inline int get_monitor_fd() {
        return monitor_file.fd;
    }
    inline void set_monitor_fd(int fd) {
        std::lock_guard lock(mutex);
        monitor_file.fd = fd;
    }
    inline void set_monitor_fd(MonitorFile &file) {
        std::lock_guard lock(mutex);
        monitor_file = std::move(file);
    }
    //inline int get_real_fd() {
    //    return real_file.fd;
    //}
    inline SpinLock &get_mutex() {
        return mutex;
    }
    virtual uint32_t poll(VThread *vthread, uint32_t events);
    virtual void notify(uint32_t events, std::unique_lock<SpinLock> &lock);
    virtual void notify_batch(uint32_t events, std::unique_lock<SpinLock> &lock,
                              BatchNotifyState &state);
    virtual uint32_t get_cap();
    virtual std::shared_ptr<File> clone(const FileDescriptorReference &fdr);
    int create_monitor_fd(const FileDescriptorReference &fd);
    void drop_cap_real(VThread *vthread, int fd);
protected:
    friend class EpollFile;

    SpinLock mutex;
    MonitorFile monitor_file;
    std::unordered_map<EpollFile *, std::weak_ptr<EpollFile>> watching_epfiles;
    std::unordered_map<EpollFile *, std::weak_ptr<EpollFile>> exclusive_epfiles;
};

struct BatchNotifyState {
    void add(const std::shared_ptr<EpollFile> &epfile, File *file, uint32_t events);
    void finish();
    void clear();
    struct Item {
        std::shared_ptr<EpollFile> epfile;
        std::unordered_map<File *, uint32_t> events;
    };
    std::unordered_map<EpollFile *, Item> epfiles;
};

class PassthroughFile : virtual public File {
public:
    PassthroughFile(USwitchContext *ucontext, int fd);
    virtual ~PassthroughFile();
    virtual ssize_t read(VThread *vthread, int fd, void *buf, size_t len);
    virtual ssize_t write(VThread *vthread, int fd, const void *buf, size_t len);
    virtual ssize_t readv(VThread *vthread, int fd, const struct iovec *iov, int iovcnt);
    virtual ssize_t writev(VThread *vthread, int fd, const struct iovec *iov, int iovcnt);
    virtual int fcntl(VThread *vthread, int fd, const long *args);
    virtual int ioctl(VThread *vthread, int fd, const long *args);
    virtual ssize_t sendfile(VThread *vthread, int fd, int in_fd, off_t *offset, size_t len);
    virtual uint32_t get_cap();
};

class NonblockingFile : virtual public File {
public:
    NonblockingFile(USwitchContext *ucontext, int fd, bool nonblock_ = false);
    virtual ~NonblockingFile();
    virtual ssize_t read(VThread *vthread, int fd, void *buf, size_t len);
    virtual ssize_t write(VThread *vthread, int fd, const void *buf, size_t len);
    virtual ssize_t readv(VThread *vthread, int fd, const struct iovec *iov, int iovcnt);
    virtual ssize_t writev(VThread *vthread, int fd, const struct iovec *iov, int iovcnt);
    virtual int fcntl(VThread *vthread, int fd, const long *args);
    virtual int ioctl(VThread *vthread, int fd, const long *args);
    virtual ssize_t sendfile(VThread *vthread, int fd, int in_fd, off_t *offset, size_t len);
    //virtual uint32_t poll(VThread *vthread, uint32_t events);
    //virtual void notify(uint32_t events, std::unique_lock<SpinLock> &lock);
    virtual uint32_t get_cap();
protected:
    bool block_until_event(uint32_t events);
    bool block_until_event(uint32_t events, const std::shared_ptr<WaitQueue> &wq,
                           std::unique_lock<SpinLock> &lock);

    std::atomic_bool nonblock;
};

class SignalFdFile : public File {
public:
    SignalFdFile(VProcess *vprocess_);
    virtual ~SignalFdFile();
    void activate();
    virtual ssize_t read(VThread *vthread, int fd, void *buf, size_t len);
    ssize_t read_once(VThread *vthread, void *buf, size_t len);
    virtual uint32_t poll(VThread *vthread, uint32_t events);
    virtual int fcntl(VThread *vthread, int fd, const long *args);
    virtual int ioctl(VThread *vthread, int fd, const long *args);
    virtual uint32_t get_cap();
    void notify();
    inline uint64_t get_mask() {
        return mask.load(std::memory_order_acquire);
    }
    inline void set_mask(uint64_t mask_) {
        mask.store(mask_, std::memory_order_release);
    }
    inline bool get_nonblock() {
        return nonblock.load(std::memory_order_acquire);
    }
    inline void set_nonblock(bool nonblock_) {
        nonblock.store(nonblock_, std::memory_order_release);
    }
    inline void set_mask_nonblock(uint64_t mask_, bool nonblock_) {
        std::lock_guard lock(mutex);
        set_mask(mask_);
        set_nonblock(nonblock_);
    }
private:
    std::atomic_uint64_t mask;
    std::atomic_bool nonblock;
    std::weak_ptr<VProcess> vprocess;
    std::shared_ptr<WaitQueue> wq;
};

class FileTable {
public:
    FileTable();
    inline std::shared_ptr<File> get_file(int fd) {
        std::shared_lock lock(mutex);
        if (fd < 0 || (size_t)fd >= files.size()) {
            return nullptr;
        }
        return files[fd].file;
    }
    int add_file(VThread *vthread, FileDescriptor &fd, const std::shared_ptr<File> &file);
    int add_files(VThread *vthread, FDFilePair *new_files, size_t n);
    std::shared_ptr<FileTable> clone(USwitchContext *ucontext);
    int dup(VThread *vthread, int oldfd, int newfd, int flags);
    int close(VThread *vthread, int fd);
    int close_range(VThread *vthread, int first, int last, int flags);
private:
    inline FDFilePair *get_or_alloc(int fd) {
        if (fd < 0) {
            return nullptr;
        } else if ((size_t)fd < files.size()) {
            return &files[fd];
        }
        try {
            files.resize(fd + 1);
        } catch (std::bad_alloc &e) {
            return nullptr;
        }
        return &files[fd];
    }
    RWSpinLock mutex;
    //std::unordered_map<int, FDFilePair> files;
    std::vector<FDFilePair> files;
};

static constexpr int MaxIovecSize = 1024;
static constexpr int MaxStackIovecSize = 8;
class MM;
struct iovec *load_iovec(MM *mm, const struct iovec *piov, int iovcnt,
                         std::unique_ptr<struct iovec[]> &iov_slow, struct iovec *iov_fast, int &err);
}