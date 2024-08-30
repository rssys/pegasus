#pragma once
#include "socket.h"
#include "../ioworker_fstack.h"

namespace pegasus {
class IOWorker;

class WaitQueue;
class DPDKSocket : virtual public File {
public:
    DPDKSocket(IOWorkerFd &dfd_, int domain_, bool nonblock_);
    virtual ~DPDKSocket();
    virtual ssize_t read(VThread *vthread, int fd, void *buf, size_t len);
    virtual ssize_t write(VThread *vthread, int fd, const void *buf, size_t len);
    virtual ssize_t readv(VThread *vthread, int fd, const struct iovec *iov, int iovcnt);
    virtual ssize_t writev(VThread *vthread, int fd, const struct iovec *iov, int iovcnt);
    virtual int fcntl(VThread *vthread, int fd, const long *args);
    virtual int ioctl(VThread *vthread, int fd, const long *args);
    virtual ssize_t sendfile(VThread *vthread, int fd, int in_fd, off_t *offset, size_t len);
    //virtual uint32_t poll(VThread *vthread, uint32_t events);
    virtual void notify(uint32_t events, std::unique_lock<SpinLock> &lock);
    virtual void notify_batch(uint32_t events, std::unique_lock<SpinLock> &lock,
                              BatchNotifyState &state);
    virtual uint32_t get_cap();
    virtual ssize_t recvfrom(VThread *vthread, int fd, void *buf, size_t len, int flags,
                             struct sockaddr *addr, socklen_t *addrlen);
    virtual ssize_t sendto(VThread *vthread, int fd, const void *buf, size_t len, int flags,
                           const struct sockaddr *addr, socklen_t addrlen);
    virtual ssize_t recvmsg(VThread *vthread, int fd, struct msghdr *msg, int flags);
    virtual ssize_t sendmsg(VThread *vthread, int fd, const struct msghdr *msg, int flags);
    virtual int listen(VThread *vthread, int fd, int backlog);
    virtual int bind(VThread *vthread, int fd, const struct sockaddr *addr, socklen_t len);
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
    static inline uint32_t get_overlay() {
        return OverlayIOW;
    }
protected:
    friend class IOWorker;
    bool block_until_event(uint32_t events);
    bool block_until_event(uint32_t events, const std::shared_ptr<WaitQueue> &wq,
                           std::unique_lock<SpinLock> &lock);
    int accept_once(VThread *vthread, struct sockaddr *addr, socklen_t *len, int flags);
    ssize_t recvfrom_once(VThread *vthread, void *buf, size_t len, int flags,
                          struct sockaddr *addr, socklen_t *addrlen);
    ssize_t sendto_once(VThread *vthread, const void *buf, size_t len, int flags,
                        const struct sockaddr *addr, socklen_t addrlen);
    ssize_t readv_once(VThread *vthread, const struct iovec *piov, int iovcnt);
    ssize_t writev_once(VThread *vthread, const struct iovec *piov, int iovcnt);
    ssize_t recvmsg_once(VThread *vthread, struct msghdr *msg, int flags);
    ssize_t sendmsg_once(VThread *vthread, const struct msghdr *msg, int flags);
    ssize_t sendfile_once(VThread *vthread, int in_fd, off_t *offset, size_t len);
    IOWorkerFd fd;
    std::shared_ptr<WaitQueue> wq;
    int domain;
    std::atomic_bool nonblock;
};

class DPDKSocketWithLO : public DPDKSocket, public LinuxSocket {
public:
    DPDKSocketWithLO(USwitchContext *ucontext, int fd, IOWorkerFd &dfd,
                     int domain, bool nonblock);
    ~DPDKSocketWithLO();
    virtual ssize_t read(VThread *vthread, int fd, void *buf, size_t len);
    virtual ssize_t write(VThread *vthread, int fd, const void *buf, size_t len);
    virtual ssize_t readv(VThread *vthread, int fd, const struct iovec *iov, int iovcnt);
    virtual ssize_t writev(VThread *vthread, int fd, const struct iovec *iov, int iovcnt);
    virtual int fcntl(VThread *vthread, int fd, const long *args);
    virtual int ioctl(VThread *vthread, int fd, const long *args);
    virtual ssize_t sendfile(VThread *vthread, int fd, int in_fd, off_t *offset, size_t len);
    virtual uint32_t poll(VThread *vthread, uint32_t events);
    virtual void notify(uint32_t events, std::unique_lock<SpinLock> &lock);
    virtual uint32_t get_cap();
    virtual ssize_t recvfrom(VThread *vthread, int fd, void *buf, size_t len, int flags,
                             struct sockaddr *addr, socklen_t *addrlen);
    virtual ssize_t sendto(VThread *vthread, int fd, const void *buf, size_t len, int flags,
                           const struct sockaddr *addr, socklen_t addrlen);
    virtual ssize_t recvmsg(VThread *vthread, int fd, struct msghdr *msg, int flags);
    virtual ssize_t sendmsg(VThread *vthread, int fd, const struct msghdr *msg, int flags);
    virtual int listen(VThread *vthread, int fd, int backlog);
    virtual int bind(VThread *vthread, int fd, const struct sockaddr *paddr, socklen_t len);
    virtual int accept4(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *len, int flags,
                        AcceptHook &hook = nullptr);
    virtual int connect(VThread *vthread, int fd, const struct sockaddr *paddr, socklen_t len);
    virtual int shutdown(VThread *vthread, int fd, int how);
    virtual int getsockopt(VThread *vthread, int fd, int level, int optname, void *optval, socklen_t *optlen);
    virtual int setsockopt(VThread *vthread, int fd, int level, int optname, const void *optval, socklen_t optlen);
    virtual int getsockname(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *addrlen);
    virtual int getpeername(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *addrlen);
    virtual bool is_nonblock();
    virtual int get_domain();
private:
    enum {
        Initial = 0,
        Connecting = 1,
        Connected = 2,
        ConnectedLocal = 3,
        ConnectingLocal = 4,
        Listen = 5,
    };
    inline bool is_local() {
        int state_ = state.load(std::memory_order_acquire);
        return state_ == ConnectedLocal || state_ == ConnectingLocal;
    }
    int accept_once(VThread *vthread, struct sockaddr *paddr, socklen_t *plen, int flags);
    std::atomic_int state;
};
}
