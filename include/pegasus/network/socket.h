#pragma once
#include <atomic>
#include <functional>
#include <sys/socket.h>
#include "pegasus/file.h"
#include "pegasus/sched.h"

namespace pegasus {
struct VirtualConnection;
struct VirtualServer;
class LocalSocket : virtual public File {
public:
    LocalSocket(int domain);
    virtual ~LocalSocket();
    inline static bool support(int domain, int type, int protocol) {
        return (domain == AF_INET || domain == AF_INET6) &&
            (type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) == SOCK_STREAM;
    }
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
private:
    template <typename T>
    friend class SocketWrapper;
    ssize_t recvfrom_once(VThread *vthread, void *buf, size_t len, int flags, uint32_t &peer_events);
    ssize_t sendto_once(VThread *vthread, const void *buf, size_t len, uint32_t &peer_events);
    ssize_t readv_once(VThread *vthread, const struct iovec *iov, int iovcnt,
                       int flags, uint32_t &peer_events);
    ssize_t writev_once(VThread *vthread, const struct iovec *iov, int iovcnt, uint32_t &peer_events);
    ssize_t sendfile_once(VThread *vthread, int in_fd, off_t *offset, size_t len, uint32_t &peer_events);
    void notify_peer(uint32_t events);

    std::shared_ptr<VirtualConnection> vconn;
    std::shared_ptr<WaitQueue> wq;
    std::atomic_bool nonblock;
    bool is_client;
    int domain;
    std::atomic_int last_err;
};

static constexpr int NoFastPath = 0x10000000;

class LinuxSocket : public NonblockingFile {
public:
    static bool create(VThread *vthread, FDFilePair &out, bool local, int domain, int type, int protocol);
    static int socketpair(VThread *vthread, int domain, int type, int protocol, FDFilePair out[2]);
    ~LinuxSocket();
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
        return OverlayReal;
    }
protected:
    LinuxSocket(USwitchContext *ucontext, int fd_, int domain_);
    int accept_once(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *len, int flags);

    int domain;
};

using SocketFactory =
    bool (*)(VThread *, FDFilePair &, bool, int, int, int);
}
