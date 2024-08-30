#include <memory>
#include <unordered_map>
#include <list>
#include <vector>
#include <type_traits>
#include <sys/socket.h>
#include <netinet/in.h>
#include "pegasus/lock.h"
#include "pegasus/runtime.h"
#include "pegasus/wait_queue.h"
#include "socket.h"

namespace std {
template <>
struct hash<struct in_addr> {
    size_t operator()(const struct in_addr &x) const {
        return hash<uint32_t>()(x.s_addr);
    }
};

template <>
struct hash<struct in6_addr> {
    size_t operator()(const struct in6_addr &x) const {
        uint64_t h = *(uint64_t *)(x.s6_addr);
        uint64_t l = *(uint64_t *)(x.s6_addr + 8);
        return hash<uint64_t>()(h) ^ hash<uint64_t>()(l);
    }
};
}

inline static bool operator==(const struct in_addr &x, const struct in_addr &y) {
    return x.s_addr == y.s_addr;
}

inline static bool operator==(const struct in6_addr &x, const struct in6_addr &y) {
    return memcmp(&x, &y, sizeof(struct in6_addr)) == 0;
}

namespace pegasus {

static constexpr size_t DefaultConnBufferSize = 1024 * 256;

struct Pipe;
struct VirtualConnection {
    VirtualConnection(size_t buffer_size = DefaultConnBufferSize);
    ~VirtualConnection();
    SpinLock mutex;
    std::shared_ptr<Pipe> upstream;
    std::shared_ptr<Pipe> downstream;
    std::weak_ptr<File> server_sock;
    std::weak_ptr<File> client_sock;
    uint16_t server_port;
    uint16_t client_port;
};

struct VirtualServer {
    VirtualServer(int domain_, int port_, int max_waiting_);
    void notify();
    std::shared_ptr<VirtualConnection> get_conn();
    bool add_conn(const std::shared_ptr<VirtualConnection> &conn);

    bool ready;
    int domain;
    int port;
    int max_waiting;
    SpinLock mutex;
    std::shared_ptr<WaitQueue> accept_wq;
    std::list<std::shared_ptr<VirtualConnection>> waiting_connections;
    std::weak_ptr<File> sock;
};

struct USwitchContext;
class VirtualNetwork {
public:
    VirtualNetwork(USwitchContext *ucontext, int netns_fd);
    ~VirtualNetwork();
    std::shared_ptr<VirtualServer> get_ipv4_server(const struct sockaddr_in *addr);
    std::shared_ptr<VirtualServer> get_ipv6_server(const struct sockaddr_in6 *addr);
    void set_ipv4_server(int port, const std::shared_ptr<VirtualServer> &server);
    void set_ipv6_server(int port, const std::shared_ptr<VirtualServer> &server);
    void add_server(const std::shared_ptr<VirtualServer> &server);
    std::shared_ptr<VirtualServer> get_server(const sockaddr *addr);
private:
    SpinLock mutex;
    std::unordered_map<int, std::weak_ptr<VirtualServer>> ipv4_servers;
    std::unordered_map<int, std::weak_ptr<VirtualServer>> ipv6_servers;
    std::unordered_set<struct in_addr> addr_in;
    std::unordered_set<struct in6_addr> addr_in6;
};

class NetworkContext {
public:
    NetworkContext(USwitchContext *ucontext, int netns_fd);
    ~NetworkContext();
    bool create_socket(VThread *vthread, FDFilePair &out, bool allow_local,
                       int domain, int type, int protocol);
    static std::shared_ptr<NetworkContext> get_network_context(USwitchContext *ucontext, int netns_fd);
    inline VirtualNetwork *get_vnetwork() {
        return vnetwork.get();
    }
private:
    std::vector<SocketFactory> factories;
    std::shared_ptr<VirtualNetwork> vnetwork;
};

template <typename T>
class SocketWrapper : public T, public LocalSocket {
public:
    template <typename... Args>
    SocketWrapper(USwitchContext *ucontext_, int fd_,
                  int domain, int type, int protocol, Args&&... args)
        : File(ucontext_, fd_), T(args...), LocalSocket(domain),
          vserver(std::make_shared<VirtualServer>(domain, 0, 0)), state(Initial) {
    }
    ~SocketWrapper() {
    }
    virtual ssize_t read(VThread *vthread, int fd, void *buf, size_t len) {
        return !is_local() ?
            T::read(vthread, fd, buf, len) :
            LocalSocket::read(vthread, fd, buf, len);
    }
    virtual ssize_t write(VThread *vthread, int fd, const void *buf, size_t len) {
        return !is_local() ?
            T::write(vthread, fd, buf, len) :
            LocalSocket::write(vthread, fd, buf, len);
    }
    virtual ssize_t readv(VThread *vthread, int fd, const struct iovec *iov, int iovcnt)  {
        return !is_local() ?
            T::readv(vthread, fd, iov, iovcnt) :
            LocalSocket::readv(vthread, fd, iov, iovcnt);
    }
    virtual ssize_t writev(VThread *vthread, int fd, const struct iovec *iov, int iovcnt) {
        return !is_local() ?
            T::writev(vthread, fd, iov, iovcnt) :
            LocalSocket::writev(vthread, fd, iov, iovcnt);
    }
    virtual int fcntl(VThread *vthread, int fd, const long *args) {
        return !is_local() ?
            T::fcntl(vthread, fd, args) :
            LocalSocket::fcntl(vthread, fd, args);
    }
    virtual int ioctl(VThread *vthread, int fd, const long *args) {
        return !is_local() ?
            T::ioctl(vthread, fd, args) :
            LocalSocket::ioctl(vthread, fd, args);
    }
    virtual ssize_t sendfile(VThread *vthread, int fd, int in_fd, off_t *offset, size_t len) {
        return !is_local() ?
            T::sendfile(vthread, fd, in_fd, offset, len) :
            LocalSocket::sendfile(vthread, fd, in_fd, offset, len);
    }
    virtual uint32_t poll(VThread *vthread, uint32_t events) {
        if (is_local()) {
            return LocalSocket::poll(vthread, events);
        }
        uint32_t res = T::poll(vthread, events);
        if (state.load(std::memory_order_acquire) == Listen) {
            std::lock_guard lock(vserver->mutex);
            if (vserver->waiting_connections.size()) {
                res |= EPOLLIN;
            }
        }
        return res;
    }
    virtual void notify(uint32_t events, std::unique_lock<SpinLock> &lock) {
        if (is_local()) {
            LocalSocket::notify(events, lock);
        } else {
            T::notify(events, lock);
        }
    }
    virtual uint32_t get_cap() {
        return !is_local() ?
            (T::get_cap() | Pollable) :
            (LocalSocket::get_cap() | T::get_overlay());
    }
    virtual ssize_t recvfrom(VThread *vthread, int fd, void *buf, size_t len, int flags,
                             struct sockaddr *addr, socklen_t *addrlen) {
            return !is_local() ?
            T::recvfrom(vthread, fd, buf, len, flags, addr, addrlen) :
            LocalSocket::recvfrom(vthread, fd, buf, len, flags, addr, addrlen);
    }
    virtual ssize_t sendto(VThread *vthread, int fd, const void *buf, size_t len, int flags,
                           const struct sockaddr *addr, socklen_t addrlen) {
            return !is_local() ?
            T::sendto(vthread, fd, buf, len, flags, addr, addrlen) :
            LocalSocket::sendto(vthread, fd, buf, len, flags, addr, addrlen);
    }
    virtual ssize_t recvmsg(VThread *vthread, int fd, struct msghdr *msg, int flags) {
            return !is_local() ?
            T::recvmsg(vthread, fd, msg, flags) :
            LocalSocket::recvmsg(vthread, fd, msg, flags);
    }
    virtual ssize_t sendmsg(VThread *vthread, int fd, const struct msghdr *msg, int flags) {
            return !is_local() ?
            T::sendmsg(vthread, fd, msg, flags) :
            LocalSocket::sendmsg(vthread, fd, msg, flags);
    }
    virtual int listen(VThread *vthread, int fd, int backlog) {
        int res = T::listen(vthread, fd, backlog);
        if (res == 0) {
            state.store(Listen, std::memory_order_release);
        }
        {
            std::lock_guard lock(vserver->mutex);
            if (vserver->ready) {
                vserver->max_waiting = backlog;
            }
        }
        VirtualNetwork *vn = vthread->get_vprocess()->get_network_context()->get_vnetwork();
        vn->add_server(vserver);
        return res;
    }
    virtual int bind(VThread *vthread, int fd, const struct sockaddr *paddr, socklen_t len) {
        struct sockaddr_storage addr;
        if (len > sizeof(struct sockaddr_storage)) {
            return -EINVAL;
        }
        MM *mm = vthread->get_vprocess()->get_mm();
        try {
            mm->copy_from_sandbox(&addr, paddr, len);
        } catch (FaultException &e) {
            return -EFAULT;
        }
        int res = T::bind(vthread, fd, paddr, len);
        if (res < 0) {
            return res;
        }
        int port = -1;
        if (len == sizeof(struct sockaddr_in) && addr.ss_family == AF_INET) {
            port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
        } else if (len == sizeof(struct sockaddr_in6) && addr.ss_family == AF_INET6) {
            port = ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
        }
        if (port != -1) {
            std::lock_guard lock(vserver->mutex);
            vserver->port = port;
            vserver->sock = T::shared_from_this();
            vserver->ready = true;
        }
        return res;
    }
    virtual int accept4(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *len, int flags,
                        AcceptHook &hook = nullptr) {
        if (state.load(std::memory_order_acquire) != Listen) {
            return -EINVAL;
        }
        return T::accept4(vthread, fd, addr, len, flags,
            [&] (std::shared_ptr<WaitQueue> &wq, std::unique_lock<SpinLock> &lock) {
                if (!lock) {
                    lock = std::move(std::unique_lock(vserver->mutex));
                    wq = vserver->accept_wq;
                }
                return accept_once(vthread, addr, len, flags);
            }
        );
    }
    virtual int connect(VThread *vthread, int fd, const struct sockaddr *paddr, socklen_t len) {
        MM *mm = vthread->get_vprocess()->get_mm();
        struct sockaddr_storage addr;
        if (len > sizeof(addr)) {
            return -EINVAL;
        }
        try {
            mm->copy_from_sandbox(&addr, paddr, len);
        } catch (FaultException &e) {
            return -EFAULT;
        }
        int initial = Initial;
        if (!state.compare_exchange_strong(initial, Connecting)) {
            return state.load(std::memory_order_relaxed) == Connecting ? -EALREADY : -EISCONN;
        }

        VirtualNetwork *vn = vthread->get_vprocess()->get_network_context()->get_vnetwork();
        std::shared_ptr<VirtualServer> vserver = vn->get_server((struct sockaddr *)&addr);
        std::shared_ptr<VirtualConnection> vconn;

        if (vserver) {
            vconn = std::make_shared<VirtualConnection>();
            vconn->client_sock = T::shared_from_this();
            vconn->server_port = vserver->port;
            vconn->client_port = Socket::BogusPortNumber;
        }

        if (vconn) {
            {
                std::lock_guard lock(vserver->mutex);
                vserver->waiting_connections.push_back(vconn);
            }
            std::shared_ptr<File> server = vserver->sock.lock();
            if (server) {
                std::unique_lock lock(server->get_mutex());
                server->notify(EPOLLIN, lock);
            }
            vserver->accept_wq->wake_one();
            LocalSocket::vconn = vconn;
            LocalSocket::is_client = true;
            LocalSocket::nonblock.store(T::is_nonblock(), std::memory_order_release);

            state.store(ConnectedLocal, std::memory_order_release);
            return 0;
        }

        int res = T::connect(vthread, fd, paddr, len);
        if (res == 0) {
            state.store(Connected, std::memory_order_release);
        } else if (res != -EINPROGRESS && res != -EAGAIN) {
            state.store(Initial, std::memory_order_release);
        }
        return res;
    }
    virtual int shutdown(VThread *vthread, int fd, int how) {
        return !is_local() ?
            T::shutdown(vthread, fd, how) :
            LocalSocket::shutdown(vthread, fd, how);
    }
    virtual int getsockopt(VThread *vthread, int fd, int level, int optname, void *optval, socklen_t *optlen) {
        return !is_local() ?
            T::getsockopt(vthread, fd, level, optname, optval, optlen) :
            LocalSocket::getsockopt(vthread, fd, level, optname, optval, optlen);
    }
    virtual int setsockopt(VThread *vthread, int fd, int level, int optname, const void *optval, socklen_t optlen) {
        return !is_local() ?
            T::setsockopt(vthread, fd, level, optname, optval, optlen) :
            LocalSocket::setsockopt(vthread, fd, level, optname, optval, optlen);
    }
    virtual int getsockname(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *addrlen) {
        return !is_local() ?
            T::getsockname(vthread, fd, addr, addrlen) :
            LocalSocket::getsockname(vthread, fd, addr, addrlen);
    }
    virtual int getpeername(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *addrlen) {
        return !is_local() ?
            T::getpeername(vthread, fd, addr, addrlen) :
            LocalSocket::getpeername(vthread, fd, addr, addrlen);
    }
    virtual bool is_nonblock() {
        return !is_local() ? T::is_nonblock() : LocalSocket::is_nonblock();
    }
    virtual int get_domain() {
        return T::get_domain();
    }
private:
    enum {
        Initial = 0,
        Connecting = 1,
        Connected = 2,
        ConnectedLocal = 3,
        Listen = 4,
    };
    inline bool is_local() {
        return state.load(std::memory_order_acquire) == ConnectedLocal;
    }
    int accept_once(VThread *vthread, struct sockaddr *paddr, socklen_t *plen, int flags) {
        if (!vserver->ready) {
            return -EAGAIN;
        }
        std::shared_ptr<VirtualConnection> vconn = vserver->get_conn();
        if (!vconn) {
            return -EAGAIN;
        }
        MM *mm = vthread->get_vprocess()->get_mm();
        std::lock_guard lock(vconn->mutex);
        std::shared_ptr<LocalSocket> sock = std::make_shared<LocalSocket>(get_domain());

        vconn->server_sock = sock;
        sock->vconn = vconn;
        sock->nonblock.store(flags & SOCK_NONBLOCK, std::memory_order_release);
        sock->is_client = false;
        FileTable *ft = vthread->get_vprocess()->get_file_table();
        FileDescriptor fd(nullptr, -1);
        if (paddr) {
            struct sockaddr_in a;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            a.sin_port = BogusPortNumber;
            a.sin_family = AF_INET;
            try {
                socklen_t len = mm->get_sandbox<socklen_t>(plen);
                if (len < sizeof(struct sockaddr_in)) {
                    return -EINVAL;
                }
                mm->copy_to_sandbox(paddr, &a, sizeof(struct sockaddr_in));
                mm->put_sandbox<socklen_t>(sizeof(struct sockaddr_in), plen);
            } catch (FaultException &e) {
                return -EFAULT;
            }
        }
        return ft->add_file(vthread, fd, std::static_pointer_cast<File>(sock));
    }
    std::shared_ptr<VirtualServer> vserver;
    std::atomic_int state;
    static_assert(std::is_convertible<SocketWrapper *, File *>::value, "");
};
}
