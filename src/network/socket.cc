#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "pegasus/file.h"
#include "pegasus/monitor.h"
#include "pegasus/runtime.h"
#include "pegasus/stat.h"
#include "pegasus/syscall.h"
#include "pegasus/uswitch.h"
#include "pegasus/network/network.h"
#include "pegasus/network/socket.h"

using namespace pegasus;

ssize_t Socket::recvfrom(VThread *vthread, int fd, void *buf, size_t len, int flags,
                         struct sockaddr *addr, socklen_t *addrlen) {
    return -ENOTSOCK;
}

ssize_t Socket::sendto(VThread *vthread, int fd, const void *buf, size_t len, int flags,
                       const struct sockaddr *addr, socklen_t addrlen) {
    return -ENOTSOCK;
}

ssize_t Socket::recvmsg(VThread *vthread, int fd, struct msghdr *msg, int flags) {
    return -ENOTSOCK;
}

ssize_t Socket::sendmsg(VThread *vthread, int fd, const struct msghdr *msg, int flags) {
    return -ENOTSOCK;
}

int Socket::listen(VThread *vthread, int fd, int backlog) {
    return -ENOTSOCK;
}

int Socket::bind(VThread *vthread, int fd, const sockaddr *addr, socklen_t len) {
    return -ENOTSOCK;
}

int Socket::accept4(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *len, int flags,
                    AcceptHook &hook) {
    return -ENOTSOCK;
}

int Socket::connect(VThread *vthread, int fd, const struct sockaddr *addr, socklen_t len) {
    return -ENOTSOCK;
}

int Socket::shutdown(VThread *vthread, int fd, int how) {
    return -ENOTSOCK;
}

int Socket::getsockopt(VThread *vthread, int fd, int level, int optname, void *optval, socklen_t *optlen) {
    return -ENOTSOCK;
}

int Socket::setsockopt(VThread *vthread, int fd, int level, int optname, const void *optval, socklen_t optlen) {
    return -ENOTSOCK;
}

int Socket::getsockname(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *addrlen) {
    return -ENOTSOCK;
}

int Socket::getpeername(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *addrlen) {
    return -ENOTSOCK;
}

bool Socket::is_nonblock() {
    return false;
}

int Socket::get_domain() {
    return -ENOTSOCK;
}

bool LinuxSocket::create(VThread *vthread, FDFilePair &out, bool local,
                         int domain, int type, int protocol) {
    USwitchContext *ucontext = vthread->get_vprocess()->get_ucontext();
    int res;
    bool no_local = type & NoFastPath;
    type &= ~NoFastPath;
    ucontext->run_on_behalf_of([&] {
        res = socket(domain, type | SOCK_NONBLOCK, protocol);
        if (res == -1) {
            res = -errno;
        }
    });
    if (res < 0) {
        return false;
    }
    FileDescriptor fd(ucontext, res);
    std::shared_ptr<File> file;
    if (local && !no_local) {
        SocketWrapper<LinuxSocket> *s;
        try {
            s = new SocketWrapper<LinuxSocket>(
                    ucontext, fd.fd, domain, type, protocol, ucontext, fd.fd, domain);
        } catch (std::bad_alloc &e) {
            return false;
        }
        if (type & SOCK_NONBLOCK) {
            s->LinuxSocket::nonblock.store(true, std::memory_order_relaxed);
        }
        file = std::shared_ptr<SocketWrapper<LinuxSocket>>(s);
    } else {
        LinuxSocket *s;
        try {
            s = new LinuxSocket(ucontext, fd.fd, domain);
        } catch (std::bad_alloc &e) {
            return false;
        }
        if (type & SOCK_NONBLOCK) {
            s->nonblock.store(true, std::memory_order_relaxed);
        }
        file = std::shared_ptr<LinuxSocket>(s);
    }
    out.fd = std::move(fd);
    out.file = file;
    return true;
}

int LinuxSocket::socketpair(VThread *vthread, int domain, int type, int protocol, FDFilePair out[2]) {
    VProcess *vprocess = vthread->get_vprocess();
    USwitchContext *ucontext = vprocess->get_ucontext();
    int res;
    int sv[2];
    ucontext->run_on_behalf_of([&] {
        res = ::socketpair(domain, type | SOCK_NONBLOCK, protocol, sv);
        if (res < 0) {
            res = -errno;
        }
    });
    if (res < 0) {
        return res;
    }
    FileDescriptor fds[2] = {
        {ucontext, sv[0]},
        {ucontext, sv[1]}
    };
    LinuxSocket *socks[2];
    try {
        socks[0] = new LinuxSocket(ucontext, sv[0], domain);
        socks[1] = new LinuxSocket(ucontext, sv[1], domain);
    } catch (FaultException &e) {
        return -ENOMEM;
    }
    if (type & SOCK_NONBLOCK) {
        socks[0]->nonblock.store(true, std::memory_order_relaxed);
        socks[0]->nonblock.store(true, std::memory_order_relaxed);
    }
    out[0].fd = std::move(fds[0]);
    out[0].file.reset(socks[0]);
    out[1].fd = std::move(fds[1]);
    out[1].file.reset(socks[1]);
    return 0;
}

LinuxSocket::LinuxSocket(USwitchContext *ucontext, int fd_, int domain_)
    : File(ucontext, fd_), NonblockingFile(ucontext, fd_), domain(domain_) {
}

LinuxSocket::~LinuxSocket() {
}

ssize_t LinuxSocket::recvfrom(VThread *vthread, int fd, void *buf, size_t len, int flags,
                              struct sockaddr *paddr, socklen_t *paddrlen) {
    bool nonblock_ = nonblock.load(std::memory_order_acquire) || (flags & MSG_DONTWAIT);
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    USwitchContext *ucontext = vprocess->get_ucontext();
    if (!mm->check_memory_range((uintptr_t)buf, len)) {
        return -EFAULT;
    }
    socklen_t addrlen = 0;
    if (paddrlen) {
        try {
            addrlen = mm->get_sandbox<socklen_t>(paddrlen);
        } catch (FaultException &e) {
            return -EFAULT;
        }
        if (!mm->check_memory_range((uintptr_t)paddr, addrlen)) {
            return -EFAULT;
        }
    } else {
        paddr = nullptr;
    }
    ssize_t res = ucontext->invoke_fd_syscall(::recvfrom, fd, get_monitor_fd(),
                                              buf, len, flags, paddr, paddrlen);
    if (nonblock_ || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLIN)) {
            res = -EINTR;
            break;
        }
        res = ucontext->invoke_fd_syscall(::recvfrom, fd, get_monitor_fd(),
                                          buf, len, flags, paddr, paddrlen);
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

ssize_t LinuxSocket::sendto(VThread *vthread, int fd, const void *buf, size_t len, int flags,
                       const struct sockaddr *paddr, socklen_t addrlen) {
    bool nonblock_ = nonblock.load(std::memory_order_acquire) || (flags & MSG_DONTWAIT);
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    USwitchContext *ucontext = vprocess->get_ucontext();
    if (!mm->check_memory_range((uintptr_t)buf, len)) {
        return -EFAULT;
    }
    if (paddr) {
        if (!mm->check_memory_range((uintptr_t)paddr, addrlen)) {
            return -EFAULT;
        }
    } else {
        addrlen = 0;
    }
    ssize_t res = ucontext->invoke_fd_syscall(::sendto, fd, get_monitor_fd(),
                                              buf, len, flags, paddr, addrlen);
    if (nonblock_ || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLOUT)) {
            res = -EINTR;
            break;
        }
        res = ucontext->invoke_fd_syscall(::sendto, fd, get_monitor_fd(),
                                          buf, len, flags, paddr, addrlen);
        if (res != -EAGAIN && res != -EWOULDBLOCK) {
            break;
        }
    }
out:
    if (res == -EPIPE && !(flags & MSG_NOSIGNAL)) {
        siginfo_t si = {};
        si.si_code = SI_KERNEL;
        vthread->send_signal(SIGPIPE, &si);
    }
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

ssize_t LinuxSocket::recvmsg(VThread *vthread, int fd, struct msghdr *msg, int flags) {
    bool nonblock_ = nonblock.load(std::memory_order_acquire) || (flags & MSG_DONTWAIT);
    long args[6] = {fd, (long)msg, flags};
    ssize_t res = vthread->invoke_syscall(SYS_recvmsg, args);
    if (nonblock_ || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLIN)) {
            res = -EINTR;
            break;
        }
        res = vthread->invoke_syscall(SYS_recvmsg, args);
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

ssize_t LinuxSocket::sendmsg(VThread *vthread, int fd, const struct msghdr *msg, int flags) {
    bool nonblock_ = nonblock.load(std::memory_order_acquire) || (flags & MSG_DONTWAIT);
    long args[6] = {fd, (long)msg, flags};
    ssize_t res = vthread->invoke_syscall(SYS_sendmsg, args);
    if (nonblock_ || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLOUT)) {
            res = -EINTR;
            break;
        }
        res = vthread->invoke_syscall(SYS_sendmsg, args);
        if (res != -EAGAIN && res != -EWOULDBLOCK) {
            break;
        }
    }
out:
    if (res == -EPIPE && !(flags & MSG_NOSIGNAL)) {
        siginfo_t si = {};
        si.si_code = SI_KERNEL;
        vthread->send_signal(SIGPIPE, &si);
    }
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

int LinuxSocket::listen(VThread *vthread, int fd, int backlog) {
    USwitchContext *ucontext = vthread->get_vprocess()->get_ucontext();
    return ucontext->invoke_fd_syscall(::listen, fd, get_monitor_fd(), backlog);
}

int LinuxSocket::bind(VThread *vthread, int fd, const struct sockaddr *paddr, socklen_t len) {
    MM *mm = vthread->get_vprocess()->get_mm();
    USwitchContext *ucontext = vthread->get_vprocess()->get_ucontext();
    if (!mm->check_memory_range((uintptr_t)paddr, len)) {
        return -EFAULT;
    }
    int res;
    ucontext->run_on_behalf_of([&] {
        res = ::bind(fd, paddr, len);
        if (res < 0) {
            res = -errno;
        }
    });
    return res;
}

int LinuxSocket::accept_once(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *len, int flags) {
    bool conn_nonblock = flags & SOCK_NONBLOCK;
    long args[6] = {fd, (long)addr, (long)len, SOCK_NONBLOCK};
    int res = vthread->invoke_syscall(SYS_accept4, args);
    if (res < 0) {
        return res;
    }
    VProcess *vprocess = vthread->get_vprocess();
    USwitchContext *ucontext = vprocess->get_ucontext();
    FileTable *file_table = vprocess->get_file_table();
    std::shared_ptr<LinuxSocket> socket;
    try {
        socket.reset(new LinuxSocket(ucontext, res, domain));
    } catch (std::bad_alloc &e) {
        return -ENOMEM;
    }
    FileDescriptor newfd(ucontext, res);
    socket->nonblock.store(conn_nonblock, std::memory_order_relaxed);
    return file_table->add_file(vthread, newfd, socket);
}

int LinuxSocket::accept4(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *len, int flags,
                         AcceptHook &hook) {
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    std::shared_ptr<WaitQueue> wq;
    std::unique_lock<SpinLock> lock;
    int res = hook ? hook(wq, lock) : -1;
    if (res < 0) {
        res = accept_once(vthread, fd, addr, len, flags);
    }
    if (nonblock_ || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (wq) {
            if (block_until_event(EPOLLIN, wq, lock)) {
                res = -EINTR;
                break;
            }
        } else {
            if (block_until_event(EPOLLIN)) {
                res = -EINTR;
                break;
            }
        }
        res = hook ? hook(wq, lock) : -1;
        if (res < 0) {
            res = accept_once(vthread, fd, addr, len, flags);
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

int LinuxSocket::connect(VThread *vthread, int fd, const struct sockaddr *paddr, socklen_t len) {
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    MM *mm = vthread->get_vprocess()->get_mm();
    USwitchContext *ucontext = vthread->get_vprocess()->get_ucontext();
    struct sockaddr_storage addr;
    if (len > sizeof(addr)) {
        return -EINVAL;
    }
    try {
        mm->copy_from_sandbox(&addr, paddr, len);
    } catch (FaultException &e) {
        return -EFAULT;
    }
    int res;
    // must use sandbox's ucontext for network namespace
    ucontext->run_on_behalf_of([&] {
        res = ::connect(fd, (struct sockaddr *)&addr, len);
        if (res < 0) {
            res = -errno;
        }
    });
    if (nonblock_ || !((res == -EAGAIN && domain == AF_LOCAL) || res == -EINPROGRESS)) {
        return res;
    }
    while (true) {
        if (block_until_event(EPOLLOUT)) {
            res = -EINTR;
            break;
        }
        ucontext->run_on_behalf_of([&] {
            int err;
            socklen_t len = sizeof(err);
            res = ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
            if (res == -1) {
                res = -errno;
            } else {
                res = -err;
            }
        });
        if (!(res == -EAGAIN && domain == AF_LOCAL) && res != -EINPROGRESS) {
            break;
        }
    }
    return res;
}

int LinuxSocket::shutdown(VThread *vthread, int fd, int how) {
    USwitchContext *ucontext = vthread->get_vprocess()->get_ucontext();
    return ucontext->invoke_fd_syscall(::shutdown, fd, get_monitor_fd(), how);
}

int LinuxSocket::getsockopt(VThread *vthread, int fd, int level, int optname, void *optval, socklen_t *optlen) {
    long args[6] = {fd, level, optname, (long)optval, (long)optlen};
    long res = vthread->invoke_syscall(SYS_getsockopt, args);
    return res;
}

int LinuxSocket::setsockopt(VThread *vthread, int fd, int level, int optname, const void *optval, socklen_t optlen) {
    long args[6] = {fd, level, optname, (long)optval, (long)optlen};
    return vthread->invoke_syscall(SYS_setsockopt, args);
}

int LinuxSocket::getsockname(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *addrlen) {
    long args[6] = {fd, (long)addr, (long)addrlen};
    return vthread->invoke_syscall(SYS_getsockname, args);
}

int LinuxSocket::getpeername(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *addrlen) {
    long args[6] = {fd, (long)addr, (long)addrlen};
    return vthread->invoke_syscall(SYS_getpeername, args);
}

bool LinuxSocket::is_nonblock() {
    return nonblock.load(std::memory_order_acquire);
}

int LinuxSocket::get_domain() {
    return domain;
}
