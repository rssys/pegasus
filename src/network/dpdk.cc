#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ff_api.h>
#include <ff_epoll.h>
#include "pegasus/file.h"
#include "pegasus/gate.h"
#include "pegasus/ioworker.h"
#include "pegasus/monitor.h"
#include "pegasus/runtime.h"
#include "pegasus/stat.h"
#include "pegasus/syscall.h"
#include "pegasus/uswitch.h"
#include "pegasus/network/dpdk.h"
#include "pegasus/network/network.h"
#include "pegasus/network/socket.h"

using namespace pegasus;

static MM *MonitorMM = (MM *)0x1;
static thread_local MM *active_mm;

extern "C" bool ff_copyin(const void *uaddr, void *kaddr, size_t len) {
    if (!active_mm) {
        return false;
    }
    if (active_mm == MonitorMM) {
        memcpy(kaddr, uaddr, len);
        return true;
    }
    try {
        active_mm->copy_from_sandbox(kaddr, uaddr, len);
    } catch (FaultException &e) {
        return false;
    }
    return true;
}

extern "C" bool ff_copyout(const void *kaddr, void *uaddr, size_t len) {
    if (!active_mm) {
        return false;
    }
    if (active_mm == MonitorMM) {
        memcpy(uaddr, kaddr, len);
        return true;
    }
    try {
        active_mm->copy_to_sandbox(uaddr, kaddr, len);
    } catch (FaultException &e) {
        return false;
    }
    return true;
}

extern "C" bool ff_copyinstr(const void *uaddr, void *kaddr, size_t len, size_t *done) {
    if (!active_mm) {
        return false;
    }
    size_t s = active_mm->copy_str_from_sandbox((char *)kaddr, uaddr, len);
    if (s == -1ull) {
        return false;
    }
    if (done) {
        *done = s;
    }
    return true;
}

void IOWorkerFd::reset() {
    if (fd == -1 || !iow) {
        return;
    }
    if (fp) {
        ff_fdrop(fp);
    }
    ff_close(fd);
    iow = nullptr;
    fp = nullptr;
    fd = -1;
}

void IOWorkerEpollFd::reset() {
    if (kq) {
        ff_kqueue_release(kq);
        kq = nullptr;
    }
    IOWorkerFd::reset();
}

DPDKSocket::DPDKSocket(IOWorkerFd &dfd_, int domain_, bool nonblock_)
    : File(nullptr, -1), fd(std::move(dfd_)), wq(std::make_shared<WaitQueue>()), domain(domain_) {
    nonblock.store(nonblock_, std::memory_order_release);
}

DPDKSocket::~DPDKSocket() {
    if (fd.iow) {
        fd.iow->remove_file(fd);
    }
}

ssize_t DPDKSocket::read(VThread *vthread, int fd_, void *buf, size_t len) {
    (void)fd_;
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    ssize_t res;
    pegasus_trace_time(1);
    MM *mm = vthread->get_vprocess()->get_mm();
    if (!mm->check_memory_range((uintptr_t)buf, len)) {
        return -EFAULT;
    }
    res = ff_read_fast_path(fd.fp, buf, len);
    if (res < 0) {
        res = -errno;
    }
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLIN)) {
            res = -EINTR;
            break;
        }
        pegasus_trace_time(4);
        res = ff_read_fast_path(fd.fp, buf, len);
        pegasus_trace_time(5);
        if (res < 0) {
            res = -errno;
        }
        if (res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
            break;
        }
    }
out:
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

ssize_t DPDKSocket::write(VThread *vthread, int fd_, const void *buf, size_t len) {
    (void)fd_;
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    ssize_t res;
    pegasus_trace_time(7);
    MM *mm = vthread->get_vprocess()->get_mm();
    if (!mm->check_memory_range((uintptr_t)buf, len)) {
        return -EFAULT;
    }
    res = ff_write_fast_path(fd.fp, buf, len);
    if (res < 0) {
        res = -errno;
    }
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLOUT)) {
            res = -EINTR;
            break;
        }
        res = ff_write_fast_path(fd.fp, buf, len);
        if (res < 0) {
            res = -errno;
        }
        if (res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
            break;
        }
    }
out:
    pegasus_trace_time(9);
    if (res == -EPIPE) {
        vthread->send_signal(SIGPIPE, nullptr);
    }
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

ssize_t DPDKSocket::readv_once(VThread *vthread, const struct iovec *piov, int iovcnt) {
    MM *mm = vthread->get_vprocess()->get_mm();

    std::unique_ptr<struct iovec[]> iov_slow;
    struct iovec iov_fast[MaxStackIovecSize];
    int err;
    struct iovec *iov = load_iovec(mm, piov, iovcnt, iov_slow, iov_fast, err);
    if (!iov) {
        return err;
    }

    ssize_t res;
    active_mm = mm;
    res = ff_readv_fp(fd.fd, fd.fp, iov, iovcnt);
    if (res < 0) {
        res = -errno;
    }
    active_mm = nullptr;
    return res;
}

ssize_t DPDKSocket::readv(VThread *vthread, int fd_, const struct iovec *iov, int iovcnt) {
    (void)fd_;
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    ssize_t res = readv_once(vthread, iov, iovcnt);
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLIN)) {
            res = -EINTR;
            break;
        }
        res = readv_once(vthread, iov, iovcnt);
        if (res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
            break;
        }
    }
out:
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

ssize_t DPDKSocket::writev_once(VThread *vthread, const struct iovec *piov, int iovcnt) {
    MM *mm = vthread->get_vprocess()->get_mm();

    std::unique_ptr<struct iovec[]> iov_slow;
    struct iovec iov_fast[MaxStackIovecSize];
    int err;
    struct iovec *iov = load_iovec(mm, piov, iovcnt, iov_slow, iov_fast, err);
    if (!iov) {
        return err;
    }

    ssize_t res;
    active_mm = mm;
    res = ff_writev_fp(fd.fd, fd.fp, iov, iovcnt);
    if (res < 0) {
        res = -errno;
    }
    active_mm = nullptr;
    return res;
}

ssize_t DPDKSocket::writev(VThread *vthread, int fd_, const struct iovec *iov, int iovcnt) {
    (void)fd_;
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    ssize_t res = writev_once(vthread, iov, iovcnt);
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLOUT)) {
            res = -EINTR;
            break;
        }
        res = writev_once(vthread, iov, iovcnt);
        if (res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
            break;
        }
    }
out:
    if (res == -EPIPE) {
        vthread->send_signal(SIGPIPE, nullptr);
    }
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

int DPDKSocket::fcntl(VThread *vthread, int fd_, const long *args) {
    //std::lock_guard lock(mutex);
    (void)fd_;
    int cmd = args[1];
    int res = -EPERM;
    if (cmd == F_GETFL) {
        res = ff_fcntl(fd.fd, F_GETFL);
        if (res < 0) {
            res = -errno;
        } else {
            res &= ~O_NONBLOCK;
            if (nonblock.load(std::memory_order_acquire)) {
                res |= O_NONBLOCK;
            }
        }
    } else if (cmd == F_SETFL) {
        int flags = args[2];
        int orig_flags = flags;
        flags |= O_NONBLOCK;
        res = ff_fcntl(fd.fd, F_SETFL, flags);
        if (res < 0) {
            res = -errno;
        } else {
            nonblock.store(orig_flags & O_NONBLOCK, std::memory_order_release);
        }
    } else if (cmd == F_GETFD || cmd == F_SETFD) {
        return 0;
    }
    return res;
}

int DPDKSocket::ioctl(VThread *vthread, int fd_, const long *args) {
    (void)fd_;
    MM *mm = vthread->get_vprocess()->get_mm();
    int request = args[1];
    if (request == FIONBIO) {
        int opt;
        try {
            opt = mm->get_sandbox<int>((const int *)args[2]);
        } catch (FaultException &e) {
            return -EFAULT;
        }
        nonblock.store(opt, std::memory_order_release);
        return 0;
    } else if (request == FIONREAD) {
        int res, n;
        res = ff_ioctl(fd.fd, FIONREAD, &n);
        if (res < 0) {
            return -errno;
        }
        try {
            mm->put_sandbox(n, (int *)args[2]);
        } catch (FaultException &e) {
            return -EFAULT;
        }
        return 0;
    }
    return -EPERM;
}

#define FIONSPACE 0x40046676

ssize_t DPDKSocket::sendfile_once(VThread *vthread, int in_fd, off_t *poffset, size_t len) {
    static constexpr size_t MaxSendfileBuffer = 128 * 1024;
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    USwitchContext *ucontext = vprocess->get_ucontext();
    size_t wb_space;
    if (ff_ioctl_freebsd(fd.fd, FIONSPACE, &wb_space) < 0) {
        return -EAGAIN;
    }
    if (len > wb_space) {
        len = wb_space;
    }
    if (len > MaxSendfileBuffer) {
        len = MaxSendfileBuffer;
    }
    if (len == 0) {
        return -EAGAIN;
    }
    std::unique_ptr<uint8_t[]> buf;
    try {
        buf.reset(new uint8_t[len]);
    } catch (std::bad_alloc &e) {
        return -ENOMEM;
    }
    off_t offset;
    ssize_t read_res;
    if (poffset) {
        try {
            offset = mm->get_sandbox<size_t>(poffset);
        } catch (FaultException &e) {
            return -EFAULT;
        }
        ucontext->run_on_behalf_of([&] {
            read_res = pread(in_fd, buf.get(), len, offset);
            if (read_res < 0) {
                read_res = -errno;
            }
        });
    } else {
        ucontext->run_on_behalf_of([&] {
            read_res = ::read(in_fd, buf.get(), len);
            if (read_res < 0) {
                read_res = -errno;
            }
        });
    }
    if (read_res < 0) {
        return read_res;
    }
    ssize_t write_res;
    active_mm = MonitorMM;
    write_res = ff_write_fp(fd.fd, fd.fp, buf.get(), read_res);
    if (write_res == -1) {
        write_res = -errno;
    }
    active_mm = nullptr;
    ssize_t goback_len;
    if (write_res < 0) {
        goback_len = read_res;
    } else {
        goback_len = read_res - write_res;
    }
    if (!offset) {
        if (goback_len) {
            ucontext->run_on_behalf_of([&] {
                lseek64(in_fd, -goback_len, SEEK_CUR);
            });
        }
    } else {
        offset += read_res - goback_len;
        if (poffset){
            try {
                mm->put_sandbox(offset, poffset);
            } catch (FaultException &e) {
                return -EFAULT;
            }
        }
    }
    return write_res;
}

ssize_t DPDKSocket::sendfile(VThread *vthread, int fd_, int in_fd, off_t *offset, size_t len) {
    (void)fd_;
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    ssize_t res = sendfile_once(vthread, in_fd, offset, len);
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLOUT)) {
            res = -EINTR;
            break;
        }
        res = sendfile_once(vthread, in_fd, offset, len);
        if (res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
            break;
        }
    }
out:
    if (res == -EPIPE) {
        vthread->send_signal(SIGPIPE, nullptr);
    }
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

void DPDKSocket::notify(uint32_t events, std::unique_lock<SpinLock> &lock) {
    wq->wake_all(events);
    File::notify(events, lock);
}

void DPDKSocket::notify_batch(uint32_t events, std::unique_lock<SpinLock> &lock,
                              BatchNotifyState &state) {
    wq->wake_all(events);
    File::notify_batch(events, lock, state);
}

uint32_t DPDKSocket::get_cap() {
    return FromIOWorker;
}

ssize_t DPDKSocket::recvfrom_once(VThread *vthread, void *buf, size_t len, int flags,
                                  struct sockaddr *paddr, socklen_t *paddrlen) {
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    struct sockaddr_storage addr;
    socklen_t addrlen;
    if (paddr) {
        try {
            addrlen = mm->get_sandbox<socklen_t>(paddrlen);
        } catch (FaultException &e) {
            return -EFAULT;
        }
        if (addrlen > sizeof(addr)) {
            addrlen = sizeof(addr);
        }
    }
    ssize_t res;
    active_mm = mm;
    res = ff_recvfrom_fp(fd.fd, fd.fp, buf, len, flags,
                         paddr ? (struct linux_sockaddr *)&addr : nullptr,
                         paddr ? &addrlen : nullptr);
    if (res < 0) {
        res = -errno;
    }
    active_mm = nullptr;
    if (res >= 0 && paddr) {
        try {
            mm->copy_to_sandbox(paddr, &addr, addrlen);
            mm->copy_to_sandbox(paddrlen, &addrlen, sizeof(addrlen));
        } catch (FaultException &e) {
            return -EFAULT;
        }
    }
    return res;
}

ssize_t DPDKSocket::recvfrom(VThread *vthread, int fd_, void *buf, size_t len, int flags,
                             struct sockaddr *addr, socklen_t *addrlen) {
    (void)fd_;
    bool nonblock_ = nonblock.load(std::memory_order_acquire) || (flags & MSG_DONTWAIT);
    ssize_t res = recvfrom_once(vthread, buf, len, flags, addr, addrlen);
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLIN)) {
            res = -EINTR;
            break;
        }
        res = recvfrom_once(vthread, buf, len, flags, addr, addrlen);
        if (res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
            break;
        }
    }
out:
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

ssize_t DPDKSocket::sendto_once(VThread *vthread, const void *buf, size_t len, int flags,
                                const struct sockaddr *paddr, socklen_t addrlen) {
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    struct sockaddr_storage addr;
    if (paddr) {
        if (addrlen > sizeof(addr)) {
            return -EINVAL;
        }
        try {
            mm->copy_from_sandbox(&addr, paddr, addrlen);
        } catch (FaultException &e) {
            return -EFAULT;
        }
    } else {
        addrlen = 0;
    }
    ssize_t res;
    active_mm = mm;
    res = ff_sendto_fp(fd.fd, fd.fp, buf, len, flags,
                       paddr ? (const struct linux_sockaddr *)&addr : nullptr, addrlen);
    if (res < 0) {
        res = -errno;
    }
    active_mm = nullptr;
    return res;
}

ssize_t DPDKSocket::sendto(VThread *vthread, int fd_, const void *buf, size_t len, int flags,
                           const struct sockaddr *addr, socklen_t addrlen) {
    (void)fd_;
    bool nonblock_ = nonblock.load(std::memory_order_acquire) || (flags & MSG_DONTWAIT);
    ssize_t res = sendto_once(vthread, buf, len, flags, addr, addrlen);
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLOUT)) {
            res = -EINTR;
            break;
        }
        res = sendto_once(vthread, buf, len, flags, addr, addrlen);
        if (res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
            break;
        }
    }
out:
    if (res == -EPIPE && !(flags & MSG_NOSIGNAL)) {
        vthread->send_signal(SIGPIPE, nullptr);
    }
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

ssize_t DPDKSocket::recvmsg_once(VThread *vthread, struct msghdr *pmsg, int flags) {
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    struct msghdr msg;
    try {
        mm->copy_from_sandbox(&msg, pmsg, sizeof(struct msghdr));
    } catch (FaultException &e) {
        return -EFAULT;
    }
    struct msghdr m = {};
    std::unique_ptr<struct iovec[]> iov_slow;
    struct iovec iov_fast[MaxStackIovecSize];
    int err;
    struct iovec *iov = load_iovec(mm, msg.msg_iov, msg.msg_iovlen, iov_slow, iov_fast, err);
    if (!iov) {
        return err;
    }
    m.msg_iov = iov;
    m.msg_iovlen = msg.msg_iovlen;
    struct sockaddr_storage addr;
    if (msg.msg_name) {
        if (msg.msg_namelen > sizeof(addr)) {
            m.msg_namelen = sizeof(addr);
        } else {
            m.msg_namelen = msg.msg_namelen;
        }
        m.msg_name = &addr;
    }
    if (msg.msg_control) {
        m.msg_control = msg.msg_control;
        m.msg_controllen = msg.msg_controllen;
    }
    ssize_t res;
    active_mm = mm;
    res = ff_recvmsg_fp(fd.fd, fd.fp, &m, flags);
    if (res < 0) {
        res = -errno;
    }
    active_mm = nullptr;
    if (res < 0) {
        return res;
    }
    if (msg.msg_name) {
        try {
            mm->copy_to_sandbox(msg.msg_name, &addr, m.msg_namelen);
        } catch (FaultException &e) {
            return -EFAULT;
        }
        msg.msg_namelen = m.msg_namelen;
    }
    msg.msg_controllen = m.msg_controllen;
    msg.msg_flags = m.msg_flags;
    try {
        mm->copy_to_sandbox(pmsg, &m, sizeof(m));
    } catch (FaultException &e) {
        return -EFAULT;
    }
    return res;
}

ssize_t DPDKSocket::recvmsg(VThread *vthread, int fd_, struct msghdr *msg, int flags) {
    (void)fd_;
    bool nonblock_ = nonblock.load(std::memory_order_acquire) || (flags & MSG_DONTWAIT);
    ssize_t res = recvmsg_once(vthread, msg, flags);
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLIN)) {
            res = -EINTR;
            break;
        }
        res = recvmsg_once(vthread, msg, flags);
        if (res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
            break;
        }
    }
out:
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}


ssize_t DPDKSocket::sendmsg_once(VThread *vthread, const struct msghdr *pmsg, int flags) {
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    struct msghdr msg;
    try {
        mm->copy_from_sandbox(&msg, pmsg, sizeof(struct msghdr));
    } catch (FaultException &e) {
        return -EFAULT;
    }
    struct msghdr m = {};
    std::unique_ptr<struct iovec[]> iov_slow;
    struct iovec iov_fast[MaxStackIovecSize];
    int err;
    struct iovec *iov = load_iovec(mm, msg.msg_iov, msg.msg_iovlen, iov_slow, iov_fast, err);
    if (!iov) {
        return err;
    }
    m.msg_iov = iov;
    m.msg_iovlen = msg.msg_iovlen;
    struct sockaddr_storage addr;
    if (msg.msg_name) {
        if (msg.msg_namelen > sizeof(addr)) {
            return -EINVAL;
        }
        try {
            mm->copy_from_sandbox(&addr, msg.msg_name, msg.msg_namelen);
        } catch (FaultException &e) {
            return -EFAULT;
        }
        m.msg_name = &addr;
        m.msg_namelen = msg.msg_namelen;
    }
    if (msg.msg_control) {
        m.msg_control = msg.msg_control;
        m.msg_controllen = msg.msg_controllen;
    }
    ssize_t res;
    active_mm = mm;
    res = ff_sendmsg_fp(fd.fd, fd.fp, &m, flags);
    if (res < 0) {
        res = -errno;
    }
    active_mm = nullptr;
    return res;
}

ssize_t DPDKSocket::sendmsg(VThread *vthread, int fd_, const struct msghdr *msg, int flags) {
    (void)fd_;
    bool nonblock_ = nonblock.load(std::memory_order_acquire) || (flags & MSG_DONTWAIT);
    ssize_t res = sendmsg_once(vthread, msg, flags);
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLOUT)) {
            res = -EINTR;
            break;
        }
        res = sendmsg_once(vthread, msg, flags);
        if (res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
            break;
        }
    }
out:
    if (res == -EPIPE && !(flags & MSG_NOSIGNAL)) {
        vthread->send_signal(SIGPIPE, nullptr);
    }
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

int DPDKSocket::listen(VThread *vthread, int fd_, int backlog) {
    (void)fd_;
    int res;
    res = ff_listen(fd.fd, backlog);
    if (res < 0) {
        res = -errno;
    }
    //ff_set_solisten_upcall(fd.fp, IOWorker::socket_upcall, fd.iow);
    //uint32_t revents = poll(vthread, POLLIN);
    //if (revents) {
    //    std::unique_lock lock(mutex);
    //    notify(revents, lock);
    //}
    return res;
}

int DPDKSocket::bind(VThread *vthread, int fd_, const struct sockaddr *paddr, socklen_t len) {
    (void)fd_;
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
    int res;
    res = ff_bind(fd.fd, (const struct linux_sockaddr *)&addr, len);
    if (res < 0) {
        res = -errno;
    }
    return res;
}

#define FREEBSD_SOCK_NONBLOCK 0x20000000

int DPDKSocket::accept_once(VThread *vthread, struct sockaddr *paddr, socklen_t *plen, int flags) {
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    FileTable *ft = vprocess->get_file_table();
    struct sockaddr_storage addr;
    socklen_t len;
    bool nonblock = flags & SOCK_NONBLOCK;
    if (paddr) {
        try {
            len = mm->get_sandbox<socklen_t>(plen);
        } catch (FaultException &e) {
            return -EFAULT;
        }
        if (len > sizeof(addr)) {
            len = sizeof(addr);
        }
    }
    int res;
    res = ff_accept4(fd.fd, paddr ? (struct linux_sockaddr *)&addr : nullptr,
                     paddr ? &len : nullptr, FREEBSD_SOCK_NONBLOCK);
    if (res < 0) {
        res = -errno;
    }
    if (res < 0) {
        return res;
    }
    if (paddr) {
        try {
            mm->copy_to_sandbox(paddr, &addr, len);
            mm->copy_to_sandbox(plen, &len, sizeof(socklen_t));
        } catch (FaultException &e) {
            return -EFAULT;
        }
    }
    IOWorkerFd newdfd;
    newdfd.fd = res;
    newdfd.iow = fd.iow;
    newdfd.fp = ff_fget(res);
    if (!newdfd.fp) {
        return -EBADF;
    }
    std::shared_ptr<DPDKSocket> sock = std::make_shared<DPDKSocket>(newdfd, domain, nonblock);
    //fd.iow->add_file(sock);
    
    FileDescriptor newfd;
    return ft->add_file(vthread, newfd, sock);
}

int DPDKSocket::accept4(VThread *vthread, int fd_, struct sockaddr *addr, socklen_t *len, int flags,
                        AcceptHook &hook) {
    (void)fd_;
    std::unique_lock<SpinLock> lock;
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    std::shared_ptr<WaitQueue> wwq;
    int res = hook ? hook(wwq, lock) : -1;
    if (res < 0) {
        res = accept_once(vthread, addr, len, flags);
    }
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        if (wwq) {
            if (block_until_event(EPOLLIN, wwq, lock)) {
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
            res = accept_once(vthread, addr, len, flags);
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

int DPDKSocket::connect(VThread *vthread, int fd_, const struct sockaddr *paddr, socklen_t len) {
    (void)fd_;
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
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    int res;
    res = ff_connect(fd.fd, (const struct linux_sockaddr *)&addr, len);
    if (res < 0) {
        res = -errno;
    }
    if (nonblock_ || res == 0 || res != -EINPROGRESS) {
        goto out;
    }
    while (true) {
        if (block_until_event(EPOLLOUT)) {
            res = -EINTR;
            break;
        }
        active_mm = MonitorMM;
        int err;
        socklen_t len = sizeof(int);
        res = ff_getsockopt(fd.fd, SOL_SOCKET, SO_ERROR, &err, &len);
        if (res < 0) {
            res = -errno;
        } else {
            res = -err;
        }
        active_mm = nullptr;
        if (res != -EINPROGRESS) {
            break;
        }
    }
out:
    if (res == -EINTR) {
        vthread->set_restart();
    }
    return res;
}

int DPDKSocket::shutdown(VThread *vthread, int fd_, int how) {
    (void)fd_;
    int res;
    res = ff_shutdown(fd.fd, how);
    if (res < 0) {
        res = -errno;
    }
    return res;
}

int DPDKSocket::getsockopt(VThread *vthread, int fd_, int level, int optname, void *optval, socklen_t *optlen) {
    (void)fd_;
    active_mm = vthread->get_vprocess()->get_mm();
    int res;
    res = ff_getsockopt(fd.fd, level, optname, optval, optlen);
    if (res < 0) {
        res = -errno;
    }
    active_mm = nullptr;
    return res;
}

int DPDKSocket::setsockopt(VThread *vthread, int fd_, int level, int optname, const void *optval, socklen_t optlen) {
    (void)fd_;
    active_mm = vthread->get_vprocess()->get_mm();
    int res;
    res = ff_setsockopt(fd.fd, level, optname, optval, optlen);
    if (res < 0) {
        res = -errno;
    }
    active_mm = nullptr;
    return res;
}

int DPDKSocket::getsockname(VThread *vthread, int fd_, struct sockaddr *paddr, socklen_t *paddrlen) {
    (void)fd_;
    MM *mm = vthread->get_vprocess()->get_mm();
    struct sockaddr_storage addr;
    socklen_t len;
    try {
        len = mm->get_sandbox<socklen_t>(paddrlen);
    } catch (FaultException &e) {
        return -EFAULT;
    }
    if (len > sizeof(addr)) {
        len = sizeof(addr);
    }
    int res;
    res = ff_getsockname(fd.fd, (struct linux_sockaddr *)&addr, &len);
    if (res < 0) {
        res = -errno;
    }
    if (res == 0) {
        try {
            mm->copy_to_sandbox(paddr, &addr, len);
            mm->copy_to_sandbox(paddrlen, &len, sizeof(socklen_t));
        } catch (FaultException &e) {
            return -EFAULT;
        }
    }
    return res;
}

int DPDKSocket::getpeername(VThread *vthread, int fd_, struct sockaddr *paddr, socklen_t *paddrlen) {
    (void)fd_;
    MM *mm = vthread->get_vprocess()->get_mm();
    struct sockaddr_storage addr;
    socklen_t len;
    try {
        len = mm->get_sandbox<socklen_t>(paddrlen);
    } catch (FaultException &e) {
        return -EFAULT;
    }
    if (len > sizeof(addr)) {
        len = sizeof(addr);
    }
    int res;
    res = ff_getpeername(fd.fd, (struct linux_sockaddr *)&addr, &len);
    if (res < 0) {
        res = -errno;
    }
    if (res == 0) {
        try {
            mm->copy_to_sandbox(paddr, &addr, len);
            mm->copy_to_sandbox(paddrlen, &len, sizeof(socklen_t));
        } catch (FaultException &e) {
            return -EFAULT;
        }
    }
    return res;
}

bool DPDKSocket::is_nonblock() {
    return nonblock.load(std::memory_order_acquire);
}

int DPDKSocket::get_domain() {
    return domain;
}

bool DPDKSocket::block_until_event(uint32_t events) {
    std::shared_ptr<Task> task = Executor::get_current_task();
    wq->add_task(task);
    uintptr_t key = fd.iow->poll_file(fd, wq, task, events | EPOLLERR | EPOLLHUP);
    Executor::block();
    if (!task->wq_res.from_iow) {
        fd.iow->cancel_poll_file(fd, key);
    }
    return task->wq_res.from_signal;
}

bool DPDKSocket::block_until_event(uint32_t events, const std::shared_ptr<WaitQueue> &wwq,
                                   std::unique_lock<SpinLock> &lock) {
    std::shared_ptr<Task> task = Executor::get_current_task();
    wwq->add_task(task);
    uintptr_t key = fd.iow->poll_file(fd, wwq, task, events | EPOLLERR | EPOLLHUP);
    lock.unlock();
    Executor::block();
    lock.lock();
    if (!task->wq_res.from_iow) {
        fd.iow->cancel_poll_file(fd, key);
    }
    return task->wq_res.from_signal;
}

DPDKSocketWithLO::DPDKSocketWithLO(USwitchContext *ucontext, int fd, IOWorkerFd &dfd,
                                   int domain, bool nonblock)
    : File(ucontext, fd), DPDKSocket(dfd, domain, nonblock),
      LinuxSocket(ucontext, fd, domain) {
    LinuxSocket::nonblock.store(nonblock, std::memory_order_relaxed);
}

DPDKSocketWithLO::~DPDKSocketWithLO() {
}

ssize_t DPDKSocketWithLO::read(VThread *vthread, int fd, void *buf, size_t len) {
    return !is_local() ?
        DPDKSocket::read(vthread, fd, buf, len) :
        LinuxSocket::read(vthread, fd, buf, len);
}

ssize_t DPDKSocketWithLO::write(VThread *vthread, int fd, const void *buf, size_t len) {
    return !is_local() ?
        DPDKSocket::write(vthread, fd, buf, len) :
        LinuxSocket::write(vthread, fd, buf, len);
}

ssize_t DPDKSocketWithLO::readv(VThread *vthread, int fd, const struct iovec *iov, int iovcnt)  {
    return !is_local() ?
        DPDKSocket::readv(vthread, fd, iov, iovcnt) :
        LinuxSocket::readv(vthread, fd, iov, iovcnt);
}

ssize_t DPDKSocketWithLO::writev(VThread *vthread, int fd, const struct iovec *iov, int iovcnt) {
    return !is_local() ?
        DPDKSocket::writev(vthread, fd, iov, iovcnt) :
        LinuxSocket::writev(vthread, fd, iov, iovcnt);
}

int DPDKSocketWithLO::fcntl(VThread *vthread, int fd, const long *args) {
    return !is_local() ?
        DPDKSocket::fcntl(vthread, fd, args) :
        LinuxSocket::fcntl(vthread, fd, args);
}

int DPDKSocketWithLO::ioctl(VThread *vthread, int fd, const long *args) {
    return !is_local() ?
        DPDKSocket::ioctl(vthread, fd, args) :
        LinuxSocket::ioctl(vthread, fd, args);
}

ssize_t DPDKSocketWithLO::sendfile(VThread *vthread, int fd, int in_fd, off_t *offset, size_t len) {
    return !is_local() ?
        DPDKSocket::sendfile(vthread, fd, in_fd, offset, len) :
        LinuxSocket::sendfile(vthread, fd, in_fd, offset, len);
}

uint32_t DPDKSocketWithLO::poll(VThread *vthread, uint32_t events) {
    return DPDKSocket::poll(vthread, events);
}

void DPDKSocketWithLO::notify(uint32_t events, std::unique_lock<SpinLock> &lock) {
    if (is_local()) {
        LinuxSocket::notify(events, lock);
    } else {
        DPDKSocket::notify(events, lock);
    }
}

uint32_t DPDKSocketWithLO::get_cap() {
    return !is_local() ?
        (DPDKSocket::get_cap() | LinuxSocket::get_cap()) :
        (LinuxSocket::get_cap() | OverlayIOW);
}

ssize_t DPDKSocketWithLO::recvfrom(VThread *vthread, int fd, void *buf, size_t len, int flags,
                         struct sockaddr *addr, socklen_t *addrlen) {
        return !is_local() ?
        DPDKSocket::recvfrom(vthread, fd, buf, len, flags, addr, addrlen) :
        LinuxSocket::recvfrom(vthread, fd, buf, len, flags, addr, addrlen);
}

ssize_t DPDKSocketWithLO::sendto(VThread *vthread, int fd, const void *buf, size_t len, int flags,
                       const struct sockaddr *addr, socklen_t addrlen) {
        return !is_local() ?
        DPDKSocket::sendto(vthread, fd, buf, len, flags, addr, addrlen) :
        LinuxSocket::sendto(vthread, fd, buf, len, flags, addr, addrlen);
}

ssize_t DPDKSocketWithLO::recvmsg(VThread *vthread, int fd, struct msghdr *msg, int flags) {
        return !is_local() ?
        DPDKSocket::recvmsg(vthread, fd, msg, flags) :
        LinuxSocket::recvmsg(vthread, fd, msg, flags);
}

ssize_t DPDKSocketWithLO::sendmsg(VThread *vthread, int fd, const struct msghdr *msg, int flags) {
        return !is_local() ?
        DPDKSocket::sendmsg(vthread, fd, msg, flags) :
        LinuxSocket::sendmsg(vthread, fd, msg, flags);
}

int DPDKSocketWithLO::listen(VThread *vthread, int fd, int backlog) {
    int res = DPDKSocket::listen(vthread, fd, backlog);
    if (res < 0) {
        return res;
    }
    res = LinuxSocket::listen(vthread, fd, backlog);
    if (res < 0) {
        return res;
    }
    state.store(Listen, std::memory_order_release);
    return 0;
}

int DPDKSocketWithLO::bind(VThread *vthread, int fd, const struct sockaddr *paddr, socklen_t len) {
    struct sockaddr_storage addr;
    if (len > sizeof(struct sockaddr_storage)) {
        return -EINVAL;
    }
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    USwitchContext *ucontext = vprocess->get_ucontext();
    try {
        mm->copy_from_sandbox(&addr, paddr, len);
    } catch (FaultException &e) {
        return -EFAULT;
    }
    int res = DPDKSocket::bind(vthread, fd, paddr, len);
    if (res < 0) {
        return res;
    }
    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&addr;
        a->sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&addr;
        memcpy(&a->sin6_addr, &in6addr_any, sizeof(in6_addr));
    } else {
        return 0;
    }
    ucontext->run_on_behalf_of([&] {
        res = ::bind(fd, (struct sockaddr *)&addr, len);
        if (res < 0) {
            res = -errno;
        }
    });
    return res;
}

int DPDKSocketWithLO::accept4(VThread *vthread, int fd_, struct sockaddr *addr, socklen_t *len, int flags,
                              AcceptHook &hook) {
    if (state.load(std::memory_order_acquire) != Listen) {
        return -EINVAL;
    }
    bool nonblock_ = DPDKSocket::is_nonblock();
    int res = DPDKSocket::accept_once(vthread, addr, len, flags);
    if (res < 0) {
        res = LinuxSocket::accept_once(vthread, fd_, addr, len, flags);
    }
    if (nonblock_ || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    while (true) {
        std::shared_ptr<Task> task = Executor::get_current_task();
        Executor::get_current_executor()->get_eq().
            add_task_poll_timeout(wq, task, monitor_file.fd, EPOLLIN);
        uintptr_t key = fd.iow->poll_file(fd, wq, task, EPOLLIN | EPOLLERR | EPOLLHUP);
        Executor::block();
        if (!task->wq_res.from_iow) {
            fd.iow->cancel_poll_file(fd, key);
        }
        if (task->wq_res.from_signal) {
            res = -EINTR;
            goto out;
        }
        res = DPDKSocket::accept_once(vthread, addr, len, flags);
        if (res < 0) {
            res = LinuxSocket::accept_once(vthread, fd_, addr, len, flags);
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

int DPDKSocketWithLO::connect(VThread *vthread, int fd, const struct sockaddr *paddr, socklen_t len) {
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

    bool is_local = false;
    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&addr;
        if (a->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
            is_local = true;
        }
    } else if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&addr;
        if (!memcmp(&a->sin6_addr, &in6addr_loopback, sizeof(in6_addr))) {
            is_local = true;
        }
    }
    int res;
    if (is_local) {
        LinuxSocket::nonblock.store(DPDKSocket::is_nonblock(), std::memory_order_release);
        res = LinuxSocket::connect(vthread, fd, paddr, len);
        if (res == -EINPROGRESS) {
            state.store(ConnectingLocal, std::memory_order_release);
        }
    } else {
        res = DPDKSocket::connect(vthread, fd, paddr, len);
    }
    if (res == 0) {
        if (is_local) {
            state.store(ConnectedLocal, std::memory_order_release);
        } else {
            state.store(Connected, std::memory_order_release);
        }
    } else if (res != -EINPROGRESS && res != -EAGAIN) {
        state.store(Initial, std::memory_order_release);
    }
    return res;
}

int DPDKSocketWithLO::shutdown(VThread *vthread, int fd, int how) {
    return !is_local() ?
        DPDKSocket::shutdown(vthread, fd, how) :
        LinuxSocket::shutdown(vthread, fd, how);
}

int DPDKSocketWithLO::getsockopt(VThread *vthread, int fd, int level, int optname, void *optval, socklen_t *optlen) {
    return !is_local() ?
        DPDKSocket::getsockopt(vthread, fd, level, optname, optval, optlen) :
        LinuxSocket::getsockopt(vthread, fd, level, optname, optval, optlen);
}

int DPDKSocketWithLO::setsockopt(VThread *vthread, int fd, int level, int optname, const void *optval, socklen_t optlen) {
    return !is_local() ?
        DPDKSocket::setsockopt(vthread, fd, level, optname, optval, optlen) :
        LinuxSocket::setsockopt(vthread, fd, level, optname, optval, optlen);
}

int DPDKSocketWithLO::getsockname(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *addrlen) {
    return !is_local() ?
        DPDKSocket::getsockname(vthread, fd, addr, addrlen) :
        LinuxSocket::getsockname(vthread, fd, addr, addrlen);
}

int DPDKSocketWithLO::getpeername(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *addrlen) {
    return !is_local() ?
        DPDKSocket::getpeername(vthread, fd, addr, addrlen) :
        LinuxSocket::getpeername(vthread, fd, addr, addrlen);
}

bool DPDKSocketWithLO::is_nonblock() {
    return !is_local() ? DPDKSocket::is_nonblock() : LinuxSocket::is_nonblock();
}

int DPDKSocketWithLO::get_domain() {
    return DPDKSocket::get_domain();
}