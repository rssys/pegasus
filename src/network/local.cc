#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/in.h>
#include "pegasus/monitor.h"
#include "pegasus/stat.h"
#include "pegasus/wait_queue.h"
#include "pegasus/network/local.h"
#include "pegasus/network/network.h"

using namespace pegasus;

Pipe::Pipe(size_t buffer_size_)
    : buffer(nullptr), buffer_size(buffer_size_), write_ptr(0), read_ptr(0),
      shutdown_write(false), shutdown_read(false) {
    buffer = new uint8_t[buffer_size];
    if (buffer_size & (buffer_size - 1)) {
        throw Exception("ring buffer size is not the power of 2");
    }
}

Pipe::~Pipe() {
    delete[] buffer;
}

extern std::vector<std::tuple<int, int, uint64_t>> *timestamps;

template <typename T>
static bool check_iov(Pipe::CachedPointer &c, T &r) {
    if (r.vec[0].start > c.n || r.vec[1].start > c.n) {
        goto fail;
    }
    if (r.vec[0].start + r.vec[0].size > c.n || r.vec[1].start + r.vec[1].size > c.n) {
        goto fail;
    }
    if (r.vec[0].start + r.vec[0].size < r.vec[0].start || r.vec[1].start + r.vec[1].size < r.vec[1].start) {
        goto fail;
    }
    return true;
fail:
    printf("N: %lx S: %lx, Vec0: %lx %lx, Vec1: %lx %lx\n",
           c.n, r.s, r.vec[0].start, r.vec[0].size, r.vec[1].start, r.vec[1].size);
    return false;
}

Pipe::Reservation Pipe::reserve(Pipe::CachedPointer &curr, size_t size) {
    Reservation reserv{};
    reserv.w = curr.w;
    size_t s = curr.free_space();
    if (s > size) {
        s = size;
    }
    if (s == 0) {
        return reserv;
    }
    size_t w = curr.wrap(curr.w);
    size_t r = curr.wrap(curr.r);
    if (w >= r) {
        //assert(curr.n - (w - r) == curr.free_space());
        size_t s1 = curr.n - w;
        size_t s2;
        if (s <= s1) {
            s1 = s;
            s2 = 0;
        } else {
            s2 = s - s1;
        }
        reserv.vec[0].start = w;
        reserv.vec[0].size = s1;
        reserv.vec[1].start = 0;
        reserv.vec[1].size = s2;
    } else {
        //assert(r - w == curr.free_space());
        reserv.vec[0].start = w;
        reserv.vec[0].size = s;
    }
    reserv.s = s;
    reserv.w = curr.wrap2(curr.w + s);
    curr.w = reserv.w;
    //assert(check_iov(curr, reserv));
    return reserv;
}

Pipe::Retrieve Pipe::retrieve(CachedPointer &curr, size_t size) {
    Retrieve retr{};
    retr.r = curr.r;
    size_t s = curr.used_space();
    if (s > size) {
        s = size;
    }
    if (s == 0) {
        return retr;
    }
    size_t w = curr.wrap(curr.w);
    size_t r = curr.wrap(curr.r);
    if (w > r) {
        //assert(w - r == curr.used_space());
        retr.vec[0].start = r;
        retr.vec[0].size = s;
    } else {
        //assert(curr.n - (r - w) == curr.used_space());
        size_t s1 = curr.n - r;
        size_t s2;
        if (s <= s1) {
            s1 = s;
            s2 = 0;
        } else {
            s2 = s - s1;
        }
        retr.vec[0].start = r;
        retr.vec[0].size = s1;
        retr.vec[1].start = 0;
        retr.vec[1].size = s2;
    }
    retr.s = s;
    retr.r = curr.wrap2(curr.r + s);
    curr.r = retr.r;
    //assert(check_iov(curr, retr));
    return retr;
}

void Pipe::commit_write(CachedPointer &curr) {
    write_ptr.store(curr.w, std::memory_order_release);
}

void Pipe::commit_read(CachedPointer &curr) {
    read_ptr.store(curr.r, std::memory_order_release);
}

ssize_t Pipe::write(VThread *vthread, const uint8_t *buf, size_t size, uint32_t &peer_events) {
    std::shared_ptr<Task> task = Executor::get_current_task();
    std::unique_lock lock(write_mutex);
    if (shutdown_write.load(std::memory_order_acquire)) {
        return -EPIPE;
    }
    if (size == 0) {
        return 0;
    }
    CachedPointer curr = get_cached_pointer();
    if (curr.full()) {
        return -EAGAIN;
    }

    MM *mm = vthread->get_vprocess()->get_mm();
    Reservation reserv = reserve(curr, size);
    ssize_t n = 0;
    try {
        for (int i = 0; i < 2; ++i) {
            if (reserv.vec[i].size) {
                mm->copy_from_sandbox(buffer + reserv.vec[i].start, buf + n, reserv.vec[i].size);
                n += reserv.vec[i].size;
            }
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }
    commit_write(curr);
    peer_events = EPOLLIN;
    return n;
}

ssize_t Pipe::read(VThread *vthread, uint8_t *buf, size_t size, uint32_t &peer_events, bool peek) {
    std::shared_ptr<Task> task = Executor::get_current_task();
    std::unique_lock lock(read_mutex);
    CachedPointer curr = get_cached_pointer();
    if (curr.empty()) {
        if (shutdown_write.load(std::memory_order_acquire)) {
            shutdown_read.store(true, std::memory_order_release);
        }
        if (shutdown_read.load(std::memory_order_acquire)) {
            return 0;
        } else {
            return -EAGAIN;
        }
    }

    if (size == 0) {
        return 0;
    }

    if (curr.empty()) {
        return -EAGAIN;
    }

    MM *mm = vthread->get_vprocess()->get_mm();
    Retrieve retr = retrieve(curr, size);
    ssize_t n = 0;
    try {
        for (int i = 0; i < 2; ++i) {
            if (retr.vec[i].size) {
                mm->copy_to_sandbox(buf + n, buffer + retr.vec[i].start, retr.vec[i].size);
                n += retr.vec[i].size;
            }
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }
    if (!peek) {
        commit_read(curr);
        peer_events = EPOLLOUT;
        if (curr.empty() && shutdown_write.load(std::memory_order_acquire)) {
            shutdown_read.store(true, std::memory_order_release);
        }
    }
    return n;
}

ssize_t Pipe::writev(VThread *vthread, const struct iovec *iov, int iovcnt, uint32_t &peer_events) {
    std::shared_ptr<Task> task = Executor::get_current_task();
    std::unique_lock lock(write_mutex);
    if (shutdown_write.load(std::memory_order_acquire)) {
        return -EPIPE;
    }
    CachedPointer curr = get_cached_pointer();
    if (curr.full()) {
        return -EAGAIN;
    }

    MM *mm = vthread->get_vprocess()->get_mm();
    ssize_t n = 0;
    try {
        for (int i = 0; i < iovcnt; ++i) {
            Reservation reserv = reserve(curr, iov[i].iov_len);
            if (!reserv.s) {
                break;
            }
            ssize_t m = 0;
            for (int j = 0; j < 2; ++j) {
                if (reserv.vec[j].size) {
                    mm->copy_from_sandbox(buffer + reserv.vec[j].start,
                                          (uint8_t *)iov[i].iov_base + m,
                                          reserv.vec[j].size);
                    m += reserv.vec[j].size;
                }
            }
            n += m;
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }
    commit_write(curr);
    peer_events = EPOLLIN;
    return n;
}

ssize_t Pipe::readv(VThread *vthread, const struct iovec *iov, int iovcnt, uint32_t &peer_events, bool peek) {
    std::shared_ptr<Task> task = Executor::get_current_task();
    std::unique_lock lock(read_mutex);
    CachedPointer curr = get_cached_pointer();
    if (curr.empty()) {
        if (shutdown_write.load(std::memory_order_acquire)) {
            shutdown_read.store(true, std::memory_order_release);
        }
        if (shutdown_read.load(std::memory_order_acquire)) {
            return 0;
        } else {
            return -EAGAIN;
        }
    }

    if (curr.empty()) {
        return -EAGAIN;
    }

    MM *mm = vthread->get_vprocess()->get_mm();
    ssize_t n = 0;
    try {
        for (int i = 0; i < iovcnt; ++i) {
            Retrieve retr = retrieve(curr, iov[i].iov_len);
            if (!retr.s) {
                break;
            }
            ssize_t m = 0;
            for (int j = 0; j < 2; ++j) {
                if (retr.vec[j].size) {
                    mm->copy_to_sandbox((uint8_t *)iov[i].iov_base + m,
                                        buffer + retr.vec[j].start,
                                        retr.vec[j].size);
                    m += retr.vec[j].size;
                }
            }
            n += m;
        }
    } catch (FaultException &e) {
        return -EFAULT;
    }
    if (!peek) {
        commit_read(curr);
        peer_events = EPOLLOUT;
        if (curr.empty() && shutdown_write.load(std::memory_order_acquire)) {
            shutdown_read.store(true, std::memory_order_release);
        }
    }
    return n;
}

ssize_t Pipe::sendfile(VThread *vthread, int in_fd, off_t *offset, size_t size, uint32_t &peer_events) {
    std::shared_ptr<Task> task = Executor::get_current_task();
    std::unique_lock lock(write_mutex);
    if (shutdown_write.load(std::memory_order_acquire)) {
        return -EPIPE;
    }
    if (size == 0) {
        return 0;
    }
    CachedPointer curr = get_cached_pointer();
    if (curr.full()) {
        return -EAGAIN;
    }

    VProcess *vprocess = vthread->get_vprocess();
    USwitchContext *ucontext = vprocess->get_ucontext();
    Reservation reserv = reserve(curr, size);
    struct iovec iov[2] = {
        {buffer + reserv.vec[0].start, reserv.vec[0].size}
    };
    int iovcnt = 1;
    if (reserv.vec[1].size) {
        ++iovcnt;
        iov[1] = {buffer + reserv.vec[1].start, reserv.vec[1].size};
    }
    ssize_t n;
    off_t off = 0;
    if (offset) {
        off = *offset;
        ucontext->run_on_behalf_of([&] {
            n = ::preadv(in_fd, iov, iovcnt, off);
            if (n < 0) {
                n = -errno;
            }
        });
    } else {
        ucontext->run_on_behalf_of([&] {
            n = ::readv(in_fd, iov, iovcnt);
            if (n < 0) {
                n = -errno;
            }
        });
    }
    if (n >= 0 && offset) {
        *offset = off + n;
    }
    
    commit_write(curr);
    peer_events = EPOLLIN;
    return n;
}

int Pipe::shutdown(int how) {
    {
        if (how == SHUT_RD) {
            shutdown_read.store(true, std::memory_order_relaxed);
        } else if (how == SHUT_WR) {
            shutdown_write.store(true, std::memory_order_relaxed);
            if (get_cached_pointer().empty()) {
                shutdown_read.store(true, std::memory_order_relaxed);
            }
        }
    }
    return 0;
}

int Pipe::readable() {
    if (shutdown_read.load(std::memory_order_acquire)) {
        return 0;
    }
    return get_cached_pointer().used_space();
}

int Pipe::writable() {
    if (shutdown_write.load(std::memory_order_acquire)) {
        return 0;
    }
    return get_cached_pointer().free_space();
}

LocalSocket::LocalSocket(int domain)
    : File(nullptr, -1), domain(domain), nonblock(false), last_err(0),
      wq(std::make_shared<WaitQueue>()) {

}

struct ShutdownPeerTasklet {
    std::weak_ptr<VirtualConnection> vconn;
    bool is_client;
    void operator()() {
        std::shared_ptr<VirtualConnection> vc = vconn.lock();
        if (!vc) {
            return;
        }
        std::shared_ptr<File> peer;
        if (is_client) {
            vc->downstream->shutdown(SHUT_RD);
            vc->upstream->shutdown(SHUT_WR);
            peer = vc->server_sock.lock();
        } else {
            vc->upstream->shutdown(SHUT_RD);
            vc->downstream->shutdown(SHUT_WR);
            peer = vc->client_sock.lock();
        }
        if (!peer) {
            return;
        }
        uint32_t e = 0;
        if (is_client) {
            if (vc->downstream->shutdown_write && vc->upstream->shutdown_read) {
                e |= EPOLLHUP;
            }
            if (vc->upstream->shutdown_read) {
                e |= EPOLLRDHUP;
            }
        } else {
            if (vc->upstream->shutdown_write && vc->downstream->shutdown_read) {
                e |= EPOLLHUP;
            }
            if (vc->downstream->shutdown_read) {
                e |= EPOLLRDHUP;
            }
        }
        std::unique_lock lock(peer->get_mutex());
        peer->notify(e, lock);
    }
};

LocalSocket::~LocalSocket() {
    if (!vconn) {
        return;
    }
    try {
        GET_PER_CPU_PRIV(cwm)->add(ShutdownPeerTasklet{vconn, is_client});
    } catch (...) {
    }
}

ssize_t LocalSocket::read(VThread *vthread, int fd, void *buf, size_t len) {
    return recvfrom(vthread, fd, buf, len, 0, nullptr, nullptr);
}

ssize_t LocalSocket::write(VThread *vthread, int fd, const void *buf, size_t len) {
    return sendto(vthread, fd, buf, len, 0, nullptr, 0);
}

ssize_t LocalSocket::readv_once(VThread *vthread, const struct iovec *iov, int iovcnt,
                                int flags, uint32_t &peer_events) {
    if (is_client) {
        return vconn->downstream->readv(vthread, iov, iovcnt, peer_events, flags & MSG_PEEK);
    } else {
        return vconn->upstream->readv(vthread, iov, iovcnt, peer_events, flags & MSG_PEEK);
    }
}

ssize_t LocalSocket::readv(VThread *vthread, int fd, const struct iovec *piov, int iovcnt) {
    MM *mm = vthread->get_vprocess()->get_mm();

    std::unique_ptr<struct iovec[]> iov_slow;
    struct iovec iov_fast[MaxStackIovecSize];
    int err;
    struct iovec *iov = load_iovec(mm, piov, iovcnt, iov_slow, iov_fast, err);
    if (!iov) {
        return err;
    }
    
    std::unique_lock lock(mutex);
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    ssize_t res;
    uint32_t peer_events = 0;

    res = readv_once(vthread, piov, iovcnt, 0, peer_events);
    std::shared_ptr<Task> task;
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    task = Executor::get_current_task();
    while (true) {
        wq->add_task(task, EPOLLIN | EPOLLERR | EPOLLHUP);
        lock.unlock();
        Executor::block();
        lock.lock();
        if (task->wq_res.from_signal) {
            res = -EINTR;
            break;
        }
        res = readv_once(vthread, piov, iovcnt, 0, peer_events);
        if (res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
            break;
        }
    }

out:
    if (res == -EINTR) {
        vthread->set_restart();
    }
    last_err.store(res < 0 ? -res : 0, std::memory_order_release);
    lock.unlock();
    if (peer_events) {
        notify_peer(peer_events);
    }
    return res;
}

ssize_t LocalSocket::writev_once(VThread *vthread, const struct iovec *iov,
                                 int iovcnt, uint32_t &peer_events) {
    if (is_client) {
        return vconn->upstream->writev(vthread, iov, iovcnt, peer_events);
    } else {
        return vconn->downstream->writev(vthread, iov, iovcnt, peer_events);
    }
}

ssize_t LocalSocket::writev(VThread *vthread, int fd, const struct iovec *piov, int iovcnt) {
    MM *mm = vthread->get_vprocess()->get_mm();
    std::unique_ptr<struct iovec[]> iov_slow;
    struct iovec iov_fast[MaxStackIovecSize];
    int err;
    struct iovec *iov = load_iovec(mm, piov, iovcnt, iov_slow, iov_fast, err);
    if (!iov) {
        return err;
    }
    
    std::unique_lock lock(mutex);
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    ssize_t res;
    uint32_t peer_events = 0;

    res = writev_once(vthread, iov, iovcnt, peer_events);
    std::shared_ptr<Task> task;
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    task = Executor::get_current_task();
    while (true) {
        wq->add_task(task, EPOLLOUT | EPOLLERR | EPOLLHUP);
        lock.unlock();
        Executor::block();
        lock.lock();
        if (task->wq_res.from_signal) {
            res = -EINTR;
            break;
        }
        res = writev_once(vthread, iov, iovcnt, peer_events);
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
    last_err.store(res < 0 ? -res : 0, std::memory_order_release);
    lock.unlock();
    if (peer_events) {
        notify_peer(peer_events);
    }
    return res;
}

int LocalSocket::fcntl(VThread *vthread, int fd, const long *args) {
    int cmd = args[1];
    int res = -EINVAL;
    int err = -EINVAL;
    if (cmd == F_GETFL) {
        int flags = O_RDWR;
        if (nonblock.load(std::memory_order_acquire)) {
            flags |= O_NONBLOCK;
        }
        res = flags;
        err = 0;
    } else if (cmd == F_SETFL) {
        int flags = args[2];
        nonblock.store(flags & O_NONBLOCK, std::memory_order_release);
        res = 0;
        err = 0;
    }
    last_err.store(-err, std::memory_order_release);
    return res;
}

int LocalSocket::ioctl(VThread *vthread, int fd, const long *args) {
    int request = args[1];
    MM *mm = vthread->get_vprocess()->get_mm();
    int err = -EINVAL;
    if (request == FIONREAD) {
        int readable = 0;
        if (is_client) {
            readable = vconn->downstream->readable();
        } else {
            readable = vconn->upstream->readable();
        }
        int *p = (int *)args[2];
        try {
            mm->put_sandbox<int>(readable, p);
            err = 0;
        } catch (FaultException &e) {
            err = -EFAULT;
        }
    } else if (request == FIONBIO) {
        int opt = 0;
        try {
            opt = mm->get_sandbox<int>((int *)args[2]);
            err = 0;
        } catch (FaultException &e) {
            err = -EFAULT;
        }
        nonblock.store(opt, std::memory_order_release);
    }
    last_err.store(-err, std::memory_order_release);
    return err;
}

ssize_t LocalSocket::sendfile_once(VThread *vthread, int in_fd, off_t *offset, size_t len, uint32_t &peer_events) {
    if (is_client) {
        return vconn->upstream->sendfile(vthread, in_fd, offset, len, peer_events);
    } else {
        return vconn->downstream->sendfile(vthread, in_fd, offset, len, peer_events);
    }
}

ssize_t LocalSocket::sendfile(VThread *vthread, int fd, int in_fd, off_t *poffset, size_t len) {
    MM *mm = vthread->get_vprocess()->get_mm();
    off_t offset;

    if (poffset) {
        try {
            offset = mm->get_sandbox<off_t>(poffset);
        } catch (FaultException &e) {
            last_err.store(EFAULT, std::memory_order_release);
            return -EFAULT;
        }
    }

    std::unique_lock lock(mutex);
    bool nonblock_ = nonblock.load(std::memory_order_acquire);
    ssize_t res;
    uint32_t peer_events = 0;

    res = sendfile_once(vthread, in_fd, poffset ? &offset : nullptr, len, peer_events);
    std::shared_ptr<Task> task;
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    task = Executor::get_current_task();
    while (true) {
        wq->add_task(task, EPOLLOUT | EPOLLERR | EPOLLHUP);
        lock.unlock();
        Executor::block();
        lock.lock();
        if (task->wq_res.from_signal) {
            res = -EINTR;
            break;
        }
        res = sendfile_once(vthread, in_fd, poffset ? &offset : nullptr, len, peer_events);
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
    if (poffset) {
        try {
            mm->put_sandbox(offset, poffset);
        } catch (FaultException &e) {
            res = -EFAULT;
        }
    }
    last_err.store(res < 0 ? -res : 0, std::memory_order_release);
    lock.unlock();
    if (peer_events) {
        notify_peer(peer_events);
    }
    return res;
}

uint32_t LocalSocket::poll(VThread *vthread, uint32_t events) {
    std::lock_guard lock(mutex);
    if (is_client) {
        uint32_t revents = 0;
        if (vconn->downstream->shutdown_read) {
            revents |= EPOLLRDHUP;
        }
        if (vconn->downstream->shutdown_read && vconn->upstream->shutdown_write) {
            revents |= EPOLLHUP;
        }
        if ((events & EPOLLIN) && vconn->downstream->readable()) {
            revents |= EPOLLIN;
        }
        if ((events & EPOLLOUT) && vconn->upstream->writable()) {
            revents |= EPOLLOUT;
        }
        return revents;
    } else {
        uint32_t revents = 0;
        if (vconn->upstream->shutdown_read) {
            revents |= EPOLLRDHUP;
        }
        if (vconn->upstream->shutdown_read && vconn->downstream->shutdown_write) {
            revents |= EPOLLHUP;
        }
        if ((events & EPOLLIN) && vconn->upstream->readable()) {
            revents |= EPOLLIN;
        }
        if ((events & EPOLLOUT) && vconn->downstream->writable()) {
            revents |= EPOLLOUT;
        }
        return revents;
    }
    return 0;
}

void LocalSocket::notify(uint32_t events, std::unique_lock<SpinLock> &lock) {
    wq->wake_all(events);
    File::notify(events, lock);
}

uint32_t LocalSocket::get_cap() {
    return Pollable;
}

ssize_t LocalSocket::recvfrom_once(VThread *vthread, void *buf, size_t len, int flags, uint32_t &peer_events) {
    if (is_client) {
        return vconn->downstream->read(vthread, (uint8_t *)buf, len, peer_events, flags & MSG_PEEK);
    } else {
        return vconn->upstream->read(vthread, (uint8_t *)buf, len, peer_events, flags & MSG_PEEK);
    }
}

ssize_t LocalSocket::recvfrom(VThread *vthread, int fd, void *buf, size_t len, int flags,
                              struct sockaddr *addr, socklen_t *addrlen) {
    std::unique_lock lock(mutex);
    bool nonblock_ = nonblock.load(std::memory_order_acquire) || (flags & MSG_DONTWAIT);
    ssize_t res;
    uint32_t peer_events = 0;

    res = recvfrom_once(vthread, buf, len, flags, peer_events);
    std::shared_ptr<Task> task;
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    task = Executor::get_current_task();
    while (true) {
        wq->add_task(task, EPOLLIN | EPOLLERR | EPOLLHUP);
        lock.unlock();
        Executor::block();
        lock.lock();
        if (task->wq_res.from_signal) {
            res = -EINTR;
            break;
        }
        res = recvfrom_once(vthread, buf, len, flags, peer_events);
        if (res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
            break;
        }
    }

out:
    if (res == -EINTR) {
        vthread->set_restart();
    }
    last_err.store(res < 0 ? -res : 0, std::memory_order_release);
    lock.unlock();
    if (peer_events) {
        notify_peer(peer_events);
    }
    return res;
}

ssize_t LocalSocket::sendto_once(VThread *vthread, const void *buf, size_t len, uint32_t &peer_events) {
    if (is_client) {
        return vconn->upstream->write(vthread, (const uint8_t *)buf, len, peer_events);
    } else {
        return vconn->downstream->write(vthread, (const uint8_t *)buf, len, peer_events);
    }
}

ssize_t LocalSocket::sendto(VThread *vthread, int fd, const void *buf, size_t len, int flags,
                            const struct sockaddr *addr, socklen_t addrlen) {
    std::unique_lock lock(mutex);
    bool nonblock_ = nonblock.load(std::memory_order_acquire) || (flags & MSG_DONTWAIT);
    ssize_t res;
    uint32_t peer_events = 0;

    res = sendto_once(vthread, buf, len, peer_events);
    std::shared_ptr<Task> task;
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    task = Executor::get_current_task();
    while (true) {
        wq->add_task(task, EPOLLOUT | EPOLLERR | EPOLLHUP);
        lock.unlock();
        Executor::block();
        lock.lock();
        if (task->wq_res.from_signal) {
            res = -EINTR;
            break;
        }
        res = sendto_once(vthread, buf, len, peer_events);
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
    last_err.store(res < 0 ? -res : 0, std::memory_order_release);
    lock.unlock();
    if (peer_events) {
        notify_peer(peer_events);
    }
    return res;
}

ssize_t LocalSocket::recvmsg(VThread *vthread, int fd, struct msghdr *pmsg, int flags) {
    struct msghdr msg;
    MM *mm = vthread->get_vprocess()->get_mm();
    try {
        mm->copy_from_sandbox(&msg, pmsg, sizeof(struct msghdr));
    } catch (FaultException &e) {
        last_err.store(EFAULT, std::memory_order_release);
        return -EFAULT;
    }
    int iovcnt = (int)msg.msg_iovlen;

    std::unique_ptr<struct iovec[]> iov_slow;
    struct iovec iov_fast[MaxStackIovecSize];
    int err;
    struct iovec *iov = load_iovec(mm, msg.msg_iov, iovcnt, iov_slow, iov_fast, err);
    if (!iov) {
        last_err.store(-err, std::memory_order_release);
        return err;
    }
    
    std::unique_lock lock(mutex);
    bool nonblock_ = nonblock.load(std::memory_order_acquire) || (flags & MSG_DONTWAIT);
    ssize_t res;
    uint32_t peer_events = 0;

    res = readv_once(vthread, iov, iovcnt, flags, peer_events);
    std::shared_ptr<Task> task;
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    task = Executor::get_current_task();
    while (true) {
        wq->add_task(task, EPOLLIN | EPOLLERR | EPOLLHUP);
        lock.unlock();
        Executor::block();
        lock.lock();
        if (task->wq_res.from_signal) {
            res = -EINTR;
            break;
        }
        res = readv_once(vthread, iov, iovcnt, flags, peer_events);
        if (res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
            break;
        }
    }

out:
    if (res == -EINTR) {
        vthread->set_restart();
    }
    last_err.store(res < 0 ? -res : 0, std::memory_order_release);
    lock.unlock();
    if (peer_events) {
        notify_peer(peer_events);
    }
    return res;
}

ssize_t LocalSocket::sendmsg(VThread *vthread, int fd, const struct msghdr *pmsg, int flags) {
    struct msghdr msg;
    MM *mm = vthread->get_vprocess()->get_mm();
    try {
        mm->copy_from_sandbox(&msg, pmsg, sizeof(struct msghdr));
    } catch (FaultException &e) {
        return -EFAULT;
    }
    int iovcnt = (int)msg.msg_iovlen;

    std::unique_ptr<struct iovec[]> iov_slow;
    struct iovec iov_fast[MaxStackIovecSize];
    int err;
    struct iovec *iov = load_iovec(mm, msg.msg_iov, iovcnt, iov_slow, iov_fast, err);
    if (!iov) {
        return err;
    }
    
    std::unique_lock lock(mutex);
    bool nonblock_ = nonblock.load(std::memory_order_acquire) || (flags & MSG_DONTWAIT);
    ssize_t res;
    uint32_t peer_events = 0;

    res = writev_once(vthread, iov, iovcnt, peer_events);
    std::shared_ptr<Task> task;
    if (nonblock_ || res >= 0 || (res != -EAGAIN && res != -EWOULDBLOCK)) {
        goto out;
    }
    task = Executor::get_current_task();
    while (true) {
        wq->add_task(task, EPOLLOUT | EPOLLERR | EPOLLHUP);
        lock.unlock();
        Executor::block();
        lock.lock();
        if (task->wq_res.from_signal) {
            res = -EINTR;
            break;
        }
        res = writev_once(vthread, iov, iovcnt, peer_events);
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
    last_err.store(res < 0 ? -res : 0, std::memory_order_release);
    lock.unlock();
    if (peer_events) {
        notify_peer(peer_events);
    }
    return res;
}

int LocalSocket::listen(VThread *vthread, int fd, int backlog) {
    return -EADDRINUSE;
}

int LocalSocket::bind(VThread *vthread, int fd, const struct sockaddr *addr, socklen_t len) {
    return -EINVAL;
}

int LocalSocket::accept4(VThread *vthread, int fd, struct sockaddr *addr, socklen_t *len, int flags,
                         AcceptHook &hook) {
    return -EINVAL;
}

int LocalSocket::connect(VThread *vthread, int fd, const struct sockaddr *addr, socklen_t len) {
    return -EISCONN;
}

int LocalSocket::shutdown(VThread *vthread, int fd, int how) {
    if (!vconn) {
        return -ENOTCONN;
    }
    std::shared_ptr<File> sock1, sock2;
    if (is_client) {
        if (how == SHUT_RD || how == SHUT_RDWR) {
            vconn->downstream->shutdown(SHUT_RD);
        } else if (how == SHUT_WR || how == SHUT_RDWR) {
            vconn->upstream->shutdown(SHUT_WR);
        }
        std::lock_guard lock(vconn->mutex);
        sock1 = vconn->client_sock.lock();
        sock2 = vconn->server_sock.lock();
    } else {
        if (how == SHUT_RD || how == SHUT_RDWR) {
            vconn->upstream->shutdown(SHUT_RD);
        } else if (how == SHUT_WR || how == SHUT_RDWR) {
            vconn->downstream->shutdown(SHUT_WR);
        }
        std::lock_guard lock(vconn->mutex);
        sock1 = vconn->client_sock.lock();
        sock2 = vconn->server_sock.lock();
    }
    uint32_t e1 = 0, e2 = 0;
    if (vconn->upstream->shutdown_write && vconn->downstream->shutdown_read) {
        e1 |= EPOLLHUP;
    }
    if (vconn->downstream->shutdown_write && vconn->upstream->shutdown_read) {
        e2 |= EPOLLHUP;
    }
    if (vconn->downstream->shutdown_read) {
        e1 |= EPOLLRDHUP;
    }
    if (vconn->upstream->shutdown_read) {
        e2 |= EPOLLRDHUP;
    }
    if (sock1 && e1) {
        std::unique_lock lock(sock1->get_mutex());
        sock1->notify(e1, lock);
    }
    if (sock2 && e2) {
        std::unique_lock lock(sock2->get_mutex());
        sock2->notify(e2, lock);
    }
    return 0;
}

int LocalSocket::getsockopt(VThread *vthread, int fd, int level, int optname, void *optval, socklen_t *optlen) {
    socklen_t len;
    VProcess *vprocess = vthread->get_vprocess();
    MM *mm = vprocess->get_mm();
    try {
        len = mm->get_sandbox<socklen_t>(optlen);
    } catch (FaultException &e) {
        last_err.store(EFAULT, std::memory_order_release);
        return -EFAULT;
    }
    if (level == SOL_SOCKET && optname == SO_ERROR) {
        if (len > sizeof(int)) {
            len = sizeof(int);
        }
        int res = last_err.load(std::memory_order_acquire);
        try {
            mm->copy_to_sandbox(optval, &res, len);
        } catch (FaultException &e) {
            last_err.store(EFAULT, std::memory_order_release);
            return -EFAULT;
        }
        try {
            mm->put_sandbox(len, optlen);
        } catch (FaultException &e) {
            last_err.store(EFAULT, std::memory_order_release);
            return -EFAULT;
        }
        return 0;
    }
    last_err.store(0, std::memory_order_release);
    return 0;
}

int LocalSocket::setsockopt(VThread *vthread, int fd, int level, int optname, const void *optval, socklen_t optlen) {
    last_err.store(0, std::memory_order_release);
    return 0;
}

int LocalSocket::getsockname(VThread *vthread, int fd, struct sockaddr *paddr, socklen_t *paddrlen) {
    MM *mm = vthread->get_vprocess()->get_mm();
    socklen_t addrlen;
    try {
        addrlen = mm->get_sandbox<socklen_t>(paddrlen);
    } catch (FaultException &e) {
        last_err.store(EFAULT, std::memory_order_release);
        return -EFAULT;
    }
    struct sockaddr_storage addr;
    socklen_t real_addrlen;
    uint16_t port = is_client ? vconn->client_port : vconn->server_port;
    if (domain == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&addr;
        memset(a, 0, sizeof(sockaddr_in));
        a->sin_family = AF_INET;
        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a->sin_port = htons(port);
        real_addrlen = sizeof(struct sockaddr_in);
    } else if (domain == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&addr;
        memset(a, 0, sizeof(sockaddr_in6));
        a->sin6_family = AF_INET6;
        memcpy(&a->sin6_addr, &in6addr_loopback, sizeof(in6_addr));
        a->sin6_port = htons(port);
        real_addrlen = sizeof(struct sockaddr_in6);
    } else {
        last_err.store(ENOTSOCK, std::memory_order_release);
        return -ENOTSOCK;
    }
    if (addrlen > real_addrlen) {
        addrlen = real_addrlen;
    }
    try {
        mm->copy_to_sandbox(paddr, &addr, addrlen);
        mm->put_sandbox(real_addrlen, paddrlen);
    } catch (FaultException &e) {
        last_err.store(EFAULT, std::memory_order_release);
        return -EFAULT;
    }
    last_err.store(0, std::memory_order_release);
    return 0;
}

int LocalSocket::getpeername(VThread *vthread, int fd, struct sockaddr *paddr, socklen_t *paddrlen) {
    MM *mm = vthread->get_vprocess()->get_mm();
    socklen_t addrlen;
    try {
        addrlen = mm->get_sandbox<socklen_t>(paddrlen);
    } catch (FaultException &e) {
        last_err.store(EFAULT, std::memory_order_release);
        return -EFAULT;
    }
    struct sockaddr_storage addr;
    socklen_t real_addrlen;
    uint16_t port = is_client ? vconn->server_port : vconn->client_port;
    if (domain == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&addr;
        memset(a, 0, sizeof(sockaddr_in));
        a->sin_family = AF_INET;
        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a->sin_port = htons(port);
        real_addrlen = sizeof(struct sockaddr_in);
    } else if (domain == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&addr;
        memset(a, 0, sizeof(sockaddr_in6));
        a->sin6_family = AF_INET6;
        memcpy(&a->sin6_addr, &in6addr_loopback, sizeof(in6_addr));
        a->sin6_port = htons(port);
        real_addrlen = sizeof(struct sockaddr_in6);
    } else {
        last_err.store(ENOTSOCK, std::memory_order_release);
        return -ENOTSOCK;
    }
    if (addrlen > real_addrlen) {
        addrlen = real_addrlen;
    }
    try {
        mm->copy_to_sandbox(paddr, &addr, addrlen);
        mm->put_sandbox(real_addrlen, paddrlen);
    } catch (FaultException &e) {
        last_err.store(EFAULT, std::memory_order_release);
        return -EFAULT;
    }
    last_err.store(0, std::memory_order_release);
    return 0;
}

bool LocalSocket::is_nonblock() {
    return nonblock.load(std::memory_order_acquire);
}

int LocalSocket::get_domain() {
    return -1;
}

void LocalSocket::notify_peer(uint32_t events) {
    std::shared_ptr<File> peer;
    {
        std::lock_guard lock(vconn->mutex);
        if (is_client) {
            peer = vconn->server_sock.lock();
        } else {
            peer = vconn->client_sock.lock();
        }
    }
    if (peer) {
        std::unique_lock lock(peer->get_mutex());
        peer->notify(events, lock);
    }
}
