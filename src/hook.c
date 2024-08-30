#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <time.h>

inline long privcall(int sysno, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    register long rax asm ("rax") = 0;
    register long rdi asm ("rdi") = arg1;
    register long rsi asm ("rsi") = arg2;
    register long rdx asm ("rdx") = arg3;
    register long r10 asm ("r10") = arg4;
    register long r8  asm ("r8") = arg5;
    register long r9  asm ("r9") = arg6;
    register long rcx asm ("rcx") = sysno;
    asm volatile (
        "callq *%%gs:8\n"
        : "+r" (rax)
        : "r" (rdi), "r" (rsi), "r" (rdx), "r" (rcx), "r" (r8), "r" (r9), "r" (r10)
        : "memory", "r11", "r12", "r13", "r14", "r15"
    );
    return rax;
}

inline long privcall_syscall(int sysno, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    long res = privcall(sysno, arg1, arg2, arg3, arg4, arg5, arg6);
    if (res < 0 && res >= -4096) {
        errno = -res;
        return -1;
    }
    return res;
}

int getpid() {
    return privcall_syscall(SYS_getpid, 0, 0, 0, 0, 0, 0);
}

int gettid() {
    return privcall_syscall(SYS_gettid, 0, 0, 0, 0, 0, 0);
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    return (void *)privcall_syscall(SYS_mmap, (long)addr, len, prot, flags, fd, offset);
}

int munmap(void *addr, size_t len) {
    return privcall_syscall(SYS_munmap, (long)addr, len, 0, 0, 0, 0);
}

int mprotect(void *addr, size_t len, int prot) {
    return privcall_syscall(SYS_mprotect, (long)addr, len, prot, 0, 0, 0);
}

void *mremap(void *old_addr, size_t old_size, size_t new_size, int flags, void *new_addr) {
    return (void *)privcall_syscall(SYS_mremap, (long)old_addr, old_size, new_size, flags, (long)new_addr, 0);
}

int madvise(void *addr, size_t len, int advice) {
    return privcall_syscall(SYS_madvise, (long)addr, len, advice, 0, 0, 0);
}

int epoll_create(int size) {
    return privcall_syscall(SYS_epoll_create, size, 0, 0, 0, 0, 0);
}

int epoll_create1(int flags) {
    return privcall_syscall(SYS_epoll_create1, flags, 0, 0, 0, 0, 0);
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *events) {
    return privcall_syscall(SYS_epoll_ctl, epfd, op, fd, (long)events, 0, 0);
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    return privcall_syscall(SYS_epoll_wait, epfd, (long)events, maxevents, timeout, 0, 0);
}

int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask) {
    return privcall_syscall(SYS_epoll_pwait, epfd, (long)events, maxevents, timeout, (long)sigmask, 0);
}

int epoll_pwait2(int epfd, struct epoll_event *events, int maxevents, const struct timespec *ts, const sigset_t *sigmask) {
    return privcall_syscall(SYS_epoll_pwait2, epfd, (long)events, maxevents, (long)ts, (long)sigmask, 0);
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    return privcall_syscall(SYS_poll, (long)fds, nfds, timeout, 0, 0, 0);
}

int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *t, const sigset_t *s) {
    return privcall_syscall(SYS_ppoll, (long)fds, (long)nfds, (long)t, (long)s, 0, 0);
}

int open(const char *pathname, int flags, ...) {
    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, mode_t);
    va_end(args);
    return privcall_syscall(SYS_openat, AT_FDCWD, (long)pathname, flags, mode, 0, 0);
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, mode_t);
    va_end(args);
    return privcall_syscall(SYS_openat, dirfd, (long)pathname, flags, mode, 0, 0);
}

ssize_t read(int fd, void *buf, size_t count) {
    return privcall_syscall(SYS_read, fd, (long)buf, count, 0, 0, 0);
}

ssize_t write(int fd, const void *buf, size_t count) {
    return privcall_syscall(SYS_write, fd, (long)buf, count, 0, 0, 0);
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt) {
    return privcall_syscall(SYS_readv, fd, (long)iov, iovcnt, 0, 0, 0);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    return privcall_syscall(SYS_writev, fd, (long)iov, iovcnt, 0, 0, 0);
}

ssize_t recv(int fd, void *buf, size_t count, int flags) {
    return privcall_syscall(SYS_recvfrom, fd, (long)buf, count, flags, 0, 0);
}

ssize_t send(int fd, const void *buf, size_t count, int flags) {
    return privcall_syscall(SYS_sendto, fd, (long)buf, count, flags, 0, 0);
}

ssize_t recvfrom(int fd, void *buf, size_t count, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    return privcall_syscall(SYS_recvfrom, fd, (long)buf, count, flags, (long)src_addr, (long)addrlen);
}

ssize_t sendto(int fd, const void *buf, size_t count, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    return privcall_syscall(SYS_sendto, fd, (long)buf, count, flags, (long)dest_addr, addrlen);
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
    return privcall_syscall(SYS_recvmsg, fd, (long)msg, flags, 0, 0, 0);
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    return privcall_syscall(SYS_sendmsg, fd, (long)msg, flags, 0, 0, 0);
}

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
    return privcall_syscall(SYS_sendfile, out_fd, in_fd, (long)offset, count, 0, 0);
}

int socket(int domain, int type, int protocol) {
    return privcall_syscall(SYS_socket, domain, type, protocol, 0, 0, 0);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return privcall_syscall(SYS_connect, sockfd, (long)addr, addrlen, 0, 0, 0);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return privcall_syscall(SYS_bind, sockfd, (long)addr, addrlen, 0, 0, 0);
}

int listen(int sockfd, int backlog) {
    return privcall_syscall(SYS_listen, sockfd, backlog, 0, 0, 0, 0);
}

int accept(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    return privcall_syscall(SYS_accept, fd, (long)addr, (long)addrlen, 0, 0, 0);
}

int accept4(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    return privcall_syscall(SYS_accept4, fd, (long)addr, (long)addrlen, flags, 0, 0);
}

int shutdown(int fd, int how) {
    return privcall_syscall(SYS_shutdown, fd, how, 0, 0, 0, 0);
}

int getsockopt(int fd, int level, int optname, void *optval, socklen_t *len) {
    return privcall_syscall(SYS_getsockopt, fd, level, optname, (long)optval, (long)len, 0);
}

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t len) {
    return privcall_syscall(SYS_setsockopt, fd, level, optname, (long)optval, len, 0);
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
    return privcall_syscall(SYS_getsockname, fd, (long)addr, (long)len, 0, 0, 0);
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *len) {
    return privcall_syscall(SYS_getpeername, fd, (long)addr, (long)len, 0, 0, 0);
}

int socketpair(int domain, int type, int protocol, int sv[2]) {
    return privcall_syscall(SYS_socketpair, domain, type, protocol, (long)sv, 0, 0);
}

int pipe(int pipefd[2]) {
    return privcall_syscall(SYS_pipe, (long)pipefd, 0, 0, 0, 0, 0);
}

int pipe2(int pipefd[2], int flags) {
    return privcall_syscall(SYS_pipe2, (long)pipefd, flags, 0, 0, 0, 0);
}

int dup(int fd) {
    return privcall_syscall(SYS_dup, fd, 0, 0, 0, 0, 0);
}

int dup2(int oldfd, int newfd) {
    return privcall_syscall(SYS_dup2, oldfd, newfd, 0, 0, 0, 0);
}

int dup3(int oldfd, int newfd, int flags) {
    return privcall_syscall(SYS_dup3, oldfd, newfd, flags, 0, 0, 0);
}

int eventfd(int initial) {
    return privcall_syscall(SYS_eventfd, initial, 0, 0, 0, 0, 0);
}

int eventfd2(int initial, int flags) {
    return privcall_syscall(SYS_eventfd2, initial, flags, 0, 0, 0, 0);
}

int close(int fd) {
    return privcall_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
}
