#pragma once
#include <memory>
#include <mutex>
#include <cstddef>
#include <cinttypes>
#include <sys/uio.h>
#include "pegasus/lock.h"

namespace pegasus {
class VThread;
class WaitQueue;
struct Pipe {
    Pipe(size_t buffer_size);
    ~Pipe();
    ssize_t write(VThread *thread, const uint8_t *buf, size_t size, uint32_t &peer_events);
    ssize_t read(VThread *thread, uint8_t *buf, size_t size, uint32_t &peer_events, bool peek = false);
    ssize_t writev(VThread *thread, const struct iovec *iov, int iovcnt, uint32_t &peer_events);
    ssize_t readv(VThread *thread, const struct iovec *iov, int iovcnt, uint32_t &peer_events, bool peek = false);
    ssize_t sendfile(VThread *thread, int in_fd, off_t *offset, size_t count, uint32_t &peer_events);
    int readable();
    int writable();
    int shutdown(int how);

    struct CachedPointer {
        size_t w;
        size_t r;
        size_t n;
        inline bool empty() {
            return w == r;
        }
        inline bool full() {
            return w == (r ^ n);
        }
        inline size_t wrap(size_t p) {
            return p & (n - 1);
        }
        inline size_t wrap2(size_t p) {
            return p & (2 * n - 1);
        }
        inline size_t used_space() {
            if (w >= r) {
                return w - r;
            } else {
                return 2 * n - (r - w);
            }
        }
        inline size_t free_space() {
            return n - used_space();
        }
    };
    struct Reservation {
        struct {
            size_t start;
            size_t size;
        } vec[2];
        size_t s;
        size_t w;
    };
    struct Retrieve {
        struct {
            size_t start;
            size_t size;
        } vec[2];
        size_t s;
        size_t r;
    };
    inline CachedPointer get_cached_pointer() {
        return CachedPointer {
            write_ptr.load(std::memory_order_acquire),
            read_ptr.load(std::memory_order_acquire),
            buffer_size
        };
    }
    Reservation reserve(CachedPointer &curr, size_t size);
    Retrieve retrieve(CachedPointer &curr, size_t size);
    void commit_write(CachedPointer &curr);
    void commit_read(CachedPointer &curr);
    uint8_t *buffer;
    size_t buffer_size;
    std::atomic_size_t write_ptr;
    std::atomic_size_t read_ptr;
    SpinLock read_mutex;
    SpinLock write_mutex;
    std::atomic_bool shutdown_write;
    std::atomic_bool shutdown_read;
};
}