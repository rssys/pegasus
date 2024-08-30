#pragma once
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <atomic>

namespace pegasus {

class SpinLock {
public:
    constexpr SpinLock() : lock_(false) {}
    SpinLock(const SpinLock &) = delete;
    SpinLock &operator=(const SpinLock &) = delete;
    inline void lock() {
        while (true) {
            if (!lock_.exchange(true, std::memory_order_acquire)) {
                return;
            }
            while (lock_.load(std::memory_order_relaxed)) {
                __builtin_ia32_pause();
            }
        }
    }
    inline bool try_lock() {
        return !lock_.load(std::memory_order_relaxed) &&
            !lock_.exchange(true, std::memory_order_acquire);
    }
    inline void unlock() {
        lock_.store(false, std::memory_order_release);
    }
private:
    std::atomic<bool> lock_;
};

class TicketSpinLock {
public:
    constexpr TicketSpinLock() : now_serving(0), next_ticket(0) {}
    inline void lock() {
        uint32_t ticket = next_ticket.fetch_add(1, std::memory_order_relaxed);
        while (true) {
            uint32_t serving = now_serving.load(std::memory_order_acquire);
            if (serving == ticket) {
                break;
            }
            uint32_t prev_ticket = ticket - serving;
            uint32_t delay_slots = prev_ticket;
            while (delay_slots--) {
                __builtin_ia32_pause();
            }
        }
    }
    inline void unlock() {
        now_serving.store(now_serving.load(std::memory_order_relaxed) + 1, std::memory_order_release);
    }
private:
    std::atomic<uint32_t> now_serving;
    std::atomic<uint32_t> next_ticket;
};

class RWSpinLock {
public:
    constexpr RWSpinLock() : bits(0) {}
    RWSpinLock(const RWSpinLock &) = delete;
    RWSpinLock &operator=(const RWSpinLock &) = delete;
    inline void lock() {
        while (!try_lock());
    }
    inline void unlock() {
        bits.fetch_add(-Writer, std::memory_order_release);
    }
    inline void lock_shared() {
        while (!try_lock_shared());
    }
    inline void unlock_shared() {
        bits.fetch_add(-Reader, std::memory_order_release);
    }
    inline bool try_lock() {
        int32_t expect = 0;
        return bits.compare_exchange_strong(expect, Writer, std::memory_order_acq_rel);
    }
    inline bool try_lock_shared() {
        int32_t value = bits.fetch_add(Reader, std::memory_order_acquire);
        if (value & Writer) {
            bits.fetch_add(-Reader, std::memory_order_release);
            return false;
        }
        return true;
    }
private:
    enum : int32_t {
        Reader = 2,
        Writer = 1,
    };
    std::atomic_int32_t bits;
};

struct FakeLock {
    inline void lock() {}
    inline void unlock() {}
    inline bool try_lock() {
        return true;
    }
};

};