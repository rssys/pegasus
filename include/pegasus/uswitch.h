#pragma once
#include <functional>
#include <type_traits>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/uswitch.h>
#include "percpu.h"
#include "exception.h"

namespace pegasus {

inline static void init_global_uswitch(int flags = USWITCH_ISOLATE_CREDENTIALS | USWITCH_ISOLATE_NAMESPACES) {
    struct uswitch_data *data;
    int res = syscall(__NR_uswitch_init, &data, flags);
    if (res < 0) {
        throw Exception("failed to init uswitch");
    }
    SET_PER_CPU_PRIV(uswitch_data, data);
};

inline static void init_cpu_uswitch() {
    struct uswitch_data *data;
    int res = syscall(__NR_uswitch_cntl, USWITCH_CNTL_GET_CID, &data);
    if (res < 0) {
        throw Exception("failed to init uswitch thread");
    }
    SET_PER_CPU_PRIV(uswitch_data, data);
}

struct USwitchContext {
    USwitchContext(int flags = USWITCH_CLONE_FD_NEW | USWITCH_CLONE_FS_COPY) {
        cid = syscall(__NR_uswitch_clone, flags);
        if (cid < 0) {
            throw Exception("failed to create ucontext");
        }
    }
    ~USwitchContext() {
        if (cid != -1) {
            syscall(__NR_uswitch_cntl, USWITCH_CNTL_DESTROY_CONTEXT, cid);
        }
    }

    static volatile struct uswitch_data *get() {
        return (volatile struct uswitch_data *)GET_PER_CPU_PRIV(uswitch_data);
    }

    inline int get_file(int fd) {
        return syscall(__NR_uswitch_cntl, USWITCH_CNTL_DUP_FILE, cid, fd);
    }
    inline int get_file_from_priv(int fd) {
        use_priv_seccomp();
        switch_to();
        int res = syscall(__NR_uswitch_cntl, USWITCH_CNTL_DUP_FILE, 0, fd);
        if (res < 0) {
            res = -errno;
        }
        switch_to_priv();
        use_self_seccomp();
        if (res < 0) {
            errno = -res;
            return -1;
        }
        return res;
    }
    inline void switch_to() {
        get()->shared_descriptor = cid;
    }
    inline void set_next_descriptor() {
        get()->next_descriptor = cid;
    }
    inline static void switch_to_priv() {
        get()->shared_descriptor = 0;
    }
    inline void use_seccomp() {
        get()->seccomp_descriptor = cid;
    }
    inline static void use_priv_seccomp() {
        get()->seccomp_descriptor = 0;
    }
    inline static void use_self_seccomp() {
        get()->seccomp_descriptor = -1;
    }
    inline static void block_signals(int n = 1) {
        get()->block_signals = n;
        asm volatile ("" ::: "memory");
    }
    inline static void unblock_signals() {
        asm volatile ("" ::: "memory");
        get()->block_signals = 0;

    }
    inline bool is_current() {
        return get()->current_descriptor == cid;
    }
    inline static void run_current(const std::function<void ()> &func) {
        int current_cid = get()->current_descriptor;
        int saved_cid = get()->shared_descriptor;
        volatile struct uswitch_data *data = get();
        if (current_cid != 0) {
            use_priv_seccomp();
        }
        data->shared_descriptor = current_cid;
        try {
            func();
        } catch (...) {
            data->shared_descriptor = saved_cid;
            use_self_seccomp();
            throw;
        }
        data->shared_descriptor = saved_cid;
        use_self_seccomp();
    }
    inline static void set_signal_stack(unsigned long base, size_t size, unsigned int flags = 0, int next_block_signals = -1) {
        volatile struct uswitch_data *data = get();
        data->ss_sp = (unsigned long)base;
        data->ss_size = size;
        data->ss_flags = flags;
        data->ss_control = USWITCH_SIGNAL_STACK_USE_SHARED;
        data->next_block_signals = next_block_signals;
    }
    inline static void clear_signal_stack() {
        get()->ss_control = USWITCH_SIGNAL_STACK_USE_RSP;
    }
    inline int get_cid() {
        return cid;
    }
    inline void run_on_behalf_of(const std::function<void ()> &func, bool block_signals = false) {
        int saved_block_signals = 0;
        if (block_signals) {
            saved_block_signals = get()->block_signals;
            get()->block_signals = 1;
        }
        use_priv_seccomp();
        switch_to();
        try {
            func();
        } catch (...) {
            switch_to_priv();
            use_self_seccomp();
            throw;
        }
        switch_to_priv();
        use_self_seccomp();
        if (block_signals) {
            get()->block_signals = saved_block_signals;
        }
    }
    static inline void run_priv(const std::function<void ()> &func) {
        int saved_cid = get()->shared_descriptor;
        get()->shared_descriptor = 0;
        try {
            func();
        } catch (...) {
            get()->shared_descriptor = saved_cid;
            throw;
        }
        get()->shared_descriptor = saved_cid;
    }
    inline void run_with_euidguid(const std::function<void ()> &func) {
        int meuid = geteuid();
        int megid = getegid();
        use_priv_seccomp();
        switch_to();
        int seuid = geteuid();
        int segid = getegid();
        switch_to_priv();
        use_self_seccomp();
        if (syscall(SYS_setreuid, -1, seuid) == -1) {
            throw Exception("seteuid");
        }
        if (syscall(SYS_setregid, -1, segid) == -1) {
            syscall(SYS_setreuid, -1, meuid);
            throw Exception("setegid");
        }
        try {
            func();
        } catch (...) {
            if (syscall(SYS_setreuid, -1, meuid) == -1) {
                throw Exception("seteuid");
            }
            if (syscall(SYS_setregid, -1, megid) == -1) {
                throw Exception("setegid");
            }
            throw;
        }
        if (syscall(SYS_setreuid, -1, meuid) == -1) {
            throw Exception("seteuid");
        }
        if (syscall(SYS_setregid, -1, megid) == -1) {
            throw Exception("setegid");
        }
        
    }
    inline std::shared_ptr<USwitchContext> clone(int flags = USWITCH_CLONE_FD_COPY | USWITCH_CLONE_FS_COPY) {
        std::shared_ptr<USwitchContext> ctx;
        run_on_behalf_of([&] {
            ctx = std::make_shared<USwitchContext>(flags);
        });
        return ctx;
    }
    template <typename T, typename... Args>
    inline std::invoke_result_t<T, int, Args...> invoke_fd_syscall(T func, int fd1, int fd2, Args&&... args) {
        std::invoke_result_t<T, int, Args...> res;
        if (is_current()) {
            run_on_behalf_of([&] {
                res = func(fd1, args...);
                if (res == -1) {
                    res = -errno;
                }
            });
        } else {
            res = func(fd2, args...);
            if (res == -1) {
                res = -errno;
            }
        }
        return res;
    }

    int cid;
};
}
