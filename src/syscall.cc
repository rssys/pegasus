#include <unordered_map>
#include <unordered_set>
#include <sys/syscall.h>
#include "pegasus/monitor.h"
#include "pegasus/syscall.h"
#include "pegasus/types.h"

using namespace pegasus;

#ifndef SYS_close_range
#define SYS_close_range 436
#endif
#ifndef SYS_openat2
#define SYS_openat2 437
#endif
#ifndef SYS_faccessat2
#define SYS_faccessat2 439
#endif
#ifndef SYS_epoll_pwait2
#define SYS_epoll_pwait2 441
#endif

const std::unordered_set<int> pegasus::PassthroughSyscalls = {
    //SYS_stat,
    SYS_fstat,
    SYS_lstat,              SYS_lseek,
    SYS_pread64,            SYS_pwrite64,
    SYS_access,
    SYS_flock,              SYS_fsync,
    SYS_fdatasync,          SYS_truncate,           SYS_ftruncate,
    SYS_getdents,           SYS_getcwd,             SYS_chdir,
    SYS_fchdir,             SYS_rename,             SYS_mkdir,
    SYS_rmdir,              SYS_creat,              SYS_link,
    SYS_unlink,             SYS_symlink,
    SYS_chmod,              SYS_fchmod,             SYS_chown,
    SYS_fchown,             SYS_lchown,             SYS_umask,
    SYS_gettimeofday,
    SYS_times,              SYS_getuid,
    SYS_getgid,             SYS_geteuid,            SYS_getegid,
    SYS_getgroups,
    SYS_getresuid,          SYS_getresgid,
    SYS_capget,             SYS_utime,
    SYS_ustat,              SYS_statfs,
    SYS_fstatfs,            //SYS_getpriority,
    SYS_sync,
    SYS_readahead,          SYS_setxattr,           SYS_lsetxattr,
    SYS_fsetxattr,          SYS_getxattr,           SYS_lgetxattr,
    SYS_fgetxattr,          SYS_listxattr,          SYS_llistxattr,
    SYS_flistxattr,         SYS_removexattr,        SYS_lremovexattr,
    SYS_fremovexattr,       SYS_time,
    SYS_getdents64,         SYS_fadvise64,
    SYS_clock_gettime,      SYS_clock_getres,
    //SYS_clock_getres,
    SYS_utimes,
    SYS_inotify_add_watch,  SYS_inotify_rm_watch,
    SYS_mkdirat,            SYS_mknodat,            SYS_fchownat,
    SYS_futimesat,          SYS_unlinkat,
    SYS_renameat,           SYS_linkat,             SYS_symlinkat,
    SYS_readlinkat,         SYS_fchmodat,           SYS_faccessat,
    SYS_splice,             SYS_tee,                SYS_sync_file_range,
    SYS_vmsplice,           SYS_utimensat,
    SYS_fallocate,          SYS_timerfd_settime,
    SYS_timerfd_gettime,
    SYS_preadv,             SYS_pwritev,            SYS_recvmmsg,
    SYS_syncfs,             SYS_sendmmsg,
    SYS_renameat2,          SYS_getrandom,
    SYS_copy_file_range,    SYS_preadv2,
    SYS_pwritev2,           SYS_statx,
    SYS_faccessat2,         SYS_uname,
    SYS_setuid,             SYS_setgid,             SYS_setgroups,
    SYS_setreuid,           SYS_setregid,
    SYS_setresuid,          SYS_setresgid,
    SYS_setfsuid,           SYS_setfsgid,           SYS_membarrier
};

const std::unordered_map<int, SyscallHandler> SyscallHandlers::Handlers = {
    // mm.cc
    {SYS_brk,                   SyscallHandlers::brk},
    {SYS_mmap,                  SyscallHandlers::mmap},
    {SYS_munmap,                SyscallHandlers::munmap},
    {SYS_mprotect,              SyscallHandlers::mprotect},
    {SYS_mremap,                SyscallHandlers::mremap},
    {SYS_madvise,               SyscallHandlers::madvise},
    {SYS_mlock,                 SyscallHandlers::mlock},
    {SYS_munlock,               SyscallHandlers::munlock},

    // signal.cc
    {SYS_rt_sigaction,          SyscallHandlers::sigaction},
    {SYS_rt_sigreturn,          SyscallHandlers::sigreturn},
    {SYS_rt_sigprocmask,        SyscallHandlers::sigprocmask},
    {SYS_rt_sigsuspend,         SyscallHandlers::sigsuspend},
    {SYS_rt_sigtimedwait,       SyscallHandlers::sigtimedwait},
    {SYS_rt_sigpending,         SyscallHandlers::sigpending},
    {SYS_rt_sigqueueinfo,       SyscallHandlers::sigqueueinfo},
    {SYS_rt_tgsigqueueinfo,     SyscallHandlers::tgsigqueueinfo},
    {SYS_sigaltstack,           SyscallHandlers::sigaltstack},
    {SYS_tgkill,                SyscallHandlers::tgkill},
    {SYS_tkill,                 SyscallHandlers::tkill},
    {SYS_kill,                  SyscallHandlers::kill},
    {SYS_restart_syscall,       SyscallHandlers::restart_syscall},
    {SYS_signalfd,              SyscallHandlers::signalfd},
    {SYS_signalfd4,             SyscallHandlers::signalfd4},

    // timer.cc
    {SYS_nanosleep,             SyscallHandlers::nanosleep},
    {SYS_clock_nanosleep,       SyscallHandlers::clock_nanosleep},
    {SYS_clock_gettime,         SyscallHandlers::clock_gettime},
    {SYS_gettimeofday,          SyscallHandlers::gettimeofday},
    {SYS_sched_yield,           SyscallHandlers::sched_yield},
    {SYS_pause,                 SyscallHandlers::pause},
    {SYS_setitimer,             SyscallHandlers::setitimer},
    {SYS_getitimer,             SyscallHandlers::getitimer},
    {SYS_timer_create,          SyscallHandlers::timer_create},
    {SYS_timer_settime,         SyscallHandlers::timer_settime},
    {SYS_timer_gettime,         SyscallHandlers::timer_gettime},
    {SYS_timer_getoverrun,      SyscallHandlers::timer_getoverrun},
    {SYS_timer_delete,          SyscallHandlers::timer_delete},
    {SYS_alarm,                 SyscallHandlers::alarm},
    {SYS_timerfd_create,        SyscallHandlers::timerfd_create},

    // process.cc
    {SYS_arch_prctl,            SyscallHandlers::arch_prctl},
    {SYS_exit_group,            SyscallHandlers::exit_group},
    {SYS_exit,                  SyscallHandlers::exit},
    {SYS_gettid,                SyscallHandlers::gettid},
    {SYS_getpid,                SyscallHandlers::getpid},
    {SYS_getppid,               SyscallHandlers::getppid},
    {SYS_getpgid,               SyscallHandlers::getpgid},
    {SYS_getpgrp,               SyscallHandlers::getpgrp},
    {SYS_setpgid,               SyscallHandlers::setpgid},
    {SYS_getsid,                SyscallHandlers::getsid},
    {SYS_prlimit64,             SyscallHandlers::prlimit64},
    {SYS_getrlimit,             SyscallHandlers::getrlimit},
    {SYS_setrlimit,             SyscallHandlers::setrlimit},
    {SYS_getrusage,             SyscallHandlers::stub_handler<-ENOTSUP>},
    {SYS_sched_getaffinity,     SyscallHandlers::sched_getaffinity},
    {SYS_sched_setaffinity,     SyscallHandlers::sched_setaffinity},
    {SYS_set_tid_address,       SyscallHandlers::set_tid_address},
    {SYS_sched_setparam,        SyscallHandlers::sched_setparam},
    {SYS_sched_getparam,        SyscallHandlers::sched_getparam},
    {SYS_sched_setscheduler,    SyscallHandlers::sched_setscheduler},
    {SYS_sched_getscheduler,    SyscallHandlers::sched_getscheduler},
    {SYS_sched_get_priority_max,SyscallHandlers::sched_get_priority_max},
    {SYS_sched_get_priority_min,SyscallHandlers::sched_get_priority_max},
    {SYS_sched_rr_get_interval, SyscallHandlers::sched_rr_get_interval},
    {SYS_wait4,                 SyscallHandlers::wait4},
    {SYS_waitid,                SyscallHandlers::waitid},
    {SYS_getcpu,                SyscallHandlers::getcpu},

    // futex.cc
    {SYS_futex,                 SyscallHandlers::futex},
    {SYS_set_robust_list,       SyscallHandlers::set_robust_list},

    // clone.cc
    {SYS_clone,                 SyscallHandlers::clone},
    {SYS_clone3,                SyscallHandlers::clone3},
    {SYS_vfork,                 SyscallHandlers::vfork},
    {SYS_execve,                SyscallHandlers::execve},

    // file.cc
    {SYS_open,                  SyscallHandlers::open},
    {SYS_openat,                SyscallHandlers::openat},
    {SYS_read,                  SyscallHandlers::read},
    {SYS_write,                 SyscallHandlers::write},
    {SYS_close,                 SyscallHandlers::close},
    {SYS_readv,                 SyscallHandlers::readv},
    {SYS_writev,                SyscallHandlers::writev},
    {SYS_fcntl,                 SyscallHandlers::fcntl},
    {SYS_ioctl,                 SyscallHandlers::ioctl},
    {SYS_sendfile,              SyscallHandlers::sendfile},
    {SYS_socket,                SyscallHandlers::socket},
    {SYS_recvfrom,              SyscallHandlers::recvfrom},
    {SYS_sendto,                SyscallHandlers::sendto},
    {SYS_recvmsg,               SyscallHandlers::recvmsg},
    {SYS_sendmsg,               SyscallHandlers::sendmsg},
    {SYS_listen,                SyscallHandlers::listen},
    {SYS_bind,                  SyscallHandlers::bind},
    {SYS_accept4,               SyscallHandlers::accept4},
    {SYS_accept,                SyscallHandlers::accept},
    {SYS_connect,               SyscallHandlers::connect},
    {SYS_shutdown,              SyscallHandlers::shutdown},
    {SYS_getsockopt,            SyscallHandlers::getsockopt},
    {SYS_setsockopt,            SyscallHandlers::setsockopt},
    {SYS_getsockname,           SyscallHandlers::getsockname},
    {SYS_getpeername,           SyscallHandlers::getpeername},
    {SYS_socketpair,            SyscallHandlers::socketpair},
    {SYS_pipe,                  SyscallHandlers::pipe},
    {SYS_pipe2,                 SyscallHandlers::pipe2},
    {SYS_dup,                   SyscallHandlers::dup},
    {SYS_dup2,                  SyscallHandlers::dup2},
    {SYS_dup3,                  SyscallHandlers::dup3},
    {SYS_eventfd,               SyscallHandlers::eventfd},
    {SYS_eventfd2,              SyscallHandlers::eventfd2},
    {SYS_stat,                  SyscallHandlers::stat},
    {SYS_newfstatat,            SyscallHandlers::newfstatat},
    {SYS_readlink,              SyscallHandlers::readlink},
    {SYS_close_range,           SyscallHandlers::close_range},
    {SYS_inotify_init,          SyscallHandlers::inotify_init},
    {SYS_inotify_init1,         SyscallHandlers::inotify_init1},

    // epoll.cc
    {SYS_epoll_create,          SyscallHandlers::epoll_create},
    {SYS_epoll_create1,         SyscallHandlers::epoll_create1},
    {SYS_epoll_ctl,             SyscallHandlers::epoll_ctl},
    {SYS_epoll_wait,            SyscallHandlers::epoll_wait},
    {SYS_epoll_pwait,           SyscallHandlers::epoll_pwait},
    {SYS_epoll_pwait2,          SyscallHandlers::epoll_pwait2},
    {SYS_poll,                  SyscallHandlers::poll},
    {SYS_ppoll,                 SyscallHandlers::ppoll},
    {SYS_select,                SyscallHandlers::select},
    {SYS_pselect6,              SyscallHandlers::pselect6},

    // Fail
    {SYS_sysinfo,               SyscallHandlers::stub_handler<-ENOSYS>},
    {SYS_rseq,                  SyscallHandlers::stub_handler<-ENOSYS>},
    {SYS_prctl,                 SyscallHandlers::stub_handler<-EPERM>},
    {SYS_io_setup,              SyscallHandlers::stub_handler<-ENOSYS>},
    {SYS_shmget,                SyscallHandlers::stub_handler<-ENOSYS>},
    {SYS_mincore,               SyscallHandlers::stub_handler<-ENOSYS>},
    {SYS_msync,                 SyscallHandlers::stub_handler<-ENOSYS>},
    {SYS_get_mempolicy,         SyscallHandlers::stub_handler<-ENOSYS>},
    {SYS_getpriority,           SyscallHandlers::stub_handler<-ENOSYS>},
    {SYS_setpriority,           SyscallHandlers::stub_handler<-ENOSYS>},
    {SYS_pkey_alloc,            SyscallHandlers::stub_handler<-ENOSYS>},

    // Passthrough with fd
    {SYS_memfd_create,          SyscallHandlers::passthrough_with_fd},
    {SYS_openat2,               SyscallHandlers::passthrough_with_fd}
};

const SyscallTable<512> pegasus::SyscallHandlerTable = std::move([] {
    SyscallTable<512> table;
    for (int s : PassthroughSyscalls) {
        table[s] = SyscallHandlers::passthrough;
    }
    for (auto s : SyscallHandlers::Handlers) {
        table[s.first] = s.second;
    }
    table.default_syscall_handler = SyscallHandlers::raise_exception;
    return table;
}());

const std::unordered_set<unsigned int> pegasus::SchedulePointSyscalls = {
    SYS_connect, SYS_accept4, SYS_accept, SYS_read, SYS_write, SYS_readv, SYS_writev, SYS_sendfile,
    SYS_recvfrom, SYS_sendto, SYS_recvmsg, SYS_sendmsg,
};

long SyscallHandlers::passthrough(VThread *vthread, int sysno,
                                  const long *args, SyscallInfo *info) {
    return vthread->invoke_syscall(sysno, args);
}
