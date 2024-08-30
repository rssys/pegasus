#include <memory>
#include <cinttypes>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <libgen.h>
#include "pegasus/file.h"
#include "pegasus/mount.h"
#include "pegasus/runtime.h"
#include "pegasus/uswitch.h"

using namespace pegasus;

struct Remount {
    int target_fd;
    std::string target;
    uint64_t flags;
    const void *data;
};

struct MountState {
    MountState(const std::string &rootfs_);
    void open_rootfs_fd();
    ~MountState();
    std::string rootfs;
    int rootfs_fd;
    std::vector<Remount> remounts;
    bool mount_dev_from_host;
    void set_parent_mount_private();
    int create_and_open_ref_at(bool is_dir, const std::string &path, mode_t mode);
    void append_tmpfs_mode_if_missing(const Mount &mount, std::string &data);
    void create_symlink(const std::string &target, const std::string &dest);
    void create_missing_devs(int *terminal_fds);
    void do_mount(const std::string &source,
                  int target_fd,
                  const std::string &target,
                  const std::string &fstype,
                  uint64_t flags,
                  const void *data);
    void do_remount(int target_fd,
                    const std::string &target,
                    uint64_t flags,
                    const void *data);
    void do_mount(const Mount &mount);
    void do_pivot();
    void do_remounts();
};

static std::string readlinkat(int cwd, const std::string &path) {
    std::string buffer;
    buffer.resize(PATH_MAX);
    ssize_t res = readlinkat(cwd, path.c_str(), buffer.data(), buffer.size());
    if (res < 0) {
        return "";
    }
    buffer.resize(res);
    return buffer;
}

static int safe_openat(int dirfd, const char *path, int flags, int mode = 0) {
    struct open_how how = {};
    how.flags = flags;
    how.mode = mode;
    how.resolve = RESOLVE_IN_ROOT;
    return syscall(SYS_openat2, dirfd, path, &how, sizeof(how));
}

static std::string get_proc_path(int fd) {
    return "/proc/thread-self/fd/" + std::to_string(fd);
}

static std::string strip_slash(const std::string &str) {
    size_t p;
    for (p = 0; p < str.size() && str[p] == '/'; ++p);
    return str.substr(p);
}

static void get_file_type_at(int cwd, const std::string &path, mode_t *mode, bool nofollow) {
    int flags = AT_STATX_DONT_SYNC;
    if (path.empty()) {
        flags |= AT_EMPTY_PATH;
    }
    if (nofollow) {
        flags |= AT_SYMLINK_NOFOLLOW;
    }
    struct statx stx = {};
    int res = statx(cwd, path.c_str(), flags, STATX_TYPE, &stx);
    if (res < 0) {
        throw Exception("failed to statx: " + std::string(strerror(errno)));
    }
    *mode = stx.stx_mode;
}

static void get_file_type(const std::string &path, mode_t *mode, bool nofollow) {
    get_file_type_at(AT_FDCWD, path, mode, nofollow);
}

static int safe_ensure_at(bool do_open, bool dir, int dirfd, const std::string &dirpath,
                          std::string path, int mode, int max_readlinks) {
    if (max_readlinks <= 0) {
        throw Exception("loop in path: " + path);
    }
    path = strip_slash(path);
    if (path.empty()) {
        return 0;
    }
    std::string npath = path;
    MonitorFile wd;
    int cwd = dirfd;
    char *cur = npath.data();
    char *it = strchr(cur, '/');
    bool last_component = false;
    size_t depth = 0;
    int res;
    while (cur) {
        if (it) {
            *it = '\0';
        } else {
            last_component = true;
        }

        if (cur[0] == '\0') {
            break;
        }

        if (strcmp(cur, ".") == 0) {
            goto next;
        } else if (strcmp(cur, "..")) {
            depth++;
        } else {
            if (depth) {
                depth--;
            } else {
                if (wd.fd != -1) {
                    close(wd.fd);
                }
                wd.fd = -1;
                cwd = dirfd;
                goto next;
            }
        }
        if (last_component && !dir) {
            res = safe_openat(cwd, cur, O_CREAT | O_WRONLY | O_NOFOLLOW, 0700);
            if (res < 0) {
                if (errno == ELOOP) {
                    std::string resolved_path = readlinkat(cwd, cur);
                    return safe_ensure_at(do_open, dir, dirfd, dirpath, resolved_path, mode, max_readlinks - 1);
                }
                res = safe_openat(cwd, cur, O_PATH);
                if (res < 0) {
                    throw Exception("failed to openat " + dirpath + "/" + npath + ": " + strerror(errno));
                }
            }
            if (do_open) {
                return res;
            }
            if (wd.fd != -1) {
                close(wd.fd);
            }
            wd.fd = res;
            return 0;
        }

        res = mkdirat(cwd, cur, mode);
        if (res < 0) {
            if (errno != EEXIST) {
                throw Exception("failed to mkdir /" + npath + ": " + strerror(errno));
            }
        }
        cwd = safe_openat(dirfd, npath.c_str(), last_component ? O_PATH : 0);
        if (cwd < 0) {
            throw Exception("failed to openat /" + npath + ": " + strerror(errno));
        }

        if (!last_component) {
            mode_t st_mode;
            get_file_type_at(cwd, "", &st_mode, true);
            if ((st_mode & S_IFMT) != S_IFDIR) {
                close(cwd);
                throw Exception("failed to create directory " + path + "since " +
                                npath + "exists and it is not a directory");
            }
        }
        if (wd.fd != -1) {
            close(wd.fd);
        }
        wd.fd = cwd;
next:
        if (it == nullptr) {
            break;
        }
        cur = it + 1;
        while (*cur == '/') {
            ++cur;
        }
        *it = '/';
        it = strchr(cur, '/');
    }
    if (do_open) {
        if (cwd == dirfd) {
            res = dup(dirfd);
            if (res < 0) {
                throw Exception("failed to dup: " + std::string(strerror(errno)));
            }
            return res;
        }
        wd.fd = -1;
        return cwd;
    }
    return 0;
}

static uint64_t get_default_flags(const std::string &dest, std::string &data) {
    if (dest == "/dev") {
        data = "mode=755";
        return MS_NOEXEC | MS_STRICTATIME;
    } else if (dest == "/dev/shm") {
        data = "mode=1777,size=65536k";
        return MS_NOEXEC | MS_NOSUID | MS_NODEV;
    } else if (dest == "/dev/mqueue") {
        return MS_NOEXEC | MS_NOSUID | MS_NODEV;
    } else if (dest == "/dev/pts") {
        data = "newinstance,ptmxmode=0666,mode=620";
        return MS_NOEXEC | MS_NOSUID;
    } else if (dest == "/sys") {
        return MS_NOEXEC | MS_NOSUID | MS_NODEV;
    }
    return 0;
}

inline static bool is_path_dev(std::string path) {
    path = strip_slash(path);
    if (path.substr(0, 3) != "dev") {
        return false;
    }
    for (size_t i = 3; i < path.length(); ++i) {
        if (path[i] != '/') {
            return false;
        }
    }
    return true;
}

MountState::MountState(const std::string &rootfs_) : rootfs(rootfs_), rootfs_fd(-1), mount_dev_from_host(false) {
}

MountState::~MountState() {
    if (rootfs_fd != -1) {
        close(rootfs_fd);
    }
}

void MountState::open_rootfs_fd() {
    rootfs_fd = open(rootfs.c_str(), O_PATH);
    if (rootfs_fd == -1) {
        throw Exception("failed to open rootfs (" + rootfs + "): " + strerror(errno));
    }
}

void MountState::set_parent_mount_private() {
    std::string tmp = rootfs;
    while (true) {
        int res = mount(nullptr, tmp.c_str(), nullptr, MS_PRIVATE, nullptr);
        if (res == 0) {
            return;
        }
        if (errno == EINVAL) {
            size_t p = tmp.rfind('/');
            if (p == std::string::npos) {
                return;
            } else if (p != 0) {
                tmp.resize(p);
                continue;
            } else {
                res = mount(nullptr, "/", nullptr, MS_PRIVATE, nullptr);
                if (res == 0) {
                    return;
                }
            }
        }
        throw Exception("failed to set private mount: " + std::string(strerror(errno)));
    }
}

void MountState::append_tmpfs_mode_if_missing(const Mount &mount, std::string &data) {
    if (data.find("mode=") != std::string::npos) {
        return;
    }
    int fd = safe_openat(rootfs_fd, mount.destination.c_str(), O_RDONLY);
    if (fd < 0 && errno != ENOENT) {
        throw Exception("failed to open destination (" +
                        mount.destination + "): " + strerror(errno));
    }
    struct stat st;
    int res = fstat(fd, &st);
    if (res < 0) {
        throw Exception("failed to fstat destination (" +
                        mount.destination + "): " + strerror(errno));
    }
    if (data.empty()) {
        data += ',';
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "mode=%o", st.st_mode & 07777);
    data += buf;
}

int MountState::create_and_open_ref_at(bool is_dir, const std::string &path, mode_t mode) {
    int fd = safe_openat(rootfs_fd, path.c_str(), O_PATH);
    if (fd >= 0) {
        return fd;
    }
    return safe_ensure_at(true, is_dir, rootfs_fd, rootfs, path, mode, 32);
}

void MountState::create_symlink(const std::string &target, const std::string &dest) {
    if (dest.empty()) {
        throw Exception("dest cannot be empty");
    }
    std::string buffer = dest;
    char *part = dirname(buffer.data());
    MonitorFile parent_dir_fd;
    parent_dir_fd.fd = create_and_open_ref_at(true, part, 0755);
    buffer = dest;
    part = basename(buffer.data());
    int res = symlinkat(target.c_str(), parent_dir_fd.fd, part);
    if (res < 0) {
        if (errno == EEXIST) {
            std::string link;
            link.resize(PATH_MAX);
            ssize_t len = readlinkat(parent_dir_fd.fd, part, link.data(), link.size());
            if (len < 0) {
                throw Exception("failed to readlinkat (" + std::to_string(parent_dir_fd.fd) + "," +
                                std::string(part) + "): " + std::string(strerror(errno)));
            }
            link.resize(len);
            if (link == target) {
                return;
            }
        }
        throw Exception("failed to symlinkat: " + std::string(strerror(errno)));
    }
}

struct Device {
    const char *path;
    mode_t mode;
    dev_t dev;
};

static const Device Devices[] = {
        {"dev/null",       S_IFCHR | 0666,      makedev(1, 3)},
        {"dev/zero",       S_IFCHR | 0666,      makedev(1, 5)},
        {"dev/full",       S_IFCHR | 0666,      makedev(1, 7)},
        {"dev/random",     S_IFCHR | 0666,      makedev(1, 8)},
        {"dev/urandom",    S_IFCHR | 0666,      makedev(1, 9)}
    };

void MountState::create_missing_devs(int *terminal_fds) {
    for (const Device &d : Devices) {
        if (mknodat(rootfs_fd, d.path, d.mode, d.dev) == -1) {
            if (errno == EEXIST) {
                continue;
            }
            throw Exception("failed to create device (/" +
                std::string(d.path) + "): " + strerror(errno));
        }
        if (fchmodat(rootfs_fd, d.path, d.mode, 0) == -1) {
            throw Exception("failed to fchmodat device: " + std::string(strerror(errno)));
        }
    }
    create_symlink("/dev/pts/ptmx", "/dev/ptmx");
    MonitorFile fd_master;
    MonitorFile fd_slave;
    if (terminal_fds) {
        int fd = -1;
        while (fd < 2) {
            fd = open("/dev/null", O_RDONLY);
        }
        if (fd > 2) {
            close(fd);
        }
        fd = safe_openat(rootfs_fd, "/dev/pts/ptmx", O_RDWR | O_NOCTTY);
        if (fd == -1 || grantpt(fd) == -1 || unlockpt(fd) == -1) {
            throw Exception("failed to open pty: " + std::string(strerror(errno)));
        }
        fd_master.fd = fd;
        char path[128];
        if (ptsname_r(fd_master.fd, path, sizeof(path))) {
            throw Exception("failed to get slave pty: " + std::string(strerror(errno)));
        }
        fd_slave.fd = safe_openat(rootfs_fd, path, O_RDWR | O_NOCTTY);
        if (fd_slave.fd == -1) {
            throw Exception("failed to open slave pty: " + std::string(strerror(errno)));
        }
        create_symlink(path, "/dev/console");
        create_symlink(path, "/dev/tty");
        terminal_fds[0] = fd_master.fd;
        terminal_fds[1] = fd_slave.fd;
        fd_master.fd = -1;
        fd_slave.fd = -1;
    }
}

void MountState::do_mount(const std::string &source,
                          int target_fd,
                          const std::string &target,
                          const std::string &fstype,
                          uint64_t flags,
                          const void *data) {
    static constexpr uint64_t PropagationFlags = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE;
    static constexpr uint64_t PropagationFlagsRec = PropagationFlags | MS_REC;
    std::string real_target = target_fd == -1 ? target : get_proc_path(target_fd);
    MonitorFile ms_move_fd, new_target_fd;
    bool need_remount = false;
    bool single_instance = false;

    const char *src = source.empty() ? nullptr : source.c_str();
    const char *type = fstype.empty() ? nullptr : fstype.c_str();
    if (flags & MS_MOVE) {
        if ((flags & MS_BIND) || !fstype.empty()) {
            throw Exception("MS_MOVE cannot be used with MS_BIND or fstype");
        }
        int res = mount(src, real_target.c_str(), nullptr, MS_MOVE, nullptr);
        if (res < 0) {
            throw Exception("failed to move mount (" + source + "," + target + "): " + strerror(errno));
        }
        flags &= ~MS_MOVE;
        ms_move_fd.fd = safe_openat(rootfs_fd, target.c_str(), O_PATH);
        if (ms_move_fd.fd < 0) {
            throw Exception("failed to open target :" + std::string(strerror(errno)));
        }
        target_fd = ms_move_fd.fd;
    }

    if (!fstype.empty() || (flags & MS_BIND)) {
        uint64_t f = flags & ~(PropagationFlags | MS_RDONLY);
        int res = mount(src, real_target.c_str(), type, f, data);
        if (res == -1) {
            throw Exception("failed to mount (" + source +
                            "," + target + "," + real_target +
                            "," + type + "," + std::to_string(f) + "): " + strerror(errno));
        }
        if (target_fd >= 0) {
            int fd = safe_openat(rootfs_fd, target.c_str(), O_PATH);
            if (fd == -1) {
                throw Exception("failed to open target :" + std::string(strerror(errno)));
            }
            new_target_fd.fd = fd;
            target_fd = fd;
            real_target = get_proc_path(target_fd);
        }
    }

    if (flags & PropagationFlagsRec) {
        uint64_t rec = flags & MS_REC;
        uint64_t propagation = flags & PropagationFlags;
        if (propagation) {
            int res = mount(nullptr, real_target.c_str(), nullptr, rec | propagation, nullptr);
            if (res < 0) {
                throw Exception("failed to set propagation for " + target + ": " + strerror(errno));
            }
        }
    }

    if (flags & (MS_BIND | MS_RDONLY)) {
        need_remount = true;
    }

    if (data && fstype == "proc") {
        single_instance = true;
        need_remount = true;
    }

    if (need_remount) {
        uint64_t remount_flags = MS_REMOUNT | (single_instance ? 0 : MS_BIND) |
            (flags & ~PropagationFlagsRec);
        if (!(remount_flags & MS_RDONLY)) {
            do_remount(new_target_fd.fd, target, remount_flags, data);
        } else {
            int fd;
            if (new_target_fd.fd == -1) {
                fd = dup(target_fd);
                if (fd < 0) {
                    throw Exception("failed to dup: " + std::string(strerror(errno)));
                }
            } else {
                fd = new_target_fd.fd;
            }
            remounts.emplace_back(Remount {fd, target, remount_flags, data});
            new_target_fd.fd = -1;
        }
    }
}

void MountState::do_remount(int target_fd,
                            const std::string &target,
                            uint64_t flags,
                            const void *data) {
    std::string real_target = target_fd == -1 ? target : get_proc_path(target_fd);
    if (flags & (MS_REMOUNT | MS_RDONLY)) {
        data = nullptr;
    }
    int res = mount(nullptr, real_target.c_str(), nullptr, flags, data);
    if (res < 0) {
        struct statfs sfs;
        res = statfs(real_target.c_str(), &sfs);
        if (res == -1) {
            throw Exception("failed to statfs: " + std::string(strerror(errno)));
        }
        uint64_t remount_flags = sfs.f_flags & (MS_NOSUID | MS_NODEV | MS_NOEXEC);
        if ((flags | remount_flags) != flags) {
            res = mount(nullptr, real_target.c_str(), nullptr, flags | remount_flags, data);
            if (res == 0) {
                return;
            }
            if (sfs.f_flags & MS_RDONLY) {
                remount_flags = sfs.f_flags & (MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY);
                res = mount(nullptr, real_target.c_str(), nullptr, flags | remount_flags, data);
            }
        }
    }
    if (res < 0) {
        throw Exception("failed to remount: " + std::string(strerror(errno)));
    }
}

void MountState::do_remounts() {
    for (const Remount &r : remounts) {
        do_remount(r.target_fd, r.target, r.flags, r.data);
        if (r.target_fd < 0) {
            close(r.target_fd);
        }
    }
}

struct MountFlag {
    enum {
        OptionRecursive = 1,
        OptionCopyUp = 2,
        OptionCopySymlink = 4,
    };
    uint64_t flags;
    bool clear;
    int extra_flags;
};

static const std::unordered_map<std::string, MountFlag> FlagMap = {
    {"rw",              {MS_RDONLY,             true,   0}},
    {"rrw",             {MS_RDONLY,             true,   MountFlag::OptionRecursive}},
    {"ro",              {MS_RDONLY,             false,  0}},
    {"rro",             {MS_RDONLY,             false,  MountFlag::OptionRecursive}},
    {"rdirsync",        {MS_DIRSYNC,            false,  MountFlag::OptionRecursive}},
    {"rdiratime",       {MS_NODIRATIME,         true,   MountFlag::OptionRecursive}},
    {"rnodev",          {MS_NODEV,              false,  MountFlag::OptionRecursive}},
    {"rnorelatime",     {MS_RELATIME,           true,   MountFlag::OptionRecursive}},
    {"rnodiratime",     {MS_NODIRATIME,         false,  MountFlag::OptionRecursive}},
    {"diratime",        {MS_NODIRATIME,         true,   0}},
    {"rnoatime",        {MS_NOATIME,            false,  MountFlag::OptionRecursive}},
    {"rnomand",         {MS_MANDLOCK,           true,   MountFlag::OptionRecursive}},
    {"ratime",          {MS_NOATIME,            true,   MountFlag::OptionRecursive}},
    {"rmand",           {MS_MANDLOCK,           false,  MountFlag::OptionRecursive}},
    {"rprivate",        {MS_REC|MS_PRIVATE,     false,  0}},
    {"mand",            {MS_MANDLOCK,           false,  0}},
    {"noatime",         {MS_NOATIME,            false,  0}},
    {"nomand",          {MS_MANDLOCK,           true,   0}},
    {"dirsync",         {MS_DIRSYNC,            false,  0}},
    {"rnosuid",         {MS_NOSUID,             false,  MountFlag::OptionRecursive}},
    {"atime",           {MS_NOATIME,            true,   0}},
    {"rnoexec",         {MS_NOEXEC,             false,  MountFlag::OptionRecursive}},
    {"nodev",           {MS_NODEV,              false,  0}},
    {"rbind",           {MS_REC|MS_BIND,        false,  0}},
    {"norelatime",      {MS_RELATIME,           true,   0}},
    {"bind",            {MS_BIND,               false,  0}},
    {"rnostrictatime",  {MS_STRICTATIME,        true,   MountFlag::OptionRecursive}},
    {"strictatime",     {MS_STRICTATIME,        false,  0}},
    {"rstrictatime",    {MS_STRICTATIME,        false,  MountFlag::OptionRecursive}},
    {"defaults",        {0,                     false,  0}},
    {"rsuid",           {MS_NOSUID,             true,   MountFlag::OptionRecursive}},
    {"remount",         {MS_REMOUNT,            false,  0}},
    {"suid",            {MS_NOSUID,             true,   0}},
    {"nostrictatime",   {MS_STRICTATIME,        true,   0}},
    {"rrelatime",       {MS_RELATIME,           false,  MountFlag::OptionRecursive}},
    {"nosuid",          {MS_NOSUID,             false,  0}},
    {"noexec",          {MS_NOEXEC,             false,  0}},
    {"rslave",          {MS_REC|MS_SLAVE,       false,  0}},
    {"private",         {MS_PRIVATE,            false,  0}},
    {"rsync",           {MS_SYNCHRONOUS,        false,  MountFlag::OptionRecursive}},
    {"relatime",        {MS_RELATIME,           false,  0}},
    {"dev",             {MS_NODEV,              true,   0}},
    {"rdev",            {MS_NODEV,              true,   MountFlag::OptionRecursive}},
    {"tmpcopyup",       {0,                     false,  MountFlag::OptionCopyUp}},
    {"unbindable",      {MS_UNBINDABLE,         false,  0}},
    {"runbindable",     {MS_REC|MS_UNBINDABLE,  false,  0}},
    {"async",           {MS_SYNCHRONOUS,        true,   0}},
    {"rasync",          {MS_SYNCHRONOUS,        true,   MountFlag::OptionRecursive}},
    {"sync",            {MS_SYNCHRONOUS,        false,  0}},
    {"rexec",           {MS_NOEXEC,             true,   MountFlag::OptionRecursive}},
    {"shared",          {MS_SHARED,             false,  0}},
    {"rshared",         {MS_REC|MS_SHARED,      false,  0}},
    {"copy-symlink",    {0,                     false,  MountFlag::OptionCopySymlink}},
    {"slave",           {MS_SLAVE,              false,  0}},
    {"exec",            {MS_NOEXEC,             true,   0}},
};

void MountState::do_mount(const Mount &mount) {
    std::string target = strip_slash(mount.destination);
    uint64_t flags = 0, rec_clear = 0, rec_set = 0;
    int extra_flags = 0;
    std::string data;
    mode_t src_mode = S_IFDIR;
    bool mounted = false;
    MonitorFile target_fd;

    if (mount.options.empty()) {
        flags = get_default_flags(mount.destination, data);
    } else {
        for (const std::string &opt : mount.options) {
            auto it = FlagMap.find(opt);
            if (it != FlagMap.end()) {
                const MountFlag &f = it->second;
                if (f.clear) {
                    flags &= ~f.flags;
                    if (f.extra_flags & MountFlag::OptionRecursive) {
                        rec_clear |= f.flags;
                    }
                } else {
                    flags |= f.flags;
                    if (f.extra_flags & MountFlag::OptionRecursive) {
                        rec_set |= f.flags;
                    }
                }
                extra_flags |= f.extra_flags;
            } else {
                if (!data.empty()) {
                    data += ',';
                }
                data += opt;
            }
        }
    }

    if (mount.type.empty() && !(flags & MS_BIND)) {
        throw Exception("invalid mount type for " + mount.destination);
    }
    if (flags & MS_BIND) {
        if (is_path_dev(target)) {
            mount_dev_from_host = true;
        }
    }
    bool is_sysfs_or_proc = mount.type == "sysfs" || mount.type == "proc";
    if (mount.type == "tmpfs") {
        append_tmpfs_mode_if_missing(mount, data);
    }
    if (!mount.source.empty() && (flags & MS_BIND)) {
        get_file_type(mount.source, &src_mode, extra_flags & MountFlag::OptionCopySymlink);
        if (data.find("mode=") == std::string::npos) {
            data += data.empty() ? "mode=1755" : ",mode=1755";
        }
    }
    if (S_ISLNK(src_mode)) {
        std::string tgt = readlinkat(AT_FDCWD, mount.source);
        create_symlink(tgt, mount.destination);
        mounted = true;
    } else if (is_sysfs_or_proc) {
        int res = safe_openat(rootfs_fd, target.c_str(), O_NOFOLLOW | O_DIRECTORY);
        if (res < 0) {
            if (errno == ENOENT) {
                if (target.find('/') != std::string::npos) {
                    throw Exception("target must be mounted at the root");
                }
                res = mkdirat(rootfs_fd, target.c_str(), 0755);
                if (res < 0) {
                    throw Exception("failed to mkdirat: " + std::string(strerror(errno)));
                }
                res = safe_openat(rootfs_fd, target.c_str(), O_NOFOLLOW | O_DIRECTORY);
            } else if (errno == ENOTDIR) {
                throw Exception("target is not directory");
            }
            if (res < 0) {
                throw Exception("failed to open the target");
            }
        }
        target_fd.fd = res;
    } else {
        bool is_dir = S_ISDIR(src_mode);
        target_fd.fd = create_and_open_ref_at(is_dir, target, is_dir ? 01755 : 0755);
    }
    // TODO: TMPCOPYUP

    std::string source = mount.source.empty() ? mount.type : mount.source;
    if (!mounted) {
        do_mount(source, target_fd.fd, target, mount.type, flags, data.c_str());
    }
    if (rec_clear || rec_set) {
        MonitorFile dfd;
        dfd.fd = safe_openat(rootfs_fd, target.c_str(), O_DIRECTORY);
        if (dfd.fd == -1) {
            throw Exception("failed to open mount for target (" + target + "): " + strerror(errno));
        }
        struct mount_attr attr = {};
        attr.attr_set = rec_set;
        attr.attr_clr = rec_clear;
        int res = syscall(SYS_mount_setattr, dfd.fd, "", AT_RECURSIVE | AT_EMPTY_PATH, &attr, sizeof(attr));
        if (res == -1) {
            throw Exception("failed to mount_setattr for target (" + target + "): " + strerror(errno));
        }
    }
}

void MountState::do_pivot() {
    MonitorFile oldrootfd;
    MonitorFile newrootfd;

    oldrootfd.fd = open("/", O_DIRECTORY | O_PATH);
    newrootfd.fd = open(rootfs.c_str(), O_DIRECTORY | O_RDONLY);
    if (oldrootfd.fd == -1) {
        throw Exception("failed to open /: " + std::string(strerror(errno)));
    }
    if (newrootfd.fd == -1) {
        throw Exception("failed to open " + rootfs + ": " + strerror(errno));
    }

    int res = fchdir(newrootfd.fd);
    if (res == -1) {
        throw Exception("failed to fchdir: " + std::string(strerror(errno)));
    }
    res = syscall(SYS_pivot_root, ".", ".");
    if (res == -1) {
        throw Exception("failed to pivot_root: " + std::string(strerror(errno)));
    }
    res = fchdir(oldrootfd.fd);
    if (res == -1) {
        throw Exception("failed to fchdir: " + std::string(strerror(errno)));
    }
    do_mount("", -1, ".", "", MS_REC | MS_PRIVATE, nullptr);
    res = umount2(".", MNT_DETACH);
    if (res == -1) {
        throw Exception("failed to umount oldroot: " + std::string(strerror(errno)));
    }
    do {
        res = umount2(".", MNT_DETACH);
        if (res == -1 && errno == EINVAL) {
            break;
        }
        if (res < 0) {
            throw Exception("failed to umount oldroot: " + std::string(strerror(errno)));
        }
    } while (res == 0);
    res = chdir("/");
    if (res == -1) {
        throw Exception("failed to chdir to newroot: " + std::string(strerror(errno)));
    }
}

static const std::unordered_set<std::string> IgnoredMountTypes = {"proc", "sysfs", "cgroup"};//{"proc", "cgroup", "sysfs", "mqueue"};

static void init_mount_internal(const ProgramConfiguration &pc, int *terminal_fds) {
    MountState state(pc.rootfs);
    int rootfs_propagation = pc.rootfs_propagation;
    if (!rootfs_propagation) {
        rootfs_propagation = MS_REC | MS_PRIVATE;
    }

    state.do_mount("", -1, "/", "", rootfs_propagation, nullptr);
    state.set_parent_mount_private();
    state.do_mount(pc.rootfs, -1, pc.rootfs, "",
                   MS_BIND | MS_REC | MS_PRIVATE, nullptr);

    state.open_rootfs_fd();

    if (pc.rootfs_ro) {
        uint64_t remount_flags = MS_REMOUNT | MS_BIND | MS_RDONLY;
        MonitorFile fd;
        fd.fd = dup(state.rootfs_fd);
        if (fd.fd == -1) {
            throw Exception("failed to dup rootfs fd: " + std::string(strerror(errno)));
        }
        state.remounts.emplace_back(Remount {fd.fd, pc.rootfs, remount_flags, nullptr});
        fd.fd = -1;
    }

    for (const Mount &mount : pc.mounts) {
        if (IgnoredMountTypes.count(mount.type)) {
            continue;
        }
        state.do_mount(mount);
    }

    if (!state.mount_dev_from_host) {
        state.create_missing_devs(terminal_fds);
    }

    if (!pc.working_directory.empty()) {
        try {
            safe_ensure_at(false, true, state.rootfs_fd, state.rootfs,
                           strip_slash(pc.working_directory), 0755, 32);
        } catch (...) {
        }
    }

    // TODO: mask
    state.do_remounts();
    state.do_pivot();
    state.do_mount("", -1, "/", "", rootfs_propagation, nullptr);
}

void pegasus::init_mount(const std::shared_ptr<USwitchContext> &ucontext,
                        const ProgramConfiguration &pc, int *terminal_fds){
    ucontext->run_on_behalf_of([&] {
        init_mount_internal(pc, terminal_fds);
    });
}