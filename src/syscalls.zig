//! Which syscalls the tracer intercepts, and where their arguments live.
//!
//! The same table drives the dispatcher and the seccomp filter, so a syscall
//! the tracer handles can never be missing from the filter. Syscalls absent
//! from an architecture (aarch64 has no `open`) are simply skipped.

const std = @import("std");
const linux = std.os.linux;
const SYS = linux.SYS;

pub const H = enum(u8) {
    none,
    open,
    stat, // path + exit fixup of st_uid/st_gid
    statx,
    fstat,
    read_path,
    readlink,
    mkdir,
    mknod,
    unlink,
    rmdir,
    symlink,
    link,
    rename,
    chmod,
    fchmod,
    chown_path,
    chown_fd,
    utimens,
    utime_path,
    write_path,
    write_meta,
    chdir,
    fchdir,
    getcwd,
    execve,
    execveat,
    chroot,
    bind,
    connect,
    getsockname,
    uname,
    kill,
    getid,
    getresid,
    setid,
    getgroups,
    setgroups,
    capget,
    succeed,
    eperm,
    enosys,
    getpid,
    gettid,
    getppid,
    getpgrp,
    getpgid,
    getsid,
    setpgid,
    setsid,
    clone,
    wait4,
    waitid,
    tkill,
    tgkill,
    pid_arg,
    getdents,
    sendto,
    sendmsg,
    sendmmsg,
    setsockopt,
    sysinfo,
    affinity,
    shmget,
    shmat,
    shmdt,
    shmctl,
    ioctl_pgrp,
    prctl_caps,
};

pub const Sc = struct {
    h: H = .none,
    /// Index of the dirfd argument; -1 means paths are relative to the cwd.
    dir: i8 = -1,
    path: u8 = 0,
    /// Index of the flags argument, -1 if there is none.
    flags: i8 = -1,
    /// Index of the mode argument, -1 if there is none.
    mode: i8 = -1,
    /// Index of the output buffer patched on exit.
    out: u8 = 0,
    /// Never follow a trailing symlink (lstat, lchown, ...).
    nofollow: bool = false,
    /// Which id a get/set syscall touches.
    id: Id = .none,
    /// Index of a process id argument.
    pid: u8 = 0,
};

pub const Id = enum(u8) { none, uid, euid, gid, egid, setuid, setgid, setreuid, setregid, setresuid, setresgid, setfsuid, setfsgid };

pub const max_nr = 512;

fn add(t: *[max_nr]Sc, comptime name: []const u8, sc: Sc) void {
    if (@hasField(SYS, name)) t[@backingInt(@field(SYS, name))] = sc;
}

fn build() [max_nr]Sc {
    @setEvalBranchQuota(100_000);
    var t: [max_nr]Sc = @splat(.{});

    add(&t, "openat", .{ .h = .open, .dir = 0, .path = 1, .flags = 2, .mode = 3 });
    add(&t, "open", .{ .h = .open, .path = 0, .flags = 1, .mode = 2 });
    add(&t, "creat", .{ .h = .open, .path = 0, .mode = 1 });
    // The caller falls back to openat(), which is fully translated.
    add(&t, "openat2", .{ .h = .enosys });

    add(&t, "newfstatat", .{ .h = .stat, .dir = 0, .path = 1, .out = 2, .flags = 3 });
    add(&t, "fstatat64", .{ .h = .stat, .dir = 0, .path = 1, .out = 2, .flags = 3 });
    add(&t, "stat", .{ .h = .stat, .path = 0, .out = 1 });
    add(&t, "lstat", .{ .h = .stat, .path = 0, .out = 1, .nofollow = true });
    add(&t, "fstat", .{ .h = .fstat, .out = 1 });
    add(&t, "statx", .{ .h = .statx, .dir = 0, .path = 1, .flags = 2, .out = 4 });

    add(&t, "faccessat", .{ .h = .read_path, .dir = 0, .path = 1 });
    add(&t, "faccessat2", .{ .h = .read_path, .dir = 0, .path = 1, .flags = 3 });
    add(&t, "access", .{ .h = .read_path, .path = 0 });
    add(&t, "statfs", .{ .h = .read_path, .path = 0 });
    add(&t, "getxattr", .{ .h = .read_path, .path = 0 });
    add(&t, "listxattr", .{ .h = .read_path, .path = 0 });
    add(&t, "lgetxattr", .{ .h = .read_path, .path = 0, .nofollow = true });
    add(&t, "llistxattr", .{ .h = .read_path, .path = 0, .nofollow = true });
    add(&t, "inotify_add_watch", .{ .h = .read_path, .path = 1 });

    add(&t, "readlinkat", .{ .h = .readlink, .dir = 0, .path = 1, .out = 2 });
    add(&t, "readlink", .{ .h = .readlink, .path = 0, .out = 1 });

    add(&t, "mkdirat", .{ .h = .mkdir, .dir = 0, .path = 1, .mode = 2 });
    add(&t, "mkdir", .{ .h = .mkdir, .path = 0, .mode = 1 });
    add(&t, "mknodat", .{ .h = .mknod, .dir = 0, .path = 1, .mode = 2 });
    add(&t, "mknod", .{ .h = .mknod, .path = 0, .mode = 1 });
    add(&t, "unlinkat", .{ .h = .unlink, .dir = 0, .path = 1, .flags = 2 });
    add(&t, "unlink", .{ .h = .unlink, .path = 0 });
    add(&t, "rmdir", .{ .h = .rmdir, .path = 0 });
    add(&t, "symlinkat", .{ .h = .symlink, .dir = 1, .path = 2 });
    add(&t, "symlink", .{ .h = .symlink, .path = 1 });
    add(&t, "linkat", .{ .h = .link, .dir = 0, .path = 1, .flags = 4 });
    add(&t, "link", .{ .h = .link, .path = 0 });
    add(&t, "renameat2", .{ .h = .rename, .dir = 0, .path = 1 });
    add(&t, "renameat", .{ .h = .rename, .dir = 0, .path = 1 });
    add(&t, "rename", .{ .h = .rename, .path = 0 });

    add(&t, "fchmodat", .{ .h = .chmod, .dir = 0, .path = 1, .mode = 2 });
    add(&t, "fchmodat2", .{ .h = .chmod, .dir = 0, .path = 1, .mode = 2, .flags = 3 });
    add(&t, "chmod", .{ .h = .chmod, .path = 0, .mode = 1 });
    add(&t, "fchmod", .{ .h = .fchmod, .mode = 1 });
    add(&t, "fchownat", .{ .h = .chown_path, .dir = 0, .path = 1, .flags = 4 });
    add(&t, "chown", .{ .h = .chown_path, .path = 0 });
    add(&t, "lchown", .{ .h = .chown_path, .path = 0, .nofollow = true });
    add(&t, "fchown", .{ .h = .chown_fd });

    add(&t, "utimensat", .{ .h = .utimens, .dir = 0, .path = 1, .flags = 3 });
    add(&t, "futimesat", .{ .h = .utime_path, .dir = 0, .path = 1 });
    add(&t, "utime", .{ .h = .utime_path, .path = 0 });
    add(&t, "utimes", .{ .h = .utime_path, .path = 0 });
    add(&t, "truncate", .{ .h = .write_path, .path = 0 });
    add(&t, "setxattr", .{ .h = .write_meta, .path = 0 });
    add(&t, "removexattr", .{ .h = .write_meta, .path = 0 });
    add(&t, "lsetxattr", .{ .h = .write_meta, .path = 0, .nofollow = true });
    add(&t, "lremovexattr", .{ .h = .write_meta, .path = 0, .nofollow = true });

    add(&t, "chdir", .{ .h = .chdir, .path = 0 });
    add(&t, "fchdir", .{ .h = .fchdir });
    add(&t, "getcwd", .{ .h = .getcwd });
    add(&t, "execve", .{ .h = .execve });
    add(&t, "execveat", .{ .h = .execveat });
    add(&t, "chroot", .{ .h = .chroot, .path = 0 });

    add(&t, "bind", .{ .h = .bind });
    add(&t, "connect", .{ .h = .connect });
    add(&t, "getsockname", .{ .h = .getsockname, .out = 1 });
    add(&t, "uname", .{ .h = .uname, .out = 0 });
    add(&t, "kill", .{ .h = .kill });

    add(&t, "getuid", .{ .h = .getid, .id = .uid });
    add(&t, "geteuid", .{ .h = .getid, .id = .euid });
    add(&t, "getgid", .{ .h = .getid, .id = .gid });
    add(&t, "getegid", .{ .h = .getid, .id = .egid });
    add(&t, "getresuid", .{ .h = .getresid, .id = .uid });
    add(&t, "getresgid", .{ .h = .getresid, .id = .gid });
    add(&t, "setuid", .{ .h = .setid, .id = .setuid });
    add(&t, "setgid", .{ .h = .setid, .id = .setgid });
    add(&t, "setreuid", .{ .h = .setid, .id = .setreuid });
    add(&t, "setregid", .{ .h = .setid, .id = .setregid });
    add(&t, "setresuid", .{ .h = .setid, .id = .setresuid });
    add(&t, "setresgid", .{ .h = .setid, .id = .setresgid });
    add(&t, "setfsuid", .{ .h = .setid, .id = .setfsuid });
    add(&t, "setfsgid", .{ .h = .setid, .id = .setfsgid });
    add(&t, "getgroups", .{ .h = .getgroups });
    add(&t, "setgroups", .{ .h = .setgroups });
    add(&t, "capget", .{ .h = .capget });
    add(&t, "capset", .{ .h = .succeed });
    add(&t, "sethostname", .{ .h = .succeed });
    add(&t, "setdomainname", .{ .h = .succeed });

    // Every process-related call goes through the container's own PID table.
    add(&t, "getpid", .{ .h = .getpid });
    add(&t, "gettid", .{ .h = .gettid });
    add(&t, "getppid", .{ .h = .getppid });
    add(&t, "getpgrp", .{ .h = .getpgrp });
    add(&t, "getpgid", .{ .h = .getpgid });
    add(&t, "getsid", .{ .h = .getsid });
    add(&t, "setpgid", .{ .h = .setpgid });
    add(&t, "setsid", .{ .h = .setsid });
    add(&t, "clone", .{ .h = .clone });
    add(&t, "clone3", .{ .h = .clone });
    add(&t, "fork", .{ .h = .clone });
    add(&t, "vfork", .{ .h = .clone });
    add(&t, "wait4", .{ .h = .wait4 });
    add(&t, "waitid", .{ .h = .waitid });
    add(&t, "tkill", .{ .h = .tkill });
    add(&t, "tgkill", .{ .h = .tgkill });
    add(&t, "rt_tgsigqueueinfo", .{ .h = .tgkill });
    add(&t, "getdents64", .{ .h = .getdents });
    inline for ([_][]const u8{
        "rt_sigqueueinfo",   "sched_getparam", "sched_setparam",  "sched_getscheduler",
        "sched_setscheduler", "sched_rr_get_interval", "sched_getattr", "sched_setattr",
        "sched_setaffinity", "prlimit64",      "pidfd_open",      "process_vm_readv",
        "process_vm_writev", "get_robust_list", "move_pages",     "migrate_pages",
    }) |name| {
        add(&t, name, .{ .h = .pid_arg });
    }
    add(&t, "sched_getaffinity", .{ .h = .affinity, .out = 2 });
    add(&t, "sysinfo", .{ .h = .sysinfo, .out = 0 });
    // These reach into another process regardless of the PID table.
    add(&t, "ptrace", .{ .h = .eperm });
    add(&t, "kcmp", .{ .h = .enosys });
    add(&t, "pidfd_getfd", .{ .h = .enosys });

    add(&t, "sendto", .{ .h = .sendto });
    add(&t, "sendmsg", .{ .h = .sendmsg });
    add(&t, "sendmmsg", .{ .h = .sendmmsg });
    add(&t, "setsockopt", .{ .h = .setsockopt });

    add(&t, "shmget", .{ .h = .shmget });
    add(&t, "shmat", .{ .h = .shmat });
    add(&t, "shmdt", .{ .h = .shmdt });
    add(&t, "shmctl", .{ .h = .shmctl });
    add(&t, "ioctl", .{ .h = .ioctl_pgrp });
    add(&t, "prctl", .{ .h = .prctl_caps });

    add(&t, "mount", .{ .h = .eperm });
    add(&t, "umount2", .{ .h = .eperm });
    add(&t, "pivot_root", .{ .h = .eperm });
    // These would reach files without going through path translation.
    add(&t, "io_uring_setup", .{ .h = .enosys });
    add(&t, "name_to_handle_at", .{ .h = .enosys });
    add(&t, "open_by_handle_at", .{ .h = .enosys });
    return t;
}

pub const table: [max_nr]Sc = build();

/// The number of a syscall, if this architecture has it.
pub fn numberOf(comptime name: []const u8) ?u32 {
    if (!@hasField(SYS, name)) return null;
    return @intCast(@backingInt(@field(SYS, name)));
}

pub fn lookup(nr: u64) Sc {
    if (nr >= max_nr) return .{};
    return table[@intCast(nr)];
}
