//! Thin wrappers over raw Linux syscalls.
//!
//! The engine runs on Android without a libc, so everything goes straight to
//! the kernel. Failures are `error.Sys` with the errno left in `last`, which
//! lets the tracer hand a kernel error straight back to the guest.

const std = @import("std");
const builtin = @import("builtin");
pub const linux = std.os.linux;
pub const E = linux.E;
pub const Err = error{Sys};

pub var last: E = .SUCCESS;

pub inline fn ck(rc: usize) Err!usize {
    const e = linux.errno(rc);
    if (e != .SUCCESS) {
        last = e;
        return error.Sys;
    }
    return rc;
}

pub fn fail(e: E) Err {
    last = e;
    return error.Sys;
}

pub const AT_FDCWD: i32 = -100;
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
pub const AT_REMOVEDIR: u32 = 0x200;
pub const AT_SYMLINK_FOLLOW: u32 = 0x400;
pub const AT_EMPTY_PATH: u32 = 0x1000;

pub const O_WRONLY: usize = 1;
pub const O_RDWR: usize = 2;
pub const O_ACCMODE: usize = 3;
pub const O_CREAT: usize = 0o100;
pub const O_EXCL: usize = 0o200;
pub const O_NOCTTY: usize = 0o400;
pub const O_TRUNC: usize = 0o1000;
pub const O_APPEND: usize = 0o2000;
pub const O_NONBLOCK: usize = 0o4000;
pub const O_CLOEXEC: usize = 0o2000000;
pub const O_PATH: usize = 0o10000000;
pub const O_DIRECTORY: usize = if (builtin.cpu.arch == .aarch64) 0o40000 else 0o200000;
pub const O_NOFOLLOW: usize = if (builtin.cpu.arch == .aarch64) 0o100000 else 0o400000;
pub const O_TMPFILE: usize = 0o20000000 | O_DIRECTORY;

pub const S_IFMT: u32 = 0o170000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFIFO: u32 = 0o010000;

pub inline fn isDir(mode: u32) bool {
    return mode & S_IFMT == S_IFDIR;
}
pub inline fn isLnk(mode: u32) bool {
    return mode & S_IFMT == S_IFLNK;
}
pub inline fn isReg(mode: u32) bool {
    return mode & S_IFMT == S_IFREG;
}

/// The kernel's own `struct stat`. Also the layout the tracer patches in guest
/// memory, so it has to match the ABI exactly.
pub const Stat = switch (builtin.cpu.arch) {
    .x86_64 => extern struct {
        dev: u64,
        ino: u64,
        nlink: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        _pad0: u32,
        rdev: u64,
        size: i64,
        blksize: i64,
        blocks: i64,
        atime: i64,
        atime_nsec: i64,
        mtime: i64,
        mtime_nsec: i64,
        ctime: i64,
        ctime_nsec: i64,
        _unused: [3]i64,
    },
    .aarch64 => extern struct {
        dev: u64,
        ino: u64,
        mode: u32,
        nlink: u32,
        uid: u32,
        gid: u32,
        rdev: u64,
        _pad1: u64,
        size: i64,
        blksize: i32,
        _pad2: i32,
        blocks: i64,
        atime: i64,
        atime_nsec: i64,
        mtime: i64,
        mtime_nsec: i64,
        ctime: i64,
        ctime_nsec: i64,
        _unused: [2]u32,
    },
    else => @compileError("PocketDock supports x86_64 and aarch64 only"),
};

const nr_fstatat: usize = switch (builtin.cpu.arch) {
    .x86_64 => 262,
    .aarch64 => 79,
    else => unreachable,
};

pub const PATH_MAX = 4096;

/// A bounded, NUL-terminable path that lives on the stack.
pub const Path = struct {
    buf: [PATH_MAX]u8 = undefined,
    len: usize = 0,

    pub fn of(s: []const u8) Err!Path {
        var p: Path = .{};
        try p.append(s);
        return p;
    }

    pub fn join(a: []const u8, b: []const u8) Err!Path {
        var p = try of(a);
        try p.append(b);
        return p;
    }

    pub fn set(self: *Path, s: []const u8) Err!void {
        self.len = 0;
        try self.append(s);
    }

    pub fn append(self: *Path, s: []const u8) Err!void {
        if (self.len + s.len >= PATH_MAX) return fail(.NAMETOOLONG);
        // `s` may alias `buf`, e.g. when re-appending a sub-slice.
        std.mem.copyForwards(u8, self.buf[self.len..][0..s.len], s);
        self.len += s.len;
    }

    pub fn slice(self: *const Path) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn z(self: *Path) [*:0]const u8 {
        self.buf[self.len] = 0;
        return @ptrCast(&self.buf);
    }
};

fn addr(path: [*:0]const u8) usize {
    return @intFromPtr(path);
}

fn cwd() usize {
    return @bitCast(@as(isize, AT_FDCWD));
}

pub fn lstat(path: [*:0]const u8, st: *Stat) Err!void {
    _ = try ck(linux.syscall4(@fromBackingInt(nr_fstatat), cwd(), addr(path), @intFromPtr(st), AT_SYMLINK_NOFOLLOW));
}

pub fn stat(path: [*:0]const u8, st: *Stat) Err!void {
    _ = try ck(linux.syscall4(@fromBackingInt(nr_fstatat), cwd(), addr(path), @intFromPtr(st), 0));
}

pub fn exists(path: [*:0]const u8) bool {
    var st: Stat = undefined;
    lstat(path, &st) catch return false;
    return true;
}

pub fn open(path: [*:0]const u8, flags: usize, mode: usize) Err!i32 {
    const rc = try ck(linux.syscall4(.openat, cwd(), addr(path), flags | O_CLOEXEC, mode));
    return @intCast(rc);
}

pub fn close(fd: i32) void {
    _ = linux.close(fd);
}

pub fn read(fd: i32, buf: []u8) Err!usize {
    while (true) {
        const rc = linux.read(fd, buf.ptr, buf.len);
        if (linux.errno(rc) == .INTR) continue;
        return ck(rc);
    }
}

pub fn readFull(fd: i32, buf: []u8) Err!usize {
    var n: usize = 0;
    while (n < buf.len) {
        const r = try read(fd, buf[n..]);
        if (r == 0) break;
        n += r;
    }
    return n;
}

pub fn writeAll(fd: i32, data: []const u8) Err!void {
    var off: usize = 0;
    while (off < data.len) {
        const rc = linux.write(fd, data[off..].ptr, data.len - off);
        if (linux.errno(rc) == .INTR) continue;
        off += try ck(rc);
    }
}

pub fn print(comptime f: []const u8, a: anytype) void {
    var b: [8192]u8 = undefined;
    const s = std.fmt.bufPrint(&b, f, a) catch b[0..];
    writeAll(1, s) catch {};
}

pub fn eprint(comptime f: []const u8, a: anytype) void {
    var b: [8192]u8 = undefined;
    const s = std.fmt.bufPrint(&b, f, a) catch b[0..];
    writeAll(2, s) catch {};
}

pub fn mkdir(path: [*:0]const u8, mode: u32) Err!void {
    _ = try ck(linux.mkdirat(AT_FDCWD, path, mode));
}

/// Like `mkdir -p`. Existing directories are not an error.
pub fn mkdirP(path_in: []const u8, mode: u32) Err!void {
    var p = try Path.of(path_in);
    const end = p.len;
    var i: usize = 1;
    while (i <= end) : (i += 1) {
        if (i != end and p.buf[i] != '/') continue;
        const saved = p.len;
        p.len = i;
        const rc = linux.mkdirat(AT_FDCWD, p.z(), mode);
        p.len = saved;
        if (i < end) p.buf[i] = '/';
        const e = linux.errno(rc);
        if (e != .SUCCESS and e != .EXIST) return fail(e);
    }
}

pub fn unlink(path: [*:0]const u8) Err!void {
    _ = try ck(linux.unlinkat(AT_FDCWD, path, 0));
}

pub fn rmdir(path: [*:0]const u8) Err!void {
    _ = try ck(linux.unlinkat(AT_FDCWD, path, AT_REMOVEDIR));
}

pub fn rename(from: [*:0]const u8, to: [*:0]const u8) Err!void {
    _ = try ck(linux.renameat(AT_FDCWD, from, AT_FDCWD, to));
}

pub fn symlink(target: [*:0]const u8, path: [*:0]const u8) Err!void {
    _ = try ck(linux.symlinkat(target, AT_FDCWD, path));
}

pub fn readlink(path: [*:0]const u8, buf: []u8) Err![]u8 {
    const n = try ck(linux.readlinkat(AT_FDCWD, path, buf.ptr, buf.len));
    return buf[0..n];
}

pub fn chmod(path: [*:0]const u8, mode: u32) Err!void {
    _ = try ck(linux.fchmodat(AT_FDCWD, path, mode));
}

pub fn fchmod(fd: i32, mode: u32) Err!void {
    _ = try ck(linux.fchmod(fd, mode));
}

pub const Timespec = extern struct { sec: i64, nsec: i64 };

/// Sets atime and mtime to `sec`/`nsec`. `path` is relative to `dirfd`.
pub fn utimes(dirfd: i32, path: ?[*:0]const u8, sec: i64, nsec: i64, flags: u32) Err!void {
    const times = [2]Timespec{ .{ .sec = sec, .nsec = nsec }, .{ .sec = sec, .nsec = nsec } };
    _ = try ck(linux.syscall4(
        .utimensat,
        @bitCast(@as(isize, dirfd)),
        if (path) |p| @intFromPtr(p) else 0,
        @intFromPtr(&times),
        flags,
    ));
}

pub const Dirent = struct { name: []const u8, typ: u8 };

pub const DT_DIR: u8 = 4;
pub const DT_LNK: u8 = 10;

pub const DirIter = struct {
    fd: i32,
    buf: [16384]u8 align(8) = undefined,
    pos: usize = 0,
    end: usize = 0,

    pub fn open_(path: [*:0]const u8) Err!DirIter {
        return .{ .fd = try open(path, O_DIRECTORY, 0) };
    }

    pub fn deinit(self: *DirIter) void {
        close(self.fd);
    }

    pub fn next(self: *DirIter) Err!?Dirent {
        while (true) {
            if (self.pos >= self.end) {
                const n = try ck(linux.getdents64(self.fd, &self.buf, self.buf.len));
                if (n == 0) return null;
                self.pos = 0;
                self.end = n;
            }
            const rec = self.buf[self.pos..];
            const reclen = std.mem.readInt(u16, rec[16..18], .little);
            const typ = rec[18];
            const name = std.mem.sliceTo(rec[19..reclen], 0);
            self.pos += reclen;
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            return .{ .name = name, .typ = typ };
        }
    }
};

/// Recursively removes `path`, fixing up permissions along the way.
pub fn rmrf(path: []const u8) Err!void {
    var p = try Path.of(path);
    var st: Stat = undefined;
    lstat(p.z(), &st) catch {
        if (last == .NOENT) return;
        return error.Sys;
    };
    if (!isDir(st.mode)) return unlink(p.z());
    chmod(p.z(), 0o700) catch {};
    {
        var it = try DirIter.open_(p.z());
        defer it.deinit();
        while (try it.next()) |ent| {
            var child = try Path.join(path, "/");
            try child.append(ent.name);
            try rmrf(child.slice());
        }
    }
    try rmdir(p.z());
}

pub fn readFileAlloc(gpa: std.mem.Allocator, path: []const u8, max: usize) ![]u8 {
    var p = try Path.of(path);
    const fd = try open(p.z(), 0, 0);
    defer close(fd);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var tmp: [65536]u8 = undefined;
    while (true) {
        const n = try read(fd, &tmp);
        if (n == 0) break;
        if (out.items.len + n > max) return error.FileTooBig;
        try out.appendSlice(gpa, tmp[0..n]);
    }
    return out.toOwnedSlice(gpa);
}

/// Replaces `path` atomically so readers never observe a half-written file.
pub fn writeFileAtomic(path: []const u8, data: []const u8, mode: u32) Err!void {
    var suffix: [32]u8 = undefined;
    // Unique per process, as several supervisors can rewrite the same file.
    var tmp = try Path.join(path, std.fmt.bufPrint(&suffix, ".tmp.{d}", .{linux.getpid()}) catch unreachable);
    const fd = try open(tmp.z(), O_WRONLY | O_CREAT | O_TRUNC, mode);
    {
        defer close(fd);
        try writeAll(fd, data);
    }
    var dst = try Path.of(path);
    try rename(tmp.z(), dst.z());
}

pub fn writeFile(path: []const u8, data: []const u8, mode: u32) Err!void {
    var p = try Path.of(path);
    const fd = try open(p.z(), O_WRONLY | O_CREAT | O_TRUNC, mode);
    defer close(fd);
    try writeAll(fd, data);
}

pub fn fork() Err!i32 {
    const rc = try ck(linux.fork());
    return @intCast(rc);
}

pub fn pidAlive(pid: i32) bool {
    if (pid <= 0) return false;
    return linux.errno(linux.kill(pid, @fromBackingInt(0))) != .SRCH;
}

/// When a process started, in clock ticks since boot; 0 if that cannot be read.
pub fn procStart(pid: i32) u64 {
    var name: [32]u8 = undefined;
    const path = std.fmt.bufPrintSentinel(&name, "/proc/{d}/stat", .{pid}, 0) catch return 0;
    const fd = open(path.ptr, O_CLOEXEC, 0) catch return 0;
    defer close(fd);
    var buf: [1024]u8 = undefined;
    const n = readFull(fd, &buf) catch return 0;
    // The process name, in parentheses, may itself hold spaces.
    const paren = std.mem.lastIndexOfScalar(u8, buf[0..n], ')') orelse return 0;
    var it = std.mem.tokenizeScalar(u8, buf[paren + 1 .. n], ' ');
    var i: usize = 0;
    while (it.next()) |f| : (i += 1) {
        if (i == 19) return std.fmt.parseInt(u64, f, 10) catch 0;
    }
    return 0;
}

/// Whether `pid` is still the process that started at `start`. A pid alone
/// proves nothing after a reboot, when numbers are handed out again.
pub fn sameProcess(pid: i32, start: u64) bool {
    if (!pidAlive(pid)) return false;
    if (start == 0) return true;
    const now = procStart(pid);
    return now == 0 or now == start;
}

/// `path` with every symlink resolved.
pub fn realpath(a: std.mem.Allocator, path: []const u8) ![]u8 {
    var p = try Path.of(path);
    const fd = try open(p.z(), O_PATH | O_CLOEXEC, 0);
    defer close(fd);
    var name: [32]u8 = undefined;
    const link = std.fmt.bufPrintSentinel(&name, "/proc/self/fd/{d}", .{fd}, 0) catch unreachable;
    var buf: [PATH_MAX]u8 = undefined;
    return a.dupe(u8, try readlink(link.ptr, &buf));
}

pub const Pty = struct { master: i32, slave: i32 };

pub fn openPty() Err!Pty {
    const TIOCGPTN: u32 = 0x80045430;
    const TIOCSPTLCK: u32 = 0x40045431;
    const master = try open("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC, 0);
    errdefer close(master);
    var unlock: i32 = 0;
    _ = try ck(linux.ioctl(master, TIOCSPTLCK, @intFromPtr(&unlock)));
    var n: u32 = 0;
    _ = try ck(linux.ioctl(master, TIOCGPTN, @intFromPtr(&n)));
    var name: [32]u8 = undefined;
    const path = std.fmt.bufPrintSentinel(&name, "/dev/pts/{d}", .{n}, 0) catch unreachable;
    return .{ .master = master, .slave = try open(path.ptr, O_RDWR | O_NOCTTY | O_CLOEXEC, 0) };
}

pub fn nowNs() i128 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

pub fn monoNs() i128 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

pub fn sleepMs(ms: u64) void {
    var req: linux.timespec = .{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * std.time.ns_per_ms),
    };
    _ = linux.nanosleep(&req, null);
}

/// Formats `ns` since the epoch as RFC 3339 UTC with millisecond precision.
pub fn fmtTime(buf: []u8, ns: i128) []const u8 {
    const secs: u64 = @intCast(@divFloor(ns, std.time.ns_per_s));
    const ms: u64 = @intCast(@divFloor(@mod(ns, std.time.ns_per_s), std.time.ns_per_ms));
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        yd.year,
        md.month.numeric(),
        md.day_index + 1,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
        ms,
    }) catch buf[0..0];
}

/// Hex-encoded random id.
pub fn randomId(out: []u8) void {
    var raw: [32]u8 = undefined;
    const n = out.len / 2;
    _ = linux.getrandom(&raw, n, 0);
    const hex = "0123456789abcdef";
    for (raw[0..n], 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 15];
    }
}
