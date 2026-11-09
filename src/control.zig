//! The channel between the CLI and a running container's supervisor.
//!
//! A container has exactly one tracer, which owns its process table, ports
//! and writable layer. Everything that has to act inside a running container
//! (`exec`, `stats`) asks that tracer over a unix socket rather than starting
//! a second one. `exec` hands over its stdio with SCM_RIGHTS.

const std = @import("std");
const sys = @import("sys.zig");
const linux = sys.linux;
const Err = sys.Err;

pub const op_exec: u8 = 'x';
pub const op_stats: u8 = 's';

const Iov = extern struct { base: usize, len: usize };

const Msghdr = extern struct {
    name: usize = 0,
    namelen: u32 = 0,
    _pad0: u32 = 0,
    iov: *Iov,
    iovlen: usize = 1,
    control: usize,
    controllen: usize,
    flags: i32 = 0,
    _pad1: u32 = 0,
};

const CmsgHeader = extern struct { len: usize, level: i32, typ: i32 };

const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const MSG_NOSIGNAL: u32 = 0x4000;

fn fill(path: []const u8, sa: *linux.sockaddr.un) Err!u32 {
    if (path.len >= sa.path.len) return sys.fail(.NAMETOOLONG);
    @memset(&sa.path, 0);
    @memcpy(sa.path[0..path.len], path);
    return @intCast(2 + path.len + 1);
}

/// A socket path is limited to 108 bytes. A longer one is reached through a
/// short /proc link to its directory, which stays valid while `dirfd` is open.
fn address(path: []const u8, sa: *linux.sockaddr.un, dirfd: *i32) Err!u32 {
    dirfd.* = -1;
    if (path.len < sa.path.len) return fill(path, sa);
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return sys.fail(.NAMETOOLONG);
    var dir = try sys.Path.of(path[0..slash]);
    dirfd.* = try sys.open(dir.z(), sys.O_PATH | sys.O_DIRECTORY, 0);
    var buf: [96]u8 = undefined;
    const short = std.fmt.bufPrint(&buf, "/proc/self/fd/{d}/{s}", .{ dirfd.*, path[slash + 1 ..] }) catch return sys.fail(.NAMETOOLONG);
    return fill(short, sa);
}

fn closeDir(dirfd: i32) void {
    if (dirfd >= 0) sys.close(dirfd);
}

/// Some Android domains (`adb shell`) may not create socket files, so the
/// abstract namespace serves as a fallback there. The name is derived from
/// the path, so that client and server agree on it.
fn abstractAddress(path: []const u8, sa: *linux.sockaddr.un) u32 {
    @memset(&sa.path, 0);
    const name = std.fmt.bufPrint(sa.path[1..], "pocketdock-{x}", .{std.hash.Wyhash.hash(0, path)}) catch unreachable;
    return @intCast(2 + 1 + name.len);
}

fn newListener() Err!i32 {
    const flags = linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK;
    return @intCast(try sys.ck(linux.socket(linux.AF.UNIX, flags, 0)));
}

/// Creates the listening socket, replacing any stale one left by a crash.
pub fn listen(path: []const u8) Err!i32 {
    var sa: linux.sockaddr.un = .{ .path = undefined };
    var dirfd: i32 = -1;
    const len = try address(path, &sa, &dirfd);
    defer closeDir(dirfd);
    var p = try sys.Path.of(path);
    sys.unlink(p.z()) catch {};
    const fd = try newListener();
    errdefer sys.close(fd);
    const e = linux.errno(linux.bind(fd, @ptrCast(&sa), len));
    if (e == .ACCES or e == .PERM) {
        const alen = abstractAddress(path, &sa);
        _ = try sys.ck(linux.bind(fd, @ptrCast(&sa), alen));
    } else if (e != .SUCCESS) {
        return sys.fail(e);
    }
    _ = try sys.ck(linux.listen(fd, 8));
    return fd;
}

fn tryConnect(sa: *const linux.sockaddr.un, len: u32) Err!i32 {
    const fd: i32 = @intCast(try sys.ck(linux.socket(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0)));
    errdefer sys.close(fd);
    _ = try sys.ck(linux.connect(fd, @ptrCast(sa), len));
    return fd;
}

pub fn connect(path: []const u8) Err!i32 {
    var sa: linux.sockaddr.un = .{ .path = undefined };
    var dirfd: i32 = -1;
    const len = try address(path, &sa, &dirfd);
    defer closeDir(dirfd);
    return tryConnect(&sa, len) catch {
        const alen = abstractAddress(path, &sa);
        return tryConnect(&sa, alen);
    };
}

/// Accepts one pending connection, or returns null if there is none.
pub fn accept(fd: i32) ?i32 {
    const rc = linux.accept4(fd, null, null, linux.SOCK.CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return null;
    return @intCast(rc);
}

/// Sends one message, attaching `fds` if there are any.
pub fn send(fd: i32, data: []const u8, fds: []const i32) Err!void {
    var iov: Iov = .{ .base = @intFromPtr(data.ptr), .len = data.len };
    var control: [64]u8 align(8) = undefined;
    var msg: Msghdr = .{ .iov = &iov, .control = 0, .controllen = 0 };
    if (fds.len > 0) {
        const bytes = std.mem.sliceAsBytes(fds);
        const head: *CmsgHeader = @ptrCast(&control);
        head.* = .{ .len = @sizeOf(CmsgHeader) + bytes.len, .level = SOL_SOCKET, .typ = SCM_RIGHTS };
        @memcpy(control[@sizeOf(CmsgHeader)..][0..bytes.len], bytes);
        msg.control = @intFromPtr(&control);
        msg.controllen = std.mem.alignForward(usize, head.len, 8);
    }
    _ = try sys.ck(linux.syscall3(.sendmsg, @as(u32, @bitCast(fd)), @intFromPtr(&msg), MSG_NOSIGNAL));
}

pub const Received = struct { len: usize, nfds: usize };

/// Receives one message. Waits at most `timeout_ms`.
pub fn recv(fd: i32, buf: []u8, fds: []i32, timeout_ms: i32) Err!Received {
    var pfd = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
    const ready = linux.poll(&pfd, 1, timeout_ms);
    if (linux.errno(ready) != .SUCCESS or ready == 0) return sys.fail(.TIMEDOUT);

    var iov: Iov = .{ .base = @intFromPtr(buf.ptr), .len = buf.len };
    var control: [64]u8 align(8) = undefined;
    var msg: Msghdr = .{ .iov = &iov, .control = @intFromPtr(&control), .controllen = control.len };
    const n = try sys.ck(linux.syscall3(.recvmsg, @as(u32, @bitCast(fd)), @intFromPtr(&msg), 0));

    var nfds: usize = 0;
    if (msg.controllen >= @sizeOf(CmsgHeader)) {
        const head: *const CmsgHeader = @ptrCast(&control);
        if (head.level == SOL_SOCKET and head.typ == SCM_RIGHTS) {
            const bytes = head.len - @sizeOf(CmsgHeader);
            nfds = @min(bytes / 4, fds.len);
            @memcpy(std.mem.sliceAsBytes(fds[0..nfds]), control[@sizeOf(CmsgHeader)..][0 .. nfds * 4]);
        }
    }
    return .{ .len = n, .nfds = nfds };
}
