//! `pdock daemon`: brings containers back after their supervisor is killed.
//!
//! Each container has its own supervisor, which applies the restart policy
//! when the container exits. Nothing is left to do that when the supervisor
//! itself goes away, and on a phone it does: reboots, low memory, the Android
//! 12+ phantom process killer. The daemon watches for exactly that case.

const std = @import("std");
const sys = @import("sys.zig");
const container = @import("container.zig");
const Store = @import("store.zig").Store;
const linux = sys.linux;
const Allocator = std.mem.Allocator;

const LOCK_EX = 2;
const LOCK_NB = 4;

const tick_ms = 3000;
const first_retry_ms = 2000;
const max_retry_ms = 60_000;
/// How long a container must stay up before its retries start over.
const stable_s = 60;

const termux_prefix = "/data/data/com.termux/files/usr";

pub const Options = struct {
    detach: bool = false,
    wake_lock: bool = true,
};

fn lockPath(a: Allocator, root: []const u8) ![:0]const u8 {
    return std.fmt.allocPrintSentinel(a, "{s}/daemon.lock", .{root}, 0);
}

/// True if a daemon holds the lock on this data directory.
pub fn isRunning(a: Allocator, root: []const u8) bool {
    const path = lockPath(a, root) catch return false;
    const fd = sys.open(path.ptr, sys.O_CLOEXEC, 0) catch return false;
    defer sys.close(fd);
    return linux.errno(linux.flock(fd, LOCK_EX | LOCK_NB)) == .AGAIN;
}

const Retry = struct { next_ns: i128, delay_ms: u64 };

/// Runs `pdock start ID` as a new program, so that the supervisor it leaves
/// behind inherits neither the lock nor this process's memory.
fn launch(id: []const u8, envp: [*:null]const ?[*:0]const u8) void {
    var buf: [64]u8 = undefined;
    const id_z = std.fmt.bufPrintSentinel(&buf, "{s}", .{id}, 0) catch return;
    const argv = [_:null]?[*:0]const u8{ "pdock", "start", id_z.ptr };
    const pid = sys.fork() catch return;
    if (pid == 0) {
        _ = linux.execve("/proc/self/exe", &argv, envp);
        linux.exit_group(127);
    }
    var status: i32 = 0;
    _ = linux.waitpid(pid, &status, 0);
}

fn reconcile(gpa: Allocator, root: []const u8, retries: *std.StringHashMapUnmanaged(Retry), envp: [*:null]const ?[*:0]const u8) void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var mgr: container.Manager = .{ .a = a, .gpa = gpa, .store = .{ .root = root, .a = a } };
    const now = sys.monoNs();
    const wall_s: i64 = @intCast(@divFloor(sys.nowNs(), std.time.ns_per_s));

    for (mgr.listIds() catch return) |id| {
        if (mgr.orphaned(id)) {
            if (!retries.contains(id)) {
                const key = gpa.dupe(u8, id) catch return;
                retries.put(gpa, key, .{ .next_ns = 0, .delay_ms = first_retry_ms }) catch return;
            }
            const r = retries.getPtr(id).?;
            if (now < r.next_ns) continue;
            r.next_ns = now + @as(i128, r.delay_ms) * std.time.ns_per_ms;
            r.delay_ms = @min(r.delay_ms * 2, max_retry_ms);
            sys.eprint("reviving container {s}\n", .{id});
            launch(id, envp);
        } else if (retries.getEntry(id)) |entry| {
            const st = mgr.loadState(id) catch continue;
            if (wall_s - st.started_at < stable_s) continue;
            const key = entry.key_ptr.*;
            retries.removeByPtr(entry.key_ptr);
            gpa.free(key);
        }
    }
}

/// Keeps the CPU from sleeping while the phone serves containers. Termux
/// holds the lock itself; this only asks for it.
fn takeWakeLock() void {
    const path = termux_prefix ++ "/bin/termux-wake-lock";
    if (!sys.exists(path)) return;
    const pid = sys.fork() catch return;
    if (pid == 0) {
        const argv = [_:null]?[*:0]const u8{path};
        const envp = [_:null]?[*:0]const u8{ "PATH=" ++ termux_prefix ++ "/bin:/system/bin", "PREFIX=" ++ termux_prefix };
        _ = linux.execve(path, &argv, &envp);
        linux.exit_group(127);
    }
    var status: i32 = 0;
    _ = linux.waitpid(pid, &status, 0);
}

fn detachFromTerminal(a: Allocator, root: []const u8) void {
    const pid = sys.fork() catch linux.exit_group(1);
    if (pid != 0) linux.exit_group(0);
    _ = linux.setsid();
    const log = std.fmt.allocPrintSentinel(a, "{s}/daemon.log", .{root}, 0) catch linux.exit_group(1);
    const out = sys.open(log.ptr, sys.O_WRONLY | sys.O_CREAT | sys.O_APPEND, 0o600) catch linux.exit_group(1);
    const null_fd = sys.open("/dev/null", sys.O_RDWR, 0) catch linux.exit_group(1);
    _ = linux.dup2(null_fd, 0);
    _ = linux.dup2(out, 1);
    _ = linux.dup2(out, 2);
}

pub fn run(a: Allocator, gpa: Allocator, root: []const u8, envp: [*:null]const ?[*:0]const u8, opts: Options) !void {
    const path = try lockPath(a, root);
    const lock = try sys.open(path.ptr, sys.O_WRONLY | sys.O_CREAT | sys.O_CLOEXEC, 0o600);
    if (linux.errno(linux.flock(lock, LOCK_EX | LOCK_NB)) != .SUCCESS) {
        sys.eprint("error: the daemon is already running\n", .{});
        return error.AlreadyRunning;
    }
    // After the fork: flock belongs to the open file, which the child keeps.
    if (opts.detach) detachFromTerminal(a, root);
    if (opts.wake_lock) takeWakeLock();

    var retries: std.StringHashMapUnmanaged(Retry) = .empty;
    while (true) {
        reconcile(gpa, root, &retries, envp);
        sys.sleepMs(tick_ms);
    }
}

fn termuxHome(env: *std.process.Environ.Map) ?[]const u8 {
    const prefix = env.get("PREFIX") orelse return null;
    if (std.mem.indexOf(u8, prefix, "com.termux") == null) return null;
    return env.get("HOME");
}

/// Writes the Termux:Boot script that starts the daemon with the phone.
pub fn install(a: Allocator, root: []const u8, env: *std.process.Environ.Map) !void {
    const home = termuxHome(env) orelse {
        sys.eprint("error: run this from Termux (with the Termux:Boot app installed)\n", .{});
        return error.NotTermux;
    };
    var exe_buf: [sys.PATH_MAX]u8 = undefined;
    const exe = try sys.readlink("/proc/self/exe", &exe_buf);
    const dir = try std.fmt.allocPrint(a, "{s}/.termux/boot", .{home});
    try sys.mkdirP(dir, 0o700);
    const script = try std.fmt.allocPrint(a,
        \\#!{s}/bin/sh
        \\# Written by `pdock daemon install`.
        \\export POCKETDOCK_ROOT='{s}'
        \\exec '{s}' daemon -d
        \\
    , .{ termux_prefix, root, exe });
    const path = try std.fmt.allocPrint(a, "{s}/pocketdock", .{dir});
    try sys.writeFile(path, script, 0o700);
    var p = try sys.Path.of(path);
    try sys.chmod(p.z(), 0o700);
    sys.print("Installed {s}\nOpen the Termux:Boot app once so that Android lets it run at boot.\n", .{path});
}

/// The path of the boot script, if this device has one.
pub fn bootScript(a: Allocator, env: *std.process.Environ.Map) ?[:0]const u8 {
    const home = termuxHome(env) orelse return null;
    return std.fmt.allocPrintSentinel(a, "{s}/.termux/boot/pocketdock", .{home}, 0) catch null;
}
