//! Reports what this device's kernel allows and how containers will run.

const std = @import("std");
const sys = @import("sys.zig");
const arch = @import("arch.zig");
const daemon = @import("daemon.zig");
const linux = sys.linux;
const PT = linux.PTRACE;

fn line(name: []const u8, ok: bool, detail: []const u8) void {
    sys.print("  {s} {s: <22}{s}\n", .{ if (ok) "yes" else "no ", name, detail });
}

/// Runs `f` in a child so that a kernel refusal cannot affect this process.
fn probe(comptime f: fn () bool) bool {
    const pid = sys.fork() catch return false;
    if (pid == 0) linux.exit_group(if (f()) 0 else 1);
    var status: i32 = 0;
    _ = linux.waitpid(pid, &status, 0);
    const s: u32 = @bitCast(status);
    return linux.W.IFEXITED(s) and linux.W.EXITSTATUS(s) == 0;
}

fn tryUserNs() bool {
    const CLONE_NEWUSER = 0x10000000;
    return linux.errno(linux.unshare(CLONE_NEWUSER)) == .SUCCESS;
}

fn trySeccomp() bool {
    const PR_GET_SECCOMP = 21;
    return linux.errno(linux.prctl(PR_GET_SECCOMP, 0, 0, 0, 0)) == .SUCCESS;
}

fn tracerWorks() bool {
    const pid = sys.fork() catch return false;
    if (pid == 0) {
        _ = linux.ptrace(PT.TRACEME, 0, 0, 0, 0);
        _ = linux.kill(linux.getpid(), .STOP);
        linux.exit_group(0);
    }
    var status: i32 = 0;
    _ = linux.waitpid(pid, &status, 0);
    if (!linux.W.IFSTOPPED(@bitCast(status))) return false;
    var word: u64 = 0;
    const local = [1]std.posix.iovec{.{ .base = @ptrCast(&word), .len = 8 }};
    const remote = [1]std.posix.iovec_const{.{ .base = @ptrCast(&word), .len = 8 }};
    const ok = linux.errno(linux.process_vm_readv(pid, &local, &remote, 0)) == .SUCCESS;
    _ = linux.kill(pid, .KILL);
    _ = linux.waitpid(pid, &status, 0);
    return ok;
}

fn hardLinks(root: []const u8) bool {
    var a = sys.Path.join(root, "/.hl-a") catch return false;
    var b = sys.Path.join(root, "/.hl-b") catch return false;
    const fd = sys.open(a.z(), sys.O_WRONLY | sys.O_CREAT, 0o600) catch return false;
    sys.close(fd);
    defer sys.unlink(a.z()) catch {};
    const ok = linux.errno(linux.linkat(sys.AT_FDCWD, a.z(), sys.AT_FDCWD, b.z(), 0)) == .SUCCESS;
    if (ok) sys.unlink(b.z()) catch {};
    return ok;
}

fn hasFilesystem(name: []const u8) bool {
    var buf: [8192]u8 = undefined;
    const fd = sys.open("/proc/filesystems", 0, 0) catch return false;
    defer sys.close(fd);
    const n = sys.readFull(fd, &buf) catch return false;
    return std.mem.indexOf(u8, buf[0..n], name) != null;
}

/// The output of a system tool, or null if this app may not run it.
fn capture(a: std.mem.Allocator, path: [*:0]const u8, argv: []const ?[*:0]const u8) ?[]const u8 {
    var pipe: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })) != .SUCCESS) return null;
    const pid = sys.fork() catch return null;
    if (pid == 0) {
        const null_fd = sys.open("/dev/null", sys.O_RDWR, 0) catch linux.exit_group(127);
        _ = linux.dup2(null_fd, 0);
        _ = linux.dup2(pipe[1], 1);
        _ = linux.dup2(null_fd, 2);
        const envp = [_:null]?[*:0]const u8{"PATH=/system/bin"};
        _ = linux.execve(path, @ptrCast(argv.ptr), &envp);
        linux.exit_group(127);
    }
    sys.close(pipe[1]);
    defer sys.close(pipe[0]);
    var buf: [256]u8 = undefined;
    const n = sys.readFull(pipe[0], &buf) catch 0;
    var status: i32 = 0;
    _ = linux.waitpid(pid, &status, 0);
    const out = std.mem.trim(u8, buf[0..n], " \t\r\n");
    if (out.len == 0 or std.mem.indexOfScalar(u8, out, ' ') != null) return null;
    return a.dupe(u8, out) catch null;
}

fn androidApi(a: std.mem.Allocator) u32 {
    const data = sys.readFileAlloc(a, "/system/build.prop", 1 << 20) catch return 0;
    const key = "ro.build.version.sdk=";
    const i = std.mem.indexOf(u8, data, key) orelse return 0;
    const rest = data[i + key.len..];
    const end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
    return std.fmt.parseInt(u32, std.mem.trim(u8, rest[0..end], " \r"), 10) catch 0;
}

/// What can kill a container on this phone, and how to prevent it.
fn reportAndroid(a: std.mem.Allocator, env: *std.process.Environ.Map) void {
    sys.print("\nAndroid\n", .{});
    const api = androidApi(a);
    if (api != 0) sys.print("  API level: {d}\n", .{api});

    if (api == 0 or api >= 31) {
        const monitor = capture(a, "/system/bin/settings", &.{ "settings", "get", "global", "settings_enable_monitor_phantom_procs", null });
        const limit = capture(a, "/system/bin/device_config", &.{ "device_config", "get", "activity_manager", "max_phantom_processes", null });
        const disabled = (monitor != null and std.mem.eql(u8, monitor.?, "false")) or
            (limit != null and limit.?.len >= 9);
        if (monitor == null and limit == null) {
            sys.print("  ?   phantom process killer   cannot be read from this app\n", .{});
        } else if (disabled) {
            sys.print("  yes phantom process killer   off\n", .{});
        } else {
            sys.print("  no  phantom process killer   on (Android stops apps past 32 child processes)\n", .{});
        }
        if (!disabled) sys.print(
            \\      To turn it off, run this once from a computer with adb:
            \\        adb shell settings put global settings_enable_monitor_phantom_procs false
            \\        adb shell device_config set_sync_disabled_for_tests persistent
            \\        adb shell device_config put activity_manager max_phantom_processes 2147483647
            \\
        , .{});
    }

    const running = daemon.isRunning(a, root_for_report);
    line("daemon", running, if (running) "revives killed containers" else "start it with: pdock daemon -d");
    if (daemon.bootScript(a, env)) |path| {
        const installed = sys.exists(path.ptr);
        line("start on boot", installed, if (installed) "" else "set it up with: pdock daemon install");
    }
    sys.print(
        \\  For a phone that stays reachable, also keep it on a charger and set
        \\  Termux's battery use to Unrestricted in the Android settings.
        \\
    , .{});
}

var root_for_report: []const u8 = "";

pub fn run(a: std.mem.Allocator, root: []const u8, env: *std.process.Environ.Map) void {
    var uts: linux.utsname = undefined;
    _ = linux.uname(&uts);
    const android = sys.exists("/system/build.prop");

    sys.print("PocketDock doctor\n", .{});
    sys.print("  platform: {s}, linux {s}{s}\n", .{ arch.oci_arch, std.mem.sliceTo(&uts.release, 0), if (android) ", Android" else "" });
    sys.print("  uid: {d}\n  data: {s}\n\nKernel\n", .{ linux.getuid(), root });

    const trace = tracerWorks();
    const seccomp = probe(trySeccomp);
    line("ptrace", trace, if (trace) "required" else "required, containers cannot run");
    line("seccomp filters", seccomp, "makes tracing fast");
    const userns = probe(tryUserNs);
    line("user namespaces", userns, "kernel-level isolation");
    line("overlayfs", hasFilesystem("overlay"), "");
    line("hard links", hardLinks(root), "");

    if (android) {
        root_for_report = root;
        reportAndroid(a, env);
    }

    sys.print("\nContainers will run with the ptrace engine.\n", .{});
    sys.print(
        \\  Filesystem, users, hostname and ports are virtualised per container.
        \\  This keeps well-behaved apps apart, but it is not a security boundary
        \\  against hostile code running under the same Android user.
        \\
    , .{});
}
