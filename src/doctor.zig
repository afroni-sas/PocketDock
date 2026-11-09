//! Reports what this device's kernel allows and how containers will run.

const std = @import("std");
const sys = @import("sys.zig");
const arch = @import("arch.zig");
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

pub fn run(root: []const u8) void {
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

    sys.print("\nContainers will run with the ptrace engine.\n", .{});
    sys.print(
        \\  Filesystem, users, hostname and ports are virtualised per container.
        \\  This keeps well-behaved apps apart, but it is not a security boundary
        \\  against hostile code running under the same Android user.
        \\
    , .{});
}
