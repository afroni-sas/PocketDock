//! Reads per-process resource usage from /proc.
//!
//! Android gives apps no cgroups, so limits are enforced by the tracer from
//! these numbers instead of by the kernel.

const std = @import("std");
const sys = @import("sys.zig");
const linux = sys.linux;

pub const Limits = struct {
    /// Bytes; 0 means unlimited.
    memory: u64 = 0,
    /// Thousandths of a CPU; 0 means unlimited.
    cpus_milli: u32 = 0,
    /// Bitmask of usable CPUs; 0 means all of them.
    cpuset: u64 = 0,
    /// Maximum tasks (threads included); 0 means unlimited.
    pids: u32 = 0,
};

/// How many CPUs the container should believe it has, or 0 to leave it alone.
pub fn visibleCpus(l: Limits) u32 {
    if (l.cpuset != 0) return @popCount(l.cpuset);
    if (l.cpus_milli != 0) return @max(1, (l.cpus_milli + 999) / 1000);
    return 0;
}

fn readProc(pid: i32, name: []const u8, buf: []u8) ?[]u8 {
    var pathbuf: [64]u8 = undefined;
    const path = std.fmt.bufPrintSentinel(&pathbuf, "/proc/{d}/{s}", .{ pid, name }, 0) catch return null;
    const fd = sys.open(path.ptr, 0, 0) catch return null;
    defer sys.close(fd);
    const n = sys.readFull(fd, buf) catch return null;
    return buf[0..n];
}

pub fn pageSize() u64 {
    return linux.getauxval(std.elf.AT.PAGESZ);
}

/// Resident memory in bytes. Pages shared between processes count once each.
pub fn rss(pid: i32) ?u64 {
    var buf: [128]u8 = undefined;
    const data = readProc(pid, "statm", &buf) orelse return null;
    var it = std.mem.tokenizeScalar(u8, data, ' ');
    _ = it.next();
    const pages = std.fmt.parseInt(u64, it.next() orelse return null, 10) catch return null;
    return pages * pageSize();
}

/// Proportional memory in bytes: a shared page is split among its users.
/// Falls back to `rss` on kernels without smaps_rollup.
pub fn pss(pid: i32) ?u64 {
    var buf: [1024]u8 = undefined;
    const data = readProc(pid, "smaps_rollup", &buf) orelse return rss(pid);
    const at = std.mem.indexOf(u8, data, "\nPss:") orelse return rss(pid);
    var it = std.mem.tokenizeAny(u8, data[at + 5..], " \t");
    const kb = std.fmt.parseInt(u64, it.next() orelse return rss(pid), 10) catch return rss(pid);
    return kb * 1024;
}

/// CPU time used by the whole thread group, in clock ticks (10 ms each).
pub fn cpuTicks(pid: i32) ?u64 {
    var buf: [1024]u8 = undefined;
    const data = readProc(pid, "stat", &buf) orelse return null;
    const paren = std.mem.lastIndexOfScalar(u8, data, ')') orelse return null;
    var it = std.mem.tokenizeScalar(u8, data[paren + 1 ..], ' ');
    // Counting from `state`, utime and stime are fields 11 and 12.
    for (0..11) |_| _ = it.next() orelse return null;
    const utime = std.fmt.parseInt(u64, it.next() orelse return null, 10) catch return null;
    const stime = std.fmt.parseInt(u64, it.next() orelse return null, 10) catch return null;
    return utime + stime;
}

pub fn parseSize(s: []const u8) ?u64 {
    if (s.len == 0) return null;
    var digits = s;
    var mult: u64 = 1;
    switch (std.ascii.toLower(s[s.len - 1])) {
        'b' => digits = s[0 .. s.len - 1],
        'k' => {
            mult = 1 << 10;
            digits = s[0 .. s.len - 1];
        },
        'm' => {
            mult = 1 << 20;
            digits = s[0 .. s.len - 1];
        },
        'g' => {
            mult = 1 << 30;
            digits = s[0 .. s.len - 1];
        },
        else => {},
    }
    const n = std.fmt.parseInt(u64, digits, 10) catch return null;
    return n * mult;
}

pub fn parseCpus(s: []const u8) ?u32 {
    const v = std.fmt.parseFloat(f64, s) catch return null;
    if (v <= 0 or v > 1024) return null;
    return @intFromFloat(v * 1000);
}

/// Parses a list like "0-3,6" into a bitmask.
pub fn parseCpuset(s: []const u8) ?u64 {
    var mask: u64 = 0;
    var parts = std.mem.tokenizeScalar(u8, s, ',');
    while (parts.next()) |part| {
        const dash = std.mem.indexOfScalar(u8, part, '-');
        const first = std.fmt.parseInt(u8, if (dash) |d| part[0..d] else part, 10) catch return null;
        const last = if (dash) |d| std.fmt.parseInt(u8, part[d + 1 ..], 10) catch return null else first;
        if (first > last or last > 63) return null;
        var c = first;
        while (c <= last) : (c += 1) mask |= @as(u64, 1) << @intCast(c);
    }
    return if (mask == 0) null else mask;
}

test "parseSize understands suffixes" {
    try std.testing.expectEqual(@as(?u64, 512 * 1024 * 1024), parseSize("512m"));
    try std.testing.expectEqual(@as(?u64, 2 * 1024 * 1024 * 1024), parseSize("2G"));
    try std.testing.expectEqual(@as(?u64, 4096), parseSize("4096"));
    try std.testing.expectEqual(@as(?u64, null), parseSize("abc"));
}

test "parseCpus keeps fractions" {
    try std.testing.expectEqual(@as(?u32, 1500), parseCpus("1.5"));
    try std.testing.expectEqual(@as(?u32, null), parseCpus("0"));
}

test "parseCpuset builds a mask" {
    try std.testing.expectEqual(@as(?u64, 0b1001111), parseCpuset("0-3,6"));
    try std.testing.expectEqual(@as(?u64, null), parseCpuset("3-1"));
}

test "visibleCpus rounds up" {
    try std.testing.expectEqual(@as(u32, 2), visibleCpus(.{ .cpus_milli = 1500 }));
    try std.testing.expectEqual(@as(u32, 3), visibleCpus(.{ .cpuset = 0b111 }));
    try std.testing.expectEqual(@as(u32, 0), visibleCpus(.{}));
}
