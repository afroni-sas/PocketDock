//! System V shared memory, kept by the tracer.
//!
//! Android's seccomp policy kills shmget() and its relatives, and PostgreSQL
//! needs them to start. So the tracer answers them itself: a segment is a file
//! in the container's shm directory, and attaching one is a shared mapping of
//! that file. Like an IPC namespace, the table lives as long as the container.

const std = @import("std");
const sys = @import("sys.zig");
const linux = sys.linux;
const Err = sys.Err;
const Path = sys.Path;

pub const IPC_PRIVATE: i32 = 0;
pub const IPC_CREAT: u32 = 0o1000;
pub const IPC_EXCL: u32 = 0o2000;

pub const IPC_RMID: u32 = 0;
pub const IPC_SET: u32 = 1;
pub const IPC_STAT: u32 = 2;
pub const IPC_INFO: u32 = 3;
pub const SHM_LOCK: u32 = 11;
pub const SHM_UNLOCK: u32 = 12;
pub const SHM_STAT: u32 = 13;
pub const SHM_INFO: u32 = 14;
pub const SHM_STAT_ANY: u32 = 15;

pub const SHM_RDONLY: u32 = 0o10000;
pub const SHM_RND: u32 = 0o20000;
pub const SHM_REMAP: u32 = 0o40000;
pub const SHM_EXEC: u32 = 0o100000;

const SHM_DEST: u32 = 0o1000;

const max_segments = 4096;
const max_size: u64 = 1 << 46;

pub const stat_size = 112;
pub const info_size = 72;
pub const usage_size = 48;

pub const Who = struct { uid: u32, gid: u32, pid: i32 };

pub const Segment = struct {
    id: i32,
    key: i32,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    cpid: i32,
    lpid: i32 = 0,
    nattch: u64 = 0,
    atime: i64 = 0,
    dtime: i64 = 0,
    ctime: i64,
    removed: bool = false,

    /// `want` holds rwx bits: 4 to read, 2 to write.
    pub fn allowed(s: *const Segment, who: Who, want: u32) bool {
        if (who.uid == 0) return true;
        const granted = if (who.uid == s.uid or who.uid == s.cuid)
            s.mode >> 6
        else if (who.gid == s.gid or who.gid == s.cgid)
            s.mode >> 3
        else
            s.mode;
        return want & ~granted & 7 == 0;
    }

    pub fn isOwner(s: *const Segment, who: Who) bool {
        return who.uid == 0 or who.uid == s.uid or who.uid == s.cuid;
    }

    /// The segment as the guest's `struct shmid64_ds`, the same on x86_64 and
    /// aarch64.
    pub fn stat(s: *const Segment) [stat_size]u8 {
        var b: [stat_size]u8 = @splat(0);
        std.mem.writeInt(i32, b[0..4], if (s.removed) IPC_PRIVATE else s.key, .little);
        std.mem.writeInt(u32, b[4..8], s.uid, .little);
        std.mem.writeInt(u32, b[8..12], s.gid, .little);
        std.mem.writeInt(u32, b[12..16], s.cuid, .little);
        std.mem.writeInt(u32, b[16..20], s.cgid, .little);
        std.mem.writeInt(u32, b[20..24], s.mode | (if (s.removed) SHM_DEST else 0), .little);
        std.mem.writeInt(u64, b[48..56], s.size, .little);
        std.mem.writeInt(i64, b[56..64], s.atime, .little);
        std.mem.writeInt(i64, b[64..72], s.dtime, .little);
        std.mem.writeInt(i64, b[72..80], s.ctime, .little);
        std.mem.writeInt(i32, b[80..84], s.cpid, .little);
        std.mem.writeInt(i32, b[84..88], s.lpid, .little);
        std.mem.writeInt(u64, b[88..96], s.nattch, .little);
        return b;
    }

    /// Applies the owner and permissions of a guest's `struct shmid64_ds`.
    pub fn applySet(s: *Segment, b: *const [stat_size]u8) void {
        s.uid = std.mem.readInt(u32, b[4..8], .little);
        s.gid = std.mem.readInt(u32, b[8..12], .little);
        s.mode = std.mem.readInt(u32, b[20..24], .little) & 0o777;
        s.ctime = nowSec();
    }
};

pub const Attachment = struct { tgid: i32, addr: u64, size: u64, seg: i32 };

fn nowSec() i64 {
    return @intCast(@divFloor(sys.nowNs(), std.time.ns_per_s));
}

pub const Table = struct {
    gpa: std.mem.Allocator,
    dir: []const u8,
    segs: std.ArrayList(Segment) = .empty,
    atts: std.ArrayList(Attachment) = .empty,
    next_id: i32 = 1,

    pub fn deinit(self: *Table) void {
        self.clearDir();
        self.segs.deinit(self.gpa);
        self.atts.deinit(self.gpa);
    }

    /// Removes anything a crashed run left behind.
    pub fn clearDir(self: *Table) void {
        if (self.dir.len > 0) sys.rmrf(self.dir) catch {};
    }

    pub fn pathOf(self: *const Table, id: i32, out: *Path) Err!void {
        try out.set(self.dir);
        var num: [16]u8 = undefined;
        try out.append(std.fmt.bufPrint(&num, "/{d}", .{id}) catch unreachable);
    }

    fn byKey(self: *Table, key: i32) ?*Segment {
        for (self.segs.items) |*s| {
            if (s.key == key and !s.removed) return s;
        }
        return null;
    }

    pub fn find(self: *Table, id: i32) ?*Segment {
        for (self.segs.items) |*s| {
            if (s.id == id) return s;
        }
        return null;
    }

    pub fn get(self: *Table, key: i32, size: u64, flags: u32, who: Who) Err!i32 {
        if (key != IPC_PRIVATE) {
            if (self.byKey(key)) |s| {
                if (flags & IPC_CREAT != 0 and flags & IPC_EXCL != 0) return sys.fail(.EXIST);
                if (size > s.size) return sys.fail(.INVAL);
                if (!s.allowed(who, flags >> 6 | flags >> 3 | flags)) return sys.fail(.ACCES);
                return s.id;
            }
            if (flags & IPC_CREAT == 0) return sys.fail(.NOENT);
        }
        if (size == 0 or size > max_size) return sys.fail(.INVAL);
        if (self.segs.items.len >= max_segments or self.dir.len == 0) return sys.fail(.NOSPC);

        try sys.mkdirP(self.dir, 0o700);
        const id = self.next_id;
        var p: Path = .{};
        try self.pathOf(id, &p);
        const fd = try sys.open(p.z(), sys.O_WRONLY | sys.O_CREAT | sys.O_EXCL | sys.O_CLOEXEC, 0o600);
        defer sys.close(fd);
        if (linux.errno(linux.ftruncate(fd, @intCast(size))) != .SUCCESS) {
            sys.unlink(p.z()) catch {};
            return sys.fail(.NOSPC);
        }
        self.segs.append(self.gpa, .{
            .id = id,
            .key = key,
            .size = size,
            .mode = flags & 0o777,
            .uid = who.uid,
            .gid = who.gid,
            .cuid = who.uid,
            .cgid = who.gid,
            .cpid = who.pid,
            .ctime = nowSec(),
        }) catch return sys.fail(.NOMEM);
        self.next_id += 1;
        return id;
    }

    fn destroy(self: *Table, s: *Segment) void {
        var p: Path = .{};
        self.pathOf(s.id, &p) catch return;
        sys.unlink(p.z()) catch {};
        const i = (@intFromPtr(s) - @intFromPtr(self.segs.items.ptr)) / @sizeOf(Segment);
        _ = self.segs.swapRemove(i);
    }

    /// IPC_RMID: the segment goes away once nobody has it attached.
    pub fn remove(self: *Table, s: *Segment) void {
        s.removed = true;
        s.ctime = nowSec();
        if (s.nattch == 0) self.destroy(s);
    }

    pub fn noteAttach(self: *Table, id: i32, tgid: i32, addr: u64, pid: i32) void {
        const s = self.find(id) orelse return;
        self.atts.append(self.gpa, .{ .tgid = tgid, .addr = addr, .size = s.size, .seg = id }) catch return;
        s.nattch += 1;
        s.atime = nowSec();
        s.lpid = pid;
    }

    pub fn attachmentAt(self: *Table, tgid: i32, addr: u64) ?*Attachment {
        for (self.atts.items) |*a| {
            if (a.tgid == tgid and a.addr == addr) return a;
        }
        return null;
    }

    fn release(self: *Table, id: i32, pid: i32) void {
        const s = self.find(id) orelse return;
        s.nattch -= 1;
        s.dtime = nowSec();
        s.lpid = pid;
        if (s.removed and s.nattch == 0) self.destroy(s);
    }

    pub fn noteDetach(self: *Table, tgid: i32, addr: u64, pid: i32) void {
        for (self.atts.items, 0..) |a, i| {
            if (a.tgid != tgid or a.addr != addr) continue;
            _ = self.atts.swapRemove(i);
            self.release(a.seg, pid);
            return;
        }
    }

    /// A forked child inherits its parent's attachments.
    pub fn forked(self: *Table, parent: i32, child: i32) void {
        const n = self.atts.items.len;
        for (0..n) |i| {
            const a = self.atts.items[i];
            if (a.tgid != parent) continue;
            self.atts.append(self.gpa, .{ .tgid = child, .addr = a.addr, .size = a.size, .seg = a.seg }) catch return;
            if (self.find(a.seg)) |s| s.nattch += 1;
        }
    }

    /// A process exited or replaced its image: its mappings are gone.
    pub fn gone(self: *Table, tgid: i32) void {
        var i: usize = 0;
        while (i < self.atts.items.len) {
            if (self.atts.items[i].tgid != tgid) {
                i += 1;
                continue;
            }
            const a = self.atts.swapRemove(i);
            self.release(a.seg, 0);
        }
    }

    /// `struct shminfo64`, for IPC_INFO.
    pub fn info(_: *const Table) [info_size]u8 {
        var b: [info_size]u8 = @splat(0);
        std.mem.writeInt(u64, b[0..8], max_size, .little);
        std.mem.writeInt(u64, b[8..16], 1, .little);
        std.mem.writeInt(u64, b[16..24], max_segments, .little);
        std.mem.writeInt(u64, b[24..32], max_segments, .little);
        std.mem.writeInt(u64, b[32..40], max_size / 4096, .little);
        return b;
    }

    /// `struct shm_info`, for SHM_INFO.
    pub fn usage(self: *const Table) [usage_size]u8 {
        var b: [usage_size]u8 = @splat(0);
        var pages: u64 = 0;
        for (self.segs.items) |s| pages += (s.size + 4095) / 4096;
        std.mem.writeInt(i32, b[0..4], @intCast(self.segs.items.len), .little);
        std.mem.writeInt(u64, b[8..16], pages, .little);
        return b;
    }

    /// What IPC_INFO and SHM_INFO return: the highest used slot.
    pub fn highestIndex(self: *const Table) i64 {
        return @as(i64, @intCast(self.segs.items.len)) - 1;
    }
};

const root: Who = .{ .uid = 0, .gid = 0, .pid = 1 };

fn testTable() !Table {
    var id: [12]u8 = undefined;
    sys.randomId(&id);
    const dir = try std.fmt.allocPrint(std.testing.allocator, "/tmp/pd-sysv-{s}", .{id});
    return .{ .gpa = std.testing.allocator, .dir = dir };
}

fn freeTable(t: *Table) void {
    t.deinit();
    std.testing.allocator.free(t.dir);
}

test "a key names one segment" {
    var t = try testTable();
    defer freeTable(&t);
    const id = try t.get(42, 4096, IPC_CREAT | IPC_EXCL | 0o600, root);
    try std.testing.expectEqual(id, try t.get(42, 4096, 0, root));
    try std.testing.expectError(error.Sys, t.get(42, 4096, IPC_CREAT | IPC_EXCL | 0o600, root));
    try std.testing.expectEqual(sys.E.EXIST, sys.last);
    try std.testing.expectError(error.Sys, t.get(42, 8192, 0, root));
    try std.testing.expectEqual(sys.E.INVAL, sys.last);
    try std.testing.expectError(error.Sys, t.get(43, 4096, 0, root));
    try std.testing.expectEqual(sys.E.NOENT, sys.last);
}

test "IPC_PRIVATE always makes a new segment" {
    var t = try testTable();
    defer freeTable(&t);
    const a = try t.get(IPC_PRIVATE, 100, IPC_CREAT | 0o600, root);
    const b = try t.get(IPC_PRIVATE, 100, IPC_CREAT | 0o600, root);
    try std.testing.expect(a != b);
}

test "a removed segment stays until the last detach" {
    var t = try testTable();
    defer freeTable(&t);
    const id = try t.get(7, 4096, IPC_CREAT | 0o600, root);
    t.noteAttach(id, 100, 0x1000, 1);
    t.remove(t.find(id).?);
    try std.testing.expect(t.find(id) != null);
    // The key is free again as soon as the segment is marked.
    try std.testing.expectError(error.Sys, t.get(7, 4096, 0, root));
    t.noteDetach(100, 0x1000, 1);
    try std.testing.expect(t.find(id) == null);

    var p: Path = .{};
    try t.pathOf(id, &p);
    try std.testing.expect(!sys.exists(p.z()));
}

test "attachments follow fork, exec and exit" {
    var t = try testTable();
    defer freeTable(&t);
    const id = try t.get(9, 4096, IPC_CREAT | 0o600, root);
    t.noteAttach(id, 100, 0x1000, 1);
    t.forked(100, 200);
    try std.testing.expectEqual(@as(u64, 2), t.find(id).?.nattch);
    try std.testing.expect(t.attachmentAt(200, 0x1000) != null);
    t.gone(100);
    try std.testing.expectEqual(@as(u64, 1), t.find(id).?.nattch);
    t.remove(t.find(id).?);
    t.gone(200);
    try std.testing.expect(t.find(id) == null);
}

test "permissions are checked like file modes" {
    var t = try testTable();
    defer freeTable(&t);
    const owner: Who = .{ .uid = 70, .gid = 70, .pid = 1 };
    const other: Who = .{ .uid = 80, .gid = 80, .pid = 2 };
    const id = try t.get(5, 4096, IPC_CREAT | 0o640, owner);
    const s = t.find(id).?;
    try std.testing.expect(s.allowed(owner, 6));
    try std.testing.expect(!s.allowed(other, 4));
    try std.testing.expect(s.allowed(.{ .uid = 80, .gid = 70, .pid = 3 }, 4));
    try std.testing.expect(!s.allowed(.{ .uid = 80, .gid = 70, .pid = 3 }, 2));
    try std.testing.expect(s.allowed(root, 6));
}

test "stat fills the fields PostgreSQL reads" {
    var t = try testTable();
    defer freeTable(&t);
    const owner: Who = .{ .uid = 70, .gid = 71, .pid = 33 };
    const id = try t.get(5, 4096, IPC_CREAT | 0o600, owner);
    t.noteAttach(id, 100, 0x1000, 33);
    const b = t.find(id).?.stat();
    try std.testing.expectEqual(@as(u32, 70), std.mem.readInt(u32, b[4..8], .little));
    try std.testing.expectEqual(@as(u64, 4096), std.mem.readInt(u64, b[48..56], .little));
    try std.testing.expectEqual(@as(i32, 33), std.mem.readInt(i32, b[80..84], .little));
    try std.testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, b[88..96], .little));
}
