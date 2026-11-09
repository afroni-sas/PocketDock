//! A copy-on-write root filesystem implemented entirely in the tracer.
//!
//! Unprivileged Android has no overlayfs, no bind mounts and no hard links, so
//! the union lives in user space. `lower` is the read-only image and `upper`
//! holds this container's changes.
//!
//! Instead of whiteouts and merged directory listings, a directory is copied
//! into `upper` the first time it is modified, as a complete listing where
//! every untouched entry is a zero-length *stub*. From then on `upper` is the
//! truth for that directory: `getdents` works natively, and deleting a file is
//! just deleting its stub. Directories nobody writes to cost nothing.
//!
//! A stub is recognised by a magic mtime, which the guest can never observe
//! because every path naming a stub is redirected to the file in `lower`.

const std = @import("std");
const sys = @import("sys.zig");
const Path = sys.Path;
const Err = sys.Err;

pub const STUB_SEC: i64 = 1;
pub const STUB_NSEC: i64 = 20260109;

pub const Mount = struct {
    guest: []const u8,
    host: []const u8,
    ro: bool = false,
};

pub const Where = enum { upper, lower, mount, proc };

pub const Resolved = struct {
    /// Canonical guest path, with every symlink resolved.
    guest: Path = .{},
    /// Where the kernel should look.
    host: Path = .{},
    where: Where = .upper,
    exists: bool = false,
    /// The parent exists, so creating this path can succeed.
    parent_ok: bool = false,
    mode: u32 = 0,
    mount_ro: bool = false,
};

pub const ProcPaths = struct { cwd: []const u8, exe: []const u8 };

pub const ProcResolver = struct {
    ctx: *anyopaque,
    lookup: *const fn (ctx: *anyopaque, pid: i32) ?ProcPaths,
    /// Maps a PID as the guest knows it to the real one, or null if hidden.
    toReal: *const fn (ctx: *anyopaque, pid: i32) ?i32,
};

fn isStub(st: *const sys.Stat) bool {
    return st.mtime == STUB_SEC and st.mtime_nsec == STUB_NSEC;
}

fn dirname(canon: []const u8) []const u8 {
    const i = std.mem.lastIndexOfScalar(u8, canon, '/') orelse return "";
    return canon[0..i];
}

fn notFound() bool {
    return sys.last == .NOENT or sys.last == .NOTDIR;
}

const max_depth = 256;
const St = enum(u8) { upper, lower };
const Found = enum { missing, upper, lower, mount };

pub const Vfs = struct {
    lower: []const u8,
    upper: []const u8,
    /// Scratch space on the same filesystem as `upper`.
    work: []const u8,
    /// Host paths visible in the guest, like Docker volumes.
    mounts: []const Mount,
    procs: ?ProcResolver = null,
    tgid: i32 = 0,
    tid: i32 = 0,
    work_seq: u32 = 0,
    /// Treat `/proc` as an ordinary directory (when unpacking images).
    raw: bool = false,

    pub fn mountFor(self: *const Vfs, canon: []const u8) ?*const Mount {
        var best: ?*const Mount = null;
        for (self.mounts) |*m| {
            if (!std.mem.startsWith(u8, canon, m.guest)) continue;
            if (canon.len != m.guest.len and canon[m.guest.len] != '/') continue;
            if (best == null or best.?.guest.len < m.guest.len) best = m;
        }
        return best;
    }

    fn lookup(self: *Vfs, canon: []const u8, cur: St, host: *Path, st: *sys.Stat) Err!Found {
        if (self.mountFor(canon)) |m| {
            try host.set(m.host);
            try host.append(canon[m.guest.len..]);
            sys.lstat(host.z(), st) catch {
                if (notFound()) return .missing;
                return error.Sys;
            };
            return .mount;
        }
        if (cur == .upper) {
            try host.set(self.upper);
            try host.append(canon);
            sys.lstat(host.z(), st) catch {
                if (notFound()) return .missing;
                return error.Sys;
            };
            if (!isStub(st)) return .upper;
        }
        try host.set(self.lower);
        try host.append(canon);
        sys.lstat(host.z(), st) catch {
            if (notFound()) return .missing;
            return error.Sys;
        };
        return .lower;
    }

    /// Resolves an absolute guest path, following symlinks in guest terms so
    /// nothing can escape the container root.
    pub fn resolve(self: *Vfs, guest: []const u8, follow: bool, out: *Resolved) Err!void {
        return self.resolveNested(guest, follow, out, 0);
    }

    fn resolveNested(self: *Vfs, guest: []const u8, follow: bool, out: *Resolved, nest: u32) Err!void {
        if (nest > 8) return sys.fail(.LOOP);
        var rem = try Path.of(guest);
        var pos: usize = 0;
        var depth: usize = 0;
        var cur: St = .upper;
        var links: u32 = 0;
        var bounds: [max_depth]u16 = undefined;
        var parents: [max_depth]St = undefined;
        var stale = true; // `out.host` does not describe `canon` yet
        var last_found: Found = .upper;
        var st: sys.Stat = undefined;

        out.guest.len = 0;
        out.host.len = 0;
        out.exists = false;
        out.parent_ok = false;
        out.mount_ro = false;
        out.mode = 0;
        const canon = &out.guest;

        while (true) {
            while (pos < rem.len and rem.buf[pos] == '/') pos += 1;
            if (pos >= rem.len) break;
            const start = pos;
            while (pos < rem.len and rem.buf[pos] != '/') pos += 1;
            const comp = rem.buf[start..pos];
            if (std.mem.eql(u8, comp, ".")) {
                stale = true;
                continue;
            }
            if (std.mem.eql(u8, comp, "..")) {
                if (depth > 0) {
                    depth -= 1;
                    canon.len = bounds[depth];
                    cur = parents[depth];
                }
                stale = true;
                continue;
            }

            var next = pos;
            while (next < rem.len and rem.buf[next] == '/') next += 1;
            const is_last = next >= rem.len;
            const trailing = is_last and next > pos;

            if (depth == 0 and !self.raw and std.mem.eql(u8, comp, "proc")) {
                return self.finishProc(rem.buf[pos..rem.len], follow, out, nest);
            }

            if (depth >= max_depth) return sys.fail(.NAMETOOLONG);
            bounds[depth] = @intCast(canon.len);
            parents[depth] = cur;
            depth += 1;
            try canon.append("/");
            try canon.append(comp);

            const found = try self.lookup(canon.slice(), cur, &out.host, &st);
            stale = false;

            if (found == .missing) {
                try self.setMissing(canon.slice(), cur, is_last, out);
                if (!is_last) {
                    // The kernel reports ENOENT for the deeper path by itself.
                    try canon.append(rem.buf[pos..rem.len]);
                    try out.host.append(rem.buf[pos..rem.len]);
                } else if (trailing) {
                    try out.host.append("/");
                }
                return;
            }

            if (sys.isLnk(st.mode) and (!is_last or follow or trailing)) {
                links += 1;
                if (links > 40) return sys.fail(.LOOP);
                var tbuf: [sys.PATH_MAX]u8 = undefined;
                const target = try sys.readlink(out.host.z(), tbuf[0 .. tbuf.len - 1]);
                var nrem = try Path.of(target);
                try nrem.append(rem.buf[pos..rem.len]);
                rem = nrem;
                pos = 0;
                depth -= 1;
                if (target.len > 0 and target[0] == '/') {
                    depth = 0;
                    canon.len = 0;
                    cur = .upper;
                } else {
                    canon.len = bounds[depth];
                    cur = parents[depth];
                }
                stale = true;
                continue;
            }

            if (!is_last and !sys.isDir(st.mode)) {
                // Leave it to the kernel to report ENOTDIR.
                try out.host.append(rem.buf[pos..rem.len]);
                try canon.append(rem.buf[pos..rem.len]);
                out.where = whereOf(found);
                return;
            }

            last_found = found;
            switch (found) {
                .upper => cur = .upper,
                .lower => cur = .lower,
                else => {},
            }
            if (trailing) try out.host.append("/");
        }

        if (depth == 0) {
            try canon.set("/");
            try out.host.set(self.upper);
            out.where = .upper;
            out.exists = true;
            out.parent_ok = true;
            out.mode = sys.S_IFDIR | 0o755;
            return;
        }
        if (stale) {
            last_found = try self.lookup(canon.slice(), parents[depth - 1], &out.host, &st);
            if (last_found == .missing) {
                try self.setMissing(canon.slice(), parents[depth - 1], true, out);
                return;
            }
        }
        out.exists = true;
        out.parent_ok = true;
        out.mode = st.mode;
        out.where = whereOf(last_found);
        if (last_found == .mount) out.mount_ro = self.mountFor(canon.slice()).?.ro;
    }

    fn whereOf(f: Found) Where {
        return switch (f) {
            .upper, .missing => .upper,
            .lower => .lower,
            .mount => .mount,
        };
    }

    fn setMissing(self: *Vfs, canon: []const u8, cur: St, is_last: bool, out: *Resolved) Err!void {
        out.exists = false;
        out.parent_ok = is_last;
        if (self.mountFor(canon)) |m| {
            out.where = .mount;
            out.mount_ro = m.ro;
            return;
        }
        out.where = if (cur == .upper) .upper else .lower;
        try out.host.set(if (cur == .upper) self.upper else self.lower);
        try out.host.append(canon);
    }

    /// `/proc` belongs to the kernel, so it is handed over untouched, apart
    /// from the few links that would reveal the host's paths.
    fn finishProc(self: *Vfs, rest_in: []const u8, follow: bool, out: *Resolved, nest: u32) Err!void {
        var comps: [32][]const u8 = undefined;
        var n: usize = 0;
        var it = std.mem.tokenizeScalar(u8, rest_in, '/');
        while (it.next()) |c| {
            if (std.mem.eql(u8, c, ".")) continue;
            if (std.mem.eql(u8, c, "..")) {
                if (n > 0) n -= 1;
                continue;
            }
            if (n >= comps.len) return sys.fail(.NAMETOOLONG);
            comps[n] = c;
            n += 1;
        }

        var pidbuf: [64]u8 = undefined;
        var rest: Path = .{};
        if (n > 0 and std.mem.eql(u8, comps[0], "self")) {
            try rest.append(std.fmt.bufPrint(&pidbuf, "/{d}", .{self.tgid}) catch unreachable);
        } else if (n > 0 and std.mem.eql(u8, comps[0], "thread-self")) {
            try rest.append(std.fmt.bufPrint(&pidbuf, "/{d}/task/{d}", .{ self.tgid, self.tid }) catch unreachable);
        } else if (n > 0) {
            // A number here is a PID as the container knows it.
            var first = comps[0];
            var realbuf: [32]u8 = undefined;
            if (self.procs) |procs| {
                if (std.fmt.parseInt(i32, first, 10) catch null) |v| {
                    const real = procs.toReal(procs.ctx, v) orelse {
                        // Other containers and the tracer do not exist in here.
                        try out.guest.set("/proc/");
                        try out.guest.append(first);
                        try out.host.set("/proc/.pocketdock-hidden");
                        out.where = .proc;
                        return;
                    };
                    first = std.fmt.bufPrint(&realbuf, "{d}", .{real}) catch unreachable;
                }
            }
            try rest.append("/");
            try rest.append(first);
        }
        for (comps[@min(n, 1)..n]) |c| {
            try rest.append("/");
            try rest.append(c);
        }

        try out.guest.set("/proc");
        try out.guest.append(rest.slice());

        if (self.mountFor(out.guest.slice())) |m| {
            try out.host.set(m.host);
            try out.host.append(out.guest.slice()[m.guest.len..]);
            var st: sys.Stat = undefined;
            sys.lstat(out.host.z(), &st) catch return;
            out.exists = true;
            out.parent_ok = true;
            out.mode = st.mode;
            out.where = .mount;
            out.mount_ro = m.ro;
            return;
        }

        if (self.procs) |procs| {
            var pid_it = std.mem.tokenizeScalar(u8, rest.slice(), '/');
            const pid_s = pid_it.next() orelse "";
            const which = pid_it.next() orelse "";
            const tail = pid_it.rest();
            const pid = std.fmt.parseInt(i32, pid_s, 10) catch 0;
            if (pid != 0) {
                if (procs.lookup(procs.ctx, pid)) |info| {
                    if (std.mem.eql(u8, which, "exe") and tail.len == 0 and follow) {
                        return self.resolveNested(info.exe, true, out, nest + 1);
                    }
                    if ((std.mem.eql(u8, which, "cwd") or std.mem.eql(u8, which, "root")) and (tail.len > 0 or follow)) {
                        var g = try Path.of(if (which[0] == 'c') info.cwd else "/");
                        try g.append("/");
                        try g.append(tail);
                        return self.resolveNested(g.slice(), follow, out, nest + 1);
                    }
                }
            }
        }

        try out.host.set(out.guest.slice());
        out.where = .proc;
        out.parent_ok = true;
        var st: sys.Stat = undefined;
        sys.lstat(out.host.z(), &st) catch return;
        out.exists = true;
        out.mode = st.mode;
    }

    /// Maps a path reported by the kernel back into the guest's view.
    /// Returns false when it is not inside the container's storage.
    pub fn toGuest(self: *const Vfs, host: []const u8, out: *Path) Err!bool {
        var best: ?*const Mount = null;
        for (self.mounts) |*m| {
            if (!std.mem.startsWith(u8, host, m.host)) continue;
            if (host.len != m.host.len and host[m.host.len] != '/') continue;
            if (best == null or best.?.host.len < m.host.len) best = m;
        }
        if (best) |m| {
            try out.set(m.guest);
            try out.append(host[m.host.len..]);
            return true;
        }
        for ([_][]const u8{ self.upper, self.lower }) |base| {
            if (!std.mem.startsWith(u8, host, base)) continue;
            if (host.len == base.len) {
                try out.set("/");
                return true;
            }
            if (host[base.len] != '/') continue;
            try out.set(host[base.len..]);
            return true;
        }
        return false;
    }

    /// Turns the stub directory `prefix` into a real one with a full listing.
    /// Built aside and renamed in, so a crash never leaves a partial listing.
    fn materialize(self: *Vfs, prefix: []const u8) Err!void {
        var lower_p = try Path.join(self.lower, prefix);
        var upper_p = try Path.join(self.upper, prefix);
        var lower_st: sys.Stat = undefined;
        try sys.lstat(lower_p.z(), &lower_st);

        self.work_seq +%= 1;
        var name_buf: [64]u8 = undefined;
        var tmp = try Path.of(self.work);
        try tmp.append(std.fmt.bufPrint(&name_buf, "/s{d}.{d}", .{ self.tid, self.work_seq }) catch unreachable);
        try sys.mkdir(tmp.z(), 0o700);
        errdefer sys.rmrf(tmp.slice()) catch {};

        var it = try sys.DirIter.open_(lower_p.z());
        defer it.deinit();
        while (try it.next()) |ent| {
            var src = try Path.join(lower_p.slice(), "/");
            try src.append(ent.name);
            var dst = try Path.join(tmp.slice(), "/");
            try dst.append(ent.name);
            var st: sys.Stat = undefined;
            try sys.lstat(src.z(), &st);
            if (sys.isLnk(st.mode)) {
                var tbuf: [sys.PATH_MAX]u8 = undefined;
                const target = try sys.readlink(src.z(), tbuf[0 .. tbuf.len - 1]);
                tbuf[target.len] = 0;
                try sys.symlink(@ptrCast(&tbuf), dst.z());
            } else if (sys.isDir(st.mode)) {
                try sys.mkdir(dst.z(), (st.mode & 0o7777) | 0o700);
                try sys.utimes(sys.AT_FDCWD, dst.z(), STUB_SEC, STUB_NSEC, 0);
            } else {
                const fd = try sys.open(dst.z(), sys.O_WRONLY | sys.O_CREAT | sys.O_EXCL, (st.mode & 0o777) | 0o600);
                defer sys.close(fd);
                try sys.utimes(fd, null, STUB_SEC, STUB_NSEC, 0);
            }
        }
        try sys.chmod(tmp.z(), (lower_st.mode & 0o7777) | 0o700);
        try sys.utimes(sys.AT_FDCWD, tmp.z(), lower_st.mtime, lower_st.mtime_nsec, 0);
        try sys.rename(tmp.z(), upper_p.z());
    }

    /// Makes every directory along `canon` real in `upper`.
    pub fn sealDir(self: *Vfs, canon: []const u8) Err!void {
        var i: usize = 0;
        while (i <= canon.len) : (i += 1) {
            if (i != canon.len and canon[i] != '/') continue;
            if (i == 0 and canon.len > 0) continue; // leading slash; root is always real
            const prefix = canon[0..i];
            if (prefix.len == 0) continue;
            var upper_p = try Path.join(self.upper, prefix);
            var st: sys.Stat = undefined;
            sys.lstat(upper_p.z(), &st) catch {
                if (sys.last != .NOENT) return error.Sys;
                try self.materialize(prefix);
                continue;
            };
            if (!sys.isDir(st.mode)) return sys.fail(.NOTDIR);
            if (isStub(&st)) try self.materialize(prefix);
        }
    }

    fn sealParent(self: *Vfs, canon: []const u8) Err!void {
        return self.sealDir(dirname(canon));
    }

    fn pointAtUpper(self: *Vfs, r: *Resolved) Err!void {
        try r.host.set(self.upper);
        try r.host.append(r.guest.slice());
        r.where = .upper;
    }

    /// Copies `src` to `dst`, keeping the mode and mtime.
    pub fn copyFile(src: [*:0]const u8, dst: [*:0]const u8) Err!void {
        var st: sys.Stat = undefined;
        try sys.stat(src, &st);
        const in = try sys.open(src, 0, 0);
        defer sys.close(in);
        const out = try sys.open(dst, sys.O_WRONLY | sys.O_CREAT | sys.O_TRUNC, (st.mode & 0o777) | 0o600);
        defer sys.close(out);
        var buf: [65536]u8 = undefined;
        while (true) {
            const n = try sys.read(in, &buf);
            if (n == 0) break;
            try sys.writeAll(out, buf[0..n]);
        }
        try sys.fchmod(out, (st.mode & 0o7777) | 0o600);
        // A stub becomes real only here, so a crash mid-copy leaves a stub.
        try sys.utimes(out, null, st.mtime, st.mtime_nsec, 0);
    }

    pub fn copyUp(self: *Vfs, r: *Resolved) Err!void {
        try self.sealParent(r.guest.slice());
        var dst = try Path.join(self.upper, r.guest.slice());
        try copyFile(r.host.z(), dst.z());
        try self.pointAtUpper(r);
    }

    /// Prepares an existing path for a change to its contents or metadata.
    pub fn prepareWrite(self: *Vfs, r: *Resolved) Err!void {
        switch (r.where) {
            .upper, .proc => {},
            .mount => if (r.mount_ro) return sys.fail(.ROFS),
            .lower => if (sys.isDir(r.mode)) {
                try self.sealDir(r.guest.slice());
                try self.pointAtUpper(r);
            } else {
                try self.copyUp(r);
            },
        }
    }

    pub fn prepareCreate(self: *Vfs, r: *Resolved) Err!void {
        if (!r.parent_ok) return sys.fail(.NOENT);
        switch (r.where) {
            .proc => return sys.fail(.PERM),
            .mount => if (r.mount_ro) return sys.fail(.ROFS),
            .upper, .lower => {
                try self.sealParent(r.guest.slice());
                try self.pointAtUpper(r);
            },
        }
    }

    /// Prepares `r` to be unlinked, or replaced by a rename.
    pub fn prepareRemove(self: *Vfs, r: *Resolved) Err!void {
        switch (r.where) {
            .proc => return sys.fail(.PERM),
            .upper => {},
            .mount => {
                if (r.mount_ro) return sys.fail(.ROFS);
                const m = self.mountFor(r.guest.slice()).?;
                if (m.guest.len == r.guest.len) return sys.fail(.BUSY);
            },
            .lower => {
                try self.sealParent(r.guest.slice());
                // Listing its children makes the kernel report ENOTEMPTY.
                if (sys.isDir(r.mode)) try self.sealDir(r.guest.slice());
                try self.pointAtUpper(r);
            },
        }
    }

    /// A renamed stub would lose its link to `lower`, so whatever moves has
    /// to be fully real first.
    pub fn prepareRenameSource(self: *Vfs, r: *Resolved) Err!void {
        switch (r.where) {
            .proc => return sys.fail(.PERM),
            .mount => {
                if (r.mount_ro) return sys.fail(.ROFS);
                const m = self.mountFor(r.guest.slice()).?;
                if (m.guest.len == r.guest.len) return sys.fail(.BUSY);
            },
            .upper => if (sys.isDir(r.mode)) try self.materializeTree(r.guest.slice()),
            .lower => if (sys.isDir(r.mode)) {
                try self.sealParent(r.guest.slice());
                try self.materializeTree(r.guest.slice());
                try self.pointAtUpper(r);
            } else {
                try self.copyUp(r);
            },
        }
    }

    fn materializeTree(self: *Vfs, canon: []const u8) Err!void {
        try self.sealDir(canon);
        var dir = try Path.join(self.upper, canon);
        var it = try sys.DirIter.open_(dir.z());
        defer it.deinit();
        while (try it.next()) |ent| {
            var child = try Path.join(canon, "/");
            try child.append(ent.name);
            var up = try Path.join(self.upper, child.slice());
            var st: sys.Stat = undefined;
            try sys.lstat(up.z(), &st);
            if (sys.isDir(st.mode)) {
                try self.materializeTree(child.slice());
            } else if (isStub(&st)) {
                var low = try Path.join(self.lower, child.slice());
                try copyFile(low.z(), up.z());
            }
        }
    }

    /// Prepares the root of a new container.
    pub fn init(self: *Vfs) Err!void {
        try sys.mkdirP(self.work, 0o700);
        try sys.mkdirP(self.upper, 0o755);
        try self.materialize("");
    }

    /// Creates a directory, and its parents, if it does not exist yet.
    pub fn ensureDir(self: *Vfs, guest: []const u8) Err!void {
        var r: Resolved = .{};
        try self.resolve(guest, true, &r);
        if (r.exists) return;
        const canon = r.guest.slice();
        var i: usize = 1;
        while (i <= canon.len) : (i += 1) {
            if (i != canon.len and canon[i] != '/') continue;
            const prefix = canon[0..i];
            try self.sealDir(dirname(prefix));
            var up = try Path.join(self.upper, prefix);
            var st: sys.Stat = undefined;
            sys.lstat(up.z(), &st) catch {
                if (sys.last != .NOENT) return error.Sys;
                try sys.mkdir(up.z(), 0o755);
            };
        }
    }
};

const testing = std.testing;

/// A throwaway image with a known shape, and a container on top of it.
const Fixture = struct {
    base: Path,
    lower: Path,
    upper: Path,
    work: Path,
    vfs: Vfs,

    fn write(self: *Fixture, rel: []const u8, data: []const u8) !void {
        try sys.writeFile((try Path.join(self.lower.slice(), rel)).slice(), data, 0o644);
    }

    fn mkdir(self: *Fixture, rel: []const u8) !void {
        try sys.mkdirP((try Path.join(self.lower.slice(), rel)).slice(), 0o755);
    }

    fn lowerExists(self: *Fixture, rel: []const u8) !bool {
        var p = try Path.join(self.lower.slice(), rel);
        return sys.exists(p.z());
    }

    fn read(self: *Fixture, r: *Resolved) ![]u8 {
        _ = self;
        return sys.readFileAlloc(testing.allocator, r.host.slice(), 4096);
    }

    fn deinit(self: *Fixture) void {
        sys.rmrf(self.base.slice()) catch {};
    }
};

fn setup(fx: *Fixture) !void {
    var cwd_buf: [sys.PATH_MAX]u8 = undefined;
    const n = try sys.ck(sys.linux.getcwd(&cwd_buf, cwd_buf.len));
    var id: [12]u8 = undefined;
    sys.randomId(&id);
    fx.base = try Path.join(cwd_buf[0 .. n - 1], "/.zig-cache/tmp/vfs-");
    try fx.base.append(&id);
    fx.lower = try Path.join(fx.base.slice(), "/lower");
    fx.upper = try Path.join(fx.base.slice(), "/upper");
    fx.work = try Path.join(fx.base.slice(), "/work");
    try fx.mkdir("/etc/conf.d");
    try fx.mkdir("/usr/lib/python");
    try fx.write("/etc/passwd", "root\n");
    try fx.write("/etc/hostname", "image\n");
    try fx.write("/etc/conf.d/a", "a\n");
    try fx.write("/usr/lib/python/mod.py", "code\n");
    var link = try Path.join(fx.lower.slice(), "/escape");
    try sys.symlink("../../../../../../..", link.z());
    var abs = try Path.join(fx.lower.slice(), "/abs");
    try sys.symlink("/etc", abs.z());
    fx.vfs = .{
        .lower = fx.lower.slice(),
        .upper = fx.upper.slice(),
        .work = fx.work.slice(),
        .mounts = &.{},
        .raw = true,
    };
    try fx.vfs.init();
}

test "reads come from the image until something is written" {
    var fx: Fixture = undefined;
    try setup(&fx);
    defer fx.deinit();
    var r: Resolved = .{};
    try fx.vfs.resolve("/etc/passwd", true, &r);
    try testing.expect(r.exists);
    try testing.expectEqual(Where.lower, r.where);
    try testing.expectEqualStrings("/etc/passwd", r.guest.slice());
}

test "writing copies up and leaves the image alone" {
    var fx: Fixture = undefined;
    try setup(&fx);
    defer fx.deinit();
    var r: Resolved = .{};
    try fx.vfs.resolve("/etc/passwd", true, &r);
    try fx.vfs.prepareWrite(&r);
    try testing.expectEqual(Where.upper, r.where);
    try sys.writeFile(r.host.slice(), "changed\n", 0o644);

    var again: Resolved = .{};
    try fx.vfs.resolve("/etc/passwd", true, &again);
    const got = try fx.read(&again);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("changed\n", got);

    const orig = try sys.readFileAlloc(testing.allocator, (try Path.join(fx.lower.slice(), "/etc/passwd")).slice(), 64);
    defer testing.allocator.free(orig);
    try testing.expectEqualStrings("root\n", orig);

    // Untouched neighbours are still served from the image.
    var other: Resolved = .{};
    try fx.vfs.resolve("/etc/hostname", true, &other);
    try testing.expectEqual(Where.lower, other.where);
}

test "deleting hides the file in the container only" {
    var fx: Fixture = undefined;
    try setup(&fx);
    defer fx.deinit();
    var r: Resolved = .{};
    try fx.vfs.resolve("/etc/hostname", false, &r);
    try fx.vfs.prepareRemove(&r);
    try sys.unlink(r.host.z());

    var after: Resolved = .{};
    try fx.vfs.resolve("/etc/hostname", false, &after);
    try testing.expect(!after.exists);
    try testing.expect(try fx.lowerExists("/etc/hostname"));

    var sibling: Resolved = .{};
    try fx.vfs.resolve("/etc/passwd", false, &sibling);
    try testing.expect(sibling.exists);
}

test "removing a non-empty image directory fails like a real one" {
    var fx: Fixture = undefined;
    try setup(&fx);
    defer fx.deinit();
    var r: Resolved = .{};
    try fx.vfs.resolve("/etc/conf.d", false, &r);
    try fx.vfs.prepareRemove(&r);
    try testing.expectError(error.Sys, sys.rmdir(r.host.z()));
    try testing.expectEqual(sys.E.NOTEMPTY, sys.last);
}

test "renaming an image directory moves its whole contents" {
    var fx: Fixture = undefined;
    try setup(&fx);
    defer fx.deinit();
    var old: Resolved = .{};
    var new: Resolved = .{};
    try fx.vfs.resolve("/usr/lib/python", false, &old);
    try fx.vfs.resolve("/usr/lib/py3", false, &new);
    try fx.vfs.prepareRenameSource(&old);
    try fx.vfs.prepareCreate(&new);
    try sys.rename(old.host.z(), new.host.z());

    var moved: Resolved = .{};
    try fx.vfs.resolve("/usr/lib/py3/mod.py", true, &moved);
    try testing.expect(moved.exists);
    const got = try fx.read(&moved);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("code\n", got);

    var gone: Resolved = .{};
    try fx.vfs.resolve("/usr/lib/python/mod.py", true, &gone);
    try testing.expect(!gone.exists);
    try testing.expect(try fx.lowerExists("/usr/lib/python/mod.py"));
}

test "paths cannot climb out of the root" {
    var fx: Fixture = undefined;
    try setup(&fx);
    defer fx.deinit();
    var r: Resolved = .{};
    try fx.vfs.resolve("/../../../../etc/passwd", true, &r);
    try testing.expectEqualStrings("/etc/passwd", r.guest.slice());
    try fx.vfs.resolve("/escape/etc/passwd", true, &r);
    try testing.expectEqualStrings("/etc/passwd", r.guest.slice());
    try testing.expect(std.mem.startsWith(u8, r.host.slice(), fx.base.slice()));
}

test "absolute symlinks resolve inside the container" {
    var fx: Fixture = undefined;
    try setup(&fx);
    defer fx.deinit();
    var r: Resolved = .{};
    try fx.vfs.resolve("/abs/passwd", true, &r);
    try testing.expect(r.exists);
    try testing.expectEqualStrings("/etc/passwd", r.guest.slice());
}

test "creating a file seals only its own directory" {
    var fx: Fixture = undefined;
    try setup(&fx);
    defer fx.deinit();
    var r: Resolved = .{};
    try fx.vfs.resolve("/etc/new", false, &r);
    try testing.expect(!r.exists);
    try fx.vfs.prepareCreate(&r);
    try sys.writeFile(r.host.slice(), "x", 0o644);

    var other: Resolved = .{};
    try fx.vfs.resolve("/usr/lib/python/mod.py", true, &other);
    try testing.expectEqual(Where.lower, other.where);
    var up = try Path.join(fx.upper.slice(), "/usr/lib/python");
    var st: sys.Stat = undefined;
    try testing.expectError(error.Sys, sys.lstat(up.z(), &st));
}
