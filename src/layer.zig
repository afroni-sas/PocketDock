//! Unpacks OCI layers into a flat root filesystem.
//!
//! The parser is hand-written because layers rely on hard links, device
//! nodes, whiteouts and PAX records that need precise handling here. Android
//! apps may not create hard links or device nodes, and every path has to stay
//! inside the root even when the archive plants symlinks.

const std = @import("std");
const sys = @import("sys.zig");
const vfs_mod = @import("vfs.zig");
const Path = sys.Path;
const Reader = std.Io.Reader;

const Pending = struct {
    name: Path = .{},
    has_name: bool = false,
    link: Path = .{},
    has_link: bool = false,
    size: ?u64 = null,
    mtime: ?i64 = null,
};

fn parseOctal(f: []const u8) u64 {
    if (f.len > 0 and f[0] & 0x80 != 0) {
        // GNU base-256, used for files over 8 GiB.
        var v: u64 = f[0] & 0x7f;
        for (f[1..]) |b| v = (v << 8) | b;
        return v;
    }
    var v: u64 = 0;
    for (f) |b| {
        if (b == 0 or b == ' ') {
            if (v != 0) break;
            continue;
        }
        if (b < '0' or b > '7') break;
        v = v * 8 + (b - '0');
    }
    return v;
}

fn fieldStr(f: []const u8) []const u8 {
    return std.mem.sliceTo(f, 0);
}

/// Normalises an archive path, rejecting anything that climbs out of the root.
fn cleanName(raw: []const u8, out: *Path) bool {
    out.len = 0;
    var it = std.mem.tokenizeScalar(u8, raw, '/');
    while (it.next()) |c| {
        if (std.mem.eql(u8, c, ".")) continue;
        if (std.mem.eql(u8, c, "..")) return false;
        out.append("/") catch return false;
        out.append(c) catch return false;
    }
    return true;
}

fn parsePax(data: []const u8, p: *Pending) void {
    var rest = data;
    while (rest.len > 0) {
        const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse return;
        const len = std.fmt.parseInt(usize, rest[0..sp], 10) catch return;
        if (len == 0 or len > rest.len or len <= sp + 1) return;
        const rec = rest[sp + 1 .. len - 1];
        rest = rest[len..];
        const eq = std.mem.indexOfScalar(u8, rec, '=') orelse continue;
        const key = rec[0..eq];
        const val = rec[eq + 1 ..];
        if (std.mem.eql(u8, key, "path")) {
            p.name.set(val) catch return;
            p.has_name = true;
        } else if (std.mem.eql(u8, key, "linkpath")) {
            p.link.set(val) catch return;
            p.has_link = true;
        } else if (std.mem.eql(u8, key, "size")) {
            p.size = std.fmt.parseInt(u64, val, 10) catch null;
        } else if (std.mem.eql(u8, key, "mtime")) {
            const dot = std.mem.indexOfScalar(u8, val, '.') orelse val.len;
            p.mtime = std.fmt.parseInt(i64, val[0..dot], 10) catch null;
        }
    }
}

const Extractor = struct {
    root: []const u8,
    gpa: std.mem.Allocator,
    vfs: vfs_mod.Vfs,
    cached_dir: Path = .{},
    cached_host: Path = .{},
    has_cache: bool = false,
    buf: [] u8,

    /// Resolves the parent directory inside the root, creating it if needed.
    /// Symlinks are followed in root terms, so `/etc -> /host` stays contained.
    fn parent(self: *Extractor, dir: []const u8) !*Path {
        if (self.has_cache and std.mem.eql(u8, self.cached_dir.slice(), dir)) return &self.cached_host;
        var r: vfs_mod.Resolved = .{};
        var g = try Path.of(if (dir.len == 0) "/" else dir);
        try self.vfs.resolve(g.slice(), true, &r);
        if (!r.exists) {
            try sys.mkdirP(r.host.slice(), 0o755);
        } else if (!sys.isDir(r.mode)) {
            return sys.fail(.NOTDIR);
        }
        try self.cached_dir.set(dir);
        try self.cached_host.set(r.host.slice());
        self.has_cache = true;
        return &self.cached_host;
    }

    fn invalidate(self: *Extractor) void {
        self.has_cache = false;
    }

    /// Removes whatever occupies `p` so that a new entry can take its place.
    fn clear(self: *Extractor, p: *Path) !void {
        var st: sys.Stat = undefined;
        sys.lstat(p.z(), &st) catch {
            if (sys.last == .NOENT) return;
            return error.Sys;
        };
        self.invalidate();
        if (sys.isDir(st.mode)) return sys.rmrf(p.slice());
        return sys.unlink(p.z());
    }

    fn writeFile(self: *Extractor, r: *Reader, dst: *Path, size: u64, mode: u32, mtime: i64) !void {
        const flags = sys.O_WRONLY | sys.O_CREAT | sys.O_EXCL | sys.O_NOFOLLOW;
        var perm = mode & 0o777;
        perm |= 0o600;
        const fd = sys.open(dst.z(), flags, perm) catch blk: {
            if (sys.last != .EXIST) return error.Sys;
            try self.clear(dst);
            break :blk try sys.open(dst.z(), flags, perm);
        };
        defer sys.close(fd);
        var left = size;
        while (left > 0) {
            const want: usize = @intCast(@min(left, self.buf.len));
            try r.readSliceAll(self.buf[0..want]);
            try sys.writeAll(fd, self.buf[0..want]);
            left -= want;
        }
        sys.utimes(fd, null, mtime, 0, 0) catch {};
    }

    fn apply(self: *Extractor, r: *Reader, typ: u8, name: *Path, link: []const u8, size: u64, mode: u32, mtime: i64) !void {
        const full = name.slice();
        const slash = std.mem.lastIndexOfScalar(u8, full, '/') orelse return;
        const dir = full[0..slash];
        const base = full[slash + 1 ..];

        if (std.mem.startsWith(u8, base, ".wh.")) {
            const parent_host = try self.parent(dir);
            if (std.mem.eql(u8, base, ".wh..wh..opq")) {
                var it = try sys.DirIter.open_(parent_host.z());
                defer it.deinit();
                while (try it.next()) |ent| {
                    var c = try Path.join(parent_host.slice(), "/");
                    try c.append(ent.name);
                    try sys.rmrf(c.slice());
                }
            } else {
                var c = try Path.join(parent_host.slice(), "/");
                try c.append(base[4..]);
                try sys.rmrf(c.slice());
            }
            self.invalidate();
            return;
        }

        const parent_host = try self.parent(dir);
        var dst = try Path.join(parent_host.slice(), "/");
        try dst.append(base);

        switch (typ) {
            0, '0', '7' => try self.writeFile(r, &dst, size, mode, mtime),
            '5' => {
                const perm = (mode & 0o7777) | 0o700;
                var st: sys.Stat = undefined;
                sys.lstat(dst.z(), &st) catch {
                    if (sys.last != .NOENT) return error.Sys;
                    try sys.mkdir(dst.z(), perm);
                    return;
                };
                if (sys.isDir(st.mode)) {
                    try sys.chmod(dst.z(), perm);
                } else {
                    try self.clear(&dst);
                    try sys.mkdir(dst.z(), perm);
                }
            },
            '2' => {
                try self.clear(&dst);
                var t = try Path.of(link);
                try sys.symlink(t.z(), dst.z());
                self.invalidate();
            },
            '1' => {
                var clean: Path = .{};
                if (!cleanName(link, &clean)) return;
                var src = try Path.join(self.root, clean.slice());
                try self.clear(&dst);
                const rc = sys.linux.linkat(sys.AT_FDCWD, src.z(), sys.AT_FDCWD, dst.z(), 0);
                if (sys.linux.errno(rc) != .SUCCESS) {
                    // Android's SELinux policy denies hard links to apps.
                    var st: sys.Stat = undefined;
                    try sys.lstat(src.z(), &st);
                    if (sys.isLnk(st.mode)) {
                        var tb: [sys.PATH_MAX]u8 = undefined;
                        const target = try sys.readlink(src.z(), tb[0 .. tb.len - 1]);
                        tb[target.len] = 0;
                        try sys.symlink(@ptrCast(&tb), dst.z());
                    } else {
                        try vfs_mod.Vfs.copyFile(src.z(), dst.z());
                    }
                }
            },
            '6' => {
                try self.clear(&dst);
                _ = sys.linux.mknodat(sys.AT_FDCWD, dst.z(), sys.S_IFIFO | (mode & 0o777) | 0o600, 0);
            },
            // Character and block devices cannot be created without root,
            // and the runtime supplies the /dev entries containers need.
            else => {},
        }
    }

    fn run(self: *Extractor, r: *Reader) !u64 {
        var block: [512]u8 = undefined;
        var pending: Pending = .{};
        var count: u64 = 0;
        var aux: std.ArrayList(u8) = .empty;
        defer aux.deinit(self.gpa);

        while (true) {
            const n = try r.readSliceShort(&block);
            if (n == 0) break;
            if (n < 512) return error.TruncatedLayer;
            if (std.mem.allEqual(u8, &block, 0)) break;

            const typ = block[156];
            var size = parseOctal(block[124..136]);
            const padding = (512 - size % 512) % 512;

            switch (typ) {
                'x', 'g', 'L', 'K' => {
                    aux.clearRetainingCapacity();
                    try aux.resize(self.gpa, @intCast(size));
                    try r.readSliceAll(aux.items);
                    try r.discardAll(@intCast(padding));
                    if (typ == 'x') {
                        parsePax(aux.items, &pending);
                    } else if (typ == 'L') {
                        try pending.name.set(fieldStr(aux.items));
                        pending.has_name = true;
                    } else if (typ == 'K') {
                        try pending.link.set(fieldStr(aux.items));
                        pending.has_link = true;
                    }
                    continue;
                },
                else => {},
            }

            var raw: Path = .{};
            if (pending.has_name) {
                try raw.set(pending.name.slice());
            } else {
                const prefix = fieldStr(block[345..500]);
                const is_ustar = std.mem.startsWith(u8, block[257..263], "ustar\x00");
                if (is_ustar and prefix.len > 0) {
                    try raw.set(prefix);
                    try raw.append("/");
                }
                try raw.append(fieldStr(block[0..100]));
            }
            const link = if (pending.has_link) pending.link.slice() else fieldStr(block[157..257]);
            if (pending.size) |s| size = s;
            const mtime: i64 = pending.mtime orelse @intCast(parseOctal(block[136..148]));
            const mode: u32 = @truncate(parseOctal(block[100..108]));
            const pad2 = (512 - size % 512) % 512;

            var name: Path = .{};
            const ok = cleanName(raw.slice(), &name);
            const has_data = typ == 0 or typ == '0' or typ == '7';
            if (ok and name.len > 0) {
                try self.apply(r, typ, &name, link, size, mode, mtime);
                count += 1;
            } else if (has_data) {
                try r.discardAll64(size);
            }
            if (has_data) {
                try r.discardAll(@intCast(pad2));
            } else if (size > 0) {
                try r.discardAll64(size + pad2);
            }
            pending = .{};
        }
        return count;
    }
};

/// Extracts one layer blob on top of `root`. Returns the number of entries.
pub fn extract(gpa: std.mem.Allocator, io: std.Io, blob: []const u8, root: []const u8) !u64 {
    const file = try std.Io.Dir.openFileAbsolute(io, blob, .{});
    defer file.close(io);

    const in_buf = try gpa.alloc(u8, 1 << 18);
    defer gpa.free(in_buf);
    var file_reader = file.readerStreaming(io, in_buf);
    const input = &file_reader.interface;

    const work = try gpa.alloc(u8, 1 << 18);
    defer gpa.free(work);

    var ex: Extractor = .{
        .root = root,
        .gpa = gpa,
        .buf = work,
        .vfs = .{ .lowers = &.{}, .upper = root, .work = root, .mounts = &.{}, .raw = true },
    };

    const magic = input.peek(4) catch |e| switch (e) {
        error.EndOfStream => return 0,
        else => return e,
    };

    if (magic[0] == 0x1f and magic[1] == 0x8b) {
        const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
        defer gpa.free(window);
        var d = std.compress.flate.Decompress.init(input, .gzip, window);
        return ex.run(&d.reader);
    }
    if (std.mem.eql(u8, magic, "\x28\xb5\x2f\xfd")) {
        const opts: std.compress.zstd.Decompress.Options = .{ .window_len = 1 << 25 };
        const window = try gpa.alloc(u8, opts.window_len + std.compress.zstd.block_size_max);
        defer gpa.free(window);
        var d = std.compress.zstd.Decompress.init(input, window, opts);
        return ex.run(&d.reader);
    }
    if (input.peek(6)) |head| {
        if (std.mem.eql(u8, head, "\xfd7zXZ\x00")) {
            const window = try gpa.alloc(u8, 1 << 18);
            var d = try std.compress.xz.Decompress.init(input, gpa, window);
            defer d.deinit();
            return ex.run(&d.reader);
        }
    } else |_| {}
    return ex.run(input);
}
