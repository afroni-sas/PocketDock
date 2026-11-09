//! `pdock build`: turns a Dockerfile into an image.
//!
//! Every RUN, COPY and ADD runs in a hidden container on top of the layers
//! built so far, and its writable layer becomes the next layer. A layer's id
//! is a hash of everything that led to it, so a step whose inputs have not
//! changed finds its result already on disk and is skipped.

const std = @import("std");
const sys = @import("sys.zig");
const dockerfile = @import("dockerfile.zig");
const registry = @import("registry.zig");
const container = @import("container.zig");
const layer_mod = @import("layer.zig");
const vfs_mod = @import("vfs.zig");
const Store = @import("store.zig").Store;
const Allocator = std.mem.Allocator;
const Path = sys.Path;
const Vfs = vfs_mod.Vfs;
const Resolved = vfs_mod.Resolved;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Options = struct {
    context: []const u8,
    file: ?[]const u8 = null,
    tag: ?[]const u8 = null,
    build_args: []const []const u8 = &.{},
    no_cache: bool = false,
};

const Stage = struct {
    name: ?[]const u8,
    /// The stage's image, holding its configuration.
    id: []const u8,
    /// The top of its layers.
    layer: []const u8,
};

/// The stage being built.
const Current = struct {
    base: []const u8,
    key: [64]u8 = @splat('0'),
    name: ?[]const u8,
    env: std.ArrayList([]const u8) = .empty,
    args: std.ArrayList([]const u8) = .empty,
    cmd: []const []const u8 = &.{},
    cmd_set: bool = false,
    entrypoint: []const []const u8 = &.{},
    workdir: []const u8 = "/",
    user: []const u8 = "",
    shell: []const []const u8 = &.{ "/bin/sh", "-c" },
    ports: std.ArrayList([]const u8) = .empty,
    labels: std.ArrayList([]const u8) = .empty,
    volumes: std.ArrayList([]const u8) = .empty,
    stop_signal: []const u8 = "",
    /// The `Healthcheck` object, as JSON.
    health: ?[]const u8 = null,
    onbuild: std.ArrayList([]const u8) = .empty,
    /// WORKDIRs not yet created; they go in the next layer that gets built.
    pending_dirs: std.ArrayList([]const u8) = .empty,
};

/// A step running in its hidden container.
const Layer = struct { cfg: container.Config, vfs: *Vfs };

const Source = union(enum) {
    /// A file downloaded for ADD, and the name it should have.
    url: struct { path: []const u8, name: []const u8 },
    path: struct { guest: []const u8, archive: bool },
};

fn fail(comptime f: []const u8, a: anytype) error{BuildFailed} {
    sys.eprint("error: " ++ f ++ "\n", a);
    return error.BuildFailed;
}

fn dirnameOf(path: []const u8) []const u8 {
    const i = std.mem.lastIndexOfScalar(u8, path, '/') orelse return "/";
    return if (i == 0) "/" else path[0..i];
}

fn basenameOf(path: []const u8) []const u8 {
    const trimmed = std.mem.trimEnd(u8, path, "/");
    const i = std.mem.lastIndexOfScalar(u8, trimmed, '/') orelse return trimmed;
    return trimmed[i + 1 ..];
}

fn isUrl(s: []const u8) bool {
    return std.mem.startsWith(u8, s, "http://") or std.mem.startsWith(u8, s, "https://");
}

/// The file name a URL points at, without its query string.
fn urlName(url: []const u8) []const u8 {
    const end = std.mem.indexOfAny(u8, url, "?#") orelse url.len;
    return basenameOf(url[0..end]);
}

fn hashFile(h: *Sha256, host: [*:0]const u8) sys.Err!void {
    const fd = try sys.open(host, 0, 0);
    defer sys.close(fd);
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = try sys.read(fd, &buf);
        if (n == 0) return;
        h.update(buf[0..n]);
    }
}

const archive_names = [_][]const u8{ ".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.zst", ".tzst" };

/// Whether ADD should unpack this file: the name says tar, and the contents
/// start the way that compression format does.
fn isArchive(name: []const u8, host: [*:0]const u8) bool {
    var named = false;
    for (archive_names) |ext| named = named or std.mem.endsWith(u8, name, ext);
    if (!named) return false;
    const fd = sys.open(host, 0, 0) catch return false;
    defer sys.close(fd);
    var b: [512]u8 = undefined;
    const n = sys.readFull(fd, &b) catch return false;
    if (n >= 2 and b[0] == 0x1f and b[1] == 0x8b) return true;
    if (n >= 4 and std.mem.eql(u8, b[0..4], "\x28\xb5\x2f\xfd")) return true;
    if (n >= 6 and std.mem.eql(u8, b[0..6], "\xfd7zXZ\x00")) return true;
    return n >= 263 and std.mem.eql(u8, b[257..262], "ustar");
}

const Builder = struct {
    a: Allocator,
    gpa: Allocator,
    io: std.Io,
    store: Store,
    mgr: *container.Manager,
    opts: Options,
    context: Vfs,
    ignore: []const []const u8 = &.{},
    global_args: std.ArrayList([]const u8) = .empty,
    stages: std.ArrayList(Stage) = .empty,
    cur: ?Current = null,
    /// The hidden container of the step in progress.
    active: ?[]const u8 = null,
    tmp: ?[]const u8 = null,
    tmp_seq: u32 = 0,

    fn vars(self: *Builder) ![]const []const u8 {
        const c = &self.cur.?;
        return std.mem.concat(self.a, []const u8, &.{ c.args.items, c.env.items });
    }

    fn expanded(self: *Builder, s: []const u8) ![]const u8 {
        return dockerfile.expand(self.a, s, try self.vars());
    }

    fn buildArg(self: *Builder, name: []const u8) ?[]const u8 {
        for (self.opts.build_args) |arg| {
            if (arg.len > name.len and arg[name.len] == '=' and std.mem.startsWith(u8, arg, name)) return arg[name.len + 1 ..];
        }
        return null;
    }

    /// Resolves `NAME[=default]` to `NAME=value`, or null if it has no value.
    fn argValue(self: *Builder, spec: []const u8, inherited: []const []const u8) !?[]const u8 {
        const eq = std.mem.indexOfScalar(u8, spec, '=');
        const name = if (eq) |i| spec[0..i] else spec;
        if (self.buildArg(name)) |v| return try std.fmt.allocPrint(self.a, "{s}={s}", .{ name, v });
        if (eq != null) return spec;
        var i = inherited.len;
        while (i > 0) {
            i -= 1;
            if (inherited[i].len > name.len and inherited[i][name.len] == '=' and std.mem.startsWith(u8, inherited[i], name)) return inherited[i];
        }
        return null;
    }

    /// Mixes `parts` into the current step's identity.
    fn roll(self: *Builder, parts: []const []const u8) void {
        const c = &self.cur.?;
        var h = Sha256.init(.{});
        h.update(&c.key);
        for (parts) |p| {
            h.update(std.mem.asBytes(&p.len));
            h.update(p);
        }
        var digest: [32]u8 = undefined;
        h.final(&digest);
        _ = std.fmt.bufPrint(&c.key, "{x}", .{&digest}) catch unreachable;
    }

    fn cached(self: *Builder) bool {
        if (self.opts.no_cache) return false;
        var p = Path.of(self.store.path(&.{ "images", &self.cur.?.key, "rootfs" })) catch return false;
        return sys.exists(p.z());
    }

    fn useCached(self: *Builder) !void {
        const c = &self.cur.?;
        c.base = try self.a.dupe(u8, &c.key);
        c.pending_dirs.clearRetainingCapacity();
        sys.print(" ---> cached\n", .{});
    }

    fn beginLayer(self: *Builder) !Layer {
        const c = &self.cur.?;
        var id_buf: [8]u8 = undefined;
        sys.randomId(&id_buf);
        const cfg = try self.mgr.create(.{
            .image_id = c.base,
            .image = "build",
            .name = try std.fmt.allocPrint(self.a, "pdock-build-{s}", .{id_buf}),
            .command = &.{"/bin/true"},
            .builder = true,
        });
        self.active = cfg.id;
        const vfs = try self.mgr.makeVfs(&cfg);
        for (c.pending_dirs.items) |d| try vfs.ensureDir(d);
        c.pending_dirs.clearRetainingCapacity();
        return .{ .cfg = cfg, .vfs = vfs };
    }

    fn endLayer(self: *Builder, l: *Layer) !void {
        const c = &self.cur.?;
        const id = try self.a.dupe(u8, &c.key);
        try self.mgr.commitLayer(&l.cfg, id);
        self.active = null;
        c.base = id;
    }

    fn tmpPath(self: *Builder, name: []const u8) ![]const u8 {
        if (self.tmp == null) {
            var id_buf: [8]u8 = undefined;
            sys.randomId(&id_buf);
            const dir = self.store.path(&.{try std.fmt.allocPrint(self.a, "build-{s}", .{id_buf})});
            try sys.mkdirP(dir, 0o700);
            self.tmp = dir;
        }
        self.tmp_seq += 1;
        return std.fmt.allocPrint(self.a, "{s}/{d}-{s}", .{ self.tmp.?, self.tmp_seq, name });
    }

    /// Reads the image's settings. Returns its ONBUILD triggers.
    fn loadBaseConfig(self: *Builder, id: []const u8, c: *Current) ![]const []const u8 {
        const a = self.a;
        const raw = try sys.readFileAlloc(a, self.store.path(&.{ "images", id, "config.json" }), 1 << 22);
        const doc = try std.json.parseFromSliceLeaky(std.json.Value, a, raw, .{});
        const cfg = doc.object.get("config") orelse return &.{};
        if (cfg != .object) return &.{};
        for (try container.stringArray(a, cfg.object.get("Env"))) |e| try container.setEnv(a, &c.env, e);
        c.cmd = try container.stringArray(a, cfg.object.get("Cmd"));
        c.entrypoint = try container.stringArray(a, cfg.object.get("Entrypoint"));
        if (cfg.object.get("WorkingDir")) |w| {
            if (w == .string and w.string.len > 0) c.workdir = w.string;
        }
        if (cfg.object.get("User")) |u| {
            if (u == .string) c.user = u.string;
        }
        if (cfg.object.get("StopSignal")) |s| {
            if (s == .string) c.stop_signal = s.string;
        }
        if (cfg.object.get("ExposedPorts")) |p| {
            if (p == .object) for (p.object.keys()) |k| try c.ports.append(a, k);
        }
        if (cfg.object.get("Volumes")) |v| {
            if (v == .object) for (v.object.keys()) |k| try c.volumes.append(a, k);
        }
        if (cfg.object.get("Healthcheck")) |h| {
            if (h == .object) c.health = try std.json.Stringify.valueAlloc(a, h, .{});
        }
        if (cfg.object.get("Labels")) |l| {
            if (l == .object) {
                var it = l.object.iterator();
                while (it.next()) |kv| {
                    if (kv.value_ptr.* == .string) {
                        try c.labels.append(a, try std.fmt.allocPrint(a, "{s}={s}", .{ kv.key_ptr.*, kv.value_ptr.string }));
                    }
                }
            }
        }
        return container.stringArray(a, cfg.object.get("OnBuild"));
    }

    fn findStage(self: *Builder, name: []const u8) ?Stage {
        for (self.stages.items) |s| {
            if (s.name) |n| {
                if (std.mem.eql(u8, n, name)) return s;
            }
        }
        const index = std.fmt.parseInt(usize, name, 10) catch return null;
        return if (index < self.stages.items.len) self.stages.items[index] else null;
    }

    /// Returns the ONBUILD triggers of the base image.
    fn beginStage(self: *Builder, rest: []const u8) ![]const []const u8 {
        var words = std.ArrayList([]const u8).empty;
        for (try dockerfile.splitWords(self.a, rest)) |w| {
            if (!std.mem.startsWith(u8, w, "--")) try words.append(self.a, w);
        }
        if (words.items.len == 0) return fail("FROM needs an image", .{});
        const image = try dockerfile.expand(self.a, words.items[0], self.global_args.items);
        var name: ?[]const u8 = null;
        if (words.items.len >= 3 and std.ascii.eqlIgnoreCase(words.items[1], "as")) name = words.items[2];

        var config_id: []const u8 = undefined;
        var base: []const u8 = undefined;
        if (self.findStage(image)) |s| {
            config_id = s.id;
            base = s.layer;
        } else if (std.mem.eql(u8, image, "scratch")) {
            config_id = try self.mgr.emptyImage();
            base = config_id;
        } else {
            config_id = try registry.pull(self.a, self.gpa, self.io, self.store, image, false);
            base = config_id;
        }

        var c: Current = .{ .base = base, .name = name };
        const triggers = try self.loadBaseConfig(config_id, &c);
        self.cur = c;
        self.roll(&.{ "FROM", config_id });
        if (self.opts.no_cache) {
            var nonce: [16]u8 = undefined;
            sys.randomId(&nonce);
            self.roll(&.{&nonce});
        }
        return triggers;
    }

    fn finishStage(self: *Builder) !void {
        const c = &(self.cur orelse return);
        const a = self.a;
        if (c.pending_dirs.items.len > 0) {
            self.roll(&.{"WORKDIRS"});
            if (self.cached()) {
                try self.useCached();
            } else {
                var l = try self.beginLayer();
                try self.endLayer(&l);
            }
        }

        var out: std.ArrayList(u8) = .empty;
        const str = struct {
            fn f(al: Allocator, s: []const u8) ![]const u8 {
                return std.json.Stringify.valueAlloc(al, s, .{});
            }
        }.f;
        const list = struct {
            fn f(al: Allocator, items: []const []const u8) ![]const u8 {
                return std.json.Stringify.valueAlloc(al, items, .{});
            }
        }.f;
        const keys = struct {
            fn f(al: Allocator, o: *std.ArrayList(u8), items: []const []const u8) !void {
                for (items, 0..) |k, i| {
                    if (i > 0) try o.append(al, ',');
                    try o.print(al, "{s}:{{}}", .{try str(al, k)});
                }
            }
        }.f;
        try out.print(a, "{{\"config\":{{\"Env\":{s},\"Cmd\":{s},\"Entrypoint\":{s},\"WorkingDir\":{s},\"User\":{s},\"StopSignal\":{s},\"OnBuild\":{s},\"ExposedPorts\":{{", .{
            try list(a, c.env.items),
            try list(a, c.cmd),
            try list(a, c.entrypoint),
            try str(a, c.workdir),
            try str(a, c.user),
            try str(a, c.stop_signal),
            try list(a, c.onbuild.items),
        });
        try keys(a, &out, c.ports.items);
        try out.appendSlice(a, "},\"Volumes\":{");
        try keys(a, &out, c.volumes.items);
        try out.appendSlice(a, "},\"Labels\":{");
        for (c.labels.items, 0..) |l, i| {
            if (i > 0) try out.append(a, ',');
            const eq = std.mem.indexOfScalar(u8, l, '=') orelse l.len;
            try out.print(a, "{s}:{s}", .{ try str(a, l[0..eq]), try str(a, if (eq < l.len) l[eq + 1 ..] else "") });
        }
        try out.append(a, '}');
        if (c.health) |h| try out.print(a, ",\"Healthcheck\":{s}", .{h});
        try out.appendSlice(a, "}}");

        const id = try self.mgr.commitImage(c.base, out.items);
        try self.stages.append(a, .{ .name = c.name, .id = id, .layer = c.base });
        self.cur = null;
    }

    fn doRun(self: *Builder, instr: dockerfile.Instr) !void {
        const c = &self.cur.?;
        const a = self.a;
        var argv: []const []const u8 = undefined;
        if (instr.heredoc) |body| {
            argv = try std.mem.concat(a, []const u8, &.{ c.shell, &.{body} });
        } else if (dockerfile.execForm(a, instr.rest)) |exec| {
            argv = exec;
        } else {
            argv = try std.mem.concat(a, []const u8, &.{ c.shell, &.{instr.rest} });
        }
        if (argv.len == 0) return fail("line {d}: RUN needs a command", .{instr.line});

        self.roll(&.{
            "RUN",
            try std.mem.join(a, "\x00", argv),
            try std.mem.join(a, "\x00", try self.vars()),
            c.workdir,
            c.user,
        });
        if (self.cached()) return self.useCached();

        var l = try self.beginLayer();
        var env: std.ArrayList([]const u8) = .empty;
        for ([_][]const []const u8{ l.cfg.env, c.args.items, c.env.items }) |group| {
            for (group) |e| try container.setEnv(a, &env, e);
        }
        var uid: u32 = 0;
        var gid: u32 = 0;
        if (c.user.len > 0) {
            const u = try self.mgr.resolveUser(l.vfs, c.user);
            uid = u.uid;
            gid = u.gid;
            try container.setEnv(a, &env, try std.fmt.allocPrint(a, "HOME={s}", .{u.home}));
        }
        const code = try self.mgr.runBuildStep(&l.cfg, .{
            .argv = argv,
            .env = env.items,
            .workdir = c.workdir,
            .uid = uid,
            .gid = gid,
        });
        if (code != 0) return fail("line {d}: the command returned {d}", .{ instr.line, code });
        try self.endLayer(&l);
    }

    fn absolute(self: *Builder, path: []const u8) ![]const u8 {
        if (path.len > 0 and path[0] == '/') return path;
        return std.fmt.allocPrint(self.a, "{s}/{s}", .{ std.mem.trimEnd(u8, self.cur.?.workdir, "/"), path });
    }

    /// Puts one file or symlink at a guest path, replacing what is there.
    fn putEntry(self: *Builder, dst: *Vfs, src_host: *Path, src_mode: u32, dst_path: []const u8) !void {
        _ = self;
        try dst.ensureDir(dirnameOf(dst_path));
        var d: Resolved = .{};
        try dst.resolve(dst_path, false, &d);
        if (d.exists) {
            if (sys.isDir(d.mode)) return fail("cannot replace the directory {s} with a file", .{dst_path});
            try dst.prepareRemove(&d);
            try sys.unlink(d.host.z());
            try dst.resolve(dst_path, false, &d);
        }
        try dst.prepareCreate(&d);
        if (sys.isLnk(src_mode)) {
            var buf: [sys.PATH_MAX]u8 = undefined;
            const target = try sys.readlink(src_host.z(), buf[0 .. buf.len - 1]);
            buf[target.len] = 0;
            try sys.symlink(@ptrCast(&buf), d.host.z());
        } else {
            try Vfs.copyFile(src_host.z(), d.host.z());
        }
    }

    fn copyTree(self: *Builder, dst: *Vfs, source: *Vfs, src_path: []const u8, dst_path: []const u8, filtered: bool) !void {
        var r: Resolved = .{};
        try source.resolve(src_path, false, &r);
        try dst.ensureDir(dst_path);
        var it = try sys.DirIter.open_(r.host.z());
        defer it.deinit();
        while (try it.next()) |ent| {
            const child_src = try std.fmt.allocPrint(self.a, "{s}/{s}", .{ std.mem.trimEnd(u8, src_path, "/"), ent.name });
            const child_dst = try std.fmt.allocPrint(self.a, "{s}/{s}", .{ std.mem.trimEnd(u8, dst_path, "/"), ent.name });
            if (filtered and dockerfile.isIgnored(self.ignore, child_src[1..])) continue;
            var cr: Resolved = .{};
            try source.resolve(child_src, false, &cr);
            if (!cr.exists) continue;
            if (sys.isDir(cr.mode)) {
                try self.copyTree(dst, source, child_src, child_dst, filtered);
            } else {
                try self.putEntry(dst, &cr.host, cr.mode, child_dst);
            }
        }
    }

    /// The paths in `source` that a COPY source names, expanding a wildcard.
    fn matchSources(self: *Builder, source: *Vfs, pattern: []const u8) ![]const []const u8 {
        const a = self.a;
        var out: std.ArrayList([]const u8) = .empty;
        const clean = try std.fmt.allocPrint(a, "/{s}", .{std.mem.trimStart(u8, pattern, "/")});
        if (!dockerfile.hasGlob(clean)) {
            try out.append(a, clean);
            return out.items;
        }
        const dir = dirnameOf(clean);
        const pat = basenameOf(clean);
        var r: Resolved = .{};
        try source.resolve(dir, true, &r);
        if (!r.exists or !sys.isDir(r.mode)) return out.items;
        var it = try sys.DirIter.open_(r.host.z());
        defer it.deinit();
        while (try it.next()) |ent| {
            if (dockerfile.globMatch(pat, ent.name)) {
                try out.append(a, try std.fmt.allocPrint(a, "{s}/{s}", .{ std.mem.trimEnd(u8, dir, "/"), ent.name }));
            }
        }
        std.mem.sort([]const u8, out.items, {}, struct {
            fn lt(_: void, x: []const u8, y: []const u8) bool {
                return std.mem.lessThan(u8, x, y);
            }
        }.lt);
        return out.items;
    }

    /// Hashes names, permissions and contents, but not timestamps: a fresh
    /// checkout of the same code must still hit the cache.
    fn hashSource(self: *Builder, h: *Sha256, source: *Vfs, guest: []const u8, filtered: bool) !void {
        const a = self.a;
        var r: Resolved = .{};
        try source.resolve(guest, false, &r);
        if (!r.exists) return;
        const perm: u32 = r.mode & (sys.S_IFMT | 0o777);
        h.update(guest);
        h.update(std.mem.asBytes(&perm));
        if (sys.isLnk(r.mode)) {
            var buf: [sys.PATH_MAX]u8 = undefined;
            h.update(try sys.readlink(r.host.z(), &buf));
        } else if (sys.isDir(r.mode)) {
            var names: std.ArrayList([]const u8) = .empty;
            {
                var it = try sys.DirIter.open_(r.host.z());
                defer it.deinit();
                while (try it.next()) |ent| {
                    const child = try std.fmt.allocPrint(a, "{s}/{s}", .{ std.mem.trimEnd(u8, guest, "/"), ent.name });
                    if (filtered and dockerfile.isIgnored(self.ignore, child[1..])) continue;
                    try names.append(a, child);
                }
            }
            std.mem.sort([]const u8, names.items, {}, struct {
                fn lt(_: void, x: []const u8, y: []const u8) bool {
                    return std.mem.lessThan(u8, x, y);
                }
            }.lt);
            for (names.items) |n| try self.hashSource(h, source, n, filtered);
        } else if (sys.isReg(r.mode)) {
            try hashFile(h, r.host.z());
        }
    }

    fn doCopy(self: *Builder, instr: dockerfile.Instr, is_add: bool) !void {
        const a = self.a;
        const text = try self.expanded(instr.rest);
        var from: ?[]const u8 = null;
        var checksum: ?[]const u8 = null;
        // Flags come first, before a possible JSON list of paths.
        var rest = text;
        while (std.mem.startsWith(u8, rest, "--")) {
            const sp = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
            const flag = rest[0..sp];
            if (std.mem.startsWith(u8, flag, "--from=")) from = flag["--from=".len..];
            if (std.mem.startsWith(u8, flag, "--checksum=")) checksum = flag["--checksum=".len..];
            rest = std.mem.trimStart(u8, rest[sp..], " \t");
        }
        var words: std.ArrayList([]const u8) = .empty;
        if (dockerfile.execForm(a, rest)) |list| {
            try words.appendSlice(a, list);
        } else {
            try words.appendSlice(a, try dockerfile.splitWords(a, rest));
        }
        if (words.items.len < 2) return fail("line {d}: {s} needs a source and a destination", .{ instr.line, instr.op });

        const dest_raw = words.items[words.items.len - 1];
        const dest = try self.absolute(dest_raw);
        const srcs = words.items[0 .. words.items.len - 1];

        var source: *Vfs = &self.context;
        var source_id: []const u8 = "context";
        if (from) |f| {
            source_id = blk: {
                if (self.findStage(f)) |s| break :blk s.layer;
                break :blk try registry.pull(a, self.gpa, self.io, self.store, f, false);
            };
            source = try self.mgr.imageVfs(source_id);
        }
        const filtered = from == null;

        var items: std.ArrayList(Source) = .empty;
        var h = Sha256.init(.{});
        for (srcs) |src| {
            if (is_add and isUrl(src)) {
                if (from != null) return fail("line {d}: ADD cannot combine --from with a URL", .{instr.line});
                const name = urlName(src);
                if (name.len == 0) return fail("line {d}: cannot tell a file name from {s}", .{ instr.line, src });
                const path = try self.tmpPath(name);
                registry.downloadUrl(self.gpa, self.io, src, path) catch |e| {
                    return fail("line {d}: could not download {s}: {s}", .{ instr.line, src, @errorName(e) });
                };
                var p = try Path.of(path);
                h.update(src);
                try hashFile(&h, p.z());
                if (checksum) |want| {
                    var one = Sha256.init(.{});
                    try hashFile(&one, p.z());
                    var digest: [32]u8 = undefined;
                    one.final(&digest);
                    const got = try std.fmt.allocPrint(a, "sha256:{x}", .{&digest});
                    if (!std.mem.eql(u8, got, want)) return fail("line {d}: checksum mismatch for {s}: got {s}", .{ instr.line, src, got });
                }
                try items.append(a, .{ .url = .{ .path = path, .name = name } });
                continue;
            }
            if (!is_add and isUrl(src)) return fail("line {d}: COPY does not take URLs; use ADD", .{instr.line});

            const matches = try self.matchSources(source, src);
            if (matches.len == 0) return fail("line {d}: nothing matches {s}", .{ instr.line, src });
            for (matches) |m| {
                if (filtered and m.len > 1 and dockerfile.isIgnored(self.ignore, m[1..])) continue;
                var r: Resolved = .{};
                try source.resolve(m, true, &r);
                if (!r.exists) return fail("line {d}: {s} not found", .{ instr.line, src });
                if (filtered) try self.hashSource(&h, source, r.guest.slice(), filtered);
                const archive = is_add and filtered and sys.isReg(r.mode) and isArchive(m, r.host.z());
                try items.append(a, .{ .path = .{ .guest = m, .archive = archive } });
            }
        }

        var digest: [32]u8 = undefined;
        h.final(&digest);
        self.roll(&.{ instr.op, source_id, try std.mem.join(a, "\x00", srcs), dest, &digest });
        if (self.cached()) return self.useCached();

        var l = try self.beginLayer();
        var dest_is_dir = std.mem.endsWith(u8, dest_raw, "/") or items.items.len > 1;
        var existing: Resolved = .{};
        try l.vfs.resolve(dest, true, &existing);
        if (existing.exists and sys.isDir(existing.mode)) dest_is_dir = true;

        for (items.items) |item| {
            switch (item) {
                .url => |u| {
                    var p = try Path.of(u.path);
                    const target = if (dest_is_dir)
                        try std.fmt.allocPrint(a, "{s}/{s}", .{ std.mem.trimEnd(u8, dest, "/"), u.name })
                    else
                        dest;
                    try self.putEntry(l.vfs, &p, sys.S_IFREG | 0o600, target);
                },
                .path => |m| {
                    var r: Resolved = .{};
                    try source.resolve(m.guest, true, &r);
                    if (m.archive) {
                        const out_dir = try self.tmpPath("unpacked");
                        try sys.mkdirP(out_dir, 0o700);
                        _ = layer_mod.extract(self.gpa, self.io, r.host.slice(), out_dir) catch |e| {
                            return fail("line {d}: could not unpack {s}: {s}", .{ instr.line, m.guest, @errorName(e) });
                        };
                        var unpacked: Vfs = .{ .lowers = &.{}, .upper = out_dir, .work = "", .mounts = &.{}, .raw = true };
                        try self.copyTree(l.vfs, &unpacked, "/", dest, false);
                    } else if (sys.isDir(r.mode)) {
                        try self.copyTree(l.vfs, source, r.guest.slice(), dest, filtered);
                    } else if (dest_is_dir) {
                        const target = try std.fmt.allocPrint(a, "{s}/{s}", .{ std.mem.trimEnd(u8, dest, "/"), basenameOf(m.guest) });
                        try self.putEntry(l.vfs, &r.host, r.mode, target);
                    } else {
                        try self.putEntry(l.vfs, &r.host, r.mode, dest);
                    }
                },
            }
        }
        try self.endLayer(&l);
    }

    fn doHealthcheck(self: *Builder, instr: dockerfile.Instr) !void {
        const a = self.a;
        const c = &self.cur.?;
        var rest = instr.rest;
        if (std.ascii.eqlIgnoreCase(rest, "NONE")) {
            c.health = "{\"Test\":[\"NONE\"]}";
            return;
        }
        var interval: u64 = 0;
        var timeout: u64 = 0;
        var start: u64 = 0;
        var retries: u32 = 0;
        while (std.mem.startsWith(u8, rest, "--")) {
            const sp = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
            const flag = rest[2..sp];
            rest = std.mem.trimStart(u8, rest[sp..], " \t");
            const eq = std.mem.indexOfScalar(u8, flag, '=') orelse return fail("line {d}: bad HEALTHCHECK option {s}", .{ instr.line, flag });
            const key = flag[0..eq];
            const value = flag[eq + 1 ..];
            if (std.mem.eql(u8, key, "retries")) {
                retries = std.fmt.parseInt(u32, value, 10) catch return fail("line {d}: bad retries {s}", .{ instr.line, value });
                continue;
            }
            const ms = dockerfile.parseDuration(value) orelse return fail("line {d}: bad duration {s}", .{ instr.line, value });
            if (std.mem.eql(u8, key, "interval")) {
                interval = ms;
            } else if (std.mem.eql(u8, key, "timeout")) {
                timeout = ms;
            } else if (std.mem.eql(u8, key, "start-period")) {
                start = ms;
            }
        }
        if (rest.len < 3 or !std.ascii.eqlIgnoreCase(rest[0..3], "CMD")) return fail("line {d}: HEALTHCHECK needs CMD or NONE", .{instr.line});
        const command = std.mem.trim(u8, rest[3..], " \t");

        var test_cmd: std.ArrayList([]const u8) = .empty;
        if (dockerfile.execForm(a, command)) |exec| {
            try test_cmd.append(a, "CMD");
            try test_cmd.appendSlice(a, exec);
        } else {
            try test_cmd.append(a, "CMD-SHELL");
            try test_cmd.append(a, command);
        }
        c.health = try std.fmt.allocPrint(a, "{{\"Test\":{s},\"Interval\":{d},\"Timeout\":{d},\"StartPeriod\":{d},\"Retries\":{d}}}", .{
            try std.json.Stringify.valueAlloc(a, test_cmd.items, .{}),
            interval * std.time.ns_per_ms,
            timeout * std.time.ns_per_ms,
            start * std.time.ns_per_ms,
            retries,
        });
    }

    fn execute(self: *Builder, instr: dockerfile.Instr) !void {
        const a = self.a;
        const op = instr.op;
        const eql = std.mem.eql;
        if (self.cur == null) return fail("line {d}: {s} comes before FROM", .{ instr.line, op });
        const c = &self.cur.?;

        if (eql(u8, op, "RUN")) return self.doRun(instr);
        if (eql(u8, op, "COPY")) return self.doCopy(instr, false);
        if (eql(u8, op, "ADD")) return self.doCopy(instr, true);

        // Everything else only changes settings, which feed the next step.
        if (eql(u8, op, "ENV")) {
            const expanded_text = try self.expanded(instr.rest);
            self.roll(&.{ op, expanded_text });
            for (try dockerfile.keyValues(a, expanded_text)) |kv| try container.setEnv(a, &c.env, kv);
        } else if (eql(u8, op, "ARG")) {
            for (try dockerfile.splitWords(a, instr.rest)) |spec| {
                if (try self.argValue(spec, self.global_args.items)) |v| {
                    try container.setEnv(a, &c.args, v);
                    self.roll(&.{ op, v });
                }
            }
        } else if (eql(u8, op, "LABEL")) {
            for (try dockerfile.keyValues(a, try self.expanded(instr.rest))) |kv| try container.setEnv(a, &c.labels, kv);
        } else if (eql(u8, op, "WORKDIR")) {
            c.workdir = try self.absolute(try self.expanded(instr.rest));
            try c.pending_dirs.append(a, c.workdir);
            self.roll(&.{ op, c.workdir });
        } else if (eql(u8, op, "USER")) {
            c.user = try self.expanded(instr.rest);
            self.roll(&.{ op, c.user });
        } else if (eql(u8, op, "EXPOSE")) {
            for (try dockerfile.splitWords(a, try self.expanded(instr.rest))) |p| {
                try c.ports.append(a, if (std.mem.indexOfScalar(u8, p, '/') == null) try std.fmt.allocPrint(a, "{s}/tcp", .{p}) else p);
            }
        } else if (eql(u8, op, "CMD")) {
            c.cmd = dockerfile.execForm(a, instr.rest) orelse try std.mem.concat(a, []const u8, &.{ c.shell, &.{instr.rest} });
            c.cmd_set = true;
        } else if (eql(u8, op, "ENTRYPOINT")) {
            c.entrypoint = dockerfile.execForm(a, instr.rest) orelse try std.mem.concat(a, []const u8, &.{ c.shell, &.{instr.rest} });
            // An inherited CMD was written for the previous entrypoint.
            if (!c.cmd_set) c.cmd = &.{};
        } else if (eql(u8, op, "SHELL")) {
            c.shell = dockerfile.execForm(a, instr.rest) orelse return fail("line {d}: SHELL needs a JSON list", .{instr.line});
            self.roll(&.{ op, instr.rest });
        } else if (eql(u8, op, "VOLUME")) {
            const text = try self.expanded(instr.rest);
            const paths = dockerfile.execForm(a, text) orelse try dockerfile.splitWords(a, text);
            for (paths) |p| try c.volumes.append(a, p);
        } else if (eql(u8, op, "STOPSIGNAL")) {
            c.stop_signal = try self.expanded(instr.rest);
        } else if (eql(u8, op, "HEALTHCHECK")) {
            try self.doHealthcheck(instr);
        } else if (eql(u8, op, "ONBUILD")) {
            try c.onbuild.append(a, instr.rest);
        } else if (eql(u8, op, "MAINTAINER")) {
            try container.setEnv(a, &c.labels, try std.fmt.allocPrint(a, "maintainer={s}", .{instr.rest}));
        } else {
            return fail("line {d}: unknown instruction {s}", .{ instr.line, op });
        }
    }

    /// Removes what a build leaves behind. Finished layers stay: they are
    /// the cache, so a failed build resumes from its last good step.
    fn cleanup(self: *Builder, final: ?[]const u8) void {
        if (self.active) |id| self.mgr.discardBuild(id);
        if (self.tmp) |t| sys.rmrf(t) catch {};
        for (self.stages.items) |s| {
            if (final != null and std.mem.eql(u8, s.id, final.?)) continue;
            sys.rmrf(self.store.path(&.{ "images", s.id })) catch {};
        }
    }
};

/// Builds the image and returns its id.
pub fn build(a: Allocator, gpa: Allocator, io: std.Io, store: Store, mgr: *container.Manager, opts: Options) ![]const u8 {
    var cwd_buf: [sys.PATH_MAX]u8 = undefined;
    const n = try sys.ck(sys.linux.getcwd(&cwd_buf, cwd_buf.len));
    const cwd = cwd_buf[0 .. n - 1];
    const trimmed = std.mem.trimEnd(u8, opts.context, "/");
    const context = if (opts.context.len > 0 and opts.context[0] == '/')
        (if (trimmed.len == 0) "/" else trimmed)
    else if (std.mem.eql(u8, trimmed, "."))
        try a.dupe(u8, cwd)
    else
        try std.fmt.allocPrint(a, "{s}/{s}", .{ cwd, trimmed });

    const file = opts.file orelse try std.fmt.allocPrint(a, "{s}/Dockerfile", .{context});
    const text = sys.readFileAlloc(a, file, 1 << 22) catch return fail("cannot read {s}", .{file});
    const instrs = try dockerfile.parse(a, text);
    if (instrs.len == 0) return fail("{s} is empty", .{file});

    var b: Builder = .{
        .a = a,
        .gpa = gpa,
        .io = io,
        .store = store,
        .mgr = mgr,
        .opts = opts,
        .context = .{ .lowers = &.{}, .upper = context, .work = "", .mounts = &.{}, .raw = true },
    };
    if (sys.readFileAlloc(a, try std.fmt.allocPrint(a, "{s}/.dockerignore", .{context}), 1 << 20)) |rules| {
        b.ignore = try dockerfile.parseIgnore(a, rules);
    } else |_| {}

    var final: ?[]const u8 = null;
    defer b.cleanup(final);

    for (instrs, 0..) |instr, i| {
        sys.print("Step {d}/{d} : {s} {s}\n", .{ i + 1, instrs.len, instr.op, instr.rest });
        if (std.mem.eql(u8, instr.op, "FROM")) {
            try b.finishStage();
            const triggers = try b.beginStage(instr.rest);
            for (triggers) |trigger| {
                sys.print(" ---> ONBUILD {s}\n", .{trigger});
                for (try dockerfile.parse(a, trigger)) |t| try b.execute(t);
            }
        } else if (std.mem.eql(u8, instr.op, "ARG") and b.cur == null) {
            for (try dockerfile.splitWords(a, instr.rest)) |spec| {
                if (try b.argValue(spec, b.global_args.items)) |v| try container.setEnv(a, &b.global_args, v);
            }
        } else {
            try b.execute(instr);
        }
    }
    try b.finishStage();

    if (b.stages.items.len == 0) return fail("the Dockerfile has no FROM", .{});
    final = b.stages.items[b.stages.items.len - 1].id;
    if (opts.tag) |tag| {
        const ref = try registry.parseRef(a, tag);
        try store.setRef(ref.name, final.?);
        sys.print("Tagged {s}\n", .{ref.name});
    }
    sys.print("Built {s}\n", .{final.?[0..12]});
    return final.?;
}
