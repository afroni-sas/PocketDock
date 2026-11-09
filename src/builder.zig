//! `pdock build`: turns a Dockerfile into an image.
//!
//! Each stage runs as a hidden container on top of its base image. When the
//! stage ends, the container's writable layer simply becomes a new image
//! layer, so a build never copies its base.

const std = @import("std");
const sys = @import("sys.zig");
const dockerfile = @import("dockerfile.zig");
const registry = @import("registry.zig");
const container = @import("container.zig");
const vfs_mod = @import("vfs.zig");
const Store = @import("store.zig").Store;
const Allocator = std.mem.Allocator;
const Path = sys.Path;
const Vfs = vfs_mod.Vfs;
const Resolved = vfs_mod.Resolved;

pub const Options = struct {
    context: []const u8,
    file: ?[]const u8 = null,
    tag: ?[]const u8 = null,
    build_args: []const []const u8 = &.{},
};

const Stage = struct { name: ?[]const u8, id: []const u8 };

/// The stage being built.
const Current = struct {
    cfg: container.Config,
    vfs: *Vfs,
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

    fn loadBaseConfig(self: *Builder, id: []const u8, c: *Current) !void {
        const raw = try sys.readFileAlloc(self.a, self.store.path(&.{ "images", id, "config.json" }), 1 << 22);
        const doc = try std.json.parseFromSliceLeaky(std.json.Value, self.a, raw, .{});
        const cfg = doc.object.get("config") orelse return;
        if (cfg != .object) return;
        for (try container.stringArray(self.a, cfg.object.get("Env"))) |e| try container.setEnv(self.a, &c.env, e);
        c.cmd = try container.stringArray(self.a, cfg.object.get("Cmd"));
        c.entrypoint = try container.stringArray(self.a, cfg.object.get("Entrypoint"));
        if (cfg.object.get("WorkingDir")) |w| {
            if (w == .string and w.string.len > 0) c.workdir = w.string;
        }
        if (cfg.object.get("User")) |u| {
            if (u == .string) c.user = u.string;
        }
        if (cfg.object.get("ExposedPorts")) |p| {
            if (p == .object) for (p.object.keys()) |k| try c.ports.append(self.a, k);
        }
        if (cfg.object.get("Labels")) |l| {
            if (l == .object) {
                var it = l.object.iterator();
                while (it.next()) |kv| {
                    if (kv.value_ptr.* == .string) {
                        try c.labels.append(self.a, try std.fmt.allocPrint(self.a, "{s}={s}", .{ kv.key_ptr.*, kv.value_ptr.string }));
                    }
                }
            }
        }
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

    fn beginStage(self: *Builder, rest: []const u8) !void {
        var words = std.ArrayList([]const u8).empty;
        for (try dockerfile.splitWords(self.a, rest)) |w| {
            if (!std.mem.startsWith(u8, w, "--")) try words.append(self.a, w);
        }
        if (words.items.len == 0) return fail("FROM needs an image", .{});
        const image = try dockerfile.expand(self.a, words.items[0], self.global_args.items);
        var name: ?[]const u8 = null;
        if (words.items.len >= 3 and std.ascii.eqlIgnoreCase(words.items[1], "as")) name = words.items[2];

        const base: []const u8 = blk: {
            if (self.findStage(image)) |s| break :blk s.id;
            if (std.mem.eql(u8, image, "scratch")) break :blk try self.mgr.emptyImage();
            break :blk try registry.pull(self.a, self.gpa, self.io, self.store, image, false);
        };

        var id_buf: [8]u8 = undefined;
        sys.randomId(&id_buf);
        const cfg = try self.mgr.create(.{
            .image_id = base,
            .image = image,
            .name = try std.fmt.allocPrint(self.a, "pdock-build-{s}", .{id_buf}),
            .command = &.{"/bin/true"},
            .builder = true,
        });
        var c: Current = .{ .cfg = cfg, .vfs = try self.mgr.makeVfs(&cfg), .name = name };
        try self.loadBaseConfig(base, &c);
        self.cur = c;
    }

    fn finishStage(self: *Builder) !void {
        const c = &(self.cur orelse return);
        const a = self.a;
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
        try out.print(a, "{{\"config\":{{\"Env\":{s},\"Cmd\":{s},\"Entrypoint\":{s},\"WorkingDir\":{s},\"User\":{s},\"ExposedPorts\":{{", .{
            try list(a, c.env.items),
            try list(a, c.cmd),
            try list(a, c.entrypoint),
            try str(a, c.workdir),
            try str(a, c.user),
        });
        for (c.ports.items, 0..) |p, i| {
            if (i > 0) try out.append(a, ',');
            try out.print(a, "{s}:{{}}", .{try str(a, p)});
        }
        try out.appendSlice(a, "},\"Labels\":{");
        for (c.labels.items, 0..) |l, i| {
            if (i > 0) try out.append(a, ',');
            const eq = std.mem.indexOfScalar(u8, l, '=') orelse l.len;
            try out.print(a, "{s}:{s}", .{ try str(a, l[0..eq]), try str(a, if (eq < l.len) l[eq + 1 ..] else "") });
        }
        try out.appendSlice(a, "}}}");
        const id = try self.mgr.commitBuild(&c.cfg, out.items);
        try self.stages.append(a, .{ .name = c.name, .id = id });
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

        var env: std.ArrayList([]const u8) = .empty;
        for ([_][]const []const u8{ c.cfg.env, c.args.items, c.env.items }) |group| {
            for (group) |e| try container.setEnv(a, &env, e);
        }
        var uid: u32 = 0;
        var gid: u32 = 0;
        if (c.user.len > 0) {
            const u = try self.mgr.resolveUser(c.vfs, c.user);
            uid = u.uid;
            gid = u.gid;
        }
        const code = try self.mgr.runBuildStep(&c.cfg, .{
            .argv = argv,
            .env = env.items,
            .workdir = c.workdir,
            .uid = uid,
            .gid = gid,
        });
        if (code != 0) return fail("line {d}: the command returned {d}", .{ instr.line, code });
    }

    fn absolute(self: *Builder, path: []const u8) ![]const u8 {
        if (path.len > 0 and path[0] == '/') return path;
        return std.fmt.allocPrint(self.a, "{s}/{s}", .{ std.mem.trimEnd(u8, self.cur.?.workdir, "/"), path });
    }

    /// Puts one file or symlink at a guest path, replacing what is there.
    fn putEntry(self: *Builder, src: *Resolved, dst_path: []const u8) !void {
        const vfs = self.cur.?.vfs;
        try vfs.ensureDir(dirnameOf(dst_path));
        var d: Resolved = .{};
        try vfs.resolve(dst_path, false, &d);
        if (d.exists) {
            if (sys.isDir(d.mode)) return fail("cannot replace the directory {s} with a file", .{dst_path});
            try vfs.prepareRemove(&d);
            try sys.unlink(d.host.z());
            try vfs.resolve(dst_path, false, &d);
        }
        try vfs.prepareCreate(&d);
        if (sys.isLnk(src.mode)) {
            var buf: [sys.PATH_MAX]u8 = undefined;
            const target = try sys.readlink(src.host.z(), buf[0 .. buf.len - 1]);
            buf[target.len] = 0;
            try sys.symlink(@ptrCast(&buf), d.host.z());
        } else {
            try Vfs.copyFile(src.host.z(), d.host.z());
        }
    }

    fn copyTree(self: *Builder, source: *Vfs, src_path: []const u8, dst_path: []const u8, filtered: bool) !void {
        var r: Resolved = .{};
        try source.resolve(src_path, false, &r);
        try self.cur.?.vfs.ensureDir(dst_path);
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
                try self.copyTree(source, child_src, child_dst, filtered);
            } else {
                try self.putEntry(&cr, child_dst);
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
        return out.items;
    }

    fn doCopy(self: *Builder, instr: dockerfile.Instr, is_add: bool) !void {
        const a = self.a;
        const text = try self.expanded(instr.rest);
        var words: std.ArrayList([]const u8) = .empty;
        var from: ?[]const u8 = null;
        // Flags come first, before a possible JSON list of paths.
        var rest = text;
        while (std.mem.startsWith(u8, rest, "--")) {
            const sp = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
            const flag = rest[0..sp];
            if (std.mem.startsWith(u8, flag, "--from=")) from = flag["--from=".len..];
            rest = std.mem.trimStart(u8, rest[sp..], " \t");
        }
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
        if (from) |f| {
            const id: []const u8 = blk: {
                if (self.findStage(f)) |s| break :blk s.id;
                break :blk try registry.pull(a, self.gpa, self.io, self.store, f, false);
            };
            source = try self.mgr.imageVfs(id);
        }
        const filtered = from == null;

        var dest_is_dir = std.mem.endsWith(u8, dest_raw, "/") or srcs.len > 1;
        var existing: Resolved = .{};
        try self.cur.?.vfs.resolve(dest, true, &existing);
        if (existing.exists and sys.isDir(existing.mode)) dest_is_dir = true;

        for (srcs) |src| {
            if (is_add and (std.mem.startsWith(u8, src, "http://") or std.mem.startsWith(u8, src, "https://"))) {
                return fail("line {d}: ADD from a URL is not supported yet; use RUN with curl or wget", .{instr.line});
            }
            if (is_add and (std.mem.endsWith(u8, src, ".tar") or std.mem.endsWith(u8, src, ".tar.gz") or std.mem.endsWith(u8, src, ".tgz"))) {
                return fail("line {d}: ADD does not unpack archives yet; use COPY and RUN tar", .{instr.line});
            }
            const matches = try self.matchSources(source, src);
            if (matches.len == 0) return fail("line {d}: nothing matches {s}", .{ instr.line, src });
            if (matches.len > 1) dest_is_dir = true;
            for (matches) |m| {
                if (filtered and m.len > 1 and dockerfile.isIgnored(self.ignore, m[1..])) continue;
                var r: Resolved = .{};
                try source.resolve(m, true, &r);
                if (!r.exists) return fail("line {d}: {s} not found", .{ instr.line, src });
                if (sys.isDir(r.mode)) {
                    try self.copyTree(source, r.guest.slice(), dest, filtered);
                } else if (dest_is_dir) {
                    const target = try std.fmt.allocPrint(a, "{s}/{s}", .{ std.mem.trimEnd(u8, dest, "/"), basenameOf(m) });
                    try self.putEntry(&r, target);
                } else {
                    try self.putEntry(&r, dest);
                }
            }
        }
    }

    fn execute(self: *Builder, instr: dockerfile.Instr) !void {
        const a = self.a;
        const op = instr.op;
        const eql = std.mem.eql;
        if (self.cur == null) return fail("line {d}: {s} comes before FROM", .{ instr.line, op });
        const c = &self.cur.?;

        if (eql(u8, op, "RUN")) {
            try self.doRun(instr);
        } else if (eql(u8, op, "COPY")) {
            try self.doCopy(instr, false);
        } else if (eql(u8, op, "ADD")) {
            try self.doCopy(instr, true);
        } else if (eql(u8, op, "ENV")) {
            for (try dockerfile.keyValues(a, try self.expanded(instr.rest))) |kv| try container.setEnv(a, &c.env, kv);
        } else if (eql(u8, op, "ARG")) {
            for (try dockerfile.splitWords(a, instr.rest)) |spec| {
                if (try self.argValue(spec, self.global_args.items)) |v| try container.setEnv(a, &c.args, v);
            }
        } else if (eql(u8, op, "LABEL")) {
            for (try dockerfile.keyValues(a, try self.expanded(instr.rest))) |kv| try container.setEnv(a, &c.labels, kv);
        } else if (eql(u8, op, "WORKDIR")) {
            c.workdir = try self.absolute(try self.expanded(instr.rest));
            try c.vfs.ensureDir(c.workdir);
        } else if (eql(u8, op, "USER")) {
            c.user = try self.expanded(instr.rest);
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
        } else if (eql(u8, op, "VOLUME") or eql(u8, op, "STOPSIGNAL") or eql(u8, op, "HEALTHCHECK") or eql(u8, op, "MAINTAINER") or eql(u8, op, "ONBUILD")) {
            // Accepted so that existing Dockerfiles build, but not acted on.
        } else {
            return fail("line {d}: unknown instruction {s}", .{ instr.line, op });
        }
    }

    /// Removes what a build leaves behind. Only the final image's own chain
    /// of layers survives a successful one.
    fn cleanup(self: *Builder, final: ?[]const u8) void {
        if (self.cur) |c| self.mgr.discardBuild(c.cfg.id);
        const keep: []const []const u8 = if (final) |id| self.mgr.imageLayers(id) catch &.{} else &.{};
        for (self.stages.items) |s| {
            const layer = self.store.path(&.{ "images", s.id, "rootfs" });
            var used = false;
            for (keep) |k| used = used or std.mem.eql(u8, k, layer);
            if (!used) sys.rmrf(self.store.path(&.{ "images", s.id })) catch {};
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
            try b.beginStage(instr.rest);
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
