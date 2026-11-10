//! Container lifecycle: create, start, supervise, stop, remove.
//!
//!   <root>/containers/<id>/config.json  what to run, fixed at creation
//!   <root>/containers/<id>/state.json   what is happening now
//!   <root>/containers/<id>/ctr.log      output, one CRI-format line per line
//!   <root>/containers/<id>/upper/       the container's writable layer
//!   <root>/containers/<id>/run/         generated resolv.conf, hosts, hostname

const std = @import("std");
const sys = @import("sys.zig");
const tracer = @import("tracer.zig");
const vfs_mod = @import("vfs.zig");
const control = @import("control.zig");
const tty = @import("tty.zig");
const quota = @import("quota.zig");
const Store = @import("store.zig").Store;
const Allocator = std.mem.Allocator;
const Path = sys.Path;
const linux = sys.linux;

pub const PortSpec = struct { container: u16, host: u16 };
pub const Volume = struct { host: []const u8, guest: []const u8, ro: bool = false };

pub const Health = struct {
    command: []const []const u8,
    interval_ms: u64 = 30_000,
    timeout_ms: u64 = 30_000,
    start_ms: u64 = 0,
    retries: u32 = 3,
};

pub const Config = struct {
    id: []const u8,
    name: []const u8,
    image: []const u8,
    image_id: []const u8,
    argv: []const []const u8,
    env: []const []const u8,
    workdir: []const u8,
    hostname: []const u8,
    uid: u32 = 0,
    gid: u32 = 0,
    ports: []const PortSpec = &.{},
    volumes: []const Volume = &.{},
    /// "no", "always", "on-failure" or "unless-stopped".
    restart: []const u8 = "no",
    max_retries: u32 = 0,
    auto_remove: bool = false,
    created_at: i64 = 0,
    /// Address on the private network.
    ip: []const u8 = "",
    /// "bridge", "private" or "none".
    network: []const u8 = "bridge",
    host_gateway: bool = false,
    memory: u64 = 0,
    cpus_milli: u32 = 0,
    cpuset: u64 = 0,
    pids_limit: u32 = 0,
    /// A stage of `pdock build`, hidden from `ps`.
    builder: bool = false,
    stop_signal: []const u8 = "SIGTERM",
    health: ?Health = null,
};

pub const PortEntry = struct { container: u16, host: u16 };

pub const State = struct {
    /// "created", "running", "restarting" or "exited".
    status: []const u8 = "created",
    pid: i32 = 0,
    shim_pid: i32 = 0,
    /// When the supervisor started, which tells it from a later process that
    /// happens to get the same pid.
    shim_start: u64 = 0,
    exit_code: i32 = 0,
    started_at: i64 = 0,
    finished_at: i64 = 0,
    restarts: u32 = 0,
    ports: []const PortEntry = &.{},
    oom_killed: bool = false,
    /// "starting", "healthy" or "unhealthy"; empty without a health check.
    health: []const u8 = "",
};

pub const CreateOptions = struct {
    image_id: []const u8,
    image: []const u8,
    name: ?[]const u8 = null,
    command: []const []const u8 = &.{},
    entrypoint: ?[]const u8 = null,
    env: []const []const u8 = &.{},
    workdir: ?[]const u8 = null,
    user: ?[]const u8 = null,
    hostname: ?[]const u8 = null,
    ports: []const PortSpec = &.{},
    volumes: []const Volume = &.{},
    restart: []const u8 = "no",
    max_retries: u32 = 0,
    auto_remove: bool = false,
    network: []const u8 = "bridge",
    host_gateway: bool = false,
    memory: u64 = 0,
    cpus_milli: u32 = 0,
    cpuset: u64 = 0,
    pids_limit: u32 = 0,
    builder: bool = false,
    stop_signal: ?[]const u8 = null,
    health: ?Health = null,
    no_health: bool = false,
};

/// One RUN instruction of a build.
pub const BuildStep = struct {
    argv: []const []const u8,
    env: []const []const u8,
    workdir: []const u8,
    uid: u32,
    gid: u32,
};

pub const UserInfo = struct { uid: u32, gid: u32, home: []const u8 };

pub const Stats = struct { pids: u64, memory: u64, cpu_ms: u64 };

pub const Attach = enum { detached, foreground, interactive, tty };

const hosts_header = "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n";

const default_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

var fwd_pid: i32 = 0;

fn forwardSignal(sig: linux.SIG) callconv(.c) void {
    if (fwd_pid > 0) _ = linux.kill(fwd_pid, sig);
}

fn installForwarder(sig: linux.SIG) void {
    var act: linux.Sigaction = .{
        .handler = .{ .handler = forwardSignal },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = 0,
    };
    _ = linux.sigaction(sig, &act, null);
}

pub fn stringArray(a: Allocator, v: ?std.json.Value) ![]const []const u8 {
    const val = v orelse return &.{};
    if (val != .array) return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (val.array.items) |item| {
        if (item == .string) try out.append(a, item.string);
    }
    return out.items;
}

const PasswdEntry = struct { uid: u32, gid: u32, home: []const u8 };

fn readGuest(a: Allocator, vfs: *vfs_mod.Vfs, path: []const u8) ?[]u8 {
    var r: vfs_mod.Resolved = .{};
    vfs.resolve(path, true, &r) catch return null;
    if (!r.exists) return null;
    return sys.readFileAlloc(a, r.host.slice(), 1 << 20) catch null;
}

fn lookupPasswd(a: Allocator, vfs: *vfs_mod.Vfs, user: []const u8) ?PasswdEntry {
    const data = readGuest(a, vfs, "/etc/passwd") orelse return null;
    const num = std.fmt.parseInt(u32, user, 10) catch null;
    var lines = std.mem.tokenizeScalar(u8, data, '\n');
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ':');
        const name = f.next() orelse continue;
        _ = f.next();
        const uid = std.fmt.parseInt(u32, f.next() orelse continue, 10) catch continue;
        const gid = std.fmt.parseInt(u32, f.next() orelse continue, 10) catch continue;
        _ = f.next();
        const home = f.next() orelse "/";
        if (std.mem.eql(u8, name, user) or num == uid) return .{ .uid = uid, .gid = gid, .home = home };
    }
    return null;
}

fn lookupGroup(a: Allocator, vfs: *vfs_mod.Vfs, group: []const u8) ?u32 {
    if (std.fmt.parseInt(u32, group, 10) catch null) |g| return g;
    const data = readGuest(a, vfs, "/etc/group") orelse return null;
    var lines = std.mem.tokenizeScalar(u8, data, '\n');
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ':');
        const name = f.next() orelse continue;
        _ = f.next();
        const gid = std.fmt.parseInt(u32, f.next() orelse continue, 10) catch continue;
        if (std.mem.eql(u8, name, group)) return gid;
    }
    return null;
}

pub const Manager = struct {
    a: Allocator,
    gpa: Allocator,
    store: Store,
    debug: bool = false,

    fn dir(self: *Manager, id: []const u8) []const u8 {
        return self.store.path(&.{ "containers", id });
    }

    fn file(self: *Manager, id: []const u8, name: []const u8) []const u8 {
        return self.store.path(&.{ "containers", id, name });
    }

    /// The read-only layers of an image, topmost first.
    pub fn imageLayers(self: *Manager, image_id: []const u8) ![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        var id = image_id;
        while (true) {
            const layer = self.store.path(&.{ "images", id, "rootfs" });
            // The final image of a build holds only its configuration.
            var p = try Path.of(layer);
            if (sys.exists(p.z())) try out.append(self.a, layer);
            id = sys.readFileAlloc(self.a, self.store.path(&.{ "images", id, "parent" }), 128) catch break;
        }
        return out.items;
    }

    /// A read-only view of an image, for reading files out of it.
    pub fn imageVfs(self: *Manager, image_id: []const u8) !*vfs_mod.Vfs {
        const layers = try self.imageLayers(image_id);
        const vfs = try self.a.create(vfs_mod.Vfs);
        vfs.* = .{ .upper = layers[0], .lowers = layers[1..], .work = "", .mounts = &.{}, .raw = true };
        return vfs;
    }

    /// The base of `FROM scratch`: a layer with nothing in it.
    pub fn emptyImage(self: *Manager) ![]const u8 {
        try sys.mkdirP(self.store.path(&.{ "images", "scratch", "rootfs" }), 0o755);
        try sys.writeFile(self.store.path(&.{ "images", "scratch", "config.json" }), "{\"config\":{}}", 0o600);
        return "scratch";
    }

    /// Resolves `USER[:GROUP]` against the image's own account files.
    pub fn resolveUser(self: *Manager, vfs: *vfs_mod.Vfs, spec: []const u8) !UserInfo {
        const colon = std.mem.indexOfScalar(u8, spec, ':');
        const user = if (colon) |i| spec[0..i] else spec;
        var info: UserInfo = .{ .uid = 0, .gid = 0, .home = "/root" };
        if (lookupPasswd(self.a, vfs, user)) |e| {
            info = .{ .uid = e.uid, .gid = e.gid, .home = e.home };
        } else if (std.fmt.parseInt(u32, user, 10) catch null) |n| {
            info = .{ .uid = n, .gid = 0, .home = "/" };
        } else {
            sys.eprint("error: unknown user \"{s}\" in image\n", .{user});
            return error.UnknownUser;
        }
        if (colon) |i| {
            info.gid = lookupGroup(self.a, vfs, spec[i + 1 ..]) orelse return error.UnknownGroup;
        }
        return info;
    }

    pub fn loadConfig(self: *Manager, id: []const u8) !Config {
        const data = try sys.readFileAlloc(self.a, self.file(id, "config.json"), 1 << 20);
        return std.json.parseFromSliceLeaky(Config, self.a, data, .{ .ignore_unknown_fields = true });
    }

    pub fn loadState(self: *Manager, id: []const u8) !State {
        var st = try self.readState(id);
        // The supervisor died without saying so, e.g. the phone rebooted.
        if (claimsLive(&st) and !supervisorAlive(&st)) {
            st.status = "exited";
            st.exit_code = 137;
            st.pid = 0;
        }
        return st;
    }

    fn readState(self: *Manager, id: []const u8) !State {
        const data = try sys.readFileAlloc(self.a, self.file(id, "state.json"), 1 << 20);
        return std.json.parseFromSliceLeaky(State, self.a, data, .{ .ignore_unknown_fields = true });
    }

    /// A container that should be running but whose supervisor was killed.
    /// One that exited on its own has already had its restart policy applied.
    pub fn orphaned(self: *Manager, id: []const u8) bool {
        const cfg = self.loadConfig(id) catch return false;
        if (cfg.builder or !shouldRestart(&cfg, 137, 0)) return false;
        const st = self.readState(id) catch return false;
        if (!claimsLive(&st) or supervisorAlive(&st)) return false;
        var marker = Path.of(self.file(id, "stop-requested")) catch return false;
        return !sys.exists(marker.z());
    }

    fn saveState(self: *Manager, id: []const u8, st: State) void {
        const data = std.json.Stringify.valueAlloc(self.a, st, .{ .whitespace = .indent_2 }) catch return;
        sys.writeFileAtomic(self.file(id, "state.json"), data, 0o600) catch {};
    }

    pub fn listIds(self: *Manager) ![]const []const u8 {
        return self.store.listDir("containers");
    }

    /// Accepts a name, a full id or an unambiguous id prefix.
    pub fn find(self: *Manager, needle: []const u8) ![]const u8 {
        var found: ?[]const u8 = null;
        for (try self.listIds()) |id| {
            const cfg = self.loadConfig(id) catch continue;
            if (std.mem.eql(u8, cfg.name, needle)) return id;
            if (std.mem.startsWith(u8, id, needle)) {
                if (found != null) return error.AmbiguousContainer;
                found = id;
            }
        }
        return found orelse error.NoSuchContainer;
    }

    fn mounts(self: *Manager, cfg: *const Config) ![]const vfs_mod.Mount {
        var list: std.ArrayList(vfs_mod.Mount) = .empty;
        for ([_][]const u8{ "/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/ptmx", "/dev/pts" }) |d| {
            try list.append(self.a, .{ .guest = d, .host = d });
        }
        try list.append(self.a, .{ .guest = "/sys", .host = "/sys", .ro = true });
        const run = self.file(cfg.id, "run");
        for ([_][]const u8{ "resolv.conf", "hosts", "hostname" }) |f| {
            try list.append(self.a, .{
                .guest = try std.fmt.allocPrint(self.a, "/etc/{s}", .{f}),
                .host = try std.fmt.allocPrint(self.a, "{s}/{s}", .{ run, f }),
            });
        }
        for (cfg.volumes) |v| {
            try list.append(self.a, .{ .guest = v.guest, .host = v.host, .ro = v.ro });
        }
        return list.items;
    }

    pub fn makeVfs(self: *Manager, cfg: *const Config) !*vfs_mod.Vfs {
        const vfs = try self.a.create(vfs_mod.Vfs);
        vfs.* = .{
            .lowers = try self.imageLayers(cfg.image_id),
            .upper = self.file(cfg.id, "upper"),
            .work = self.file(cfg.id, "work"),
            .mounts = try self.mounts(cfg),
        };
        return vfs;
    }

    pub fn create(self: *Manager, opts: CreateOptions) !Config {
        const a = self.a;
        const cfg_path = self.store.path(&.{ "images", opts.image_id, "config.json" });
        const raw = try sys.readFileAlloc(a, cfg_path, 1 << 22);
        const doc = try std.json.parseFromSliceLeaky(std.json.Value, a, raw, .{});
        const img: std.json.Value = doc.object.get("config") orelse .{ .object = .empty };

        var id_buf: [12]u8 = undefined;
        sys.randomId(&id_buf);
        const id = try a.dupe(u8, &id_buf);
        const name = opts.name orelse try std.fmt.allocPrint(a, "pd-{s}", .{id[0..6]});
        for (try self.listIds()) |other| {
            const c = self.loadConfig(other) catch continue;
            if (std.mem.eql(u8, c.name, name)) {
                sys.eprint("error: the name \"{s}\" is already in use\n", .{name});
                return error.NameInUse;
            }
        }

        // Same rules as Docker for combining ENTRYPOINT, CMD and arguments.
        var entry = try stringArray(a, img.object.get("Entrypoint"));
        var cmd = try stringArray(a, img.object.get("Cmd"));
        if (opts.entrypoint) |e| {
            const one = try a.alloc([]const u8, 1);
            one[0] = e;
            entry = one;
            cmd = &.{};
        }
        if (opts.command.len > 0) cmd = opts.command;
        const argv = try std.mem.concat(a, []const u8, &.{ entry, cmd });
        if (argv.len == 0) {
            sys.eprint("error: no command specified and the image has no default\n", .{});
            return error.NoCommand;
        }

        const image_view = try self.imageVfs(opts.image_id);
        const user_str = opts.user orelse blk: {
            const u = img.object.get("User") orelse break :blk "";
            break :blk if (u == .string) u.string else "";
        };
        var uid: u32 = 0;
        var gid: u32 = 0;
        var home: []const u8 = "/root";
        if (user_str.len > 0) {
            const info = try self.resolveUser(image_view, user_str);
            uid = info.uid;
            gid = info.gid;
            home = info.home;
        }

        const hostname = opts.hostname orelse id[0..12];

        // Paths the image declares as VOLUME get their own storage, starting
        // from what the image has there, unless -v already provides one.
        var volumes: std.ArrayList(Volume) = .empty;
        try volumes.appendSlice(a, opts.volumes);
        if (!opts.builder) {
            if (img.object.get("Volumes")) |declared| {
                if (declared == .object) {
                    for (declared.object.keys(), 0..) |guest, i| {
                        var covered = false;
                        for (opts.volumes) |v| covered = covered or std.mem.eql(u8, v.guest, guest);
                        if (covered) continue;
                        const host = self.file(id, try std.fmt.allocPrint(a, "volumes/{d}", .{i}));
                        try sys.mkdirP(host, 0o755);
                        try self.seedVolume(image_view, guest, host);
                        try volumes.append(a, .{ .host = host, .guest = guest });
                    }
                }
            }
        }

        var stop_signal: []const u8 = opts.stop_signal orelse "";
        if (stop_signal.len == 0) {
            if (img.object.get("StopSignal")) |s| {
                if (s == .string) stop_signal = s.string;
            }
        }
        if (stop_signal.len == 0) stop_signal = "SIGTERM";

        const health: ?Health = if (opts.no_health)
            null
        else
            opts.health orelse try parseHealth(a, img.object.get("Healthcheck"));
        const ip = try self.allocateIp(id);

        var env: std.ArrayList([]const u8) = .empty;
        const defaults = [_][]const u8{
            "PATH=" ++ default_path,
            try std.fmt.allocPrint(a, "HOSTNAME={s}", .{hostname}),
            try std.fmt.allocPrint(a, "HOME={s}", .{home}),
        };
        const image_env = try stringArray(a, img.object.get("Env"));
        for ([_][]const []const u8{ &defaults, image_env, opts.env }) |group| {
            for (group) |entry_s| try setEnv(a, &env, entry_s);
        }

        var workdir: []const u8 = opts.workdir orelse "";
        if (workdir.len == 0) {
            if (img.object.get("WorkingDir")) |w| {
                if (w == .string) workdir = w.string;
            }
        }
        if (workdir.len == 0) workdir = "/";

        const cfg: Config = .{
            .id = id,
            .name = name,
            .image = opts.image,
            .image_id = opts.image_id,
            .argv = argv,
            .env = env.items,
            .workdir = workdir,
            .hostname = hostname,
            .uid = uid,
            .gid = gid,
            .ports = opts.ports,
            .volumes = volumes.items,
            .restart = opts.restart,
            .host_gateway = opts.host_gateway,
            .max_retries = opts.max_retries,
            .auto_remove = opts.auto_remove,
            .created_at = @intCast(@divFloor(sys.nowNs(), std.time.ns_per_s)),
            .ip = ip,
            .network = opts.network,
            .memory = opts.memory,
            .cpus_milli = opts.cpus_milli,
            .cpuset = opts.cpuset,
            .pids_limit = opts.pids_limit,
            .builder = opts.builder,
            .stop_signal = stop_signal,
            .health = health,
        };

        try sys.mkdirP(self.file(id, "run"), 0o755);
        try sys.writeFile(self.file(id, "run/hostname"), try std.fmt.allocPrint(a, "{s}\n", .{hostname}), 0o644);
        try sys.writeFile(self.file(id, "run/hosts"), hosts_header, 0o644);
        try self.writeResolvConf(id);

        for (cfg.volumes) |v| try sys.mkdirP(v.host, 0o755);

        const vfs = try self.makeVfs(&cfg);
        try vfs.init();
        for ([_][]const u8{ "/proc", "/sys", "/dev", "/tmp", cfg.workdir }) |d| try vfs.ensureDir(d);
        for (cfg.volumes) |v| try vfs.ensureDir(v.guest);
        try self.populateDev(vfs);

        const data = try std.json.Stringify.valueAlloc(a, cfg, .{ .whitespace = .indent_2 });
        try sys.writeFileAtomic(self.file(id, "config.json"), data, 0o600);
        self.saveState(id, .{});
        return cfg;
    }

    /// Hands out the next free address on the private network. The O_EXCL
    /// create is what makes this safe between concurrent `run`s.
    fn allocateIp(self: *Manager, id: []const u8) ![]const u8 {
        var host: u32 = 2;
        while (host < 65534) : (host += 1) {
            const ip = try std.fmt.allocPrint(self.a, "10.88.{d}.{d}", .{ host >> 8, host & 0xff });
            var p = try Path.of(self.store.path(&.{ "net", "ips", ip }));
            const fd = sys.open(p.z(), sys.O_WRONLY | sys.O_CREAT | sys.O_EXCL, 0o600) catch {
                if (sys.last == .EXIST) continue;
                return error.Sys;
            };
            defer sys.close(fd);
            try sys.writeAll(fd, id);
            return ip;
        }
        return error.NoFreeAddress;
    }

    /// Rewrites /etc/hosts in every running container so that each sees the
    /// others by name. Called whenever one starts or stops.
    fn syncHosts(self: *Manager) void {
        const ids = self.listIds() catch return;
        var body: std.ArrayList(u8) = .empty;
        body.appendSlice(self.a, hosts_header) catch return;
        var running: std.ArrayList([]const u8) = .empty;
        for (ids) |id| {
            const cfg = self.loadConfig(id) catch continue;
            const st = self.loadState(id) catch continue;
            if (!std.mem.eql(u8, st.status, "running")) continue;
            running.append(self.a, id) catch return;
            if (cfg.ip.len == 0) continue;
            body.print(self.a, "{s}\t{s} {s}.internal {s}\n", .{ cfg.ip, cfg.name, cfg.name, cfg.hostname }) catch return;
        }
        for (running.items) |id| {
            sys.writeFileAtomic(self.file(id, "run/hosts"), body.items, 0o644) catch {};
        }
    }

    fn writeResolvConf(self: *Manager, id: []const u8) !void {
        const dns = @import("dns.zig");
        var servers: [4][4]u8 = undefined;
        const n = dns.servers(&servers);
        var out: std.ArrayList(u8) = .empty;
        for (servers[0..n]) |s| {
            try out.print(self.a, "nameserver {d}.{d}.{d}.{d}\n", .{ s[0], s[1], s[2], s[3] });
        }
        try sys.writeFile(self.file(id, "run/resolv.conf"), out.items, 0o644);
    }

    /// Builds the container's /dev. Device nodes are visited through mounts;
    /// the empty files here only make them show up in a listing.
    fn populateDev(self: *Manager, vfs: *vfs_mod.Vfs) !void {
        _ = self;
        try vfs.sealDir("/dev");
        var dev = try Path.join(vfs.upper, "/dev");
        for ([_][]const u8{ "null", "zero", "full", "random", "urandom", "tty", "ptmx" }) |name| {
            var p = try Path.join(dev.slice(), "/");
            try p.append(name);
            const fd = try sys.open(p.z(), sys.O_WRONLY | sys.O_CREAT, 0o666);
            sys.close(fd);
        }
        for ([_][]const u8{ "pts", "shm" }) |name| {
            var p = try Path.join(dev.slice(), "/");
            try p.append(name);
            sys.mkdir(p.z(), 0o1777) catch {
                if (sys.last != .EXIST) return error.Sys;
            };
        }
        const links = [_][2][]const u8{
            .{ "fd", "/proc/self/fd" },
            .{ "stdin", "/proc/self/fd/0" },
            .{ "stdout", "/proc/self/fd/1" },
            .{ "stderr", "/proc/self/fd/2" },
        };
        for (links) |l| {
            var p = try Path.join(dev.slice(), "/");
            try p.append(l[0]);
            var t = try Path.of(l[1]);
            sys.symlink(t.z(), p.z()) catch {
                if (sys.last != .EXIST) return error.Sys;
            };
        }
    }

    /// Finds `argv0` in the guest's PATH, as a shell would.
    fn findExecutable(self: *Manager, vfs: *vfs_mod.Vfs, cfg: *const Config, argv0: []const u8) ![:0]const u8 {
        if (std.mem.indexOfScalar(u8, argv0, '/') != null) {
            if (argv0[0] == '/') return self.a.dupeSentinel(u8, argv0, 0);
            return try std.fmt.allocPrintSentinel(self.a, "{s}/{s}", .{ cfg.workdir, argv0 }, 0);
        }
        var search: []const u8 = default_path;
        for (cfg.env) |e| {
            if (std.mem.startsWith(u8, e, "PATH=")) search = e[5..];
        }
        var it = std.mem.tokenizeScalar(u8, search, ':');
        while (it.next()) |d| {
            const candidate = try std.fmt.allocPrintSentinel(self.a, "{s}/{s}", .{ d, argv0 }, 0);
            var r: vfs_mod.Resolved = .{};
            vfs.resolve(candidate, true, &r) catch continue;
            if (r.exists and !sys.isDir(r.mode) and r.mode & 0o111 != 0) return candidate;
        }
        sys.eprint("error: \"{s}\": executable file not found in $PATH\n", .{argv0});
        return error.ExecutableNotFound;
    }

    fn zList(self: *Manager, items: []const []const u8) ![]const [:0]const u8 {
        const out = try self.a.alloc([:0]const u8, items.len);
        for (items, 0..) |s, i| out[i] = try self.a.dupeSentinel(u8, s, 0);
        return out;
    }

    /// Starts `id`. Returns an exit code in the foreground, 0 once detached.
    pub fn start(self: *Manager, id: []const u8, attach: Attach) !u8 {
        const cfg = try self.loadConfig(id);
        const st = try self.loadState(id);
        if (std.mem.eql(u8, st.status, "running") or std.mem.eql(u8, st.status, "restarting")) {
            sys.eprint("error: container {s} is already running\n", .{cfg.name});
            return error.AlreadyRunning;
        }
        for (cfg.ports) |p| {
            if (!portAvailable(p.host)) {
                sys.eprint("error: host port {d} is already allocated\n", .{p.host});
                return error.PortInUse;
            }
        }
        var marker = try Path.of(self.file(id, "stop-requested"));
        sys.unlink(marker.z()) catch {};

        if (attach != .detached) return self.supervise(&cfg, attach, -1);

        var ready: [2]i32 = undefined;
        _ = try sys.ck(linux.pipe2(&ready, .{ .CLOEXEC = true }));
        const pid = try sys.fork();
        if (pid == 0) {
            sys.close(ready[0]);
            _ = linux.setsid();
            const devnull = sys.open("/dev/null", sys.O_RDWR, 0) catch linux.exit_group(1);
            _ = linux.dup2(devnull, 0);
            _ = linux.dup2(devnull, 1);
            _ = linux.dup2(devnull, 2);
            const code = self.supervise(&cfg, .detached, ready[1]) catch 1;
            linux.exit_group(code);
        }
        sys.close(ready[1]);
        var b: [1]u8 = undefined;
        const n = try sys.read(ready[0], &b);
        sys.close(ready[0]);
        if (n == 0) return error.FailedToStart;
        return 0;
    }

    const RunCtx = struct {
        mgr: *Manager,
        id: []const u8,
        state: *State,
        ready_fd: i32,
    };

    fn onStart(ctx: ?*anyopaque, pid: i32) void {
        const c: *RunCtx = @ptrCast(@alignCast(ctx.?));
        fwd_pid = pid;
        c.state.pid = pid;
        c.mgr.saveState(c.id, c.state.*);
        if (c.ready_fd >= 0) {
            _ = linux.write(c.ready_fd, "1", 1);
            sys.close(c.ready_fd);
            c.ready_fd = -1;
        }
    }

    fn onHealth(ctx: ?*anyopaque, status: []const u8) void {
        const c: *RunCtx = @ptrCast(@alignCast(ctx.?));
        c.state.health = status;
        c.mgr.saveState(c.id, c.state.*);
    }

    fn onOom(ctx: ?*anyopaque) void {
        const c: *RunCtx = @ptrCast(@alignCast(ctx.?));
        c.state.oom_killed = true;
        c.mgr.saveState(c.id, c.state.*);
    }

    fn onPorts(ctx: ?*anyopaque, ports: []const tracer.PortMap) void {
        const c: *RunCtx = @ptrCast(@alignCast(ctx.?));
        const list = c.mgr.a.alloc(PortEntry, ports.len) catch return;
        for (ports, 0..) |p, i| list[i] = .{ .container = p.container, .host = p.host };
        c.state.ports = list;
        c.mgr.saveState(c.id, c.state.*);
    }

    fn supervise(self: *Manager, cfg: *const Config, attach: Attach, ready_fd: i32) !u8 {
        const id = cfg.id;
        var state: State = .{ .shim_pid = linux.getpid(), .shim_start = sys.procStart(linux.getpid()), .status = "running" };

        // The tracer grows this list with the same allocator.
        var ports: std.ArrayList(tracer.PortMap) = .empty;
        defer ports.deinit(self.gpa);
        for (cfg.ports) |p| {
            try ports.append(self.gpa, .{ .container = p.container, .host = p.host, .fixed = true });
        }

        const vfs = try self.makeVfs(cfg);
        const exec_path = try self.findExecutable(vfs, cfg, cfg.argv[0]);
        const argv = try self.zList(cfg.argv);
        var env_list: std.ArrayList([]const u8) = .empty;
        try env_list.appendSlice(self.a, cfg.env);
        if (attach == .tty) try addDefaultTerm(self.a, &env_list);
        const envp = try self.zList(env_list.items);

        var stdout_fd: i32 = 1;
        var stderr_fd: i32 = 2;
        var pipes: [2][2]i32 = undefined;
        var logger_pid: i32 = 0;
        if (attach != .tty) {
            _ = try sys.ck(linux.pipe2(&pipes[0], .{ .CLOEXEC = true }));
            _ = try sys.ck(linux.pipe2(&pipes[1], .{ .CLOEXEC = true }));
            stdout_fd = pipes[0][1];
            stderr_fd = pipes[1][1];
            logger_pid = try sys.fork();
            if (logger_pid == 0) {
                sys.close(pipes[0][1]);
                sys.close(pipes[1][1]);
                runLogger(pipes[0][0], pipes[1][0], self.file(id, "ctr.log"), attach != .detached);
            }
            sys.close(pipes[0][0]);
            sys.close(pipes[1][0]);
        }

        // A handler rather than SIG_IGN, which the guest would inherit.
        for ([_]linux.SIG{ .TERM, .HUP, .INT, .QUIT }) |s| installForwarder(s);

        if (cfg.ports.len > 0) {
            const list = try self.a.alloc(PortEntry, cfg.ports.len);
            for (cfg.ports, 0..) |p, i| list[i] = .{ .container = p.container, .host = p.host };
            state.ports = list;
        }

        var ctx: RunCtx = .{ .mgr = self, .id = id, .state = &state, .ready_fd = ready_fd };
        var stdin_fd: i32 = 0;
        if (attach == .detached or attach == .foreground) stdin_fd = try sys.open("/dev/null", 0, 0);

        var pty: ?sys.Pty = null;
        var relay_pid: i32 = 0;
        if (attach == .tty) {
            const p = try sys.openPty();
            pty = p;
            tty.copySize(p.master);
            relay_pid = try sys.fork();
            if (relay_pid == 0) {
                sys.close(p.slave);
                runTtyRelay(p.master, self.file(id, "ctr.log"));
            }
            sys.close(p.master);
            stdin_fd = p.slave;
            stdout_fd = p.slave;
            stderr_fd = p.slave;
        }

        var health: ?tracer.HealthSpec = null;
        if (cfg.health) |h| {
            // A command missing from the image fails each check, as it should.
            const path = self.findExecutable(vfs, cfg, h.command[0]) catch try self.a.dupeSentinel(u8, h.command[0], 0);
            health = .{
                .exec_path = path,
                .argv = try self.zList(h.command),
                .interval_ms = h.interval_ms,
                .timeout_ms = h.timeout_ms,
                .start_ms = h.start_ms,
                .retries = h.retries,
            };
        }

        var spec: tracer.Spec = .{
            .vfs = vfs,
            .exec_path = exec_path,
            .argv = argv,
            .envp = envp,
            .cwd = cfg.workdir,
            .hostname = cfg.hostname,
            .uid = cfg.uid,
            .gid = cfg.gid,
            .ports = &ports,
            .sock_dir = self.store.path(&.{"sk"}),
            .port_dir = self.store.path(&.{"ports"}),
            .net_dir = self.store.path(&.{"net"}),
            .ip = parseIp(cfg.ip),
            .net_mode = std.meta.stringToEnum(tracer.NetMode, cfg.network) orelse .bridge,
            .ns_id = cfg.id,
            .ctl_path = self.file(id, "ctl.sock"),
            .limits = .{
                .memory = cfg.memory,
                .cpus_milli = cfg.cpus_milli,
                .cpuset = cfg.cpuset,
                .pids = cfg.pids_limit,
            },
            .stdin_fd = stdin_fd,
            .stdout_fd = stdout_fd,
            .stderr_fd = stderr_fd,
            .ctty = attach == .tty,
            .shm_dir = self.file(id, "shm"),
            .host_gateway = cfg.host_gateway,
            .debug = self.debug,
            .ctx = &ctx,
            .on_start = onStart,
            .on_ports = onPorts,
            .on_oom = onOom,
            .health = health,
            .on_health = onHealth,
        };

        var code: u8 = 0;
        var backoff_ms: u64 = 1000;
        while (true) {
            state.status = "running";
            state.started_at = @intCast(@divFloor(sys.nowNs(), std.time.ns_per_s));
            state.oom_killed = false;
            self.saveState(id, state);
            self.syncHosts();

            code = try tracer.Tracer.run(self.gpa, &spec);
            fwd_pid = 0;

            state.pid = 0;
            state.exit_code = code;
            state.finished_at = @intCast(@divFloor(sys.nowNs(), std.time.ns_per_s));

            var marker = try Path.of(self.file(id, "stop-requested"));
            const stopped = sys.exists(marker.z());
            if (stopped or !shouldRestart(cfg, code, state.restarts)) break;

            state.status = "restarting";
            state.restarts += 1;
            self.saveState(id, state);
            sys.sleepMs(backoff_ms);
            backoff_ms = @min(backoff_ms * 2, 30_000);
        }

        state.status = "exited";
        self.saveState(id, state);
        self.syncHosts();
        if (attach != .tty) {
            sys.close(pipes[0][1]);
            sys.close(pipes[1][1]);
            var status: i32 = 0;
            _ = linux.waitpid(logger_pid, &status, 0);
        }
        if (pty) |p| {
            // The relay sees the terminal close and puts the user's back.
            sys.close(p.slave);
            var status: i32 = 0;
            _ = linux.waitpid(relay_pid, &status, 0);
        }
        if (cfg.auto_remove) self.removeFiles(id);
        return code;
    }

    pub fn shouldRestart(cfg: *const Config, code: u8, restarts: u32) bool {
        if (std.mem.eql(u8, cfg.restart, "always") or std.mem.eql(u8, cfg.restart, "unless-stopped")) return true;
        if (std.mem.eql(u8, cfg.restart, "on-failure")) {
            if (code == 0) return false;
            return cfg.max_retries == 0 or restarts < cfg.max_retries;
        }
        return false;
    }

    /// Runs one RUN instruction inside a build stage's container.
    pub fn runBuildStep(self: *Manager, cfg: *const Config, step: BuildStep) !u8 {
        const vfs = try self.makeVfs(cfg);
        var patched = cfg.*;
        patched.env = step.env;
        patched.workdir = step.workdir;
        var ports: std.ArrayList(tracer.PortMap) = .empty;
        defer ports.deinit(self.gpa);
        var spec: tracer.Spec = .{
            .vfs = vfs,
            .exec_path = try self.findExecutable(vfs, &patched, step.argv[0]),
            .argv = try self.zList(step.argv),
            .envp = try self.zList(step.env),
            .cwd = step.workdir,
            .hostname = cfg.hostname,
            .uid = step.uid,
            .gid = step.gid,
            .ports = &ports,
            .sock_dir = self.store.path(&.{"sk"}),
            .shm_dir = self.file(cfg.id, "shm"),
            .stdin_fd = try sys.open("/dev/null", 0, 0),
            .ns_id = cfg.id,
            .debug = self.debug,
        };
        return tracer.Tracer.run(self.gpa, &spec);
    }

    /// Turns a finished build step into a layer. Its writable layer moves
    /// as it is, so this takes no time and no extra space.
    pub fn commitLayer(self: *Manager, cfg: *const Config, id: []const u8) !void {
        try sys.mkdirP(self.store.path(&.{ "images", id }), 0o700);
        var from = try Path.of(self.file(cfg.id, "upper"));
        var to = try Path.of(self.store.path(&.{ "images", id, "rootfs" }));
        try sys.rename(from.z(), to.z());
        try sys.writeFile(self.store.path(&.{ "images", id, "config.json" }), "{\"config\":{}}", 0o600);
        try sys.writeFile(self.store.path(&.{ "images", id, "parent" }), cfg.image_id, 0o600);
        self.removeFiles(cfg.id);
    }

    /// Records an image: settings on top of layers that already exist.
    pub fn commitImage(self: *Manager, parent: []const u8, config_json: []const u8) ![]const u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(config_json);
        hash.update(parent);
        var digest: [32]u8 = undefined;
        hash.final(&digest);
        const id = try std.fmt.allocPrint(self.a, "{x}", .{&digest});
        try sys.mkdirP(self.store.path(&.{ "images", id }), 0o700);
        try sys.writeFile(self.store.path(&.{ "images", id, "config.json" }), config_json, 0o600);
        try sys.writeFile(self.store.path(&.{ "images", id, "parent" }), parent, 0o600);
        return id;
    }

    /// Deletes build layers that no tagged image or container uses.
    pub fn prune(self: *Manager) !u64 {
        var keep: std.StringHashMapUnmanaged(void) = .empty;
        var roots: std.ArrayList([]const u8) = .empty;
        for (try self.store.listRefs()) |r| try roots.append(self.a, r.id);
        for (try self.listIds()) |id| {
            const cfg = self.loadConfig(id) catch continue;
            try roots.append(self.a, cfg.image_id);
        }
        for (roots.items) |root| {
            var id = root;
            while (true) {
                try keep.put(self.a, id, {});
                id = sys.readFileAlloc(self.a, self.store.path(&.{ "images", id, "parent" }), 128) catch break;
            }
        }
        var removed: u64 = 0;
        for (try self.store.listDir("images")) |id| {
            var parent = try Path.of(self.store.path(&.{ "images", id, "parent" }));
            // Only built images have a parent; pulled ones are left alone.
            if (keep.contains(id) or !sys.exists(parent.z())) continue;
            try sys.rmrf(self.store.path(&.{ "images", id }));
            removed += 1;
        }
        return removed;
    }

    /// Gives a new volume what the image has at that path.
    fn seedVolume(self: *Manager, image: *vfs_mod.Vfs, guest: []const u8, host: []const u8) !void {
        var r: vfs_mod.Resolved = .{};
        image.resolve(guest, true, &r) catch return;
        if (!r.exists or !sys.isDir(r.mode)) return;
        var it = try sys.DirIter.open_(r.host.z());
        defer it.deinit();
        while (try it.next()) |ent| {
            const child_guest = try std.fmt.allocPrint(self.a, "{s}/{s}", .{ std.mem.trimEnd(u8, guest, "/"), ent.name });
            var dst = try Path.join(host, "/");
            try dst.append(ent.name);
            var cr: vfs_mod.Resolved = .{};
            try image.resolve(child_guest, false, &cr);
            if (!cr.exists) continue;
            if (sys.isDir(cr.mode)) {
                try sys.mkdir(dst.z(), (cr.mode & 0o7777) | 0o700);
                try self.seedVolume(image, child_guest, dst.slice());
            } else if (sys.isLnk(cr.mode)) {
                var buf: [sys.PATH_MAX]u8 = undefined;
                const target = try sys.readlink(cr.host.z(), buf[0 .. buf.len - 1]);
                buf[target.len] = 0;
                try sys.symlink(@ptrCast(&buf), dst.z());
            } else {
                try vfs_mod.Vfs.copyFile(cr.host.z(), dst.z());
            }
        }
    }

    pub fn discardBuild(self: *Manager, id: []const u8) void {
        self.removeFiles(id);
    }

    /// Connects to a running container's tracer. It sits in a blocking wait,
    /// so each attempt nudges it with a signal.
    fn connectCtl(self: *Manager, id: []const u8, shim_pid: i32) !i32 {
        const path = self.file(id, "ctl.sock");
        var attempt: u32 = 0;
        while (true) : (attempt += 1) {
            if (control.connect(path)) |fd| return fd else |_| {}
            if (attempt >= 25) return error.ContainerNotResponding;
            _ = linux.kill(shim_pid, .USR2);
            sys.sleepMs(40);
        }
    }

    /// Sends one request and waits for the first reply, repeating the nudge
    /// until the tracer has noticed the connection.
    fn request(self: *Manager, fd: i32, shim_pid: i32, msg: []const u8, fds: []const i32, reply: []u8) !usize {
        _ = self;
        try control.send(fd, msg, fds);
        var attempt: u32 = 0;
        while (attempt < 50) : (attempt += 1) {
            _ = linux.kill(shim_pid, .USR2);
            var none: [0]i32 = undefined;
            const got = control.recv(fd, reply, &none, 100) catch {
                if (sys.last == .TIMEDOUT) continue;
                return error.Sys;
            };
            return got.len;
        }
        return error.ContainerNotResponding;
    }

    /// Runs one more process inside a running container.
    pub fn exec(self: *Manager, id: []const u8, command: []const []const u8, extra_env: []const []const u8, use_tty: bool) !u8 {
        const cfg = try self.loadConfig(id);
        const st = try self.loadState(id);
        if (!std.mem.eql(u8, st.status, "running")) {
            sys.eprint("error: container {s} is not running\n", .{cfg.name});
            return error.NotRunning;
        }
        var env: std.ArrayList([]const u8) = .empty;
        for (cfg.env) |e| try setEnv(self.a, &env, e);
        if (use_tty) try addDefaultTerm(self.a, &env);
        for (extra_env) |e| try setEnv(self.a, &env, e);

        const vfs = try self.makeVfs(&cfg);
        var patched = cfg;
        patched.env = env.items;
        const exec_path = try self.findExecutable(vfs, &patched, command[0]);

        var msg: std.ArrayList(u8) = .empty;
        try msg.append(self.a, if (use_tty) control.op_exec_tty else control.op_exec);
        const field = struct {
            fn f(a: Allocator, m: *std.ArrayList(u8), s: []const u8) !void {
                try m.appendSlice(a, s);
                try m.append(a, 0);
            }
        }.f;
        try field(self.a, &msg, cfg.workdir);
        try field(self.a, &msg, exec_path);
        try field(self.a, &msg, try std.fmt.allocPrint(self.a, "{d}", .{command.len}));
        for (command) |s| try field(self.a, &msg, s);
        try field(self.a, &msg, try std.fmt.allocPrint(self.a, "{d}", .{env.items.len}));
        for (env.items) |s| try field(self.a, &msg, s);

        const fd = try self.connectCtl(id, st.shim_pid);
        defer sys.close(fd);
        var pty: ?sys.Pty = null;
        var stdio = [3]i32{ 0, 1, 2 };
        if (use_tty) {
            const p = try sys.openPty();
            pty = p;
            tty.copySize(p.master);
            stdio = @splat(p.slave);
        }
        var pid_buf: [4]u8 align(4) = undefined;
        const n = try self.request(fd, st.shim_pid, msg.items, &stdio, &pid_buf);
        if (n != 4) return error.ExecFailed;
        fwd_pid = std.mem.readInt(i32, &pid_buf, .little);
        for ([_]linux.SIG{ .TERM, .HUP, .INT, .QUIT }) |s| installForwarder(s);

        if (pty) |p| {
            sys.close(p.slave);
            tty.relay(p.master, .{ .done_fd = fd });
        }

        var none: [0]i32 = undefined;
        var code: [1]u8 = undefined;
        while (true) {
            const got = control.recv(fd, &code, &none, -1) catch {
                if (sys.last == .INTR) continue;
                return error.Sys;
            };
            // The connection closes without a code if the container stopped.
            return if (got.len == 1) code[0] else 137;
        }
    }

    /// Current usage of a running container.
    pub fn stats(self: *Manager, id: []const u8, shim_pid: i32) !Stats {
        const fd = try self.connectCtl(id, shim_pid);
        defer sys.close(fd);
        var buf: [128]u8 = undefined;
        const n = try self.request(fd, shim_pid, &[1]u8{control.op_stats}, &.{}, &buf);
        var it = std.mem.tokenizeScalar(u8, buf[0..n], ' ');
        return .{
            .pids = try std.fmt.parseInt(u64, it.next() orelse return error.BadReply, 10),
            .memory = try std.fmt.parseInt(u64, it.next() orelse return error.BadReply, 10),
            .cpu_ms = try std.fmt.parseInt(u64, it.next() orelse return error.BadReply, 10),
        };
    }

    pub fn stop(self: *Manager, id: []const u8, timeout_s: u32) !void {
        const st = try self.loadState(id);
        if (!std.mem.eql(u8, st.status, "running") and !std.mem.eql(u8, st.status, "restarting")) return;
        try sys.writeFile(self.file(id, "stop-requested"), "", 0o600);
        const cfg = try self.loadConfig(id);
        if (st.pid > 0) _ = linux.kill(st.pid, parseSignal(cfg.stop_signal));
        var waited: u32 = 0;
        while (waited < timeout_s * 10) : (waited += 1) {
            const now = try self.loadState(id);
            if (std.mem.eql(u8, now.status, "exited")) return;
            sys.sleepMs(100);
        }
        const now = try self.loadState(id);
        if (now.pid > 0) _ = linux.kill(now.pid, .KILL);
        if (st.shim_pid > 0 and now.pid == 0) _ = linux.kill(st.shim_pid, .TERM);
        waited = 0;
        while (waited < 50) : (waited += 1) {
            const s = try self.loadState(id);
            if (std.mem.eql(u8, s.status, "exited")) return;
            sys.sleepMs(100);
        }
    }

    fn removeFiles(self: *Manager, id: []const u8) void {
        if (self.loadConfig(id)) |cfg| {
            if (cfg.ip.len > 0) {
                var p = Path.of(self.store.path(&.{ "net", "ips", cfg.ip })) catch return;
                sys.unlink(p.z()) catch {};
            }
        } else |_| {}
        sys.rmrf(self.dir(id)) catch |e| sys.eprint("warning: could not remove {s}: {s}\n", .{ id, @errorName(e) });
    }

    pub fn remove(self: *Manager, id: []const u8, force: bool) !void {
        const st = try self.loadState(id);
        const live = std.mem.eql(u8, st.status, "running") or std.mem.eql(u8, st.status, "restarting");
        if (live) {
            if (!force) {
                sys.eprint("error: container is running; stop it first or use -f\n", .{});
                return error.Running;
            }
            try self.stop(id, 2);
        }
        self.removeFiles(id);
    }

    /// True when a container, running or not, or another image is built on
    /// `image_id`.
    pub fn imageInUse(self: *Manager, image_id: []const u8) !bool {
        for (try self.listIds()) |id| {
            const cfg = self.loadConfig(id) catch continue;
            if (std.mem.eql(u8, cfg.image_id, image_id)) return true;
        }
        for (try self.store.listDir("images")) |other| {
            const parent = sys.readFileAlloc(self.a, self.store.path(&.{ "images", other, "parent" }), 128) catch continue;
            if (std.mem.eql(u8, parent, image_id)) return true;
        }
        return false;
    }
};

/// Accepts `SIGTERM`, `TERM` or a signal number.
pub fn parseSignal(name: []const u8) linux.SIG {
    if (std.fmt.parseInt(u32, name, 10) catch null) |n| return @fromBackingInt(n);
    var buf: [16]u8 = undefined;
    if (name.len > buf.len) return .TERM;
    const upper = std.ascii.upperString(&buf, name);
    const bare = if (std.mem.startsWith(u8, upper, "SIG")) upper[3..] else upper;
    return std.meta.stringToEnum(linux.SIG, bare) orelse .TERM;
}

/// Reads an OCI `Healthcheck` object. Times are in nanoseconds there.
fn parseHealth(a: Allocator, v: ?std.json.Value) !?Health {
    const val = v orelse return null;
    if (val != .object) return null;
    const test_cmd = try stringArray(a, val.object.get("Test"));
    if (test_cmd.len == 0 or std.mem.eql(u8, test_cmd[0], "NONE")) return null;
    var h: Health = .{ .command = &.{} };
    if (std.mem.eql(u8, test_cmd[0], "CMD-SHELL")) {
        if (test_cmd.len < 2) return null;
        const argv = try a.alloc([]const u8, 3);
        argv[0] = "/bin/sh";
        argv[1] = "-c";
        argv[2] = test_cmd[1];
        h.command = argv;
    } else if (std.mem.eql(u8, test_cmd[0], "CMD")) {
        if (test_cmd.len < 2) return null;
        h.command = test_cmd[1..];
    } else {
        return null;
    }
    const ms = struct {
        fn f(o: std.json.ObjectMap, key: []const u8) u64 {
            const x = o.get(key) orelse return 0;
            return if (x == .integer and x.integer > 0) @as(u64, @intCast(x.integer)) / std.time.ns_per_ms else 0;
        }
    }.f;
    if (ms(val.object, "Interval") != 0) h.interval_ms = ms(val.object, "Interval");
    if (ms(val.object, "Timeout") != 0) h.timeout_ms = ms(val.object, "Timeout");
    h.start_ms = ms(val.object, "StartPeriod");
    if (val.object.get("Retries")) |r| {
        if (r == .integer and r.integer > 0) h.retries = @intCast(r.integer);
    }
    return h;
}

fn parseIp(s: []const u8) [4]u8 {
    var out: [4]u8 = .{ 0, 0, 0, 0 };
    var it = std.mem.splitScalar(u8, s, '.');
    for (&out) |*b| b.* = std.fmt.parseInt(u8, it.next() orelse "0", 10) catch 0;
    return out;
}

pub fn setEnv(a: Allocator, env: *std.ArrayList([]const u8), entry: []const u8) !void {
    const eq = std.mem.indexOfScalar(u8, entry, '=') orelse return;
    const key = entry[0 .. eq + 1];
    for (env.items) |*e| {
        if (std.mem.startsWith(u8, e.*, key)) {
            e.* = entry;
            return;
        }
    }
    try env.append(a, entry);
}

fn claimsLive(st: *const State) bool {
    return std.mem.eql(u8, st.status, "running") or std.mem.eql(u8, st.status, "restarting");
}

fn supervisorAlive(st: *const State) bool {
    return sys.sameProcess(st.shim_pid, st.shim_start);
}

/// Programs need TERM to drive a terminal; Docker sets the same default.
fn addDefaultTerm(a: Allocator, env: *std.ArrayList([]const u8)) !void {
    for (env.items) |e| {
        if (std.mem.startsWith(u8, e, "TERM=")) return;
    }
    try env.append(a, "TERM=xterm");
}

fn portAvailable(port: u16) bool {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    const fd: i32 = @intCast(rc);
    defer sys.close(fd);
    const one: u32 = 1;
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @ptrCast(&one), 4);
    var sa: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = 0 };
    return linux.errno(linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) == .SUCCESS;
}

const log_max: u64 = 10 * 1024 * 1024;

const LineBuf = struct { data: [65536]u8 = undefined, len: usize = 0 };

const Log = struct {
    path: []const u8,
    fd: i32,
    size: u64,

    fn open(path: []const u8) Log {
        var p = Path.of(path) catch linux.exit_group(1);
        const fd = sys.open(p.z(), sys.O_WRONLY | sys.O_CREAT | sys.O_APPEND, 0o600) catch linux.exit_group(1);
        var st: sys.Stat = undefined;
        sys.stat(p.z(), &st) catch {};
        return .{ .path = path, .fd = fd, .size = @intCast(st.size) };
    }

    fn rotate(self: *Log) void {
        sys.close(self.fd);
        var cur = Path.of(self.path) catch return;
        var old = Path.join(self.path, ".1") catch return;
        sys.rename(cur.z(), old.z()) catch {};
        self.* = Log.open(self.path);
    }

    /// Writes one line in the CRI log format.
    fn line(self: *Log, stream: []const u8, tag: u8, msg: []const u8) void {
        var ts: [40]u8 = undefined;
        var head: [80]u8 = undefined;
        const t = sys.fmtTime(&ts, sys.nowNs());
        const h = std.fmt.bufPrint(&head, "{s} {s} {c} ", .{ t, stream, tag }) catch return;
        sys.writeAll(self.fd, h) catch {};
        sys.writeAll(self.fd, msg) catch {};
        sys.writeAll(self.fd, "\n") catch {};
        self.size += h.len + msg.len + 1;
        if (self.size > log_max) self.rotate();
    }
};

fn drain(log: *Log, buf: *LineBuf, stream: []const u8, fd: i32, tee_fd: i32) bool {
    if (buf.len == buf.data.len) {
        log.line(stream, 'P', &buf.data);
        buf.len = 0;
    }
    const n = linux.read(fd, buf.data[buf.len..].ptr, buf.data.len - buf.len);
    const e = linux.errno(n);
    if (e == .INTR or e == .AGAIN) return true;
    if (e != .SUCCESS or n == 0) return false;
    const fresh = buf.data[buf.len..][0..n];
    if (tee_fd >= 0) sys.writeAll(tee_fd, fresh) catch {};
    buf.len += n;
    var start: usize = 0;
    while (std.mem.indexOfScalarPos(u8, buf.data[0..buf.len], start, '\n')) |nl| {
        log.line(stream, 'F', buf.data[start..nl]);
        start = nl + 1;
    }
    std.mem.copyForwards(u8, buf.data[0 .. buf.len - start], buf.data[start..buf.len]);
    buf.len -= start;
    return true;
}

const TtyLog = struct {
    log: Log,
    buf: LineBuf,

    fn write(ctx: ?*anyopaque, data: []const u8) void {
        const self: *TtyLog = @ptrCast(@alignCast(ctx.?));
        var rest = data;
        while (rest.len > 0) {
            if (self.buf.len == self.buf.data.len) {
                self.log.line("stdout", 'P', &self.buf.data);
                self.buf.len = 0;
            }
            const n = @min(rest.len, self.buf.data.len - self.buf.len);
            @memcpy(self.buf.data[self.buf.len..][0..n], rest[0..n]);
            self.buf.len += n;
            rest = rest[n..];
            var start: usize = 0;
            while (std.mem.indexOfScalarPos(u8, self.buf.data[0..self.buf.len], start, '\n')) |nl| {
                self.log.line("stdout", 'F', std.mem.trimEnd(u8, self.buf.data[start..nl], "\r"));
                start = nl + 1;
            }
            std.mem.copyForwards(u8, self.buf.data[0 .. self.buf.len - start], self.buf.data[start..self.buf.len]);
            self.buf.len -= start;
        }
    }
};

/// Connects the user's terminal to a container and logs what it prints.
fn runTtyRelay(master: i32, path: []const u8) noreturn {
    const ignore: linux.Sigaction = .{
        .handler = .{ .handler = linux.SIG.IGN },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = 0,
    };
    _ = linux.sigaction(.PIPE, &ignore, null);
    var sink: TtyLog = .{ .log = Log.open(path), .buf = undefined };
    sink.buf.len = 0;
    tty.relay(master, .{ .ctx = &sink, .on_output = TtyLog.write });
    if (sink.buf.len > 0) sink.log.line("stdout", 'P', sink.buf.data[0..sink.buf.len]);
    linux.exit_group(0);
}

fn runLogger(out_fd: i32, err_fd: i32, path: []const u8, tee: bool) noreturn {
    var log = Log.open(path);
    var bufs: [2]LineBuf = undefined;
    bufs[0].len = 0;
    bufs[1].len = 0;
    var pfds = [2]linux.pollfd{
        .{ .fd = out_fd, .events = linux.POLL.IN, .revents = 0 },
        .{ .fd = err_fd, .events = linux.POLL.IN, .revents = 0 },
    };
    const names = [2][]const u8{ "stdout", "stderr" };
    const tees = [2]i32{ if (tee) 1 else -1, if (tee) 2 else -1 };
    var open_count: u32 = 2;
    while (open_count > 0) {
        const rc = linux.poll(&pfds, 2, -1);
        if (linux.errno(rc) == .INTR) continue;
        for (&pfds, 0..) |*p, i| {
            if (p.fd < 0 or p.revents == 0) continue;
            if (!drain(&log, &bufs[i], names[i], p.fd, tees[i])) {
                if (bufs[i].len > 0) log.line(names[i], 'P', bufs[i].data[0..bufs[i].len]);
                p.fd = -1;
                open_count -= 1;
            }
        }
    }
    linux.exit_group(0);
}

/// Prints a container's log. `follow` keeps going until it exits.
pub fn printLogs(mgr: *Manager, id: []const u8, follow: bool, tail: ?usize, timestamps: bool) !void {
    const path = mgr.store.path(&.{ "containers", id, "ctr.log" });
    var p = try Path.of(path);
    const fd = sys.open(p.z(), 0, 0) catch {
        if (sys.last == .NOENT) return;
        return error.Sys;
    };
    defer sys.close(fd);

    var rest: std.ArrayList(u8) = .empty;
    const data = try sys.readFileAlloc(mgr.a, path, 1 << 30);
    if (tail) |n| {
        var count: usize = 0;
        var i = data.len;
        while (i > 0) : (i -= 1) {
            if (data[i - 1] != '\n') continue;
            if (count == n) break;
            count += 1;
        }
        emit(data[i..], timestamps, &rest, mgr.a);
    } else {
        emit(data, timestamps, &rest, mgr.a);
    }
    if (!follow) return;
    _ = linux.lseek(fd, @intCast(data.len), 0);
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = try sys.read(fd, &buf);
        if (n == 0) {
            const st = try mgr.loadState(id);
            if (std.mem.eql(u8, st.status, "exited")) return;
            sys.sleepMs(200);
            continue;
        }
        emit(buf[0..n], timestamps, &rest, mgr.a);
    }
}

fn emit(chunk: []const u8, timestamps: bool, rest: *std.ArrayList(u8), a: Allocator) void {
    rest.appendSlice(a, chunk) catch return;
    var start: usize = 0;
    while (std.mem.indexOfScalarPos(u8, rest.items, start, '\n')) |nl| {
        const line = rest.items[start..nl];
        start = nl + 1;
        if (timestamps) {
            sys.print("{s}\n", .{line});
            continue;
        }
        var it = std.mem.splitScalar(u8, line, ' ');
        _ = it.next();
        const stream = it.next() orelse "stdout";
        const tag = it.next() orelse "F";
        const msg = it.rest();
        const fd: i32 = if (std.mem.eql(u8, stream, "stderr")) 2 else 1;
        sys.writeAll(fd, msg) catch {};
        if (tag.len > 0 and tag[0] == 'F') sys.writeAll(fd, "\n") catch {};
    }
    std.mem.copyForwards(u8, rest.items[0 .. rest.items.len - start], rest.items[start..]);
    rest.shrinkRetainingCapacity(rest.items.len - start);
}
