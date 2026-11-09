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
const quota = @import("quota.zig");
const Store = @import("store.zig").Store;
const Allocator = std.mem.Allocator;
const Path = sys.Path;
const linux = sys.linux;

pub const PortSpec = struct { container: u16, host: u16 };
pub const Volume = struct { host: []const u8, guest: []const u8, ro: bool = false };

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
    memory: u64 = 0,
    cpus_milli: u32 = 0,
    cpuset: u64 = 0,
    pids_limit: u32 = 0,
};

pub const PortEntry = struct { container: u16, host: u16 };

pub const State = struct {
    /// "created", "running", "restarting" or "exited".
    status: []const u8 = "created",
    pid: i32 = 0,
    shim_pid: i32 = 0,
    exit_code: i32 = 0,
    started_at: i64 = 0,
    finished_at: i64 = 0,
    restarts: u32 = 0,
    ports: []const PortEntry = &.{},
    oom_killed: bool = false,
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
    memory: u64 = 0,
    cpus_milli: u32 = 0,
    cpuset: u64 = 0,
    pids_limit: u32 = 0,
};

pub const Stats = struct { pids: u64, memory: u64, cpu_ms: u64 };

pub const Attach = enum { detached, foreground, tty };

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

fn stringArray(a: Allocator, v: ?std.json.Value) ![]const []const u8 {
    const val = v orelse return &.{};
    if (val != .array) return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (val.array.items) |item| {
        if (item == .string) try out.append(a, item.string);
    }
    return out.items;
}

const PasswdEntry = struct { uid: u32, gid: u32, home: []const u8 };

fn lookupPasswd(a: Allocator, rootfs: []const u8, user: []const u8) ?PasswdEntry {
    const path = std.fmt.allocPrint(a, "{s}/etc/passwd", .{rootfs}) catch return null;
    const data = sys.readFileAlloc(a, path, 1 << 20) catch return null;
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

fn lookupGroup(a: Allocator, rootfs: []const u8, group: []const u8) ?u32 {
    if (std.fmt.parseInt(u32, group, 10) catch null) |g| return g;
    const path = std.fmt.allocPrint(a, "{s}/etc/group", .{rootfs}) catch return null;
    const data = sys.readFileAlloc(a, path, 1 << 20) catch return null;
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

    pub fn rootfs(self: *Manager, image_id: []const u8) []const u8 {
        return self.store.path(&.{ "images", image_id, "rootfs" });
    }

    pub fn loadConfig(self: *Manager, id: []const u8) !Config {
        const data = try sys.readFileAlloc(self.a, self.file(id, "config.json"), 1 << 20);
        return std.json.parseFromSliceLeaky(Config, self.a, data, .{ .ignore_unknown_fields = true });
    }

    pub fn loadState(self: *Manager, id: []const u8) !State {
        const data = try sys.readFileAlloc(self.a, self.file(id, "state.json"), 1 << 20);
        var st = try std.json.parseFromSliceLeaky(State, self.a, data, .{ .ignore_unknown_fields = true });
        // The supervisor died without saying so, e.g. the phone rebooted.
        const live = std.mem.eql(u8, st.status, "running") or std.mem.eql(u8, st.status, "restarting");
        if (live and !sys.pidAlive(st.shim_pid)) {
            st.status = "exited";
            st.exit_code = 137;
            st.pid = 0;
        }
        return st;
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

    fn makeVfs(self: *Manager, cfg: *const Config) !*vfs_mod.Vfs {
        const vfs = try self.a.create(vfs_mod.Vfs);
        vfs.* = .{
            .lower = self.rootfs(cfg.image_id),
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

        const lower = self.rootfs(opts.image_id);
        const user_str = opts.user orelse blk: {
            const u = img.object.get("User") orelse break :blk "";
            break :blk if (u == .string) u.string else "";
        };
        var uid: u32 = 0;
        var gid: u32 = 0;
        var home: []const u8 = "/root";
        if (user_str.len > 0) {
            const colon = std.mem.indexOfScalar(u8, user_str, ':');
            const user = if (colon) |i| user_str[0..i] else user_str;
            if (lookupPasswd(a, lower, user)) |e| {
                uid = e.uid;
                gid = e.gid;
                home = e.home;
            } else if (std.fmt.parseInt(u32, user, 10) catch null) |n| {
                uid = n;
                home = "/";
            } else {
                sys.eprint("error: unknown user \"{s}\" in image\n", .{user});
                return error.UnknownUser;
            }
            if (colon) |i| {
                gid = lookupGroup(a, lower, user_str[i + 1 ..]) orelse return error.UnknownGroup;
            }
        }

        const hostname = opts.hostname orelse id[0..12];
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
            .volumes = opts.volumes,
            .restart = opts.restart,
            .max_retries = opts.max_retries,
            .auto_remove = opts.auto_remove,
            .created_at = @intCast(@divFloor(sys.nowNs(), std.time.ns_per_s)),
            .ip = ip,
            .network = opts.network,
            .memory = opts.memory,
            .cpus_milli = opts.cpus_milli,
            .cpuset = opts.cpuset,
            .pids_limit = opts.pids_limit,
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
        var state: State = .{ .shim_pid = linux.getpid(), .status = "running" };

        // The tracer grows this list with the same allocator.
        var ports: std.ArrayList(tracer.PortMap) = .empty;
        defer ports.deinit(self.gpa);
        for (cfg.ports) |p| {
            try ports.append(self.gpa, .{ .container = p.container, .host = p.host, .fixed = true });
        }

        const vfs = try self.makeVfs(cfg);
        const exec_path = try self.findExecutable(vfs, cfg, cfg.argv[0]);
        const argv = try self.zList(cfg.argv);
        const envp = try self.zList(cfg.env);

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
                runLogger(pipes[0][0], pipes[1][0], self.file(id, "ctr.log"), attach == .foreground);
            }
            sys.close(pipes[0][0]);
            sys.close(pipes[1][0]);
        }

        for ([_]linux.SIG{ .TERM, .HUP, .INT, .QUIT }) |s| {
            if (attach == .tty and (s == .INT or s == .QUIT)) {
                // The terminal already delivers these to the guest.
                var act: linux.Sigaction = .{
                    .handler = .{ .handler = linux.SIG.IGN },
                    .mask = std.mem.zeroes(linux.sigset_t),
                    .flags = 0,
                };
                _ = linux.sigaction(s, &act, null);
            } else {
                installForwarder(s);
            }
        }

        if (cfg.ports.len > 0) {
            const list = try self.a.alloc(PortEntry, cfg.ports.len);
            for (cfg.ports, 0..) |p, i| list[i] = .{ .container = p.container, .host = p.host };
            state.ports = list;
        }

        var ctx: RunCtx = .{ .mgr = self, .id = id, .state = &state, .ready_fd = ready_fd };
        var stdin_fd: i32 = 0;
        if (attach != .tty) stdin_fd = try sys.open("/dev/null", 0, 0);

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
            .new_session = attach != .tty,
            .debug = self.debug,
            .ctx = &ctx,
            .on_start = onStart,
            .on_ports = onPorts,
            .on_oom = onOom,
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
        if (cfg.auto_remove) self.removeFiles(id);
        return code;
    }

    fn shouldRestart(cfg: *const Config, code: u8, restarts: u32) bool {
        if (std.mem.eql(u8, cfg.restart, "always") or std.mem.eql(u8, cfg.restart, "unless-stopped")) return true;
        if (std.mem.eql(u8, cfg.restart, "on-failure")) {
            if (code == 0) return false;
            return cfg.max_retries == 0 or restarts < cfg.max_retries;
        }
        return false;
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
    pub fn exec(self: *Manager, id: []const u8, command: []const []const u8, extra_env: []const []const u8, tty: bool) !u8 {
        _ = tty;
        const cfg = try self.loadConfig(id);
        const st = try self.loadState(id);
        if (!std.mem.eql(u8, st.status, "running")) {
            sys.eprint("error: container {s} is not running\n", .{cfg.name});
            return error.NotRunning;
        }
        var env: std.ArrayList([]const u8) = .empty;
        for (cfg.env) |e| try setEnv(self.a, &env, e);
        for (extra_env) |e| try setEnv(self.a, &env, e);

        const vfs = try self.makeVfs(&cfg);
        var patched = cfg;
        patched.env = env.items;
        const exec_path = try self.findExecutable(vfs, &patched, command[0]);

        var msg: std.ArrayList(u8) = .empty;
        try msg.append(self.a, control.op_exec);
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
        const stdio = [3]i32{ 0, 1, 2 };
        var pid_buf: [4]u8 align(4) = undefined;
        const n = try self.request(fd, st.shim_pid, msg.items, &stdio, &pid_buf);
        if (n != 4) return error.ExecFailed;
        fwd_pid = std.mem.readInt(i32, &pid_buf, .little);
        for ([_]linux.SIG{ .TERM, .HUP, .INT, .QUIT }) |s| installForwarder(s);

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
        if (st.pid > 0) _ = linux.kill(st.pid, .TERM);
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

    /// True when any container, running or not, is based on `image_id`.
    pub fn imageInUse(self: *Manager, image_id: []const u8) !bool {
        for (try self.listIds()) |id| {
            const cfg = self.loadConfig(id) catch continue;
            if (std.mem.eql(u8, cfg.image_id, image_id)) return true;
        }
        return false;
    }
};

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
