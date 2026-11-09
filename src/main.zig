//! PocketDock: run OCI containers on Android, without root.

const std = @import("std");
const builtin = @import("builtin");
const sys = @import("sys.zig");
const arch = @import("arch.zig");
const dns = @import("dns.zig");
const registry = @import("registry.zig");
const doctor = @import("doctor.zig");
const container = @import("container.zig");
const quota = @import("quota.zig");
const Store = @import("store.zig").Store;
const Manager = container.Manager;
const Allocator = std.mem.Allocator;

const version = "0.1.0";

const usage =
    \\PocketDock: run OCI containers on Android, without root.
    \\
    \\Usage: pdock <command> [options]
    \\
    \\Containers
    \\  run [options] IMAGE [COMMAND...]   Create and start a container
    \\      -d, --detach                   Run in the background
    \\      -it, -t                        Attach a terminal
    \\      --name NAME                    Name the container
    \\      -e, --env KEY=VALUE            Set an environment variable
    \\      -p, --publish [HOST:]PORT      Publish a container port
    \\      -v, --volume HOST:GUEST[:ro]   Mount a host directory
    \\      -w, --workdir DIR              Working directory
    \\      -u, --user USER[:GROUP]        User to run as
    \\      --hostname NAME                Container hostname
    \\      --entrypoint CMD               Override the image entrypoint
    \\      --restart POLICY               no, always, on-failure[:N], unless-stopped
    \\      --rm                           Remove the container when it exits
    \\      --network MODE                 bridge (default), private or none
    \\      -m, --memory SIZE              Memory limit, e.g. 512m or 2g
    \\      --cpus N                       CPU quota, e.g. 0.5
    \\      --cpuset-cpus LIST             Usable CPUs, e.g. 0-3,6
    \\      --pids-limit N                 Maximum processes and threads
    \\  start NAME          Start a stopped container
    \\  stop [-t SEC] NAME  Stop a container
    \\  restart NAME        Restart a container
    \\  rm [-f] NAME        Remove a container
    \\  ps [-a]             List containers
    \\  stats               Live CPU, memory and process counts
    \\  logs [-f] [-t] [--tail N] NAME
    \\  exec [-it] [-e KEY=VALUE] NAME COMMAND...
    \\  inspect NAME        Print a container's configuration and state as JSON
    \\
    \\Images
    \\  pull IMAGE          Download an image
    \\  images              List images
    \\  rmi IMAGE           Remove an image
    \\
    \\System
    \\  doctor              Report what this device's kernel allows
    \\  version
    \\
    \\Environment: POCKETDOCK_ROOT (data directory), POCKETDOCK_DNS, POCKETDOCK_TRACE
    \\
;

const Ctx = struct {
    a: Allocator,
    gpa: Allocator,
    io: std.Io,
    store: Store,
    mgr: *Manager,
};

fn die(comptime f: []const u8, a: anytype) noreturn {
    sys.eprint("error: " ++ f ++ "\n", a);
    sys.linux.exit_group(1);
}

fn dataRoot(a: Allocator, env: *std.process.Environ.Map) ![]const u8 {
    if (env.get("POCKETDOCK_ROOT")) |r| return a.dupe(u8, r);
    const home = env.get("HOME") orelse "";
    if (home.len > 1) return std.fmt.allocPrint(a, "{s}/.pocketdock", .{home});
    // `adb shell` has HOME=/, which is not writable.
    var buf: [sys.PATH_MAX]u8 = undefined;
    const n = try sys.ck(sys.linux.getcwd(&buf, buf.len));
    return std.fmt.allocPrint(a, "{s}/.pocketdock", .{buf[0 .. n - 1]});
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2 or std.mem.eql(u8, args[1], "help") or std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h")) {
        sys.print("{s}", .{usage});
        return;
    }
    const cmd: []const u8 = args[1];
    const rest: []const [:0]const u8 = args[2..];

    if (std.mem.eql(u8, cmd, "version")) {
        sys.print("pdock {s} ({s}, zig {s})\n", .{ version, arch.oci_arch, builtin.zig_version_string });
        return;
    }

    const root = try dataRoot(arena, init.environ_map);
    try sys.mkdirP(root, 0o700);

    if (std.mem.eql(u8, cmd, "doctor")) return doctor.run(root);

    const io = dns.wrapIo(init.io, init.environ_map.get("POCKETDOCK_DNS"));
    const store = try Store.init(arena, root);
    const mgr = try arena.create(Manager);
    mgr.* = .{
        .a = arena,
        .gpa = init.gpa,
        .store = store,
        .debug = init.environ_map.get("POCKETDOCK_TRACE") != null,
    };
    var ctx: Ctx = .{ .a = arena, .gpa = init.gpa, .io = io, .store = store, .mgr = mgr };

    const commands = .{
        .{ "run", cmdRun },
        .{ "start", cmdStart },
        .{ "stop", cmdStop },
        .{ "restart", cmdRestart },
        .{ "rm", cmdRm },
        .{ "ps", cmdPs },
        .{ "stats", cmdStats },
        .{ "logs", cmdLogs },
        .{ "exec", cmdExec },
        .{ "inspect", cmdInspect },
        .{ "pull", cmdPull },
        .{ "images", cmdImages },
        .{ "rmi", cmdRmi },
    };
    inline for (commands) |c| {
        if (std.mem.eql(u8, cmd, c[0])) {
            c[1](&ctx, rest) catch |e| {
                if (e == error.Sys) die("{s}: {s}", .{ cmd, @tagName(sys.last) });
                die("{s}: {s}", .{ cmd, @errorName(e) });
            };
            return;
        }
    }
    die("unknown command \"{s}\" (try: pdock help)", .{cmd});
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn cmdPull(c: *Ctx, args: []const [:0]const u8) !void {
    if (args.len != 1) die("usage: pdock pull IMAGE", .{});
    _ = try registry.pull(c.a, c.gpa, c.io, c.store, args[0], true);
}

fn parsePort(s: []const u8) !container.PortSpec {
    if (std.mem.indexOfScalar(u8, s, ':')) |i| {
        return .{
            .host = try std.fmt.parseInt(u16, s[0..i], 10),
            .container = try std.fmt.parseInt(u16, s[i + 1 ..], 10),
        };
    }
    const p = try std.fmt.parseInt(u16, s, 10);
    return .{ .host = p, .container = p };
}

fn parseVolume(a: Allocator, s: []const u8) !container.Volume {
    var it = std.mem.splitScalar(u8, s, ':');
    const host = it.next() orelse return error.BadVolume;
    const guest = it.next() orelse return error.BadVolume;
    const opt = it.next() orelse "";
    if (host.len == 0 or guest.len == 0 or guest[0] != '/') return error.BadVolume;
    var abs: []const u8 = host;
    if (host[0] != '/') {
        var buf: [sys.PATH_MAX]u8 = undefined;
        const n = try sys.ck(sys.linux.getcwd(&buf, buf.len));
        abs = try std.fmt.allocPrint(a, "{s}/{s}", .{ buf[0 .. n - 1], host });
    }
    return .{ .host = abs, .guest = guest, .ro = eql(opt, "ro") };
}

fn cmdRun(c: *Ctx, args: []const [:0]const u8) !void {
    var opts: container.CreateOptions = .{ .image = "", .image_id = "" };
    var env: std.ArrayList([]const u8) = .empty;
    var ports: std.ArrayList(container.PortSpec) = .empty;
    var vols: std.ArrayList(container.Volume) = .empty;
    var detach = false;
    var tty = false;
    var i: usize = 0;

    const value = struct {
        fn f(a: []const [:0]const u8, idx: *usize) []const u8 {
            idx.* += 1;
            if (idx.* >= a.len) die("option {s} needs a value", .{a[idx.* - 1]});
            return a[idx.*];
        }
    }.f;

    while (i < args.len) : (i += 1) {
        const o: []const u8 = args[i];
        if (o.len == 0 or o[0] != '-') break;
        if (eql(o, "-d") or eql(o, "--detach")) {
            detach = true;
        } else if (eql(o, "-it") or eql(o, "-ti") or eql(o, "-t") or eql(o, "--tty")) {
            tty = true;
        } else if (eql(o, "-i") or eql(o, "--interactive")) {
            tty = true;
        } else if (eql(o, "--rm")) {
            opts.auto_remove = true;
        } else if (eql(o, "--name")) {
            opts.name = value(args, &i);
        } else if (eql(o, "-e") or eql(o, "--env")) {
            try env.append(c.a, value(args, &i));
        } else if (eql(o, "-p") or eql(o, "--publish")) {
            const v = value(args, &i);
            try ports.append(c.a, parsePort(v) catch die("invalid port mapping \"{s}\"", .{v}));
        } else if (eql(o, "-v") or eql(o, "--volume")) {
            const v = value(args, &i);
            try vols.append(c.a, parseVolume(c.a, v) catch die("invalid volume \"{s}\"", .{v}));
        } else if (eql(o, "-w") or eql(o, "--workdir")) {
            opts.workdir = value(args, &i);
        } else if (eql(o, "-u") or eql(o, "--user")) {
            opts.user = value(args, &i);
        } else if (eql(o, "--hostname")) {
            opts.hostname = value(args, &i);
        } else if (eql(o, "--entrypoint")) {
            opts.entrypoint = value(args, &i);
        } else if (eql(o, "--network") or eql(o, "--net")) {
            const v = value(args, &i);
            if (!eql(v, "bridge") and !eql(v, "private") and !eql(v, "none")) die("invalid network \"{s}\"", .{v});
            opts.network = v;
        } else if (eql(o, "-m") or eql(o, "--memory")) {
            const v = value(args, &i);
            opts.memory = quota.parseSize(v) orelse die("invalid memory size \"{s}\"", .{v});
        } else if (eql(o, "--cpus")) {
            const v = value(args, &i);
            opts.cpus_milli = quota.parseCpus(v) orelse die("invalid cpu quota \"{s}\"", .{v});
        } else if (eql(o, "--cpuset-cpus")) {
            const v = value(args, &i);
            opts.cpuset = quota.parseCpuset(v) orelse die("invalid cpu list \"{s}\"", .{v});
        } else if (eql(o, "--pids-limit")) {
            const v = value(args, &i);
            opts.pids_limit = std.fmt.parseInt(u32, v, 10) catch die("invalid pids limit \"{s}\"", .{v});
        } else if (eql(o, "--restart")) {
            const v = value(args, &i);
            const colon = std.mem.indexOfScalar(u8, v, ':');
            opts.restart = if (colon) |k| v[0..k] else v;
            if (colon) |k| opts.max_retries = std.fmt.parseInt(u32, v[k + 1 ..], 10) catch die("invalid restart policy \"{s}\"", .{v});
            const known = [_][]const u8{ "no", "always", "on-failure", "unless-stopped" };
            var ok = false;
            for (known) |k| ok = ok or eql(opts.restart, k);
            if (!ok) die("invalid restart policy \"{s}\"", .{v});
        } else {
            die("unknown option \"{s}\" for run", .{o});
        }
    }
    if (i >= args.len) die("usage: pdock run [options] IMAGE [COMMAND...]", .{});

    const image: []const u8 = args[i];
    const command = try c.a.alloc([]const u8, args.len - i - 1);
    for (args[i + 1 ..], 0..) |s, k| command[k] = s;

    const image_id = try registry.pull(c.a, c.gpa, c.io, c.store, image, false);
    opts.image = (try registry.parseRef(c.a, image)).name;
    opts.image_id = image_id;
    opts.command = command;
    opts.env = env.items;
    opts.ports = ports.items;
    opts.volumes = vols.items;

    const cfg = try c.mgr.create(opts);
    const attach: container.Attach = if (detach) .detached else if (tty) .tty else .foreground;
    const code = try c.mgr.start(cfg.id, attach);
    if (detach) {
        sys.print("{s}\n", .{cfg.id});
        return;
    }
    sys.linux.exit_group(code);
}

fn cmdStart(c: *Ctx, args: []const [:0]const u8) !void {
    if (args.len != 1) die("usage: pdock start NAME", .{});
    _ = try c.mgr.start(try c.mgr.find(args[0]), .detached);
    sys.print("{s}\n", .{args[0]});
}

fn cmdStop(c: *Ctx, args: []const [:0]const u8) !void {
    var t: u32 = 10;
    var i: usize = 0;
    if (args.len >= 2 and eql(args[0], "-t")) {
        t = try std.fmt.parseInt(u32, args[1], 10);
        i = 2;
    }
    if (i >= args.len) die("usage: pdock stop [-t SEC] NAME", .{});
    for (args[i..]) |n| {
        try c.mgr.stop(try c.mgr.find(n), t);
        sys.print("{s}\n", .{n});
    }
}

fn cmdRestart(c: *Ctx, args: []const [:0]const u8) !void {
    if (args.len != 1) die("usage: pdock restart NAME", .{});
    const id = try c.mgr.find(args[0]);
    try c.mgr.stop(id, 10);
    _ = try c.mgr.start(id, .detached);
    sys.print("{s}\n", .{args[0]});
}

fn cmdRm(c: *Ctx, args: []const [:0]const u8) !void {
    var force = false;
    var i: usize = 0;
    if (args.len >= 1 and eql(args[0], "-f")) {
        force = true;
        i = 1;
    }
    if (i >= args.len) die("usage: pdock rm [-f] NAME", .{});
    for (args[i..]) |n| {
        try c.mgr.remove(try c.mgr.find(n), force);
        sys.print("{s}\n", .{n});
    }
}

fn since(a: Allocator, then: i64) []const u8 {
    const now: i64 = @intCast(@divFloor(sys.nowNs(), std.time.ns_per_s));
    const d = now - then;
    if (d < 60) return std.fmt.allocPrint(a, "{d}s", .{d}) catch "";
    if (d < 3600) return std.fmt.allocPrint(a, "{d}m", .{@divFloor(d, 60)}) catch "";
    if (d < 86400) return std.fmt.allocPrint(a, "{d}h", .{@divFloor(d, 3600)}) catch "";
    return std.fmt.allocPrint(a, "{d}d", .{@divFloor(d, 86400)}) catch "";
}

fn shortImage(name: []const u8) []const u8 {
    const prefix = "docker.io/library/";
    if (std.mem.startsWith(u8, name, prefix)) return name[prefix.len..];
    if (std.mem.startsWith(u8, name, "docker.io/")) return name["docker.io/".len..];
    return name;
}

fn cmdPs(c: *Ctx, args: []const [:0]const u8) !void {
    const all = args.len > 0 and (eql(args[0], "-a") or eql(args[0], "--all"));
    sys.print("{s: <14}{s: <20}{s: <34}{s: <20}{s}\n", .{ "ID", "NAME", "IMAGE", "STATUS", "PORTS" });
    for (try c.mgr.listIds()) |id| {
        const cfg = c.mgr.loadConfig(id) catch continue;
        const st = c.mgr.loadState(id) catch continue;
        const running = eql(st.status, "running") or eql(st.status, "restarting");
        if (!all and !running) continue;
        const status = if (eql(st.status, "running"))
            try std.fmt.allocPrint(c.a, "Up {s}", .{since(c.a, st.started_at)})
        else if (eql(st.status, "exited"))
            try std.fmt.allocPrint(c.a, "Exited ({d})", .{st.exit_code})
        else
            st.status;
        var ports: std.ArrayList(u8) = .empty;
        for (st.ports, 0..) |p, i| {
            if (i > 0) try ports.appendSlice(c.a, ", ");
            try ports.print(c.a, "{d}->{d}", .{ p.host, p.container });
        }
        const image = shortImage(cfg.image);
        sys.print("{s: <14}{s: <20}{s: <34}{s: <20}{s}\n", .{ id, cfg.name, image, status, ports.items });
    }
}

fn human(a: Allocator, n: u64) []const u8 {
    const v: f64 = @floatFromInt(n);
    if (n >= 1 << 30) return std.fmt.allocPrint(a, "{d:.2}G", .{v / (1 << 30)}) catch "";
    if (n >= 1 << 20) return std.fmt.allocPrint(a, "{d:.1}M", .{v / (1 << 20)}) catch "";
    return std.fmt.allocPrint(a, "{d}K", .{n / 1024}) catch "";
}

fn cmdStats(c: *Ctx, _: []const [:0]const u8) !void {
    const Row = struct { id: []const u8, name: []const u8, limit: u64, shim: i32, first: container.Stats };
    var rows: std.ArrayList(Row) = .empty;
    for (try c.mgr.listIds()) |id| {
        const cfg = c.mgr.loadConfig(id) catch continue;
        const st = c.mgr.loadState(id) catch continue;
        if (!eql(st.status, "running")) continue;
        const s = c.mgr.stats(id, st.shim_pid) catch continue;
        try rows.append(c.a, .{ .id = id, .name = cfg.name, .limit = cfg.memory, .shim = st.shim_pid, .first = s });
    }
    sys.print("{s: <20}{s: <10}{s: <22}{s}\n", .{ "NAME", "CPU %", "MEM / LIMIT", "PIDS" });
    if (rows.items.len == 0) return;
    sys.sleepMs(1000);
    for (rows.items) |r| {
        const s = c.mgr.stats(r.id, r.shim) catch continue;
        const cpu = @as(f64, @floatFromInt(s.cpu_ms -| r.first.cpu_ms)) / 10.0;
        const mem = try std.fmt.allocPrint(c.a, "{s} / {s}", .{ human(c.a, s.memory), if (r.limit > 0) human(c.a, r.limit) else "-" });
        sys.print("{s: <20}{d: <10.1}{s: <22}{d}\n", .{ r.name, cpu, mem, s.pids });
    }
}

fn cmdLogs(c: *Ctx, args: []const [:0]const u8) !void {
    var follow = false;
    var ts = false;
    var tail: ?usize = null;
    var name: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const o: []const u8 = args[i];
        if (eql(o, "-f") or eql(o, "--follow")) {
            follow = true;
        } else if (eql(o, "-t") or eql(o, "--timestamps")) {
            ts = true;
        } else if (eql(o, "--tail")) {
            i += 1;
            if (i >= args.len) die("--tail needs a value", .{});
            tail = try std.fmt.parseInt(usize, args[i], 10);
        } else {
            name = o;
        }
    }
    try container.printLogs(c.mgr, try c.mgr.find(name orelse die("usage: pdock logs [-f] NAME", .{})), follow, tail, ts);
}

fn cmdExec(c: *Ctx, args: []const [:0]const u8) !void {
    var tty = false;
    var env: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const o: []const u8 = args[i];
        if (o.len == 0 or o[0] != '-') break;
        if (eql(o, "-it") or eql(o, "-ti") or eql(o, "-t") or eql(o, "-i")) {
            tty = true;
        } else if (eql(o, "-e")) {
            i += 1;
            if (i >= args.len) die("-e needs a value", .{});
            try env.append(c.a, args[i]);
        } else {
            die("unknown option \"{s}\" for exec", .{o});
        }
    }
    if (i + 1 >= args.len) die("usage: pdock exec [-it] NAME COMMAND...", .{});
    const id = try c.mgr.find(args[i]);
    const command = try c.a.alloc([]const u8, args.len - i - 1);
    for (args[i + 1 ..], 0..) |s, k| command[k] = s;
    sys.linux.exit_group(try c.mgr.exec(id, command, env.items, tty));
}

fn cmdInspect(c: *Ctx, args: []const [:0]const u8) !void {
    if (args.len != 1) die("usage: pdock inspect NAME", .{});
    const id = try c.mgr.find(args[0]);
    const data = .{ .config = try c.mgr.loadConfig(id), .state = try c.mgr.loadState(id) };
    sys.print("{s}\n", .{try std.json.Stringify.valueAlloc(c.a, data, .{ .whitespace = .indent_2 })});
}

fn cmdImages(c: *Ctx, _: []const [:0]const u8) !void {
    sys.print("{s: <48}{s}\n", .{ "IMAGE", "ID" });
    for (try c.store.listRefs()) |r| {
        sys.print("{s: <48}{s}\n", .{ r.ref, r.id[0..12] });
    }
}

fn cmdRmi(c: *Ctx, args: []const [:0]const u8) !void {
    if (args.len != 1) die("usage: pdock rmi IMAGE", .{});
    const ref = try registry.parseRef(c.a, args[0]);
    const id = c.store.getRef(ref.name) orelse die("no such image: {s}", .{args[0]});
    if (try c.mgr.imageInUse(id)) die("image is used by a container; remove the container first", .{});
    c.store.unsetRef(ref.name);
    for (try c.store.listRefs()) |r| {
        if (eql(r.id, id)) {
            sys.print("Untagged {s}\n", .{ref.name});
            return;
        }
    }
    try sys.rmrf(c.store.path(&.{ "images", id }));
    sys.print("Deleted {s}\n", .{id[0..12]});
}
