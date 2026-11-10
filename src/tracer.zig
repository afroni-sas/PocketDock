//! Runs a container's processes under ptrace and rewrites their syscalls.
//!
//! This is the isolation engine for phones where the kernel offers no
//! namespaces to an unprivileged app. A seccomp filter makes the kernel stop
//! only on the syscalls listed in `syscalls.zig`; everything else (read,
//! write, mmap, ...) runs at native speed.
//!
//! For each stop the tracer works out what the guest meant in container terms
//! and either rewrites the arguments or answers the call itself.

const std = @import("std");
const builtin = @import("builtin");
const sys = @import("sys.zig");
const arch = @import("arch.zig");
const scs = @import("syscalls.zig");
const vfs_mod = @import("vfs.zig");
const control = @import("control.zig");
const quota = @import("quota.zig");
const sysv = @import("sysv.zig");

const Vfs = vfs_mod.Vfs;
const Resolved = vfs_mod.Resolved;
const Path = sys.Path;
const Err = sys.Err;
const linux = sys.linux;
const PT = linux.PTRACE;
const Sc = scs.Sc;

pub const SocketKind = enum { v4, dual, v6only };

pub const PortMap = struct {
    container: u16,
    host: u16,
    /// Published with `-p`, so it may listen on every interface.
    fixed: bool,
    kind: SocketKind = .v4,
};

pub const NetMode = enum {
    /// Internet, LAN and the private network.
    bridge,
    /// The private network only.
    private,
    /// Loopback only.
    none,
};

pub const HealthSpec = struct {
    exec_path: [:0]const u8,
    argv: []const [:0]const u8,
    interval_ms: u64,
    timeout_ms: u64,
    start_ms: u64,
    retries: u32,
};

pub const Spec = struct {
    vfs: *Vfs,
    exec_path: [:0]const u8,
    argv: []const [:0]const u8,
    envp: []const [:0]const u8,
    cwd: []const u8,
    hostname: []const u8,
    uid: u32 = 0,
    gid: u32 = 0,
    ports: *std.ArrayList(PortMap),
    sock_dir: []const u8,
    /// Holds one file per host port in use, across all containers.
    port_dir: []const u8 = "",
    /// Directory of the private network registry; see `store.zig`.
    net_dir: []const u8 = "",
    /// This container's address on the private network.
    ip: [4]u8 = .{ 0, 0, 0, 0 },
    net_mode: NetMode = .bridge,
    /// Prefix that keeps this container's abstract unix sockets to itself.
    ns_id: []const u8 = "",
    /// Where `exec` and `stats` reach this tracer. Empty disables them.
    ctl_path: []const u8 = "",
    limits: quota.Limits = .{},
    health: ?HealthSpec = null,
    on_health: ?*const fn (ctx: ?*anyopaque, status: []const u8) void = null,
    stdout_fd: i32 = 1,
    stderr_fd: i32 = 2,
    stdin_fd: i32 = 0,
    new_session: bool = true,
    /// Makes stdin the controlling terminal of the first process.
    ctty: bool = false,
    /// Lets this container reach the phone's own loopback at 10.88.0.1.
    host_gateway: bool = false,
    /// Holds the files behind System V shared memory segments.
    shm_dir: []const u8 = "",
    /// Logs every intercepted syscall to stderr.
    debug: bool = false,
    ctx: ?*anyopaque = null,
    on_start: ?*const fn (ctx: ?*anyopaque, pid: i32) void = null,
    on_ports: ?*const fn (ctx: ?*anyopaque, ports: []const PortMap) void = null,
    on_oom: ?*const fn (ctx: ?*anyopaque) void = null,
};

const Ids = struct {
    ruid: u32,
    euid: u32,
    suid: u32,
    fsuid: u32,
    rgid: u32,
    egid: u32,
    sgid: u32,
    fsgid: u32,
    groups: [32]u32 = undefined,
    ngroups: u32 = 0,
};

/// How the real argv of a process differs from what it was launched with.
const CmdlineMode = enum { plain, ld_argv0, ld_plain };

const Proc = struct {
    refs: u32 = 1,
    tgid: i32,
    cwd: Path = .{},
    exe: Path = .{},
    pending_exe: Path = .{},
    cmdline: CmdlineMode = .plain,
    pending_cmdline: CmdlineMode = .plain,
    /// What the kernel would call this process: the name it was exec'd under.
    comm: [15]u8 = undefined,
    comm_len: u8 = 0,
    pending_comm: [15]u8 = undefined,
    pending_comm_len: u8 = 0,
    ids: Ids,
    vpid: i32 = 0,
    vppid: i32 = 0,
    vpgid: i32 = 0,
    vsid: i32 = 0,
    real_pgid: i32 = 0,
    /// Connection of the `exec` client waiting for this process to end.
    exec_ctl: i32 = -1,
    cpu_seen: u64 = 0,
};

const Zombie = struct { real: i32, vpid: i32 };

const ExitAction = enum {
    none,
    fix_stat,
    fix_statx,
    fix_readlink,
    fix_sockname,
    fix_uname,
    fix_clone,
    fix_wait,
    fix_waitid,
    fix_setsid,
    fix_setpgid,
    fix_dents,
    fix_sysinfo,
    fix_affinity,
    fix_tty_pgrp,
    fix_tty_sid,
};

/// Syscalls the tracer runs in the guest on its behalf, one after the other.
/// Used when a single guest call needs several real ones.
const Chain = struct {
    active: bool = false,
    /// The next syscall stop is an injected call's entry, not its exit.
    at_entry: bool = false,
    op: enum { shmat, shmdt } = .shmat,
    step: u8 = 0,
    /// The registers to hand back when the chain is over.
    saved: arch.Regs = undefined,
    seg: i32 = 0,
    addr: u64 = 0,
    size: u64 = 0,
    prot: u64 = 0,
    map_flags: u64 = 0,
    fd: i64 = -1,
    result: i64 = 0,
    /// Signals that arrived meanwhile, delivered once the chain is over: a
    /// handler must not run between two injected calls.
    deferred: u64 = 0,
};

const Tracee = struct {
    tid: i32,
    proc: ?*Proc = null,
    /// A SIGSTOP from the kernel is still due and must be swallowed.
    expect_stop: bool = false,
    /// It stopped before its parent's fork event told us who it belongs to.
    parked: bool = false,
    exit: ExitAction = .none,
    a0: u64 = 0,
    a1: u64 = 0,
    a2: u64 = 0,
    /// First stop of a process the tracer forked itself.
    needs_options: bool = false,
    /// A throttling SIGSTOP has been sent and not yet seen.
    stop_pending: bool = false,
    /// CPU quota: keep this task stopped.
    hold: bool = false,
    held: bool = false,
    chain: Chain = .{},
};

const WakeSignals = struct {
    var wake = std.atomic.Value(bool).init(false);

    fn handler(_: linux.SIG) callconv(.c) void {
        wake.store(true, .monotonic);
    }
};

const SockFilter = extern struct { code: u16, jt: u8, jf: u8, k: u32 };
const SockFprog = extern struct { len: u16, filter: [*]const SockFilter };

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_JGE_K: u16 = 0x35;
const BPF_RET_K: u16 = 0x06;
const RET_ALLOW: u32 = 0x7fff0000;
const RET_TRACE: u32 = 0x7ff00000;
const RET_ENOSYS: u32 = 0x00050000 | 38;

const PR_SET_KEEPCAPS: u32 = 8;
const PR_CAPBSET_DROP: u32 = 24;
const PR_SET_SECUREBITS: u32 = 28;
const PR_CAP_AMBIENT: u32 = 47;

const TIOCSCTTY: u32 = 0x540E;
const TIOCGPGRP: u32 = 0x540F;
const TIOCSPGRP: u32 = 0x5410;
const TIOCGSID: u32 = 0x5429;

fn dataArgLow(i: u32) u32 {
    return 16 + 8 * i;
}

fn buildFilter(out: []SockFilter, strict_net: bool) usize {
    var n: usize = 0;
    const emit = struct {
        fn f(o: []SockFilter, i: *usize, code: u16, jt: u8, jf: u8, k: u32) void {
            o[i.*] = .{ .code = code, .jt = jt, .jf = jf, .k = k };
            i.* += 1;
        }
    }.f;
    emit(out, &n, BPF_LD_W_ABS, 0, 0, 4);
    emit(out, &n, BPF_JEQ_K, 1, 0, arch.audit_arch);
    emit(out, &n, BPF_RET_K, 0, 0, RET_ENOSYS);
    emit(out, &n, BPF_LD_W_ABS, 0, 0, 0);
    if (builtin.cpu.arch == .x86_64) {
        // x32 shares the audit arch with x86_64 but has its own numbers.
        emit(out, &n, BPF_JGE_K, 0, 1, 0x40000000);
        emit(out, &n, BPF_RET_K, 0, 0, RET_ENOSYS);
    }
    for (scs.table, 0..) |sc, nr| {
        switch (sc.h) {
            .none => continue,
            .sendto => {
                // Hot on TCP, where the destination is NULL: stop only when
                // there is an address to look at.
                emit(out, &n, BPF_JEQ_K, 0, 6, @intCast(nr));
                emit(out, &n, BPF_LD_W_ABS, 0, 0, dataArgLow(4));
                emit(out, &n, BPF_JEQ_K, 0, 3, 0);
                emit(out, &n, BPF_LD_W_ABS, 0, 0, dataArgLow(4) + 4);
                emit(out, &n, BPF_JEQ_K, 0, 1, 0);
                emit(out, &n, BPF_RET_K, 0, 0, RET_ALLOW);
                emit(out, &n, BPF_RET_K, 0, 0, RET_TRACE);
            },
            .ioctl_pgrp => {
                // Almost every ioctl is left alone: only the terminal calls
                // that carry a process id need translating.
                emit(out, &n, BPF_JEQ_K, 0, 6, @intCast(nr));
                emit(out, &n, BPF_LD_W_ABS, 0, 0, dataArgLow(1));
                emit(out, &n, BPF_JEQ_K, 3, 0, TIOCGPGRP);
                emit(out, &n, BPF_JEQ_K, 2, 0, TIOCSPGRP);
                emit(out, &n, BPF_JEQ_K, 1, 0, TIOCGSID);
                emit(out, &n, BPF_RET_K, 0, 0, RET_ALLOW);
                emit(out, &n, BPF_RET_K, 0, 0, RET_TRACE);
            },
            .prctl_caps => {
                // The guest's root is virtual, so the kernel would refuse
                // these: Android apps run with their capability bits locked.
                emit(out, &n, BPF_JEQ_K, 0, 7, @intCast(nr));
                emit(out, &n, BPF_LD_W_ABS, 0, 0, dataArgLow(0));
                emit(out, &n, BPF_JEQ_K, 4, 0, PR_SET_KEEPCAPS);
                emit(out, &n, BPF_JEQ_K, 3, 0, PR_CAPBSET_DROP);
                emit(out, &n, BPF_JEQ_K, 2, 0, PR_SET_SECUREBITS);
                emit(out, &n, BPF_JEQ_K, 1, 0, PR_CAP_AMBIENT);
                emit(out, &n, BPF_RET_K, 0, 0, RET_ALLOW);
                emit(out, &n, BPF_RET_K, 0, 0, RET_TRACE);
            },
            .setsockopt => {
                // Only IPV6_V6ONLY matters; the rest are frequent and harmless.
                emit(out, &n, BPF_JEQ_K, 0, 6, @intCast(nr));
                emit(out, &n, BPF_LD_W_ABS, 0, 0, dataArgLow(1));
                emit(out, &n, BPF_JEQ_K, 0, 2, 41);
                emit(out, &n, BPF_LD_W_ABS, 0, 0, dataArgLow(2));
                emit(out, &n, BPF_JEQ_K, 1, 0, 26);
                emit(out, &n, BPF_RET_K, 0, 0, RET_ALLOW);
                emit(out, &n, BPF_RET_K, 0, 0, RET_TRACE);
            },
            .sendmsg, .sendmmsg => {
                // The address is behind a pointer, which BPF cannot follow.
                if (!strict_net) continue;
                emit(out, &n, BPF_JEQ_K, 0, 1, @intCast(nr));
                emit(out, &n, BPF_RET_K, 0, 0, RET_TRACE);
            },
            else => {
                emit(out, &n, BPF_JEQ_K, 0, 1, @intCast(nr));
                emit(out, &n, BPF_RET_K, 0, 0, RET_TRACE);
            },
        }
    }
    emit(out, &n, BPF_RET_K, 0, 0, RET_ALLOW);
    return n;
}

fn writeMem(pid: i32, addr: u64, data: []const u8) Err!void {
    const local = [1]std.posix.iovec_const{.{ .base = data.ptr, .len = data.len }};
    const remote = [1]std.posix.iovec_const{.{ .base = @ptrFromInt(addr), .len = data.len }};
    const rc = linux.process_vm_writev(pid, &local, &remote, 0);
    if (linux.errno(rc) == .SUCCESS and rc == data.len) return;
    // Slower, but it also reaches read-only pages and unmapped stack.
    var off: usize = 0;
    while (off < data.len) {
        const a = addr + off;
        const left = data.len - off;
        var word: u64 = 0;
        if (left < 8) _ = try sys.ck(linux.ptrace(PT.PEEKDATA, pid, a, @intFromPtr(&word), 0));
        const n = @min(left, 8);
        @memcpy(std.mem.asBytes(&word)[0..n], data[off..][0..n]);
        _ = try sys.ck(linux.ptrace(PT.POKEDATA, pid, a, word, 0));
        off += n;
    }
}

fn readMem(pid: i32, addr: u64, buf: []u8) Err!void {
    const local = [1]std.posix.iovec{.{ .base = buf.ptr, .len = buf.len }};
    const remote = [1]std.posix.iovec_const{.{ .base = @ptrFromInt(addr), .len = buf.len }};
    const rc = linux.process_vm_readv(pid, &local, &remote, 0);
    if (linux.errno(rc) == .SUCCESS and rc == buf.len) return;
    var off: usize = 0;
    while (off < buf.len) {
        var word: u64 = 0;
        _ = try sys.ck(linux.ptrace(PT.PEEKDATA, pid, addr + off, @intFromPtr(&word), 0));
        const n = @min(buf.len - off, 8);
        @memcpy(buf[off..][0..n], std.mem.asBytes(&word)[0..n]);
        off += n;
    }
}

fn readStr(pid: i32, addr: u64, out: *Path) Err!void {
    if (addr == 0) return sys.fail(.FAULT);
    var off: usize = 0;
    while (off < sys.PATH_MAX - 1) {
        const a = addr + off;
        const n = @min(4096 - (a & 4095), sys.PATH_MAX - 1 - off);
        const chunk = out.buf[off..][0..n];
        try readMem(pid, a, chunk);
        if (std.mem.indexOfScalar(u8, chunk, 0)) |i| {
            out.len = off + i;
            return;
        }
        off += n;
    }
    return sys.fail(.NAMETOOLONG);
}

/// Makes a guest stopped in a chain run one more syscall.
fn injectCall(t: *Tracee, nr: linux.SYS, args: [6]u64) void {
    var r = t.chain.saved;
    arch.rewindSyscall(&r, @backingInt(nr));
    for (args, 0..) |v, i| arch.setArg(&r, i, v);
    arch.setRegs(t.tid, &r) catch {};
    t.chain.at_entry = true;
}

const Ctx = struct {
    tr: *Tracer,
    t: *Tracee,
    p: *Proc,
    regs: arch.Regs,
    scratch: u64,
    dirty: bool = false,
    voided: bool = false,
    trapped: bool = false,

    fn arg(c: *const Ctx, i: usize) u64 {
        return arch.arg(&c.regs, i);
    }

    fn argI32(c: *const Ctx, i: usize) i32 {
        return @bitCast(@as(u32, @truncate(c.arg(i))));
    }

    fn setArg(c: *Ctx, i: usize, v: u64) void {
        arch.setArg(&c.regs, i, v);
        c.dirty = true;
    }

    fn push(c: *Ctx, data: []const u8) Err!u64 {
        c.scratch = (c.scratch - data.len) & ~@as(u64, 7);
        try writeMem(c.t.tid, c.scratch, data);
        return c.scratch;
    }

    fn pushZ(c: *Ctx, s: []const u8) Err!u64 {
        c.scratch = (c.scratch - s.len - 1) & ~@as(u64, 7);
        try writeMem(c.t.tid, c.scratch, s);
        try writeMem(c.t.tid, c.scratch + s.len, "\x00");
        return c.scratch;
    }

    /// Answers the syscall without letting the kernel run it.
    fn finish(c: *Ctx, ret: i64) void {
        c.voided = true;
        arch.setRet(&c.regs, ret);
        c.dirty = true;
    }

    fn finishErr(c: *Ctx, e: sys.E) void {
        c.finish(-@as(i64, @backingInt(e)));
    }

    /// Starts a chain with `first` in place of the current syscall.
    fn beginChain(c: *Ctx, nr: linux.SYS, args: [6]u64) Err!void {
        const ch = &c.t.chain;
        ch.active = true;
        ch.step = 0;
        ch.deferred = 0;
        ch.saved = c.regs;
        if (c.trapped) {
            // The kernel is done with this call, so step back and make the
            // guest execute the syscall instruction again.
            injectCall(c.t, nr, args);
            return;
        }
        ch.at_entry = false;
        try arch.setSysno(c.t.tid, &c.regs, @intCast(@backingInt(nr)));
        for (args, 0..) |v, i| arch.setArg(&c.regs, i, v);
        c.dirty = true;
    }

    fn flush(c: *Ctx) void {
        if (c.voided and !c.trapped) arch.setSysno(c.t.tid, &c.regs, -1) catch {};
        if (c.dirty) arch.setRegs(c.t.tid, &c.regs) catch {};
    }

    fn setPath(c: *Ctx, idx: usize, host: []const u8) Err!void {
        if (c.tr.spec.debug) sys.eprint("  [{d}] -> {s}\n", .{ c.t.tid, host });
        c.setArg(idx, try c.pushZ(host));
    }

    fn fdGuestPath(c: *Ctx, fd: i32, out: *Path) Err!void {
        var name: [64]u8 = undefined;
        const s = std.fmt.bufPrintSentinel(&name, "/proc/{d}/fd/{d}", .{ c.t.tid, fd }, 0) catch unreachable;
        var buf: [sys.PATH_MAX]u8 = undefined;
        const host = sys.readlink(s.ptr, &buf) catch return sys.fail(.BADF);
        if (!try c.tr.vfs.toGuest(host, out)) try out.set(host);
    }

    fn fdHostPath(c: *Ctx, fd: i32, buf: []u8) Err![]u8 {
        var name: [64]u8 = undefined;
        const s = std.fmt.bufPrintSentinel(&name, "/proc/{d}/fd/{d}", .{ c.t.tid, fd }, 0) catch unreachable;
        return sys.readlink(s.ptr, buf) catch sys.fail(.BADF);
    }

    fn absolutize(c: *Ctx, dirfd: i32, rel: []const u8, out: *Path) Err!void {
        if (rel.len > 0 and rel[0] == '/') return out.set(rel);
        if (dirfd == sys.AT_FDCWD) {
            try out.set(c.p.cwd.slice());
        } else {
            try c.fdGuestPath(dirfd, out);
        }
        try out.append("/");
        try out.append(rel);
    }

    fn dirArg(c: *const Ctx, sc: Sc) i32 {
        return if (sc.dir < 0) sys.AT_FDCWD else c.argI32(@intCast(sc.dir));
    }

    fn flagsArg(c: *const Ctx, sc: Sc) u64 {
        return if (sc.flags < 0) 0 else c.arg(@intCast(sc.flags));
    }

    fn guestOf(c: *Ctx, sc: Sc, out: *Path) Err!void {
        var raw: Path = .{};
        try readStr(c.t.tid, c.arg(sc.path), &raw);
        if (raw.len == 0) return sys.fail(.NOENT);
        try c.absolutize(c.dirArg(sc), raw.slice(), out);
    }

    fn resolveArg(c: *Ctx, sc: Sc, follow: bool, r: *Resolved) Err!void {
        var g: Path = .{};
        try c.guestOf(sc, &g);
        try c.tr.vfs.resolve(g.slice(), follow, r);
    }

    fn follows(c: *const Ctx, sc: Sc) bool {
        return !sc.nofollow and (c.flagsArg(sc) & sys.AT_SYMLINK_NOFOLLOW) == 0;
    }

    /// True when an fd-based syscall (`AT_EMPTY_PATH`) has no path to translate.
    fn emptyPath(c: *Ctx, sc: Sc) Err!bool {
        if (sc.flags < 0 or c.flagsArg(sc) & sys.AT_EMPTY_PATH == 0) return false;
        const addr = c.arg(sc.path);
        if (addr == 0) return true;
        var b: [1]u8 = undefined;
        try readMem(c.t.tid, addr, &b);
        return b[0] == 0;
    }
};

pub const Tracer = struct {
    gpa: std.mem.Allocator,
    spec: *const Spec,
    vfs: *Vfs,
    tracees: std.AutoHashMapUnmanaged(i32, *Tracee) = .empty,
    main_tid: i32 = 0,
    main_status: ?u32 = null,
    real_uid: u32,
    real_gid: u32,
    ld_cache: [8]struct { path: Path = .{}, has_argv0: bool = false } = @splat(.{}),
    ld_count: usize = 0,
    next_port: u16 = 20000,
    held: std.ArrayList(u16) = .empty,
    by_vpid: std.AutoHashMapUnmanaged(i32, *Proc) = .empty,
    zombies: std.ArrayList(Zombie) = .empty,
    next_vpid: i32 = 1,
    /// Sockets that called bind(port 0) and have not asked which port they got.
    zero_binds: [16]struct { tgid: i32 = 0, fd: i32 = 0, kind: SocketKind = .v4 } = @splat(.{}),
    zero_next: usize = 0,
    /// Sockets on which the guest set IPV6_V6ONLY.
    v6only: [16]struct { tgid: i32 = 0, fd: i32 = 0, on: bool = false } = @splat(.{}),
    v6only_next: usize = 0,
    host_addrs: [32][4]u8 = undefined,
    host_addr_count: usize = 0,
    host_addrs_at: i128 = 0,
    ctl_fd: i32 = -1,
    filter: [1024]SockFilter = undefined,
    filter_len: usize = 0,
    lower_z: Path = .{},
    fake_seq: u32 = 0,
    cpu_total: u64 = 0,
    throttled: bool = false,
    debt_ms: i64 = 0,
    last_tick: i128 = 0,
    last_mem_check: i128 = 0,
    health_tid: i32 = 0,
    health_deadline: i128 = 0,
    next_health: i128 = 0,
    health_failures: u32 = 0,
    started_at: i128 = 0,
    health_status: []const u8 = "",
    shm: sysv.Table,
    /// Unix sockets cannot be files here, so they live in the abstract namespace.
    unix_abstract: bool = false,

    fn procToReal(ctx: *anyopaque, v: i32) ?i32 {
        const self: *Tracer = @ptrCast(@alignCast(ctx));
        return self.tidToReal(v);
    }

    fn procLookup(ctx: *anyopaque, pid: i32) ?vfs_mod.ProcPaths {
        const self: *Tracer = @ptrCast(@alignCast(ctx));
        const t = self.tracees.get(pid) orelse return null;
        const p = t.proc orelse return null;
        return .{ .cwd = p.cwd.slice(), .exe = p.exe.slice() };
    }

    fn allocVpid(self: *Tracer) i32 {
        // Threads other than the leader keep their real id, so a virtual
        // number must not collide with one.
        while (true) {
            const v = self.next_vpid;
            self.next_vpid += 1;
            if (!self.tracees.contains(v)) return v;
        }
    }

    fn newProc(self: *Tracer, tgid: i32, from: ?*const Proc) !*Proc {
        const p = try self.gpa.create(Proc);
        const vpid = self.allocVpid();
        if (from) |f| {
            p.* = f.*;
            p.refs = 1;
            p.tgid = tgid;
            p.vpid = vpid;
            p.vppid = f.vpid;
            p.exec_ctl = -1;
            p.cpu_seen = 0;
        } else {
            const s = self.spec;
            p.* = .{
                .tgid = tgid,
                .vpid = vpid,
                .vppid = 0,
                .vpgid = vpid,
                .vsid = vpid,
                .real_pgid = tgid,
                .ids = .{
                    .ruid = s.uid,
                    .euid = s.uid,
                    .suid = s.uid,
                    .fsuid = s.uid,
                    .rgid = s.gid,
                    .egid = s.gid,
                    .sgid = s.gid,
                    .fsgid = s.gid,
                },
            };
            try p.cwd.set(s.cwd);
        }
        try self.by_vpid.put(self.gpa, vpid, p);
        return p;
    }

    /// The real pid of a process, including one awaiting its parent's wait().
    fn vToReal(self: *Tracer, v: i32) ?i32 {
        if (self.by_vpid.get(v)) |p| return p.tgid;
        for (self.zombies.items) |z| if (z.vpid == v) return z.real;
        return null;
    }

    /// The real id behind a thread id as the guest knows it. The main thread
    /// of a process is known by its virtual PID, any other by its real id.
    fn tidToReal(self: *Tracer, v: i32) ?i32 {
        if (self.by_vpid.get(v)) |p| return p.tgid;
        if (self.tracees.contains(v)) return v;
        return null;
    }

    fn realToV(self: *Tracer, real: i32, reap: bool) ?i32 {
        if (self.tracees.get(real)) |t| {
            if (t.proc) |p| return if (p.tgid == real) p.vpid else real;
        }
        for (self.zombies.items, 0..) |z, i| {
            if (z.real != real) continue;
            if (reap) _ = self.zombies.swapRemove(i);
            return z.vpid;
        }
        return null;
    }

    fn groupReal(self: *Tracer, vpgid: i32) ?i32 {
        var it = self.by_vpid.valueIterator();
        while (it.next()) |p| if (p.*.vpgid == vpgid) return p.*.real_pgid;
        return null;
    }

    fn forgetProc(self: *Tracer, p: *Proc) void {
        self.shm.gone(p.tgid);
        _ = self.by_vpid.remove(p.vpid);
        // Its parent may still collect it with wait().
        if (p.vppid != 0 and self.by_vpid.contains(p.vppid)) {
            if (self.zombies.items.len >= 1024) _ = self.zombies.orderedRemove(0);
            self.zombies.append(self.gpa, .{ .real = p.tgid, .vpid = p.vpid }) catch {};
        }
        var it = self.by_vpid.valueIterator();
        while (it.next()) |child_p| {
            if (child_p.*.vppid == p.vpid) child_p.*.vppid = 1;
        }
        if (p.exec_ctl >= 0) sys.close(p.exec_ctl);
        self.gpa.destroy(p);
    }

    fn getOrAdd(self: *Tracer, tid: i32) !*Tracee {
        const gop = try self.tracees.getOrPut(self.gpa, tid);
        if (!gop.found_existing) {
            const t = try self.gpa.create(Tracee);
            t.* = .{ .tid = tid };
            gop.value_ptr.* = t;
        }
        return gop.value_ptr.*;
    }

    fn drop(self: *Tracer, tid: i32) void {
        const kv = self.tracees.fetchRemove(tid) orelse return;
        const t = kv.value;
        if (t.proc) |p| {
            p.refs -= 1;
            if (p.refs == 0) self.forgetProc(p);
        }
        self.gpa.destroy(t);
    }

    fn resumeT(_: *Tracer, t: *Tracee, sig: usize) void {
        const req: u32 = if (t.exit != .none or t.chain.active) PT.SYSCALL else PT.CONT;
        _ = linux.ptrace(req, t.tid, 0, sig, 0);
    }

    fn portFree(port: u16) bool {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return false;
        const fd: i32 = @intCast(rc);
        defer sys.close(fd);
        const one: u32 = 1;
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @ptrCast(&one), 4);
        var sa: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = 0 };
        return linux.errno(linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) == .SUCCESS;
    }

    /// Takes exclusive ownership of a host port across containers. Probing
    /// alone is racy: two containers starting together both see it free.
    fn reserve(self: *Tracer, port: u16) bool {
        if (self.spec.port_dir.len == 0) return true;
        var name: [32]u8 = undefined;
        var path = Path.of(self.spec.port_dir) catch return false;
        path.append(std.fmt.bufPrint(&name, "/{d}", .{port}) catch unreachable) catch return false;
        // With its start time: after a reboot, another process may have this pid.
        var num: [48]u8 = undefined;
        const me = std.fmt.bufPrintSentinel(&num, "{d}.{d}", .{ linux.getpid(), sys.procStart(linux.getpid()) }, 0) catch unreachable;
        for (0..2) |_| {
            // A symlink appears atomically with its target, so unlike a file
            // that gets written after being created, there is no moment when
            // a live lock looks empty and could be mistaken for a stale one.
            sys.symlink(me.ptr, path.z()) catch {
                if (sys.last != .EXIST) return false;
                var buf: [48]u8 = undefined;
                const target = sys.readlink(path.z(), &buf) catch continue;
                var parts = std.mem.splitScalar(u8, target, '.');
                const owner = std.fmt.parseInt(i32, parts.first(), 10) catch 0;
                const started = std.fmt.parseInt(u64, parts.next() orelse "0", 10) catch 0;
                if (owner == linux.getpid()) return true;
                if (owner != 0 and sys.sameProcess(owner, started)) return false;
                sys.unlink(path.z()) catch return false;
                continue;
            };
            self.held.append(self.gpa, port) catch {};
            return true;
        }
        return false;
    }

    fn release(self: *Tracer, port: u16) void {
        var name: [32]u8 = undefined;
        var path = Path.of(self.spec.port_dir) catch return;
        path.append(std.fmt.bufPrint(&name, "/{d}", .{port}) catch unreachable) catch return;
        sys.unlink(path.z()) catch {};
    }

    fn claim(self: *Tracer, port: u16) bool {
        if (!self.reserve(port)) return false;
        if (portFree(port)) return true;
        if (self.spec.port_dir.len > 0) {
            self.release(port);
            _ = self.held.pop();
        }
        return false;
    }

    fn publishPort(self: *Tracer, container_port: u16, host: u16) void {
        if (self.spec.net_dir.len == 0) return;
        var buf: [96]u8 = undefined;
        var p = Path.of(self.spec.net_dir) catch return;
        const ip = self.spec.ip;
        p.append(std.fmt.bufPrint(&buf, "/{d}.{d}.{d}.{d}/{d}", .{ ip[0], ip[1], ip[2], ip[3], container_port }) catch unreachable) catch return;
        var num: [16]u8 = undefined;
        sys.writeFile(p.slice(), std.fmt.bufPrint(&num, "{d}", .{host}) catch unreachable, 0o600) catch {};
    }

    fn addMapping(self: *Tracer, m: PortMap) void {
        self.spec.ports.append(self.gpa, m) catch return;
        self.publishPort(m.container, m.host);
        if (self.spec.on_ports) |f| f(self.spec.ctx, self.spec.ports.items);
    }

    /// Without a network namespace containers share the host's ports, so
    /// each guest port is quietly backed by a host port that is really free.
    fn mapPort(self: *Tracer, port: u16, kind: SocketKind) PortMap {
        for (self.spec.ports.items) |*m| {
            if (m.container != port) continue;
            m.kind = kind;
            return m.*;
        }
        var host = port;
        if (port < 1024 or !self.claim(port)) {
            while (!self.claim(self.next_port)) self.next_port +%= 1;
            host = self.next_port;
            self.next_port +%= 1;
        }
        const m: PortMap = .{ .container = port, .host = host, .fixed = false, .kind = kind };
        self.addMapping(m);
        return m;
    }

    fn findPort(self: *Tracer, port: u16) ?PortMap {
        for (self.spec.ports.items) |m| if (m.container == port) return m;
        return null;
    }

    fn containerPort(self: *Tracer, host: u16) ?u16 {
        for (self.spec.ports.items) |m| if (m.host == host) return m.container;
        return null;
    }

    /// The host port behind an address on the private network.
    fn peerPort(self: *Tracer, ip: [4]u8, port: u16) Err!u16 {
        var buf: [96]u8 = undefined;
        var dir = try Path.of(self.spec.net_dir);
        try dir.append(std.fmt.bufPrint(&buf, "/{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch unreachable);
        if (!sys.exists(dir.z())) return sys.fail(.HOSTUNREACH);
        try dir.append(std.fmt.bufPrint(&buf, "/{d}", .{port}) catch unreachable);
        const fd = sys.open(dir.z(), 0, 0) catch return sys.fail(.CONNREFUSED);
        defer sys.close(fd);
        var num: [16]u8 = undefined;
        const n = try sys.read(fd, &num);
        return std.fmt.parseInt(u16, num[0..n], 10) catch sys.fail(.CONNREFUSED);
    }

    /// True for the phone's own addresses, which are reachable from outside
    /// the container only: going through them would bypass the private network.
    fn isHostAddr(self: *Tracer, ip: [4]u8) bool {
        const now = sys.monoNs();
        if (now - self.host_addrs_at > 5 * std.time.ns_per_s) {
            self.host_addrs_at = now;
            self.host_addr_count = 0;
            const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
            if (linux.errno(rc) == .SUCCESS) {
                const fd: i32 = @intCast(rc);
                defer sys.close(fd);
                var buf: [40 * 32]u8 align(8) = undefined;
                const Ifconf = extern struct { len: i32, _pad: i32 = 0, ptr: usize };
                var ifc: Ifconf = .{ .len = buf.len, .ptr = @intFromPtr(&buf) };
                const SIOCGIFCONF = 0x8912;
                if (linux.errno(linux.ioctl(fd, SIOCGIFCONF, @intFromPtr(&ifc))) == .SUCCESS) {
                    const count = @min(@as(usize, @intCast(ifc.len)) / 40, self.host_addrs.len);
                    for (0..count) |i| @memcpy(&self.host_addrs[i], buf[i * 40 + 20..][0..4]);
                    self.host_addr_count = count;
                }
            }
        }
        for (self.host_addrs[0..self.host_addr_count]) |a| {
            if (std.mem.eql(u8, &a, &ip)) return true;
        }
        return false;
    }

    fn noteZeroBind(self: *Tracer, tgid: i32, fd: i32, kind: SocketKind) void {
        self.zero_binds[self.zero_next] = .{ .tgid = tgid, .fd = fd, .kind = kind };
        self.zero_next = (self.zero_next + 1) % self.zero_binds.len;
    }

    fn noteV6Only(self: *Tracer, tgid: i32, fd: i32, on: bool) void {
        for (&self.v6only) |*e| {
            if (e.tgid == tgid and e.fd == fd) {
                e.on = on;
                return;
            }
        }
        self.v6only[self.v6only_next] = .{ .tgid = tgid, .fd = fd, .on = on };
        self.v6only_next = (self.v6only_next + 1) % self.v6only.len;
    }

    fn isV6Only(self: *Tracer, tgid: i32, fd: i32) bool {
        for (&self.v6only) |*e| {
            if (e.tgid == tgid and e.fd == fd) return e.on;
        }
        return false;
    }

    fn ldHasArgv0(self: *Tracer, host: []const u8) bool {
        for (self.ld_cache[0..self.ld_count]) |*e| {
            if (std.mem.eql(u8, e.path.slice(), host)) return e.has_argv0;
        }
        const has = scanForArgv0(host);
        if (self.ld_count < self.ld_cache.len) {
            const e = &self.ld_cache[self.ld_count];
            e.path.set(host) catch return has;
            e.has_argv0 = has;
            self.ld_count += 1;
        }
        return has;
    }

    fn scanForArgv0(host: []const u8) bool {
        var p = Path.of(host) catch return false;
        const fd = sys.open(p.z(), 0, 0) catch return false;
        defer sys.close(fd);
        var buf: [65536 + 8]u8 = undefined;
        var carry: usize = 0;
        while (true) {
            const n = sys.read(fd, buf[carry..]) catch return false;
            if (n == 0) return false;
            const have = carry + n;
            // glibc compares "--argv0"; musl compares "argv0" after the dashes.
            if (std.mem.indexOf(u8, buf[0..have], "argv0") != null) return true;
            carry = @min(have, 5);
            std.mem.copyForwards(u8, buf[0..carry], buf[have - carry..have]);
        }
    }

    pub fn run(gpa: std.mem.Allocator, spec: *const Spec) !u8 {
        var self: Tracer = .{
            .gpa = gpa,
            .spec = spec,
            .vfs = spec.vfs,
            .real_uid = linux.getuid(),
            .real_gid = linux.getgid(),
            .shm = .{ .gpa = gpa, .dir = spec.shm_dir },
        };
        self.shm.clearDir();
        defer self.shm.deinit();
        self.unix_abstract = !socketFilesWork(spec.sock_dir);
        spec.vfs.procs = .{ .ctx = &self, .lookup = procLookup, .toReal = procToReal };
        var net_dir_path: ?Path = null;
        if (spec.net_dir.len > 0) {
            var buf: [48]u8 = undefined;
            const ip = spec.ip;
            net_dir_path = try Path.join(spec.net_dir, std.fmt.bufPrint(&buf, "/{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch unreachable);
            if (spec.net_mode != .none) try sys.mkdirP(net_dir_path.?.slice(), 0o700);
        }
        defer {
            for (self.held.items) |p| self.release(p);
            self.held.deinit(gpa);
            self.tracees.deinit(gpa);
            self.by_vpid.deinit(gpa);
            self.zombies.deinit(gpa);
            if (net_dir_path) |p| sys.rmrf(p.slice()) catch {};
            if (self.ctl_fd >= 0) {
                sys.close(self.ctl_fd);
                var ctl = Path.of(spec.ctl_path) catch unreachable;
                sys.unlink(ctl.z()) catch {};
            }
            setTimer(0);
        }
        var i: usize = 0;
        while (i < spec.ports.items.len) {
            const m = spec.ports.items[i];
            if (self.reserve(m.host)) {
                self.publishPort(m.container, m.host);
                i += 1;
            } else if (m.fixed) {
                sys.eprint("error: host port {d} is already allocated\n", .{m.host});
                return error.PortInUse;
            } else {
                // An automatic port lost across a restart gets a new one.
                _ = spec.ports.orderedRemove(i);
            }
        }

        // Before forking: a failure past this point would strand the child.
        if (spec.ctl_path.len > 0) self.ctl_fd = try control.listen(spec.ctl_path);

        self.filter_len = buildFilter(&self.filter, spec.net_mode != .bridge);
        try self.lower_z.set(spec.vfs.lowers[spec.vfs.lowers.len - 1]);

        // Prepared before forking: the child must not allocate.
        const argv_z = try gpa.alloc(?[*:0]const u8, spec.argv.len + 1);
        defer gpa.free(argv_z);
        for (spec.argv, 0..) |a, k| argv_z[k] = a.ptr;
        argv_z[spec.argv.len] = null;
        const envp_z = try gpa.alloc(?[*:0]const u8, spec.envp.len + 1);
        defer gpa.free(envp_z);
        for (spec.envp, 0..) |a, k| envp_z[k] = a.ptr;
        envp_z[spec.envp.len] = null;

        const pid = try sys.fork();
        if (pid == 0) {
            self.childMain(.{
                .exec_path = spec.exec_path.ptr,
                .argv = argv_z,
                .envp = envp_z,
                .stdin_fd = spec.stdin_fd,
                .stdout_fd = spec.stdout_fd,
                .stderr_fd = spec.stderr_fd,
                .new_session = spec.new_session,
                .ctty = spec.ctty,
            });
        }

        _ = linux.prctl(@backingInt(linux.PR.SET_CHILD_SUBREAPER), 1, 0, 0, 0);

        self.main_tid = pid;
        const first = try self.getOrAdd(pid);
        first.proc = try self.newProc(pid, null);
        try first.proc.?.exe.set(spec.exec_path);
        first.expect_stop = true;
        first.needs_options = true;

        installWake(.USR2);
        const period_ms: u32 = if (spec.limits.cpus_milli > 0)
            100
        else if (spec.limits.memory > 0)
            200
        else if (spec.health != null)
            500
        else
            0;
        if (period_ms > 0) {
            installWake(.ALRM);
            setTimer(period_ms);
        }
        self.last_tick = sys.monoNs();
        if (spec.health) |h| {
            self.started_at = self.last_tick;
            self.next_health = self.last_tick + @as(i128, h.interval_ms) * std.time.ns_per_ms;
            self.setHealth("starting");
        }

        const opts: usize = PT.O.TRACESYSGOOD | PT.O.TRACEFORK | PT.O.TRACEVFORK |
            PT.O.TRACECLONE | PT.O.TRACEEXEC | PT.O.TRACESECCOMP | PT.O.EXITKILL;

        const WALL: u32 = 0x40000000;
        var started = false;
        while (true) {
            if (WakeSignals.wake.swap(false, .monotonic)) {
                self.pollControl();
                self.tick();
            }
            var raw: i32 = 0;
            const rc = linux.waitpid(-1, &raw, WALL);
            const e = linux.errno(rc);
            if (e == .INTR) continue;
            if (e != .SUCCESS) break; // ECHILD: everything has exited
            const tid: i32 = @intCast(rc);
            const status: u32 = @bitCast(raw);

            if (linux.W.IFEXITED(status) or linux.W.IFSIGNALED(status)) {
                if (self.tracees.get(tid)) |gone| {
                    if (gone.proc) |p| {
                        if (p.exec_ctl >= 0 and p.tgid == tid) {
                            const code = [1]u8{exitCode(status)};
                            control.send(p.exec_ctl, &code, &.{}) catch {};
                        }
                    }
                }
                if (tid == self.health_tid) self.healthResult(exitCode(status));
                if (tid == self.main_tid) {
                    self.main_status = status;
                    self.killAll();
                }
                self.drop(tid);
                // The supervisor has other children (the log writer), so
                // waiting for ECHILD alone would never finish.
                if (self.main_status != null and self.tracees.count() == 0) break;
                continue;
            }
            if (!linux.W.IFSTOPPED(status)) continue;

            const sig: u32 = (status >> 8) & 0xff;
            const event: u32 = status >> 16;
            const t = try self.getOrAdd(tid);

            if (t.proc == null) {
                // A new child reported in before its parent's fork event.
                t.parked = true;
                continue;
            }

            const SIGSTOP: u32 = @backingInt(linux.SIG.STOP);
            if (event == PT.EVENT.SECCOMP) {
                if (!t.chain.active) self.onEnter(t);
                self.resumeT(t, 0);
            } else if (sig == @as(u32, @backingInt(linux.SIG.TRAP)) | 0x80) {
                if (t.chain.active) {
                    self.chainStop(t);
                } else {
                    self.onExit(t);
                    t.exit = .none;
                }
                self.resumeT(t, 0);
            } else if (event == PT.EVENT.FORK or event == PT.EVENT.VFORK or event == PT.EVENT.CLONE) {
                try self.onFork(t, event);
                self.resumeT(t, 0);
            } else if (event == PT.EVENT.EXEC) {
                self.onExec(t);
                self.resumeT(t, 0);
            } else if (event != 0) {
                self.resumeT(t, 0);
            } else if (sig == SIGSTOP and t.expect_stop) {
                t.expect_stop = false;
                if (t.needs_options) {
                    t.needs_options = false;
                    _ = linux.ptrace(PT.SETOPTIONS, tid, 0, opts, 0);
                }
                if (tid == self.main_tid and !started) {
                    started = true;
                    if (spec.on_start) |f| f(spec.ctx, tid);
                }
                self.resumeT(t, 0);
            } else if (sig == SIGSTOP and t.stop_pending) {
                t.stop_pending = false;
                if (t.hold) {
                    t.held = true;
                } else {
                    self.resumeT(t, 0);
                }
            } else if (t.chain.active) {
                t.chain.deferred |= @as(u64, 1) << @intCast(sig - 1);
                self.resumeT(t, 0);
            } else if (sig == @as(u32, @backingInt(linux.SIG.SYS)) and self.onSigsys(t)) {
                self.resumeT(t, 0);
            } else {
                self.patchSiginfo(t, sig);
                self.resumeT(t, sig);
            }
        }

        const st = self.main_status orelse return 127;
        return exitCode(st);
    }

    fn exitCode(status: u32) u8 {
        if (linux.W.IFEXITED(status)) return linux.W.EXITSTATUS(status);
        return 128 +% @as(u8, @intCast(@backingInt(linux.W.TERMSIG(status)) & 0x7f));
    }

    fn installWake(sig: linux.SIG) void {
        var act: linux.Sigaction = .{
            .handler = .{ .handler = WakeSignals.handler },
            .mask = std.mem.zeroes(linux.sigset_t),
            .flags = 0,
        };
        _ = linux.sigaction(sig, &act, null);
    }

    fn setTimer(ms: u32) void {
        const usec: i64 = @as(i64, ms) * 1000;
        const secs = @divFloor(usec, 1_000_000);
        const rem = @mod(usec, 1_000_000);
        const value = [4]i64{ secs, rem, secs, rem };
        _ = linux.syscall3(.setitimer, 0, @intFromPtr(&value), 0);
    }

    const ChildArgs = struct {
        exec_path: [*:0]const u8,
        argv: []?[*:0]const u8,
        envp: []?[*:0]const u8,
        stdin_fd: i32,
        stdout_fd: i32,
        stderr_fd: i32,
        new_session: bool,
        ctty: bool = false,
    };

    /// Becomes a traced guest process. Runs between fork and exec, so it
    /// must not allocate.
    fn childMain(self: *Tracer, args: ChildArgs) noreturn {
        _ = linux.ptrace(PT.TRACEME, 0, 0, 0, 0);
        if (args.new_session) _ = linux.setsid();
        _ = linux.chdir(self.lower_z.z());
        _ = linux.dup2(args.stdin_fd, 0);
        _ = linux.dup2(args.stdout_fd, 1);
        _ = linux.dup2(args.stderr_fd, 2);
        for ([_]i32{ args.stdin_fd, args.stdout_fd, args.stderr_fd }) |fd| {
            if (fd > 2) sys.close(fd);
        }
        if (args.ctty) _ = linux.ioctl(0, TIOCSCTTY, 0);
        if (self.spec.limits.cpuset != 0) {
            var mask: [16]u64 = @splat(0);
            mask[0] = self.spec.limits.cpuset;
            _ = linux.syscall3(.sched_setaffinity, 0, @sizeOf(@TypeOf(mask)), @intFromPtr(&mask));
        }
        _ = linux.kill(linux.getpid(), .STOP);
        const PR_SET_NO_NEW_PRIVS = 38;
        _ = linux.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        var prog: SockFprog = .{ .len = @intCast(self.filter_len), .filter = &self.filter };
        const SECCOMP_SET_MODE_FILTER = 1;
        const rc = linux.seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog);
        if (linux.errno(rc) != .SUCCESS) linux.exit_group(126);
        _ = linux.execve(args.exec_path, @ptrCast(args.argv.ptr), @ptrCast(args.envp.ptr));
        linux.exit_group(127);
    }

    fn pollControl(self: *Tracer) void {
        if (self.ctl_fd < 0) return;
        while (control.accept(self.ctl_fd)) |conn| {
            self.serveControl(conn) catch sys.close(conn);
        }
    }

    fn serveControl(self: *Tracer, conn: i32) !void {
        const buf = try self.gpa.alloc(u8, 256 * 1024);
        defer self.gpa.free(buf);
        var fds: [3]i32 = undefined;
        const got = try control.recv(conn, buf, &fds, 1000);
        if (got.len == 0) return error.EmptyRequest;
        switch (buf[0]) {
            control.op_stats => {
                defer sys.close(conn);
                _ = self.sampleCpu();
                var out: [128]u8 = undefined;
                const s = try std.fmt.bufPrint(&out, "{d} {d} {d}", .{ self.tracees.count(), self.memoryUsed(true), self.cpu_total * 10 });
                try control.send(conn, s, &.{});
            },
            control.op_exec, control.op_exec_tty => {
                if (got.nfds != 3) return error.BadRequest;
                try self.spawnExec(conn, buf[1..got.len], &fds, buf[0] == control.op_exec_tty);
            },
            else => return error.BadRequest,
        }
    }

    /// Starts an `exec` process. Doing it here keeps it in the container's
    /// process table and lets it die with the container, as Docker does.
    fn spawnExec(self: *Tracer, conn: i32, msg: []u8, fds: *[3]i32, ctty: bool) !void {
        defer for (fds) |fd| sys.close(fd);
        const nextStr = struct {
            fn f(m: []u8, pos: *usize) ![*:0]const u8 {
                if (pos.* >= m.len) return error.BadRequest;
                const end = std.mem.indexOfScalarPos(u8, m, pos.*, 0) orelse return error.BadRequest;
                const s: [*:0]const u8 = @ptrCast(m[pos.*..end :0].ptr);
                pos.* = end + 1;
                return s;
            }
        }.f;
        var pos: usize = 0;
        const cwd = try nextStr(msg, &pos);
        const exec_path = try nextStr(msg, &pos);
        const argc = try std.fmt.parseInt(usize, std.mem.span(try nextStr(msg, &pos)), 10);
        const argv = try self.gpa.alloc(?[*:0]const u8, argc + 1);
        defer self.gpa.free(argv);
        for (argv[0..argc]) |*a| a.* = try nextStr(msg, &pos);
        argv[argc] = null;
        const envc = try std.fmt.parseInt(usize, std.mem.span(try nextStr(msg, &pos)), 10);
        const envp = try self.gpa.alloc(?[*:0]const u8, envc + 1);
        defer self.gpa.free(envp);
        for (envp[0..envc]) |*a| a.* = try nextStr(msg, &pos);
        envp[envc] = null;

        const pid = try sys.fork();
        if (pid == 0) {
            self.childMain(.{
                .exec_path = exec_path,
                .argv = argv,
                .envp = envp,
                .stdin_fd = fds[0],
                .stdout_fd = fds[1],
                .stderr_fd = fds[2],
                .new_session = true,
                .ctty = ctty,
            });
        }
        const t = try self.getOrAdd(pid);
        const p = try self.newProc(pid, null);
        try p.cwd.set(std.mem.span(cwd));
        try p.exe.set(std.mem.span(exec_path));
        p.exec_ctl = conn;
        t.proc = p;
        t.expect_stop = true;
        t.needs_options = true;
        try control.send(conn, std.mem.asBytes(&pid), &.{});
    }

    fn sampleCpu(self: *Tracer) u64 {
        var ticks: u64 = 0;
        var it = self.by_vpid.valueIterator();
        while (it.next()) |pp| {
            const p = pp.*;
            const cur = quota.cpuTicks(p.tgid) orelse continue;
            if (cur > p.cpu_seen) ticks += cur - p.cpu_seen;
            p.cpu_seen = cur;
        }
        self.cpu_total += ticks;
        return ticks;
    }

    fn memoryUsed(self: *Tracer, precise: bool) u64 {
        var total: u64 = 0;
        var it = self.by_vpid.valueIterator();
        while (it.next()) |pp| {
            const v = if (precise) quota.pss(pp.*.tgid) else quota.rss(pp.*.tgid);
            total += v orelse 0;
        }
        return total;
    }

    fn tick(self: *Tracer) void {
        const now = sys.monoNs();
        const limits = self.spec.limits;
        if (limits.memory > 0 and now - self.last_mem_check >= 180 * std.time.ns_per_ms) {
            self.last_mem_check = now;
            self.checkMemory();
        }
        if (limits.cpus_milli > 0) self.throttle(now);
        if (self.spec.health) |h| self.healthTick(now, h);
        self.last_tick = now;
    }

    fn setHealth(self: *Tracer, status: []const u8) void {
        if (std.mem.eql(u8, self.health_status, status)) return;
        self.health_status = status;
        if (self.spec.on_health) |f| f(self.spec.ctx, status);
    }

    fn healthTick(self: *Tracer, now: i128, h: HealthSpec) void {
        if (self.health_tid != 0) {
            if (now > self.health_deadline) _ = linux.kill(self.health_tid, .KILL);
            return;
        }
        if (now < self.next_health) return;
        self.startHealthCheck(now, h) catch self.healthResult(1);
    }

    /// Runs the check inside the container, like `exec` does.
    fn startHealthCheck(self: *Tracer, now: i128, h: HealthSpec) !void {
        const gpa = self.gpa;
        const spec = self.spec;
        const argv_z = try gpa.alloc(?[*:0]const u8, h.argv.len + 1);
        defer gpa.free(argv_z);
        for (h.argv, 0..) |a, k| argv_z[k] = a.ptr;
        argv_z[h.argv.len] = null;
        const envp_z = try gpa.alloc(?[*:0]const u8, spec.envp.len + 1);
        defer gpa.free(envp_z);
        for (spec.envp, 0..) |a, k| envp_z[k] = a.ptr;
        envp_z[spec.envp.len] = null;

        const devnull = try sys.open("/dev/null", sys.O_RDWR, 0);
        defer sys.close(devnull);
        const pid = try sys.fork();
        if (pid == 0) {
            self.childMain(.{
                .exec_path = h.exec_path.ptr,
                .argv = argv_z,
                .envp = envp_z,
                .stdin_fd = devnull,
                .stdout_fd = devnull,
                .stderr_fd = devnull,
                .new_session = true,
            });
        }
        const t = try self.getOrAdd(pid);
        const p = try self.newProc(pid, null);
        try p.exe.set(h.exec_path);
        t.proc = p;
        t.expect_stop = true;
        t.needs_options = true;
        self.health_tid = pid;
        self.health_deadline = now + @as(i128, h.timeout_ms) * std.time.ns_per_ms;
    }

    fn healthResult(self: *Tracer, code: u8) void {
        const h = self.spec.health.?;
        const now = sys.monoNs();
        self.health_tid = 0;
        self.next_health = now + @as(i128, h.interval_ms) * std.time.ns_per_ms;
        if (code == 0) {
            self.health_failures = 0;
            self.setHealth("healthy");
            return;
        }
        // Failures during the start period do not count against the container.
        if (now - self.started_at < @as(i128, h.start_ms) * std.time.ns_per_ms) return;
        self.health_failures += 1;
        if (self.health_failures >= h.retries) self.setHealth("unhealthy");
    }

    /// The memory cgroup's job, done by hand: over the limit, the largest
    /// process is killed. RSS counts shared pages repeatedly, so the costlier
    /// PSS only gets read once RSS suggests there may be a problem.
    fn checkMemory(self: *Tracer) void {
        const limit = self.spec.limits.memory;
        if (self.memoryUsed(false) <= limit) return;
        if (self.memoryUsed(true) <= limit) return;
        var worst: ?*Proc = null;
        var worst_size: u64 = 0;
        var it = self.by_vpid.valueIterator();
        while (it.next()) |pp| {
            const size = quota.pss(pp.*.tgid) orelse continue;
            if (size >= worst_size) {
                worst = pp.*;
                worst_size = size;
            }
        }
        const p = worst orelse return;
        _ = linux.kill(p.tgid, .KILL);
        if (self.spec.on_oom) |f| f(self.spec.ctx);
    }

    /// A token bucket over /proc CPU times: past the budget, every task is
    /// stopped until enough wall-clock time has paid the excess back.
    fn throttle(self: *Tracer, now: i128) void {
        const dt_ms: i64 = @intCast(@divFloor(now - self.last_tick, std.time.ns_per_ms));
        if (dt_ms <= 0) return;
        const used_ms: i64 = @intCast(self.sampleCpu() * 10);
        const allowed = @divFloor(@as(i64, self.spec.limits.cpus_milli) * dt_ms, 1000);
        self.debt_ms = @max(0, self.debt_ms + used_ms - allowed);
        if (!self.throttled and self.debt_ms > allowed) {
            self.throttled = true;
            var it = self.tracees.valueIterator();
            while (it.next()) |tp| {
                const t = tp.*;
                const p = t.proc orelse continue;
                if (t.expect_stop) continue;
                t.hold = true;
                if (t.stop_pending or t.held) continue;
                t.stop_pending = true;
                _ = linux.tgkill(p.tgid, t.tid, .STOP);
            }
        } else if (self.throttled and self.debt_ms <= allowed) {
            self.throttled = false;
            var it = self.tracees.valueIterator();
            while (it.next()) |tp| {
                const t = tp.*;
                t.hold = false;
                if (t.held) {
                    t.held = false;
                    self.resumeT(t, 0);
                }
            }
        }
    }

    /// Puts the sender's virtual PID in the signal handler's siginfo.
    fn patchSiginfo(self: *Tracer, t: *Tracee, sig: u32) void {
        var si: [128]u8 align(8) = undefined;
        if (linux.errno(linux.ptrace(PT.GETSIGINFO, t.tid, 0, @intFromPtr(&si), 0)) != .SUCCESS) return;
        const code = std.mem.readInt(i32, si[8..12], .little);
        const SIGCHLD: u32 = @backingInt(linux.SIG.CHLD);
        if (code > 0 and sig != SIGCHLD) return;
        const real = std.mem.readInt(i32, si[12..16], .little);
        if (real == 0) return;
        std.mem.writeInt(i32, si[12..16], self.realToV(real, false) orelse 0, .little);
        _ = linux.ptrace(PT.SETSIGINFO, t.tid, 0, @intFromPtr(&si), 0);
    }

    fn killAll(self: *Tracer) void {
        var it = self.tracees.iterator();
        while (it.next()) |kv| {
            if (kv.key_ptr.* != self.main_tid) _ = linux.kill(kv.key_ptr.*, .KILL);
        }
    }

    fn onFork(self: *Tracer, parent: *Tracee, event: u32) !void {
        var msg: u64 = 0;
        _ = linux.ptrace(PT.GETEVENTMSG, parent.tid, 0, @intFromPtr(&msg), 0);
        const new_tid: i32 = @intCast(msg);
        const child_t = try self.getOrAdd(new_tid);
        const pp = parent.proc.?;

        var is_thread = false;
        if (event == PT.EVENT.CLONE) {
            var buf: [64]u8 = undefined;
            const s = std.fmt.bufPrintSentinel(&buf, "/proc/{d}/task/{d}", .{ pp.tgid, new_tid }, 0) catch unreachable;
            is_thread = sys.exists(s.ptr);
        }
        if (is_thread) {
            pp.refs += 1;
            child_t.proc = pp;
        } else {
            child_t.proc = try self.newProc(new_tid, pp);
            self.shm.forked(pp.tgid, new_tid);
        }
        if (child_t.parked) {
            child_t.parked = false;
            self.resumeT(child_t, 0);
        } else {
            child_t.expect_stop = true;
        }
    }

    fn onExec(self: *Tracer, t: *Tracee) void {
        var old: u64 = 0;
        _ = linux.ptrace(PT.GETEVENTMSG, t.tid, 0, @intFromPtr(&old), 0);
        const old_tid: i32 = @intCast(old);
        if (old_tid != t.tid) self.drop(old_tid);
        if (t.proc) |p| {
            self.shm.gone(p.tgid);
            if (p.pending_exe.len > 0) {
                p.exe = p.pending_exe;
                p.pending_exe.len = 0;
                p.cmdline = p.pending_cmdline;
                p.comm = p.pending_comm;
                p.comm_len = p.pending_comm_len;
            }
        }
    }

    fn makeCtx(self: *Tracer, t: *Tracee) ?Ctx {
        var c: Ctx = .{
            .tr = self,
            .t = t,
            .p = t.proc.?,
            .regs = undefined,
            .scratch = 0,
        };
        arch.getRegs(t.tid, &c.regs) catch return null;
        c.scratch = (arch.sp(&c.regs) - 256) & ~@as(u64, 15);
        self.vfs.tgid = c.p.tgid;
        self.vfs.tid = t.tid;
        return c;
    }

    fn onEnter(self: *Tracer, t: *Tracee) void {
        var c = self.makeCtx(t) orelse return;
        const sc = scs.lookup(arch.sysno(&c.regs));
        if (self.spec.debug) sys.eprint("[{d}] {s} nr={d}\n", .{ t.tid, @tagName(sc.h), arch.sysno(&c.regs) });
        dispatch(&c, sc) catch {
            if (self.spec.debug) sys.eprint("  [{d}] failed: {s}\n", .{ t.tid, @tagName(sys.last) });
            t.exit = .none;
            c.finishErr(sys.last);
        };
        if (c.voided) t.exit = .none;
        c.flush();
    }

    /// Android's own seccomp policy kills some calls (setuid, chroot, ...) with
    /// SIGSYS before our filter sees them. Answer them here instead.
    fn onSigsys(self: *Tracer, t: *Tracee) bool {
        var si: [128]u8 align(8) = undefined;
        if (linux.errno(linux.ptrace(PT.GETSIGINFO, t.tid, 0, @intFromPtr(&si), 0)) != .SUCCESS) return false;
        const code = std.mem.readInt(i32, si[8..12], .little);
        if (code != 1) return false;
        const nr = std.mem.readInt(i32, si[24..28], .little);
        var c = self.makeCtx(t) orelse return false;
        c.trapped = true;
        const sc = scs.lookup(@intCast(nr));
        switch (sc.h) {
            .getid, .getresid, .setid, .getgroups, .setgroups, .capget, .succeed, .eperm, .enosys, .shmget, .shmat, .shmdt, .shmctl => {
                dispatch(&c, sc) catch c.finishErr(sys.last);
            },
            .chroot => c.finish(0),
            else => c.finishErr(.NOSYS),
        }
        t.exit = .none;
        c.flush();
        return true;
    }

    fn onExit(self: *Tracer, t: *Tracee) void {
        var regs: arch.Regs = undefined;
        arch.getRegs(t.tid, &regs) catch return;
        const ret = arch.ret(&regs);
        switch (t.exit) {
            .none => {},
            .fix_stat => if (ret == 0) self.patchIds(t, t.a0 + arch.stat_uid_off),
            .fix_statx => if (ret == 0) self.patchIds(t, t.a0 + 0x14),
            .fix_readlink => if (ret > 0) self.patchReadlink(t, &regs, ret),
            .fix_sockname => if (ret == 0) self.patchSockname(t),
            .fix_uname => if (ret == 0) {
                var name: [65]u8 = @splat(0);
                const n = @min(self.spec.hostname.len, 64);
                @memcpy(name[0..n], self.spec.hostname[0..n]);
                writeMem(t.tid, t.a0 + 65, &name) catch {};
            },
            .fix_clone => if (ret > 0) {
                const real: i32 = @intCast(ret);
                const v = self.realToV(real, false) orelse return;
                if (v != real) self.setResult(t, &regs, v);
            },
            .fix_wait => if (ret > 0) {
                const real: i32 = @intCast(ret);
                const v = self.realToV(real, true) orelse return;
                if (v != real) self.setResult(t, &regs, v);
            },
            .fix_waitid => if (ret == 0 and t.a0 != 0) {
                var b: [4]u8 = undefined;
                readMem(t.tid, t.a0 + 12, &b) catch return;
                const real = std.mem.readInt(i32, &b, .little);
                if (real == 0) return;
                const WNOWAIT = 0x01000000;
                const v = self.realToV(real, t.a1 & WNOWAIT == 0) orelse return;
                std.mem.writeInt(i32, &b, v, .little);
                writeMem(t.tid, t.a0 + 12, &b) catch {};
            },
            .fix_setsid => if (ret > 0) {
                const p = t.proc.?;
                p.vsid = p.vpid;
                p.vpgid = p.vpid;
                p.real_pgid = p.tgid;
                self.setResult(t, &regs, p.vpid);
            },
            .fix_setpgid => if (ret == 0) {
                const target: i32 = @intCast(t.a0);
                const tt = self.tracees.get(target) orelse return;
                const p = tt.proc orelse return;
                p.vpgid = @intCast(t.a1);
                p.real_pgid = @intCast(t.a2);
            },
            .fix_dents => if (ret > 0) self.patchDents(t, &regs, ret),
            .fix_sysinfo => if (ret == 0) self.patchSysinfo(t),
            .fix_affinity => if (ret > 0) self.patchAffinity(t, ret),
            .fix_tty_pgrp => if (ret == 0) self.patchTtyId(t, true),
            .fix_tty_sid => if (ret == 0) self.patchTtyId(t, false),
        }
    }

    /// The kernel answers terminal queries with real ids.
    fn patchTtyId(self: *Tracer, t: *Tracee, is_group: bool) void {
        var b: [4]u8 = undefined;
        readMem(t.tid, t.a0, &b) catch return;
        const real = std.mem.readInt(i32, &b, .little);
        var v: ?i32 = null;
        if (is_group) {
            var it = self.by_vpid.valueIterator();
            while (it.next()) |p| {
                if (p.*.real_pgid == real) v = p.*.vpgid;
            }
        } else {
            v = self.realToV(real, false);
        }
        std.mem.writeInt(i32, &b, v orelse return, .little);
        writeMem(t.tid, t.a0, &b) catch {};
    }

    /// A syscall stop of a guest in the middle of a chain.
    fn chainStop(self: *Tracer, t: *Tracee) void {
        const ch = &t.chain;
        if (ch.at_entry) {
            ch.at_entry = false;
            return;
        }
        var regs: arch.Regs = undefined;
        arch.getRegs(t.tid, &regs) catch return;
        const ret = arch.ret(&regs);
        const p = t.proc.?;
        switch (ch.op) {
            .shmat => switch (ch.step) {
                0 => {
                    if (ret < 0) return self.endChain(t, ret);
                    ch.fd = ret;
                    ch.step = 1;
                    injectCall(t, .mmap, .{ ch.addr, ch.size, ch.prot, ch.map_flags, @bitCast(ret), 0 });
                },
                1 => {
                    // A mapping refused for overlapping is EINVAL to shmat().
                    const EEXIST: i64 = -@as(i64, @backingInt(linux.E.EXIST));
                    const EINVAL: i64 = -@as(i64, @backingInt(linux.E.INVAL));
                    ch.result = if (ret == EEXIST) EINVAL else ret;
                    ch.step = 2;
                    injectCall(t, .close, .{ @bitCast(ch.fd), 0, 0, 0, 0, 0 });
                },
                else => {
                    if (ch.result >= 0) self.shm.noteAttach(ch.seg, p.tgid, @bitCast(ch.result), p.vpid);
                    self.endChain(t, ch.result);
                },
            },
            .shmdt => {
                if (ret == 0) self.shm.noteDetach(p.tgid, ch.addr, p.vpid);
                self.endChain(t, ret);
            },
        }
    }

    fn endChain(_: *Tracer, t: *Tracee, result: i64) void {
        const ch = &t.chain;
        var r = ch.saved;
        arch.setRet(&r, result);
        arch.setRegs(t.tid, &r) catch {};
        ch.active = false;
        var mask = ch.deferred;
        while (mask != 0) : (mask &= mask - 1) {
            const n: u32 = @ctz(mask) + 1;
            _ = linux.tgkill(t.proc.?.tgid, t.tid, @fromBackingInt(n));
        }
    }

    fn setResult(_: *Tracer, t: *Tracee, regs: *arch.Regs, v: i64) void {
        arch.setRet(regs, v);
        arch.setRegs(t.tid, regs) catch {};
    }

    /// Shows only this container's processes in a listing of /proc, under
    /// their virtual PIDs.
    fn patchDents(self: *Tracer, t: *Tracee, regs: *arch.Regs, ret: i64) void {
        var buf: [65536]u8 align(8) = undefined;
        const n = @min(@as(usize, @intCast(ret)), buf.len);
        readMem(t.tid, t.a0, buf[0..n]) catch return;
        var pos: usize = 0;
        var out: usize = 0;
        while (pos + 19 <= n) {
            const reclen = std.mem.readInt(u16, buf[pos + 16 ..][0..2], .little);
            if (reclen == 0 or pos + reclen > n) break;
            const name = std.mem.sliceTo(buf[pos + 19 .. pos + reclen], 0);
            var keep = true;
            if (std.fmt.parseInt(i32, name, 10) catch null) |real| {
                keep = false;
                if (self.tracees.get(real)) |target| {
                    if (target.proc) |p| {
                        if (p.tgid == real) {
                            var num: [16]u8 = undefined;
                            const s = std.fmt.bufPrint(&num, "{d}", .{p.vpid}) catch unreachable;
                            if (s.len <= name.len) {
                                @memset(buf[pos + 19 .. pos + reclen], 0);
                                @memcpy(buf[pos + 19 ..][0..s.len], s);
                                keep = true;
                            }
                        }
                    }
                }
            } else if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) {
                // Android forbids apps most of /proc; do not list what would
                // only produce "permission denied".
                var entry = Path.join("/proc/", name) catch unreachable;
                var st: sys.Stat = undefined;
                sys.lstat(entry.z(), &st) catch {
                    keep = false;
                };
            }
            if (keep) {
                std.mem.copyForwards(u8, buf[out .. out + reclen], buf[pos .. pos + reclen]);
                out += reclen;
            }
            pos += reclen;
        }
        if (out == n) {
            writeMem(t.tid, t.a0, buf[0..n]) catch {};
            return;
        }
        if (out == 0) {
            // An empty result would mean end of directory. "." is skipped by
            // everything that reads one, and the listing carries on.
            @memset(buf[0..24], 0);
            std.mem.writeInt(u16, buf[16..18], 24, .little);
            buf[18] = sys.DT_DIR;
            buf[19] = '.';
            out = 24;
        }
        writeMem(t.tid, t.a0, buf[0..out]) catch return;
        self.setResult(t, regs, @intCast(out));
    }

    fn patchSysinfo(self: *Tracer, t: *Tracee) void {
        var b: [112]u8 align(8) = undefined;
        readMem(t.tid, t.a0, &b) catch return;
        var unit: u64 = std.mem.readInt(u32, b[104..108], .little);
        if (unit == 0) unit = 1;
        const limit = self.spec.limits.memory;
        const used = @min(self.memoryUsed(false), limit);
        std.mem.writeInt(u64, b[32..40], limit / unit, .little);
        std.mem.writeInt(u64, b[40..48], (limit - used) / unit, .little);
        std.mem.writeInt(u64, b[48..56], 0, .little);
        std.mem.writeInt(u64, b[56..64], 0, .little);
        std.mem.writeInt(u64, b[64..72], 0, .little);
        std.mem.writeInt(u64, b[72..80], 0, .little);
        writeMem(t.tid, t.a0, &b) catch {};
    }

    fn patchAffinity(self: *Tracer, t: *Tracee, ret: i64) void {
        var mask: [128]u8 = undefined;
        const n = @min(@as(usize, @intCast(ret)), mask.len);
        readMem(t.tid, t.a0, mask[0..n]) catch return;
        var left = quota.visibleCpus(self.spec.limits);
        for (mask[0..n]) |*byte| {
            var bit: u4 = 0;
            while (bit < 8) : (bit += 1) {
                const m = @as(u8, 1) << @intCast(bit);
                if (byte.* & m == 0) continue;
                if (left == 0) {
                    byte.* &= ~m;
                } else {
                    left -= 1;
                }
            }
        }
        writeMem(t.tid, t.a0, mask[0..n]) catch {};
    }

    /// Stores generated contents and returns a path the guest can open.
    /// Slots are replaced by rename, so an open file keeps its old contents.
    fn serveFake(self: *Tracer, r: *Resolved, data: []const u8) Err!void {
        var num: [32]u8 = undefined;
        self.fake_seq = (self.fake_seq + 1) % 32;
        var p = try Path.of(self.vfs.work);
        try p.append(std.fmt.bufPrint(&num, "/fp{d}", .{self.fake_seq}) catch unreachable);
        try sys.writeFileAtomic(p.slice(), data, 0o600);
        try r.host.set(p.slice());
    }

    fn commName(p: *const Proc) []const u8 {
        return p.comm[0..p.comm_len];
    }

    /// Replaces the /proc files that would reveal real PIDs, the host's
    /// resources, or that every program is really the dynamic loader.
    fn maybeFake(self: *Tracer, r: *Resolved) Err!void {
        self.buildFake(r) catch |e| {
            // Only a failure to serve the file is the guest's problem. If the
            // real one cannot be read or parsed, it just gets the real one.
            if (e == error.Sys) return error.Sys;
        };
    }

    fn buildFake(self: *Tracer, r: *Resolved) !void {
        if (!r.exists) return;
        const g = r.guest.slice();
        const gpa = self.gpa;
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        const limits = self.spec.limits;
        const cpus = quota.visibleCpus(limits);

        if (cpus > 0 and std.mem.startsWith(u8, g, "/sys/devices/system/cpu/")) {
            const leaf = g["/sys/devices/system/cpu/".len..];
            if (std.mem.eql(u8, leaf, "online") or std.mem.eql(u8, leaf, "present") or std.mem.eql(u8, leaf, "possible")) {
                if (cpus == 1) {
                    try out.appendSlice(gpa, "0\n");
                } else {
                    try out.print(gpa, "0-{d}\n", .{cpus - 1});
                }
                try self.serveFake(r, out.items);
            }
            return;
        }
        if (r.where != .proc) return;
        if (std.mem.eql(u8, g, "/proc/meminfo")) {
            if (limits.memory > 0) try self.fakeMeminfo(&out);
            if (out.items.len > 0) try self.serveFake(r, out.items);
            return;
        }
        if (std.mem.eql(u8, g, "/proc/stat")) {
            if (cpus > 0) {
                const src = try sys.readFileAlloc(gpa, "/proc/stat", 1 << 20);
                defer gpa.free(src);
                var seen: u32 = 0;
                var lines = std.mem.splitScalar(u8, src, '\n');
                while (lines.next()) |line| {
                    if (line.len == 0) continue;
                    if (line.len > 3 and std.mem.startsWith(u8, line, "cpu") and std.ascii.isDigit(line[3])) {
                        if (seen >= cpus) continue;
                        seen += 1;
                    }
                    try out.appendSlice(gpa, line);
                    try out.append(gpa, '\n');
                }
                try self.serveFake(r, out.items);
            }
            return;
        }
        if (std.mem.eql(u8, g, "/proc/cpuinfo")) {
            if (cpus > 0) try self.fakeCpuinfo(&out, cpus);
            if (out.items.len > 0) try self.serveFake(r, out.items);
            return;
        }
        var it = std.mem.tokenizeScalar(u8, g, '/');
        _ = it.next();
        const real = std.fmt.parseInt(i32, it.next() orelse return, 10) catch return;
        const name = it.next() orelse return;
        if (it.next() != null) return;
        const t = self.tracees.get(real) orelse return;
        const p = t.proc orelse return;
        if (p.tgid != real) return;
        const kind = std.meta.stringToEnum(enum { stat, status, cmdline, comm }, name) orelse return;
        const source = try sys.readFileAlloc(gpa, r.host.slice(), 1 << 20);
        defer gpa.free(source);
        switch (kind) {
            .stat => try fakeStat(gpa, p, source, &out),
            .status => try self.fakeStatus(p, source, &out),
            .cmdline => try fakeCmdline(gpa, p, source, &out),
            .comm => try out.print(gpa, "{s}\n", .{commName(p)}),
        }
        try self.serveFake(r, out.items);
    }

    fn fakeStat(gpa: std.mem.Allocator, p: *const Proc, src: []const u8, out: *std.ArrayList(u8)) !void {
        const paren = std.mem.lastIndexOfScalar(u8, src, ')') orelse return error.BadFormat;
        var it = std.mem.tokenizeScalar(u8, src[paren + 1 ..], ' ');
        const state = it.next() orelse return error.BadFormat;
        for (0..3) |_| _ = it.next(); // ppid, pgrp, session
        try out.print(gpa, "{d} ({s}) {s} {d} {d} {d} {s}", .{ p.vpid, commName(p), state, p.vppid, p.vpgid, p.vsid, it.rest() });
    }

    fn fakeStatus(self: *Tracer, p: *const Proc, src: []const u8, out: *std.ArrayList(u8)) !void {
        const gpa = self.gpa;
        const ids = &p.ids;
        var lines = std.mem.splitScalar(u8, src, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const key = line[0..colon];
            if (std.mem.eql(u8, key, "Name")) {
                try out.print(gpa, "Name:\t{s}\n", .{commName(p)});
            } else if (std.mem.eql(u8, key, "Tgid") or std.mem.eql(u8, key, "Pid") or std.mem.eql(u8, key, "NStgid") or std.mem.eql(u8, key, "NSpid")) {
                try out.print(gpa, "{s}:\t{d}\n", .{ key, p.vpid });
            } else if (std.mem.eql(u8, key, "PPid")) {
                try out.print(gpa, "PPid:\t{d}\n", .{p.vppid});
            } else if (std.mem.eql(u8, key, "TracerPid")) {
                try out.appendSlice(gpa, "TracerPid:\t0\n");
            } else if (std.mem.eql(u8, key, "NSpgid")) {
                try out.print(gpa, "NSpgid:\t{d}\n", .{p.vpgid});
            } else if (std.mem.eql(u8, key, "NSsid")) {
                try out.print(gpa, "NSsid:\t{d}\n", .{p.vsid});
            } else if (std.mem.eql(u8, key, "Uid")) {
                try out.print(gpa, "Uid:\t{d}\t{d}\t{d}\t{d}\n", .{ ids.ruid, ids.euid, ids.suid, ids.fsuid });
            } else if (std.mem.eql(u8, key, "Gid")) {
                try out.print(gpa, "Gid:\t{d}\t{d}\t{d}\t{d}\n", .{ ids.rgid, ids.egid, ids.sgid, ids.fsgid });
            } else {
                try out.appendSlice(gpa, line);
                try out.append(gpa, '\n');
            }
        }
    }

    fn fakeCmdline(gpa: std.mem.Allocator, p: *const Proc, src: []const u8, out: *std.ArrayList(u8)) !void {
        var args = std.mem.splitScalar(u8, src, 0);
        var skip_after_first = false;
        switch (p.cmdline) {
            .plain => {},
            .ld_plain => _ = args.next(), // the loader's own argv[0]
            .ld_argv0 => {
                _ = args.next();
                _ = args.next(); // --argv0
                skip_after_first = true;
            },
        }
        var first = true;
        while (args.next()) |a| {
            if (args.index == null and a.len == 0) break; // after the final NUL
            try out.appendSlice(gpa, a);
            try out.append(gpa, 0);
            if (first and skip_after_first) _ = args.next(); // the program path
            first = false;
        }
    }

    fn fakeMeminfo(self: *Tracer, out: *std.ArrayList(u8)) !void {
        const gpa = self.gpa;
        const limit = self.spec.limits.memory;
        const used = @min(self.memoryUsed(false), limit);
        const total_kb = limit / 1024;
        const free_kb = (limit - used) / 1024;
        const src = sys.readFileAlloc(gpa, "/proc/meminfo", 1 << 20) catch return;
        defer gpa.free(src);
        var lines = std.mem.splitScalar(u8, src, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const key = line[0..colon];
            if (std.mem.eql(u8, key, "MemTotal")) {
                try out.print(gpa, "MemTotal:{d: >16} kB\n", .{total_kb});
            } else if (std.mem.eql(u8, key, "MemFree") or std.mem.eql(u8, key, "MemAvailable")) {
                try out.print(gpa, "{s}:{d: >16} kB\n", .{ key, free_kb });
            } else if (std.mem.eql(u8, key, "Buffers") or std.mem.eql(u8, key, "Cached") or
                std.mem.eql(u8, key, "SwapTotal") or std.mem.eql(u8, key, "SwapFree") or std.mem.eql(u8, key, "SwapCached"))
            {
                try out.print(gpa, "{s}:{d: >16} kB\n", .{ key, 0 });
            } else {
                try out.appendSlice(gpa, line);
                try out.append(gpa, '\n');
            }
        }
    }

    fn fakeCpuinfo(self: *Tracer, out: *std.ArrayList(u8), cpus: u32) !void {
        const gpa = self.gpa;
        const src = sys.readFileAlloc(gpa, "/proc/cpuinfo", 1 << 20) catch return;
        defer gpa.free(src);
        var seen: u32 = 0;
        var blocks = std.mem.splitSequence(u8, src, "\n\n");
        while (blocks.next()) |block| {
            if (block.len == 0) continue;
            if (std.mem.startsWith(u8, block, "processor")) {
                if (seen >= cpus) continue;
                seen += 1;
            }
            try out.appendSlice(gpa, block);
            try out.appendSlice(gpa, "\n\n");
        }
    }

    fn patchIds(self: *Tracer, t: *Tracee, addr: u64) void {
        var ids: [2]u32 = undefined;
        readMem(t.tid, addr, std.mem.sliceAsBytes(&ids)) catch return;
        const p = t.proc.?;
        var changed = false;
        if (ids[0] == self.real_uid and p.ids.euid != self.real_uid) {
            ids[0] = p.ids.euid;
            changed = true;
        }
        if (ids[1] == self.real_gid and p.ids.egid != self.real_gid) {
            ids[1] = p.ids.egid;
            changed = true;
        }
        if (changed) writeMem(t.tid, addr, std.mem.sliceAsBytes(&ids)) catch {};
    }

    fn patchReadlink(self: *Tracer, t: *Tracee, regs: *arch.Regs, ret: i64) void {
        var buf: [sys.PATH_MAX]u8 = undefined;
        const n = @min(@as(usize, @intCast(ret)), buf.len);
        readMem(t.tid, t.a0, buf[0..n]) catch return;
        var g: Path = .{};
        const mapped = self.vfs.toGuest(buf[0..n], &g) catch return;
        if (!mapped) return;
        const m = @min(g.len, @as(usize, @intCast(t.a1)));
        writeMem(t.tid, t.a0, g.buf[0..m]) catch return;
        arch.setRet(regs, @intCast(m));
        arch.setRegs(t.tid, regs) catch {};
    }

    fn patchSockname(self: *Tracer, t: *Tracee) void {
        var sa: [4]u8 = undefined;
        readMem(t.tid, t.a0, &sa) catch return;
        const fam = std.mem.readInt(u16, sa[0..2], .little);
        if (fam != linux.AF.INET and fam != linux.AF.INET6) return;
        const port = std.mem.readInt(u16, sa[2..4], .big);
        if (self.containerPort(port)) |c| {
            if (c == port) return;
            std.mem.writeInt(u16, sa[2..4], c, .big);
            writeMem(t.tid, t.a0, &sa) catch {};
            return;
        }
        // A socket bound to port 0 learns its port here, and may now tell
        // others in the container to connect to it.
        const tgid = t.proc.?.tgid;
        const fd: i32 = @intCast(t.a1);
        for (&self.zero_binds) |*z| {
            if (z.tgid != tgid or z.fd != fd or port == 0) continue;
            z.tgid = 0;
            self.addMapping(.{ .container = port, .host = port, .fixed = false, .kind = z.kind });
            return;
        }
    }
};

fn dispatch(c: *Ctx, sc: Sc) Err!void {
    switch (sc.h) {
        .none => {},
        .open => try doOpen(c, sc),
        .stat => try doStat(c, sc, .fix_stat),
        .statx => try doStat(c, sc, .fix_statx),
        .fstat => {
            c.t.exit = .fix_stat;
            c.t.a0 = c.arg(sc.out);
        },
        .read_path => {
            var r: Resolved = .{};
            try c.resolveArg(sc, c.follows(sc), &r);
            try c.setPath(sc.path, r.host.slice());
        },
        .readlink => try doReadlink(c, sc),
        .mkdir => {
            var r: Resolved = .{};
            try c.resolveArg(sc, false, &r);
            if (r.exists) return sys.fail(.EXIST);
            try c.tr.vfs.prepareCreate(&r);
            c.setArg(@intCast(sc.mode), c.arg(@intCast(sc.mode)) | 0o700);
            try c.setPath(sc.path, r.host.slice());
        },
        .mknod => try doMknod(c, sc),
        .unlink, .rmdir => try doUnlink(c, sc),
        .symlink => {
            var r: Resolved = .{};
            try c.resolveArg(sc, false, &r);
            if (r.exists) return sys.fail(.EXIST);
            try c.tr.vfs.prepareCreate(&r);
            try c.setPath(sc.path, r.host.slice());
        },
        .link => try doLink(c, sc),
        .rename => try doRename(c, sc),
        .chmod => try doChmod(c, sc),
        .fchmod => try doFchmod(c, sc),
        .chown_path => {
            if (try c.emptyPath(sc)) return c.finish(0);
            var r: Resolved = .{};
            try c.resolveArg(sc, c.follows(sc), &r);
            if (!r.exists) return sys.fail(.NOENT);
            c.finish(0);
        },
        .chown_fd => c.finish(0),
        .utimens => try doUtimens(c, sc),
        .utime_path, .write_path, .write_meta => {
            var r: Resolved = .{};
            try c.resolveArg(sc, c.follows(sc), &r);
            if (r.exists) try c.tr.vfs.prepareWrite(&r);
            try c.setPath(sc.path, r.host.slice());
        },
        .chdir => {
            var r: Resolved = .{};
            try c.resolveArg(sc, true, &r);
            if (!r.exists) return sys.fail(.NOENT);
            if (!sys.isDir(r.mode)) return sys.fail(.NOTDIR);
            try c.p.cwd.set(r.guest.slice());
            c.finish(0);
        },
        .fchdir => {
            var g: Path = .{};
            try c.fdGuestPath(c.argI32(0), &g);
            var r: Resolved = .{};
            try c.tr.vfs.resolve(g.slice(), true, &r);
            if (!r.exists) return sys.fail(.NOENT);
            if (!sys.isDir(r.mode)) return sys.fail(.NOTDIR);
            try c.p.cwd.set(r.guest.slice());
            c.finish(0);
        },
        .getcwd => {
            const cwd = c.p.cwd.slice();
            if (c.arg(1) < cwd.len + 1) return sys.fail(.RANGE);
            try writeMem(c.t.tid, c.arg(0), cwd);
            try writeMem(c.t.tid, c.arg(0) + cwd.len, "\x00");
            c.finish(@intCast(cwd.len + 1));
        },
        .execve => try doExec(c, sys.AT_FDCWD, 0, 1, 0),
        .execveat => try doExec(c, c.argI32(0), 1, 2, c.arg(4)),
        .chroot => {
            var r: Resolved = .{};
            try c.resolveArg(sc, true, &r);
            if (r.guest.len == 1) return c.finish(0);
            return sys.fail(.PERM);
        },
        .bind => try doSock(c, false),
        .connect => try doSock(c, true),
        .getsockname => {
            c.t.exit = .fix_sockname;
            c.t.a0 = c.arg(sc.out);
            c.t.a1 = @bitCast(@as(i64, c.argI32(0)));
        },
        .sendto => try doSendto(c),
        .sendmsg => try doSendmsg(c),
        .sendmmsg => return sys.fail(.NETUNREACH),
        .setsockopt => {
            var v: [4]u8 = undefined;
            try readMem(c.t.tid, c.arg(3), &v);
            c.tr.noteV6Only(c.p.tgid, c.argI32(0), std.mem.readInt(i32, &v, .little) != 0);
        },
        .uname => {
            c.t.exit = .fix_uname;
            c.t.a0 = c.arg(sc.out);
        },
        .kill => try doKill(c),
        .tkill => {
            c.setArg(0, @intCast(c.tr.tidToReal(c.argI32(0)) orelse return sys.fail(.SRCH)));
        },
        .tgkill => {
            c.setArg(0, @intCast(c.tr.vToReal(c.argI32(0)) orelse return sys.fail(.SRCH)));
            c.setArg(1, @intCast(c.tr.tidToReal(c.argI32(1)) orelse return sys.fail(.SRCH)));
        },
        .pid_arg => {
            const v = c.argI32(sc.pid);
            if (v != 0) c.setArg(sc.pid, @intCast(c.tr.tidToReal(v) orelse return sys.fail(.SRCH)));
        },
        .getpid => c.finish(c.p.vpid),
        .gettid => c.finish(if (c.t.tid == c.p.tgid) c.p.vpid else c.t.tid),
        .getppid => c.finish(c.p.vppid),
        .getpgrp => c.finish(c.p.vpgid),
        .getpgid, .getsid => {
            const v = c.argI32(0);
            const p = if (v == 0) c.p else c.tr.by_vpid.get(v) orelse return sys.fail(.SRCH);
            c.finish(if (sc.h == .getpgid) p.vpgid else p.vsid);
        },
        .setpgid => try doSetpgid(c),
        .setsid => c.t.exit = .fix_setsid,
        .clone => {
            const max = c.tr.spec.limits.pids;
            if (max > 0 and c.tr.tracees.count() >= max) return sys.fail(.AGAIN);
            c.t.exit = .fix_clone;
        },
        .wait4 => {
            try translateWaitPid(c, 0);
            c.t.exit = .fix_wait;
        },
        .waitid => {
            const P_PID = 1;
            const P_PGID = 2;
            const id = c.argI32(1);
            if (c.arg(0) == P_PID) {
                c.setArg(1, @intCast(c.tr.vToReal(id) orelse return sys.fail(.CHILD)));
            } else if (c.arg(0) == P_PGID and id > 0) {
                c.setArg(1, @intCast(c.tr.groupReal(id) orelse return sys.fail(.CHILD)));
            }
            c.t.exit = .fix_waitid;
            c.t.a0 = c.arg(2);
            c.t.a1 = c.arg(3);
        },
        .getdents => {
            var buf: [sys.PATH_MAX]u8 = undefined;
            const host = c.fdHostPath(c.argI32(0), &buf) catch return;
            if (!std.mem.eql(u8, host, "/proc")) return;
            c.t.exit = .fix_dents;
            c.t.a0 = c.arg(1);
        },
        .sysinfo => if (c.tr.spec.limits.memory > 0) {
            c.t.exit = .fix_sysinfo;
            c.t.a0 = c.arg(sc.out);
        },
        .affinity => {
            const v = c.argI32(0);
            if (v != 0) c.setArg(0, @intCast(c.tr.tidToReal(v) orelse return sys.fail(.SRCH)));
            // With --cpus the mask is untouched but the guest should size its
            // thread pools for the quota.
            const l = c.tr.spec.limits;
            if (l.cpus_milli > 0 and l.cpuset == 0) {
                c.t.exit = .fix_affinity;
                c.t.a0 = c.arg(sc.out);
            }
        },
        .getid => {
            const ids = &c.p.ids;
            c.finish(switch (sc.id) {
                .uid => ids.ruid,
                .euid => ids.euid,
                .gid => ids.rgid,
                .egid => ids.egid,
                else => unreachable,
            });
        },
        .getresid => {
            const ids = &c.p.ids;
            const v: [3]u32 = if (sc.id == .uid)
                .{ ids.ruid, ids.euid, ids.suid }
            else
                .{ ids.rgid, ids.egid, ids.sgid };
            for (v, 0..) |x, i| try writeMem(c.t.tid, c.arg(i), std.mem.asBytes(&x));
            c.finish(0);
        },
        .setid => doSetId(c, sc.id),
        .getgroups => {
            const ids = &c.p.ids;
            const size = c.arg(0) & 0xffffffff;
            if (size != 0) {
                if (size < ids.ngroups) return sys.fail(.INVAL);
                try writeMem(c.t.tid, c.arg(1), std.mem.sliceAsBytes(ids.groups[0..ids.ngroups]));
            }
            c.finish(ids.ngroups);
        },
        .setgroups => {
            const ids = &c.p.ids;
            const n = @min(c.arg(0) & 0xffffffff, ids.groups.len);
            if (n > 0) try readMem(c.t.tid, c.arg(1), std.mem.sliceAsBytes(ids.groups[0..n]));
            ids.ngroups = @intCast(n);
            c.finish(0);
        },
        .capget => try doCapget(c),
        .succeed => c.finish(0),
        .eperm => return sys.fail(.PERM),
        .enosys => return sys.fail(.NOSYS),
        .shmget => try doShmget(c),
        .shmat => try doShmat(c),
        .shmdt => try doShmdt(c),
        .shmctl => try doShmctl(c),
        .ioctl_pgrp => try doTtyIoctl(c),
        .prctl_caps => c.finish(0),
    }
}

fn shmWho(c: *const Ctx) sysv.Who {
    return .{ .uid = c.p.ids.euid, .gid = c.p.ids.egid, .pid = c.p.vpid };
}

fn doShmget(c: *Ctx) Err!void {
    c.finish(try c.tr.shm.get(c.argI32(0), c.arg(1), @truncate(c.arg(2)), shmWho(c)));
}

fn doShmat(c: *Ctx) Err!void {
    const seg = c.tr.shm.find(c.argI32(0)) orelse return sys.fail(.INVAL);
    const flags: u32 = @truncate(c.arg(2));
    const read_only = flags & sysv.SHM_RDONLY != 0;
    if (!seg.allowed(shmWho(c), if (read_only) 4 else 6)) return sys.fail(.ACCES);

    const page: u64 = std.heap.pageSize();
    var addr = c.arg(1);
    if (addr != 0) {
        if (flags & sysv.SHM_RND != 0) addr &= ~(page - 1);
        if (addr & (page - 1) != 0) return sys.fail(.INVAL);
    } else if (flags & sysv.SHM_REMAP != 0) {
        return sys.fail(.INVAL);
    }

    const MAP_SHARED: u64 = 1;
    const MAP_FIXED: u64 = 0x10;
    const MAP_FIXED_NOREPLACE: u64 = 0x100000;
    var map_flags = MAP_SHARED;
    if (addr != 0) map_flags |= if (flags & sysv.SHM_REMAP != 0) MAP_FIXED else MAP_FIXED_NOREPLACE;
    var prot: u64 = 1;
    if (!read_only) prot |= 2;
    if (flags & sysv.SHM_EXEC != 0) prot |= 4;

    var file: Path = .{};
    try c.tr.shm.pathOf(seg.id, &file);
    const path = try c.pushZ(file.slice());
    const ch = &c.t.chain;
    ch.op = .shmat;
    ch.seg = seg.id;
    ch.addr = addr;
    ch.size = seg.size;
    ch.prot = prot;
    ch.map_flags = map_flags;
    const mode: u64 = if (read_only) 0 else sys.O_RDWR;
    try c.beginChain(.openat, .{ @bitCast(@as(i64, sys.AT_FDCWD)), path, mode | sys.O_CLOEXEC, 0, 0, 0 });
}

fn doShmdt(c: *Ctx) Err!void {
    const addr = c.arg(0);
    const a = c.tr.shm.attachmentAt(c.p.tgid, addr) orelse return sys.fail(.INVAL);
    c.t.chain.op = .shmdt;
    c.t.chain.addr = addr;
    try c.beginChain(.munmap, .{ addr, a.size, 0, 0, 0, 0 });
}

fn doShmctl(c: *Ctx) Err!void {
    const shm = &c.tr.shm;
    const who = shmWho(c);
    const IPC_64: u32 = 0x100;
    const cmd = @as(u32, @truncate(c.arg(1))) & ~IPC_64;
    const buf = c.arg(2);
    switch (cmd) {
        sysv.IPC_INFO => {
            const b = shm.info();
            try writeMem(c.t.tid, buf, &b);
            c.finish(@max(0, shm.highestIndex()));
        },
        sysv.SHM_INFO => {
            const b = shm.usage();
            try writeMem(c.t.tid, buf, &b);
            c.finish(@max(0, shm.highestIndex()));
        },
        sysv.SHM_STAT, sysv.SHM_STAT_ANY => {
            const index: usize = @truncate(c.arg(0) & 0xffffffff);
            if (index >= shm.segs.items.len) return sys.fail(.INVAL);
            const s = &shm.segs.items[index];
            if (cmd == sysv.SHM_STAT and !s.allowed(who, 4)) return sys.fail(.ACCES);
            const b = s.stat();
            try writeMem(c.t.tid, buf, &b);
            c.finish(s.id);
        },
        sysv.IPC_STAT => {
            const s = shm.find(c.argI32(0)) orelse return sys.fail(.INVAL);
            if (!s.allowed(who, 4)) return sys.fail(.ACCES);
            const b = s.stat();
            try writeMem(c.t.tid, buf, &b);
            c.finish(0);
        },
        sysv.IPC_SET => {
            const s = shm.find(c.argI32(0)) orelse return sys.fail(.INVAL);
            if (!s.isOwner(who)) return sys.fail(.PERM);
            var b: [sysv.stat_size]u8 = undefined;
            try readMem(c.t.tid, buf, &b);
            s.applySet(&b);
            c.finish(0);
        },
        sysv.IPC_RMID => {
            const s = shm.find(c.argI32(0)) orelse return sys.fail(.INVAL);
            if (!s.isOwner(who)) return sys.fail(.PERM);
            shm.remove(s);
            c.finish(0);
        },
        sysv.SHM_LOCK, sysv.SHM_UNLOCK => {
            if (shm.find(c.argI32(0)) == null) return sys.fail(.INVAL);
            c.finish(0);
        },
        else => return sys.fail(.INVAL),
    }
}

/// Terminal ioctls name process groups, which the guest knows by virtual id.
fn doTtyIoctl(c: *Ctx) Err!void {
    const cmd: u32 = @truncate(c.arg(1));
    switch (cmd) {
        TIOCSPGRP => {
            var b: [4]u8 = undefined;
            try readMem(c.t.tid, c.arg(2), &b);
            const real = c.tr.groupReal(std.mem.readInt(i32, &b, .little)) orelse return sys.fail(.SRCH);
            std.mem.writeInt(i32, &b, real, .little);
            c.setArg(2, try c.push(&b));
        },
        TIOCGPGRP, TIOCGSID => {
            c.t.exit = if (cmd == TIOCGPGRP) .fix_tty_pgrp else .fix_tty_sid;
            c.t.a0 = c.arg(2);
        },
        else => {},
    }
}

fn doOpen(c: *Ctx, sc: Sc) Err!void {
    const flags: usize = if (sc.flags >= 0)
        @truncate(c.arg(@intCast(sc.flags)))
    else
        sys.O_CREAT | sys.O_WRONLY | sys.O_TRUNC;
    const tmpfile = flags & sys.O_TMPFILE == sys.O_TMPFILE;
    const create = flags & sys.O_CREAT != 0 and !tmpfile;
    const nofollow = flags & sys.O_NOFOLLOW != 0 or (create and flags & sys.O_EXCL != 0);
    const writes = flags & sys.O_ACCMODE != 0 or flags & sys.O_TRUNC != 0;

    var r: Resolved = .{};
    try c.resolveArg(sc, !nofollow, &r);
    const vfs = c.tr.vfs;
    if (tmpfile) {
        if (r.exists) try vfs.prepareWrite(&r);
    } else if (create and !r.exists) {
        try vfs.prepareCreate(&r);
    } else if (r.exists and writes and !sys.isDir(r.mode)) {
        try vfs.prepareWrite(&r);
    }
    if (create or tmpfile) {
        const i: usize = @intCast(sc.mode);
        c.setArg(i, c.arg(i) | 0o600);
    }
    if (!writes and !create and !tmpfile) try c.tr.maybeFake(&r);
    try c.setPath(sc.path, r.host.slice());
}

fn doStat(c: *Ctx, sc: Sc, action: ExitAction) Err!void {
    c.t.exit = action;
    c.t.a0 = c.arg(sc.out);
    if (try c.emptyPath(sc)) return;
    var r: Resolved = .{};
    try c.resolveArg(sc, c.follows(sc), &r);
    try c.setPath(sc.path, r.host.slice());
}

fn doReadlink(c: *Ctx, sc: Sc) Err!void {
    var g: Path = .{};
    try c.guestOf(sc, &g);
    var num: [64]u8 = undefined;
    const self_link: ?[]const u8 = if (std.mem.eql(u8, g.slice(), "/proc/self"))
        std.fmt.bufPrint(&num, "{d}", .{c.p.vpid}) catch unreachable
    else if (std.mem.eql(u8, g.slice(), "/proc/thread-self"))
        std.fmt.bufPrint(&num, "{d}/task/{d}", .{ c.p.vpid, c.t.tid }) catch unreachable
    else
        null;
    if (self_link) |s| {
        const n = @min(s.len, c.arg(sc.out + 1));
        try writeMem(c.t.tid, c.arg(sc.out), s[0..n]);
        return c.finish(@intCast(n));
    }

    var r: Resolved = .{};
    try c.tr.vfs.resolve(g.slice(), false, &r);
    if (r.where == .proc) {
        var it = std.mem.tokenizeScalar(u8, r.guest.slice(), '/');
        _ = it.next();
        const pid_s = it.next() orelse "";
        const which = it.next() orelse "";
        const more = it.next();
        const pid = std.fmt.parseInt(i32, pid_s, 10) catch 0;
        if (pid != 0 and more == null and which.len > 0) {
            if (c.tr.tracees.get(pid)) |t| if (t.proc) |p| {
                const s: ?[]const u8 = if (std.mem.eql(u8, which, "exe"))
                    p.exe.slice()
                else if (std.mem.eql(u8, which, "cwd"))
                    p.cwd.slice()
                else if (std.mem.eql(u8, which, "root"))
                    "/"
                else
                    null;
                if (s) |str| {
                    const n = @min(str.len, c.arg(sc.out + 1));
                    try writeMem(c.t.tid, c.arg(sc.out), str[0..n]);
                    return c.finish(@intCast(n));
                }
            };
        }
        // Links like /proc/N/fd/M can point into the container's storage.
        c.t.exit = .fix_readlink;
        c.t.a0 = c.arg(sc.out);
        c.t.a1 = c.arg(sc.out + 1);
    }
    try c.setPath(sc.path, r.host.slice());
}

fn doMknod(c: *Ctx, sc: Sc) Err!void {
    var r: Resolved = .{};
    try c.resolveArg(sc, false, &r);
    if (r.exists) return sys.fail(.EXIST);
    try c.tr.vfs.prepareCreate(&r);
    const mode: u32 = @truncate(c.arg(@intCast(sc.mode)));
    const typ = mode & sys.S_IFMT;
    if (typ == sys.S_IFCHR or typ == sys.S_IFBLK) {
        // Device nodes need real root. A plain file is enough for what
        // packages do with them, which is mostly creating them.
        const fd = try sys.open(r.host.z(), sys.O_WRONLY | sys.O_CREAT | sys.O_EXCL, 0o600);
        sys.close(fd);
        return c.finish(0);
    }
    try c.setPath(sc.path, r.host.slice());
}

fn doUnlink(c: *Ctx, sc: Sc) Err!void {
    var r: Resolved = .{};
    try c.resolveArg(sc, false, &r);
    if (r.exists) try c.tr.vfs.prepareRemove(&r);
    try c.setPath(sc.path, r.host.slice());
}

fn doLink(c: *Ctx, sc: Sc) Err!void {
    const at = sc.dir >= 0;
    const old_dir = if (at) c.argI32(0) else sys.AT_FDCWD;
    const new_dir = if (at) c.argI32(2) else sys.AT_FDCWD;
    const old_addr = c.arg(if (at) 1 else 0);
    const new_addr = c.arg(if (at) 3 else 1);
    const flags: u64 = if (at) c.arg(4) else 0;

    var raw: Path = .{};
    var g: Path = .{};
    var old: Resolved = .{};
    var new: Resolved = .{};
    const vfs = c.tr.vfs;
    try readStr(c.t.tid, old_addr, &raw);
    try c.absolutize(old_dir, raw.slice(), &g);
    try vfs.resolve(g.slice(), flags & sys.AT_SYMLINK_FOLLOW != 0, &old);
    try readStr(c.t.tid, new_addr, &raw);
    try c.absolutize(new_dir, raw.slice(), &g);
    try vfs.resolve(g.slice(), false, &new);

    if (!old.exists) return sys.fail(.NOENT);
    if (sys.isDir(old.mode)) return sys.fail(.PERM);
    if (new.exists) return sys.fail(.EXIST);
    try vfs.prepareWrite(&old);
    try vfs.prepareCreate(&new);

    const rc = linux.linkat(sys.AT_FDCWD, old.host.z(), sys.AT_FDCWD, new.host.z(), 0);
    const e = linux.errno(rc);
    if (e == .SUCCESS) return c.finish(0);
    // SELinux forbids hard links to Android apps; a copy behaves the same
    // for nearly everything that makes them.
    if (e != .PERM and e != .ACCES and e != .XDEV and e != .OPNOTSUPP) return sys.fail(e);
    if (sys.isLnk(old.mode)) {
        var tbuf: [sys.PATH_MAX]u8 = undefined;
        const target = try sys.readlink(old.host.z(), tbuf[0 .. tbuf.len - 1]);
        tbuf[target.len] = 0;
        try sys.symlink(@ptrCast(&tbuf), new.host.z());
    } else {
        try Vfs.copyFile(old.host.z(), new.host.z());
    }
    c.finish(0);
}

fn doRename(c: *Ctx, sc: Sc) Err!void {
    const at = sc.dir >= 0;
    const old_dir = if (at) c.argI32(0) else sys.AT_FDCWD;
    const new_dir = if (at) c.argI32(2) else sys.AT_FDCWD;
    const old_idx: usize = if (at) 1 else 0;
    const new_idx: usize = if (at) 3 else 1;

    var raw: Path = .{};
    var g: Path = .{};
    var old: Resolved = .{};
    var new: Resolved = .{};
    const vfs = c.tr.vfs;
    try readStr(c.t.tid, c.arg(old_idx), &raw);
    try c.absolutize(old_dir, raw.slice(), &g);
    try vfs.resolve(g.slice(), false, &old);
    try readStr(c.t.tid, c.arg(new_idx), &raw);
    try c.absolutize(new_dir, raw.slice(), &g);
    try vfs.resolve(g.slice(), false, &new);

    if (!old.exists) return sys.fail(.NOENT);
    try vfs.prepareRenameSource(&old);
    if (new.exists) {
        try vfs.prepareRemove(&new);
    } else {
        try vfs.prepareCreate(&new);
    }
    try c.setPath(old_idx, old.host.slice());
    try c.setPath(new_idx, new.host.slice());
}

fn doChmod(c: *Ctx, sc: Sc) Err!void {
    var r: Resolved = .{};
    try c.resolveArg(sc, c.follows(sc), &r);
    if (r.exists) {
        try c.tr.vfs.prepareWrite(&r);
        const i: usize = @intCast(sc.mode);
        c.setArg(i, c.arg(i) | (if (sys.isDir(r.mode)) @as(u64, 0o700) else 0o600));
    }
    try c.setPath(sc.path, r.host.slice());
}

/// True when an fd refers to the read-only image rather than to `upper`.
fn fdInLower(c: *Ctx, fd: i32) Err!bool {
    var buf: [sys.PATH_MAX]u8 = undefined;
    const host = try c.fdHostPath(fd, &buf);
    for (c.tr.vfs.lowers) |lower| {
        if (std.mem.startsWith(u8, host, lower) and (host.len == lower.len or host[lower.len] == '/')) return true;
    }
    return false;
}

fn doFchmod(c: *Ctx, sc: Sc) Err!void {
    const fd = c.argI32(0);
    const i: usize = @intCast(sc.mode);
    const mode: u32 = @truncate(c.arg(i));
    if (try fdInLower(c, fd)) {
        // The fd points into the image, which must stay pristine.
        var g: Path = .{};
        try c.fdGuestPath(fd, &g);
        var r: Resolved = .{};
        try c.tr.vfs.resolve(g.slice(), true, &r);
        if (r.exists) {
            try c.tr.vfs.prepareWrite(&r);
            try sys.chmod(r.host.z(), mode | (if (sys.isDir(r.mode)) @as(u32, 0o700) else 0o600));
        }
        return c.finish(0);
    }
    c.setArg(i, mode | 0o600);
}

fn doUtimens(c: *Ctx, sc: Sc) Err!void {
    const addr = c.arg(sc.path);
    if (addr == 0 or try c.emptyPath(sc)) {
        // futimens(): leave the image's timestamps alone.
        if (try fdInLower(c, c.argI32(0))) c.finish(0);
        return;
    }
    var r: Resolved = .{};
    try c.resolveArg(sc, c.follows(sc), &r);
    if (r.exists) try c.tr.vfs.prepareWrite(&r);
    try c.setPath(sc.path, r.host.slice());
}

fn doSetId(c: *Ctx, id: scs.Id) void {
    const ids = &c.p.ids;
    const none: u32 = 0xffffffff;
    const a0: u32 = @truncate(c.arg(0));
    const a1: u32 = @truncate(c.arg(1));
    const a2: u32 = @truncate(c.arg(2));
    switch (id) {
        .setuid => {
            if (ids.euid == 0) {
                ids.ruid = a0;
                ids.suid = a0;
            }
            ids.euid = a0;
            ids.fsuid = a0;
        },
        .setgid => {
            if (ids.euid == 0) {
                ids.rgid = a0;
                ids.sgid = a0;
            }
            ids.egid = a0;
            ids.fsgid = a0;
        },
        .setreuid, .setresuid => {
            if (a0 != none) ids.ruid = a0;
            if (a1 != none) {
                ids.euid = a1;
                ids.fsuid = a1;
            }
            if (id == .setresuid and a2 != none) ids.suid = a2;
        },
        .setregid, .setresgid => {
            if (a0 != none) ids.rgid = a0;
            if (a1 != none) {
                ids.egid = a1;
                ids.fsgid = a1;
            }
            if (id == .setresgid and a2 != none) ids.sgid = a2;
        },
        .setfsuid => {
            const old = ids.fsuid;
            if (a0 != none) ids.fsuid = a0;
            return c.finish(old);
        },
        .setfsgid => {
            const old = ids.fsgid;
            if (a0 != none) ids.fsgid = a0;
            return c.finish(old);
        },
        else => unreachable,
    }
    c.finish(0);
}

fn doCapget(c: *Ctx) Err!void {
    const V3: u32 = 0x20080522;
    var hdr: [2]u32 = undefined;
    try readMem(c.t.tid, c.arg(0), std.mem.sliceAsBytes(&hdr));
    if (hdr[0] != V3 and hdr[0] != 0x20071026 and hdr[0] != 0x19980330) {
        hdr[0] = V3;
        try writeMem(c.t.tid, c.arg(0), std.mem.sliceAsBytes(&hdr));
        if (c.arg(1) == 0) return c.finish(0);
        return sys.fail(.INVAL);
    }
    if (c.arg(1) != 0) {
        const v: u32 = if (c.p.ids.euid == 0) 0xffffffff else 0;
        const data = [6]u32{ v, v, 0, v, v, 0 };
        const n: usize = if (hdr[0] == 0x19980330) 3 else 6;
        try writeMem(c.t.tid, c.arg(1), std.mem.sliceAsBytes(data[0..n]));
    }
    c.finish(0);
}

fn doKill(c: *Ctx) Err!void {
    const pid = c.argI32(0);
    const sig: u32 = @truncate(c.arg(1));
    if (pid > 0) {
        c.setArg(0, @intCast(c.tr.tidToReal(pid) orelse c.tr.vToReal(pid) orelse return sys.fail(.SRCH)));
        return;
    }
    if (pid == -1) {
        // Must never reach the tracer or another container.
        if (sig != 0) {
            var it = c.tr.by_vpid.valueIterator();
            while (it.next()) |p| {
                if (p.*.tgid != c.p.tgid) _ = linux.kill(p.*.tgid, @fromBackingInt(sig));
            }
        }
        return c.finish(0);
    }
    if (pid < -1) {
        const real = c.tr.groupReal(-pid) orelse return sys.fail(.SRCH);
        c.setArg(0, @bitCast(@as(i64, -real)));
    }
}

fn translateWaitPid(c: *Ctx, idx: usize) Err!void {
    const v = c.argI32(idx);
    if (v > 0) {
        c.setArg(idx, @intCast(c.tr.vToReal(v) orelse return sys.fail(.CHILD)));
    } else if (v < -1) {
        const real = c.tr.groupReal(-v) orelse return sys.fail(.CHILD);
        c.setArg(idx, @bitCast(@as(i64, -real)));
    }
}

fn doSetpgid(c: *Ctx) Err!void {
    const v = c.argI32(0);
    const target = if (v == 0) c.p else c.tr.by_vpid.get(v) orelse return sys.fail(.SRCH);
    const vg = c.argI32(1);
    const new_group = if (vg == 0) target.vpid else vg;
    const real_group = if (new_group == target.vpid)
        target.tgid
    else
        c.tr.groupReal(new_group) orelse return sys.fail(.PERM);
    c.setArg(0, @intCast(target.tgid));
    c.setArg(1, @intCast(real_group));
    c.t.exit = .fix_setpgid;
    c.t.a0 = @intCast(target.tgid);
    c.t.a1 = @intCast(new_group);
    c.t.a2 = @intCast(real_group);
}

fn sockIp4(fam: u16, sa: []const u8) ?[4]u8 {
    if (fam == linux.AF.INET) return sa[4..8].*;
    if (sa.len < 24) return null;
    const ip = sa[8..24];
    if (std.mem.allEqual(u8, ip[0..10], 0) and ip[10] == 0xff and ip[11] == 0xff) return ip[12..16].*;
    return null;
}

fn isWildcard(fam: u16, sa: []const u8) bool {
    if (fam == linux.AF.INET) return std.mem.allEqual(u8, sa[4..8], 0);
    return sa.len >= 24 and std.mem.allEqual(u8, sa[8..24], 0);
}

fn isV6Loopback(sa: []const u8) bool {
    return sa.len >= 24 and std.mem.allEqual(u8, sa[8..23], 0) and sa[23] == 1;
}

fn setPort(sa: []u8, port: u16) void {
    std.mem.writeInt(u16, sa[2..4], port, .big);
}

/// Points an address at IPv4 loopback, in the socket's own family.
fn setLoopback(fam: u16, sa: []u8) void {
    if (fam == linux.AF.INET) {
        @memcpy(sa[4..8], &[4]u8{ 127, 0, 0, 1 });
    } else {
        @memset(sa[8..18], 0);
        @memcpy(sa[18..24], &[6]u8{ 0xff, 0xff, 127, 0, 0, 1 });
    }
}

fn setV6Loopback(sa: []u8) void {
    @memset(sa[8..23], 0);
    sa[23] = 1;
}

/// Applies the container's network rules to an outgoing address. Returns true
/// if `sa` was rewritten; denied destinations fail with the given errno.
fn routeOut(c: *Ctx, fam: u16, sa: []u8) Err!bool {
    const tr = c.tr;
    if (sa.len < 8 or (fam == linux.AF.INET6 and sa.len < 24)) return false;
    const port = std.mem.readInt(u16, sa[2..4], .big);
    const ip4 = sockIp4(fam, sa);
    const v6_lo = fam == linux.AF.INET6 and isV6Loopback(sa);
    const wildcard = isWildcard(fam, sa);

    if (v6_lo or wildcard or (ip4 != null and ip4.?[0] == 127)) {
        // Loopback is private to the container, as in a network namespace.
        // A port nobody bound goes to one that is always closed, rather than
        // failing here: connect() on a UDP socket must succeed all the same,
        // and musl's getaddrinfo relies on that to test for a network.
        const m = tr.findPort(port) orelse PortMap{ .container = port, .host = 1, .fixed = false };
        setPort(sa, m.host);
        if (wildcard) setLoopback(fam, sa);
        if (v6_lo and m.kind == .dual) setLoopback(fam, sa);
        return true;
    }

    if (ip4) |ip| {
        if (ip[0] == 10 and ip[1] == 88) {
            if (tr.spec.net_mode == .none) return sys.fail(.NETUNREACH);
            if (tr.spec.host_gateway and ip[2] == 0 and ip[3] == 1) {
                setLoopback(fam, sa);
                return true;
            }
            setPort(sa, try tr.peerPort(ip, port));
            setLoopback(fam, sa);
            return true;
        }
        if (tr.isHostAddr(ip)) return sys.fail(.CONNREFUSED);
    }
    if (tr.spec.net_mode != .bridge) return sys.fail(.NETUNREACH);
    return false;
}

/// Decides where a listening socket really goes. Only ports published with
/// `-p` may face the LAN; the rest stay on loopback, reachable through the
/// private network.
fn routeBind(c: *Ctx, fam: u16, sa: []u8, fd: i32) bool {
    const tr = c.tr;
    if (sa.len < 8 or (fam == linux.AF.INET6 and sa.len < 24)) return false;
    const kind: SocketKind = if (fam == linux.AF.INET)
        .v4
    else if (tr.isV6Only(c.p.tgid, fd))
        .v6only
    else
        .dual;
    const port = std.mem.readInt(u16, sa[2..4], .big);
    const wildcard = isWildcard(fam, sa);
    const ip4 = sockIp4(fam, sa);
    const own = ip4 != null and std.mem.eql(u8, &ip4.?, &tr.spec.ip);

    var published = false;
    var changed = false;
    if (port == 0) {
        // Usually a client choosing its source address (DNS lookups do this).
        // On loopback it could not reach anything outside.
        tr.noteZeroBind(c.p.tgid, fd, kind);
        return false;
    } else {
        const m = tr.mapPort(port, kind);
        published = m.fixed;
        if (m.host != port) {
            setPort(sa, m.host);
            changed = true;
        }
    }
    if ((wildcard or own) and !published) {
        if (kind == .v6only) setV6Loopback(sa) else setLoopback(fam, sa);
        changed = true;
    } else if (own) {
        @memset(sa[4..8], 0);
        changed = true;
    }
    return changed;
}

fn doSendto(c: *Ctx) Err!void {
    const addr = c.arg(4);
    const len: usize = @truncate(c.arg(5));
    if (addr == 0 or len < 2) return;
    var sa: [128]u8 = undefined;
    const n = @min(len, sa.len);
    try readMem(c.t.tid, addr, sa[0..n]);
    const fam = std.mem.readInt(u16, sa[0..2], .little);
    if (fam != linux.AF.INET and fam != linux.AF.INET6) return;
    if (try routeOut(c, fam, sa[0..n])) c.setArg(4, try c.push(sa[0..n]));
}

fn doSendmsg(c: *Ctx) Err!void {
    var msg: [56]u8 align(8) = undefined;
    try readMem(c.t.tid, c.arg(1), &msg);
    const name = std.mem.readInt(u64, msg[0..8], .little);
    const namelen = std.mem.readInt(u32, msg[8..12], .little);
    if (name == 0 or namelen < 2) return;
    var sa: [128]u8 = undefined;
    const n = @min(namelen, sa.len);
    try readMem(c.t.tid, name, sa[0..n]);
    const fam = std.mem.readInt(u16, sa[0..2], .little);
    if (fam != linux.AF.INET and fam != linux.AF.INET6) return;
    if (try routeOut(c, fam, sa[0..n])) {
        std.mem.writeInt(u64, msg[0..8], try c.push(sa[0..n]), .little);
        c.setArg(1, try c.push(&msg));
    }
}

/// So that stat() and unlink() still see something at the socket's path.
fn keepSocketVisible(r: *Resolved) void {
    const fd = sys.open(r.host.z(), sys.O_WRONLY | sys.O_CREAT, 0o600) catch -1;
    if (fd >= 0) sys.close(fd);
}

/// Whether a socket file can be created in `dir`. It cannot when the path does
/// not fit in an address, or for Android domains like `adb shell`, where
/// SELinux forbids socket files altogether.
fn socketFilesWork(dir: []const u8) bool {
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return true;
    const fd: i32 = @intCast(rc);
    defer sys.close(fd);
    var sa: linux.sockaddr.un = .{ .path = undefined };
    @memset(&sa.path, 0);
    // Room is left for the 16-digit names used for long paths.
    if (dir.len + 18 >= sa.path.len) return false;
    const name = std.fmt.bufPrint(&sa.path, "{s}/p{d}", .{ dir, linux.getpid() }) catch return false;
    const e = linux.errno(linux.bind(fd, @ptrCast(&sa), @intCast(2 + name.len + 1)));
    if (e == .SUCCESS or e == .ADDRINUSE) {
        const path: [*:0]const u8 = @ptrCast(&sa.path);
        sys.unlink(path) catch {};
        return true;
    }
    return e != .ACCES and e != .PERM;
}

fn doSock(c: *Ctx, is_connect: bool) Err!void {
    const addr = c.arg(1);
    const len: usize = @truncate(c.arg(2));
    if (addr == 0 or len < 2) return;
    var sa: [128]u8 = undefined;
    const n = @min(len, sa.len);
    try readMem(c.t.tid, addr, sa[0..n]);
    const fam = std.mem.readInt(u16, sa[0..2], .little);

    if (fam == linux.AF.UNIX) {
        if (n <= 2) return; // unnamed
        if (sa[2] == 0) {
            // Abstract sockets are global; keep each container's to itself.
            const ns = c.tr.spec.ns_id;
            if (ns.len == 0) return;
            var out: [110]u8 = undefined;
            const total = n + ns.len;
            if (total > out.len) return sys.fail(.NAMETOOLONG);
            @memcpy(out[0..3], sa[0..3]);
            @memcpy(out[3..][0..ns.len], ns);
            @memcpy(out[3 + ns.len..][0 .. n - 3], sa[3..n]);
            c.setArg(1, try c.push(out[0..total]));
            c.setArg(2, total);
            return;
        }
        const name = std.mem.sliceTo(sa[2..n], 0);
        var g: Path = .{};
        try c.absolutize(sys.AT_FDCWD, name, &g);
        var r: Resolved = .{};
        const vfs = c.tr.vfs;
        try vfs.resolve(g.slice(), is_connect, &r);
        if (!is_connect) {
            if (r.exists) return sys.fail(.ADDRINUSE);
            try vfs.prepareCreate(&r);
        }

        if (c.tr.unix_abstract) {
            if (is_connect and !r.exists) return sys.fail(.NOENT);
            if (!is_connect) keepSocketVisible(&r);
            var abs: [40]u8 = undefined;
            std.mem.writeInt(u16, abs[0..2], linux.AF.UNIX, .little);
            abs[2] = 0;
            // Named after the file, so a socket on a shared volume is still shared.
            const label = std.fmt.bufPrint(abs[3..], "pdock-{x}", .{std.hash.Wyhash.hash(0, r.host.slice())}) catch unreachable;
            c.setArg(1, try c.push(abs[0 .. 3 + label.len]));
            c.setArg(2, 3 + label.len);
            return;
        }

        // sun_path holds 108 bytes, and container paths are often longer.
        var host = r.host;
        if (host.len >= 100) {
            var h: [64]u8 = undefined;
            const hash = std.hash.Wyhash.hash(0, r.host.slice());
            host = try Path.of(c.tr.spec.sock_dir);
            try host.append(std.fmt.bufPrint(&h, "/{x}", .{hash}) catch unreachable);
            if (host.len >= 108) return sys.fail(.NAMETOOLONG);
            if (!is_connect) {
                sys.unlink(host.z()) catch {};
                keepSocketVisible(&r);
            }
        }
        var out: [110]u8 = undefined;
        std.mem.writeInt(u16, out[0..2], linux.AF.UNIX, .little);
        @memcpy(out[2..][0..host.len], host.slice());
        out[2 + host.len] = 0;
        const total = 2 + host.len + 1;
        c.setArg(1, try c.push(out[0..total]));
        c.setArg(2, total);
        return;
    }

    if (fam != linux.AF.INET and fam != linux.AF.INET6) return;
    const changed = if (is_connect)
        try routeOut(c, fam, sa[0..n])
    else
        routeBind(c, fam, sa[0..n], c.argI32(0));
    if (changed) c.setArg(1, try c.push(sa[0..n]));
}

const ElfKind = union(enum) { not_elf, wrong_arch, static, dynamic: Path };

fn inspectElf(host: [*:0]const u8) Err!ElfKind {
    const fd = try sys.open(host, 0, 0);
    defer sys.close(fd);
    var eh: [64]u8 = undefined;
    const n = try sys.readFull(fd, &eh);
    if (n < 64 or !std.mem.eql(u8, eh[0..4], "\x7fELF")) return .not_elf;
    if (eh[4] != 2 or std.mem.readInt(u16, eh[18..20], .little) != arch.elf_machine) return .wrong_arch;
    const phoff = std.mem.readInt(u64, eh[32..40], .little);
    const phentsize = std.mem.readInt(u16, eh[54..56], .little);
    const phnum = std.mem.readInt(u16, eh[56..58], .little);
    var i: u16 = 0;
    while (i < phnum) : (i += 1) {
        var ph: [56]u8 = undefined;
        const off = phoff + @as(u64, i) * phentsize;
        _ = try sys.ck(linux.pread(fd, &ph, ph.len, @intCast(off)));
        if (std.mem.readInt(u32, ph[0..4], .little) != 3) continue; // PT_INTERP
        const p_off = std.mem.readInt(u64, ph[8..16], .little);
        const p_size = std.mem.readInt(u64, ph[32..40], .little);
        if (p_size == 0 or p_size >= sys.PATH_MAX) return sys.fail(.NOEXEC);
        var interp: Path = .{};
        _ = try sys.ck(linux.pread(fd, &interp.buf, p_size, @intCast(p_off)));
        interp.len = std.mem.indexOfScalar(u8, interp.buf[0..p_size], 0) orelse p_size;
        return .{ .dynamic = interp };
    }
    return .static;
}

const max_front = 12;

/// The kernel would look for a script's interpreter, or a binary's dynamic
/// loader, on the host. So the tracer does that part of exec itself and
/// launches the guest's loader directly.
fn doExec(c: *Ctx, dirfd: i32, path_idx: usize, argv_idx: usize, flags: u64) Err!void {
    const vfs = c.tr.vfs;
    var raw: Path = .{};
    var g: Path = .{};
    if (flags & sys.AT_EMPTY_PATH != 0) {
        try c.fdGuestPath(dirfd, &g);
        raw = g;
    } else {
        try readStr(c.t.tid, c.arg(path_idx), &raw);
        if (raw.len == 0) return sys.fail(.NOENT);
        try c.absolutize(dirfd, raw.slice(), &g);
    }

    {
        const slash = std.mem.lastIndexOfScalar(u8, raw.slice(), '/');
        const base = if (slash) |i| raw.slice()[i + 1 ..] else raw.slice();
        const n = @min(base.len, c.p.pending_comm.len);
        @memcpy(c.p.pending_comm[0..n], base[0..n]);
        c.p.pending_comm_len = @intCast(n);
    }

    var front: [max_front]Path = undefined;
    var nfront: usize = 0;
    var replaced = false;
    var r: Resolved = .{};
    var kind: ElfKind = .not_elf;

    var depth: u32 = 0;
    while (true) : (depth += 1) {
        if (depth > 4) return sys.fail(.LOOP);
        try vfs.resolve(g.slice(), true, &r);
        if (!r.exists) return sys.fail(.NOENT);
        if (sys.isDir(r.mode) or r.mode & 0o111 == 0) return sys.fail(.ACCES);

        const fd = try sys.open(r.host.z(), 0, 0);
        var head: [256]u8 = undefined;
        const n = sys.readFull(fd, &head) catch 0;
        sys.close(fd);

        if (n >= 2 and head[0] == '#' and head[1] == '!') {
            const eol = std.mem.indexOfScalar(u8, head[2..n], '\n') orelse n - 2;
            const line = std.mem.trim(u8, head[2..][0..eol], " \t\r");
            if (line.len == 0) return sys.fail(.NOEXEC);
            const sp = std.mem.indexOfAny(u8, line, " \t");
            const interp = if (sp) |i| line[0..i] else line;
            const opt = if (sp) |i| std.mem.trim(u8, line[i..], " \t") else "";

            var next: [max_front]Path = undefined;
            var nn: usize = 0;
            next[nn] = try Path.of(interp);
            nn += 1;
            if (opt.len > 0) {
                next[nn] = try Path.of(opt);
                nn += 1;
            }
            next[nn] = raw;
            nn += 1;
            if (replaced) {
                for (front[1..nfront]) |f| {
                    if (nn >= max_front) return sys.fail(.@"2BIG");
                    next[nn] = f;
                    nn += 1;
                }
            }
            front = next;
            nfront = nn;
            replaced = true;
            try raw.set(interp);
            try c.absolutize(sys.AT_FDCWD, interp, &g);
            continue;
        }

        kind = try inspectElf(r.host.z());
        break;
    }

    switch (kind) {
        .not_elf, .wrong_arch => return sys.fail(.NOEXEC),
        else => {},
    }

    // Read the original argv, whose strings can be reused in place.
    var orig: std.ArrayList(u64) = .empty;
    defer orig.deinit(c.tr.gpa);
    var ap = c.arg(argv_idx);
    if (ap != 0) {
        while (orig.items.len < 1 << 20) : (ap += 8) {
            var v: u64 = 0;
            try readMem(c.t.tid, ap, std.mem.asBytes(&v));
            if (v == 0) break;
            orig.append(c.tr.gpa, v) catch return sys.fail(.NOMEM);
        }
    }

    var new_argv: std.ArrayList(u64) = .empty;
    defer new_argv.deinit(c.tr.gpa);
    const gpa = c.tr.gpa;
    const oom = struct {
        fn f() Err {
            return sys.fail(.NOMEM);
        }
    }.f;

    var exec_host: Path = undefined;
    const rewrite: bool = switch (kind) {
        .dynamic => true,
        else => replaced,
    };

    switch (kind) {
        .dynamic => |interp| {
            var ld: Resolved = .{};
            var interp_copy = interp;
            try vfs.resolve(interp_copy.slice(), true, &ld);
            if (!ld.exists) return sys.fail(.NOENT);
            exec_host = ld.host;

            const prog_addr = try c.pushZ(r.guest.slice());
            new_argv.append(gpa, prog_addr) catch return oom();

            const has_argv0 = c.tr.ldHasArgv0(ld.host.slice());
            c.p.pending_cmdline = if (has_argv0) .ld_argv0 else .ld_plain;
            if (has_argv0) {
                const opt_addr = try c.pushZ("--argv0");
                new_argv.append(gpa, opt_addr) catch return oom();
                const a0: u64 = if (replaced)
                    try c.pushZ(front[0].slice())
                else if (orig.items.len > 0)
                    orig.items[0]
                else
                    prog_addr;
                new_argv.append(gpa, a0) catch return oom();
            }
            new_argv.append(gpa, prog_addr) catch return oom();
        },
        else => {
            exec_host = r.host;
            c.p.pending_cmdline = .plain;
        },
    }

    if (rewrite) {
        if (replaced) {
            // A static interpreter needs its own argv[0]; for a dynamic one
            // the program path above already plays that role.
            const skip: usize = if (kind == .dynamic) 1 else 0;
            for (front[skip..nfront]) |f| {
                new_argv.append(gpa, try c.pushZ(f.slice())) catch return oom();
            }
        }
        if (orig.items.len > 1) {
            new_argv.appendSlice(gpa, orig.items[1..]) catch return oom();
        }
        new_argv.append(gpa, 0) catch return oom();
        c.setArg(argv_idx, try c.push(std.mem.sliceAsBytes(new_argv.items)));
    }

    try c.p.pending_exe.set(r.guest.slice());
    try c.setPath(path_idx, exec_host.slice());
    if (path_idx == 1) c.setArg(4, 0); // execveat: the path is now absolute
}
