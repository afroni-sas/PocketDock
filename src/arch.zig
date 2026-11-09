//! Per-architecture register access for the tracer.

const std = @import("std");
const builtin = @import("builtin");
const sys = @import("sys.zig");
const linux = sys.linux;
const PT = linux.PTRACE;

pub const audit_arch: u32 = switch (builtin.cpu.arch) {
    .x86_64 => 0xC000003E,
    .aarch64 => 0xC00000B7,
    else => @compileError("PocketDock supports x86_64 and aarch64 only"),
};

pub const elf_machine: u16 = switch (builtin.cpu.arch) {
    .x86_64 => 62,
    .aarch64 => 183,
    else => unreachable,
};

/// Name of this CPU in OCI image platforms.
pub const oci_arch: []const u8 = switch (builtin.cpu.arch) {
    .x86_64 => "amd64",
    .aarch64 => "arm64",
    else => unreachable,
};

pub const Regs = switch (builtin.cpu.arch) {
    .x86_64 => extern struct {
        r15: u64,
        r14: u64,
        r13: u64,
        r12: u64,
        rbp: u64,
        rbx: u64,
        r11: u64,
        r10: u64,
        r9: u64,
        r8: u64,
        rax: u64,
        rcx: u64,
        rdx: u64,
        rsi: u64,
        rdi: u64,
        orig_rax: u64,
        rip: u64,
        cs: u64,
        eflags: u64,
        rsp: u64,
        ss: u64,
        fs_base: u64,
        gs_base: u64,
        ds: u64,
        es: u64,
        fs: u64,
        gs: u64,
    },
    .aarch64 => extern struct {
        regs: [31]u64,
        sp: u64,
        pc: u64,
        pstate: u64,
    },
    else => unreachable,
};

const NT_PRSTATUS: usize = 1;
const NT_ARM_SYSTEM_CALL: usize = 0x404;

const IoVec = extern struct { base: usize, len: usize };

pub fn getRegs(pid: i32, r: *Regs) sys.Err!void {
    if (builtin.cpu.arch == .x86_64) {
        _ = try sys.ck(linux.ptrace(PT.GETREGS, pid, 0, @intFromPtr(r), 0));
    } else {
        var iov: IoVec = .{ .base = @intFromPtr(r), .len = @sizeOf(Regs) };
        _ = try sys.ck(linux.ptrace(PT.GETREGSET, pid, NT_PRSTATUS, @intFromPtr(&iov), 0));
    }
}

pub fn setRegs(pid: i32, r: *Regs) sys.Err!void {
    if (builtin.cpu.arch == .x86_64) {
        _ = try sys.ck(linux.ptrace(PT.SETREGS, pid, 0, @intFromPtr(r), 0));
    } else {
        var iov: IoVec = .{ .base = @intFromPtr(r), .len = @sizeOf(Regs) };
        _ = try sys.ck(linux.ptrace(PT.SETREGSET, pid, NT_PRSTATUS, @intFromPtr(&iov), 0));
    }
}

pub fn sysno(r: *const Regs) u64 {
    return if (builtin.cpu.arch == .x86_64) r.orig_rax else r.regs[8];
}

/// Changes the pending syscall. -1 makes the kernel skip it entirely, leaving
/// the return register as the tracer set it.
pub fn setSysno(pid: i32, r: *Regs, nr: i64) sys.Err!void {
    if (builtin.cpu.arch == .x86_64) {
        r.orig_rax = @bitCast(nr);
    } else {
        var v: i32 = @intCast(nr);
        var iov: IoVec = .{ .base = @intFromPtr(&v), .len = @sizeOf(i32) };
        _ = try sys.ck(linux.ptrace(PT.SETREGSET, pid, NT_ARM_SYSTEM_CALL, @intFromPtr(&iov), 0));
        r.regs[8] = @bitCast(nr);
    }
}

pub fn arg(r: *const Regs, i: usize) u64 {
    if (builtin.cpu.arch == .x86_64) {
        return switch (i) {
            0 => r.rdi,
            1 => r.rsi,
            2 => r.rdx,
            3 => r.r10,
            4 => r.r8,
            5 => r.r9,
            else => unreachable,
        };
    }
    return r.regs[i];
}

pub fn setArg(r: *Regs, i: usize, v: u64) void {
    if (builtin.cpu.arch == .x86_64) {
        switch (i) {
            0 => r.rdi = v,
            1 => r.rsi = v,
            2 => r.rdx = v,
            3 => r.r10 = v,
            4 => r.r8 = v,
            5 => r.r9 = v,
            else => unreachable,
        }
    } else {
        r.regs[i] = v;
    }
}

pub fn ret(r: *const Regs) i64 {
    return @bitCast(if (builtin.cpu.arch == .x86_64) r.rax else r.regs[0]);
}

pub fn setRet(r: *Regs, v: i64) void {
    if (builtin.cpu.arch == .x86_64) r.rax = @bitCast(v) else r.regs[0] = @bitCast(v);
}

pub fn sp(r: *const Regs) u64 {
    return if (builtin.cpu.arch == .x86_64) r.rsp else r.sp;
}

/// Offsets of `st_uid`/`st_gid` in the guest's `struct stat`.
pub const stat_uid_off: u64 = @offsetOf(sys.Stat, "uid");
pub const stat_gid_off: u64 = @offsetOf(sys.Stat, "gid");
