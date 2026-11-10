//! The user's side of `run -it` and `exec -it`.
//!
//! The guest gets a real pseudo-terminal. This end copies bytes between it and
//! the user's terminal, which goes into raw mode so that Ctrl-C and friends
//! reach the guest's own line discipline instead of acting on PocketDock.

const std = @import("std");
const sys = @import("sys.zig");
const linux = sys.linux;

const TCGETS: u32 = 0x5401;
const TCSETSW: u32 = 0x5403;
const TIOCGWINSZ: u32 = 0x5413;
const TIOCSWINSZ: u32 = 0x5414;

/// The kernel's `struct termios`, the same on x86_64 and aarch64.
const Termios = extern struct {
    iflag: u32,
    oflag: u32,
    cflag: u32,
    lflag: u32,
    line: u8,
    cc: [19]u8,
};

var resized = std.atomic.Value(bool).init(false);

fn onWinch(_: linux.SIG) callconv(.c) void {
    resized.store(true, .monotonic);
}

/// Gives terminal `to` the size of the user's terminal. Either end of a
/// pipeline may be something else, so stdin and stdout are both tried.
pub fn copySize(to: i32) void {
    var size: [8]u8 align(8) = undefined;
    for ([_]i32{ 0, 1 }) |from| {
        if (linux.errno(linux.ioctl(from, TIOCGWINSZ, @intFromPtr(&size))) != .SUCCESS) continue;
        _ = linux.ioctl(to, TIOCSWINSZ, @intFromPtr(&size));
        return;
    }
}

const RawMode = struct {
    fd: i32,
    saved: Termios = undefined,
    active: bool = false,

    fn enter(fd: i32) RawMode {
        var self: RawMode = .{ .fd = fd };
        if (linux.errno(linux.ioctl(fd, TCGETS, @intFromPtr(&self.saved))) != .SUCCESS) return self;
        var t = self.saved;
        const IGNBRK = 0o1;
        const BRKINT = 0o2;
        const PARMRK = 0o10;
        const ISTRIP = 0o40;
        const INLCR = 0o100;
        const IGNCR = 0o200;
        const ICRNL = 0o400;
        const IXON = 0o2000;
        const OPOST = 0o1;
        const ISIG = 0o1;
        const ICANON = 0o2;
        const ECHO = 0o10;
        const ECHONL = 0o100;
        const IEXTEN = 0o100000;
        const CSIZE = 0o60;
        const PARENB = 0o400;
        const CS8 = 0o60;
        const VTIME = 5;
        const VMIN = 6;
        t.iflag &= ~@as(u32, IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
        t.oflag &= ~@as(u32, OPOST);
        t.lflag &= ~@as(u32, ECHO | ECHONL | ICANON | ISIG | IEXTEN);
        t.cflag = (t.cflag & ~@as(u32, CSIZE | PARENB)) | CS8;
        t.cc[VMIN] = 1;
        t.cc[VTIME] = 0;
        self.active = linux.errno(linux.ioctl(fd, TCSETSW, @intFromPtr(&t))) == .SUCCESS;
        return self;
    }

    fn leave(self: *RawMode) void {
        if (self.active) _ = linux.ioctl(self.fd, TCSETSW, @intFromPtr(&self.saved));
        self.active = false;
    }
};

pub const Options = struct {
    /// Becomes readable when the guest is finished, even if something else
    /// still holds the terminal open.
    done_fd: i32 = -1,
    ctx: ?*anyopaque = null,
    /// Called with everything the guest prints.
    on_output: ?*const fn (ctx: ?*anyopaque, data: []const u8) void = null,
};

fn showOutput(opts: Options, data: []const u8) void {
    sys.writeAll(1, data) catch {};
    if (opts.on_output) |f| f(opts.ctx, data);
}

/// Prints what the guest has written and nobody has read yet.
fn drainOutput(master: i32, opts: Options, buf: []u8) void {
    while (true) {
        const n = linux.read(master, buf.ptr, buf.len);
        if (linux.errno(n) != .SUCCESS or n == 0) return;
        showOutput(opts, buf[0..n]);
    }
}

/// Copies between the user's terminal and `master` until the guest is done.
pub fn relay(master: i32, opts: Options) void {
    var act: linux.Sigaction = .{
        .handler = .{ .handler = onWinch },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = 0,
    };
    _ = linux.sigaction(.WINCH, &act, null);

    // Only the pty end is non-blocking: a guest that stops reading must not
    // stop its output from being shown. The user's own descriptors are shared
    // with their shell and are left as they are.
    _ = linux.fcntl(master, linux.F.SETFL, sys.O_RDWR | sys.O_NONBLOCK);
    var raw = RawMode.enter(0);
    defer raw.leave();

    var input: [4096]u8 = undefined;
    var in_off: usize = 0;
    var in_len: usize = 0;
    var output: [16384]u8 = undefined;
    var input_open = true;

    while (true) {
        if (resized.swap(false, .monotonic)) copySize(master);

        var pfds = [3]linux.pollfd{
            .{ .fd = if (input_open and in_len == 0) 0 else -1, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = master, .events = linux.POLL.IN | @as(i16, if (in_len > 0) linux.POLL.OUT else 0), .revents = 0 },
            .{ .fd = opts.done_fd, .events = linux.POLL.IN, .revents = 0 },
        };
        const rc = linux.poll(&pfds, 3, -1);
        if (linux.errno(rc) == .INTR) continue;
        if (linux.errno(rc) != .SUCCESS) return;

        if (pfds[0].revents != 0) {
            const n = linux.read(0, &input, input.len);
            const e = linux.errno(n);
            if (e == .SUCCESS and n > 0) {
                in_off = 0;
                in_len = n;
            } else if (e != .INTR and e != .AGAIN) {
                // End of input reaches the guest as Ctrl-D.
                input_open = false;
                input[0] = 4;
                in_off = 0;
                in_len = 1;
            }
        }
        if (in_len > 0) {
            const n = linux.write(master, input[in_off..].ptr, in_len);
            if (linux.errno(n) == .SUCCESS) {
                in_off += n;
                in_len -= n;
            }
        }
        if (pfds[1].revents & linux.POLL.IN != 0) {
            const n = linux.read(master, &output, output.len);
            const e = linux.errno(n);
            if (e == .SUCCESS and n > 0) {
                showOutput(opts, output[0..n]);
            } else if (e != .INTR and e != .AGAIN) {
                return;
            }
        } else if (pfds[1].revents & (linux.POLL.HUP | linux.POLL.ERR) != 0) {
            return; // every copy of the terminal has been closed
        }
        if (pfds[2].revents != 0) {
            drainOutput(master, opts, &output);
            return;
        }
    }
}
