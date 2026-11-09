//! DNS for a static binary on Android.
//!
//! Android has no `/etc/resolv.conf`, and bionic's resolver is out of reach
//! without a libc, so Zig's standard lookup has nothing to work with there.
//! This wraps the `Io` implementation and answers lookups with plain UDP
//! queries when the system offers no resolver configuration.

const std = @import("std");
const sys = @import("sys.zig");
const linux = sys.linux;
const Io = std.Io;
const net = Io.net;

var base: Io = undefined;
var vtable: Io.VTable = undefined;
var servers_override: ?[]const u8 = null;

pub fn wrapIo(io: Io, dns_env: ?[]const u8) Io {
    base = io;
    vtable = io.vtable.*;
    vtable.netLookup = netLookup;
    servers_override = dns_env;
    return .{ .userdata = io.userdata, .vtable = &vtable };
}

fn netLookup(
    userdata: ?*anyopaque,
    host_name: net.HostName,
    resolved: *Io.Queue(net.HostName.LookupResult),
    options: net.HostName.LookupOptions,
) net.HostName.LookupError!void {
    if (sys.exists("/etc/resolv.conf") and servers_override == null) {
        return base.vtable.netLookup(userdata, host_name, resolved, options);
    }
    defer resolved.close(base);
    if (net.IpAddress.parseIp4(host_name.bytes, options.port)) |addr| {
        resolved.putOne(base, .{ .address = addr }) catch return error.NoAddressReturned;
        return;
    } else |_| {}

    var ip: [4]u8 = undefined;
    if (!resolve(host_name.bytes, &ip)) return error.UnknownHostName;
    resolved.putOne(base, .{ .address = .{ .ip4 = .{ .bytes = ip, .port = options.port } } }) catch
        return error.NoAddressReturned;
    if (options.canonical_name_buffer) |buf| {
        @memcpy(buf[0..host_name.bytes.len], host_name.bytes);
        resolved.putOne(base, .{ .canonical_name = .{ .bytes = buf[0..host_name.bytes.len] } }) catch {};
    }
}

fn parseServers(text: []const u8, out: *[4][4]u8) usize {
    var n: usize = 0;
    var lines = std.mem.tokenizeAny(u8, text, "\n,");
    while (lines.next()) |raw| {
        var words = std.mem.tokenizeAny(u8, raw, " \t");
        var w = words.next() orelse continue;
        if (std.mem.eql(u8, w, "nameserver")) w = words.next() orelse continue;
        const addr = net.Ip4Address.parse(w, 53) catch continue;
        if (n == out.len) break;
        out[n] = addr.bytes;
        n += 1;
    }
    return n;
}

/// Servers for plain UDP queries, and for the guest's resolv.conf, in order:
/// `$POCKETDOCK_DNS`, Termux's configuration, then public resolvers.
pub fn servers(out: *[4][4]u8) usize {
    if (servers_override) |s| {
        const n = parseServers(s, out);
        if (n > 0) return n;
    }
    var buf: [2048]u8 = undefined;
    const termux_conf: [*:0]const u8 = "/data/data/com.termux/files/usr/etc/resolv.conf";
    if (sys.open(termux_conf, 0, 0)) |fd| {
        defer sys.close(fd);
        const len = sys.read(fd, &buf) catch 0;
        const n = parseServers(buf[0..len], out);
        if (n > 0) return n;
    } else |_| {}
    out[0] = .{ 1, 1, 1, 1 };
    out[1] = .{ 8, 8, 8, 8 };
    return 2;
}

/// Asks Android's own resolver daemon, the one bionic's getaddrinfo talks to.
/// It knows the DNS servers of the active network and private DNS settings.
fn androidResolve(name: []const u8, out: *[4]u8) bool {
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    const fd: i32 = @intCast(rc);
    defer sys.close(fd);

    const path = "/dev/socket/dnsproxyd";
    var sa: linux.sockaddr.un = .{ .path = undefined };
    @memset(&sa.path, 0);
    @memcpy(sa.path[0..path.len], path);
    if (linux.errno(linux.connect(fd, @ptrCast(&sa), 2 + path.len + 1)) != .SUCCESS) return false;

    // hostname, service (^ = none), flags, AF_INET, SOCK_STREAM, TCP, netid.
    var cmd: [512]u8 = undefined;
    const s = std.fmt.bufPrint(&cmd, "getaddrinfo {s} ^ 0 2 1 6 0\x00", .{name}) catch return false;
    sys.writeAll(fd, s) catch return false;

    var pfd = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
    if (linux.poll(&pfd, 1, 15000) == 0) return false;

    var head: [4]u8 = undefined;
    if ((sys.readFull(fd, &head) catch return false) != 4) return false;
    if (!std.mem.eql(u8, head[0..3], "222")) return false;

    // A list of addrinfo records, each preceded by a "there is more" flag.
    while (true) {
        var more: [4]u8 = undefined;
        if ((sys.readFull(fd, &more) catch return false) != 4) return false;
        if (std.mem.readInt(u32, &more, .big) == 0) return false;
        var fields: [20]u8 = undefined;
        if ((sys.readFull(fd, &fields) catch return false) != 20) return false;
        const addr_len = std.mem.readInt(u32, fields[16..20], .big);
        var addr: [128]u8 = undefined;
        if (addr_len > addr.len) return false;
        if ((sys.readFull(fd, addr[0..addr_len]) catch return false) != addr_len) return false;
        var name_len_buf: [4]u8 = undefined;
        if ((sys.readFull(fd, &name_len_buf) catch return false) != 4) return false;
        var skip = std.mem.readInt(u32, &name_len_buf, .big);
        while (skip > 0) {
            var junk: [256]u8 = undefined;
            const n = sys.read(fd, junk[0..@min(skip, junk.len)]) catch return false;
            if (n == 0) return false;
            skip -= @intCast(n);
        }
        if (addr_len >= 8 and std.mem.readInt(u16, addr[0..2], .little) == linux.AF.INET) {
            @memcpy(out, addr[4..8]);
            return true;
        }
    }
}

pub fn resolve(name: []const u8, out: *[4]u8) bool {
    if (androidResolve(name, out)) return true;
    var list: [4][4]u8 = undefined;
    const n = servers(&list);
    for (0..2) |_| {
        for (list[0..n]) |server| {
            if (query(server, name, out)) return true;
        }
    }
    return false;
}

fn query(server: [4]u8, name: []const u8, out: *[4]u8) bool {
    var pkt: [512]u8 = undefined;
    var id: [2]u8 = undefined;
    _ = linux.getrandom(&id, 2, 0);
    @memcpy(pkt[0..2], &id);
    // Standard query, recursion desired, one question.
    @memcpy(pkt[2..12], "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00");
    var i: usize = 12;
    var labels = std.mem.tokenizeScalar(u8, name, '.');
    while (labels.next()) |l| {
        if (l.len > 63 or i + l.len + 6 > pkt.len) return false;
        pkt[i] = @intCast(l.len);
        @memcpy(pkt[i + 1 ..][0..l.len], l);
        i += l.len + 1;
    }
    pkt[i] = 0;
    i += 1;
    @memcpy(pkt[i..][0..4], "\x00\x01\x00\x01"); // A, IN
    i += 4;

    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    const fd: i32 = @intCast(rc);
    defer sys.close(fd);
    var sa: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, 53),
        .addr = @bitCast(server),
    };
    if (linux.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return false;
    if (linux.errno(linux.write(fd, &pkt, i)) != .SUCCESS) return false;

    var pfd = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
    if (linux.poll(&pfd, 1, 2500) == 0) return false;
    var resp: [1500]u8 = undefined;
    const got = linux.read(fd, &resp, resp.len);
    if (linux.errno(got) != .SUCCESS or got < 12) return false;
    if (!std.mem.eql(u8, resp[0..2], &id)) return false;

    const ancount = std.mem.readInt(u16, resp[6..8], .big);
    var p: usize = 12;
    p = skipName(resp[0..got], p) orelse return false;
    p += 4;
    var a: u16 = 0;
    while (a < ancount) : (a += 1) {
        p = skipName(resp[0..got], p) orelse return false;
        if (p + 10 > got) return false;
        const typ = std.mem.readInt(u16, resp[p..][0..2], .big);
        const rdlen = std.mem.readInt(u16, resp[p + 8 ..][0..2], .big);
        p += 10;
        if (p + rdlen > got) return false;
        if (typ == 1 and rdlen == 4) {
            @memcpy(out, resp[p..][0..4]);
            return true;
        }
        p += rdlen;
    }
    return false;
}

fn skipName(m: []const u8, start: usize) ?usize {
    var p = start;
    while (p < m.len) {
        const b = m[p];
        if (b == 0) return p + 1;
        if (b & 0xC0 == 0xC0) return p + 2;
        p += @as(usize, b) + 1;
    }
    return null;
}
