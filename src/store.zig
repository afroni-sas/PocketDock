//! On-disk layout of images and containers.
//!
//!   <root>/blobs/<hex>             downloads in progress
//!   <root>/images/<id>/rootfs      the flattened image, never modified
//!   <root>/images/<id>/config.json the OCI image config
//!   <root>/refs/<escaped-name>     name:tag -> image id
//!   <root>/containers/<id>/...     see container.zig
//!   <root>/sk/                     short paths for long unix socket names
//!   <root>/ports/<port>            which supervisor owns a host port
//!   <root>/net/ips/<ip>            which container holds a private IP
//!   <root>/net/<ip>/<port>         the host port behind a private address

const std = @import("std");
const sys = @import("sys.zig");
const Allocator = std.mem.Allocator;

pub const Store = struct {
    root: []const u8,
    a: Allocator,

    pub fn init(a: Allocator, root: []const u8) !Store {
        const self: Store = .{ .root = root, .a = a };
        for ([_][]const u8{ "blobs", "images", "refs", "containers", "sk", "ports", "net", "net/ips" }) |d| {
            try sys.mkdirP(self.path(&.{d}), 0o700);
        }
        return self;
    }

    pub fn path(self: Store, parts: []const []const u8) []const u8 {
        var out: std.ArrayList(u8) = .empty;
        out.appendSlice(self.a, self.root) catch @panic("OOM");
        for (parts) |p| {
            out.append(self.a, '/') catch @panic("OOM");
            out.appendSlice(self.a, p) catch @panic("OOM");
        }
        return out.items;
    }

    fn escape(self: Store, ref: []const u8) []const u8 {
        const out = self.a.dupe(u8, ref) catch @panic("OOM");
        for (out) |*c| {
            if (c.* == '/') c.* = '!';
        }
        return out;
    }

    pub fn setRef(self: Store, ref: []const u8, id: []const u8) !void {
        try sys.writeFileAtomic(self.path(&.{ "refs", self.escape(ref) }), id, 0o600);
    }

    pub fn getRef(self: Store, ref: []const u8) ?[]const u8 {
        return sys.readFileAlloc(self.a, self.path(&.{ "refs", self.escape(ref) }), 256) catch null;
    }

    pub fn unsetRef(self: Store, ref: []const u8) void {
        const p = self.a.dupeSentinel(u8, self.path(&.{ "refs", self.escape(ref) }), 0) catch return;
        sys.unlink(p.ptr) catch {};
    }

    pub const RefEntry = struct { ref: []const u8, id: []const u8 };

    pub fn listRefs(self: Store) ![]RefEntry {
        var out: std.ArrayList(RefEntry) = .empty;
        const dir = try self.a.dupeSentinel(u8, self.path(&.{"refs"}), 0);
        var it = try sys.DirIter.open_(dir.ptr);
        defer it.deinit();
        while (try it.next()) |ent| {
            if (std.mem.indexOf(u8, ent.name, ".tmp") != null) continue;
            const name = try self.a.dupe(u8, ent.name);
            for (name) |*c| {
                if (c.* == '!') c.* = '/';
            }
            if (self.getRef(name)) |id| try out.append(self.a, .{ .ref = name, .id = id });
        }
        return out.items;
    }

    pub fn listDir(self: Store, sub: []const u8) ![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        const dir = try self.a.dupeSentinel(u8, self.path(&.{sub}), 0);
        var it = try sys.DirIter.open_(dir.ptr);
        defer it.deinit();
        while (try it.next()) |ent| try out.append(self.a, try self.a.dupe(u8, ent.name));
        return out.items;
    }
};
