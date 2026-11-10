//! A client for OCI registries: Docker Hub, GHCR, Quay and so on.
//!
//! Any language or framework that ships as a Linux image runs unchanged,
//! which is what frees the engine from a fixed list of runtimes.

const std = @import("std");
const sys = @import("sys.zig");
const arch = @import("arch.zig");
const layer = @import("layer.zig");
const Store = @import("store.zig").Store;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Ref = struct {
    host: []const u8,
    repo: []const u8,
    reference: []const u8,
    /// Normalised name that images are stored under.
    name: []const u8,
};

pub fn parseRef(a: Allocator, input: []const u8) !Ref {
    var rest = input;
    var digest: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, rest, '@')) |i| {
        digest = rest[i + 1 ..];
        rest = rest[0..i];
    }
    var registry: []const u8 = "docker.io";
    if (std.mem.indexOfScalar(u8, rest, '/')) |i| {
        const first = rest[0..i];
        if (std.mem.indexOfAny(u8, first, ".:") != null or std.mem.eql(u8, first, "localhost")) {
            registry = first;
            rest = rest[i + 1 ..];
        }
    }
    var tag: []const u8 = "latest";
    if (std.mem.lastIndexOfScalar(u8, rest, ':')) |i| {
        tag = rest[i + 1 ..];
        rest = rest[0..i];
    }
    const docker_hub = std.mem.eql(u8, registry, "docker.io");
    const repo = if (docker_hub and std.mem.indexOfScalar(u8, rest, '/') == null)
        try std.fmt.allocPrint(a, "library/{s}", .{rest})
    else
        rest;
    return .{
        .host = if (docker_hub) "registry-1.docker.io" else registry,
        .repo = repo,
        .reference = digest orelse tag,
        .name = try std.fmt.allocPrint(a, "{s}/{s}{s}{s}", .{
            registry,
            repo,
            if (digest != null) "@" else ":",
            digest orelse tag,
        }),
    };
}

const accept_all = "application/vnd.oci.image.index.v1+json, " ++
    "application/vnd.docker.distribution.manifest.list.v2+json, " ++
    "application/vnd.oci.image.manifest.v1+json, " ++
    "application/vnd.docker.distribution.manifest.v2+json";

const Sink = union(enum) {
    bytes: *std.ArrayList(u8),
    file: struct { fd: i32, hash: *Sha256, label: []const u8, total: u64, offset: u64 },
};

/// Where `pdock login` keeps credentials, in Docker's own format:
/// {"auths": {"ghcr.io": {"auth": base64("user:password")}}}.
const Auths = struct { auths: std.json.ArrayHashMap(struct { auth: []const u8 = "" }) = .{} };

/// Docker Hub answers to several names; credentials are filed under one.
pub fn credentialKey(host: []const u8) []const u8 {
    if (std.mem.eql(u8, host, "registry-1.docker.io") or std.mem.eql(u8, host, "index.docker.io")) return "docker.io";
    return host;
}

fn loadAuths(a: Allocator, store: Store) Auths {
    const data = sys.readFileAlloc(a, store.path(&.{"auth.json"}), 1 << 20) catch return .{};
    return std.json.parseFromSliceLeaky(Auths, a, data, .{ .ignore_unknown_fields = true }) catch .{};
}

/// The value of an `Authorization: Basic` header for `host`, if logged in.
pub fn credentials(a: Allocator, store: Store, host: []const u8) ?[]const u8 {
    const auths = loadAuths(a, store);
    const entry = auths.auths.map.get(credentialKey(host)) orelse return null;
    if (entry.auth.len == 0) return null;
    return std.fmt.allocPrint(a, "Basic {s}", .{entry.auth}) catch null;
}

pub fn loggedIn(a: Allocator, store: Store) []const []const u8 {
    return loadAuths(a, store).auths.map.keys();
}

pub fn saveCredentials(a: Allocator, store: Store, host: []const u8, user: []const u8, password: []const u8) !void {
    var auths = loadAuths(a, store);
    const plain = try std.fmt.allocPrint(a, "{s}:{s}", .{ user, password });
    const enc = std.base64.standard.Encoder;
    const encoded = try a.alloc(u8, enc.calcSize(plain.len));
    _ = enc.encode(encoded, plain);
    try auths.auths.map.put(a, try a.dupe(u8, credentialKey(host)), .{ .auth = encoded });
    try sys.writeFileAtomic(store.path(&.{"auth.json"}), try std.json.Stringify.valueAlloc(a, auths, .{ .whitespace = .indent_2 }), 0o600);
}

pub fn removeCredentials(a: Allocator, store: Store, host: []const u8) !bool {
    var auths = loadAuths(a, store);
    if (!auths.auths.map.orderedRemove(credentialKey(host))) return false;
    try sys.writeFileAtomic(store.path(&.{"auth.json"}), try std.json.Stringify.valueAlloc(a, auths, .{ .whitespace = .indent_2 }), 0o600);
    return true;
}

const Client = struct {
    a: Allocator,
    http: *std.http.Client,
    ref: Ref,
    token: ?[]const u8 = null,
    www_auth: ?[]const u8 = null,
    /// From `pdock login`: traded for a token, or sent as is to registries
    /// that ask for Basic authentication.
    basic: ?[]const u8 = null,
    use_basic: bool = false,

    fn get(self: *Client, url: []const u8, accept: []const u8, sink: Sink) !std.http.Status {
        var auth: ?[]const u8 = null;
        if (self.use_basic) {
            auth = self.basic;
        } else if (self.token) |t| {
            auth = try std.fmt.allocPrint(self.a, "Bearer {s}", .{t});
        }
        return self.getWith(url, accept, sink, auth);
    }

    fn getWith(self: *Client, url: []const u8, accept: []const u8, sink: Sink, first_auth: ?[]const u8) !std.http.Status {
        var current = url;
        // Credentials are for the registry only. Blobs usually redirect to a
        // signed CDN URL, which rejects (and must not see) them.
        var auth = first_auth;
        var hops: u32 = 0;
        while (hops < 6) : (hops += 1) {
            const next = try self.getOnce(current, accept, sink, auth);
            switch (next) {
                .done => |status| return status,
                .redirect => |location| {
                    current = location;
                    auth = null;
                },
            }
        }
        return error.TooManyRedirects;
    }

    const Step = union(enum) { done: std.http.Status, redirect: []const u8 };

    fn getOnce(self: *Client, url: []const u8, accept: []const u8, sink: Sink, auth: ?[]const u8) !Step {
        const uri = try std.Uri.parse(url);
        var extra_buf = [_]std.http.Header{
            .{ .name = "Accept", .value = accept },
            .{ .name = "Range", .value = "" },
        };
        var extra: []const std.http.Header = extra_buf[0..1];
        if (sink == .file and sink.file.offset > 0) {
            extra_buf[1].value = try std.fmt.allocPrint(self.a, "bytes={d}-", .{sink.file.offset});
            extra = &extra_buf;
        }

        var req = try self.http.request(.GET, uri, .{
            .redirect_behavior = .unhandled,
            // A registry drops idle connections during a long download, and
            // retrying on the same dead one would fail every time.
            .keep_alive = false,
            .headers = .{
                .accept_encoding = .omit,
                .user_agent = .{ .override = "pocketdock/0.1" },
                .authorization = if (auth) |v| .{ .override = v } else .omit,
            },
            .extra_headers = extra,
        });
        defer req.deinit();
        try req.sendBodiless();

        var head_buf: [16384]u8 = undefined;
        var resp = try req.receiveHead(&head_buf);
        const status = resp.head.status;
        if (status.class() == .redirect) {
            var it = resp.head.iterateHeaders();
            while (it.next()) |h| {
                if (!std.ascii.eqlIgnoreCase(h.name, "location")) continue;
                if (h.value.len > 0 and h.value[0] == '/') {
                    return .{ .redirect = try std.fmt.allocPrint(self.a, "https://{s}{s}", .{ self.ref.host, h.value }) };
                }
                return .{ .redirect = try self.a.dupe(u8, h.value) };
            }
            return error.RedirectWithoutLocation;
        }
        if (status == .unauthorized) {
            var it = resp.head.iterateHeaders();
            while (it.next()) |h| {
                if (std.ascii.eqlIgnoreCase(h.name, "www-authenticate")) {
                    self.www_auth = try self.a.dupe(u8, h.value);
                }
            }
            return .{ .done = status };
        }
        if (status != .ok and status != .partial_content) return .{ .done = status };

        var done: u64 = 0;
        if (sink == .file) {
            if (status == .ok and sink.file.offset > 0) {
                // The server ignored the Range header, so start over.
                _ = try sys.ck(sys.linux.ftruncate(sink.file.fd, 0));
                _ = sys.linux.lseek(sink.file.fd, 0, 0);
                sink.file.hash.* = Sha256.init(.{});
            } else {
                done = sink.file.offset;
            }
        }

        var transfer: [65536]u8 = undefined;
        const rd = resp.reader(&transfer);
        var buf: [262144]u8 = undefined;
        var last_print: i128 = 0;
        while (true) {
            const n = try rd.readSliceShort(&buf);
            if (n == 0) break;
            done += n;
            switch (sink) {
                .bytes => |list| try list.appendSlice(self.a, buf[0..n]),
                .file => |f| {
                    f.hash.update(buf[0..n]);
                    try sys.writeAll(f.fd, buf[0..n]);
                    const now = sys.nowNs();
                    if (now - last_print > 400 * std.time.ns_per_ms) {
                        last_print = now;
                        sys.print("\r  {s}: {d:.1}/{d:.1} MB ", .{ f.label, mb(done), mb(f.total) });
                    }
                },
            }
        }
        return .{ .done = status };
    }

    fn authenticate(self: *Client) !void {
        const header = self.www_auth orelse return error.RegistryAuthFailed;
        if (std.ascii.startsWithIgnoreCase(header, "basic ")) {
            if (self.basic == null or self.use_basic) return error.RegistryAuthFailed;
            self.use_basic = true;
            return;
        }
        if (!std.ascii.startsWithIgnoreCase(header, "bearer ")) return error.RegistryAuthFailed;
        var realm: []const u8 = "";
        var service: []const u8 = "";
        var scope: []const u8 = "";
        var it = std.mem.tokenizeScalar(u8, header[7..], ',');
        while (it.next()) |kv| {
            const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
            const key = std.mem.trim(u8, kv[0..eq], " ");
            const val = std.mem.trim(u8, kv[eq + 1 ..], " \"");
            if (std.mem.eql(u8, key, "realm")) realm = val;
            if (std.mem.eql(u8, key, "service")) service = val;
            if (std.mem.eql(u8, key, "scope")) scope = val;
        }
        if (scope.len == 0) scope = try std.fmt.allocPrint(self.a, "repository:{s}:pull", .{self.ref.repo});
        const url = try std.fmt.allocPrint(self.a, "{s}?service={s}&scope={s}", .{ realm, service, scope });

        var body: std.ArrayList(u8) = .empty;
        self.token = null;
        const status = try self.getWith(url, "application/json", .{ .bytes = &body }, self.basic);
        if (status != .ok) {
            if (self.basic != null) sys.eprint("error: {s} refused the credentials of pdock login\n", .{self.ref.host});
            return error.RegistryAuthFailed;
        }
        const v = try std.json.parseFromSliceLeaky(std.json.Value, self.a, body.items, .{});
        const tok = v.object.get("token") orelse v.object.get("access_token") orelse return error.RegistryAuthFailed;
        self.token = tok.string;
    }

    /// Phone networks drop out, so transport errors are retried with backoff.
    fn fetch(self: *Client, url: []const u8, accept: []const u8) ![]u8 {
        var attempt: u32 = 0;
        while (true) : (attempt += 1) {
            return self.fetchOnce(url, accept) catch |e| {
                if (e == error.RegistryError or e == error.RegistryAuthFailed or attempt >= max_retries) return e;
                sys.print("  network error ({s}), retrying\n", .{@errorName(e)});
                sys.sleepMs(backoffMs(attempt));
                continue;
            };
        }
    }

    fn fetchOnce(self: *Client, url: []const u8, accept: []const u8) ![]u8 {
        var body: std.ArrayList(u8) = .empty;
        var status = try self.get(url, accept, .{ .bytes = &body });
        if (status == .unauthorized) {
            try self.authenticate();
            body.clearRetainingCapacity();
            status = try self.get(url, accept, .{ .bytes = &body });
        }
        if (status != .ok) {
            sys.eprint("registry error: HTTP {d} for {s}\n", .{ @backingInt(status), url });
            return error.RegistryError;
        }
        return body.items;
    }

    fn manifestUrl(self: *Client, reference: []const u8) ![]const u8 {
        return std.fmt.allocPrint(self.a, "https://{s}/v2/{s}/manifests/{s}", .{ self.ref.host, self.ref.repo, reference });
    }

    fn download(self: *Client, digest: []const u8, dest: []const u8, label: []const u8, total: u64) !void {
        const url = try std.fmt.allocPrint(self.a, "https://{s}/v2/{s}/blobs/{s}", .{ self.ref.host, self.ref.repo, digest });
        var attempt: u32 = 0;
        while (true) : (attempt += 1) {
            self.downloadOnce(url, digest, dest, label, total) catch |e| {
                if (e == error.DigestMismatch) {
                    var p = try sys.Path.of(dest);
                    sys.unlink(p.z()) catch {};
                }
                if (attempt >= max_retries) return e;
                sys.print("\n  {s} ({s}), resuming\n", .{ label, @errorName(e) });
                sys.sleepMs(backoffMs(attempt));
                continue;
            };
            return;
        }
    }

    /// Continues from whatever a previous attempt left on disk.
    fn downloadOnce(self: *Client, url: []const u8, digest: []const u8, dest: []const u8, label: []const u8, total: u64) !void {
        var p = try sys.Path.of(dest);
        const fd = try sys.open(p.z(), sys.O_RDWR | sys.O_CREAT, 0o600);
        defer sys.close(fd);

        var hash = Sha256.init(.{});
        var have: u64 = 0;
        var buf: [262144]u8 = undefined;
        while (true) {
            const n = try sys.read(fd, &buf);
            if (n == 0) break;
            hash.update(buf[0..n]);
            have += n;
        }

        if (have < total or total == 0) {
            const sink: Sink = .{ .file = .{ .fd = fd, .hash = &hash, .label = label, .total = total, .offset = have } };
            var status = try self.get(url, "*/*", sink);
            if (status == .unauthorized) {
                try self.authenticate();
                status = try self.get(url, "*/*", sink);
            }
            if (status != .ok and status != .partial_content) return error.RegistryError;
        }

        var out: [32]u8 = undefined;
        hash.final(&out);
        var hex: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hex, "{x}", .{&out}) catch unreachable;
        const want = if (std.mem.startsWith(u8, digest, "sha256:")) digest[7..] else digest;
        if (!std.mem.eql(u8, want, &hex)) return error.DigestMismatch;
    }
};

const max_retries = 8;

fn backoffMs(attempt: u32) u64 {
    return @min(@as(u64, 1000) << @intCast(@min(attempt, 5)), 15_000);
}

/// Downloads a plain URL to `dest`, for `ADD`.
pub fn downloadUrl(gpa: Allocator, io: std.Io, url: []const u8, dest: []const u8) !void {
    var http: std.http.Client = .{ .allocator = gpa, .io = io };
    defer http.deinit();
    const uri = try std.Uri.parse(url);
    var req = try http.request(.GET, uri, .{
        .headers = .{
            .accept_encoding = .omit,
            .user_agent = .{ .override = "pocketdock/0.1" },
        },
    });
    defer req.deinit();
    try req.sendBodiless();
    var head_buf: [16384]u8 = undefined;
    var resp = try req.receiveHead(&head_buf);
    if (resp.head.status != .ok) return error.DownloadFailed;

    var p = try sys.Path.of(dest);
    const fd = try sys.open(p.z(), sys.O_WRONLY | sys.O_CREAT | sys.O_TRUNC, 0o600);
    defer sys.close(fd);
    var transfer: [65536]u8 = undefined;
    const rd = resp.reader(&transfer);
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = try rd.readSliceShort(&buf);
        if (n == 0) return;
        try sys.writeAll(fd, buf[0..n]);
    }
}

fn mb(n: u64) f64 {
    return @as(f64, @floatFromInt(n)) / (1024 * 1024);
}

fn isIndex(media: []const u8) bool {
    return std.mem.indexOf(u8, media, "index") != null or std.mem.indexOf(u8, media, "manifest.list") != null;
}

/// Picks the manifest matching this CPU out of a multi-architecture index.
fn pickPlatform(index: std.json.Value) ?[]const u8 {
    const list = index.object.get("manifests") orelse return null;
    for (list.array.items) |m| {
        const platform = m.object.get("platform") orelse continue;
        const os = platform.object.get("os") orelse continue;
        const cpu = platform.object.get("architecture") orelse continue;
        if (!std.mem.eql(u8, os.string, "linux")) continue;
        if (!std.mem.eql(u8, cpu.string, arch.oci_arch)) continue;
        return m.object.get("digest").?.string;
    }
    return null;
}

/// Pulls `name` unless it is already stored. Returns the image id.
pub fn pull(a: Allocator, gpa: Allocator, io: std.Io, store: Store, name: []const u8, force: bool) ![]const u8 {
    const ref = try parseRef(a, name);
    if (!force) {
        if (store.getRef(ref.name)) |id| return id;
    }

    var http: std.http.Client = .{ .allocator = gpa, .io = io };
    defer http.deinit();
    var client: Client = .{ .a = a, .http = &http, .ref = ref, .basic = credentials(a, store, ref.host) };

    sys.print("Pulling {s} for linux/{s}\n", .{ ref.name, arch.oci_arch });
    var body = try client.fetch(try client.manifestUrl(ref.reference), accept_all);
    var doc = try std.json.parseFromSliceLeaky(std.json.Value, a, body, .{});

    const media = if (doc.object.get("mediaType")) |m| m.string else "";
    if (isIndex(media) or doc.object.get("manifests") != null) {
        const digest = pickPlatform(doc) orelse {
            sys.eprint("error: {s} has no linux/{s} image\n", .{ ref.name, arch.oci_arch });
            return error.NoMatchingPlatform;
        };
        body = try client.fetch(try client.manifestUrl(digest), accept_all);
        doc = try std.json.parseFromSliceLeaky(std.json.Value, a, body, .{});
    }

    const config_digest = doc.object.get("config").?.object.get("digest").?.string;
    const id = config_digest["sha256:".len..];

    const image_dir = store.path(&.{ "images", id });
    var rootfs_z = try sys.Path.join(image_dir, "/rootfs");
    if (sys.exists(rootfs_z.z())) {
        try store.setRef(ref.name, id);
        sys.print("Image already present: {s}\n", .{id[0..12]});
        return id;
    }

    const cfg_url = try std.fmt.allocPrint(a, "https://{s}/v2/{s}/blobs/{s}", .{ ref.host, ref.repo, config_digest });
    const cfg = try client.fetch(cfg_url, "*/*");

    const tmp_root = try std.fmt.allocPrint(a, "{s}/rootfs.tmp", .{image_dir});
    try sys.rmrf(tmp_root);
    try sys.mkdirP(tmp_root, 0o755);

    // Layers are unpacked one by one and deleted straight after: phone storage
    // is scarce, and the flattened rootfs is all a container needs.
    const layers = doc.object.get("layers").?.array.items;
    _ = sys.linux.syscall1(.umask, 0);
    for (layers, 0..) |l, i| {
        const digest = l.object.get("digest").?.string;
        const size: u64 = @intCast(l.object.get("size").?.integer);
        const hex = digest["sha256:".len..];
        const blob = store.path(&.{ "blobs", hex });
        const label = try std.fmt.allocPrint(a, "layer {d}/{d}", .{ i + 1, layers.len });
        try client.download(digest, blob, label, size);
        sys.print("\r  {s}: {d:.1} MB, extracting...   ", .{ label, mb(size) });
        const entries = try layer.extract(gpa, io, blob, tmp_root);
        sys.print("\r  {s}: {d:.1} MB, {d} files       \n", .{ label, mb(size), entries });
        var blob_z = try sys.Path.of(blob);
        sys.unlink(blob_z.z()) catch {};
    }

    try sys.writeFile(store.path(&.{ "images", id, "config.json" }), cfg, 0o600);
    var from = try sys.Path.of(tmp_root);
    try sys.rename(from.z(), rootfs_z.z());
    try store.setRef(ref.name, id);
    sys.print("Done: {s}\n", .{id[0..12]});
    return id;
}

const testing = std.testing;

test "Docker Hub credentials are filed under one name" {
    try testing.expectEqualStrings("docker.io", credentialKey("registry-1.docker.io"));
    try testing.expectEqualStrings("docker.io", credentialKey("index.docker.io"));
    try testing.expectEqualStrings("ghcr.io", credentialKey("ghcr.io"));
}
