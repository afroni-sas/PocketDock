//! Parses Dockerfiles: instructions, variable substitution, quoting and the
//! patterns used by `COPY` and `.dockerignore`.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Instr = struct {
    /// Upper-cased instruction name.
    op: []const u8,
    rest: []const u8,
    /// Body of a `RUN <<EOF` block.
    heredoc: ?[]const u8 = null,
    line: usize,
};

fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r");
}

pub fn parse(a: Allocator, text: []const u8) ![]Instr {
    var out: std.ArrayList(Instr) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var n: usize = 0;
    while (lines.next()) |raw| {
        n += 1;
        const first = trim(raw);
        if (first.len == 0 or first[0] == '#') continue;
        const start = n;

        var joined: std.ArrayList(u8) = .empty;
        var cur = first;
        while (true) {
            if (cur.len == 0 or cur[cur.len - 1] != '\\') {
                try joined.appendSlice(a, cur);
                break;
            }
            try joined.appendSlice(a, cur[0 .. cur.len - 1]);
            try joined.append(a, ' ');
            // Blank lines and comments may sit inside a continuation.
            var next: ?[]const u8 = null;
            while (lines.next()) |l| {
                n += 1;
                const t = trim(l);
                if (t.len == 0 or t[0] == '#') continue;
                next = t;
                break;
            }
            cur = next orelse break;
        }

        const line = trim(joined.items);
        const sp = std.mem.indexOfAny(u8, line, " \t") orelse line.len;
        const op = try std.ascii.allocUpperString(a, line[0..sp]);
        const rest = trim(line[sp..]);
        var instr: Instr = .{ .op = op, .rest = rest, .line = start };

        if (std.mem.eql(u8, op, "RUN") and std.mem.startsWith(u8, rest, "<<")) {
            const delim = std.mem.trim(u8, rest[2..], " \t-'\"");
            var body: std.ArrayList(u8) = .empty;
            while (lines.next()) |l| {
                n += 1;
                if (std.mem.eql(u8, trim(l), delim)) break;
                try body.appendSlice(a, l);
                try body.append(a, '\n');
            }
            instr.heredoc = body.items;
        }
        try out.append(a, instr);
    }
    return out.items;
}

fn lookup(vars: []const []const u8, name: []const u8) ?[]const u8 {
    var i = vars.len;
    while (i > 0) {
        i -= 1;
        const v = vars[i];
        if (v.len > name.len and v[name.len] == '=' and std.mem.startsWith(u8, v, name)) return v[name.len + 1 ..];
    }
    return null;
}

fn isNameChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

/// Expands `$VAR`, `${VAR}`, `${VAR:-default}` and `${VAR:+alternative}`.
/// In `vars`, later `KEY=VALUE` entries win.
pub fn expand(a: Allocator, s: []const u8, vars: []const []const u8) ![]const u8 {
    if (std.mem.indexOfScalar(u8, s, '$') == null) return s;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c == '\\' and i + 1 < s.len and s[i + 1] == '$') {
            try out.append(a, '$');
            i += 2;
            continue;
        }
        if (c != '$' or i + 1 >= s.len) {
            try out.append(a, c);
            i += 1;
            continue;
        }
        if (s[i + 1] == '{') {
            const end = std.mem.indexOfScalarPos(u8, s, i + 2, '}') orelse {
                try out.append(a, c);
                i += 1;
                continue;
            };
            const body = s[i + 2 .. end];
            i = end + 1;
            const colon = std.mem.indexOfScalar(u8, body, ':');
            if (colon != null and colon.? + 1 < body.len) {
                const name = body[0..colon.?];
                const op = body[colon.? + 1];
                const word = body[colon.? + 2 ..];
                const value = lookup(vars, name);
                const present = value != null and value.?.len > 0;
                if (op == '-') {
                    try out.appendSlice(a, if (present) value.? else word);
                } else if (op == '+' and present) {
                    try out.appendSlice(a, word);
                }
            } else {
                try out.appendSlice(a, lookup(vars, body) orelse "");
            }
            continue;
        }
        var j = i + 1;
        while (j < s.len and isNameChar(s[j])) j += 1;
        if (j == i + 1) {
            try out.append(a, c);
            i += 1;
            continue;
        }
        try out.appendSlice(a, lookup(vars, s[i + 1 .. j]) orelse "");
        i = j;
    }
    return out.items;
}

/// Splits on spaces, honouring quotes and backslashes, and removes the quotes.
pub fn splitWords(a: Allocator, s: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var word: std.ArrayList(u8) = .empty;
    var in_word = false;
    var quote: u8 = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (quote != 0) {
            if (c == quote) {
                quote = 0;
            } else if (c == '\\' and quote == '"' and i + 1 < s.len) {
                i += 1;
                try word.append(a, s[i]);
            } else {
                try word.append(a, c);
            }
        } else if (c == '"' or c == '\'') {
            quote = c;
            in_word = true;
        } else if (c == '\\' and i + 1 < s.len) {
            i += 1;
            try word.append(a, s[i]);
            in_word = true;
        } else if (c == ' ' or c == '\t') {
            if (in_word) {
                try out.append(a, try word.toOwnedSlice(a));
                in_word = false;
            }
        } else {
            try word.append(a, c);
            in_word = true;
        }
    }
    if (in_word) try out.append(a, try word.toOwnedSlice(a));
    return out.items;
}

/// Parses `KEY=VALUE KEY2="value 2"`, or the older `KEY value with spaces`,
/// into `KEY=VALUE` strings.
pub fn keyValues(a: Allocator, s: []const u8) ![]const []const u8 {
    const words = try splitWords(a, s);
    if (words.len == 0) return &.{};
    if (std.mem.indexOfScalar(u8, words[0], '=') != null) return words;
    const sp = std.mem.indexOfAny(u8, s, " \t") orelse return error.BadInstruction;
    const out = try a.alloc([]const u8, 1);
    const value = try splitWords(a, s[sp..]);
    out[0] = try std.fmt.allocPrint(a, "{s}={s}", .{ s[0..sp], try std.mem.join(a, " ", value) });
    return out;
}

/// The argument list of the exec form, `["a", "b"]`, or null for shell form.
pub fn execForm(a: Allocator, s: []const u8) ?[]const []const u8 {
    if (s.len == 0 or s[0] != '[') return null;
    const v = std.json.parseFromSliceLeaky(std.json.Value, a, s, .{}) catch return null;
    if (v != .array) return null;
    var out: std.ArrayList([]const u8) = .empty;
    for (v.array.items) |item| {
        if (item != .string) return null;
        out.append(a, item.string) catch return null;
    }
    return out.items;
}

/// Shell-style matching. `*` and `?` stay within one path segment; `**`
/// crosses them.
pub fn globMatch(pattern: []const u8, name: []const u8) bool {
    if (pattern.len == 0) return name.len == 0;
    if (std.mem.startsWith(u8, pattern, "**")) {
        var rest = pattern[2..];
        if (rest.len > 0 and rest[0] == '/') rest = rest[1..];
        var i: usize = 0;
        while (i <= name.len) : (i += 1) {
            if (globMatch(rest, name[i..])) return true;
        }
        return false;
    }
    switch (pattern[0]) {
        '*' => {
            var i: usize = 0;
            while (true) : (i += 1) {
                if (globMatch(pattern[1..], name[i..])) return true;
                if (i >= name.len or name[i] == '/') return false;
            }
        },
        '?' => return name.len > 0 and name[0] != '/' and globMatch(pattern[1..], name[1..]),
        else => return name.len > 0 and name[0] == pattern[0] and globMatch(pattern[1..], name[1..]),
    }
}

pub fn hasGlob(s: []const u8) bool {
    return std.mem.indexOfAny(u8, s, "*?") != null;
}

/// Applies `.dockerignore` rules, in order, to a path relative to the context.
/// A rule on a directory covers everything inside it.
pub fn isIgnored(rules: []const []const u8, path: []const u8) bool {
    var ignored = false;
    for (rules) |rule| {
        const negate = rule[0] == '!';
        const pat = if (negate) rule[1..] else rule;
        var matched = globMatch(pat, path);
        var i: usize = 0;
        while (!matched and i < path.len) : (i += 1) {
            if (path[i] == '/') matched = globMatch(pat, path[0..i]);
        }
        if (matched) ignored = !negate;
    }
    return ignored;
}

/// Reads the rules of a `.dockerignore` file.
pub fn parseIgnore(a: Allocator, text: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = trim(raw);
        if (line.len == 0 or line[0] == '#') continue;
        try out.append(a, std.mem.trim(u8, line, "/"));
    }
    return out.items;
}

/// Parses a duration like `1m30s`, `5s` or `500ms` into milliseconds.
pub fn parseDuration(s: []const u8) ?u64 {
    if (s.len == 0) return null;
    var total: u64 = 0;
    var i: usize = 0;
    while (i < s.len) {
        var j = i;
        while (j < s.len and std.ascii.isDigit(s[j])) j += 1;
        if (j == i) return null;
        const n = std.fmt.parseInt(u64, s[i..j], 10) catch return null;
        var k = j;
        while (k < s.len and std.ascii.isAlphabetic(s[k])) k += 1;
        const unit = s[j..k];
        const mult: u64 = if (std.mem.eql(u8, unit, "ms"))
            1
        else if (std.mem.eql(u8, unit, "s"))
            1000
        else if (std.mem.eql(u8, unit, "m"))
            60_000
        else if (std.mem.eql(u8, unit, "h"))
            3_600_000
        else
            return null;
        total += n * mult;
        i = k;
    }
    return total;
}

const testing = std.testing;

fn arena() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(testing.allocator);
}

test "parse joins continuations and skips comments" {
    var ar = arena();
    defer ar.deinit();
    const out = try parse(ar.allocator(),
        \\# a comment
        \\FROM alpine:3.20 AS base
        \\
        \\run apk add \
        \\    # inside a continuation
        \\    curl \
        \\    git
        \\CMD ["sh"]
    );
    try testing.expectEqual(@as(usize, 3), out.len);
    try testing.expectEqualStrings("FROM", out[0].op);
    try testing.expectEqualStrings("RUN", out[1].op);
    try testing.expectEqualStrings("apk add  curl  git", out[1].rest);
}

test "parse reads a heredoc" {
    var ar = arena();
    defer ar.deinit();
    const out = try parse(ar.allocator(), "RUN <<EOF\necho one\necho two\nEOF\nCMD x\n");
    try testing.expectEqual(@as(usize, 2), out.len);
    try testing.expectEqualStrings("echo one\necho two\n", out[0].heredoc.?);
}

test "expand substitutes variables" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const vars = [_][]const u8{ "A=1", "B=two", "A=3" };
    try testing.expectEqualStrings("3-two", try expand(a, "$A-${B}", &vars));
    try testing.expectEqualStrings("x", try expand(a, "${NOPE:-x}", &vars));
    try testing.expectEqualStrings("y", try expand(a, "${B:+y}", &vars));
    try testing.expectEqualStrings("$A", try expand(a, "\\$A", &vars));
    try testing.expectEqualStrings("", try expand(a, "$NOPE", &vars));
}

test "keyValues handles both forms" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const modern = try keyValues(a, "A=1 B=\"two words\"");
    try testing.expectEqualStrings("B=two words", modern[1]);
    const old = try keyValues(a, "KEY some value");
    try testing.expectEqualStrings("KEY=some value", old[0]);
}

test "execForm tells the two forms apart" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    try testing.expectEqual(@as(usize, 2), execForm(a, "[\"a\", \"b\"]").?.len);
    try testing.expect(execForm(a, "echo [x]") == null);
    try testing.expect(execForm(a, "[not json") == null);
}

test "globMatch and ignore rules" {
    try testing.expect(globMatch("*.js", "a.js"));
    try testing.expect(!globMatch("*.js", "dir/a.js"));
    try testing.expect(globMatch("**/a.js", "x/y/a.js"));
    const rules = [_][]const u8{ "node_modules", "*.log", "!keep.log" };
    try testing.expect(isIgnored(&rules, "node_modules/x/y"));
    try testing.expect(isIgnored(&rules, "a.log"));
    try testing.expect(!isIgnored(&rules, "keep.log"));
    try testing.expect(!isIgnored(&rules, "src/a.js"));
}

test "parseDuration combines units" {
    try testing.expectEqual(@as(?u64, 90_000), parseDuration("1m30s"));
    try testing.expectEqual(@as(?u64, 500), parseDuration("500ms"));
    try testing.expectEqual(@as(?u64, null), parseDuration("5"));
    try testing.expectEqual(@as(?u64, null), parseDuration("abc"));
}
