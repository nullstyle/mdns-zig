//! DNS-SD TXT records (RFC 6763 section 6).
//!
//! Wire form is a sequence of length-prefixed strings (section 6.1). Each
//! string is `key=value` or a bare `key` (a boolean attribute, section
//! 6.4). Keys are ASCII, case-insensitive, and the first occurrence of a
//! key wins (section 6.4); a string with an empty key is ignored (6.4).
//! The library caps TXT rdata at 400 octets on both sides (plan section
//! 4.5); section 6.2 recommends staying under that on the wire.
const std = @import("std");
const ascii = std.ascii;
const Bounded = @import("bounded.zig").Bounded;

/// TXT rdata limit for advertise and for events (plan section 4.5).
pub const max_len = 400;
/// One TXT string is length-prefixed with a single octet (section 6.1).
pub const max_string_len = 255;

/// One attribute as the caller writes it or as `iterate` yields it.
/// `value == null` is a boolean attribute (`key` with no `=`); an empty
/// slice is `key=` with an empty value. RFC 6763 section 6.4 keeps the two
/// distinct.
pub const TxtPair = struct {
    key: []const u8,
    value: ?[]const u8 = null,
};

pub const BuildError = error{
    /// Total rdata would exceed `max_len`.
    TxtTooLarge,
    /// One `key=value` string would exceed 255 octets.
    TxtStringTooLong,
    /// Key is empty, contains `=`, or a non-printable / non-ASCII octet
    /// (RFC 6763 section 6.4).
    InvalidTxtKey,
};

/// Zero-copy view over TXT rdata bytes of any origin.
pub const View = struct {
    bytes: []const u8,

    /// Structural validity: every length prefix fits (section 6.1). An
    /// empty rdata is accepted as "no attributes" for interoperability,
    /// though section 6.1 says the empty TXT is a single zero octet.
    pub fn validate(v: View) error{Malformed}!void {
        var pos: usize = 0;
        while (pos < v.bytes.len) {
            const l: usize = v.bytes[pos];
            if (pos + 1 + l > v.bytes.len) return error.Malformed;
            pos += 1 + l;
        }
    }

    pub fn iterate(v: View) Iterator {
        return .{ .bytes = v.bytes, .pos = 0 };
    }

    /// Value of the first string whose key matches ASCII case-insensitively
    /// (section 6.4). Null when the key is absent or the attribute is a
    /// boolean (`key` with no `=`); use `has` for presence.
    pub fn get(v: View, key: []const u8) ?[]const u8 {
        return (v.find(key) orelse return null).value;
    }

    /// True when any string has this key, with or without a value.
    pub fn has(v: View, key: []const u8) bool {
        return v.find(key) != null;
    }

    /// The first pair with this key, if any.
    pub fn find(v: View, key: []const u8) ?TxtPair {
        var it = v.iterate();
        while (it.next()) |p| {
            if (ascii.eqlIgnoreCase(p.key, key)) return p;
        }
        return null;
    }

    /// Number of attributes `iterate` yields.
    pub fn count(v: View) usize {
        var n: usize = 0;
        var it = v.iterate();
        while (it.next()) |_| n += 1;
        return n;
    }

    pub const Iterator = struct {
        bytes: []const u8,
        pos: usize,

        /// Yields attributes in wire order, skipping empty strings and
        /// strings with an empty key (section 6.4). A length prefix that
        /// runs past the end ends iteration.
        pub fn next(it: *Iterator) ?TxtPair {
            while (it.pos < it.bytes.len) {
                const l: usize = it.bytes[it.pos];
                if (it.pos + 1 + l > it.bytes.len) {
                    it.pos = it.bytes.len;
                    return null;
                }
                const s = it.bytes[it.pos + 1 ..][0..l];
                it.pos += 1 + l;
                if (s.len == 0) continue;
                if (std.mem.indexOfScalar(u8, s, '=')) |eq| {
                    if (eq == 0) continue; // empty key: ignored
                    return .{ .key = s[0..eq], .value = s[eq + 1 ..] };
                }
                return .{ .key = s, .value = null };
            }
            return null;
        }
    };
};

/// Owned TXT rdata, at most `max_len` octets. A value type: copy freely.
pub const Txt = struct {
    bytes: Bounded(u8, max_len) = .{},

    /// The empty TXT: one zero-length string (RFC 6763 section 6.1).
    pub const empty: Txt = .{ .bytes = .{ .len = 1, .buf = @splat(0) } };

    /// Encode `pairs` (RFC 6763 section 6). No pairs gives `empty`.
    pub fn build(pairs: []const TxtPair) BuildError!Txt {
        var t: Txt = .{};
        t.bytes.len = try buildInto(pairs, &t.bytes.buf);
        return t;
    }

    /// Encode into a caller buffer; returns the rdata length. `out` shorter
    /// than the encoding is `error.TxtTooLarge` even below 400 octets.
    pub fn buildInto(pairs: []const TxtPair, out: []u8) BuildError!usize {
        const limit = @min(out.len, max_len);
        if (pairs.len == 0) {
            if (limit < 1) return error.TxtTooLarge;
            out[0] = 0;
            return 1;
        }
        var pos: usize = 0;
        for (pairs) |p| {
            try validateKey(p.key);
            const value_len: usize = if (p.value) |v| v.len + 1 else 0;
            const s_len = p.key.len + value_len;
            if (s_len > max_string_len) return error.TxtStringTooLong;
            if (pos + 1 + s_len > limit) return error.TxtTooLarge;
            out[pos] = @intCast(s_len);
            @memcpy(out[pos + 1 ..][0..p.key.len], p.key);
            if (p.value) |v| {
                out[pos + 1 + p.key.len] = '=';
                @memcpy(out[pos + 2 + p.key.len ..][0..v.len], v);
            }
            pos += 1 + s_len;
        }
        return pos;
    }

    /// Copy wire rdata. Structure is validated; size over 400 octets is
    /// `error.TxtTooLarge`.
    pub fn fromWire(rdata: []const u8) error{ Malformed, TxtTooLarge }!Txt {
        try (View{ .bytes = rdata }).validate();
        if (rdata.len > max_len) return error.TxtTooLarge;
        var t: Txt = .{};
        @memcpy(t.bytes.buf[0..rdata.len], rdata);
        t.bytes.len = rdata.len;
        return t;
    }

    pub const Truncated = struct { txt: Txt, truncated: bool };

    /// Copy wire rdata, dropping whole strings from the end until it fits
    /// in 400 octets (plan section 4.5: a received TXT over 400 B is
    /// truncated in the event and counted). Structure is validated first.
    pub fn fromWireTruncated(rdata: []const u8) error{Malformed}!Truncated {
        try (View{ .bytes = rdata }).validate();
        var keep: usize = 0;
        var pos: usize = 0;
        while (pos < rdata.len) {
            const l: usize = rdata[pos];
            if (pos + 1 + l > max_len) break;
            pos += 1 + l;
            keep = pos;
        }
        var t: Txt = .{};
        @memcpy(t.bytes.buf[0..keep], rdata[0..keep]);
        t.bytes.len = keep;
        return .{ .txt = t, .truncated = keep != rdata.len };
    }

    pub fn slice(t: *const Txt) []const u8 {
        return t.bytes.slice();
    }

    pub fn view(t: *const Txt) View {
        return .{ .bytes = t.bytes.slice() };
    }

    pub fn iterate(t: *const Txt) View.Iterator {
        return t.view().iterate();
    }

    pub fn get(t: *const Txt, key: []const u8) ?[]const u8 {
        return t.view().get(key);
    }

    pub fn has(t: *const Txt, key: []const u8) bool {
        return t.view().has(key);
    }

    pub fn find(t: *const Txt, key: []const u8) ?TxtPair {
        return t.view().find(key);
    }

    pub fn count(t: *const Txt) usize {
        return t.view().count();
    }

    /// Byte equality of the rdata (what the responder compares to detect
    /// a no-op `updateTxt`).
    pub fn eql(a: *const Txt, b: *const Txt) bool {
        return std.mem.eql(u8, a.slice(), b.slice());
    }
};

/// RFC 6763 section 6.4: a key is at least one printable US-ASCII
/// character (0x20..0x7E) other than `=`. Section 6.4 recommends at most
/// nine characters; that is not enforced.
pub fn validateKey(key: []const u8) error{InvalidTxtKey}!void {
    if (key.len == 0) return error.InvalidTxtKey;
    for (key) |c| {
        if (c < 0x20 or c > 0x7E or c == '=') return error.InvalidTxtKey;
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "empty TXT is a single zero byte" {
    const t = try Txt.build(&.{});
    try testing.expectEqualSlices(u8, "\x00", t.slice());
    try testing.expect(t.eql(&Txt.empty));
    try testing.expectEqual(@as(usize, 0), t.count());
    var it = t.iterate();
    try testing.expect(it.next() == null);
    var out: [1]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), try Txt.buildInto(&.{}, &out));
    try testing.expectError(error.TxtTooLarge, Txt.buildInto(&.{}, out[0..0]));
}

test "build and iterate pairs" {
    const t = try Txt.build(&.{
        .{ .key = "txtvers", .value = "1" },
        .{ .key = "path", .value = "/a=b" },
        .{ .key = "flag" },
        .{ .key = "empty", .value = "" },
    });
    try testing.expectEqualSlices(u8, "\x09txtvers=1\x09path=/a=b\x04flag\x06empty=", t.slice());
    var it = t.iterate();
    const p1 = it.next().?;
    try testing.expectEqualStrings("txtvers", p1.key);
    try testing.expectEqualStrings("1", p1.value.?);
    const p2 = it.next().?;
    try testing.expectEqualStrings("path", p2.key);
    try testing.expectEqualStrings("/a=b", p2.value.?);
    const p3 = it.next().?;
    try testing.expectEqualStrings("flag", p3.key);
    try testing.expect(p3.value == null);
    const p4 = it.next().?;
    try testing.expectEqualStrings("empty", p4.key);
    try testing.expectEqualStrings("", p4.value.?);
    try testing.expect(it.next() == null);
    try testing.expectEqual(@as(usize, 4), t.count());
    try testing.expect(t.has("flag"));
    try testing.expect(t.get("flag") == null);
    try testing.expectEqualStrings("", t.get("empty").?);
    try testing.expect(!t.has("nope"));
    try testing.expect(t.get("nope") == null);
    // Round trip through the wire.
    const back = try Txt.fromWire(t.slice());
    try testing.expect(back.eql(&t));
}

test "TXT key lookup is case-insensitive" {
    const t = try Txt.build(&.{
        .{ .key = "Path", .value = "/first" },
        .{ .key = "PATH", .value = "/second" },
        .{ .key = "Bool" },
    });
    try testing.expectEqualStrings("/first", t.get("path").?);
    try testing.expectEqualStrings("/first", t.get("PATH").?);
    try testing.expectEqualStrings("/first", t.get("pAtH").?);
    try testing.expect(t.has("bool"));
    try testing.expect(t.has("BOOL"));
    const found = t.find("PaTh").?;
    try testing.expectEqualStrings("Path", found.key);
    // First match wins even when the first is a boolean and the second has
    // a value.
    const u = try Txt.build(&.{ .{ .key = "k" }, .{ .key = "K", .value = "v" } });
    try testing.expect(u.has("k"));
    try testing.expect(u.get("k") == null);
}

test "TXT over 400 B is rejected" {
    // 2 strings of 1 + 199 = 200 octets each fit exactly.
    const v199: [197]u8 = @splat('v');
    const two = try Txt.build(&.{
        .{ .key = "a", .value = &v199 },
        .{ .key = "b", .value = &v199 },
    });
    try testing.expectEqual(@as(usize, 400), two.slice().len);
    // One more octet does not.
    const v198: [198]u8 = @splat('v');
    try testing.expectError(error.TxtTooLarge, Txt.build(&.{
        .{ .key = "a", .value = &v199 },
        .{ .key = "b", .value = &v198 },
    }));
    // fromWire applies the same cap.
    var big: [401]u8 = @splat(0);
    try testing.expectError(error.TxtTooLarge, Txt.fromWire(&big));
    _ = try Txt.fromWire(big[0..400]);
    // A caller buffer shorter than the encoding.
    var small: [4]u8 = undefined;
    try testing.expectError(error.TxtTooLarge, Txt.buildInto(&.{.{ .key = "abcd" }}, &small));
    try testing.expectEqual(@as(usize, 4), try Txt.buildInto(&.{.{ .key = "abc" }}, &small));
}

test "TXT string over 255 and bad keys are rejected" {
    const v254: [254]u8 = @splat('v');
    _ = try Txt.build(&.{.{ .key = "k", .value = v254[0..253] }}); // 1 + 1 + 253 = 255
    try testing.expectError(error.TxtStringTooLong, Txt.build(&.{.{ .key = "k", .value = &v254 }}));
    try testing.expectError(error.InvalidTxtKey, Txt.build(&.{.{ .key = "" }}));
    try testing.expectError(error.InvalidTxtKey, Txt.build(&.{.{ .key = "a=b" }}));
    try testing.expectError(error.InvalidTxtKey, Txt.build(&.{.{ .key = "a\x01" }}));
    try testing.expectError(error.InvalidTxtKey, Txt.build(&.{.{ .key = "caf\xc3\xa9" }}));
    try testing.expectError(error.InvalidTxtKey, Txt.build(&.{.{ .key = "a b\x7f" }}));
    _ = try Txt.build(&.{.{ .key = "a b~!" }});
}

test "iterate skips empty strings and empty keys" {
    const v: View = .{ .bytes = "\x00\x02=x\x03a=1\x00\x01=\x01b" };
    try v.validate();
    var it = v.iterate();
    const p1 = it.next().?;
    try testing.expectEqualStrings("a", p1.key);
    try testing.expectEqualStrings("1", p1.value.?);
    const p2 = it.next().?;
    try testing.expectEqualStrings("b", p2.key);
    try testing.expect(p2.value == null);
    try testing.expect(it.next() == null);
    try testing.expectEqual(@as(usize, 2), v.count());
}

test "malformed TXT lengths are safe" {
    const bad: View = .{ .bytes = "\x03a=1\x09b" };
    try testing.expectError(error.Malformed, bad.validate());
    try testing.expectError(error.Malformed, Txt.fromWire(bad.bytes));
    var it = bad.iterate();
    try testing.expectEqualStrings("a", it.next().?.key);
    try testing.expect(it.next() == null);
    try testing.expect(it.next() == null);
    try testing.expect(!bad.has("b"));
    const empty: View = .{ .bytes = "" };
    try empty.validate();
    try testing.expectEqual(@as(usize, 0), empty.count());
}

test "fromWireTruncated drops whole strings past 400 B" {
    // Three strings: 200 + 199 + 3 = 402 octets.
    var raw: [402]u8 = undefined;
    raw[0] = 199;
    @memset(raw[1..200], 'a');
    raw[200] = 198;
    @memset(raw[201..399], 'b');
    raw[399] = 2;
    raw[400] = 'c';
    raw[401] = 'd';
    const r = try Txt.fromWireTruncated(&raw);
    try testing.expect(r.truncated);
    try testing.expectEqual(@as(usize, 399), r.txt.slice().len);
    try testing.expectEqual(@as(usize, 2), r.txt.count());
    const ok = try Txt.fromWireTruncated(raw[0..399]);
    try testing.expect(!ok.truncated);
    try testing.expectEqual(@as(usize, 399), ok.txt.slice().len);
    try testing.expectError(error.Malformed, Txt.fromWireTruncated("\x05ab"));
}
