//! DNS names in wire form (RFC 1035 section 3.1): a sequence of
//! length-prefixed labels ending in a zero octet, at most 255 octets in
//! total, each label at most 63 octets.
//!
//! `Name` is a value type. Decoding follows compression pointers
//! (RFC 1035 section 4.1.4) with a strictly-backward rule and a hop budget,
//! so a hostile packet can never make the decoder loop or read forward.
//! Equality and hashing fold ASCII case (RFC 6762 section 16). Presentation
//! form uses the RFC 6763 section 4.3 escaping (`\.`, `\\`, `\ddd`).
//!
//! No function here allocates. No function here panics on packet bytes.
const std = @import("std");
const ascii = std.ascii;

/// Maximum wire length of a name, including the terminating zero octet
/// (RFC 1035 section 2.3.4).
pub const max_wire_len = 255;
/// Maximum length of one label (RFC 1035 section 2.3.4).
pub const max_label_len = 63;
/// Compression-pointer hop budget. The strictly-backward rule already
/// prevents loops; this is the second fence (plan section 6, name.zig).
pub const max_hops = 64;
/// Lowest legal compression-pointer target. A pointer refers to a prior
/// name (RFC 1035 section 4.1.4) and the first name in any message starts
/// after the 12-octet header, so a pointer into the header is malformed.
pub const min_pointer_target = 12;
/// Upper bound on the presentation form of any `Name`: every label octet
/// may expand to four characters (`\ddd`), plus the label separators.
pub const max_text_len = 1024;

/// A compression pointer octet starts with these two bits set.
const pointer_tag: u8 = 0xC0;

pub const DecodeError = error{Malformed};
pub const ParseError = error{ LabelTooLong, NameTooLong, EmptyLabel, BadEscape };
pub const BuildError = error{ LabelTooLong, NameTooLong };

/// Deviation from the plan section 5 sketch (`Bounded(u8, 255)`): `Name`
/// is a validated wire-form value with the same `len`/`buf`/`slice()`
/// shape, but its default is the root name (`len` 1, one zero octet), not
/// an empty buffer, and it is built through `parse`, `fromLabels`,
/// `fromWire` and `appendLabel` rather than `Bounded`'s raw `append`, so
/// every `Name` in existence is a well-formed name.
pub const Name = struct {
    /// Wire length, including the final zero. The default value is the
    /// root name (a single zero octet).
    len: usize = 1,
    buf: [max_wire_len]u8 = @splat(0),

    pub const root: Name = .{};

    /// The result of decoding a name out of a message.
    pub const Decoded = struct {
        name: Name,
        /// Offset of the first octet after the name as it appears in the
        /// message (after the terminating zero or after the first pointer).
        end: usize,
    };

    /// Wire bytes of the name, always ending in a zero octet.
    pub fn slice(n: *const Name) []const u8 {
        return n.buf[0..n.len];
    }

    /// Build from raw, unescaped labels. Labels may hold any bytes
    /// (RFC 6762 section 16: names are UTF-8 on the wire).
    pub fn fromLabels(items: []const []const u8) BuildError!Name {
        var n: Name = .{};
        for (items) |l| try n.appendLabel(l);
        return n;
    }

    /// Validate an uncompressed wire-form name and copy it.
    pub fn fromWire(bytes: []const u8) DecodeError!Name {
        const d = try decode(bytes, 0);
        if (d.end != bytes.len) return error.Malformed;
        // `decode` rejects pointers into bytes[0..0), so `d.name` is exactly
        // `bytes` and no compression could have occurred.
        return d.name;
    }

    /// Append one raw label. `label` must be 1..63 octets.
    pub fn appendLabel(n: *Name, label: []const u8) BuildError!void {
        if (label.len == 0 or label.len > max_label_len) return error.LabelTooLong;
        // n.len already counts the terminator.
        if (n.len + 1 + label.len > max_wire_len) return error.NameTooLong;
        const at = n.len - 1;
        n.buf[at] = @intCast(label.len);
        @memcpy(n.buf[at + 1 ..][0..label.len], label);
        n.buf[at + 1 + label.len] = 0;
        n.len += 1 + label.len;
    }

    /// Append every label of `suffix`.
    pub fn appendName(n: *Name, suffix: Name) BuildError!void {
        if (n.len - 1 + suffix.len > max_wire_len) return error.NameTooLong;
        const at = n.len - 1;
        @memcpy(n.buf[at..][0..suffix.len], suffix.slice());
        n.len = at + suffix.len;
    }

    /// `<instance>.<service>.<domain>`, e.g. `("Alice", "_qmsg._udp",
    /// "local")`. `instance` is one raw label; `service` and `domain` are
    /// presentation-form names.
    pub fn serviceInstance(instance: []const u8, service: []const u8, domain: []const u8) (BuildError || ParseError)!Name {
        var n: Name = .{};
        try n.appendLabel(instance);
        try n.appendName(try parse(service));
        try n.appendName(try parse(domain));
        return n;
    }

    /// Decode the name at `offset` in `msg`, following compression
    /// pointers.
    ///
    /// Bounds: every pointer must target an offset strictly lower than the
    /// lowest offset reached so far (initially `offset`). A pointer to
    /// itself, a forward pointer, or a pointer back into a name already on
    /// the chain is therefore `error.Malformed`. This is the RFC 1035
    /// "prior occurrence" rule made mechanical, and it guarantees the walk
    /// terminates; `max_hops` is a second fence. A pointer into the header
    /// (target below `min_pointer_target`) is rejected. Output over 255
    /// octets is `error.Malformed`. Extended label types (0x40, 0x80) are
    /// rejected.
    pub fn decode(msg: []const u8, offset: usize) DecodeError!Decoded {
        var name: Name = .{};
        name.len = 0;
        var pos = offset;
        var bound = offset; // every pointer must land strictly below this
        var end: ?usize = null;
        var hops: usize = 0;
        while (true) {
            if (pos >= msg.len) return error.Malformed;
            const b = msg[pos];
            switch (b & pointer_tag) {
                0x00 => {
                    if (b == 0) {
                        if (name.len + 1 > max_wire_len) return error.Malformed;
                        name.buf[name.len] = 0;
                        name.len += 1;
                        if (end == null) end = pos + 1;
                        break;
                    }
                    const label_len: usize = b;
                    if (pos + 1 + label_len > msg.len) return error.Malformed;
                    // +1 for the length octet, +1 for the terminator that
                    // must still fit.
                    if (name.len + 1 + label_len + 1 > max_wire_len) return error.Malformed;
                    @memcpy(name.buf[name.len..][0 .. 1 + label_len], msg[pos..][0 .. 1 + label_len]);
                    name.len += 1 + label_len;
                    pos += 1 + label_len;
                },
                pointer_tag => {
                    if (pos + 1 >= msg.len) return error.Malformed;
                    const target: usize = (@as(usize, b & 0x3F) << 8) | msg[pos + 1];
                    if (target >= bound or target < min_pointer_target) return error.Malformed;
                    hops += 1;
                    if (hops > max_hops) return error.Malformed;
                    if (end == null) end = pos + 2;
                    bound = target;
                    pos = target;
                },
                else => return error.Malformed,
            }
        }
        return .{ .name = name, .end = end orelse offset };
    }

    /// Copy the uncompressed wire form into `out`. Returns the length.
    pub fn encode(n: *const Name, out: []u8) error{NoSpace}!usize {
        if (out.len < n.len) return error.NoSpace;
        @memcpy(out[0..n.len], n.slice());
        return n.len;
    }

    /// Parse presentation form with RFC 6763 section 4.3 escaping:
    /// `\.` is a literal dot, `\\` a literal backslash, `\ddd` (three
    /// decimal digits, 0..255) an arbitrary octet, and any other `\x` is
    /// `x`. A trailing dot is accepted. `"."` and `""` are the root.
    pub fn parse(text: []const u8) ParseError!Name {
        var n: Name = .{};
        if (text.len == 0 or std.mem.eql(u8, text, ".")) return n;
        var label: [max_label_len]u8 = undefined;
        var label_len: usize = 0;
        var i: usize = 0;
        while (i < text.len) {
            const c = text[i];
            if (c == '.') {
                if (label_len == 0) return error.EmptyLabel;
                try n.appendLabel(label[0..label_len]);
                label_len = 0;
                i += 1;
                continue;
            }
            var out: u8 = c;
            if (c == '\\') {
                if (i + 1 >= text.len) return error.BadEscape;
                const d0 = text[i + 1];
                if (ascii.isDigit(d0)) {
                    if (i + 3 >= text.len or !ascii.isDigit(text[i + 2]) or !ascii.isDigit(text[i + 3])) {
                        return error.BadEscape;
                    }
                    const v: u32 = @as(u32, d0 - '0') * 100 + @as(u32, text[i + 2] - '0') * 10 + (text[i + 3] - '0');
                    if (v > 255) return error.BadEscape;
                    out = @intCast(v);
                    i += 4;
                } else {
                    out = d0;
                    i += 2;
                }
            } else {
                i += 1;
            }
            if (label_len >= max_label_len) return error.LabelTooLong;
            label[label_len] = out;
            label_len += 1;
        }
        if (label_len > 0) try n.appendLabel(label[0..label_len]);
        return n;
    }

    /// Presentation form into `out` (`max_text_len` always suffices).
    /// Labels are separated by dots; no trailing dot; the root is `"."`.
    pub fn toText(n: *const Name, out: []u8) error{NoSpace}![]const u8 {
        var w: std.Io.Writer = .fixed(out);
        n.format(&w) catch return error.NoSpace;
        return w.buffered();
    }

    /// `{f}` support. Same output as `toText`.
    pub fn format(n: *const Name, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var it = n.labels();
        var first = true;
        if (it.peekEmpty()) return w.writeByte('.');
        while (it.next()) |label| {
            if (!first) try w.writeByte('.');
            first = false;
            for (label) |c| try writeEscaped(w, c);
        }
    }

    fn writeEscaped(w: *std.Io.Writer, c: u8) std.Io.Writer.Error!void {
        switch (c) {
            '.', '\\' => {
                try w.writeByte('\\');
                try w.writeByte(c);
            },
            0x00...0x1F, 0x7F => {
                var d: [4]u8 = undefined;
                d[0] = '\\';
                d[1] = '0' + c / 100;
                d[2] = '0' + (c / 10) % 10;
                d[3] = '0' + c % 10;
                try w.writeAll(&d);
            },
            else => try w.writeByte(c),
        }
    }

    /// ASCII case-insensitive equality (RFC 6762 section 16). Non-ASCII
    /// octets compare exactly.
    pub fn eql(a: *const Name, b: *const Name) bool {
        return ascii.eqlIgnoreCase(a.slice(), b.slice());
    }

    /// Hash consistent with `eql`.
    pub fn hash(n: *const Name) u64 {
        var lower: [max_wire_len]u8 = undefined;
        const s = n.slice();
        for (s, 0..) |c, i| lower[i] = ascii.toLower(c);
        return std.hash.Wyhash.hash(0, lower[0..s.len]);
    }

    /// True when `suffix` is `n` itself or a parent of `n` (case folded).
    pub fn endsWith(n: *const Name, suffix: *const Name) bool {
        if (suffix.len > n.len) return false;
        const n_count = n.labelCount();
        const s_count = suffix.labelCount();
        if (s_count > n_count) return false;
        var it = n.labels();
        var skip = n_count - s_count;
        while (skip > 0) : (skip -= 1) _ = it.next();
        return ascii.eqlIgnoreCase(n.buf[it.pos..n.len], suffix.slice());
    }

    pub fn isRoot(n: *const Name) bool {
        return n.len == 1;
    }

    pub fn labelCount(n: *const Name) usize {
        var it = n.labels();
        var c: usize = 0;
        while (it.next()) |_| c += 1;
        return c;
    }

    /// The first label, or null for the root.
    pub fn firstLabel(n: *const Name) ?[]const u8 {
        var it = n.labels();
        return it.next();
    }

    /// The name without its first label. The root's parent is the root.
    pub fn parent(n: *const Name) Name {
        if (n.isRoot()) return n.*;
        const first_len: usize = n.buf[0];
        // Invariant: first_len <= 63 and 1 + first_len < n.len; guard it
        // anyway so a hand-built Name cannot slice out of bounds.
        if (1 + first_len >= n.len) return Name.root;
        return Name.fromWire(n.buf[1 + first_len .. n.len]) catch Name.root;
    }

    pub fn labels(n: *const Name) LabelIterator {
        return .{ .name = n, .pos = 0 };
    }

    pub const LabelIterator = struct {
        name: *const Name,
        pos: usize,

        pub fn next(it: *LabelIterator) ?[]const u8 {
            if (it.pos >= it.name.len) return null;
            const l: usize = it.name.buf[it.pos];
            if (l == 0 or it.pos + 1 + l > it.name.len) {
                it.pos = it.name.len;
                return null;
            }
            const label = it.name.buf[it.pos + 1 ..][0..l];
            it.pos += 1 + l;
            return label;
        }

        fn peekEmpty(it: *const LabelIterator) bool {
            return it.pos >= it.name.len or it.name.buf[it.pos] == 0;
        }
    };
};

// ---------------------------------------------------------------------------
// DNS-SD name validation
// ---------------------------------------------------------------------------

pub const ServiceNameError = error{
    /// The type is not `_name._tcp` or `_name._udp`.
    BadServiceType,
    /// Protocol label is neither `_tcp` nor `_udp` (RFC 6763 section 7).
    BadProtocol,
    /// Service label body is empty or longer than 15 characters.
    BadLength,
    /// A character outside `[A-Za-z0-9-]`.
    BadChar,
    /// No letter at all (all digits, or digits and hyphens).
    NoLetter,
    /// A hyphen at the start or the end.
    EdgeHyphen,
    /// Two hyphens in a row.
    DoubleHyphen,
};

/// Validate a DNS-SD service type `_name._tcp` or `_name._udp`
/// (RFC 6763 section 7). The `name` part must follow RFC 6335 section 5.1:
/// 1..15 characters; letters, digits and hyphens only; at least one letter;
/// no hyphen at either end; no consecutive hyphens.
pub fn validateServiceName(service_type: []const u8) ServiceNameError!void {
    const dot = std.mem.indexOfScalar(u8, service_type, '.') orelse return error.BadServiceType;
    const svc = service_type[0..dot];
    const proto = service_type[dot + 1 ..];
    if (std.mem.indexOfScalar(u8, proto, '.') != null) return error.BadServiceType;
    if (!ascii.eqlIgnoreCase(proto, "_tcp") and !ascii.eqlIgnoreCase(proto, "_udp")) return error.BadProtocol;
    if (svc.len == 0 or svc[0] != '_') return error.BadServiceType;
    const body = svc[1..];
    if (body.len == 0 or body.len > 15) return error.BadLength;
    var has_letter = false;
    var prev_hyphen = false;
    for (body, 0..) |c, i| {
        if (ascii.isAlphabetic(c)) {
            has_letter = true;
            prev_hyphen = false;
        } else if (ascii.isDigit(c)) {
            prev_hyphen = false;
        } else if (c == '-') {
            if (i == 0 or i == body.len - 1) return error.EdgeHyphen;
            if (prev_hyphen) return error.DoubleHyphen;
            prev_hyphen = true;
        } else {
            return error.BadChar;
        }
    }
    if (!has_letter) return error.NoLetter;
}

pub const InstanceError = error{InvalidInstance};

/// Validate a DNS-SD instance name (RFC 6763 section 4.1.1): 1..63 octets
/// of valid UTF-8 with no control characters (0x00..0x1F, 0x7F).
pub fn validateInstance(instance: []const u8) InstanceError!void {
    if (instance.len == 0 or instance.len > max_label_len) return error.InvalidInstance;
    if (!std.unicode.utf8ValidateSlice(instance)) return error.InvalidInstance;
    for (instance) |c| if (ascii.isControl(c)) return error.InvalidInstance;
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "root name" {
    const r: Name = .{};
    try testing.expect(r.isRoot());
    try testing.expectEqualSlices(u8, &.{0}, r.slice());
    try testing.expectEqual(@as(usize, 0), r.labelCount());
    var buf: [max_text_len]u8 = undefined;
    try testing.expectEqualStrings(".", try r.toText(&buf));
    try testing.expect((try Name.parse(".")).isRoot());
    try testing.expect((try Name.parse("")).isRoot());
}

test "fromLabels and parse agree" {
    const a = try Name.fromLabels(&.{ "_qmsg", "_udp", "local" });
    const b = try Name.parse("_qmsg._udp.local");
    const c = try Name.parse("_qmsg._udp.local.");
    try testing.expectEqualSlices(u8, "\x05_qmsg\x04_udp\x05local\x00", a.slice());
    try testing.expect(a.eql(&b));
    try testing.expect(a.eql(&c));
    try testing.expectEqual(@as(usize, 3), a.labelCount());
    try testing.expectEqualStrings("_qmsg", a.firstLabel().?);
    const p = a.parent();
    try testing.expect(p.eql(&(try Name.parse("_udp.local"))));
    try testing.expect(a.endsWith(&(try Name.parse("LOCAL"))));
    try testing.expect(a.endsWith(&(try Name.parse("_udp.local"))));
    try testing.expect(!a.endsWith(&(try Name.parse("_tcp.local"))));
    try testing.expect(a.endsWith(&Name.root));
    // More labels but fewer octets than the name: no underflow.
    const wide = try Name.parse("aaaaaaaaaa");
    const deep = try Name.parse("a.b.c");
    try testing.expect(!wide.endsWith(&deep));
    try testing.expect(!deep.endsWith(&wide));
    try testing.expect(deep.endsWith(&deep));
    try testing.expect(Name.root.endsWith(&Name.root));
    try testing.expect(!Name.root.endsWith(&deep));
    try testing.expect(Name.root.parent().isRoot());
}

test "equality and hash fold ASCII case only" {
    const a = try Name.parse("Alice._qmsg._udp.local");
    const b = try Name.parse("ALICE._QMSG._UDP.LOCAL");
    const c = try Name.parse("Bob._qmsg._udp.local");
    try testing.expect(a.eql(&b));
    try testing.expect(!a.eql(&c));
    try testing.expectEqual(a.hash(), b.hash());
    try testing.expect(a.hash() != c.hash());
    // Non-ASCII octets compare exactly.
    const e_lower = try Name.fromLabels(&.{"\xc3\xa9"});
    const e_upper = try Name.fromLabels(&.{"\xc3\x89"});
    try testing.expect(!e_lower.eql(&e_upper));
}

test "escaping round trip" {
    const n = try Name.parse("My\\.Service\\032(2)._http._tcp.local");
    try testing.expectEqualStrings("My.Service (2)", n.firstLabel().?);
    var buf: [max_text_len]u8 = undefined;
    const text = try n.toText(&buf);
    try testing.expectEqualStrings("My\\.Service (2)._http._tcp.local", text);
    const again = try Name.parse(text);
    try testing.expect(n.eql(&again));
    try testing.expectEqualSlices(u8, n.slice(), again.slice());

    // Control bytes and backslashes.
    const raw = try Name.fromLabels(&.{ "a\\b\x01\x7f.c", "local" });
    const t2 = try raw.toText(&buf);
    try testing.expectEqualStrings("a\\\\b\\001\\127\\.c.local", t2);
    const back = try Name.parse(t2);
    try testing.expectEqualSlices(u8, raw.slice(), back.slice());
    // {f} formatting matches toText.
    try testing.expectFmt("a\\\\b\\001\\127\\.c.local", "{f}", .{raw});
}

test "parse rejects bad input" {
    try testing.expectError(error.EmptyLabel, Name.parse("a..b"));
    try testing.expectError(error.EmptyLabel, Name.parse(".a"));
    try testing.expectError(error.BadEscape, Name.parse("a\\"));
    try testing.expectError(error.BadEscape, Name.parse("a\\1x"));
    try testing.expectError(error.BadEscape, Name.parse("a\\999"));
    try testing.expectError(error.LabelTooLong, Name.parse(rep(64, 'a')));
    _ = try Name.parse(rep(63, 'a'));
    // 4 labels of 63 = 4*64 = 256 > 255.
    try testing.expectError(error.NameTooLong, Name.parse(rep(63, 'a') ++ "." ++ rep(63, 'b') ++ "." ++ rep(63, 'c') ++ "." ++ rep(63, 'd')));
    // 3 labels of 63 + one of 61: 64*3 + 62 + 1 = 255 fits.
    const fits = try Name.parse(rep(63, 'a') ++ "." ++ rep(63, 'b') ++ "." ++ rep(63, 'c') ++ "." ++ rep(61, 'd'));
    try testing.expectEqual(@as(usize, 255), fits.len);
    try testing.expectError(error.NameTooLong, Name.parse(rep(63, 'a') ++ "." ++ rep(63, 'b') ++ "." ++ rep(63, 'c') ++ "." ++ rep(62, 'd')));
}

test "decode follows backward pointers" {
    // 12 header bytes worth of padding, then "b.local", then "a" + ptr->12.
    const msg = rep(12, '\x00') ++ "\x01b\x05local\x00" ++ "\x01a\xc0\x0c" ++ "tail";
    const d = try Name.decode(msg, 21);
    try expectText("a.b.local", d.name);
    try testing.expectEqual(@as(usize, 25), d.end);
    // Chain: "c" + ptr->21 -> "a" + ptr->12.
    const msg2 = msg ++ "\x01c\xc0\x15";
    const d2 = try Name.decode(msg2, 29);
    try expectText("c.a.b.local", d2.name);
    try testing.expectEqual(@as(usize, 33), d2.end);
}

/// Test helper: a comptime string of `n` copies of `c`.
fn rep(comptime n: usize, comptime c: u8) *const [n]u8 {
    const arr: [n]u8 = @splat(c);
    return &arr;
}

/// Test helper: presentation form of `n` equals `expected`.
pub fn expectText(expected: []const u8, n: Name) !void {
    var buf: [max_text_len]u8 = undefined;
    try testing.expectEqualStrings(expected, try n.toText(&buf));
}

test "compression pointer loop is rejected" {
    // Pointer at 12 -> 14, pointer at 14 -> 12: a two-node loop. The second
    // pointer targets an offset that is not strictly below the first
    // target, so it is rejected before any repetition.
    const msg = rep(12, '\x00') ++ "\xc0\x0e" ++ "\xc0\x0c";
    try testing.expectError(error.Malformed, Name.decode(msg, 12));
    try testing.expectError(error.Malformed, Name.decode(msg, 14));
    // Pointer to self.
    const self_ptr = rep(12, '\x00') ++ "\xc0\x0c";
    try testing.expectError(error.Malformed, Name.decode(self_ptr, 12));
    // Label then pointer back to the label's own start: "a" + ptr->12.
    const own = rep(12, '\x00') ++ "\x01a\xc0\x0c";
    try testing.expectError(error.Malformed, Name.decode(own, 12));
    // Indirect: the name at 12 is a label whose body hides a pointer that
    // lands back on 12 through a pointer at 61 -> 30 -> 12.
    var buf: [64]u8 = @splat(0);
    buf[12] = 48; // label of 48 octets covering 13..60
    buf[30] = 0xc0;
    buf[31] = 12;
    buf[61] = 0xc0;
    buf[62] = 30;
    try testing.expectError(error.Malformed, Name.decode(&buf, 12));
}

test "forward pointer is rejected" {
    const msg = rep(12, '\x00') ++ "\x01a\xc0\x12" ++ "\x05local\x00";
    try testing.expectError(error.Malformed, Name.decode(msg, 12));
    // Even a pointer that targets a valid name later in the message.
    try testing.expectError(error.Malformed, Name.decode(msg, 14));
    // Pointer target past the end of the message.
    const past = rep(12, '\x00') ++ "\xc0\xff";
    try testing.expectError(error.Malformed, Name.decode(past, 12));
    // A pointer whose second octet is missing.
    try testing.expectError(error.Malformed, Name.decode(rep(12, '\x00') ++ "\xc0", 12));
}

test "name over 255 octets is rejected" {
    // Uncompressed: four 63-octet labels = 256 octets before the zero.
    var long: [1 + 4 * 64 + 1]u8 = undefined;
    long[0] = 0;
    var i: usize = 1;
    for (0..4) |_| {
        long[i] = 63;
        @memset(long[i + 1 ..][0..63], 'x');
        i += 64;
    }
    long[i] = 0;
    try testing.expectError(error.Malformed, Name.decode(&long, 1));
    // Through compression: "y"*63 + ptr -> a 3*64+62 = 254-octet name gives
    // 254 + 64 = 318 > 255.
    var msg: [512]u8 = @splat(0);
    i = 12;
    for (0..3) |_| {
        msg[i] = 63;
        @memset(msg[i + 1 ..][0..63], 'a');
        i += 64;
    }
    msg[i] = 61;
    @memset(msg[i + 1 ..][0..61], 'b');
    i += 62;
    msg[i] = 0;
    i += 1;
    const base_end = i;
    const ok = try Name.decode(&msg, 12);
    try testing.expectEqual(@as(usize, 255), ok.name.len);
    try testing.expectEqual(base_end, ok.end);
    msg[i] = 1;
    msg[i + 1] = 'y';
    msg[i + 2] = 0xc0;
    msg[i + 3] = 12;
    try testing.expectError(error.Malformed, Name.decode(&msg, base_end));
    // fromWire rejects a trailing byte and an oversized name.
    try testing.expectError(error.Malformed, Name.fromWire("\x01a\x00\x00"));
    try testing.expectError(error.Malformed, Name.fromWire(long[1..]));
    _ = try Name.fromWire("\x01a\x00");
}

test "decode rejects truncation and extended labels" {
    try testing.expectError(error.Malformed, Name.decode("", 0));
    try testing.expectError(error.Malformed, Name.decode("\x03ab", 0));
    try testing.expectError(error.Malformed, Name.decode("\x01a", 0));
    try testing.expectError(error.Malformed, Name.decode("\x40a\x00", 0));
    try testing.expectError(error.Malformed, Name.decode("\x80a\x00", 0));
    try testing.expectError(error.Malformed, Name.decode("\x00", 1));
    try testing.expectError(error.Malformed, Name.decode("\x40", 0));
}

test "hop budget is enforced independently of the backward rule" {
    // Root at offset 12, then 66 pointers each stepping back one entry.
    var msg: [12 + 1 + 2 * 66]u8 = @splat(0);
    var i: usize = 13;
    var idx: usize = 0;
    while (idx < 66) : (idx += 1) {
        const target = if (idx == 0) @as(usize, 12) else i - 2;
        msg[i] = 0xc0 | @as(u8, @intCast(target >> 8));
        msg[i + 1] = @intCast(target & 0xff);
        i += 2;
    }
    // From the last pointer there are 66 hops: over budget.
    try testing.expectError(error.Malformed, Name.decode(msg[0..i], i - 2));
    // From the 64th pointer there are exactly 64 hops: within budget.
    const d = try Name.decode(msg[0..i], 13 + 63 * 2);
    try testing.expect(d.name.isRoot());
    try testing.expectEqual(@as(usize, 13 + 64 * 2), d.end);
}

test "pointer into the header is rejected" {
    const msg = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\xc0\x05";
    try testing.expectError(error.Malformed, Name.decode(msg, 12));
    try testing.expectError(error.Malformed, Name.decode(msg, 13));
}

test "service name rejects leading hyphen, double hyphen and all-digit" {
    try validateServiceName("_http._tcp");
    try validateServiceName("_qmsg._udp");
    try validateServiceName("_shared-studio._udp");
    try validateServiceName("_a1._tcp");
    try validateServiceName("_1a._TCP");
    try validateServiceName("_abcdefghijklmno._tcp"); // 15 chars
    try testing.expectError(error.EdgeHyphen, validateServiceName("_-http._tcp"));
    try testing.expectError(error.EdgeHyphen, validateServiceName("_http-._tcp"));
    try testing.expectError(error.DoubleHyphen, validateServiceName("_ht--tp._tcp"));
    try testing.expectError(error.NoLetter, validateServiceName("_123._tcp"));
    try testing.expectError(error.NoLetter, validateServiceName("_1-2._tcp"));
    try testing.expectError(error.BadLength, validateServiceName("_abcdefghijklmnop._tcp")); // 16
    try testing.expectError(error.BadLength, validateServiceName("_._tcp"));
    try testing.expectError(error.BadChar, validateServiceName("_ht_tp._tcp"));
    try testing.expectError(error.BadChar, validateServiceName("_http\xc3\xa9._tcp"));
    try testing.expectError(error.BadProtocol, validateServiceName("_http._sctp"));
    try testing.expectError(error.BadServiceType, validateServiceName("http._tcp"));
    try testing.expectError(error.BadServiceType, validateServiceName("_http"));
    try testing.expectError(error.BadServiceType, validateServiceName("_http._tcp.local"));
}

test "validateInstance bounds and control bytes" {
    try validateInstance("Alice");
    try validateInstance("My.Service (2)");
    try validateInstance("caf\xc3\xa9");
    try validateInstance(rep(63, 'x'));
    try testing.expectError(error.InvalidInstance, validateInstance(""));
    try testing.expectError(error.InvalidInstance, validateInstance(rep(64, 'x')));
    try testing.expectError(error.InvalidInstance, validateInstance("a\x00b"));
    try testing.expectError(error.InvalidInstance, validateInstance("a\x7fb"));
    try testing.expectError(error.InvalidInstance, validateInstance("a\tb"));
    try testing.expectError(error.InvalidInstance, validateInstance("\xc3")); // truncated UTF-8
    try testing.expectError(error.InvalidInstance, validateInstance("\xff"));
}

test "serviceInstance builds Instance.Service.Domain" {
    const n = try Name.serviceInstance("My.Service", "_http._tcp", "local");
    var buf: [max_text_len]u8 = undefined;
    try testing.expectEqualStrings("My\\.Service._http._tcp.local", try n.toText(&buf));
    try testing.expectEqual(@as(usize, 4), n.labelCount());
    try testing.expectError(error.LabelTooLong, Name.serviceInstance("", "_http._tcp", "local"));
}
