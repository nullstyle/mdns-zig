//! Fuzz targets over the wire codec (plan §7 M1, §8 tier 3): `Message.parse`,
//! `Name.decode`, `Txt.iterate`, a `Builder` round trip and, since M3,
//! `Engine.handle` with random bytes and `RxMeta`. Each is a
//! `std.testing.fuzz` target written against the Smith API of this pin
//! (`std/testing.zig` `pub inline fn fuzz`, `std/testing/Smith.zig`):
//! `testOne(context, smith: *std.testing.Smith)` pulls bytes with
//! `smith.slice(&buf)` and structured values with `smith.value*`.
//!
//! Invariants (SECURITY.md): no panic, no unchecked slicing, every parse
//! loop bounded. Every decoder returns `error.Malformed` on bad input, so
//! the targets treat that error as a normal outcome and assert the codec's
//! own contracts on the accepting path: iterators walk exactly the header
//! counts, names round-trip through their text form, canonical rdata
//! exists for every parsed record, and whatever the Builder writes parses
//! back to the same records.
//!
//! Corpus framing (`Smith.zig` `sliceWeightedWithHash`, the `s.in` branch):
//! on replay each `slice` call consumes a 4-byte little-endian length and
//! then that many bytes; each `value`/`valueRange*` call on an integer
//! consumes 8 bytes (u64 LE) and falls back to the range minimum when the
//! input is exhausted or the value is out of range. Seeds below follow that
//! framing. Under a plain `zig build test` the runner feeds every corpus
//! entry plus the empty input through `testOne` once, so each target also
//! runs as an ordinary test.
//!
//! Do not add per-target build steps: a filtered test binary under
//! `--fuzz` aborts the build runner (ziglang/zig#25352). `zig build test
//! --fuzz=N` drives every target in this file together.
const std = @import("std");
const mdns = @import("mdns");
const wire = mdns.wire;
const Smith = std.testing.Smith;

const Name = wire.Name;
const Message = wire.Message;
const Record = wire.Record;
const RType = wire.RType;
const Section = wire.Section;
const rdata = wire.rdata;
const txt = wire.txt;

// ---------------------------------------------------------------------------
// corpus helpers
// ---------------------------------------------------------------------------

/// Decode one fixture (`tests/fixtures/raw/NNNN.hex`: lowercase hex, one
/// line) at comptime and frame it for one `smith.slice` call.
fn fixtureSeed(comptime hex_file: []const u8) []const u8 {
    @setEvalBranchQuota(20_000);
    const hex = comptime std.mem.trimEnd(u8, hex_file, "\r\n");
    return comptime framed(hexToBytes(hex));
}

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(100_000);
    if (hex.len % 2 != 0) @compileError("fixture hex has odd length");
    var out: [hex.len / 2]u8 = undefined;
    for (&out, 0..) |*b, i| {
        b.* = std.fmt.parseInt(u8, hex[2 * i ..][0..2], 16) catch @compileError("fixture hex is not hex");
    }
    return out;
}

/// `[u32 LE len][bytes]`: what one `smith.slice` call reads on replay.
fn framed(comptime bytes: anytype) []const u8 {
    @setEvalBranchQuota(100_000);
    const n = bytes.len;
    var out: [4 + n]u8 = undefined;
    std.mem.writeInt(u32, out[0..4], n, .little);
    @memcpy(out[4..], &bytes);
    const final = out;
    return &final;
}

/// A framed slice followed by one u64 LE integer, for targets that read
/// bytes and then one `valueRangeAtMost` offset.
fn framedWithInt(comptime bytes: anytype, comptime int: u64) []const u8 {
    @setEvalBranchQuota(100_000);
    const n = bytes.len;
    var out: [4 + n + 8]u8 = undefined;
    std.mem.writeInt(u32, out[0..4], n, .little);
    @memcpy(out[4 .. 4 + n], &bytes);
    std.mem.writeInt(u64, out[4 + n ..][0..8], int, .little);
    const final = out;
    return &final;
}

/// A byte array of `n` copies of `c` (the `**` operator does not parse on
/// this pin; use `@splat`).
fn rep(comptime n: usize, comptime c: u8) [n]u8 {
    const a: [n]u8 = @splat(c);
    return a;
}

// Real mDNSResponder datagrams (see tests/fixtures/README.md): a probe
// (ANY question + authority SRV), a full announce (A/PTR/TXT/AAAA/SRV/NSEC
// with cache-flush), a query with six known answers, the largest query
// (20 known answers), the resolve query (two questions), a goodbye PTR
// (TTL 0) and a five-answer query.
const fixture_probe = @embedFile("fixtures/raw/0011.hex");
const fixture_announce = @embedFile("fixtures/raw/0024.hex");
const fixture_ka6 = @embedFile("fixtures/raw/0029.hex");
const fixture_ka20 = @embedFile("fixtures/raw/0034.hex");
const fixture_resolve = @embedFile("fixtures/raw/0180.hex");
const fixture_goodbye = @embedFile("fixtures/raw/0188.hex");
const fixture_ka5 = @embedFile("fixtures/raw/0212.hex");

// Hand-built malformed packets from the message.zig unit corpus.
const hdr_query_1q = [_]u8{ 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
const hdr_resp_1a = [_]u8{ 0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0 };
/// Count overflow: qdcount 0xFFFF with one question present.
const malformed_count = [_]u8{ 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0 } ++ [_]u8{ 1, 'a', 0, 0, 12, 0, 1 };
/// Pointer to self at offset 12.
const malformed_self_pointer = hdr_query_1q ++ [_]u8{ 0xC0, 12, 0, 12, 0, 1 };
/// Forward pointer (target 20 from offset 12).
const malformed_forward = hdr_query_1q ++ [_]u8{ 0xC0, 20, 0, 12, 0, 1, 0, 0, 5, 'l', 'o', 'c', 'a', 'l', 0 };
/// Two-name loop: name at 12 points to 15, which points back to 12.
const malformed_loop = hdr_query_1q ++ [_]u8{ 1, 'a', 0xC0, 15, 0xC0, 12, 0, 12, 0, 1 };
/// Pointer into the header.
const malformed_header_pointer = hdr_query_1q ++ [_]u8{ 0xC0, 3, 0, 12, 0, 1 };
/// rdlength past the end of the packet.
const malformed_rdlength = hdr_resp_1a ++ [_]u8{ 1, 'a', 0, 0, 1, 0, 1, 0, 0, 0, 120, 0, 40, 1, 2, 3, 4 };
/// Label length 64 (over 63) and an extended label type.
const malformed_label = hdr_query_1q ++ [_]u8{64} ++ rep(64, 'x') ++ [_]u8{ 0, 0, 12, 0, 1 };
const malformed_ext_label = hdr_query_1q ++ [_]u8{ 0x41, 'a', 0, 0, 12, 0, 1 };
/// Truncated header.
const malformed_short = [_]u8{ 0, 0, 0, 0, 0, 1 };

// ---------------------------------------------------------------------------
// shared checks
// ---------------------------------------------------------------------------

/// Contracts every decoded name must satisfy: wire form is at most 255
/// octets ending in a zero, the text form parses back to the same name,
/// `hash` agrees with `eql`, and the label walk matches `labelCount`.
fn checkName(n: *const Name) !void {
    try std.testing.expect(n.len >= 1 and n.len <= wire.name.max_wire_len);
    try std.testing.expectEqual(@as(u8, 0), n.buf[n.len - 1]);

    var text_buf: [wire.name.max_text_len]u8 = undefined;
    const text = try n.toText(&text_buf);
    const back = try Name.parse(text);
    try std.testing.expect(n.eql(&back));
    try std.testing.expectEqualSlices(u8, n.slice(), back.slice());
    try std.testing.expectEqual(n.hash(), back.hash());

    var wire_buf: [wire.name.max_wire_len]u8 = undefined;
    const wlen = try n.encode(&wire_buf);
    const from_wire = try Name.fromWire(wire_buf[0..wlen]);
    try std.testing.expect(n.eql(&from_wire));

    var count: usize = 0;
    var labels = n.labels();
    while (labels.next()) |label| {
        try std.testing.expect(label.len >= 1 and label.len <= wire.name.max_label_len);
        count += 1;
    }
    try std.testing.expectEqual(n.labelCount(), count);
    try std.testing.expectEqual(count == 0, n.isRoot());
    try std.testing.expect(n.endsWith(&Name.root));
    try std.testing.expect(n.endsWith(n));
    if (count > 0) {
        const p = n.parent();
        try std.testing.expectEqual(count - 1, p.labelCount());
        try std.testing.expect(n.endsWith(&p));
    }
}

/// Decode a parsed record's rdata with the decoder for its type. A
/// `Malformed` result is a valid outcome (the rdata is attacker bytes);
/// a decoder that returns a value must produce a canonical form.
fn checkRecord(msg: []const u8, rec: Record) !void {
    try checkName(&rec.name);
    try std.testing.expect(rec.rdata_offset + rec.rdata.len <= msg.len);
    try std.testing.expectEqual(rec.class_raw & ~wire.cache_flush_bit, rec.class);
    try std.testing.expectEqual(rec.class_raw & wire.cache_flush_bit != 0, rec.cache_flush);

    var scratch: [wire.max_message_len]u8 = undefined;
    switch (rec.rtype) {
        .a => _ = rdata.decodeA(rec.rdata) catch {},
        .aaaa => _ = rdata.decodeAaaa(rec.rdata) catch {},
        .ptr, .ns, .cname => {
            if (rdata.decodePtr(msg, rec)) |n| {
                try checkName(&n);
                const canon = try rdata.canonicalRdata(msg, rec, &scratch);
                try std.testing.expectEqualSlices(u8, n.slice(), canon);
            } else |_| {
                try std.testing.expectError(error.Malformed, rdata.canonicalRdata(msg, rec, &scratch));
            }
        },
        .srv => {
            if (rdata.decodeSrv(msg, rec)) |srv| {
                try checkName(&srv.target);
                const canon = try rdata.canonicalRdata(msg, rec, &scratch);
                var enc: [rdata.max_name_rdata_len]u8 = undefined;
                const n = try rdata.encodeSrv(srv, &enc);
                try std.testing.expectEqualSlices(u8, enc[0..n], canon);
            } else |_| {
                try std.testing.expectError(error.Malformed, rdata.canonicalRdata(msg, rec, &scratch));
            }
        },
        .txt => {
            if (rdata.decodeTxt(rec)) |view| {
                try checkTxtView(view);
            } else |_| {}
            _ = try rdata.canonicalRdata(msg, rec, &scratch);
        },
        .nsec => {
            if (rdata.decodeNsec(msg, rec)) |nsec| {
                try checkName(&nsec.next);
                try std.testing.expect(nsec.bitmapLen() <= 32);
                _ = try rdata.canonicalRdata(msg, rec, &scratch);
            } else |_| {}
        },
        .hinfo => {
            if (rdata.decodeHinfo(rec)) |h| {
                try std.testing.expectEqual(rec.rdata.len, 2 + h.cpu.len + h.os.len);
            } else |_| {}
            _ = try rdata.canonicalRdata(msg, rec, &scratch);
        },
        else => _ = try rdata.canonicalRdata(msg, rec, &scratch),
    }

    // RFC 6762 §8.2: a record compares equal to itself whenever its
    // canonical form exists.
    if (rdata.compareRecords(msg, rec, msg, rec)) |order| {
        try std.testing.expectEqual(std.math.Order.eq, order);
    } else |_| {}
}

/// Contracts of the TXT view: `count` matches the walk, every pair has a
/// non-empty key without '=', and `find` on any key returns the first
/// pair with that key (case-insensitively).
fn checkTxtView(view: txt.View) !void {
    var n: usize = 0;
    var first: ?wire.TxtPair = null;
    var it = view.iterate();
    while (it.next()) |p| {
        try std.testing.expect(p.key.len >= 1);
        try std.testing.expect(std.mem.findScalar(u8, p.key, '=') == null);
        try std.testing.expect(p.key.len <= txt.max_string_len);
        if (p.value) |v| try std.testing.expect(p.key.len + 1 + v.len <= txt.max_string_len);
        if (first == null) first = p;
        n += 1;
    }
    try std.testing.expectEqual(n, view.count());
    if (first) |p| {
        const found = view.find(p.key) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualSlices(u8, p.key, found.key);
        try std.testing.expectEqual(p.value == null, found.value == null);
        if (p.value) |v| try std.testing.expectEqualSlices(u8, v, found.value.?);
        try std.testing.expect(view.has(p.key));
        try std.testing.expectEqual(p.value == null, view.get(p.key) == null);
        // Case-insensitive lookup finds the same pair.
        var upper: [txt.max_string_len]u8 = undefined;
        const key_upper = std.ascii.upperString(upper[0..p.key.len], p.key);
        try std.testing.expect(view.has(key_upper));
    } else {
        try std.testing.expect(!view.has("k"));
    }
}

// ---------------------------------------------------------------------------
// Message.parse
// ---------------------------------------------------------------------------

const message_corpus: []const []const u8 = &.{
    fixtureSeed(fixture_probe),
    fixtureSeed(fixture_announce),
    fixtureSeed(fixture_ka6),
    fixtureSeed(fixture_ka20),
    fixtureSeed(fixture_resolve),
    fixtureSeed(fixture_goodbye),
    fixtureSeed(fixture_ka5),
    framed(hdr_query_1q),
    framed(malformed_count),
    framed(malformed_self_pointer),
    framed(malformed_forward),
    framed(malformed_loop),
    framed(malformed_header_pointer),
    framed(malformed_rdlength),
    framed(malformed_label),
    framed(malformed_ext_label),
    framed(malformed_short),
};

test "fuzz Message.parse never panics" {
    try std.testing.fuzz({}, fuzzMessageParse, .{
        .corpus = message_corpus,
    });
}

/// Largest input for the parse target: one Ethernet-sized datagram plus
/// room to exceed it. The 9000-octet cap has its own unit test.
const parse_buf_len = 2048;

fn fuzzMessageParse(_: void, smith: *Smith) anyerror!void {
    var buf: [parse_buf_len]u8 = undefined;
    const len = smith.slice(&buf);
    const bytes = buf[0..len];

    const m = Message.parse(bytes) catch |err| switch (err) {
        error.Malformed => return,
    };
    try std.testing.expect(m.end <= bytes.len);
    try std.testing.expect(m.end >= wire.Header.len);

    var nq: usize = 0;
    var qs = m.questions();
    while (qs.next()) |q| {
        try checkName(&q.name);
        try std.testing.expectEqual(@as(u16, 0), q.qclass & wire.qu_bit);
        nq += 1;
    }
    try std.testing.expectEqual(@as(usize, m.header.qdcount), nq);

    var nr: usize = 0;
    var last_section: Section = .answer;
    var recs = m.allRecords();
    while (recs.next()) |rec| {
        try std.testing.expect(@backingInt(rec.section) >= @backingInt(last_section));
        last_section = rec.section;
        try checkRecord(bytes, rec);
        nr += 1;
    }
    const total: usize = @as(usize, m.header.ancount) + m.header.nscount + m.header.arcount;
    try std.testing.expectEqual(total, nr);

    // Per-section iterators cover the same records.
    var per_section: usize = 0;
    for ([_]Section{ .answer, .authority, .additional }) |s| {
        var it = m.records(s);
        while (it.next()) |rec| {
            try std.testing.expectEqual(s, rec.section);
            per_section += 1;
        }
    }
    try std.testing.expectEqual(nr, per_section);
}

// ---------------------------------------------------------------------------
// Name.decode
// ---------------------------------------------------------------------------

const name_corpus: []const []const u8 = &.{
    // A compressed name inside a real packet, decoded at its offset.
    framedWithInt(hexToBytes(std.mem.trimEnd(u8, fixture_announce, "\r\n")), 12),
    framedWithInt(hexToBytes(std.mem.trimEnd(u8, fixture_announce, "\r\n")), 50),
    framedWithInt(malformed_self_pointer, 12),
    framedWithInt(malformed_forward, 12),
    framedWithInt(malformed_loop, 12),
    framedWithInt(malformed_header_pointer, 12),
    framedWithInt(malformed_label, 12),
    framedWithInt(hdr_query_1q ++ [_]u8{ 5, 'l', 'o', 'c', 'a', 'l', 0 }, 12),
    // Offset past the end.
    framedWithInt(hdr_query_1q, 12),
};

test "fuzz Name.decode never panics" {
    try std.testing.fuzz({}, fuzzNameDecode, .{
        .corpus = name_corpus,
    });
}

/// Enough room for a 255-octet name plus pointer chains and padding.
const name_buf_len = 640;

fn fuzzNameDecode(_: void, smith: *Smith) anyerror!void {
    var buf: [name_buf_len]u8 = undefined;
    const len = smith.slice(&buf);
    const bytes = buf[0..len];
    // Any offset, including past the end of the buffer.
    const offset = smith.valueRangeAtMost(u16, 0, name_buf_len);

    const d = Name.decode(bytes, offset) catch |err| switch (err) {
        error.Malformed => return,
    };
    try std.testing.expect(offset < len);
    try std.testing.expect(d.end > offset and d.end <= len);
    try checkName(&d.name);

    // Decoding is deterministic and the decoded name re-decodes from its
    // own uncompressed wire form.
    const again = try Name.decode(bytes, offset);
    try std.testing.expectEqual(d.end, again.end);
    try std.testing.expectEqualSlices(u8, d.name.slice(), again.name.slice());
    const plain = try Name.decode(d.name.slice(), 0);
    try std.testing.expectEqual(d.name.len, plain.end);
    try std.testing.expect(d.name.eql(&plain.name));
}

// ---------------------------------------------------------------------------
// Txt.iterate
// ---------------------------------------------------------------------------

const txt_corpus: []const []const u8 = &.{
    framed([_]u8{0}),
    framed([_]u8{ 3, 'k', '=', 'v' }),
    framed([_]u8{ 3, 'k', '=', 'v', 1, 'x', 2, '=', 'y', 0, 4, 'K', '=', 'V', '2' }),
    framed([_]u8{ 9, 'k', '=', 'v' }), // length past the end
    framed(rep(401, 0)), // over 400 B
    framed([_]u8{255} ++ rep(255, 'a')),
};

test "fuzz Txt.iterate never panics" {
    try std.testing.fuzz({}, fuzzTxtIterate, .{
        .corpus = txt_corpus,
    });
}

const txt_buf_len = 520;

fn fuzzTxtIterate(_: void, smith: *Smith) anyerror!void {
    var buf: [txt_buf_len]u8 = undefined;
    const len = smith.slice(&buf);
    const bytes = buf[0..len];

    // The zero-copy view never fails; a bad length ends the walk.
    const view: txt.View = .{ .bytes = bytes };
    try checkTxtView(view);

    const valid = if (view.validate()) true else |_| false;

    // The owned copy accepts exactly the structurally valid inputs that fit.
    if (wire.Txt.fromWire(bytes)) |owned| {
        try std.testing.expect(valid);
        try std.testing.expect(len <= txt.max_len);
        try std.testing.expectEqualSlices(u8, bytes, owned.slice());
        try std.testing.expectEqual(view.count(), owned.count());
    } else |err| switch (err) {
        error.Malformed => try std.testing.expect(!valid),
        error.TxtTooLarge => {
            try std.testing.expect(valid);
            try std.testing.expect(len > txt.max_len);
        },
    }

    // Truncation keeps a valid prefix of whole strings within 400 B.
    if (wire.Txt.fromWireTruncated(bytes)) |t| {
        try std.testing.expect(valid);
        try std.testing.expect(t.txt.slice().len <= txt.max_len);
        try std.testing.expect(t.txt.slice().len <= len);
        try std.testing.expectEqualSlices(u8, bytes[0..t.txt.slice().len], t.txt.slice());
        try std.testing.expectEqual(t.txt.slice().len != len, t.truncated);
        try t.txt.view().validate();
        try std.testing.expect(t.txt.count() <= view.count());
    } else |_| {
        try std.testing.expect(!valid);
    }
}

// ---------------------------------------------------------------------------
// Builder round trip
// ---------------------------------------------------------------------------

const builder_corpus: []const []const u8 = &.{
    "",
    &rep(64, 0),
    &rep(200, 1),
    &rep(400, 0xFF),
};

test "fuzz Builder round trip" {
    try std.testing.fuzz({}, fuzzBuilderRoundTrip, .{
        .corpus = builder_corpus,
    });
}

const max_questions = 3;
const max_records = 8;
const raw_len = 64;
const build_buf_len = 2000;

/// Labels that recur across generated names so the compression table gets
/// real suffix matches.
const label_pool = [_][]const u8{ "local", "_udp", "_tcp", "_mdnszig", "m0demo", "host", "_services", "_dns-sd" };

const RecordSpec = struct {
    section: Section,
    name: Name,
    rtype: RType,
    class: u16,
    cache_flush: bool,
    ttl: u32,
    kind: Kind,
    // Backing storage for the name-bearing and byte-bearing rdata kinds.
    target: Name = .root,
    srv: wire.Srv = .{ .port = 0, .target = .root },
    nsec: wire.Nsec = .{ .next = .root },
    raw: [raw_len]u8 = @splat(0),
    raw_len: usize = 0,
    split: usize = 0,
    a: [4]u8 = @splat(0),
    aaaa: [16]u8 = @splat(0),

    const Kind = enum(u8) { raw, a, aaaa, ptr, srv, txt, nsec, hinfo };

    fn rdataUnion(s: *const RecordSpec) wire.Rdata {
        return switch (s.kind) {
            .raw => .{ .raw = s.raw[0..s.raw_len] },
            .a => .{ .a = s.a },
            .aaaa => .{ .aaaa = s.aaaa },
            .ptr => .{ .ptr = s.target },
            .srv => .{ .srv = s.srv },
            .txt => .{ .txt = s.raw[0..s.raw_len] },
            .nsec => .{ .nsec = s.nsec },
            .hinfo => .{ .hinfo = .{ .cpu = s.raw[0..s.split], .os = s.raw[s.split..s.raw_len] } },
        };
    }

    /// The uncompressed rdata the Builder must have written, as
    /// `canonicalRdata` will report it after parsing.
    fn expectedCanonical(s: *const RecordSpec, out: []u8) ![]const u8 {
        return switch (s.kind) {
            .raw => blk: {
                @memcpy(out[0..s.raw_len], s.raw[0..s.raw_len]);
                break :blk out[0..s.raw_len];
            },
            // RFC 6763 section 6.1: an empty TXT goes out as one zero octet.
            .txt => blk: {
                if (s.raw_len == 0) {
                    out[0] = 0;
                    break :blk out[0..1];
                }
                @memcpy(out[0..s.raw_len], s.raw[0..s.raw_len]);
                break :blk out[0..s.raw_len];
            },
            .a => out[0..try rdata.encodeA(s.a, out)],
            .aaaa => out[0..try rdata.encodeAaaa(s.aaaa, out)],
            .ptr => out[0..try rdata.encodePtr(s.target, out)],
            .srv => out[0..try rdata.encodeSrv(s.srv, out)],
            .nsec => out[0..try rdata.encodeNsec(s.nsec, out)],
            .hinfo => out[0..try rdata.encodeHinfo(.{ .cpu = s.raw[0..s.split], .os = s.raw[s.split..s.raw_len] }, out)],
        };
    }
};

fn randomName(smith: *Smith) Name {
    var n: Name = .root;
    const nlabels = smith.valueRangeAtMost(u8, 0, 5);
    var i: u8 = 0;
    while (i < nlabels) : (i += 1) {
        if (smith.boolWeighted(1, 3)) {
            n.appendLabel(label_pool[smith.index(label_pool.len)]) catch break;
        } else {
            var lb: [wire.name.max_label_len]u8 = undefined;
            const l = smith.slice(&lb);
            if (l == 0) continue;
            n.appendLabel(lb[0..l]) catch break;
        }
    }
    return n;
}

fn randomRType(smith: *Smith, kind: RecordSpec.Kind) RType {
    return switch (kind) {
        .a => .a,
        .aaaa => .aaaa,
        .ptr => if (smith.boolWeighted(3, 1)) .ptr else .cname,
        .srv => .srv,
        .txt => .txt,
        .nsec => .nsec,
        .hinfo => .hinfo,
        // Types the Builder does not interpret, including OPT and unknown.
        .raw => RType.fromInt(smith.value(u16)),
    };
}

fn randomRecord(smith: *Smith) RecordSpec {
    const kind = smith.value(RecordSpec.Kind);
    var s: RecordSpec = .{
        .section = smith.value(Section),
        .name = randomName(smith),
        .rtype = randomRType(smith, kind),
        .class = smith.value(u16),
        .cache_flush = smith.value(bool),
        .ttl = smith.value(u32),
        .kind = kind,
    };
    switch (kind) {
        .raw, .txt, .hinfo => {
            s.raw_len = smith.slice(&s.raw);
            s.split = smith.valueRangeAtMost(u8, 0, @intCast(s.raw_len));
        },
        .a => s.a = smith.value([4]u8),
        .aaaa => s.aaaa = smith.value([16]u8),
        .ptr => s.target = randomName(smith),
        .srv => s.srv = .{
            .priority = smith.value(u16),
            .weight = smith.value(u16),
            .port = smith.value(u16),
            .target = randomName(smith),
        },
        .nsec => {
            s.nsec = .{ .next = randomName(smith) };
            const ntypes = smith.valueRangeAtMost(u8, 0, 4);
            var i: u8 = 0;
            // Types over 255 and type 47 are refused by `set` (RFC 6762
            // section 6.1) and leave the bitmap unchanged.
            while (i < ntypes) : (i += 1) s.nsec.set(RType.fromInt(smith.value(u16))) catch {};
        },
    }
    // The raw kind with a name-bearing type would be re-read through a
    // name decoder; keep raw bytes on types the codec copies verbatim.
    if (kind == .raw) switch (s.rtype) {
        .ptr, .ns, .cname, .srv, .nsec => s.rtype = .opt,
        else => {},
    };
    return s;
}

const QuestionSpec = struct { name: Name, qtype: RType, qclass: u16, qu: bool };

fn fuzzBuilderRoundTrip(_: void, smith: *Smith) anyerror!void {
    var buf: [build_buf_len]u8 = undefined;
    const family: wire.Family = smith.value(wire.Family);
    const legacy = smith.value(bool);
    var b = wire.Builder.init(&buf, .{ .family = family, .legacy = legacy });
    const id = smith.value(u16);
    const flags = wire.Header.Flags.fromInt(smith.value(u16));
    b.setId(id);
    b.setFlags(flags);

    // Questions first (any later question must be refused).
    var questions: [max_questions]QuestionSpec = undefined;
    var nq: usize = 0;
    const want_q = smith.valueRangeAtMost(u8, 0, max_questions);
    while (nq < want_q) {
        const q: QuestionSpec = .{
            .name = randomName(smith),
            .qtype = RType.fromInt(smith.value(u16)),
            .qclass = smith.value(u16),
            .qu = smith.value(bool),
        };
        const before = b.payloadLen();
        b.addQuestion(q.name, q.qtype, q.qclass, q.qu) catch |err| switch (err) {
            error.NoSpace => {
                try std.testing.expectEqual(before, b.payloadLen());
                break;
            },
            else => return err,
        };
        questions[nq] = q;
        nq += 1;
    }

    var records: [max_records]RecordSpec = undefined;
    var nr: usize = 0;
    var last_section: ?Section = null;
    const want_r = smith.valueRangeAtMost(u8, 0, max_records);
    // Bound the attempts: a rejected spec (`SectionOrder`, `InvalidTxt`)
    // does not advance `nr`, and once the fuzz input is exhausted the
    // Smith repeats the same values, so an unbounded loop never ends.
    var attempts: usize = 0;
    while (nr < want_r and attempts < max_records * 4) : (attempts += 1) {
        const spec = randomRecord(smith);
        const before = b.payloadLen();
        b.addRR(spec.section, spec.name, spec.rtype, spec.class, spec.cache_flush, spec.ttl, spec.rdataUnion()) catch |err| switch (err) {
            error.NoSpace => {
                try std.testing.expectEqual(before, b.payloadLen());
                break;
            },
            error.SectionOrder => {
                try std.testing.expectEqual(before, b.payloadLen());
                const last = last_section orelse return error.TestUnexpectedResult;
                try std.testing.expect(@backingInt(spec.section) < @backingInt(last));
                continue;
            },
            error.InvalidTxt => {
                // Random `.txt` bytes need not be a valid string sequence;
                // the Builder refuses them and stays unchanged.
                try std.testing.expectEqual(before, b.payloadLen());
                try std.testing.expectEqual(RecordSpec.Kind.txt, spec.kind);
                try std.testing.expectError(error.Malformed, (wire.TxtView{ .bytes = spec.raw[0..spec.raw_len] }).validate());
                continue;
            },
            error.StringTooLong => return err, // raw_len <= 64, impossible
        };
        records[nr] = spec;
        nr += 1;
        last_section = spec.section;
    }
    // A question after any record is a section-order error.
    if (nr > 0) {
        try std.testing.expectError(error.SectionOrder, b.addQuestion(Name.root, .ptr, wire.class_in, false));
    }

    // Size rules (RFC 6762 §17): never over the hard cap; with two or more
    // records never over the soft target (only a lone first record may
    // exceed it).
    const packet = b.finish();
    try std.testing.expect(packet.len <= wire.builder.hardLimit(family));
    try std.testing.expect(packet.len <= build_buf_len);
    if (nr >= 2) try std.testing.expect(packet.len <= wire.builder.softLimit(family));
    try std.testing.expectEqual(nr, b.recordCount());
    try std.testing.expectEqual(nq, b.questionCount());

    // Parse back and compare structurally.
    const m = try Message.parse(packet);
    try std.testing.expectEqual(packet.len, m.end);
    try std.testing.expectEqual(id, m.header.id);
    try std.testing.expectEqual(flags.toInt(), m.header.flags.toInt());
    try std.testing.expectEqual(@as(usize, m.header.qdcount), nq);
    const total: usize = @as(usize, m.header.ancount) + m.header.nscount + m.header.arcount;
    try std.testing.expectEqual(nr, total);

    var qi: usize = 0;
    var qs = m.questions();
    while (qs.next()) |q| : (qi += 1) {
        const want = questions[qi];
        try std.testing.expect(want.name.eql(&q.name));
        try std.testing.expectEqual(want.qtype, q.qtype);
        try std.testing.expectEqual(want.qclass & ~wire.qu_bit, q.qclass);
        try std.testing.expectEqual(want.qu, q.qu);
    }
    try std.testing.expectEqual(nq, qi);

    var ri: usize = 0;
    var recs = m.allRecords();
    var canon_want: [wire.max_message_len]u8 = undefined;
    var canon_got: [wire.max_message_len]u8 = undefined;
    while (recs.next()) |rec| : (ri += 1) {
        const want = &records[ri];
        try std.testing.expect(want.name.eql(&rec.name));
        try std.testing.expectEqual(want.rtype, rec.rtype);
        try std.testing.expectEqual(want.section, rec.section);
        // Legacy (RFC 6762 §6.7): TTL capped at 10 s, cache-flush cleared.
        const want_flush = want.cache_flush and !legacy;
        const want_ttl = if (legacy) @min(want.ttl, wire.builder.legacy_ttl_cap_s) else want.ttl;
        try std.testing.expectEqual(want_flush, rec.cache_flush);
        try std.testing.expectEqual(want.class & ~wire.cache_flush_bit, rec.class);
        try std.testing.expectEqual(want_ttl, rec.ttl);

        // Byte-exact on purpose: the Builder only compresses against a
        // prior occurrence with identical bytes (case included), so the
        // decompressed rdata is exactly the spec's uncompressed encoding.
        const expected = try want.expectedCanonical(&canon_want);
        const got = try rdata.canonicalRdata(packet, rec, &canon_got);
        try std.testing.expectEqualSlices(u8, expected, got);

        // RFC 6762 §18.14: a legacy response never compresses the SRV
        // target, so the target is a complete uncompressed name in rdata.
        if (legacy and want.kind == .srv) {
            const target = try Name.fromWire(rec.rdata[wire.Srv.fixed_len..]);
            try std.testing.expect(target.eql(&want.srv.target));
        }
    }
    try std.testing.expectEqual(nr, ri);

    // `reset` starts a fresh packet in the same buffer and keeps the id.
    b.reset();
    try std.testing.expect(b.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), b.recordCount());
    const empty = b.finish();
    try std.testing.expectEqual(@as(usize, wire.Header.len), empty.len);
    const em = try Message.parse(empty);
    try std.testing.expectEqual(id, em.header.id);
}

// ---------------------------------------------------------------------------
// corpus framing guard
// ---------------------------------------------------------------------------

// The fixture seeds must replay as well-formed packets, or the fuzzer
// starts from inputs that die at the header and the seeds are worthless.
// ---------------------------------------------------------------------------
// Engine.handle
// ---------------------------------------------------------------------------

// Engine target (plan section 8 tier 3, M3): random datagrams with a
// random `RxMeta` and monotonic clock steps into a browsing Engine.
// Invariants: no panic, no leak (`std.testing.allocator`), the cache
// never exceeds its cap, `nextDeadline` after a tick is never in the
// past, `handle` never allocates (the FailingAllocator sweep in
// `tests/querier_test.zig` proves that part).
test "fuzz Engine.handle never panics" {
    try std.testing.fuzz({}, fuzzEngineHandle, .{
        .corpus = message_corpus,
    });
}

fn fuzzEngineHandle(_: void, smith: *Smith) anyerror!void {
    var prng = std.Random.DefaultPrng.init(smith.valueRangeAtMost(u64, 0, std.math.maxInt(u64)));
    var e = try mdns.Engine.init(std.testing.allocator, .{
        .host_label = "fuzz",
        .random = prng.random(),
        .limits = .{ .max_cache_records = 16, .max_events = 8, .max_interfaces = 2, .max_browses = 2 },
    });
    defer e.deinit();
    var iface: mdns.Interface = .{ .index = 3 };
    try iface.v4.append(.{ .addr = .{ 10, 0, 3, 1 }, .prefix_len = 24 });
    var ll: [16]u8 = @splat(0);
    ll[0] = 0xfe;
    ll[1] = 0x80;
    ll[15] = 1;
    try iface.v6.append(.{ .addr = ll, .prefix_len = 64 });
    try e.setInterfaces(&.{iface}, 0);
    _ = try e.browse("_qmsg._udp", 0);

    var now: u64 = 0;
    var buf: [parse_buf_len]u8 = undefined;
    var out: [wire.max_message_len]u8 = undefined;
    var rounds: usize = 0;
    while (rounds < 8) : (rounds += 1) {
        const len = smith.slice(&buf);
        const meta: mdns.Engine.RxMeta = .{
            .from = switch (smith.valueRangeAtMost(u8, 0, 3)) {
                0 => .{ .ip4 = .{ .bytes = .{ 10, 0, 3, smith.valueRangeAtMost(u8, 0, 255) }, .port = 5353 } },
                1 => .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 1 }, .port = 5353 } }, // our own address
                2 => .{ .ip4 = .{ .bytes = .{ 172, 16, 0, 9 }, .port = smith.valueRangeAtMost(u16, 1, 65535) } },
                else => .{ .ip6 = .{ .bytes = ll, .port = 5353, .interface = .{ .index = 3 } } },
            },
            .ifindex = smith.valueRangeAtMost(u32, 0, 4),
            .dst_multicast = smith.valueRangeAtMost(u8, 0, 1) == 1,
        };
        e.handle(buf[0..len], meta, now);
        try std.testing.expect(e.cacheCount() <= 16);
        now += smith.valueRangeAtMost(u64, 0, 200 * std.time.us_per_s);
        e.tick(now);
        if (e.nextDeadline(now)) |d| try std.testing.expect(d >= now);
        while (e.pollDatagram(&out, now)) |d| {
            try std.testing.expect(d.len <= out.len);
            const msg = try Message.parse(out[0..d.len]);
            try std.testing.expect(!msg.isResponse());
            // Our own query comes back as an echo and is dropped.
            const before = e.stats().rx_echo;
            e.handle(out[0..d.len], .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 1 }, .port = 5353 } }, .ifindex = 3, .dst_multicast = true }, now);
            try std.testing.expectEqual(before + 1, e.stats().rx_echo);
        }
        while (e.pollEvent()) |_| {}
    }
    try std.testing.expectEqual(@as(u64, 0), e.stats().tx_dropped);
}

test "fuzz corpus seeds replay through Smith as intended" {
    const fixture_seed_count = 7;
    for (message_corpus[0..fixture_seed_count]) |seed| {
        var smith: Smith = .{ .in = seed };
        var buf: [parse_buf_len]u8 = undefined;
        const len = smith.slice(&buf);
        try std.testing.expectEqual(seed.len - 4, @as(usize, len));
        const m = try Message.parse(buf[0..len]);
        try std.testing.expectEqual(@as(usize, len), m.end);
    }
    for (message_corpus[fixture_seed_count..]) |seed| {
        var smith: Smith = .{ .in = seed };
        var buf: [parse_buf_len]u8 = undefined;
        const len = smith.slice(&buf);
        if (Message.parse(buf[0..len])) |m| {
            // Only the bare one-question header template is well formed.
            try std.testing.expectEqual(@as(u16, 0), m.header.qdcount);
        } else |_| {}
    }
    // The first two name seeds decode a compressed owner inside a real
    // announce; the rest are the malformed cases and must be rejected.
    for (name_corpus, 0..) |seed, i| {
        var smith: Smith = .{ .in = seed };
        var buf: [name_buf_len]u8 = undefined;
        const len = smith.slice(&buf);
        const offset = smith.valueRangeAtMost(u16, 0, name_buf_len);
        const result = Name.decode(buf[0..len], offset);
        if (i < 2 or i == name_corpus.len - 2) {
            const d = try result;
            try std.testing.expect(!d.name.isRoot());
        } else {
            try std.testing.expectError(error.Malformed, result);
        }
    }
}
