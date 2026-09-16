//! Fixture decode tests for the wire codec (plan §7 M1 "Every fixture
//! decodes", §8 tier 2). Every test walks the whole corpus under
//! `tests/fixtures/raw` through `loader.Iterator` and checks the public
//! `mdns.wire` API against what `tests/fixtures/README.md` says the capture
//! contains: mDNSResponder traffic for the `m0demo._mdnszig._udp.local`
//! registration (probes, announcements, resolve answers, goodbyes) and
//! `_services._dns-sd._udp.local` enumeration.
//!
//! Nothing here allocates on the codec side; the loader allocates for the
//! directory listing and the JSON sidecar with `std.testing.allocator`.
const std = @import("std");
const mdns = @import("mdns");
const wire = mdns.wire;
const loader = @import("fixtures/loader.zig");

const Name = wire.Name;
const Message = wire.Message;
const Record = wire.Record;
const rdata = wire.rdata;

/// Per-type record counts over the corpus.
const Counts = struct {
    a: usize = 0,
    aaaa: usize = 0,
    ptr: usize = 0,
    srv: usize = 0,
    txt: usize = 0,
    nsec: usize = 0,
    opt: usize = 0,
    other: usize = 0,
    questions: usize = 0,
    messages: usize = 0,
};

/// Decode `rec`'s rdata with the decoder for its type. Fails the test on
/// `error.Malformed`: every fixture is a well-formed capture (README,
/// "What is in it").
fn decodeByType(msg: []const u8, rec: Record, counts: *Counts) !void {
    switch (rec.rtype) {
        .a => {
            _ = try rdata.decodeA(rec.rdata);
            counts.a += 1;
        },
        .aaaa => {
            _ = try rdata.decodeAaaa(rec.rdata);
            counts.aaaa += 1;
        },
        .ptr => {
            const target = try rdata.decodePtr(msg, rec);
            try std.testing.expect(!target.isRoot());
            counts.ptr += 1;
        },
        .srv => {
            const srv = try rdata.decodeSrv(msg, rec);
            try std.testing.expect(!srv.target.isRoot());
            counts.srv += 1;
        },
        .txt => {
            const view = try rdata.decodeTxt(rec);
            _ = view.count();
            counts.txt += 1;
        },
        .nsec => {
            const nsec = try rdata.decodeNsec(msg, rec);
            // mDNSResponder emits the restricted form (RFC 6762 §6.1): the
            // next-domain name is the owner and at least one type is set.
            try std.testing.expect(nsec.next.eql(&rec.name));
            try std.testing.expect(nsec.bitmapLen() > 0);
            counts.nsec += 1;
        },
        .opt => counts.opt += 1,
        else => counts.other += 1,
    }
    // The §8.2 canonical form must exist for every record we can decode.
    var scratch: [wire.max_message_len]u8 = undefined;
    _ = try rdata.canonicalRdata(msg, rec, &scratch);
}

test "every fixture parses" {
    const io = std.testing.io;
    var it = try loader.Iterator.init(std.testing.allocator, io);
    defer it.deinit(io);

    var counts: Counts = .{};
    var buf: [loader.max_datagram]u8 = undefined;
    while (try it.next(io, &buf)) |fx| {
        const m = Message.parse(fx.bytes) catch |err| {
            std.debug.print("fixture {s}: Message.parse failed: {t}\n", .{ fx.stem(), err });
            return err;
        };
        counts.messages += 1;
        // The README measured every capture to walk exactly to the payload
        // end: no trailing bytes.
        try std.testing.expectEqual(fx.bytes.len, m.end);
        // RFC 6762 §18: opcode 0, rcode 0 on everything mDNSResponder sends.
        try std.testing.expectEqual(@as(u4, 0), m.header.flags.opcode);
        try std.testing.expectEqual(@as(u4, 0), m.header.flags.rcode);
        try std.testing.expect(!m.header.flags.tc);

        var nq: usize = 0;
        var qs = m.questions();
        while (qs.next()) |q| {
            nq += 1;
            try std.testing.expect(!q.name.isRoot());
            try std.testing.expectEqual(wire.class_in, q.qclass);
        }
        try std.testing.expectEqual(@as(usize, m.header.qdcount), nq);
        counts.questions += nq;

        var nr: usize = 0;
        var recs = m.allRecords();
        while (recs.next()) |rec| {
            nr += 1;
            try std.testing.expect(!rec.name.isRoot());
            if (rec.rtype != .opt) try std.testing.expectEqual(wire.class_in, rec.class);
            decodeByType(fx.bytes, rec, &counts) catch |err| {
                std.debug.print("fixture {s}: rdata decode failed for type {d} ({t})\n", .{ fx.stem(), rec.rtype.toInt(), err });
                return err;
            };
        }
        const expected_rr: usize = @as(usize, m.header.ancount) + m.header.nscount + m.header.arcount;
        try std.testing.expectEqual(expected_rr, nr);

        // The per-section iterators agree with the combined walk.
        var per_section: usize = 0;
        for ([_]wire.Section{ .answer, .authority, .additional }) |s| {
            var sit = m.records(s);
            while (sit.next()) |rec| {
                try std.testing.expectEqual(s, rec.section);
                per_section += 1;
            }
        }
        try std.testing.expectEqual(nr, per_section);
    }

    try std.testing.expectEqual(it.count(), counts.messages);
    try std.testing.expect(counts.messages >= 100);
    try std.testing.expect(counts.questions > 0);
    try std.testing.expect(counts.ptr > 0);
    try std.testing.expect(counts.srv > 0);
    try std.testing.expect(counts.txt > 0);
    try std.testing.expect(counts.a > 0);
    try std.testing.expect(counts.aaaa > 0);
    try std.testing.expect(counts.nsec > 0);
    // Only the types the README lists appear (PTR, NSEC, TXT, AAAA, SRV,
    // A, OPT).
    try std.testing.expectEqual(@as(usize, 0), counts.other);
}

/// Rebuild `m` through the Builder with the same header, questions and
/// records, returning the new packet in `out`.
fn rebuild(m: *const Message, family: loader.Family, out: []u8) ![]const u8 {
    var b = wire.Builder.init(out, .{
        .family = switch (family) {
            .v4 => .v4,
            .v6 => .v6,
        },
        // A capture is one datagram; never split it across packets here.
        .soft_limit = loader.max_datagram,
        .hard_limit = loader.max_datagram,
    });
    b.setId(m.header.id);
    b.setFlags(m.header.flags);

    var qs = m.questions();
    while (qs.next()) |q| try b.addQuestion(q.name, q.qtype, q.qclass, q.qu);

    var recs = m.allRecords();
    while (recs.next()) |rec| {
        const rd: wire.Rdata = switch (rec.rtype) {
            .a => .{ .a = try rdata.decodeA(rec.rdata) },
            .aaaa => .{ .aaaa = try rdata.decodeAaaa(rec.rdata) },
            .ptr => .{ .ptr = try rdata.decodePtr(m.bytes, rec) },
            .srv => .{ .srv = try rdata.decodeSrv(m.bytes, rec) },
            .txt => .{ .txt = rec.rdata },
            .nsec => .{ .nsec = try rdata.decodeNsec(m.bytes, rec) },
            else => .{ .raw = rec.rdata },
        };
        try b.addRR(rec.section, rec.name, rec.rtype, rec.class, rec.cache_flush, rec.ttl, rd);
    }
    return b.finish();
}

test "fixture re-encode is decode-equal" {
    const io = std.testing.io;
    var it = try loader.Iterator.init(std.testing.allocator, io);
    defer it.deinit(io);

    var buf: [loader.max_datagram]u8 = undefined;
    var out: [loader.max_datagram]u8 = undefined;
    var byte_equal: usize = 0;
    var total: usize = 0;
    while (try it.next(io, &buf)) |fx| {
        total += 1;
        const orig = try Message.parse(fx.bytes);
        const rebuilt_bytes = rebuild(&orig, fx.family, &out) catch |err| {
            std.debug.print("fixture {s}: rebuild failed: {t}\n", .{ fx.stem(), err });
            return err;
        };
        const rebuilt = Message.parse(rebuilt_bytes) catch |err| {
            std.debug.print("fixture {s}: rebuilt packet does not parse: {t}\n", .{ fx.stem(), err });
            return err;
        };
        if (std.mem.eql(u8, fx.bytes, rebuilt_bytes)) byte_equal += 1;

        // Header.
        try std.testing.expectEqual(orig.header.id, rebuilt.header.id);
        try std.testing.expectEqual(orig.header.flags.toInt(), rebuilt.header.flags.toInt());
        try std.testing.expectEqual(orig.header.qdcount, rebuilt.header.qdcount);
        try std.testing.expectEqual(orig.header.ancount, rebuilt.header.ancount);
        try std.testing.expectEqual(orig.header.nscount, rebuilt.header.nscount);
        try std.testing.expectEqual(orig.header.arcount, rebuilt.header.arcount);
        try std.testing.expectEqual(rebuilt_bytes.len, rebuilt.end);

        // Questions, pairwise.
        var qa = orig.questions();
        var qb = rebuilt.questions();
        while (qa.next()) |a| {
            const b = qb.next() orelse return error.TestUnexpectedResult;
            try std.testing.expect(a.name.eql(&b.name));
            try std.testing.expectEqual(a.qtype, b.qtype);
            try std.testing.expectEqual(a.qclass, b.qclass);
            try std.testing.expectEqual(a.qu, b.qu);
        }
        try std.testing.expectEqual(@as(?wire.Question, null), qb.next());

        // Records, pairwise: same owner (case-insensitive), type, raw
        // class (cache-flush bit included), TTL, section, and rdata equal
        // after decompression (RFC 6762 §8.2 comparison).
        var ra = orig.allRecords();
        var rb = rebuilt.allRecords();
        while (ra.next()) |a| {
            const b = rb.next() orelse return error.TestUnexpectedResult;
            try std.testing.expect(a.name.eql(&b.name));
            try std.testing.expectEqual(a.rtype, b.rtype);
            try std.testing.expectEqual(a.class_raw, b.class_raw);
            try std.testing.expectEqual(a.ttl, b.ttl);
            try std.testing.expectEqual(a.section, b.section);
            const order = rdata.compareRecords(orig.bytes, a, rebuilt.bytes, b) catch |err| {
                std.debug.print("fixture {s}: compareRecords failed on type {d}: {t}\n", .{ fx.stem(), a.rtype.toInt(), err });
                return err;
            };
            try std.testing.expectEqual(std.math.Order.eq, order);
        }
        try std.testing.expect(rb.next() == null);
    }
    try std.testing.expectEqual(it.count(), total);
    // Byte equality is not required by the plan (compression choices may
    // differ), but mDNSResponder's compression matches the Builder's
    // longest-suffix rule on every fixture in this corpus, and the
    // CHANGELOG advertises that. Guard it so a change in the Builder's
    // compression choice is noticed rather than silently degrading.
    if (byte_equal != total) {
        std.debug.print("codec_test: {d}/{d} fixtures re-encoded byte-identical (decode-equal on all)\n", .{ byte_equal, total });
    }
    try std.testing.expectEqual(total, byte_equal);
}

/// True when `n` is `m0demo._mdnszig._udp.local` or a name under
/// `_mdnszig._udp.local`.
fn isMdnszig(n: *const Name) bool {
    const suffix = Name.parse("_mdnszig._udp.local") catch return false;
    return n.endsWith(&suffix);
}

test "fixture goodbye records have TTL 0" {
    const io = std.testing.io;
    var it = try loader.Iterator.init(std.testing.allocator, io);
    defer it.deinit(io);

    var buf: [loader.max_datagram]u8 = undefined;
    var goodbyes: usize = 0;
    var goodbye_messages: usize = 0;
    const services = try Name.parse("_services._dns-sd._udp.local");
    while (try it.next(io, &buf)) |fx| {
        const m = try Message.parse(fx.bytes);
        var seen_here = false;
        var recs = m.allRecords();
        while (recs.next()) |rec| {
            if (rec.ttl != 0) continue;
            // RFC 6762 §10.1: a goodbye is a response carrying TTL 0 in
            // the answer section for a record the sender is withdrawing.
            try std.testing.expect(m.isResponse());
            try std.testing.expectEqual(wire.Section.answer, rec.section);
            // Only the m0demo registration was withdrawn during the
            // capture: its SRV/TXT/NSEC under the instance name, the PTR
            // from the service type and the enumeration PTR from
            // _services._dns-sd._udp.local whose target is the type.
            switch (rec.rtype) {
                .ptr => {
                    const target = try rdata.decodePtr(fx.bytes, rec);
                    try std.testing.expect(isMdnszig(&target));
                    try std.testing.expect(isMdnszig(&rec.name) or rec.name.eql(&services));
                },
                else => try std.testing.expect(isMdnszig(&rec.name)),
            }
            goodbyes += 1;
            seen_here = true;
        }
        if (seen_here) goodbye_messages += 1;
    }
    try std.testing.expect(goodbyes > 0);
    try std.testing.expect(goodbye_messages > 0);
}

test "fixture probes use qtype ANY with proposed records in authority" {
    const io = std.testing.io;
    var it = try loader.Iterator.init(std.testing.allocator, io);
    defer it.deinit(io);

    var buf: [loader.max_datagram]u8 = undefined;
    var probes: usize = 0;
    var probe_messages: usize = 0;
    var qu_set: usize = 0;
    while (try it.next(io, &buf)) |fx| {
        const m = try Message.parse(fx.bytes);
        var seen_here = false;
        var qs = m.questions();
        while (qs.next()) |q| {
            if (q.qtype != .any) continue;
            // RFC 6762 §8.1: a probe is a query with qtype ANY and the
            // proposed records in the Authority section. The same section
            // says the querier SHOULD set the unicast-response (QU) bit
            // on the first probe only when the host has just started;
            // the eight probes in this corpus (0011, 0013-0019) come from
            // a long-running mDNSResponder and all have QU clear, so QU
            // is counted here, not required.
            try std.testing.expect(!m.isResponse());
            try std.testing.expectEqual(wire.class_in, q.qclass);
            try std.testing.expect(m.header.nscount > 0);
            if (q.qu) qu_set += 1;
            // The proposed records carry the probed name.
            var found_owner = false;
            var auth = m.authority();
            while (auth.next()) |rec| {
                if (rec.name.eql(&q.name)) found_owner = true;
            }
            try std.testing.expect(found_owner);
            probes += 1;
            seen_here = true;
        }
        if (seen_here) probe_messages += 1;
    }
    try std.testing.expect(probes > 0);
    try std.testing.expect(probe_messages > 0);
    try std.testing.expect(qu_set <= probes);
}

test "fixture TXT records parse as key=value" {
    const io = std.testing.io;
    var it = try loader.Iterator.init(std.testing.allocator, io);
    defer it.deinit(io);

    var buf: [loader.max_datagram]u8 = undefined;
    var txt_records: usize = 0;
    var m0demo_txt: usize = 0;
    const instance = try Name.serviceInstance("m0demo", "_mdnszig._udp", "local");
    while (try it.next(io, &buf)) |fx| {
        const m = try Message.parse(fx.bytes);
        var recs = m.allRecords();
        while (recs.next()) |rec| {
            if (rec.rtype != .txt) continue;
            txt_records += 1;
            const view = try rdata.decodeTxt(rec);
            // RFC 6763 §6.1: at least one string (an empty TXT is one
            // zero octet), each at most 255 octets.
            try std.testing.expect(rec.rdata.len >= 1);
            var pairs = view.iterate();
            while (pairs.next()) |p| {
                // RFC 6763 §6.4: a key is printable ASCII without '='.
                try wire.txt.validateKey(p.key);
                try std.testing.expect(p.key.len <= wire.txt.max_string_len);
            }
            // The owned copy agrees with the view.
            const owned = try wire.Txt.fromWire(rec.rdata);
            try std.testing.expectEqualSlices(u8, rec.rdata, owned.slice());
            try std.testing.expectEqual(view.count(), owned.count());

            if (rec.name.eql(&instance)) {
                m0demo_txt += 1;
                // `dns-sd -R m0demo _mdnszig._udp . 4433 k=v`.
                if (rec.ttl != 0) {
                    try std.testing.expectEqualStrings("v", view.get("k") orelse return error.TestUnexpectedResult);
                    try std.testing.expectEqualStrings("v", view.get("K") orelse return error.TestUnexpectedResult);
                    try std.testing.expect(view.has("k"));
                    try std.testing.expect(!view.has("v"));
                    try std.testing.expectEqual(@as(usize, 1), view.count());
                }
            }
        }
    }
    try std.testing.expect(txt_records > 0);
    try std.testing.expect(m0demo_txt > 0);
}
