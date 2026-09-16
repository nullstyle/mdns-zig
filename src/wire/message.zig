//! DNS message parsing (RFC 1035 section 4.1) with the mDNS bit rules
//! (RFC 6762 section 18): header, question iterator with the QU bit
//! (section 5.4), and RR iterators with the cache-flush bit (section 10.2).
//!
//! `Message.parse` validates the whole packet walk once. The iterators are
//! zero-copy views into the caller's datagram buffer; only names are copied
//! out (they must be, because of compression). Nothing here allocates or
//! panics on packet bytes.
const std = @import("std");
const name_mod = @import("name.zig");
pub const Name = name_mod.Name;

/// Largest datagram the codec accepts (RFC 6762 section 17: 9000 octets
/// including the IP and UDP headers, so any payload this long is already
/// over the limit; receive buffers are 9000 octets, plan section 4.5).
pub const max_message_len = 9000;

/// Resource record types used by mDNS and DNS-SD. Non-exhaustive: unknown
/// types pass through as their number.
pub const RType = enum(u16) {
    a = 1,
    ns = 2,
    cname = 5,
    ptr = 12,
    hinfo = 13,
    txt = 16,
    aaaa = 28,
    srv = 33,
    opt = 41,
    nsec = 47,
    any = 255,
    _,

    pub fn fromInt(v: u16) RType {
        return @fromBackingInt(@intCast(v));
    }

    pub fn toInt(t: RType) u16 {
        return @backingInt(t);
    }
};

/// The Internet class.
pub const class_in: u16 = 1;
/// RFC 6762 section 5.4: the top bit of a question's class asks for a
/// unicast response.
pub const qu_bit: u16 = 0x8000;
/// RFC 6762 section 10.2: the top bit of a record's class says the record
/// set is unique and caches must flush older entries.
pub const cache_flush_bit: u16 = 0x8000;

pub const Section = enum(u2) { answer = 0, authority = 1, additional = 2 };

pub const Header = struct {
    pub const len = 12;

    id: u16 = 0,
    flags: Flags = .{},
    qdcount: u16 = 0,
    ancount: u16 = 0,
    nscount: u16 = 0,
    arcount: u16 = 0,

    /// RFC 1035 section 4.1.1 flag word. Field order is least-significant
    /// bit first: RCODE occupies bits 0..3 and QR is bit 15.
    pub const Flags = packed struct(u16) {
        rcode: u4 = 0,
        z: u3 = 0,
        ra: bool = false,
        rd: bool = false,
        tc: bool = false,
        aa: bool = false,
        opcode: u4 = 0,
        qr: bool = false,

        pub fn toInt(f: Flags) u16 {
            return @bitCast(f);
        }

        pub fn fromInt(v: u16) Flags {
            return @bitCast(v);
        }

        /// A standard mDNS response: QR=1, AA=1, everything else zero
        /// (RFC 6762 section 18).
        pub const response: Flags = .{ .qr = true, .aa = true };
        pub const query: Flags = .{};
    };

    pub fn parse(bytes: []const u8) error{Malformed}!Header {
        if (bytes.len < len) return error.Malformed;
        return .{
            .id = std.mem.readInt(u16, bytes[0..2], .big),
            .flags = Flags.fromInt(std.mem.readInt(u16, bytes[2..4], .big)),
            .qdcount = std.mem.readInt(u16, bytes[4..6], .big),
            .ancount = std.mem.readInt(u16, bytes[6..8], .big),
            .nscount = std.mem.readInt(u16, bytes[8..10], .big),
            .arcount = std.mem.readInt(u16, bytes[10..12], .big),
        };
    }

    pub fn write(h: Header, out: *[len]u8) void {
        std.mem.writeInt(u16, out[0..2], h.id, .big);
        std.mem.writeInt(u16, out[2..4], h.flags.toInt(), .big);
        std.mem.writeInt(u16, out[4..6], h.qdcount, .big);
        std.mem.writeInt(u16, out[6..8], h.ancount, .big);
        std.mem.writeInt(u16, out[8..10], h.nscount, .big);
        std.mem.writeInt(u16, out[10..12], h.arcount, .big);
    }

    pub fn count(h: Header, section: Section) u16 {
        return switch (section) {
            .answer => h.ancount,
            .authority => h.nscount,
            .additional => h.arcount,
        };
    }
};

pub const Question = struct {
    name: Name,
    qtype: RType,
    /// Class with the QU bit stripped.
    qclass: u16,
    /// RFC 6762 section 5.4 unicast-response bit.
    qu: bool,
};

pub const Record = struct {
    name: Name,
    rtype: RType,
    /// Class with the cache-flush bit stripped. For OPT records the field
    /// carries the requester's UDP payload size and the top bit is not a
    /// cache-flush bit; use `class_raw` there.
    class: u16,
    /// RFC 6762 section 10.2 cache-flush bit (top bit of the class).
    cache_flush: bool,
    /// The class field exactly as it appeared on the wire.
    class_raw: u16,
    ttl: u32,
    /// View into the message. Names inside it may be compressed; the
    /// `rdata` module decoders take the message and `rdata_offset`.
    rdata: []const u8,
    /// Offset of `rdata` within the message.
    rdata_offset: usize,
    /// Which section this record came from.
    section: Section,
};

/// A parsed message. Holds a view into the caller's buffer plus the
/// section offsets found during validation.
pub const Message = struct {
    bytes: []const u8,
    header: Header,
    /// Offset of the first question.
    questions_offset: usize,
    /// Offsets of the first record of each section, indexed by `Section`.
    section_offsets: [3]usize,
    /// Offset after the last record. Bytes after it are ignored trailing
    /// data (accepted for interoperability).
    end: usize,

    /// Validate every question and record in `bytes`. Every later
    /// iterator call is guaranteed to succeed on a message this returned.
    pub fn parse(bytes: []const u8) error{Malformed}!Message {
        if (bytes.len > max_message_len) return error.Malformed;
        const header = try Header.parse(bytes);
        var pos: usize = Header.len;
        var i: usize = 0;
        while (i < header.qdcount) : (i += 1) {
            const q = try parseQuestionAt(bytes, pos);
            pos = q.end;
        }
        var section_offsets: [3]usize = undefined;
        for ([_]Section{ .answer, .authority, .additional }) |section| {
            section_offsets[@backingInt(section)] = pos;
            i = 0;
            while (i < header.count(section)) : (i += 1) {
                const r = try parseRecordAt(bytes, pos, section);
                pos = r.end;
            }
        }
        return .{
            .bytes = bytes,
            .header = header,
            .questions_offset = Header.len,
            .section_offsets = section_offsets,
            .end = pos,
        };
    }

    pub fn questions(m: *const Message) QuestionIterator {
        return .{ .bytes = m.bytes, .pos = m.questions_offset, .remaining = m.header.qdcount };
    }

    pub fn records(m: *const Message, section: Section) RecordIterator {
        return .{
            .bytes = m.bytes,
            .pos = m.section_offsets[@backingInt(section)],
            .remaining = m.header.count(section),
            .section = section,
        };
    }

    pub fn answers(m: *const Message) RecordIterator {
        return m.records(.answer);
    }

    pub fn authority(m: *const Message) RecordIterator {
        return m.records(.authority);
    }

    pub fn additional(m: *const Message) RecordIterator {
        return m.records(.additional);
    }

    /// Every record of every section in wire order.
    pub fn allRecords(m: *const Message) RecordIterator {
        const total: u32 = @as(u32, m.header.ancount) + m.header.nscount + m.header.arcount;
        return .{
            .bytes = m.bytes,
            .pos = m.section_offsets[0],
            .remaining = total,
            .section = .answer,
            .boundaries = .{ m.section_offsets[1], m.section_offsets[2] },
        };
    }

    pub fn isResponse(m: *const Message) bool {
        return m.header.flags.qr;
    }
};

const ParsedQuestion = struct { question: Question, end: usize };
const ParsedRecord = struct { record: Record, end: usize };

fn parseQuestionAt(bytes: []const u8, pos: usize) error{Malformed}!ParsedQuestion {
    const d = try Name.decode(bytes, pos);
    if (d.end + 4 > bytes.len) return error.Malformed;
    const qtype = std.mem.readInt(u16, bytes[d.end..][0..2], .big);
    const qclass_raw = std.mem.readInt(u16, bytes[d.end + 2 ..][0..2], .big);
    return .{
        .question = .{
            .name = d.name,
            .qtype = RType.fromInt(qtype),
            .qclass = qclass_raw & ~qu_bit,
            .qu = qclass_raw & qu_bit != 0,
        },
        .end = d.end + 4,
    };
}

fn parseRecordAt(bytes: []const u8, pos: usize, section: Section) error{Malformed}!ParsedRecord {
    const d = try Name.decode(bytes, pos);
    if (d.end + 10 > bytes.len) return error.Malformed;
    const fixed = bytes[d.end..][0..10];
    const rtype = std.mem.readInt(u16, fixed[0..2], .big);
    const class_raw = std.mem.readInt(u16, fixed[2..4], .big);
    const ttl = std.mem.readInt(u32, fixed[4..8], .big);
    const rdlength: usize = std.mem.readInt(u16, fixed[8..10], .big);
    const rdata_offset = d.end + 10;
    if (rdata_offset + rdlength > bytes.len) return error.Malformed;
    return .{
        .record = .{
            .name = d.name,
            .rtype = RType.fromInt(rtype),
            .class = class_raw & ~cache_flush_bit,
            .cache_flush = class_raw & cache_flush_bit != 0,
            .class_raw = class_raw,
            .ttl = ttl,
            .rdata = bytes[rdata_offset..][0..rdlength],
            .rdata_offset = rdata_offset,
            .section = section,
        },
        .end = rdata_offset + rdlength,
    };
}

pub const QuestionIterator = struct {
    bytes: []const u8,
    pos: usize,
    remaining: u16,

    /// Returns null at the end. On a message from `Message.parse` this
    /// never stops early; the `catch` only guards an iterator built by
    /// hand over unvalidated bytes.
    pub fn next(it: *QuestionIterator) ?Question {
        if (it.remaining == 0) return null;
        const q = parseQuestionAt(it.bytes, it.pos) catch {
            it.remaining = 0;
            return null;
        };
        it.remaining -= 1;
        it.pos = q.end;
        return q.question;
    }
};

pub const RecordIterator = struct {
    bytes: []const u8,
    pos: usize,
    remaining: u32,
    section: Section,
    /// For `allRecords`: offsets where authority and additional begin.
    boundaries: ?[2]usize = null,

    pub fn next(it: *RecordIterator) ?Record {
        if (it.remaining == 0) return null;
        if (it.boundaries) |b| {
            if (it.pos >= b[1]) {
                it.section = .additional;
            } else if (it.pos >= b[0]) {
                it.section = .authority;
            }
        }
        const r = parseRecordAt(it.bytes, it.pos, it.section) catch {
            it.remaining = 0;
            return null;
        };
        it.remaining -= 1;
        it.pos = r.end;
        return r.record;
    }
};

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn rep(comptime n: usize, comptime c: u8) *const [n]u8 {
    const arr: [n]u8 = @splat(c);
    return &arr;
}

test "header flag bit layout" {
    const f = Header.Flags.fromInt(0x8400);
    try testing.expect(f.qr and f.aa);
    try testing.expect(!f.tc and !f.rd and !f.ra);
    try testing.expectEqual(@as(u4, 0), f.opcode);
    try testing.expectEqual(@as(u4, 0), f.rcode);
    try testing.expectEqual(@as(u16, 0x8400), Header.Flags.response.toInt());
    const g: Header.Flags = .{ .qr = true, .opcode = 5, .tc = true, .rcode = 3 };
    try testing.expectEqual(@as(u16, 0x8000 | (5 << 11) | 0x0200 | 3), g.toInt());
    var out: [12]u8 = undefined;
    (Header{ .id = 0x1234, .flags = g, .qdcount = 1, .ancount = 2, .nscount = 3, .arcount = 4 }).write(&out);
    const back = try Header.parse(&out);
    try testing.expectEqual(@as(u16, 0x1234), back.id);
    try testing.expectEqual(g.toInt(), back.flags.toInt());
    try testing.expectEqual(@as(u16, 4), back.arcount);
    try testing.expectEqual(@as(u16, 3), back.count(.authority));
}

// A real mDNSResponder probe (fixture 0011): question
// m0demo._mdnszig._udp.local ANY, proposed SRV (ttl 4500) in the authority
// section with a compressed target (m5roscoe + ptr -> local).
const fixture_0011 = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00" ++
    "\x06m0demo\x08_mdnszig\x04_udp\x05local\x00\x00\xff\x00\x01" ++
    "\xc0\x0c\x00\x21\x00\x01\x00\x00\x11\x94\x00\x11" ++
    "\x00\x00\x00\x00\x11\x51\x08m5roscoe\xc0\x21";

test "parse a captured mDNSResponder packet" {
    const m = try Message.parse(fixture_0011);
    try testing.expectEqual(@as(u16, 1), m.header.qdcount);
    try testing.expectEqual(@as(u16, 0), m.header.ancount);
    try testing.expectEqual(@as(u16, 1), m.header.nscount);
    try testing.expect(!m.isResponse());
    var qs = m.questions();
    const q = qs.next().?;
    try name_mod.expectText("m0demo._mdnszig._udp.local", q.name);
    try testing.expectEqual(RType.any, q.qtype);
    try testing.expectEqual(class_in, q.qclass);
    try testing.expect(!q.qu);
    try testing.expect(qs.next() == null);
    var rs = m.authority();
    const r = rs.next().?;
    try testing.expect(r.name.eql(&q.name));
    try testing.expectEqual(RType.srv, r.rtype);
    try testing.expectEqual(class_in, r.class);
    try testing.expect(!r.cache_flush);
    try testing.expectEqual(@as(u32, 4500), r.ttl);
    try testing.expectEqual(@as(usize, 17), r.rdata.len);
    try testing.expectEqual(@as(usize, 56), r.rdata_offset);
    try testing.expectEqual(Section.authority, r.section);
    try testing.expect(rs.next() == null);
    var ans = m.answers();
    try testing.expect(ans.next() == null);
    var ar = m.additional();
    try testing.expect(ar.next() == null);
    try testing.expectEqual(fixture_0011.len, m.end);
}

test "QU and cache-flush bits" {
    // Question with QU set, one answer with cache-flush set.
    const msg = "\x00\x00\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00" ++
        "\x01a\x05local\x00\x00\x01\x80\x01" ++
        "\xc0\x0c\x00\x01\x80\x01\x00\x00\x00\x78\x00\x04\x0a\x00\x00\x01";
    const m = try Message.parse(msg);
    var qs = m.questions();
    const q = qs.next().?;
    try testing.expect(q.qu);
    try testing.expectEqual(class_in, q.qclass);
    var rs = m.answers();
    const r = rs.next().?;
    try testing.expect(r.cache_flush);
    try testing.expectEqual(class_in, r.class);
    try testing.expectEqual(@as(u16, 0x8001), r.class_raw);
    try testing.expectEqual(@as(u32, 120), r.ttl);
    try testing.expectEqualSlices(u8, "\x0a\x00\x00\x01", r.rdata);
    try testing.expect(m.header.flags.qr and m.header.flags.aa);
}

test "allRecords walks the sections in order" {
    const msg = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x01\x00\x01" ++
        "\x01a\x05local\x00\x00\x01\x00\x01\x00\x00\x00\x78\x00\x04\x0a\x00\x00\x01" ++
        "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x78\x00\x04\x0a\x00\x00\x02" ++
        "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x78\x00\x04\x0a\x00\x00\x03";
    const m = try Message.parse(msg);
    var it = m.allRecords();
    const r1 = it.next().?;
    const r2 = it.next().?;
    const r3 = it.next().?;
    try testing.expect(it.next() == null);
    try testing.expectEqual(Section.answer, r1.section);
    try testing.expectEqual(Section.authority, r2.section);
    try testing.expectEqual(Section.additional, r3.section);
    try testing.expectEqual(@as(u8, 3), r3.rdata[3]);
    var au = m.authority();
    try testing.expectEqual(@as(u8, 2), au.next().?.rdata[3]);
    try testing.expect(au.next() == null);
}

test "malformed corpus is rejected without panicking" {
    // Zero-length packet.
    try testing.expectError(error.Malformed, Message.parse(""));
    // Truncated header.
    try testing.expectError(error.Malformed, Message.parse(rep(11, 0)));
    // Header only, zero counts: valid.
    _ = try Message.parse(rep(12, 0));
    // Count overflow: claims 65535 questions, has none.
    try testing.expectError(error.Malformed, Message.parse("\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00"));
    try testing.expectError(error.Malformed, Message.parse("\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00"));
    // Label > 63 (0x40 is an extended label type).
    try testing.expectError(error.Malformed, Message.parse("\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\x40" ++ rep(64, 'a') ++ "\x00\x00\x01\x00\x01"));
    // Question fixed part truncated.
    try testing.expectError(error.Malformed, Message.parse("\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\x01a\x00\x00\x01\x00"));
    // rdlength past end.
    try testing.expectError(error.Malformed, Message.parse("\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x01a\x00\x00\x01\x00\x01\x00\x00\x00\x78\x00\x05\x0a\x00\x00\x01"));
    // RR fixed part truncated.
    try testing.expectError(error.Malformed, Message.parse("\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x01a\x00\x00\x01\x00\x01\x00\x00\x00\x78\x00"));
    // Pointer to self.
    try testing.expectError(error.Malformed, Message.parse("\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\xc0\x0c\x00\x01\x00\x01"));
    // Forward pointer.
    try testing.expectError(error.Malformed, Message.parse("\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\xc0\x10\x00\x01\x00\x01\x01a\x00"));
    // Pointer into the middle of a pointer: the question at 12 is
    // "a" + ptr->15, where 15 is the second octet (0x0c) of the pointer
    // c0 0c that sits at 14..15, read as a label length 12 that runs past
    // the end of the packet.
    try testing.expectError(error.Malformed, Message.parse("\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\x01a\xc0\x0c\xc0\x0f\x00\x01\x00\x01"));
    // Pointer into the header.
    try testing.expectError(error.Malformed, Message.parse("\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\xc0\x05\x00\x01\x00\x01"));
    // 9001 B packet.
    var big: [9001]u8 = @splat(0);
    try testing.expectError(error.Malformed, Message.parse(&big));
    // 9000 B header-only packet with trailing zeros is accepted.
    _ = try Message.parse(big[0..9000]);
}

test "iterators over a hand-built unvalidated view stop safely" {
    var it: QuestionIterator = .{ .bytes = "\xc0\x00", .pos = 0, .remaining = 5 };
    try testing.expect(it.next() == null);
    try testing.expect(it.next() == null);
    var rit: RecordIterator = .{ .bytes = "\x01a", .pos = 0, .remaining = 5, .section = .answer };
    try testing.expect(rit.next() == null);
}
