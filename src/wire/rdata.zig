//! Resource-record data codecs for the types mDNS and DNS-SD use: A, AAAA,
//! PTR, SRV, TXT, NSEC (the RFC 6762 section 6.1 restricted form) and
//! HINFO, plus the RFC 6762 section 8.2 lexicographic comparison used for
//! probe tie-breaking and conflict detection.
//!
//! Decoders that can meet a name take the whole message, because RFC 6762
//! section 18.14 allows the names inside PTR, SRV and NSEC rdata to be
//! compressed. Encoders write the uncompressed form; the `Builder` does
//! the compression. Nothing here allocates or panics on packet bytes.
const std = @import("std");
const name_mod = @import("name.zig");
const message = @import("message.zig");
const txt_mod = @import("txt.zig");

pub const Name = name_mod.Name;
pub const Record = message.Record;
pub const RType = message.RType;

pub const DecodeError = error{Malformed};
pub const EncodeError = error{NoSpace};

/// Largest uncompressed rdata this module ever produces for a name-bearing
/// type: SRV is 6 + 255 octets; NSEC is 255 + 2 + 32.
pub const max_name_rdata_len = 6 + name_mod.max_wire_len + 34;

pub const Srv = struct {
    priority: u16 = 0,
    weight: u16 = 0,
    port: u16,
    target: Name,

    pub const fixed_len = 6;
};

/// RFC 6762 section 6.1 restricted NSEC: next-domain name (normally the
/// owner) plus a type bitmap for window block 0 (types 0..255) only.
pub const Nsec = struct {
    next: Name,
    /// RFC 4034 section 4.1.2 bitmap for window 0: bit 0 of byte 0 is the
    /// most-significant bit and stands for type 0.
    bitmap: [32]u8 = @splat(0),

    pub const SetError = error{
        /// RFC 6762 section 6.1: a responder holding "records with rrtypes
        /// above 255 [...] MUST NOT generate these restricted-form NSEC
        /// records". The caller must emit no NSEC (or a full RFC 4034 one)
        /// for that name.
        TypeOutsideWindow0,
        /// RFC 6762 section 6.1: synthesized mDNS NSEC records "MUST NOT
        /// have the NSEC bit set in the Type Bit Map".
        NsecBitNotAllowed,
    };

    pub fn fromTypes(next: Name, types: []const RType) SetError!Nsec {
        var n: Nsec = .{ .next = next };
        for (types) |t| try n.set(t);
        return n;
    }

    /// Mark a type present. A type over 255 is outside window 0, which
    /// the restricted form cannot express, and type 47 (NSEC) is never
    /// set in an mDNS NSEC; both return an error and leave `n` unchanged.
    pub fn set(n: *Nsec, t: RType) SetError!void {
        const v = t.toInt();
        if (v > 255) return error.TypeOutsideWindow0;
        if (t == .nsec) return error.NsecBitNotAllowed;
        n.bitmap[v / 8] |= @as(u8, 0x80) >> @intCast(v % 8);
    }

    pub fn has(n: *const Nsec, t: RType) bool {
        const v = t.toInt();
        if (v > 255) return false;
        return n.bitmap[v / 8] & (@as(u8, 0x80) >> @intCast(v % 8)) != 0;
    }

    /// Number of bitmap octets needed: index of the last non-zero octet
    /// plus one, or zero when no type is set.
    pub fn bitmapLen(n: *const Nsec) usize {
        return bitmapLenOf(&n.bitmap);
    }

    pub const WireBitmap = struct { buf: [32]u8, len: usize };

    /// The window-0 bitmap as it goes on the wire: the NSEC bit (type 47)
    /// cleared, because RFC 6762 section 6.1 synthesized NSEC records
    /// "MUST NOT have the NSEC bit set", and trailing zero octets
    /// dropped (RFC 4034 section 4.1.2). `set` already refuses type 47;
    /// this covers a `bitmap` written directly, so the encoders never
    /// emit it.
    pub fn wireBitmap(n: *const Nsec) WireBitmap {
        var w: WireBitmap = .{ .buf = n.bitmap, .len = 0 };
        const nsec_type = RType.nsec.toInt();
        w.buf[nsec_type / 8] &= ~(@as(u8, 0x80) >> @intCast(nsec_type % 8));
        w.len = bitmapLenOf(&w.buf);
        return w;
    }

    fn bitmapLenOf(bitmap: *const [32]u8) usize {
        var i: usize = 32;
        while (i > 0) : (i -= 1) {
            if (bitmap[i - 1] != 0) return i;
        }
        return 0;
    }
};

pub const Hinfo = struct {
    cpu: []const u8,
    os: []const u8,
};

// ---------------------------------------------------------------------------
// decode
// ---------------------------------------------------------------------------

pub fn decodeA(rdata: []const u8) DecodeError![4]u8 {
    if (rdata.len != 4) return error.Malformed;
    return rdata[0..4].*;
}

pub fn decodeAaaa(rdata: []const u8) DecodeError![16]u8 {
    if (rdata.len != 16) return error.Malformed;
    return rdata[0..16].*;
}

/// PTR (and NS, CNAME): one possibly compressed name filling the rdata.
pub fn decodePtr(msg: []const u8, rec: Record) DecodeError!Name {
    const d = try decodeNameIn(msg, rec, rec.rdata_offset);
    if (d.end != rec.rdata_offset + rec.rdata.len) return error.Malformed;
    return d.name;
}

pub fn decodeSrv(msg: []const u8, rec: Record) DecodeError!Srv {
    if (rec.rdata.len < Srv.fixed_len) return error.Malformed;
    const d = try decodeNameIn(msg, rec, rec.rdata_offset + Srv.fixed_len);
    if (d.end != rec.rdata_offset + rec.rdata.len) return error.Malformed;
    return .{
        .priority = std.mem.readInt(u16, rec.rdata[0..2], .big),
        .weight = std.mem.readInt(u16, rec.rdata[2..4], .big),
        .port = std.mem.readInt(u16, rec.rdata[4..6], .big),
        .target = d.name,
    };
}

/// TXT: a validated zero-copy view over the strings.
pub fn decodeTxt(rec: Record) DecodeError!txt_mod.View {
    const v: txt_mod.View = .{ .bytes = rec.rdata };
    try v.validate();
    return v;
}

/// NSEC: next name, then zero or more window blocks. Only window 0 is
/// kept; other windows are checked structurally and skipped. RFC 4034
/// section 4.1.2: each block is 1..32 octets and "blocks are present [...]
/// in increasing numerical order", so a repeated or out-of-order window
/// is `error.Malformed`. Trailing zero octets inside a block ("MUST be
/// omitted" by the sender) are tolerated on receive: they change nothing
/// in the decoded bitmap and rejecting them would only cost interop.
pub fn decodeNsec(msg: []const u8, rec: Record) DecodeError!Nsec {
    const d = try decodeNameIn(msg, rec, rec.rdata_offset);
    var n: Nsec = .{ .next = d.name };
    const rd_end = rec.rdata_offset + rec.rdata.len;
    var pos = d.end;
    var last_window: ?u8 = null;
    while (pos < rd_end) {
        if (pos + 2 > rd_end) return error.Malformed;
        const window = msg[pos];
        const len: usize = msg[pos + 1];
        if (len == 0 or len > 32) return error.Malformed;
        if (pos + 2 + len > rd_end) return error.Malformed;
        if (last_window) |l| {
            if (window <= l) return error.Malformed;
        }
        last_window = window;
        if (window == 0) {
            @memcpy(n.bitmap[0..len], msg[pos + 2 ..][0..len]);
        }
        pos += 2 + len;
    }
    return n;
}

/// HINFO: two character-strings, CPU then OS.
pub fn decodeHinfo(rec: Record) DecodeError!Hinfo {
    const rd = rec.rdata;
    if (rd.len < 1) return error.Malformed;
    const cpu_len: usize = rd[0];
    if (1 + cpu_len + 1 > rd.len) return error.Malformed;
    const os_len: usize = rd[1 + cpu_len];
    if (1 + cpu_len + 1 + os_len != rd.len) return error.Malformed;
    return .{
        .cpu = rd[1..][0..cpu_len],
        .os = rd[2 + cpu_len ..][0..os_len],
    };
}

/// Decode a name at `offset` that must lie inside `rec.rdata` and end
/// inside it too (pointers may of course lead anywhere earlier).
fn decodeNameIn(msg: []const u8, rec: Record, offset: usize) DecodeError!Name.Decoded {
    const rd_end = rec.rdata_offset + rec.rdata.len;
    if (offset < rec.rdata_offset or offset >= rd_end or rd_end > msg.len) return error.Malformed;
    const d = try Name.decode(msg[0..rd_end], offset);
    return d;
}

// ---------------------------------------------------------------------------
// encode (uncompressed)
// ---------------------------------------------------------------------------

pub fn encodeA(addr: [4]u8, out: []u8) EncodeError!usize {
    if (out.len < 4) return error.NoSpace;
    out[0..4].* = addr;
    return 4;
}

pub fn encodeAaaa(addr: [16]u8, out: []u8) EncodeError!usize {
    if (out.len < 16) return error.NoSpace;
    out[0..16].* = addr;
    return 16;
}

pub fn encodePtr(target: Name, out: []u8) EncodeError!usize {
    return target.encode(out);
}

pub fn encodeSrv(srv: Srv, out: []u8) EncodeError!usize {
    if (out.len < Srv.fixed_len + srv.target.len) return error.NoSpace;
    std.mem.writeInt(u16, out[0..2], srv.priority, .big);
    std.mem.writeInt(u16, out[2..4], srv.weight, .big);
    std.mem.writeInt(u16, out[4..6], srv.port, .big);
    return Srv.fixed_len + try srv.target.encode(out[Srv.fixed_len..]);
}

/// Writes `nsec.wireBitmap()`: the NSEC bit is never emitted (RFC 6762
/// section 6.1).
pub fn encodeNsec(nsec: Nsec, out: []u8) EncodeError!usize {
    const wb = nsec.wireBitmap();
    const block_len: usize = if (wb.len == 0) 0 else 2 + wb.len;
    if (out.len < nsec.next.len + block_len) return error.NoSpace;
    var pos = try nsec.next.encode(out);
    if (wb.len != 0) {
        out[pos] = 0;
        out[pos + 1] = @intCast(wb.len);
        @memcpy(out[pos + 2 ..][0..wb.len], wb.buf[0..wb.len]);
        pos += 2 + wb.len;
    }
    return pos;
}

pub fn encodeHinfo(h: Hinfo, out: []u8) error{ NoSpace, StringTooLong }!usize {
    if (h.cpu.len > 255 or h.os.len > 255) return error.StringTooLong;
    const total = 2 + h.cpu.len + h.os.len;
    if (out.len < total) return error.NoSpace;
    out[0] = @intCast(h.cpu.len);
    @memcpy(out[1..][0..h.cpu.len], h.cpu);
    out[1 + h.cpu.len] = @intCast(h.os.len);
    @memcpy(out[2 + h.cpu.len ..][0..h.os.len], h.os);
    return total;
}

// ---------------------------------------------------------------------------
// comparison (RFC 6762 section 8.2)
// ---------------------------------------------------------------------------

/// Copy a record's rdata into `out` with every embedded name expanded
/// (PTR, NS, CNAME, SRV, NSEC). Other types are copied as they are.
pub fn canonicalRdata(msg: []const u8, rec: Record, out: []u8) error{ Malformed, NoSpace }![]const u8 {
    switch (rec.rtype) {
        .ptr, .ns, .cname => {
            const n = try decodePtr(msg, rec);
            return out[0..try n.encode(out)];
        },
        .srv => {
            const s = try decodeSrv(msg, rec);
            return out[0..try encodeSrv(s, out)];
        },
        .nsec => {
            const d = try decodeNameIn(msg, rec, rec.rdata_offset);
            const rest = msg[d.end .. rec.rdata_offset + rec.rdata.len];
            if (out.len < d.name.len + rest.len) return error.NoSpace;
            const nl = try d.name.encode(out);
            @memcpy(out[nl..][0..rest.len], rest);
            return out[0 .. nl + rest.len];
        },
        else => {
            if (out.len < rec.rdata.len) return error.NoSpace;
            @memcpy(out[0..rec.rdata.len], rec.rdata);
            return out[0..rec.rdata.len];
        },
    }
}

/// What section 8.2 compares: class without the cache-flush bit, type,
/// then the uncompressed rdata.
pub const Key = struct {
    class: u16,
    rtype: u16,
    rdata: []const u8,
};

/// RFC 6762 section 8.2 order: class (numerically, cache-flush bit
/// excluded), then type, then rdata octet by octet as unsigned values; a
/// strict prefix sorts first.
pub fn rdataCompare(a: Key, b: Key) std.math.Order {
    const ac = a.class & ~message.cache_flush_bit;
    const bc = b.class & ~message.cache_flush_bit;
    if (ac != bc) return std.math.order(ac, bc);
    if (a.rtype != b.rtype) return std.math.order(a.rtype, b.rtype);
    return std.mem.order(u8, a.rdata, b.rdata);
}

pub fn rdataEqual(a: Key, b: Key) bool {
    return rdataCompare(a, b) == .eq;
}

/// Compare two records that may live in different messages. Names inside
/// the rdata are expanded first, so compression never changes the result.
pub fn compareRecords(msg_a: []const u8, a: Record, msg_b: []const u8, b: Record) error{Malformed}!std.math.Order {
    var buf_a: [message.max_message_len]u8 = undefined;
    var buf_b: [message.max_message_len]u8 = undefined;
    // Rdata is a slice of a message that is at most max_message_len, and
    // expansion of a name-bearing type is bounded by max_name_rdata_len,
    // so NoSpace cannot happen; map it to Malformed rather than trusting
    // that argument.
    const ca = canonicalRdata(msg_a, a, &buf_a) catch return error.Malformed;
    const cb = canonicalRdata(msg_b, b, &buf_b) catch return error.Malformed;
    return rdataCompare(
        .{ .class = a.class_raw, .rtype = a.rtype.toInt(), .rdata = ca },
        .{ .class = b.class_raw, .rtype = b.rtype.toInt(), .rdata = cb },
    );
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const Message = message.Message;

// Response with: PTR (compressed), SRV (compressed target), TXT, NSEC
// (compressed next, bitmap A + SRV), A, AAAA, HINFO.
// Layout:
//  12: q "_svc._udp.local" (17) -> 29, +4 -> 33
//  33: RR PTR name ptr->12 (2) +10 = 45; rdata "inst" + ptr->12 (7) -> 52
//  52: RR SRV name ptr->45 (2) +10 = 64; rdata 0 0 0x1151 "host" + ptr->22 (13) -> 77; target name starts at 70
//  77: RR TXT name ptr->45 +10 = 89; rdata "\x03k=v" (4) -> 93
//  93: RR NSEC name ptr->70 ("host.local") +10 = 105; rdata ptr->70 (2) + 00 05 40 00 00 00 40 (7) -> 114
// 114: RR A name ptr->70 +10 = 126; rdata 4 -> 130
// 130: RR AAAA name ptr->70 +10 = 142; rdata 16 -> 158
// 158: RR HINFO name ptr->70 +10 = 170; rdata "\x03arm\x05macOS" (10) -> 180
const compressed_msg =
    "\x00\x00\x84\x00\x00\x01\x00\x07\x00\x00\x00\x00" ++
    "\x04_svc\x04_udp\x05local\x00\x00\x0c\x00\x01" ++
    "\xc0\x0c\x00\x0c\x00\x01\x00\x00\x11\x94\x00\x07\x04inst\xc0\x0c" ++
    "\xc0\x2d\x00\x21\x80\x01\x00\x00\x00\x78\x00\x0d\x00\x00\x00\x00\x11\x51\x04host\xc0\x16" ++
    "\xc0\x2d\x00\x10\x80\x01\x00\x00\x11\x94\x00\x04\x03k=v" ++
    "\xc0\x46\x00\x2f\x80\x01\x00\x00\x00\x78\x00\x09\xc0\x46\x00\x05\x40\x00\x00\x00\x40" ++
    "\xc0\x46\x00\x01\x80\x01\x00\x00\x00\x78\x00\x04\x0a\x00\x00\x01" ++
    "\xc0\x46\x00\x1c\x80\x01\x00\x00\x00\x78\x00\x10\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" ++
    "\xc0\x46\x00\x0d\x80\x01\x00\x00\x00\x78\x00\x0a\x03arm\x05macOS";

test "decode every rdata type inside a compressed message" {
    const m = try Message.parse(compressed_msg);
    try testing.expectEqual(compressed_msg.len, m.end);
    var it = m.answers();

    const ptr = it.next().?;
    try testing.expectEqual(RType.ptr, ptr.rtype);
    const ptr_name = try decodePtr(m.bytes, ptr);
    try name_mod.expectText("inst._svc._udp.local", ptr_name);

    const srv = it.next().?;
    try testing.expectEqual(RType.srv, srv.rtype);
    try name_mod.expectText("inst._svc._udp.local", srv.name);
    const s = try decodeSrv(m.bytes, srv);
    try testing.expectEqual(@as(u16, 0x1151), s.port);
    try testing.expectEqual(@as(u16, 0), s.priority);
    try name_mod.expectText("host.local", s.target);

    const txt = it.next().?;
    const tv = try decodeTxt(txt);
    try testing.expectEqualStrings("v", tv.get("K").?);

    const nsec = it.next().?;
    try name_mod.expectText("host.local", nsec.name);
    const n = try decodeNsec(m.bytes, nsec);
    try name_mod.expectText("host.local", n.next);
    try testing.expect(n.has(.a));
    try testing.expect(n.has(.srv));
    try testing.expect(!n.has(.aaaa));
    try testing.expect(!n.has(.txt));
    try testing.expect(!n.has(RType.fromInt(300)));
    try testing.expectEqual(@as(usize, 5), n.bitmapLen());

    const a = it.next().?;
    try testing.expectEqual([4]u8{ 10, 0, 0, 1 }, try decodeA(a.rdata));
    const aaaa = it.next().?;
    const v6 = try decodeAaaa(aaaa.rdata);
    try testing.expectEqual(@as(u8, 0xfe), v6[0]);
    try testing.expectEqual(@as(u8, 1), v6[15]);

    const hinfo = it.next().?;
    const h = try decodeHinfo(hinfo);
    try testing.expectEqualStrings("arm", h.cpu);
    try testing.expectEqualStrings("macOS", h.os);
    try testing.expect(it.next() == null);
}

test "rdata decoders reject wrong lengths and names that overrun rdata" {
    try testing.expectError(error.Malformed, decodeA("\x0a\x00\x00"));
    try testing.expectError(error.Malformed, decodeA("\x0a\x00\x00\x01\x00"));
    try testing.expectError(error.Malformed, decodeAaaa("\x00"));
    // SRV whose rdlength cuts the target short: rdata = 6 fixed + "\x04ho".
    const msg = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x01a\x00\x00\x21\x00\x01\x00\x00\x00\x78\x00\x09\x00\x00\x00\x00\x11\x51\x04ho\x00" ++
        "st\x00";
    const m = try Message.parse(msg);
    var it = m.answers();
    const srv = it.next().?;
    try testing.expectError(error.Malformed, decodeSrv(m.bytes, srv));
    // SRV shorter than the fixed part.
    const short = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x01a\x00\x00\x21\x00\x01\x00\x00\x00\x78\x00\x03\x00\x00\x00";
    const m2 = try Message.parse(short);
    var it2 = m2.answers();
    try testing.expectError(error.Malformed, decodeSrv(m2.bytes, it2.next().?));
    // PTR with trailing garbage after the name.
    const ptr = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x01a\x00\x00\x0c\x00\x01\x00\x00\x00\x78\x00\x04\x01b\x00\x00";
    const m3 = try Message.parse(ptr);
    var it3 = m3.answers();
    try testing.expectError(error.Malformed, decodePtr(m3.bytes, it3.next().?));
    // PTR with empty rdata.
    const empty = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x01a\x00\x00\x0c\x00\x01\x00\x00\x00\x78\x00\x00";
    const m4 = try Message.parse(empty);
    var it4 = m4.answers();
    const r4 = it4.next().?;
    try testing.expectError(error.Malformed, decodePtr(m4.bytes, r4));
    try testing.expectError(error.Malformed, decodeNsec(m4.bytes, r4));
    try testing.expectError(error.Malformed, decodeHinfo(r4));
    // NSEC with a bad window block.
    const nsec = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x01a\x00\x00\x2f\x00\x01\x00\x00\x00\x78\x00\x05\xc0\x0c\x00\x00\x40";
    const m5 = try Message.parse(nsec);
    var it5 = m5.answers();
    try testing.expectError(error.Malformed, decodeNsec(m5.bytes, it5.next().?));
    const nsec2 = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x01a\x00\x00\x2f\x00\x01\x00\x00\x00\x78\x00\x05\xc0\x0c\x00\x21\x40";
    const m6 = try Message.parse(nsec2);
    var it6 = m6.answers();
    try testing.expectError(error.Malformed, decodeNsec(m6.bytes, it6.next().?));
    // RFC 4034 section 4.1.2: window blocks appear once each, in
    // increasing order. Two window-0 blocks (would merge to 80 01) ...
    const nsec_dup = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x01a\x00\x00\x2f\x00\x01\x00\x00\x00\x78\x00\x09\xc0\x0c\x00\x02\x00\x01\x00\x01\x80";
    const m8 = try Message.parse(nsec_dup);
    var it8 = m8.answers();
    try testing.expectError(error.Malformed, decodeNsec(m8.bytes, it8.next().?));
    // ... and window 1 before window 0 (would report A present).
    const nsec_ooo = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x01a\x00\x00\x2f\x00\x01\x00\x00\x00\x78\x00\x08\xc0\x0c\x01\x01\x80\x00\x01\x40";
    const m9 = try Message.parse(nsec_ooo);
    var it9 = m9.answers();
    try testing.expectError(error.Malformed, decodeNsec(m9.bytes, it9.next().?));
    // Window 0 then window 1 in order is fine; window 1 is skipped.
    const nsec_ok = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x01a\x00\x00\x2f\x00\x01\x00\x00\x00\x78\x00\x08\xc0\x0c\x00\x01\x40\x01\x01\x80";
    const m10 = try Message.parse(nsec_ok);
    var it10 = m10.answers();
    const ok = try decodeNsec(m10.bytes, it10.next().?);
    try testing.expect(ok.has(.a));
    try testing.expectEqual(@as(usize, 1), ok.bitmapLen());
    // HINFO os string running past the end.
    const hinfo = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x01a\x00\x00\x0d\x00\x01\x00\x00\x00\x78\x00\x04\x01x\x05y";
    const m7 = try Message.parse(hinfo);
    var it7 = m7.answers();
    try testing.expectError(error.Malformed, decodeHinfo(it7.next().?));
}

test "encode round trips" {
    var buf: [512]u8 = undefined;
    const target = try Name.parse("host.local");
    const srv: Srv = .{ .priority = 1, .weight = 2, .port = 4433, .target = target };
    const sl = try encodeSrv(srv, &buf);
    try testing.expectEqualSlices(u8, "\x00\x01\x00\x02\x11\x51\x04host\x05local\x00", buf[0..sl]);
    try testing.expectError(error.NoSpace, encodeSrv(srv, buf[0..10]));

    var nsec = try Nsec.fromTypes(target, &.{ .a, .aaaa });
    try testing.expectError(error.TypeOutsideWindow0, nsec.set(RType.fromInt(1000)));
    const nl = try encodeNsec(nsec, &buf);
    try testing.expectEqualSlices(u8, "\x04host\x05local\x00\x00\x04\x40\x00\x00\x08", buf[0..nl]);
    const empty_nsec: Nsec = .{ .next = target };
    try testing.expectEqual(@as(usize, 0), empty_nsec.bitmapLen());
    try testing.expectEqual(target.len, try encodeNsec(empty_nsec, &buf));

    const hl = try encodeHinfo(.{ .cpu = "arm", .os = "macOS" }, &buf);
    try testing.expectEqualSlices(u8, "\x03arm\x05macOS", buf[0..hl]);
    const long: [256]u8 = @splat('x');
    try testing.expectError(error.StringTooLong, encodeHinfo(.{ .cpu = &long, .os = "" }, &buf));

    try testing.expectEqual(@as(usize, 4), try encodeA(.{ 1, 2, 3, 4 }, &buf));
    try testing.expectEqualSlices(u8, "\x01\x02\x03\x04", buf[0..4]);
    try testing.expectError(error.NoSpace, encodeA(.{ 1, 2, 3, 4 }, buf[0..3]));
    try testing.expectEqual(@as(usize, 16), try encodeAaaa(@splat(9), &buf));
    try testing.expectError(error.NoSpace, encodeAaaa(@splat(9), buf[0..15]));
    try testing.expectEqual(target.len, try encodePtr(target, &buf));
}

test "restricted NSEC refuses types over 255 and never sets the NSEC bit" {
    const host = try Name.parse("host.local");
    // RFC 6762 section 6.1: rrtypes above 255 cannot be expressed; the
    // caller gets a signal instead of a silently incomplete record.
    try testing.expectError(error.TypeOutsideWindow0, Nsec.fromTypes(host, &.{ .a, RType.fromInt(256) }));
    var n: Nsec = .{ .next = host };
    try n.set(.a);
    try testing.expectError(error.TypeOutsideWindow0, n.set(RType.fromInt(65535)));
    try testing.expect(n.has(.a));
    // Type 47 (NSEC) is refused by `set`...
    try testing.expectError(error.NsecBitNotAllowed, n.set(.nsec));
    try testing.expect(!n.has(.nsec));
    // ...and cleared by the encoders when the bitmap was written directly.
    n.bitmap[47 / 8] |= @as(u8, 0x80) >> @intCast(47 % 8);
    try testing.expect(n.has(.nsec));
    try testing.expectEqual(@as(usize, 6), n.bitmapLen());
    const wb = n.wireBitmap();
    try testing.expectEqual(@as(usize, 1), wb.len);
    try testing.expectEqual(@as(u8, 0x40), wb.buf[0]);
    var buf: [64]u8 = undefined;
    const nl = try encodeNsec(n, &buf);
    try testing.expectEqualSlices(u8, "\x04host\x05local\x00\x00\x01\x40", buf[0..nl]);
    // A bitmap holding only the NSEC bit encodes as no window block at all.
    var only: Nsec = .{ .next = host };
    only.bitmap[47 / 8] |= @as(u8, 0x80) >> @intCast(47 % 8);
    try testing.expectEqual(@as(usize, 0), only.wireBitmap().len);
    try testing.expectEqual(host.len, try encodeNsec(only, &buf));
}

test "rdataCompare follows RFC 6762 section 8.2" {
    const in_a: Key = .{ .class = 1, .rtype = 1, .rdata = "\x0a\x00\x00\x01" };
    const in_a2: Key = .{ .class = 0x8001, .rtype = 1, .rdata = "\x0a\x00\x00\x02" };
    const in_aaaa: Key = .{ .class = 1, .rtype = 28, .rdata = "\x00" };
    const other_class: Key = .{ .class = 2, .rtype = 1, .rdata = "\x00" };
    try testing.expectEqual(std.math.Order.lt, rdataCompare(in_a, in_a2));
    try testing.expectEqual(std.math.Order.gt, rdataCompare(in_a2, in_a));
    try testing.expectEqual(std.math.Order.lt, rdataCompare(in_a, in_aaaa));
    try testing.expectEqual(std.math.Order.lt, rdataCompare(in_aaaa, other_class));
    // Cache-flush bit is excluded from the class comparison.
    try testing.expect(rdataEqual(in_a, .{ .class = 0x8001, .rtype = 1, .rdata = "\x0a\x00\x00\x01" }));
    // Prefix sorts first; octets compare unsigned.
    try testing.expectEqual(std.math.Order.lt, rdataCompare(
        .{ .class = 1, .rtype = 16, .rdata = "\x01a" },
        .{ .class = 1, .rtype = 16, .rdata = "\x01a\x01b" },
    ));
    try testing.expectEqual(std.math.Order.lt, rdataCompare(
        .{ .class = 1, .rtype = 16, .rdata = "\x7f" },
        .{ .class = 1, .rtype = 16, .rdata = "\x80" },
    ));
}

test "compareRecords expands compression before comparing" {
    // Same SRV, once compressed (in compressed_msg) and once flat.
    const m = try Message.parse(compressed_msg);
    var it = m.answers();
    _ = it.next(); // PTR
    const srv_c = it.next().?;
    const flat = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x04inst\x04_svc\x04_udp\x05local\x00\x00\x21\x00\x01\x00\x00\x00\x78\x00\x12" ++
        "\x00\x00\x00\x00\x11\x51\x04host\x05local\x00";
    const mf = try Message.parse(flat);
    var itf = mf.answers();
    const srv_f = itf.next().?;
    try testing.expectEqual(std.math.Order.eq, try compareRecords(m.bytes, srv_c, mf.bytes, srv_f));
    try testing.expect(!std.mem.eql(u8, srv_c.rdata, srv_f.rdata));
    var buf: [512]u8 = undefined;
    const canon = try canonicalRdata(m.bytes, srv_c, &buf);
    try testing.expectEqualSlices(u8, srv_f.rdata, canon);
    try testing.expectError(error.NoSpace, canonicalRdata(m.bytes, srv_c, buf[0..5]));
    // A different port sorts after.
    const flat2 = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x04inst\x04_svc\x04_udp\x05local\x00\x00\x21\x00\x01\x00\x00\x00\x78\x00\x12" ++
        "\x00\x00\x00\x00\x11\x52\x04host\x05local\x00";
    const mf2 = try Message.parse(flat2);
    var itf2 = mf2.answers();
    try testing.expectEqual(std.math.Order.lt, try compareRecords(m.bytes, srv_c, mf2.bytes, itf2.next().?));
    // NSEC and PTR canonical forms.
    _ = it.next(); // TXT
    const nsec_c = it.next().?;
    const nsec_canon = try canonicalRdata(m.bytes, nsec_c, &buf);
    try testing.expectEqualSlices(u8, "\x04host\x05local\x00\x00\x05\x40\x00\x00\x00\x40", nsec_canon);
    var it2 = m.answers();
    const ptr_c = it2.next().?;
    const ptr_canon = try canonicalRdata(m.bytes, ptr_c, &buf);
    try testing.expectEqualSlices(u8, "\x04inst\x04_svc\x04_udp\x05local\x00", ptr_canon);
    // Raw types copy through.
    const a_rec = it.next().?;
    try testing.expectEqualSlices(u8, a_rec.rdata, try canonicalRdata(m.bytes, a_rec, &buf));
}
