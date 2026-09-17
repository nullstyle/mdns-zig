//! mdns.profiles: the TXT schemas of the workspace consumers (plan
//! section 3.4) as typed adverts and parsers.
//!
//! - `qmsg`: `_qmsg._udp` (`Advert`, `Parsed`).
//! - `qmesh`: `_qmesh._udp` (`Advert`, `Parsed`, `SeedSet`).
//! - `studio`: `_shared-studio._udp` (`Advert`, `Parsed`, `Role`).
//!
//! An `Advert` validates its fields once in `init` and renders the TXT
//! pairs into its own fixed buffers; `desc()` returns the `ServiceDesc`
//! that `Service.advertise` copies. A `Parsed` is a value read out of a
//! `Resolved` event; it holds no pointer into the event.
//!
//! Import rule (plan section 6, "profiles/root.zig ... asserts the import
//! graph is std-only"): this directory imports `std`, the codec
//! (`src/wire/`) and the value types (`src/core/events.zig`), nothing
//! else. In particular it never imports `service.zig`, the Engine or
//! `platform/`, so a consumer can use the schemas in a process that runs
//! no mDNS at all (a qmesh node that reads a TXT out of a config file, a
//! test). `tests/profiles_test.zig` walks the `@import` closure of this
//! file and fails when it reaches anything outside that set.
//!
//! Security posture (plan section 3): a `spki` or `id` in TXT is an
//! unauthenticated selector. It tells the consumer which peer to dial and
//! which `expected_peer_spki` to pin; the pinned-CA mTLS handshake is the
//! proof. Nothing here trusts a TXT value beyond its syntax.
const std = @import("std");
const events = @import("../core/events.zig");
const wire = @import("../wire/root.zig");

pub const qmsg = @import("qmsg.zig");
pub const qmesh = @import("qmesh.zig");
pub const studio = @import("studio.zig");

// ---- value types the profiles speak in ------------------------------

pub const Bounded = events.Bounded;
pub const Name = events.Name;
pub const Txt = events.Txt;
pub const TxtPair = events.TxtPair;
pub const ServiceDesc = events.ServiceDesc;
pub const Resolved = events.Resolved;

/// Every profile starts its TXT with `txtvers=1` (RFC 6763 section 6.7).
pub const txtvers = "1";

/// TXT rdata limit on both sides (plan section 4.5). Every profile's
/// maximal TXT stays under it; `tests/profiles_test.zig` proves it.
pub const max_txt_len = wire.txt.max_len;

/// `sn=<value>` must fit one TXT string of 255 octets (RFC 6763
/// section 6.1): 255 - "sn=".len.
pub const max_server_name_len = wire.txt.max_string_len - "sn=".len;

/// Longest `epoch` value: a u128 in hex.
pub const max_epoch_hex = 32;

/// `pat` is a u64 in hex.
pub const max_pat_hex = 16;

/// Errors `Advert.init` returns. The Engine validates the same fields
/// again at `advertise`; `init` fails early so a bad advert never reaches
/// the Service.
pub const InitError = error{
    /// Not 1..63 octets of UTF-8 without control characters (RFC 6763
    /// section 4.1.1), or (qmesh) a derived instance was requested with
    /// an explicit empty string.
    InvalidInstance,
    /// Port 0 is not dialable.
    InvalidPort,
    /// `sn` is empty, over `max_server_name_len`, or contains a control
    /// or non-ASCII octet.
    InvalidServerName,
};

/// Errors the `parse` functions return. Unknown keys are ignored
/// (RFC 6763 section 6.4); only the keys the schema names are checked.
pub const ParseError = error{
    /// `resolved.service_type` is not this profile's type.
    WrongServiceType,
    /// A required key is absent or is a boolean attribute (no `=`).
    MissingKey,
    /// `txtvers` is present but not `1`.
    TxtVersionMismatch,
    /// `alpn` is present but not the profile's ALPN.
    AlpnMismatch,
    /// A fixed-value key (`fv`, `clip`) is present with another value.
    FormatMismatch,
    /// `spki` / `id` is not exactly 64 lowercase hex digits.
    InvalidDigest,
    /// `epoch` is not 1..32 hex digits.
    InvalidEpoch,
    /// `pat` is not 1..16 hex digits.
    InvalidPat,
    /// `role` is not `conductor` or `performer`.
    InvalidRole,
    /// `sn` is empty, too long, or (studio) not `shared-studio`.
    InvalidServerName,
};

/// An `epoch` value as received: the integer and the number of octets
/// the sender encoded (`(hex digits + 1) / 2`). qmesh sends 16 (a u128),
/// shared-studio sends 8 (a u64); both parse.
pub const Epoch = struct {
    value: u128,
    /// 1..16.
    len: u8,
};

// ---- Advert-side validation ------------------------------------------

pub fn validateInstance(instance: []const u8) InitError!void {
    wire.validateInstance(instance) catch return error.InvalidInstance;
}

pub fn validatePort(port: u16) InitError!void {
    if (port == 0) return error.InvalidPort;
}

/// 1..`max_server_name_len` printable ASCII octets (an SNI host name).
pub fn validateServerName(sn: []const u8) InitError!void {
    if (sn.len == 0 or sn.len > max_server_name_len) return error.InvalidServerName;
    for (sn) |c| if (c < 0x21 or c > 0x7e) return error.InvalidServerName;
}

/// Lowercase hex of a 32-byte digest, the wire form of `spki` and `id`.
pub fn digestHex(digest: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(digest, .lower);
}

/// Fixed-width lowercase hex of an unsigned integer (`@bitSizeOf(T) / 4`
/// digits, zero-padded). The wire form of `epoch` (u64 or u128) and
/// `pat` (u64).
pub fn intHex(comptime T: type, value: T) [@bitSizeOf(T) / 4]u8 {
    comptime std.debug.assert(@typeInfo(T) == .int and @typeInfo(T).int.signedness == .unsigned);
    const digits = @bitSizeOf(T) / 4;
    var out: [digits]u8 = undefined;
    var v = value;
    var i: usize = digits;
    while (i > 0) {
        i -= 1;
        out[i] = "0123456789abcdef"[@as(u4, @truncate(v))];
        v >>= 4;
    }
    return out;
}

// ---- Parsed-side helpers ---------------------------------------------

/// The value of `key`, or `error.MissingKey` when the key is absent or a
/// boolean attribute. Keys compare case-insensitively (RFC 6763
/// section 6.4); the first occurrence wins.
pub fn require(txt: *const Txt, key: []const u8) ParseError![]const u8 {
    return txt.get(key) orelse error.MissingKey;
}

/// `txtvers` must be `1` when present. A missing `txtvers` is accepted:
/// RFC 6763 section 6.7 makes it optional, and every other check still
/// applies.
pub fn checkTxtVersion(txt: *const Txt) ParseError!void {
    const v = txt.get("txtvers") orelse return;
    if (!std.mem.eql(u8, v, txtvers)) return error.TxtVersionMismatch;
}

/// A key that carries one fixed value in the schema (`alpn`, `fv`,
/// `clip`, studio `sn`): absent is accepted, another value is `err`.
/// Values compare byte-exact.
pub fn checkFixed(txt: *const Txt, key: []const u8, expected: []const u8, comptime err: ParseError) ParseError!void {
    const v = txt.get(key) orelse return;
    if (!std.mem.eql(u8, v, expected)) return err;
}

/// `resolved.service_type` must start with the two labels of
/// `service_type` (`_qmsg._udp`), ASCII case-insensitively. The Engine
/// fills it with `<type>.local`.
pub fn checkServiceType(resolved: *const Resolved, service_type: []const u8) ParseError!void {
    var want = std.mem.splitScalar(u8, service_type, '.');
    var have = resolved.service_type.labels();
    while (want.next()) |w| {
        const h = have.next() orelse return error.WrongServiceType;
        if (!std.ascii.eqlIgnoreCase(w, h)) return error.WrongServiceType;
    }
}

/// True when every octet is a hex digit and, with `lower_only`, none is
/// `A`..`F`. An empty slice is not hex.
pub fn isHex(s: []const u8, lower_only: bool) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        const ok = std.ascii.isDigit(c) or (c >= 'a' and c <= 'f') or (!lower_only and c >= 'A' and c <= 'F');
        if (!ok) return false;
    }
    return true;
}

/// `key=<64 lowercase hex>` to 32 bytes. Anything else (missing, wrong
/// length, uppercase, a non-hex octet) is rejected before decoding, as
/// plan section 3.4 asks.
pub fn parseDigest(txt: *const Txt, key: []const u8) ParseError![32]u8 {
    const v = try require(txt, key);
    if (v.len != 64 or !isHex(v, true)) return error.InvalidDigest;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, v) catch return error.InvalidDigest;
    return out;
}

/// Hex digits of either case to an unsigned integer; `s` must be
/// 1..`@bitSizeOf(T) / 4` digits. Not `std.fmt.parseUnsigned`: that one
/// accepts `_` separators.
pub fn parseHexInt(comptime T: type, s: []const u8) ?T {
    if (!isHex(s, false) or s.len > @bitSizeOf(T) / 4) return null;
    var v: T = 0;
    for (s) |c| {
        const d: u4 = @intCast(std.fmt.charToDigit(c, 16) catch return null);
        v = (v << 4) | d;
    }
    return v;
}

/// `epoch=<1..32 hex>`; the sender's width is kept in `Epoch.len`.
pub fn parseEpoch(txt: *const Txt) ParseError!Epoch {
    const v = try require(txt, "epoch");
    if (v.len > max_epoch_hex) return error.InvalidEpoch;
    const value = parseHexInt(u128, v) orelse return error.InvalidEpoch;
    return .{ .value = value, .len = @intCast((v.len + 1) / 2) };
}

/// `pat=<1..16 hex>` when present. An optional hint (plan section 3.4):
/// HELLO negotiation after connect is authoritative.
pub fn parsePat(txt: *const Txt) ParseError!?u64 {
    const v = txt.get("pat") orelse return null;
    if (v.len > max_pat_hex) return error.InvalidPat;
    return parseHexInt(u64, v) orelse error.InvalidPat;
}

/// `sn=<1..252 printable ASCII>` copied into a value.
pub fn parseServerName(txt: *const Txt) ParseError!Bounded(u8, max_server_name_len) {
    const v = try require(txt, "sn");
    validateServerName(v) catch return error.InvalidServerName;
    // `validateServerName` bounds `v.len`; the error branch is kept so no
    // network-fed path ends in `unreachable`.
    return Bounded(u8, max_server_name_len).fromSlice(v) catch error.InvalidServerName;
}

test {
    std.testing.refAllDecls(@This());
    _ = qmsg;
    _ = qmesh;
    _ = studio;
}

test "intHex is fixed width and lowercase" {
    try std.testing.expectEqualStrings("0000000000000001", &intHex(u64, 1));
    try std.testing.expectEqualStrings("00000000000000000000000000000000", &intHex(u128, 0));
    try std.testing.expectEqualStrings("ffffffffffffffffffffffffffffffff", &intHex(u128, std.math.maxInt(u128)));
    try std.testing.expectEqualStrings("00000000deadbeef", &intHex(u64, 0xdeadbeef));
}

test "parseHexInt rejects separators, empty and overflow" {
    try std.testing.expectEqual(@as(?u64, 0xdeadbeef), parseHexInt(u64, "DeadBeef"));
    try std.testing.expectEqual(@as(?u64, null), parseHexInt(u64, "dead_beef"));
    try std.testing.expectEqual(@as(?u64, null), parseHexInt(u64, ""));
    try std.testing.expectEqual(@as(?u64, null), parseHexInt(u64, "10000000000000000"));
    try std.testing.expectEqual(@as(?u64, 0), parseHexInt(u64, "0000000000000000"));
}
