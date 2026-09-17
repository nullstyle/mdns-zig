//! `_qmsg._udp` (plan section 3.4): one qmsg QUIC endpoint.
//!
//! TXT, in this order: `txtvers=1`, `alpn=qmsg/1`, `spki=<64 lowercase
//! hex>`, `sn=<server_name>`, `pat=<hex u64>` (optional hint).
//!
//! `spki` is the SHA-256 of the leaf certificate's DER SubjectPublicKeyInfo
//! (`qmsg Session.peer_cert_spki`). A browser dials the resolved address
//! with `QuicDialOptions{ .expected_peer_spki = parsed.spki, .server_name
//! = parsed.sn.slice() }`; the handshake, not the TXT, proves the peer.
//! `pat` mirrors `transport.supported_patterns`; HELLO after connect is
//! authoritative (`qmsg/AUTH.md`).
const std = @import("std");
const profiles = @import("root.zig");

const Bounded = profiles.Bounded;
const Txt = profiles.Txt;
const TxtPair = profiles.TxtPair;
const ServiceDesc = profiles.ServiceDesc;
const Resolved = profiles.Resolved;

pub const service_type = "_qmsg._udp";
pub const alpn = "qmsg/1";

pub const InitError = profiles.InitError;
pub const ParseError = profiles.ParseError;

/// What `Advert.init` takes. The slices are borrowed: they must outlive
/// every `desc()` / `txt()` call (a string literal or config memory).
pub const Options = struct {
    /// The user label or the host; one instance label, 1..63 octets.
    instance: []const u8,
    /// The listener's port after bind.
    port: u16,
    /// Local certificate SPKI SHA-256 (`certificateSpki(cert_pem)`).
    spki: [32]u8,
    /// `QuicListenOptions` / `QuicDialOptions.server_name`.
    sn: []const u8,
    /// `transport.supported_patterns` as a hint, or null to omit the key.
    pat: ?u64 = null,
};

/// A validated advert with its TXT rendered into fixed buffers. `desc()`
/// and `txt()` return slices into `self`, so keep the `Advert` in place
/// (not moved) while a `ServiceDesc` from it is in use; `Service.advertise`
/// and `Service.updateTxt` copy at the call.
pub const Advert = struct {
    instance: []const u8,
    port: u16,
    sn: []const u8,
    spki_hex: [64]u8,
    pat_hex: [16]u8 = @splat('0'),
    has_pat: bool,
    pairs: [max_pairs]TxtPair = undefined,

    pub const max_pairs = 5;

    pub fn init(opts: Options) InitError!Advert {
        try profiles.validateInstance(opts.instance);
        try profiles.validatePort(opts.port);
        try profiles.validateServerName(opts.sn);
        var a: Advert = .{
            .instance = opts.instance,
            .port = opts.port,
            .sn = opts.sn,
            .spki_hex = profiles.digestHex(opts.spki),
            .has_pat = opts.pat != null,
        };
        if (opts.pat) |p| a.pat_hex = profiles.intHex(u64, p);
        return a;
    }

    /// Replace or drop the `pat` hint; announce it with
    /// `Service.updateTxt(id, advert.txt())`.
    pub fn setPat(a: *Advert, pat: ?u64) void {
        a.has_pat = pat != null;
        if (pat) |p| a.pat_hex = profiles.intHex(u64, p);
    }

    /// The TXT pairs in schema order, `txtvers=1` first.
    pub fn txt(a: *Advert) []const TxtPair {
        a.pairs[0] = .{ .key = "txtvers", .value = profiles.txtvers };
        a.pairs[1] = .{ .key = "alpn", .value = alpn };
        a.pairs[2] = .{ .key = "spki", .value = &a.spki_hex };
        a.pairs[3] = .{ .key = "sn", .value = a.sn };
        var n: usize = 4;
        if (a.has_pat) {
            a.pairs[n] = .{ .key = "pat", .value = &a.pat_hex };
            n += 1;
        }
        return a.pairs[0..n];
    }

    /// What `Service.advertise` takes.
    pub fn desc(a: *Advert) ServiceDesc {
        return .{ .service_type = service_type, .instance = a.instance, .port = a.port, .txt = a.txt() };
    }
};

/// The schema fields read out of a `Resolved` event. A value: no pointer
/// into the event. The address and port stay in the `Resolved`.
pub const Parsed = struct {
    spki: [32]u8,
    sn: Bounded(u8, profiles.max_server_name_len),
    pat: ?u64,

    /// Checks `service_type`, `txtvers` and `alpn`; requires `spki` and
    /// `sn`; reads `pat` when present. Unknown keys are ignored.
    pub fn parse(resolved: *const Resolved) ParseError!Parsed {
        try profiles.checkServiceType(resolved, service_type);
        return parseTxt(&resolved.txt);
    }

    /// The TXT half of `parse`, for a TXT that did not arrive in a
    /// `Resolved` (a fixture, a config file).
    pub fn parseTxt(txt: *const Txt) ParseError!Parsed {
        try profiles.checkTxtVersion(txt);
        try profiles.checkFixed(txt, "alpn", alpn, error.AlpnMismatch);
        return .{
            .spki = try profiles.parseDigest(txt, "spki"),
            .sn = try profiles.parseServerName(txt),
            .pat = try profiles.parsePat(txt),
        };
    }
};

test "qmsg advert renders the schema in order" {
    var a = try Advert.init(.{ .instance = "alice", .port = 4433, .spki = @splat(0xab), .sn = "alice.example", .pat = 0x3 });
    const d = a.desc();
    try std.testing.expectEqualStrings(service_type, d.service_type);
    try std.testing.expectEqualStrings("alice", d.instance);
    try std.testing.expectEqual(@as(u16, 4433), d.port);
    try std.testing.expectEqual(@as(usize, 5), d.txt.len);
    try std.testing.expectEqualStrings("txtvers", d.txt[0].key);
    try std.testing.expectEqualStrings("1", d.txt[0].value.?);
    try std.testing.expectEqualStrings("alpn", d.txt[1].key);
    try std.testing.expectEqualStrings("qmsg/1", d.txt[1].value.?);
    try std.testing.expectEqualStrings("spki", d.txt[2].key);
    const spki_hex = profiles.digestHex(@splat(0xab));
    try std.testing.expectEqualStrings(&spki_hex, d.txt[2].value.?);
    try std.testing.expectEqualStrings("abababab", spki_hex[0..8]);
    try std.testing.expectEqualStrings("sn", d.txt[3].key);
    try std.testing.expectEqualStrings("alice.example", d.txt[3].value.?);
    try std.testing.expectEqualStrings("pat", d.txt[4].key);
    try std.testing.expectEqualStrings("0000000000000003", d.txt[4].value.?);
    a.setPat(null);
    try std.testing.expectEqual(@as(usize, 4), a.txt().len);
}

test "qmsg advert init validates" {
    const ok: Options = .{ .instance = "a", .port = 1, .spki = @splat(0), .sn = "s" };
    _ = try Advert.init(ok);
    var bad = ok;
    bad.instance = "";
    try std.testing.expectError(error.InvalidInstance, Advert.init(bad));
    bad = ok;
    bad.instance = "with\x01control";
    try std.testing.expectError(error.InvalidInstance, Advert.init(bad));
    bad = ok;
    bad.port = 0;
    try std.testing.expectError(error.InvalidPort, Advert.init(bad));
    bad = ok;
    bad.sn = "";
    try std.testing.expectError(error.InvalidServerName, Advert.init(bad));
    bad = ok;
    bad.sn = "has space";
    try std.testing.expectError(error.InvalidServerName, Advert.init(bad));
    const long: [profiles.max_server_name_len + 1]u8 = @splat('a');
    bad = ok;
    bad.sn = &long;
    try std.testing.expectError(error.InvalidServerName, Advert.init(bad));
    bad.sn = long[0..profiles.max_server_name_len];
    _ = try Advert.init(bad);
}
