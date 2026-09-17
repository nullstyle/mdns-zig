//! `_shared-studio._udp` (plan section 3.4): one shared-studio performer
//! or conductor, dialable over qmsg.
//!
//! TXT, in this order: `txtvers=1`, `alpn=qmsg/1`, `spki=<64 lowercase
//! hex>`, `epoch=<16 hex u64>`, `role=conductor|performer`,
//! `sn=shared-studio`, `clip=v2`.
//!
//! `spki` is the local certificate SPKI SHA-256 (`certificateSpki`);
//! `epoch` is `Config.epoch`, the process incarnation musical events carry.
//! A browser fills `Config.peer_host` / `peer_port` from the `Resolved`
//! (`dialAddress`, v0.1.1: ranked against the browser's own interface
//! table) and `expected_peer_spki` from `Parsed.spki`; the mTLS
//! handshake is the proof.
const std = @import("std");
const Io = std.Io;
const profiles = @import("root.zig");

const Txt = profiles.Txt;
const TxtPair = profiles.TxtPair;
const ServiceDesc = profiles.ServiceDesc;
const Resolved = profiles.Resolved;
const Interface = profiles.Interface;
const Preferred = profiles.Preferred;

pub const service_type = "_shared-studio._udp";
pub const alpn = "qmsg/1";
/// `Config.server_name` default; every studio peer dials with it.
pub const server_name = "shared-studio";
/// Clip snapshot format.
pub const clip = "v2";

pub const InitError = profiles.InitError;
pub const ParseError = profiles.ParseError;

pub const Role = enum {
    conductor,
    performer,

    /// The TXT value.
    pub fn label(r: Role) []const u8 {
        return switch (r) {
            .conductor => "conductor",
            .performer => "performer",
        };
    }

    /// Byte-exact match of a TXT value.
    pub fn parse(s: []const u8) ?Role {
        return std.meta.stringToEnum(Role, s);
    }
};

pub const Options = struct {
    /// Performer display name; one instance label, 1..63 octets.
    instance: []const u8,
    /// `listen_port` from `localAddress()` after bind.
    port: u16,
    spki: [32]u8,
    /// `Config.epoch`.
    epoch: u64,
    role: Role,
};

/// A validated advert with its TXT rendered into fixed buffers. `desc()`
/// and `txt()` return slices into `self`; keep the `Advert` in place while
/// they are in use. `Service.advertise` / `updateTxt` copy at the call.
pub const Advert = struct {
    instance: []const u8,
    port: u16,
    role: Role,
    spki_hex: [64]u8,
    epoch_hex: [16]u8,
    pairs: [max_pairs]TxtPair = undefined,

    pub const max_pairs = 7;

    pub fn init(opts: Options) InitError!Advert {
        try profiles.validateInstance(opts.instance);
        try profiles.validatePort(opts.port);
        return .{
            .instance = opts.instance,
            .port = opts.port,
            .role = opts.role,
            .spki_hex = profiles.digestHex(opts.spki),
            .epoch_hex = profiles.intHex(u64, opts.epoch),
        };
    }

    /// New incarnation; announce it with `Service.updateTxt(id,
    /// advert.txt())`.
    pub fn setEpoch(a: *Advert, epoch: u64) void {
        a.epoch_hex = profiles.intHex(u64, epoch);
    }

    pub fn setRole(a: *Advert, role: Role) void {
        a.role = role;
    }

    /// The TXT pairs in schema order, `txtvers=1` first.
    pub fn txt(a: *Advert) []const TxtPair {
        a.pairs = .{
            .{ .key = "txtvers", .value = profiles.txtvers },
            .{ .key = "alpn", .value = alpn },
            .{ .key = "spki", .value = &a.spki_hex },
            .{ .key = "epoch", .value = &a.epoch_hex },
            .{ .key = "role", .value = a.role.label() },
            .{ .key = "sn", .value = server_name },
            .{ .key = "clip", .value = clip },
        };
        return &a.pairs;
    }

    pub fn desc(a: *Advert) ServiceDesc {
        return .{ .service_type = service_type, .instance = a.instance, .port = a.port, .txt = a.txt() };
    }
};

/// The schema fields read out of a `Resolved` event. A value.
pub const Parsed = struct {
    spki: [32]u8,
    epoch: profiles.Epoch,
    role: Role,

    /// Checks `service_type`, `txtvers`, `alpn`, `sn` and `clip`;
    /// requires `spki`, `epoch` and `role`. Unknown keys are ignored.
    pub fn parse(resolved: *const Resolved) ParseError!Parsed {
        try profiles.checkServiceType(resolved, service_type);
        return parseTxt(&resolved.txt);
    }

    pub fn parseTxt(txt: *const Txt) ParseError!Parsed {
        try profiles.checkTxtVersion(txt);
        try profiles.checkFixed(txt, "alpn", alpn, error.AlpnMismatch);
        try profiles.checkFixed(txt, "sn", server_name, error.InvalidServerName);
        try profiles.checkFixed(txt, "clip", clip, error.FormatMismatch);
        const role_s = try profiles.require(txt, "role");
        return .{
            .spki = try profiles.parseDigest(txt, "spki"),
            .epoch = try profiles.parseEpoch(txt),
            .role = Role.parse(role_s) orelse return error.InvalidRole,
        };
    }
};

/// The address a studio peer is dialed at, with the SRV port:
/// `Resolved.preferred` against `local` (the browser's `Service.
/// interfaces()`, or `&.{}` for the table-less v4-first order), minus
/// link-local IPv6, which needs a `%zone` the qmsg endpoint parser
/// rejects. Returns the rank too, so a consumer keeping a ring of dial
/// candidates can order them best first and let a later `resolved`
/// (another interface of a multi-homed peer) supersede an earlier,
/// worse one: `candidate.betterThan(previous)` (the canonical
/// comparison; `AddrRank.better` is the raw with-table order only).
pub fn dialCandidate(resolved: *const Resolved, local: []const Interface) ?Preferred {
    const p = resolved.preferred(local) orelse return null;
    if (p.rank == .scoped_ll) return null;
    return p;
}

/// `dialCandidate` without the rank.
pub fn dialAddress(resolved: *const Resolved, local: []const Interface) ?Io.net.IpAddress {
    const p = dialCandidate(resolved, local) orelse return null;
    return p.addr;
}

test "studio advert renders the schema in order" {
    var a = try Advert.init(.{ .instance = "Alice", .port = 5000, .spki = @splat(0x01), .epoch = 0xfeed, .role = .conductor });
    const d = a.desc();
    try std.testing.expectEqualStrings(service_type, d.service_type);
    try std.testing.expectEqualStrings("Alice", d.instance);
    try std.testing.expectEqual(@as(usize, 7), d.txt.len);
    const keys = [_][]const u8{ "txtvers", "alpn", "spki", "epoch", "role", "sn", "clip" };
    for (keys, d.txt) |k, p| try std.testing.expectEqualStrings(k, p.key);
    try std.testing.expectEqualStrings("000000000000feed", d.txt[3].value.?);
    try std.testing.expectEqualStrings("conductor", d.txt[4].value.?);
    try std.testing.expectEqualStrings("shared-studio", d.txt[5].value.?);
    try std.testing.expectEqualStrings("v2", d.txt[6].value.?);
    a.setRole(.performer);
    a.setEpoch(1);
    const t = a.txt();
    try std.testing.expectEqualStrings("0000000000000001", t[3].value.?);
    try std.testing.expectEqualStrings("performer", t[4].value.?);
    try std.testing.expectError(error.InvalidInstance, Advert.init(.{ .instance = "", .port = 1, .spki = @splat(0), .epoch = 0, .role = .performer }));
    try std.testing.expectError(error.InvalidPort, Advert.init(.{ .instance = "a", .port = 0, .spki = @splat(0), .epoch = 0, .role = .performer }));
}
