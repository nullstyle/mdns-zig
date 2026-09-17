//! `_qmesh._udp` (plan section 3.4): one qmesh node as a seed contact.
//!
//! TXT, in this order: `txtvers=1`, `alpn=qmesh/2`, `fv=2`, `id=<64
//! lowercase hex PeerId>`, `epoch=<32 hex u128>`.
//!
//! `id` is the qmesh `PeerId` (SHA-256 of the leaf certificate SPKI, the
//! same bytes as qmsg `spki`). `epoch` is the node's `boot_epoch`; a node
//! that restarts advertises a new one through `Service.updateTxt`, the
//! browser gets a fresh `resolved`, and `SeedSet` admits the peer again.
//!
//! `SeedSet` is the browser-side glue of plan section 5, flow 2: it turns
//! `resolved` events into at most one `Contact` per `(id, epoch)` and
//! picks the address a qmesh `Addr` can carry. The `switch` into
//! `qmesh.Addr` lives in the consumer (plan section 11, decision 5), so
//! this file never imports qmesh.
const std = @import("std");
const Io = std.Io;
const profiles = @import("root.zig");

const Txt = profiles.Txt;
const TxtPair = profiles.TxtPair;
const ServiceDesc = profiles.ServiceDesc;
const Resolved = profiles.Resolved;

pub const service_type = "_qmesh._udp";
pub const alpn = "qmesh/2";
/// Frame version, `qmesh/2`.
pub const fv = "2";

pub const InitError = profiles.InitError;
pub const ParseError = profiles.ParseError;

pub const Options = struct {
    /// One instance label, or null for the first 16 hex digits of `id`
    /// (plan section 3.4: "first 16 hex of PeerId or host").
    instance: ?[]const u8 = null,
    /// `Runner.localAddress()` port.
    port: u16,
    /// `PeerId.bytes`.
    id: [32]u8,
    /// `Endpoint.Options.boot_epoch`.
    epoch: u128,
};

/// A validated advert with its TXT rendered into fixed buffers. `desc()`
/// and `txt()` return slices into `self`; keep the `Advert` in place while
/// they are in use. `Service.advertise` / `updateTxt` copy at the call.
pub const Advert = struct {
    instance: ?[]const u8,
    port: u16,
    id_hex: [64]u8,
    epoch_hex: [32]u8,
    pairs: [max_pairs]TxtPair = undefined,

    pub const max_pairs = 5;
    /// Instance label length when derived from `id`.
    pub const derived_instance_len = 16;

    pub fn init(opts: Options) InitError!Advert {
        if (opts.instance) |i| try profiles.validateInstance(i);
        try profiles.validatePort(opts.port);
        return .{
            .instance = opts.instance,
            .port = opts.port,
            .id_hex = profiles.digestHex(opts.id),
            .epoch_hex = profiles.intHex(u128, opts.epoch),
        };
    }

    /// New `boot_epoch`; announce it with `Service.updateTxt(id,
    /// advert.txt())` (RFC 6762 section 8.4: re-announce, no probe).
    pub fn setEpoch(a: *Advert, epoch: u128) void {
        a.epoch_hex = profiles.intHex(u128, epoch);
    }

    /// The instance label `desc()` uses: the explicit one or the first 16
    /// hex digits of `id`.
    pub fn instanceLabel(a: *const Advert) []const u8 {
        return a.instance orelse a.id_hex[0..derived_instance_len];
    }

    /// The TXT pairs in schema order, `txtvers=1` first.
    pub fn txt(a: *Advert) []const TxtPair {
        a.pairs = .{
            .{ .key = "txtvers", .value = profiles.txtvers },
            .{ .key = "alpn", .value = alpn },
            .{ .key = "fv", .value = fv },
            .{ .key = "id", .value = &a.id_hex },
            .{ .key = "epoch", .value = &a.epoch_hex },
        };
        return &a.pairs;
    }

    pub fn desc(a: *Advert) ServiceDesc {
        return .{ .service_type = service_type, .instance = a.instanceLabel(), .port = a.port, .txt = a.txt() };
    }
};

/// The schema fields read out of a `Resolved` event. A value.
pub const Parsed = struct {
    id: [32]u8,
    epoch: profiles.Epoch,

    /// Checks `service_type`, `txtvers`, `alpn` and `fv`; requires `id`
    /// and `epoch`. Unknown keys are ignored.
    pub fn parse(resolved: *const Resolved) ParseError!Parsed {
        try profiles.checkServiceType(resolved, service_type);
        return parseTxt(&resolved.txt);
    }

    pub fn parseTxt(txt: *const Txt) ParseError!Parsed {
        try profiles.checkTxtVersion(txt);
        try profiles.checkFixed(txt, "alpn", alpn, error.AlpnMismatch);
        try profiles.checkFixed(txt, "fv", fv, error.FormatMismatch);
        return .{
            .id = try profiles.parseDigest(txt, "id"),
            .epoch = try profiles.parseEpoch(txt),
        };
    }
};

/// One seed to hand to `Endpoint.startJoin`. `addr` carries
/// `resolved.port`; a link-local v6 `addr` carries its scope in
/// `.ip6.interface`.
pub const Contact = struct {
    id: [32]u8,
    epoch: u128,
    addr: Io.net.IpAddress,
    /// The interface the `resolved` was heard on.
    ifindex: u32,
};

/// The address a qmesh `Addr` (no scope field) can dial, from
/// `resolved.addrs`, in this preference order:
///
/// 1. the first IPv4 address (not `0.0.0.0`);
/// 2. else the first IPv6 address outside `fe80::/10` (global or ULA, not
///    `::`);
/// 3. else the first link-local IPv6 address whose scope is set
///    (`.ip6.interface.index != 0`); a `fe80::` address without a scope
///    is never returned, because nothing can dial it.
///
/// IPv4 first: every consumer parses a plain literal, a v4 address on the
/// link is always reachable, and v6 global addresses rotate (privacy
/// extensions) more often than the TTL of the AAAA record. The port is
/// `resolved.port`.
pub fn pickAddr(resolved: *const Resolved) ?Io.net.IpAddress {
    const port = resolved.port;
    const addrs = resolved.addrs.slice();
    for (addrs) |a| {
        if (a == .ip4 and !std.mem.allEqual(u8, &a.ip4.bytes, 0)) {
            return .{ .ip4 = .{ .bytes = a.ip4.bytes, .port = port } };
        }
    }
    for (addrs) |a| {
        if (a == .ip6 and !isLinkLocal6(a.ip6.bytes) and !std.mem.allEqual(u8, &a.ip6.bytes, 0)) {
            return .{ .ip6 = .{ .bytes = a.ip6.bytes, .port = port, .interface = a.ip6.interface } };
        }
    }
    for (addrs) |a| {
        if (a == .ip6 and isLinkLocal6(a.ip6.bytes) and a.ip6.interface.index != 0) {
            return .{ .ip6 = .{ .bytes = a.ip6.bytes, .port = port, .interface = a.ip6.interface } };
        }
    }
    return null;
}

/// `fe80::/10` (RFC 4291 section 2.5.6); local copy so this file needs
/// only the value types.
pub fn isLinkLocal6(addr: [16]u8) bool {
    return addr[0] == 0xfe and (addr[1] & 0xc0) == 0x80;
}

/// Counters a consumer can log.
pub const SeedStats = struct {
    /// `resolved` values that were not a valid `_qmesh._udp` advert.
    rejected: u64 = 0,
    /// Valid adverts with no dialable address.
    no_addr: u64 = 0,
    /// Valid adverts already admitted under the same `(id, epoch)`.
    duplicates: u64 = 0,
    /// Entries forgotten because the set was full.
    evicted: u64 = 0,
};

/// Fixed-capacity admission set over `(id, epoch)`. `.{}` is the empty
/// set; no allocation, no `deinit`.
pub fn SeedSetSized(comptime cap: usize) type {
    return struct {
        const Self = @This();

        pub const capacity = cap;

        entries: [cap]Entry = undefined,
        len: usize = 0,
        /// Admission counter: each entry carries the value it was
        /// admitted at, so a full set evicts the entry admitted longest
        /// ago even after `forget` reordered the array.
        seq: u64 = 0,
        stats: SeedStats = .{},

        pub const Entry = struct { id: [32]u8, epoch: u128, seq: u64 };

        /// One `Contact` per `(id, epoch)`. Returns null for an invalid
        /// advert, for an advert with no dialable address (see
        /// `pickAddr`), and for a pair already admitted. A `resolved`
        /// re-emitted with a new `epoch` passes again; one re-emitted for
        /// an address or SRV change under the same epoch does not.
        pub fn accept(s: *Self, resolved: *const Resolved) ?Contact {
            const p = Parsed.parse(resolved) catch {
                s.stats.rejected += 1;
                return null;
            };
            const addr = pickAddr(resolved) orelse {
                s.stats.no_addr += 1;
                return null;
            };
            if (s.contains(p.id, p.epoch.value)) {
                s.stats.duplicates += 1;
                return null;
            }
            s.insert(p.id, p.epoch.value);
            return .{ .id = p.id, .epoch = p.epoch.value, .addr = addr, .ifindex = resolved.ifindex };
        }

        pub fn contains(s: *const Self, id: [32]u8, epoch: u128) bool {
            for (s.entries[0..s.len]) |e| {
                if (e.epoch == epoch and std.mem.eql(u8, &e.id, &id)) return true;
            }
            return false;
        }

        /// Forget every `(id, *)` so the peer is admitted again at its
        /// next `resolved`. Returns the number of entries removed.
        pub fn forget(s: *Self, id: [32]u8) usize {
            var removed: usize = 0;
            var i: usize = 0;
            while (i < s.len) {
                if (std.mem.eql(u8, &s.entries[i].id, &id)) {
                    s.len -= 1;
                    s.entries[i] = s.entries[s.len];
                    removed += 1;
                } else {
                    i += 1;
                }
            }
            return removed;
        }

        pub fn clear(s: *Self) void {
            s.len = 0;
        }

        /// Append while there is room; when full, overwrite the entry
        /// admitted longest ago (smallest `seq`, one pass over at most
        /// `cap` entries).
        fn insert(s: *Self, id: [32]u8, epoch: u128) void {
            const entry: Entry = .{ .id = id, .epoch = epoch, .seq = s.seq };
            s.seq += 1;
            if (s.len < cap) {
                s.entries[s.len] = entry;
                s.len += 1;
                return;
            }
            var oldest: usize = 0;
            for (s.entries[1..s.len], 1..) |e, i| {
                if (e.seq < s.entries[oldest].seq) oldest = i;
            }
            s.entries[oldest] = entry;
            s.stats.evicted += 1;
        }
    };
}

/// The default set: 64 `(id, epoch, seq)` entries, 4 KiB.
pub const SeedSet = SeedSetSized(64);

test "qmesh advert derives the instance from the id" {
    var id: [32]u8 = @splat(0);
    id[0] = 0x0a;
    id[1] = 0xbc;
    var a = try Advert.init(.{ .port = 4433, .id = id, .epoch = 7 });
    const d = a.desc();
    try std.testing.expectEqualStrings("0abc000000000000", d.instance);
    try std.testing.expectEqual(@as(usize, 5), d.txt.len);
    try std.testing.expectEqualStrings("fv", d.txt[2].key);
    try std.testing.expectEqualStrings("2", d.txt[2].value.?);
    try std.testing.expectEqualStrings("epoch", d.txt[4].key);
    try std.testing.expectEqualStrings("00000000000000000000000000000007", d.txt[4].value.?);
    a.setEpoch(0x10);
    try std.testing.expectEqualStrings("00000000000000000000000000000010", a.txt()[4].value.?);
    var named = try Advert.init(.{ .instance = "node-a", .port = 1, .id = id, .epoch = 0 });
    try std.testing.expectEqualStrings("node-a", named.desc().instance);
    try std.testing.expectError(error.InvalidInstance, Advert.init(.{ .instance = "", .port = 1, .id = id, .epoch = 0 }));
    try std.testing.expectError(error.InvalidPort, Advert.init(.{ .port = 0, .id = id, .epoch = 0 }));
}

test "SeedSet ring evicts the oldest when full" {
    var s: SeedSetSized(2) = .{};
    try std.testing.expect(!s.contains(@splat(1), 0));
    s.insert(@splat(1), 0);
    s.insert(@splat(2), 0);
    s.insert(@splat(3), 0);
    try std.testing.expect(!s.contains(@splat(1), 0));
    try std.testing.expect(s.contains(@splat(2), 0));
    try std.testing.expect(s.contains(@splat(3), 0));
    try std.testing.expectEqual(@as(u64, 1), s.stats.evicted);
    try std.testing.expectEqual(@as(usize, 1), s.forget(@splat(2)));
    try std.testing.expect(!s.contains(@splat(2), 0));
    try std.testing.expectEqual(@as(usize, 1), s.len);
    // After a forget the set refills, and the next eviction still takes
    // the entry admitted longest ago (3), not the newest (4). (A ring
    // cursor left where it was by the swap-remove took the newest.)
    s.insert(@splat(4), 0);
    try std.testing.expectEqual(@as(usize, 2), s.len);
    s.insert(@splat(5), 0);
    try std.testing.expect(!s.contains(@splat(3), 0));
    try std.testing.expect(s.contains(@splat(4), 0));
    try std.testing.expect(s.contains(@splat(5), 0));
    try std.testing.expectEqual(@as(u64, 2), s.stats.evicted);
    // Forgetting the oldest and refilling: the survivor is the older of
    // the two that remain.
    try std.testing.expectEqual(@as(usize, 1), s.forget(@splat(4)));
    s.insert(@splat(6), 0);
    s.insert(@splat(7), 0);
    try std.testing.expect(!s.contains(@splat(5), 0));
    try std.testing.expect(s.contains(@splat(6), 0));
    try std.testing.expect(s.contains(@splat(7), 0));
    s.clear();
    try std.testing.expectEqual(@as(usize, 0), s.len);
    try std.testing.expect(!s.contains(@splat(7), 0));
}
