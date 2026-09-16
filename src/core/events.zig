//! Public value types (plan section 5): `Event`, `Warning`, `Resolved`,
//! `Interface`, `Limits`, `Stats` and friends, plus the drop-oldest
//! `EventQueue` the Engine (and the Service, for its own warnings) queues
//! events in (plan section 4.5, section 6).
//!
//! Every type here that crosses the Engine boundary as an event is a
//! fixed-size value with no pointers or slices into Engine state: copying
//! an `Event` copies everything it refers to, so a consumer may hold it
//! for any length of time and hand it to another thread by value (plan
//! section 4.7). `assertPointerFree` checks that at comptime; the M3
//! Engine must keep it true when it fills in the remaining payloads.
//!
//! `ServiceDesc` and `TxtPair` are *input* types (the caller passes
//! slices in); they are not events and carry no pointer-free guarantee.
const std = @import("std");
const Io = std.Io;
const wire = @import("../wire/root.zig");

// ---- re-exports from the codec ---------------------------------------
//
// `Bounded` lives in `wire/bounded.zig` (Revision 4 item 2) because the
// codec needs it and the codec must not depend on the core. `events` is
// its public home.

/// Fixed-capacity inline array: the value type behind names, TXT and the
/// `Interface` address lists.
pub const Bounded = wire.Bounded;

/// A wire-form DNS name, at most 255 octets. The codec's `Name` is a
/// fixed-size value (`len` + `[255]u8`) that is always well-formed, so it
/// serves as the plan's `Bounded(u8, 255)` name type.
pub const Name = wire.Name;

/// Owned TXT rdata over a `Bounded(u8, 400)` with case-insensitive `get`
/// and `iterate` (RFC 6763 section 6).
pub const Txt = wire.Txt;

/// One TXT attribute as the caller writes it: `value == null` is a boolean
/// attribute.
pub const TxtPair = wire.TxtPair;

// ---- addresses and interfaces ----------------------------------------

/// One IPv4 address with its on-link prefix (RFC 6762 section 11).
pub const Prefix4 = struct {
    addr: [4]u8,
    prefix_len: u8,

    /// `(I & M) == (P & M)` with `M` the prefix mask (section 11).
    pub fn contains(p: Prefix4, ip: [4]u8) bool {
        return prefixEql(&p.addr, &ip, p.prefix_len);
    }
};

/// One IPv6 address with its on-link prefix. Link-local (`fe80::/10`)
/// entries carry the interface's `index` as their scope; the address bytes
/// never embed it.
pub const Prefix6 = struct {
    addr: [16]u8,
    prefix_len: u8,

    pub fn contains(p: Prefix6, ip: [16]u8) bool {
        return prefixEql(&p.addr, &ip, p.prefix_len);
    }

    /// `fe80::/10` (RFC 4291 section 2.5.6).
    pub fn isLinkLocal(p: Prefix6) bool {
        return isLinkLocal6(p.addr);
    }
};

/// True when `addr` is in `fe80::/10`.
pub fn isLinkLocal6(addr: [16]u8) bool {
    return addr[0] == 0xfe and (addr[1] & 0xc0) == 0x80;
}

/// Compare the first `prefix_len` bits of two equal-length byte arrays.
/// A `prefix_len` beyond the array width compares the whole array.
pub fn prefixEql(a: []const u8, b: []const u8, prefix_len: u8) bool {
    std.debug.assert(a.len == b.len);
    const total_bits = a.len * 8;
    const bits: usize = @min(@as(usize, prefix_len), total_bits);
    const full = bits / 8;
    if (!std.mem.eql(u8, a[0..full], b[0..full])) return false;
    const rem: u3 = @intCast(bits % 8);
    if (rem == 0) return true;
    const mask: u8 = @as(u8, 0xff) << @intCast(8 - @as(u4, rem));
    return (a[full] & mask) == (b[full] & mask);
}

/// Maximum kept addresses per family per interface (plan section 4.8,
/// "Address overflow per interface").
pub const max_addrs_per_family = 8;

/// `IFNAMSIZ - 1`: the longest interface name without its terminator.
pub const max_iface_name_len = 15;

/// One network interface as `ifaces.zig` reports it and as the Engine
/// keeps it (plan section 4.8, "Interface model"). All addresses that were
/// up and multicast-capable on that interface, at most 8 per family; the
/// overflow is counted, not silently lost.
pub const Interface = struct {
    /// Kernel interface index (`if_nametoindex`); what the cmsg codec and
    /// `Ip6Address.interface` carry.
    index: u32,
    name: Bounded(u8, max_iface_name_len) = .{},
    v4: Bounded(Prefix4, max_addrs_per_family) = .{},
    /// Global (and ULA) addresses first, link-local last.
    v6: Bounded(Prefix6, max_addrs_per_family) = .{},
    /// Addresses over the 8 cap that `ifaces.zig` did not keep.
    /// `Engine.setInterfaces` sums them into `stats.addrs_dropped`.
    v4_dropped: u8 = 0,
    v6_dropped: u8 = 0,

    /// True when `ip` is one of this interface's own addresses.
    pub fn hasAddr4(i: *const Interface, ip: [4]u8) bool {
        for (i.v4.slice()) |p| if (std.mem.eql(u8, &p.addr, &ip)) return true;
        return false;
    }

    pub fn hasAddr6(i: *const Interface, ip: [16]u8) bool {
        for (i.v6.slice()) |p| if (std.mem.eql(u8, &p.addr, &ip)) return true;
        return false;
    }

    /// RFC 6762 section 11 on-link test against the kept prefixes.
    pub fn onLink4(i: *const Interface, ip: [4]u8) bool {
        for (i.v4.slice()) |p| if (p.contains(ip)) return true;
        return false;
    }

    pub fn onLink6(i: *const Interface, ip: [16]u8) bool {
        for (i.v6.slice()) |p| if (p.contains(ip)) return true;
        return false;
    }

    /// Same address set (order-insensitive), ignoring name and drop counts.
    pub fn sameAddrs(a: *const Interface, b: *const Interface) bool {
        if (a.v4.len != b.v4.len or a.v6.len != b.v6.len) return false;
        for (a.v4.slice()) |p| {
            if (!containsPrefix4(b.v4.slice(), p)) return false;
        }
        for (a.v6.slice()) |p| {
            if (!containsPrefix6(b.v6.slice(), p)) return false;
        }
        return true;
    }

    fn containsPrefix4(list: []const Prefix4, p: Prefix4) bool {
        for (list) |q| if (q.prefix_len == p.prefix_len and std.mem.eql(u8, &q.addr, &p.addr)) return true;
        return false;
    }

    fn containsPrefix6(list: []const Prefix6, p: Prefix6) bool {
        for (list) |q| if (q.prefix_len == p.prefix_len and std.mem.eql(u8, &q.addr, &p.addr)) return true;
        return false;
    }
};

// ---- registration and browse inputs ----------------------------------

/// What `advertise` takes. An input type: the slices are the caller's and
/// are copied at the call.
pub const ServiceDesc = struct {
    /// `_qmsg._udp` form (RFC 6763 section 7; RFC 6335 names).
    service_type: []const u8,
    /// One raw label, at most 63 octets (RFC 6763 section 4.1.1).
    instance: []const u8,
    port: u16,
    txt: []const TxtPair = &.{},
};

/// A registration handle. Values are Engine-private; `_` keeps consumers
/// from inventing one.
pub const RegId = enum(u8) { _ };

/// A browse handle.
pub const BrowseId = enum(u8) { _ };

/// Address family, as `Warning` payloads and `ifaces.zig` name it.
pub const Family = enum(u8) {
    v4,
    v6,

    pub fn fromIp(f: Io.net.IpAddress.Family) Family {
        return switch (f) {
            .ip4 => .v4,
            .ip6 => .v6,
        };
    }
};

// ---- events ----------------------------------------------------------

/// A fully resolved service instance (plan section 5, "resolved re-emit
/// rule").
pub const Resolved = struct {
    instance: Name,
    service_type: Name,
    host: Name,
    port: u16,
    /// `fe80::` entries carry `.ip6.interface = arrival ifindex`.
    addrs: Bounded(Io.net.IpAddress, max_addrs_per_family) = .{},
    txt: Txt = .{},
    ifindex: u32,
    /// Shortest remaining TTL among the SRV, TXT, A and AAAA records that
    /// built this value.
    ttl_s: u32,
};

/// Non-fatal conditions (plan section 4.6, "Degrade"). Every payload is a
/// value.
pub const Warning = union(enum) {
    /// The v6 socket could not be bound; v4 continues.
    v6_unavailable: void,
    /// One multicast join failed; init still succeeds. `ifindex` and
    /// `family` let an operator name the interface.
    join_failed: JoinFailed,
    /// Allow-list set and zero interfaces joined at init;
    /// `refreshInterfaces` retries when they appear.
    no_interfaces: void,
    /// More than 8 (or more than `max_addrs_per_iface`) addresses of that
    /// family on that interface; the extra ones are not advertised.
    addrs_truncated: AddrsTruncated,
    /// A browse saw zero packets and zero errors for 10 s (macOS Local
    /// Network privacy signature: `tx > 0`, `rx == 0`).
    no_packets_10s: void,
    /// The Engine ring or the `Mailbox` dropped at least one event.
    events_dropped: void,

    pub const JoinFailed = struct { ifindex: u32, family: Family };
    pub const AddrsTruncated = struct { ifindex: u32, family: Family };
};

/// What `pollEvent` / `Service.poll` / `Mailbox.next` deliver.
pub const Event = union(enum) {
    /// A PTR for a service type with an active browse (only those).
    found: Found,
    lost: Lost,
    /// First full resolve; again when SRV, TXT or the address set changes;
    /// never for a same-data refresh.
    resolved: Resolved,
    /// Probing succeeded; the name is ours.
    registered: Registered,
    /// A probe conflict renamed the instance (`Name (2)`).
    renamed: Renamed,
    /// A host-name conflict renamed the host (`<label>-2.local`).
    host_renamed: HostRenamed,
    /// `setInterfaces` changed the interface table.
    interfaces_changed: void,
    warning: Warning,

    pub const Found = struct { instance: Name, service_type: Name, ifindex: u32 };
    pub const Lost = struct { instance: Name, service_type: Name, ifindex: u32 };
    pub const Registered = struct { id: RegId, instance: Name };
    pub const Renamed = struct { id: RegId, old: Name, new: Name };
    pub const HostRenamed = struct { old: Name, new: Name };
};

/// Pool sizes `Engine.init` preallocates (plan section 4.5).
pub const Limits = struct {
    max_cache_records: u32 = 4096,
    max_registrations: u16 = 32,
    max_browses: u16 = 16,
    max_pending_answers: u16 = 256,
    max_events: u16 = 64,
    max_interfaces: u8 = 32,
};

/// Counters (plan section 5). Every field is monotonic since `init`.
pub const Stats = struct {
    rx: u64 = 0,
    tx: u64 = 0,
    tx_dropped: u64 = 0,
    dropped_malformed: u64 = 0,
    dropped_bad_port: u64 = 0,
    dropped_off_link: u64 = 0,
    conflicts: u64 = 0,
    evictions: u64 = 0,
    events_dropped: u64 = 0,
    answers_dropped: u64 = 0,
    txt_truncated: u64 = 0,
    /// `Interface.v4_dropped + v6_dropped` (8 cap in `ifaces.zig`) plus
    /// `max_addrs_per_iface` drops, summed by `setInterfaces`.
    addrs_dropped: u64 = 0,
};

// ---- pointer-free check ----------------------------------------------

/// Comptime walk of `T`: fails compilation if any reachable field is a
/// pointer, slice, function, opaque or frame. Enums, ints, floats, bools,
/// void, arrays, vectors, optionals, structs and unions (tagged or not)
/// pass. Every event type below is checked in `comptime` so a later edit
/// cannot smuggle a slice into an `Event`.
pub fn assertPointerFree(comptime T: type) void {
    comptime {
        if (!isPointerFree(T)) {
            @compileError("type " ++ @typeName(T) ++ " is not pointer-free");
        }
    }
}

/// The predicate behind `assertPointerFree`. Comptime only.
pub fn isPointerFree(comptime T: type) bool {
    comptime return switch (@typeInfo(T)) {
        .int, .float, .bool, .void, .@"enum", .enum_literal, .error_set => true,
        .array => |a| isPointerFree(a.child),
        .vector => |v| isPointerFree(v.child),
        .optional => |o| isPointerFree(o.child),
        .error_union => |e| isPointerFree(e.payload),
        // This pin's `@typeInfo` carries `field_types` (not a `fields`
        // slice of structs) for structs and unions.
        .@"struct" => |s| blk: {
            for (s.field_types) |F| if (!isPointerFree(F)) break :blk false;
            break :blk true;
        },
        .@"union" => |u| blk: {
            for (u.field_types) |F| if (!isPointerFree(F)) break :blk false;
            break :blk true;
        },
        // Pointers, slices, functions, opaques, frames and anything the
        // pin adds later (its `@typeInfo` union grows: `spirv` on
        // dev.1786) are rejected, not silently accepted.
        else => false,
    };
}

comptime {
    assertPointerFree(Event);
    assertPointerFree(Warning);
    assertPointerFree(Resolved);
    assertPointerFree(Interface);
    assertPointerFree(Limits);
    assertPointerFree(Stats);
}

// ---- event ring ------------------------------------------------------

/// Drop-oldest FIFO of events over a caller-owned slice (plan section
/// 4.5): the capacity comes from `Limits.max_events` at init, so the
/// storage is runtime-sized but allocated once. `push` never fails and
/// never blocks; when the ring is full it discards the oldest event,
/// counts it in `dropped` and reports the drop, and the Engine bumps
/// `stats.events_dropped` and emits `warning.events_dropped` once.
pub const EventQueue = struct {
    buf: []Event,
    head: usize = 0,
    len: usize = 0,
    /// Events discarded by `push` since init. Monotonic.
    dropped: u64 = 0,

    /// Append `ev`; if the ring is full, the oldest event is dropped
    /// first. Returns true when a drop happened.
    pub fn push(r: *EventQueue, ev: Event) bool {
        var did_drop = false;
        if (r.len == r.buf.len) {
            r.head = (r.head + 1) % r.buf.len;
            r.len -= 1;
            r.dropped += 1;
            did_drop = true;
        }
        r.buf[(r.head + r.len) % r.buf.len] = ev;
        r.len += 1;
        return did_drop;
    }

    /// Oldest event, or null when empty.
    pub fn pop(r: *EventQueue) ?Event {
        if (r.len == 0) return null;
        const ev = r.buf[r.head];
        r.head = (r.head + 1) % r.buf.len;
        r.len -= 1;
        return ev;
    }

    pub fn count(r: *const EventQueue) usize {
        return r.len;
    }

    pub fn isEmpty(r: *const EventQueue) bool {
        return r.len == 0;
    }

    pub fn isFull(r: *const EventQueue) bool {
        return r.len == r.buf.len;
    }

    pub fn clear(r: *EventQueue) void {
        r.head = 0;
        r.len = 0;
    }
};

// ---- tests -----------------------------------------------------------

const testing = std.testing;

test "events are pointer-free values" {
    // The comptime block above already fails the build if these regress;
    // this test makes the property visible in the test list and checks
    // the predicate itself in both directions.
    try testing.expect(comptime isPointerFree(Event));
    try testing.expect(comptime isPointerFree(Warning));
    try testing.expect(comptime isPointerFree(Resolved));
    try testing.expect(comptime isPointerFree(Interface));
    try testing.expect(comptime isPointerFree(Stats));
    try testing.expect(comptime isPointerFree(Limits));
    try testing.expect(comptime isPointerFree(Io.net.IpAddress));
    // Input types carry slices and must be rejected.
    try testing.expect(comptime !isPointerFree(ServiceDesc));
    try testing.expect(comptime !isPointerFree(TxtPair));
    try testing.expect(comptime !isPointerFree([]const u8));
    try testing.expect(comptime !isPointerFree(*u8));
    try testing.expect(comptime !isPointerFree(struct { a: u8, b: ?*const u8 }));
    try testing.expect(comptime !isPointerFree(union(enum) { a: u8, b: [2][]const u8 }));
    try testing.expect(comptime isPointerFree(struct { a: [3]u8, b: ?u32, c: enum { x }, d: union { p: u8, q: bool } }));
}

test "event ring drops oldest and counts" {
    // The ring the Engine and the Service ship: `EventQueue` over a
    // caller-owned buffer (here 3 slots).
    var storage: [3]Event = undefined;
    var ring: EventQueue = .{ .buf = &storage };
    try testing.expect(ring.isEmpty());
    try testing.expectEqual(null, ring.pop());
    try testing.expect(!ring.push(.{ .warning = .{ .join_failed = .{ .ifindex = 1, .family = .v4 } } }));
    try testing.expect(!ring.push(.{ .warning = .{ .join_failed = .{ .ifindex = 2, .family = .v6 } } }));
    try testing.expect(!ring.push(.interfaces_changed));
    try testing.expect(ring.isFull());
    try testing.expectEqual(@as(u64, 0), ring.dropped);
    // Fourth push evicts ifindex 1.
    try testing.expect(ring.push(.{ .warning = .events_dropped }));
    try testing.expectEqual(@as(u64, 1), ring.dropped);
    try testing.expectEqual(@as(usize, 3), ring.count());
    const first = ring.pop().?;
    try testing.expectEqual(@as(u32, 2), first.warning.join_failed.ifindex);
    try testing.expectEqual(Family.v6, first.warning.join_failed.family);
    try testing.expectEqual(Event.interfaces_changed, ring.pop().?);
    try testing.expectEqual(Warning.events_dropped, ring.pop().?.warning);
    try testing.expectEqual(null, ring.pop());
    // Wrap around many times; the counter is monotonic.
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        _ = ring.push(.{ .warning = .{ .addrs_truncated = .{ .ifindex = i, .family = .v4 } } });
    }
    try testing.expectEqual(@as(u64, 8), ring.dropped);
    try testing.expectEqual(@as(u32, 7), ring.pop().?.warning.addrs_truncated.ifindex);
    try testing.expectEqual(@as(u32, 8), ring.pop().?.warning.addrs_truncated.ifindex);
    try testing.expectEqual(@as(u32, 9), ring.pop().?.warning.addrs_truncated.ifindex);
    try testing.expect(ring.isEmpty());
}

test "prefix compare and on-link helpers" {
    const p4: Prefix4 = .{ .addr = .{ 192, 168, 1, 10 }, .prefix_len = 24 };
    try testing.expect(p4.contains(.{ 192, 168, 1, 200 }));
    try testing.expect(!p4.contains(.{ 192, 168, 2, 200 }));
    const p4b: Prefix4 = .{ .addr = .{ 10, 0, 0, 1 }, .prefix_len = 30 };
    try testing.expect(p4b.contains(.{ 10, 0, 0, 3 }));
    try testing.expect(!p4b.contains(.{ 10, 0, 0, 4 }));
    const host: Prefix4 = .{ .addr = .{ 10, 0, 0, 1 }, .prefix_len = 32 };
    try testing.expect(host.contains(.{ 10, 0, 0, 1 }));
    try testing.expect(!host.contains(.{ 10, 0, 0, 2 }));
    // prefix_len past the width behaves like the full width.
    try testing.expect(prefixEql(&.{ 1, 2 }, &.{ 1, 2 }, 200));
    try testing.expect(!prefixEql(&.{ 1, 2 }, &.{ 1, 3 }, 200));
    // /0 matches everything.
    try testing.expect(prefixEql(&.{ 1, 2 }, &.{ 9, 9 }, 0));

    var ll: [16]u8 = @splat(0);
    ll[0] = 0xfe;
    ll[1] = 0x80;
    ll[15] = 1;
    try testing.expect(isLinkLocal6(ll));
    ll[1] = 0xbf;
    try testing.expect(isLinkLocal6(ll));
    ll[1] = 0xc0;
    try testing.expect(!isLinkLocal6(ll));
    var g: [16]u8 = @splat(0);
    g[0] = 0x20;
    g[1] = 0x01;
    try testing.expect(!isLinkLocal6(g));

    var iface: Interface = .{ .index = 7 };
    try iface.v4.append(p4);
    try iface.v6.append(.{ .addr = g, .prefix_len = 64 });
    try testing.expect(iface.hasAddr4(.{ 192, 168, 1, 10 }));
    try testing.expect(!iface.hasAddr4(.{ 192, 168, 1, 11 }));
    try testing.expect(iface.onLink4(.{ 192, 168, 1, 11 }));
    try testing.expect(!iface.onLink4(.{ 172, 16, 0, 1 }));
    var g2 = g;
    g2[15] = 0x42;
    try testing.expect(iface.onLink6(g2));
    try testing.expect(!iface.hasAddr6(g2));
    try testing.expect(iface.hasAddr6(g));

    var other: Interface = .{ .index = 7 };
    try other.v6.append(.{ .addr = g, .prefix_len = 64 });
    try other.v4.append(p4);
    try testing.expect(iface.sameAddrs(&other));
    try other.v4.append(host);
    try testing.expect(!iface.sameAddrs(&other));
}
