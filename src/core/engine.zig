//! Engine: the sans-IO core behind `Service` (plan section 4.2).
//!
//! ---------------------------------------------------------------------
//! M2 STUB. The public surface below is the plan section 5 `Engine`
//! contract and is what M3/M4 keep; only the internals are placeholders.
//! What the stub does:
//!   - `setInterfaces` stores the table, applies `max_addrs_per_iface`,
//!     sums the drops into `stats.addrs_dropped`, emits
//!     `warning.addrs_truncated` and `.interfaces_changed`.
//!   - `handle` counts `rx`, parses with `wire.Message.parse`
//!     (`dropped_malformed` on error) and drops QR=1 responses from a
//!     source port other than 5353 (`dropped_bad_port`, RFC 6762
//!     section 6). Nothing is cached.
//!   - `tick` schedules one PTR query for `_services._dns-sd._udp.local`
//!     every `stub_query_interval_us` (2 s) per interface per family, so
//!     the live tests see traffic ("echo a fixed PTR query").
//!   - `pollDatagram` builds that query with `wire.Builder` (QM, ID 0)
//!     to 224.0.0.251:5353 or [ff02::fb]:5353 with the interface index.
//!   - `advertise`, `updateTxt` and `browse` return `error.NotImplemented`
//!     (a temporary member of their error sets); `withdraw` and
//!     `stopBrowse` are no-ops.
//! M3 (querier, cache) and M4 (responder) replace the internals and
//! remove `error.NotImplemented`.
//! ---------------------------------------------------------------------
//!
//! Contract (plan section 4.2): `handle` never returns an error and never
//! allocates; `tick` fires due timers; `pollDatagram` drains outbound into
//! the caller's buffer; `nextDeadline` returns the next timer;
//! `pollEvent` returns a value-type event. `now_us` is `u64` microseconds
//! from a caller-owned origin. This file never imports `platform`.
const std = @import("std");
const Io = std.Io;
const wire = @import("../wire/root.zig");
const events = @import("events.zig");

pub const Event = events.Event;
pub const Warning = events.Warning;
pub const Interface = events.Interface;
pub const Limits = events.Limits;
pub const Stats = events.Stats;
pub const ServiceDesc = events.ServiceDesc;
pub const TxtPair = events.TxtPair;
pub const RegId = events.RegId;
pub const BrowseId = events.BrowseId;
pub const Family = events.Family;

/// mDNS port (RFC 6762 section 2); the Engine only knows it for the
/// source-port rule and for the destination of its own queries.
pub const mdns_port: u16 = 5353;
pub const group_v4: [4]u8 = .{ 224, 0, 0, 251 };
pub const group_v6: [16]u8 = .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb };

/// Longest host label (one DNS label, RFC 1035 section 2.3.4).
pub const max_host_label_len = 63;

pub const Engine = struct {
    pub const Options = struct {
        /// First label of our host name (`<host_label>.local`).
        host_label: []const u8,
        /// Every RFC jitter draws from it.
        random: std.Random,
        limits: Limits = .{},
        /// False when the port is shared (`first_binder == false`): our
        /// queries never set QU (plan section 4.8, "Port sharing").
        qu_allowed: bool = true,
        /// Per family, at most 8. `setInterfaces` drops extra addresses,
        /// counts them and warns once per call.
        max_addrs_per_iface: u8 = events.max_addrs_per_family,
    };

    /// What `Service` learns about one received datagram.
    pub const RxMeta = struct {
        from: Io.net.IpAddress,
        /// Arrival interface from the pktinfo / recvif cmsg; 0 = unknown.
        ifindex: u32,
        /// Destination was a multicast group (skips the section 11
        /// on-link check).
        dst_multicast: bool,
        /// IPv4 TTL or IPv6 hop limit when the OS delivered it.
        ttl: ?u8 = null,
    };

    /// One outbound datagram written into the caller's buffer.
    pub const TxDatagram = struct {
        len: usize,
        to: Io.net.IpAddress,
        /// Egress interface (pktinfo cmsg / IP_MULTICAST_IF); 0 = let the
        /// OS route it.
        ifindex: u32,
    };

    pub const InitError = error{OutOfMemory};
    pub const SetInterfacesError = error{LimitReached};

    /// `error.NotImplemented` is the M2 stub marker; M3/M4 remove it.
    pub const AdvertiseError = error{
        NotImplemented,
        LimitReached,
        TxtTooLarge,
        InvalidServiceType,
        InvalidInstance,
        DuplicateRegistration,
    };
    pub const UpdateTxtError = error{
        NotImplemented,
        TxtTooLarge,
        UnknownRegistration,
    };
    pub const BrowseError = error{
        NotImplemented,
        LimitReached,
        InvalidServiceType,
    };

    /// STUB: interval of the fixed `_services._dns-sd._udp.local` PTR query.
    pub const stub_query_interval_us: u64 = 2_000_000;
    /// STUB: the one question the stub asks (RFC 6763 section 9).
    pub const stub_query_name = "_services._dns-sd._udp.local";

    const PendingQuery = struct { ifindex: u32, family: Family };
    /// At most one v4 and one v6 query per interface per firing.
    const max_pending = 2 * std.math.maxInt(u8) + 2;

    gpa: std.mem.Allocator,
    host_label: events.Bounded(u8, max_host_label_len),
    random: std.Random,
    limits: Limits,
    qu_allowed: bool,
    max_addrs_per_iface: u8,

    /// Interface table (`limits.max_interfaces` slots, allocated once).
    ifaces: []Interface,
    ifaces_len: usize,

    /// Event ring (`limits.max_events` slots, allocated once; drop-oldest).
    ring: EventQueue,
    events_dropped_warned: bool,

    counters: Stats,

    // ---- STUB timer state ---------------------------------------------
    /// Next firing of the fixed query; null until the first `tick`.
    next_query_us: ?u64,
    pending: [max_pending]PendingQuery,
    pending_head: usize,
    pending_len: usize,

    /// Preallocates every pool sized by `opts.limits`. The only allocation
    /// the Engine ever makes; `handle`, `tick` and `pollDatagram` never
    /// allocate.
    pub fn init(gpa: std.mem.Allocator, opts: Options) InitError!Engine {
        const n_ifaces: usize = @max(@as(usize, opts.limits.max_interfaces), 1);
        const ifaces = try gpa.alloc(Interface, n_ifaces);
        errdefer gpa.free(ifaces);
        const n_events: usize = @max(@as(usize, opts.limits.max_events), 1);
        const ring_buf = try gpa.alloc(Event, n_events);
        errdefer gpa.free(ring_buf);

        var label: events.Bounded(u8, max_host_label_len) = .{};
        // A longer label is truncated here; M4 validates it and rejects
        // it with a typed error.
        label.appendSlice(opts.host_label[0..@min(opts.host_label.len, max_host_label_len)]) catch unreachable;

        return .{
            .gpa = gpa,
            .host_label = label,
            .random = opts.random,
            .limits = opts.limits,
            .qu_allowed = opts.qu_allowed,
            .max_addrs_per_iface = @min(opts.max_addrs_per_iface, events.max_addrs_per_family),
            .ifaces = ifaces,
            .ifaces_len = 0,
            .ring = .{ .buf = ring_buf },
            .events_dropped_warned = false,
            .counters = .{},
            .next_query_us = null,
            .pending = undefined,
            .pending_head = 0,
            .pending_len = 0,
        };
    }

    pub fn deinit(e: *Engine) void {
        e.gpa.free(e.ring.buf);
        e.gpa.free(e.ifaces);
        e.* = undefined;
    }

    // ---- interfaces ---------------------------------------------------

    /// Replace the interface table. Keeps the first `max_addrs_per_iface`
    /// addresses per family in the order given, adds every drop (the
    /// `Interface.*_dropped` counts from `ifaces.zig` plus its own cap)
    /// into `stats.addrs_dropped`, emits `warning.addrs_truncated` once
    /// per (interface, family) that lost an address in this call, and
    /// `.interfaces_changed` when the table differs from the previous one.
    /// M3 adds the per-interface probe / goodbye / re-query work.
    pub fn setInterfaces(e: *Engine, ifs: []const Interface, now_us: u64) SetInterfacesError!void {
        _ = now_us;
        if (ifs.len > e.ifaces.len) return error.LimitReached;

        var changed = ifs.len != e.ifaces_len;
        var i: usize = 0;
        while (i < ifs.len) : (i += 1) {
            var kept = ifs[i];
            var dropped4: u64 = kept.v4_dropped;
            var dropped6: u64 = kept.v6_dropped;
            if (kept.v4.len > e.max_addrs_per_iface) {
                dropped4 += kept.v4.len - e.max_addrs_per_iface;
                kept.v4.len = e.max_addrs_per_iface;
            }
            if (kept.v6.len > e.max_addrs_per_iface) {
                dropped6 += kept.v6.len - e.max_addrs_per_iface;
                kept.v6.len = e.max_addrs_per_iface;
            }
            e.counters.addrs_dropped += dropped4 + dropped6;
            if (dropped4 != 0) e.pushEvent(.{ .warning = .{ .addrs_truncated = .{ .ifindex = kept.index, .family = .v4 } } });
            if (dropped6 != 0) e.pushEvent(.{ .warning = .{ .addrs_truncated = .{ .ifindex = kept.index, .family = .v6 } } });

            if (!changed) {
                const old = e.findInterface(kept.index);
                if (old == null or !old.?.sameAddrs(&kept)) changed = true;
            }
            e.ifaces[i] = kept;
        }
        e.ifaces_len = ifs.len;
        if (changed) e.pushEvent(.interfaces_changed);
    }

    /// The current table (what `setInterfaces` kept).
    pub fn interfaces(e: *const Engine) []const Interface {
        return e.ifaces[0..e.ifaces_len];
    }

    fn findInterface(e: *const Engine, index: u32) ?*const Interface {
        for (e.ifaces[0..e.ifaces_len]) |*i| if (i.index == index) return i;
        return null;
    }

    // ---- registrations and browses (STUB) -----------------------------

    /// M2 stub (M4 fills it): always `error.NotImplemented`.
    pub fn advertise(e: *Engine, desc: ServiceDesc, now_us: u64) AdvertiseError!RegId {
        _ = e;
        _ = desc;
        _ = now_us;
        return error.NotImplemented;
    }

    /// M2 stub (M4 fills it): no-op.
    pub fn withdraw(e: *Engine, id: RegId, now_us: u64) void {
        _ = e;
        _ = id;
        _ = now_us;
    }

    /// M2 stub (M4 fills it): always `error.NotImplemented`.
    pub fn updateTxt(e: *Engine, id: RegId, txt: []const TxtPair, now_us: u64) UpdateTxtError!void {
        _ = e;
        _ = id;
        _ = txt;
        _ = now_us;
        return error.NotImplemented;
    }

    /// M2 stub (M3 fills it): always `error.NotImplemented`.
    pub fn browse(e: *Engine, service_type: []const u8, now_us: u64) BrowseError!BrowseId {
        _ = e;
        _ = service_type;
        _ = now_us;
        return error.NotImplemented;
    }

    /// M2 stub (M3 fills it): no-op.
    pub fn stopBrowse(e: *Engine, id: BrowseId, now_us: u64) void {
        _ = e;
        _ = id;
        _ = now_us;
    }

    // ---- packets ------------------------------------------------------

    /// Feed one received datagram. Never fails, never allocates. Malformed
    /// input is counted in `dropped_malformed`; a response from a source
    /// port other than 5353 in `dropped_bad_port` (RFC 6762 section 6).
    /// STUB: nothing is cached or answered yet (M3/M4).
    pub fn handle(e: *Engine, datagram: []const u8, meta: RxMeta, now_us: u64) void {
        _ = now_us;
        e.counters.rx += 1;
        const msg = wire.Message.parse(datagram) catch {
            e.counters.dropped_malformed += 1;
            return;
        };
        if (msg.isResponse() and sourcePort(meta.from) != mdns_port) {
            e.counters.dropped_bad_port += 1;
            return;
        }
        // M3: own-echo test, section 11 on-link check, cache update.
    }

    fn sourcePort(addr: Io.net.IpAddress) u16 {
        return switch (addr) {
            .ip4 => |a| a.port,
            .ip6 => |a| a.port,
        };
    }

    /// Fire due timers. STUB: every `stub_query_interval_us` queue one
    /// PTR query per interface per family that has an address.
    pub fn tick(e: *Engine, now_us: u64) void {
        const due = e.next_query_us orelse now_us;
        if (now_us < due) return;
        e.next_query_us = now_us + stub_query_interval_us;
        for (e.ifaces[0..e.ifaces_len]) |*iface| {
            if (iface.v4.len != 0) e.enqueueQuery(.{ .ifindex = iface.index, .family = .v4 });
            if (iface.v6.len != 0) e.enqueueQuery(.{ .ifindex = iface.index, .family = .v6 });
        }
    }

    fn enqueueQuery(e: *Engine, q: PendingQuery) void {
        if (e.pending_len == e.pending.len) {
            // Cannot happen with max_interfaces <= 255; counted, not trapped.
            e.counters.tx_dropped += 1;
            return;
        }
        e.pending[(e.pending_head + e.pending_len) % e.pending.len] = q;
        e.pending_len += 1;
    }

    /// Drain one outbound datagram into `buf`. Never allocates. STUB: the
    /// fixed `_services._dns-sd._udp.local` PTR query, QM, ID 0.
    pub fn pollDatagram(e: *Engine, buf: []u8, now_us: u64) ?TxDatagram {
        _ = now_us;
        while (e.pending_len != 0) {
            const q = e.pending[e.pending_head];
            e.pending_head = (e.pending_head + 1) % e.pending.len;
            e.pending_len -= 1;

            if (buf.len < wire.Header.len) {
                e.counters.tx_dropped += 1;
                continue;
            }
            var b: wire.Builder = .init(buf, .{ .family = switch (q.family) {
                .v4 => .v4,
                .v6 => .v6,
            } });
            b.setId(0);
            const qname = wire.Name.parse(stub_query_name) catch unreachable; // comptime-known literal
            b.addQuestion(qname, .ptr, wire.class_in, false) catch {
                e.counters.tx_dropped += 1;
                continue;
            };
            const packet = b.finish();
            e.counters.tx += 1;
            return .{
                .len = packet.len,
                .to = switch (q.family) {
                    .v4 => .{ .ip4 = .{ .bytes = group_v4, .port = mdns_port } },
                    .v6 => .{ .ip6 = .{ .bytes = group_v6, .port = mdns_port, .interface = .{ .index = q.ifindex } } },
                },
                .ifindex = q.ifindex,
            };
        }
        return null;
    }

    /// The next timer, or null before the first `tick`. When a datagram is
    /// already queued the deadline is `now_us` so the caller drains at once.
    pub fn nextDeadline(e: *const Engine, now_us: u64) ?u64 {
        if (e.pending_len != 0) return now_us;
        return e.next_query_us;
    }

    // ---- events -------------------------------------------------------

    pub fn pollEvent(e: *Engine) ?Event {
        return e.ring.pop();
    }

    /// Queue an event with the drop-oldest rule (plan section 4.5). A drop
    /// bumps `stats.events_dropped` and emits `warning.events_dropped`
    /// once per Engine lifetime.
    pub fn pushEvent(e: *Engine, ev: Event) void {
        if (e.ring.push(ev)) {
            e.counters.events_dropped += 1;
            if (!e.events_dropped_warned) {
                e.events_dropped_warned = true;
                if (e.ring.push(.{ .warning = .events_dropped })) e.counters.events_dropped += 1;
            }
        }
    }

    pub fn stats(e: *const Engine) Stats {
        return e.counters;
    }
};

/// The drop-oldest ring from `events.zig`, re-exported for `Service`.
pub const EventQueue = events.EventQueue;

// ---- tests -----------------------------------------------------------

const testing = std.testing;

fn testEngine(limits: Limits) !Engine {
    var prng = std.Random.DefaultPrng.init(7);
    return Engine.init(testing.allocator, .{ .host_label = "unit", .random = prng.random(), .limits = limits });
}

fn testIface(index: u32, n4: usize, n6: usize) Interface {
    var i: Interface = .{ .index = index };
    var k: usize = 0;
    while (k < n4) : (k += 1) i.v4.append(.{ .addr = .{ 10, 0, @intCast(index), @intCast(k + 1) }, .prefix_len = 24 }) catch unreachable;
    k = 0;
    while (k < n6) : (k += 1) {
        var a: [16]u8 = @splat(0);
        a[0] = 0xfd;
        a[15] = @intCast(k + 1);
        i.v6.append(.{ .addr = a, .prefix_len = 64 }) catch unreachable;
    }
    return i;
}

test "engine stub schedules one services query per interface per family every 2 s" {
    var e = try testEngine(.{});
    defer e.deinit();
    try testing.expectEqual(null, e.nextDeadline(0));

    try e.setInterfaces(&.{ testIface(3, 1, 1), testIface(4, 1, 0) }, 0);
    try testing.expectEqual(Event.interfaces_changed, e.pollEvent().?);
    try testing.expectEqual(null, e.pollEvent());

    var buf: [1500]u8 = undefined;
    // Nothing before the first tick.
    try testing.expectEqual(null, e.pollDatagram(&buf, 0));
    e.tick(1_000);
    try testing.expectEqual(@as(?u64, 1_000), e.nextDeadline(1_000)); // queued => now
    var count: usize = 0;
    var saw_v6 = false;
    while (e.pollDatagram(&buf, 1_000)) |d| {
        count += 1;
        const msg = try wire.Message.parse(buf[0..d.len]);
        try testing.expect(!msg.isResponse());
        try testing.expectEqual(@as(u16, 1), msg.header.qdcount);
        var qs = msg.questions();
        const q = qs.next().?;
        try testing.expectEqual(wire.RType.ptr, q.qtype);
        try testing.expect(!q.qu);
        var text: [64]u8 = undefined;
        try testing.expectEqualStrings(Engine.stub_query_name, try q.name.toText(&text));
        switch (d.to) {
            .ip4 => |a| {
                try testing.expectEqual(group_v4, a.bytes);
                try testing.expectEqual(mdns_port, a.port);
            },
            .ip6 => |a| {
                try testing.expectEqual(group_v6, a.bytes);
                try testing.expectEqual(d.ifindex, a.interface.index);
                saw_v6 = true;
            },
        }
        try testing.expect(d.ifindex == 3 or d.ifindex == 4);
    }
    try testing.expectEqual(@as(usize, 3), count);
    try testing.expect(saw_v6);
    try testing.expectEqual(@as(u64, 3), e.stats().tx);
    try testing.expectEqual(@as(?u64, 1_000 + Engine.stub_query_interval_us), e.nextDeadline(1_000));
    // Not due yet: nothing new.
    e.tick(1_000 + Engine.stub_query_interval_us - 1);
    try testing.expectEqual(null, e.pollDatagram(&buf, 2_000));
    e.tick(1_000 + Engine.stub_query_interval_us);
    try testing.expect(e.pollDatagram(&buf, 3_000) != null);
}

test "engine handle counts malformed and bad-port drops" {
    var e = try testEngine(.{});
    defer e.deinit();
    const from5353: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 168, 1, 2 }, .port = 5353 } };
    const from_other: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 168, 1, 2 }, .port = 40000 } };

    e.handle(&.{ 1, 2, 3 }, .{ .from = from5353, .ifindex = 1, .dst_multicast = true }, 0);
    try testing.expectEqual(@as(u64, 1), e.stats().rx);
    try testing.expectEqual(@as(u64, 1), e.stats().dropped_malformed);

    // A well-formed response header with no records.
    var resp: [12]u8 = @splat(0);
    resp[2] = 0x84; // QR=1, AA=1
    e.handle(&resp, .{ .from = from_other, .ifindex = 1, .dst_multicast = true }, 0);
    try testing.expectEqual(@as(u64, 1), e.stats().dropped_bad_port);
    e.handle(&resp, .{ .from = from5353, .ifindex = 1, .dst_multicast = true }, 0);
    try testing.expectEqual(@as(u64, 1), e.stats().dropped_bad_port);
    // A query from an ephemeral port is a legacy query, not a drop.
    var query: [12]u8 = @splat(0);
    e.handle(&query, .{ .from = from_other, .ifindex = 1, .dst_multicast = false }, 0);
    try testing.expectEqual(@as(u64, 1), e.stats().dropped_bad_port);
    try testing.expectEqual(@as(u64, 4), e.stats().rx);
}

test "engine setInterfaces caps addresses and warns once per family" {
    var prng = std.Random.DefaultPrng.init(1);
    var e = try Engine.init(testing.allocator, .{
        .host_label = "unit",
        .random = prng.random(),
        .limits = .{ .max_interfaces = 2 },
        .max_addrs_per_iface = 2,
    });
    defer e.deinit();

    var i = testIface(9, 4, 1);
    i.v6_dropped = 3; // ifaces.zig already dropped three v6 addresses
    try e.setInterfaces(&.{i}, 0);
    // 2 v4 over the cap + 3 v6 reported by ifaces.zig.
    try testing.expectEqual(@as(u64, 5), e.stats().addrs_dropped);
    try testing.expectEqual(@as(usize, 2), e.interfaces()[0].v4.len);
    const w4 = e.pollEvent().?;
    try testing.expectEqual(@as(u32, 9), w4.warning.addrs_truncated.ifindex);
    try testing.expectEqual(Family.v4, w4.warning.addrs_truncated.family);
    const w6 = e.pollEvent().?;
    try testing.expectEqual(Family.v6, w6.warning.addrs_truncated.family);
    try testing.expectEqual(Event.interfaces_changed, e.pollEvent().?);
    try testing.expectEqual(null, e.pollEvent());

    // Same table again: no interfaces_changed (the truncation warning
    // repeats, "once per call").
    try e.setInterfaces(&.{i}, 1);
    _ = e.pollEvent().?;
    _ = e.pollEvent().?;
    try testing.expectEqual(null, e.pollEvent());

    // Over the limit.
    try testing.expectError(error.LimitReached, e.setInterfaces(&.{ testIface(1, 1, 0), testIface(2, 1, 0), testIface(3, 1, 0) }, 2));

    // Stub mutations.
    try testing.expectError(error.NotImplemented, e.advertise(.{ .service_type = "_x._udp", .instance = "a", .port = 1 }, 0));
    try testing.expectError(error.NotImplemented, e.browse("_x._udp", 0));
}

test "engine event ring drops oldest and warns once" {
    var e = try testEngine(.{ .max_events = 2 });
    defer e.deinit();
    e.pushEvent(.interfaces_changed);
    e.pushEvent(.interfaces_changed);
    e.pushEvent(.{ .warning = .no_interfaces });
    // The third push dropped one; the once-only warning dropped another.
    try testing.expectEqual(@as(u64, 2), e.stats().events_dropped);
    try testing.expectEqual(Warning.no_interfaces, e.pollEvent().?.warning);
    try testing.expectEqual(Warning.events_dropped, e.pollEvent().?.warning);
    try testing.expectEqual(null, e.pollEvent());
    e.pushEvent(.interfaces_changed);
    e.pushEvent(.interfaces_changed);
    e.pushEvent(.interfaces_changed);
    try testing.expectEqual(@as(u64, 3), e.stats().events_dropped);
    _ = e.pollEvent().?;
    _ = e.pollEvent().?;
    try testing.expectEqual(null, e.pollEvent());
}
