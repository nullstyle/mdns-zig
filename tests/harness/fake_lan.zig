//! Virtual LAN for the deterministic tier-1 tests (plan section 8,
//! section 6 `tests/harness/fake_lan.zig`): N Engines, per-interface
//! fan-out, loopback echo, loss, bridging and a packet log. It only uses
//! the plan section 5 `Engine` surface (`setInterfaces`, `handle`, `tick`,
//! `pollDatagram`, `nextDeadline`, `pollEvent`). `setInterfaces` marks
//! every family with an address as joined, which is exactly the
//! harness's own receiver rule (`hasFamily`); a test that wants a joined
//! pair without an address, or an unjoined pair with one, calls
//! `Engine.setJoined` after `addEngine`.
//!
//! Model:
//! - A **segment** is one broadcast domain (one physical link). Every
//!   engine interface (`Interface.index`) is attached to exactly one
//!   segment. Several engines may sit on one segment; one engine may sit
//!   on several segments (a multi-homed host).
//! - `pump(now_us)` drains every engine's `pollDatagram` into a 9000 B
//!   buffer, logs each datagram, then delivers it. A datagram sent from
//!   interface `i` on segment `s` reaches every interface attached to `s`
//!   (or to a segment bridged with `s`) that has an address of the
//!   datagram's family. That includes the sender's own interface `i`:
//!   multicast loopback is ON, so the sender gets its own bytes back
//!   with `RxMeta.from` = its own address on `i` (plan section 4.8
//!   own-echo rule). When `s` is bridged to another segment where the
//!   same engine has a second interface, that second interface receives
//!   the datagram too, again with `from` = the sender's address on `i`
//!   (the bridged-echo case: same bytes, a foreign-looking arrival
//!   interface).
//! - `RxMeta.from` is the sender's first v4 address for 224.0.0.251
//!   destinations and its first link-local v6 address (else its first v6
//!   address) for ff02::fb, with `.interface = { .index = receiver ifindex }`,
//!   port 5353. A unicast destination is routed to the one interface on
//!   a connected segment that owns that address (`dst_multicast = false`).
//! - Loss is per segment (the sender's), drawn from a caller-supplied
//!   seeded `std.Random`, and applies to deliveries over the link. The
//!   in-host loopback echo is never lost (a real kernel loops the bytes
//!   back without touching the wire).
//! - Two logs: `sent` (one entry per datagram an engine emitted, with an
//!   owned copy of the bytes and a query/response/malformed
//!   classification) and `deliveries` (one entry per `handle` call).
//!
//! The harness allocates (owned byte copies in the log) with the
//! allocator given to `init`; the Engines under test still never do.
const std = @import("std");
const Io = std.Io;
const mdns = @import("mdns");
const wire = mdns.wire;

pub const Engine = mdns.Engine;
pub const Interface = mdns.Interface;
pub const Family = mdns.Family;
pub const RxMeta = Engine.RxMeta;
pub const TxDatagram = Engine.TxDatagram;

/// mDNS port and groups, as the Engine names them.
pub const mdns_port: u16 = mdns.core.engine.mdns_port;
pub const group_v4 = mdns.core.engine.group_v4;
pub const group_v6 = mdns.core.engine.group_v6;

/// Receive buffer size (RFC 6762 section 17; plan section 4.5).
pub const max_datagram = wire.max_message_len;

/// What `Message.parse` says about a datagram an engine emitted.
pub const PacketKind = enum(u8) { query, response, malformed };

/// One datagram an engine emitted (one entry per `pollDatagram` result).
pub const Sent = struct {
    from_engine: usize,
    /// Egress interface (`TxDatagram.ifindex`, after the 0 -> first
    /// interface fallback).
    ifindex: u32,
    /// Segment the egress interface is attached to.
    segment: u32,
    family: Family,
    kind: PacketKind,
    now_us: u64,
    /// Owned copy (freed by `deinit` / `clearLog`).
    bytes: []const u8 = &.{},
    to: Io.net.IpAddress = .{ .ip4 = .{ .bytes = group_v4, .port = mdns_port } },
    /// `handle` calls this datagram produced (including the echo).
    delivered: u16 = 0,
    /// Deliveries the loss model dropped.
    lost: u16 = 0,

    pub fn isMulticast(s: *const Sent) bool {
        return isMulticastAddr(s.to);
    }
};

/// One `Engine.handle` call the harness made.
pub const Delivery = struct {
    /// Index into the `sent` log (`null` for `injectForeign`).
    sent: ?usize,
    /// `null` for `injectForeign`.
    from_engine: ?usize,
    to_engine: usize,
    meta: RxMeta,
    /// `to_engine == from_engine`: loopback echo (same interface) or
    /// bridged echo (another interface of the same engine).
    echo: bool,
    /// Echo that arrived on an interface other than the one it was sent
    /// from (only possible with bridging).
    bridged: bool,
    now_us: u64,
};

pub fn isMulticastAddr(a: Io.net.IpAddress) bool {
    return switch (a) {
        .ip4 => |v| std.mem.eql(u8, &v.bytes, &group_v4),
        .ip6 => |v| std.mem.eql(u8, &v.bytes, &group_v6),
    };
}

pub fn familyOf(a: Io.net.IpAddress) Family {
    return switch (a) {
        .ip4 => .v4,
        .ip6 => .v6,
    };
}

/// A virtual LAN of at most `max_engines` engines. Declare it with `var`
/// (it embeds the 9000 B receive buffer and the interface tables).
pub fn FakeLan(comptime max_engines: usize) type {
    return struct {
        const Self = @This();

        /// Interfaces one engine may attach.
        pub const max_ifaces_per_engine = 8;
        /// Distinct segment ids (0-based, dense) the LAN supports.
        pub const max_segments = 16;
        /// Bridged segment pairs.
        pub const max_bridges = 16;

        pub const Node = struct {
            engine: *Engine,
            ifaces: mdns.Bounded(Interface, max_ifaces_per_engine) = .{},
            /// `segments[k]` is the segment of `ifaces.slice()[k]`.
            segments: [max_ifaces_per_engine]u32 = @splat(0),

            pub fn slotOf(n: *const Node, ifindex: u32) ?usize {
                for (n.ifaces.slice(), 0..) |*i, k| if (i.index == ifindex) return k;
                return null;
            }

            pub fn ifaceOf(n: *const Node, ifindex: u32) ?*const Interface {
                const k = n.slotOf(ifindex) orelse return null;
                return &n.ifaces.slice()[k];
            }

            pub fn segmentOf(n: *const Node, ifindex: u32) ?u32 {
                const k = n.slotOf(ifindex) orelse return null;
                return n.segments[k];
            }

            /// The address the OS would stamp as the source of a datagram
            /// this node sends from `ifindex` in `family`, or null when the
            /// interface has no address of that family.
            pub fn sourceAddr(n: *const Node, ifindex: u32, family: Family, scope_ifindex: u32) ?Io.net.IpAddress {
                const iface = n.ifaceOf(ifindex) orelse return null;
                return sourceAddrOf(iface, family, scope_ifindex);
            }
        };

        pub const Bridge = struct { a: u32, b: u32 };

        /// Harness-side counters for engine misbehaviour the deliveries do
        /// not show.
        pub const HarnessStats = struct {
            /// `TxDatagram.ifindex` named no attached interface; dropped.
            tx_unknown_iface: u64 = 0,
            /// `TxDatagram.ifindex == 0`; routed via the first interface.
            tx_ifindex_zero: u64 = 0,
            /// The egress interface has no address of the datagram's
            /// family (the pair is not "joined"); dropped.
            tx_no_source: u64 = 0,
            /// Unicast destination nobody on a connected segment owns.
            tx_unroutable: u64 = 0,
        };

        gpa: std.mem.Allocator,
        nodes: [max_engines]Node = undefined,
        nodes_len: usize = 0,
        /// Loss probability per segment, 0..1.
        loss: [max_segments]f32 = @splat(0),
        /// Source of loss draws; required when any loss is non-zero.
        random: ?std.Random = null,
        bridges: mdns.Bounded(Bridge, max_bridges) = .{},
        sent: std.ArrayList(Sent) = .empty,
        deliveries: std.ArrayList(Delivery) = .empty,
        harness_stats: HarnessStats = .{},
        rx_buf: [max_datagram]u8 = undefined,

        pub fn init(gpa: std.mem.Allocator) Self {
            return .{ .gpa = gpa };
        }

        pub fn deinit(lan: *Self) void {
            lan.clearLog();
            lan.sent.deinit(lan.gpa);
            lan.deliveries.deinit(lan.gpa);
            lan.* = undefined;
        }

        // ---- topology -------------------------------------------------

        /// Attach `engine` with `ifaces` (interface `k` on `segments[k]`)
        /// and call `engine.setInterfaces(ifaces, now_us)`. Returns the
        /// engine's index in the LAN (its `from_engine` / `to_engine` id).
        pub fn addEngine(lan: *Self, engine: *Engine, ifaces: []const Interface, segments: []const u32, now_us: u64) !usize {
            if (lan.nodes_len == max_engines) return error.LimitReached;
            if (ifaces.len != segments.len) return error.SegmentCountMismatch;
            if (ifaces.len > max_ifaces_per_engine) return error.LimitReached;
            for (segments) |s| if (s >= max_segments) return error.SegmentOutOfRange;
            for (ifaces, 0..) |*i, k| {
                if (i.index == 0) return error.ZeroIfindex;
                for (ifaces[0..k]) |*j| if (j.index == i.index) return error.DuplicateIfindex;
            }
            var new_node: Node = .{ .engine = engine };
            new_node.ifaces.appendSlice(ifaces) catch unreachable; // len checked above
            @memcpy(new_node.segments[0..segments.len], segments);
            try engine.setInterfaces(ifaces, now_us);
            lan.nodes[lan.nodes_len] = new_node;
            lan.nodes_len += 1;
            return lan.nodes_len - 1;
        }

        /// One engine on one segment with one interface: the common case.
        pub fn addEngineOn(lan: *Self, engine: *Engine, iface: Interface, segment: u32, now_us: u64) !usize {
            return lan.addEngine(engine, &.{iface}, &.{segment}, now_us);
        }

        pub fn node(lan: *Self, idx: usize) *Node {
            return &lan.nodes[idx];
        }

        pub fn engineAt(lan: *Self, idx: usize) *Engine {
            return lan.nodes[idx].engine;
        }

        pub fn engineCount(lan: *const Self) usize {
            return lan.nodes_len;
        }

        /// Set the loss probability (0..1) on `segment`. Draws come from
        /// `random` (a seeded PRNG from `Scenario.random()`).
        pub fn setLoss(lan: *Self, segment: u32, probability: f32, random: std.Random) void {
            std.debug.assert(segment < max_segments);
            std.debug.assert(probability >= 0 and probability <= 1);
            lan.loss[segment] = probability;
            lan.random = random;
        }

        /// Join two segments so a datagram on either reaches both (a
        /// switch bridging two links). Transitive across several bridges.
        pub fn bridge(lan: *Self, a: u32, b: u32) !void {
            if (a >= max_segments or b >= max_segments) return error.SegmentOutOfRange;
            if (a == b) return;
            if (lan.bridgeIndex(a, b) != null) return;
            try lan.bridges.append(.{ .a = a, .b = b });
        }

        pub fn unbridge(lan: *Self, a: u32, b: u32) void {
            const k = lan.bridgeIndex(a, b) orelse return;
            const items = lan.bridges.sliceMut();
            items[k] = items[items.len - 1];
            lan.bridges.len -= 1;
        }

        fn bridgeIndex(lan: *const Self, a: u32, b: u32) ?usize {
            for (lan.bridges.slice(), 0..) |br, k| {
                if ((br.a == a and br.b == b) or (br.a == b and br.b == a)) return k;
            }
            return null;
        }

        /// True when a datagram on `from` reaches `to` (same segment or a
        /// chain of bridges).
        pub fn connected(lan: *const Self, from: u32, to: u32) bool {
            if (from == to) return true;
            var reach: [max_segments]bool = @splat(false);
            reach[from] = true;
            var changed = true;
            while (changed) {
                changed = false;
                for (lan.bridges.slice()) |br| {
                    if (reach[br.a] and !reach[br.b]) {
                        reach[br.b] = true;
                        changed = true;
                    }
                    if (reach[br.b] and !reach[br.a]) {
                        reach[br.a] = true;
                        changed = true;
                    }
                }
            }
            return reach[to];
        }

        // ---- driving --------------------------------------------------

        /// `engine.tick(now_us)` on every engine, in registration order.
        pub fn tickAll(lan: *Self, now_us: u64) void {
            for (lan.nodes[0..lan.nodes_len]) |*n| n.engine.tick(now_us);
        }

        /// Soonest `nextDeadline` over all engines, or null when none has
        /// one.
        pub fn nextDeadline(lan: *const Self, now_us: u64) ?u64 {
            var best: ?u64 = null;
            for (lan.nodes[0..lan.nodes_len]) |*n| {
                const d = n.engine.nextDeadline(now_us) orelse continue;
                best = if (best) |b| @min(b, d) else d;
            }
            return best;
        }

        /// Drain every engine's outbound queue, log each datagram, then
        /// deliver them all (at `now_us`). Datagrams an engine queues in
        /// reaction to a delivery go out on the next pump.
        pub fn pump(lan: *Self, now_us: u64) !void {
            const first = lan.sent.items.len;
            var idx: usize = 0;
            while (idx < lan.nodes_len) : (idx += 1) {
                const n = &lan.nodes[idx];
                while (n.engine.pollDatagram(&lan.rx_buf, now_us)) |d| {
                    try lan.logSent(idx, n, d, now_us);
                }
            }
            var k = first;
            while (k < lan.sent.items.len) : (k += 1) {
                try lan.deliver(k, now_us);
            }
        }

        /// Fixed-step loop: at `from_us`, every `step_us`, and at `to_us`,
        /// tick every engine then pump. `step_us` must be > 0.
        pub fn run(lan: *Self, from_us: u64, to_us: u64, step_us: u64) !void {
            std.debug.assert(step_us > 0);
            std.debug.assert(to_us >= from_us);
            var t = from_us;
            while (true) {
                lan.tickAll(t);
                try lan.pump(t);
                if (t >= to_us) break;
                t = @min(t +| step_us, to_us);
            }
        }

        /// Deadline-driven loop: after each tick+pump, jump to the soonest
        /// engine deadline (at least 1 us ahead, at most `max_step_us`),
        /// so a simulated day costs one iteration per timer, not per
        /// millisecond.
        pub fn runToDeadlines(lan: *Self, from_us: u64, to_us: u64, max_step_us: u64) !void {
            std.debug.assert(max_step_us > 0);
            std.debug.assert(to_us >= from_us);
            var t = from_us;
            while (true) {
                lan.tickAll(t);
                try lan.pump(t);
                if (t >= to_us) break;
                var next = t +| max_step_us;
                if (lan.nextDeadline(t)) |d| next = @min(next, @max(d, t + 1));
                t = @min(next, to_us);
            }
        }

        /// Deliver a datagram that did not come from any engine (a foreign
        /// responder, a fixture capture) to every interface on segments
        /// connected to `segment` with an address of `from`'s family. The
        /// v6 `from` gets `.interface.index` set per receiver. Useful for
        /// "byte-identical query from a foreign source is not an echo".
        pub fn injectForeign(lan: *Self, segment: u32, bytes: []const u8, from: Io.net.IpAddress, dst_multicast: bool, now_us: u64) !usize {
            const family = familyOf(from);
            var count: usize = 0;
            for (lan.nodes[0..lan.nodes_len], 0..) |*n, ti| {
                for (n.ifaces.slice(), 0..) |*iface, k| {
                    if (!lan.connected(segment, n.segments[k])) continue;
                    if (!hasFamily(iface, family)) continue;
                    const meta: RxMeta = .{ .from = scoped(from, iface.index), .ifindex = iface.index, .dst_multicast = dst_multicast };
                    n.engine.handle(bytes, meta, now_us);
                    try lan.deliveries.append(lan.gpa, .{ .sent = null, .from_engine = null, .to_engine = ti, .meta = meta, .echo = false, .bridged = false, .now_us = now_us });
                    count += 1;
                }
            }
            return count;
        }

        /// Deliver `bytes` to exactly one engine interface with a
        /// caller-chosen `RxMeta` (off-link unicast, wrong-port sources,
        /// ...). Logged as a foreign delivery.
        pub fn injectTo(lan: *Self, to_engine: usize, bytes: []const u8, meta: RxMeta, now_us: u64) !void {
            lan.nodes[to_engine].engine.handle(bytes, meta, now_us);
            try lan.deliveries.append(lan.gpa, .{ .sent = null, .from_engine = null, .to_engine = to_engine, .meta = meta, .echo = false, .bridged = false, .now_us = now_us });
        }

        // ---- logs -----------------------------------------------------

        pub fn sentLog(lan: *const Self) []const Sent {
            return lan.sent.items;
        }

        pub fn deliveryLog(lan: *const Self) []const Delivery {
            return lan.deliveries.items;
        }

        /// Drop both logs (and the owned byte copies). Counters stay.
        pub fn clearLog(lan: *Self) void {
            for (lan.sent.items) |s| lan.gpa.free(s.bytes);
            lan.sent.clearRetainingCapacity();
            lan.deliveries.clearRetainingCapacity();
        }

        /// Deliveries into `to_engine` (all of them, or only echoes /
        /// only foreign ones).
        pub fn countDeliveries(lan: *const Self, to_engine: usize, echo: ?bool) usize {
            var n: usize = 0;
            for (lan.deliveries.items) |d| {
                if (d.to_engine != to_engine) continue;
                if (echo) |want| if (d.echo != want) continue;
                n += 1;
            }
            return n;
        }

        // ---- internals ------------------------------------------------

        fn logSent(lan: *Self, from_idx: usize, n: *const Node, d: TxDatagram, now_us: u64) !void {
            const family = familyOf(d.to);
            const to_ifindex: u32 = blk: {
                if (d.ifindex == 0) {
                    lan.harness_stats.tx_ifindex_zero += 1;
                    break :blk n.ifaces.slice()[0].index;
                }
                break :blk d.ifindex;
            };
            const segment = n.segmentOf(to_ifindex) orelse {
                lan.harness_stats.tx_unknown_iface += 1;
                return;
            };
            const len = @min(d.len, lan.rx_buf.len);
            const copy = try lan.gpa.dupe(u8, lan.rx_buf[0..len]);
            errdefer lan.gpa.free(copy);
            try lan.sent.append(lan.gpa, .{
                .from_engine = from_idx,
                .ifindex = to_ifindex,
                .segment = segment,
                .family = family,
                .kind = classify(copy),
                .now_us = now_us,
                .bytes = copy,
                .to = d.to,
            });
        }

        fn deliver(lan: *Self, sent_idx: usize, now_us: u64) !void {
            const s = &lan.sent.items[sent_idx];
            const sender = &lan.nodes[s.from_engine];
            const src_iface = sender.ifaceOf(s.ifindex).?; // logSent checked it
            if (sourceAddrOf(src_iface, s.family, 0) == null) {
                lan.harness_stats.tx_no_source += 1;
                return;
            }
            if (isMulticastAddr(s.to)) {
                try lan.deliverMulticast(sent_idx, now_us);
            } else {
                try lan.deliverUnicast(sent_idx, now_us);
            }
        }

        fn deliverMulticast(lan: *Self, sent_idx: usize, now_us: u64) !void {
            const s = lan.sent.items[sent_idx];
            const sender = &lan.nodes[s.from_engine];
            const src_iface = sender.ifaceOf(s.ifindex).?;
            var ti: usize = 0;
            while (ti < lan.nodes_len) : (ti += 1) {
                const n = &lan.nodes[ti];
                for (n.ifaces.slice(), 0..) |*iface, k| {
                    if (!lan.connected(s.segment, n.segments[k])) continue;
                    if (!hasFamily(iface, s.family)) continue;
                    const echo = ti == s.from_engine;
                    const bridged = echo and iface.index != s.ifindex;
                    if (!echo and lan.lost(s.segment)) {
                        lan.sent.items[sent_idx].lost += 1;
                        continue;
                    }
                    const from = sourceAddrOf(src_iface, s.family, iface.index).?;
                    const meta: RxMeta = .{ .from = from, .ifindex = iface.index, .dst_multicast = true };
                    n.engine.handle(s.bytes, meta, now_us);
                    lan.sent.items[sent_idx].delivered += 1;
                    try lan.deliveries.append(lan.gpa, .{
                        .sent = sent_idx,
                        .from_engine = s.from_engine,
                        .to_engine = ti,
                        .meta = meta,
                        .echo = echo,
                        .bridged = bridged,
                        .now_us = now_us,
                    });
                }
            }
        }

        fn deliverUnicast(lan: *Self, sent_idx: usize, now_us: u64) !void {
            const s = lan.sent.items[sent_idx];
            const sender = &lan.nodes[s.from_engine];
            const src_iface = sender.ifaceOf(s.ifindex).?;
            var ti: usize = 0;
            while (ti < lan.nodes_len) : (ti += 1) {
                const n = &lan.nodes[ti];
                for (n.ifaces.slice(), 0..) |*iface, k| {
                    if (!lan.connected(s.segment, n.segments[k])) continue;
                    if (!ownsAddr(iface, s.to)) continue;
                    const echo = ti == s.from_engine;
                    if (!echo and lan.lost(s.segment)) {
                        lan.sent.items[sent_idx].lost += 1;
                        return;
                    }
                    const from = sourceAddrOf(src_iface, s.family, iface.index).?;
                    const meta: RxMeta = .{ .from = from, .ifindex = iface.index, .dst_multicast = false };
                    n.engine.handle(s.bytes, meta, now_us);
                    lan.sent.items[sent_idx].delivered += 1;
                    try lan.deliveries.append(lan.gpa, .{
                        .sent = sent_idx,
                        .from_engine = s.from_engine,
                        .to_engine = ti,
                        .meta = meta,
                        .echo = echo,
                        .bridged = echo and iface.index != s.ifindex,
                        .now_us = now_us,
                    });
                    return;
                }
            }
            lan.harness_stats.tx_unroutable += 1;
        }

        fn lost(lan: *Self, segment: u32) bool {
            const p = lan.loss[segment];
            if (p <= 0) return false;
            if (p >= 1) return true;
            const r = lan.random orelse return false;
            return r.float(f32) < p;
        }
    };
}

/// The address the OS would stamp on a datagram leaving `iface` in
/// `family`: the first v4 address, or the first link-local v6 address
/// (else the first v6 address) with `.interface.index = scope_ifindex`
/// (the receiver's interface, as `IPV6_RECVPKTINFO` scopes it).
pub fn sourceAddrOf(iface: *const Interface, family: Family, scope_ifindex: u32) ?Io.net.IpAddress {
    switch (family) {
        .v4 => {
            if (iface.v4.len == 0) return null;
            return .{ .ip4 = .{ .bytes = iface.v4.slice()[0].addr, .port = mdns_port } };
        },
        .v6 => {
            if (iface.v6.len == 0) return null;
            var pick = iface.v6.slice()[0];
            for (iface.v6.slice()) |p| if (p.isLinkLocal()) {
                pick = p;
                break;
            };
            return .{ .ip6 = .{ .bytes = pick.addr, .port = mdns_port, .interface = .{ .index = scope_ifindex } } };
        },
    }
}

fn hasFamily(iface: *const Interface, family: Family) bool {
    return switch (family) {
        .v4 => iface.v4.len != 0,
        .v6 => iface.v6.len != 0,
    };
}

fn ownsAddr(iface: *const Interface, a: Io.net.IpAddress) bool {
    return switch (a) {
        .ip4 => |v| iface.hasAddr4(v.bytes),
        .ip6 => |v| iface.hasAddr6(v.bytes),
    };
}

/// Stamp the receiver's ifindex on a v6 source (the kernel's scope id).
fn scoped(a: Io.net.IpAddress, ifindex: u32) Io.net.IpAddress {
    return switch (a) {
        .ip4 => a,
        .ip6 => |v| .{ .ip6 = .{ .bytes = v.bytes, .port = v.port, .flow = v.flow, .interface = .{ .index = ifindex } } },
    };
}

/// Query / response / malformed by `Message.parse` and the QR bit.
pub fn classify(bytes: []const u8) PacketKind {
    const msg = wire.Message.parse(bytes) catch return .malformed;
    return if (msg.isResponse()) .response else .query;
}

// ---- interface builders for tests -------------------------------------

/// `Interface{ index, name, v4 = [a.b.c.d/prefix] }`.
pub fn iface4(index: u32, name: []const u8, addr: [4]u8, prefix_len: u8) Interface {
    var i: Interface = .{ .index = index };
    i.name.appendSlice(name[0..@min(name.len, mdns.core.events.max_iface_name_len)]) catch unreachable;
    i.v4.append(.{ .addr = addr, .prefix_len = prefix_len }) catch unreachable;
    return i;
}

/// `iface4` plus one link-local v6 address `fe80::<suffix>/64`.
pub fn ifaceDual(index: u32, name: []const u8, addr4: [4]u8, prefix4: u8, ll_suffix: u16) Interface {
    var i = iface4(index, name, addr4, prefix4);
    i.v6.append(.{ .addr = linkLocal6(ll_suffix), .prefix_len = 64 }) catch unreachable;
    return i;
}

/// `fe80::<suffix>`.
pub fn linkLocal6(suffix: u16) [16]u8 {
    var a: [16]u8 = @splat(0);
    a[0] = 0xfe;
    a[1] = 0x80;
    std.mem.writeInt(u16, a[14..16], suffix, .big);
    return a;
}

// ---- self tests -------------------------------------------------------

const testing = std.testing;

test "classify and source address derivation" {
    var q: [12]u8 = @splat(0);
    try testing.expectEqual(PacketKind.query, classify(&q));
    q[2] = 0x84;
    try testing.expectEqual(PacketKind.response, classify(&q));
    try testing.expectEqual(PacketKind.malformed, classify(q[0..5]));

    const i = ifaceDual(3, "en0", .{ 10, 1, 2, 3 }, 24, 0x0303);
    const s4 = sourceAddrOf(&i, .v4, 9).?;
    try testing.expectEqual([4]u8{ 10, 1, 2, 3 }, s4.ip4.bytes);
    try testing.expectEqual(mdns_port, s4.ip4.port);
    const s6 = sourceAddrOf(&i, .v6, 9).?;
    try testing.expectEqual(linkLocal6(0x0303), s6.ip6.bytes);
    try testing.expectEqual(@as(u32, 9), s6.ip6.interface.index);
    const only4 = iface4(4, "en1", .{ 10, 1, 2, 4 }, 24);
    try testing.expectEqual(null, sourceAddrOf(&only4, .v6, 4));
    try testing.expect(isMulticastAddr(.{ .ip4 = .{ .bytes = group_v4, .port = mdns_port } }));
    try testing.expect(!isMulticastAddr(s4));
}

test "bridging is symmetric and transitive" {
    var lan: FakeLan(2) = .init(testing.allocator);
    defer lan.deinit();
    try testing.expect(lan.connected(0, 0));
    try testing.expect(!lan.connected(0, 1));
    try lan.bridge(0, 1);
    try lan.bridge(1, 2);
    try lan.bridge(1, 0); // duplicate, ignored
    try testing.expectEqual(@as(usize, 2), lan.bridges.len);
    try testing.expect(lan.connected(0, 1));
    try testing.expect(lan.connected(1, 0));
    try testing.expect(lan.connected(0, 2));
    try testing.expect(!lan.connected(0, 3));
    lan.unbridge(0, 1);
    try testing.expect(!lan.connected(0, 2));
    try testing.expect(lan.connected(1, 2));
    try testing.expectError(error.SegmentOutOfRange, lan.bridge(0, FakeLan(2).max_segments));
}
