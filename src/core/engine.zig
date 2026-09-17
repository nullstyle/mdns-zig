//! Engine: the sans-IO core behind `Service` (plan section 4.2, section 5).
//!
//! Contract: `handle` never returns an error and never allocates; `tick`
//! fires due timers; `pollDatagram` drains outbound into the caller's
//! buffer and never allocates; `nextDeadline` returns the next timer;
//! `pollEvent` returns a value-type event. `now_us` is `u64`
//! microseconds from a caller-owned origin; randomness is the injected
//! `std.Random`. Every pool is preallocated in `init` from `Limits`.
//! This file never imports `platform`.
//!
//! What lives here (M3): the interface table with its joined (ifindex,
//! family) pairs, the own-echo ring, the ingress checks of plan sections
//! 4.6 and 4.8 (malformed, ignored opcode / rcode, source port, section
//! 11 on-link, the 2 s QU window for unicast responses), the event ring
//! and the counters. The querier (`core/querier.zig`) owns browses, the
//! cache and the resolve join. The responder (`core/responder.zig`, M4)
//! owns registrations, the host record set, probing, announcing,
//! answering, conflicts and goodbyes; `advertise`, `withdraw` and
//! `updateTxt` forward to it.
//!
//! Ingress order in `handle`:
//! 1. own echo: the datagram digest is in the echo ring
//!    (`timers.echo_window_us`, 1 s) AND the source address is one of
//!    our interface addresses (plan section 4.8; both tests, never one).
//!    A bridged echo (arrival interface is not the one that owns the
//!    source address) is noted for the M4 re-announce hook. Echoes count
//!    in `stats.rx_echo`. A response or a probe (Authority section
//!    present) goes no further: our own records are never cached from an
//!    echo and never read as a conflict. A plain query (QR=0, no
//!    Authority) continues to step 2 and is answered like any other: on
//!    one host a second program's browse query for the same type is
//!    byte-identical to ours (ID 0, one question, empty known-answer list,
//!    RFC 6762 section 18.1) AND comes from our own address, so both echo
//!    tests pass for it; dropping it left that program unanswered
//!    (v0.1.1, `byte-identical query from our own address is still
//!    answered`). The price is answering our own ladder queries when we
//!    browse a type we advertise (about 36 answers per pair per day, the
//!    1 s rate rule and the known-answer list bound it); such answers
//!    count in `stats.rx_echo_answered`.
//! 2. `wire.Message.parse`: malformed -> `dropped_malformed`.
//! 3. OPCODE != 0 or RCODE != 0 -> `dropped_ignored` (RFC 6762 sections
//!    18.3, 18.11).
//! 4. QR=1 from a source port other than 5353 -> `dropped_bad_port`
//!    (section 6; plan section 4.6).
//! 5. unicast destination: section 11 on-link check against the arrival
//!    interface's kept prefixes -> `dropped_off_link`; then a unicast
//!    response is accepted only within 2 s of our own QU query (plan
//!    section 4.8 "Port sharing"): browse queries never set QU, so in M3
//!    every unicast response -> `dropped_unicast_unexpected`. Multicast-
//!    destination packets skip both. When the platform could not report
//!    the destination (`dst_known = false`, counted in `rx_dst_unknown`)
//!    the on-link check still runs but the QU-window drop does not: on
//!    such a socket every multicast response would otherwise be dropped
//!    and browsing would silently die.
//! 6. responses -> `Querier.handleResponse` and
//!    `Responder.handleResponse` (conflict detection on our unique names,
//!    section 9); queries -> `Responder.handleQuery`. A querier's
//!    known-answer list is never cached (section 7.1).
const std = @import("std");
const Io = std.Io;
const wire = @import("../wire/root.zig");
const events = @import("events.zig");
const timers = @import("timers.zig");
const echo_ring = @import("echo_ring.zig");
const querier_mod = @import("querier.zig");
const responder_mod = @import("responder.zig");

pub const Event = events.Event;
pub const Warning = events.Warning;
pub const Interface = events.Interface;
pub const Limits = events.Limits;
pub const Stats = events.Stats;
pub const ServiceDesc = events.ServiceDesc;
pub const TxtPair = events.TxtPair;
pub const Txt = events.Txt;
pub const RegId = events.RegId;
pub const BrowseId = events.BrowseId;
pub const Family = events.Family;
pub const Querier = querier_mod.Querier;
pub const Responder = responder_mod.Responder;
pub const validateHostLabel = responder_mod.validateHostLabel;
pub const EchoRing = echo_ring.EchoRing;

/// mDNS port (RFC 6762 section 2): the source-port rule and the
/// destination of our own queries.
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
        /// False when another stack shares 5353 (`Service.firstBinder()`):
        /// probes are defended by multicast plus the unicast copy (plan
        /// section 4.8, "Port sharing").
        first_binder: bool = true,
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
        /// False when the platform delivered no destination-address cmsg
        /// and `dst_multicast` is a guess: the on-link check applies, the
        /// QU-window drop does not (see the module doc, step 5).
        dst_known: bool = true,
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

    /// Joined state of one interface, per family. `setInterfaces` marks
    /// every family that has an address as joined; `setJoined` is the
    /// Service's correction (a failed join, Linux `lo` v6, Revision 5).
    pub const Joined = struct { v4: bool = false, v6: bool = false };

    /// A bridged own echo (plan section 4.8): our own datagram came back
    /// on an interface other than the one whose address it carries. M4's
    /// responder re-announces that interface's address RRSet from here.
    pub const BridgedEcho = struct { sent_ifindex: u32, arrival_ifindex: u32, now_us: u64 };

    /// `InvalidHostLabel`: `Options.host_label` is not one label of 1..63
    /// octets of UTF-8 without control characters (Revision 5 item 8).
    pub const InitError = error{ OutOfMemory, InvalidHostLabel };
    pub const SetInterfacesError = error{LimitReached};

    pub const AdvertiseError = responder_mod.AdvertiseError;
    pub const UpdateTxtError = responder_mod.UpdateTxtError;
    pub const BrowseError = querier_mod.BrowseError;

    /// Pairs the Engine can hand the querier per tick.
    const max_pairs = 2 * (std.math.maxInt(u8) + 1);

    gpa: std.mem.Allocator,
    host_label: events.Bounded(u8, max_host_label_len),
    random: std.Random,
    limits: Limits,
    qu_allowed: bool,
    first_binder: bool,
    max_addrs_per_iface: u8,

    /// Interface table (`limits.max_interfaces` slots, allocated once)
    /// and the joined flags parallel to it.
    ifaces: []Interface,
    joined: []Joined,
    ifaces_len: usize,

    /// Event ring (`limits.max_events` slots, allocated once; drop-oldest).
    ring: EventQueue,
    events_dropped_warned: bool,

    counters: Stats,

    querier: Querier,
    responder: Responder,
    echoes: EchoRing,
    /// Time of our last QU query (a probe with QU): the 2 s unicast
    /// window.
    last_qu_query_us: ?u64,
    /// Last bridged echo seen (the M4 hook reads and clears it).
    bridged_echo: ?BridgedEcho,

    /// Preallocates every pool sized by `opts.limits`. The only allocation
    /// the Engine ever makes; `handle`, `tick` and `pollDatagram` never
    /// allocate.
    pub fn init(gpa: std.mem.Allocator, opts: Options) InitError!Engine {
        const n_ifaces: usize = @max(@as(usize, opts.limits.max_interfaces), 1);
        const ifaces = try gpa.alloc(Interface, n_ifaces);
        errdefer gpa.free(ifaces);
        const joined = try gpa.alloc(Joined, n_ifaces);
        errdefer gpa.free(joined);
        const n_events: usize = @max(@as(usize, opts.limits.max_events), 1);
        const ring_buf = try gpa.alloc(Event, n_events);
        errdefer gpa.free(ring_buf);
        var querier = try Querier.init(gpa, opts.limits, opts.random);
        errdefer querier.deinit(gpa);
        try responder_mod.validateHostLabel(opts.host_label);
        var responder = try Responder.init(gpa, opts.limits, opts.host_label);
        errdefer responder.deinit(gpa);

        var label: events.Bounded(u8, max_host_label_len) = .{};
        label.appendSlice(opts.host_label) catch unreachable; // validated <= 63
        @memset(joined, .{});

        return .{
            .gpa = gpa,
            .host_label = label,
            .random = opts.random,
            .limits = opts.limits,
            .qu_allowed = opts.qu_allowed,
            .first_binder = opts.first_binder,
            .max_addrs_per_iface = @min(opts.max_addrs_per_iface, events.max_addrs_per_family),
            .ifaces = ifaces,
            .joined = joined,
            .ifaces_len = 0,
            .ring = .{ .buf = ring_buf },
            .events_dropped_warned = false,
            .counters = .{},
            .querier = querier,
            .responder = responder,
            .echoes = .empty,
            .last_qu_query_us = null,
            .bridged_echo = null,
        };
    }

    pub fn deinit(e: *Engine) void {
        e.responder.deinit(e.gpa);
        e.querier.deinit(e.gpa);
        e.gpa.free(e.ring.buf);
        e.gpa.free(e.joined);
        e.gpa.free(e.ifaces);
        e.* = undefined;
    }

    fn sink(e: *Engine) querier_mod.Sink {
        return .{ .ctx = e, .emit = emitFromQuerier };
    }

    fn emitFromQuerier(ctx: *anyopaque, ev: Event) void {
        const e: *Engine = @ptrCast(@alignCast(ctx));
        e.pushEvent(ev);
    }

    /// The responder's view of the Engine for one call: the interface
    /// table, the joined pairs (in `pairs`, caller storage), the
    /// port-sharing flags and the event sink.
    fn env(e: *Engine, pairs: *[max_pairs]querier_mod.Pair) responder_mod.Env {
        return .{
            .ifaces = e.ifaces[0..e.ifaces_len],
            .pairs = e.joinedPairs(pairs),
            .random = e.random,
            .qu_allowed = e.qu_allowed,
            .first_binder = e.first_binder,
            .sink = e.sink(),
        };
    }

    /// `first_binder` after init (`Service` learns it from the trial
    /// bind before the Engine exists; this is for embedders that build
    /// the Engine first).
    pub fn setFirstBinder(e: *Engine, first_binder: bool) void {
        e.first_binder = first_binder;
        e.qu_allowed = first_binder;
    }

    pub fn firstBinder(e: *const Engine) bool {
        return e.first_binder;
    }

    // ---- interfaces ---------------------------------------------------

    /// Replace the interface table. Keeps the first `max_addrs_per_iface`
    /// addresses per family in the order given, adds every drop (the
    /// `Interface.*_dropped` counts from `ifaces.zig` plus its own cap)
    /// into `stats.addrs_dropped`, emits `warning.addrs_truncated` once
    /// per (interface, family) that lost an address in this call, and
    /// `.interfaces_changed` when the table differs from the previous one.
    /// A family with at least one address starts as joined (see
    /// `setJoined`); joined flags of interfaces already in the table are
    /// carried over. An added interface restarts every browse ladder so
    /// the new link hears our questions (M4 adds probing there). A
    /// removed interface takes its cache scope with it: every record
    /// heard on it is dropped through the expiry path (`lost` for its
    /// browsed instances, after `.interfaces_changed`), because the
    /// per-interface cache key means nothing could ever refresh them.
    pub fn setInterfaces(e: *Engine, ifs: []const Interface, now_us: u64) SetInterfacesError!void {
        if (ifs.len > e.ifaces.len) return error.LimitReached;

        var changed = ifs.len != e.ifaces_len;
        var added = false;
        var new_joined: [max_pairs / 2]Joined = @splat(.{});
        var removed: [max_pairs / 2]u32 = undefined;
        var removed_len: usize = 0;
        // Interfaces that are new or changed their addresses: the
        // responder announces its records there (M4).
        var fresh: [max_pairs / 2]u32 = undefined;
        var fresh_len: usize = 0;
        for (e.ifaces[0..e.ifaces_len]) |*old| {
            var kept = false;
            for (ifs) |*n| if (n.index == old.index) {
                kept = true;
                break;
            };
            if (!kept) {
                removed[removed_len] = old.index;
                removed_len += 1;
            }
        }
        // Pass 1 reads the old table: drops, warnings, change detection
        // and the joined flags. Pass 2 overwrites it.
        var i: usize = 0;
        while (i < ifs.len) : (i += 1) {
            const c = e.capped(&ifs[i]);
            e.counters.addrs_dropped += c.dropped4 + c.dropped6;
            if (c.dropped4 != 0) e.pushEvent(.{ .warning = .{ .addrs_truncated = .{ .ifindex = c.iface.index, .family = .v4 } } });
            if (c.dropped6 != 0) e.pushEvent(.{ .warning = .{ .addrs_truncated = .{ .ifindex = c.iface.index, .family = .v6 } } });

            if (e.findSlot(c.iface.index)) |s| {
                const old = &e.ifaces[s];
                if (!old.sameAddrs(&c.iface)) {
                    changed = true;
                    fresh[fresh_len] = c.iface.index;
                    fresh_len += 1;
                }
                new_joined[i] = .{
                    .v4 = (e.joined[s].v4 or old.v4.len == 0) and c.iface.v4.len != 0,
                    .v6 = (e.joined[s].v6 or old.v6.len == 0) and c.iface.v6.len != 0,
                };
            } else {
                changed = true;
                added = true;
                fresh[fresh_len] = c.iface.index;
                fresh_len += 1;
                new_joined[i] = .{ .v4 = c.iface.v4.len != 0, .v6 = c.iface.v6.len != 0 };
            }
        }
        i = 0;
        while (i < ifs.len) : (i += 1) e.ifaces[i] = e.capped(&ifs[i]).iface;
        e.ifaces_len = ifs.len;
        @memcpy(e.joined[0..ifs.len], new_joined[0..ifs.len]);
        if (changed) e.pushEvent(.interfaces_changed);
        for (removed[0..removed_len]) |ifindex| e.querier.dropInterface(ifindex, e.sink());
        if (added) e.querier.restartSchedules(now_us);
        if (fresh_len != 0) {
            var pairs: [max_pairs]querier_mod.Pair = undefined;
            const rx = e.env(&pairs);
            for (fresh[0..fresh_len]) |ifindex| e.responder.onInterfaceAdded(&rx, ifindex, now_us);
        }
    }

    const Capped = struct { iface: Interface, dropped4: u64, dropped6: u64 };

    /// `iface` with at most `max_addrs_per_iface` addresses per family,
    /// plus the total drops (its own `*_dropped` counts and this cap).
    fn capped(e: *const Engine, iface: *const Interface) Capped {
        var kept = iface.*;
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
        return .{ .iface = kept, .dropped4 = dropped4, .dropped6 = dropped6 };
    }

    /// The current table (what `setInterfaces` kept).
    pub fn interfaces(e: *const Engine) []const Interface {
        return e.ifaces[0..e.ifaces_len];
    }

    /// Record whether the multicast group is joined on `(ifindex,
    /// family)`. Queries (and, in M4, announcements) go out only on joined
    /// pairs (Revision 5 item 1). Unknown `ifindex` is ignored.
    pub fn setJoined(e: *Engine, ifindex: u32, family: Family, joined: bool) void {
        const s = e.findSlot(ifindex) orelse return;
        switch (family) {
            .v4 => e.joined[s].v4 = joined,
            .v6 => e.joined[s].v6 = joined,
        }
    }

    pub fn isJoined(e: *const Engine, ifindex: u32, family: Family) bool {
        const s = e.findSlot(ifindex) orelse return false;
        return switch (family) {
            .v4 => e.joined[s].v4,
            .v6 => e.joined[s].v6,
        };
    }

    fn findSlot(e: *const Engine, index: u32) ?usize {
        for (e.ifaces[0..e.ifaces_len], 0..) |*i, s| if (i.index == index) return s;
        return null;
    }

    fn findInterface(e: *const Engine, index: u32) ?*const Interface {
        const s = e.findSlot(index) orelse return null;
        return &e.ifaces[s];
    }

    /// Every joined (ifindex, family) pair, v4 before v6 per interface.
    fn joinedPairs(e: *const Engine, out: *[max_pairs]querier_mod.Pair) []const querier_mod.Pair {
        var n: usize = 0;
        for (e.ifaces[0..e.ifaces_len], 0..) |*i, s| {
            if (e.joined[s].v4 and i.v4.len != 0) {
                out[n] = .{ .ifindex = i.index, .family = .v4 };
                n += 1;
            }
            if (e.joined[s].v6 and i.v6.len != 0) {
                out[n] = .{ .ifindex = i.index, .family = .v6 };
                n += 1;
            }
        }
        return out[0..n];
    }

    /// The interface that owns `addr` (one of our own source addresses),
    /// or null.
    fn ownerOf(e: *const Engine, addr: Io.net.IpAddress) ?u32 {
        for (e.ifaces[0..e.ifaces_len]) |*i| {
            const owns = switch (addr) {
                .ip4 => |a| i.hasAddr4(a.bytes),
                .ip6 => |a| i.hasAddr6(a.bytes),
            };
            if (owns) return i.index;
        }
        return null;
    }

    /// RFC 6762 section 11: is `addr` on-link for the arrival interface?
    /// With an unknown arrival interface every interface's prefixes are
    /// tried. A link-local v6 source is on-link by definition.
    pub fn onLink(e: *const Engine, addr: Io.net.IpAddress, ifindex: u32) bool {
        if (addr == .ip6 and events.isLinkLocal6(addr.ip6.bytes)) return true;
        if (e.findInterface(ifindex)) |i| return onLinkOf(i, addr);
        for (e.ifaces[0..e.ifaces_len]) |*i| if (onLinkOf(i, addr)) return true;
        return false;
    }

    fn onLinkOf(i: *const Interface, addr: Io.net.IpAddress) bool {
        return switch (addr) {
            .ip4 => |a| i.onLink4(a.bytes),
            .ip6 => |a| i.onLink6(a.bytes),
        };
    }

    // ---- registrations ------------------------------------------------

    /// Register one DNS-SD instance (RFC 6763 section 4): validates the
    /// type (RFC 6335), the instance label (1..63 octets of UTF-8) and
    /// the TXT (at most 400 octets), then starts probing (RFC 6762
    /// section 8.1; the host's address records are probed with the first
    /// registration). `registered` fires after the second announcement.
    pub fn advertise(e: *Engine, desc: ServiceDesc, now_us: u64) AdvertiseError!RegId {
        var pairs: [max_pairs]querier_mod.Pair = undefined;
        const rx = e.env(&pairs);
        return e.responder.advertise(&rx, desc, now_us);
    }

    /// The validating half of `advertise`, without a clock: the typed
    /// errors are returned now and the slot is taken (`Service.advertise`
    /// returns this id synchronously), but nothing is scheduled until
    /// `startRegistration`. Plan section 4.2: the Service applies the
    /// start at its next tick with that tick's `now_us`.
    pub fn reserveRegistration(e: *Engine, desc: ServiceDesc) AdvertiseError!RegId {
        return e.responder.reserve(desc);
    }

    /// The scheduling half of `advertise`: start probing a reserved
    /// registration from `now_us`. Any other id is ignored.
    pub fn startRegistration(e: *Engine, id: RegId, now_us: u64) void {
        var pairs: [max_pairs]querier_mod.Pair = undefined;
        const rx = e.env(&pairs);
        e.responder.start(&rx, id, now_us);
    }

    /// Schedule a goodbye (TTL 0, RFC 6762 section 10.1) for the
    /// registration's records, and for the host's when it was the last
    /// one. Unknown ids are ignored.
    pub fn withdraw(e: *Engine, id: RegId, now_us: u64) void {
        var pairs: [max_pairs]querier_mod.Pair = undefined;
        const rx = e.env(&pairs);
        e.responder.withdraw(&rx, id, now_us);
    }

    /// Withdraw every registration (`Service.deinit`'s goodbye flush).
    pub fn withdrawAll(e: *Engine, now_us: u64) void {
        var pairs: [max_pairs]querier_mod.Pair = undefined;
        const rx = e.env(&pairs);
        e.responder.withdrawAll(&rx, now_us);
    }

    /// Replace the TXT rdata (RFC 6762 section 8.4: two announcements
    /// with cache-flush, no probe; identical rdata is a no-op; deferred
    /// while probing; over 400 B is `error.TxtTooLarge` and keeps the old
    /// TXT).
    pub fn updateTxt(e: *Engine, id: RegId, txt: []const TxtPair, now_us: u64) UpdateTxtError!void {
        var pairs: [max_pairs]querier_mod.Pair = undefined;
        const rx = e.env(&pairs);
        return e.responder.updateTxt(&rx, id, txt, now_us);
    }

    /// `updateTxt` with the rdata already encoded by `Txt.build`
    /// (`Service.updateTxt` validates at the call and applies the built
    /// TXT at its next tick).
    pub fn updateTxtBuilt(e: *Engine, id: RegId, txt: Txt, now_us: u64) error{UnknownRegistration}!void {
        var pairs: [max_pairs]querier_mod.Pair = undefined;
        const rx = e.env(&pairs);
        return e.responder.updateTxtBuilt(&rx, id, txt, now_us);
    }

    /// True while `id` names a live (reserved, probing, announcing or
    /// established) registration.
    pub fn hasRegistration(e: *const Engine, id: RegId) bool {
        return e.responder.regState(id) != null;
    }

    /// Live registrations.
    pub fn registrationCount(e: *const Engine) usize {
        return e.responder.count();
    }

    /// Our host name (`<label>.local`, after any rename).
    pub fn hostName(e: *const Engine) wire.Name {
        return e.responder.hostName();
    }

    // ---- browses ------------------------------------------------------

    /// Start browsing `service_type` (`_qmsg._udp`; RFC 6763 section 7).
    /// Resolve is automatic: `found`, then `resolved` once SRV, TXT and an
    /// address are known. The first query goes out 20-120 ms from
    /// `now_us`, QM, on every joined pair.
    pub fn browse(e: *Engine, service_type: []const u8, now_us: u64) BrowseError!BrowseId {
        return e.querier.browse(service_type, now_us, e.sink());
    }

    /// The two halves of `browse` for the `Service`'s queued mutations
    /// (plan section 4.2, like `reserveRegistration` / `startRegistration`):
    /// validate and take the slot now, without a clock; schedule at the
    /// next tick with that tick's `now_us`. `stopBrowse` frees a reserved
    /// id like a started one.
    pub fn reserveBrowse(e: *Engine, service_type: []const u8) BrowseError!BrowseId {
        return e.querier.reserveBrowse(service_type);
    }
    pub fn startBrowse(e: *Engine, id: BrowseId, now_us: u64) void {
        e.querier.startBrowse(id, now_us, e.sink());
    }

    /// Stop the query schedule and the `found` / `lost` / `resolved`
    /// stream for that type; cached records stay until they expire.
    pub fn stopBrowse(e: *Engine, id: BrowseId, now_us: u64) void {
        e.querier.stopBrowse(id, now_us);
    }

    /// Active browses.
    pub fn browseCount(e: *const Engine) usize {
        return e.querier.browseCount();
    }

    /// Cached records (for tests and diagnostics).
    pub fn cacheCount(e: *const Engine) usize {
        return e.querier.cache.count();
    }

    // ---- packets ------------------------------------------------------

    /// Feed one received datagram. Never fails, never allocates. See the
    /// module doc for the ingress order and the counters.
    pub fn handle(e: *Engine, datagram: []const u8, meta: RxMeta, now_us: u64) void {
        e.counters.rx += 1;

        // 1. own echo (plan section 4.8): both tests, never one alone.
        if (e.echoes.matches(datagram, now_us)) {
            if (e.ownerOf(meta.from)) |sent_ifindex| {
                e.counters.rx_echo += 1;
                if (meta.ifindex != 0 and meta.ifindex != sent_ifindex) {
                    e.onBridgedEcho(datagram, sent_ifindex, meta.ifindex, now_us);
                }
                // A response or a probe stops here (conflict logic, no
                // self-caching). A plain query is answered anyway: on one
                // host a peer program's query can be byte-identical to
                // ours and arrive from our own address (module doc, 1).
                if (!isPlainQuery(datagram)) return;
                e.counters.rx_echo_answered += 1;
            }
        }

        // 2. parse.
        const msg = wire.Message.parse(datagram) catch {
            e.counters.dropped_malformed += 1;
            return;
        };
        // 3. RFC 6762 sections 18.3 and 18.11.
        if (msg.header.flags.opcode != 0 or msg.header.flags.rcode != 0) {
            e.counters.dropped_ignored += 1;
            return;
        }
        // 4. source port (section 6).
        if (msg.isResponse() and sourcePort(meta.from) != mdns_port) {
            e.counters.dropped_bad_port += 1;
            return;
        }
        // 5. unicast destination: on-link, then the QU window.
        if (!meta.dst_known) e.counters.rx_dst_unknown += 1;
        if (!meta.dst_multicast) {
            if (!e.onLink(meta.from, meta.ifindex)) {
                e.counters.dropped_off_link += 1;
                return;
            }
            if (meta.dst_known and msg.isResponse() and !e.inQuWindow(now_us)) {
                e.counters.dropped_unicast_unexpected += 1;
                return;
            }
        }
        // 6. dispatch.
        var pairs: [max_pairs]querier_mod.Pair = undefined;
        const rx = e.env(&pairs);
        if (msg.isResponse()) {
            e.querier.handleResponse(&msg, meta.ifindex, now_us, e.sink());
            e.responder.handleResponse(&rx, &msg, now_us);
        } else {
            // A multicast query skipped the section 11 check above; the
            // responder still needs it for the unicast reply target
            // (legacy and QU replies never go off-link).
            const on_link = !meta.dst_multicast or e.onLink(meta.from, meta.ifindex);
            e.responder.handleQuery(&rx, &msg, .{
                .from = meta.from,
                .ifindex = meta.ifindex,
                .source_port = sourcePort(meta.from),
                .dst_unicast = meta.dst_known and !meta.dst_multicast,
                .on_link = on_link,
            }, now_us);
        }
    }

    /// QR=0 with an empty Authority section: a browse, resolve or
    /// follow-up query, never a probe. Our own probes always carry the
    /// proposed records in Authority (RFC 6762 section 8.1; the responder
    /// emits `nscount != 0` for every probe), so an echoed probe still
    /// stops at step 1 and never reaches the tie-break or defence paths.
    /// A 12-byte header peek; no allocation.
    fn isPlainQuery(datagram: []const u8) bool {
        const h = wire.Header.parse(datagram) catch return false;
        return !h.flags.qr and h.nscount == 0;
    }

    /// Plan section 4.8 "Port sharing": a unicast response is ours only
    /// within 2 s of our own QU query.
    fn inQuWindow(e: *const Engine, now_us: u64) bool {
        const last = e.last_qu_query_us orelse return false;
        return now_us -| last <= timers.qu_unicast_window_us;
    }

    /// Plan section 4.8 "Bridged echo": our own datagram came back on
    /// `arrival_ifindex` from `sent_ifindex`'s address. When it carried
    /// cache-flush A/AAAA for our host name it just flushed our
    /// `arrival_ifindex` addresses out of every cache on that link, so
    /// the responder re-announces that interface's address RRSet under
    /// the one-second rule (section 10.2).
    fn onBridgedEcho(e: *Engine, datagram: []const u8, sent_ifindex: u32, arrival_ifindex: u32, now_us: u64) void {
        e.counters.rx_echo_bridged += 1;
        e.bridged_echo = .{ .sent_ifindex = sent_ifindex, .arrival_ifindex = arrival_ifindex, .now_us = now_us };
        const msg = wire.Message.parse(datagram) catch return;
        if (!msg.isResponse()) return;
        const host = e.responder.hostName();
        var it = msg.allRecords();
        while (it.next()) |rec| {
            if (!rec.cache_flush) continue;
            if (rec.rtype != .a and rec.rtype != .aaaa) continue;
            if (!rec.name.eql(&host)) continue;
            var pairs: [max_pairs]querier_mod.Pair = undefined;
            const rx = e.env(&pairs);
            e.responder.reannounceAddresses(&rx, arrival_ifindex, now_us);
            return;
        }
    }

    /// The last bridged echo, cleared on read (M4 consumes it).
    pub fn takeBridgedEcho(e: *Engine) ?BridgedEcho {
        const b = e.bridged_echo;
        e.bridged_echo = null;
        return b;
    }

    fn sourcePort(addr: Io.net.IpAddress) u16 {
        return switch (addr) {
            .ip4 => |a| a.port,
            .ip6 => |a| a.port,
        };
    }

    /// Fire due timers: the responder's probe and announce steps, then
    /// cache expiry (`lost`, `resolved` re-emits on address-set changes),
    /// browse queries, follow-ups and requery marks. Due packets are
    /// queued for every joined (interface, family) pair and drained by
    /// `pollDatagram`.
    pub fn tick(e: *Engine, now_us: u64) void {
        var pairs: [max_pairs]querier_mod.Pair = undefined;
        const rx = e.env(&pairs);
        e.responder.tick(&rx, now_us);
        e.querier.tick(now_us, rx.pairs, e.sink());
    }

    /// Drain one outbound datagram into `buf`. Never allocates. Queries
    /// are QM with ID 0 (RFC 6762 section 18.1), to 224.0.0.251:5353 or
    /// [ff02::fb]:5353 with the egress interface as the v6 scope; every
    /// sent datagram is recorded in the echo ring.
    ///
    /// A job queued by `tick` for a pair that is no longer joined (its
    /// interface left the table or lost its membership between the tick
    /// and this drain) is not sent: it is a counted `tx_dropped`, so the
    /// platform never sees a pktinfo naming an interface it does not
    /// have.
    pub fn pollDatagram(e: *Engine, buf: []u8, now_us: u64) ?TxDatagram {
        // Responder packets first: answers and probe defences are the
        // time-critical ones.
        {
            var pairs: [max_pairs]querier_mod.Pair = undefined;
            const rx = e.env(&pairs);
            while (e.responder.pollDatagram(&rx, buf, now_us)) |b| {
                if (!e.isJoined(b.pair.ifindex, b.pair.family)) {
                    e.counters.tx_dropped += 1;
                    e.responder.dropJobsOn(b.pair);
                    continue;
                }
                e.echoes.record(buf[0..b.len], now_us);
                e.counters.tx += 1;
                if (b.qu) e.last_qu_query_us = now_us;
                return .{
                    .len = b.len,
                    .to = b.to orelse e.groupOf(b.pair),
                    .ifindex = b.pair.ifindex,
                };
            }
        }
        const built = while (e.querier.buildNext(buf, now_us)) |b| {
            if (e.isJoined(b.pair.ifindex, b.pair.family)) break b;
            e.counters.tx_dropped += 1;
        } else return null;
        e.echoes.record(buf[0..built.len], now_us);
        e.counters.tx += 1;
        return .{
            .len = built.len,
            .to = e.groupOf(built.pair),
            .ifindex = built.pair.ifindex,
        };
    }

    /// The multicast group of the pair's family, scoped to its
    /// interface for v6.
    fn groupOf(e: *const Engine, pair: querier_mod.Pair) Io.net.IpAddress {
        _ = e;
        return switch (pair.family) {
            .v4 => .{ .ip4 = .{ .bytes = group_v4, .port = mdns_port } },
            .v6 => .{ .ip6 = .{ .bytes = group_v6, .port = mdns_port, .interface = .{ .index = pair.ifindex } } },
        };
    }

    /// The next timer, or null when nothing is scheduled. When a datagram
    /// is already queued the deadline is `now_us` so the caller drains at
    /// once.
    pub fn nextDeadline(e: *const Engine, now_us: u64) ?u64 {
        if (e.querier.hasPendingTx()) return now_us;
        const q = e.querier.nextDeadline();
        const r = e.responder.nextDeadline(now_us);
        if (q) |a| {
            if (r) |b| return @min(a, b);
            return a;
        }
        return r;
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

    /// Engine counters plus the cache's (`evictions`, `evictions_pinned`,
    /// `txt_truncated`, `cache_rejected`) and the querier's
    /// (`instances_dropped`, `questions_deferred`).
    pub fn stats(e: *const Engine) Stats {
        var st = e.counters;
        const cs = &e.querier.cache.stats;
        st.evictions += cs.evictions;
        st.evictions_pinned += cs.evictions_pinned;
        st.txt_truncated += cs.txt_truncated;
        st.cache_rejected += cs.rejected_oversize + cs.rejected_full;
        st.instances_dropped += e.querier.stats.instances_dropped;
        st.questions_deferred += e.querier.stats.questions_deferred;
        const rs = &e.responder.stats;
        st.conflicts += rs.conflicts;
        st.answers_dropped += rs.answers_dropped;
        st.tx_dropped += rs.jobs_dropped;
        st.dropped_off_link += rs.queries_off_link;
        st.dropped_bad_port += rs.queries_bad_port;
        return st;
    }

    /// Responder-side counters.
    pub fn responderStats(e: *const Engine) responder_mod.RStats {
        return e.responder.stats;
    }

    /// Querier-side counters (instances without a resolve slot, deferred
    /// questions).
    pub fn querierStats(e: *const Engine) querier_mod.QStats {
        return e.querier.stats;
    }
};

/// The drop-oldest ring from `events.zig`, re-exported for `Service`.
pub const EventQueue = events.EventQueue;

// ---- tests -----------------------------------------------------------

const testing = std.testing;

/// The test PRNG must outlive the Engine (`std.Random` is a pointer to
/// it): a stack-local one dangles after `testEngine` returns.
var test_prng = std.Random.DefaultPrng.init(7);

fn testEngine(limits: Limits) !Engine {
    test_prng = std.Random.DefaultPrng.init(7);
    return Engine.init(testing.allocator, .{ .host_label = "unit", .random = test_prng.random(), .limits = limits });
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
    e.handle(&query, .{ .from = from_other, .ifindex = 1, .dst_multicast = true }, 0);
    try testing.expectEqual(@as(u64, 1), e.stats().dropped_bad_port);
    try testing.expectEqual(@as(u64, 4), e.stats().rx);
    // OPCODE != 0 and RCODE != 0 are ignored (sections 18.3, 18.11).
    var op: [12]u8 = @splat(0);
    op[2] = 0x08; // opcode 1
    e.handle(&op, .{ .from = from5353, .ifindex = 1, .dst_multicast = true }, 0);
    var rc: [12]u8 = @splat(0);
    rc[2] = 0x84;
    rc[3] = 0x03; // NXDOMAIN
    e.handle(&rc, .{ .from = from5353, .ifindex = 1, .dst_multicast = true }, 0);
    try testing.expectEqual(@as(u64, 2), e.stats().dropped_ignored);
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

    // Responder input validation.
    try testing.expectError(error.InvalidServiceType, e.advertise(.{ .service_type = "x", .instance = "a", .port = 1 }, 0));
    try testing.expectError(error.InvalidInstance, e.advertise(.{ .service_type = "_x._udp", .instance = "", .port = 1 }, 0));
}

test "engine joined pairs default to families with an address and follow setJoined" {
    var e = try testEngine(.{ .max_interfaces = 4 });
    defer e.deinit();
    try e.setInterfaces(&.{ testIface(3, 1, 1), testIface(4, 1, 0) }, 0);
    try testing.expect(e.isJoined(3, .v4));
    try testing.expect(e.isJoined(3, .v6));
    try testing.expect(e.isJoined(4, .v4));
    try testing.expect(!e.isJoined(4, .v6));
    e.setJoined(3, .v6, false);
    try testing.expect(!e.isJoined(3, .v6));
    // A re-set of the same table keeps the correction; a new interface
    // starts joined; a removed one is forgotten.
    try e.setInterfaces(&.{ testIface(3, 1, 1), testIface(5, 0, 1) }, 1);
    try testing.expect(!e.isJoined(3, .v6));
    try testing.expect(e.isJoined(3, .v4));
    try testing.expect(e.isJoined(5, .v6));
    try testing.expect(!e.isJoined(4, .v4));
    var pairs: [Engine.max_pairs]querier_mod.Pair = undefined;
    const joined = e.joinedPairs(&pairs);
    try testing.expectEqual(@as(usize, 2), joined.len);
    try testing.expectEqual(@as(u32, 3), joined[0].ifindex);
    try testing.expectEqual(Family.v4, joined[0].family);
    try testing.expectEqual(@as(u32, 5), joined[1].ifindex);
    try testing.expectEqual(Family.v6, joined[1].family);
}

test "egress skips a joined pair whose interface has no address of that family" {
    // The pure egress-filter decision behind `tick` / `pollDatagram`: a
    // datagram goes out on (ifindex, family) only when the Service
    // reported the join AND the interface holds an address of that
    // family (Revision 5 item 1). Neither alone is enough: a stale
    // `setJoined(true)` on an addressless family (a v6 join that
    // succeeded before the address went away, or Linux `lo` v6) must
    // not produce a send, and an address without a join must not either.
    var e = try testEngine(.{ .max_interfaces = 4 });
    defer e.deinit();
    try e.setInterfaces(&.{ testIface(3, 1, 0), testIface(4, 0, 1), testIface(5, 1, 1) }, 0);
    // Force the "joined but addressless" state the filter must reject.
    e.setJoined(3, .v6, true);
    e.setJoined(4, .v4, true);
    // And the "address but no join" state.
    e.setJoined(5, .v6, false);
    var pairs: [Engine.max_pairs]querier_mod.Pair = undefined;
    const joined = e.joinedPairs(&pairs);
    try testing.expectEqual(@as(usize, 3), joined.len);
    try testing.expectEqual(@as(u32, 3), joined[0].ifindex);
    try testing.expectEqual(Family.v4, joined[0].family);
    try testing.expectEqual(@as(u32, 4), joined[1].ifindex);
    try testing.expectEqual(Family.v6, joined[1].family);
    try testing.expectEqual(@as(u32, 5), joined[2].ifindex);
    try testing.expectEqual(Family.v4, joined[2].family);
    // No interfaces at all: nothing to send on.
    try e.setInterfaces(&.{}, 1);
    try testing.expectEqual(@as(usize, 0), e.joinedPairs(&pairs).len);
}

test "pollDatagram drops a queued job for a pair that is no longer joined" {
    // A tick queues one job per joined pair; when a pair loses its
    // membership (or its interface leaves the table) before the drain,
    // the built packet is not handed out: it is a counted `tx_dropped`,
    // so the platform never gets a pktinfo for an interface it no longer
    // has. The other pair's packet still goes out.
    var e = try testEngine(.{ .max_interfaces = 4 });
    defer e.deinit();
    try e.setInterfaces(&.{ testIface(3, 1, 0), testIface(4, 1, 0) }, 0);
    _ = try e.browse("_qmsg._udp", 0);
    const first = e.nextDeadline(0).?;
    e.tick(first);
    e.setJoined(4, .v4, false);
    var buf: [1500]u8 = undefined;
    const d = e.pollDatagram(&buf, first).?;
    try testing.expectEqual(@as(u32, 3), d.ifindex);
    try testing.expectEqual(null, e.pollDatagram(&buf, first));
    try testing.expectEqual(@as(u64, 1), e.stats().tx);
    try testing.expectEqual(@as(u64, 1), e.stats().tx_dropped);
    // The same for an interface that left the table between tick and drain.
    const second = e.nextDeadline(first).?;
    e.tick(second);
    try e.setInterfaces(&.{testIface(4, 1, 0)}, second);
    e.setJoined(4, .v4, true);
    var sent: usize = 0;
    while (e.pollDatagram(&buf, second)) |dg| {
        sent += 1;
        try testing.expectEqual(@as(u32, 4), dg.ifindex);
    }
    try testing.expectEqual(@as(usize, 0), sent); // only 3's job was queued (4 was unjoined at the tick)
    try testing.expectEqual(@as(u64, 2), e.stats().tx_dropped);
}

test "engine on-link check uses the arrival interface prefixes" {
    var e = try testEngine(.{ .max_interfaces = 4 });
    defer e.deinit();
    try e.setInterfaces(&.{ testIface(3, 1, 1), testIface(4, 1, 0) }, 0);
    // 10.0.3.0/24 on ifindex 3, 10.0.4.0/24 on ifindex 4.
    try testing.expect(e.onLink(.{ .ip4 = .{ .bytes = .{ 10, 0, 3, 200 }, .port = 5353 } }, 3));
    try testing.expect(!e.onLink(.{ .ip4 = .{ .bytes = .{ 10, 0, 4, 200 }, .port = 5353 } }, 3));
    try testing.expect(e.onLink(.{ .ip4 = .{ .bytes = .{ 10, 0, 4, 200 }, .port = 5353 } }, 4));
    // Unknown arrival interface: any interface's prefix counts.
    try testing.expect(e.onLink(.{ .ip4 = .{ .bytes = .{ 10, 0, 4, 200 }, .port = 5353 } }, 0));
    try testing.expect(!e.onLink(.{ .ip4 = .{ .bytes = .{ 172, 16, 0, 1 }, .port = 5353 } }, 0));
    // fd00::/64 on ifindex 3; a link-local source is always on-link.
    var g: [16]u8 = @splat(0);
    g[0] = 0xfd;
    g[15] = 0x99;
    try testing.expect(e.onLink(.{ .ip6 = .{ .bytes = g, .port = 5353 } }, 3));
    try testing.expect(!e.onLink(.{ .ip6 = .{ .bytes = g, .port = 5353 } }, 4));
    var ll: [16]u8 = @splat(0);
    ll[0] = 0xfe;
    ll[1] = 0x80;
    ll[15] = 1;
    try testing.expect(e.onLink(.{ .ip6 = .{ .bytes = ll, .port = 5353 } }, 4));
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

test "engine browse schedules a QM PTR query per joined pair and records the echo" {
    var e = try testEngine(.{ .max_interfaces = 4 });
    defer e.deinit();
    try e.setInterfaces(&.{ testIface(3, 1, 1), testIface(4, 1, 0) }, 0);
    e.setJoined(4, .v4, false);
    _ = e.pollEvent(); // interfaces_changed
    try testing.expectEqual(null, e.nextDeadline(0));
    const id = try e.browse("_qmsg._udp", 0);
    try testing.expectError(error.DuplicateBrowse, e.browse("_qmsg._udp", 0));
    try testing.expectError(error.InvalidServiceType, e.browse("bogus", 0));
    const first = e.nextDeadline(0).?;
    try testing.expect(first >= timers.query_first_delay_min_us and first <= timers.query_first_delay_max_us);

    var buf: [1500]u8 = undefined;
    e.tick(first - 1);
    try testing.expectEqual(null, e.pollDatagram(&buf, first - 1));
    e.tick(first);
    try testing.expectEqual(@as(?u64, first), e.nextDeadline(first)); // queued => now
    var count: usize = 0;
    var saw_v6 = false;
    while (e.pollDatagram(&buf, first)) |d| {
        count += 1;
        const msg = try wire.Message.parse(buf[0..d.len]);
        try testing.expect(!msg.isResponse());
        try testing.expectEqual(@as(u16, 0), msg.header.id);
        try testing.expectEqual(@as(u16, 1), msg.header.qdcount);
        var qs = msg.questions();
        const q = qs.next().?;
        try testing.expectEqual(wire.RType.ptr, q.qtype);
        try testing.expect(!q.qu);
        var text: [64]u8 = undefined;
        try testing.expectEqualStrings("_qmsg._udp.local", try q.name.toText(&text));
        try testing.expectEqual(@as(u32, 3), d.ifindex);
        switch (d.to) {
            .ip4 => |a| try testing.expectEqual(group_v4, a.bytes),
            .ip6 => |a| {
                try testing.expectEqual(group_v6, a.bytes);
                try testing.expectEqual(@as(u32, 3), a.interface.index);
                saw_v6 = true;
            },
        }
        // Our own bytes back from our own address: an echo.
        const before = e.stats().rx_echo;
        e.handle(buf[0..d.len], .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 1 }, .port = 5353 } }, .ifindex = 3, .dst_multicast = true }, first);
        try testing.expectEqual(before + 1, e.stats().rx_echo);
    }
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expect(saw_v6);
    try testing.expectEqual(@as(u64, 2), e.stats().tx);
    // Next query 1 s (+0-2 %) later.
    const second = e.nextDeadline(first).?;
    try testing.expect(second >= first + timers.s(1) and second <= first + timers.s(1) + timers.ms(20));
    e.stopBrowse(id, first);
    try testing.expectEqual(null, e.nextDeadline(first));
}

test "engine ignores RD RA and Z on receipt and sends them clear" {
    // RFC 6762 sections 18.6-18.10: RD, RA and Z are 0 on send and ignored
    // on receipt (AD and CD live inside Z in the header layout).
    var e = try testEngine(.{ .max_interfaces = 2 });
    defer e.deinit();
    try e.setInterfaces(&.{testIface(3, 1, 0)}, 0);
    _ = try e.browse("_x._udp", 0);
    const due = e.nextDeadline(0).?;
    e.tick(due);
    var buf: [1500]u8 = undefined;
    const d = e.pollDatagram(&buf, due).?;
    const sent = try wire.Message.parse(buf[0..d.len]);
    try testing.expect(!sent.header.flags.rd);
    try testing.expect(!sent.header.flags.ra);
    try testing.expectEqual(@as(u3, 0), sent.header.flags.z);
    try testing.expect(!sent.header.flags.tc);
    // A response with RD, RA and every Z bit set, PTR for the browsed
    // type: processed (found), not dropped.
    var rb: [1500]u8 = undefined;
    var b: wire.Builder = .init(&rb, .{});
    b.setResponse();
    b.setFlags(.{ .qr = true, .aa = true, .rd = true, .ra = true, .z = 7 });
    const t = try wire.Name.parse("_x._udp.local");
    const inst = try wire.Name.parse("a._x._udp.local");
    try b.addRR(.answer, t, .ptr, wire.class_in, false, 4500, .{ .ptr = inst });
    const bytes = b.finish();
    e.handle(bytes, .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 9 }, .port = 5353 } }, .ifindex = 3, .dst_multicast = true }, due);
    try testing.expectEqual(@as(u64, 0), e.stats().dropped_ignored);
    try testing.expectEqual(@as(u64, 0), e.stats().dropped_malformed);
    var found = false;
    while (e.pollEvent()) |ev| if (ev == .found) {
        found = true;
    };
    try testing.expect(found);
}

test "engine handle never fails after init under a failing allocator" {
    // Every allocation happens in `init`; the sweep proves `init` fails
    // cleanly (no leak) at each allocation count, and that once it
    // succeeds `handle` runs with an allocator that fails everything.
    var fail_at: usize = 0;
    while (true) : (fail_at += 1) {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_at });
        var prng = std.Random.DefaultPrng.init(3);
        var e = Engine.init(fa.allocator(), .{ .host_label = "sweep", .random = prng.random(), .limits = .{ .max_cache_records = 8, .max_events = 4, .max_interfaces = 2 } }) catch |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            continue;
        };
        defer e.deinit();
        try testing.expect(fa.has_induced_failure == false);
        try e.setInterfaces(&.{testIface(3, 1, 1)}, 0);
        _ = try e.browse("_x._udp", 0);
        // From here every allocation would fail; none may be attempted.
        var resp: [12]u8 = @splat(0);
        resp[2] = 0x84;
        e.handle(&resp, .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 9 }, .port = 5353 } }, .ifindex = 3, .dst_multicast = true }, 1);
        e.handle(&.{ 1, 2 }, .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 9 }, .port = 5353 } }, .ifindex = 3, .dst_multicast = true }, 1);
        e.tick(timers.s(1));
        var buf: [1500]u8 = undefined;
        while (e.pollDatagram(&buf, timers.s(1))) |_| {}
        try testing.expect(fa.has_induced_failure == false);
        break;
    }
    try testing.expect(fail_at > 0);
}
