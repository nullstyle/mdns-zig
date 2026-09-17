//! Querier conformance tests (plan section 7, M3 named tests): the RFC
//! 6762 section 5.2 schedule, QM-only browse queries, known-answer lists
//! and requery merging, cache-flush and goodbye timing, the source-port,
//! on-link and QU-window ingress checks, the cache cap, link-local
//! scoping, own-echo recognition and `setInterfaces` accounting. Every
//! test runs one `Engine` on a fake clock with a seeded PRNG; packets
//! come from `tests/harness/packets.zig`.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const mdns = @import("mdns");
const wire = mdns.wire;
const scenario = @import("harness/scenario.zig");
const packets = @import("harness/packets.zig");
const fake_lan = @import("harness/fake_lan.zig");

const Scenario = scenario.Scenario;
const Sink = scenario.Sink;
const Engine = mdns.Engine;
const Packet = packets.Packet;
const timers = mdns.core.timers;

const s_us = scenario.us_per_s;
const ms_us = scenario.us_per_ms;
const svc_type = "_qmsg._udp";

/// One engine on ifindex 3 (10.0.3.1/24 + fe80::1/64), both families
/// joined, with `interfaces_changed` already drained.
const Rig = struct {
    sc: Scenario,
    e: Engine,
    sink: Sink,

    fn init(seed: u64, limits: mdns.Limits) !*Rig {
        const r = try testing.allocator.create(Rig);
        errdefer testing.allocator.destroy(r);
        r.sc = .init(seed);
        r.e = try Engine.init(testing.allocator, .{ .host_label = "rig", .random = r.sc.random(), .limits = limits });
        errdefer r.e.deinit();
        r.sink = .init(testing.allocator);
        try r.e.setInterfaces(&.{fake_lan.ifaceDual(3, "en0", .{ 10, 0, 3, 1 }, 24, 1)}, 0);
        _ = try r.sink.drain(&r.e);
        r.sink.clear();
        return r;
    }

    fn deinit(r: *Rig) void {
        r.sink.deinit();
        r.e.deinit();
        testing.allocator.destroy(r);
    }

    fn now(r: *const Rig) u64 {
        return r.sc.nowUs();
    }

    /// Multicast delivery from a peer on the link, port 5353.
    fn rx(r: *Rig, bytes: []const u8) !void {
        r.e.handle(bytes, peerMeta(true), r.now());
        _ = try r.sink.drain(&r.e);
    }

    fn tick(r: *Rig) !void {
        r.e.tick(r.now());
        _ = try r.sink.drain(&r.e);
    }

    /// Advance to `at`, tick, drain events.
    fn tickAt(r: *Rig, at: u64) !void {
        r.sc.set(at);
        try r.tick();
    }

    /// Run every due timer up to and including `until`, draining every
    /// datagram into `count` (queries sent) and events into the sink.
    fn runUntil(r: *Rig, until: u64) !usize {
        var sent: usize = 0;
        var buf: [9000]u8 = undefined;
        while (true) {
            const d = r.e.nextDeadline(r.now()) orelse break;
            if (d > until) break;
            r.sc.set(@max(d, r.now()));
            try r.tick();
            while (r.e.pollDatagram(&buf, r.now())) |_| sent += 1;
        }
        r.sc.set(@max(until, r.now()));
        try r.tick();
        while (r.e.pollDatagram(&buf, r.now())) |_| sent += 1;
        return sent;
    }
};

fn peerMeta(dst_multicast: bool) Engine.RxMeta {
    return .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 9 }, .port = 5353 } }, .ifindex = 3, .dst_multicast = dst_multicast };
}

/// Every question of every packet an engine sends.
const Sent = struct {
    packets: usize = 0,
    questions: usize = 0,
    qu_seen: bool = false,
    answers: usize = 0,
    tc_seen: bool = false,
};

fn drainQueries(e: *Engine, now_us: u64) !Sent {
    var out: Sent = .{};
    var buf: [9000]u8 = undefined;
    while (e.pollDatagram(&buf, now_us)) |d| {
        out.packets += 1;
        const msg = try wire.Message.parse(buf[0..d.len]);
        try testing.expect(!msg.isResponse());
        try testing.expectEqual(@as(u16, 0), msg.header.id);
        if (msg.header.flags.tc) out.tc_seen = true;
        var qs = msg.questions();
        while (qs.next()) |q| {
            out.questions += 1;
            if (q.qu) out.qu_seen = true;
        }
        out.answers += msg.header.ancount;
    }
    return out;
}

// ---- section 5.2 schedule --------------------------------------------

test "first query delayed 20-120ms" {
    // 10 k seeded engines: the first deadline after `browse` is always
    // inside [20 ms, 120 ms] (RFC 6762 section 5.2), never at once.
    var seed: u64 = 0;
    var min_seen: u64 = std.math.maxInt(u64);
    var max_seen: u64 = 0;
    while (seed < 10_000) : (seed += 1) {
        var sc: Scenario = .initAt(seed, seed * 1000);
        var e = try Engine.init(testing.allocator, .{ .host_label = "d", .random = sc.random(), .limits = .{ .max_cache_records = 2, .max_events = 2, .max_interfaces = 1, .max_browses = 1 } });
        defer e.deinit();
        try e.setInterfaces(&.{fake_lan.iface4(3, "en0", .{ 10, 0, 3, 1 }, 24)}, sc.nowUs());
        try testing.expectEqual(null, e.nextDeadline(sc.nowUs()));
        _ = try e.browse(svc_type, sc.nowUs());
        const d = e.nextDeadline(sc.nowUs()).?;
        const delay = d - sc.nowUs();
        try testing.expect(delay >= 20 * ms_us and delay <= 120 * ms_us);
        min_seen = @min(min_seen, delay);
        max_seen = @max(max_seen, delay);
        // Nothing goes out before the deadline.
        var buf: [1500]u8 = undefined;
        e.tick(d - 1);
        try testing.expectEqual(null, e.pollDatagram(&buf, d - 1));
        e.tick(d);
        try testing.expect(e.pollDatagram(&buf, d) != null);
    }
    // The draw covers the window (uniform over 100 ms in 10 k draws).
    try testing.expect(min_seen < 25 * ms_us);
    try testing.expect(max_seen > 115 * ms_us);
}

test "query intervals double and cap at 60min" {
    var r = try Rig.init(0x5eed, .{});
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [1500]u8 = undefined;
    var prev = r.e.nextDeadline(0).?;
    r.sc.set(prev);
    try r.tick();
    try testing.expectEqual(@as(usize, 2), (try drainQueries(&r.e, prev)).packets); // v4 + v6
    var step: u32 = 0;
    var capped_steps: u32 = 0;
    var prev_gap: u64 = 0;
    while (capped_steps < 3) : (step += 1) {
        const next = r.e.nextDeadline(r.now()).?;
        const gap = next - prev;
        const base = timers.queryIntervalUs(step);
        // Section 5.2: at least 1 s, then every real gap at least twice
        // the previous real gap (the 0-2 % jitter compounds, so the
        // ladder only stretches), capped at 3600 s (+0-2 %).
        try testing.expect(gap >= base);
        if (base == timers.query_interval_cap_us) {
            try testing.expect(gap <= base + base / 50);
            capped_steps += 1;
        } else {
            if (prev_gap != 0) try testing.expect(gap >= 2 * prev_gap);
            try testing.expect(gap <= 2 * prev_gap + 2 * prev_gap / 50 or prev_gap == 0);
            if (prev_gap == 0) try testing.expect(gap <= base + base / 50);
        }
        prev_gap = gap;
        r.sc.set(next);
        try r.tick();
        try testing.expectEqual(@as(usize, 2), (try drainQueries(&r.e, next)).packets);
        try testing.expectEqual(null, r.e.pollDatagram(&buf, next));
        prev = next;
    }
    try testing.expectEqual(@as(u32, 12 + 3), step);
    // The 24 h ladder from the timers table: 35 queries per pair (+1
    // jitter allowance = the flood budget).
    try testing.expectEqual(@as(u32, 36), timers.query_schedule_24h_budget);
}

test "browse queries never set QU" {
    var r = try Rig.init(7, .{});
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    // A found instance with nothing else known: follow-up questions too.
    var buf: [1500]u8 = undefined;
    var p: Packet = .response(&buf);
    try p.ptr(svc_type, "alice", 4500);
    try r.rx(p.bytes());
    try r.sink.expectCount(.found, 1);
    var total: Sent = .{};
    while (r.now() < 30 * s_us) {
        const d = r.e.nextDeadline(r.now()) orelse break;
        r.sc.set(d);
        try r.tick();
        const s = try drainQueries(&r.e, r.now());
        total.packets += s.packets;
        total.questions += s.questions;
        if (s.qu_seen) total.qu_seen = true;
    }
    try testing.expect(total.packets >= 6);
    try testing.expect(total.questions > total.packets); // follow-ups rode along
    try testing.expect(!total.qu_seen);
}

test "requery marks merge into one packet" {
    var r = try Rig.init(11, .{});
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [1500]u8 = undefined;
    // PTR, TXT 4500 s; SRV, A 120 s: their 80 % marks fall at 96 s + 0-2.4 s.
    try r.rx(try packets.fullInstance(&buf, svc_type, "alice", "host-a", 4433, .{ 10, 0, 3, 5 }));
    try r.sink.expectCount(.resolved, 1);
    // Drain the ladder up to 40 s (queries at 0.1, 1.1, 3.1, ..., 31.1).
    _ = try r.runUntil(40 * s_us);
    // The 63 s browse query carries the PTR as a known answer (section
    // 7.1; 4500 s TTL, far from half) and not the SRV / A (past half of
    // their 120 s).
    const q63 = r.e.nextDeadline(r.now()).?;
    try testing.expect(q63 >= 63 * s_us and q63 < 66 * s_us);
    r.sc.set(q63);
    try r.tick();
    var seen: usize = 0;
    while (r.e.pollDatagram(&buf, r.now())) |d| {
        seen += 1;
        const msg = try wire.Message.parse(buf[0..d.len]);
        try testing.expect(!msg.header.flags.tc);
        try testing.expectEqual(@as(u16, 1), msg.header.qdcount);
        try testing.expectEqual(@as(u16, 1), msg.header.ancount);
        var an = msg.answers();
        const rec = an.next().?;
        try testing.expectEqual(wire.RType.ptr, rec.rtype);
        try testing.expect(!rec.cache_flush);
        try testing.expect(rec.ttl <= 4500 - 63 and rec.ttl >= 4500 - 66);
        try wire.name.expectText("alice._qmsg._udp.local", try wire.rdata.decodePtr(buf[0..d.len], rec));
    }
    try testing.expectEqual(@as(usize, 2), seen); // one per pair
    try testing.expectEqual(null, r.e.pollDatagram(&buf, r.now()));

    // Next: the 80 % marks of SRV and A (96 s + 0-2.4 s each).
    const mark = r.e.nextDeadline(r.now()).?;
    try testing.expect(mark >= 96 * s_us and mark <= 98_400_000);
    // Jump past both marks in one tick: the SRV and A questions fold
    // into one packet per pair; no known answers (both past half TTL).
    r.sc.set(98_500_000);
    try r.tick();
    seen = 0;
    while (r.e.pollDatagram(&buf, r.now())) |d| {
        seen += 1;
        const msg = try wire.Message.parse(buf[0..d.len]);
        try testing.expect(!msg.header.flags.tc);
        try testing.expectEqual(@as(u16, 2), msg.header.qdcount); // SRV + A
        try testing.expectEqual(@as(u16, 0), msg.header.ancount);
        var srv_q = false;
        var a_q = false;
        var qs = msg.questions();
        while (qs.next()) |q| {
            try testing.expect(!q.qu);
            if (q.qtype == .srv) srv_q = true;
            if (q.qtype == .a) a_q = true;
        }
        try testing.expect(srv_q and a_q);
    }
    try testing.expectEqual(@as(usize, 2), seen);
    // The 85 % marks are scheduled next (102 s + 0-2.4 s).
    const next = r.e.nextDeadline(r.now()).?;
    try testing.expect(next > 98_500_000 and next <= 104_400_000);
}

test "known-answer list continues in further packets with TC set" {
    // RFC 6762 section 7.2: known answers that do not fit the first
    // packet follow in more packets, TC set on all but the last.
    var r = try Rig.init(16, .{});
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [9000]u8 = undefined;
    // 120 fully resolvable instances (so no follow-up questions are
    // pending): their PTRs alone are ~35 B each on the wire, well over
    // one 1472 B packet.
    var k: usize = 0;
    while (k < 15) : (k += 1) {
        var p: Packet = .response(&buf);
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            var name: [32]u8 = undefined;
            const label = try std.fmt.bufPrint(&name, "instance-number-{d}", .{k * 8 + i});
            try p.ptr(svc_type, label, 4500);
            try p.srv(label, svc_type, 4433, "host-a", 4500, true);
            try p.txt(label, svc_type, &.{}, 4500, true);
        }
        try p.a("host-a", .{ 10, 0, 3, 5 }, 4500, true);
        try r.rx(p.bytes());
    }
    try r.sink.expectCount(.found, 120);
    try r.sink.expectCount(.resolved, 120);
    // The first browse query (20-120 ms) carries them all as known
    // answers, split across packets per pair.
    const d0 = r.e.nextDeadline(r.now()).?;
    r.sc.set(d0);
    try r.tick();
    var per_pair_packets: [2]usize = .{ 0, 0 };
    var per_pair_answers: [2]usize = .{ 0, 0 };
    var per_pair_questions: [2]usize = .{ 0, 0 };
    var last_tc: [2]bool = .{ true, true };
    while (r.e.pollDatagram(&buf, r.now())) |d| {
        const fam: usize = if (d.to == .ip4) 0 else 1;
        const msg = try wire.Message.parse(buf[0..d.len]);
        try testing.expect(d.len <= 1472);
        per_pair_packets[fam] += 1;
        per_pair_answers[fam] += msg.header.ancount;
        per_pair_questions[fam] += msg.header.qdcount;
        // Every packet but the last of a pair has TC set.
        try testing.expect(last_tc[fam]);
        last_tc[fam] = msg.header.flags.tc;
    }
    for (0..2) |fam| {
        try testing.expect(per_pair_packets[fam] >= 2);
        try testing.expectEqual(@as(usize, 120), per_pair_answers[fam]);
        try testing.expectEqual(@as(usize, 1), per_pair_questions[fam]);
        try testing.expect(!last_tc[fam]);
    }
    try testing.expectEqual(null, r.e.pollDatagram(&buf, r.now()));
}

// ---- cache timing ------------------------------------------------------

test "cache-flush keeps records younger than 1s" {
    var r = try Rig.init(3, .{});
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [1500]u8 = undefined;
    try r.rx(try packets.fullInstance(&buf, svc_type, "alice", "host-a", 4433, .{ 10, 0, 3, 5 }));
    try r.sink.expectCount(.resolved, 1);
    try testing.expectEqual(@as(usize, 1), r.sink.last(.resolved).?.resolved.addrs.len);

    // 500 ms later a second cache-flush A: the first is younger than
    // 1 s, so both are kept (section 10.2).
    r.sc.set(500 * ms_us);
    var p: Packet = .response(&buf);
    try p.a("host-a", .{ 10, 0, 3, 6 }, 120, true);
    try r.rx(p.bytes());
    try r.sink.expectCount(.resolved, 2);
    try testing.expectEqual(@as(usize, 2), r.sink.last(.resolved).?.resolved.addrs.len);

    // 5 s later a third cache-flush A: both older ones are flushed.
    r.sc.set(5 * s_us);
    var p2: Packet = .response(&buf);
    try p2.a("host-a", .{ 10, 0, 3, 7 }, 120, true);
    try r.rx(p2.bytes());
    try r.sink.expectCount(.resolved, 3);
    const last = r.sink.last(.resolved).?.resolved;
    try testing.expectEqual(@as(usize, 1), last.addrs.len);
    try testing.expectEqual([4]u8{ 10, 0, 3, 7 }, last.addrs.slice()[0].ip4.bytes);
    // They leave the cache one second later without another event.
    try testing.expectEqual(@as(usize, 6), r.e.cacheCount());
    try r.tickAt(6 * s_us);
    try testing.expectEqual(@as(usize, 4), r.e.cacheCount());
    try r.sink.expectCount(.resolved, 3);
}

test "goodbye removes after 1s" {
    var r = try Rig.init(4, .{});
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [1500]u8 = undefined;
    try r.rx(try packets.fullInstance(&buf, svc_type, "alice", "host-a", 4433, .{ 10, 0, 3, 5 }));
    try r.sink.expectCount(.found, 1);
    r.sc.set(10 * s_us);
    var p: Packet = .response(&buf);
    try p.ptrGoodbye(svc_type, "alice");
    try r.rx(p.bytes());
    try r.sink.expectCount(.lost, 0);
    try r.tickAt(10 * s_us + 999 * ms_us);
    try r.sink.expectCount(.lost, 0);
    try r.tickAt(11 * s_us);
    try r.sink.expectCount(.lost, 1);
    const lost = r.sink.last(.lost).?.lost;
    try wire.name.expectText("alice._qmsg._udp.local", lost.instance);
    try wire.name.expectText("_qmsg._udp.local", lost.service_type);
    try testing.expectEqual(@as(u32, 3), lost.ifindex);
}

// ---- ingress checks ----------------------------------------------------

test "response from non-5353 source is ignored" {
    var r = try Rig.init(5, .{});
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [1500]u8 = undefined;
    const bytes = try packets.fullInstance(&buf, svc_type, "alice", "host-a", 4433, .{ 10, 0, 3, 5 });
    r.e.handle(bytes, .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 9 }, .port = 40_000 } }, .ifindex = 3, .dst_multicast = true }, 0);
    _ = try r.sink.drain(&r.e);
    try testing.expectEqual(@as(u64, 1), r.e.stats().dropped_bad_port);
    try testing.expectEqual(@as(usize, 0), r.e.cacheCount());
    try r.sink.expectCount(.found, 0);
    // Same bytes from 5353: accepted.
    try r.rx(bytes);
    try r.sink.expectCount(.found, 1);
}

test "unicast outside 2s QU window discarded" {
    var r = try Rig.init(6, .{});
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [1500]u8 = undefined;
    const bytes = try packets.fullInstance(&buf, svc_type, "alice", "host-a", 4433, .{ 10, 0, 3, 5 });
    // On-link source, unicast destination: we never sent a QU query.
    r.e.handle(bytes, peerMeta(false), 0);
    _ = try r.sink.drain(&r.e);
    try testing.expectEqual(@as(u64, 1), r.e.stats().dropped_unicast_unexpected);
    try testing.expectEqual(@as(u64, 0), r.e.stats().dropped_off_link);
    try testing.expectEqual(@as(usize, 0), r.e.cacheCount());
    try r.sink.expectCount(.found, 0);
}

test "off-link unicast discarded by prefix" {
    var r = try Rig.init(8, .{});
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [1500]u8 = undefined;
    const bytes = try packets.fullInstance(&buf, svc_type, "alice", "host-a", 4433, .{ 10, 0, 3, 5 });
    // 10.0.9.9 is not inside 10.0.3.0/24.
    r.e.handle(bytes, .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 0, 9, 9 }, .port = 5353 } }, .ifindex = 3, .dst_multicast = false }, 0);
    _ = try r.sink.drain(&r.e);
    try testing.expectEqual(@as(u64, 1), r.e.stats().dropped_off_link);
    try testing.expectEqual(@as(u64, 0), r.e.stats().dropped_unicast_unexpected);
    try testing.expectEqual(@as(usize, 0), r.e.cacheCount());
    // A global v6 source outside fe80::/64 and off every prefix, too.
    var g: [16]u8 = @splat(0);
    g[0] = 0x20;
    g[1] = 0x01;
    g[15] = 9;
    r.e.handle(bytes, .{ .from = .{ .ip6 = .{ .bytes = g, .port = 5353 } }, .ifindex = 3, .dst_multicast = false }, 0);
    try testing.expectEqual(@as(u64, 2), r.e.stats().dropped_off_link);
    // A unicast *query* from off-link is dropped by the same rule.
    var q: Packet = .query(&buf);
    try q.question(packets.typeName(svc_type), .ptr, false);
    r.e.handle(q.bytes(), .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 0, 9, 9 }, .port = 5353 } }, .ifindex = 3, .dst_multicast = false }, 0);
    try testing.expectEqual(@as(u64, 3), r.e.stats().dropped_off_link);
}

test "multicast-destination packet skips on-link check" {
    var r = try Rig.init(9, .{});
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [1500]u8 = undefined;
    const bytes = try packets.fullInstance(&buf, svc_type, "alice", "host-a", 4433, .{ 10, 0, 3, 5 });
    // The same off-link source, but to the multicast group: accepted.
    r.e.handle(bytes, .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 0, 9, 9 }, .port = 5353 } }, .ifindex = 3, .dst_multicast = true }, 0);
    _ = try r.sink.drain(&r.e);
    try testing.expectEqual(@as(u64, 0), r.e.stats().dropped_off_link);
    try r.sink.expectCount(.found, 1);
    try r.sink.expectCount(.resolved, 1);
}

test "KA records from other queriers not cached" {
    var r = try Rig.init(10, .{});
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [1500]u8 = undefined;
    // Another querier's browse query with a known-answer list naming an
    // instance (RFC 6762 section 7.1): not authoritative, never cached.
    var q: Packet = .query(&buf);
    try q.question(packets.typeName(svc_type), .ptr, false);
    try q.ptr(svc_type, "alice", 4000);
    q.in(.additional);
    try q.srv("alice", svc_type, 4433, "host-a", 100, false);
    try r.rx(q.bytes());
    try testing.expectEqual(@as(usize, 0), r.e.cacheCount());
    try r.sink.expectCount(.found, 0);
    try testing.expectEqual(@as(u64, 1), r.e.stats().rx);
    try testing.expectEqual(@as(u64, 0), r.e.stats().dropped_malformed);
}

test "cache cap evicts soonest expiry" {
    var r = try Rig.init(12, .{ .max_cache_records = 4 });
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [1500]u8 = undefined;
    // Four foreign records (no browse cares): TTL 100, 50, 200, 300.
    var p: Packet = .response(&buf);
    try p.a("h1", .{ 10, 0, 3, 11 }, 100, false);
    try p.a("h2", .{ 10, 0, 3, 12 }, 50, false);
    try p.a("h3", .{ 10, 0, 3, 13 }, 200, false);
    try p.a("h4", .{ 10, 0, 3, 14 }, 300, false);
    try r.rx(p.bytes());
    try testing.expectEqual(@as(usize, 4), r.e.cacheCount());
    try testing.expectEqual(@as(u64, 0), r.e.stats().evictions);
    // A fifth record evicts h2 (soonest expiry), nothing else.
    var p2: Packet = .response(&buf);
    try p2.a("h5", .{ 10, 0, 3, 15 }, 400, false);
    try r.rx(p2.bytes());
    try testing.expectEqual(@as(usize, 4), r.e.cacheCount());
    try testing.expectEqual(@as(u64, 1), r.e.stats().evictions);
    const cache = &r.e.querier.cache;
    try testing.expectEqual(@as(usize, 0), cache.countLive(&packets.hostName("h2"), .a, wire.class_in));
    try testing.expectEqual(@as(usize, 1), cache.countLive(&packets.hostName("h1"), .a, wire.class_in));
    try testing.expectEqual(@as(usize, 1), cache.countLive(&packets.hostName("h5"), .a, wire.class_in));
    // A browsed PTR is pinned: it displaces the next-soonest foreign
    // record (h1), never the other way round.
    var p3: Packet = .response(&buf);
    try p3.ptr(svc_type, "alice", 10);
    try r.rx(p3.bytes());
    try r.sink.expectCount(.found, 1);
    try testing.expectEqual(@as(u64, 2), r.e.stats().evictions);
    try testing.expectEqual(@as(usize, 0), cache.countLive(&packets.hostName("h1"), .a, wire.class_in));
    var p4: Packet = .response(&buf);
    try p4.a("h6", .{ 10, 0, 3, 16 }, 500, false);
    try r.rx(p4.bytes());
    try testing.expectEqual(@as(u64, 3), r.e.stats().evictions);
    try testing.expectEqual(@as(usize, 1), cache.countLive(&packets.typeName(svc_type), .ptr, wire.class_in));
}

test "link-local AAAA carries ifindex" {
    var r = try Rig.init(13, .{});
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [1500]u8 = undefined;
    var p: Packet = .response(&buf);
    try p.ptr(svc_type, "alice", 4500);
    p.in(.additional);
    try p.srv("alice", svc_type, 4433, "host-a", 120, true);
    try p.txt("alice", svc_type, &.{}, 4500, true);
    try p.aaaa("host-a", fake_lan.linkLocal6(0x0005), 120, true);
    var g: [16]u8 = @splat(0);
    g[0] = 0x20;
    g[1] = 0x01;
    g[15] = 5;
    try p.aaaa("host-a", g, 120, true);
    try r.rx(p.bytes());
    try r.sink.expectCount(.resolved, 1);
    const res = r.sink.last(.resolved).?.resolved;
    try testing.expectEqual(@as(usize, 2), res.addrs.len);
    var ll_scoped = false;
    var global_unscoped = false;
    for (res.addrs.slice()) |a| {
        try testing.expect(a == .ip6);
        try testing.expectEqual(@as(u16, 4433), a.ip6.port);
        if (mdns.core.events.isLinkLocal6(a.ip6.bytes)) {
            try testing.expectEqual(@as(u32, 3), a.ip6.interface.index);
            ll_scoped = true;
        } else {
            try testing.expectEqual(@as(u32, 0), a.ip6.interface.index);
            global_unscoped = true;
        }
    }
    try testing.expect(ll_scoped and global_unscoped);
    try testing.expectEqual(@as(u32, 3), res.ifindex);
}

test "byte-identical query from a foreign source is not an echo" {
    var r = try Rig.init(14, .{});
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    const d0 = r.e.nextDeadline(0).?;
    r.sc.set(d0);
    try r.tick();
    var buf: [1500]u8 = undefined;
    const d = r.e.pollDatagram(&buf, r.now()).?;
    const sent = buf[0..d.len];
    // The same bytes from a peer (its first browse query is identical:
    // ID 0, one question, empty known-answer list): a real packet.
    r.e.handle(sent, peerMeta(true), r.now());
    try testing.expectEqual(@as(u64, 0), r.e.stats().rx_echo);
    try testing.expectEqual(@as(u64, 1), r.e.stats().rx);
    // From our own address: an echo, counted. A plain query still goes
    // to the responder (a same-host peer's identical query, v0.1.1);
    // this engine advertises nothing, so nothing is answered.
    const own: Engine.RxMeta = .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 1 }, .port = 5353 } }, .ifindex = 3, .dst_multicast = true };
    r.e.handle(sent, own, r.now());
    try testing.expectEqual(@as(u64, 1), r.e.stats().rx_echo);
    try testing.expectEqual(@as(u64, 1), r.e.stats().rx_echo_answered);
    try testing.expectEqual(@as(u64, 1), r.e.stats().tx);
    // Our own address but different bytes (a peer stack on this host,
    // e.g. mDNSResponder): not an echo either.
    var buf2: [1500]u8 = undefined;
    var other: Packet = .query(&buf2);
    try other.question(packets.typeName("_other._tcp"), .ptr, false);
    r.e.handle(other.bytes(), own, r.now());
    try testing.expectEqual(@as(u64, 1), r.e.stats().rx_echo);
    // After the echo window the digest has aged out.
    r.e.handle(sent, own, r.now() + timers.echo_window_us + 1);
    try testing.expectEqual(@as(u64, 1), r.e.stats().rx_echo);
    try testing.expectEqual(@as(u64, 4), r.e.stats().rx);
    try testing.expectEqual(@as(u64, 0), r.e.stats().dropped_malformed);
}

test "setInterfaces sums Interface dropped counts into addrs_dropped and warns once" {
    var sc: Scenario = .init(15);
    var e = try Engine.init(testing.allocator, .{
        .host_label = "rig",
        .random = sc.random(),
        .limits = .{ .max_interfaces = 4 },
        .max_addrs_per_iface = 3,
    });
    defer e.deinit();
    var sink: Sink = .init(testing.allocator);
    defer sink.deinit();

    // ifaces.zig kept 5 v4 (2 over its own cap, reported) and 2 v6 (1
    // reported); the Engine's cap of 3 drops 2 more v4.
    var i: mdns.Interface = .{ .index = 3, .v4_dropped = 2, .v6_dropped = 1 };
    var k: u8 = 0;
    while (k < 5) : (k += 1) try i.v4.append(.{ .addr = .{ 10, 0, 3, k + 1 }, .prefix_len = 24 });
    try i.v6.append(.{ .addr = fake_lan.linkLocal6(1), .prefix_len = 64 });
    try i.v6.append(.{ .addr = fake_lan.linkLocal6(2), .prefix_len = 64 });
    try e.setInterfaces(&.{i}, 0);
    try testing.expectEqual(@as(u64, 2 + 2 + 1), e.stats().addrs_dropped);
    try testing.expectEqual(@as(usize, 3), e.interfaces()[0].v4.len);
    try testing.expectEqual(@as(usize, 2), e.interfaces()[0].v6.len);
    _ = try sink.drain(&e);
    try sink.expectCount(.interfaces_changed, 1);
    try testing.expectEqual(@as(usize, 2), sink.countWarning(.addrs_truncated));
    var v4_warn: usize = 0;
    var v6_warn: usize = 0;
    for (sink.items()) |ev| switch (ev) {
        .warning => |w| switch (w) {
            .addrs_truncated => |t| {
                try testing.expectEqual(@as(u32, 3), t.ifindex);
                switch (t.family) {
                    .v4 => v4_warn += 1,
                    .v6 => v6_warn += 1,
                }
            },
            else => {},
        },
        else => {},
    };
    try testing.expectEqual(@as(usize, 1), v4_warn);
    try testing.expectEqual(@as(usize, 1), v6_warn);
    // An interface with nothing dropped adds nothing and warns nothing.
    sink.clear();
    try e.setInterfaces(&.{ i, fake_lan.iface4(4, "en1", .{ 10, 0, 4, 1 }, 24) }, 1);
    _ = try sink.drain(&e);
    try testing.expectEqual(@as(u64, 10), e.stats().addrs_dropped); // once more per call
    try testing.expectEqual(@as(usize, 2), sink.countWarning(.addrs_truncated));
    try sink.expectCount(.interfaces_changed, 1);
}

test "handle never fails after init under a FailingAllocator sweep" {
    // `Engine.init` is the only allocating call. Sweep every failure
    // index: init either fails cleanly or the Engine works with an
    // allocator that refuses everything from then on.
    var fail_at: usize = 0;
    var inits_ok: usize = 0;
    while (fail_at < 64) : (fail_at += 1) {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_at });
        var sc: Scenario = .init(fail_at);
        var e = Engine.init(fa.allocator(), .{ .host_label = "sweep", .random = sc.random(), .limits = .{ .max_cache_records = 8, .max_events = 4, .max_interfaces = 2, .max_browses = 2 } }) catch |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            continue;
        };
        defer e.deinit();
        inits_ok += 1;
        try e.setInterfaces(&.{fake_lan.ifaceDual(3, "en0", .{ 10, 0, 3, 1 }, 24, 1)}, 0);
        _ = try e.browse(svc_type, 0);
        var buf: [1500]u8 = undefined;
        const bytes = try packets.fullInstance(&buf, svc_type, "alice", "host-a", 4433, .{ 10, 0, 3, 5 });
        var t: u64 = 0;
        while (t < 200 * s_us) : (t += 7 * s_us) {
            e.handle(bytes, peerMeta(true), t);
            e.handle(bytes[0..17], peerMeta(true), t);
            e.tick(t);
            var out: [1500]u8 = undefined;
            while (e.pollDatagram(&out, t)) |_| {}
            while (e.pollEvent()) |_| {}
        }
        try testing.expect(!fa.has_induced_failure);
        try testing.expect(e.stats().rx > 0);
    }
    try testing.expect(inits_ok > 0);
}

// ---- cache pressure and adversarial input ------------------------------

fn hostLabel(buf: *[24]u8, i: usize) []const u8 {
    return std.fmt.bufPrint(buf, "h{d}", .{i}) catch unreachable;
}

test "a full pool of descending TTLs is evicted without walking the instance table" {
    // The eviction scan reads the pin bit on the entry: one pass over the
    // pool per evicting record, no per-candidate predicate that walks the
    // instance table. 4096 foreign A records with strictly descending
    // TTLs (every slot beats the running minimum), then one 9000 B packet
    // whose every record evicts.
    const cap: u32 = 4096;
    var r = try Rig.init(41, .{ .max_cache_records = cap, .max_interfaces = 2 });
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [9000]u8 = undefined;
    var label: [24]u8 = undefined;
    var i: usize = 0;
    while (i < cap) {
        var p: Packet = .response(&buf);
        var n: usize = 0;
        while (n < 200 and i < cap) : (n += 1) {
            const ttl: u32 = @intCast(cap + 1000 - i);
            p.a(hostLabel(&label, i), .{ 10, 1, @intCast(i >> 8), @intCast(i & 255) }, ttl, false) catch break;
            i += 1;
        }
        try r.rx(p.bytes());
    }
    try testing.expectEqual(@as(usize, cap), r.e.cacheCount());

    var p: Packet = .responseLarge(&buf);
    var added: usize = 0;
    while (true) : (added += 1) {
        p.a(hostLabel(&label, 100_000 + added), .{ 10, 2, 0, 1 }, 5, false) catch break;
    }
    try testing.expect(added >= 300);
    const t0 = Io.Timestamp.now(testing.io, .awake);
    try r.rx(p.bytes());
    const elapsed_ms = @divTrunc(t0.durationTo(Io.Timestamp.now(testing.io, .awake)).toMicroseconds(), 1000);
    try testing.expectEqual(@as(u64, added), r.e.stats().evictions);
    try testing.expectEqual(@as(u64, 0), r.e.stats().evictions_pinned);
    try testing.expectEqual(@as(usize, cap), r.e.cacheCount());
    // Was 2.9 s in ReleaseSafe with the predicate scan; the flat scan is
    // ~4 ms. The bound is generous for a loaded Debug runner.
    try testing.expect(elapsed_ms < 1000);
}

test "junk SRV records for a found instance do not pin the pool" {
    // Plan section 4.5: only the records the resolve join consumes are
    // pinned (one SRV, one TXT, 8 + 8 addresses per instance). Extra SRV
    // rdata for a found instance is cached but evictable, so a peer
    // cannot fill the pool with records we would protect and starve
    // every later instance.
    const cap: u32 = 64;
    var r = try Rig.init(42, .{ .max_cache_records = cap, .max_events = 256 });
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [1500]u8 = undefined;
    var p: Packet = .response(&buf);
    try p.ptr(svc_type, "alice", 4500);
    try r.rx(p.bytes());
    try r.sink.expectCount(.found, 1);
    // 63 SRV records for alice, one per port, TTL max.
    var port: u16 = 1;
    while (port < cap) : (port += 1) {
        var j: Packet = .response(&buf);
        try j.srv("alice", svc_type, port, "host-a", std.math.maxInt(u32), false);
        try r.rx(j.bytes());
    }
    try testing.expectEqual(@as(usize, cap), r.e.cacheCount());
    // A legitimate second instance: found and resolved, the junk yields.
    try r.rx(try packets.fullInstance(&buf, svc_type, "bob", "host-b", 4434, .{ 10, 0, 3, 6 }));
    try r.sink.expectCount(.found, 2);
    try r.sink.expectCount(.resolved, 1);
    try testing.expectEqual(@as(u16, 4434), r.sink.last(.resolved).?.resolved.port);
    const st = r.e.stats();
    try testing.expect(st.evictions >= 4);
    try testing.expectEqual(@as(u64, 0), st.evictions_pinned);
    try testing.expectEqual(@as(u64, 0), st.cache_rejected);
    try testing.expectEqual(@as(usize, cap), r.e.cacheCount());
    // Alice's PTR (pinned) and the SRV the join used are still there.
    const cache = &r.e.querier.cache;
    try testing.expectEqual(@as(usize, 2), cache.countLive(&packets.typeName(svc_type), .ptr, wire.class_in));
    try testing.expect(cache.countLive(&packets.instanceName("alice", svc_type), .srv, wire.class_in) >= 1);
}

test "a pool full of browse data evicts the soonest-expiring pinned record and reports it" {
    // Every record pinned (real instances of the browsed type): the
    // cache takes the soonest-expiring pinned one rather than refusing
    // the newcomer, and the querier hears about it (a PTR eviction is a
    // `lost`).
    var r = try Rig.init(43, .{ .max_cache_records = 4, .max_events = 64 });
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [1500]u8 = undefined;
    var p: Packet = .response(&buf);
    try p.ptr(svc_type, "alice", 100);
    try p.ptr(svc_type, "bob", 200);
    try p.ptr(svc_type, "carol", 300);
    try p.ptr(svc_type, "dave", 400);
    try r.rx(p.bytes());
    try r.sink.expectCount(.found, 4);
    try testing.expect(r.e.cacheCount() == 4);
    var p2: Packet = .response(&buf);
    try p2.ptr(svc_type, "erin", 500);
    try r.rx(p2.bytes());
    try r.sink.expectCount(.found, 5);
    try r.sink.expectCount(.lost, 1);
    try wire.name.expectText("alice._qmsg._udp.local", r.sink.last(.lost).?.lost.instance);
    const st = r.e.stats();
    try testing.expectEqual(@as(u64, 1), st.evictions);
    try testing.expectEqual(@as(u64, 1), st.evictions_pinned);
    try testing.expectEqual(@as(u64, 0), st.cache_rejected);
    try testing.expectEqual(@as(usize, 4), r.e.querier.instanceCount());
}

test "a full due batch retries at the next tick instead of skipping a ladder step" {
    // 200 found instances with nothing else known need 400 follow-up
    // questions; one tick holds 256. The rest are counted as deferred
    // and go out at the very next tick, not at the next doubled step.
    var r = try Rig.init(44, .{ .max_cache_records = 1024, .max_events = 512 });
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [9000]u8 = undefined;
    var k: usize = 0;
    while (k < 10) : (k += 1) {
        var p: Packet = .response(&buf);
        var i: usize = 0;
        while (i < 20) : (i += 1) {
            var name: [32]u8 = undefined;
            const label = try std.fmt.bufPrint(&name, "instance-{d}", .{k * 20 + i});
            try p.ptr(svc_type, label, 4500);
        }
        try r.rx(p.bytes());
    }
    try r.sink.expectCount(.found, 200);
    // Every follow-up (and the browse question) is due by 120 ms.
    r.sc.set(200 * ms_us);
    try r.tick();
    const first = try drainQueries(&r.e, r.now());
    try testing.expectEqual(@as(usize, 256 * 2), first.questions); // per pair
    try testing.expectEqual(@as(u64, 401 - 256), r.e.stats().questions_deferred);
    // The deferred instances are due at once, not one ladder step later.
    try testing.expect(r.e.nextDeadline(r.now()).? <= r.now());
    r.sc.set(r.now() + 1);
    try r.tick();
    const second = try drainQueries(&r.e, r.now());
    // 72 whole instances plus the one whose TXT did not fit (it retries
    // both questions).
    try testing.expectEqual(@as(usize, (401 - 256 + 1) * 2), second.questions);
    try testing.expectEqual(@as(u64, 401 - 256), r.e.stats().questions_deferred);
    // Now everything waits for its next (doubled) step.
    try testing.expect(r.e.nextDeadline(r.now()).? >= r.now() + 1 * s_us);
}

test "unknown destination skips the QU-window drop but not the on-link check" {
    // A socket that delivers no destination cmsg: `dst_known = false`.
    // Responses from on-link sources are processed (otherwise browsing
    // would silently die); off-link sources are still dropped.
    var r = try Rig.init(45, .{});
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    var buf: [1500]u8 = undefined;
    const bytes = try packets.fullInstance(&buf, svc_type, "alice", "host-a", 4433, .{ 10, 0, 3, 5 });
    r.e.handle(bytes, .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 0, 9, 9 }, .port = 5353 } }, .ifindex = 3, .dst_multicast = false, .dst_known = false }, 0);
    _ = try r.sink.drain(&r.e);
    try testing.expectEqual(@as(u64, 1), r.e.stats().dropped_off_link);
    try testing.expectEqual(@as(u64, 1), r.e.stats().rx_dst_unknown);
    try r.sink.expectCount(.found, 0);
    r.e.handle(bytes, .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 9 }, .port = 5353 } }, .ifindex = 3, .dst_multicast = false, .dst_known = false }, 0);
    _ = try r.sink.drain(&r.e);
    try testing.expectEqual(@as(u64, 0), r.e.stats().dropped_unicast_unexpected);
    try testing.expectEqual(@as(u64, 2), r.e.stats().rx_dst_unknown);
    try r.sink.expectCount(.found, 1);
    try r.sink.expectCount(.resolved, 1);
}
