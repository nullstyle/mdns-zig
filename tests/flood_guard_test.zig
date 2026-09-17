//! Flood-guard tests (plan section 7 M5, section 4.4 query budget,
//! section 8 tier 1): packet budgets derived from the RFC 6762 schedule,
//! simulated over hours or a day in microseconds on the fake LAN with a
//! seeded PRNG and deadline-driven stepping (one iteration per timer,
//! not per millisecond, so a simulated day costs milliseconds of wall
//! clock).
//!
//! What each test pins:
//! - the section 5.2 browse ladder over 24 h against
//!   `timers.query_schedule_24h_budget` (36; plan section 4.4);
//! - an idle registration: exactly the section 8 probes and
//!   announcements, then not one unsolicited packet for a day;
//! - a hundred simultaneous probers of one name (section 8.2 tie-break,
//!   section 9 conflicts, the fifteen-conflicts-in-ten-seconds backoff)
//!   converging to unique names inside a packet budget;
//! - bridged interfaces (plan section 4.8, Revision 7 item 3): own
//!   echoes never rename, and the re-announce obeys the one-second rule
//!   per (record, interface, family) pair;
//! - two browsers of one type: section 7.1 known-answer suppression
//!   keeps the responder quiet after the first answer (each browser
//!   still runs its full ladder; section 7.3 duplicate-question
//!   suppression between browsers is an M6 item);
//! - a probe storm from a hostile peer: multicast defences at most one
//!   per `timers.defence_rate_limit_us` (250 ms) per pair (section 6),
//!   unicast copies at most one per probe, and never a rename.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const mdns = @import("mdns");
const wire = mdns.wire;
const scenario = @import("harness/scenario.zig");
const packets = @import("harness/packets.zig");
const fake_lan = @import("harness/fake_lan.zig");
const fake_responder = @import("harness/fake_responder.zig");

const Scenario = scenario.Scenario;
const Sink = scenario.Sink;
const Engine = mdns.Engine;
const Packet = packets.Packet;
const Name = wire.Name;
const timers = mdns.core.timers;
const State = mdns.core.responder.State;

const s_us = scenario.us_per_s;
const ms_us = scenario.us_per_ms;
const day_us = scenario.us_per_day;
const hour_us = scenario.us_per_hour;

const svc_type = "_mdnszig._udp";
const inst = "demo";
const port: u16 = 4433;

const foreign4: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 9 }, .port = 5353 } };

fn instName() Name {
    return packets.instanceName(inst, svc_type);
}

/// `10.0.3.<k+1>` for k < 254, else `10.0.4.<k-253>`.
fn lanAddr4(k: usize) [4]u8 {
    if (k < 254) return .{ 10, 0, 3, @intCast(k + 1) };
    return .{ 10, 0, 4, @intCast(k - 253) };
}

/// First record with that name and type in `section` of `bytes`, or
/// null (also null when the bytes do not parse).
fn recIn(bytes: []const u8, section: wire.Section, name: Name, rtype: wire.RType) ?wire.Record {
    const m = wire.Message.parse(bytes) catch return null;
    var it = m.records(section);
    while (it.next()) |rec| if (rec.rtype == rtype and rec.name.eql(&name)) return rec;
    return null;
}

/// Records with that name and type in any section of `bytes`.
fn countIn(bytes: []const u8, name: Name, rtype: wire.RType) usize {
    const m = wire.Message.parse(bytes) catch return 0;
    var n: usize = 0;
    var it = m.allRecords();
    while (it.next()) |rec| if (rec.rtype == rtype and rec.name.eql(&name)) {
        n += 1;
    };
    return n;
}

/// A foreign probe for `name` proposing an SRV of `their_port` at
/// `other.local` and an empty TXT (what a DNS-SD prober puts in the
/// Authority section).
fn foreignProbe(buf: []u8, their_port: u16, qu: bool) ![]const u8 {
    var p: Packet = .query(buf);
    try p.question(instName(), .any, qu);
    p.in(.authority);
    try p.srv(inst, svc_type, their_port, "other", 120, false);
    try p.txt(inst, svc_type, &.{}, 4500, false);
    return p.bytes();
}

// ---- rig ------------------------------------------------------------------

/// Up to `max` engines (`h<k>.local`) with one event sink each on one
/// `FakeLan`, a seeded clock and the deadline-driven loop. Everything
/// lives on the heap (a hundred engines do not fit a test's stack).
/// The engine's LAN index equals `k` as long as engines are attached in
/// order. `conflict_times[k]` records the clock at every step in which
/// engine `k`'s `stats().conflicts` grew (one entry per conflict), so a
/// test can check the section 9 backoff against the probe log.
fn Rig(comptime max: usize) type {
    return struct {
        const Self = @This();
        pub const Lan = fake_lan.FakeLan(max);

        sc: Scenario,
        lan: Lan,
        engines: []Engine,
        sinks: []Sink,
        conflict_times: []std.ArrayList(u64),
        conflicts_seen: []u64,
        responders: []const *fake_responder.FakeResponder = &.{},
        count: usize,
        /// Largest jump of the deadline-driven loop when nothing is
        /// scheduled.
        max_step_us: u64 = 10 * s_us,

        const Options = struct {
            seed: u64 = 0xf100d,
            count: usize = 1,
            limits: mdns.Limits = .{ .max_interfaces = 4, .max_events = 64 },
        };

        fn init(opts: Options) !*Self {
            std.debug.assert(opts.count <= max);
            const r = try testing.allocator.create(Self);
            errdefer testing.allocator.destroy(r);
            const engines = try testing.allocator.alloc(Engine, opts.count);
            errdefer testing.allocator.free(engines);
            const sinks = try testing.allocator.alloc(Sink, opts.count);
            errdefer testing.allocator.free(sinks);
            const conflict_times = try testing.allocator.alloc(std.ArrayList(u64), opts.count);
            errdefer testing.allocator.free(conflict_times);
            const conflicts_seen = try testing.allocator.alloc(u64, opts.count);
            errdefer testing.allocator.free(conflicts_seen);
            @memset(conflict_times, .empty);
            @memset(conflicts_seen, 0);
            r.* = .{
                .sc = .init(opts.seed),
                .lan = .init(testing.allocator),
                .engines = engines,
                .sinks = sinks,
                .conflict_times = conflict_times,
                .conflicts_seen = conflicts_seen,
                .count = 0,
            };
            errdefer r.lan.deinit();
            errdefer {
                for (r.engines[0..r.count], r.sinks[0..r.count]) |*e, *s| {
                    s.deinit();
                    e.deinit();
                }
            }
            while (r.count < opts.count) {
                var label: [16]u8 = undefined;
                r.engines[r.count] = try Engine.init(testing.allocator, .{
                    .host_label = try std.fmt.bufPrint(&label, "h{d}", .{r.count}),
                    .random = r.sc.random(),
                    .limits = opts.limits,
                });
                r.sinks[r.count] = .init(testing.allocator);
                r.count += 1;
            }
            return r;
        }

        fn deinit(r: *Self) void {
            r.lan.deinit();
            for (r.engines[0..r.count], r.sinks[0..r.count]) |*e, *s| {
                s.deinit();
                e.deinit();
            }
            for (r.conflict_times) |*c| c.deinit(testing.allocator);
            testing.allocator.free(r.conflict_times);
            testing.allocator.free(r.conflicts_seen);
            testing.allocator.free(r.sinks);
            testing.allocator.free(r.engines);
            testing.allocator.destroy(r);
        }

        /// Engine `k` on `segment` with one v4-only interface (ifindex 3,
        /// `10.0.3.<k+1>`/24): one joined pair.
        fn attach4(r: *Self, k: usize, segment: u32) !void {
            const idx = try r.lan.addEngineOn(&r.engines[k], fake_lan.iface4(3, "en0", lanAddr4(k), 24), segment, r.now());
            try testing.expectEqual(k, idx);
            try r.drainAll();
            r.sinks[k].clear();
        }

        /// Engine `k` on `segment` with ifindex 3, `10.0.3.<k+1>`/24 and
        /// `fe80::<k+1>`/64: two joined pairs.
        fn attachDual(r: *Self, k: usize, segment: u32) !void {
            const idx = try r.lan.addEngineOn(&r.engines[k], fake_lan.ifaceDual(3, "en0", lanAddr4(k), 24, @intCast(k + 1)), segment, r.now());
            try testing.expectEqual(k, idx);
            try r.drainAll();
            r.sinks[k].clear();
        }

        fn now(r: *const Self) u64 {
            return r.sc.nowUs();
        }

        fn drainAll(r: *Self) !void {
            for (r.engines[0..r.count], r.sinks[0..r.count], 0..) |*e, *s, k| {
                _ = try s.drain(e);
                const c = e.stats().conflicts;
                while (r.conflicts_seen[k] < c) : (r.conflicts_seen[k] += 1) {
                    try r.conflict_times[k].append(testing.allocator, r.now());
                }
            }
        }

        /// Tick every engine, pump the LAN, pump the scripted
        /// responders and drain every sink, at the current clock.
        fn step(r: *Self) !void {
            const t = r.now();
            r.lan.tickAll(t);
            try r.lan.pump(t);
            for (r.responders) |resp| try resp.pump(&r.lan, t);
            try r.drainAll();
        }

        /// The clock of the next step after `t`: the soonest engine
        /// deadline (at least 1 us ahead), at most `max_step_us` ahead,
        /// never past `until`.
        fn nextStep(r: *const Self, t: u64, until: u64) u64 {
            var next = t +| r.max_step_us;
            if (r.lan.nextDeadline(t)) |d| next = @min(next, @max(d, t + 1));
            for (r.responders) |resp| if (resp.nextDueUs()) |d| {
                next = @min(next, @max(d, t + 1));
            };
            return @min(next, until);
        }

        /// Step at the current clock, then jump from deadline to deadline
        /// until `until` (inclusive).
        fn runTo(r: *Self, until: u64) !void {
            while (true) {
                try r.step();
                const t = r.now();
                if (t >= until) break;
                r.sc.set(r.nextStep(t, until));
            }
        }

        fn advance(r: *Self, us: u64) !void {
            try r.runTo(r.now() + us);
        }

        /// Run until no engine has sent a packet for `quiet_us`, or fail
        /// with `error.NotQuiet` once `cap_us` has passed.
        fn runUntilQuiet(r: *Self, quiet_us: u64, cap_us: u64) !void {
            const start = r.now();
            const cap = start +| cap_us;
            while (true) {
                try r.step();
                const t = r.now();
                const last = if (r.log().len == 0) start else r.log()[r.log().len - 1].now_us;
                if (t >= last +| quiet_us) return;
                if (t >= cap) return error.NotQuiet;
                r.sc.set(r.nextStep(t, @min(cap, last +| quiet_us)));
            }
        }

        fn advertiseOn(r: *Self, k: usize, instance: []const u8, svc_port: u16) !mdns.RegId {
            return r.engines[k].advertise(.{ .service_type = svc_type, .instance = instance, .port = svc_port, .txt = &.{.{ .key = "txtvers", .value = "1" }} }, r.now());
        }

        fn log(r: *const Self) []const fake_lan.Sent {
            return r.lan.sentLog();
        }

        fn sent(r: *const Self, filter: scenario.Filter) usize {
            return scenario.countSent(r.log(), filter);
        }
    };
}

// ---- the tests ------------------------------------------------------------

test "browse budget over 24h matches derived schedule" {
    // RFC 6762 section 5.2: first query 20-120 ms after `browse`, then
    // gaps of 1, 2, 4, ... s, each plus 0-2 % jitter, capped at 60 min.
    // One engine, one browse, one joined pair, nobody answering: the
    // packets over a day are exactly that ladder, within the budget the
    // timers table derives from it (35 + 1 = 36, plan section 4.4).
    const r = try Rig(1).init(.{ .seed = 0x24b0d6e7 });
    defer r.deinit();
    try r.attach4(0, 0);
    r.max_step_us = hour_us;
    _ = try r.engines[0].browse(svc_type, r.now());
    try r.runTo(day_us);

    const queries: scenario.Filter = .{ .from_engine = 0, .kind = .query };
    var buf: [64]u64 = undefined;
    const at = scenario.sendTimes(r.log(), queries, &buf);
    try testing.expectEqual(at.len, r.log().len); // nothing but queries
    try testing.expect(at.len <= timers.query_schedule_24h_budget);
    try testing.expect(at.len >= 30);
    try testing.expectEqual(@as(usize, 0), r.sent(.{ .kind = .malformed }));
    // First query inside the 20-120 ms window.
    try testing.expect(at[0] >= timers.query_first_delay_min_us);
    try testing.expect(at[0] <= timers.query_first_delay_max_us);
    // Gaps: the first is 1 s (+2 %); each later one is at least the
    // doubled previous gap until the cap, so the sequence never shrinks
    // while doubling, and in the capped steady state every gap is
    // 3600 s plus the section 5.2 jitter (0-2 %), never more.
    const cap = timers.query_interval_cap_us;
    const cap_jittered = cap + (cap / 100) * timers.query_jitter_max_pct;
    var prev_gap: u64 = 0;
    for (at[1..], 1..) |t, i| {
        const gap = t - at[i - 1];
        if (i == 1) {
            try testing.expect(gap >= timers.query_interval_first_us);
            try testing.expect(gap <= timers.query_interval_first_us + timers.query_interval_first_us / 50);
        } else {
            try testing.expect(gap >= @min(2 * prev_gap, cap));
        }
        try testing.expect(gap <= cap_jittered);
        prev_gap = gap;
    }
    // The tail of the day is in the capped regime: the last gap is a
    // full hour (+ jitter).
    try testing.expect(prev_gap >= cap);
    // Every packet is a QM PTR question for the type on the one pair;
    // the own echo never fed the cache.
    for (r.log()) |*s| {
        try testing.expectEqual(@as(u32, 3), s.ifindex);
        try testing.expectEqual(mdns.Family.v4, s.family);
        try testing.expect(s.isMulticast());
        const m = try wire.Message.parse(s.bytes);
        try testing.expectEqual(@as(u16, 1), m.header.qdcount);
        var qs = m.questions();
        const q = qs.next().?;
        try testing.expect(q.name.eql(&packets.typeName(svc_type)));
        try testing.expectEqual(wire.RType.ptr, q.qtype);
        try testing.expect(!q.qu);
    }
    const st = r.engines[0].stats();
    try testing.expectEqual(@as(u64, at.len), st.tx);
    try testing.expectEqual(st.rx, st.rx_echo);
    try testing.expectEqual(@as(usize, 0), r.engines[0].cacheCount());
    try r.sinks[0].expectCount(.found, 0);
    try r.sinks[0].expectCount(.warning, 0);
}

test "idle advertised service emits zero unsolicited packets over 24h" {
    // One registration on a dual-stack interface (two joined pairs):
    // three probes and two announcements per pair inside the first 3 s
    // (section 8.1: 0-250 ms, then 250 ms apart; section 8.3: 1 s
    // apart), then nothing for a day. Every packet comes back as a
    // loopback echo and changes nothing.
    const r = try Rig(1).init(.{ .seed = 0x1d1e });
    defer r.deinit();
    try r.attachDual(0, 0);
    _ = try r.advertiseOn(0, inst, port);
    try r.runTo(3 * s_us);
    try r.sinks[0].expectCount(.registered, 1);
    try r.sinks[0].expectCount(.renamed, 0);
    try r.sinks[0].expectCount(.host_renamed, 0);
    try r.sinks[0].expectCount(.warning, 0);
    const pairs = [_]struct { ifindex: u32, family: mdns.Family }{ .{ .ifindex = 3, .family = .v4 }, .{ .ifindex = 3, .family = .v6 } };
    for (pairs) |p| {
        try testing.expectEqual(@as(usize, timers.probe_count), r.sent(.{ .ifindex = p.ifindex, .family = p.family, .kind = .query }));
        try testing.expectEqual(@as(usize, timers.announce_count), r.sent(.{ .ifindex = p.ifindex, .family = p.family, .kind = .response }));
    }
    const total = pairs.len * (timers.probe_count + timers.announce_count);
    try testing.expectEqual(total, r.log().len);
    const last = r.log()[r.log().len - 1].now_us;
    try testing.expect(last <= timers.probe_first_delay_max_us + timers.probe_count * timers.probe_interval_us + timers.announce_interval_us);
    try testing.expectEqual(null, r.engines[0].nextDeadline(r.now()));

    // A day of silence, stepped an hour at a time when nothing is due.
    r.lan.clearLog();
    r.max_step_us = hour_us;
    try r.advance(day_us);
    try testing.expectEqual(@as(usize, 0), r.log().len);
    const st = r.engines[0].stats();
    try testing.expectEqual(@as(u64, total), st.tx);
    try testing.expectEqual(@as(u64, total), st.rx);
    try testing.expectEqual(@as(u64, total), st.rx_echo);
    try testing.expectEqual(@as(u64, 0), st.rx_echo_bridged);
    try testing.expectEqual(@as(u64, 0), st.conflicts);
    try testing.expectEqual(@as(u64, 0), st.tx_dropped);
    try testing.expectEqual(@as(u64, 0), st.answers_dropped);
    try testing.expectEqual(@as(usize, 0), r.engines[0].cacheCount());
    try testing.expectEqual(null, r.engines[0].nextDeadline(r.now()));
    try r.sinks[0].expectCount(.registered, 1);
    try r.sinks[0].expectCount(.renamed, 0);
    try r.sinks[0].expectCount(.warning, 0);
    try testing.expectEqual(State.established, r.engines[0].responder.regState(r.sinks[0].first(.registered).?.registered.id).?);
}

test "hundred simultaneous probers converge to unique names" {
    // A hundred hosts on one segment advertise the instance `Same` of
    // one type at the same instant, each with its own SRV (port and
    // host). Section 8.2 tie-breaks settle the simultaneous probes,
    // section 9 conflicts rename the late ones (`Same (2)`, ...), and
    // the fifteen-conflicts-in-ten-seconds rule slows every host that
    // keeps losing. In the end every host is established under its own
    // name, exactly one kept `Same`, the names are `Same` and `Same (2)`
    // through `Same (100)`, and the whole affair stayed inside a packet
    // budget.
    const n = 100;
    const r = try Rig(n).init(.{
        .seed = 0xc0e5,
        .count = n,
        .limits = .{ .max_interfaces = 1, .max_events = 64, .max_registrations = 1, .max_browses = 1, .max_pending_answers = 32, .max_cache_records = 32 },
    });
    defer r.deinit();
    // A hundred `handle` calls per datagram: count them, do not log them.
    r.lan.log_deliveries = false;
    for (0..n) |k| try r.attach4(k, 0);
    var ids: [n]mdns.RegId = undefined;
    for (&ids, 0..) |*id, k| id.* = try r.advertiseOn(k, "Same", @intCast(1000 + k));
    // Quiet for a minute (the longest timer in play is the 5 s backoff
    // plus a probe round); a name storm that has not settled after an
    // hour of simulated time is a bug.
    try r.runUntilQuiet(60 * s_us, hour_us);
    const settled_us = r.log()[r.log().len - 1].now_us;

    var names: [n]Name = undefined;
    var claimed: [n + 1]bool = @splat(false); // claimed[k]: `Same (k)` (k >= 2); claimed[1]: `Same`
    var renames_total: usize = 0;
    for (r.engines[0..n], r.sinks[0..n], 0..) |*e, *s, k| {
        try testing.expectEqual(State.established, e.responder.regState(ids[k]).?);
        try testing.expectEqual(@as(usize, 1), e.registrationCount());
        try testing.expect(s.count(.registered) >= 1);
        names[k] = e.responder.instanceName(ids[k]).?;
        try testing.expect(s.last(.registered).?.registered.instance.eql(&names[k]));
        try s.expectCount(.host_renamed, 0);
        try s.expectCount(.warning, 0);
        // `Same` or `Same (j)`, 2 <= j <= 100, each taken once.
        const label = names[k].firstLabel().?;
        const j: usize = blk: {
            if (std.mem.eql(u8, label, "Same")) break :blk 1;
            try testing.expect(std.mem.startsWith(u8, label, "Same ("));
            try testing.expect(std.mem.endsWith(u8, label, ")"));
            break :blk try std.fmt.parseInt(usize, label["Same (".len .. label.len - 1], 10);
        };
        try testing.expect(j >= 1 and j <= n);
        try testing.expect(!claimed[j]);
        claimed[j] = true;
        // Renamed exactly as far as its final suffix says, one step at a
        // time from `Same`; never more than the 99 a hundred probers
        // can force.
        const renames = s.count(.renamed);
        try testing.expectEqual(j - 1, renames);
        try testing.expect(renames <= n - 1);
        renames_total += renames;
        if (renames != 0) {
            try testing.expect(s.first(.renamed).?.renamed.old.eql(&packets.instanceName("Same", svc_type)));
            try testing.expect(s.last(.renamed).?.renamed.new.eql(&names[k]));
        }
    }
    for (claimed[1..]) |c| try testing.expect(c);
    try testing.expectEqual(@as(usize, n * (n - 1) / 2), renames_total);
    for (names, 0..) |a, i| for (names[i + 1 ..]) |b| try testing.expect(!a.eql(&b));

    // Section 9 backoff: after fifteen conflicts within ten seconds no
    // probe leaves that engine for five seconds. Conflict times come
    // from the per-step counter samples; probes are the engine's
    // queries in the LAN log.
    var backoffs: usize = 0;
    var probe_times: std.ArrayList(u64) = .empty;
    defer probe_times.deinit(testing.allocator);
    for (0..n) |k| {
        const c = r.conflict_times[k].items;
        try testing.expectEqual(@as(u64, c.len), r.engines[k].stats().conflicts);
        probe_times.clearRetainingCapacity();
        for (r.log()) |*s| if (s.from_engine == k and s.kind == .query) try probe_times.append(testing.allocator, s.now_us);
        var i: usize = timers.conflict_backoff_count - 1;
        while (i < c.len) : (i += 1) {
            const oldest = c[i + 1 - timers.conflict_backoff_count];
            if (c[i] - oldest > timers.conflict_backoff_window_us) continue;
            backoffs += 1;
            // A probe drained in the same step was sent before the
            // conflict was delivered (the LAN drains, then delivers), so
            // the window is open at the conflict's own instant.
            for (probe_times.items) |tp| if (tp > c[i] and tp < c[i] + timers.conflict_backoff_delay_us) {
                std.debug.print("engine {d}: probe at {d} us inside the 5 s backoff after conflict {d} at {d} us\n", .{ k, tp, i + 1, c[i] });
                return error.TestUnexpectedResult;
            };
        }
    }
    // A hundred probers of one name do trip the rule.
    try testing.expect(backoffs > 0);

    // Budget. The schedule alone gives a loose bound (a probe round
    // aborts at its first conflict, so `(renames + 1) * 3` probes per
    // engine never happen); the observed order with this seed is 3484
    // packets (3083 probes, 401 responses) and 50 for the busiest
    // engine, so the bounds sit just above that and a 15 % regression
    // trips them. Every packet well-formed.
    const total = r.log().len;
    try testing.expect(total <= 4000);
    try testing.expectEqual(@as(usize, 0), r.sent(.{ .kind = .malformed }));
    var queries: usize = 0;
    var responses: usize = 0;
    var max_per_engine: usize = 0;
    for (0..n) |k| {
        queries += r.sent(.{ .from_engine = k, .kind = .query });
        responses += r.sent(.{ .from_engine = k, .kind = .response });
        max_per_engine = @max(max_per_engine, r.sent(.{ .from_engine = k }));
    }
    try testing.expect(max_per_engine <= 60);
    // Every engine probed (3 probes per round, at least one round) and
    // then announced twice.
    try testing.expect(queries >= n * 3);
    try testing.expect(responses >= n * 2);
    std.log.debug("hundred probers: {d} packets ({d} probes, {d} responses), busiest engine {d}, {d} renames, {d} backoffs, settled at {d} s", .{ total, queries, responses, max_per_engine, renames_total, backoffs, settled_us / s_us });
    // Then silence: nothing else is scheduled but cache expiry.
    r.lan.clearLog();
    try r.advance(60 * s_us);
    try testing.expectEqual(@as(usize, 0), r.log().len);
}

test "bridged interfaces never rename on own echo" {
    // One engine with two interfaces on two segments that a switch
    // bridges (plan section 4.8 "Bridged echo", Revision 7 item 3):
    // every packet on ifindex 3 comes back on ifindex 4 from our own
    // 10.0.3.1 and the other way round. Own echoes never count as a
    // conflict, never rename, and the address re-announce they may
    // trigger is dropped, not deferred, under the one-second rule per
    // (record, interface, family) pair, so the bridge never ping-pongs.
    const r = try Rig(1).init(.{ .seed = 0xb21d });
    defer r.deinit();
    const if3 = fake_lan.ifaceDual(3, "en0", .{ 10, 0, 3, 1 }, 24, 1);
    const if4 = fake_lan.iface4(4, "en1", .{ 10, 0, 4, 1 }, 24);
    try r.lan.bridge(0, 1);
    _ = try r.lan.addEngine(&r.engines[0], &.{ if3, if4 }, &.{ 0, 1 }, 0);
    try r.drainAll();
    r.sinks[0].clear();
    const host = packets.hostName("h0");
    const pairs = [_]struct { ifindex: u32, family: mdns.Family }{ .{ .ifindex = 3, .family = .v4 }, .{ .ifindex = 3, .family = .v6 }, .{ .ifindex = 4, .family = .v4 } };

    // Phase 1: both interfaces come up together and announce; 60 s.
    _ = try r.advertiseOn(0, inst, port);
    try r.runTo(60 * s_us);
    try r.sinks[0].expectCount(.registered, 1);
    try r.sinks[0].expectCount(.renamed, 0);
    try r.sinks[0].expectCount(.host_renamed, 0);
    var st = r.engines[0].stats();
    try testing.expectEqual(@as(u64, 0), st.conflicts);
    try testing.expect(st.rx_echo_bridged > 0);
    try testing.expectEqual(st.rx, st.rx_echo);
    try testing.expectEqual(@as(usize, 0), r.engines[0].cacheCount());
    try testing.expect(r.engines[0].hostName().eql(&host));
    try testing.expect(r.engines[0].responder.instanceName(r.sinks[0].first(.registered).?.registered.id).?.eql(&instName()));
    try checkAddressRate(r.log(), &pairs, host);
    for (pairs) |p| {
        try testing.expectEqual(@as(usize, timers.probe_count), r.sent(.{ .ifindex = p.ifindex, .family = p.family, .kind = .query }));
        // The two announcements, plus at most one re-announce per
        // announcement echoed across the bridge.
        const responses = r.sent(.{ .ifindex = p.ifindex, .family = p.family, .kind = .response });
        try testing.expect(responses >= timers.announce_count);
        try testing.expect(responses <= 2 * timers.announce_count);
    }
    try testing.expect(r.log()[r.log().len - 1].now_us <= 3 * s_us);

    // Phase 2: ifindex 4 leaves and comes back alone; its announcements
    // echo onto ifindex 3 more than a second after ifindex 3 last
    // multicast its addresses, so the re-announce actually fires. Still
    // no rename, still one address multicast per pair per second, and
    // silence after a few seconds.
    r.lan.clearLog();
    try r.lan.setInterfaces(0, &.{if3}, &.{0}, r.now());
    try r.advance(5 * s_us);
    r.lan.clearLog();
    r.sinks[0].clear();
    const t_add = r.now();
    try r.lan.setInterfaces(0, &.{ if3, if4 }, &.{ 0, 1 }, t_add);
    try r.runTo(t_add + 60 * s_us);
    try r.sinks[0].expectCount(.renamed, 0);
    try r.sinks[0].expectCount(.host_renamed, 0);
    st = r.engines[0].stats();
    try testing.expectEqual(@as(u64, 0), st.conflicts);
    try testing.expectEqual(st.rx, st.rx_echo);
    try testing.expect(r.engines[0].hostName().eql(&host));
    try testing.expectEqual(@as(usize, 0), r.sent(.{ .kind = .query }));
    try checkAddressRate(r.log(), &pairs, host);
    var reannounced: usize = 0;
    for (r.log()) |*s| {
        try testing.expectEqual(fake_lan.PacketKind.response, s.kind);
        try testing.expect(s.now_us <= t_add + 3 * s_us);
        if (countIn(s.bytes, instName(), .srv) == 0) reannounced += 1;
    }
    try testing.expect(reannounced >= 1);
    try testing.expectEqual(@as(usize, timers.announce_count), r.sent(.{ .ifindex = 4 }));
    // Then silence.
    r.lan.clearLog();
    try r.advance(60 * s_us);
    try testing.expectEqual(@as(usize, 0), r.log().len);
    try testing.expectEqual(null, r.engines[0].nextDeadline(r.now()));
}

/// The one-second rule on the host's address records per pair: among
/// the responses on a pair that carry the host's A or AAAA, never two
/// inside one second (`maxInWindow` over `[t, t + 1 s)`).
fn checkAddressRate(log: []const fake_lan.Sent, pairs: anytype, host: Name) !void {
    for (pairs) |p| {
        var best: usize = 0;
        for (log, 0..) |*anchor, i| {
            if (!carriesAddr(anchor, p.ifindex, p.family, host)) continue;
            var count: usize = 0;
            const end = anchor.now_us + timers.record_rate_limit_us;
            for (log[i..]) |*s| {
                if (s.now_us >= end) break;
                if (carriesAddr(s, p.ifindex, p.family, host)) count += 1;
            }
            best = @max(best, count);
        }
        if (best > 1) {
            std.debug.print("pair ({d}, {s}): {d} address multicasts inside one second\n", .{ p.ifindex, @tagName(p.family), best });
            return error.TestUnexpectedResult;
        }
    }
}

fn carriesAddr(s: *const fake_lan.Sent, ifindex: u32, family: mdns.Family, host: Name) bool {
    if (s.ifindex != ifindex or s.family != family or s.kind != .response) return false;
    return countIn(s.bytes, host, .a) != 0 or countIn(s.bytes, host, .aaaa) != 0;
}

test "two browsers of one type get at most two answers and known-answer lists silence the rest" {
    // Two browsers of one type on one segment and a scripted responder
    // with one instance (RFC 6762 section 7.1 on the responder side).
    // Every browser hears every multicast answer, so after the first
    // reply both list the PTR as a known answer at full TTL and the
    // responder stays silent: two ladders of queries, one or two
    // answers. (Section 7.3 duplicate-question suppression between the
    // two browsers is an M6 item; the ladders themselves are not
    // thinned here.) The TTLs are long enough that no requery mark
    // fires inside the window.
    const table = [_]fake_responder.InstanceSpec{
        .{ .instance = "shared", .service_type = svc_type, .host = "host-r", .port = 5000, .txt = &.{.{ .key = "txtvers", .value = "1" }}, .addrs4 = &.{.{ 10, 0, 3, 200 }} },
    };
    var resp: fake_responder.FakeResponder = .init(0, .{ 10, 0, 3, 200 }, 200, &table, .{ .srv_ttl = 4500, .addr_ttl = 4500 });
    const r = try Rig(2).init(.{ .seed = 0x5ea6, .count = 2 });
    defer r.deinit();
    try r.attach4(0, 0);
    try r.attach4(1, 0);
    r.responders = &.{&resp};
    _ = try r.engines[0].browse(svc_type, r.now());
    _ = try r.engines[1].browse(svc_type, r.now());
    // 80 % of 4500 s is 3600 s: stop before the first requery mark.
    const window = 3500 * s_us;
    try r.runTo(window);

    for (r.sinks[0..2]) |*s| {
        try s.expectCount(.found, 1);
        try s.expectCount(.resolved, 1);
        try s.expectCount(.lost, 0);
        try s.expectCount(.warning, 0);
    }
    // Twelve ladder queries each (0, 1, 3, ..., 2047 s, +jitter), all
    // seen by the responder.
    const q0 = r.sent(.{ .from_engine = 0, .kind = .query });
    const q1 = r.sent(.{ .from_engine = 1, .kind = .query });
    try testing.expectEqual(@as(usize, 12), q0);
    try testing.expectEqual(@as(usize, 12), q1);
    try testing.expectEqual(@as(u64, q0 + q1), resp.stats.queries_seen);
    try testing.expectEqual(@as(usize, 0), r.sent(.{ .kind = .response }));
    // One answer per query that arrived before the first answer (at
    // most two), then the known-answer list suppresses every other one.
    try testing.expect(resp.stats.responses_sent >= 1);
    try testing.expect(resp.stats.responses_sent <= 2);
    try testing.expectEqual(@as(u64, q0 + q1), resp.stats.responses_sent + resp.stats.suppressed);
    try testing.expect(resp.stats.suppressed >= 22);
    try testing.expectEqual(@as(u64, 0), resp.stats.pending_overflow);
    try testing.expectEqual(@as(u64, 0), resp.stats.questions_unanswered);
    // Every query after the first answer carried the PTR as a known
    // answer (section 7.1), with at least half its TTL left.
    var first_answer: ?u64 = null;
    for (r.lan.deliveryLog()) |d| if (d.from_engine == null and (first_answer == null or d.now_us < first_answer.?)) {
        first_answer = d.now_us;
    };
    try testing.expect(first_answer != null);
    for (r.log()) |*s| {
        if (s.now_us <= first_answer.?) continue;
        const rec = recIn(s.bytes, .answer, packets.typeName(svc_type), .ptr) orelse return error.TestUnexpectedResult;
        try testing.expect(rec.ttl >= 4500 / 2);
    }
}

test "probe storm from a hostile peer is rate bounded" {
    // A hostile peer probes for our established name every 10 ms for
    // 10 s (a thousand probes) on the v4 pair. Section 6: a probe for a
    // name we own is defended at once, exempt from the one-second rule
    // but never more than once per 250 ms per record and interface
    // (`timers.defence_rate_limit_us`); a defence held back is deferred
    // to the next allowed moment, not lost. Probes alone never rename
    // us: we are established, so they are answered, not tie-broken.
    const r = try Rig(1).init(.{ .seed = 0x5707 });
    defer r.deinit();
    try r.attachDual(0, 0);
    const id = try r.advertiseOn(0, inst, port);
    try r.runTo(4 * s_us);
    try r.sinks[0].expectCount(.registered, 1);
    r.lan.clearLog();
    r.sinks[0].clear();

    // Phase 1: QM probes. Every defence goes by multicast.
    var buf: [512]u8 = undefined;
    const probe = try foreignProbe(&buf, 9999, false);
    const t0 = r.now();
    const storm_probes: usize = 1000;
    const storm_gap = 10 * ms_us;
    var k: usize = 0;
    while (k < storm_probes) : (k += 1) {
        _ = try r.lan.injectForeign(0, probe, foreign4, true, r.now());
        try r.advance(storm_gap);
    }
    try r.advance(s_us);
    const storm_us = storm_probes * storm_gap;
    const v4: scenario.Filter = .{ .from_engine = 0, .kind = .response, .ifindex = 3, .family = .v4 };
    const defences = r.sent(v4);
    // One per 250 ms over the storm, plus the deferred defence of the
    // burst's tail; never fewer than the storm's length allows.
    const bound: usize = storm_us / timers.defence_rate_limit_us + 1;
    try testing.expect(defences <= bound);
    try testing.expect(defences >= bound - 1);
    try testing.expectEqual(@as(usize, 1), scenario.maxInWindow(r.log(), v4, timers.defence_rate_limit_us));
    try testing.expectEqual(defences, r.log().len); // nothing else at all
    var last: ?u64 = null;
    for (r.log()) |*s| {
        try testing.expect(s.isMulticast());
        try testing.expect(s.now_us >= t0 and s.now_us <= t0 + storm_us);
        const srv = recIn(s.bytes, .answer, instName(), .srv) orelse return error.TestUnexpectedResult;
        try testing.expect(srv.cache_flush);
        try testing.expectEqual(port, (try wire.rdata.decodeSrv(s.bytes, srv)).port);
        if (last) |l| try testing.expect(s.now_us - l >= timers.defence_rate_limit_us);
        last = s.now_us;
    }
    try testing.expectEqual(@as(usize, 0), r.sent(.{ .kind = .query }));
    try testing.expectEqual(@as(usize, 0), r.sent(.{ .family = .v6 }));
    try r.sinks[0].expectCount(.renamed, 0);
    try r.sinks[0].expectCount(.host_renamed, 0);
    try r.sinks[0].expectCount(.registered, 0);
    var st = r.engines[0].stats();
    try testing.expectEqual(@as(u64, 0), st.conflicts);
    try testing.expectEqual(@as(u64, 0), st.answers_dropped);
    try testing.expectEqual(State.established, r.engines[0].responder.regState(id).?);
    try testing.expect(r.engines[0].responder.instanceName(id).?.eql(&instName()));

    // Phase 2: the same storm with QU set. A unicast copy is never
    // rate-limited (section 5.4), but it is one reply per probe to the
    // prober itself, never amplified; multicast defences keep the 250 ms
    // spacing (and stay away while the records were multicast within
    // TTL/4, section 5.4).
    r.lan.clearLog();
    const probe_qu = try foreignProbe(&buf, 9999, true);
    const t1 = r.now();
    k = 0;
    while (k < storm_probes) : (k += 1) {
        _ = try r.lan.injectForeign(0, probe_qu, foreign4, true, r.now());
        try r.advance(storm_gap);
    }
    try r.advance(s_us);
    var unicast: usize = 0;
    var unicast_bytes: usize = 0;
    var multicast: usize = 0;
    for (r.log()) |*s| {
        try testing.expectEqual(fake_lan.PacketKind.response, s.kind);
        try testing.expectEqual(@as(u32, 3), s.ifindex);
        try testing.expectEqual(mdns.Family.v4, s.family);
        try testing.expect(s.now_us >= t1 and s.now_us <= t1 + storm_us);
        if (s.isMulticast()) {
            multicast += 1;
        } else {
            try testing.expectEqual(foreign4.ip4.bytes, s.to.ip4.bytes);
            unicast += 1;
            unicast_bytes += s.bytes.len;
        }
    }
    try testing.expect(unicast <= storm_probes);
    // Byte amplification towards the (on-link) prober: one reply per
    // probe, each carrying SRV + TXT + A + NSEC for our name (125 B for
    // an 81 B probe here, about 1.5x). SECURITY.md states this bound; a
    // change to the reply shape or to the per-probe rule shows up here.
    try testing.expect(unicast_bytes <= 2 * storm_probes * probe_qu.len);
    try testing.expect(multicast <= bound);
    var v4_mc = v4;
    v4_mc.multicast = true;
    try testing.expect(scenario.maxInWindow(r.log(), v4_mc, timers.defence_rate_limit_us) <= 1);
    try testing.expectEqual(@as(usize, 0), r.sent(.{ .kind = .query }));
    try r.sinks[0].expectCount(.renamed, 0);
    try r.sinks[0].expectCount(.host_renamed, 0);
    st = r.engines[0].stats();
    try testing.expectEqual(@as(u64, 0), st.conflicts);
    try testing.expectEqual(State.established, r.engines[0].responder.regState(id).?);
    try testing.expect(r.engines[0].responder.instanceName(id).?.eql(&instName()));
    std.log.debug("probe storm: {d} QM probes -> {d} multicast defences; {d} QU probes -> {d} unicast ({d} B for {d} B of probes) + {d} multicast", .{ storm_probes, defences, storm_probes, unicast, unicast_bytes, storm_probes * probe_qu.len, multicast });

    // And quiet afterwards.
    r.lan.clearLog();
    try r.advance(30 * s_us);
    try testing.expectEqual(@as(usize, 0), r.log().len);
}
