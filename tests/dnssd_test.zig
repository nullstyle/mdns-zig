//! DNS-SD (RFC 6763) tests over the Engine (plan section 7, M3): the
//! cache model of plan section 4.5 (order-independent harvesting, three
//! hashicorp/mdns regressions) and the `resolved` re-emit rule of plan
//! section 5.
const std = @import("std");
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

const s_us = scenario.us_per_s;
const svc_type = "_qmsg._udp";

const Rig = struct {
    sc: Scenario,
    e: Engine,
    sink: Sink,
    id: mdns.BrowseId,

    /// One engine on ifindex 3 (10.0.3.1/24 + fe80::1/64) browsing
    /// `_qmsg._udp` from t = 0.
    fn init(seed: u64) !*Rig {
        const r = try testing.allocator.create(Rig);
        errdefer testing.allocator.destroy(r);
        r.sc = .init(seed);
        r.e = try Engine.init(testing.allocator, .{ .host_label = "rig", .random = r.sc.random() });
        errdefer r.e.deinit();
        r.sink = .init(testing.allocator);
        try r.e.setInterfaces(&.{fake_lan.ifaceDual(3, "en0", .{ 10, 0, 3, 1 }, 24, 1)}, 0);
        r.id = try r.e.browse(svc_type, 0);
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

    fn rx(r: *Rig, bytes: []const u8) !void {
        r.e.handle(bytes, .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 9 }, .port = 5353 } }, .ifindex = 3, .dst_multicast = true }, r.now());
        _ = try r.sink.drain(&r.e);
    }

    /// Advance to `at`, running every timer on the way (queries are
    /// drained and dropped).
    fn runTo(r: *Rig, at: u64) !void {
        var buf: [9000]u8 = undefined;
        while (true) {
            const d = r.e.nextDeadline(r.now()) orelse break;
            if (d > at) break;
            r.sc.set(@max(d, r.now()));
            r.e.tick(r.now());
            _ = try r.sink.drain(&r.e);
            while (r.e.pollDatagram(&buf, r.now())) |_| {}
        }
        r.sc.set(@max(at, r.now()));
        r.e.tick(r.now());
        _ = try r.sink.drain(&r.e);
        while (r.e.pollDatagram(&buf, r.now())) |_| {}
    }

    fn lastResolved(r: *const Rig) mdns.Resolved {
        return r.sink.last(.resolved).?.resolved;
    }
};

fn expectAddrs(res: *const mdns.Resolved, expected: []const [4]u8) !void {
    try testing.expectEqual(expected.len, res.addrs.len);
    for (expected) |want| {
        var seen = false;
        for (res.addrs.slice()) |a| if (a == .ip4 and std.mem.eql(u8, &a.ip4.bytes, &want)) {
            seen = true;
        };
        try testing.expect(seen);
    }
}

// ---- cache model (plan section 4.5) -------------------------------------

test "reversed record order still resolves" {
    // hashicorp/mdns #145: A, TXT and SRV before the PTR, all in the
    // answer section.
    var r = try Rig.init(1);
    defer r.deinit();
    var buf: [1500]u8 = undefined;
    var p: Packet = .response(&buf);
    try p.a("host-a", .{ 10, 0, 3, 5 }, 120, true);
    try p.txt("alice", svc_type, &.{.{ .key = "k", .value = "v" }}, 4500, true);
    try p.srv("alice", svc_type, 4433, "host-a", 120, true);
    try p.ptr(svc_type, "alice", 4500);
    try r.rx(p.bytes());
    try r.sink.expectCount(.found, 1);
    try r.sink.expectCount(.resolved, 1);
    const res = r.lastResolved();
    try wire.name.expectText("alice._qmsg._udp.local", res.instance);
    try wire.name.expectText("_qmsg._udp.local", res.service_type);
    try wire.name.expectText("host-a.local", res.host);
    try testing.expectEqual(@as(u16, 4433), res.port);
    try expectAddrs(&res, &.{.{ 10, 0, 3, 5 }});
    try testing.expectEqualStrings("v", res.txt.get("k").?);
    // The found event precedes the resolved one.
    try testing.expect(r.sink.items()[0] == .found);
    try testing.expect(r.sink.items()[1] == .resolved);
}

test "three PTRs in one packet yield three found events" {
    // hashicorp/mdns #92.
    var r = try Rig.init(2);
    defer r.deinit();
    var buf: [1500]u8 = undefined;
    var p: Packet = .response(&buf);
    try p.ptr(svc_type, "alice", 4500);
    try p.ptr(svc_type, "bob", 4500);
    try p.ptr(svc_type, "carol", 4500);
    try r.rx(p.bytes());
    try r.sink.expectCount(.found, 3);
    var names: [3]bool = @splat(false);
    for (r.sink.items()) |ev| {
        const f = ev.found;
        try wire.name.expectText("_qmsg._udp.local", f.service_type);
        try testing.expectEqual(@as(u32, 3), f.ifindex);
        const first = f.instance.firstLabel().?;
        if (std.mem.eql(u8, first, "alice")) names[0] = true;
        if (std.mem.eql(u8, first, "bob")) names[1] = true;
        if (std.mem.eql(u8, first, "carol")) names[2] = true;
    }
    try testing.expect(names[0] and names[1] and names[2]);
    try testing.expectEqual(@as(usize, 3), r.e.cacheCount());
    // The same three again: a refresh, no new found.
    try r.rx(p.bytes());
    try r.sink.expectCount(.found, 3);
}

test "PTR for a foreign service type emits no found" {
    // hashicorp/mdns #96: cached, no event, and a later browse of that
    // type starts warm.
    var r = try Rig.init(3);
    defer r.deinit();
    var buf: [1500]u8 = undefined;
    try r.rx(try packets.fullInstance(&buf, "_printer._tcp", "lpr", "host-p", 515, .{ 10, 0, 3, 8 }));
    try r.sink.expectCount(.found, 0);
    try r.sink.expectCount(.resolved, 0);
    try testing.expectEqual(@as(usize, 4), r.e.cacheCount());
    // Browsing that type now: found at once from the cache, and the
    // resolve join runs on the cached SRV/TXT/A.
    const id = try r.e.browse("_printer._tcp", r.now());
    _ = try r.sink.drain(&r.e);
    try r.sink.expectCount(.found, 1);
    try wire.name.expectText("lpr._printer._tcp.local", r.sink.first(.found).?.found.instance);
    try r.sink.expectCount(.resolved, 1);
    try testing.expectEqual(@as(u16, 515), r.lastResolved().port);
    r.e.stopBrowse(id, r.now());
}

// ---- resolved re-emit rule (plan section 5) -----------------------------

test "resolved is emitted once when SRV, TXT and an address are present" {
    var r = try Rig.init(4);
    defer r.deinit();
    var buf: [1500]u8 = undefined;
    var p1: Packet = .response(&buf);
    try p1.ptr(svc_type, "alice", 4500);
    p1.in(.additional);
    try p1.srv("alice", svc_type, 4433, "host-a", 120, true);
    try r.rx(p1.bytes());
    try r.sink.expectCount(.found, 1);
    try r.sink.expectCount(.resolved, 0);
    var p2: Packet = .response(&buf);
    try p2.txt("alice", svc_type, &.{.{ .key = "txtvers", .value = "1" }}, 4500, true);
    try r.rx(p2.bytes());
    try r.sink.expectCount(.resolved, 0);
    var p3: Packet = .response(&buf);
    try p3.a("host-a", .{ 10, 0, 3, 5 }, 120, true);
    try r.rx(p3.bytes());
    try r.sink.expectCount(.resolved, 1);
    // All three again in one packet: no second resolved.
    try r.rx(try packets.fullInstance(&buf, svc_type, "alice", "host-a", 4433, .{ 10, 0, 3, 5 }));
    try r.sink.expectCount(.resolved, 1);
    try r.sink.expectCount(.found, 1);
}

test "resolved re-emitted on TXT change" {
    var r = try Rig.init(5);
    defer r.deinit();
    var buf: [1500]u8 = undefined;
    try r.rx(try packets.fullInstance(&buf, svc_type, "alice", "host-a", 4433, .{ 10, 0, 3, 5 }));
    try r.sink.expectCount(.resolved, 1);
    try testing.expectEqualStrings("1", r.lastResolved().txt.get("txtvers").?);
    r.sc.set(2 * s_us);
    var p: Packet = .response(&buf);
    try p.txt("alice", svc_type, &.{ .{ .key = "txtvers", .value = "1" }, .{ .key = "seq", .value = "7" } }, 4500, true);
    try r.rx(p.bytes());
    try r.sink.expectCount(.resolved, 2);
    try testing.expectEqualStrings("7", r.lastResolved().txt.get("seq").?);
    try testing.expectEqual(@as(u16, 4433), r.lastResolved().port);
}

test "resolved re-emitted on SRV port change" {
    var r = try Rig.init(6);
    defer r.deinit();
    var buf: [1500]u8 = undefined;
    try r.rx(try packets.fullInstance(&buf, svc_type, "alice", "host-a", 4433, .{ 10, 0, 3, 5 }));
    try r.sink.expectCount(.resolved, 1);
    r.sc.set(2 * s_us);
    var p: Packet = .response(&buf);
    try p.srv("alice", svc_type, 4434, "host-a", 120, true);
    try r.rx(p.bytes());
    try r.sink.expectCount(.resolved, 2);
    try testing.expectEqual(@as(u16, 4434), r.lastResolved().port);
    try expectAddrs(&r.lastResolved(), &.{.{ 10, 0, 3, 5 }});
}

test "resolved re-emitted when an address is added or expires" {
    var r = try Rig.init(7);
    defer r.deinit();
    var buf: [1500]u8 = undefined;
    var p: Packet = .response(&buf);
    try p.ptr(svc_type, "alice", 4500);
    p.in(.additional);
    try p.srv("alice", svc_type, 4433, "host-a", 4500, true);
    try p.txt("alice", svc_type, &.{}, 4500, true);
    try p.a("host-a", .{ 10, 0, 3, 5 }, 120, true);
    try r.rx(p.bytes());
    try r.sink.expectCount(.resolved, 1);
    // A second address (within the 1 s cache-flush grace: both kept).
    r.sc.set(500_000);
    var p2: Packet = .response(&buf);
    try p2.a("host-a", .{ 10, 0, 3, 6 }, 300, true);
    try r.rx(p2.bytes());
    try r.sink.expectCount(.resolved, 2);
    try expectAddrs(&r.lastResolved(), &.{ .{ 10, 0, 3, 5 }, .{ 10, 0, 3, 6 } });
    // The first address expires at 120 s (no refresh arrives): re-emit
    // with the second one only.
    try r.runTo(119 * s_us);
    try r.sink.expectCount(.resolved, 2);
    try r.runTo(120 * s_us);
    try r.sink.expectCount(.resolved, 3);
    try expectAddrs(&r.lastResolved(), &.{.{ 10, 0, 3, 6 }});
    try r.sink.expectCount(.lost, 0);
    // The last address expires at 300.5 s: nothing to resolve, no event;
    // the instance is still found (PTR 4500 s).
    try r.runTo(301 * s_us);
    try r.sink.expectCount(.resolved, 3);
    try r.sink.expectCount(.lost, 0);
    // It comes back: the set changed from {} to {.6}, but that is the
    // same set as last emitted, so no event ("same data").
    var p3: Packet = .response(&buf);
    try p3.a("host-a", .{ 10, 0, 3, 6 }, 300, true);
    try r.rx(p3.bytes());
    try r.sink.expectCount(.resolved, 3);
    // A different address: re-emit.
    var p4: Packet = .response(&buf);
    try p4.a("host-a", .{ 10, 0, 3, 7 }, 300, true);
    try r.rx(p4.bytes());
    try r.sink.expectCount(.resolved, 4);
    try expectAddrs(&r.lastResolved(), &.{ .{ 10, 0, 3, 6 }, .{ 10, 0, 3, 7 } });
}

test "same-data refresh does not re-emit resolved" {
    var r = try Rig.init(8);
    defer r.deinit();
    var buf: [1500]u8 = undefined;
    const bytes = try packets.fullInstance(&buf, svc_type, "alice", "host-a", 4433, .{ 10, 0, 3, 5 });
    try r.rx(bytes);
    try r.sink.expectCount(.resolved, 1);
    // Refreshes every 30 s for ten minutes: TTLs refresh, no event.
    var t: u64 = 30 * s_us;
    while (t <= 600 * s_us) : (t += 30 * s_us) {
        try r.runTo(t);
        try r.rx(bytes);
    }
    try r.sink.expectCount(.resolved, 1);
    try r.sink.expectCount(.found, 1);
    try r.sink.expectCount(.lost, 0);
    // Case-only change of the host label in the SRV target is a different
    // rdata on the wire and re-emits (names compare case-insensitively
    // for the cache key, rdata octet for octet, RFC 6762 section 8.2).
    var p: Packet = .response(&buf);
    try p.srv("alice", svc_type, 4433, "Host-A", 120, true);
    try r.rx(p.bytes());
    try r.sink.expectCount(.resolved, 2);
}

test "resolved ttl_s is the shortest RR TTL" {
    var r = try Rig.init(9);
    defer r.deinit();
    var buf: [1500]u8 = undefined;
    var p: Packet = .response(&buf);
    try p.ptr(svc_type, "alice", 4500);
    p.in(.additional);
    try p.srv("alice", svc_type, 4433, "host-a", 120, true);
    try p.txt("alice", svc_type, &.{}, 4500, true);
    try p.a("host-a", .{ 10, 0, 3, 5 }, 100, true);
    try r.rx(p.bytes());
    try r.sink.expectCount(.resolved, 1);
    try testing.expectEqual(@as(u32, 100), r.lastResolved().ttl_s);
    // 30 s later a TXT-only change: the A has 70 s left.
    r.sc.set(30 * s_us);
    var p2: Packet = .response(&buf);
    try p2.txt("alice", svc_type, &.{.{ .key = "seq", .value = "1" }}, 4500, true);
    try r.rx(p2.bytes());
    try r.sink.expectCount(.resolved, 2);
    try testing.expectEqual(@as(u32, 70), r.lastResolved().ttl_s);
    // The PTR's TTL never enters the value.
    try testing.expect(r.lastResolved().ttl_s < 4500);
}

test "stopBrowse stops queries and found/lost but keeps the cache" {
    var r = try Rig.init(10);
    defer r.deinit();
    var buf: [1500]u8 = undefined;
    try r.rx(try packets.fullInstance(&buf, svc_type, "alice", "host-a", 4433, .{ 10, 0, 3, 5 }));
    try r.sink.expectCount(.found, 1);
    try r.sink.expectCount(.resolved, 1);
    try r.runTo(5 * s_us);
    try testing.expect(r.e.stats().tx > 0);
    const tx_before = r.e.stats().tx;
    try testing.expectEqual(@as(usize, 4), r.e.cacheCount());

    r.e.stopBrowse(r.id, r.now());
    // No schedule left: nothing to send (cache expiry timers remain).
    try r.runTo(60 * s_us);
    try testing.expectEqual(tx_before, r.e.stats().tx);
    // The cache stays.
    try testing.expectEqual(@as(usize, 4), r.e.cacheCount());
    // A new instance of that type: cached, no found.
    try r.rx(try packets.fullInstance(&buf, svc_type, "bob", "host-b", 4434, .{ 10, 0, 3, 6 }));
    try r.sink.expectCount(.found, 1);
    try r.sink.expectCount(.resolved, 1);
    try testing.expectEqual(@as(usize, 8), r.e.cacheCount());
    // A goodbye for alice: no lost.
    var g: Packet = .response(&buf);
    try g.ptrGoodbye(svc_type, "alice");
    try r.rx(g.bytes());
    try r.runTo(62 * s_us);
    try r.sink.expectCount(.lost, 0);
    try testing.expectEqual(@as(usize, 7), r.e.cacheCount());
    // Browsing again starts warm: bob is found from the cache and
    // resolves from the cached records; the schedule restarts.
    const id2 = try r.e.browse(svc_type, r.now());
    _ = try r.sink.drain(&r.e);
    try r.sink.expectCount(.found, 2);
    try wire.name.expectText("bob._qmsg._udp.local", r.sink.last(.found).?.found.instance);
    try r.sink.expectCount(.resolved, 2);
    try testing.expectEqual(@as(u16, 4434), r.lastResolved().port);
    try testing.expect(r.e.nextDeadline(r.now()) != null);
    try r.runTo(63 * s_us);
    try testing.expect(r.e.stats().tx > tx_before);
    r.e.stopBrowse(id2, r.now());
}

// ---- over the fake LAN with a scripted responder -------------------------

const fake_responder = @import("harness/fake_responder.zig");
const FakeResponder = fake_responder.FakeResponder;
const Lan = fake_lan.FakeLan(2);

const lan_table = [_]fake_responder.InstanceSpec{
    .{ .instance = "demo", .service_type = svc_type, .host = "host-d", .port = 4433, .txt = &.{.{ .key = "spki", .value = "00" }}, .addrs4 = &.{.{ 10, 0, 3, 7 }} },
};

/// One or two engines on segment 0 (10.0.3.1/24 and 10.0.3.2/24, v4
/// only) and a scripted responder at 10.0.3.7 on the same segment.
const LanRig = struct {
    sc: Scenario,
    engines: [2]Engine,
    sinks: [2]Sink,
    lan: Lan,
    responder: FakeResponder,
    count: usize,

    fn init(seed: u64, count: usize, opts: fake_responder.Options) !*LanRig {
        const r = try testing.allocator.create(LanRig);
        errdefer testing.allocator.destroy(r);
        r.count = count;
        r.sc = .init(seed);
        r.lan = .init(testing.allocator);
        r.responder = .init(0, .{ 10, 0, 3, 7 }, 7, &lan_table, opts);
        var i: usize = 0;
        while (i < count) : (i += 1) {
            r.engines[i] = try Engine.init(testing.allocator, .{ .host_label = "lan", .random = r.sc.random() });
            r.sinks[i] = .init(testing.allocator);
            _ = try r.lan.addEngineOn(&r.engines[i], fake_lan.iface4(3, "en0", .{ 10, 0, 3, @intCast(i + 1) }, 24), 0, 0);
        }
        return r;
    }

    fn deinit(r: *LanRig) void {
        r.lan.deinit();
        var i: usize = 0;
        while (i < r.count) : (i += 1) {
            r.sinks[i].deinit();
            r.engines[i].deinit();
        }
        testing.allocator.destroy(r);
    }

    fn drainAll(ctx: *anyopaque, _: u64) anyerror!void {
        const r: *LanRig = @ptrCast(@alignCast(ctx));
        var i: usize = 0;
        while (i < r.count) : (i += 1) _ = try r.sinks[i].drain(&r.engines[i]);
    }

    /// Run the LAN and the responder from the current clock to `until`
    /// in 10 ms steps, draining events after every step.
    fn runTo(r: *LanRig, until: u64) !void {
        try fake_responder.run(&r.lan, &.{&r.responder}, r.sc.nowUs(), until, 10_000, .{ .ctx = r, .f = drainAll });
        r.sc.set(until);
    }
};

test "a scripted responder on the LAN resolves a browse and is suppressed by the known-answer list" {
    var r = try LanRig.init(21, 1, .{});
    defer r.deinit();
    _ = try r.engines[0].browse(svc_type, 0);
    // First query at 20-120 ms, answer 50 ms later: resolved well
    // inside the first second.
    try r.runTo(1 * s_us);
    try r.sinks[0].expectCount(.found, 1);
    try r.sinks[0].expectCount(.resolved, 1);
    const res = r.sinks[0].last(.resolved).?.resolved;
    try testing.expectEqual(@as(u16, 4433), res.port);
    try testing.expectEqualStrings("00", res.txt.get("spki").?);
    try testing.expectEqual(@as(usize, 1), res.addrs.len);
    try testing.expectEqual(@as(u64, 1), r.responder.stats.queries_seen);
    try testing.expectEqual(@as(u64, 1), r.responder.stats.responses_sent);
    // The 1 s query carries the PTR as a known answer (4500 s TTL, far
    // from half): the responder stays quiet (RFC 6762 section 7.1).
    try r.runTo(2 * s_us);
    try testing.expectEqual(@as(u64, 2), r.responder.stats.queries_seen);
    try testing.expectEqual(@as(u64, 1), r.responder.stats.responses_sent);
    try testing.expectEqual(@as(u64, 1), r.responder.stats.suppressed);
    try r.sinks[0].expectCount(.resolved, 1);
    // Our own queries came back as echoes (counted in rx, dropped as
    // echoes); the one response is the only real reception.
    try testing.expectEqual(@as(u64, 2), r.engines[0].stats().rx_echo);
    try testing.expectEqual(@as(u64, 3), r.engines[0].stats().rx);
}

test "requery marks over the LAN refresh the records without re-emitting resolved" {
    var r = try LanRig.init(22, 1, .{});
    defer r.deinit();
    _ = try r.engines[0].browse(svc_type, 0);
    try r.runTo(2 * s_us);
    try r.sinks[0].expectCount(.resolved, 1);
    const sent_before = r.responder.stats.responses_sent;
    // The SRV and A (120 s) reach their 80 % marks at 96-98.4 s; the
    // responder answers both questions, the data is unchanged.
    try r.runTo(100 * s_us);
    try testing.expect(r.responder.stats.responses_sent > sent_before);
    try r.sinks[0].expectCount(.resolved, 1);
    try r.sinks[0].expectCount(.lost, 0);
    // With refreshes every ~100 s nothing expires over ten minutes.
    try r.runTo(600 * s_us);
    try r.sinks[0].expectCount(.lost, 0);
    try r.sinks[0].expectCount(.resolved, 1);
}

test "a responder answering from an ephemeral port is ignored over the LAN" {
    var r = try LanRig.init(23, 1, .{ .source_port = 40_000 });
    defer r.deinit();
    _ = try r.engines[0].browse(svc_type, 0);
    try r.runTo(3 * s_us);
    try testing.expect(r.responder.stats.responses_sent >= 2);
    try r.sinks[0].expectCount(.found, 0);
    try testing.expectEqual(r.responder.stats.responses_sent, r.engines[0].stats().dropped_bad_port);
    try testing.expectEqual(@as(usize, 0), r.engines[0].cacheCount());
}

test "a responder replying by unicast is discarded outside the QU window over the LAN" {
    var r = try LanRig.init(24, 1, .{ .unicast_reply = true });
    defer r.deinit();
    _ = try r.engines[0].browse(svc_type, 0);
    try r.runTo(3 * s_us);
    try testing.expect(r.responder.stats.responses_sent >= 2);
    try r.sinks[0].expectCount(.found, 0);
    try testing.expectEqual(r.responder.stats.responses_sent, r.engines[0].stats().dropped_unicast_unexpected);
    try testing.expectEqual(@as(u64, 0), r.engines[0].stats().dropped_off_link);
}

test "a goodbye over the LAN emits lost one second later" {
    var r = try LanRig.init(25, 1, .{});
    defer r.deinit();
    _ = try r.engines[0].browse(svc_type, 0);
    try r.runTo(2 * s_us);
    try r.sinks[0].expectCount(.resolved, 1);
    try r.responder.goodbye(&r.lan, 0, r.sc.nowUs());
    _ = try r.sinks[0].drain(&r.engines[0]);
    try r.sinks[0].expectCount(.lost, 0);
    try r.runTo(2 * s_us + 990_000);
    try r.sinks[0].expectCount(.lost, 0);
    try r.runTo(3 * s_us + 10_000);
    try r.sinks[0].expectCount(.lost, 1);
    try wire.name.expectText("demo._qmsg._udp.local", r.sinks[0].last(.lost).?.lost.instance);
    try testing.expectEqual(@as(usize, 0), r.engines[0].cacheCount());
}

test "reversed answer-only records from a responder still resolve over the LAN" {
    var r = try LanRig.init(26, 1, .{ .order = .reversed, .additionals = false, .tc = true });
    defer r.deinit();
    _ = try r.engines[0].browse(svc_type, 0);
    try r.runTo(1 * s_us);
    try r.sinks[0].expectCount(.found, 1);
    try r.sinks[0].expectCount(.resolved, 1);
    try testing.expectEqual(@as(u16, 4433), r.sinks[0].last(.resolved).?.resolved.port);
}

test "two queriers on one segment both resolve and see each other's queries as foreign" {
    var r = try LanRig.init(27, 2, .{});
    defer r.deinit();
    _ = try r.engines[0].browse(svc_type, 0);
    _ = try r.engines[1].browse(svc_type, 0);
    try r.runTo(2 * s_us);
    for (0..2) |i| {
        try r.sinks[i].expectCount(.found, 1);
        try r.sinks[i].expectCount(.resolved, 1);
        try testing.expectEqual(@as(u16, 4433), r.sinks[i].last(.resolved).?.resolved.port);
        const st = r.engines[i].stats();
        // Own queries: echoes. The peer's queries and the responder's
        // answers: real receptions.
        try testing.expectEqual(@as(u64, 2), st.rx_echo);
        try testing.expect(st.rx >= 2 + 2 + 1);
        try testing.expectEqual(@as(u64, 0), st.dropped_malformed);
    }
    // The responder answered each first query once (the second engine's
    // first query has no known answers yet: the responses cross).
    try testing.expectEqual(@as(u64, 4), r.responder.stats.queries_seen);
    try testing.expect(r.responder.stats.responses_sent >= 1 and r.responder.stats.responses_sent <= 2);
}

// ---- requery marks are order-independent ----------------------------------

/// Questions of one type in every packet the engine sends until `until`.
fn countQuestions(r: *Rig, until: u64, rtype: wire.RType) !usize {
    var n: usize = 0;
    var buf: [9000]u8 = undefined;
    while (true) {
        const d = r.e.nextDeadline(r.now()) orelse break;
        if (d > until) break;
        r.sc.set(@max(d, r.now()));
        r.e.tick(r.now());
        _ = try r.sink.drain(&r.e);
        while (r.e.pollDatagram(&buf, r.now())) |dg| {
            const msg = try wire.Message.parse(buf[0..dg.len]);
            var qs = msg.questions();
            while (qs.next()) |q| if (q.qtype == rtype) {
                n += 1;
            };
        }
    }
    return n;
}

test "reversed record order still schedules requery marks" {
    // RFC 6762 section 5.2 cache maintenance must not depend on the
    // order records arrive in: the SRV/TXT/A before the PTR (hashicorp
    // #145) get their 80/85/90/95 % marks from the resolve join.
    var r = try Rig.init(31);
    defer r.deinit();
    var buf: [1500]u8 = undefined;
    var p: Packet = .response(&buf);
    try p.a("host-a", .{ 10, 0, 3, 5 }, 120, true);
    try p.txt("alice", svc_type, &.{.{ .key = "k", .value = "v" }}, 4500, true);
    try p.srv("alice", svc_type, 4433, "host-a", 120, true);
    try p.ptr(svc_type, "alice", 4500);
    try r.rx(p.bytes());
    try r.sink.expectCount(.resolved, 1);
    // The soonest mark is the 80 % mark of the 120 s SRV / A: 96-98.4 s.
    const mark = r.e.querier.cache.nextRequeryUs().?;
    try testing.expect(mark >= 96 * s_us and mark <= 98_400_000);
    // Run the ladder to 40 s (queries at 0.1, 1.1, ..., 31.1 s carry no
    // SRV / A question: the instance is resolved), then to 99 s: the SRV
    // and A marks went out, on both pairs.
    try testing.expectEqual(@as(usize, 0), try countQuestions(r, 40 * s_us, .srv));
    try testing.expectEqual(@as(usize, 0), try countQuestions(r, 95 * s_us, .a));
    try testing.expect(try countQuestions(r, 99 * s_us, .srv) >= 2);
    try r.sink.expectCount(.resolved, 1);
}

test "host records that arrive before the service still get requery marks" {
    // The common two-packet sequence: a host announces A/AAAA, then a
    // service names it in an SRV. Both ways round, the A gets its marks.
    var r = try Rig.init(32);
    defer r.deinit();
    var buf: [1500]u8 = undefined;
    var p1: Packet = .response(&buf);
    try p1.a("host-a", .{ 10, 0, 3, 5 }, 120, true);
    try r.rx(p1.bytes());
    try testing.expectEqual(@as(?u64, null), r.e.querier.cache.nextRequeryUs());
    var p2: Packet = .response(&buf);
    try p2.ptr(svc_type, "alice", 4500);
    p2.in(.additional);
    try p2.srv("alice", svc_type, 4433, "host-a", 4500, true);
    try p2.txt("alice", svc_type, &.{}, 4500, true);
    try r.rx(p2.bytes());
    try r.sink.expectCount(.resolved, 1);
    const mark = r.e.querier.cache.nextRequeryUs().?;
    try testing.expect(mark >= 96 * s_us and mark <= 98_400_000);
    try testing.expect(try countQuestions(r, 99 * s_us, .a) >= 2);
    try r.sink.expectCount(.resolved, 1);
}

test "resolved lists at most 8 addresses per family" {
    // Plan section 4.8 caps each family at 8: ten A records for the host
    // must not crowd out its AAAA.
    var r = try Rig.init(33);
    defer r.deinit();
    var buf: [1500]u8 = undefined;
    var p: Packet = .response(&buf);
    try p.ptr(svc_type, "alice", 4500);
    p.in(.additional);
    try p.srv("alice", svc_type, 4433, "host-a", 120, true);
    try p.txt("alice", svc_type, &.{}, 4500, true);
    var i: u8 = 0;
    while (i < 10) : (i += 1) try p.a("host-a", .{ 10, 0, 3, 100 + i }, 120, true);
    try p.aaaa("host-a", fake_lan.linkLocal6(0x0005), 120, true);
    try p.aaaa("host-a", fake_lan.linkLocal6(0x0006), 120, true);
    try r.rx(p.bytes());
    try r.sink.expectCount(.resolved, 1);
    const res = r.lastResolved();
    try testing.expectEqual(@as(usize, 10), res.addrs.len);
    var n4: usize = 0;
    var n6: usize = 0;
    for (res.addrs.slice()) |a| switch (a) {
        .ip4 => n4 += 1,
        .ip6 => n6 += 1,
    };
    try testing.expectEqual(@as(usize, 8), n4);
    try testing.expectEqual(@as(usize, 2), n6);
}

test "goodbye for SRV and PTR sends no follow-up queries" {
    // RFC 6762 section 10.1: a responder that says goodbye to an
    // instance's SRV (and PTR) is not asked for it again.
    var r = try Rig.init(34);
    defer r.deinit();
    var buf: [1500]u8 = undefined;
    try r.rx(try packets.fullInstance(&buf, svc_type, "alice", "host-a", 4433, .{ 10, 0, 3, 5 }));
    try r.sink.expectCount(.resolved, 1);
    try r.runTo(10 * s_us);
    // Goodbye for the SRV and the PTR in one packet.
    var g: Packet = .response(&buf);
    try g.srv("alice", svc_type, 4433, "host-a", 0, true);
    try g.ptrGoodbye(svc_type, "alice");
    try r.rx(g.bytes());
    const srv_q = try countQuestions(r, 12 * s_us, .srv);
    try testing.expectEqual(@as(usize, 0), srv_q);
    try r.sink.expectCount(.lost, 1);
    // SRV goodbye alone: no follow-ups either, until a live SRV returns.
    r.sink.clear();
    try r.rx(try packets.fullInstance(&buf, svc_type, "alice", "host-a", 4433, .{ 10, 0, 3, 5 }));
    try r.sink.expectCount(.found, 1);
    try r.sink.expectCount(.resolved, 1);
    try r.runTo(20 * s_us);
    var g2: Packet = .response(&buf);
    try g2.srv("alice", svc_type, 4433, "host-a", 0, true);
    try r.rx(g2.bytes());
    try testing.expectEqual(@as(usize, 0), try countQuestions(r, 30 * s_us, .srv));
    try r.sink.expectCount(.lost, 0);
    // The SRV comes back live: resolved again, marks armed, no ladder.
    var p: Packet = .response(&buf);
    try p.srv("alice", svc_type, 4434, "host-a", 120, true);
    try r.rx(p.bytes());
    try r.sink.expectCount(.resolved, 2);
    try testing.expectEqual(@as(u16, 4434), r.lastResolved().port);
}

// ---- multi-homed responder: one result per interface ---------------------

/// A querier with two interfaces on two segments, and one responder
/// present on both (a multi-homed host: same instance, same host name,
/// a different address on each link, RFC 6762 section 6.2). Segment 1's
/// copy answers 1.2 s late and known-answer suppression is off, so the
/// querier keeps receiving cache-flush answers from both interfaces more
/// than 1 s apart, which is exactly what made the merged cache cycle its
/// address set on the M3 gate (`resolved` re-emitted every second).
const multi_table_a = [_]fake_responder.InstanceSpec{
    .{ .instance = "demo", .service_type = svc_type, .host = "host-d", .port = 4433, .txt = &.{.{ .key = "spki", .value = "00" }}, .addrs4 = &.{.{ 10, 0, 3, 7 }} },
};
const multi_table_b = [_]fake_responder.InstanceSpec{
    .{ .instance = "demo", .service_type = svc_type, .host = "host-d", .port = 4433, .txt = &.{.{ .key = "spki", .value = "00" }}, .addrs4 = &.{.{ 10, 0, 4, 7 }} },
};

const MultiRig = struct {
    sc: Scenario,
    e: Engine,
    sink: Sink,
    lan: Lan,
    ra: FakeResponder,
    rb: FakeResponder,

    fn init(seed: u64) !*MultiRig {
        const r = try testing.allocator.create(MultiRig);
        errdefer testing.allocator.destroy(r);
        r.sc = .init(seed);
        r.lan = .init(testing.allocator);
        r.e = try Engine.init(testing.allocator, .{ .host_label = "mh", .random = r.sc.random() });
        r.sink = .init(testing.allocator);
        _ = try r.lan.addEngine(&r.e, &.{
            fake_lan.iface4(3, "en0", .{ 10, 0, 3, 1 }, 24),
            fake_lan.iface4(4, "en1", .{ 10, 0, 4, 1 }, 24),
        }, &.{ 0, 1 }, 0);
        r.ra = .init(0, .{ 10, 0, 3, 7 }, 7, &multi_table_a, .{ .known_answer_suppression = false });
        r.rb = .init(1, .{ 10, 0, 4, 7 }, 8, &multi_table_b, .{ .known_answer_suppression = false, .delay_us = 1_200_000 });
        return r;
    }

    fn deinit(r: *MultiRig) void {
        r.lan.deinit();
        r.sink.deinit();
        r.e.deinit();
        testing.allocator.destroy(r);
    }

    fn drain(ctx: *anyopaque, _: u64) anyerror!void {
        const r: *MultiRig = @ptrCast(@alignCast(ctx));
        _ = try r.sink.drain(&r.e);
    }

    fn runTo(r: *MultiRig, until: u64) !void {
        try fake_responder.run(&r.lan, &.{ &r.ra, &r.rb }, r.sc.nowUs(), until, 10_000, .{ .ctx = r, .f = drain });
        r.sc.set(until);
    }

    /// The `resolved` for `ifindex`, or null.
    fn resolvedOn(r: *const MultiRig, ifindex: u32) ?mdns.Resolved {
        var found: ?mdns.Resolved = null;
        for (r.sink.items()) |ev| switch (ev) {
            .resolved => |res| if (res.ifindex == ifindex) {
                found = res;
            },
            else => {},
        };
        return found;
    }

    fn countOn(r: *const MultiRig, tag: scenario.EventTag, ifindex: u32) usize {
        var n: usize = 0;
        for (r.sink.items()) |ev| {
            if (std.meta.activeTag(ev) != tag) continue;
            const i = switch (ev) {
                .found => |f| f.ifindex,
                .lost => |l| l.ifindex,
                .resolved => |res| res.ifindex,
                else => continue,
            };
            if (i == ifindex) n += 1;
        }
        return n;
    }
};

test "multi-homed responder yields one stable resolved per interface" {
    // RFC 6762 sections 6.2 and 14: each interface's answer is its own
    // RRSet with cache-flush set; the querier keeps them apart and
    // reports one `found` and one `resolved` per interface, each with
    // only that interface's address, and never re-emits while nothing
    // changes. Before the fix this rig produced found=1 and resolved=7
    // over 10 s, cycling {3.7}, {4.7, 3.7}, {4.7}, ... as each
    // interface's cache-flush answer flushed the other's address.
    var r = try MultiRig.init(51);
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    try r.runTo(10 * s_us);
    try r.sink.expectCount(.found, 2);
    try r.sink.expectCount(.resolved, 2);
    try r.sink.expectCount(.lost, 0);
    try testing.expectEqual(@as(usize, 1), r.countOn(.found, 3));
    try testing.expectEqual(@as(usize, 1), r.countOn(.found, 4));
    const on3 = r.resolvedOn(3).?;
    const on4 = r.resolvedOn(4).?;
    try testing.expectEqual(@as(usize, 1), on3.addrs.len);
    try testing.expectEqual(@as(usize, 1), on4.addrs.len);
    try testing.expectEqual([4]u8{ 10, 0, 3, 7 }, on3.addrs.slice()[0].ip4.bytes);
    try testing.expectEqual([4]u8{ 10, 0, 4, 7 }, on4.addrs.slice()[0].ip4.bytes);
    try testing.expectEqual(@as(u16, 4433), on3.port);
    try testing.expectEqual(@as(u16, 4433), on4.port);
    try wire.name.expectText("host-d.local", on3.host);
    try wire.name.expectText("host-d.local", on4.host);
    // Both responders kept answering (no known-answer suppression) and
    // none of those refreshes re-emitted.
    try testing.expect(r.ra.stats.responses_sent >= 3);
    try testing.expect(r.rb.stats.responses_sent >= 3);
    try r.runTo(20 * s_us);
    try r.sink.expectCount(.resolved, 2);
    try r.sink.expectCount(.found, 2);
    try r.sink.expectCount(.lost, 0);
    // Two copies of each of the four records (PTR, SRV, TXT, A): one
    // per interface.
    try testing.expectEqual(@as(usize, 8), r.e.cacheCount());
}

test "lost fires per interface" {
    // A goodbye is heard on the interface where the responder withdraws
    // (RFC 6762 section 10.1); it removes that interface's copy only, so
    // `lost` carries that interface and the other interface's instance
    // is untouched (no new `found` / `resolved`, no `lost`). Before the
    // fix the merged PTR was gone after the first goodbye and the second
    // interface never reported a loss.
    var r = try MultiRig.init(52);
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    try r.runTo(3 * s_us);
    try r.sink.expectCount(.resolved, 2);
    const events_before = r.sink.items().len;

    try r.rb.goodbye(&r.lan, 0, r.sc.nowUs());
    try r.runTo(5 * s_us);
    try r.sink.expectCount(.lost, 1);
    try testing.expectEqual(@as(u32, 4), r.sink.last(.lost).?.lost.ifindex);
    try wire.name.expectText("demo._qmsg._udp.local", r.sink.last(.lost).?.lost.instance);
    try testing.expectEqual(@as(usize, 1), r.countOn(.lost, 4));
    try testing.expectEqual(@as(usize, 0), r.countOn(.lost, 3));
    // Nothing else moved: the interface-3 instance is still resolved
    // with its own address and emitted nothing new.
    try testing.expectEqual(events_before + 1, r.sink.items().len);
    try r.sink.expectCount(.resolved, 2);
    try r.sink.expectCount(.found, 2);
    // Only interface 3's four records remain (the goodbye put interface
    // 4's copies into their 1 s grace, now over).
    try testing.expectEqual(@as(usize, 4), r.e.cacheCount());

    try r.ra.goodbye(&r.lan, 0, r.sc.nowUs());
    try r.runTo(7 * s_us);
    try r.sink.expectCount(.lost, 2);
    try testing.expectEqual(@as(u32, 3), r.sink.last(.lost).?.lost.ifindex);
    try testing.expectEqual(@as(usize, 1), r.countOn(.lost, 3));
    try testing.expectEqual(@as(usize, 0), r.e.cacheCount());
    try r.sink.expectCount(.resolved, 2);
}

test "interface removal drops its cached records and emits lost" {
    // An interface that leaves the table takes its cache scope with it
    // (the per-interface key means nothing could refresh those records:
    // no answer arrives with that ifindex again, and the surviving
    // interface's answers land in their own key). The Engine drops them
    // through the expiry path at `setInterfaces`: one `lost` for the
    // removed interface's instance, right after `interfaces_changed`,
    // the other interface's four records untouched, and nothing more for
    // 10 s (no late `lost` when the orphan PTR would have expired, no
    // requery marks for it).
    var r = try MultiRig.init(54);
    defer r.deinit();
    _ = try r.e.browse(svc_type, 0);
    try r.runTo(3 * s_us);
    try r.sink.expectCount(.resolved, 2);
    try testing.expectEqual(@as(usize, 8), r.e.cacheCount());
    const events_before = r.sink.items().len;

    try r.lan.setInterfaces(0, &.{fake_lan.iface4(3, "en0", .{ 10, 0, 3, 1 }, 24)}, &.{0}, r.sc.nowUs());
    _ = try r.sink.drain(&r.e);
    try testing.expectEqual(events_before + 2, r.sink.items().len);
    try testing.expectEqual(mdns.Event.interfaces_changed, r.sink.items()[events_before]);
    try r.sink.expectCount(.lost, 1);
    try testing.expectEqual(@as(u32, 4), r.sink.last(.lost).?.lost.ifindex);
    try wire.name.expectText("demo._qmsg._udp.local", r.sink.last(.lost).?.lost.instance);
    try testing.expectEqual(@as(usize, 4), r.e.cacheCount());
    try testing.expectEqual(@as(usize, 1), r.e.querier.instanceCount());

    try r.runTo(13 * s_us);
    try testing.expectEqual(events_before + 2, r.sink.items().len);
    try r.sink.expectCount(.lost, 1);
    try r.sink.expectCount(.resolved, 2);
    try testing.expectEqual(@as(usize, 4), r.e.cacheCount());
    try testing.expectEqual(@as(u32, 3), r.resolvedOn(3).?.ifindex);
    // Nothing went out on interface 4 after the removal.
    for (r.lan.sentLog()) |sent| {
        if (sent.now_us > 3 * s_us) try testing.expectEqual(@as(u32, 3), sent.ifindex);
    }
}

test "follow-ups for an instance found on one interface stay on that interface" {
    // A PTR-only answer heard on interface 3 makes the instance need
    // SRV / TXT follow-ups; they are scoped to interface 3 (RFC 6762
    // section 14: the instance was found there), so the packets on
    // interface 4 carry only the browse's PTR question, and the
    // follow-up budget does not multiply with the interface count.
    var sc: Scenario = .init(55);
    var e = try Engine.init(testing.allocator, .{ .host_label = "fu", .random = sc.random() });
    defer e.deinit();
    var sink: Sink = .init(testing.allocator);
    defer sink.deinit();
    var lan: Lan = .init(testing.allocator);
    defer lan.deinit();
    _ = try lan.addEngine(&e, &.{
        fake_lan.iface4(3, "en0", .{ 10, 0, 3, 1 }, 24),
        fake_lan.iface4(4, "en1", .{ 10, 0, 4, 1 }, 24),
    }, &.{ 0, 1 }, 0);
    _ = try e.browse(svc_type, 0);
    var buf: [1500]u8 = undefined;
    var p: Packet = .response(&buf);
    try p.ptr(svc_type, "alice", 4500);
    _ = try lan.injectForeign(0, p.bytes(), .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 9 }, .port = 5353 } }, true, 0);
    _ = try sink.drain(&e);
    try sink.expectCount(.found, 1);
    try testing.expectEqual(@as(u32, 3), sink.last(.found).?.found.ifindex);

    try lan.runToDeadlines(0, 30 * s_us, 250_000);
    var ptr_on: [2]usize = .{ 0, 0 };
    var followups_on: [2]usize = .{ 0, 0 };
    for (lan.sentLog()) |sent| {
        if (sent.kind != .query) continue;
        const slot: usize = switch (sent.ifindex) {
            3 => 0,
            4 => 1,
            else => return error.UnexpectedInterface,
        };
        const msg = try wire.Message.parse(sent.bytes);
        var qs = msg.questions();
        while (qs.next()) |q| switch (q.qtype) {
            .ptr => ptr_on[slot] += 1,
            .srv, .txt => followups_on[slot] += 1,
            else => return error.UnexpectedQuestion,
        };
    }
    try testing.expect(ptr_on[0] >= 5 and ptr_on[1] >= 5); // the browse ladder on both
    try testing.expect(followups_on[0] >= 2 * 5); // SRV and TXT, ladder on interface 3
    try testing.expectEqual(@as(usize, 0), followups_on[1]);
}

test "bridged segments report the same responder once per interface" {
    // Two interfaces of one querier on ONE segment (a bridge, plan
    // section 4.8 "Bridged echo"): the responder's one answer arrives on
    // both interfaces and the querier reports it twice, with identical
    // addresses, exactly as `dns-sd -B` lists a row per interfaceIndex.
    // Duplicates are the correct per-interface result, not a merge.
    var sc: Scenario = .init(53);
    var e = try Engine.init(testing.allocator, .{ .host_label = "br", .random = sc.random() });
    defer e.deinit();
    var sink: Sink = .init(testing.allocator);
    defer sink.deinit();
    var lan: Lan = .init(testing.allocator);
    defer lan.deinit();
    _ = try lan.addEngine(&e, &.{
        fake_lan.iface4(3, "en0", .{ 10, 0, 3, 1 }, 24),
        fake_lan.iface4(4, "en1", .{ 10, 0, 3, 2 }, 24),
    }, &.{ 0, 0 }, 0);
    var responder: FakeResponder = .init(0, .{ 10, 0, 3, 7 }, 7, &multi_table_a, .{});
    _ = try e.browse(svc_type, 0);
    const Ctx = struct {
        e: *Engine,
        sink: *Sink,
        fn drain(ctx: *anyopaque, _: u64) anyerror!void {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            _ = try c.sink.drain(c.e);
        }
    };
    var ctx: Ctx = .{ .e = &e, .sink = &sink };
    try fake_responder.run(&lan, &.{&responder}, 0, 5 * s_us, 10_000, .{ .ctx = &ctx, .f = Ctx.drain });
    try sink.expectCount(.found, 2);
    try sink.expectCount(.resolved, 2);
    var seen3 = false;
    var seen4 = false;
    for (sink.items()) |ev| switch (ev) {
        .resolved => |res| {
            try testing.expectEqual(@as(usize, 1), res.addrs.len);
            try testing.expectEqual([4]u8{ 10, 0, 3, 7 }, res.addrs.slice()[0].ip4.bytes);
            if (res.ifindex == 3) seen3 = true;
            if (res.ifindex == 4) seen4 = true;
        },
        else => {},
    };
    try testing.expect(seen3 and seen4);
}
