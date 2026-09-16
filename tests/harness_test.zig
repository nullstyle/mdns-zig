//! Smoke tests for the deterministic harness (tests/harness/*): two
//! engines on one virtual segment, each browsing one type. They exercise
//! only the plan section 5 `Engine` surface. Packet counts follow the RFC
//! 6762 section 5.2 ladder: first query 20-120 ms after `browse`, then
//! 1 s, 2 s, 4 s, ... (+0-2 %) later, per joined (interface, family).
const std = @import("std");
const testing = std.testing;
const mdns = @import("mdns");
const scenario = @import("harness/scenario.zig");
const fake_lan = @import("harness/fake_lan.zig");

const Scenario = scenario.Scenario;
const Sink = scenario.Sink;
const Lan = fake_lan.FakeLan(3);
const Engine = mdns.Engine;

const s_us = scenario.us_per_s;
const browse_type = "_harness._udp";

fn newEngine(sc: *Scenario, label: []const u8) !Engine {
    return Engine.init(testing.allocator, .{ .host_label = label, .random = sc.random(), .limits = .{ .max_events = 16 } });
}

/// Unjittered ladder: queries at t0, t0+1 s, t0+3 s, t0+7 s, ... with
/// t0 <= 120 ms; the jitter adds at most 2 % per step.
fn ladderCountWithin(duration_us: u64) usize {
    var n: usize = 0;
    while (mdns.core.querier.ladderOffsetUs(@intCast(n)) < duration_us) n += 1;
    return n;
}

test "harness: two engines on one segment see each other's queries and their own echo" {
    var sc: Scenario = .init(0x5eed);
    var a = try newEngine(&sc, "a");
    defer a.deinit();
    var b = try newEngine(&sc, "b");
    defer b.deinit();

    var lan: Lan = .init(testing.allocator);
    defer lan.deinit();
    const ia = fake_lan.ifaceDual(3, "en0", .{ 10, 0, 0, 1 }, 24, 0x0001);
    const ib = fake_lan.ifaceDual(7, "eth0", .{ 10, 0, 0, 2 }, 24, 0x0002);
    const A = try lan.addEngineOn(&a, ia, 0, sc.nowUs());
    const B = try lan.addEngineOn(&b, ib, 0, sc.nowUs());
    try testing.expectEqual(@as(usize, 0), A);
    try testing.expectEqual(@as(usize, 1), B);

    // Both engines got the table.
    var sink_a: Sink = .init(testing.allocator);
    defer sink_a.deinit();
    try testing.expectEqual(@as(usize, 1), try sink_a.drain(&a));
    try sink_a.expectCount(.interfaces_changed, 1);
    _ = try a.browse(browse_type, sc.nowUs());
    _ = try b.browse(browse_type, sc.nowUs());

    // 4 s in 100 ms steps: the ladder fires at ~0.1 s, ~1.1 s and ~3.1 s
    // (the fourth query, ~7 s, is outside the window).
    try sc.runFor(&lan, 4 * s_us, 100_000);
    try testing.expectEqual(4 * s_us, sc.nowUs());
    try testing.expectEqual(@as(usize, 3), ladderCountWithin(4 * s_us - 120_000));

    const log = lan.sentLog();
    // 3 firings x 2 families x 2 engines.
    try testing.expectEqual(@as(usize, 12), log.len);
    for (log) |*p| {
        try testing.expectEqual(fake_lan.PacketKind.query, p.kind);
        try testing.expect(p.isMulticast());
        try testing.expectEqual(@as(u16, 2), p.delivered); // peer + echo
        try testing.expectEqual(@as(u16, 0), p.lost);
        try testing.expectEqual(@as(usize, 0), lan.harness_stats.tx_unknown_iface);
    }
    // The packet log: per engine per family, one query in [0, 1 s), one
    // in [1 s, 2 s) and one in [3 s, 4 s]; never two inside 900 ms.
    inline for (.{ A, B }) |eng| {
        inline for (.{ mdns.Family.v4, mdns.Family.v6 }) |fam| {
            try testing.expectEqual(@as(usize, 1), scenario.countSent(log, .{ .from_engine = eng, .family = fam, .from_us = 0, .to_us = 1 * s_us }));
            try testing.expectEqual(@as(usize, 1), scenario.countSent(log, .{ .from_engine = eng, .family = fam, .from_us = 1 * s_us, .to_us = 2 * s_us }));
            try testing.expectEqual(@as(usize, 0), scenario.countSent(log, .{ .from_engine = eng, .family = fam, .from_us = 2 * s_us, .to_us = 3 * s_us }));
            try scenario.expectBudget(log, .{ .from_engine = eng, .family = fam, .kind = .query }, 3);
            try testing.expectEqual(@as(usize, 1), scenario.maxInWindow(log, .{ .from_engine = eng, .family = fam }, 900_000));
        }
    }
    try testing.expectEqual(@as(usize, 3), scenario.countSent(log, .{ .from_engine = A, .ifindex = 3, .family = .v4 }));
    try testing.expectEqual(@as(usize, 3), scenario.countSent(log, .{ .from_engine = B, .ifindex = 7, .family = .v6 }));

    // Every delivery: A's queries reach B on ifindex 7 with dst_multicast
    // and from = A's own address; A's echo comes back on ifindex 3 with
    // the same source. And symmetrically.
    const dl = lan.deliveryLog();
    try testing.expectEqual(@as(usize, 24), dl.len);
    try testing.expectEqual(@as(usize, 6), lan.countDeliveries(B, false)); // from A
    try testing.expectEqual(@as(usize, 6), lan.countDeliveries(B, true)); // own echo
    try testing.expectEqual(@as(usize, 6), lan.countDeliveries(A, false));
    try testing.expectEqual(@as(usize, 6), lan.countDeliveries(A, true));
    for (dl) |d| {
        try testing.expect(d.meta.dst_multicast);
        try testing.expect(!d.bridged);
        const sent = log[d.sent.?];
        try testing.expectEqual(sent.from_engine, d.from_engine.?);
        try testing.expectEqual(d.echo, sent.from_engine == d.to_engine);
        const expect_ifindex: u32 = if (d.to_engine == A) 3 else 7;
        try testing.expectEqual(expect_ifindex, d.meta.ifindex);
        const sender_v4: [4]u8 = if (sent.from_engine == A) .{ 10, 0, 0, 1 } else .{ 10, 0, 0, 2 };
        const sender_ll: [16]u8 = fake_lan.linkLocal6(if (sent.from_engine == A) 0x0001 else 0x0002);
        switch (d.meta.from) {
            .ip4 => |v| {
                try testing.expectEqual(mdns.Family.v4, sent.family);
                try testing.expectEqual(sender_v4, v.bytes);
                try testing.expectEqual(@as(u16, 5353), v.port);
            },
            .ip6 => |v| {
                try testing.expectEqual(mdns.Family.v6, sent.family);
                try testing.expectEqual(sender_ll, v.bytes);
                try testing.expectEqual(@as(u16, 5353), v.port);
                // Link-local source scoped to the *receiver's* interface.
                try testing.expectEqual(expect_ifindex, v.interface.index);
            },
        }
    }
    // The engines counted every delivery as a received datagram.
    try testing.expectEqual(@as(u64, 12), a.stats().rx);
    try testing.expectEqual(@as(u64, 12), b.stats().rx);
    try testing.expectEqual(@as(u64, 6), a.stats().tx);
    try testing.expectEqual(@as(u64, 0), a.stats().dropped_malformed);
    try testing.expectEqual(@as(u64, 0), a.stats().dropped_bad_port);
}

test "harness: loss 1.0 delivers nothing across the link but keeps the loopback echo" {
    var sc: Scenario = .init(2);
    var a = try newEngine(&sc, "a");
    defer a.deinit();
    var b = try newEngine(&sc, "b");
    defer b.deinit();
    var lan: Lan = .init(testing.allocator);
    defer lan.deinit();
    const A = try lan.addEngineOn(&a, fake_lan.iface4(3, "en0", .{ 10, 0, 0, 1 }, 24), 0, 0);
    const B = try lan.addEngineOn(&b, fake_lan.iface4(7, "eth0", .{ 10, 0, 0, 2 }, 24), 0, 0);
    lan.setLoss(0, 1.0, sc.random());
    _ = try a.browse(browse_type, 0);
    _ = try b.browse(browse_type, 0);

    // Ladder in 2 s: ~0.1 s and ~1.1 s (the third is ~3.1 s).
    try sc.runFor(&lan, 2 * s_us, 250_000);
    const log = lan.sentLog();
    try testing.expectEqual(@as(usize, 4), log.len); // 2 firings x 2 engines (v4 only)
    for (log) |*p| {
        try testing.expectEqual(@as(u16, 1), p.delivered); // echo only
        try testing.expectEqual(@as(u16, 1), p.lost);
    }
    try testing.expectEqual(@as(usize, 0), lan.countDeliveries(A, false));
    try testing.expectEqual(@as(usize, 0), lan.countDeliveries(B, false));
    try testing.expectEqual(@as(usize, 2), lan.countDeliveries(A, true));
    try testing.expectEqual(@as(usize, 2), lan.countDeliveries(B, true));
    try testing.expectEqual(@as(u64, 2), a.stats().rx);

    // Loss 0 again: everything flows (the ~3.1 s query).
    lan.setLoss(0, 0.0, sc.random());
    lan.clearLog();
    try sc.runFor(&lan, 2 * s_us, 250_000);
    try testing.expectEqual(@as(usize, 1), lan.countDeliveries(B, false));
    try testing.expectEqual(@as(usize, 1), lan.countDeliveries(A, false));
}

test "harness: partial loss is seeded and reproducible" {
    var counts: [2]usize = undefined;
    for (&counts) |*out| {
        var sc: Scenario = .init(77);
        var a = try newEngine(&sc, "a");
        defer a.deinit();
        var b = try newEngine(&sc, "b");
        defer b.deinit();
        var lan: Lan = .init(testing.allocator);
        defer lan.deinit();
        _ = try lan.addEngineOn(&a, fake_lan.iface4(3, "en0", .{ 10, 0, 0, 1 }, 24), 0, 0);
        const B = try lan.addEngineOn(&b, fake_lan.iface4(7, "eth0", .{ 10, 0, 0, 2 }, 24), 0, 0);
        lan.setLoss(0, 0.5, sc.random());
        _ = try a.browse(browse_type, 0);
        _ = try b.browse(browse_type, 0);
        try sc.runForByDeadlines(&lan, 2000 * s_us, 10 * s_us);
        // The ladder fires 11 times in 2000 s (0, 1, 3, ..., 1023 s
        // after the first delay; 2047 s is outside); some reached B.
        try testing.expectEqual(@as(usize, 11), ladderCountWithin(2000 * s_us - 120_000));
        try testing.expectEqual(@as(usize, 11), scenario.countSent(lan.sentLog(), .{ .from_engine = 0 }));
        out.* = lan.countDeliveries(B, false);
        try testing.expect(out.* > 0 and out.* < 11);
    }
    try testing.expectEqual(counts[0], counts[1]);
}

test "harness: a bridged pair delivers the echo on the second interface" {
    var sc: Scenario = .init(3);
    var a = try newEngine(&sc, "a");
    defer a.deinit();
    var b = try newEngine(&sc, "b");
    defer b.deinit();
    var lan: Lan = .init(testing.allocator);
    defer lan.deinit();
    // A is multi-homed: ifindex 3 on segment 0, ifindex 5 on segment 1.
    // B sits on segment 1 only.
    const A = try lan.addEngine(&a, &.{
        fake_lan.iface4(3, "en0", .{ 10, 0, 0, 1 }, 24),
        fake_lan.iface4(5, "en1", .{ 10, 0, 1, 1 }, 24),
    }, &.{ 0, 1 }, 0);
    const B = try lan.addEngineOn(&b, fake_lan.iface4(7, "eth0", .{ 10, 0, 1, 2 }, 24), 1, 0);
    _ = try a.browse(browse_type, 0);
    _ = try b.browse(browse_type, 0);

    // Not bridged: A's ifindex-3 query stays on segment 0 (echo only).
    // The first queries are due within 120 ms.
    lan.tickAll(120_000);
    try lan.pump(120_000);
    {
        const log = lan.sentLog();
        try testing.expectEqual(@as(usize, 3), log.len); // one per A interface, one from B
        const q3 = log[0];
        try testing.expectEqual(@as(u32, 3), q3.ifindex);
        try testing.expectEqual(@as(u16, 1), q3.delivered); // echo only
        const q5 = log[1];
        try testing.expectEqual(@as(u32, 5), q5.ifindex);
        try testing.expectEqual(@as(u16, 2), q5.delivered); // echo + B
        const q7 = log[2];
        try testing.expectEqual(B, q7.from_engine);
        try testing.expectEqual(@as(u16, 2), q7.delivered); // echo + A's ifindex 5
        for (lan.deliveryLog()) |d| try testing.expect(!d.bridged);
    }

    // Bridged: the ifindex-3 query also arrives on A's ifindex 5 (from =
    // A's own 10.0.0.1, a foreign-looking interface) and at B.
    try lan.bridge(0, 1);
    lan.clearLog();
    // The second query of each ladder is due 1 s (+0-2 %) after the
    // first was sent (120 ms): by 1.3 s it has fired.
    lan.tickAll(1_300_000);
    try lan.pump(1_300_000);
    const log = lan.sentLog();
    try testing.expectEqual(@as(usize, 3), log.len);
    try testing.expectEqual(@as(u16, 3), log[0].delivered); // echo(3) + bridged echo(5) + B
    try testing.expectEqual(@as(u16, 3), log[1].delivered); // echo(5) + bridged echo(3) + B
    try testing.expectEqual(@as(u16, 3), log[2].delivered); // B's echo + A's 3 and 5
    var bridged_seen: usize = 0;
    for (lan.deliveryLog()) |d| {
        if (!d.bridged) continue;
        bridged_seen += 1;
        try testing.expectEqual(A, d.to_engine);
        try testing.expect(d.echo);
        try testing.expect(d.meta.dst_multicast);
        const sent = log[d.sent.?];
        try testing.expect(d.meta.ifindex != sent.ifindex);
        const expect_from: [4]u8 = if (sent.ifindex == 3) .{ 10, 0, 0, 1 } else .{ 10, 0, 1, 1 };
        try testing.expectEqual(expect_from, d.meta.from.ip4.bytes);
    }
    try testing.expectEqual(@as(usize, 2), bridged_seen);
    try testing.expectEqual(@as(usize, 2), lan.countDeliveries(B, false));
    try testing.expectEqual(@as(usize, 4), lan.countDeliveries(A, true));
    try testing.expectEqual(@as(usize, 2), lan.countDeliveries(A, false)); // B's query on 3 and 5
}

test "harness: injectForeign reaches every interface on the segment with the receiver's scope" {
    var sc: Scenario = .init(4);
    var a = try newEngine(&sc, "a");
    defer a.deinit();
    var lan: Lan = .init(testing.allocator);
    defer lan.deinit();
    const A = try lan.addEngineOn(&a, fake_lan.ifaceDual(3, "en0", .{ 10, 0, 0, 1 }, 24, 1), 0, 0);

    var query: [12]u8 = @splat(0);
    const from6: std.Io.net.IpAddress = .{ .ip6 = .{ .bytes = fake_lan.linkLocal6(0xbeef), .port = 5353 } };
    try testing.expectEqual(@as(usize, 1), try lan.injectForeign(0, &query, from6, true, 0));
    // Segment 1 is not connected: nobody hears it.
    try testing.expectEqual(@as(usize, 0), try lan.injectForeign(1, &query, from6, true, 0));
    const d = lan.deliveryLog()[0];
    try testing.expectEqual(A, d.to_engine);
    try testing.expectEqual(null, d.sent);
    try testing.expect(!d.echo);
    try testing.expectEqual(@as(u32, 3), d.meta.ifindex);
    try testing.expectEqual(@as(u32, 3), d.meta.from.ip6.interface.index);
    try testing.expectEqual(@as(u64, 1), a.stats().rx);

    // injectTo hands over the caller's RxMeta untouched.
    var resp: [12]u8 = @splat(0);
    resp[2] = 0x84;
    try lan.injectTo(A, &resp, .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 9 }, .port = 40000 } }, .ifindex = 3, .dst_multicast = false }, 5);
    try testing.expectEqual(@as(u64, 1), a.stats().dropped_bad_port);
    try testing.expectEqual(@as(usize, 2), lan.deliveryLog().len);
}
