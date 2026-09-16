//! Public-API tests for `mdns.Service`, `mdns.Engine` and `mdns.Mailbox`
//! (plan section 7, M2). Real sockets: a bind that the sandbox refuses
//! (`PermissionDenied`) or that a non-reuse holder owns (`AddressInUse`)
//! skips the test instead of failing it.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const mdns = @import("mdns");

const Service = mdns.Service;
const Event = mdns.Event;

fn initOrSkip(opts: Service.Options) !Service {
    return Service.init(testing.allocator, testing.io, opts) catch |err| switch (err) {
        error.PermissionDenied, error.AddressInUse => return error.SkipZigTest,
        else => return err,
    };
}

test "Service.init binds 5353 beside the OS daemon" {
    var svc = initOrSkip(.{ .host_label = "api", .include_loopback = true }) catch |err| switch (err) {
        // A host with no multicast-capable interface at all.
        error.NoMulticastInterface => return error.SkipZigTest,
        else => return err,
    };
    defer svc.deinit();

    // Both sockets sit on *:5353 whether or not mDNSResponder / avahi
    // holds the port (SO_REUSEADDR + SO_REUSEPORT); `firstBinder` tells
    // which case this is.
    try testing.expect(svc.sockets().len >= 1);
    for (svc.sockets()) |sock| {
        const port: u16 = switch (sock.address) {
            .ip4 => |a| a.port,
            .ip6 => |a| a.port,
        };
        try testing.expectEqual(@as(u16, 5353), port);
    }
    try testing.expect(svc.joinedCount() >= 1);
    try testing.expect(svc.interfaces().len >= 1);

    // init hands the table to the Engine: interfaces_changed is queued.
    var evs: [16]Event = undefined;
    var saw_changed = false;
    while (true) {
        const n = svc.poll(&evs);
        if (n == 0) break;
        for (evs[0..n]) |ev| if (ev == .interfaces_changed) {
            saw_changed = true;
        };
    }
    try testing.expect(saw_changed);

    // Mode B: a bounded step never fails on an idle socket. Nothing is
    // sent without a browse; with one, the first query (20-120 ms after
    // `browse`) goes out on every joined pair within a few steps.
    try svc.step(.fromMilliseconds(20));
    try testing.expectEqual(@as(u64, 0), svc.stats().tx);
    // No query is scheduled without a browse. A record from real LAN
    // traffic may already sit in the cache (foreign types are cached
    // silently), whose expiry deadline is at least the 1 s goodbye grace
    // away; a browse deadline is at most 120 ms away.
    if (svc.nextDeadline(svc.nowUs())) |d| try testing.expect(d >= svc.nowUs() + std.time.us_per_s);
    _ = try svc.browse("_mdns-zig-test._udp");
    const first = svc.nextDeadline(svc.nowUs()).?;
    try testing.expect(first <= svc.nowUs() + 120 * std.time.us_per_ms);
    var i: usize = 0;
    while (i < 8 and svc.stats().tx == 0) : (i += 1) try svc.step(.fromMilliseconds(50));
    const st = svc.stats();
    try testing.expect(st.tx >= 1);
    try testing.expectEqual(@as(u64, 0), st.tx_dropped);
}

test "allow-list with zero joined interfaces emits no_interfaces and init succeeds" {
    // An ifindex no host has: ifaces.zig reports nothing for it, so zero
    // interfaces are joined. With an allow-list that is a warning.
    const allow = [_]u32{4_000_002};
    var svc = try initOrSkip(.{ .host_label = "api", .interfaces = &allow });
    defer svc.deinit();

    try testing.expectEqual(@as(usize, 0), svc.joinedCount());
    try testing.expectEqual(@as(usize, 0), svc.interfaces().len);
    var evs: [8]Event = undefined;
    const n = svc.poll(&evs);
    var no_interfaces: usize = 0;
    var join_failed: usize = 0;
    for (evs[0..n]) |ev| switch (ev) {
        .warning => |w| switch (w) {
            .no_interfaces => no_interfaces += 1,
            .join_failed => join_failed += 1,
            else => {},
        },
        else => {},
    };
    try testing.expectEqual(@as(usize, 1), no_interfaces);
    try testing.expectEqual(@as(usize, 0), join_failed);

    // Mode A keeps working with nothing joined; the refresh cadence
    // re-snapshots and still finds nothing to join.
    try svc.tick(0);
    try svc.tick(5_000);
    try svc.refreshInterfaces();
    try testing.expectEqual(@as(usize, 0), svc.joinedCount());
    try testing.expectEqual(@as(u64, 0), svc.stats().tx);
}

test "mode A tick follows the embedder clock and the query ladder" {
    var svc = initOrSkip(.{ .host_label = "api", .include_loopback = true, .rx_poll_interval_us = 5_000 }) catch |err| switch (err) {
        error.NoMulticastInterface => return error.SkipZigTest,
        else => return err,
    };
    defer svc.deinit();
    // No browse: a tick sends nothing.
    try svc.tick(1_000);
    try testing.expectEqual(@as(u64, 0), svc.stats().tx);
    // A browse schedules its first query 20-120 ms after the last tick.
    _ = try svc.browse("_mdns-zig-test._udp");
    const first = svc.nextDeadline(1_000).?;
    try testing.expect(first >= 1_000 + 20_000 and first <= 1_000 + 120_000);
    try svc.tick(first - 1);
    try testing.expectEqual(@as(u64, 0), svc.stats().tx);
    try svc.tick(first);
    try testing.expect(svc.stats().tx >= 1);
    const tx_after_first = svc.stats().tx;
    // The second query is due 1 s (+0-2 %) later; not before.
    const second = svc.nextDeadline(first).?;
    try testing.expect(second >= first + 1_000_000 and second <= first + 1_020_000);
    try svc.tick(first + 900_000);
    try testing.expectEqual(tx_after_first, svc.stats().tx);
    try svc.tick(second);
    try testing.expect(svc.stats().tx > tx_after_first);
    // Then at least twice the previous gap (+0-2 %): RFC 6762 section
    // 5.2 "MUST increase by at least a factor of two".
    const third = svc.nextDeadline(second).?;
    const gap1 = second - first;
    try testing.expect(third - second >= 2 * gap1 and third - second <= 2 * gap1 + 2 * gap1 / 50);
}

test "mode C serve delivers events into a Mailbox and ends on close" {
    var svc = initOrSkip(.{ .host_label = "api", .include_loopback = true }) catch |err| switch (err) {
        error.NoMulticastInterface => return error.SkipZigTest,
        else => return err,
    };
    defer svc.deinit();
    const io = testing.io;

    // A browse so serve has something to send.
    _ = try svc.browse("_mdns-zig-test._udp");
    var mbuf: [16]Event = undefined;
    var mailbox: mdns.Mailbox = .init(&mbuf);
    var group: Io.Group = .init;
    group.concurrent(io, Service.serve, .{ &svc, &mailbox }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.SkipZigTest,
    };
    // init queued interfaces_changed; serve pushes it after its first step.
    var saw_changed = false;
    var rounds: usize = 0;
    while (!saw_changed and rounds < 64) : (rounds += 1) {
        const ev = try mailbox.next(io);
        if (ev == .interfaces_changed) saw_changed = true;
    }
    try testing.expect(saw_changed);
    // Let the browse's first query (due within 120 ms) go out, then
    // close: serve ends within one step cap.
    try (Io.Clock.Duration{ .raw = .fromMilliseconds(300), .clock = .awake }).sleep(io);
    mailbox.close(io);
    try group.await(io);
    try testing.expect(svc.stats().tx >= 1);
}

test "Engine surface is reachable from the module root" {
    var prng = std.Random.DefaultPrng.init(3);
    var e = try mdns.Engine.init(testing.allocator, .{ .host_label = "api", .random = prng.random() });
    defer e.deinit();
    try testing.expectEqual(null, e.nextDeadline(0));
    try testing.expectEqual(null, e.pollEvent());
    var iface: mdns.Interface = .{ .index = 1 };
    try iface.v4.append(.{ .addr = .{ 127, 0, 0, 1 }, .prefix_len = 8 });
    try e.setInterfaces(&.{iface}, 0);
    try testing.expectEqual(Event.interfaces_changed, e.pollEvent().?);
    const id = try e.browse("_mdns-zig-test._udp", 0);
    const due = e.nextDeadline(0).?;
    e.tick(due);
    var buf: [1500]u8 = undefined;
    const d = e.pollDatagram(&buf, due).?;
    try testing.expectEqual(@as(u32, 1), d.ifindex);
    try testing.expectEqual(@as(u16, 5353), d.to.ip4.port);
    const msg = try mdns.wire.Message.parse(buf[0..d.len]);
    try testing.expectEqual(@as(u16, 1), msg.header.qdcount);
    e.handle(buf[0..d.len], .{ .from = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 5353 } }, .ifindex = 1, .dst_multicast = true }, due + 1);
    try testing.expectEqual(@as(u64, 1), e.stats().rx);
    try testing.expectEqual(@as(u64, 1), e.stats().rx_echo);
    try testing.expectEqual(@as(u64, 1), e.stats().tx);
    e.stopBrowse(id, due + 1);
    try testing.expectEqual(null, e.nextDeadline(due + 1));
}
