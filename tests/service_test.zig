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

    // Mode B: a bounded step never fails on an idle socket and sends the
    // stub query on every joined interface.
    try svc.step(.fromMilliseconds(20));
    const st = svc.stats();
    try testing.expect(st.tx >= 1);
    try testing.expectEqual(@as(u64, 0), st.tx_dropped);
    // `nextDeadline` follows the Engine's 2 s stub cadence.
    try testing.expect(svc.nextDeadline(svc.nowUs()) != null);
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

test "mode A tick follows the embedder clock and the stub cadence" {
    var svc = initOrSkip(.{ .host_label = "api", .include_loopback = true, .rx_poll_interval_us = 5_000 }) catch |err| switch (err) {
        error.NoMulticastInterface => return error.SkipZigTest,
        else => return err,
    };
    defer svc.deinit();
    // The first tick drains (nothing drained yet), ticks the stub (query
    // due at once) and sends.
    try svc.tick(1_000);
    try testing.expect(svc.stats().tx >= 1);
    const tx_after_first = svc.stats().tx;
    // Inside the 2 s stub interval no new query goes out.
    try svc.tick(2_000);
    try svc.tick(1_000_000);
    try testing.expectEqual(tx_after_first, svc.stats().tx);
    // At the 2 s mark the next round goes out.
    try svc.tick(1_000 + mdns.Engine.stub_query_interval_us);
    try testing.expect(svc.stats().tx > tx_after_first);
    try testing.expectEqual(@as(?u64, 1_000 + 2 * mdns.Engine.stub_query_interval_us), svc.nextDeadline(1_000 + mdns.Engine.stub_query_interval_us));
}

test "mode C serve delivers events into a Mailbox and ends on close" {
    var svc = initOrSkip(.{ .host_label = "api", .include_loopback = true }) catch |err| switch (err) {
        error.NoMulticastInterface => return error.SkipZigTest,
        else => return err,
    };
    defer svc.deinit();
    const io = testing.io;

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
    // Closing the mailbox ends serve within one step cap.
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
    e.tick(0);
    var buf: [1500]u8 = undefined;
    const d = e.pollDatagram(&buf, 0).?;
    try testing.expectEqual(@as(u32, 1), d.ifindex);
    try testing.expectEqual(@as(u16, 5353), d.to.ip4.port);
    const msg = try mdns.wire.Message.parse(buf[0..d.len]);
    try testing.expectEqual(@as(u16, 1), msg.header.qdcount);
    e.handle(buf[0..d.len], .{ .from = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 5353 } }, .ifindex = 1, .dst_multicast = true }, 1);
    try testing.expectEqual(@as(u64, 1), e.stats().rx);
    try testing.expectEqual(@as(u64, 1), e.stats().tx);
}
