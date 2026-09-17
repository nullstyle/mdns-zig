//! Loop-mode tests for `mdns.Service` and `mdns.Mailbox` (plan section 7,
//! M5: queued mutations, the Mailbox full policy, `serve` exits, and the
//! `lookup` rules of section 5). Real sockets on `*:5353`: a bind the
//! sandbox refuses (`PermissionDenied`) or that a non-reuse holder owns
//! (`AddressInUse`) skips the test. The two-Service tests talk over the
//! loopback interface only (v4, `include_loopback`), so nothing reaches
//! the LAN; a host without a usable loopback, or `MDNS_HERMETIC=1` in
//! the environment, skips them.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const mdns = @import("mdns");

const Service = mdns.Service;
const Mailbox = mdns.Mailbox;
const Event = mdns.Event;
const Warning = mdns.Warning;
const RegState = mdns.core.responder.State;

const us_per_ms = std.time.us_per_ms;
const us_per_s = std.time.us_per_s;

fn sleepMs(io: Io, ms: u32) !void {
    try (Io.Clock.Duration{ .raw = .fromMilliseconds(ms), .clock = .awake }).sleep(io);
}

fn initOrSkip(opts: Service.Options) !Service {
    return Service.init(testing.allocator, testing.io, opts) catch |err| switch (err) {
        error.PermissionDenied, error.AddressInUse => return error.SkipZigTest,
        else => return err,
    };
}

/// A Service that joins nothing (an allow-list naming an interface no
/// host has), so its ticks and steps never touch the LAN.
fn initUnjoinedOrSkip(label: []const u8) !Service {
    const bogus = [_]u32{4_000_001};
    return initOrSkip(.{ .host_label = label, .interfaces = &bogus });
}

/// The loopback interface's index (the one owning a 127/8 address).
fn loopbackIndex() ?u32 {
    const snap = mdns.platform.ifaces.snapshot(.{ .include_loopback = true, .ipv6 = false }) catch return null;
    for (snap.slice()) |*iface| {
        for (iface.v4.slice()) |p| if (p.addr[0] == 127) return iface.index;
    }
    return null;
}

/// A Service joined on loopback only, v4 only (Linux `lo` has no v6
/// multicast route, Revision 5 item 1). Two of these in one process see
/// each other's multicast through the loopback echo.
fn initLoopbackOrSkip(base_label: []const u8) !Service {
    // `MDNS_HERMETIC=1` (the CI macOS portability lane, plan section 8
    // "hermetic only"): skip the tests that exchange multicast over the
    // loopback, which a locked-down runner may bind but not deliver.
    if (std.c.getenv("MDNS_HERMETIC")) |v| {
        if (v[0] != 0 and v[0] != '0') return error.SkipZigTest;
    }
    const lo = loopbackIndex() orelse return error.SkipZigTest;
    const allow = [_]u32{lo};
    var label_buf: [32]u8 = undefined;
    const label = names().label(&label_buf, base_label);
    var svc = try initOrSkip(.{ .host_label = label, .include_loopback = true, .ipv6 = false, .interfaces = &allow });
    if (svc.joinedCountFor(.v4) == 0) {
        svc.deinit();
        return error.SkipZigTest;
    }
    return svc;
}

/// Per-process names for the loopback tests. Another mdns-zig test
/// binary on the same host (a second suite, another agent's run) hears
/// everything we multicast on `lo0`, and with fixed names it would
/// answer our PTR query or rename against our instance, so `lookup`
/// would see two results and the exact-count assertions would fail.
/// A random 4-hex suffix makes the type, the instances and the host
/// labels unique to this process: `_mdnszig-XXXX._udp` (13 chars, under
/// the RFC 6335 15-char limit), `quiet-XXXX`, `loop-adv-XXXX`.
const LoopNames = struct {
    suffix: [4]u8,
    type_buf: [32]u8,
    type_len: usize,

    fn init() LoopNames {
        var n: LoopNames = undefined;
        var r: [2]u8 = undefined;
        testing.io.random(&r);
        _ = std.fmt.bufPrint(&n.suffix, "{x:0>4}", .{std.mem.readInt(u16, &r, .little)}) catch unreachable; // 4 hex digits always fit
        const t = std.fmt.bufPrint(&n.type_buf, "_mdnszig-{s}._udp", .{n.suffix}) catch unreachable; // 18 chars fit
        n.type_len = t.len;
        return n;
    }

    fn serviceType(n: *const LoopNames) []const u8 {
        return n.type_buf[0..n.type_len];
    }

    /// `<label>-<suffix>` in `buf`.
    fn label(n: *const LoopNames, buf: []u8, base: []const u8) []const u8 {
        return std.fmt.bufPrint(buf, "{s}-{s}", .{ base, n.suffix }) catch unreachable; // callers pass a 32 B buffer for <= 20 chars
    }

    /// `<instance>-<suffix>.<type>.local` as a `Name`.
    fn instanceName(n: *const LoopNames, base: []const u8) !mdns.Name {
        var buf: [96]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "{s}-{s}.{s}.local", .{ base, n.suffix, n.serviceType() });
        return mdns.Name.parse(text);
    }
};

var loop_names: ?LoopNames = null;

/// The process-wide names, built on first use (the default test runner
/// runs tests one at a time on one thread).
fn names() *const LoopNames {
    if (loop_names == null) loop_names = LoopNames.init();
    return &loop_names.?;
}

/// Drives a browsing Service in mode B until `pred` accepts an event or
/// `budget_us` passes. Returns whether it was accepted.
fn stepUntil(svc: *Service, budget_us: u64, comptime pred: fn (Event, *const mdns.Name) bool, instance: *const mdns.Name) !bool {
    const start = svc.nowUs();
    var evs: [8]Event = undefined;
    while (svc.nowUs() - start < budget_us) {
        try svc.step(.fromMilliseconds(100));
        while (true) {
            const n = svc.poll(&evs);
            if (n == 0) break;
            for (evs[0..n]) |ev| if (pred(ev, instance)) return true;
        }
    }
    return false;
}

/// `resolved` / `lost` for this test's own instance only; anything else
/// on the host's loopback is ignored.
fn isResolvedNamed(ev: Event, instance: *const mdns.Name) bool {
    return ev == .resolved and ev.resolved.instance.eql(instance);
}

fn isLostNamed(ev: Event, instance: *const mdns.Name) bool {
    return ev == .lost and ev.lost.instance.eql(instance);
}

// ---------------------------------------------------------------------------
// Queued mutations (plan 4.2, Revision 7 item 7)
// ---------------------------------------------------------------------------

test "advertise before first tick starts probing at first tick" {
    var svc = try initUnjoinedOrSkip("queued");
    defer svc.deinit();
    var evs: [8]Event = undefined;
    _ = svc.poll(&evs);

    // Validation and the id happen at the call: the typed errors of
    // `Engine.advertise` come back before any tick.
    const desc: mdns.ServiceDesc = .{ .service_type = "_mdnszig-q._udp", .instance = "queued", .port = 4433, .txt = &.{.{ .key = "v", .value = "1" }} };
    const id = try svc.advertise(desc);
    try testing.expectError(error.DuplicateRegistration, svc.advertise(desc));
    try testing.expectError(error.InvalidServiceType, svc.advertise(.{ .service_type = "notatype", .instance = "x", .port = 1 }));
    try testing.expectError(error.InvalidInstance, svc.advertise(.{ .service_type = "_mdnszig-q._udp", .instance = "", .port = 1 }));
    const long: [200]u8 = @splat('a');
    try testing.expectError(error.TxtTooLarge, svc.advertise(.{
        .service_type = "_mdnszig-q._udp",
        .instance = "big",
        .port = 1,
        .txt = &.{ .{ .key = "a", .value = &long }, .{ .key = "b", .value = &long } },
    }));
    try testing.expectError(error.InvalidTxt, svc.advertise(.{ .service_type = "_mdnszig-q._udp", .instance = "badtxt", .port = 1, .txt = &.{.{ .key = "a=b" }} }));

    // Nothing is scheduled before the first tick: the slot is reserved,
    // the start is queued, the Engine has no deadline.
    try testing.expectEqual(@as(usize, 1), svc.engine.registrationCount());
    try testing.expectEqual(RegState.reserved, svc.engine.responder.regState(id).?);
    try testing.expectEqual(@as(usize, 1), svc.pendingCount());
    try testing.expectEqual(@as(?u64, null), svc.nextDeadline(0));

    // The first tick applies the start with its own clock: the first
    // probe is 0-250 ms from THAT clock (RFC 6762 section 8.1), not from
    // the call.
    const t1: u64 = 1_000_000;
    try svc.tick(t1);
    try testing.expectEqual(@as(usize, 0), svc.pendingCount());
    try testing.expectEqual(RegState.probing, svc.engine.responder.regState(id).?);
    const due = svc.nextDeadline(t1).?;
    try testing.expect(due >= t1 and due <= t1 + 250_000);

    // `updateTxt` and `withdraw` follow the same rule: validated now,
    // applied at the next tick.
    try svc.updateTxt(id, &.{.{ .key = "v", .value = "2" }});
    try testing.expectError(error.UnknownRegistration, svc.updateTxt(@fromBackingInt(@intCast(200)), &.{}));
    try testing.expectError(error.TxtTooLarge, svc.updateTxt(id, &.{ .{ .key = "a", .value = &long }, .{ .key = "b", .value = &long } }));
    try testing.expectError(error.InvalidTxt, svc.updateTxt(id, &.{.{ .key = "" }}));
    svc.withdraw(id);
    try testing.expectEqual(@as(usize, 2), svc.pendingCount());
    try testing.expectEqual(@as(usize, 1), svc.engine.registrationCount());
    try svc.tick(t1 + 1_000);
    try testing.expectEqual(@as(usize, 0), svc.pendingCount());
    try testing.expectEqual(@as(usize, 0), svc.engine.registrationCount());
    try testing.expectEqual(@as(?u64, null), svc.nextDeadline(t1 + 1_000));
}

test "stopBrowse is applied at the next tick" {
    var svc = try initUnjoinedOrSkip("queued");
    defer svc.deinit();
    try svc.tick(0);
    // `browse` is queued too: the slot and the id are taken at the
    // call, the schedule starts at the next tick with its clock.
    const id = try svc.browse("_mdnszig-s._udp");
    try testing.expectEqual(@as(usize, 1), svc.engine.browseCount());
    try testing.expectEqual(@as(usize, 1), svc.pendingCount());
    try testing.expectEqual(@as(?u64, null), svc.nextDeadline(0));
    try svc.tick(500);
    try testing.expectEqual(@as(usize, 0), svc.pendingCount());
    const first = svc.nextDeadline(500).?;
    try testing.expect(first >= 500 + 20_000 and first <= 500 + 120_000);

    // Queued: the schedule keeps running until the tick that applies it.
    svc.stopBrowse(id);
    try testing.expectEqual(@as(usize, 1), svc.pendingCount());
    try testing.expectEqual(@as(usize, 1), svc.engine.browseCount());
    try testing.expectEqual(@as(?u64, first), svc.nextDeadline(500));

    try svc.tick(1_000);
    try testing.expectEqual(@as(usize, 0), svc.pendingCount());
    try testing.expectEqual(@as(usize, 0), svc.engine.browseCount());
    try testing.expectEqual(@as(?u64, null), svc.nextDeadline(1_000));
    try testing.expectEqual(@as(u64, 0), svc.stats().tx);
}

// ---------------------------------------------------------------------------
// Mailbox (plan 4.3)
// ---------------------------------------------------------------------------

test "mailbox next maps Closed" {
    const io = testing.io;
    var buf: [2]Event = undefined;
    var m: Mailbox = .init(&buf);
    try m.put(io, .interfaces_changed, .zero);
    m.close(io);
    // Queued events stay readable; then the closed queue is `error.Closed`.
    try testing.expectEqual(Event.interfaces_changed, try m.next(io));
    try testing.expectError(error.Closed, m.next(io));
    try testing.expectError(error.Closed, m.next(io));
    // A put into a closed mailbox is `error.Closed` too (what ends `serve`).
    try testing.expectError(error.Closed, m.put(io, .interfaces_changed, .zero));
    try testing.expect(try m.isClosed(io));
}

const Reader = struct {
    /// Frees one slot after `delay_ms`.
    fn run(m: *Mailbox, io: Io, delay_ms: u32, got: *?Event) void {
        sleepMs(io, delay_ms) catch return;
        got.* = m.next(io) catch null;
    }
};

const Watchdog = struct {
    /// Closes the mailbox after `budget_ms` unless canceled first, so a
    /// reader blocked in `next` fails with `error.Closed` instead of
    /// hanging the suite.
    fn run(m: *Mailbox, io: Io, budget_ms: u32) void {
        sleepMs(io, budget_ms) catch return;
        m.close(io);
    }
};

test "mailbox full waits up to the cap then drops oldest and counts" {
    const io = testing.io;
    var buf: [2]Event = undefined;
    var m: Mailbox = .init(&buf);
    try m.put(io, .{ .warning = .no_interfaces }, .zero);
    try m.put(io, .{ .warning = .v6_unavailable }, .zero);

    // Full and nobody reads: `put` waits the whole cap in 10 ms rounds,
    // then drops the oldest, counts it and queues the new one.
    const before = Io.Clock.Timestamp.now(io, .awake);
    try m.put(io, .interfaces_changed, .fromMilliseconds(40));
    const waited_ms = before.durationTo(Io.Clock.Timestamp.now(io, .awake)).raw.toMilliseconds();
    try testing.expect(waited_ms >= 30);
    try testing.expect(waited_ms < 1_000);
    try testing.expectEqual(@as(u64, 1), m.dropped);
    try testing.expectEqual(Warning.v6_unavailable, (try m.next(io)).warning);
    try testing.expectEqual(Event.interfaces_changed, try m.next(io));

    // Full but a reader frees a slot inside the cap: no drop, and `put`
    // returns as soon as the slot appears, not after the whole cap.
    try m.put(io, .{ .warning = .no_interfaces }, .zero);
    try m.put(io, .{ .warning = .v6_unavailable }, .zero);
    var got: ?Event = null;
    var group: Io.Group = .init;
    group.concurrent(io, Reader.run, .{ &m, io, 30, &got }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.SkipZigTest,
    };
    const before2 = Io.Clock.Timestamp.now(io, .awake);
    try m.put(io, .interfaces_changed, .fromMilliseconds(250));
    const waited2_ms = before2.durationTo(Io.Clock.Timestamp.now(io, .awake)).raw.toMilliseconds();
    try group.await(io);
    try testing.expectEqual(@as(u64, 1), m.dropped);
    try testing.expect(waited2_ms < 200);
    try testing.expectEqual(Warning.no_interfaces, got.?.warning);
    try testing.expectEqual(Warning.v6_unavailable, (try m.next(io)).warning);
    try testing.expectEqual(Event.interfaces_changed, try m.next(io));
}

test "mailbox drop emits warning.events_dropped once" {
    // A one-slot mailbox nobody reads for a while: every event after the
    // first costs `serve` one step cap and drops the previous one. After
    // the first drop `serve` queues `warning.events_dropped` exactly
    // once, and the count reaches `stats().events_dropped`.
    var svc = try initUnjoinedOrSkip("mbox");
    defer svc.deinit();
    const io = testing.io;
    // Three events the Engine ring already holds when `serve` starts
    // (plus the `no_interfaces` warning from init).
    svc.engine.pushEvent(.interfaces_changed);
    svc.engine.pushEvent(.interfaces_changed);
    svc.engine.pushEvent(.interfaces_changed);

    var mbuf: [1]Event = undefined;
    var mailbox: Mailbox = .init(&mbuf);
    var group: Io.Group = .init;
    group.concurrent(io, Service.serve, .{ &svc, &mailbox }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.SkipZigTest,
    };
    // Stay away long enough for at least one drop: the first put lands
    // after the first step (one cap), the second waits one more cap and
    // then drops it. Every 250 ms this sleeps past that point is margin
    // for a slow runner; a longer sleep only adds drops.
    try sleepMs(io, 2_500);

    // Then read until the warning arrives instead of assuming `serve`
    // finished its capped puts inside a fixed budget: on the macOS CI
    // runner it had not after 2.5 s, and the mailbox was closed under
    // it before the drop check ran. With a getter waiting, each put is
    // delivered as it happens (`Io.Queue` serves getters first), so
    // `serve` drains its ring and reaches the warning at its own pace.
    // `serve` can queue at most the four events plus one warning per
    // family it could not bind; more reads than that is a wrong stream,
    // not a slow one. The watchdog turns a stream with no warning at
    // all (no drop happened, or `serve` never says so) into a failure
    // here rather than a hang: it closes the mailbox, and `next` fails.
    var watchdog: Io.Group = .init;
    watchdog.concurrent(io, Watchdog.run, .{ &mailbox, io, 30_000 }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.SkipZigTest,
    };
    var warnings: usize = 0;
    var others: usize = 0;
    const read: Mailbox.NextError!void = while (others < 16) {
        const ev = mailbox.next(io) catch |err| break err;
        if (ev == .warning and ev.warning == .events_dropped) {
            warnings += 1;
            break {};
        }
        others += 1;
    } else {};
    // Tear down in order on every outcome, then judge it: a `Closed`
    // here is the watchdog's, that is no drop warning within 30 s.
    watchdog.cancel(io);
    mailbox.close(io);
    try group.await(io);
    try read;
    try testing.expectEqual(@as(usize, 1), warnings);

    // Nothing follows the warning: `serve` says it once per lifetime.
    while (mailbox.next(io)) |ev| {
        if (ev == .warning and ev.warning == .events_dropped) warnings += 1 else others += 1;
    } else |err| try testing.expectEqual(error.Closed, err);
    try testing.expectEqual(@as(usize, 1), warnings);
    try testing.expect(svc.events_dropped_warned);
    try testing.expect(mailbox.dropped >= 1);
    try testing.expectEqual(mailbox.dropped, svc.stats().events_dropped);
}

// ---------------------------------------------------------------------------
// serve (mode C)
// ---------------------------------------------------------------------------

const ServeProbe = struct {
    fn run(svc: *Service, mailbox: *Mailbox, result: *Service.ServeError!void) void {
        result.* = svc.serve(mailbox);
    }
};

test "serve returns Canceled after group.cancel and a peer sees goodbye" {
    var adv = try initLoopbackOrSkip("loop-adv");
    defer adv.deinit();
    var brw = try initLoopbackOrSkip("loop-brw");
    defer brw.deinit();
    const io = testing.io;

    var inst_buf: [32]u8 = undefined;
    const goodbye_name = try names().instanceName("goodbye");
    _ = try adv.advertise(.{ .service_type = names().serviceType(), .instance = names().label(&inst_buf, "goodbye"), .port = 4433 });
    var mbuf: [64]Event = undefined;
    var mailbox: Mailbox = .init(&mbuf);
    var result: Service.ServeError!void = {};
    var group: Io.Group = .init;
    group.concurrent(io, ServeProbe.run, .{ &adv, &mailbox, &result }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.SkipZigTest,
    };

    // The browser (mode B) hears the announcements after the ~1 s probe.
    _ = try brw.browse(names().serviceType());
    const seen = try stepUntil(&brw, 6 * us_per_s, isResolvedNamed, &goodbye_name);
    if (!seen) {
        group.cancel(io);
        return error.TestUnexpectedResult;
    }

    // Cancel: `serve` returns `error.Canceled` itself, after its goodbye
    // flush withdrew the registration.
    group.cancel(io);
    try testing.expectError(error.Canceled, result);
    try testing.expectEqual(@as(usize, 0), adv.engine.registrationCount());
    // The peer sees the goodbye as `lost` (TTL 0 -> 1 s grace).
    try testing.expect(try stepUntil(&brw, 2_500 * us_per_ms, isLostNamed, &goodbye_name));
}

test "serve refuses inline run on single-threaded Io" {
    // Plan 4.3: `serve` must be started with `Group.concurrent`. On
    // `Threaded.global_single_threaded` (allocator `.failing`,
    // `concurrent_limit = .nothing`) `Group.concurrent` returns
    // `error.ConcurrencyUnavailable` from its own task allocation before
    // `serve` is ever called (Threaded.zig `groupConcurrent`), so the
    // refusal is the caller's error and nothing runs inline.
    var svc = try initUnjoinedOrSkip("single");
    defer svc.deinit();
    const single = Io.Threaded.global_single_threaded.io();
    var mbuf: [4]Event = undefined;
    var mailbox: Mailbox = .init(&mbuf);
    var group: Io.Group = .init;
    try testing.expectError(error.ConcurrencyUnavailable, group.concurrent(single, Service.serve, .{ &svc, &mailbox }));
    // `serve` never ran: the Service is still unbound to a clock, so a
    // mode A tick is legal (it would assert after a `serve`), nothing
    // was sent and the mailbox saw nothing.
    try svc.tick(0);
    try testing.expectEqual(@as(u64, 0), svc.stats().tx);
    try testing.expectEqual(@as(u64, 0), mailbox.dropped);
    try testing.expect(!try mailbox.isClosed(testing.io));
}

// ---------------------------------------------------------------------------
// lookup (plan section 5, "Rules behind the sketch")
// ---------------------------------------------------------------------------

const Runner = struct {
    /// `Service.run` as a Group task; `run` returns `anyerror` so it is
    /// wrapped to the `Cancelable!void` the Group wants.
    fn run(svc: *Service, shutdown: *std.atomic.Value(bool), hook: ?Service.Hook) void {
        svc.run(shutdown, hook) catch {};
    }
};

/// An advertising peer on loopback, run in a Group task.
const Peer = struct {
    svc: Service,
    shutdown: std.atomic.Value(bool) = .init(false),
    group: Io.Group = .init,

    fn start(p: *Peer, hook: ?Service.Hook) !void {
        p.group.concurrent(testing.io, Runner.run, .{ &p.svc, &p.shutdown, hook }) catch |err| switch (err) {
            error.ConcurrencyUnavailable => return error.SkipZigTest,
        };
    }

    fn stop(p: *Peer) void {
        p.shutdown.store(true, .release);
        p.group.await(testing.io) catch {};
    }
};

test "lookup returns after quiet_us with one result" {
    var peer: Peer = .{ .svc = try initLoopbackOrSkip("loop-adv") };
    defer peer.svc.deinit();
    var brw = try initLoopbackOrSkip("loop-brw");
    defer brw.deinit();
    const io = testing.io;

    var inst_buf: [32]u8 = undefined;
    _ = try peer.svc.advertise(.{ .service_type = names().serviceType(), .instance = names().label(&inst_buf, "quiet"), .port = 4433, .txt = &.{.{ .key = "v", .value = "1" }} });
    try peer.start(null);
    defer peer.stop();
    // Let the peer finish probing and announcing (about 2 s).
    try sleepMs(io, 2_500);

    var out: [4]mdns.Resolved = undefined;
    const t0 = brw.nowUs();
    const n = try brw.lookup(names().serviceType(), .{ .timeout_us = 5 * us_per_s, .quiet_us = 500 * us_per_ms }, &out);
    const elapsed = brw.nowUs() - t0;
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expect(out[0].instance.eql(&try names().instanceName("quiet")));
    try testing.expectEqual(@as(u16, 4433), out[0].port);
    try testing.expectEqualStrings("1", out[0].txt.get("v").?);
    try testing.expect(out[0].addrs.len >= 1);
    // Returned by the quiet rule: at least quiet_us after the resolve,
    // well before the timeout.
    try testing.expect(elapsed >= 500 * us_per_ms);
    try testing.expect(elapsed < 3 * us_per_s);
    // The browse is stopped when `lookup` returns; no tick needed.
    try testing.expectEqual(@as(usize, 0), brw.engine.browseCount());
}

test "lookup returns at timeout_us with zero results" {
    var svc = try initUnjoinedOrSkip("none");
    defer svc.deinit();
    var out: [4]mdns.Resolved = undefined;
    const t0 = svc.nowUs();
    const n = try svc.lookup("_mdnszig-none._udp", .{ .timeout_us = 300 * us_per_ms, .quiet_us = 50 * us_per_ms }, &out);
    const elapsed = svc.nowUs() - t0;
    try testing.expectEqual(@as(usize, 0), n);
    // The quiet rule needs >= 1 result; with none the call runs to the
    // timeout (steps are capped at what is left of it).
    try testing.expect(elapsed >= 300 * us_per_ms);
    try testing.expect(elapsed < 1_000 * us_per_ms);
    try testing.expectEqual(@as(usize, 0), svc.engine.browseCount());
    // A browse of that type is possible again (no leaked browse slot).
    const id = try svc.browse("_mdnszig-none._udp");
    _ = id;
    try testing.expectEqual(@as(usize, 1), svc.engine.browseCount());
    // A lookup of a type with an active browse is DuplicateBrowse.
    try testing.expectError(error.DuplicateBrowse, svc.lookup("_mdnszig-none._udp", .{ .timeout_us = 10_000 }, &out));
}

const LookupProbe = struct {
    fn run(svc: *Service, out: []mdns.Resolved, result: *Service.LookupError!usize) void {
        result.* = svc.lookup("_mdnszig-cancel._udp", .{ .timeout_us = 30 * us_per_s, .quiet_us = 1 * us_per_s }, out);
    }
};

test "lookup returns Canceled after group.cancel and the browse is stopped" {
    var svc = try initUnjoinedOrSkip("cancel");
    defer svc.deinit();
    const io = testing.io;
    var out: [4]mdns.Resolved = undefined;
    var result: Service.LookupError!usize = 0;
    var group: Io.Group = .init;
    group.concurrent(io, LookupProbe.run, .{ &svc, &out, &result }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.SkipZigTest,
    };
    try sleepMs(io, 60);
    const before = Io.Clock.Timestamp.now(io, .awake);
    group.cancel(io);
    const took_ms = before.durationTo(Io.Clock.Timestamp.now(io, .awake)).raw.toMilliseconds();
    // The cancel lands on the step's timed receive; `lookup` stops the
    // browse on its way out and returns `error.Canceled` long before its
    // 30 s timeout.
    try testing.expectError(error.Canceled, result);
    try testing.expect(took_ms < 2_000);
    try testing.expectEqual(@as(usize, 0), svc.engine.browseCount());
    try testing.expectEqual(@as(?u64, null), svc.nextDeadline(svc.nowUs()));
}

const TxtBump = struct {
    id: mdns.RegId,
    at_us: u64,
    done: bool = false,

    /// `Service.run` hook: one `updateTxt` once the peer's clock passes
    /// `at_us` (on the peer's own loop thread, as the API requires).
    fn hook(ctx: ?*anyopaque, svc: *Service, now_us: u64) anyerror!void {
        const b: *TxtBump = @ptrCast(@alignCast(ctx.?));
        if (b.done or now_us < b.at_us) return;
        b.done = true;
        try svc.updateTxt(b.id, &.{.{ .key = "v", .value = "2" }});
    }
};

test "lookup replaces an earlier resolved for the same instance" {
    var peer: Peer = .{ .svc = try initLoopbackOrSkip("loop-adv") };
    defer peer.svc.deinit();
    var brw = try initLoopbackOrSkip("loop-brw");
    defer brw.deinit();
    const io = testing.io;

    var inst_buf: [32]u8 = undefined;
    const id = try peer.svc.advertise(.{ .service_type = names().serviceType(), .instance = names().label(&inst_buf, "replace"), .port = 4433, .txt = &.{.{ .key = "v", .value = "1" }} });
    // The TXT changes 3.2 s into the peer's life: after the browser's
    // first `resolved` (v=1, about 2.6 s) and inside its quiet window,
    // so the re-emitted `resolved` (v=2) must replace the slot rather
    // than take a second one, and the quiet timer restarts.
    var bump: TxtBump = .{ .id = id, .at_us = 3_200 * us_per_ms };
    try peer.start(.{ .ctx = &bump, .f = TxtBump.hook });
    defer peer.stop();
    try sleepMs(io, 2_500);

    var out: [4]mdns.Resolved = undefined;
    const t0 = brw.nowUs();
    const n = try brw.lookup(names().serviceType(), .{ .timeout_us = 6 * us_per_s, .quiet_us = 1_200 * us_per_ms }, &out);
    const elapsed = brw.nowUs() - t0;
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expect(out[0].instance.eql(&try names().instanceName("replace")));
    try testing.expectEqualStrings("2", out[0].txt.get("v").?);
    try testing.expect(bump.done);
    // The second resolve restarted the quiet window: the call outlived
    // the first resolve plus one quiet period.
    try testing.expect(elapsed >= 1_200 * us_per_ms);
    try testing.expect(elapsed < 6 * us_per_s);
    try testing.expectEqual(@as(usize, 0), brw.engine.browseCount());
}
