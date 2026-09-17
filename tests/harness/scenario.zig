//! Deterministic scenario support for the tier-1 tests (plan section 8):
//! a fake clock, a seeded PRNG, an event `Sink` per engine and packet
//! budget helpers over the `FakeLan` log. No wall clock, no threads.
//!
//! Usage sketch:
//!
//! ```zig
//! var sc: Scenario = .init(42);
//! var e = try mdns.Engine.init(gpa, .{ .host_label = "a", .random = sc.random() });
//! ...
//! sc.advance(1_000_000);          // now_us == 1 s
//! var sink: Sink = .init(gpa);    // collects every Event an engine emits
//! defer sink.deinit();
//! try sink.drain(&e);
//! try std.testing.expectEqual(1, sink.count(.found));
//! ```
//!
//! `Scenario.random()` hands out a `std.Random` that points into the
//! scenario, so a `Scenario` must live at a fixed address for as long as
//! any Engine holds that `std.Random` (declare it with `var` in the test
//! body; do not return it by value afterwards).
const std = @import("std");
const mdns = @import("mdns");
const fake_lan = @import("fake_lan.zig");

pub const Engine = mdns.Engine;
pub const Event = mdns.Event;
pub const EventTag = std.meta.Tag(Event);
pub const PacketKind = fake_lan.PacketKind;
pub const Sent = fake_lan.Sent;

pub const us_per_ms: u64 = 1_000;
pub const us_per_s: u64 = 1_000_000;
pub const us_per_min: u64 = 60 * us_per_s;
pub const us_per_hour: u64 = 60 * us_per_min;
pub const us_per_day: u64 = 24 * us_per_hour;

/// Fake clock plus seeded randomness. `now_us` starts at `start_us`
/// (default 0) and only `advance` / `set` move it, so every timer the
/// Engine schedules is reproducible from the seed.
pub const Scenario = struct {
    prng: std.Random.DefaultPrng,
    seed: u64,
    now_us: u64,

    pub fn init(seed: u64) Scenario {
        return initAt(seed, 0);
    }

    pub fn initAt(seed: u64, start_us: u64) Scenario {
        return .{ .prng = .init(seed), .seed = seed, .now_us = start_us };
    }

    /// The `std.Random` to hand to `Engine.Options.random` (and to
    /// `FakeLan.setLoss`). Points into `sc`.
    pub fn random(sc: *Scenario) std.Random {
        return sc.prng.random();
    }

    /// Reseed in place; the Engines keep their `std.Random` handle.
    pub fn reseed(sc: *Scenario, seed: u64) void {
        sc.prng = .init(seed);
        sc.seed = seed;
    }

    pub fn nowUs(sc: *const Scenario) u64 {
        return sc.now_us;
    }

    /// Move the clock forward by `us`. Saturates rather than wraps.
    pub fn advance(sc: *Scenario, us: u64) void {
        sc.now_us = sc.now_us +| us;
    }

    pub fn advanceMs(sc: *Scenario, ms: u64) void {
        sc.advance(ms * us_per_ms);
    }

    pub fn advanceS(sc: *Scenario, s: u64) void {
        sc.advance(s * us_per_s);
    }

    /// Jump the clock to an absolute time (never backwards: a test that
    /// tries to rewind is a test bug, so this asserts).
    pub fn set(sc: *Scenario, now_us: u64) void {
        std.debug.assert(now_us >= sc.now_us);
        sc.now_us = now_us;
    }

    /// Drive a `FakeLan` (or anything with `run(from, to, step)`) for
    /// `duration_us` from the current clock in `step_us` steps and leave
    /// the clock at the end. Each step ticks every engine and pumps.
    pub fn runFor(sc: *Scenario, lan: anytype, duration_us: u64, step_us: u64) !void {
        const to = sc.now_us +| duration_us;
        try lan.run(sc.now_us, to, step_us);
        sc.now_us = to;
    }

    /// Like `runFor` but jumps between engine deadlines instead of fixed
    /// steps (see `FakeLan.runToDeadlines`), for day-long budget tests.
    pub fn runForByDeadlines(sc: *Scenario, lan: anytype, duration_us: u64, max_step_us: u64) !void {
        const to = sc.now_us +| duration_us;
        try lan.runToDeadlines(sc.now_us, to, max_step_us);
        sc.now_us = to;
    }
};

/// Everything an engine emitted, in order, as values. Allocates with the
/// test allocator (the harness may allocate; the Engine may not).
pub const Sink = struct {
    gpa: std.mem.Allocator,
    events: std.ArrayList(Event) = .empty,

    pub fn init(gpa: std.mem.Allocator) Sink {
        return .{ .gpa = gpa };
    }

    pub fn deinit(s: *Sink) void {
        s.events.deinit(s.gpa);
        s.* = undefined;
    }

    /// Pop every pending event from `e` into the sink. Returns how many
    /// were taken.
    pub fn drain(s: *Sink, e: *Engine) !usize {
        var n: usize = 0;
        while (e.pollEvent()) |ev| {
            try s.events.append(s.gpa, ev);
            n += 1;
        }
        return n;
    }

    pub fn items(s: *const Sink) []const Event {
        return s.events.items;
    }

    pub fn len(s: *const Sink) usize {
        return s.events.items.len;
    }

    pub fn clear(s: *Sink) void {
        s.events.clearRetainingCapacity();
    }

    /// Number of collected events with that tag.
    pub fn count(s: *const Sink, tag: EventTag) usize {
        var n: usize = 0;
        for (s.events.items) |ev| if (ev == tag) {
            n += 1;
        };
        return n;
    }

    /// The `n`-th (0-based) event with that tag, or null.
    pub fn nth(s: *const Sink, tag: EventTag, n: usize) ?Event {
        var seen: usize = 0;
        for (s.events.items) |ev| {
            if (ev != tag) continue;
            if (seen == n) return ev;
            seen += 1;
        }
        return null;
    }

    /// The first event with that tag, or null.
    pub fn first(s: *const Sink, tag: EventTag) ?Event {
        return s.nth(tag, 0);
    }

    /// The most recent event with that tag, or null.
    pub fn last(s: *const Sink, tag: EventTag) ?Event {
        var i = s.events.items.len;
        while (i > 0) {
            i -= 1;
            if (s.events.items[i] == tag) return s.events.items[i];
        }
        return null;
    }

    /// Number of `warning` events of one kind.
    pub fn countWarning(s: *const Sink, tag: std.meta.Tag(mdns.Warning)) usize {
        var n: usize = 0;
        for (s.events.items) |ev| switch (ev) {
            .warning => |w| if (w == tag) {
                n += 1;
            },
            else => {},
        };
        return n;
    }

    /// Fail the test unless exactly `expected` events of `tag` were seen.
    pub fn expectCount(s: *const Sink, tag: EventTag, expected: usize) !void {
        try std.testing.expectEqual(expected, s.count(tag));
    }
};

// ---- packet budgets --------------------------------------------------

/// Filter over the `FakeLan` send log. Every field is optional; `null`
/// matches everything. The window is `[from_us, to_us)`.
pub const Filter = struct {
    from_engine: ?usize = null,
    ifindex: ?u32 = null,
    segment: ?u32 = null,
    kind: ?PacketKind = null,
    family: ?mdns.Family = null,
    /// `true`: only datagrams to a multicast group; `false`: only
    /// unicast ones (legacy and QU replies, unicast probe defences).
    multicast: ?bool = null,
    from_us: u64 = 0,
    to_us: u64 = std.math.maxInt(u64),

    pub fn matches(f: Filter, s: *const Sent) bool {
        if (f.from_engine) |v| if (s.from_engine != v) return false;
        if (f.ifindex) |v| if (s.ifindex != v) return false;
        if (f.segment) |v| if (s.segment != v) return false;
        if (f.kind) |v| if (s.kind != v) return false;
        if (f.family) |v| if (s.family != v) return false;
        if (f.multicast) |v| if (s.isMulticast() != v) return false;
        if (s.now_us < f.from_us or s.now_us >= f.to_us) return false;
        return true;
    }
};

/// Number of sent datagrams in the log that match `filter`.
pub fn countSent(log: []const Sent, filter: Filter) usize {
    var n: usize = 0;
    for (log) |*s| if (filter.matches(s)) {
        n += 1;
    };
    return n;
}

/// Fail the test when more than `budget` datagrams match `filter`. The
/// message names the count so a flood shows up in the failure.
pub fn expectBudget(log: []const Sent, filter: Filter, budget: usize) !void {
    const n = countSent(log, filter);
    if (n > budget) {
        std.debug.print("packet budget exceeded: {d} sent, budget {d} (filter {any})\n", .{ n, budget, filter });
        return error.TestUnexpectedResult;
    }
}

/// Fail the test unless at least `min` datagrams match `filter`.
pub fn expectAtLeast(log: []const Sent, filter: Filter, min: usize) !void {
    const n = countSent(log, filter);
    if (n < min) {
        std.debug.print("too few packets: {d} sent, expected at least {d} (filter {any})\n", .{ n, min, filter });
        return error.TestUnexpectedResult;
    }
}

/// Largest number of matching datagrams in any sliding window of
/// `window_us` (aligned to each packet's send time). Rate-limit tests
/// ("at most N per second on an interface") use it.
pub fn maxInWindow(log: []const Sent, filter: Filter, window_us: u64) usize {
    var best: usize = 0;
    for (log, 0..) |*anchor, i| {
        if (!filter.matches(anchor)) continue;
        var n: usize = 0;
        const end = anchor.now_us +| window_us;
        for (log[i..]) |*s| {
            if (s.now_us >= end) break;
            if (filter.matches(s)) n += 1;
        }
        best = @max(best, n);
    }
    return best;
}

/// Send times (microseconds) of the matching datagrams, in log order,
/// into `out`; returns the filled prefix. Timer tests check gaps with it.
pub fn sendTimes(log: []const Sent, filter: Filter, out: []u64) []u64 {
    var n: usize = 0;
    for (log) |*s| {
        if (n == out.len) break;
        if (filter.matches(s)) {
            out[n] = s.now_us;
            n += 1;
        }
    }
    return out[0..n];
}

// ---- self tests ------------------------------------------------------

const testing = std.testing;

test "Scenario clock and prng are deterministic from the seed" {
    var a: Scenario = .init(9);
    var b: Scenario = .init(9);
    try testing.expectEqual(a.random().int(u64), b.random().int(u64));
    a.advanceMs(20);
    a.advanceS(1);
    try testing.expectEqual(@as(u64, 1_020_000), a.nowUs());
    a.set(2_000_000);
    try testing.expectEqual(@as(u64, 2_000_000), a.now_us);
    a.advance(std.math.maxInt(u64));
    try testing.expectEqual(std.math.maxInt(u64), a.now_us);
}

test "Sink counts and indexes events by tag" {
    var s: Sink = .init(testing.allocator);
    defer s.deinit();
    var sc: Scenario = .init(1);
    var e = try Engine.init(testing.allocator, .{ .host_label = "sink", .random = sc.random(), .limits = .{ .max_events = 4 } });
    defer e.deinit();
    e.pushEvent(.interfaces_changed);
    e.pushEvent(.{ .warning = .no_interfaces });
    e.pushEvent(.interfaces_changed);
    try testing.expectEqual(@as(usize, 3), try s.drain(&e));
    try testing.expectEqual(@as(usize, 0), try s.drain(&e));
    try s.expectCount(.interfaces_changed, 2);
    try s.expectCount(.warning, 1);
    try s.expectCount(.found, 0);
    try testing.expectEqual(@as(usize, 1), s.countWarning(.no_interfaces));
    try testing.expectEqual(@as(usize, 0), s.countWarning(.events_dropped));
    try testing.expectEqual(EventTag.warning, std.meta.activeTag(s.nth(.warning, 0).?));
    try testing.expectEqual(null, s.nth(.warning, 1));
    try testing.expect(s.first(.interfaces_changed) != null);
    try testing.expect(s.last(.warning) != null);
    s.clear();
    try testing.expectEqual(@as(usize, 0), s.len());
}

test "budget helpers count sent datagrams in a window" {
    const log = [_]Sent{
        .{ .from_engine = 0, .ifindex = 1, .segment = 0, .family = .v4, .kind = .query, .now_us = 0, .bytes = &.{}, .delivered = 1, .lost = 0 },
        .{ .from_engine = 0, .ifindex = 1, .segment = 0, .family = .v4, .kind = .query, .now_us = 500_000, .bytes = &.{}, .delivered = 1, .lost = 0 },
        .{ .from_engine = 1, .ifindex = 7, .segment = 0, .family = .v6, .kind = .response, .now_us = 900_000, .bytes = &.{}, .delivered = 1, .lost = 0 },
        .{ .from_engine = 0, .ifindex = 1, .segment = 0, .family = .v4, .kind = .query, .now_us = 2_000_000, .bytes = &.{}, .delivered = 0, .lost = 1 },
    };
    try testing.expectEqual(@as(usize, 3), countSent(&log, .{ .kind = .query }));
    try testing.expectEqual(@as(usize, 2), countSent(&log, .{ .kind = .query, .to_us = 1_000_000 }));
    try testing.expectEqual(@as(usize, 1), countSent(&log, .{ .from_engine = 1 }));
    try testing.expectEqual(@as(usize, 1), countSent(&log, .{ .family = .v6 }));
    try testing.expectEqual(@as(usize, 0), countSent(&log, .{ .ifindex = 2 }));
    try testing.expectEqual(@as(usize, 4), countSent(&log, .{ .multicast = true }));
    try testing.expectEqual(@as(usize, 0), countSent(&log, .{ .multicast = false }));
    try expectBudget(&log, .{ .kind = .query }, 3);
    try expectAtLeast(&log, .{}, 4);
    try testing.expectEqual(@as(usize, 2), maxInWindow(&log, .{ .kind = .query }, us_per_s));
    try testing.expectEqual(@as(usize, 1), maxInWindow(&log, .{ .kind = .query }, 500_000));
    var times: [8]u64 = undefined;
    const t = sendTimes(&log, .{ .from_engine = 0 }, &times);
    try testing.expectEqualSlices(u64, &.{ 0, 500_000, 2_000_000 }, t);
}
