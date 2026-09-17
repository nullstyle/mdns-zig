//! Digests of recently sent datagrams, for own-echo recognition (plan
//! section 4.8).
//!
//! Multicast loopback is on, so every datagram the Engine sends comes
//! back through `handle`. A datagram is an own echo only when BOTH tests
//! pass:
//!
//!   1. its digest matches one recorded here within `window_us`
//!      (`timers.echo_window_us`, 1 s; the derivation is there), and
//!   2. its source address is one of our own interface addresses.
//!
//! This file implements test 1 only. The caller (`Engine.handle`) ANDs it
//! with the source-address test from the Interface table. The digest
//! alone is not enough: multicast query IDs are zero (RFC 6762
//! section 18.1), so a peer's first browse query for the same type with
//! an empty known-answer list is byte-identical to ours and must still be
//! answered. The source test alone is not enough either: mDNSResponder or
//! avahi on the same host send from the same IP and can carry real
//! conflicts. And both tests together still pass for a same-host peer
//! program's identical query (same bytes, our address), so the Engine
//! answers a plain query even when it is an echo and stops only
//! responses and probes (v0.1.1).
//!
//! No allocation: 32 inline entries, oldest overwritten.
const std = @import("std");
const testing = std.testing;
const timers = @import("timers.zig");

/// Number of digests kept. One browse per interface plus a few answers
/// per second fit comfortably; an entry only has to survive the loopback
/// round trip, which is well under the window.
pub const capacity: usize = 32;

/// Window after `record` in which `matches` reports an echo (plan
/// section 4.8; `timers.echo_window_us`, 1 s).
pub const window_us: u64 = timers.echo_window_us;

/// Wyhash seed. Fixed: the digests never leave the process, and the
/// input is bytes we produced ourselves.
const digest_seed: u64 = 0x6d646e732d7a6967; // "mdns-zig"

pub const Entry = struct {
    digest: u64,
    sent_us: u64,
};

pub const EchoRing = struct {
    entries: [capacity]Entry = undefined,
    /// Number of valid entries (saturates at `capacity`).
    len: usize = 0,
    /// Slot the next `record` writes; wraps at `capacity`.
    next: usize = 0,

    pub const empty: EchoRing = .{};

    /// Digest of a datagram: `std.hash.Wyhash` over the whole payload.
    pub fn digest(bytes: []const u8) u64 {
        return std.hash.Wyhash.hash(digest_seed, bytes);
    }

    /// Remember a datagram sent at `now_us`. Overwrites the oldest entry
    /// when the ring is full.
    pub fn record(self: *EchoRing, bytes: []const u8, now_us: u64) void {
        self.entries[self.next] = .{ .digest = digest(bytes), .sent_us = now_us };
        self.next = (self.next + 1) % capacity;
        if (self.len < capacity) self.len += 1;
    }

    /// True when `bytes` digests to an entry recorded within `window_us`
    /// before `now_us`. An entry recorded "after" `now_us` (a
    /// non-monotonic caller clock) reads as age 0 and still matches.
    pub fn matches(self: *const EchoRing, bytes: []const u8, now_us: u64) bool {
        if (self.len == 0) return false;
        const d = digest(bytes);
        for (self.entries[0..self.len]) |e| {
            if (e.digest != d) continue;
            if (now_us -| e.sent_us <= window_us) return true;
        }
        return false;
    }

    /// Number of live entries.
    pub fn count(self: *const EchoRing) usize {
        return self.len;
    }

    /// Forget everything.
    pub fn clear(self: *EchoRing) void {
        self.len = 0;
        self.next = 0;
    }
};

// ---- tests ------------------------------------------------------------

test "echo ring matches within the window" {
    var ring: EchoRing = .empty;
    const pkt = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05_qmsg\x04_udp\x05local\x00\x00\x0c\x00\x01";
    try testing.expect(!ring.matches(pkt, 1_000_000));
    ring.record(pkt, 1_000_000);
    try testing.expect(ring.matches(pkt, 1_000_000));
    try testing.expect(ring.matches(pkt, 1_000_000 + 1));
    try testing.expect(ring.matches(pkt, 1_000_000 + window_us / 2));
    try testing.expect(ring.matches(pkt, 1_000_000 + window_us));
    try testing.expectEqual(@as(usize, 1), ring.count());
}

test "echo ring no match after the window" {
    var ring: EchoRing = .empty;
    const pkt = "abcdefgh";
    ring.record(pkt, 5_000_000);
    try testing.expect(ring.matches(pkt, 5_000_000 + window_us));
    try testing.expect(!ring.matches(pkt, 5_000_000 + window_us + 1));
    try testing.expect(!ring.matches(pkt, 5_000_000 + timers.s(60)));
    // The entry is still there; a fresh record of the same bytes matches
    // again.
    ring.record(pkt, 9_000_000);
    try testing.expect(ring.matches(pkt, 9_000_000 + 10));
}

test "echo ring wraps at 32" {
    var ring: EchoRing = .empty;
    var pkts: [capacity + 1][4]u8 = undefined;
    for (&pkts, 0..) |*p, i| {
        p.* = .{ 'p', 'k', 't', @intCast(i) };
    }
    // Fill exactly to capacity: every packet matches.
    for (pkts[0..capacity], 0..) |*p, i| ring.record(p, @intCast(i));
    try testing.expectEqual(capacity, ring.count());
    for (pkts[0..capacity]) |*p| try testing.expect(ring.matches(p, 100));

    // One more overwrites the oldest (index 0) and nothing else.
    ring.record(&pkts[capacity], 100);
    try testing.expectEqual(capacity, ring.count());
    try testing.expect(!ring.matches(&pkts[0], 100));
    for (pkts[1 .. capacity + 1]) |*p| try testing.expect(ring.matches(p, 100));

    // A full lap later the ring holds only the newest 32.
    var i: usize = 0;
    while (i < capacity) : (i += 1) ring.record(&pkts[capacity], 200);
    try testing.expectEqual(capacity, ring.count());
    for (pkts[0..capacity]) |*p| try testing.expect(!ring.matches(p, 200));
    try testing.expect(ring.matches(&pkts[capacity], 200));

    ring.clear();
    try testing.expectEqual(@as(usize, 0), ring.count());
    try testing.expect(!ring.matches(&pkts[capacity], 200));
}

test "digest differs for different bytes" {
    const a = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00";
    const b = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x01";
    try testing.expect(EchoRing.digest(a) != EchoRing.digest(b));
    try testing.expect(EchoRing.digest(a) == EchoRing.digest(a));
    try testing.expect(EchoRing.digest("") != EchoRing.digest("\x00"));

    var ring: EchoRing = .empty;
    ring.record(a, 0);
    try testing.expect(ring.matches(a, 0));
    try testing.expect(!ring.matches(b, 0));
    // A prefix or a suffix of a recorded datagram is a different datagram.
    try testing.expect(!ring.matches(a[0 .. a.len - 1], 0));
    try testing.expect(!ring.matches(a ++ "\x00", 0));
}
