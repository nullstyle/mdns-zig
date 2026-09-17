//! Time constants, the RFC 6762 timer arithmetic and the fixed-capacity
//! deadline set (plan section 4.4).
//!
//! Every RFC 6762 timer and TTL the Engine uses is a named comptime
//! constant here, with its RFC section. Durations are `u64` microseconds
//! on the caller's `now_us` clock (plan section 4.2). TTLs stay in seconds
//! because they are wire values (RFC 6762 section 10). The rule helpers
//! (`requeryMarkUs`, `expiryUs`, `kaOmit`, `quReplyMulticast`) are the
//! single implementation of their clause: `core/cache.zig` calls the
//! first three, the M4 responder the last. All of them saturate instead
//! of wrapping near the end of the `u64` clock.
//!
//! Randomness is never drawn here from a global: every jittered draw takes
//! the injected `std.Random` (plan section 4.2).
//!
//! `DeadlineSet` is a sorted, fixed-capacity deadline structure: capacity
//! is a comptime parameter and a full set reports `error.Full` rather than
//! silently dropping a deadline. The M3 querier does not use it: its
//! deadlines (browse steps, follow-ups, requery marks, cache expiry) live
//! on the browse, instance and cache entries themselves and are memoised
//! into one `next_deadline` after every state change
//! (`Querier.recomputeDeadline`), which is cheaper than keeping a heap in
//! sync with every refresh. It is reserved for the M4 responder (probe
//! steps, announce steps, rate-limit expiry, pending answers), whose
//! deadlines are not attached to cache entries.
const std = @import("std");
const testing = std.testing;

// ---- unit helpers -----------------------------------------------------

pub const us_per_ms: u64 = 1_000;
pub const us_per_s: u64 = 1_000_000;

/// Milliseconds to microseconds at comptime or runtime.
pub inline fn ms(v: u64) u64 {
    return v * us_per_ms;
}

/// Seconds to microseconds at comptime or runtime.
pub inline fn s(v: u64) u64 {
    return v * us_per_s;
}

// ---- TTLs (seconds, wire values) --------------------------------------

/// TTL for host records: A, AAAA, SRV and the NSEC that covers them
/// (RFC 6762 section 10: "records whose rdata names a host", 120 s).
pub const ttl_host_s: u32 = 120;

/// TTL for every other record: DNS-SD PTR and TXT (RFC 6762 section 10,
/// 75 minutes = 4500 s).
pub const ttl_other_s: u32 = 4500;

/// TTL cap on legacy unicast replies (RFC 6762 section 6.7: a responder
/// "SHOULD NOT" send a TTL over 10 s to a legacy querier).
pub const ttl_legacy_cap_s: u32 = 10;

// ---- responder: probing and announcing --------------------------------

/// Lower bound of the random delay before the first probe (RFC 6762
/// section 8.1: 0-250 ms).
pub const probe_first_delay_min_us: u64 = 0;

/// Upper bound of the random delay before the first probe (RFC 6762
/// section 8.1: 0-250 ms).
pub const probe_first_delay_max_us: u64 = ms(250);

/// Spacing between successive probes (RFC 6762 section 8.1: 250 ms).
pub const probe_interval_us: u64 = ms(250);

/// Number of probes before a record is established (RFC 6762 section 8.1:
/// three).
pub const probe_count: u32 = 3;

/// Wait after losing a simultaneous-probe tie-break before probing again
/// (RFC 6762 section 8.2: "waits one second").
pub const probe_tiebreak_wait_us: u64 = s(1);

/// Spacing between announcements (RFC 6762 section 8.3: at least 1 s).
pub const announce_interval_us: u64 = s(1);

/// Number of announcements after probing (RFC 6762 section 8.3: "at
/// least two", we send two).
pub const announce_count: u32 = 2;

// ---- querier: continuous querying -------------------------------------

/// Lower bound of the random delay before a question's first query
/// (RFC 6762 section 5.2: 20-120 ms).
pub const query_first_delay_min_us: u64 = ms(20);

/// Upper bound of the random delay before a question's first query
/// (RFC 6762 section 5.2: 20-120 ms).
pub const query_first_delay_max_us: u64 = ms(120);

/// Interval between the first and second query of a question (RFC 6762
/// section 5.2: "at least one second"). Every later interval doubles.
pub const query_interval_first_us: u64 = s(1);

/// Cap on the doubling query interval (RFC 6762 section 5.2: "60
/// minutes").
pub const query_interval_cap_us: u64 = s(3600);

/// Maximum jitter added to a scheduled query, in percent of the interval
/// (RFC 6762 section 5.2: "0-2 %" is the permitted variation; the same
/// bound applies to the requery marks).
pub const query_jitter_max_pct: u64 = 2;

/// Requery marks as a percentage of a record's TTL (RFC 6762 section 5.2:
/// 80, 85, 90 and 95 %). Each mark also gets `+0-2 %` of the TTL as
/// jitter; see `requeryMarkUs`.
pub const requery_marks_pct = [_]u64{ 80, 85, 90, 95 };

/// Number of requery marks per record.
pub const requery_mark_count: u32 = requery_marks_pct.len;

/// Maximum requery jitter, in percent of the TTL (RFC 6762 section 5.2).
pub const requery_jitter_max_pct: u64 = 2;

/// One day in microseconds: the window the flood tests budget over.
pub const day_us: u64 = s(24 * 3600);

/// Queries the section 5.2 ladder sends per interface in 24 h: 0, 1, 3,
/// 7, ..., 4095 s (13 queries while doubling) and then one per 3600 s (22
/// more). Derived at comptime from `queryIntervalUs`; the test `query
/// schedule ladder sums to 35 queries in 24h` pins it.
pub const query_schedule_24h_count: u32 = queryScheduleCount(day_us);

/// Budget for the flood test: the ladder count plus one for jitter and
/// boundary effects (plan section 4.4: 36).
pub const query_schedule_24h_budget: u32 = query_schedule_24h_count + 1;

// ---- responder: answering ---------------------------------------------

/// Lower bound of the random delay before a shared-record answer
/// (RFC 6762 section 6: 20-120 ms).
pub const answer_delay_min_us: u64 = ms(20);

/// Upper bound of the random delay before a shared-record answer
/// (RFC 6762 section 6: 20-120 ms).
pub const answer_delay_max_us: u64 = ms(120);

/// Lower bound of the delay before answering a query whose TC bit was set,
/// so the querier's continuation packets arrive first (RFC 6762
/// section 6: 400-500 ms).
pub const answer_delay_tc_min_us: u64 = ms(400);

/// Upper bound of the delay after a TC query (RFC 6762 section 6).
pub const answer_delay_tc_max_us: u64 = ms(500);

/// Minimum spacing between multicasts of the same record on the same
/// interface (RFC 6762 section 6: "MUST NOT multicast a record ... more
/// than once per second"). Probe defence is exempt (section 6, last
/// paragraph on defending).
pub const record_rate_limit_us: u64 = s(1);

/// Minimum spacing between multicasts of the same record on the same
/// interface when defending a probe (RFC 6762 section 6, last paragraph
/// on defending: exempt from the one-second rule, but "only required to
/// delay its transmission as necessary to ensure an interval of at least
/// 250 ms since the last time the record was multicast on that
/// interface"). Bounds the amplification a probe flood can extract.
pub const defence_rate_limit_us: u64 = ms(250);

/// Window after a QU query in which a unicast response is ours
/// (RFC 6762 sections 5.4 and 6; plan section 4.8 port-sharing rule:
/// 2 s).
pub const qu_unicast_window_us: u64 = s(2);

/// A QU query gets a unicast reply unless the record was not multicast
/// within the last quarter of its TTL (RFC 6762 section 5.4). Divisor of
/// the TTL for that check.
pub const qu_multicast_ttl_divisor: u32 = 4;

/// Known-answer records at or past this fraction of their TTL are omitted
/// from the KA list (RFC 6762 section 7.1: "less than half the original
/// TTL remaining"; plan section 4.4 fixes the boundary as "at or past
/// TTL/2"). See `kaOmit`.
pub const ka_half_ttl_divisor: u32 = 2;

// ---- cache: flush, goodbye, expiry ------------------------------------

/// Cache-flush grace: on a cache-flush answer, other records of the same
/// RRSet are flushed only when they are older than this (RFC 6762
/// section 10.2: 1 s).
pub const cache_flush_grace_us: u64 = s(1);

/// Goodbye grace: a record announced with TTL 0 is treated as expiring
/// this long from now, not immediately (RFC 6762 section 10.1: 1 s).
pub const goodbye_grace_us: u64 = s(1);

// ---- responder: conflicts ---------------------------------------------

/// Conflict count that triggers the rate limit (RFC 6762 section 9:
/// "fifteen conflicts within any ten-second period").
pub const conflict_backoff_count: u32 = 15;

/// Window over which conflicts are counted (RFC 6762 section 9: 10 s).
pub const conflict_backoff_window_us: u64 = s(10);

/// Delay before the next probe once the count is hit (RFC 6762
/// section 9: "at least five seconds").
pub const conflict_backoff_delay_us: u64 = s(5);

// ---- own-echo recognition ---------------------------------------------

/// A datagram matches the echo ring only within this window after it was
/// sent (plan section 4.8, own-echo rule: 2 s).
pub const echo_window_us: u64 = s(2);

// ---- jitter and schedule helpers --------------------------------------

/// A uniform draw in `[min_us, max_us]` from the injected `random`.
pub fn drawRange(random: std.Random, min_us: u64, max_us: u64) u64 {
    std.debug.assert(min_us <= max_us);
    return random.intRangeAtMost(u64, min_us, max_us);
}

/// `base_us` plus `0..max_pct` percent of it, drawn from `random`.
/// The jitter is never negative, so a schedule only stretches (RFC 6762
/// section 5.2).
pub fn jitterPct(random: std.Random, base_us: u64, max_pct: u64) u64 {
    const span = (base_us / 100) * max_pct;
    return base_us + random.uintAtMost(u64, span);
}

/// Delay before a question's first query (RFC 6762 section 5.2).
pub fn queryFirstDelayUs(random: std.Random) u64 {
    return drawRange(random, query_first_delay_min_us, query_first_delay_max_us);
}

/// Delay before the first probe (RFC 6762 section 8.1).
pub fn probeFirstDelayUs(random: std.Random) u64 {
    return drawRange(random, probe_first_delay_min_us, probe_first_delay_max_us);
}

/// Shared-record answer delay (RFC 6762 section 6); `after_tc` selects
/// the 400-500 ms window used after a truncated query.
pub fn answerDelayUs(random: std.Random, after_tc: bool) u64 {
    return if (after_tc)
        drawRange(random, answer_delay_tc_min_us, answer_delay_tc_max_us)
    else
        drawRange(random, answer_delay_min_us, answer_delay_max_us);
}

/// Interval before query number `step + 1` of a question, without
/// jitter: `step` 0 is the gap between the first and second query (1 s),
/// each later step doubles, capped at 60 min (RFC 6762 section 5.2).
pub fn queryIntervalUs(step: u32) u64 {
    // 2^step seconds; past 2^62 the shift would overflow, and the cap
    // is reached long before that.
    if (step >= 32) return query_interval_cap_us;
    const raw = query_interval_first_us << @intCast(step);
    return @min(raw, query_interval_cap_us);
}

/// The next interval after `prev_us`: doubled and capped (RFC 6762
/// section 5.2). Starting from 0 yields the first interval.
pub fn nextQueryIntervalUs(prev_us: u64) u64 {
    if (prev_us == 0) return query_interval_first_us;
    const doubled = prev_us *| 2;
    return @min(doubled, query_interval_cap_us);
}

/// Number of queries the unjittered ladder sends in `[0, window_us)`:
/// one at 0, then at each accumulated interval. Runs at comptime for the
/// budget constants.
pub fn queryScheduleCount(window_us: u64) u32 {
    var count: u32 = 0;
    var t: u64 = 0;
    var step: u32 = 0;
    while (t < window_us) : (step += 1) {
        count += 1;
        t += queryIntervalUs(step);
    }
    return count;
}

/// Absolute time of requery mark `index` (0..3) for a record received at
/// `received_us` with TTL `ttl_s`: 80/85/90/95 % of the TTL plus a
/// uniform 0-2 % of the TTL (RFC 6762 section 5.2). Saturates at the end
/// of the clock. The cache's `scheduleRequery` calls it.
pub fn requeryMarkUs(random: std.Random, received_us: u64, ttl_s: u32, index: u32) u64 {
    std.debug.assert(index < requery_mark_count);
    const ttl_us = s(ttl_s);
    const base = (ttl_us / 100) * requery_marks_pct[index];
    const jitter = random.uintAtMost(u64, (ttl_us / 100) * requery_jitter_max_pct);
    return received_us +| base +| jitter;
}

/// Absolute expiry of a record received at `received_us` with TTL
/// `ttl_s` (RFC 6762 section 10). A TTL of 0 is a goodbye: it expires
/// after `goodbye_grace_us` (section 10.1). Saturates at the end of the
/// clock. The cache's `fill` calls it.
pub fn expiryUs(received_us: u64, ttl_s: u32) u64 {
    if (ttl_s == 0) return received_us +| goodbye_grace_us;
    return received_us +| s(ttl_s);
}

/// Known-answer rule (RFC 6762 section 7.1): a cached record is omitted
/// from the known-answer list once it has "less than half the original
/// TTL remaining". Plan section 4.4 (`ka_half_ttl`) pins the boundary as
/// "at or past TTL/2": at exactly half the record is omitted, one
/// microsecond earlier it is listed. Returns true when the record must
/// be omitted. `Entry.pastHalfTtl` calls it.
pub fn kaOmit(received_us: u64, ttl_s: u32, now_us: u64) bool {
    const age_us = now_us -| received_us;
    return age_us >= s(ttl_s) / ka_half_ttl_divisor;
}

/// QU rule (RFC 6762 section 5.4): reply by multicast instead of unicast
/// when the record was not multicast within the last quarter of its TTL.
/// `last_multicast_us == null` means never multicast. The M4 responder
/// calls it (plan section 4.8 "QU replies").
pub fn quReplyMulticast(last_multicast_us: ?u64, ttl_s: u32, now_us: u64) bool {
    const last = last_multicast_us orelse return true;
    const age_us = now_us -| last;
    return age_us >= s(ttl_s) / qu_multicast_ttl_divisor;
}

// ---- DeadlineSet ------------------------------------------------------

/// A fixed-capacity min-structure over `(deadline_us, tag)`. `Tag` is a
/// small value type the owner defines (an enum, or a tagged union with an
/// index payload); `removeAll` compares tags with `std.meta.eql`.
///
/// Equal deadlines pop in insertion order. No allocation: the storage is
/// inline, and `insert` on a full set returns `error.Full`.
pub fn DeadlineSet(comptime Tag: type, comptime cap: usize) type {
    return struct {
        const Self = @This();

        pub const capacity = cap;
        pub const TagType = Tag;

        pub const Entry = struct {
            deadline_us: u64,
            tag: Tag,
        };

        const Node = struct {
            deadline_us: u64,
            seq: u64,
            tag: Tag,

            fn before(a: Node, b: Node) bool {
                if (a.deadline_us != b.deadline_us) return a.deadline_us < b.deadline_us;
                return a.seq < b.seq;
            }
        };

        /// Binary min-heap; `heap[0]` is the soonest.
        heap: [cap]Node = undefined,
        len: usize = 0,
        next_seq: u64 = 0,

        pub const empty: Self = .{};

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        pub fn isEmpty(self: *const Self) bool {
            return self.len == 0;
        }

        pub fn isFull(self: *const Self) bool {
            return self.len == cap;
        }

        pub fn clear(self: *Self) void {
            self.len = 0;
        }

        /// Add one deadline. A full set returns `error.Full`; nothing is
        /// dropped.
        pub fn insert(self: *Self, deadline_us: u64, tag: Tag) error{Full}!void {
            if (self.len >= cap) return error.Full;
            const i = self.len;
            self.heap[i] = .{ .deadline_us = deadline_us, .seq = self.next_seq, .tag = tag };
            self.next_seq += 1;
            self.len += 1;
            self.siftUp(i);
        }

        /// Remove every entry whose tag equals `tag`. Returns how many
        /// were removed.
        pub fn removeAll(self: *Self, tag: Tag) usize {
            var kept: usize = 0;
            var i: usize = 0;
            while (i < self.len) : (i += 1) {
                if (std.meta.eql(self.heap[i].tag, tag)) continue;
                self.heap[kept] = self.heap[i];
                kept += 1;
            }
            const removed = self.len - kept;
            if (removed != 0) {
                self.len = kept;
                self.heapify();
            }
            return removed;
        }

        /// Replace every deadline carrying `tag` with a single new one.
        pub fn reschedule(self: *Self, deadline_us: u64, tag: Tag) error{Full}!void {
            _ = self.removeAll(tag);
            return self.insert(deadline_us, tag);
        }

        /// True when some entry carries `tag`.
        pub fn contains(self: *const Self, tag: Tag) bool {
            for (self.heap[0..self.len]) |n| {
                if (std.meta.eql(n.tag, tag)) return true;
            }
            return false;
        }

        /// The soonest entry without removing it.
        pub fn peek(self: *const Self) ?Entry {
            if (self.len == 0) return null;
            const n = self.heap[0];
            return .{ .deadline_us = n.deadline_us, .tag = n.tag };
        }

        /// The soonest deadline, or null when empty. This is what
        /// `Engine.nextDeadline` reports.
        pub fn soonestUs(self: *const Self) ?u64 {
            if (self.len == 0) return null;
            return self.heap[0].deadline_us;
        }

        /// Remove and return the soonest entry, or null when empty.
        pub fn pop(self: *Self) ?Entry {
            if (self.len == 0) return null;
            const n = self.heap[0];
            self.len -= 1;
            if (self.len != 0) {
                self.heap[0] = self.heap[self.len];
                self.siftDown(0);
            }
            return .{ .deadline_us = n.deadline_us, .tag = n.tag };
        }

        /// Remove and return the soonest entry if its deadline is at or
        /// before `now_us`.
        pub fn popIfDue(self: *Self, now_us: u64) ?Entry {
            if (self.len == 0) return null;
            if (self.heap[0].deadline_us > now_us) return null;
            return self.pop();
        }

        /// Iterator that pops entries due at `now_us`, soonest first.
        /// Each `next` looks at the live set, so a deadline inserted at
        /// or before `now_us` while iterating is also popped: a caller
        /// that re-arms a due timer at `now_us` inside the loop must
        /// bound its own loop.
        pub const DueIterator = struct {
            set: *Self,
            now_us: u64,

            pub fn next(it: *DueIterator) ?Entry {
                return it.set.popIfDue(it.now_us);
            }
        };

        pub fn popDue(self: *Self, now_us: u64) DueIterator {
            return .{ .set = self, .now_us = now_us };
        }

        fn siftUp(self: *Self, start: usize) void {
            var i = start;
            while (i > 0) {
                const parent = (i - 1) / 2;
                if (!self.heap[i].before(self.heap[parent])) return;
                std.mem.swap(Node, &self.heap[i], &self.heap[parent]);
                i = parent;
            }
        }

        fn siftDown(self: *Self, start: usize) void {
            var i = start;
            while (true) {
                const l = 2 * i + 1;
                const r = l + 1;
                var m = i;
                if (l < self.len and self.heap[l].before(self.heap[m])) m = l;
                if (r < self.len and self.heap[r].before(self.heap[m])) m = r;
                if (m == i) return;
                std.mem.swap(Node, &self.heap[i], &self.heap[m]);
                i = m;
            }
        }

        fn heapify(self: *Self) void {
            if (self.len < 2) return;
            var i = self.len / 2;
            while (i > 0) {
                i -= 1;
                self.siftDown(i);
            }
        }
    };
}

// ---- tests ------------------------------------------------------------

const TestTag = union(enum) {
    probe: u8,
    announce: u8,
    query: u16,
    grace,
};

const TestSet = DeadlineSet(TestTag, 8);

test "DeadlineSet pops in deadline order regardless of insert order" {
    var set: TestSet = .empty;
    try set.insert(300, .{ .query = 3 });
    try set.insert(100, .{ .query = 1 });
    try set.insert(200, .{ .query = 2 });
    try set.insert(50, .grace);
    try testing.expectEqual(@as(usize, 4), set.count());
    try testing.expectEqual(@as(?u64, 50), set.soonestUs());

    const p = set.peek().?;
    try testing.expectEqual(@as(u64, 50), p.deadline_us);
    try testing.expectEqual(TestTag.grace, p.tag);
    try testing.expectEqual(@as(usize, 4), set.count());

    try testing.expectEqual(@as(u64, 50), set.pop().?.deadline_us);
    try testing.expectEqual(@as(u64, 100), set.pop().?.deadline_us);
    try testing.expectEqual(@as(u64, 200), set.pop().?.deadline_us);
    try testing.expectEqual(@as(u64, 300), set.pop().?.deadline_us);
    try testing.expect(set.pop() == null);
    try testing.expect(set.peek() == null);
    try testing.expect(set.soonestUs() == null);
}

test "DeadlineSet removeAll by tag keeps the rest ordered" {
    var set: TestSet = .empty;
    try set.insert(10, .{ .probe = 1 });
    try set.insert(20, .{ .query = 7 });
    try set.insert(30, .{ .probe = 1 });
    try set.insert(40, .{ .probe = 2 });
    try set.insert(5, .{ .probe = 1 });

    try testing.expect(set.contains(.{ .probe = 1 }));
    try testing.expectEqual(@as(usize, 3), set.removeAll(.{ .probe = 1 }));
    try testing.expect(!set.contains(.{ .probe = 1 }));
    try testing.expectEqual(@as(usize, 0), set.removeAll(.{ .probe = 1 }));
    try testing.expectEqual(@as(usize, 2), set.count());

    // A different payload of the same union variant is a different tag.
    try testing.expect(set.contains(.{ .probe = 2 }));
    try testing.expectEqual(@as(u64, 20), set.pop().?.deadline_us);
    try testing.expectEqual(@as(u64, 40), set.pop().?.deadline_us);
    try testing.expect(set.isEmpty());
}

test "DeadlineSet reschedule replaces every deadline of the tag" {
    var set: TestSet = .empty;
    try set.insert(10, .{ .query = 1 });
    try set.insert(20, .{ .query = 1 });
    try set.insert(15, .{ .query = 2 });
    try set.reschedule(99, .{ .query = 1 });
    try testing.expectEqual(@as(usize, 2), set.count());
    try testing.expectEqual(@as(u64, 15), set.pop().?.deadline_us);
    const e = set.pop().?;
    try testing.expectEqual(@as(u64, 99), e.deadline_us);
    try testing.expectEqual(TestTag{ .query = 1 }, e.tag);
}

test "DeadlineSet popDue pops equal deadlines in insertion order and stops at the future" {
    var set: TestSet = .empty;
    try set.insert(100, .{ .announce = 3 });
    try set.insert(100, .{ .announce = 1 });
    try set.insert(100, .{ .announce = 2 });
    try set.insert(101, .{ .announce = 9 });
    try set.insert(100, .grace);

    var it = set.popDue(100);
    try testing.expectEqual(TestTag{ .announce = 3 }, it.next().?.tag);
    try testing.expectEqual(TestTag{ .announce = 1 }, it.next().?.tag);
    try testing.expectEqual(TestTag{ .announce = 2 }, it.next().?.tag);
    try testing.expectEqual(TestTag.grace, it.next().?.tag);
    try testing.expect(it.next() == null);
    try testing.expect(it.next() == null);
    try testing.expectEqual(@as(usize, 1), set.count());
    try testing.expectEqual(@as(?u64, 101), set.soonestUs());

    // Nothing is due before its deadline.
    try testing.expect(set.popIfDue(100) == null);
    var later = set.popDue(101);
    try testing.expectEqual(TestTag{ .announce = 9 }, later.next().?.tag);
    try testing.expect(set.isEmpty());
}

test "DeadlineSet insert when full returns error.Full and drops nothing" {
    var set: DeadlineSet(u8, 3) = .empty;
    try set.insert(3, 3);
    try set.insert(1, 1);
    try set.insert(2, 2);
    try testing.expect(set.isFull());
    try testing.expectError(error.Full, set.insert(0, 0));
    try testing.expectError(error.Full, set.reschedule(0, 9));
    try testing.expectEqual(@as(usize, 3), set.count());
    try testing.expectEqual(@as(u64, 1), set.pop().?.deadline_us);
    try testing.expectEqual(@as(u64, 2), set.pop().?.deadline_us);
    try testing.expectEqual(@as(u64, 3), set.pop().?.deadline_us);

    // reschedule on a full set of the same tag still fits.
    try set.insert(5, 5);
    try set.insert(6, 6);
    try set.insert(7, 7);
    try set.reschedule(1, 7);
    try testing.expectEqual(@as(u64, 1), set.pop().?.deadline_us);
}

test "DeadlineSet heap stays ordered under a random workload" {
    var prng = std.Random.DefaultPrng.init(0x6d646e73);
    const random = prng.random();
    var set: DeadlineSet(u16, 64) = .empty;
    var round: usize = 0;
    while (round < 200) : (round += 1) {
        var n: usize = 0;
        while (n < 48) : (n += 1) {
            try set.insert(random.uintAtMost(u64, 1000), random.uintAtMost(u16, 15));
        }
        _ = set.removeAll(random.uintAtMost(u16, 15));
        var last: u64 = 0;
        while (set.pop()) |e| {
            try testing.expect(e.deadline_us >= last);
            last = e.deadline_us;
        }
    }
}

test "query schedule ladder sums to 35 queries in 24h" {
    // 0, 1, 3, 7, ..., 4095 s: 13 queries while doubling.
    try testing.expectEqual(s(1), queryIntervalUs(0));
    try testing.expectEqual(s(2), queryIntervalUs(1));
    try testing.expectEqual(s(2048), queryIntervalUs(11));
    try testing.expectEqual(s(3600), queryIntervalUs(12));
    try testing.expectEqual(s(3600), queryIntervalUs(40));
    var t: u64 = 0;
    var step: u32 = 0;
    while (step < 12) : (step += 1) t += queryIntervalUs(step);
    try testing.expectEqual(s(4095), t);
    // Then one per 3600 s until 86400 s: (86400 - 4095) / 3600 = 22 more.
    try testing.expectEqual(@as(u32, 13 + 22), queryScheduleCount(day_us));
    try testing.expectEqual(@as(u32, 35), query_schedule_24h_count);
    try testing.expectEqual(@as(u32, 36), query_schedule_24h_budget);

    // The interval-based form agrees with the step form.
    var prev: u64 = 0;
    step = 0;
    while (step < 20) : (step += 1) {
        prev = nextQueryIntervalUs(prev);
        try testing.expectEqual(queryIntervalUs(step), prev);
    }
}

test "jitter draws stay inside their RFC bounds" {
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        const q = queryFirstDelayUs(random);
        try testing.expect(q >= ms(20) and q <= ms(120));
        const p = probeFirstDelayUs(random);
        try testing.expect(p <= ms(250));
        const a = answerDelayUs(random, false);
        try testing.expect(a >= ms(20) and a <= ms(120));
        const tc = answerDelayUs(random, true);
        try testing.expect(tc >= ms(400) and tc <= ms(500));
        const j = jitterPct(random, s(100), query_jitter_max_pct);
        try testing.expect(j >= s(100) and j <= s(102));
        const m = requeryMarkUs(random, 1000, 4500, 2);
        try testing.expect(m >= 1000 + s(4500) * 90 / 100);
        try testing.expect(m <= 1000 + s(4500) * 92 / 100);
    }
}

test "expiry goodbye and known-answer helpers" {
    try testing.expectEqual(s(120) + 7, expiryUs(7, 120));
    try testing.expectEqual(goodbye_grace_us + 7, expiryUs(7, 0));
    // The end of the clock saturates instead of wrapping.
    const late = std.math.maxInt(u64) - 1;
    try testing.expectEqual(std.math.maxInt(u64), expiryUs(late, 120));
    try testing.expectEqual(std.math.maxInt(u64), expiryUs(late, 0));
    var prng = std.Random.DefaultPrng.init(9);
    try testing.expectEqual(std.math.maxInt(u64), requeryMarkUs(prng.random(), late, 4500, 3));

    // KA: omit at or past TTL/2.
    try testing.expect(!kaOmit(0, 120, s(59)));
    try testing.expect(kaOmit(0, 120, s(60)));
    try testing.expect(kaOmit(0, 120, s(300)));
    // Clock skew (received after now) reads as age 0.
    try testing.expect(!kaOmit(s(5), 120, 0));

    // QU: multicast when never multicast, or not within TTL/4.
    try testing.expect(quReplyMulticast(null, 120, s(1)));
    try testing.expect(!quReplyMulticast(0, 120, s(29)));
    try testing.expect(quReplyMulticast(0, 120, s(30)));
}

test "constant table matches plan section 4.4" {
    try testing.expectEqual(@as(u32, 120), ttl_host_s);
    try testing.expectEqual(@as(u32, 4500), ttl_other_s);
    try testing.expectEqual(@as(u32, 10), ttl_legacy_cap_s);
    try testing.expectEqual(ms(250), probe_first_delay_max_us);
    try testing.expectEqual(ms(250), probe_interval_us);
    try testing.expectEqual(@as(u32, 3), probe_count);
    try testing.expectEqual(s(1), probe_tiebreak_wait_us);
    try testing.expectEqual(s(1), announce_interval_us);
    try testing.expectEqual(@as(u32, 2), announce_count);
    try testing.expectEqual(s(1), record_rate_limit_us);
    try testing.expectEqual(s(1), cache_flush_grace_us);
    try testing.expectEqual(s(1), goodbye_grace_us);
    try testing.expectEqual(@as(u32, 15), conflict_backoff_count);
    try testing.expectEqual(s(10), conflict_backoff_window_us);
    try testing.expectEqual(s(5), conflict_backoff_delay_us);
    try testing.expectEqual(s(2), qu_unicast_window_us);
    try testing.expectEqual(s(2), echo_window_us);
    try testing.expectEqual(@as(u32, 4), requery_mark_count);
}
