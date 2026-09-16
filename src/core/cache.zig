//! Record cache for the querier (plan section 4.5 "cache model", section
//! 6 `core/cache.zig`): a preallocated pool of resource records keyed by
//! `(name, type, class, ifindex)`, with the RFC 6762 rules that act on
//! cached records:
//!
//! - section 10.2 cache-flush: a record with the cache-flush bit marks
//!   every other record of the same key that was received more than 1 s
//!   ago to expire in 1 s; younger records are kept (they may be part of
//!   the same burst). The key includes the arrival interface, so a
//!   cache-flush answer heard on one interface never flushes what was
//!   heard on another: a multi-homed responder MUST answer on each
//!   interface with only that interface's addresses (section 6.2) and a
//!   multihomed querier keeps the results of each link apart (section
//!   14; mDNSResponder does the same, one `dns-sd -B` row per
//!   interface). Merging them would make every interface's answer flush
//!   the others' addresses in turn (the M3 gate "resolved flicker");
//! - section 10.1 goodbye: a record with TTL 0 is recorded with a TTL of
//!   1 s and removed one second later, so a cooperating responder has
//!   time to defend it;
//! - section 5.2 cache maintenance: a record a client cares about is
//!   re-queried at 80, 85, 90 and 95 % of its TTL, each mark plus a
//!   random 0-2 % of the TTL (`scheduleRequery`);
//! - section 7.1 known-answer half-TTL rule (`Entry.pastHalfTtl`).
//!
//! Names compare ASCII case-insensitively (RFC 6762 section 16). Records
//! with the same key form one RRSet: `lookupOn` walks it, `upsert`
//! updates one member in place, so the order of records inside a packet
//! does not matter (hashicorp/mdns #145, #92). `lookup` walks the RRSets
//! of every interface for `(name, type, class)` (they share one bucket
//! chain: the hash leaves the interface out). A record heard on k
//! interfaces costs k entries; size `max_cache_records` as interfaces x
//! records per instance x instances. An arrival interface of 0 (a
//! platform that reports none) is a scope of its own.
//!
//! Allocation happens once, in `init`; `upsert`, `lookup`, `expireDue`
//! and every other call after that never allocate and never fail with
//! OOM. When the pool is full, `upsert` evicts the used entry with the
//! soonest expiry among those not `pinned` (the querier pins the records
//! backing an active browse, plan section 4.5) and counts it in
//! `stats.evictions`. When every entry is pinned the soonest-expiring
//! pinned entry goes instead (`stats.evictions_pinned`), so a full pool
//! of browse data can never wedge a browse. Every eviction is reported
//! through the caller's `EvictHook` before the entry is unlinked, so the
//! querier can drop resolve state exactly as it does on expiry. Both
//! scans are O(entries) with no callback per candidate.
//!
//! Bucket indexes mix the public `Name.hash` with a per-cache secret seed
//! drawn at `init`, so a peer cannot precompute names that share a bucket
//! and turn every lookup into a chain walk (SECURITY.md posture).
//!
//! The cache never touches a clock or a socket: time is the caller's
//! `now_us`, randomness the caller's `std.Random`.
const std = @import("std");
const wire = @import("../wire/root.zig");
const timers = @import("timers.zig");

pub const Name = wire.Name;
pub const RType = wire.RType;

// ---- constants -------------------------------------------------------
//
// Aliases of the `core/timers.zig` table (plan section 4.4) that the
// cache applies; `timers.zig` is the single source of every RFC constant.

/// RFC 6762 section 10.2: records of the same key received more than
/// this long ago are flushed when a cache-flush record arrives, and they
/// expire this long after the flush.
pub const cache_flush_grace_us: u64 = timers.cache_flush_grace_us;

/// RFC 6762 section 10.1: a TTL-0 goodbye is recorded with a TTL of one
/// second and deleted after it.
pub const goodbye_grace_us: u64 = timers.goodbye_grace_us;

/// RFC 6762 section 5.2: percentages of the TTL at which a record of
/// interest is re-queried.
pub const requery_marks_percent = timers.requery_marks_pct;

/// RFC 6762 section 5.2: random variation of 0-2 % of the TTL added to
/// every mark so queriers do not synchronise.
pub const requery_jitter_percent: u64 = timers.requery_jitter_max_pct;

/// Largest rdata an entry stores. TXT is capped at 400 octets on both
/// sides (plan section 4.5). SRV (6 + 255), PTR (255), NSEC (255 + 2 +
/// 32), A and AAAA all fit. A TXT over the cap is truncated to whole
/// strings and counted; any other type over the cap is rejected.
pub const max_rdata_len: usize = wire.txt.max_len;

comptime {
    std.debug.assert(wire.rdata.max_name_rdata_len <= max_rdata_len);
}

/// Index sentinel for the intrusive lists.
const none: u32 = std.math.maxInt(u32);

// ---- types -----------------------------------------------------------

/// Per-entry state bits.
pub const Flags = packed struct {
    /// The last record that refreshed this entry carried the cache-flush
    /// bit (section 10.2): the RRSet is unique on the responder's side.
    cache_flush_seen: bool = false,
    /// A goodbye (TTL 0) was received; the entry expires at
    /// `expires_us` and is not a live record any more (section 10.1).
    goodbye_pending: bool = false,
    /// A cache-flush record for the same key superseded this entry; it
    /// expires at `expires_us` (section 10.2).
    flush_pending: bool = false,
    /// Eviction guard (plan section 4.5): the querier sets it on the
    /// records an active browse consumes (its PTRs, the SRV/TXT the
    /// resolve join used, the A/AAAA it listed) and clears it when the
    /// browse or the instance goes away. `takeSlot` evicts pinned entries
    /// only when nothing else is left. A refresh keeps the bit; a new
    /// entry starts unpinned.
    pinned: bool = false,
};

/// One cached resource record. Values are owned copies; nothing points
/// into a packet.
pub const Entry = struct {
    name: Name,
    rtype: RType,
    /// Class with the cache-flush bit stripped.
    class: u16,
    /// TTL as received (1 for a goodbye).
    ttl_s: u32,
    /// When the record was last received or refreshed.
    received_us: u64,
    /// When the record leaves the cache: `received_us + ttl`, or the 1 s
    /// grace after a goodbye or a cache-flush.
    expires_us: u64,
    ifindex: u32,
    flags: Flags,
    /// Requery state (section 5.2). `next_requery_us` is null until the
    /// querier calls `scheduleRequery`; `upsert` clears it on every
    /// refresh so the caller re-plans from the new TTL.
    requery_idx: u8,
    next_requery_us: ?u64,
    rdata_len: u16,
    rdata: [max_rdata_len]u8,

    // intrusive chain through the hash bucket
    next_in_bucket: u32,
    used: bool,

    pub fn rdataSlice(e: *const Entry) []const u8 {
        return e.rdata[0..e.rdata_len];
    }

    /// True when the full key `(name, rtype, class, ifindex)` matches,
    /// name case folded.
    pub fn keyEql(e: *const Entry, name: *const Name, rtype: RType, class: u16, ifindex: u32) bool {
        return e.ifindex == ifindex and e.rrsetEql(name, rtype, class);
    }

    /// True when `(name, rtype, class)` matches on any interface.
    pub fn rrsetEql(e: *const Entry, name: *const Name, rtype: RType, class: u16) bool {
        return e.rtype == rtype and e.class == class and e.name.eql(name);
    }

    /// A live record: not a goodbye and not flushed (an expiring record
    /// is still in the cache but should not be reported or listed as a
    /// known answer).
    pub fn isLive(e: *const Entry) bool {
        return !e.flags.goodbye_pending and !e.flags.flush_pending;
    }

    /// Remaining lifetime in whole seconds at `now_us`, saturating at 0.
    pub fn remainingTtlS(e: *const Entry, now_us: u64) u32 {
        if (e.expires_us <= now_us) return 0;
        const rem_s = (e.expires_us - now_us) / std.time.us_per_s;
        return @intCast(@min(rem_s, std.math.maxInt(u32)));
    }

    /// RFC 6762 section 7.1: a known answer is omitted from a query when
    /// at or past half its original TTL (`timers.kaOmit`; plan section
    /// 4.4 `ka_half_ttl`).
    pub fn pastHalfTtl(e: *const Entry, now_us: u64) bool {
        return timers.kaOmit(e.received_us, e.ttl_s, now_us);
    }
};

/// A record as the querier hands it to `upsert`: a parsed and expanded
/// (compression-free) record. `class` must have the cache-flush bit
/// stripped; the bit goes in `upsert`'s `cache_flush` argument.
pub const Record = struct {
    name: Name,
    rtype: RType,
    class: u16,
    ttl_s: u32,
    /// Uncompressed rdata (`wire.rdata.canonicalRdata`).
    rdata: []const u8,
    ifindex: u32,
};

pub const Outcome = enum {
    /// A new entry was created.
    added,
    /// The same record (key and rdata) was already cached but was
    /// pending removal (goodbye or flush); it is live again.
    updated,
    /// The same record was already cached and live on that interface;
    /// its TTL, `received_us` and `cache_flush_seen` were refreshed.
    unchanged,
    /// A TTL-0 goodbye: the matching entry (if any) now expires in 1 s.
    goodbye,
    /// Not cached: rdata over the cap for a non-TXT type or a malformed
    /// TXT (or, defensively, a full pool that yielded no victim).
    rejected,
};

pub const UpsertResult = struct {
    outcome: Outcome,
    /// Same-key (same interface) entries marked to expire by the section
    /// 10.2 rule.
    flushed_count: u32 = 0,
    /// A TXT rdata was cut to whole strings within 400 octets.
    truncated: bool = false,
    /// An entry was evicted to make room.
    evicted: bool = false,
    /// The evicted entry was pinned (every entry was).
    evicted_pinned: bool = false,
    /// Pool index of the entry the record maps to; null on `rejected`
    /// and on a goodbye for a record that was not cached.
    index: ?u32 = null,
};

/// Eviction notice: `upsert` calls `f(ctx, entry)` for the entry it is
/// about to evict, while it is still linked (the querier drops resolve
/// state there, as in `expireDue`). Type erased so the querier can pass
/// itself without generics; `.none` for callers without state.
pub const EvictHook = struct {
    ctx: ?*anyopaque = null,
    f: ?*const fn (?*anyopaque, *const Entry) void = null,

    pub const none: EvictHook = .{};

    pub fn call(h: EvictHook, e: *const Entry) void {
        const f = h.f orelse return;
        f(h.ctx, e);
    }
};

/// Cache-local counters; the Engine folds them into its `Stats`.
pub const Stats = struct {
    /// Entries removed to make room for a new record (pinned ones
    /// included).
    evictions: u64 = 0,
    /// Evictions that had to take a pinned entry because every entry was
    /// pinned (a pool full of records the browses consume).
    evictions_pinned: u64 = 0,
    /// Received TXT rdata over 400 octets, truncated (plan section 4.5).
    txt_truncated: u64 = 0,
    /// Non-TXT rdata over the cap, or a TXT with a bad length prefix.
    rejected_oversize: u64 = 0,
    /// A full pool yielded no victim. Cannot happen (a full pool always
    /// has a soonest-expiring entry); counted, never trapped.
    rejected_full: u64 = 0,
};

fn ttlUs(ttl_s: u32) u64 {
    return @as(u64, ttl_s) * std.time.us_per_s;
}

// ---- the cache -------------------------------------------------------

pub const Cache = struct {
    entries: []Entry,
    /// Head entry index per hash bucket, or `none`. Power-of-two length.
    buckets: []u32,
    /// Stack of free entry indexes.
    free: []u32,
    free_len: usize,
    used_count: usize,
    /// Secret bucket-index seed (see the module doc).
    seed: u64,
    stats: Stats,

    pub const InitError = error{OutOfMemory};

    /// Preallocate `max_records` entries (at least 1) and the bucket
    /// index. The only allocation this module makes. `seed` should come
    /// from the injected `std.Random` (tests pass a constant).
    pub fn init(gpa: std.mem.Allocator, max_records: u32, seed: u64) InitError!Cache {
        const n: usize = @max(@as(usize, max_records), 1);
        const entries = try gpa.alloc(Entry, n);
        errdefer gpa.free(entries);
        const n_buckets = std.math.ceilPowerOfTwo(usize, @max(n * 2, 16)) catch return error.OutOfMemory;
        const buckets = try gpa.alloc(u32, n_buckets);
        errdefer gpa.free(buckets);
        const free = try gpa.alloc(u32, n);
        errdefer gpa.free(free);

        @memset(buckets, none);
        for (entries, 0..) |*e, i| {
            e.used = false;
            e.next_in_bucket = none;
            // Free stack: index n-1 on the bottom, 0 on top, so the first
            // records land in the first slots (nice for debugging).
            free[i] = @intCast(n - 1 - i);
        }
        return .{
            .entries = entries,
            .buckets = buckets,
            .free = free,
            .free_len = n,
            .used_count = 0,
            .seed = seed,
            .stats = .{},
        };
    }

    pub fn deinit(c: *Cache, gpa: std.mem.Allocator) void {
        gpa.free(c.free);
        gpa.free(c.buckets);
        gpa.free(c.entries);
        c.* = undefined;
    }

    pub fn count(c: *const Cache) usize {
        return c.used_count;
    }

    pub fn capacity(c: *const Cache) usize {
        return c.entries.len;
    }

    pub fn isFull(c: *const Cache) bool {
        return c.free_len == 0;
    }

    /// The entry at a pool index handed out by `upsert` or an iterator.
    /// Asserts the slot is in use.
    pub fn entryAt(c: *Cache, index: u32) *Entry {
        const e = &c.entries[index];
        std.debug.assert(e.used);
        return e;
    }

    // ---- hashing ------------------------------------------------------

    fn bucketOf(c: *const Cache, name: *const Name, rtype: RType, class: u16) usize {
        return bucketIndex(c.seed, name.hash(), rtype, class, c.buckets.len);
    }

    /// Bucket of a key: the public name hash, the type and the class mixed
    /// under a secret seed (a peer that knows `Name.hash` cannot aim at one
    /// bucket). `n_buckets` is a power of two.
    pub fn bucketIndex(seed: u64, name_hash: u64, rtype: RType, class: u16, n_buckets: usize) usize {
        var key: [12]u8 = undefined;
        std.mem.writeInt(u64, key[0..8], name_hash, .little);
        std.mem.writeInt(u16, key[8..10], rtype.toInt(), .little);
        std.mem.writeInt(u16, key[10..12], class, .little);
        const h = std.hash.Wyhash.hash(seed, &key);
        return @intCast(h & (n_buckets - 1));
    }

    fn findExact(c: *Cache, rec: *const Record) ?u32 {
        const b = c.bucketOf(&rec.name, rec.rtype, rec.class);
        var i = c.buckets[b];
        while (i != none) : (i = c.entries[i].next_in_bucket) {
            const e = &c.entries[i];
            if (e.keyEql(&rec.name, rec.rtype, rec.class, rec.ifindex) and
                std.mem.eql(u8, e.rdataSlice(), rec.rdata))
            {
                return i;
            }
        }
        return null;
    }

    // ---- insert / update ---------------------------------------------

    /// Apply one received record (plan section 4.5; RFC 6762 sections
    /// 10.1, 10.2). Never allocates, never fails: an unstorable record is
    /// reported as `rejected` and counted.
    ///
    /// Order of effects: (1) with `cache_flush`, every other live entry
    /// of the same key (same arrival interface) received more than 1 s
    /// ago is marked to expire 1 s from `now_us` (`flushed_count`); (2) a
    /// TTL 0 marks the matching entry (if any) as a goodbye expiring in
    /// 1 s; (3) otherwise
    /// the matching entry is refreshed, or a new one is created, evicting
    /// the soonest-expiring unpinned entry (or, with everything pinned,
    /// the soonest-expiring pinned one) when the pool is full; `on_evict`
    /// sees the victim first.
    pub fn upsert(c: *Cache, rec: Record, now_us: u64, cache_flush: bool, on_evict: EvictHook) UpsertResult {
        var result: UpsertResult = .{ .outcome = .rejected };

        // Bound the rdata first: a rejected record still must not flush
        // (a forged oversize record would otherwise be a cheap cache
        // wipe), so the size check comes before everything else.
        var rdata_buf: [max_rdata_len]u8 = undefined;
        var rdata = rec.rdata;
        if (rdata.len > max_rdata_len) {
            if (rec.rtype != .txt) {
                c.stats.rejected_oversize += 1;
                return result;
            }
            const t = wire.Txt.fromWireTruncated(rdata) catch {
                c.stats.rejected_oversize += 1;
                return result;
            };
            @memcpy(rdata_buf[0..t.txt.bytes.len], t.txt.slice());
            rdata = rdata_buf[0..t.txt.bytes.len];
            result.truncated = t.truncated;
            if (t.truncated) c.stats.txt_truncated += 1;
        }
        const bounded: Record = .{
            .name = rec.name,
            .rtype = rec.rtype,
            .class = rec.class,
            .ttl_s = rec.ttl_s,
            .rdata = rdata,
            .ifindex = rec.ifindex,
        };

        const existing = c.findExact(&bounded);

        if (cache_flush) {
            result.flushed_count = c.flushOthers(&bounded, existing, now_us);
        }

        if (rec.ttl_s == 0) {
            // Section 10.1: record a TTL of 1 and delete one second later.
            result.outcome = .goodbye;
            if (existing) |i| {
                const e = &c.entries[i];
                e.ttl_s = 1;
                e.received_us = now_us;
                e.expires_us = now_us +| goodbye_grace_us;
                e.flags.goodbye_pending = true;
                e.flags.flush_pending = false;
                if (cache_flush) e.flags.cache_flush_seen = true;
                e.requery_idx = 0;
                e.next_requery_us = null;
                result.index = i;
            }
            return result;
        }

        if (existing) |i| {
            const e = &c.entries[i];
            result.outcome = if (e.isLive()) .unchanged else .updated;
            fill(e, &bounded, now_us, cache_flush);
            result.index = i;
            return result;
        }

        const slot = c.takeSlot(on_evict) orelse {
            c.stats.rejected_full += 1;
            return result;
        };
        result.evicted = slot.evicted;
        result.evicted_pinned = slot.evicted_pinned;
        const e = &c.entries[slot.index];
        e.used = true;
        e.flags = .{};
        fill(e, &bounded, now_us, cache_flush);
        const b = c.bucketOf(&bounded.name, bounded.rtype, bounded.class);
        e.next_in_bucket = c.buckets[b];
        c.buckets[b] = slot.index;
        c.used_count += 1;
        result.outcome = .added;
        result.index = slot.index;
        return result;
    }

    /// Write a live record into `e` (new or refreshed). The pin survives a
    /// refresh: the querier re-derives it from the resolve join, and an
    /// unpinned instant inside one packet would let the packet's other
    /// records evict the very record they refresh.
    fn fill(e: *Entry, rec: *const Record, now_us: u64, cache_flush: bool) void {
        e.name = rec.name;
        e.rtype = rec.rtype;
        e.class = rec.class;
        e.ttl_s = rec.ttl_s;
        e.received_us = now_us;
        e.expires_us = timers.expiryUs(now_us, rec.ttl_s);
        e.ifindex = rec.ifindex;
        e.flags = .{ .cache_flush_seen = cache_flush, .pinned = e.flags.pinned };
        e.requery_idx = 0;
        e.next_requery_us = null;
        e.rdata_len = @intCast(rec.rdata.len);
        @memcpy(e.rdata[0..rec.rdata.len], rec.rdata);
    }

    /// Section 10.2: mark same-key entries (same name, type, class AND
    /// arrival interface) other than `keep` that were received more than
    /// 1 s ago to expire 1 s from now. Entries already due sooner keep
    /// their earlier expiry. Returns how many were newly marked. Records
    /// of the same RRSet heard on another interface are untouched (RFC
    /// 6762 sections 6.2, 14: each interface's answer is its own RRSet).
    fn flushOthers(c: *Cache, rec: *const Record, keep: ?u32, now_us: u64) u32 {
        var flushed: u32 = 0;
        const b = c.bucketOf(&rec.name, rec.rtype, rec.class);
        var i = c.buckets[b];
        while (i != none) : (i = c.entries[i].next_in_bucket) {
            if (keep != null and keep.? == i) continue;
            const e = &c.entries[i];
            if (!e.keyEql(&rec.name, rec.rtype, rec.class, rec.ifindex)) continue;
            if (e.flags.goodbye_pending or e.flags.flush_pending) continue;
            // "received more than one second ago": exactly one second is
            // not more.
            if (e.received_us +| cache_flush_grace_us >= now_us) continue;
            e.flags.flush_pending = true;
            e.expires_us = @min(e.expires_us, now_us +| cache_flush_grace_us);
            e.next_requery_us = null;
            flushed += 1;
        }
        return flushed;
    }

    const Slot = struct { index: u32, evicted: bool, evicted_pinned: bool };

    /// A free slot, evicting the soonest-expiring unpinned entry when the
    /// pool is full, or the soonest-expiring pinned one when every entry
    /// is pinned. One pass; no per-candidate callback.
    fn takeSlot(c: *Cache, on_evict: EvictHook) ?Slot {
        if (c.free_len > 0) {
            c.free_len -= 1;
            return .{ .index = c.free[c.free_len], .evicted = false, .evicted_pinned = false };
        }
        var victim: ?u32 = null;
        var victim_expires: u64 = std.math.maxInt(u64);
        var pinned_victim: ?u32 = null;
        var pinned_expires: u64 = std.math.maxInt(u64);
        for (c.entries, 0..) |*e, i| {
            if (!e.used) continue;
            if (e.flags.pinned) {
                if (e.expires_us < pinned_expires) {
                    pinned_victim = @intCast(i);
                    pinned_expires = e.expires_us;
                }
                continue;
            }
            if (e.expires_us < victim_expires) {
                victim = @intCast(i);
                victim_expires = e.expires_us;
            }
        }
        const took_pinned = victim == null;
        // The pool is full, so one of the two exists; a null here would
        // be a bookkeeping bug, reported as a rejection rather than a trap.
        const v = victim orelse pinned_victim orelse return null;
        on_evict.call(&c.entries[v]);
        c.remove(v);
        c.stats.evictions += 1;
        if (took_pinned) c.stats.evictions_pinned += 1;
        c.free_len -= 1;
        return .{ .index = c.free[c.free_len], .evicted = true, .evicted_pinned = took_pinned };
    }

    // ---- removal ------------------------------------------------------

    /// Unlink and free the entry at `index`. Asserts the slot is in use.
    /// Never call it from inside a `lookup` / `all` walk.
    pub fn remove(c: *Cache, index: u32) void {
        const e = &c.entries[index];
        std.debug.assert(e.used);
        const b = c.bucketOf(&e.name, e.rtype, e.class);
        if (c.buckets[b] == index) {
            c.buckets[b] = e.next_in_bucket;
        } else {
            var i = c.buckets[b];
            while (i != none) : (i = c.entries[i].next_in_bucket) {
                if (c.entries[i].next_in_bucket == index) {
                    c.entries[i].next_in_bucket = e.next_in_bucket;
                    break;
                }
            }
        }
        e.used = false;
        e.flags = .{};
        e.next_in_bucket = none;
        c.free[c.free_len] = index;
        c.free_len += 1;
        c.used_count -= 1;
    }

    /// Remove every entry whose `expires_us <= now_us`, calling
    /// `callback(ctx, entry)` for each one before it is unlinked (the
    /// querier emits `lost` and drops resolve state there). Returns the
    /// number removed. Never allocates.
    pub fn expireDue(c: *Cache, now_us: u64, ctx: anytype, comptime callback: fn (@TypeOf(ctx), *const Entry) void) usize {
        var removed: usize = 0;
        for (c.entries, 0..) |*e, i| {
            if (!e.used) continue;
            if (e.expires_us > now_us) continue;
            callback(ctx, e);
            c.remove(@intCast(i));
            removed += 1;
        }
        return removed;
    }

    /// Remove every entry heard on `ifindex`, calling `callback(ctx,
    /// entry)` for each one before it is unlinked, exactly as `expireDue`
    /// does (the querier emits `lost` and drops resolve state there).
    /// For an interface that left the table: its records can never be
    /// refreshed (no answer arrives with that ifindex again; answers on
    /// the surviving interfaces land in their own keys) and they would
    /// otherwise linger until their TTL, emit `lost` for an interface
    /// that vanished long before, or attach to an unrelated interface if
    /// the OS reuses the index. Returns the number removed. Never
    /// allocates.
    pub fn expireInterface(c: *Cache, ifindex: u32, ctx: anytype, comptime callback: fn (@TypeOf(ctx), *const Entry) void) usize {
        var removed: usize = 0;
        for (c.entries, 0..) |*e, i| {
            if (!e.used) continue;
            if (e.ifindex != ifindex) continue;
            callback(ctx, e);
            c.remove(@intCast(i));
            removed += 1;
        }
        return removed;
    }

    /// Remove everything. Counters are kept.
    pub fn clear(c: *Cache) void {
        for (c.entries, 0..) |*e, i| {
            if (e.used) c.remove(@intCast(i));
        }
    }

    // ---- deadlines ----------------------------------------------------

    /// Soonest `expires_us` over the cache, or null when empty. The
    /// Engine merges it into `nextDeadline`.
    pub fn nextExpiryUs(c: *const Cache) ?u64 {
        var best: ?u64 = null;
        for (c.entries) |*e| {
            if (!e.used) continue;
            if (best == null or e.expires_us < best.?) best = e.expires_us;
        }
        return best;
    }

    /// Soonest scheduled requery mark over the cache, or null when no
    /// entry has one.
    pub fn nextRequeryUs(c: *const Cache) ?u64 {
        var best: ?u64 = null;
        for (c.entries) |*e| {
            if (!e.used) continue;
            const t = e.next_requery_us orelse continue;
            if (best == null or t < best.?) best = t;
        }
        return best;
    }

    /// RFC 6762 section 5.2 cache maintenance: plan the next requery of
    /// `e` after `now_us` at the first remaining mark of 80, 85, 90 or
    /// 95 % of the TTL (from `received_us`), plus a random 0-2 % of the
    /// TTL (`timers.requeryMarkUs`). Stores it in `e.next_requery_us` and
    /// returns it. Returns null (and clears the field) when every mark
    /// has passed, the record is a goodbye or flushed, or the TTL is 0.
    /// Only call it for records a local client cares about (section 5.2
    /// MUST NOT otherwise).
    pub fn scheduleRequery(e: *Entry, now_us: u64, random: std.Random) ?u64 {
        e.next_requery_us = null;
        if (!e.isLive() or e.ttl_s == 0) return null;
        while (e.requery_idx < requery_marks_percent.len) {
            const idx = e.requery_idx;
            e.requery_idx += 1;
            const at = timers.requeryMarkUs(random, e.received_us, e.ttl_s, idx);
            if (at <= now_us) continue;
            e.next_requery_us = at;
            return at;
        }
        return null;
    }

    /// Entries whose scheduled requery is due: for each `e` with
    /// `next_requery_us <= now_us`, clears the mark and calls
    /// `callback(ctx, e)` (the querier folds the question into its next
    /// packet and calls `scheduleRequery` again). Returns the number
    /// fired.
    pub fn popDueRequeries(c: *Cache, now_us: u64, ctx: anytype, comptime callback: fn (@TypeOf(ctx), *Entry) void) usize {
        var fired: usize = 0;
        for (c.entries) |*e| {
            if (!e.used) continue;
            const t = e.next_requery_us orelse continue;
            if (t > now_us) continue;
            e.next_requery_us = null;
            callback(ctx, e);
            fired += 1;
        }
        return fired;
    }

    // ---- lookup -------------------------------------------------------

    /// Walk every entry for `(name, rtype, class)` on every interface;
    /// entries include those pending removal (check `Entry.isLive`). Do
    /// not `remove` or `upsert` during the walk.
    pub fn lookup(c: *Cache, name: *const Name, rtype: RType, class: u16) Iterator {
        return .{
            .cache = c,
            .next_index = c.buckets[c.bucketOf(name, rtype, class)],
            .name = name,
            .rtype = rtype,
            .class = class,
            .ifindex = null,
        };
    }

    /// Walk the RRSet for `(name, rtype, class)` as heard on `ifindex`.
    pub fn lookupOn(c: *Cache, name: *const Name, rtype: RType, class: u16, ifindex: u32) Iterator {
        var it = c.lookup(name, rtype, class);
        it.ifindex = ifindex;
        return it;
    }

    pub const Iterator = struct {
        cache: *Cache,
        next_index: u32,
        name: *const Name,
        rtype: RType,
        class: u16,
        /// Null: every interface.
        ifindex: ?u32,

        pub fn next(it: *Iterator) ?*Entry {
            while (it.next_index != none) {
                const e = &it.cache.entries[it.next_index];
                it.next_index = e.next_in_bucket;
                if (!e.rrsetEql(it.name, it.rtype, it.class)) continue;
                if (it.ifindex) |i| if (e.ifindex != i) continue;
                return e;
            }
            return null;
        }
    };

    /// Number of live entries for the key over every interface.
    pub fn countLive(c: *Cache, name: *const Name, rtype: RType, class: u16) usize {
        var n: usize = 0;
        var it = c.lookup(name, rtype, class);
        while (it.next()) |e| {
            if (e.isLive()) n += 1;
        }
        return n;
    }

    /// Number of live entries in the RRSet heard on `ifindex`.
    pub fn countLiveOn(c: *Cache, name: *const Name, rtype: RType, class: u16, ifindex: u32) usize {
        var n: usize = 0;
        var it = c.lookupOn(name, rtype, class, ifindex);
        while (it.next()) |e| {
            if (e.isLive()) n += 1;
        }
        return n;
    }

    /// Walk every used entry in pool order. Do not `remove` or `upsert`
    /// during the walk.
    pub fn all(c: *Cache) AllIterator {
        return .{ .cache = c, .pos = 0 };
    }

    pub const AllIterator = struct {
        cache: *Cache,
        pos: usize,

        pub fn next(it: *AllIterator) ?*Entry {
            while (it.pos < it.cache.entries.len) {
                const e = &it.cache.entries[it.pos];
                it.pos += 1;
                if (e.used) return e;
            }
            return null;
        }

        /// Pool index of the entry the last `next` returned.
        pub fn lastIndex(it: *const AllIterator) u32 {
            return @intCast(it.pos - 1);
        }
    };
};

// ---- tests -----------------------------------------------------------

const testing = std.testing;
const us_per_s = std.time.us_per_s;

fn nameOf(text: []const u8) Name {
    return Name.parse(text) catch unreachable;
}

/// An A record on ifindex 1 whose rdata borrows a caller-owned array.
fn a4(name: []const u8, ip: *const [4]u8, ttl_s: u32) Record {
    return .{ .name = nameOf(name), .rtype = .a, .class = wire.class_in, .ttl_s = ttl_s, .rdata = ip, .ifindex = 1 };
}

const ExpiredLog = struct {
    names: [16]Name = undefined,
    types: [16]RType = undefined,
    n: usize = 0,

    fn on(log: *ExpiredLog, e: *const Entry) void {
        if (log.n < log.names.len) {
            log.names[log.n] = e.name;
            log.types[log.n] = e.rtype;
        }
        log.n += 1;
    }
};

test "cache-flush keeps records younger than 1s" {
    // RFC 6762 section 10.2: a cache-flush record flushes other same-key
    // records received more than one second ago; younger ones stay.
    var c = try Cache.init(testing.allocator, 16, 0x1234);
    defer c.deinit(testing.allocator);
    const ip1: [4]u8 = .{ 10, 0, 0, 1 };
    const ip2: [4]u8 = .{ 10, 0, 0, 2 };
    const ip3: [4]u8 = .{ 10, 0, 0, 3 };
    const host = nameOf("box.local");

    var r = c.upsert(a4("box.local", &ip1, 120), 0, false, .none);
    try testing.expectEqual(Outcome.added, r.outcome);
    // 500 ms later a cache-flush record arrives: ip1 is younger than 1 s
    // and is kept.
    r = c.upsert(a4("box.local", &ip2, 120), 500_000, true, .none);
    try testing.expectEqual(Outcome.added, r.outcome);
    try testing.expectEqual(@as(u32, 0), r.flushed_count);
    try testing.expectEqual(@as(usize, 2), c.countLive(&host, .a, wire.class_in));

    // 1.5 s: another cache-flush record. ip1 (age 1.5 s) is marked to
    // expire at 2.5 s; ip2 is exactly 1.0 s old, which is not "more than
    // one second ago", and stays.
    r = c.upsert(a4("box.local", &ip3, 120), 1_500_000, true, .none);
    try testing.expectEqual(Outcome.added, r.outcome);
    try testing.expectEqual(@as(u32, 1), r.flushed_count);
    try testing.expectEqual(@as(usize, 3), c.count());
    try testing.expectEqual(@as(usize, 2), c.countLive(&host, .a, wire.class_in));
    try testing.expectEqual(@as(?u64, 2_500_000), c.nextExpiryUs());
    // One microsecond past the second: ip2 is flushed too.
    r = c.upsert(a4("box.local", &ip3, 120), 1_500_001, true, .none);
    try testing.expectEqual(Outcome.unchanged, r.outcome);
    try testing.expectEqual(@as(u32, 1), r.flushed_count);
    try testing.expectEqual(@as(usize, 1), c.countLive(&host, .a, wire.class_in));
    try testing.expectEqual(@as(?u64, 2_500_000), c.nextExpiryUs());

    // Still present just before the grace ends; gone at it.
    var log: ExpiredLog = .{};
    try testing.expectEqual(@as(usize, 0), c.expireDue(2_499_999, &log, ExpiredLog.on));
    try testing.expectEqual(@as(usize, 3), c.count());
    try testing.expectEqual(@as(usize, 1), c.expireDue(2_500_000, &log, ExpiredLog.on));
    try testing.expectEqual(@as(usize, 1), c.expireDue(2_500_001, &log, ExpiredLog.on));
    try testing.expectEqual(@as(usize, 2), log.n);
    try testing.expectEqual(@as(usize, 1), c.count());
    var it = c.lookup(&host, .a, wire.class_in);
    const only = it.next().?;
    try testing.expectEqualSlices(u8, &ip3, only.rdataSlice());
    try testing.expect(only.flags.cache_flush_seen);
    try testing.expectEqual(@as(?*Entry, null), it.next());

    // A flushed entry that is received again before it expires is live
    // again and reports `updated`.
    r = c.upsert(a4("box.local", &ip1, 120), 3_000_000, false, .none);
    try testing.expectEqual(Outcome.added, r.outcome);
    r = c.upsert(a4("box.local", &ip2, 120), 4_500_000, true, .none);
    try testing.expectEqual(@as(u32, 2), r.flushed_count);
    r = c.upsert(a4("box.local", &ip1, 120), 4_600_000, false, .none);
    try testing.expectEqual(Outcome.updated, r.outcome);
    try testing.expect(c.entryAt(r.index.?).isLive());
    try testing.expectEqual(@as(u64, 4_600_000 + 120 * us_per_s), c.entryAt(r.index.?).expires_us);
}

test "goodbye removes after 1s" {
    // RFC 6762 section 10.1: TTL 0 -> record a TTL of 1 and delete one
    // second later.
    var c = try Cache.init(testing.allocator, 4, 0x1234);
    defer c.deinit(testing.allocator);
    const ip: [4]u8 = .{ 10, 0, 0, 1 };
    const host = nameOf("box.local");

    var r = c.upsert(a4("box.local", &ip, 120), 1_000_000, false, .none);
    try testing.expectEqual(Outcome.added, r.outcome);
    r = c.upsert(a4("box.local", &ip, 0), 5_000_000, false, .none);
    try testing.expectEqual(Outcome.goodbye, r.outcome);
    const e = c.entryAt(r.index.?);
    try testing.expect(e.flags.goodbye_pending);
    try testing.expect(!e.isLive());
    try testing.expectEqual(@as(u32, 1), e.ttl_s);
    try testing.expectEqual(@as(u64, 6_000_000), e.expires_us);
    try testing.expectEqual(@as(u32, 1), e.remainingTtlS(5_000_000));
    try testing.expectEqual(@as(usize, 0), c.countLive(&host, .a, wire.class_in));

    var log: ExpiredLog = .{};
    try testing.expectEqual(@as(usize, 0), c.expireDue(5_999_999, &log, ExpiredLog.on));
    try testing.expectEqual(@as(usize, 1), c.expireDue(6_000_000, &log, ExpiredLog.on));
    try testing.expectEqual(@as(usize, 1), log.n);
    try testing.expect(log.names[0].eql(&host));
    try testing.expectEqual(RType.a, log.types[0]);
    try testing.expectEqual(@as(usize, 0), c.count());
    try testing.expectEqual(@as(?u64, null), c.nextExpiryUs());

    // A goodbye for a record we never had caches nothing.
    r = c.upsert(a4("other.local", &ip, 0), 7_000_000, false, .none);
    try testing.expectEqual(Outcome.goodbye, r.outcome);
    try testing.expectEqual(@as(?u32, null), r.index);
    try testing.expectEqual(@as(usize, 0), c.count());

    // The record reappearing during the grace revives it.
    _ = c.upsert(a4("box.local", &ip, 120), 8_000_000, false, .none);
    _ = c.upsert(a4("box.local", &ip, 0), 9_000_000, false, .none);
    r = c.upsert(a4("box.local", &ip, 120), 9_500_000, false, .none);
    try testing.expectEqual(Outcome.updated, r.outcome);
    try testing.expect(c.entryAt(r.index.?).isLive());
    try testing.expectEqual(@as(usize, 0), c.expireDue(10_000_000, &log, ExpiredLog.on));
}

test "cache cap evicts soonest expiry" {
    var c = try Cache.init(testing.allocator, 3, 0x1234);
    defer c.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 3), c.capacity());
    const ip: [4]u8 = .{ 1, 1, 1, 1 };
    // Three records, different TTLs, received at the same time: the
    // 30 s one expires soonest.
    _ = c.upsert(a4("long.local", &ip, 4500), 0, false, .none);
    _ = c.upsert(a4("short.local", &ip, 30), 0, false, .none);
    _ = c.upsert(a4("mid.local", &ip, 120), 0, false, .none);
    try testing.expect(c.isFull());

    const r = c.upsert(a4("new.local", &ip, 120), 1_000_000, false, .none);
    try testing.expectEqual(Outcome.added, r.outcome);
    try testing.expect(r.evicted);
    try testing.expectEqual(@as(u64, 1), c.stats.evictions);
    try testing.expectEqual(@as(usize, 3), c.count());
    const short = nameOf("short.local");
    var it = c.lookup(&short, .a, wire.class_in);
    try testing.expectEqual(@as(?*Entry, null), it.next());
    const long = nameOf("long.local");
    it = c.lookup(&long, .a, wire.class_in);
    try testing.expect(it.next() != null);
    const mid = nameOf("mid.local");
    it = c.lookup(&mid, .a, wire.class_in);
    try testing.expect(it.next() != null);

    // A goodbye entry (expiring in 1 s) is the soonest of all.
    _ = c.upsert(a4("mid.local", &ip, 0), 2_000_000, false, .none);
    const r2 = c.upsert(a4("newer.local", &ip, 120), 2_100_000, false, .none);
    try testing.expectEqual(Outcome.added, r2.outcome);
    try testing.expectEqual(@as(u64, 2), c.stats.evictions);
    it = c.lookup(&mid, .a, wire.class_in);
    try testing.expectEqual(@as(?*Entry, null), it.next());
}

const EvictLog = struct {
    n: usize = 0,
    last: Name = .{},
    fn on(ctx: ?*anyopaque, e: *const Entry) void {
        const log: *EvictLog = @ptrCast(@alignCast(ctx.?));
        log.n += 1;
        log.last = e.name;
    }
    fn hook(log: *EvictLog) EvictHook {
        return .{ .ctx = @ptrCast(log), .f = on };
    }
};

test "eviction skips pinned records" {
    var c = try Cache.init(testing.allocator, 2, 0x1234);
    defer c.deinit(testing.allocator);
    const ip: [4]u8 = .{ 1, 1, 1, 1 };
    const short = nameOf("short.local");
    var log: EvictLog = .{};

    const rs = c.upsert(a4("short.local", &ip, 30), 0, false, log.hook());
    c.entryAt(rs.index.?).flags.pinned = true;
    _ = c.upsert(a4("long.local", &ip, 4500), 0, false, log.hook());
    // short.local would be the victim; pinned, so long.local goes, and
    // the hook sees it before it is unlinked.
    var r = c.upsert(a4("new.local", &ip, 120), 1_000_000, false, log.hook());
    try testing.expectEqual(Outcome.added, r.outcome);
    try testing.expect(r.evicted);
    try testing.expect(!r.evicted_pinned);
    try testing.expectEqual(@as(u64, 1), c.stats.evictions);
    try testing.expectEqual(@as(u64, 0), c.stats.evictions_pinned);
    try testing.expectEqual(@as(usize, 1), log.n);
    try testing.expectEqualStrings("\x04long\x05local\x00", log.last.slice());
    var it = c.lookup(&short, .a, wire.class_in);
    try testing.expect(it.next() != null);
    const long = nameOf("long.local");
    it = c.lookup(&long, .a, wire.class_in);
    try testing.expectEqual(@as(?*Entry, null), it.next());

    // A refresh keeps the pin; a re-used slot starts unpinned.
    r = c.upsert(a4("short.local", &ip, 30), 1_000_000, false, log.hook());
    try testing.expectEqual(Outcome.unchanged, r.outcome);
    try testing.expect(c.entryAt(r.index.?).flags.pinned);
    const new_name = nameOf("new.local");
    it = c.lookup(&new_name, .a, wire.class_in);
    try testing.expect(!it.next().?.flags.pinned);

    // Everything pinned: the soonest-expiring pinned entry goes (never a
    // rejection), counted separately and reported through the hook.
    c.entryAt(0).flags.pinned = true;
    c.entryAt(1).flags.pinned = true;
    r = c.upsert(a4("another.local", &ip, 120), 2_000_000, false, log.hook());
    try testing.expectEqual(Outcome.added, r.outcome);
    try testing.expect(r.evicted);
    try testing.expect(r.evicted_pinned);
    try testing.expectEqual(@as(u64, 2), c.stats.evictions);
    try testing.expectEqual(@as(u64, 1), c.stats.evictions_pinned);
    try testing.expectEqual(@as(u64, 0), c.stats.rejected_full);
    try testing.expectEqual(@as(usize, 2), log.n);
    try testing.expect(log.last.eql(&short)); // 30 s TTL: soonest
    try testing.expectEqual(@as(usize, 2), c.count());
    try testing.expect(!c.entryAt(r.index.?).flags.pinned);
    // A refresh of a cached record needs no slot and still works.
    const another = nameOf("another.local");
    r = c.upsert(a4("another.local", &ip, 120), 2_000_000, false, log.hook());
    try testing.expectEqual(Outcome.unchanged, r.outcome);
    try testing.expectEqual(@as(usize, 1), c.countLive(&another, .a, wire.class_in));
    // `remove` clears the pin so a re-used slot never inherits it.
    c.entryAt(r.index.?).flags.pinned = true;
    c.remove(r.index.?);
    const r3 = c.upsert(a4("third.local", &ip, 120), 2_000_000, false, log.hook());
    try testing.expect(!c.entryAt(r3.index.?).flags.pinned);
}

test "same key different rdata forms one RRSet" {
    var c = try Cache.init(testing.allocator, 16, 0x1234);
    defer c.deinit(testing.allocator);
    const host = nameOf("box.local");
    const ip1: [4]u8 = .{ 10, 0, 0, 1 };
    const ip2: [4]u8 = .{ 10, 0, 0, 2 };
    const ip3: [4]u8 = .{ 10, 0, 0, 3 };
    _ = c.upsert(a4("box.local", &ip1, 120), 0, false, .none);
    _ = c.upsert(a4("box.local", &ip2, 120), 0, false, .none);
    _ = c.upsert(a4("box.local", &ip3, 120), 0, false, .none);
    // Same name, other type: a different key.
    var aaaa: [16]u8 = @splat(0);
    aaaa[15] = 1;
    _ = c.upsert(.{ .name = host, .rtype = .aaaa, .class = wire.class_in, .ttl_s = 120, .rdata = &aaaa, .ifindex = 1 }, 0, false, .none);
    // Same name and type, other class: a different key too.
    _ = c.upsert(a4("box.local", &ip1, 120), 0, false, .none); // unchanged
    var other_class = a4("box.local", &ip1, 120);
    other_class.class = 3;
    _ = c.upsert(other_class, 0, false, .none);
    try testing.expectEqual(@as(usize, 5), c.count());

    var seen: [3]bool = @splat(false);
    var it = c.lookup(&host, .a, wire.class_in);
    var n: usize = 0;
    while (it.next()) |e| : (n += 1) {
        try testing.expectEqual(RType.a, e.rtype);
        try testing.expectEqual(@as(u16, 1), e.class);
        const last = e.rdataSlice()[3];
        try testing.expect(last >= 1 and last <= 3);
        try testing.expect(!seen[last - 1]);
        seen[last - 1] = true;
    }
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqual(@as(usize, 1), c.countLive(&host, .aaaa, wire.class_in));
    try testing.expectEqual(@as(usize, 1), c.countLive(&host, .a, 3));
    const missing = nameOf("nobody.local");
    try testing.expectEqual(@as(usize, 0), c.countLive(&missing, .a, wire.class_in));

    // Removing a middle member keeps the other two reachable.
    it = c.lookup(&host, .a, wire.class_in);
    _ = it.next().?;
    const middle = it.next().?;
    const middle_ip = middle.rdata[3];
    var idx: u32 = 0;
    var all = c.all();
    while (all.next()) |e| {
        if (e == middle) idx = all.lastIndex();
    }
    c.remove(idx);
    try testing.expectEqual(@as(usize, 2), c.countLive(&host, .a, wire.class_in));
    it = c.lookup(&host, .a, wire.class_in);
    while (it.next()) |e| try testing.expect(e.rdata[3] != middle_ip);
    try testing.expectEqual(@as(usize, 4), c.count());
}

test "name compare is ASCII case-insensitive" {
    var c = try Cache.init(testing.allocator, 8, 0x1234);
    defer c.deinit(testing.allocator);
    const ip: [4]u8 = .{ 10, 0, 0, 1 };
    var r = c.upsert(a4("Box.Local", &ip, 120), 0, false, .none);
    try testing.expectEqual(Outcome.added, r.outcome);
    r = c.upsert(a4("BOX.local", &ip, 120), 1, false, .none);
    try testing.expectEqual(Outcome.unchanged, r.outcome);
    r = c.upsert(a4("box.LOCAL", &ip, 120), 2, false, .none);
    try testing.expectEqual(Outcome.unchanged, r.outcome);
    try testing.expectEqual(@as(usize, 1), c.count());
    const lower = nameOf("box.local");
    const upper = nameOf("BOX.LOCAL");
    try testing.expectEqual(@as(usize, 1), c.countLive(&lower, .a, wire.class_in));
    try testing.expectEqual(@as(usize, 1), c.countLive(&upper, .a, wire.class_in));
    // The stored spelling is the latest received one.
    var it = c.lookup(&lower, .a, wire.class_in);
    try testing.expectEqualStrings("\x03box\x05LOCAL\x00", it.next().?.name.slice());
    // A different name is not folded into it.
    r = c.upsert(a4("bok.local", &ip, 120), 3, false, .none);
    try testing.expectEqual(Outcome.added, r.outcome);
    try testing.expectEqual(@as(usize, 2), c.count());
    // Cache-flush folds case too.
    const ip2: [4]u8 = .{ 10, 0, 0, 2 };
    r = c.upsert(a4("bOx.lOcAl", &ip2, 120), 5_000_000, true, .none);
    try testing.expectEqual(@as(u32, 1), r.flushed_count);
}

test "requery marks fall at 80 85 90 95 percent plus jitter" {
    // RFC 6762 section 5.2: 80/85/90/95 % of the TTL, each plus a random
    // 0-2 % of the TTL. 10 k seeded iterations over random TTLs and
    // receive times; every mark must land in [p, p + 2] % of the TTL
    // measured from received_us, and the marks must be strictly ordered.
    var prng = std.Random.DefaultPrng.init(0x6762_5200);
    const random = prng.random();
    var e: Entry = undefined;
    e.used = true;
    var iter: usize = 0;
    while (iter < 10_000) : (iter += 1) {
        const ttl_s = random.intRangeAtMost(u32, 1, 4500);
        const received = random.uintAtMost(u64, 1_000_000_000_000);
        e.ttl_s = ttl_s;
        e.received_us = received;
        e.expires_us = received + ttlUs(ttl_s);
        e.flags = .{};
        e.requery_idx = 0;
        e.next_requery_us = null;
        const ttl = ttlUs(ttl_s);
        var now = received;
        var prev: u64 = 0;
        for (requery_marks_percent) |p| {
            const at = Cache.scheduleRequery(&e, now, random) orelse return error.TestUnexpectedResult;
            try testing.expectEqual(@as(?u64, at), e.next_requery_us);
            const lo = received + (ttl / 100) * p;
            const hi = lo + (ttl / 100) * requery_jitter_percent;
            try testing.expect(at >= lo);
            try testing.expect(at <= hi);
            try testing.expect(at > now);
            try testing.expect(at > prev);
            try testing.expect(at < e.expires_us);
            prev = at;
            now = at;
        }
        // Past the last mark: nothing more.
        try testing.expectEqual(@as(?u64, null), Cache.scheduleRequery(&e, now, random));
        try testing.expectEqual(@as(?u64, null), e.next_requery_us);
    }

    // Marks already in the past are skipped: at 87 % the next mark is 90.
    e.ttl_s = 100;
    e.received_us = 0;
    e.expires_us = 100 * us_per_s;
    e.flags = .{};
    e.requery_idx = 0;
    const at = Cache.scheduleRequery(&e, 87 * us_per_s, random).?;
    try testing.expect(at >= 90 * us_per_s and at <= 92 * us_per_s);
    try testing.expectEqual(@as(u8, 3), e.requery_idx);
    // Goodbye and flushed records are never re-queried.
    e.flags = .{ .goodbye_pending = true };
    e.requery_idx = 0;
    try testing.expectEqual(@as(?u64, null), Cache.scheduleRequery(&e, 0, random));
    e.flags = .{ .flush_pending = true };
    try testing.expectEqual(@as(?u64, null), Cache.scheduleRequery(&e, 0, random));
}

const RequeryLog = struct {
    n: usize = 0,
    fn on(log: *RequeryLog, e: *Entry) void {
        _ = e;
        log.n += 1;
    }
};

test "requery marks are cleared by a refresh and popped when due" {
    var prng = std.Random.DefaultPrng.init(3);
    const random = prng.random();
    var c = try Cache.init(testing.allocator, 4, 0x1234);
    defer c.deinit(testing.allocator);
    const ip: [4]u8 = .{ 10, 0, 0, 1 };
    const r = c.upsert(a4("box.local", &ip, 100), 0, false, .none);
    try testing.expectEqual(@as(?u64, null), c.nextRequeryUs());
    const e = c.entryAt(r.index.?);
    const at = Cache.scheduleRequery(e, 0, random).?;
    try testing.expectEqual(@as(?u64, at), c.nextRequeryUs());
    var log: RequeryLog = .{};
    try testing.expectEqual(@as(usize, 0), c.popDueRequeries(at - 1, &log, RequeryLog.on));
    try testing.expectEqual(@as(usize, 1), c.popDueRequeries(at, &log, RequeryLog.on));
    try testing.expectEqual(@as(usize, 1), log.n);
    try testing.expectEqual(@as(?u64, null), c.nextRequeryUs());
    // Re-plan; then a refresh clears the plan (the querier re-plans from
    // the new TTL).
    _ = Cache.scheduleRequery(e, at, random).?;
    try testing.expect(c.nextRequeryUs() != null);
    _ = c.upsert(a4("box.local", &ip, 100), at, false, .none);
    try testing.expectEqual(@as(?u64, null), c.nextRequeryUs());
    try testing.expectEqual(@as(u8, 0), e.requery_idx);
}

test "upsert with identical rdata refreshes TTL and reports unchanged" {
    var c = try Cache.init(testing.allocator, 4, 0x1234);
    defer c.deinit(testing.allocator);
    const ip: [4]u8 = .{ 10, 0, 0, 1 };
    var rec = a4("box.local", &ip, 120);
    rec.ifindex = 1;
    var r = c.upsert(rec, 10 * us_per_s, false, .none);
    try testing.expectEqual(Outcome.added, r.outcome);
    const e = c.entryAt(r.index.?);
    try testing.expectEqual(@as(u64, 130 * us_per_s), e.expires_us);
    try testing.expectEqual(@as(u32, 120), e.remainingTtlS(10 * us_per_s));
    try testing.expectEqual(@as(u32, 60), e.remainingTtlS(70 * us_per_s));
    // Plan section 4.4 `ka_half_ttl`: omitted at or past TTL/2.
    try testing.expect(!e.pastHalfTtl(70 * us_per_s - 1));
    try testing.expect(e.pastHalfTtl(70 * us_per_s));

    rec.ttl_s = 4500;
    r = c.upsert(rec, 100 * us_per_s, true, .none);
    try testing.expectEqual(Outcome.unchanged, r.outcome);
    try testing.expectEqual(r.index, @as(?u32, 0));
    try testing.expectEqual(@as(usize, 1), c.count());
    try testing.expectEqual(@as(u32, 4500), e.ttl_s);
    try testing.expectEqual(@as(u64, 100 * us_per_s), e.received_us);
    try testing.expectEqual(@as(u64, 4600 * us_per_s), e.expires_us);
    try testing.expectEqual(@as(u32, 1), e.ifindex);
    try testing.expect(e.flags.cache_flush_seen);
    try testing.expectEqual(@as(u32, 0), r.flushed_count);
    try testing.expectEqual(@as(?u64, 4600 * us_per_s), c.nextExpiryUs());

    // The same record heard on another interface is a distinct entry
    // (RFC 6762 section 14; the key is (name, type, class, ifindex)),
    // and its cache-flush bit flushes nothing on interface 1. (Before
    // the P2 fix this refresh reported `unchanged` and moved the entry
    // to ifindex 2.)
    const host = nameOf("box.local");
    rec.ifindex = 2;
    r = c.upsert(rec, 100 * us_per_s, true, .none);
    try testing.expectEqual(Outcome.added, r.outcome);
    try testing.expectEqual(@as(u32, 0), r.flushed_count);
    try testing.expectEqual(@as(usize, 2), c.count());
    try testing.expectEqual(@as(usize, 2), c.countLive(&host, .a, wire.class_in));
    try testing.expectEqual(@as(usize, 1), c.countLiveOn(&host, .a, wire.class_in, 1));
    try testing.expectEqual(@as(usize, 1), c.countLiveOn(&host, .a, wire.class_in, 2));
    try testing.expectEqual(@as(usize, 0), c.countLiveOn(&host, .a, wire.class_in, 3));
    try testing.expectEqual(@as(u32, 2), c.entryAt(r.index.?).ifindex);
    try testing.expectEqual(@as(u32, 1), e.ifindex);
    rec.ifindex = 1;
    // Time saturates instead of wrapping.
    r = c.upsert(rec, std.math.maxInt(u64) - 1, false, .none);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), e.expires_us);
}

test "cache-flush only flushes records from the same interface" {
    // RFC 6762 sections 6.2 and 14 (and section 10.2 as mDNSResponder
    // applies it, per InterfaceID): a multi-homed responder answers on
    // each interface with only that interface's addresses, cache-flush
    // set. A querier that merged the interfaces would let each answer
    // flush the other interface's address after the 1 s grace, cycling
    // the address set forever (the M3 gate "resolved flicker"). The
    // cache key carries the arrival interface, so a flush is scoped to
    // it.
    var c = try Cache.init(testing.allocator, 16, 0x1234);
    defer c.deinit(testing.allocator);
    const host = nameOf("box.local");
    const ip1: [4]u8 = .{ 10, 0, 1, 7 };
    const ip2: [4]u8 = .{ 10, 0, 2, 7 };
    const ip3: [4]u8 = .{ 10, 0, 1, 8 };
    var on1 = a4("box.local", &ip1, 120);
    on1.ifindex = 1;
    var on2 = a4("box.local", &ip2, 120);
    on2.ifindex = 2;
    _ = c.upsert(on1, 0, true, .none);
    _ = c.upsert(on2, 0, true, .none);
    try testing.expectEqual(@as(usize, 2), c.count());

    // 5 s later interface 1 hears a cache-flush A with a new address:
    // ip1 (same interface, older than 1 s) is flushed, ip2 (interface
    // 2) is untouched.
    var on1b = a4("box.local", &ip3, 120);
    on1b.ifindex = 1;
    var r = c.upsert(on1b, 5 * us_per_s, true, .none);
    try testing.expectEqual(Outcome.added, r.outcome);
    try testing.expectEqual(@as(u32, 1), r.flushed_count);
    try testing.expectEqual(@as(usize, 3), c.count());
    try testing.expectEqual(@as(usize, 1), c.countLiveOn(&host, .a, wire.class_in, 1));
    try testing.expectEqual(@as(usize, 1), c.countLiveOn(&host, .a, wire.class_in, 2));
    var it = c.lookupOn(&host, .a, wire.class_in, 1);
    while (it.next()) |e| {
        if (std.mem.eql(u8, e.rdataSlice(), &ip1)) {
            try testing.expect(e.flags.flush_pending);
            try testing.expectEqual(@as(u64, 6 * us_per_s), e.expires_us);
        } else {
            try testing.expect(e.isLive());
        }
    }
    it = c.lookupOn(&host, .a, wire.class_in, 2);
    const only2 = it.next().?;
    try testing.expect(only2.isLive());
    try testing.expectEqualSlices(u8, &ip2, only2.rdataSlice());
    try testing.expectEqual(@as(?*Entry, null), it.next());

    // The mirror image: a cache-flush refresh of ip2 on interface 2
    // flushes nothing (ip2 is the record itself, ip1/ip3 are on
    // interface 1), and a cache-flush of ip1's rdata arriving on
    // interface 2 is a new entry there that flushes only ip2.
    r = c.upsert(on2, 5 * us_per_s, true, .none);
    try testing.expectEqual(Outcome.unchanged, r.outcome);
    try testing.expectEqual(@as(u32, 0), r.flushed_count);
    var on2b = a4("box.local", &ip1, 120);
    on2b.ifindex = 2;
    r = c.upsert(on2b, 7 * us_per_s, true, .none);
    try testing.expectEqual(Outcome.added, r.outcome);
    try testing.expectEqual(@as(u32, 1), r.flushed_count);
    try testing.expectEqual(@as(usize, 1), c.countLiveOn(&host, .a, wire.class_in, 1));
    try testing.expectEqual(@as(usize, 1), c.countLiveOn(&host, .a, wire.class_in, 2));
    try testing.expectEqual(@as(usize, 2), c.countLive(&host, .a, wire.class_in));

    // Expiry removes exactly the two flushed entries (ip1 on 1 at 6 s,
    // ip2 on 2 at 8 s).
    var log: ExpiredLog = .{};
    try testing.expectEqual(@as(usize, 1), c.expireDue(6 * us_per_s, &log, ExpiredLog.on));
    try testing.expectEqual(@as(usize, 1), c.expireDue(8 * us_per_s, &log, ExpiredLog.on));
    try testing.expectEqual(@as(usize, 2), c.count());
    try testing.expectEqual(@as(usize, 1), c.countLiveOn(&host, .a, wire.class_in, 1));
    try testing.expectEqual(@as(usize, 1), c.countLiveOn(&host, .a, wire.class_in, 2));

    // A goodbye is scoped the same way: TTL 0 for ip3 on interface 2
    // (where it was never heard) changes nothing.
    var bye = a4("box.local", &ip3, 0);
    bye.ifindex = 2;
    r = c.upsert(bye, 9 * us_per_s, false, .none);
    try testing.expectEqual(Outcome.goodbye, r.outcome);
    try testing.expectEqual(@as(?u32, null), r.index);
    try testing.expectEqual(@as(usize, 1), c.countLiveOn(&host, .a, wire.class_in, 1));
}

test "TXT rdata over 400 B is truncated and counted" {
    var c = try Cache.init(testing.allocator, 4, 0x1234);
    defer c.deinit(testing.allocator);
    const name = nameOf("Demo._qmsg._udp.local");
    // Five strings of 100 octets (1 + 99): 500 B on the wire. Four fit.
    var big: [500]u8 = undefined;
    var pos: usize = 0;
    var s: u8 = 0;
    while (s < 5) : (s += 1) {
        big[pos] = 99;
        @memset(big[pos + 1 ..][0..99], 'a' + s);
        pos += 100;
    }
    var r = c.upsert(.{ .name = name, .rtype = .txt, .class = wire.class_in, .ttl_s = 4500, .rdata = &big, .ifindex = 1 }, 0, true, .none);
    try testing.expectEqual(Outcome.added, r.outcome);
    try testing.expect(r.truncated);
    try testing.expectEqual(@as(u64, 1), c.stats.txt_truncated);
    const e = c.entryAt(r.index.?);
    try testing.expectEqual(@as(usize, 400), e.rdataSlice().len);
    try testing.expectEqualSlices(u8, big[0..400], e.rdataSlice());

    // The same oversize TXT again matches the truncated entry.
    r = c.upsert(.{ .name = name, .rtype = .txt, .class = wire.class_in, .ttl_s = 4500, .rdata = &big, .ifindex = 1 }, 1, true, .none);
    try testing.expectEqual(Outcome.unchanged, r.outcome);
    try testing.expectEqual(@as(u64, 2), c.stats.txt_truncated);
    try testing.expectEqual(@as(usize, 1), c.count());

    // A TXT of exactly 400 B is stored whole and not counted.
    var exact: [400]u8 = undefined;
    exact[0] = 199;
    @memset(exact[1..200], 'x');
    exact[200] = 199;
    @memset(exact[201..400], 'y');
    r = c.upsert(.{ .name = name, .rtype = .txt, .class = wire.class_in, .ttl_s = 4500, .rdata = &exact, .ifindex = 1 }, 2, false, .none);
    try testing.expectEqual(Outcome.added, r.outcome);
    try testing.expect(!r.truncated);
    try testing.expectEqual(@as(u64, 2), c.stats.txt_truncated);
    try testing.expectEqual(@as(usize, 400), c.entryAt(r.index.?).rdataSlice().len);

    // An oversize TXT whose length prefixes do not add up is rejected.
    var bad: [401]u8 = @splat(0);
    bad[0] = 255;
    bad[256] = 255;
    r = c.upsert(.{ .name = name, .rtype = .txt, .class = wire.class_in, .ttl_s = 4500, .rdata = &bad, .ifindex = 1 }, 3, true, .none);
    try testing.expectEqual(Outcome.rejected, r.outcome);
    try testing.expectEqual(@as(u64, 1), c.stats.rejected_oversize);
    try testing.expectEqual(@as(u32, 0), r.flushed_count);
    try testing.expectEqual(@as(usize, 2), c.count());
}

test "oversize non-TXT rdata is rejected and never flushes" {
    var c = try Cache.init(testing.allocator, 4, 0x1234);
    defer c.deinit(testing.allocator);
    const host = nameOf("box.local");
    const ip: [4]u8 = .{ 10, 0, 0, 1 };
    _ = c.upsert(a4("box.local", &ip, 120), 0, false, .none);
    var huge: [401]u8 = @splat(7);
    huge[0] = 0;
    const r = c.upsert(.{ .name = host, .rtype = .a, .class = wire.class_in, .ttl_s = 120, .rdata = &huge, .ifindex = 1 }, 5_000_000, true, .none);
    try testing.expectEqual(Outcome.rejected, r.outcome);
    try testing.expectEqual(@as(u32, 0), r.flushed_count);
    try testing.expectEqual(@as(u64, 1), c.stats.rejected_oversize);
    try testing.expectEqual(@as(usize, 1), c.countLive(&host, .a, wire.class_in));
    // The largest name-bearing rdata (SRV with a 255-octet target) fits.
    var srv_rdata: [wire.rdata.max_name_rdata_len]u8 = @splat(1);
    const r2 = c.upsert(.{ .name = host, .rtype = .srv, .class = wire.class_in, .ttl_s = 120, .rdata = srv_rdata[0 .. 6 + 255], .ifindex = 1 }, 5_000_000, true, .none);
    try testing.expectEqual(Outcome.added, r2.outcome);
}

test "pool fills, drains and refills without leaking slots" {
    var c = try Cache.init(testing.allocator, 64, 0x1234);
    defer c.deinit(testing.allocator);
    var round: u32 = 0;
    while (round < 5) : (round += 1) {
        var i: u32 = 0;
        while (i < 64) : (i += 1) {
            var label: [8]u8 = undefined;
            const text = std.fmt.bufPrint(&label, "h{d}", .{i}) catch unreachable;
            var n = Name.root;
            n.appendLabel(text) catch unreachable;
            n.appendLabel("local") catch unreachable;
            const ip: [4]u8 = .{ 10, 0, @intCast(round), @intCast(i) };
            const r = c.upsert(.{ .name = n, .rtype = .a, .class = wire.class_in, .ttl_s = 1 + i, .rdata = &ip, .ifindex = 1 }, round * 1_000_000, false, .none);
            try testing.expectEqual(Outcome.added, r.outcome);
        }
        try testing.expect(c.isFull());
        try testing.expectEqual(@as(usize, 64), c.count());
        var log: ExpiredLog = .{};
        // Expire the shortest half, then the rest.
        const half = c.expireDue(round * 1_000_000 + 32 * us_per_s, &log, ExpiredLog.on);
        try testing.expectEqual(@as(usize, 32), half);
        try testing.expectEqual(@as(usize, 32), c.count());
        c.clear();
        try testing.expectEqual(@as(usize, 0), c.count());
        try testing.expectEqual(@as(usize, 64), c.free_len);
        try testing.expectEqual(@as(?u64, null), c.nextExpiryUs());
    }
    try testing.expectEqual(@as(u64, 0), c.stats.evictions);
}

test "bucket index depends on the secret seed" {
    // A peer that precomputes names sharing a bucket under one seed gets
    // a different spread under another: the bucket is a keyed hash of
    // the public `Name.hash`, not a fixed shift of it.
    const n_buckets: usize = 8192;
    var same: usize = 0;
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        var label: [16]u8 = undefined;
        const text = std.fmt.bufPrint(&label, "h{d}.local", .{i}) catch unreachable;
        const name = nameOf(text);
        const h = name.hash();
        const a = Cache.bucketIndex(0x1111, h, .a, wire.class_in, n_buckets);
        const b = Cache.bucketIndex(0x2222, h, .a, wire.class_in, n_buckets);
        if (a == b) same += 1;
        // Type and class are part of the key.
        try testing.expect(Cache.bucketIndex(0x1111, h, .aaaa, wire.class_in, n_buckets) != a or
            Cache.bucketIndex(0x1111, h, .a, 3, n_buckets) != a);
    }
    // 256 keys over 8192 buckets: expected ~0.03 accidental matches.
    try testing.expect(same < 8);
    // Two caches with different seeds place the same key differently
    // for most keys; the querier draws the seed from its `std.Random`.
    var c1 = try Cache.init(testing.allocator, 64, 1);
    defer c1.deinit(testing.allocator);
    var c2 = try Cache.init(testing.allocator, 64, 2);
    defer c2.deinit(testing.allocator);
    var differ: usize = 0;
    i = 0;
    while (i < 64) : (i += 1) {
        var label: [16]u8 = undefined;
        const text = std.fmt.bufPrint(&label, "n{d}.local", .{i}) catch unreachable;
        const name = nameOf(text);
        if (c1.bucketOf(&name, .a, wire.class_in) != c2.bucketOf(&name, .a, wire.class_in)) differ += 1;
    }
    try testing.expect(differ > 48);
}
