//! Querier: browses, the RFC 6762 section 5.2 continuous-query schedule,
//! known-answer lists, requery marks, the record cache and the DNS-SD
//! resolve join (plan sections 4.4, 4.5, 5 "Rules behind the sketch",
//! section 6 `core/querier.zig`).
//!
//! The Engine owns one `Querier` and drives it with the same contract it
//! has itself: no clock, no socket, no allocation after `init`, and no
//! failure on a path fed by network bytes. Time is the caller's `now_us`,
//! randomness the injected `std.Random`, events go out through a type-
//! erased `Sink` the Engine passes on every call (the Engine is a value
//! that may move, so nothing here stores a pointer to it).
//!
//! Model:
//! - A **browse** is one PTR question for `<type>.local` (RFC 6763
//!   section 4). Its first query goes out 20-120 ms after `browse`, then
//!   1 s later, then 2 s, 4 s, ... capped at 60 min, each interval plus a
//!   random 0-2 % (RFC 6762 section 5.2). Browse queries are QM, never QU
//!   (section 5.4; plan section 4.8 "QU policy").
//! - The **cache** (`core/cache.zig`) keys records by `(name, type,
//!   class, ifindex)`, so the order of records inside a packet does not
//!   matter and what one interface hears never flushes what another
//!   heard (RFC 6762 sections 6.2, 14). `handleResponse` harvests every
//!   answer and additional record first, then runs the resolve join for
//!   every instance the packet touched (plan section 4.5).
//! - An **instance** is a PTR target of a browsed type **on one
//!   interface**: the same service heard on two interfaces is two
//!   instances, as with `dns-sd -B` (one row per interfaceIndex).
//!   `found` fires when its PTR enters the cache, `lost` when the PTR
//!   leaves it (expiry, or one second after a goodbye, section 10.1),
//!   each carrying the interface. A PTR for a type without an active
//!   browse is cached and emits nothing (hashicorp/mdns #96), so a later
//!   browse of that type starts warm. An interface that leaves the table
//!   takes its records and instances with it (`dropInterface`: `lost`
//!   for each browsed instance heard there).
//! - `resolved` fires when the instance's SRV, TXT and at least one
//!   address of the SRV target are live in the cache **on the instance's
//!   interface**, again whenever the SRV rdata, the TXT rdata or that
//!   interface's address set changes, and never for a refresh that
//!   carries the same data. `Resolved.addrs` holds exactly the addresses
//!   the responder gave on that interface (section 6.2). `ttl_s` is the
//!   shortest remaining TTL among the records that built the value.
//! - A found instance that lacks SRV, TXT or an address gets **follow-up
//!   questions** (SRV + TXT, then A + AAAA for the SRV target) on their
//!   own section 5.2 ladder, sent only on the instance's interface
//!   (`Question.ifindex`; requery marks are scoped the same way, browse
//!   PTR questions go to every joined pair). They stop when the
//!   instance resolves.
//! - Records a local client cares about get **requery marks** at 80, 85,
//!   90 and 95 % of their TTL (+0-2 %); a due mark folds its question
//!   into the next query packet. Nothing else is ever re-queried (section
//!   5.2 MUST NOT). The set is exactly what the resolve join consumes:
//!   browsed PTRs, the SRV and TXT the join used for a found instance and
//!   the A/AAAA it listed for its host. The marks are armed from the join,
//!   so the order records arrive in (A/TXT/SRV before the PTR, or the host
//!   records a packet ahead of the service) never matters (hashicorp/mdns
//!   #145). The same records carry the cache's eviction **pin** (plan
//!   section 4.5); a second SRV for the same instance, or a ninth address,
//!   is cached but neither pinned nor re-queried, so a peer cannot fill the
//!   pool with records we would protect.
//! - A goodbye (section 10.1) for an instance's PTR, SRV or TXT stops its
//!   follow-up ladder instead of restarting it: the responder just said
//!   the record is gone. A live record for the instance resumes it.
//! - A query packet carries every due question (section 5.3) and the
//!   **known-answer list**: cached live records answering those questions
//!   that are not yet past half their TTL (section 7.1). Known answers
//!   that do not fit continue in further packets with TC set on all but
//!   the last (section 7.2).
//!
//! Sizes: every pool is allocated once in `init` from `Limits`. The
//! instance table has `max_cache_records` slots; the due-question list
//! `max_due_questions`; the outbound job queue one slot per (interface,
//! family) pair. Instances are indexed three ways, all O(1) on average:
//! by name (bucket chain), by SRV-target hash (a second chain, so the
//! "does any instance live on this host" test behind A/AAAA harvesting,
//! pinning and requery marks never walks the table) and by the pool slot
//! of their PTR entry (`ptr_to_inst`). Both chains mix the hash with a
//! secret per-querier seed, like the cache's buckets.
const std = @import("std");
const Io = std.Io;
const wire = @import("../wire/root.zig");
const events = @import("events.zig");
const cache_mod = @import("cache.zig");
const timers = @import("timers.zig");

pub const Cache = cache_mod.Cache;
pub const Entry = cache_mod.Entry;
pub const Name = wire.Name;
pub const RType = wire.RType;
pub const Event = events.Event;
pub const Family = events.Family;
pub const Limits = events.Limits;
pub const Resolved = events.Resolved;
pub const BrowseId = events.BrowseId;

/// Domain every browse and every service instance lives in (RFC 6762
/// section 3).
pub const local_domain = "local";

/// Due questions one tick may hold for the next packet (browse
/// questions, follow-ups and requery marks together). A question that
/// does not fit waits for its next schedule step.
pub const max_due_questions: usize = 256;

/// Hash seed for the rdata / address-set digests behind the `resolved`
/// re-emit rule.
const digest_seed: u64 = 0x6d646e73_71726965; // "mdnsqrie"

const none: u32 = std.math.maxInt(u32);

// ---- event sink ------------------------------------------------------

/// Type-erased event output: the Engine passes `Sink.of(engine)` on every
/// call, never stores it.
pub const Sink = struct {
    ctx: *anyopaque,
    emit: *const fn (*anyopaque, Event) void,

    pub fn push(s: Sink, ev: Event) void {
        s.emit(s.ctx, ev);
    }
};

// ---- state -----------------------------------------------------------

/// One question (class IN) due for the next query packet. `ifindex`
/// scopes it to one interface's jobs (a follow-up for an instance found
/// there, a requery mark of a record heard there); null goes out on
/// every joined pair (a browse's PTR question).
pub const Question = struct {
    name: Name,
    rtype: RType,
    ifindex: ?u32 = null,

    /// Same name and type (the interface is not part of it).
    pub fn eql(a: *const Question, b: *const Question) bool {
        return a.rtype == b.rtype and a.name.eql(&b.name);
    }

    /// Does this question go out on `ifindex`'s pairs?
    pub fn appliesTo(q: *const Question, ifindex: u32) bool {
        return q.ifindex == null or q.ifindex.? == ifindex;
    }
};

/// One active browse.
pub const Browse = struct {
    used: bool = false,
    /// `<type>.local`.
    service_type: Name = .{},
    /// When the next PTR query is due.
    next_query_us: u64 = 0,
    /// Interval before the *next* query after that (0 = first query
    /// pending; then 1 s, 2 s, ... capped, RFC 6762 section 5.2). It is
    /// the jittered gap actually used, so the next step doubles the real
    /// gap ("MUST increase by at least a factor of two").
    interval_us: u64 = 0,
};

/// One found service instance on one interface: the resolve state
/// behind `found`, `lost`, `resolved` and the follow-up questions. The
/// instance name is the rdata of the PTR entry at `ptr_index` and the
/// interface is that entry's; the state lives exactly as long as that
/// entry (it is freed in the expiry callback, and browsed PTRs are pinned
/// against eviction). Identity is (instance name, ifindex).
pub const Instance = struct {
    used: bool = false,
    /// Cache pool index of the PTR entry whose rdata names this instance.
    ptr_index: u32 = none,
    /// Arrival interface of that PTR: every record the join reads for
    /// this instance is looked up on it.
    ifindex: u32 = 0,
    /// `Name.hash` of the instance name (bucket key).
    name_hash: u64 = 0,
    /// `Name.hash` of the SRV target once an SRV was seen (A/AAAA
    /// records match on it before the names are compared).
    host_hash: ?u64 = null,
    /// Digests of the last emitted `resolved` (valid when `emitted`).
    srv_digest: u64 = 0,
    txt_digest: u64 = 0,
    addr_digest: u64 = 0,
    emitted: bool = false,
    /// A record of this instance changed since the last join.
    dirty: bool = false,
    /// Follow-up schedule (null when resolved or not started).
    followup_next_us: ?u64 = null,
    /// Interval before the *next* follow-up after `followup_next_us`
    /// (the jittered gap actually used, so each step doubles the real
    /// gap: RFC 6762 section 5.2 "at least a factor of two").
    followup_interval_us: u64 = 0,
    /// A goodbye for the PTR, SRV or TXT stopped the follow-up ladder;
    /// cleared when a live SRV or TXT arrives (section 10.1).
    followups_suppressed: bool = false,
    next_in_bucket: u32 = none,
    /// Chain through `host_buckets` (linked while `host_hash != null`).
    next_in_host_bucket: u32 = none,
};

/// One (interface, family) pair the Engine queries on.
pub const Pair = struct { ifindex: u32, family: Family };

/// Progress of the current due-question batch on one pair: which
/// questions and which known answers went out already (multi-packet
/// known-answer lists, RFC 6762 section 7.2).
const TxJob = struct {
    pair: Pair,
    q_pos: u32 = 0,
    ka_pos: u32 = 0,
};

/// What `buildNext` produced.
pub const Built = struct {
    len: usize,
    pair: Pair,
};

/// Querier-local counters the Engine folds into `Stats`.
pub const QStats = struct {
    /// `found` instances with no free resolve slot (no `resolved`, no
    /// follow-ups for them).
    instances_dropped: u64 = 0,
    /// Due questions that did not fit `max_due_questions` and wait for
    /// their next schedule step.
    questions_deferred: u64 = 0,
    /// Known-answer records that were needed in a query packet but could
    /// not be encoded (never expected; counted, not trapped).
    ka_encode_failed: u64 = 0,
};

pub const BrowseError = error{
    LimitReached,
    InvalidServiceType,
    /// A browse for this type is already active.
    DuplicateBrowse,
};

pub const Querier = struct {
    cache: Cache,
    browses: []Browse,
    instances: []Instance,
    /// Head instance index per name bucket (power-of-two length).
    inst_buckets: []u32,
    /// Head instance index per SRV-target bucket (same length).
    host_buckets: []u32,
    /// Instance index per cache pool slot (the PTR entry's slot), or
    /// `none`.
    ptr_to_inst: []u32,
    /// Secret seed for both instance chains.
    seed: u64,
    inst_used: usize,
    due: []Question,
    due_len: usize,
    jobs: []TxJob,
    jobs_head: usize,
    jobs_len: usize,
    random: std.Random,
    stats: QStats,
    /// Memo of the soonest timer; recomputed after every state change so
    /// `nextDeadline` costs nothing per call.
    next_deadline: ?u64,
    /// Scratch for canonical rdata while harvesting (largest TXT rdata a
    /// packet can carry).
    scratch: [wire.max_message_len]u8,

    pub const InitError = error{OutOfMemory};

    /// Preallocates every pool. The only allocation this module makes.
    pub fn init(gpa: std.mem.Allocator, limits: Limits, random: std.Random) InitError!Querier {
        var cache = try Cache.init(gpa, limits.max_cache_records, random.int(u64));
        errdefer cache.deinit(gpa);
        const n_browses: usize = @min(@max(@as(usize, limits.max_browses), 1), std.math.maxInt(u8) + 1);
        const browses = try gpa.alloc(Browse, n_browses);
        errdefer gpa.free(browses);
        const n_inst = cache.capacity();
        const instances = try gpa.alloc(Instance, n_inst);
        errdefer gpa.free(instances);
        const n_buckets = std.math.ceilPowerOfTwo(usize, @max(n_inst * 2, 16)) catch return error.OutOfMemory;
        const buckets = try gpa.alloc(u32, n_buckets);
        errdefer gpa.free(buckets);
        const host_buckets = try gpa.alloc(u32, n_buckets);
        errdefer gpa.free(host_buckets);
        const ptr_to_inst = try gpa.alloc(u32, n_inst);
        errdefer gpa.free(ptr_to_inst);
        const due = try gpa.alloc(Question, max_due_questions);
        errdefer gpa.free(due);
        const n_jobs: usize = 2 * @max(@as(usize, limits.max_interfaces), 1);
        const jobs = try gpa.alloc(TxJob, n_jobs);
        errdefer gpa.free(jobs);

        @memset(browses, .{});
        @memset(instances, .{});
        @memset(buckets, none);
        @memset(host_buckets, none);
        @memset(ptr_to_inst, none);
        return .{
            .cache = cache,
            .browses = browses,
            .instances = instances,
            .inst_buckets = buckets,
            .host_buckets = host_buckets,
            .ptr_to_inst = ptr_to_inst,
            .seed = random.int(u64),
            .inst_used = 0,
            .due = due,
            .due_len = 0,
            .jobs = jobs,
            .jobs_head = 0,
            .jobs_len = 0,
            .random = random,
            .stats = .{},
            .next_deadline = null,
            .scratch = undefined,
        };
    }

    pub fn deinit(q: *Querier, gpa: std.mem.Allocator) void {
        gpa.free(q.jobs);
        gpa.free(q.due);
        gpa.free(q.ptr_to_inst);
        gpa.free(q.host_buckets);
        gpa.free(q.inst_buckets);
        gpa.free(q.instances);
        gpa.free(q.browses);
        q.cache.deinit(gpa);
        q.* = undefined;
    }

    // ---- browses ------------------------------------------------------

    /// Start browsing `service_type` (`_qmsg._udp` form; RFC 6763 section
    /// 7, RFC 6335 names). Emits `found` at once for every live PTR of
    /// that type already in the cache (warm start) and schedules the
    /// first query 20-120 ms from `now_us`.
    pub fn browse(q: *Querier, service_type: []const u8, now_us: u64, sink: Sink) BrowseError!BrowseId {
        wire.validateServiceName(service_type) catch return error.InvalidServiceType;
        const type_name = serviceTypeName(service_type) catch return error.InvalidServiceType;
        if (q.findBrowse(&type_name) != null) return error.DuplicateBrowse;
        const slot = q.freeBrowseSlot() orelse return error.LimitReached;
        q.browses[slot] = .{
            .used = true,
            .service_type = type_name,
            .next_query_us = now_us +| timers.queryFirstDelayUs(q.random),
            .interval_us = 0,
        };
        // Warm start: PTRs cached while nobody browsed (plan section 4.5).
        var it = q.cache.lookup(&type_name, .ptr, wire.class_in);
        while (it.next()) |e| {
            if (!e.isLive()) continue;
            const index: u32 = q.indexOf(e);
            const inst = q.instanceByPtr(index) orelse q.createInstance(index);
            if (inst) |i| {
                i.dirty = true;
            }
            const instance = Name.fromWire(e.rdataSlice()) catch continue;
            sink.push(.{ .found = .{ .instance = instance, .service_type = e.name, .ifindex = e.ifindex } });
            q.careAbout(e, now_us);
        }
        q.joinDirty(now_us, sink);
        q.recomputeDeadline();
        return @fromBackingInt(@as(u8, @intCast(slot)));
    }

    /// Stop the schedule and the `found` / `lost` / `resolved` stream for
    /// that type. Cached records stay until they expire (plan section 5).
    pub fn stopBrowse(q: *Querier, id: BrowseId, now_us: u64) void {
        _ = now_us;
        const slot: usize = @backingInt(id);
        if (slot >= q.browses.len or !q.browses[slot].used) return;
        const type_name = q.browses[slot].service_type;
        q.browses[slot] = .{};
        // Drop the resolve state of that type's instances and the pins
        // on its PTRs (the records stay until they expire).
        var it = q.cache.lookup(&type_name, .ptr, wire.class_in);
        while (it.next()) |e| {
            e.flags.pinned = false;
            if (q.instanceByPtr(q.indexOf(e))) |inst| q.freeInstance(q.instanceIndex(inst));
        }
        q.recomputeDeadline();
    }

    pub fn browseCount(q: *const Querier) usize {
        var n: usize = 0;
        for (q.browses) |b| if (b.used) {
            n += 1;
        };
        return n;
    }

    /// `<type>.local` as a wire name.
    pub fn serviceTypeName(service_type: []const u8) error{InvalidServiceType}!Name {
        var n = Name.parse(service_type) catch return error.InvalidServiceType;
        n.appendName(Name.parse(local_domain) catch unreachable) catch return error.InvalidServiceType; // literal
        return n;
    }

    fn findBrowse(q: *const Querier, type_name: *const Name) ?usize {
        for (q.browses, 0..) |*b, i| {
            if (b.used and b.service_type.eql(type_name)) return i;
        }
        return null;
    }

    fn freeBrowseSlot(q: *const Querier) ?usize {
        for (q.browses, 0..) |*b, i| if (!b.used) return i;
        return null;
    }

    /// Restart every browse ladder from its first step (an interface was
    /// added: the new link has never seen our questions).
    pub fn restartSchedules(q: *Querier, now_us: u64) void {
        for (q.browses) |*b| {
            if (!b.used) continue;
            b.interval_us = 0;
            b.next_query_us = now_us +| timers.queryFirstDelayUs(q.random);
        }
        for (q.instances) |*inst| {
            if (!inst.used or inst.followup_next_us == null) continue;
            inst.followup_interval_us = 0;
            inst.followup_next_us = now_us +| timers.queryFirstDelayUs(q.random);
        }
        q.recomputeDeadline();
    }

    // ---- instances ----------------------------------------------------

    fn indexOf(q: *const Querier, e: *const Entry) u32 {
        const base = @intFromPtr(q.cache.entries.ptr);
        return @intCast((@intFromPtr(e) - base) / @sizeOf(Entry));
    }

    /// The PTR entry behind an instance, or null when the slot no longer
    /// holds it (defensive: it cannot happen while the state is used).
    fn ptrEntry(q: *Querier, inst: *const Instance) ?*Entry {
        if (inst.ptr_index >= q.cache.entries.len) return null;
        const e = &q.cache.entries[inst.ptr_index];
        if (!e.used or e.rtype != .ptr) return null;
        return e;
    }

    fn instanceName(q: *Querier, inst: *const Instance) ?Name {
        const e = q.ptrEntry(inst) orelse return null;
        return Name.fromWire(e.rdataSlice()) catch null;
    }

    fn instanceIndex(q: *const Querier, inst: *const Instance) u32 {
        const base = @intFromPtr(q.instances.ptr);
        return @intCast((@intFromPtr(inst) - base) / @sizeOf(Instance));
    }

    fn instanceByPtr(q: *Querier, ptr_index: u32) ?*Instance {
        if (ptr_index >= q.ptr_to_inst.len) return null;
        const i = q.ptr_to_inst[ptr_index];
        if (i == none) return null;
        const inst = &q.instances[i];
        if (!inst.used or inst.ptr_index != ptr_index) return null;
        return inst;
    }

    /// The instance named `name` on `ifindex`, or null.
    fn instanceByName(q: *Querier, name: *const Name, ifindex: u32) ?*Instance {
        const h = name.hash();
        var i = q.inst_buckets[q.bucketOfHash(h)];
        while (i != none) : (i = q.instances[i].next_in_bucket) {
            const inst = &q.instances[i];
            if (inst.name_hash != h or inst.ifindex != ifindex) continue;
            const n = q.instanceName(inst) orelse continue;
            if (n.eql(name)) return inst;
        }
        return null;
    }

    /// Bucket of a name or host hash under the secret seed (both chains
    /// have `inst_buckets.len` buckets).
    fn bucketOfHash(q: *const Querier, h: u64) usize {
        const mixed = std.hash.Wyhash.hash(q.seed, std.mem.asBytes(&h));
        return @intCast(mixed & (q.inst_buckets.len - 1));
    }

    fn createInstance(q: *Querier, ptr_index: u32) ?*Instance {
        const e = &q.cache.entries[ptr_index];
        const name = Name.fromWire(e.rdataSlice()) catch return null;
        var slot: ?usize = null;
        for (q.instances, 0..) |*inst, i| if (!inst.used) {
            slot = i;
            break;
        };
        const i = slot orelse {
            q.stats.instances_dropped += 1;
            return null;
        };
        const h = name.hash();
        const b = q.bucketOfHash(h);
        q.instances[i] = .{
            .used = true,
            .ptr_index = ptr_index,
            .ifindex = e.ifindex,
            .name_hash = h,
            .next_in_bucket = q.inst_buckets[b],
        };
        q.inst_buckets[b] = @intCast(i);
        q.ptr_to_inst[ptr_index] = @intCast(i);
        q.inst_used += 1;
        return &q.instances[i];
    }

    /// Drop the resolve state at `index` and the pins on the records it
    /// consumed (its SRV/TXT, and its host's A/AAAA unless another
    /// instance on the same interface lives on that host). The PTR entry
    /// must still be linked (it is, in every caller: expiry and eviction
    /// callbacks run before the unlink, `stopBrowse` walks live entries).
    fn freeInstance(q: *Querier, index: u32) void {
        const inst = &q.instances[index];
        if (!inst.used) return;
        if (q.instanceName(inst)) |name| {
            q.unpinAllOn(&name, .srv, inst.ifindex);
            q.unpinAllOn(&name, .txt, inst.ifindex);
            if (q.liveSrv(&name, inst.ifindex)) |s| {
                q.setHost(inst, null);
                if (!q.anyHostOn(s.srv.target.hash(), inst.ifindex)) {
                    q.unpinAllOn(&s.srv.target, .a, inst.ifindex);
                    q.unpinAllOn(&s.srv.target, .aaaa, inst.ifindex);
                }
            }
        }
        q.setHost(inst, null);
        const b = q.bucketOfHash(inst.name_hash);
        if (q.inst_buckets[b] == index) {
            q.inst_buckets[b] = inst.next_in_bucket;
        } else {
            var i = q.inst_buckets[b];
            while (i != none) : (i = q.instances[i].next_in_bucket) {
                if (q.instances[i].next_in_bucket == index) {
                    q.instances[i].next_in_bucket = inst.next_in_bucket;
                    break;
                }
            }
        }
        if (inst.ptr_index < q.ptr_to_inst.len and q.ptr_to_inst[inst.ptr_index] == index) {
            q.ptr_to_inst[inst.ptr_index] = none;
        }
        inst.* = .{};
        q.inst_used -= 1;
    }

    /// Set (or clear) the SRV-target hash of an instance, keeping the host
    /// chain in step.
    fn setHost(q: *Querier, inst: *Instance, host_hash: ?u64) void {
        if (inst.host_hash == host_hash) return;
        const index = q.instanceIndex(inst);
        if (inst.host_hash) |old| {
            const b = q.bucketOfHash(old);
            if (q.host_buckets[b] == index) {
                q.host_buckets[b] = inst.next_in_host_bucket;
            } else {
                var i = q.host_buckets[b];
                while (i != none) : (i = q.instances[i].next_in_host_bucket) {
                    if (q.instances[i].next_in_host_bucket == index) {
                        q.instances[i].next_in_host_bucket = inst.next_in_host_bucket;
                        break;
                    }
                }
            }
            inst.next_in_host_bucket = none;
            inst.host_hash = null;
        }
        if (host_hash) |h| {
            const b = q.bucketOfHash(h);
            inst.next_in_host_bucket = q.host_buckets[b];
            q.host_buckets[b] = index;
            inst.host_hash = h;
        }
    }

    /// Clear the eviction pin on every entry of one RRSet on one
    /// interface.
    fn unpinAllOn(q: *Querier, name: *const Name, rtype: RType, ifindex: u32) void {
        var it = q.cache.lookupOn(name, rtype, wire.class_in, ifindex);
        while (it.next()) |e| e.flags.pinned = false;
    }

    pub fn instanceCount(q: *const Querier) usize {
        return q.inst_used;
    }

    /// Mark every instance on `ifindex` whose SRV target is `host` dirty.
    /// Returns true when at least one matched.
    fn dirtyByHost(q: *Querier, host: *const Name, ifindex: u32) bool {
        const h = host.hash();
        var any = false;
        var i = q.host_buckets[q.bucketOfHash(h)];
        while (i != none) : (i = q.instances[i].next_in_host_bucket) {
            const inst = &q.instances[i];
            if (inst.host_hash != h or inst.ifindex != ifindex) continue;
            // Hash match; confirm through the live SRV target.
            const name = q.instanceName(inst) orelse continue;
            const srv = q.liveSrv(&name, inst.ifindex) orelse continue;
            if (!srv.srv.target.eql(host)) continue;
            inst.dirty = true;
            any = true;
        }
        return any;
    }

    /// Whether any instance on `ifindex` has an SRV target hashing to `h`
    /// (host chain walk).
    fn anyHostOn(q: *const Querier, h: u64, ifindex: u32) bool {
        var i = q.host_buckets[q.bucketOfHash(h)];
        while (i != none) : (i = q.instances[i].next_in_host_bucket) {
            const inst = &q.instances[i];
            if (inst.host_hash == h and inst.ifindex == ifindex) return true;
        }
        return false;
    }

    // ---- cache eviction hook -------------------------------------------

    /// The cache reports every eviction here before the unlink, so the
    /// resolve state follows it exactly as on expiry. Pinned entries go
    /// only when every entry is pinned (`cache.zig`). The context lives
    /// on the caller's stack for the duration of one `upsert`.
    const HookCtx = struct { q: *Querier, sink: Sink };

    fn evictFn(ctx: ?*anyopaque, e: *const Entry) void {
        const hc: *HookCtx = @ptrCast(@alignCast(ctx.?));
        hc.q.onExpired(e, hc.sink);
    }

    // ---- ingress ------------------------------------------------------

    /// Harvest every answer and additional record of a response into the
    /// cache, then run the resolve join for the instances it touched.
    /// Never allocates, never fails: an unusable record is skipped.
    pub fn handleResponse(q: *Querier, msg: *const wire.Message, ifindex: u32, now_us: u64, sink: Sink) void {
        var touched = false;
        var it = msg.allRecords();
        while (it.next()) |rec| {
            if (rec.section == .authority) continue;
            if (rec.class != wire.class_in) continue;
            if (q.harvest(msg, rec, ifindex, now_us, sink)) touched = true;
        }
        if (touched) q.joinDirty(now_us, sink);
        q.recomputeDeadline();
    }

    /// One record into the cache with the plan section 4.5 reactions.
    /// Returns true when an instance was marked dirty or created.
    fn harvest(q: *Querier, msg: *const wire.Message, rec: wire.Record, ifindex: u32, now_us: u64, sink: Sink) bool {
        switch (rec.rtype) {
            .a => _ = wire.rdata.decodeA(rec.rdata) catch return false,
            .aaaa => _ = wire.rdata.decodeAaaa(rec.rdata) catch return false,
            .txt => _ = wire.rdata.decodeTxt(rec) catch return false,
            .srv => _ = wire.rdata.decodeSrv(msg.bytes, rec) catch return false,
            .ptr => {},
            else => return false,
        }
        const rdata = wire.rdata.canonicalRdata(msg.bytes, rec, &q.scratch) catch return false;
        var hc: HookCtx = .{ .q = q, .sink = sink };
        const result = q.cache.upsert(.{
            .name = rec.name,
            .rtype = rec.rtype,
            .class = rec.class,
            .ttl_s = rec.ttl,
            .rdata = rdata,
            .ifindex = ifindex,
        }, now_us, rec.cache_flush, .{ .ctx = @ptrCast(&hc), .f = evictFn });
        if (result.outcome == .rejected) return false;
        const index = result.index orelse return false;
        const e = q.cache.entryAt(index);

        switch (rec.rtype) {
            .ptr => {
                if (q.findBrowse(&rec.name) == null) return false; // foreign type: cached, no event
                var inst = q.instanceByPtr(index);
                if (result.outcome == .added) {
                    if (inst == null) inst = q.createInstance(index);
                    const instance = Name.fromWire(e.rdataSlice()) catch return false;
                    sink.push(.{ .found = .{ .instance = instance, .service_type = e.name, .ifindex = e.ifindex } });
                } else if (inst == null and e.isLive()) {
                    inst = q.createInstance(index);
                }
                if (inst) |i| {
                    i.dirty = true;
                    // A PTR that (re)appears live lifts a goodbye
                    // suppression; a plain refresh does not.
                    if (result.outcome != .unchanged and e.isLive()) i.followups_suppressed = false;
                }
                q.careAbout(e, now_us);
                return inst != null;
            },
            .srv, .txt => {
                const inst = q.instanceByName(&rec.name, ifindex) orelse return false;
                inst.dirty = true;
                if (e.isLive()) {
                    inst.followups_suppressed = false;
                    // Provisional pin until the join re-derives the pins
                    // of the whole RRSet (so the packet's later records
                    // cannot evict it first); the marks come from the
                    // join, which consumes exactly one live SRV and TXT.
                    e.flags.pinned = true;
                }
                return true;
            },
            .a, .aaaa => {
                if (!q.dirtyByHost(&rec.name, ifindex)) return false;
                if (e.isLive()) e.flags.pinned = true; // provisional, see above
                return true;
            },
            else => return false,
        }
    }

    /// A record the resolve join consumes (or a browsed PTR): pin it
    /// against eviction (plan section 4.5) and schedule its section 5.2
    /// requery marks, once per refresh (`upsert` clears the mark on every
    /// refresh, and keeps the pin).
    fn careAbout(q: *Querier, e: *Entry, now_us: u64) void {
        if (!e.isLive()) return;
        e.flags.pinned = true;
        if (e.next_requery_us != null or e.requery_idx != 0) return;
        _ = Cache.scheduleRequery(e, now_us, q.random);
    }

    /// Still of local interest (RFC 6762 section 5.2 MUST NOT re-query
    /// otherwise): used when a mark pops, so a stopped browse silently
    /// ends the marks of its records.
    fn caredAbout(q: *Querier, e: *const Entry) bool {
        return switch (e.rtype) {
            .ptr => q.findBrowse(&e.name) != null,
            .srv, .txt => q.instanceByName(&e.name, e.ifindex) != null,
            .a, .aaaa => q.anyHostOn(e.name.hash(), e.ifindex),
            else => false,
        };
    }

    // ---- resolve join -------------------------------------------------

    fn srvTarget(e: *const Entry) ?Name {
        const rd = e.rdataSlice();
        if (rd.len < wire.Srv.fixed_len) return null;
        return Name.fromWire(rd[wire.Srv.fixed_len..]) catch null;
    }

    const LiveSrv = struct { entry: *Entry, srv: wire.Srv };

    fn liveSrv(q: *Querier, instance: *const Name, ifindex: u32) ?LiveSrv {
        var it = q.cache.lookupOn(instance, .srv, wire.class_in, ifindex);
        while (it.next()) |e| {
            if (!e.isLive()) continue;
            const rd = e.rdataSlice();
            if (rd.len < wire.Srv.fixed_len) continue;
            const target = Name.fromWire(rd[wire.Srv.fixed_len..]) catch continue;
            return .{ .entry = e, .srv = .{
                .priority = std.mem.readInt(u16, rd[0..2], .big),
                .weight = std.mem.readInt(u16, rd[2..4], .big),
                .port = std.mem.readInt(u16, rd[4..6], .big),
                .target = target,
            } };
        }
        return null;
    }

    fn liveFirst(q: *Querier, name: *const Name, rtype: RType, ifindex: u32) ?*Entry {
        var it = q.cache.lookupOn(name, rtype, wire.class_in, ifindex);
        while (it.next()) |e| {
            if (e.isLive()) return e;
        }
        return null;
    }

    /// A goodbye (section 10.1) for `(name, rtype)` on `ifindex` is in
    /// its grace second.
    fn hasGoodbye(q: *Querier, name: *const Name, rtype: RType, ifindex: u32) bool {
        var it = q.cache.lookupOn(name, rtype, wire.class_in, ifindex);
        while (it.next()) |e| {
            if (e.flags.goodbye_pending) return true;
        }
        return false;
    }

    fn joinDirty(q: *Querier, now_us: u64, sink: Sink) void {
        for (q.instances) |*inst| {
            if (!inst.used or !inst.dirty) continue;
            inst.dirty = false;
            q.join(inst, now_us, sink);
        }
    }

    /// The plan section 5 "resolved re-emit rule" for one instance. Also
    /// the one place that decides which records a client cares about:
    /// the SRV, TXT and addresses it reads get their pins and requery
    /// marks here, whatever order they arrived in. Every lookup is on
    /// the instance's interface: the join never mixes what two
    /// interfaces heard.
    fn join(q: *Querier, inst: *Instance, now_us: u64, sink: Sink) void {
        const name = q.instanceName(inst) orelse return;
        const ifindex = inst.ifindex;
        const srv = q.liveSrv(&name, ifindex);
        const txt = q.liveFirst(&name, .txt, ifindex);
        // Pins follow the join: the consumed SRV / TXT keep theirs, every
        // other member of the RRSet (a second SRV, junk) loses it.
        q.unpinAllOn(&name, .srv, ifindex);
        q.unpinAllOn(&name, .txt, ifindex);
        var addrs: events.Bounded(Io.net.IpAddress, events.max_resolved_addrs) = .{};
        var addr_digest: u64 = 0;
        var min_ttl: u32 = std.math.maxInt(u32);
        if (srv) |s| {
            q.setHost(inst, s.srv.target.hash());
            q.careAbout(s.entry, now_us);
            min_ttl = @min(min_ttl, s.entry.remainingTtlS(now_us));
            q.collectAddrs(&s.srv.target, s.srv.port, ifindex, now_us, &addrs, &addr_digest, &min_ttl);
        }
        if (txt) |t| {
            q.careAbout(t, now_us);
            min_ttl = @min(min_ttl, t.remainingTtlS(now_us));
        }

        const complete = srv != null and txt != null and addrs.len != 0;
        if (!complete) {
            // Not resolvable: (re)start the follow-up ladder, unless the
            // responder said goodbye to the PTR or to the missing SRV/TXT
            // (section 10.1): asking again would be pointless.
            const ptr_live = if (q.ptrEntry(inst)) |pe| pe.isLive() else false;
            if (!ptr_live or (srv == null and q.hasGoodbye(&name, .srv, ifindex)) or (txt == null and q.hasGoodbye(&name, .txt, ifindex))) {
                inst.followups_suppressed = true;
            }
            if (inst.followups_suppressed) {
                inst.followup_next_us = null;
                inst.followup_interval_us = 0;
                return;
            }
            if (inst.followup_next_us == null) {
                inst.followup_interval_us = 0;
                inst.followup_next_us = now_us +| timers.queryFirstDelayUs(q.random);
            }
            return;
        }
        inst.followup_next_us = null;
        inst.followup_interval_us = 0;

        const s = srv.?;
        const srv_digest = std.hash.Wyhash.hash(digest_seed, s.entry.rdataSlice());
        const txt_digest = std.hash.Wyhash.hash(digest_seed, txt.?.rdataSlice());
        if (inst.emitted and inst.srv_digest == srv_digest and inst.txt_digest == txt_digest and inst.addr_digest == addr_digest) return;
        inst.emitted = true;
        inst.srv_digest = srv_digest;
        inst.txt_digest = txt_digest;
        inst.addr_digest = addr_digest;

        const txt_value = wire.Txt.fromWire(txt.?.rdataSlice()) catch wire.Txt.empty;
        const type_name = if (q.ptrEntry(inst)) |pe| pe.name else name.parent();
        sink.push(.{ .resolved = .{
            .instance = name,
            .service_type = type_name,
            .host = s.srv.target,
            .port = s.srv.port,
            .addrs = addrs,
            .txt = txt_value,
            .ifindex = ifindex,
            .ttl_s = if (min_ttl == std.math.maxInt(u32)) 0 else min_ttl,
        } });
    }

    /// Every live A then AAAA of `host` heard on `ifindex` (at most 8 per
    /// family, plan section 4.8) as `IpAddress` values with `port`;
    /// link-local v6 carries the record's arrival interface (RFC 6762
    /// section 15, plan section 5). Each listed record is pinned and gets
    /// its requery marks. The digest is order-independent (a wrapping sum
    /// of per-address hashes).
    fn collectAddrs(
        q: *Querier,
        host: *const Name,
        port: u16,
        ifindex: u32,
        now_us: u64,
        addrs: *events.Bounded(Io.net.IpAddress, events.max_resolved_addrs),
        digest: *u64,
        min_ttl: *u32,
    ) void {
        q.unpinAllOn(host, .a, ifindex);
        q.unpinAllOn(host, .aaaa, ifindex);
        var n4: usize = 0;
        var it4 = q.cache.lookupOn(host, .a, wire.class_in, ifindex);
        while (it4.next()) |e| {
            if (n4 == events.max_addrs_per_family) break;
            if (!e.isLive() or e.rdata_len != 4) continue;
            const bytes = e.rdata[0..4].*;
            addrs.append(.{ .ip4 = .{ .bytes = bytes, .port = port } }) catch break;
            n4 += 1;
            q.careAbout(e, now_us);
            digest.* +%= std.hash.Wyhash.hash(digest_seed + 4, &bytes);
            min_ttl.* = @min(min_ttl.*, e.remainingTtlS(now_us));
        }
        var n6: usize = 0;
        var it6 = q.cache.lookupOn(host, .aaaa, wire.class_in, ifindex);
        while (it6.next()) |e| {
            if (n6 == events.max_addrs_per_family) break;
            if (!e.isLive() or e.rdata_len != 16) continue;
            const bytes = e.rdata[0..16].*;
            const link_local = events.isLinkLocal6(bytes);
            const scope: u32 = if (link_local) e.ifindex else 0;
            addrs.append(.{ .ip6 = .{ .bytes = bytes, .port = port, .interface = .{ .index = scope } } }) catch break;
            n6 += 1;
            q.careAbout(e, now_us);
            var keyed: [20]u8 = undefined;
            keyed[0..16].* = bytes;
            std.mem.writeInt(u32, keyed[16..20], scope, .big);
            digest.* +%= std.hash.Wyhash.hash(digest_seed + 6, &keyed);
            min_ttl.* = @min(min_ttl.*, e.remainingTtlS(now_us));
        }
    }

    // ---- timers -------------------------------------------------------

    /// Fire due timers: cache expiry (`lost`, address-set changes), browse
    /// queries, follow-ups and requery marks. Newly due questions are
    /// batched for every pair in `pairs` and go out through `buildNext`.
    pub fn tick(q: *Querier, now_us: u64, pairs: []const Pair, sink: Sink) void {
        q.expire(now_us, sink);

        // A question that does not fit the batch (`addDue` false) leaves
        // its schedule untouched, so it retries at the next tick instead
        // of skipping a doubled step.
        for (q.browses) |*b| {
            if (!b.used or b.next_query_us > now_us) continue;
            if (!q.addDue(.{ .name = b.service_type, .rtype = .ptr })) continue;
            b.interval_us = q.nextGapUs(b.interval_us);
            b.next_query_us = now_us +| b.interval_us;
        }

        for (q.instances) |*inst| {
            if (!inst.used) continue;
            const due = inst.followup_next_us orelse continue;
            if (due > now_us) continue;
            const added = q.addFollowups(inst) orelse {
                inst.followup_next_us = null;
                inst.followup_interval_us = 0;
                continue;
            };
            if (!added) continue;
            inst.followup_interval_us = q.nextGapUs(inst.followup_interval_us);
            inst.followup_next_us = now_us +| inst.followup_interval_us;
        }

        const RequeryCtx = struct { q: *Querier, now_us: u64 };
        _ = q.cache.popDueRequeries(now_us, RequeryCtx{ .q = q, .now_us = now_us }, struct {
            fn cb(ctx: RequeryCtx, e: *Entry) void {
                if (!ctx.q.caredAbout(e)) {
                    e.flags.pinned = false;
                    return;
                }
                if (!ctx.q.addDue(.{ .name = e.name, .rtype = e.rtype, .ifindex = e.ifindex })) {
                    // Batch full: keep this mark for the next tick.
                    e.next_requery_us = ctx.now_us;
                    return;
                }
                _ = Cache.scheduleRequery(e, ctx.now_us, ctx.q.random);
            }
        }.cb);

        if (q.due_len != 0 and q.jobs_len == 0) {
            if (pairs.len == 0) {
                q.due_len = 0; // nowhere to send
            } else {
                for (pairs) |p| {
                    if (q.jobs_len == q.jobs.len) break;
                    q.jobs[(q.jobs_head + q.jobs_len) % q.jobs.len] = .{ .pair = p };
                    q.jobs_len += 1;
                }
            }
        }

        q.joinDirty(now_us, sink);
        q.recomputeDeadline();
    }

    /// The next ladder gap after `prev_us` (0 = the first gap): doubled,
    /// capped at 60 min, plus 0-2 % jitter. The jittered gap is what the
    /// caller stores, so consecutive real gaps keep the factor of two
    /// (RFC 6762 section 5.2) and the capped steady state stays within
    /// 3600-3672 s.
    fn nextGapUs(q: *Querier, prev_us: u64) u64 {
        const base = timers.nextQueryIntervalUs(@min(prev_us, timers.query_interval_cap_us));
        return timers.jitterPct(q.random, base, timers.query_jitter_max_pct);
    }

    /// Queue the SRV / TXT / A / AAAA questions a found instance still
    /// needs on its interface. Null when it needs none (or its ladder is
    /// suppressed by a goodbye); otherwise whether every one of them fit
    /// the batch (a partial fit retries whole at the next tick). The
    /// questions are scoped to the instance's interface (`buildNext`
    /// leaves them out of the other pairs' packets): an instance heard
    /// on one link is resolved on that link, and its follow-ups do not
    /// multiply with the interface count.
    fn addFollowups(q: *Querier, inst: *Instance) ?bool {
        if (inst.followups_suppressed) return null;
        const name = q.instanceName(inst) orelse return null;
        const ifindex = inst.ifindex;
        var needed = false;
        var all_queued = true;
        const srv = q.liveSrv(&name, ifindex);
        if (srv == null) {
            needed = true;
            if (!q.addDue(.{ .name = name, .rtype = .srv, .ifindex = ifindex })) all_queued = false;
        }
        if (q.liveFirst(&name, .txt, ifindex) == null) {
            needed = true;
            if (!q.addDue(.{ .name = name, .rtype = .txt, .ifindex = ifindex })) all_queued = false;
        }
        if (srv) |s| {
            if (q.liveFirst(&s.srv.target, .a, ifindex) == null and q.liveFirst(&s.srv.target, .aaaa, ifindex) == null) {
                needed = true;
                if (!q.addDue(.{ .name = s.srv.target, .rtype = .a, .ifindex = ifindex })) all_queued = false;
                if (!q.addDue(.{ .name = s.srv.target, .rtype = .aaaa, .ifindex = ifindex })) all_queued = false;
            }
        }
        if (!needed) return null;
        return all_queued;
    }

    /// Queue a question for the next packet. True when it is in the
    /// batch (already there counts: the same question for every pair, or
    /// for this one); false when the batch is full, which is counted in
    /// `questions_deferred`. Two entries for the same question on
    /// different interfaces can coexist, and an every-pair entry beside
    /// an interface-scoped one: `buildNext` encodes each question once
    /// per packet.
    fn addDue(q: *Querier, question: Question) bool {
        for (q.due[0..q.due_len]) |*d| {
            if (!d.eql(&question)) continue;
            if (d.ifindex == null or d.ifindex == question.ifindex) return true;
        }
        if (q.due_len == q.due.len) {
            q.stats.questions_deferred += 1;
            return false;
        }
        q.due[q.due_len] = question;
        q.due_len += 1;
        return true;
    }

    const ExpireCtx = struct { q: *Querier, sink: Sink };

    fn expire(q: *Querier, now_us: u64, sink: Sink) void {
        _ = q.cache.expireDue(now_us, ExpireCtx{ .q = q, .sink = sink }, struct {
            fn cb(ctx: ExpireCtx, e: *const Entry) void {
                ctx.q.onExpired(e, ctx.sink);
            }
        }.cb);
    }

    /// An interface left the table: drop every record heard on it and
    /// the resolve state bound to it, through the expiry path (browsed
    /// PTRs emit `lost{ifindex}`, instances are freed, pins go), so
    /// nothing of a vanished interface lingers until its TTL, re-queries
    /// on the surviving interfaces, or attaches to a reused index (RFC
    /// 6762 section 14: results belong to the interface they were heard
    /// on). Never allocates (one pool walk). The Engine calls it from
    /// `setInterfaces`.
    pub fn dropInterface(q: *Querier, ifindex: u32, sink: Sink) void {
        _ = q.cache.expireInterface(ifindex, ExpireCtx{ .q = q, .sink = sink }, struct {
            fn cb(ctx: ExpireCtx, e: *const Entry) void {
                ctx.q.onExpired(e, ctx.sink);
            }
        }.cb);
        q.recomputeDeadline();
    }

    /// Called for each entry about to leave the cache, by expiry or by
    /// eviction (it is still linked, so lookups must not rely on it being
    /// gone).
    fn onExpired(q: *Querier, e: *const Entry, sink: Sink) void {
        switch (e.rtype) {
            .ptr => {
                const index = q.indexOf(e);
                if (q.instanceByPtr(index)) |inst| q.freeInstance(q.instanceIndex(inst));
                if (q.findBrowse(&e.name) == null) return;
                const instance = Name.fromWire(e.rdataSlice()) catch return;
                sink.push(.{ .lost = .{ .instance = instance, .service_type = e.name, .ifindex = e.ifindex } });
            },
            .srv, .txt => {
                if (q.instanceByName(&e.name, e.ifindex)) |inst| inst.dirty = true;
            },
            .a, .aaaa => _ = q.dirtyByHost(&e.name, e.ifindex),
            else => {},
        }
    }

    /// Soonest timer over browses, follow-ups, requery marks and cache
    /// expiry (memoised).
    pub fn nextDeadline(q: *const Querier) ?u64 {
        return q.next_deadline;
    }

    pub fn hasPendingTx(q: *const Querier) bool {
        return q.jobs_len != 0;
    }

    fn recomputeDeadline(q: *Querier) void {
        var best: ?u64 = null;
        for (q.browses) |*b| if (b.used) {
            best = minOpt(best, b.next_query_us);
        };
        for (q.instances) |*inst| {
            if (!inst.used) continue;
            if (inst.followup_next_us) |t| best = minOpt(best, t);
        }
        if (q.cache.nextExpiryUs()) |t| best = minOpt(best, t);
        if (q.cache.nextRequeryUs()) |t| best = minOpt(best, t);
        q.next_deadline = best;
    }

    fn minOpt(a: ?u64, b: u64) u64 {
        return if (a) |x| @min(x, b) else b;
    }

    // ---- egress -------------------------------------------------------

    /// Build the next query packet of the current batch into `buf`: the
    /// due questions (QM, ID 0) and the known-answer list, continued over
    /// further packets with TC set when it does not fit (RFC 6762
    /// sections 5.3, 7.1, 7.2, 18.1). Null when nothing is pending.
    pub fn buildNext(q: *Querier, buf: []u8, now_us: u64) ?Built {
        while (q.jobs_len != 0) {
            if (buf.len < wire.Header.len) {
                q.popJob();
                continue;
            }
            const job = &q.jobs[q.jobs_head];
            var b: wire.Builder = .init(buf, .{ .family = switch (job.pair.family) {
                .v4 => .v4,
                .v6 => .v6,
            } });
            b.setId(0);

            // Questions (section 5.3: as many as fit), those for this
            // pair's interface only, each once.
            while (job.q_pos < q.due_len) {
                const d = &q.due[job.q_pos];
                if (!d.appliesTo(job.pair.ifindex) or q.dueBefore(job.q_pos, job.pair.ifindex)) {
                    job.q_pos += 1;
                    continue;
                }
                b.addQuestion(d.name, d.rtype, wire.class_in, false) catch |err| switch (err) {
                    error.NoSpace => {
                        if (b.questionCount() != 0) break;
                        job.q_pos += 1; // cannot happen (a question is < 300 B); skip, never spin
                        continue;
                    },
                    else => {
                        job.q_pos += 1;
                        continue;
                    },
                };
                job.q_pos += 1;
            }
            var more = job.q_pos < q.due_len;

            // Known answers (section 7.1), resumable (section 7.2).
            if (!more) {
                while (job.ka_pos < q.cache.entries.len) {
                    const e = &q.cache.entries[job.ka_pos];
                    if (!q.isKnownAnswer(e, now_us, job.pair.ifindex)) {
                        job.ka_pos += 1;
                        continue;
                    }
                    b.addRR(.answer, e.name, e.rtype, wire.class_in, false, e.remainingTtlS(now_us), .{ .raw = e.rdataSlice() }) catch |err| switch (err) {
                        error.NoSpace => {
                            if (b.recordCount() == 0 and b.questionCount() == 0) {
                                // A lone record over the hard cap: cannot happen (rdata <= 400 B).
                                q.stats.ka_encode_failed += 1;
                                job.ka_pos += 1;
                                continue;
                            }
                            more = true;
                            break;
                        },
                        else => {
                            q.stats.ka_encode_failed += 1;
                            job.ka_pos += 1;
                            continue;
                        },
                    };
                    job.ka_pos += 1;
                }
            }
            b.setTruncated(more);
            const pair = job.pair;
            if (b.isEmpty()) {
                // Nothing to send on this pair (every due question was
                // unencodable): drop the job rather than spin.
                q.popJob();
                continue;
            }
            if (!more) q.popJob();
            const packet = b.finish();
            return .{ .len = packet.len, .pair = pair };
        }
        return null;
    }

    /// Is the question at `pos` already covered, for `ifindex`'s packet,
    /// by an earlier due entry (same name and type, applying to that
    /// interface)? Keeps a per-interface requery mark and an every-pair
    /// browse question from appearing twice in one packet.
    fn dueBefore(q: *const Querier, pos: usize, ifindex: u32) bool {
        const d = &q.due[pos];
        for (q.due[0..pos]) |*earlier| {
            if (earlier.appliesTo(ifindex) and earlier.eql(d)) return true;
        }
        return false;
    }

    fn popJob(q: *Querier) void {
        q.jobs_head = (q.jobs_head + 1) % q.jobs.len;
        q.jobs_len -= 1;
        if (q.jobs_len == 0) q.due_len = 0;
    }

    /// RFC 6762 section 7.1: a cached live record heard on `ifindex` that
    /// answers one of the due questions and is not yet past half its TTL.
    /// Records heard on other interfaces are not listed: a responder on
    /// this link has not necessarily given them, and listing them would
    /// suppress its answer (section 7.1) until the record passes half
    /// its TTL.
    fn isKnownAnswer(q: *const Querier, e: *const Entry, now_us: u64, ifindex: u32) bool {
        if (!e.used or !e.isLive() or e.class != wire.class_in) return false;
        if (e.ifindex != ifindex) return false;
        if (e.pastHalfTtl(now_us)) return false;
        for (q.due[0..q.due_len]) |*d| {
            if (d.appliesTo(ifindex) and d.rtype == e.rtype and d.name.eql(&e.name)) return true;
        }
        return false;
    }
};

// ---- pure helpers under test ------------------------------------------

/// The unjittered RFC 6762 section 5.2 ladder: the `n`-th query (0-based)
/// of a question goes out at `firstDelayUs + sum(intervals)`. Exposed for
/// tests and docs.
pub fn ladderOffsetUs(n: u32) u64 {
    var t: u64 = 0;
    var step: u32 = 0;
    while (step < n) : (step += 1) t += timers.queryIntervalUs(step);
    return t;
}

// ---- tests -----------------------------------------------------------

const testing = std.testing;

const NullSink = struct {
    fn emit(_: *anyopaque, _: Event) void {}
};
var null_ctx: u8 = 0;
const null_sink: Sink = .{ .ctx = &null_ctx, .emit = NullSink.emit };

test "ladder computation doubles from 1 s and caps at 60 min" {
    try testing.expectEqual(@as(u64, 0), ladderOffsetUs(0));
    try testing.expectEqual(timers.s(1), ladderOffsetUs(1));
    try testing.expectEqual(timers.s(3), ladderOffsetUs(2));
    try testing.expectEqual(timers.s(7), ladderOffsetUs(3));
    try testing.expectEqual(timers.s(4095), ladderOffsetUs(12));
    // Step 12 is 4096 s > 3600 s: capped from there on.
    try testing.expectEqual(timers.s(4095 + 3600), ladderOffsetUs(13));
    try testing.expectEqual(timers.s(4095 + 2 * 3600), ladderOffsetUs(14));
    try testing.expectEqual(@as(u32, 35), timers.query_schedule_24h_count);
}

test "KA half-TTL filter" {
    var prng = std.Random.DefaultPrng.init(1);
    var q = try Querier.init(testing.allocator, .{ .max_cache_records = 8, .max_browses = 2, .max_interfaces = 1 }, prng.random());
    defer q.deinit(testing.allocator);
    const name = try Name.parse("_x._udp.local");
    const target = try Name.parse("a._x._udp.local");
    var rd: [256]u8 = undefined;
    const n = try target.encode(&rd);
    const r = q.cache.upsert(.{ .name = name, .rtype = .ptr, .class = wire.class_in, .ttl_s = 100, .rdata = rd[0..n], .ifindex = 1 }, 0, false, .none);
    const e = q.cache.entryAt(r.index.?);
    // No due question: never a known answer.
    try testing.expect(!q.isKnownAnswer(e, 10, 1));
    _ = q.addDue(.{ .name = name, .rtype = .ptr });
    try testing.expect(q.isKnownAnswer(e, 10, 1));
    try testing.expect(q.isKnownAnswer(e, timers.s(49), 1));
    try testing.expect(!q.isKnownAnswer(e, timers.s(50), 1));
    // A record heard on interface 1 is not a known answer for a query
    // going out on interface 2.
    try testing.expect(!q.isKnownAnswer(e, 10, 2));
    // A different type is not an answer to a PTR question.
    q.due_len = 0;
    _ = q.addDue(.{ .name = name, .rtype = .srv });
    try testing.expect(!q.isKnownAnswer(e, 10, 1));
}

test "resolve-join decision emits once and again on change" {
    var prng = std.Random.DefaultPrng.init(2);
    var q = try Querier.init(testing.allocator, .{ .max_cache_records = 16, .max_browses = 2, .max_interfaces = 1 }, prng.random());
    defer q.deinit(testing.allocator);
    const Collector = struct {
        n: usize = 0,
        last: ?Resolved = null,
        fn emit(ctx: *anyopaque, ev: Event) void {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            if (ev == .resolved) {
                c.n += 1;
                c.last = ev.resolved;
            }
        }
    };
    var col: Collector = .{};
    const sink: Sink = .{ .ctx = &col, .emit = Collector.emit };

    _ = try q.browse("_x._udp", 0, sink);
    const type_name = try Name.parse("_x._udp.local");
    const inst_name = try Name.parse("a._x._udp.local");
    const host = try Name.parse("h.local");
    var rd: [300]u8 = undefined;
    var n = try inst_name.encode(&rd);
    const pr = q.cache.upsert(.{ .name = type_name, .rtype = .ptr, .class = wire.class_in, .ttl_s = 4500, .rdata = rd[0..n], .ifindex = 1 }, 0, false, .none);
    const inst = q.createInstance(pr.index.?).?;
    q.join(inst, 0, sink);
    try testing.expectEqual(@as(usize, 0), col.n);
    try testing.expect(inst.followup_next_us != null);

    n = try wire.rdata.encodeSrv(.{ .port = 8080, .target = host }, &rd);
    _ = q.cache.upsert(.{ .name = inst_name, .rtype = .srv, .class = wire.class_in, .ttl_s = 120, .rdata = rd[0..n], .ifindex = 1 }, 0, false, .none);
    _ = q.cache.upsert(.{ .name = inst_name, .rtype = .txt, .class = wire.class_in, .ttl_s = 4500, .rdata = &.{0}, .ifindex = 1 }, 0, false, .none);
    q.join(inst, 0, sink);
    try testing.expectEqual(@as(usize, 0), col.n); // no address yet
    _ = q.cache.upsert(.{ .name = host, .rtype = .a, .class = wire.class_in, .ttl_s = 120, .rdata = &.{ 10, 0, 0, 5 }, .ifindex = 1 }, 0, false, .none);
    q.join(inst, 0, sink);
    try testing.expectEqual(@as(usize, 1), col.n);
    try testing.expectEqual(@as(u16, 8080), col.last.?.port);
    try testing.expectEqual(@as(u32, 120), col.last.?.ttl_s);
    try testing.expectEqual(null, inst.followup_next_us);
    // Same data again: nothing.
    q.join(inst, 5, sink);
    try testing.expectEqual(@as(usize, 1), col.n);
    // A second address: re-emit with two.
    _ = q.cache.upsert(.{ .name = host, .rtype = .a, .class = wire.class_in, .ttl_s = 120, .rdata = &.{ 10, 0, 0, 6 }, .ifindex = 1 }, 5, false, .none);
    q.join(inst, 5, sink);
    try testing.expectEqual(@as(usize, 2), col.n);
    try testing.expectEqual(@as(usize, 2), col.last.?.addrs.len);
}
