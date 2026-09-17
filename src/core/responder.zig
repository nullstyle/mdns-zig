//! Responder: registrations, the RFC 6762 section 8 probe / announce
//! state machine, section 9 conflict handling, section 6 answering
//! (delays, aggregation, known-answer suppression, the per-(record,
//! interface) rate limit, NSEC negative answers, legacy and QU replies)
//! and section 10.1 goodbyes (plan sections 4.4, 4.5, 4.8, 5, 6
//! `core/responder.zig`, milestone M4).
//!
//! The Engine owns one `Responder` and drives it with the Engine's own
//! contract: no clock, no socket, no allocation after `init`, no failure
//! on a path fed by network bytes. Time is the caller's `now_us`,
//! randomness the injected `std.Random`, and everything the responder
//! needs from the Engine (the interface table, the joined pairs, the
//! port-sharing flags, the event sink) arrives in an `Env` on every call,
//! so nothing here stores a pointer to the Engine.
//!
//! Model:
//! - The **host** is `<label>.local` with one A per kept v4 address and
//!   one AAAA per kept v6 address *of the interface a packet goes out on*
//!   (section 6.2). It is a unique RRSet (TTL 120, section 10). It is
//!   probed together with the first registration and said goodbye to
//!   with the last one. A host-name conflict renames it `<label>-2`
//!   (plan section 4.8 "Host-name conflicts"); every SRV then changes
//!   rdata and is re-announced (section 8.4).
//! - A **registration** is one DNS-SD instance: `<instance>.<type>.local`
//!   with SRV (TTL 120) and TXT (TTL 4500) as unique RRSets and a shared
//!   PTR `<type>.local -> <instance>` (TTL 4500; RFC 6763 section 4). An
//!   instance-name conflict renames it `Name (2)`.
//! - **Probing** (section 8.1): a random 0-250 ms first delay, then three
//!   probes 250 ms apart, qtype ANY, the proposed records in the
//!   Authority section, QU only when `Env.qu_allowed` (plan section 4.8
//!   "QU policy"), one packet per joined (interface, family) pair. Probe
//!   records never carry cache-flush (section 10.2). A registration whose
//!   three probes are done waits for the host when the host is still
//!   probing (its SRV names the host).
//! - **Tie-break** (section 8.2): a probe from another host for a name
//!   we are probing compares the two proposed record sets, each sorted
//!   by (class, type, rdata); the set that is lexicographically later
//!   wins, and the set that runs out first loses. A loser waits one
//!   second and probes again; a second loss renames (plan M4).
//! - **Announcing** (section 8.3): two unsolicited responses one second
//!   apart, cache-flush on the unique records, PTR without. `registered`
//!   fires when the second one is queued.
//! - **Conflicts** (section 9): a response carrying one of our unique
//!   names with different rdata resets that name to probing with the
//!   *same* name; only a failed probe (a conflicting response while
//!   probing, or a second tie-break loss) renames (plan section 4.8
//!   "Conflict order"). Fifteen conflicts in ten seconds delay the next
//!   probe by five seconds. Own echoes never reach this file: the Engine
//!   drops them (digest AND source address, plan section 4.8), so a peer
//!   on our own IP with different rdata is a real conflict.
//! - **Answering** (section 6): unique records answer at once, shared
//!   PTRs after a random 20-120 ms (400-500 ms after a TC query, section
//!   7.2); answers due together on one pair aggregate into one packet
//!   (section 6.4); a record listed in the query's known-answer section
//!   with at least half our TTL is omitted (section 7.1); a record is
//!   never multicast twice within one second on one interface except to
//!   defend a probe (section 6); additionals follow RFC 6763 section 12;
//!   a query for one of our unique names and a type we do not hold gets
//!   an NSEC (section 6.1), and an address answer on an interface with
//!   one address family carries the NSEC for the other in the
//!   additionals (section 6.2); a query from a port other than 5353 is
//!   answered by unicast in legacy shape (section 6.7: ID echoed,
//!   questions repeated, TTL capped at 10, no cache-flush, SRV
//!   uncompressed, one 512-octet packet with TC when it overflows); a
//!   QU question (or a query delivered by direct unicast, section 5.5)
//!   is answered by unicast unless a record was not multicast within
//!   TTL/4 (section 5.4), per question; a unicast reply never goes to a
//!   source that is not on the arrival link (section 11). A probe for a
//!   name we own is defended at once, exempt from the one-second rule
//!   but never more than once per 250 ms per record and interface
//!   (section 6), and by multicast plus a unicast copy when the prober
//!   is on our own host or the port is shared (plan section 4.8 "Port
//!   sharing"). The known answers in a TC query's continuation packets
//!   trim the answer still waiting for that querier (section 7.2).
//! - **updateTxt** (section 8.4): the TXT rdata is swapped and announced
//!   twice with cache-flush, no probe; identical rdata is a no-op; an
//!   update during probing is applied when the probe succeeds.
//! - **Goodbye** (section 10.1): `withdraw` queues one response with TTL
//!   0 for the registration's records (and the host's when it was the
//!   last one), sent at once; goodbyes waiting on one pair share a
//!   packet. Announcements queued for the host are dropped when it
//!   stops being owned (a section 9 re-probe or the last goodbye).
//! - **Link change** (section 8, "Link Change"): a new or re-addressed
//!   interface gets the two announcements of section 8.3 at once; v0.1
//!   does not re-probe per link (docs/conformance.md, section 8 row).
//!
//! Sizes: every pool is allocated once in `init` from `Limits`
//! (`max_registrations`, capped at 256 because `RegId` is a `u8`;
//! `max_pending_answers`; a job queue of eight entries per joined pair).
//! A full pending-answer pool drops the oldest answer and counts it; a
//! full job queue drops the job and counts it (goodbyes aggregate per
//! pair, so `withdrawAll` needs one slot per pair whatever the
//! registration count). Deadlines are found by a scan
//! over the pools (a few hundred entries) rather than a heap.
const std = @import("std");
const Io = std.Io;
const wire = @import("../wire/root.zig");
const events = @import("events.zig");
const timers = @import("timers.zig");
const querier_mod = @import("querier.zig");

pub const Name = wire.Name;
pub const RType = wire.RType;
pub const Txt = wire.Txt;
pub const TxtPair = wire.TxtPair;
pub const Interface = events.Interface;
pub const Family = events.Family;
pub const Event = events.Event;
pub const RegId = events.RegId;
pub const Limits = events.Limits;
pub const Bounded = events.Bounded;
pub const Pair = querier_mod.Pair;
pub const Sink = querier_mod.Sink;

/// `RegId` is a `u8`: the registration pool never exceeds this.
pub const max_registrations_cap = 256;
/// One DNS label (RFC 1035 section 2.3.4); instance names and the host
/// label are one label each.
pub const max_label_len = wire.name.max_label_len;
/// `_` + 15 (RFC 6335) + `._udp`.
pub const max_type_text_len = 1 + 15 + 5;
/// Records per name a peer's probe contributes to the section 8.2
/// comparison; extra ones are ignored.
pub const max_tiebreak_records = 32;
/// The domain every name lives in (RFC 6762 section 3).
pub const local_domain = querier_mod.local_domain;
/// mDNS port (RFC 6762 section 2): the legacy-query test and the unicast
/// reply port.
pub const mdns_port: u16 = 5353;

pub const RegMask = std.bit_set.Array(u64, max_registrations_cap);

pub const AdvertiseError = error{
    LimitReached,
    TxtTooLarge,
    InvalidTxt,
    InvalidServiceType,
    InvalidInstance,
    DuplicateRegistration,
};
pub const UpdateTxtError = error{
    TxtTooLarge,
    InvalidTxt,
    UnknownRegistration,
};
pub const HostLabelError = error{InvalidHostLabel};

/// What the Engine hands the responder on every call.
pub const Env = struct {
    /// The Engine's interface table (what `setInterfaces` kept).
    ifaces: []const Interface,
    /// Every joined (interface, family) pair with an address of that
    /// family (Revision 6 item 3): where probes, announcements and
    /// goodbyes go.
    pairs: []const Pair,
    random: std.Random,
    /// QU on probes (plan section 4.8 "QU policy").
    qu_allowed: bool,
    /// False when another stack shares 5353: defend by multicast (plan
    /// section 4.8 "Port sharing").
    first_binder: bool,
    sink: Sink,

    pub fn iface(env: *const Env, ifindex: u32) ?*const Interface {
        for (env.ifaces) |*i| if (i.index == ifindex) return i;
        return null;
    }

    /// True when `addr` is one of our own interface addresses.
    pub fn ownsAddr(env: *const Env, addr: Io.net.IpAddress) bool {
        for (env.ifaces) |*i| {
            const owns = switch (addr) {
                .ip4 => |a| i.hasAddr4(a.bytes),
                .ip6 => |a| i.hasAddr6(a.bytes),
            };
            if (owns) return true;
        }
        return false;
    }

    pub fn hasPair(env: *const Env, pair: Pair) bool {
        for (env.pairs) |p| if (p.ifindex == pair.ifindex and p.family == pair.family) return true;
        return false;
    }

    /// True when some interface holds `addr` as an address.
    fn hasAddr4(env: *const Env, addr: [4]u8) bool {
        for (env.ifaces) |*i| if (i.hasAddr4(addr)) return true;
        return false;
    }

    fn hasAddr6(env: *const Env, addr: [16]u8) bool {
        for (env.ifaces) |*i| if (i.hasAddr6(addr)) return true;
        return false;
    }
};

/// One outbound datagram the responder built into the caller's buffer.
pub const Built = struct {
    len: usize,
    pair: Pair,
    /// Null: the multicast group of `pair.family`.
    to: ?Io.net.IpAddress,
    /// The packet is a probe with QU set: the Engine opens its 2 s
    /// unicast window.
    qu: bool,
};

/// Responder counters the Engine folds into `Stats`.
pub const RStats = struct {
    conflicts: u64 = 0,
    answers_dropped: u64 = 0,
    /// Probe / announce / goodbye jobs that found no queue slot.
    jobs_dropped: u64 = 0,
    /// Records that did not fit any packet (an oversize proposed set).
    records_dropped: u64 = 0,
    /// Legacy queries whose source is not on the arrival link (RFC 6762
    /// section 11 applied to the unicast reply target): no reply.
    queries_off_link: u64 = 0,
    /// Queries from UDP source port 0 (no reply can reach them).
    queries_bad_port: u64 = 0,
};

/// Per-entity state of the section 8 machine.
pub const State = enum(u8) {
    /// Host only: no registration needs it.
    idle,
    probing,
    announcing,
    established,
    /// Registration only: goodbye queued, slot freed when it is built.
    withdrawn,
    /// Registration only: validated and copied by `reserve`, probing not
    /// started yet (`Service.advertise` queues the start for its next
    /// tick, plan section 4.2). Invisible on the wire: never answered,
    /// never probed, never compared in a tie-break, no deadline.
    reserved,
};

/// Never multicast (rate table and TTL/4 rule).
const never: u64 = std.math.maxInt(u64);
/// A registration whose probes are done and that waits for the host.
const waiting: u64 = std.math.maxInt(u64);

const Host = struct {
    label: Bounded(u8, max_label_len) = .{},
    name: Name = .{},
    state: State = .idle,
    step: u8 = 0,
    next_us: u64 = 0,
    /// Tie-break losses in the current probe round.
    losses: u8 = 0,

    fn owned(h: *const Host) bool {
        return h.state == .announcing or h.state == .established;
    }
};

const Registration = struct {
    used: bool = false,
    instance: Bounded(u8, max_label_len) = .{},
    service_type: Bounded(u8, max_type_text_len) = .{},
    type_name: Name = .{},
    inst_name: Name = .{},
    port: u16 = 0,
    txt: Txt = .empty,
    /// An `updateTxt` made while probing, applied when the probe succeeds.
    pending_txt: ?Txt = null,
    state: State = .probing,
    step: u8 = 0,
    next_us: u64 = 0,
    losses: u8 = 0,
    /// The current announce sequence carries only the TXT (section 8.4
    /// after `updateTxt`).
    txt_only: bool = false,
    /// The current announce sequence follows a successful probe:
    /// `registered` fires when it completes (a re-announce after
    /// `updateTxt` or a host rename fires nothing).
    probed: bool = false,
    /// Goodbye jobs still to build before the slot is freed.
    goodbye_left: u16 = 0,

    fn owned(r: *const Registration) bool {
        return r.used and (r.state == .announcing or r.state == .established);
    }
};

/// The records the responder can put in a packet.
pub const RecKind = enum(u8) { host_a, host_aaaa, host_nsec, ptr, srv, txt, inst_nsec };

pub const RecordRef = struct {
    kind: RecKind,
    /// Registration slot for `ptr` / `srv` / `txt` / `inst_nsec`.
    reg: u8 = 0,
};

/// A set of records: the host's three plus four per registration.
pub const RecordSet = struct {
    host_a: bool = false,
    host_aaaa: bool = false,
    host_nsec: bool = false,
    ptr: RegMask = .empty,
    srv: RegMask = .empty,
    txt: RegMask = .empty,
    nsec: RegMask = .empty,

    pub const empty: RecordSet = .{};

    pub fn isEmpty(s: *const RecordSet) bool {
        return !s.host_a and !s.host_aaaa and !s.host_nsec and
            s.ptr.count() == 0 and s.srv.count() == 0 and s.txt.count() == 0 and s.nsec.count() == 0;
    }

    pub fn merge(s: *RecordSet, o: *const RecordSet) void {
        s.host_a = s.host_a or o.host_a;
        s.host_aaaa = s.host_aaaa or o.host_aaaa;
        s.host_nsec = s.host_nsec or o.host_nsec;
        s.ptr.setUnion(o.ptr);
        s.srv.setUnion(o.srv);
        s.txt.setUnion(o.txt);
        s.nsec.setUnion(o.nsec);
    }

    /// Remove every record of `o` from `s`.
    pub fn subtract(s: *RecordSet, o: *const RecordSet) void {
        s.host_a = s.host_a and !o.host_a;
        s.host_aaaa = s.host_aaaa and !o.host_aaaa;
        s.host_nsec = s.host_nsec and !o.host_nsec;
        s.ptr.setIntersection(o.ptr.complement());
        s.srv.setIntersection(o.srv.complement());
        s.txt.setIntersection(o.txt.complement());
        s.nsec.setIntersection(o.nsec.complement());
    }

    pub fn has(s: *const RecordSet, ref: RecordRef) bool {
        return switch (ref.kind) {
            .host_a => s.host_a,
            .host_aaaa => s.host_aaaa,
            .host_nsec => s.host_nsec,
            .ptr => s.ptr.isSet(ref.reg),
            .srv => s.srv.isSet(ref.reg),
            .txt => s.txt.isSet(ref.reg),
            .inst_nsec => s.nsec.isSet(ref.reg),
        };
    }

    pub fn add(s: *RecordSet, ref: RecordRef) void {
        switch (ref.kind) {
            .host_a => s.host_a = true,
            .host_aaaa => s.host_aaaa = true,
            .host_nsec => s.host_nsec = true,
            .ptr => s.ptr.set(ref.reg),
            .srv => s.srv.set(ref.reg),
            .txt => s.txt.set(ref.reg),
            .inst_nsec => s.nsec.set(ref.reg),
        }
    }

    pub fn remove(s: *RecordSet, ref: RecordRef) void {
        switch (ref.kind) {
            .host_a => s.host_a = false,
            .host_aaaa => s.host_aaaa = false,
            .host_nsec => s.host_nsec = false,
            .ptr => s.ptr.unset(ref.reg),
            .srv => s.srv.unset(ref.reg),
            .txt => s.txt.unset(ref.reg),
            .inst_nsec => s.nsec.unset(ref.reg),
        }
    }

    /// Fixed enumeration order: host A, AAAA, NSEC, then per registration
    /// (ascending slot) PTR, SRV, TXT, NSEC. `cursor`s index into it.
    pub fn collect(s: *const RecordSet, out: *[max_refs]RecordRef) []RecordRef {
        var n: usize = 0;
        if (s.host_a) {
            out[n] = .{ .kind = .host_a };
            n += 1;
        }
        if (s.host_aaaa) {
            out[n] = .{ .kind = .host_aaaa };
            n += 1;
        }
        if (s.host_nsec) {
            out[n] = .{ .kind = .host_nsec };
            n += 1;
        }
        var i: usize = 0;
        while (i < max_registrations_cap) : (i += 1) {
            const r: u8 = @intCast(i);
            if (s.ptr.isSet(i)) {
                out[n] = .{ .kind = .ptr, .reg = r };
                n += 1;
            }
            if (s.srv.isSet(i)) {
                out[n] = .{ .kind = .srv, .reg = r };
                n += 1;
            }
            if (s.txt.isSet(i)) {
                out[n] = .{ .kind = .txt, .reg = r };
                n += 1;
            }
            if (s.nsec.isSet(i)) {
                out[n] = .{ .kind = .inst_nsec, .reg = r };
                n += 1;
            }
        }
        return out[0..n];
    }

    pub const max_refs = 3 + 4 * max_registrations_cap;
};

const JobKind = enum(u8) { probe, announce, goodbye };

/// One probe / announce / goodbye packet (or packet sequence) on one
/// pair.
const Job = struct {
    used: bool = false,
    kind: JobKind = .probe,
    pair: Pair = .{ .ifindex = 0, .family = .v4 },
    due_us: u64 = 0,
    seq: u64 = 0,
    host: bool = false,
    regs: RegMask = .empty,
    /// Records of the set already emitted (multi-packet continuation).
    cursor: u16 = 0,
};

/// A query's echoed question (legacy replies, RFC 6762 section 6.7).
const EchoQuestion = struct {
    name: Name,
    qtype: RType,
    qclass: u16,
};

/// Questions echoed in one legacy reply (RFC 6762 section 6.7 repeats
/// "the question given in the query message"); a query with more gets
/// the first ones.
pub const max_echo_questions = 4;

/// One scheduled answer.
const PendingAnswer = struct {
    used: bool = false,
    due_us: u64 = 0,
    seq: u64 = 0,
    pair: Pair = .{ .ifindex = 0, .family = .v4 },
    /// Null: the multicast group.
    to: ?Io.net.IpAddress = null,
    /// The querier (section 7.2: known answers in its later packets
    /// remove records from this answer while it waits). Null once
    /// answers for two queriers were aggregated.
    from: ?Io.net.IpAddress = null,
    legacy: bool = false,
    id: u16 = 0,
    questions: [max_echo_questions]EchoQuestion = undefined,
    n_questions: u8 = 0,
    /// Probe defence: exempt from the one-second rule (section 6), still
    /// spaced 250 ms per record and interface.
    defence: bool = false,
    set: RecordSet = .empty,
    cursor: u16 = 0,

    fn multicast(p: *const PendingAnswer) bool {
        return p.to == null;
    }
};

/// Same host: family and address bytes, ignoring the port.
fn sameHost(a: Io.net.IpAddress, b: Io.net.IpAddress) bool {
    return switch (a) {
        .ip4 => |x| switch (b) {
            .ip4 => |y| std.mem.eql(u8, &x.bytes, &y.bytes),
            .ip6 => false,
        },
        .ip6 => |x| switch (b) {
            .ip6 => |y| std.mem.eql(u8, &x.bytes, &y.bytes),
            .ip4 => false,
        },
    };
}

// ---- rate table --------------------------------------------------------

/// Last multicast time per (record, interface, family) for the section
/// 6 one-second rule and the section 5.4 TTL/4 rule. The key is the
/// egress pair, not the bare interface: a dual-stack link carries the
/// same record once over v4 and once over v6, and each transport is
/// "that interface" to the querier behind it. Pairs get a slot on first
/// use; a full table recycles the slot of an interface that is no longer
/// in the Engine's table (or, failing that, slot 0).
pub const RateTable = struct {
    /// Pair per slot; `ifindex` 0 = free.
    slot_pair: []Pair,
    /// `[slot * records + record]`, `never` when not yet multicast.
    last: []u64,
    records: usize,

    pub fn init(gpa: std.mem.Allocator, n_pairs: usize, n_records: usize) error{OutOfMemory}!RateTable {
        const slots = try gpa.alloc(Pair, n_pairs);
        errdefer gpa.free(slots);
        const last = try gpa.alloc(u64, n_pairs * n_records);
        errdefer gpa.free(last);
        @memset(slots, .{ .ifindex = 0, .family = .v4 });
        @memset(last, never);
        return .{ .slot_pair = slots, .last = last, .records = n_records };
    }

    pub fn deinit(t: *RateTable, gpa: std.mem.Allocator) void {
        gpa.free(t.last);
        gpa.free(t.slot_pair);
    }

    fn findSlot(t: *const RateTable, pair: Pair) ?usize {
        for (t.slot_pair, 0..) |v, i| if (v.ifindex == pair.ifindex and v.family == pair.family) return i;
        return null;
    }

    fn slotFor(t: *RateTable, pair: Pair, live: []const Interface) usize {
        if (t.findSlot(pair)) |s| return s;
        var victim: usize = 0;
        for (t.slot_pair, 0..) |v, i| {
            if (v.ifindex == 0) {
                victim = i;
                break;
            }
            var in_table = false;
            for (live) |*l| if (l.index == v.ifindex) {
                in_table = true;
                break;
            };
            if (!in_table) victim = i;
        }
        t.slot_pair[victim] = pair;
        @memset(t.last[victim * t.records ..][0..t.records], never);
        return victim;
    }

    /// Last multicast of `record` on `pair`, or null.
    pub fn lastMulticast(t: *const RateTable, record: usize, pair: Pair) ?u64 {
        const s = t.findSlot(pair) orelse return null;
        const v = t.last[s * t.records + record];
        return if (v == never) null else v;
    }

    /// Section 6: at least one second since the last multicast on that
    /// pair (or never multicast).
    pub fn allowed(t: *const RateTable, record: usize, pair: Pair, now_us: u64) bool {
        return t.allowedSince(record, pair, now_us, timers.record_rate_limit_us);
    }

    /// At least `min_us` since the last multicast on that pair (or never
    /// multicast).
    pub fn allowedSince(t: *const RateTable, record: usize, pair: Pair, now_us: u64, min_us: u64) bool {
        const last = t.lastMulticast(record, pair) orelse return true;
        return now_us -| last >= min_us;
    }

    pub fn mark(t: *RateTable, record: usize, pair: Pair, now_us: u64, live: []const Interface) void {
        const s = t.slotFor(pair, live);
        t.last[s * t.records + record] = now_us;
    }
};

/// Job slots per joined pair (see `Responder.init`).
const jobs_per_pair = 8;
/// Records per registration in the rate table.
const rate_per_reg = 4;
/// Host records in the rate table (A, AAAA, NSEC).
const rate_host = 3;

fn rateIndex(ref: RecordRef) usize {
    return switch (ref.kind) {
        .host_a => 0,
        .host_aaaa => 1,
        .host_nsec => 2,
        .ptr => rate_host + @as(usize, ref.reg) * rate_per_reg + 0,
        .srv => rate_host + @as(usize, ref.reg) * rate_per_reg + 1,
        .txt => rate_host + @as(usize, ref.reg) * rate_per_reg + 2,
        .inst_nsec => rate_host + @as(usize, ref.reg) * rate_per_reg + 3,
    };
}

fn ttlOf(kind: RecKind) u32 {
    return switch (kind) {
        .host_a, .host_aaaa, .host_nsec, .srv, .inst_nsec => timers.ttl_host_s,
        .ptr, .txt => timers.ttl_other_s,
    };
}

/// PTR is the one shared record (RFC 6763 section 4; RFC 6762 section
/// 10.2: cache-flush only on unique records).
fn isUnique(kind: RecKind) bool {
    return kind != .ptr;
}

// ---- Responder -----------------------------------------------------------

pub const Responder = struct {
    regs: []Registration,
    pending: []PendingAnswer,
    jobs: []Job,
    rate: RateTable,
    host: Host,
    stats: RStats,
    /// FIFO order among equal deadlines.
    next_seq: u64,
    /// Section 9 backoff: times of the last fifteen conflicts (ring).
    conflict_times: [timers.conflict_backoff_count]u64,
    conflict_len: usize,
    conflict_head: usize,
    /// No probe starts before this (section 9, "at least five seconds").
    backoff_until: u64,

    pub const InitError = error{OutOfMemory};

    /// Preallocates every pool. `host_label` must already be validated
    /// (`validateHostLabel`).
    pub fn init(gpa: std.mem.Allocator, limits: Limits, host_label: []const u8) InitError!Responder {
        const n_regs: usize = @max(@min(@as(usize, limits.max_registrations), max_registrations_cap), 1);
        const regs = try gpa.alloc(Registration, n_regs);
        errdefer gpa.free(regs);
        const n_pending: usize = @max(@as(usize, limits.max_pending_answers), 1);
        const pending = try gpa.alloc(PendingAnswer, n_pending);
        errdefer gpa.free(pending);
        const n_ifaces: usize = @max(@as(usize, limits.max_interfaces), 1);
        // Per joined pair (two per interface): one probe, up to four
        // announces (a tick's, `onInterfaceAdded`'s two, a bridged-echo
        // re-announce), one aggregated goodbye, and slack.
        const jobs = try gpa.alloc(Job, jobs_per_pair * 2 * n_ifaces);
        errdefer gpa.free(jobs);
        var rate = try RateTable.init(gpa, 2 * n_ifaces, rate_host + rate_per_reg * n_regs);
        errdefer rate.deinit(gpa);

        @memset(regs, .{});
        @memset(pending, .{});
        @memset(jobs, .{});

        var host: Host = .{};
        host.label.appendSlice(host_label[0..@min(host_label.len, max_label_len)]) catch unreachable;
        host.name = hostNameOf(host.label.slice());

        return .{
            .regs = regs,
            .pending = pending,
            .jobs = jobs,
            .rate = rate,
            .host = host,
            .stats = .{},
            .next_seq = 0,
            .conflict_times = @splat(0),
            .conflict_len = 0,
            .conflict_head = 0,
            .backoff_until = 0,
        };
    }

    pub fn deinit(r: *Responder, gpa: std.mem.Allocator) void {
        r.rate.deinit(gpa);
        gpa.free(r.jobs);
        gpa.free(r.pending);
        gpa.free(r.regs);
        r.* = undefined;
    }

    /// `<label>.local`; `label` is a validated single label.
    fn hostNameOf(label: []const u8) Name {
        // A validated label is 1..63 octets and `local` is 5: it fits;
        // the fallback keeps the path panic-free.
        return Name.fromLabels(&.{ label, local_domain }) catch Name.fromLabels(&.{local_domain}) catch .{};
    }

    /// Our host name (`<label>.local`), after any rename.
    pub fn hostName(r: *const Responder) Name {
        return r.host.name;
    }

    pub fn hostState(r: *const Responder) State {
        return r.host.state;
    }

    /// Live registrations (probing, announcing or established).
    pub fn count(r: *const Responder) usize {
        var n: usize = 0;
        for (r.regs) |*g| if (g.used and g.state != .withdrawn) {
            n += 1;
        };
        return n;
    }

    pub fn regState(r: *const Responder, id: RegId) ?State {
        const g = r.regOf(id) orelse return null;
        return g.state;
    }

    /// The registration's current instance name (`<inst>.<type>.local`).
    pub fn instanceName(r: *const Responder, id: RegId) ?Name {
        const g = r.regOf(id) orelse return null;
        return g.inst_name;
    }

    pub fn txtOf(r: *const Responder, id: RegId) ?Txt {
        const g = r.regOf(id) orelse return null;
        return g.txt;
    }

    fn regOf(r: *const Responder, id: RegId) ?*const Registration {
        const slot: usize = @backingInt(id);
        if (slot >= r.regs.len) return null;
        const g = &r.regs[slot];
        if (!g.used or g.state == .withdrawn) return null;
        return g;
    }

    fn regOfMut(r: *Responder, id: RegId) ?*Registration {
        const slot: usize = @backingInt(id);
        if (slot >= r.regs.len) return null;
        const g = &r.regs[slot];
        if (!g.used or g.state == .withdrawn) return null;
        return g;
    }

    fn idOf(slot: usize) RegId {
        return @fromBackingInt(@as(u8, @intCast(slot)));
    }

    fn seq(r: *Responder) u64 {
        const s = r.next_seq;
        r.next_seq += 1;
        return s;
    }

    // ---- registrations ------------------------------------------------

    /// Validate `desc`, copy it into a free slot and start probing
    /// (together with the host when nothing was registered yet).
    /// `reserve` followed by `start`.
    pub fn advertise(r: *Responder, env: *const Env, desc: events.ServiceDesc, now_us: u64) AdvertiseError!RegId {
        const id = try r.reserve(desc);
        r.start(env, id, now_us);
        return id;
    }

    /// The validating half of `advertise`: copy `desc` into a free slot
    /// in state `.reserved` and return its id. Nothing is scheduled
    /// until `start`. A reserved slot counts as live for `count` and the
    /// duplicate check, and `withdraw` frees it silently.
    pub fn reserve(r: *Responder, desc: events.ServiceDesc) AdvertiseError!RegId {
        wire.validateServiceName(desc.service_type) catch return error.InvalidServiceType;
        wire.validateInstance(desc.instance) catch return error.InvalidInstance;
        const type_name = querier_mod.Querier.serviceTypeName(desc.service_type) catch return error.InvalidServiceType;
        const inst_name = Name.serviceInstance(desc.instance, desc.service_type, local_domain) catch return error.InvalidInstance;
        const txt = buildTxt(desc.txt) catch |err| return switch (err) {
            error.TxtTooLarge => error.TxtTooLarge,
            error.InvalidTxt => error.InvalidTxt,
        };
        for (r.regs) |*g| {
            if (g.used and g.state != .withdrawn and g.inst_name.eql(&inst_name)) return error.DuplicateRegistration;
        }
        var free: ?usize = null;
        for (r.regs, 0..) |*g, i| if (!g.used) {
            free = i;
            break;
        };
        const slot = free orelse return error.LimitReached;
        const g = &r.regs[slot];
        g.* = .{
            .used = true,
            .type_name = type_name,
            .inst_name = inst_name,
            .port = desc.port,
            .txt = txt,
        };
        g.instance.appendSlice(desc.instance) catch unreachable; // validated <= 63
        g.service_type.appendSlice(desc.service_type[0..@min(desc.service_type.len, max_type_text_len)]) catch unreachable;
        g.state = .reserved;
        return idOf(slot);
    }

    /// The scheduling half of `advertise`: start probing a `.reserved`
    /// registration from `now_us` (RFC 6762 section 8.1). Any other id
    /// (unknown, withdrawn, already started) is ignored.
    pub fn start(r: *Responder, env: *const Env, id: RegId, now_us: u64) void {
        const g = r.regOfMut(id) orelse return;
        if (g.state != .reserved) return;
        // Section 8.1: the host set is probed with the first registration
        // and shares its first delay so both go out in one packet.
        const delay = r.probeStartUs(env, now_us);
        if (r.host.state == .idle) {
            r.host.state = .probing;
            r.host.step = 0;
            r.host.losses = 0;
            r.host.next_us = delay;
        }
        g.state = .probing;
        g.step = 0;
        g.losses = 0;
        g.next_us = delay;
    }

    /// First probe time from `now_us`: the random 0-250 ms of section
    /// 8.1, never before the section 9 backoff.
    fn probeStartUs(r: *const Responder, env: *const Env, now_us: u64) u64 {
        return @max(now_us +| timers.probeFirstDelayUs(env.random), r.backoff_until);
    }

    fn buildTxt(pairs: []const TxtPair) error{ TxtTooLarge, InvalidTxt }!Txt {
        return Txt.build(pairs) catch |err| switch (err) {
            error.TxtTooLarge => error.TxtTooLarge,
            error.TxtStringTooLong, error.InvalidTxtKey => error.InvalidTxt,
        };
    }

    /// Goodbye (section 10.1) for an owned registration, at once; a
    /// registration still probing just disappears. The host's records go
    /// with the last one.
    pub fn withdraw(r: *Responder, env: *const Env, id: RegId, now_us: u64) void {
        const slot: usize = @backingInt(id);
        if (slot >= r.regs.len) return;
        const g = &r.regs[slot];
        if (!g.used or g.state == .withdrawn) return;
        const was_owned = g.owned();
        g.state = .withdrawn;
        g.pending_txt = null;
        const last = r.count() == 0;
        if (!was_owned) {
            g.used = false;
            if (last) r.host.state = .idle;
            return;
        }
        const bye_host = last and r.host.owned();
        const queued = r.queueGoodbye(env, bye_host, slot, now_us);
        if (last) {
            r.host.state = .idle;
            // Nothing announces the host after its goodbye (section
            // 10.1); `buildSet` also gates on `host.owned()`.
            r.dropHostAnnounces();
        }
        if (queued == 0) {
            g.used = false;
        } else {
            g.goodbye_left = @intCast(queued);
        }
    }

    /// Queue the goodbye for registration `slot` on every joined pair,
    /// joining a goodbye job already waiting on that pair (all goodbyes
    /// are due at once): `withdrawAll` then needs one job per pair, not
    /// one per registration and pair. Returns the number of jobs that
    /// carry it.
    fn queueGoodbye(r: *Responder, env: *const Env, host: bool, slot: usize, now_us: u64) usize {
        var queued: usize = 0;
        for (env.pairs) |p| {
            var found: ?*Job = null;
            for (r.jobs) |*j| {
                if (!j.used or j.kind != .goodbye or j.cursor != 0) continue;
                if (j.pair.ifindex != p.ifindex or j.pair.family != p.family) continue;
                found = j;
                break;
            }
            const j = found orelse r.freeJob() orelse {
                r.stats.jobs_dropped += 1;
                continue;
            };
            if (found == null) {
                j.* = .{
                    .used = true,
                    .kind = .goodbye,
                    .pair = p,
                    .due_us = now_us,
                    .seq = r.seq(),
                };
            }
            j.host = j.host or host;
            j.regs.set(slot);
            queued += 1;
        }
        return queued;
    }

    /// Take the host's address set out of every queued announcement
    /// (the host left `owned`: section 9 re-probe or the last goodbye)
    /// and drop announcements left with nothing to say.
    fn dropHostAnnounces(r: *Responder) void {
        for (r.jobs) |*j| {
            if (!j.used or j.kind != .announce) continue;
            j.host = false;
            if (j.regs.count() == 0) j.used = false;
        }
    }

    /// Withdraw every registration (`Service.deinit`'s goodbye flush).
    pub fn withdrawAll(r: *Responder, env: *const Env, now_us: u64) void {
        for (r.regs, 0..) |*g, i| if (g.used and g.state != .withdrawn) r.withdraw(env, idOf(i), now_us);
    }

    /// Section 8.4: swap the TXT rdata and announce it twice with
    /// cache-flush, no probe. Identical rdata is a no-op; while probing
    /// the new TXT waits for the probe; over 400 B is rejected and the
    /// old TXT stays.
    pub fn updateTxt(r: *Responder, env: *const Env, id: RegId, pairs: []const TxtPair, now_us: u64) UpdateTxtError!void {
        if (r.regOf(id) == null) return error.UnknownRegistration;
        const txt = buildTxt(pairs) catch |err| return switch (err) {
            error.TxtTooLarge => error.TxtTooLarge,
            error.InvalidTxt => error.InvalidTxt,
        };
        return r.updateTxtBuilt(env, id, txt, now_us);
    }

    /// `updateTxt` with the rdata already encoded (`Txt.build` validated
    /// it): the half `Service.updateTxt` queues and applies at its next
    /// tick (plan section 4.2).
    pub fn updateTxtBuilt(r: *Responder, env: *const Env, id: RegId, txt: Txt, now_us: u64) error{UnknownRegistration}!void {
        const g = r.regOfMut(id) orelse return error.UnknownRegistration;
        if (g.state == .reserved) {
            // Not started: nothing announced yet, so the new TXT simply
            // becomes the one probed and announced by `start`.
            g.txt = txt;
            return;
        }
        if (g.state == .probing) {
            if (g.txt.eql(&txt)) {
                g.pending_txt = null;
            } else {
                g.pending_txt = txt;
            }
            return;
        }
        if (g.txt.eql(&txt)) return;
        g.txt = txt;
        // An update in the middle of the initial announcements restarts
        // them for the whole set (both go out twice); an update on an
        // established registration announces the TXT alone.
        g.txt_only = g.state == .established;
        g.state = .announcing;
        g.step = 0;
        g.next_us = now_us;
        _ = env;
    }

    // ---- interfaces ---------------------------------------------------

    /// An interface joined the table or changed its addresses: announce
    /// the host's address set and every owned registration on its joined
    /// pairs, twice one second apart as after a "Link Change" (section
    /// 8.3: "MUST send at least two unsolicited responses, one second
    /// apart"; 8.4 for the changed addresses). Records are already
    /// probed; a per-link re-probe is not done in v0.1.
    pub fn onInterfaceAdded(r: *Responder, env: *const Env, ifindex: u32, now_us: u64) void {
        if (!r.host.owned()) return;
        var mask: RegMask = .empty;
        for (r.regs, 0..) |*g, i| if (g.owned()) mask.set(i);
        var step: u32 = 0;
        while (step < timers.announce_count) : (step += 1) {
            _ = r.queueJobs(env, .announce, true, mask, now_us +| step * timers.announce_interval_us, ifindex);
        }
    }

    /// Plan section 4.8 "Bridged echo": our own cache-flush address
    /// records reached `ifindex` from another interface; re-announce
    /// that interface's address RRSet at once (RFC 6762 section 10.2:
    /// "immediately re-announce ... so that both sets remain valid and
    /// live in peer caches", inside the peers' one-second flush grace).
    /// The one-second rule (section 6) is applied as a drop, not a
    /// deferral: when the interface's addresses were multicast within
    /// the last second the peers already hold both sets within the
    /// grace, and re-announcing a second later would itself flush the
    /// other interface's set and echo back across the bridge, once per
    /// second, forever.
    pub fn reannounceAddresses(r: *Responder, env: *const Env, ifindex: u32, now_us: u64) void {
        if (!r.host.owned()) return;
        for ([_]Family{ .v4, .v6 }) |family| {
            const pair: Pair = .{ .ifindex = ifindex, .family = family };
            const a = r.rate.lastMulticast(rateIndex(.{ .kind = .host_a }), pair);
            const aaaa = r.rate.lastMulticast(rateIndex(.{ .kind = .host_aaaa }), pair);
            if (a) |t| if (now_us -| t < timers.record_rate_limit_us) return;
            if (aaaa) |t| if (now_us -| t < timers.record_rate_limit_us) return;
        }
        // One re-announce at a time per interface.
        for (r.jobs) |*j| {
            if (j.used and j.kind == .announce and j.host and j.regs.count() == 0 and j.pair.ifindex == ifindex) return;
        }
        _ = r.queueJobs(env, .announce, true, .empty, now_us, ifindex);
    }

    // ---- jobs ---------------------------------------------------------

    /// Queue one `kind` job per joined pair (or per joined pair of
    /// `only_ifindex`). Returns how many were queued.
    fn queueJobs(r: *Responder, env: *const Env, kind: JobKind, host: bool, regs: RegMask, due_us: u64, only_ifindex: ?u32) usize {
        if (!host and regs.count() == 0) return 0;
        var queued: usize = 0;
        for (env.pairs) |p| {
            if (only_ifindex) |i| if (p.ifindex != i) continue;
            const slot = r.freeJob() orelse {
                r.stats.jobs_dropped += 1;
                continue;
            };
            slot.* = .{
                .used = true,
                .kind = kind,
                .pair = p,
                .due_us = due_us,
                .seq = r.seq(),
                .host = host,
                .regs = regs,
            };
            queued += 1;
        }
        return queued;
    }

    fn freeJob(r: *Responder) ?*Job {
        for (r.jobs) |*j| if (!j.used) return j;
        return null;
    }

    // ---- timers -------------------------------------------------------

    /// Fire due probe and announce steps and queue their packets.
    pub fn tick(r: *Responder, env: *const Env, now_us: u64) void {
        var probe_host = false;
        var probe_regs: RegMask = .empty;
        var ann_host = false;
        var ann_regs: RegMask = .empty;

        // Host first: a registration whose probes are done may finish in
        // the same tick the host does.
        if (r.host.state == .probing and now_us >= r.host.next_us) {
            if (r.host.step < timers.probe_count) {
                probe_host = true;
                r.host.step += 1;
                r.host.next_us = now_us +| timers.probe_interval_us;
            } else {
                r.host.state = .announcing;
                r.host.step = 0;
                r.host.next_us = now_us;
                // Wake registrations that waited for the host, and
                // re-announce every owned one: the host name may have
                // changed (section 8.4).
                for (r.regs) |*g| {
                    if (!g.used) continue;
                    if (g.state == .probing and g.step >= timers.probe_count) g.next_us = now_us;
                    if (g.owned()) {
                        g.state = .announcing;
                        g.step = 0;
                        g.next_us = now_us;
                        g.txt_only = false;
                    }
                }
            }
        }
        if (r.host.state == .announcing and now_us >= r.host.next_us) {
            ann_host = true;
            r.host.step += 1;
            if (r.host.step >= timers.announce_count) {
                r.host.state = .established;
            } else {
                r.host.next_us = now_us +| timers.announce_interval_us;
            }
        }

        for (r.regs, 0..) |*g, i| {
            if (!g.used) continue;
            switch (g.state) {
                .probing => if (now_us >= g.next_us) {
                    if (g.step < timers.probe_count) {
                        probe_regs.set(i);
                        g.step += 1;
                        g.next_us = now_us +| timers.probe_interval_us;
                    } else if (r.host.state == .probing) {
                        g.next_us = waiting;
                    } else {
                        // Probing succeeded: apply a deferred TXT and
                        // announce.
                        if (g.pending_txt) |t| {
                            g.txt = t;
                            g.pending_txt = null;
                        }
                        g.state = .announcing;
                        g.step = 0;
                        g.next_us = now_us;
                        g.txt_only = false;
                        g.probed = true;
                        g.losses = 0;
                    }
                },
                else => {},
            }
            if (g.state == .announcing and now_us >= g.next_us) {
                ann_regs.set(i);
                g.step += 1;
                if (g.step >= timers.announce_count) {
                    g.state = .established;
                    g.txt_only = false;
                    if (g.probed) env.sink.push(.{ .registered = .{ .id = idOf(i), .instance = g.inst_name } });
                    g.probed = false;
                } else {
                    g.next_us = now_us +| timers.announce_interval_us;
                }
            }
        }

        if (probe_host or probe_regs.count() != 0) _ = r.queueJobs(env, .probe, probe_host, probe_regs, now_us, null);
        if (ann_host or ann_regs.count() != 0) _ = r.queueJobs(env, .announce, ann_host, ann_regs, now_us, null);
    }

    /// The soonest responder timer, or null. `now_us` when a packet is
    /// already due.
    pub fn nextDeadline(r: *const Responder, now_us: u64) ?u64 {
        var best: ?u64 = null;
        switch (r.host.state) {
            .probing, .announcing => best = minOpt(best, r.host.next_us),
            else => {},
        }
        for (r.regs) |*g| {
            if (!g.used) continue;
            switch (g.state) {
                .probing, .announcing => if (g.next_us != waiting) {
                    best = minOpt(best, g.next_us);
                },
                else => {},
            }
        }
        for (r.pending) |*p| if (p.used) {
            best = minOpt(best, p.due_us);
        };
        for (r.jobs) |*j| if (j.used) {
            best = minOpt(best, j.due_us);
        };
        if (best) |b| return @max(b, now_us);
        return null;
    }

    fn minOpt(a: ?u64, b: u64) u64 {
        return if (a) |x| @min(x, b) else b;
    }

    /// True when something is scheduled (tests).
    pub fn hasPending(r: *const Responder) bool {
        for (r.pending) |*p| if (p.used) return true;
        for (r.jobs) |*j| if (j.used) return true;
        return false;
    }

    // ---- conflicts ----------------------------------------------------

    /// Count a conflict for the section 9 rate limit; the fifteenth
    /// inside ten seconds arms a five-second backoff.
    fn noteConflict(r: *Responder, now_us: u64) void {
        r.stats.conflicts += 1;
        const cap = timers.conflict_backoff_count;
        r.conflict_times[r.conflict_head] = now_us;
        r.conflict_head = (r.conflict_head + 1) % cap;
        if (r.conflict_len < cap) r.conflict_len += 1;
        if (r.conflict_len == cap) {
            // The oldest is the slot the head now points at.
            const oldest = r.conflict_times[r.conflict_head];
            if (now_us -| oldest <= timers.conflict_backoff_window_us) {
                r.backoff_until = now_us +| timers.conflict_backoff_delay_us;
            }
        }
    }

    /// Section 9 on the host: while probing the probe failed (rename);
    /// otherwise re-probe the same name.
    ///
    /// A conflict while probing renames only once the current name has
    /// actually been probed (a probe went out, or a tie-break was lost
    /// on it): a burst of conflicting responses inside the 0-250 ms
    /// first-probe delay, or during the section 9 five-second backoff,
    /// is one conflict for the name, not one rename per packet (a
    /// hostile peer could otherwise walk the name up at wire speed). It
    /// is still counted for the backoff rule.
    fn hostConflict(r: *Responder, env: *const Env, now_us: u64) void {
        r.noteConflict(now_us);
        if (r.host.state == .probing) {
            if (r.host.step == 0 and r.host.losses == 0) {
                r.host.next_us = @max(r.host.next_us, r.backoff_until);
                return;
            }
            r.renameHost(env);
        }
        r.host.state = .probing;
        r.host.step = 0;
        r.host.losses = 0;
        r.host.next_us = r.probeStartUs(env, now_us);
        // Section 8.1 / 10.2: nothing announces the host until the
        // re-probe succeeds.
        r.dropHostAnnounces();
    }

    fn regConflict(r: *Responder, env: *const Env, slot: usize, now_us: u64) void {
        const g = &r.regs[slot];
        r.noteConflict(now_us);
        if (g.state == .probing) {
            if (g.step == 0 and g.losses == 0) {
                g.next_us = @max(g.next_us, r.backoff_until);
                return;
            }
            r.renameReg(env, slot);
        }
        g.state = .probing;
        g.step = 0;
        g.losses = 0;
        g.txt_only = false;
        g.next_us = r.probeStartUs(env, now_us);
    }

    fn renameHost(r: *Responder, env: *const Env) void {
        const old = r.host.name;
        var buf: [max_label_len]u8 = undefined;
        const next = bumpHostLabel(r.host.label.slice(), &buf);
        // `bumpHostLabel` returns at most `max_label_len` octets; the
        // append cannot fail, and a network-fed path never panics.
        r.host.label = .{};
        r.host.label.appendSlice(next) catch {};
        r.host.name = hostNameOf(next);
        env.sink.push(.{ .host_renamed = .{ .old = old, .new = r.host.name } });
    }

    fn renameReg(r: *Responder, env: *const Env, slot: usize) void {
        const g = &r.regs[slot];
        const old = g.inst_name;
        var buf: [max_label_len]u8 = undefined;
        const next = bumpInstance(g.instance.slice(), &buf);
        g.instance = .{};
        g.instance.appendSlice(next) catch {};
        // The label is at most 63 octets and the type name was validated:
        // the name fits as it did before.
        g.inst_name = Name.serviceInstance(next, g.service_type.slice(), local_domain) catch old;
        env.sink.push(.{ .renamed = .{ .id = idOf(slot), .old = old, .new = g.inst_name } });
    }

    /// Responses from other hosts: a record naming one of our unique
    /// names with different rdata is a conflict (section 9). Goodbyes
    /// (TTL 0) and identical rdata (section 6.6 cooperation) are not.
    pub fn handleResponse(r: *Responder, env: *const Env, msg: *const wire.Message, now_us: u64) void {
        var host_hit = false;
        var reg_hits: RegMask = .empty;
        var it = msg.allRecords();
        while (it.next()) |rec| {
            if (rec.class != wire.class_in or rec.ttl == 0) continue;
            if (r.host.state != .idle and rec.name.eql(&r.host.name)) {
                switch (rec.rtype) {
                    .a => {
                        const a = wire.rdata.decodeA(rec.rdata) catch continue;
                        if (!env.hasAddr4(a)) host_hit = true;
                    },
                    .aaaa => {
                        const a = wire.rdata.decodeAaaa(rec.rdata) catch continue;
                        if (!env.hasAddr6(a)) host_hit = true;
                    },
                    else => {},
                }
                continue;
            }
            for (r.regs, 0..) |*g, i| {
                if (!g.used or g.state == .withdrawn or g.state == .reserved) continue;
                if (!rec.name.eql(&g.inst_name)) continue;
                switch (rec.rtype) {
                    .srv => {
                        var ours: [wire.rdata.max_name_rdata_len]u8 = undefined;
                        const ours_len = wire.rdata.encodeSrv(.{ .port = g.port, .target = r.host.name }, &ours) catch continue;
                        var theirs: [wire.max_message_len]u8 = undefined;
                        const t = wire.rdata.canonicalRdata(msg.bytes, rec, &theirs) catch continue;
                        if (!std.mem.eql(u8, ours[0..ours_len], t)) reg_hits.set(i);
                    },
                    .txt => {
                        if (!std.mem.eql(u8, g.txt.slice(), rec.rdata)) reg_hits.set(i);
                    },
                    else => {},
                }
            }
        }
        if (host_hit) r.hostConflict(env, now_us);
        var hits = reg_hits.iterator(.{});
        while (hits.next()) |i| r.regConflict(env, i, now_us);
    }

    // ---- queries ------------------------------------------------------

    /// One received query: section 7.2 continuation known answers
    /// against the answers still waiting for this querier, probe
    /// defence and tie-break from its Authority section, the answer set
    /// per question (QU and QM parts kept apart, section 5.4),
    /// known-answer suppression, and the destination / delay decision.
    pub fn handleQuery(r: *Responder, env: *const Env, msg: *const wire.Message, meta: RxMetaLike, now_us: u64) void {
        const pair = r.arrivalPair(env, meta) orelse return;
        // A reply to port 0 cannot be sent: nothing to do with it.
        if (meta.source_port == 0) {
            r.stats.queries_bad_port += 1;
            return;
        }
        const legacy = meta.source_port != mdns_port;
        // Section 11 on the reply target: a legacy reply goes by unicast
        // to the source port, so an off-link source (a spoofed address
        // behind a multicast query) gets nothing rather than a reflected
        // packet.
        if (legacy and !meta.on_link) {
            r.stats.queries_off_link += 1;
            return;
        }
        const own_source = env.ownsAddr(meta.from);

        // 0. Section 7.2: a multi-packet query's later packets (usually
        // qdcount 0) list known answers for what is still waiting.
        if (msg.header.ancount != 0) r.suppressPendingFor(env, msg, pair, meta.from, now_us);

        // 1. Questions: one set per question, merged into the QU or the
        // QM part (section 5.4 makes the unicast-response bit a
        // per-question property; a direct unicast query counts as QU,
        // section 5.5). Every question is remembered for a legacy echo.
        var qu_set: RecordSet = .empty;
        var qm_set: RecordSet = .empty;
        var echo: [max_echo_questions]EchoQuestion = undefined;
        var n_echo: u8 = 0;
        var n_questions: usize = 0;
        var qs = msg.questions();
        while (qs.next()) |q| {
            n_questions += 1;
            if (n_echo < max_echo_questions) {
                echo[n_echo] = .{ .name = q.name, .qtype = q.qtype, .qclass = q.qclass };
                n_echo += 1;
            }
            if (q.qclass != wire.class_in and q.qclass != 255) continue;
            var qset: RecordSet = .empty;
            if (r.host.owned() and q.name.eql(&r.host.name)) {
                r.hostAnswerSet(env, pair.ifindex, q.qtype, &qset);
            } else for (r.regs, 0..) |*g, i| {
                if (!g.owned()) continue;
                if (q.name.eql(&g.inst_name)) {
                    switch (q.qtype) {
                        .srv => qset.srv.set(i),
                        .txt => qset.txt.set(i),
                        .any => {
                            qset.srv.set(i);
                            qset.txt.set(i);
                        },
                        else => qset.nsec.set(i),
                    }
                } else if ((q.qtype == .ptr or q.qtype == .any) and q.name.eql(&g.type_name)) {
                    qset.ptr.set(i);
                }
            }
            if (q.qu or meta.dst_unicast) qu_set.merge(&qset) else qm_set.merge(&qset);
        }

        // 2. Probes (section 8.1): our names in the Authority section,
        // proposed by a question of the same packet (section 8.2: the
        // Authority section "is used to specify the RRSet(s) the host
        // is proposing", alongside the probe question). One tie-break
        // per name per packet (the comparison covers every record of the
        // name at once). A defence goes with that question's QU bit.
        var defence_qu = false;
        var defence_qm = false;
        var host_compared = false;
        var regs_compared: RegMask = .empty;
        var auth = msg.authority();
        while (auth.next()) |rec| {
            if (rec.class != wire.class_in) continue;
            const q_qu = questionFor(msg, &rec.name) orelse continue;
            const qu = q_qu or meta.dst_unicast;
            if (rec.name.eql(&r.host.name)) {
                if (r.host.owned()) {
                    r.hostAnswerSet(env, pair.ifindex, .any, if (qu) &qu_set else &qm_set);
                    if (qu) defence_qu = true else defence_qm = true;
                } else if (r.host.state == .probing and !host_compared) {
                    host_compared = true;
                    r.tieBreakHost(env, msg, pair.ifindex, now_us);
                }
                continue;
            }
            for (r.regs, 0..) |*g, i| {
                if (!g.used or g.state == .withdrawn or g.state == .reserved) continue;
                if (!rec.name.eql(&g.inst_name)) continue;
                if (g.owned()) {
                    const set = if (qu) &qu_set else &qm_set;
                    set.srv.set(i);
                    set.txt.set(i);
                    if (qu) defence_qu = true else defence_qm = true;
                } else if (g.state == .probing and !regs_compared.isSet(i)) {
                    regs_compared.set(i);
                    r.tieBreakReg(env, msg, i, now_us);
                }
            }
        }

        // 3. Known-answer suppression (section 7.1); a record asked both
        // ways goes by multicast once.
        r.suppressKnownAnswers(env, msg, pair.ifindex, &qu_set);
        r.suppressKnownAnswers(env, msg, pair.ifindex, &qm_set);
        qu_set.subtract(&qm_set);
        if (qu_set.isEmpty() and qm_set.isEmpty()) return;

        // 4. Delay: shared records wait 20-120 ms, 400-500 ms after TC;
        // unique-only and defence go at once (section 6). One draw per
        // packet keeps both parts together.
        const tc = msg.header.flags.tc;
        const shared_delay: u64 = if (tc or qu_set.ptr.count() != 0 or qm_set.ptr.count() != 0)
            timers.answerDelayUs(env.random, tc)
        else
            0;
        const due_qu = now_us +| (if (tc or (qu_set.ptr.count() != 0 and !defence_qu)) shared_delay else 0);
        const due_qm = now_us +| (if (tc or (qm_set.ptr.count() != 0 and !defence_qm)) shared_delay else 0);

        // 5. Destination (sections 5.4, 5.5, 6.7; plan section 4.8).
        if (legacy) {
            var set = qm_set;
            set.merge(&qu_set);
            var p: PendingAnswer = .{
                .used = true,
                .due_us = @min(due_qu, due_qm),
                .pair = pair,
                .to = meta.from,
                .from = meta.from,
                .legacy = true,
                .id = msg.header.id,
                .n_questions = n_echo,
                .defence = defence_qu or defence_qm,
                .set = set,
            };
            @memcpy(p.questions[0..n_echo], echo[0..n_echo]);
            r.schedule(p, now_us);
            return;
        }
        if (!qm_set.isEmpty()) r.scheduleMulticast(pair, due_qm, defence_qm, qm_set, meta.from, now_us);
        if (!qu_set.isEmpty()) {
            const forced_multicast = defence_qu and (own_source or !env.first_binder);
            const stale = r.needsMulticast(&qu_set, pair, now_us);
            // Section 11 on the reply target again: an off-link source
            // is never unicast to; it hears the multicast copy.
            const unicast_ok = meta.on_link and (forced_multicast or !stale);
            if (unicast_ok) {
                r.schedule(.{
                    .used = true,
                    .due_us = due_qu,
                    .pair = pair,
                    .to = unicastTo(meta.from, pair.ifindex),
                    .from = meta.from,
                    .defence = defence_qu,
                    .set = qu_set,
                }, now_us);
            }
            if (forced_multicast or stale or !meta.on_link) r.scheduleMulticast(pair, due_qu, defence_qu, qu_set, meta.from, now_us);
        }
    }

    /// The QU bit of the first question of `msg` naming `name`, or null
    /// when no question does.
    fn questionFor(msg: *const wire.Message, name: *const Name) ?bool {
        var qs = msg.questions();
        while (qs.next()) |q| if (q.name.eql(name)) return q.qu;
        return null;
    }

    /// Section 7.2: the known answers of a later packet from the same
    /// querier remove records from every answer still waiting for it on
    /// the arrival pair ("it MUST delete that answer from the list of
    /// answers it is planning to give"). An answer left empty is dropped.
    fn suppressPendingFor(r: *Responder, env: *const Env, msg: *const wire.Message, pair: Pair, from: Io.net.IpAddress, now_us: u64) void {
        for (r.pending) |*p| {
            if (!p.used or p.due_us <= now_us or p.cursor != 0) continue;
            if (p.pair.ifindex != pair.ifindex or p.pair.family != pair.family) continue;
            const src = p.from orelse continue;
            if (!sameHost(src, from)) continue;
            r.suppressKnownAnswers(env, msg, pair.ifindex, &p.set);
            if (p.set.isEmpty()) p.used = false;
        }
    }

    /// What the Engine tells the responder about a query's arrival.
    pub const RxMetaLike = struct {
        from: Io.net.IpAddress,
        ifindex: u32,
        source_port: u16,
        /// The query came by direct unicast to port 5353 (destination
        /// known and not a group): answered as QU (section 5.5).
        dst_unicast: bool = false,
        /// The source is on the arrival link (section 11): a unicast
        /// reply may go to it.
        on_link: bool = true,
    };

    /// The pair a query arrived on. An unknown arrival interface falls
    /// back to the first joined pair of the packet's family.
    fn arrivalPair(r: *const Responder, env: *const Env, meta: RxMetaLike) ?Pair {
        _ = r;
        const family: Family = switch (meta.from) {
            .ip4 => .v4,
            .ip6 => .v6,
        };
        if (meta.ifindex != 0) {
            const p: Pair = .{ .ifindex = meta.ifindex, .family = family };
            return if (env.hasPair(p)) p else null;
        }
        for (env.pairs) |p| if (p.family == family) return p;
        return null;
    }

    fn unicastTo(from: Io.net.IpAddress, ifindex: u32) Io.net.IpAddress {
        var to = from;
        switch (to) {
            .ip4 => |*a| a.port = mdns_port,
            .ip6 => |*a| {
                a.port = mdns_port;
                if (a.interface.index == 0 and events.isLinkLocal6(a.bytes)) a.interface = .{ .index = ifindex };
            },
        }
        return to;
    }

    /// Host records for `qtype` on `ifindex`: A / AAAA when the interface
    /// has addresses of that family, else the NSEC (section 6.1).
    fn hostAnswerSet(r: *const Responder, env: *const Env, ifindex: u32, qtype: RType, set: *RecordSet) void {
        _ = r;
        const iface = env.iface(ifindex) orelse return;
        const has4 = iface.v4.len != 0;
        const has6 = iface.v6.len != 0;
        switch (qtype) {
            .a => if (has4) {
                set.host_a = true;
            } else {
                set.host_nsec = true;
            },
            .aaaa => if (has6) {
                set.host_aaaa = true;
            } else {
                set.host_nsec = true;
            },
            .any => {
                if (has4) set.host_a = true;
                if (has6) set.host_aaaa = true;
                if (!has4 and !has6) set.host_nsec = true;
            },
            else => set.host_nsec = true,
        }
    }

    /// Section 7.1: drop from `set` every record the querier already
    /// lists with at least half our TTL. The host's address set is
    /// suppressed only when every address of the interface is listed.
    fn suppressKnownAnswers(r: *const Responder, env: *const Env, msg: *const wire.Message, ifindex: u32, set: *RecordSet) void {
        if (msg.header.ancount == 0) return;
        var a_seen: u8 = 0;
        var aaaa_seen: u8 = 0;
        var ans = msg.answers();
        while (ans.next()) |rec| {
            if (rec.class != wire.class_in) continue;
            if ((set.host_a or set.host_aaaa) and rec.name.eql(&r.host.name)) {
                const iface = env.iface(ifindex) orelse continue;
                switch (rec.rtype) {
                    .a => {
                        if (!kaSuppresses(rec.ttl, timers.ttl_host_s)) continue;
                        const a = wire.rdata.decodeA(rec.rdata) catch continue;
                        for (iface.v4.slice(), 0..) |p, k| if (std.mem.eql(u8, &p.addr, &a)) {
                            a_seen |= @as(u8, 1) << @intCast(k);
                        };
                    },
                    .aaaa => {
                        if (!kaSuppresses(rec.ttl, timers.ttl_host_s)) continue;
                        const a = wire.rdata.decodeAaaa(rec.rdata) catch continue;
                        for (iface.v6.slice(), 0..) |p, k| if (std.mem.eql(u8, &p.addr, &a)) {
                            aaaa_seen |= @as(u8, 1) << @intCast(k);
                        };
                    },
                    else => {},
                }
                continue;
            }
            for (r.regs, 0..) |*g, i| {
                if (!g.owned()) continue;
                switch (rec.rtype) {
                    .ptr => if (set.ptr.isSet(i) and rec.name.eql(&g.type_name)) {
                        if (!kaSuppresses(rec.ttl, timers.ttl_other_s)) continue;
                        const target = wire.rdata.decodePtr(msg.bytes, rec) catch continue;
                        if (target.eql(&g.inst_name)) set.ptr.unset(i);
                    },
                    .srv => if (set.srv.isSet(i) and rec.name.eql(&g.inst_name)) {
                        if (!kaSuppresses(rec.ttl, timers.ttl_host_s)) continue;
                        var ours: [wire.rdata.max_name_rdata_len]u8 = undefined;
                        const ours_len = wire.rdata.encodeSrv(.{ .port = g.port, .target = r.host.name }, &ours) catch continue;
                        var theirs: [wire.max_message_len]u8 = undefined;
                        const t = wire.rdata.canonicalRdata(msg.bytes, rec, &theirs) catch continue;
                        if (std.mem.eql(u8, ours[0..ours_len], t)) set.srv.unset(i);
                    },
                    .txt => if (set.txt.isSet(i) and rec.name.eql(&g.inst_name)) {
                        if (!kaSuppresses(rec.ttl, timers.ttl_other_s)) continue;
                        if (std.mem.eql(u8, g.txt.slice(), rec.rdata)) set.txt.unset(i);
                    },
                    else => {},
                }
            }
        }
        if (env.iface(ifindex)) |iface| {
            if (set.host_a and iface.v4.len != 0 and a_seen == fullMask(iface.v4.len)) set.host_a = false;
            if (set.host_aaaa and iface.v6.len != 0 and aaaa_seen == fullMask(iface.v6.len)) set.host_aaaa = false;
        }
    }

    fn fullMask(n: usize) u8 {
        if (n >= 8) return 0xff;
        return (@as(u8, 1) << @intCast(n)) - 1;
    }

    /// Section 5.4: some record of `set` was not multicast on `ifindex`
    /// within the last quarter of its TTL.
    fn needsMulticast(r: *const Responder, set: *const RecordSet, pair: Pair, now_us: u64) bool {
        var refs: [RecordSet.max_refs]RecordRef = undefined;
        for (set.collect(&refs)) |ref| {
            const last = r.rate.lastMulticast(rateIndex(ref), pair);
            if (timers.quReplyMulticast(last, ttlOf(ref.kind), now_us)) return true;
        }
        return false;
    }

    /// Queue a multicast answer on `pair`, aggregating into a pending
    /// multicast answer of the same kind (immediate with immediate,
    /// delayed with delayed; section 6.4).
    fn scheduleMulticast(r: *Responder, pair: Pair, due_us: u64, defence: bool, set: RecordSet, from: Io.net.IpAddress, now_us: u64) void {
        const delayed = due_us > now_us;
        for (r.pending) |*p| {
            if (!p.used or !p.multicast() or p.legacy or p.cursor != 0) continue;
            if (p.pair.ifindex != pair.ifindex or p.pair.family != pair.family) continue;
            // A defence joins a waiting defence whatever its due time
            // (one deferred by the 250 ms rule answers every probe of
            // the burst); other answers pair immediate with immediate
            // and delayed with delayed.
            if (!(defence and p.defence) and (p.due_us > now_us) != delayed) continue;
            p.set.merge(&set);
            p.defence = p.defence or defence;
            if (due_us < p.due_us) p.due_us = due_us;
            // Two queriers behind one answer: section 7.2 continuation
            // packets of either can no longer trim it safely.
            if (p.from) |f| if (!sameHost(f, from)) {
                p.from = null;
            };
            return;
        }
        r.schedule(.{
            .used = true,
            .due_us = due_us,
            .pair = pair,
            .from = from,
            .defence = defence,
            .set = set,
        }, now_us);
    }

    /// Take a pending slot; a full pool drops the oldest (plan section
    /// 4.5) and counts it.
    fn schedule(r: *Responder, answer: PendingAnswer, now_us: u64) void {
        _ = now_us;
        var slot: ?*PendingAnswer = null;
        var oldest: ?*PendingAnswer = null;
        for (r.pending) |*p| {
            if (!p.used) {
                slot = p;
                break;
            }
            if (oldest == null or p.seq < oldest.?.seq) oldest = p;
        }
        if (slot == null) {
            r.stats.answers_dropped += 1;
            slot = oldest;
        }
        const p = slot orelse return;
        p.* = answer;
        p.seq = r.seq();
    }

    // ---- tie-break ----------------------------------------------------

    /// Section 8.2 for the host name against a peer's probe that arrived
    /// on `ifindex`: our proposed set is that interface's addresses.
    fn tieBreakHost(r: *Responder, env: *const Env, msg: *const wire.Message, ifindex: u32, now_us: u64) void {
        const iface = env.iface(ifindex) orelse return;
        var ours: [2 * events.max_addrs_per_family]wire.rdata.Key = undefined;
        var n: usize = 0;
        for (iface.v4.slice()) |*p| {
            ours[n] = .{ .class = wire.class_in, .rtype = RType.a.toInt(), .rdata = &p.addr };
            n += 1;
        }
        for (iface.v6.slice()) |*p| {
            ours[n] = .{ .class = wire.class_in, .rtype = RType.aaaa.toInt(), .rdata = &p.addr };
            n += 1;
        }
        const order = tieBreakAgainst(ours[0..n], msg, &r.host.name);
        if (order != .lt) return;
        r.host.losses += 1;
        if (r.host.losses >= max_tiebreak_losses) {
            r.noteConflict(now_us);
            r.renameHost(env);
            r.host.losses = 0;
            r.host.next_us = r.probeStartUs(env, now_us);
        } else {
            r.host.next_us = @max(now_us +| timers.probe_tiebreak_wait_us, r.backoff_until);
        }
        r.host.step = 0;
    }

    fn tieBreakReg(r: *Responder, env: *const Env, msg: *const wire.Message, slot: usize, now_us: u64) void {
        const g = &r.regs[slot];
        var srv_buf: [wire.rdata.max_name_rdata_len]u8 = undefined;
        const srv_len = wire.rdata.encodeSrv(.{ .port = g.port, .target = r.host.name }, &srv_buf) catch return;
        const ours = [_]wire.rdata.Key{
            .{ .class = wire.class_in, .rtype = RType.srv.toInt(), .rdata = srv_buf[0..srv_len] },
            .{ .class = wire.class_in, .rtype = RType.txt.toInt(), .rdata = g.txt.slice() },
        };
        const order = tieBreakAgainst(&ours, msg, &g.inst_name);
        if (order != .lt) return;
        g.losses += 1;
        if (g.losses >= max_tiebreak_losses) {
            r.noteConflict(now_us);
            r.renameReg(env, slot);
            g.losses = 0;
            g.next_us = r.probeStartUs(env, now_us);
        } else {
            g.next_us = @max(now_us +| timers.probe_tiebreak_wait_us, r.backoff_until);
        }
        g.step = 0;
    }

    /// Tie-break losses that turn into a rename (plan M4).
    pub const max_tiebreak_losses = 2;

    // ---- egress -------------------------------------------------------

    /// Build the next due packet into `buf`: due answers first (oldest
    /// first), then due jobs. Null when nothing is due.
    pub fn pollDatagram(r: *Responder, env: *const Env, buf: []u8, now_us: u64) ?Built {
        if (buf.len < wire.Header.len) return null;
        while (r.dueAnswer(now_us)) |p| {
            if (r.buildAnswer(env, p, buf, now_us)) |b| return b;
        }
        while (r.dueJob(now_us)) |j| {
            if (r.buildJob(env, j, buf, now_us)) |b| return b;
        }
        return null;
    }

    fn dueAnswer(r: *Responder, now_us: u64) ?*PendingAnswer {
        var best: ?*PendingAnswer = null;
        for (r.pending) |*p| {
            if (!p.used or p.due_us > now_us) continue;
            if (best == null or p.seq < best.?.seq) best = p;
        }
        return best;
    }

    fn dueJob(r: *Responder, now_us: u64) ?*Job {
        var best: ?*Job = null;
        for (r.jobs) |*j| {
            if (!j.used or j.due_us > now_us) continue;
            if (best == null or j.seq < best.?.seq) best = j;
        }
        return best;
    }

    fn builderFamily(f: Family) wire.Family {
        return switch (f) {
            .v4 => .v4,
            .v6 => .v6,
        };
    }

    /// One packet of a pending answer. Frees the slot when its set is
    /// exhausted (or when nothing of it may be sent). A legacy reply is
    /// one conventional 512-octet packet (section 6.7; RFC 1035 section
    /// 4.2.1): what does not fit sets TC instead of continuing.
    fn buildAnswer(r: *Responder, env: *const Env, p: *PendingAnswer, buf: []u8, now_us: u64) ?Built {
        var b: wire.Builder = .init(buf, .{
            .family = builderFamily(p.pair.family),
            .legacy = p.legacy,
            .soft_limit = if (p.legacy) wire.builder.legacy_max_payload else null,
            .hard_limit = if (p.legacy) wire.builder.legacy_max_payload else null,
        });
        b.setResponse();
        if (p.legacy) {
            // Section 6.7 / 18.1: echo the ID and the questions.
            b.setId(p.id);
            for (p.questions[0..p.n_questions]) |q| b.addQuestion(q.name, q.qtype, q.qclass, false) catch break;
        }
        var refs: [RecordSet.max_refs]RecordRef = undefined;
        const all = p.set.collect(&refs);
        const multicast = p.multicast();
        // Section 6: a unicast copy is never rate-limited; a multicast
        // probe defence skips the one-second rule but keeps 250 ms
        // between multicasts of one record on one interface ("delay its
        // transmission as necessary"): the whole defence is deferred to
        // the moment its records are allowed, so the prober still hears
        // it (it has at most three probes 250 ms apart).
        const min_gap_us: u64 = if (p.defence) timers.defence_rate_limit_us else timers.record_rate_limit_us;
        const exempt = !multicast;
        if (multicast and p.defence) {
            var not_before: u64 = now_us;
            for (all[p.cursor..]) |ref| {
                if (!r.refLive(ref)) continue;
                if (r.rate.lastMulticast(rateIndex(ref), p.pair)) |last| {
                    not_before = @max(not_before, last +| min_gap_us);
                }
            }
            if (not_before > now_us) {
                p.due_us = not_before;
                return null;
            }
        }

        var emitted: [RecordSet.max_refs]RecordRef = undefined;
        var n_emitted: usize = 0;
        var i: usize = p.cursor;
        while (i < all.len) : (i += 1) {
            const ref = all[i];
            if (!r.refLive(ref)) continue;
            if (!exempt and !r.rate.allowedSince(rateIndex(ref), p.pair, now_us, min_gap_us)) continue;
            const ok = r.emitRef(env, &b, .answer, ref, p.pair.ifindex, isUnique(ref.kind), false) catch |err| switch (err) {
                error.NoSpace => {
                    if (n_emitted == 0) {
                        r.stats.records_dropped += 1;
                        continue;
                    }
                    break;
                },
                else => continue,
            };
            if (!ok) continue;
            if (multicast) r.rate.mark(rateIndex(ref), p.pair, now_us, env.ifaces);
            emitted[n_emitted] = ref;
            n_emitted += 1;
        }
        const done = i >= all.len;
        if (n_emitted == 0) {
            p.used = false;
            return null;
        }
        // RFC 6763 section 12 additionals for this packet's answers, and
        // RFC 6762 section 6.2: with an address answer on an interface
        // that has addresses of one family only, the NSEC that says so.
        var extra: RecordSet = .empty;
        for (emitted[0..n_emitted]) |ref| switch (ref.kind) {
            .ptr => {
                extra.srv.set(ref.reg);
                extra.txt.set(ref.reg);
                extra.host_a = true;
                extra.host_aaaa = true;
            },
            .srv => {
                extra.host_a = true;
                extra.host_aaaa = true;
            },
            .host_a, .host_aaaa => extra.host_nsec = true,
            else => {},
        };
        if ((extra.host_a or extra.host_aaaa) and r.host.owned()) extra.host_nsec = true;
        if (extra.host_nsec) {
            const iface = env.iface(p.pair.ifindex);
            const one_family = if (iface) |ifc| (ifc.v4.len != 0) != (ifc.v6.len != 0) else false;
            if (!one_family) extra.host_nsec = false;
        }
        var extra_refs: [RecordSet.max_refs]RecordRef = undefined;
        for (extra.collect(&extra_refs)) |ref| {
            if (p.set.has(ref)) continue;
            if (!r.refLive(ref)) continue;
            if (!exempt and !r.rate.allowedSince(rateIndex(ref), p.pair, now_us, min_gap_us)) continue;
            const ok = r.emitRef(env, &b, .additional, ref, p.pair.ifindex, isUnique(ref.kind), false) catch break;
            if (ok and multicast) r.rate.mark(rateIndex(ref), p.pair, now_us, env.ifaces);
        }
        if (p.legacy and !done) b.setTruncated(true);
        const out = b.finish();
        const built: Built = .{ .len = out.len, .pair = p.pair, .to = p.to, .qu = false };
        if (done or p.legacy) {
            p.used = false;
        } else {
            p.cursor = @intCast(i);
        }
        return built;
    }

    /// The record's owner still answers for it.
    fn refLive(r: *const Responder, ref: RecordRef) bool {
        return switch (ref.kind) {
            .host_a, .host_aaaa, .host_nsec => r.host.owned(),
            .ptr, .srv, .txt, .inst_nsec => r.regs[ref.reg].owned(),
        };
    }

    /// One packet of a probe / announce / goodbye job.
    fn buildJob(r: *Responder, env: *const Env, j: *Job, buf: []u8, now_us: u64) ?Built {
        switch (j.kind) {
            .probe => return r.buildProbe(env, j, buf),
            .announce, .goodbye => return r.buildSet(env, j, buf, now_us),
        }
    }

    /// Section 8.1: one question per probed name (qtype ANY, QU when
    /// allowed) and the proposed records in Authority, no cache-flush.
    /// Proposed records that do not fit are dropped and counted.
    fn buildProbe(r: *Responder, env: *const Env, j: *Job, buf: []u8) ?Built {
        defer j.used = false;
        var b: wire.Builder = .init(buf, .{ .family = builderFamily(j.pair.family) });
        const qu = env.qu_allowed;
        var any_q = false;
        if (j.host and r.host.state == .probing) {
            b.addQuestion(r.host.name, .any, wire.class_in, qu) catch return null;
            any_q = true;
        }
        var it = j.regs.iterator(.{});
        while (it.next()) |i| {
            const g = &r.regs[i];
            if (!g.used or g.state != .probing) continue;
            b.addQuestion(g.inst_name, .any, wire.class_in, qu) catch continue;
            any_q = true;
        }
        if (!any_q) return null;
        if (j.host and r.host.state == .probing) {
            _ = r.emitRef(env, &b, .authority, .{ .kind = .host_a }, j.pair.ifindex, false, false) catch {
                r.stats.records_dropped += 1;
            };
            _ = r.emitRef(env, &b, .authority, .{ .kind = .host_aaaa }, j.pair.ifindex, false, false) catch {
                r.stats.records_dropped += 1;
            };
        }
        it = j.regs.iterator(.{});
        while (it.next()) |i| {
            const g = &r.regs[i];
            if (!g.used or g.state != .probing) continue;
            const reg: u8 = @intCast(i);
            _ = r.emitRef(env, &b, .authority, .{ .kind = .srv, .reg = reg }, j.pair.ifindex, false, false) catch {
                r.stats.records_dropped += 1;
            };
            _ = r.emitRef(env, &b, .authority, .{ .kind = .txt, .reg = reg }, j.pair.ifindex, false, false) catch {
                r.stats.records_dropped += 1;
            };
        }
        const out = b.finish();
        return .{ .len = out.len, .pair = j.pair, .to = null, .qu = qu };
    }

    /// Section 8.3 announcement or section 10.1 goodbye: the job's
    /// records in the Answer section, cache-flush on unique records
    /// (announce), TTL 0 (goodbye). An announcement whose records were
    /// multicast on the pair less than a second ago is deferred as a
    /// whole until the one-second rule allows it (section 6), so the two
    /// announcements of section 8.3 / 8.4 are never silently lost;
    /// goodbyes go at once. Continues in further packets when needed.
    fn buildSet(r: *Responder, env: *const Env, j: *Job, buf: []u8, now_us: u64) ?Built {
        const goodbye = j.kind == .goodbye;
        var set: RecordSet = .empty;
        // The host set is announced only while the host is owned (a
        // section 9 re-probe or the last goodbye may have intervened
        // since the job was queued: sections 8.1, 10.1, 10.2); a goodbye
        // job says goodbye to it regardless.
        if (j.host and (goodbye or r.host.owned())) {
            if (env.iface(j.pair.ifindex)) |iface| {
                if (iface.v4.len != 0) set.host_a = true;
                if (iface.v6.len != 0) set.host_aaaa = true;
            }
        }
        var it = j.regs.iterator(.{});
        while (it.next()) |i| {
            const g = &r.regs[i];
            if (!g.used) continue;
            if (goodbye) {
                if (g.state != .withdrawn) continue;
            } else if (!g.owned()) continue;
            set.txt.set(i);
            if (!(g.txt_only and !goodbye)) {
                set.ptr.set(i);
                set.srv.set(i);
            }
        }
        var refs: [RecordSet.max_refs]RecordRef = undefined;
        const all = set.collect(&refs);

        if (!goodbye) {
            var not_before: u64 = now_us;
            for (all[j.cursor..]) |ref| {
                if (r.rate.lastMulticast(rateIndex(ref), j.pair)) |last| {
                    not_before = @max(not_before, last +| timers.record_rate_limit_us);
                }
            }
            if (not_before > now_us) {
                j.due_us = not_before;
                return null;
            }
        }

        var b: wire.Builder = .init(buf, .{ .family = builderFamily(j.pair.family) });
        b.setResponse();
        var n_emitted: usize = 0;
        var i: usize = j.cursor;
        while (i < all.len) : (i += 1) {
            const ref = all[i];
            const ok = r.emitRef(env, &b, .answer, ref, j.pair.ifindex, !goodbye and isUnique(ref.kind), goodbye) catch |err| switch (err) {
                error.NoSpace => {
                    if (n_emitted == 0) {
                        r.stats.records_dropped += 1;
                        continue;
                    }
                    break;
                },
                else => continue,
            };
            if (!ok) continue;
            if (!goodbye) r.rate.mark(rateIndex(ref), j.pair, now_us, env.ifaces);
            n_emitted += 1;
        }
        const done = i >= all.len;
        if (done) {
            r.finishJob(j);
        } else {
            j.cursor = @intCast(i);
        }
        if (n_emitted == 0) return null;
        const out = b.finish();
        return .{ .len = out.len, .pair = j.pair, .to = null, .qu = false };
    }

    /// Free a job; a goodbye job releases its registration slot once
    /// every pair's goodbye has been built.
    fn finishJob(r: *Responder, j: *Job) void {
        j.used = false;
        if (j.kind != .goodbye) return;
        var it = j.regs.iterator(.{});
        while (it.next()) |i| {
            const g = &r.regs[i];
            if (!g.used or g.state != .withdrawn) continue;
            if (g.goodbye_left > 0) g.goodbye_left -= 1;
            if (g.goodbye_left == 0) g.used = false;
        }
    }

    /// Drop every job on a pair that is no longer joined (the Engine's
    /// `isJoined` check); goodbye bookkeeping still runs.
    pub fn dropJobsOn(r: *Responder, pair: Pair) void {
        for (r.jobs) |*j| {
            if (!j.used or j.pair.ifindex != pair.ifindex or j.pair.family != pair.family) continue;
            r.finishJob(j);
        }
        for (r.pending) |*p| {
            if (!p.used or p.pair.ifindex != pair.ifindex or p.pair.family != pair.family) continue;
            p.used = false;
        }
    }

    /// Write the record(s) behind `ref` into `section`. Returns false
    /// when the ref has nothing to write on this interface (no address
    /// of that family). `error.NoSpace` after a partial multi-address
    /// set leaves the earlier addresses in the packet.
    fn emitRef(r: *const Responder, env: *const Env, b: *wire.Builder, section: wire.Section, ref: RecordRef, ifindex: u32, flush: bool, ttl0: bool) wire.builder.Error!bool {
        const ttl: u32 = if (ttl0) 0 else ttlOf(ref.kind);
        switch (ref.kind) {
            .host_a => {
                const iface = env.iface(ifindex) orelse return false;
                if (iface.v4.len == 0) return false;
                for (iface.v4.slice()) |p| try b.addRR(section, r.host.name, .a, wire.class_in, flush, ttl, .{ .a = p.addr });
                return true;
            },
            .host_aaaa => {
                const iface = env.iface(ifindex) orelse return false;
                if (iface.v6.len == 0) return false;
                for (iface.v6.slice()) |p| try b.addRR(section, r.host.name, .aaaa, wire.class_in, flush, ttl, .{ .aaaa = p.addr });
                return true;
            },
            .host_nsec => {
                const iface = env.iface(ifindex) orelse return false;
                const nsec = hostNsec(r.host.name, iface.v4.len != 0, iface.v6.len != 0);
                try b.addRR(section, r.host.name, .nsec, wire.class_in, flush, ttl, .{ .nsec = nsec });
                return true;
            },
            .ptr => {
                const g = &r.regs[ref.reg];
                try b.addRR(section, g.type_name, .ptr, wire.class_in, false, ttl, .{ .ptr = g.inst_name });
                return true;
            },
            .srv => {
                const g = &r.regs[ref.reg];
                try b.addRR(section, g.inst_name, .srv, wire.class_in, flush, ttl, .{ .srv = .{ .port = g.port, .target = r.host.name } });
                return true;
            },
            .txt => {
                const g = &r.regs[ref.reg];
                try b.addRR(section, g.inst_name, .txt, wire.class_in, flush, ttl, .{ .txt = g.txt.slice() });
                return true;
            },
            .inst_nsec => {
                const g = &r.regs[ref.reg];
                const nsec = instanceNsec(g.inst_name);
                try b.addRR(section, g.inst_name, .nsec, wire.class_in, flush, ttl, .{ .nsec = nsec });
                return true;
            },
        }
    }
};

// ---- pure helpers -------------------------------------------------------

/// Section 7.1 known-answer rule: the querier's copy suppresses ours
/// when its TTL is at least half of ours (plan section 4.4
/// `ka_half_ttl`).
pub fn kaSuppresses(ka_ttl_s: u32, our_ttl_s: u32) bool {
    return ka_ttl_s >= our_ttl_s / timers.ka_half_ttl_divisor;
}

/// Section 6.1 NSEC for the host name: the bitmap lists the address
/// types the interface holds; next-domain is the name itself.
pub fn hostNsec(host: Name, has_a: bool, has_aaaa: bool) wire.Nsec {
    var n: wire.Nsec = .{ .next = host };
    // A and AAAA are inside window 0 and are not the NSEC type: `set`
    // cannot fail for them.
    if (has_a) n.set(.a) catch {};
    if (has_aaaa) n.set(.aaaa) catch {};
    return n;
}

/// Section 6.1 NSEC for an instance name: SRV and TXT are present.
pub fn instanceNsec(inst: Name) wire.Nsec {
    return wire.Nsec.fromTypes(inst, &.{ .srv, .txt }) catch .{ .next = inst };
}

/// Section 8.2 over two sorted record sets: the lexicographically later
/// set wins; the set that runs out first loses; `.lt` means `ours`
/// loses, `.gt` means `ours` wins, `.eq` is a tie (identical sets).
pub fn compareSortedSets(ours: []const wire.rdata.Key, theirs: []const wire.rdata.Key) std.math.Order {
    var i: usize = 0;
    while (true) : (i += 1) {
        if (i >= ours.len and i >= theirs.len) return .eq;
        if (i >= ours.len) return .lt;
        if (i >= theirs.len) return .gt;
        const c = wire.rdata.rdataCompare(ours[i], theirs[i]);
        if (c != .eq) return c;
    }
}

fn keyLess(_: void, a: wire.rdata.Key, b: wire.rdata.Key) bool {
    return wire.rdata.rdataCompare(a, b) == .lt;
}

/// Sort `keys` into section 8.2 order (class, type, rdata).
pub fn sortKeys(keys: []wire.rdata.Key) void {
    std.sort.insertion(wire.rdata.Key, keys, {}, keyLess);
}

/// Section 8.2 against a peer's probe: our proposed records for `name`
/// (unsorted; sorted here) against every Authority record of `msg` with
/// that name (at most `max_tiebreak_records`, names expanded).
pub fn tieBreakAgainst(ours_in: []const wire.rdata.Key, msg: *const wire.Message, name: *const Name) std.math.Order {
    var ours: [2 * events.max_addrs_per_family]wire.rdata.Key = undefined;
    const n_ours = @min(ours_in.len, ours.len);
    @memcpy(ours[0..n_ours], ours_in[0..n_ours]);
    sortKeys(ours[0..n_ours]);

    var scratch: [wire.max_message_len]u8 = undefined;
    var used: usize = 0;
    var theirs: [max_tiebreak_records]wire.rdata.Key = undefined;
    var n_theirs: usize = 0;
    var it = msg.authority();
    while (it.next()) |rec| {
        if (n_theirs == theirs.len) break;
        if (!rec.name.eql(name)) continue;
        const canon = wire.rdata.canonicalRdata(msg.bytes, rec, scratch[used..]) catch continue;
        theirs[n_theirs] = .{ .class = rec.class, .rtype = rec.rtype.toInt(), .rdata = canon };
        n_theirs += 1;
        used += canon.len;
    }
    sortKeys(theirs[0..n_theirs]);
    return compareSortedSets(ours[0..n_ours], theirs[0..n_theirs]);
}

/// Cut `s` to at most `max` octets on a UTF-8 boundary.
fn truncateUtf8(s: []const u8, max: usize) []const u8 {
    if (s.len <= max) return s;
    var len = max;
    while (len > 0 and (s[len] & 0xC0) == 0x80) len -= 1;
    return s[0..len];
}

/// Instance rename (RFC 6762 section 9; plan section 4.8): `Name` ->
/// `Name (2)`, `Name (2)` -> `Name (3)`. The base is cut on a UTF-8
/// boundary so the result stays one label of at most 63 octets.
pub fn bumpInstance(cur: []const u8, out: *[max_label_len]u8) []const u8 {
    var base = cur;
    var n: u32 = 1;
    if (cur.len >= 4 and cur[cur.len - 1] == ')') {
        if (std.mem.lastIndexOf(u8, cur, " (")) |open| {
            const digits = cur[open + 2 .. cur.len - 1];
            if (digits.len > 0 and digits.len <= 9 and allDigits(digits)) {
                base = cur[0..open];
                n = std.fmt.parseInt(u32, digits, 10) catch 1;
            }
        }
    }
    const next = @max(n + 1, 2);
    var suffix: [16]u8 = undefined;
    const sfx = std.fmt.bufPrint(&suffix, " ({d})", .{next}) catch unreachable;
    const room = max_label_len - sfx.len;
    const kept = truncateUtf8(base, room);
    @memcpy(out[0..kept.len], kept);
    @memcpy(out[kept.len..][0..sfx.len], sfx);
    return out[0 .. kept.len + sfx.len];
}

/// Host rename (plan section 4.8 "Host-name conflicts"): `label` ->
/// `label-2`, `label-2` -> `label-3`.
pub fn bumpHostLabel(cur: []const u8, out: *[max_label_len]u8) []const u8 {
    var base = cur;
    var n: u32 = 1;
    if (std.mem.lastIndexOfScalar(u8, cur, '-')) |dash| {
        const digits = cur[dash + 1 ..];
        if (dash > 0 and digits.len > 0 and digits.len <= 9 and allDigits(digits)) {
            base = cur[0..dash];
            n = std.fmt.parseInt(u32, digits, 10) catch 1;
        }
    }
    const next = @max(n + 1, 2);
    var suffix: [16]u8 = undefined;
    const sfx = std.fmt.bufPrint(&suffix, "-{d}", .{next}) catch unreachable;
    const room = max_label_len - sfx.len;
    const kept = truncateUtf8(base, room);
    @memcpy(out[0..kept.len], kept);
    @memcpy(out[kept.len..][0..sfx.len], sfx);
    return out[0 .. kept.len + sfx.len];
}

fn allDigits(s: []const u8) bool {
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

/// A host label: one label of 1..63 octets of valid UTF-8, no control
/// characters and no `.` (RFC 6762 section 16; Revision 5 item 8).
pub fn validateHostLabel(label: []const u8) HostLabelError!void {
    if (label.len == 0 or label.len > max_label_len) return error.InvalidHostLabel;
    if (!std.unicode.utf8ValidateSlice(label)) return error.InvalidHostLabel;
    for (label) |c| if (std.ascii.isControl(c) or c == '.') return error.InvalidHostLabel;
}

/// Validate a TXT the way `advertise` does (plan section 4.5: wire form
/// at most 400 octets).
pub fn validateTxt(pairs: []const TxtPair) error{ TxtTooLarge, InvalidTxt }!void {
    _ = try Responder.buildTxt(pairs);
}

// ---- tests ------------------------------------------------------------

const testing = std.testing;

test "tie-break compare follows section 8.2 order and the run-out rule" {
    const a1: [4]u8 = .{ 10, 0, 0, 1 };
    const a2: [4]u8 = .{ 10, 0, 0, 2 };
    const ka1: wire.rdata.Key = .{ .class = 1, .rtype = 1, .rdata = &a1 };
    const ka2: wire.rdata.Key = .{ .class = 1, .rtype = 1, .rdata = &a2 };
    const kaaaa: wire.rdata.Key = .{ .class = 1, .rtype = 28, .rdata = &(@as([16]u8, @splat(0))) };
    // Higher rdata wins.
    try testing.expectEqual(std.math.Order.lt, compareSortedSets(&.{ka1}, &.{ka2}));
    try testing.expectEqual(std.math.Order.gt, compareSortedSets(&.{ka2}, &.{ka1}));
    try testing.expectEqual(std.math.Order.eq, compareSortedSets(&.{ka1}, &.{ka1}));
    // Type is compared before rdata; the cache-flush bit is ignored.
    const flushed: wire.rdata.Key = .{ .class = 0x8001, .rtype = 1, .rdata = &a1 };
    try testing.expectEqual(std.math.Order.lt, compareSortedSets(&.{ka2}, &.{kaaaa}));
    try testing.expectEqual(std.math.Order.eq, compareSortedSets(&.{ka1}, &.{flushed}));
    // The set that runs out first loses.
    try testing.expectEqual(std.math.Order.lt, compareSortedSets(&.{ka1}, &.{ ka1, kaaaa }));
    try testing.expectEqual(std.math.Order.gt, compareSortedSets(&.{ ka1, kaaaa }, &.{ka1}));
    try testing.expectEqual(std.math.Order.eq, compareSortedSets(&.{}, &.{}));
    // sortKeys puts the set into (class, type, rdata) order.
    var keys = [_]wire.rdata.Key{ kaaaa, ka2, ka1 };
    sortKeys(&keys);
    try testing.expectEqual(@as(u16, 1), keys[0].rtype);
    try testing.expectEqualSlices(u8, &a1, keys[0].rdata);
    try testing.expectEqualSlices(u8, &a2, keys[1].rdata);
    try testing.expectEqual(@as(u16, 28), keys[2].rtype);
}

test "KA suppression predicate omits at or past half TTL" {
    try testing.expect(kaSuppresses(60, 120));
    try testing.expect(kaSuppresses(120, 120));
    try testing.expect(!kaSuppresses(59, 120));
    try testing.expect(kaSuppresses(2250, 4500));
    try testing.expect(!kaSuppresses(2249, 4500));
    try testing.expect(!kaSuppresses(0, 120));
}

test "NSEC bitmap lists only the types present" {
    const host = try Name.parse("h.local");
    const both = hostNsec(host, true, true);
    try testing.expect(both.has(.a) and both.has(.aaaa) and !both.has(.srv) and !both.has(.nsec));
    try testing.expect(both.next.eql(&host));
    const v4 = hostNsec(host, true, false);
    try testing.expect(v4.has(.a) and !v4.has(.aaaa));
    const none_at_all = hostNsec(host, false, false);
    try testing.expectEqual(@as(usize, 0), none_at_all.bitmapLen());
    const inst = try Name.parse("a._x._udp.local");
    const n = instanceNsec(inst);
    try testing.expect(n.has(.srv) and n.has(.txt) and !n.has(.a) and !n.has(.ptr));
    // On the wire: window 0, A (1) and AAAA (28) => 4 octets, AAAA in
    // octet 3 bit 4.
    const wb = both.wireBitmap();
    try testing.expectEqual(@as(usize, 4), wb.len);
    try testing.expectEqual(@as(u8, 0x40), wb.buf[0]);
    try testing.expectEqual(@as(u8, 0x08), wb.buf[3]);
}

test "rate-limit bookkeeping is per record and per interface" {
    var t = try RateTable.init(testing.allocator, 2, 5);
    defer t.deinit(testing.allocator);
    const live = [_]Interface{ .{ .index = 3 }, .{ .index = 4 } };
    const p3: Pair = .{ .ifindex = 3, .family = .v4 };
    const p3v6: Pair = .{ .ifindex = 3, .family = .v6 };
    const p4: Pair = .{ .ifindex = 4, .family = .v4 };
    const p9: Pair = .{ .ifindex = 9, .family = .v4 };
    try testing.expect(t.allowed(1, p3, 0));
    try testing.expectEqual(null, t.lastMulticast(1, p3));
    t.mark(1, p3, timers.ms(500), &live);
    try testing.expectEqual(@as(?u64, timers.ms(500)), t.lastMulticast(1, p3));
    try testing.expect(!t.allowed(1, p3, timers.ms(1499)));
    try testing.expect(t.allowed(1, p3, timers.ms(1500)));
    // Another record, the other family and another interface are
    // independent.
    try testing.expect(t.allowed(2, p3, timers.ms(600)));
    try testing.expect(t.allowed(1, p3v6, timers.ms(600)));
    try testing.expect(t.allowed(1, p4, timers.ms(600)));
    t.mark(1, p4, timers.ms(600), &live);
    try testing.expect(!t.allowed(1, p4, timers.ms(700)));
    // A third interface recycles a slot not in the live table.
    const live2 = [_]Interface{ .{ .index = 4 }, .{ .index = 9 } };
    t.mark(0, p9, timers.ms(700), &live2);
    try testing.expectEqual(null, t.lastMulticast(1, p3));
    try testing.expectEqual(@as(?u64, timers.ms(600)), t.lastMulticast(1, p4));
    try testing.expectEqual(@as(?u64, timers.ms(700)), t.lastMulticast(0, p9));
}

test "rename helpers bump Name (2) to Name (3) and label-2 to label-3" {
    var buf: [max_label_len]u8 = undefined;
    try testing.expectEqualStrings("Name (2)", bumpInstance("Name", &buf));
    try testing.expectEqualStrings("Name (3)", bumpInstance("Name (2)", &buf));
    try testing.expectEqualStrings("Name (10)", bumpInstance("Name (9)", &buf));
    try testing.expectEqualStrings("Name (2)", bumpInstance("Name (1)", &buf));
    try testing.expectEqualStrings("Name (x) (2)", bumpInstance("Name (x)", &buf));
    try testing.expectEqualStrings("(2) (2)", bumpInstance("(2)", &buf));
    try testing.expectEqualStrings("label-2", bumpHostLabel("label", &buf));
    try testing.expectEqualStrings("label-3", bumpHostLabel("label-2", &buf));
    try testing.expectEqualStrings("my-host-2", bumpHostLabel("my-host", &buf));
    try testing.expectEqualStrings("my-host-3", bumpHostLabel("my-host-2", &buf));
    try testing.expectEqualStrings("-9-2", bumpHostLabel("-9", &buf));
    // A 63-octet name is cut on a UTF-8 boundary to make room.
    const long: [63]u8 = @splat('a');
    const r = bumpInstance(&long, &buf);
    try testing.expectEqual(@as(usize, 63), r.len);
    try testing.expect(std.mem.endsWith(u8, r, " (2)"));
    var utf: [63]u8 = @splat('a');
    utf[59] = 0xE2; // three-octet sequence at 59..61 ("…")
    utf[60] = 0x80;
    utf[61] = 0xA6;
    utf[62] = 'b';
    const r2 = bumpHostLabel(&utf, &buf);
    try testing.expect(std.unicode.utf8ValidateSlice(r2));
    try testing.expect(r2.len <= 63);
    try testing.expect(std.mem.endsWith(u8, r2, "-2"));
}

test "TXT and host-label validation" {
    try validateTxt(&.{});
    try validateTxt(&.{ .{ .key = "k", .value = "v" }, .{ .key = "flag" } });
    const big: [253]u8 = @splat('x'); // "a=" + 253 fits one 255-octet string; two exceed 400
    try testing.expectError(error.TxtTooLarge, validateTxt(&.{ .{ .key = "a", .value = &big }, .{ .key = "b", .value = &big } }));
    try testing.expectError(error.InvalidTxt, validateTxt(&.{.{ .key = "" }}));
    try testing.expectError(error.InvalidTxt, validateTxt(&.{.{ .key = "a=b" }}));
    try validateHostLabel("studio-a");
    try validateHostLabel("ünïcode");
    try testing.expectError(error.InvalidHostLabel, validateHostLabel(""));
    try testing.expectError(error.InvalidHostLabel, validateHostLabel("a.b"));
    try testing.expectError(error.InvalidHostLabel, validateHostLabel("a\nb"));
    try testing.expectError(error.InvalidHostLabel, validateHostLabel(&(@as([64]u8, @splat('a')))));
    try testing.expectError(error.InvalidHostLabel, validateHostLabel(&.{ 0xff, 0xfe }));
}

test "record set collect order and merge" {
    var s: RecordSet = .empty;
    try testing.expect(s.isEmpty());
    s.add(.{ .kind = .txt, .reg = 2 });
    s.add(.{ .kind = .host_aaaa });
    s.add(.{ .kind = .ptr, .reg = 0 });
    var o: RecordSet = .empty;
    o.add(.{ .kind = .srv, .reg = 2 });
    s.merge(&o);
    var refs: [RecordSet.max_refs]RecordRef = undefined;
    const all = s.collect(&refs);
    try testing.expectEqual(@as(usize, 4), all.len);
    try testing.expectEqual(RecKind.host_aaaa, all[0].kind);
    try testing.expectEqual(RecKind.ptr, all[1].kind);
    try testing.expectEqual(@as(u8, 0), all[1].reg);
    try testing.expectEqual(RecKind.srv, all[2].kind);
    try testing.expectEqual(RecKind.txt, all[3].kind);
    try testing.expect(s.has(.{ .kind = .srv, .reg = 2 }));
    s.remove(.{ .kind = .srv, .reg = 2 });
    try testing.expect(!s.has(.{ .kind = .srv, .reg = 2 }));
}
