//! A scripted DNS-SD responder for the tier-1 LAN tests (plan section 7
//! M3: "build responder packets without M4's responder"). It answers
//! PTR / SRV / TXT / A / AAAA questions from a static instance table
//! through `wire.Builder` and sits on a `FakeLan` segment as a
//! pseudo-engine: `pump` reads the LAN's `sent` log for queries on its
//! segment, queues an answer per query after `Options.delay_us`, and
//! injects due answers with `injectForeign` (so every engine on the
//! segment receives them with the responder's source address).
//!
//! Knobs (`Options`): record order (PTR first or reversed, hashicorp/mdns
//! #145), additionals on or off (everything in the answer section), the
//! cache-flush bit, per-type TTLs, TC, the source port (a non-5353
//! responder is an RFC 6762 section 6 violation the querier must ignore),
//! unicast replies (dropped outside the 2 s QU window) and responder-side
//! known-answer suppression (section 7.1: a PTR listed in the query with
//! at least half its TTL left is not answered again).
//!
//! What it is not: it never probes, announces, defends or rate-limits;
//! M4's `core/responder.zig` does. Injected answers bypass the LAN loss
//! model (`injectForeign` delivers unconditionally).
const std = @import("std");
const Io = std.Io;
const mdns = @import("mdns");
const wire = mdns.wire;
const packets = @import("packets.zig");
const fake_lan = @import("fake_lan.zig");

pub const Name = wire.Name;
pub const Family = mdns.Family;

/// One advertised instance.
pub const InstanceSpec = struct {
    instance: []const u8,
    /// `_qmsg._udp` form (no `.local`).
    service_type: []const u8,
    /// Host label (no `.local`).
    host: []const u8,
    port: u16,
    txt: []const wire.TxtPair = &.{},
    addrs4: []const [4]u8 = &.{},
    addrs6: []const [16]u8 = &.{},
};

pub const Order = enum { ptr_first, reversed };

pub const Options = struct {
    order: Order = .ptr_first,
    /// PTR answer carries SRV / TXT / A / AAAA as additionals (RFC 6763
    /// section 12). Off: every record goes into the answer section.
    additionals: bool = true,
    /// Cache-flush on the unique records (SRV, TXT, A, AAAA); never on
    /// the shared PTR.
    cache_flush: bool = true,
    ptr_ttl: u32 = 4500,
    srv_ttl: u32 = 120,
    txt_ttl: u32 = 4500,
    addr_ttl: u32 = 120,
    /// Set TC on every response (the querier must ignore it, RFC 6762
    /// section 18.5).
    tc: bool = false,
    /// Source UDP port of every response. 5353 is the only legal value
    /// (section 6); anything else must be dropped by the querier.
    source_port: u16 = 5353,
    /// Reply with a unicast destination instead of the group.
    unicast_reply: bool = false,
    /// Fixed answer delay (a real responder draws 20-120 ms, section 6).
    delay_us: u64 = 50_000,
    /// RFC 6762 section 7.1 responder side.
    known_answer_suppression: bool = true,
};

pub const Stats = struct {
    queries_seen: u64 = 0,
    responses_sent: u64 = 0,
    /// PTR answers withheld because the query listed them as known.
    suppressed: u64 = 0,
    /// Questions for names or types this responder does not serve.
    questions_unanswered: u64 = 0,
    /// Answers dropped because the pending ring was full.
    pending_overflow: u64 = 0,
};

pub const max_pending = 8;
pub const max_response = 2048;

const Pending = struct {
    due_us: u64,
    family: Family,
    len: usize,
    bytes: [max_response]u8,
};

pub const FakeResponder = struct {
    segment: u32,
    addr4: [4]u8,
    ll6: [16]u8,
    table: []const InstanceSpec,
    opts: Options,
    stats: Stats = .{},
    /// Next `sent` log index to examine.
    cursor: usize = 0,
    pending: [max_pending]Pending = undefined,
    pending_len: usize = 0,
    /// Bit i set: `table[i]` was withdrawn by `goodbye` and is no longer
    /// answered.
    withdrawn: u64 = 0,

    /// `ll_suffix` forms the responder's `fe80::<suffix>` source for v6
    /// queries. `table` must outlive the responder.
    pub fn init(segment: u32, addr4: [4]u8, ll_suffix: u16, table: []const InstanceSpec, opts: Options) FakeResponder {
        return .{ .segment = segment, .addr4 = addr4, .ll6 = fake_lan.linkLocal6(ll_suffix), .table = table, .opts = opts };
    }

    pub fn sourceAddr(r: *const FakeResponder, family: Family) Io.net.IpAddress {
        return switch (family) {
            .v4 => .{ .ip4 = .{ .bytes = r.addr4, .port = r.opts.source_port } },
            .v6 => .{ .ip6 = .{ .bytes = r.ll6, .port = r.opts.source_port } },
        };
    }

    /// Read new queries from the LAN log and queue answers, then inject
    /// every answer that is due. Call after `lan.pump(now_us)`.
    pub fn pump(r: *FakeResponder, lan: anytype, now_us: u64) !void {
        try r.observe(lan, now_us);
        try r.flush(lan, now_us);
    }

    pub fn observe(r: *FakeResponder, lan: anytype, now_us: u64) !void {
        const log = lan.sentLog();
        while (r.cursor < log.len) : (r.cursor += 1) {
            const s = &log[r.cursor];
            if (s.kind != .query) continue;
            if (!lan.connected(s.segment, r.segment)) continue;
            r.stats.queries_seen += 1;
            if (r.pending_len == max_pending) {
                r.stats.pending_overflow += 1;
                continue;
            }
            const slot = &r.pending[r.pending_len];
            const out = (try r.answerQuery(s.bytes, &slot.bytes)) orelse continue;
            slot.due_us = now_us + r.opts.delay_us;
            slot.family = s.family;
            slot.len = out.len;
            r.pending_len += 1;
        }
    }

    pub fn flush(r: *FakeResponder, lan: anytype, now_us: u64) !void {
        var i: usize = 0;
        while (i < r.pending_len) {
            const p = &r.pending[i];
            if (p.due_us > now_us) {
                i += 1;
                continue;
            }
            _ = try lan.injectForeign(r.segment, p.bytes[0..p.len], r.sourceAddr(p.family), !r.opts.unicast_reply, now_us);
            r.stats.responses_sent += 1;
            // Remove by swapping the last one in (order is irrelevant).
            r.pending_len -= 1;
            if (i != r.pending_len) r.pending[i] = r.pending[r.pending_len];
        }
    }

    /// Nothing queued.
    pub fn idle(r: *const FakeResponder) bool {
        return r.pending_len == 0;
    }

    /// Due time of the soonest queued answer, or null when idle (for a
    /// deadline-driven loop: jump here rather than crawl to it).
    pub fn nextDueUs(r: *const FakeResponder) ?u64 {
        var best: ?u64 = null;
        for (r.pending[0..r.pending_len]) |*p| best = if (best) |b| @min(b, p.due_us) else p.due_us;
        return best;
    }

    /// Withdraw `table[idx]` at once: one multicast packet from the v4
    /// source with the PTR, SRV, TXT and addresses at TTL 0 (RFC 6762
    /// section 10.1); the row is not answered again.
    pub fn goodbye(r: *FakeResponder, lan: anytype, idx: usize, now_us: u64) !void {
        std.debug.assert(idx < 64);
        r.withdrawn |= @as(u64, 1) << @intCast(idx);
        const spec = &r.table[idx];
        var buf: [max_response]u8 = undefined;
        var p: packets.Packet = .response(&buf);
        try p.ptr(spec.service_type, spec.instance, 0);
        try p.srv(spec.instance, spec.service_type, spec.port, spec.host, 0, false);
        try p.txt(spec.instance, spec.service_type, spec.txt, 0, false);
        for (spec.addrs4) |a| try p.a(spec.host, a, 0, false);
        for (spec.addrs6) |a| try p.aaaa(spec.host, a, 0, false);
        const bytes = p.bytes();
        _ = try lan.injectForeign(r.segment, bytes, r.sourceAddr(.v4), true, now_us);
        r.stats.responses_sent += 1;
    }

    /// Build the response to `query` into `buf`; null when nothing in the
    /// query is answerable (or everything was suppressed).
    pub fn answerQuery(r: *FakeResponder, query: []const u8, buf: []u8) !?[]const u8 {
        const msg = wire.Message.parse(query) catch return null;
        if (msg.isResponse()) return null;
        var p: packets.Packet = .response(buf);
        p.b.setTruncated(r.opts.tc);
        var answered: usize = 0;
        // Pass 1: answer-section records; pass 2: additionals. The
        // Builder refuses an answer record after an additional one.
        var qs = msg.questions();
        while (qs.next()) |q| answered += try r.answerSection(&p, &msg, q, .answer);
        if (answered == 0) return null;
        if (r.opts.additionals) {
            p.in(.additional);
            var qs2 = msg.questions();
            while (qs2.next()) |q| _ = try r.answerSection(&p, &msg, q, .additional);
        }
        return p.bytes();
    }

    /// Records for `q` that belong in `section`. Returns the number
    /// written.
    fn answerSection(r: *FakeResponder, p: *packets.Packet, msg: *const wire.Message, q: wire.Question, section: wire.Section) !usize {
        var n: usize = 0;
        var matched = false;
        for (r.table, 0..) |*spec, idx| {
            if (idx < 64 and (r.withdrawn >> @intCast(idx)) & 1 == 1) continue;
            const tname = packets.typeName(spec.service_type);
            const iname = packets.instanceName(spec.instance, spec.service_type);
            const hname = packets.hostName(spec.host);
            switch (q.qtype) {
                .ptr => if (q.name.eql(&tname)) {
                    matched = true;
                    const known = r.opts.known_answer_suppression and try r.isKnown(msg, &tname, &iname);
                    if (section == .answer) {
                        if (known) {
                            r.stats.suppressed += 1;
                            continue;
                        }
                        if (r.opts.order == .reversed and !r.opts.additionals) n += try r.addUnique(p, spec, .all);
                        try p.ptr(spec.service_type, spec.instance, r.opts.ptr_ttl);
                        n += 1;
                        if (r.opts.order == .ptr_first and !r.opts.additionals) n += try r.addUnique(p, spec, .all);
                    } else if (!known) {
                        n += try r.addUnique(p, spec, .all);
                    }
                },
                .srv => if (q.name.eql(&iname)) {
                    matched = true;
                    n += try r.addUnique(p, spec, if (section == .answer) .srv_only else .addrs_only);
                },
                .txt => if (q.name.eql(&iname)) {
                    matched = true;
                    if (section == .answer) n += try r.addUnique(p, spec, .txt_only);
                },
                .a, .aaaa => if (q.name.eql(&hname)) {
                    matched = true;
                    if (section == .answer) n += try r.addUnique(p, spec, if (q.qtype == .a) .a_only else .aaaa_only);
                },
                else => {},
            }
        }
        if (section == .answer and !matched) r.stats.questions_unanswered += 1;
        return n;
    }

    const Which = enum { all, srv_only, txt_only, addrs_only, a_only, aaaa_only };

    fn addUnique(r: *const FakeResponder, p: *packets.Packet, spec: *const InstanceSpec, which: Which) !usize {
        const cf = r.opts.cache_flush;
        var n: usize = 0;
        const srv_first = r.opts.order == .ptr_first;
        if (srv_first) {
            if (which == .all or which == .srv_only) {
                try p.srv(spec.instance, spec.service_type, spec.port, spec.host, r.opts.srv_ttl, cf);
                n += 1;
            }
            if (which == .all or which == .txt_only) {
                try p.txt(spec.instance, spec.service_type, spec.txt, r.opts.txt_ttl, cf);
                n += 1;
            }
        }
        if (which == .all or which == .addrs_only or which == .a_only) {
            for (spec.addrs4) |a| {
                try p.a(spec.host, a, r.opts.addr_ttl, cf);
                n += 1;
            }
        }
        if (which == .all or which == .addrs_only or which == .aaaa_only) {
            for (spec.addrs6) |a| {
                try p.aaaa(spec.host, a, r.opts.addr_ttl, cf);
                n += 1;
            }
        }
        if (!srv_first) {
            if (which == .all or which == .txt_only) {
                try p.txt(spec.instance, spec.service_type, spec.txt, r.opts.txt_ttl, cf);
                n += 1;
            }
            if (which == .all or which == .srv_only) {
                try p.srv(spec.instance, spec.service_type, spec.port, spec.host, r.opts.srv_ttl, cf);
                n += 1;
            }
        }
        return n;
    }

    /// RFC 6762 section 7.1: the query's answer section lists this PTR
    /// with at least half of our TTL left.
    fn isKnown(r: *const FakeResponder, msg: *const wire.Message, tname: *const Name, iname: *const Name) !bool {
        var it = msg.answers();
        while (it.next()) |rec| {
            if (rec.rtype != .ptr or !rec.name.eql(tname)) continue;
            const target = wire.rdata.decodePtr(msg.bytes, rec) catch continue;
            if (!target.eql(iname)) continue;
            if (rec.ttl >= r.opts.ptr_ttl / 2) return true;
        }
        return false;
    }
};

/// Called after every step of `run` with that step's clock (drain the
/// event sinks here).
pub const Hook = struct {
    ctx: *anyopaque,
    f: *const fn (*anyopaque, u64) anyerror!void,
};

/// `lan.run` with responders interleaved: tick, pump, every responder,
/// then `hook`, at `from_us`, every `step_us`, and at `to_us`.
pub fn run(lan: anytype, responders: []const *FakeResponder, from_us: u64, to_us: u64, step_us: u64, hook: ?Hook) !void {
    std.debug.assert(step_us > 0);
    std.debug.assert(to_us >= from_us);
    var t = from_us;
    while (true) {
        lan.tickAll(t);
        try lan.pump(t);
        for (responders) |r| try r.pump(lan, t);
        if (hook) |h| try h.f(h.ctx, t);
        if (t >= to_us) break;
        t = @min(t +| step_us, to_us);
    }
}

const testing = std.testing;

const demo_table = [_]InstanceSpec{
    .{ .instance = "demo", .service_type = "_qmsg._udp", .host = "host-d", .port = 4433, .txt = &.{.{ .key = "spki", .value = "00" }}, .addrs4 = &.{.{ 10, 0, 3, 7 }} },
    .{ .instance = "other", .service_type = "_printer._tcp", .host = "host-p", .port = 515, .addrs4 = &.{.{ 10, 0, 3, 8 }} },
};

test "fake responder answers a PTR query with additionals and honours known answers" {
    var r: FakeResponder = .init(1, .{ 10, 0, 3, 7 }, 7, &demo_table, .{});
    var qbuf: [512]u8 = undefined;
    var q: packets.Packet = .query(&qbuf);
    try q.question(packets.typeName("_qmsg._udp"), .ptr, false);
    var out: [max_response]u8 = undefined;
    const bytes = (try r.answerQuery(q.bytes(), &out)).?;
    const msg = try wire.Message.parse(bytes);
    try testing.expect(msg.isResponse());
    try testing.expectEqual(@as(u16, 1), msg.header.ancount);
    try testing.expectEqual(@as(u16, 3), msg.header.arcount); // SRV, TXT, A
    try testing.expectEqual(@as(u64, 0), r.stats.suppressed);
    // The printer instance is not an answer to a _qmsg question.
    var an = msg.answers();
    const ptr = an.next().?;
    try wire.name.expectText("demo._qmsg._udp.local", try wire.rdata.decodePtr(bytes, ptr));

    // The same question with the PTR as a known answer at full TTL:
    // suppressed, nothing to send.
    var q2: packets.Packet = .query(&qbuf);
    try q2.question(packets.typeName("_qmsg._udp"), .ptr, false);
    try q2.ptr("_qmsg._udp", "demo", 4000);
    try testing.expectEqual(null, try r.answerQuery(q2.bytes(), &out));
    try testing.expectEqual(@as(u64, 1), r.stats.suppressed);
    // Below half TTL the known answer no longer suppresses.
    var q3: packets.Packet = .query(&qbuf);
    try q3.question(packets.typeName("_qmsg._udp"), .ptr, false);
    try q3.ptr("_qmsg._udp", "demo", 2000);
    try testing.expect((try r.answerQuery(q3.bytes(), &out)) != null);
}

test "fake responder reversed order without additionals puts the PTR last" {
    var r: FakeResponder = .init(1, .{ 10, 0, 3, 7 }, 7, &demo_table, .{ .order = .reversed, .additionals = false, .source_port = 40_000 });
    var qbuf: [512]u8 = undefined;
    var q: packets.Packet = .query(&qbuf);
    try q.question(packets.typeName("_qmsg._udp"), .ptr, false);
    var out: [max_response]u8 = undefined;
    const bytes = (try r.answerQuery(q.bytes(), &out)).?;
    const msg = try wire.Message.parse(bytes);
    try testing.expectEqual(@as(u16, 4), msg.header.ancount);
    try testing.expectEqual(@as(u16, 0), msg.header.arcount);
    var it = msg.answers();
    try testing.expectEqual(wire.RType.a, it.next().?.rtype);
    try testing.expectEqual(wire.RType.txt, it.next().?.rtype);
    try testing.expectEqual(wire.RType.srv, it.next().?.rtype);
    try testing.expectEqual(wire.RType.ptr, it.next().?.rtype);
    try testing.expectEqual(@as(u16, 40_000), r.sourceAddr(.v4).ip4.port);
}

test "fake responder answers SRV TXT and A questions for its names only" {
    var r: FakeResponder = .init(1, .{ 10, 0, 3, 7 }, 7, &demo_table, .{});
    var qbuf: [512]u8 = undefined;
    var q: packets.Packet = .query(&qbuf);
    try q.question(packets.instanceName("demo", "_qmsg._udp"), .srv, false);
    try q.question(packets.instanceName("demo", "_qmsg._udp"), .txt, false);
    try q.question(packets.hostName("host-d"), .a, false);
    try q.question(packets.hostName("nobody"), .a, false);
    var out: [max_response]u8 = undefined;
    const bytes = (try r.answerQuery(q.bytes(), &out)).?;
    const msg = try wire.Message.parse(bytes);
    try testing.expectEqual(@as(u16, 3), msg.header.ancount); // SRV, TXT, A
    try testing.expectEqual(@as(u16, 1), msg.header.arcount); // A for the SRV target
    try testing.expectEqual(@as(u64, 1), r.stats.questions_unanswered); // nobody.local

}
