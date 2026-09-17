//! Responder conformance tests (plan section 7, M4 named tests): RFC
//! 6762 section 8 probing and announcing, section 8.2 tie-break, section
//! 9 conflicts, renames and backoff, section 6 answering (immediate
//! unique answers, delayed shared answers, the one-second rate limit,
//! per-interface addresses, NSEC, legacy and QU replies, probe defence),
//! section 7.1 known-answer suppression, section 8.4 `updateTxt`, the
//! bridged-echo re-announce and the record TTLs. The first part runs
//! one `Engine` on a fake clock with a seeded PRNG against hand-built
//! packets from `tests/harness/packets.zig` (the hostile peer: foreign
//! probes, responses claiming our names, legacy and QU queries, echoes
//! from our own address); the second part ("over the fake LAN") puts
//! real engines on both sides of a `tests/harness/fake_lan.zig` segment
//! for the end-to-end, budget and flood checks.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const mdns = @import("mdns");
const wire = mdns.wire;
const scenario = @import("harness/scenario.zig");
const packets = @import("harness/packets.zig");
const fake_lan = @import("harness/fake_lan.zig");

const Scenario = scenario.Scenario;
const Sink = scenario.Sink;
const Engine = mdns.Engine;
const Packet = packets.Packet;
const timers = mdns.core.timers;
const Name = wire.Name;

const s_us = scenario.us_per_s;
const ms_us = scenario.us_per_ms;
const svc_type = "_mdnszig._udp";
const inst = "demo";
const host_label = "unit";
const port: u16 = 4433;

const foreign4: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 9 }, .port = 5353 } };
const own4: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 1 }, .port = 5353 } };

/// First record with that name and type in `section` of `bytes`, or
/// null (also null when the bytes do not parse).
fn recIn(bytes: []const u8, section: wire.Section, name: Name, rtype: wire.RType) ?wire.Record {
    const m = wire.Message.parse(bytes) catch return null;
    var it = m.records(section);
    while (it.next()) |rec| if (rec.rtype == rtype and rec.name.eql(&name)) return rec;
    return null;
}

/// Records with that name and type in any section of `bytes`.
fn countIn(bytes: []const u8, name: Name, rtype: wire.RType) usize {
    const m = wire.Message.parse(bytes) catch return 0;
    var n: usize = 0;
    var it = m.allRecords();
    while (it.next()) |rec| if (rec.rtype == rtype and rec.name.eql(&name)) {
        n += 1;
    };
    return n;
}

fn questionIn(bytes: []const u8, name: Name, qtype: wire.RType) bool {
    const m = wire.Message.parse(bytes) catch return false;
    var it = m.questions();
    while (it.next()) |q| if (q.qtype == qtype and q.name.eql(&name)) return true;
    return false;
}

fn queryBytes(bytes: []const u8) bool {
    const m = wire.Message.parse(bytes) catch return false;
    return !m.isResponse();
}

/// One datagram the Engine emitted.
const Sent = struct {
    now_us: u64,
    ifindex: u32,
    to: Io.net.IpAddress,
    bytes: []u8,

    fn multicast(s: *const Sent) bool {
        return fake_lan.isMulticastAddr(s.to);
    }

    fn msg(s: *const Sent) !wire.Message {
        return wire.Message.parse(s.bytes);
    }

    fn isQuery(s: *const Sent) bool {
        return queryBytes(s.bytes);
    }

    /// First record with that name and type in `section`, or null.
    fn find(s: *const Sent, section: wire.Section, name: Name, rtype: wire.RType) ?wire.Record {
        return recIn(s.bytes, section, name, rtype);
    }

    fn countRecords(s: *const Sent, name: Name, rtype: wire.RType) usize {
        return countIn(s.bytes, name, rtype);
    }

    fn hasQuestion(s: *const Sent, name: Name, qtype: wire.RType) bool {
        return questionIn(s.bytes, name, qtype);
    }
};

/// One engine on ifindex 3 (10.0.3.1/24 + fe80::1/64) and ifindex 4
/// (10.0.4.1/24, v4 only), every family with an address joined, with
/// `interfaces_changed` already drained, and a log of every datagram it
/// emits.
const Rig = struct {
    sc: Scenario,
    e: Engine,
    sink: Sink,
    log: std.ArrayList(Sent) = .empty,

    const Options = struct {
        first_binder: bool = true,
        two_ifaces: bool = true,
        seed: u64 = 0x4d34,
    };

    fn init(opts: Options) !*Rig {
        const r = try testing.allocator.create(Rig);
        errdefer testing.allocator.destroy(r);
        r.* = .{ .sc = .init(opts.seed), .e = undefined, .sink = .init(testing.allocator) };
        r.e = try Engine.init(testing.allocator, .{
            .host_label = host_label,
            .random = r.sc.random(),
            .limits = .{ .max_interfaces = 4, .max_events = 32 },
            .qu_allowed = opts.first_binder,
            .first_binder = opts.first_binder,
        });
        errdefer r.e.deinit();
        if (opts.two_ifaces) {
            try r.e.setInterfaces(&.{ fake_lan.ifaceDual(3, "en0", .{ 10, 0, 3, 1 }, 24, 1), fake_lan.iface4(4, "en1", .{ 10, 0, 4, 1 }, 24) }, 0);
        } else {
            try r.e.setInterfaces(&.{fake_lan.ifaceDual(3, "en0", .{ 10, 0, 3, 1 }, 24, 1)}, 0);
        }
        _ = try r.sink.drain(&r.e);
        r.sink.clear();
        return r;
    }

    fn deinit(r: *Rig) void {
        r.clearLog();
        r.log.deinit(testing.allocator);
        r.sink.deinit();
        r.e.deinit();
        testing.allocator.destroy(r);
    }

    fn now(r: *const Rig) u64 {
        return r.sc.nowUs();
    }

    fn clearLog(r: *Rig) void {
        for (r.log.items) |s| testing.allocator.free(s.bytes);
        r.log.clearRetainingCapacity();
    }

    /// Drain `pollDatagram` at the current clock into the log.
    fn drain(r: *Rig) !void {
        var buf: [9000]u8 = undefined;
        while (r.e.pollDatagram(&buf, r.now())) |d| {
            const copy = try testing.allocator.dupe(u8, buf[0..d.len]);
            try r.log.append(testing.allocator, .{ .now_us = r.now(), .ifindex = d.ifindex, .to = d.to, .bytes = copy });
        }
        _ = try r.sink.drain(&r.e);
    }

    /// Tick at the current clock and drain.
    fn tick(r: *Rig) !void {
        r.e.tick(r.now());
        try r.drain();
    }

    /// Advance to `t`, ticking at every deadline on the way and at `t`.
    fn runTo(r: *Rig, t: u64) !void {
        while (r.e.nextDeadline(r.now())) |d| {
            if (d > t) break;
            r.sc.set(@max(d, r.now()));
            try r.tick();
        }
        r.sc.set(@max(t, r.now()));
        try r.tick();
    }

    fn advance(r: *Rig, us: u64) !void {
        try r.runTo(r.now() + us);
    }

    /// Run deadline by deadline until `registered` fires; the clock then
    /// sits at the second announcement.
    fn runUntilRegistered(r: *Rig) !void {
        var guard: usize = 0;
        while (r.sink.count(.registered) == 0) : (guard += 1) {
            try testing.expect(guard < 64);
            const d = r.e.nextDeadline(r.now()) orelse return error.TestUnexpectedResult;
            try r.runTo(d);
        }
    }

    fn rx(r: *Rig, bytes: []const u8, from: Io.net.IpAddress, ifindex: u32) !void {
        r.e.handle(bytes, .{ .from = from, .ifindex = ifindex, .dst_multicast = true }, r.now());
        _ = try r.sink.drain(&r.e);
    }

    fn rxUnicast(r: *Rig, bytes: []const u8, from: Io.net.IpAddress, ifindex: u32) !void {
        r.e.handle(bytes, .{ .from = from, .ifindex = ifindex, .dst_multicast = false }, r.now());
        _ = try r.sink.drain(&r.e);
    }

    /// Advertise the default instance and run until it is registered.
    fn establish(r: *Rig) !mdns.RegId {
        const id = try r.e.advertise(.{ .service_type = svc_type, .instance = inst, .port = port, .txt = &.{.{ .key = "txtvers", .value = "1" }} }, r.now());
        try r.advance(3 * s_us);
        try r.sink.expectCount(.registered, 1);
        r.sink.clear();
        r.clearLog();
        return id;
    }

    fn queries(r: *const Rig) usize {
        var n: usize = 0;
        for (r.log.items) |*s| if (s.isQuery()) {
            n += 1;
        };
        return n;
    }

    fn responses(r: *const Rig) usize {
        return r.log.items.len - r.queries();
    }

    fn onIface(r: *const Rig, ifindex: u32) usize {
        var n: usize = 0;
        for (r.log.items) |*s| if (s.ifindex == ifindex) {
            n += 1;
        };
        return n;
    }
};

fn instName() Name {
    return packets.instanceName(inst, svc_type);
}

fn typeName() Name {
    return packets.typeName(svc_type);
}

fn hostName() Name {
    return packets.hostName(host_label);
}

/// A foreign response carrying our instance's SRV with `their_port`.
fn conflictingSrv(buf: []u8, their_port: u16) ![]const u8 {
    return conflictingSrvFor(buf, instName(), their_port);
}

/// The same for an arbitrary (renamed) instance name.
fn conflictingSrvFor(buf: []u8, name: Name, their_port: u16) ![]const u8 {
    var p: Packet = .response(buf);
    try p.b.addRR(.answer, name, .srv, wire.class_in, true, 120, .{ .srv = .{ .port = their_port, .target = packets.hostName("other") } });
    return p.bytes();
}

/// A foreign probe for our instance name with an SRV of `their_port`
/// and an empty TXT in the Authority section (what a DNS-SD prober
/// proposes; the section 8.2 comparison walks the sorted sets, so a
/// set without the TXT would lose to ours on the first record's type).
fn foreignProbe(buf: []u8, their_port: u16, qu: bool) ![]const u8 {
    var p: Packet = .query(buf);
    try p.question(instName(), .any, qu);
    p.in(.authority);
    try p.srv(inst, svc_type, their_port, "other", 120, false);
    try p.txt(inst, svc_type, &.{}, 4500, false);
    return p.bytes();
}

fn simpleQuery(buf: []u8, name: Name, qtype: wire.RType, qu: bool) ![]const u8 {
    var p: Packet = .query(buf);
    try p.question(name, qtype, qu);
    return p.bytes();
}

test "probe timing" {
    const r = try Rig.init(.{});
    defer r.deinit();
    const id = try r.e.advertise(.{ .service_type = svc_type, .instance = inst, .port = port, .txt = &.{.{ .key = "k", .value = "v" }} }, 0);
    // First probe 0-250 ms after advertise (section 8.1).
    const first = r.e.nextDeadline(0).?;
    try testing.expect(first <= timers.probe_first_delay_max_us);
    try testing.expectEqual(@as(usize, 0), r.log.items.len);

    // Three probes 250 ms apart on each of the three joined pairs
    // (3/v4, 3/v6, 4/v4).
    try r.runTo(first);
    try testing.expectEqual(@as(usize, 3), r.log.items.len);
    for (r.log.items) |*s| {
        try testing.expect(s.isQuery());
        try testing.expect(s.multicast());
        const m = try s.msg();
        try testing.expectEqual(@as(u16, 0), m.header.id);
        try testing.expect(s.hasQuestion(instName(), .any));
        try testing.expect(s.hasQuestion(hostName(), .any));
        var qs = m.questions();
        while (qs.next()) |q| try testing.expect(q.qu); // first binder
        // Proposed records in Authority, never cache-flush there.
        const srv = s.find(.authority, instName(), .srv).?;
        try testing.expect(!srv.cache_flush);
        try testing.expectEqual(@as(u32, 120), srv.ttl);
        try testing.expect(s.find(.authority, instName(), .txt) != null);
        try testing.expect(s.find(.authority, hostName(), .a) != null);
        try testing.expectEqual(@as(u16, 0), m.header.ancount);
        if (s.ifindex == 3) {
            try testing.expect(s.find(.authority, hostName(), .aaaa) != null);
        } else {
            try testing.expect(s.find(.authority, hostName(), .aaaa) == null);
        }
    }
    try testing.expectEqual(@as(?u64, first + timers.probe_interval_us), r.e.nextDeadline(first));
    try r.runTo(first + timers.probe_interval_us);
    try testing.expectEqual(@as(usize, 6), r.log.items.len);
    try r.runTo(first + 2 * timers.probe_interval_us);
    try testing.expectEqual(@as(usize, 9), r.log.items.len);
    try testing.expectEqual(@as(usize, 9), r.queries());
    try r.sink.expectCount(.registered, 0);

    // Announce 250 ms after the last probe, again 1 s later; then
    // `registered`; then silence.
    const ann1 = first + 3 * timers.probe_interval_us;
    try testing.expectEqual(@as(?u64, ann1), r.e.nextDeadline(r.now()));
    try r.runTo(ann1);
    try testing.expectEqual(@as(usize, 12), r.log.items.len);
    for (r.log.items[9..12]) |*s| {
        try testing.expect(!s.isQuery());
        try testing.expect(s.find(.answer, instName(), .srv).?.cache_flush);
        try testing.expect(s.find(.answer, instName(), .txt).?.cache_flush);
        try testing.expect(!s.find(.answer, typeName(), .ptr).?.cache_flush);
        try testing.expect(s.find(.answer, hostName(), .a).?.cache_flush);
    }
    try r.sink.expectCount(.registered, 0);
    try testing.expectEqual(@as(?u64, ann1 + timers.announce_interval_us), r.e.nextDeadline(r.now()));
    try r.runTo(ann1 + timers.announce_interval_us);
    try testing.expectEqual(@as(usize, 15), r.log.items.len);
    try r.sink.expectCount(.registered, 1);
    const reg = r.sink.first(.registered).?.registered;
    try testing.expectEqual(id, reg.id);
    try testing.expect(reg.instance.eql(&instName()));
    try testing.expectEqual(null, r.e.nextDeadline(r.now()));
    try r.advance(60 * s_us);
    try testing.expectEqual(@as(usize, 15), r.log.items.len);
    try testing.expectEqual(@as(usize, 1), r.e.registrationCount());

    // Section 6: a unique record answers at once, a shared one after
    // 20-120 ms.
    r.clearLog();
    try r.advance(2 * s_us);
    var qb: [512]u8 = undefined;
    try r.rx(try simpleQuery(&qb, instName(), .srv, false), foreign4, 3);
    try testing.expectEqual(@as(?u64, r.now()), r.e.nextDeadline(r.now()));
    try r.drain();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expect(r.log.items[0].find(.answer, instName(), .srv) != null);
    try testing.expectEqual(@as(u32, 3), r.log.items[0].ifindex);
    r.clearLog();
    try r.advance(2 * s_us);
    const t0 = r.now();
    try r.rx(try simpleQuery(&qb, typeName(), .ptr, false), foreign4, 3);
    const due = r.e.nextDeadline(t0).?;
    try testing.expect(due - t0 >= timers.answer_delay_min_us and due - t0 <= timers.answer_delay_max_us);
    try r.drain();
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
    try r.runTo(due);
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    const ans = &r.log.items[0];
    try testing.expect(ans.find(.answer, typeName(), .ptr) != null);
    // RFC 6763 section 12.1 additionals.
    try testing.expect(ans.find(.additional, instName(), .srv) != null);
    try testing.expect(ans.find(.additional, instName(), .txt) != null);
    try testing.expect(ans.find(.additional, hostName(), .a) != null);

    // Ten thousand seeds (plan section 8, tier 1: "timing tests run 10 k
    // seeded iterations"), one engine on one v4 pair, reseeded and
    // re-advertised ten seconds apart (the goodbye of the previous round
    // drained first): the first probe lands in [0, 250] ms after the
    // advertise, the next two follow 250 ms apart, the first announcement
    // comes 250 ms after the third probe (section 8.1: "if, by 250 ms
    // after the third probe, no conflicting ... responses have been
    // received, the host may move to the next step") and the second one
    // second later (section 8.3). Five datagrams, then nothing; the draw
    // spans the range.
    var sc: Scenario = .init(0);
    var e = try Engine.init(testing.allocator, .{
        .host_label = host_label,
        .random = sc.random(),
        .limits = .{ .max_cache_records = 8, .max_events = 4, .max_interfaces = 1, .max_browses = 1, .max_registrations = 1, .max_pending_answers = 1 },
    });
    defer e.deinit();
    try e.setInterfaces(&.{fake_lan.iface4(3, "en0", .{ 10, 0, 3, 1 }, 24)}, 0);
    while (e.pollEvent()) |_| {}
    var min_first: u64 = std.math.maxInt(u64);
    var max_first: u64 = 0;
    var seed: u64 = 0;
    var buf: [1500]u8 = undefined;
    while (seed < 10_000) : (seed += 1) {
        sc.reseed(seed);
        const base = seed * 10 * s_us;
        const rid = try e.advertise(.{ .service_type = svc_type, .instance = inst, .port = port }, base);
        var times: [8]u64 = undefined;
        var n: usize = 0;
        var t: u64 = base;
        var guard: usize = 0;
        while (e.nextDeadline(t)) |d| : (guard += 1) {
            try testing.expect(guard < 16);
            try testing.expect(d >= t);
            t = d;
            e.tick(t);
            while (e.pollDatagram(&buf, t)) |dg| {
                try testing.expect(n < times.len);
                times[n] = t - base;
                n += 1;
                const m = try wire.Message.parse(buf[0..dg.len]);
                try testing.expectEqual(n <= timers.probe_count, !m.isResponse());
            }
            while (e.pollEvent()) |_| {}
        }
        try testing.expectEqual(@as(usize, timers.probe_count + timers.announce_count), n);
        try testing.expect(times[0] >= timers.probe_first_delay_min_us and times[0] <= timers.probe_first_delay_max_us);
        try testing.expectEqual(times[0] + timers.probe_interval_us, times[1]);
        try testing.expectEqual(times[1] + timers.probe_interval_us, times[2]);
        try testing.expectEqual(times[2] + timers.probe_interval_us, times[3]);
        try testing.expectEqual(times[3] + timers.announce_interval_us, times[4]);
        min_first = @min(min_first, times[0]);
        max_first = @max(max_first, times[0]);
        e.withdraw(rid, t);
        var goodbyes: usize = 0;
        while (e.pollDatagram(&buf, t)) |_| goodbyes += 1;
        try testing.expectEqual(@as(usize, 1), goodbyes);
        while (e.pollEvent()) |_| {}
        try testing.expectEqual(null, e.nextDeadline(t));
    }
    try testing.expect(min_first < 25 * ms_us);
    try testing.expect(max_first > 225 * ms_us);
}

test "tie-break loser waits 1s" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.e.advertise(.{ .service_type = svc_type, .instance = inst, .port = port }, 0);
    const first = r.e.nextDeadline(0).?;
    try r.runTo(first);
    try testing.expectEqual(@as(usize, 3), r.log.items.len);
    r.clearLog();

    // A peer probes the same name with a higher SRV rdata (port 9999 >
    // 4433): we lose and wait one second before probing that name again.
    // The host's own probes are unaffected and keep their schedule.
    const t_loss = r.now();
    var pb: [512]u8 = undefined;
    try r.rx(try foreignProbe(&pb, 9999, true), foreign4, 3);
    try r.sink.expectCount(.renamed, 0);
    try r.advance(timers.probe_tiebreak_wait_us - 1);
    for (r.log.items) |*s| try testing.expect(!s.hasQuestion(instName(), .any));
    r.clearLog();
    try r.advance(1);
    try testing.expectEqual(@as(usize, 3), r.log.items.len);
    try testing.expectEqual(t_loss + timers.probe_tiebreak_wait_us, r.log.items[0].now_us);
    try testing.expect(r.log.items[0].hasQuestion(instName(), .any));
    r.clearLog();

    // A lower rdata (port 1) is our win: the schedule is untouched.
    const before = r.e.nextDeadline(r.now()).?;
    try r.rx(try foreignProbe(&pb, 1, true), foreign4, 3);
    try testing.expectEqual(@as(?u64, before), r.e.nextDeadline(r.now()));
    try r.sink.expectCount(.renamed, 0);

    // A second loss renames (plan M4) and the new name is probed.
    try r.rx(try foreignProbe(&pb, 9999, true), foreign4, 3);
    try r.sink.expectCount(.renamed, 1);
    const ev = r.sink.first(.renamed).?.renamed;
    try testing.expect(ev.old.eql(&instName()));
    try testing.expect(ev.new.eql(&packets.instanceName("demo (2)", svc_type)));
    try r.advance(3 * s_us);
    try testing.expect(r.log.items[0].hasQuestion(packets.instanceName("demo (2)", svc_type), .any));
    try r.sink.expectCount(.registered, 1);
    try testing.expect(r.sink.first(.registered).?.registered.instance.eql(&packets.instanceName("demo (2)", svc_type)));
}

test "identical rdata is not a conflict" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.establish();
    var buf: [1500]u8 = undefined;
    var p: Packet = .response(&buf);
    try p.srv(inst, svc_type, port, host_label, 120, true);
    try p.txt(inst, svc_type, &.{.{ .key = "txtvers", .value = "1" }}, 4500, true);
    try p.a(host_label, .{ 10, 0, 3, 1 }, 120, true);
    try r.rx(p.bytes(), foreign4, 3);
    try testing.expectEqual(@as(u64, 0), r.e.stats().conflicts);
    try r.advance(3 * s_us);
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
    try testing.expectEqual(@as(usize, 0), r.sink.len());
    // A goodbye for our name (TTL 0) is not a conflict either.
    var gb: [512]u8 = undefined;
    var g: Packet = .response(&gb);
    try g.srv(inst, svc_type, 1, "other", 0, true);
    try r.rx(g.bytes(), foreign4, 3);
    try testing.expectEqual(@as(u64, 0), r.e.stats().conflicts);
}

test "own echo via loopback never defends renames or flushes" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.e.advertise(.{ .service_type = svc_type, .instance = inst, .port = port }, 0);
    try r.advance(3 * s_us);
    try r.sink.expectCount(.registered, 1);
    // Every probe and announcement comes back from our own address on
    // its own interface: recognised as an echo, processed no further.
    const sent = r.log.items.len;
    for (r.log.items) |*s| {
        const from: Io.net.IpAddress = if (s.ifindex == 3) own4 else .{ .ip4 = .{ .bytes = .{ 10, 0, 4, 1 }, .port = 5353 } };
        r.e.handle(s.bytes, .{ .from = from, .ifindex = s.ifindex, .dst_multicast = true }, s.now_us + 100);
    }
    try testing.expectEqual(@as(u64, sent), r.e.stats().rx_echo);
    try testing.expectEqual(@as(u64, 0), r.e.stats().conflicts);
    _ = try r.sink.drain(&r.e);
    try r.sink.expectCount(.renamed, 0);
    try r.sink.expectCount(.host_renamed, 0);
    try r.advance(3 * s_us);
    try testing.expectEqual(@as(usize, sent), r.log.items.len);
    try testing.expectEqual(@as(usize, 0), r.e.cacheCount());
}

test "same-IP different rdata is a conflict" {
    const r = try Rig.init(.{});
    defer r.deinit();
    const id = try r.establish();
    var buf: [512]u8 = undefined;
    // Another stack on our own IP announces our instance with another
    // port: not an echo (the bytes were never ours), a real conflict.
    try r.rx(try conflictingSrv(&buf, 9999), own4, 3);
    try testing.expectEqual(@as(u64, 0), r.e.stats().rx_echo);
    try testing.expectEqual(@as(u64, 1), r.e.stats().conflicts);
    try testing.expectEqual(mdns.core.responder.State.probing, r.e.responder.regState(id).?);
    try r.sink.expectCount(.renamed, 0);
}

test "conflict after announce re-probes before renaming" {
    const r = try Rig.init(.{});
    defer r.deinit();
    const id = try r.establish();
    var buf: [512]u8 = undefined;
    try r.rx(try conflictingSrv(&buf, 9999), foreign4, 3);
    try testing.expectEqual(@as(u64, 1), r.e.stats().conflicts);
    // The next packets are probes for the SAME name (section 9).
    const next = r.e.nextDeadline(r.now()).?;
    try testing.expect(next - r.now() <= timers.probe_first_delay_max_us);
    try r.runTo(next);
    try testing.expect(r.log.items.len >= 1);
    try testing.expect(r.log.items[0].isQuery());
    try testing.expect(r.log.items[0].hasQuestion(instName(), .any));
    try r.sink.expectCount(.renamed, 0);
    try testing.expectEqual(mdns.core.responder.State.probing, r.e.responder.regState(id).?);
    // Nobody objects: the same name is announced again and registered.
    try r.advance(3 * s_us);
    try r.sink.expectCount(.renamed, 0);
    try r.sink.expectCount(.registered, 1);
    try testing.expect(r.sink.first(.registered).?.registered.instance.eql(&instName()));
}

test "probe failure after conflict renames" {
    const r = try Rig.init(.{});
    defer r.deinit();
    const id = try r.establish();
    var buf: [512]u8 = undefined;
    try r.rx(try conflictingSrv(&buf, 9999), foreign4, 3);
    const next = r.e.nextDeadline(r.now()).?;
    try r.runTo(next);
    r.clearLog();
    // The other host defends while we re-probe: the probe failed, rename.
    try r.rx(try conflictingSrv(&buf, 9999), foreign4, 3);
    try testing.expectEqual(@as(u64, 2), r.e.stats().conflicts);
    try r.sink.expectCount(.renamed, 1);
    const ev = r.sink.first(.renamed).?.renamed;
    try testing.expectEqual(id, ev.id);
    try testing.expect(ev.old.eql(&instName()));
    const renamed = packets.instanceName("demo (2)", svc_type);
    try testing.expect(ev.new.eql(&renamed));
    try testing.expect(r.e.responder.instanceName(id).?.eql(&renamed));
    try r.advance(3 * s_us);
    try testing.expect(r.log.items[0].isQuery());
    try testing.expect(r.log.items[0].hasQuestion(renamed, .any));
    try testing.expect(!r.log.items[0].hasQuestion(instName(), .any));
    try r.sink.expectCount(.registered, 1);
    // The announcement carries the new name's SRV and PTR.
    const last = &r.log.items[r.log.items.len - 1];
    try testing.expect(!last.isQuery());
    try testing.expect(last.find(.answer, renamed, .srv) != null);
    try testing.expect(last.countRecords(instName(), .srv) == 0);
}

test "host rename to label-2 re-announces SRV" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.establish();
    var buf: [512]u8 = undefined;
    var p: Packet = .response(&buf);
    try p.a(host_label, .{ 10, 9, 9, 9 }, 120, true);
    try r.rx(p.bytes(), foreign4, 3);
    try testing.expectEqual(@as(u64, 1), r.e.stats().conflicts);
    try testing.expectEqual(mdns.core.responder.State.probing, r.e.responder.hostState());
    try r.sink.expectCount(.host_renamed, 0);
    const next = r.e.nextDeadline(r.now()).?;
    try r.runTo(next);
    try testing.expect(r.log.items[0].hasQuestion(hostName(), .any));
    r.clearLog();
    // Defended during the re-probe: the host is renamed `unit-2`.
    try r.rx(p.bytes(), foreign4, 3);
    try r.sink.expectCount(.host_renamed, 1);
    const ev = r.sink.first(.host_renamed).?.host_renamed;
    try testing.expect(ev.old.eql(&hostName()));
    const new_host = packets.hostName("unit-2");
    try testing.expect(ev.new.eql(&new_host));
    try testing.expect(r.e.hostName().eql(&new_host));
    try r.advance(3 * s_us);
    // Probes name the new host; the announcements re-announce every SRV
    // with the new target and cache-flush (section 8.4).
    try testing.expect(r.log.items[0].isQuery());
    try testing.expect(r.log.items[0].hasQuestion(new_host, .any));
    var announced_srv = false;
    var announced_a = false;
    for (r.log.items) |*s| {
        if (s.isQuery()) continue;
        if (s.find(.answer, instName(), .srv)) |srv| {
            try testing.expect(srv.cache_flush);
            const decoded = try wire.rdata.decodeSrv(s.bytes, srv);
            try testing.expect(decoded.target.eql(&new_host));
            announced_srv = true;
        }
        if (s.find(.answer, new_host, .a)) |a| {
            try testing.expect(a.cache_flush);
            announced_a = true;
        }
        try testing.expect(s.countRecords(hostName(), .a) == 0);
    }
    try testing.expect(announced_srv);
    try testing.expect(announced_a);
    // The instance itself was not renamed.
    try r.sink.expectCount(.renamed, 0);
}

test "fifteen conflicts trigger backoff" {
    const r = try Rig.init(.{});
    defer r.deinit();
    const id = try r.establish();
    var buf: [512]u8 = undefined;
    var i: u32 = 0;
    while (i < timers.conflict_backoff_count - 1) : (i += 1) {
        // Every conflict while probing renames: hit the current name.
        try r.rx(try conflictingSrvFor(&buf, r.e.responder.instanceName(id).?, 9999), foreign4, 3);
        // Well inside the ten-second window.
        try r.advance(100 * ms_us);
        // Still the ordinary 0-250 ms probe schedule.
        const d = r.e.nextDeadline(r.now()) orelse r.now();
        try testing.expect(d - r.now() <= timers.probe_first_delay_max_us);
    }
    try testing.expectEqual(@as(u64, timers.conflict_backoff_count - 1), r.e.stats().conflicts);
    // The fifteenth within ten seconds: the next probe waits five seconds.
    try r.rx(try conflictingSrvFor(&buf, r.e.responder.instanceName(id).?, 9999), foreign4, 3);
    try testing.expectEqual(@as(u64, timers.conflict_backoff_count), r.e.stats().conflicts);
    const d = r.e.nextDeadline(r.now()).?;
    try testing.expect(d - r.now() >= timers.conflict_backoff_delay_us);
    try testing.expect(d - r.now() <= timers.conflict_backoff_delay_us + timers.probe_first_delay_max_us);
    r.clearLog();
    try r.advance(timers.conflict_backoff_delay_us - 1);
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
}

test "KA at half TTL suppresses" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.establish();
    try r.advance(2 * s_us);
    var buf: [1500]u8 = undefined;
    // PTR (TTL 4500) listed with 2250 s left: suppressed.
    var p: Packet = .query(&buf);
    try p.question(typeName(), .ptr, false);
    try p.ptr(svc_type, inst, timers.ttl_other_s / 2);
    try r.rx(p.bytes(), foreign4, 3);
    try r.advance(s_us);
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
    // One second less: answered.
    var q: Packet = .query(&buf);
    try q.question(typeName(), .ptr, false);
    try q.ptr(svc_type, inst, timers.ttl_other_s / 2 - 1);
    try r.rx(q.bytes(), foreign4, 3);
    try r.advance(s_us);
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expect(r.log.items[0].find(.answer, typeName(), .ptr) != null);
    r.clearLog();
    try r.advance(2 * s_us);
    // The same for a unique record: SRV (TTL 120) listed with 60 s.
    var u: Packet = .query(&buf);
    try u.question(instName(), .srv, false);
    try u.srv(inst, svc_type, port, host_label, timers.ttl_host_s / 2, false);
    try r.rx(u.bytes(), foreign4, 3);
    try r.advance(s_us);
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
    // A KA with different rdata does not suppress.
    var v: Packet = .query(&buf);
    try v.question(instName(), .srv, false);
    try v.srv(inst, svc_type, 1, host_label, timers.ttl_host_s, false);
    try r.rx(v.bytes(), foreign4, 3);
    try r.advance(s_us);
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
}

test "record never multicast twice within 1s per interface except defence" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.e.advertise(.{ .service_type = svc_type, .instance = inst, .port = port }, 0);
    try r.runUntilRegistered();
    // The last announcement multicast the SRV at `t_ann`.
    const t_ann = r.log.items[r.log.items.len - 1].now_us;
    try testing.expectEqual(t_ann, r.now());
    try testing.expect(t_ann <= 2 * s_us);
    r.clearLog();
    r.sc.set(t_ann + 500 * ms_us);
    var buf: [512]u8 = undefined;
    // 500 ms later on ifindex 3: suppressed (the announcement counts).
    try r.rx(try simpleQuery(&buf, instName(), .srv, false), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
    // Exactly one second after: allowed again on ifindex 3.
    r.sc.set(t_ann + s_us);
    try r.rx(try simpleQuery(&buf, instName(), .srv, false), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expectEqual(@as(u32, 3), r.log.items[0].ifindex);
    r.clearLog();
    // 500 ms later: ifindex 3 is throttled by that answer, ifindex 4 is
    // an independent interface whose last multicast was the
    // announcement, so it answers.
    r.sc.set(t_ann + s_us + 500 * ms_us);
    try r.rx(try simpleQuery(&buf, instName(), .srv, false), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
    try r.rx(try simpleQuery(&buf, instName(), .srv, false), .{ .ip4 = .{ .bytes = .{ 10, 0, 4, 9 }, .port = 5353 } }, 4);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expectEqual(@as(u32, 4), r.log.items[0].ifindex);
    r.clearLog();
    r.sc.set(t_ann + 2 * s_us);
    // 200 ms later a probe for our name: defended at once regardless.
    r.sc.set(t_ann + 2 * s_us + 200 * ms_us);
    try r.rx(try foreignProbe(&buf, 9999, false), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expect(r.log.items[0].multicast());
    try testing.expect(r.log.items[0].find(.answer, instName(), .srv).?.cache_flush);
    // And a plain query right after is suppressed again.
    r.clearLog();
    r.sc.set(t_ann + 2 * s_us + 300 * ms_us);
    try r.rx(try simpleQuery(&buf, instName(), .srv, false), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
}

test "A answer contains only the sending interface's kept addresses" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.establish();
    try r.advance(2 * s_us);
    var buf: [512]u8 = undefined;
    try r.rx(try simpleQuery(&buf, hostName(), .a, false), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    const on3 = &r.log.items[0];
    try testing.expectEqual(@as(u32, 3), on3.ifindex);
    try testing.expectEqual(@as(usize, 1), on3.countRecords(hostName(), .a));
    const a3 = try wire.rdata.decodeA(on3.find(.answer, hostName(), .a).?.rdata);
    try testing.expectEqual([4]u8{ 10, 0, 3, 1 }, a3);
    r.clearLog();
    try r.rx(try simpleQuery(&buf, hostName(), .a, false), .{ .ip4 = .{ .bytes = .{ 10, 0, 4, 9 }, .port = 5353 } }, 4);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    const on4 = &r.log.items[0];
    try testing.expectEqual(@as(u32, 4), on4.ifindex);
    const a4 = try wire.rdata.decodeA(on4.find(.answer, hostName(), .a).?.rdata);
    try testing.expectEqual([4]u8{ 10, 0, 4, 1 }, a4);
    try testing.expectEqual(@as(usize, 0), on4.countRecords(hostName(), .aaaa));
    // Announcements too: every packet on ifindex 4 carried only 10.0.4.1.
    r.clearLog();
    try r.e.setInterfaces(&.{ fake_lan.ifaceDual(3, "en0", .{ 10, 0, 3, 1 }, 24, 1), fake_lan.iface4(4, "en1", .{ 10, 0, 4, 1 }, 24), fake_lan.iface4(5, "en2", .{ 10, 0, 5, 1 }, 24) }, r.now());
    try r.advance(2 * s_us);
    for (r.log.items) |*s| {
        try testing.expectEqual(@as(u32, 5), s.ifindex);
        const a5 = try wire.rdata.decodeA(s.find(.answer, hostName(), .a).?.rdata);
        try testing.expectEqual([4]u8{ 10, 0, 5, 1 }, a5);
    }
    try testing.expect(r.log.items.len >= 1);
}

test "NSEC for any absent type under a unique name" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.establish();
    try r.advance(2 * s_us);
    var buf: [512]u8 = undefined;
    // Host name, TXT: NSEC next = host, bitmap A + AAAA (ifindex 3 has both).
    try r.rx(try simpleQuery(&buf, hostName(), .txt, false), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    const n1 = r.log.items[0].find(.answer, hostName(), .nsec).?;
    try testing.expect(n1.cache_flush);
    try testing.expectEqual(timers.ttl_host_s, n1.ttl);
    const d1 = try wire.rdata.decodeNsec(r.log.items[0].bytes, n1);
    try testing.expect(d1.next.eql(&hostName()));
    try testing.expect(d1.has(.a) and d1.has(.aaaa) and !d1.has(.txt));
    r.clearLog();
    // Host name, AAAA on the v4-only interface: NSEC with A only.
    try r.rx(try simpleQuery(&buf, hostName(), .aaaa, false), .{ .ip4 = .{ .bytes = .{ 10, 0, 4, 9 }, .port = 5353 } }, 4);
    try r.tick();
    const n2 = r.log.items[0].find(.answer, hostName(), .nsec).?;
    const d2 = try wire.rdata.decodeNsec(r.log.items[0].bytes, n2);
    try testing.expect(d2.has(.a) and !d2.has(.aaaa));
    try testing.expectEqual(@as(usize, 0), r.log.items[0].countRecords(hostName(), .aaaa));
    r.clearLog();
    // Instance name, A: NSEC with SRV + TXT.
    try r.advance(2 * s_us);
    try r.rx(try simpleQuery(&buf, instName(), .a, false), foreign4, 3);
    try r.tick();
    const n3 = r.log.items[0].find(.answer, instName(), .nsec).?;
    const d3 = try wire.rdata.decodeNsec(r.log.items[0].bytes, n3);
    try testing.expect(d3.next.eql(&instName()));
    try testing.expect(d3.has(.srv) and d3.has(.txt) and !d3.has(.a) and !d3.has(.nsec));
    r.clearLog();
    // HINFO under the instance: also NSEC (any absent type).
    try r.advance(2 * s_us);
    try r.rx(try simpleQuery(&buf, instName(), .hinfo, false), foreign4, 3);
    try r.tick();
    try testing.expect(r.log.items[0].find(.answer, instName(), .nsec) != null);
    r.clearLog();
    // A shared name (the type) with an absent type gets nothing.
    try r.rx(try simpleQuery(&buf, typeName(), .srv, false), foreign4, 3);
    try r.advance(s_us);
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
}

test "legacy reply shape" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.establish();
    try r.advance(2 * s_us);
    var buf: [512]u8 = undefined;
    var b: wire.Builder = .init(&buf, .{});
    b.setId(0x1234);
    try b.addQuestion(instName(), .srv, wire.class_in, false);
    const legacy_from: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 9 }, .port = 40000 } };
    try r.rx(b.finish(), legacy_from, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    const s = &r.log.items[0];
    // Unicast to the source port, ID echoed, the question repeated.
    try testing.expect(!s.multicast());
    try testing.expectEqual(legacy_from, s.to);
    try testing.expectEqual(@as(u32, 3), s.ifindex);
    const m = try s.msg();
    try testing.expectEqual(@as(u16, 0x1234), m.header.id);
    try testing.expect(m.header.flags.qr and m.header.flags.aa);
    try testing.expectEqual(@as(u16, 1), m.header.qdcount);
    try testing.expect(s.hasQuestion(instName(), .srv));
    // TTL capped at 10, no cache-flush, SRV target uncompressed.
    const srv = s.find(.answer, instName(), .srv).?;
    try testing.expect(srv.ttl <= timers.ttl_legacy_cap_s);
    try testing.expect(!srv.cache_flush);
    try testing.expect(srv.rdata[6] < 0xC0);
    const decoded = try wire.rdata.decodeSrv(s.bytes, srv);
    try testing.expectEqual(port, decoded.port);
    var it = m.allRecords();
    while (it.next()) |rec| {
        try testing.expect(rec.ttl <= timers.ttl_legacy_cap_s);
        try testing.expect(!rec.cache_flush);
    }
    // RFC 6763 section 12.2: the A record rides along.
    try testing.expect(s.find(.additional, hostName(), .a) != null);
    // Not multicast: the one-second rule is untouched by it, and a
    // second legacy query right away is answered too.
    r.clearLog();
    try r.rx(b.finish(), legacy_from, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
}

test "QU reply multicast when not multicast within TTL/4" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.e.advertise(.{ .service_type = svc_type, .instance = inst, .port = port }, 0);
    try r.runUntilRegistered();
    const t_ann = r.log.items[r.log.items.len - 1].now_us;
    r.clearLog();
    var buf: [512]u8 = undefined;
    // 2 s after the announcement: multicast recently, so unicast.
    r.sc.set(t_ann + 2 * s_us);
    try r.rx(try simpleQuery(&buf, instName(), .srv, true), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expect(!r.log.items[0].multicast());
    try testing.expectEqual(foreign4, r.log.items[0].to);
    try testing.expect(r.log.items[0].find(.answer, instName(), .srv).?.cache_flush);
    r.clearLog();
    // 31 s after (> 120 / 4): not multicast within TTL/4, so multicast.
    r.sc.set(t_ann + 31 * s_us);
    try r.rx(try simpleQuery(&buf, instName(), .srv, true), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expect(r.log.items[0].multicast());
    r.clearLog();
    // Which resets the clock: unicast again right after.
    r.sc.set(t_ann + 32 * s_us);
    try r.rx(try simpleQuery(&buf, instName(), .srv, true), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expect(!r.log.items[0].multicast());
}

test "same-host probe is defended by multicast" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.establish();
    try r.advance(2 * s_us);
    var buf: [512]u8 = undefined;
    // `dns-sd -R` on this host probes our name with QU from our own IP.
    try r.rx(try foreignProbe(&buf, 9999, true), own4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 2), r.log.items.len);
    var mc: usize = 0;
    var uc: usize = 0;
    for (r.log.items) |*s| {
        try testing.expect(s.find(.answer, instName(), .srv) != null);
        try testing.expect(s.find(.answer, instName(), .txt) != null);
        if (s.multicast()) {
            mc += 1;
        } else {
            uc += 1;
            try testing.expectEqual(own4, s.to);
        }
    }
    try testing.expectEqual(@as(usize, 1), mc);
    try testing.expectEqual(@as(usize, 1), uc);
    // A foreign QU probe right after the announcement gets a unicast
    // defence only (section 5.4 applies).
    r.clearLog();
    try r.rx(try foreignProbe(&buf, 9999, true), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expect(!r.log.items[0].multicast());
    // Our records were never touched by any of it.
    try testing.expectEqual(@as(u64, 0), r.e.stats().conflicts);
    try r.sink.expectCount(.renamed, 0);
}

test "shared port probe is defended by multicast" {
    const r = try Rig.init(.{ .first_binder = false });
    defer r.deinit();
    _ = try r.e.advertise(.{ .service_type = svc_type, .instance = inst, .port = port }, 0);
    try r.advance(3 * s_us);
    // Probes over a shared port never set QU.
    for (r.log.items) |*s| if (s.isQuery()) {
        const m = try s.msg();
        var qs = m.questions();
        while (qs.next()) |q| try testing.expect(!q.qu);
    };
    r.clearLog();
    try r.advance(2 * s_us);
    var buf: [512]u8 = undefined;
    try r.rx(try foreignProbe(&buf, 9999, true), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 2), r.log.items.len);
    var mc: usize = 0;
    for (r.log.items) |*s| if (s.multicast()) {
        mc += 1;
    };
    try testing.expectEqual(@as(usize, 1), mc);
}

test "bridged echo re-announces address records" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.e.advertise(.{ .service_type = svc_type, .instance = inst, .port = port }, 0);
    try r.runUntilRegistered();
    // The last announcement sent on ifindex 3 (cache-flush A 10.0.3.1),
    // copied out of the log before it is cleared.
    var ann3: ?Sent = null;
    for (r.log.items) |s| if (!s.isQuery() and s.ifindex == 3 and s.to == .ip4) {
        ann3 = s;
    };
    var echo_buf: [1500]u8 = undefined;
    var echo = ann3.?;
    @memcpy(echo_buf[0..echo.bytes.len], echo.bytes);
    echo.bytes = echo_buf[0..echo.bytes.len];
    try testing.expect(echo.find(.answer, hostName(), .a).?.cache_flush);
    const t_ann = echo.now_us;
    r.clearLog();
    r.sink.clear();

    // It arrives on ifindex 4 from our own 10.0.3.1 100 ms later: a
    // bridged echo, not a conflict. Ifindex 4 announced its own
    // addresses at `t_ann` too, so every peer on the bridged link holds
    // both sets inside the section 10.2 one-second grace: nothing to
    // re-announce, and no deferred re-announce either (that would arrive
    // after the grace, flush the other set and echo back, once a second,
    // forever).
    r.sc.set(t_ann + 100 * ms_us);
    r.e.handle(echo.bytes, .{ .from = own4, .ifindex = 4, .dst_multicast = true }, r.now());
    try testing.expectEqual(@as(u64, 1), r.e.stats().rx_echo_bridged);
    try testing.expectEqual(@as(u64, 0), r.e.stats().conflicts);
    _ = try r.sink.drain(&r.e);
    try r.sink.expectCount(.host_renamed, 0);
    try testing.expectEqual(null, r.e.nextDeadline(r.now()));
    try r.advance(500 * ms_us);
    try testing.expectEqual(@as(usize, 0), r.log.items.len);

    // The same echo (still inside the echo ring's window) more than a
    // second after ifindex 4 last multicast its addresses (the
    // wireless-to-wired case of section 10.2 where the two announcements
    // were not simultaneous): re-announced at once, address records
    // only, ifindex 4's own address.
    r.sc.set(t_ann + 1500 * ms_us);
    r.e.handle(echo.bytes, .{ .from = own4, .ifindex = 4, .dst_multicast = true }, r.now());
    try testing.expectEqual(@as(u64, 2), r.e.stats().rx_echo_bridged);
    try testing.expectEqual(@as(u64, 0), r.e.stats().conflicts);
    try testing.expectEqual(@as(?u64, r.now()), r.e.nextDeadline(r.now()));
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    const re = &r.log.items[0];
    try testing.expectEqual(@as(u32, 4), re.ifindex);
    try testing.expect(re.multicast());
    const a = re.find(.answer, hostName(), .a).?;
    try testing.expect(a.cache_flush);
    try testing.expectEqual([4]u8{ 10, 0, 4, 1 }, try wire.rdata.decodeA(a.rdata));
    try testing.expectEqual(@as(usize, 0), re.countRecords(instName(), .srv));
    try testing.expectEqual(@as(usize, 0), re.countRecords(typeName(), .ptr));
    try testing.expectEqual(@as(usize, 0), re.countRecords(instName(), .txt));
    _ = try r.sink.drain(&r.e);
    try r.sink.expectCount(.host_renamed, 0);
    try r.sink.expectCount(.registered, 0);
    // Its own bridged echo back on ifindex 3 flushed ifindex 3's set
    // from the peers (last multicast 1.55 s ago, past the grace): ifindex
    // 3 re-announces its addresses at once on both its pairs. That echo
    // lands on ifindex 4 within a second of ifindex 4's own re-announce
    // and starts nothing: the bounce ends there.
    r.sc.advance(50 * ms_us);
    var re_buf: [1500]u8 = undefined;
    @memcpy(re_buf[0..re.bytes.len], re.bytes);
    const re_bytes = re_buf[0..re.bytes.len];
    r.clearLog();
    r.e.handle(re_bytes, .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 0, 4, 1 }, .port = 5353 } }, .ifindex = 3, .dst_multicast = true }, r.now());
    try testing.expectEqual(@as(u64, 3), r.e.stats().rx_echo_bridged);
    try testing.expectEqual(@as(?u64, r.now()), r.e.nextDeadline(r.now()));
    try r.tick();
    try testing.expectEqual(@as(usize, 2), r.log.items.len);
    for (r.log.items) |*s| {
        try testing.expectEqual(@as(u32, 3), s.ifindex);
        try testing.expectEqual(@as(usize, 0), s.countRecords(instName(), .srv));
        try testing.expectEqual([4]u8{ 10, 0, 3, 1 }, try wire.rdata.decodeA(s.find(.answer, hostName(), .a).?.rdata));
    }
    r.sc.advance(50 * ms_us);
    r.e.handle(r.log.items[0].bytes, .{ .from = own4, .ifindex = 4, .dst_multicast = true }, r.now());
    try testing.expectEqual(@as(u64, 4), r.e.stats().rx_echo_bridged);
    try testing.expectEqual(null, r.e.nextDeadline(r.now()));
    try r.advance(5 * s_us);
    try testing.expectEqual(@as(usize, 2), r.log.items.len);
    try testing.expectEqual(@as(u64, 0), r.e.stats().conflicts);
    _ = try r.sink.drain(&r.e);
    try testing.expectEqual(@as(usize, 0), r.sink.len());
}

test "SRV TTL is 120 and PTR TTL is 4500" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.e.advertise(.{ .service_type = svc_type, .instance = inst, .port = port, .txt = &.{.{ .key = "a", .value = "b" }} }, 0);
    try r.advance(3 * s_us);
    var checked = false;
    for (r.log.items) |*s| {
        if (s.isQuery()) continue;
        const srv = s.find(.answer, instName(), .srv).?;
        try testing.expectEqual(@as(u32, 120), srv.ttl);
        try testing.expect(srv.cache_flush);
        const ptr = s.find(.answer, typeName(), .ptr).?;
        try testing.expectEqual(@as(u32, 4500), ptr.ttl);
        try testing.expect(!ptr.cache_flush);
        const txt = s.find(.answer, instName(), .txt).?;
        try testing.expectEqual(@as(u32, 4500), txt.ttl);
        try testing.expect(txt.cache_flush);
        const a = s.find(.answer, hostName(), .a).?;
        try testing.expectEqual(@as(u32, 120), a.ttl);
        try testing.expect(a.cache_flush);
        if (s.find(.answer, hostName(), .aaaa)) |aaaa| try testing.expectEqual(@as(u32, 120), aaaa.ttl);
        checked = true;
    }
    try testing.expect(checked);
}

test "updateTxt re-announces twice with cache-flush and never probes" {
    const r = try Rig.init(.{});
    defer r.deinit();
    const id = try r.establish();
    try r.advance(2 * s_us);
    const t0 = r.now();
    try r.e.updateTxt(id, &.{.{ .key = "seq", .value = "1" }}, t0);
    try testing.expectEqual(@as(?u64, t0), r.e.nextDeadline(t0));
    try r.tick();
    // One packet per joined pair, TXT only, cache-flush, the new rdata.
    try testing.expectEqual(@as(usize, 3), r.log.items.len);
    const want = try wire.Txt.build(&.{.{ .key = "seq", .value = "1" }});
    for (r.log.items) |*s| {
        try testing.expect(!s.isQuery());
        const txt = s.find(.answer, instName(), .txt).?;
        try testing.expect(txt.cache_flush);
        try testing.expectEqualSlices(u8, want.slice(), txt.rdata);
        try testing.expectEqual(@as(usize, 0), s.countRecords(instName(), .srv));
        try testing.expectEqual(@as(usize, 0), s.countRecords(typeName(), .ptr));
    }
    try testing.expectEqual(@as(?u64, t0 + timers.announce_interval_us), r.e.nextDeadline(r.now()));
    try r.runTo(t0 + timers.announce_interval_us);
    try testing.expectEqual(@as(usize, 6), r.log.items.len);
    try testing.expectEqual(@as(usize, 0), r.queries());
    try r.advance(5 * s_us);
    try testing.expectEqual(@as(usize, 6), r.log.items.len);
    try testing.expectEqual(@as(usize, 0), r.sink.len());
    try testing.expect(r.e.responder.txtOf(id).?.eql(&want));
}

test "updateTxt with identical rdata sends nothing" {
    const r = try Rig.init(.{});
    defer r.deinit();
    const id = try r.establish();
    try r.advance(2 * s_us);
    try r.e.updateTxt(id, &.{.{ .key = "txtvers", .value = "1" }}, r.now());
    try testing.expectEqual(null, r.e.nextDeadline(r.now()));
    try r.advance(3 * s_us);
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
    try testing.expectError(error.UnknownRegistration, r.e.updateTxt(@fromBackingInt(@as(u8, 7)), &.{}, r.now()));
}

test "updateTxt during probing waits for the probe" {
    const r = try Rig.init(.{});
    defer r.deinit();
    const id = try r.e.advertise(.{ .service_type = svc_type, .instance = inst, .port = port, .txt = &.{.{ .key = "seq", .value = "0" }} }, 0);
    const first = r.e.nextDeadline(0).?;
    try r.runTo(first);
    try testing.expectEqual(@as(usize, 3), r.queries());
    // Updated mid-probe: no announcement, the probes continue.
    try r.e.updateTxt(id, &.{.{ .key = "seq", .value = "1" }}, r.now());
    try testing.expectEqual(@as(?u64, first + timers.probe_interval_us), r.e.nextDeadline(r.now()));
    try r.runTo(first + 2 * timers.probe_interval_us);
    try testing.expectEqual(@as(usize, 9), r.log.items.len);
    try testing.expectEqual(@as(usize, 0), r.responses());
    // The probes carried the old TXT (the proposed set is unchanged).
    const old = try wire.Txt.build(&.{.{ .key = "seq", .value = "0" }});
    try testing.expectEqualSlices(u8, old.slice(), r.log.items[8].find(.authority, instName(), .txt).?.rdata);
    // The announcements carry the new TXT, and only two of them.
    try r.advance(3 * s_us);
    const new = try wire.Txt.build(&.{.{ .key = "seq", .value = "1" }});
    try testing.expectEqual(@as(usize, 6), r.responses());
    for (r.log.items[9..]) |*s| {
        try testing.expectEqualSlices(u8, new.slice(), s.find(.answer, instName(), .txt).?.rdata);
    }
    try r.sink.expectCount(.registered, 1);
}

test "updateTxt over 400 B is rejected and keeps the old TXT" {
    const r = try Rig.init(.{});
    defer r.deinit();
    const id = try r.establish();
    try r.advance(2 * s_us);
    const big: [253]u8 = @splat('x');
    try testing.expectError(error.TxtTooLarge, r.e.updateTxt(id, &.{ .{ .key = "a", .value = &big }, .{ .key = "b", .value = &big } }, r.now()));
    try testing.expectError(error.InvalidTxt, r.e.updateTxt(id, &.{.{ .key = "" }}, r.now()));
    try testing.expectEqual(null, r.e.nextDeadline(r.now()));
    // A TXT query is answered with the old rdata.
    var buf: [512]u8 = undefined;
    try r.rx(try simpleQuery(&buf, instName(), .txt, false), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    const old = try wire.Txt.build(&.{.{ .key = "txtvers", .value = "1" }});
    try testing.expectEqualSlices(u8, old.slice(), r.log.items[0].find(.answer, instName(), .txt).?.rdata);
    // The same at advertise time.
    try testing.expectError(error.TxtTooLarge, r.e.advertise(.{ .service_type = svc_type, .instance = "big", .port = 1, .txt = &.{ .{ .key = "a", .value = &big }, .{ .key = "b", .value = &big } } }, r.now()));
    try testing.expectEqual(@as(usize, 1), r.e.registrationCount());
}

test "withdraw sends a goodbye with TTL 0 and the host goes with the last registration" {
    const r = try Rig.init(.{});
    defer r.deinit();
    const id = try r.establish();
    const other = try r.e.advertise(.{ .service_type = svc_type, .instance = "second", .port = 1 }, r.now());
    try r.advance(3 * s_us);
    try r.sink.expectCount(.registered, 1);
    r.clearLog();
    r.e.withdraw(id, r.now());
    try testing.expectEqual(@as(?u64, r.now()), r.e.nextDeadline(r.now()));
    try r.drain();
    // One goodbye per pair, only that instance's records, TTL 0, no
    // cache-flush; the host stays (another registration needs it).
    try testing.expectEqual(@as(usize, 3), r.log.items.len);
    for (r.log.items) |*s| {
        try testing.expect(!s.isQuery());
        const srv = s.find(.answer, instName(), .srv).?;
        try testing.expectEqual(@as(u32, 0), srv.ttl);
        try testing.expectEqual(@as(u32, 0), s.find(.answer, typeName(), .ptr).?.ttl);
        try testing.expectEqual(@as(u32, 0), s.find(.answer, instName(), .txt).?.ttl);
        try testing.expectEqual(@as(usize, 0), s.countRecords(hostName(), .a));
        try testing.expectEqual(@as(usize, 0), s.countRecords(packets.instanceName("second", svc_type), .srv));
    }
    try testing.expectEqual(@as(usize, 1), r.e.registrationCount());
    // A query for the withdrawn name is no longer answered.
    r.clearLog();
    try r.advance(2 * s_us);
    var buf: [512]u8 = undefined;
    try r.rx(try simpleQuery(&buf, instName(), .srv, false), foreign4, 3);
    try r.advance(s_us);
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
    // The last one takes the host records with it.
    r.e.withdraw(other, r.now());
    try r.drain();
    try testing.expectEqual(@as(usize, 3), r.log.items.len);
    for (r.log.items) |*s| {
        try testing.expectEqual(@as(u32, 0), s.find(.answer, hostName(), .a).?.ttl);
    }
    try testing.expectEqual(@as(usize, 0), r.e.registrationCount());
    try testing.expectEqual(null, r.e.nextDeadline(r.now()));
    try testing.expectEqual(mdns.core.responder.State.idle, r.e.responder.hostState());
    // Withdrawing while probing is silent, and the slot is reusable.
    const again = try r.e.advertise(.{ .service_type = svc_type, .instance = inst, .port = port }, r.now());
    r.clearLog();
    r.e.withdraw(again, r.now());
    try r.advance(3 * s_us);
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
    try testing.expectEqual(@as(usize, 0), r.e.registrationCount());
    try testing.expectError(error.DuplicateRegistration, blk: {
        _ = try r.e.advertise(.{ .service_type = svc_type, .instance = inst, .port = port }, r.now());
        break :blk r.e.advertise(.{ .service_type = svc_type, .instance = "DEMO", .port = port }, r.now());
    });
}

test "shared answers aggregate into one packet and TC delays 400-500ms" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.establish();
    _ = try r.e.advertise(.{ .service_type = svc_type, .instance = "second", .port = 2 }, r.now());
    try r.advance(3 * s_us);
    r.clearLog();
    try r.advance(2 * s_us);
    var buf: [512]u8 = undefined;
    // Two PTR queries 5 ms apart: one delayed packet with both PTRs.
    try r.rx(try simpleQuery(&buf, typeName(), .ptr, false), foreign4, 3);
    r.sc.advance(5 * ms_us);
    try r.rx(try simpleQuery(&buf, typeName(), .ptr, false), .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 8 }, .port = 5353 } }, 3);
    try r.advance(s_us);
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expectEqual(@as(usize, 2), r.log.items[0].countRecords(typeName(), .ptr));
    r.clearLog();
    try r.advance(2 * s_us);
    // A TC query waits 400-500 ms (section 7.2).
    var b: wire.Builder = .init(&buf, .{});
    b.setTruncated(true);
    try b.addQuestion(instName(), .srv, wire.class_in, false);
    const t0 = r.now();
    try r.rx(b.finish(), foreign4, 3);
    const due = r.e.nextDeadline(t0).?;
    try testing.expect(due - t0 >= timers.answer_delay_tc_min_us and due - t0 <= timers.answer_delay_tc_max_us);
}

test "handle never fails after init under a FailingAllocator sweep with a registration" {
    // `Engine.init` is the only allocating call, with a registration as
    // much as with a browse (plan section 4.5). Sweep every failure
    // index: init either fails cleanly with `OutOfMemory`, or the Engine
    // advertises, probes, announces, answers, defends, re-probes,
    // updates its TXT and says goodbye with an allocator that refuses
    // everything from then on, and the allocation count never moves
    // after init.
    var fail_at: usize = 0;
    var inits_ok: usize = 0;
    while (fail_at < 64) : (fail_at += 1) {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_at });
        var sc: Scenario = .init(fail_at);
        var e = Engine.init(fa.allocator(), .{
            .host_label = "sweep",
            .random = sc.random(),
            .limits = .{ .max_cache_records = 8, .max_events = 4, .max_interfaces = 2, .max_browses = 1, .max_registrations = 2, .max_pending_answers = 4 },
        }) catch |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            continue;
        };
        defer e.deinit();
        inits_ok += 1;
        const allocations = fa.allocations;
        try e.setInterfaces(&.{fake_lan.ifaceDual(3, "en0", .{ 10, 0, 3, 1 }, 24, 1)}, 0);
        const id = try e.advertise(.{ .service_type = svc_type, .instance = inst, .port = port, .txt = &.{.{ .key = "k", .value = "v" }} }, 0);
        var now: u64 = 0;
        var buf: [9000]u8 = undefined;
        var pk: [512]u8 = undefined;
        var lb: [512]u8 = undefined;
        var legacy: wire.Builder = .init(&lb, .{});
        legacy.setId(0x77);
        try legacy.addQuestion(instName(), .srv, wire.class_in, false);
        const legacy_bytes = legacy.finish();
        const legacy_from: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 9 }, .port = 40000 } };
        while (now < 20 * s_us) : (now += 50 * ms_us) {
            e.tick(now);
            while (e.pollDatagram(&buf, now)) |_| {}
            e.handle(try simpleQuery(&pk, instName(), .any, true), .{ .from = foreign4, .ifindex = 3, .dst_multicast = true }, now);
            e.handle(try simpleQuery(&pk, typeName(), .ptr, false), .{ .from = foreign4, .ifindex = 3, .dst_multicast = true }, now);
            e.handle(try foreignProbe(&pk, 9999, true), .{ .from = foreign4, .ifindex = 3, .dst_multicast = true }, now);
            e.handle(legacy_bytes, .{ .from = legacy_from, .ifindex = 3, .dst_multicast = false }, now);
            e.handle(legacy_bytes[0..7], .{ .from = legacy_from, .ifindex = 3, .dst_multicast = false }, now);
            if (now % (3 * s_us) == 0) {
                e.handle(try conflictingSrvFor(&pk, e.responder.instanceName(id).?, 9999), .{ .from = foreign4, .ifindex = 3, .dst_multicast = true }, now);
            }
            if (now % (5 * s_us) == 0) {
                e.updateTxt(id, &.{.{ .key = "k", .value = if ((now / (5 * s_us)) % 2 == 0) "w" else "v" }}, now) catch |err| return err;
            }
            while (e.pollEvent()) |_| {}
        }
        e.withdraw(id, now);
        while (e.pollDatagram(&buf, now)) |_| {}
        while (e.pollEvent()) |_| {}
        try testing.expect(!fa.has_induced_failure);
        try testing.expectEqual(allocations, fa.allocations);
        try testing.expect(e.stats().rx > 0);
        try testing.expect(e.stats().tx > 0);
        try testing.expect(e.stats().conflicts > 0);
    }
    try testing.expect(inits_ok > 0);
}

test "multi-question and ANY queries get one aggregated response with the section 12 additionals" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.establish();
    try r.advance(2 * s_us);
    var buf: [512]u8 = undefined;
    // Two questions (RFC 6762 sections 5.3, 6.3): instance ANY and host
    // A, answered in one packet with AA set (section 18.4). ANY on the
    // instance yields every record we hold under that name (section
    // 6.5); the SRV answer brings the address records along (RFC 6763
    // section 12.2), never duplicated with the A already answered.
    var p: Packet = .query(&buf);
    try p.question(instName(), .any, false);
    try p.question(hostName(), .a, false);
    try r.rx(p.bytes(), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    const s = &r.log.items[0];
    const m = try s.msg();
    try testing.expect(m.header.flags.qr and m.header.flags.aa);
    try testing.expectEqual(@as(u16, 0), m.header.id);
    try testing.expect(s.find(.answer, instName(), .srv) != null);
    try testing.expect(s.find(.answer, instName(), .txt) != null);
    try testing.expect(s.find(.answer, hostName(), .a) != null);
    try testing.expectEqual(@as(usize, 1), s.countRecords(hostName(), .a));
    try testing.expectEqual(@as(usize, 1), s.countRecords(hostName(), .aaaa));
    r.clearLog();
    try r.advance(2 * s_us);
    // A TXT answer carries no additionals (RFC 6763 section 12.3).
    try r.rx(try simpleQuery(&buf, instName(), .txt, false), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expectEqual(@as(u16, 0), (try r.log.items[0].msg()).header.arcount);
    r.clearLog();
    try r.advance(2 * s_us);
    // An A answer carries none either (section 12.4).
    try r.rx(try simpleQuery(&buf, hostName(), .a, false), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(u16, 0), (try r.log.items[0].msg()).header.arcount);
    r.clearLog();
    try r.advance(2 * s_us);
    // An SRV answer brings A and AAAA (section 12.2), a PTR answer brings
    // SRV, TXT, A and AAAA (section 12.1).
    try r.rx(try simpleQuery(&buf, instName(), .srv, false), foreign4, 3);
    try r.tick();
    try testing.expect(r.log.items[0].find(.additional, hostName(), .a) != null);
    try testing.expect(r.log.items[0].find(.additional, hostName(), .aaaa) != null);
    try testing.expectEqual(@as(usize, 0), r.log.items[0].countRecords(instName(), .txt));
    r.clearLog();
    try r.advance(2 * s_us);
    try r.rx(try simpleQuery(&buf, typeName(), .ptr, false), foreign4, 3);
    try r.advance(s_us);
    const ptr = &r.log.items[0];
    try testing.expect(ptr.find(.answer, typeName(), .ptr) != null);
    try testing.expect(ptr.find(.additional, instName(), .srv) != null);
    try testing.expect(ptr.find(.additional, instName(), .txt) != null);
    try testing.expect(ptr.find(.additional, hostName(), .a) != null);
    try testing.expect(ptr.find(.additional, hostName(), .aaaa) != null);
}

test "advertise validates the instance label and the service type" {
    const r = try Rig.init(.{});
    defer r.deinit();
    // RFC 6763 section 4.1: one UTF-8 label of 1..63 octets, no control
    // characters; RFC 6335 service names.
    try testing.expectError(error.InvalidInstance, r.e.advertise(.{ .service_type = svc_type, .instance = "", .port = 1 }, 0));
    try testing.expectError(error.InvalidInstance, r.e.advertise(.{ .service_type = svc_type, .instance = &(@as([64]u8, @splat('a'))), .port = 1 }, 0));
    try testing.expectError(error.InvalidInstance, r.e.advertise(.{ .service_type = svc_type, .instance = "a\tb", .port = 1 }, 0));
    try testing.expectError(error.InvalidInstance, r.e.advertise(.{ .service_type = svc_type, .instance = &.{ 0xff, 0xfe }, .port = 1 }, 0));
    try testing.expectError(error.InvalidServiceType, r.e.advertise(.{ .service_type = "_x", .instance = "a", .port = 1 }, 0));
    try testing.expectError(error.InvalidServiceType, r.e.advertise(.{ .service_type = "_toolongservicename._udp", .instance = "a", .port = 1 }, 0));
    try testing.expectError(error.InvalidServiceType, r.e.advertise(.{ .service_type = "_x._sctp", .instance = "a", .port = 1 }, 0));
    try testing.expectError(error.InvalidTxt, r.e.advertise(.{ .service_type = svc_type, .instance = "a", .port = 1, .txt = &.{.{ .key = "a=b" }} }, 0));
    try testing.expectEqual(@as(usize, 0), r.e.registrationCount());
    // A 63-octet UTF-8 instance with spaces and dots is fine.
    const id = try r.e.advertise(.{ .service_type = svc_type, .instance = "Alice's Zig Box 3.0 (ünïcödé) ........................", .port = 1 }, 0);
    try testing.expectEqual(@as(usize, 1), r.e.registrationCount());
    try testing.expectEqual(@as(usize, 4), r.e.responder.instanceName(id).?.labelCount());
    // Duplicates compare the whole name case-insensitively.
    try testing.expectError(error.DuplicateRegistration, r.e.advertise(.{ .service_type = svc_type, .instance = "ALICE'S ZIG BOX 3.0 (ünïcödé) ........................", .port = 2 }, 0));
    // The pool limit.
    var i: usize = 1;
    while (i < 32) : (i += 1) {
        var name: [8]u8 = undefined;
        _ = try r.e.advertise(.{ .service_type = svc_type, .instance = try std.fmt.bufPrint(&name, "n{d}", .{i}), .port = 1 }, 0);
    }
    try testing.expectError(error.LimitReached, r.e.advertise(.{ .service_type = svc_type, .instance = "one-too-many", .port = 1 }, 0));
}

test "announcements defer to the one-second rule instead of losing a step" {
    const r = try Rig.init(.{});
    defer r.deinit();
    const id = try r.e.advertise(.{ .service_type = svc_type, .instance = inst, .port = port }, 0);
    try r.runUntilRegistered();
    const t_ann = r.now();
    r.clearLog();
    r.sink.clear();
    // A TXT update 300 ms after the last announcement: the first of its
    // two announcements waits until t_ann + 1 s, the second follows one
    // second later; neither is dropped.
    r.sc.set(t_ann + 300 * ms_us);
    try r.e.updateTxt(id, &.{.{ .key = "seq", .value = "1" }}, r.now());
    try r.tick();
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
    try testing.expectEqual(@as(?u64, t_ann + s_us), r.e.nextDeadline(r.now()));
    try r.runTo(t_ann + s_us);
    try testing.expectEqual(@as(usize, 3), r.log.items.len);
    for (r.log.items) |*s| try testing.expect(s.find(.answer, instName(), .txt).?.cache_flush);
    try r.runTo(t_ann + 3 * s_us);
    try testing.expectEqual(@as(usize, 6), r.log.items.len);
    try testing.expectEqual(t_ann + 2 * s_us, r.log.items[5].now_us);
    try testing.expectEqual(@as(usize, 0), r.sink.len());
}

/// A conflicting A record for our host name (a foreign host that
/// claims `unit.local`).
fn conflictingHostA(buf: []u8) ![]const u8 {
    var p: Packet = .response(buf);
    try p.a(host_label, .{ 10, 0, 3, 77 }, 120, true);
    return p.bytes();
}

/// Cache-flush A answers for our host name in the log with TTL 120.
fn liveHostAnnouncements(r: *const Rig) usize {
    var n: usize = 0;
    for (r.log.items) |*s| {
        if (s.isQuery()) continue;
        const a = s.find(.answer, hostName(), .a) orelse continue;
        if (a.cache_flush and a.ttl != 0) n += 1;
    }
    return n;
}

test "announce queued before a conflict or a withdraw is not sent" {
    // Part 1: an interface change queues two announcements (now and
    // +1 s); a host conflict before the second fires resets the host to
    // probing (section 9), and no cache-flush A may go out until the
    // re-probe succeeds (section 8.1; section 10.2).
    {
        const r = try Rig.init(.{});
        defer r.deinit();
        _ = try r.establish();
        try r.advance(2 * s_us);
        r.clearLog();
        try r.e.setInterfaces(&.{ fake_lan.ifaceDual(3, "en0", .{ 10, 0, 3, 1 }, 24, 1), fake_lan.iface4(4, "en1", .{ 10, 0, 4, 2 }, 24) }, r.now());
        try r.tick();
        try testing.expect(liveHostAnnouncements(r) >= 1);
        r.clearLog();
        var buf: [512]u8 = undefined;
        r.sc.advance(500 * ms_us);
        try r.rx(try conflictingHostA(&buf), foreign4, 3);
        try testing.expectEqual(mdns.core.responder.State.probing, r.e.responder.hostState());
        // Run the probes and the announcements; every packet before the
        // host is owned again must be a probe or carry no live A.
        var guard: usize = 0;
        while (r.e.responder.hostState() == .probing) : (guard += 1) {
            try testing.expect(guard < 16);
            const d = r.e.nextDeadline(r.now()) orelse return error.TestUnexpectedResult;
            try r.runTo(d);
            if (r.e.responder.hostState() == .probing) try testing.expectEqual(@as(usize, 0), liveHostAnnouncements(r));
        }
        try testing.expect(r.queries() >= 3);
        try r.advance(3 * s_us);
        try testing.expect(liveHostAnnouncements(r) >= 1);
        _ = try r.sink.drain(&r.e);
        try r.sink.expectCount(.host_renamed, 0);
    }
    // Part 2: the interface change, then the last registration is
    // withdrawn at once: the goodbye goes, and nothing re-announces the
    // host afterwards (section 10.1).
    {
        const r = try Rig.init(.{});
        defer r.deinit();
        const id = try r.establish();
        try r.advance(2 * s_us);
        r.clearLog();
        try r.e.setInterfaces(&.{ fake_lan.ifaceDual(3, "en0", .{ 10, 0, 3, 1 }, 24, 1), fake_lan.iface4(4, "en1", .{ 10, 0, 4, 2 }, 24) }, r.now());
        r.e.withdraw(id, r.now());
        try r.drain();
        var goodbyes: usize = 0;
        for (r.log.items) |*s| {
            const a = s.find(.answer, hostName(), .a) orelse continue;
            try testing.expectEqual(@as(u32, 0), a.ttl);
            goodbyes += 1;
        }
        try testing.expect(goodbyes >= 1);
        r.clearLog();
        try r.advance(3 * s_us);
        try testing.expectEqual(@as(usize, 0), r.log.items.len);
        try testing.expectEqual(null, r.e.nextDeadline(r.now()));
    }
}

test "200 probes in 1 s yield at most 5 defence packets per pair" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.establish();
    try r.advance(2 * s_us);
    r.clearLog();
    var buf: [512]u8 = undefined;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        try r.rx(try foreignProbe(&buf, 9999, false), foreign4, 3);
        try r.tick();
        r.sc.advance(5 * ms_us);
    }
    // A defence held back by the 250 ms rule is deferred, not lost: the
    // last probes of the burst are answered at the next allowed moment.
    try r.advance(s_us);
    // Every defence is multicast on the arrival pair and carries the
    // SRV with cache-flush; at most one per 250 ms (section 6).
    try testing.expect(r.log.items.len >= 4);
    try testing.expect(r.log.items.len <= 5);
    var last: ?u64 = null;
    for (r.log.items) |*s| {
        try testing.expect(s.multicast());
        try testing.expectEqual(@as(u32, 3), s.ifindex);
        try testing.expect(s.find(.answer, instName(), .srv).?.cache_flush);
        if (last) |l| try testing.expect(s.now_us - l >= timers.defence_rate_limit_us);
        last = s.now_us;
    }
    // A probe on the other interface is defended at once regardless.
    r.clearLog();
    try r.rx(try foreignProbe(&buf, 9999, false), .{ .ip4 = .{ .bytes = .{ 10, 0, 4, 9 }, .port = 5353 } }, 4);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expectEqual(@as(u32, 4), r.log.items[0].ifindex);
    // Authority records without a question for that name are not a
    // probe (section 8.2): no defence, no packet.
    r.clearLog();
    r.sc.advance(s_us);
    var p: Packet = .query(&buf);
    try p.question(packets.typeName("_other._udp"), .ptr, false);
    p.in(.authority);
    try p.srv(inst, svc_type, 9999, "other", 120, false);
    try r.rx(p.bytes(), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
}

test "TC continuation known answers suppress the deferred response" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.establish();
    try r.advance(2 * s_us);
    r.clearLog();
    var buf: [512]u8 = undefined;
    // A PTR query with TC set: the answer waits 400-500 ms (section 7.2).
    var b: wire.Builder = .init(&buf, .{});
    try b.addQuestion(typeName(), .ptr, wire.class_in, false);
    b.setTruncated(true);
    try r.rx(b.finish(), foreign4, 3);
    const due = r.e.nextDeadline(r.now()).?;
    try testing.expect(due - r.now() >= timers.answer_delay_tc_min_us);
    try testing.expect(due - r.now() <= timers.answer_delay_tc_max_us);
    // 50 ms later the continuation packet (qdcount 0) from the same
    // querier lists our PTR with its full TTL: the pending answer is
    // deleted.
    r.sc.advance(50 * ms_us);
    var ka: Packet = .query(&buf);
    ka.in(.answer);
    try ka.ptr(svc_type, inst, 4500);
    try r.rx(ka.bytes(), foreign4, 3);
    try r.advance(s_us);
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
    // The same continuation from another host does not touch an answer
    // waiting for the first querier.
    b = .init(&buf, .{});
    try b.addQuestion(typeName(), .ptr, wire.class_in, false);
    b.setTruncated(true);
    try r.rx(b.finish(), foreign4, 3);
    r.sc.advance(50 * ms_us);
    var ka2: Packet = .query(&buf);
    ka2.in(.answer);
    try ka2.ptr(svc_type, inst, 4500);
    try r.rx(ka2.bytes(), .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 10 }, .port = 5353 } }, 3);
    try r.advance(s_us);
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expect(r.log.items[0].find(.answer, typeName(), .ptr) != null);
}

test "A answer on a v4-only interface carries the NSEC for AAAA in additionals" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.establish();
    try r.advance(2 * s_us);
    r.clearLog();
    var buf: [512]u8 = undefined;
    const from4: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 10, 0, 4, 9 }, .port = 5353 } };
    // Ifindex 4 has a v4 address only (section 6.2: "the appropriate
    // NSEC record SHOULD be placed into the additional section").
    try r.rx(try simpleQuery(&buf, hostName(), .a, false), from4, 4);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    const s = &r.log.items[0];
    try testing.expect(s.find(.answer, hostName(), .a) != null);
    const nsec = s.find(.additional, hostName(), .nsec).?;
    try testing.expect(nsec.cache_flush);
    const decoded = try wire.rdata.decodeNsec(s.bytes, nsec);
    try testing.expect(decoded.next.eql(&hostName()));
    try testing.expect(decoded.has(.a) and !decoded.has(.aaaa));
    // The section 12 additionals of a PTR answer carry it too.
    r.clearLog();
    r.sc.advance(2 * s_us);
    try r.rx(try simpleQuery(&buf, typeName(), .ptr, false), from4, 4);
    try r.advance(s_us);
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expect(r.log.items[0].find(.additional, hostName(), .a) != null);
    try testing.expect(r.log.items[0].find(.additional, hostName(), .nsec) != null);
    // A dual-stack interface has nothing to say: no NSEC beside the A.
    r.clearLog();
    r.sc.advance(2 * s_us);
    try r.rx(try simpleQuery(&buf, hostName(), .a, false), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expect(r.log.items[0].find(.additional, hostName(), .nsec) == null);
}

test "direct unicast query is answered like QU" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.establish();
    try r.advance(2 * s_us);
    r.clearLog();
    var buf: [512]u8 = undefined;
    // A QM question delivered by unicast to port 5353 from port 5353
    // (section 5.5): the reply is unicast to the source, port 5353,
    // since the SRV was multicast within TTL/4.
    try r.rxUnicast(try simpleQuery(&buf, instName(), .srv, false), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expect(!r.log.items[0].multicast());
    try testing.expectEqual(foreign4, r.log.items[0].to);
    try testing.expect(r.log.items[0].find(.answer, instName(), .srv).?.cache_flush);
    // The same query by multicast is answered by multicast.
    r.clearLog();
    r.sc.advance(2 * s_us);
    try r.rx(try simpleQuery(&buf, instName(), .srv, false), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expect(r.log.items[0].multicast());
}

test "QU query from an off-link source is answered by multicast or dropped" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.establish();
    try r.advance(2 * s_us);
    r.clearLog();
    var buf: [512]u8 = undefined;
    const spoofed: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 8, 8, 8, 8 }, .port = 5353 } };
    // A multicast QU query with a spoofed off-link source: no unicast
    // reply to it (section 11 on the reply target), the answer goes to
    // the group instead.
    try r.rx(try simpleQuery(&buf, instName(), .srv, true), spoofed, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expect(r.log.items[0].multicast());
    // A legacy query from an off-link source gets nothing, counted.
    r.clearLog();
    r.sc.advance(2 * s_us);
    var b: wire.Builder = .init(&buf, .{});
    b.setId(7);
    try b.addQuestion(instName(), .srv, wire.class_in, false);
    try r.rx(b.finish(), .{ .ip4 = .{ .bytes = .{ 8, 8, 8, 8 }, .port = 40000 } }, 3);
    try r.advance(s_us);
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
    try testing.expectEqual(@as(u64, 1), r.e.stats().dropped_off_link);
    // And a query from source port 0 is dropped too (nothing could reach
    // it).
    try r.rx(try simpleQuery(&buf, instName(), .srv, false), .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 9 }, .port = 0 } }, 3);
    try r.advance(s_us);
    try testing.expectEqual(@as(usize, 0), r.log.items.len);
    try testing.expectEqual(@as(u64, 1), r.e.stats().dropped_bad_port);
}

test "withdrawAll says goodbye for every registration on every pair" {
    const r = try Rig.init(.{});
    defer r.deinit();
    // Twelve registrations on three joined pairs would need 36 per-
    // registration goodbye jobs; goodbyes aggregate per pair instead.
    var ids: [12]mdns.RegId = undefined;
    var names: [12]Name = undefined;
    for (&ids, 0..) |*id, k| {
        var nb: [16]u8 = undefined;
        const n = try std.fmt.bufPrint(&nb, "inst{d}", .{k});
        id.* = try r.e.advertise(.{ .service_type = svc_type, .instance = n, .port = @intCast(1000 + k) }, r.now());
        names[k] = packets.instanceName(n, svc_type);
    }
    try r.advance(4 * s_us);
    try r.sink.expectCount(.registered, 12);
    r.clearLog();
    r.e.withdrawAll(r.now());
    try r.drain();
    try testing.expectEqual(@as(u64, 0), r.e.responderStats().jobs_dropped);
    try testing.expectEqual(@as(usize, 0), r.e.registrationCount());
    // Every registration's SRV with TTL 0 on each of the three pairs.
    for (names) |name| {
        var per_pair: usize = 0;
        for (r.log.items) |*s| {
            const srv = s.find(.answer, name, .srv) orelse continue;
            try testing.expectEqual(@as(u32, 0), srv.ttl);
            per_pair += 1;
        }
        try testing.expectEqual(@as(usize, 3), per_pair);
    }
    // The host went with them, once per pair.
    var host_byes: usize = 0;
    for (r.log.items) |*s| if (s.find(.answer, hostName(), .a)) |a| {
        try testing.expectEqual(@as(u32, 0), a.ttl);
        host_byes += 1;
    };
    try testing.expectEqual(@as(usize, 3), host_byes);
    try testing.expectEqual(null, r.e.nextDeadline(r.now()));
}

test "legacy reply echoes every question and stays within 512 octets" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.establish();
    try r.advance(2 * s_us);
    r.clearLog();
    var buf: [512]u8 = undefined;
    var b: wire.Builder = .init(&buf, .{});
    b.setId(0x4242);
    try b.addQuestion(instName(), .srv, wire.class_in, false);
    try b.addQuestion(instName(), .txt, wire.class_in, false);
    const legacy_from: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 10, 0, 3, 9 }, .port = 40000 } };
    try r.rx(b.finish(), legacy_from, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    const s = &r.log.items[0];
    const m = try s.msg();
    try testing.expectEqual(@as(u16, 0x4242), m.header.id);
    try testing.expectEqual(@as(u16, 2), m.header.qdcount);
    try testing.expect(s.hasQuestion(instName(), .srv));
    try testing.expect(s.hasQuestion(instName(), .txt));
    try testing.expect(s.find(.answer, instName(), .srv) != null);
    try testing.expect(s.find(.answer, instName(), .txt) != null);
    try testing.expect(s.bytes.len <= wire.builder.legacy_max_payload);
    try testing.expect(!m.header.flags.tc);
    // Many registrations under one type: a legacy PTR reply is one
    // packet of at most 512 octets with TC set when the rest does not
    // fit (RFC 1035 section 4.2.1), never a continuation.
    var k: usize = 0;
    while (k < 20) : (k += 1) {
        var nb: [40]u8 = undefined;
        const n = try std.fmt.bufPrint(&nb, "a-rather-long-instance-name-{d}", .{k});
        _ = try r.e.advertise(.{ .service_type = svc_type, .instance = n, .port = @intCast(2000 + k) }, r.now());
    }
    try r.advance(4 * s_us);
    r.clearLog();
    b = .init(&buf, .{});
    b.setId(0x4343);
    try b.addQuestion(typeName(), .ptr, wire.class_in, false);
    try r.rx(b.finish(), legacy_from, 3);
    try r.advance(s_us);
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    const big = &r.log.items[0];
    try testing.expect(big.bytes.len <= wire.builder.legacy_max_payload);
    const bm = try big.msg();
    try testing.expect(bm.header.flags.tc);
    try testing.expect(bm.header.ancount >= 1);
    try testing.expect(bm.header.ancount < 21);
}

test "a query mixing QU and QM questions is answered per question" {
    const r = try Rig.init(.{});
    defer r.deinit();
    _ = try r.establish();
    try r.advance(2 * s_us);
    r.clearLog();
    var buf: [512]u8 = undefined;
    // SRV asked QU, TXT asked QM (section 5.4: per-question bit): the
    // SRV goes by unicast, the TXT by multicast.
    var p: Packet = .query(&buf);
    try p.question(instName(), .srv, true);
    try p.question(instName(), .txt, false);
    try r.rx(p.bytes(), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 2), r.log.items.len);
    var unicast: usize = 0;
    for (r.log.items) |*s| {
        if (s.multicast()) {
            try testing.expect(s.find(.answer, instName(), .txt) != null);
            try testing.expect(s.find(.answer, instName(), .srv) == null);
        } else {
            unicast += 1;
            try testing.expectEqual(foreign4, s.to);
            try testing.expect(s.find(.answer, instName(), .srv) != null);
            try testing.expect(s.find(.answer, instName(), .txt) == null);
        }
    }
    try testing.expectEqual(@as(usize, 1), unicast);
    // The same record asked both ways goes by multicast once.
    r.clearLog();
    r.sc.advance(2 * s_us);
    p = .query(&buf);
    try p.question(instName(), .srv, true);
    try p.question(instName(), .srv, false);
    try r.rx(p.bytes(), foreign4, 3);
    try r.tick();
    try testing.expectEqual(@as(usize, 1), r.log.items.len);
    try testing.expect(r.log.items[0].multicast());
}

test "conflicts before the first probe of a name rename it once" {
    const r = try Rig.init(.{});
    defer r.deinit();
    const id = try r.establish();
    var buf: [512]u8 = undefined;
    // Established -> conflict -> re-probe the same name; a burst of
    // conflicting responses before that probe goes out is one conflict
    // for the name (each counted for the section 9 backoff), and the
    // rename happens once the probe has been sent and answered.
    try r.rx(try conflictingSrv(&buf, 9999), foreign4, 3);
    try r.sink.expectCount(.renamed, 0);
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        try r.rx(try conflictingSrvFor(&buf, r.e.responder.instanceName(id).?, 9999), foreign4, 3);
        r.sc.advance(ms_us);
    }
    try r.sink.expectCount(.renamed, 0);
    try testing.expect(r.e.stats().conflicts >= 100);
    // The hostile peer keeps answering every probe: renames are bounded
    // by the probe rate (one per name probed), never by the packet rate.
    var probes: usize = 0;
    var guard: usize = 0;
    while (probes < 3) : (guard += 1) {
        try testing.expect(guard < 64);
        const d = r.e.nextDeadline(r.now()) orelse return error.TestUnexpectedResult;
        r.clearLog();
        try r.runTo(d);
        if (r.queries() == 0) continue;
        probes += 1;
        var k: usize = 0;
        while (k < 10) : (k += 1) {
            try r.rx(try conflictingSrvFor(&buf, r.e.responder.instanceName(id).?, 9999), foreign4, 3);
            r.sc.advance(ms_us);
        }
    }
    try testing.expectEqual(@as(usize, 3), r.sink.count(.renamed));
}

// ---- over the fake LAN ----------------------------------------------------
//
// End to end: real engines on both sides of a `FakeLan` segment with
// multicast loopback on (every engine hears its own packets back, as a
// kernel delivers them), the seeded clock, deadline-driven stepping.
// What the hand-built packets above cannot show: a real querier
// resolving a real responder, a goodbye turning into `lost`, the idle
// budget with the echoes flowing, the rate limit under a query flood,
// simultaneous probers tie-breaking against each other, a second stack
// on our own IP, and a bridge between two of our own interfaces.

const Lan = fake_lan.FakeLan(4);
const max_lan_engines = 4;
/// Largest jump of the deadline-driven loop when nothing is scheduled.
const lan_max_step_us = 10 * s_us;

/// `10.0.3.<k+1>`.
fn lanAddr4(k: usize) [4]u8 {
    return .{ 10, 0, 3, @intCast(k + 1) };
}

fn lanHost(k: usize) Name {
    var buf: [16]u8 = undefined;
    return packets.hostName(std.fmt.bufPrint(&buf, "host-{d}", .{k}) catch unreachable);
}

/// Up to four engines (`host-<k>.local`) with one sink each on one
/// `FakeLan`; `attach` puts engine `k` on a segment. The engine's LAN
/// index equals `k` as long as the engines are attached in order.
const LanRig = struct {
    sc: Scenario,
    lan: Lan,
    engines: [max_lan_engines]Engine,
    sinks: [max_lan_engines]Sink,
    count: usize,

    const Options = struct {
        seed: u64 = 0x4d34,
        count: usize = 2,
        first_binder: bool = true,
    };

    fn init(opts: Options) !*LanRig {
        const r = try testing.allocator.create(LanRig);
        errdefer testing.allocator.destroy(r);
        r.* = .{ .sc = .init(opts.seed), .lan = .init(testing.allocator), .engines = undefined, .sinks = undefined, .count = 0 };
        errdefer r.lan.deinit();
        errdefer {
            for (r.engines[0..r.count], r.sinks[0..r.count]) |*e, *s| {
                s.deinit();
                e.deinit();
            }
        }
        while (r.count < opts.count) {
            var label: [16]u8 = undefined;
            r.engines[r.count] = try Engine.init(testing.allocator, .{
                .host_label = try std.fmt.bufPrint(&label, "host-{d}", .{r.count}),
                .random = r.sc.random(),
                .limits = .{ .max_interfaces = 4, .max_events = 64 },
                .qu_allowed = opts.first_binder,
                .first_binder = opts.first_binder,
            });
            r.sinks[r.count] = .init(testing.allocator);
            r.count += 1;
        }
        return r;
    }

    fn deinit(r: *LanRig) void {
        r.lan.deinit();
        for (r.engines[0..r.count], r.sinks[0..r.count]) |*e, *s| {
            s.deinit();
            e.deinit();
        }
        testing.allocator.destroy(r);
    }

    /// Engine `k` on `segment` with ifindex 3, `addr4`/24 and
    /// `fe80::<ll_suffix>`/64: two joined pairs.
    fn attachWith(r: *LanRig, k: usize, segment: u32, addr4: [4]u8, ll_suffix: u16) !void {
        const idx = try r.lan.addEngineOn(&r.engines[k], fake_lan.ifaceDual(3, "en0", addr4, 24, ll_suffix), segment, r.now());
        try testing.expectEqual(k, idx);
        try r.drainAll();
        r.sinks[k].clear();
    }

    /// Engine `k` on segment 0 as `10.0.3.<k+1>` / `fe80::<k+1>`.
    fn attach(r: *LanRig, k: usize) !void {
        try r.attachWith(k, 0, lanAddr4(k), @intCast(k + 1));
    }

    fn attachAll(r: *LanRig) !void {
        var k: usize = 0;
        while (k < r.count) : (k += 1) try r.attach(k);
    }

    fn now(r: *const LanRig) u64 {
        return r.sc.nowUs();
    }

    fn drainAll(r: *LanRig) !void {
        for (r.engines[0..r.count], r.sinks[0..r.count]) |*e, *s| _ = try s.drain(e);
    }

    /// Tick every engine and pump the LAN at the current clock, then jump
    /// to the soonest deadline (at most `lan_max_step_us` ahead) until
    /// `until`, draining every sink after every step.
    fn runTo(r: *LanRig, until: u64) !void {
        var t = r.now();
        while (true) {
            r.lan.tickAll(t);
            try r.lan.pump(t);
            try r.drainAll();
            if (t >= until) break;
            var next = t +| lan_max_step_us;
            if (r.lan.nextDeadline(t)) |d| next = @min(next, @max(d, t + 1));
            t = @min(next, until);
            r.sc.set(t);
        }
    }

    fn advance(r: *LanRig, us: u64) !void {
        try r.runTo(r.now() + us);
    }

    fn advertiseOn(r: *LanRig, k: usize, instance: []const u8, svc_port: u16) !mdns.RegId {
        return r.engines[k].advertise(.{ .service_type = svc_type, .instance = instance, .port = svc_port, .txt = &.{.{ .key = "txtvers", .value = "1" }} }, r.now());
    }

    fn log(r: *const LanRig) []const fake_lan.Sent {
        return r.lan.sentLog();
    }

    fn sent(r: *const LanRig, filter: scenario.Filter) usize {
        return scenario.countSent(r.log(), filter);
    }

    /// Send times of the matching datagrams (at most 64).
    fn times(r: *const LanRig, filter: scenario.Filter, out: *[64]u64) []u64 {
        return scenario.sendTimes(r.log(), filter, out);
    }
};

test "advertise then browse on a second engine resolves within 3 simulated seconds" {
    const r = try LanRig.init(.{ .count = 2 });
    defer r.deinit();
    try r.attachAll();
    const id = try r.advertiseOn(0, inst, port);
    _ = try r.engines[1].browse(svc_type, r.now());
    try r.runTo(3 * s_us);

    // The advertiser probed, announced and registered its one instance.
    try r.sinks[0].expectCount(.registered, 1);
    try testing.expectEqual(id, r.sinks[0].first(.registered).?.registered.id);
    try r.sinks[0].expectCount(.renamed, 0);
    try r.sinks[0].expectCount(.host_renamed, 0);
    try testing.expectEqual(@as(u64, 0), r.engines[0].stats().conflicts);

    // The browser saw the PTR and resolved SRV, TXT and both addresses of
    // engine 0's interface (RFC 6762 section 6.2) once, on its ifindex 3.
    try r.sinks[1].expectCount(.found, 1);
    try r.sinks[1].expectCount(.resolved, 1);
    try r.sinks[1].expectCount(.lost, 0);
    const res = r.sinks[1].first(.resolved).?.resolved;
    try testing.expect(res.instance.eql(&instName()));
    try testing.expect(res.service_type.eql(&typeName()));
    try testing.expect(res.host.eql(&lanHost(0)));
    try testing.expectEqual(port, res.port);
    try testing.expectEqualStrings("1", res.txt.get("txtvers").?);
    try testing.expectEqual(@as(u32, 3), res.ifindex);
    try testing.expectEqual(@as(usize, 2), res.addrs.len);
    var saw4 = false;
    var saw6 = false;
    for (res.addrs.slice()) |a| switch (a) {
        .ip4 => |v| {
            try testing.expectEqual(lanAddr4(0), v.bytes);
            saw4 = true;
        },
        .ip6 => |v| {
            try testing.expectEqual(fake_lan.linkLocal6(1), v.bytes);
            try testing.expectEqual(@as(u32, 3), v.interface.index);
            saw6 = true;
        },
    };
    try testing.expect(saw4 and saw6);

    // Section 8.1: nothing was answered while probing. Engine 0's first
    // response on each pair is the first announcement, 250 ms after its
    // third probe; the second announcement follows one second later.
    inline for (.{ mdns.Family.v4, mdns.Family.v6 }) |family| {
        var pt: [64]u64 = undefined;
        const probes = r.times(.{ .from_engine = 0, .kind = .query, .family = family }, &pt);
        try testing.expectEqual(@as(usize, timers.probe_count), probes.len);
        var rt: [64]u64 = undefined;
        const responses = r.times(.{ .from_engine = 0, .kind = .response, .family = family }, &rt);
        try testing.expect(responses.len >= timers.announce_count);
        try testing.expectEqual(probes[2] + timers.probe_interval_us, responses[0]);
        try testing.expectEqual(responses[0] + timers.announce_interval_us, responses[1]);
    }
    // The browser's queries reached engine 0 as foreign packets, and every
    // own packet came back as an echo on both engines.
    try testing.expect(r.sent(.{ .from_engine = 1, .kind = .query }) >= 2);
    for (r.engines[0..2]) |*e| try testing.expectEqual(e.stats().tx, e.stats().rx_echo);
}

test "withdraw sends goodbye and the browser emits lost within 1s" {
    const r = try LanRig.init(.{ .count = 2, .seed = 0x9004 });
    defer r.deinit();
    try r.attachAll();
    const id = try r.advertiseOn(0, inst, port);
    _ = try r.engines[1].browse(svc_type, r.now());
    try r.runTo(4 * s_us);
    try r.sinks[1].expectCount(.resolved, 1);
    r.lan.clearLog();
    r.sinks[1].clear();

    const t_w = r.now();
    r.engines[0].withdraw(id, t_w);
    try testing.expectEqual(@as(usize, 0), r.engines[0].registrationCount());
    try r.runTo(t_w + timers.goodbye_grace_us - 10 * ms_us);
    // One goodbye per pair (RFC 6762 section 10.1): a response whose
    // answer section carries the instance's PTR, SRV and TXT and, this
    // being the last registration, the host's addresses, all with TTL 0.
    try testing.expectEqual(@as(usize, 2), r.sent(.{ .from_engine = 0 }));
    for (r.log()) |*s| {
        if (s.from_engine != 0) continue;
        try testing.expectEqual(t_w, s.now_us);
        try testing.expectEqual(fake_lan.PacketKind.response, s.kind);
        try testing.expect(s.isMulticast());
        try testing.expectEqual(@as(u32, 0), recIn(s.bytes, .answer, typeName(), .ptr).?.ttl);
        try testing.expectEqual(@as(u32, 0), recIn(s.bytes, .answer, instName(), .srv).?.ttl);
        try testing.expectEqual(@as(u32, 0), recIn(s.bytes, .answer, instName(), .txt).?.ttl);
        try testing.expectEqual(@as(u32, 0), recIn(s.bytes, .answer, lanHost(0), .a).?.ttl);
        try testing.expectEqual(@as(u32, 0), recIn(s.bytes, .answer, lanHost(0), .aaaa).?.ttl);
    }
    // The browser holds the record for the one-second goodbye grace, then
    // reports the loss (section 10.1: "the record is set to expire in 1 s").
    try r.sinks[1].expectCount(.lost, 0);
    try r.runTo(t_w + timers.goodbye_grace_us + 10 * ms_us);
    try r.sinks[1].expectCount(.lost, 1);
    const lost = r.sinks[1].first(.lost).?.lost;
    try testing.expect(lost.instance.eql(&instName()));
    try testing.expectEqual(@as(u32, 3), lost.ifindex);
    try testing.expectEqual(@as(usize, 0), r.engines[1].cacheCount());

    // The browser keeps querying; engine 0 has nothing left to say.
    r.lan.clearLog();
    try r.advance(20 * s_us);
    try testing.expect(r.sent(.{ .from_engine = 1, .kind = .query }) >= 1);
    try testing.expectEqual(@as(usize, 0), r.sent(.{ .from_engine = 0 }));
    try r.sinks[1].expectCount(.found, 0);
}

test "idle advertised service sends nothing after announcing" {
    const r = try LanRig.init(.{ .count = 1, .seed = 0x1d1e });
    defer r.deinit();
    // ifindex 3 (v4 + v6) on segment 0 and ifindex 4 (v4) on segment 1:
    // three joined pairs, every multicast comes back as a loopback echo.
    _ = try r.lan.addEngine(&r.engines[0], &.{ fake_lan.ifaceDual(3, "en0", .{ 10, 0, 3, 1 }, 24, 1), fake_lan.iface4(4, "en1", .{ 10, 0, 4, 1 }, 24) }, &.{ 0, 1 }, 0);
    try r.drainAll();
    r.sinks[0].clear();
    _ = try r.advertiseOn(0, inst, port);
    try r.runTo(30 * s_us);
    try r.sinks[0].expectCount(.registered, 1);
    try r.sinks[0].expectCount(.renamed, 0);
    try r.sinks[0].expectCount(.host_renamed, 0);
    try r.sinks[0].expectCount(.warning, 0);

    // Exactly three probes and two announcements per joined pair, and
    // nothing else, over thirty seconds.
    const pairs = [_]struct { ifindex: u32, family: mdns.Family }{ .{ .ifindex = 3, .family = .v4 }, .{ .ifindex = 3, .family = .v6 }, .{ .ifindex = 4, .family = .v4 } };
    for (pairs) |p| {
        try testing.expectEqual(@as(usize, timers.probe_count), r.sent(.{ .ifindex = p.ifindex, .family = p.family, .kind = .query }));
        try testing.expectEqual(@as(usize, timers.announce_count), r.sent(.{ .ifindex = p.ifindex, .family = p.family, .kind = .response }));
    }
    const total = pairs.len * (timers.probe_count + timers.announce_count);
    try testing.expectEqual(total, r.log().len);
    try testing.expectEqual(@as(usize, 0), r.sent(.{ .kind = .malformed }));
    // The last packet is the second announcement, no later than 250 ms +
    // 3 x 250 ms + 1 s after the advertise.
    const last = r.log()[r.log().len - 1].now_us;
    try testing.expect(last <= timers.probe_first_delay_max_us + timers.probe_count * timers.probe_interval_us + timers.announce_interval_us);
    // Every packet echoed back exactly once (multicast loopback) and the
    // echoes changed nothing: no conflict, no cache entry, no answer.
    const st = r.engines[0].stats();
    try testing.expectEqual(@as(u64, total), st.tx);
    try testing.expectEqual(@as(u64, total), st.rx);
    try testing.expectEqual(@as(u64, total), st.rx_echo);
    try testing.expectEqual(@as(u64, 0), st.rx_echo_bridged);
    try testing.expectEqual(@as(u64, 0), st.conflicts);
    try testing.expectEqual(@as(u64, 0), st.tx_dropped);
    try testing.expectEqual(@as(usize, 0), r.engines[0].cacheCount());
    try testing.expectEqual(null, r.engines[0].nextDeadline(r.now()));
    // Ten more minutes of silence.
    r.lan.clearLog();
    try r.advance(10 * scenario.us_per_min);
    try testing.expectEqual(@as(usize, 0), r.log().len);
    try testing.expectEqual(@as(u64, total), r.engines[0].stats().tx);
}

test "a query flood is answered at most once per second per pair" {
    // RFC 6762 section 6: "a Multicast DNS responder MUST NOT multicast a
    // record on a given interface until at least one second has elapsed
    // since the last time that record was multicast on that particular
    // interface". A hostile querier asking every 5 ms gets one answer a
    // second, unique (SRV, at once) and shared (PTR, 20-120 ms) alike.
    const r = try LanRig.init(.{ .count = 1, .seed = 0xf100d });
    defer r.deinit();
    try r.attachAll();
    _ = try r.advertiseOn(0, inst, port);
    try r.runTo(4 * s_us);
    try r.sinks[0].expectCount(.registered, 1);
    r.lan.clearLog();

    var qb: [512]u8 = undefined;
    const q = try simpleQuery(&qb, instName(), .srv, false);
    const t0 = r.now();
    var k: usize = 0;
    while (k <= 400) : (k += 1) {
        _ = try r.lan.injectForeign(0, q, foreign4, true, r.now());
        try r.advance(5 * ms_us);
    }
    // Answered at t0, t0 + 1 s and t0 + 2 s on (3, v4) only (the 398
    // queries in between were dropped, not deferred: the querier will
    // ask again); the flood arrived over v4, so v6 stays quiet.
    const answers: scenario.Filter = .{ .from_engine = 0, .kind = .response };
    try testing.expectEqual(@as(usize, 3), r.sent(answers));
    try testing.expectEqual(@as(usize, 1), scenario.maxInWindow(r.log(), answers, timers.record_rate_limit_us));
    var at: [64]u64 = undefined;
    try testing.expectEqualSlices(u64, &.{ t0, t0 + s_us, t0 + 2 * s_us }, r.times(answers, &at));
    for (r.log()) |*s| {
        try testing.expectEqual(mdns.Family.v4, s.family);
        try testing.expect(s.isMulticast());
        try testing.expect(recIn(s.bytes, .answer, instName(), .srv) != null);
    }
    try testing.expectEqual(@as(usize, 0), r.sent(.{ .from_engine = 0, .kind = .query }));

    // The same for the shared PTR: the delayed answers aggregate and the
    // rate limit still holds per second.
    r.lan.clearLog();
    try r.advance(2 * s_us);
    const pq = try simpleQuery(&qb, typeName(), .ptr, false);
    const t1 = r.now();
    k = 0;
    while (k <= 400) : (k += 1) {
        _ = try r.lan.injectForeign(0, pq, foreign4, true, r.now());
        try r.advance(5 * ms_us);
    }
    try r.advance(s_us);
    const ptr_answers = r.sent(answers);
    try testing.expect(ptr_answers >= 2 and ptr_answers <= 3);
    try testing.expectEqual(@as(usize, 1), scenario.maxInWindow(r.log(), answers, timers.record_rate_limit_us));
    for (r.log()) |*s| {
        try testing.expect(s.now_us >= t1 + timers.answer_delay_min_us);
        try testing.expect(recIn(s.bytes, .answer, typeName(), .ptr) != null);
    }
    try testing.expectEqual(@as(u64, 0), r.engines[0].stats().conflicts);
    try r.sinks[0].expectCount(.renamed, 0);
}

test "simultaneous probers of one name converge to distinct names" {
    // Four hosts advertise `demo` at the same instant on one segment.
    // Section 8.2 tie-breaks decide the simultaneous probes, section 9
    // conflicts rename the late ones; every host ends up registered
    // under its own name, nobody is renamed by its own echo, and the
    // whole affair stays inside a small packet budget before going
    // silent.
    const r = try LanRig.init(.{ .count = 4, .seed = 0xc0e5 });
    defer r.deinit();
    try r.attachAll();
    var ids: [4]mdns.RegId = undefined;
    for (&ids, 0..) |*id, k| id.* = try r.advertiseOn(k, inst, port);
    try r.runTo(30 * s_us);

    var names: [4]Name = undefined;
    for (r.engines[0..4], r.sinks[0..4], 0..) |*e, *s, k| {
        try testing.expect(s.count(.registered) >= 1);
        try testing.expectEqual(mdns.core.responder.State.established, e.responder.regState(ids[k]).?);
        names[k] = e.responder.instanceName(ids[k]).?;
        try testing.expect(s.last(.registered).?.registered.instance.eql(&names[k]));
        try testing.expectEqual(@as(usize, 1), e.registrationCount());
        // The host names never clashed: `host-<k>` are distinct.
        try s.expectCount(.host_renamed, 0);
        try testing.expect(e.hostName().eql(&lanHost(k)));
    }
    for (names, 0..) |a, i| for (names[i + 1 ..]) |b| try testing.expect(!a.eql(&b));
    // Somebody kept `demo`, and the renames run `demo (2)`, `demo (3)`, ...
    var kept_demo = false;
    var renames: usize = 0;
    for (names, 0..) |n, k| {
        if (n.eql(&instName())) kept_demo = true;
        renames += r.sinks[k].count(.renamed);
    }
    try testing.expect(kept_demo);
    // The shortest chain: three hosts move to `demo (2)`, two of those
    // to `demo (3)`, one to `demo (4)`.
    try testing.expectEqual(@as(usize, 6), renames);
    // Budget per engine and pair: at most four probe rounds (one per
    // name tried) and one announce sequence; the section 8.2 losers
    // that hear a second foreign probe rename without re-probing the
    // lost name, and the defences of the established ones are answers
    // to probes, not extra rounds. Converges well inside three seconds.
    const per_pair_budget: usize = 4 * timers.probe_count + timers.announce_count;
    try testing.expect(r.log()[r.log().len - 1].now_us <= 3 * s_us);
    for (0..4) |k| {
        try scenario.expectBudget(r.log(), .{ .from_engine = k, .family = .v4 }, per_pair_budget);
        try scenario.expectBudget(r.log(), .{ .from_engine = k, .family = .v6 }, per_pair_budget);
    }
    try testing.expectEqual(@as(usize, 0), r.sent(.{ .kind = .malformed }));
    // Then silence.
    r.lan.clearLog();
    try r.advance(30 * s_us);
    try testing.expectEqual(@as(usize, 0), r.log().len);
}

test "a second stack on our own IP loses to the multicast defence and renames" {
    // Two engines on one segment sharing one IP per family (two stacks
    // on one host, `dns-sd -R` beside us). Engine 0 owns `demo`; engine
    // 1 probes it from what engine 0 sees as its own address. Not an
    // echo (the bytes were never engine 0's), so engine 0 defends by
    // multicast plus the unicast copy (plan section 4.8 "Port sharing"),
    // and engine 1 hears the defence during its probe and renames.
    const r = try LanRig.init(.{ .count = 2, .seed = 0x5a3e });
    defer r.deinit();
    try r.attachWith(0, 0, .{ 10, 0, 3, 1 }, 1);
    try r.attachWith(1, 0, .{ 10, 0, 3, 1 }, 1);
    _ = try r.advertiseOn(0, inst, port);
    try r.runTo(4 * s_us);
    try r.sinks[0].expectCount(.registered, 1);
    r.lan.clearLog();

    const id1 = try r.advertiseOn(1, inst, 9999);
    try r.advance(6 * s_us);
    // Engine 1: renamed once, registered as `demo (2)`.
    try r.sinks[1].expectCount(.renamed, 1);
    const ev = r.sinks[1].first(.renamed).?.renamed;
    try testing.expectEqual(id1, ev.id);
    try testing.expect(ev.old.eql(&instName()));
    const renamed = packets.instanceName("demo (2)", svc_type);
    try testing.expect(ev.new.eql(&renamed));
    try r.sinks[1].expectCount(.registered, 1);
    try testing.expect(r.sinks[1].first(.registered).?.registered.instance.eql(&renamed));
    try testing.expect(r.engines[1].responder.instanceName(id1).?.eql(&renamed));
    // Engine 0: untouched, no conflict, no rename.
    try testing.expectEqual(@as(u64, 0), r.engines[0].stats().conflicts);
    try r.sinks[0].expectCount(.renamed, 0);
    try r.sinks[0].expectCount(.host_renamed, 0);
    try testing.expect(r.engines[0].responder.instanceName(r.sinks[0].first(.registered).?.registered.id).?.eql(&instName()));
    // The defence: with engine 1's first probe (the harness pumps a
    // reaction one step, one microsecond, later), engine 0 multicast
    // `demo`'s SRV with cache-flush on that pair.
    var pt: [64]u64 = undefined;
    const probes = r.times(.{ .from_engine = 1, .kind = .query, .family = .v4 }, &pt);
    try testing.expect(probes.len >= 1);
    var defended = false;
    for (r.log()) |*s| {
        if (s.from_engine != 0 or s.kind != .response or !s.isMulticast() or s.family != .v4) continue;
        if (s.now_us < probes[0] or s.now_us > probes[0] + 1) continue;
        const srv = recIn(s.bytes, .answer, instName(), .srv) orelse continue;
        try testing.expect(srv.cache_flush);
        try testing.expectEqual(port, (try wire.rdata.decodeSrv(s.bytes, srv)).port);
        defended = true;
    }
    try testing.expect(defended);
    // Engine 0's own packets came back from its own address as echoes;
    // engine 1's probes from that same address did not.
    try testing.expect(r.engines[0].stats().rx > r.engines[0].stats().rx_echo);
}

test "bridged interfaces re-announce the echoed addresses and never rename" {
    // One engine with two interfaces on two segments that a switch
    // bridges (plan section 4.8 "Bridged echo"; RFC 6762 section 10.2):
    // every packet on ifindex 3 comes back on ifindex 4 from our own
    // 10.0.3.1 and the other way round. Never a conflict, never a
    // rename; the address re-announce fires only when the echoed
    // cache-flush could have flushed a set the peers do not hold within
    // the one-second grace, and it settles instead of ping-ponging across
    // the bridge once a second forever.
    const r = try LanRig.init(.{ .count = 1, .seed = 0xb21d });
    defer r.deinit();
    const if3 = fake_lan.ifaceDual(3, "en0", .{ 10, 0, 3, 1 }, 24, 1);
    const if4 = fake_lan.iface4(4, "en1", .{ 10, 0, 4, 1 }, 24);
    try r.lan.bridge(0, 1);

    // Phase 1: both interfaces announce together. Every echo arrives
    // inside the second, so the peers hold both address sets and nothing
    // is re-announced: the idle budget, no more.
    _ = try r.lan.addEngine(&r.engines[0], &.{ if3, if4 }, &.{ 0, 1 }, 0);
    try r.drainAll();
    r.sinks[0].clear();
    _ = try r.advertiseOn(0, inst, port);
    try r.runTo(30 * s_us);
    try r.sinks[0].expectCount(.registered, 1);
    try r.sinks[0].expectCount(.renamed, 0);
    try r.sinks[0].expectCount(.host_renamed, 0);
    var st = r.engines[0].stats();
    try testing.expectEqual(@as(u64, 0), st.conflicts);
    try testing.expect(st.rx_echo_bridged > 0);
    try testing.expectEqual(st.rx, st.rx_echo);
    try testing.expectEqual(@as(usize, 0), r.engines[0].cacheCount());
    try testing.expectEqual(@as(usize, 3 * (timers.probe_count + timers.announce_count)), r.log().len);
    try testing.expect(r.log()[r.log().len - 1].now_us <= 3 * s_us);

    // Phase 2: ifindex 4 leaves and comes back alone. Its announcements
    // echo onto ifindex 3 more than a second after ifindex 3 last
    // multicast its addresses, so ifindex 3 re-announces its address
    // RRSet at once (A/AAAA only); that re-announce echoes back onto
    // ifindex 4 within the second and starts nothing.
    r.lan.clearLog();
    try r.lan.setInterfaces(0, &.{if3}, &.{0}, r.now());
    try r.advance(5 * s_us);
    r.lan.clearLog();
    r.sinks[0].clear();
    const t_add = r.now();
    try r.lan.setInterfaces(0, &.{ if3, if4 }, &.{ 0, 1 }, t_add);
    try r.runTo(t_add + 30 * s_us);
    try r.sinks[0].expectCount(.renamed, 0);
    try r.sinks[0].expectCount(.host_renamed, 0);
    st = r.engines[0].stats();
    try testing.expectEqual(@as(u64, 0), st.conflicts);
    try testing.expectEqual(st.rx, st.rx_echo);
    var reann3: usize = 0;
    var reann4: usize = 0;
    var ann4: usize = 0;
    for (r.log()) |*s| {
        try testing.expectEqual(fake_lan.PacketKind.response, s.kind);
        try testing.expect(s.now_us <= t_add + 2 * s_us);
        const a = recIn(s.bytes, .answer, lanHost(0), .a).?;
        try testing.expect(a.cache_flush);
        const want: [4]u8 = if (s.ifindex == 3) .{ 10, 0, 3, 1 } else .{ 10, 0, 4, 1 };
        try testing.expectEqual(want, try wire.rdata.decodeA(a.rdata));
        if (countIn(s.bytes, instName(), .srv) != 0) {
            try testing.expectEqual(@as(u32, 4), s.ifindex);
            ann4 += 1;
        } else if (s.ifindex == 3) {
            reann3 += 1;
        } else {
            reann4 += 1;
        }
    }
    // ifindex 4 announced its records (host and instance); ifindex 3
    // re-announced its addresses on its two pairs, at most once per
    // announcement echoed; ifindex 4 never re-announced (every echo it
    // got came within a second of its own announcement).
    try testing.expectEqual(@as(usize, timers.announce_count), ann4);
    try testing.expect(reann3 >= 2 and reann3 <= 2 * timers.announce_count);
    try testing.expectEqual(@as(usize, 0), reann4);
    // Then silence.
    r.lan.clearLog();
    try r.advance(60 * s_us);
    try testing.expectEqual(@as(usize, 0), r.log().len);
    try testing.expectEqual(null, r.engines[0].nextDeadline(r.now()));
}
