//! `mdns.profiles` tests (plan section 7, M5): the import-graph guard,
//! Advert -> wire -> Engine -> `Resolved` -> `Parsed` round trips for the
//! three schemas, the parser rules of plan section 3.4 and the qmesh
//! `SeedSet` admission rule.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const build_options = @import("build_options");
const mdns = @import("mdns");
const profiles = mdns.profiles;
const wire = mdns.wire;
const scenario = @import("harness/scenario.zig");
const packets = @import("harness/packets.zig");
const fake_lan = @import("harness/fake_lan.zig");

const Engine = mdns.Engine;
const Resolved = mdns.Resolved;
const Packet = packets.Packet;

// ---- import graph ---------------------------------------------------------
//
// Zig has no reflection over a file's imports, so the guard works on the
// source text: starting at `src/profiles/root.zig` it collects every
// `@import("...")` literal, resolves relative paths against the importing
// file, and follows each one. Every reachable file must be one of the
// allowed value-type files, and every non-path import must be `std` (or
// `builtin`). A `@import("../service.zig")`, `@import("mdns")` or a path
// into `platform/` / `core/engine.zig` fails the test with the offending
// file and import named. `@import` always takes a string literal, so the
// textual scan sees exactly what the compiler sees; the price is that a
// comment containing `@import("x")` counts too, which is conservative.

const profiles_root = "src/profiles/root.zig";
const allowed_prefixes = [_][]const u8{ "src/profiles/", "src/wire/" };
const allowed_files = [_][]const u8{"src/core/events.zig"};
const allowed_modules = [_][]const u8{ "std", "builtin" };
const max_source_bytes = 4 << 20;

fn isAllowedFile(path: []const u8) bool {
    for (allowed_prefixes) |p| if (std.mem.startsWith(u8, path, p)) return true;
    for (allowed_files) |f| if (std.mem.eql(u8, path, f)) return true;
    return false;
}

fn isAllowedModule(name: []const u8) bool {
    for (allowed_modules) |m| if (std.mem.eql(u8, name, m)) return true;
    return false;
}

/// `dir/rel` with `.` and `..` folded, as a repo-relative path.
fn joinNormalized(allocator: std.mem.Allocator, dir: []const u8, rel: []const u8) ![]u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(allocator);
    for ([_][]const u8{ dir, rel }) |s| {
        var it = std.mem.splitScalar(u8, s, '/');
        while (it.next()) |c| {
            if (c.len == 0 or std.mem.eql(u8, c, ".")) continue;
            if (std.mem.eql(u8, c, "..")) {
                if (parts.items.len == 0) return error.EscapesRepo;
                _ = parts.pop();
                continue;
            }
            try parts.append(allocator, c);
        }
    }
    return std.mem.join(allocator, "/", parts.items);
}

/// Every `@import("...")` literal in `source`, in order.
const ImportIterator = struct {
    source: []const u8,
    pos: usize = 0,

    fn next(it: *ImportIterator) ?[]const u8 {
        const needle = "@import(\"";
        const start = std.mem.indexOfPos(u8, it.source, it.pos, needle) orelse return null;
        const lit_start = start + needle.len;
        const lit_end = std.mem.indexOfScalarPos(u8, it.source, lit_start, '"') orelse return null;
        it.pos = lit_end + 1;
        return it.source[lit_start..lit_end];
    }
};

test "profiles import graph is std-only" {
    const allocator = testing.allocator;
    const io = testing.io;

    var repo = try Io.Dir.cwd().openDir(io, build_options.repo_root, .{});
    defer repo.close(io);

    var visited: std.StringArrayHashMapUnmanaged(void) = .empty;
    defer {
        for (visited.keys()) |k| allocator.free(k);
        visited.deinit(allocator);
    }
    try visited.put(allocator, try allocator.dupe(u8, profiles_root), {});

    var failures: usize = 0;
    var i: usize = 0;
    while (i < visited.count()) : (i += 1) {
        const path = visited.keys()[i];
        const source = try repo.readFileAlloc(io, path, allocator, .limited(max_source_bytes));
        defer allocator.free(source);
        const dir = std.fs.path.dirname(path) orelse "";
        var it: ImportIterator = .{ .source = source };
        while (it.next()) |imp| {
            if (!std.mem.endsWith(u8, imp, ".zig")) {
                if (!isAllowedModule(imp)) {
                    failures += 1;
                    std.debug.print("{s}: imports module \"{s}\"; only std is allowed\n", .{ path, imp });
                }
                continue;
            }
            const target = try joinNormalized(allocator, dir, imp);
            if (!isAllowedFile(target)) {
                failures += 1;
                std.debug.print("{s}: imports \"{s}\" ({s}), outside src/profiles, src/wire and core/events.zig\n", .{ path, imp, target });
                allocator.free(target);
                continue;
            }
            if (visited.contains(target)) {
                allocator.free(target);
            } else {
                try visited.put(allocator, target, {});
            }
        }
    }
    // The closure must reach the three schema files and the value types,
    // or the guard is checking the wrong thing.
    for ([_][]const u8{ "src/profiles/qmsg.zig", "src/profiles/qmesh.zig", "src/profiles/studio.zig", "src/core/events.zig", "src/wire/txt.zig" }) |must| {
        try testing.expect(visited.contains(must));
    }
    try testing.expect(!visited.contains("src/service.zig"));
    try testing.expect(!visited.contains("src/core/engine.zig"));
    if (failures != 0) return error.ProfilesImportGraphNotStdOnly;
}

// ---- helpers --------------------------------------------------------------

const Addr = Io.net.IpAddress;

fn v4(bytes: [4]u8, port: u16) Addr {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

fn v6(bytes: [16]u8, port: u16, scope: u32) Addr {
    return .{ .ip6 = .{ .bytes = bytes, .port = port, .interface = .{ .index = scope } } };
}

fn global6(last: u8) [16]u8 {
    var a: [16]u8 = @splat(0);
    a[0] = 0x2a;
    a[1] = 0x01;
    a[15] = last;
    return a;
}

/// A `Resolved` value as the Engine would emit it, from parts.
fn resolvedWith(service_type: []const u8, instance: []const u8, port: u16, pairs: []const mdns.TxtPair, addrs: []const Addr, ifindex: u32) !Resolved {
    var r: Resolved = .{
        .instance = packets.instanceName(instance, service_type),
        .service_type = packets.typeName(service_type),
        .host = packets.hostName("host-x"),
        .port = port,
        .txt = try mdns.Txt.build(pairs),
        .ifindex = ifindex,
        .ttl_s = 120,
    };
    for (addrs) |a| try r.addrs.append(a);
    return r;
}

const spki_a: [32]u8 = @splat(0xa1);
const id_b: [32]u8 = @splat(0xb2);

fn hexOf(d: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(d, .lower);
}

/// One Engine browsing `service_type` on ifindex 3; `deliver` feeds a
/// response built from a `ServiceDesc` and returns the `resolved` event.
const Rig = struct {
    sc: scenario.Scenario,
    e: Engine,
    sink: scenario.Sink,

    fn init(service_type: []const u8) !*Rig {
        const r = try testing.allocator.create(Rig);
        errdefer testing.allocator.destroy(r);
        r.sc = .init(0x5eed);
        r.e = try Engine.init(testing.allocator, .{ .host_label = "rig", .random = r.sc.random() });
        errdefer r.e.deinit();
        r.sink = .init(testing.allocator);
        try r.e.setInterfaces(&.{fake_lan.ifaceDual(3, "en0", .{ 10, 0, 3, 1 }, 24, 1)}, 0);
        _ = try r.e.browse(service_type, 0);
        _ = try r.sink.drain(&r.e);
        r.sink.clear();
        return r;
    }

    fn deinit(r: *Rig) void {
        r.sink.deinit();
        r.e.deinit();
        testing.allocator.destroy(r);
    }

    /// PTR + SRV + TXT + A + AAAA for `desc`, through the codec and the
    /// Engine's cache, as a peer's announcement would arrive.
    fn deliver(r: *Rig, desc: mdns.ServiceDesc) !Resolved {
        var buf: [1472]u8 = undefined;
        var p: Packet = .response(&buf);
        try p.ptr(desc.service_type, desc.instance, 4500);
        try p.srv(desc.instance, desc.service_type, desc.port, "host-x", 120, true);
        try p.txt(desc.instance, desc.service_type, desc.txt, 4500, true);
        try p.a("host-x", .{ 10, 0, 3, 9 }, 120, true);
        try p.aaaa("host-x", fake_lan.linkLocal6(9), 120, true);
        r.sc.advanceMs(10);
        r.e.handle(p.bytes(), .{ .from = v4(.{ 10, 0, 3, 9 }, 5353), .ifindex = 3, .dst_multicast = true }, r.sc.nowUs());
        _ = try r.sink.drain(&r.e);
        const ev = r.sink.last(.resolved) orelse return error.NoResolved;
        return ev.resolved;
    }
};

// ---- round trips ----------------------------------------------------------

test "qmsg advert round trips through the Engine" {
    var r = try Rig.init(profiles.qmsg.service_type);
    defer r.deinit();
    var ad = try profiles.qmsg.Advert.init(.{ .instance = "alice", .port = 4433, .spki = spki_a, .sn = "alice.example", .pat = 0xdead_beef });
    const res = try r.deliver(ad.desc());
    try testing.expectEqual(@as(u16, 4433), res.port);
    try wire.name.expectText("alice._qmsg._udp.local", res.instance);
    // The TXT crossed the wire in schema order with txtvers first.
    var it = res.txt.iterate();
    try testing.expectEqualStrings("txtvers", it.next().?.key);
    try testing.expectEqualStrings("alpn", it.next().?.key);
    const p = try profiles.qmsg.Parsed.parse(&res);
    try testing.expectEqualSlices(u8, &spki_a, &p.spki);
    try testing.expectEqualStrings("alice.example", p.sn.slice());
    try testing.expectEqual(@as(?u64, 0xdead_beef), p.pat);
    // Without pat.
    var ad2 = try profiles.qmsg.Advert.init(.{ .instance = "bob", .port = 1, .spki = spki_a, .sn = "b" });
    const res2 = try r.deliver(ad2.desc());
    const p2 = try profiles.qmsg.Parsed.parse(&res2);
    try testing.expectEqual(@as(?u64, null), p2.pat);
    try testing.expectEqualStrings("b", p2.sn.slice());
}

test "qmesh advert round trips through the Engine" {
    var r = try Rig.init(profiles.qmesh.service_type);
    defer r.deinit();
    const epoch: u128 = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210;
    var ad = try profiles.qmesh.Advert.init(.{ .port = 7000, .id = id_b, .epoch = epoch });
    const res = try r.deliver(ad.desc());
    try wire.name.expectText("b2b2b2b2b2b2b2b2._qmesh._udp.local", res.instance);
    const p = try profiles.qmesh.Parsed.parse(&res);
    try testing.expectEqualSlices(u8, &id_b, &p.id);
    try testing.expectEqual(epoch, p.epoch.value);
    try testing.expectEqual(@as(u8, 16), p.epoch.len);
    // The same value through SeedSet yields one contact with the v4 address.
    var seeds: profiles.qmesh.SeedSet = .{};
    const c = seeds.accept(&res) orelse return error.NoContact;
    try testing.expectEqualSlices(u8, &id_b, &c.id);
    try testing.expectEqual(@as(u32, 3), c.ifindex);
    try testing.expectEqual(v4(.{ 10, 0, 3, 9 }, 7000), c.addr);
}

test "studio advert round trips through the Engine" {
    var r = try Rig.init(profiles.studio.service_type);
    defer r.deinit();
    var ad = try profiles.studio.Advert.init(.{ .instance = "Alice Ⅱ", .port = 5000, .spki = spki_a, .epoch = 0xfeed_face_cafe_f00d, .role = .conductor });
    const res = try r.deliver(ad.desc());
    const p = try profiles.studio.Parsed.parse(&res);
    try testing.expectEqualSlices(u8, &spki_a, &p.spki);
    try testing.expectEqual(@as(u128, 0xfeed_face_cafe_f00d), p.epoch.value);
    try testing.expectEqual(@as(u8, 8), p.epoch.len);
    try testing.expectEqual(profiles.studio.Role.conductor, p.role);
    try testing.expectEqualStrings("shared-studio", res.txt.get("sn").?);
    try testing.expectEqualStrings("v2", res.txt.get("clip").?);
}

test "Engine.advertise accepts every profile desc" {
    var sc: scenario.Scenario = .init(1);
    var e = try Engine.init(testing.allocator, .{ .host_label = "adv", .random = sc.random() });
    defer e.deinit();
    var a = try profiles.qmsg.Advert.init(.{ .instance = "alice", .port = 4433, .spki = spki_a, .sn = "alice.example", .pat = 1 });
    var b = try profiles.qmesh.Advert.init(.{ .port = 7000, .id = id_b, .epoch = 1 });
    var c = try profiles.studio.Advert.init(.{ .instance = "Alice", .port = 5000, .spki = spki_a, .epoch = 1, .role = .performer });
    const ra = try e.advertise(a.desc(), 0);
    const rb = try e.advertise(b.desc(), 0);
    const rc = try e.advertise(c.desc(), 0);
    try testing.expect(ra != rb and rb != rc);
    // updateTxt with the re-rendered pairs after a field change.
    b.setEpoch(2);
    try e.updateTxt(rb, b.txt(), 0);
    a.setPat(null);
    try e.updateTxt(ra, a.txt(), 0);
    c.setRole(.conductor);
    try e.updateTxt(rc, c.txt(), 0);
}

test "profile TXT stays under 400 B at maximal field lengths" {
    const max_sn: [profiles.max_server_name_len]u8 = @splat('s');
    var a = try profiles.qmsg.Advert.init(.{ .instance = "x", .port = 1, .spki = @splat(0xff), .sn = &max_sn, .pat = std.math.maxInt(u64) });
    const ta = try mdns.Txt.build(a.txt());
    try testing.expect(ta.slice().len < profiles.max_txt_len);
    try testing.expectEqual(@as(usize, 10 + 12 + 70 + 256 + 21), ta.slice().len);

    var b = try profiles.qmesh.Advert.init(.{ .port = 1, .id = @splat(0xff), .epoch = std.math.maxInt(u128) });
    const tb = try mdns.Txt.build(b.txt());
    try testing.expect(tb.slice().len < profiles.max_txt_len);
    try testing.expectEqual(@as(usize, 10 + 13 + 5 + 68 + 39), tb.slice().len);

    var c = try profiles.studio.Advert.init(.{ .instance = "x", .port = 1, .spki = @splat(0xff), .epoch = std.math.maxInt(u64), .role = .performer });
    const tc = try mdns.Txt.build(c.txt());
    try testing.expect(tc.slice().len < profiles.max_txt_len);
    try testing.expectEqual(@as(usize, 10 + 12 + 70 + 23 + 15 + 17 + 8), tc.slice().len);
}

// ---- parser rules (plan section 3.4) -------------------------------------

test "spki must be 64 lowercase hex" {
    const good = hexOf(spki_a);
    // Accepted.
    {
        const r = try qmsgRes(&good);
        const p = try profiles.qmsg.Parsed.parse(&r);
        try testing.expectEqualSlices(u8, &spki_a, &p.spki);
    }
    // Uppercase.
    {
        var upper = good;
        upper[0] = 'A';
        const r = try qmsgRes(&upper);
        try testing.expectError(error.InvalidDigest, profiles.qmsg.Parsed.parse(&r));
    }
    // 63 and 65 digits.
    {
        const r = try qmsgRes(good[0..63]);
        try testing.expectError(error.InvalidDigest, profiles.qmsg.Parsed.parse(&r));
        const long: [65]u8 = @splat('a');
        const r2 = try qmsgRes(&long);
        try testing.expectError(error.InvalidDigest, profiles.qmsg.Parsed.parse(&r2));
    }
    // A non-hex octet; a `_` separator that std.fmt.parseUnsigned would take.
    {
        var bad = good;
        bad[10] = 'g';
        const r = try qmsgRes(&bad);
        try testing.expectError(error.InvalidDigest, profiles.qmsg.Parsed.parse(&r));
        bad[10] = '_';
        const r2 = try qmsgRes(&bad);
        try testing.expectError(error.InvalidDigest, profiles.qmsg.Parsed.parse(&r2));
    }
    // Missing, and a boolean `spki` attribute.
    {
        const r = try resolvedWith("_qmsg._udp", "a", 1, &.{ .{ .key = "txtvers", .value = "1" }, .{ .key = "sn", .value = "s" } }, &.{}, 3);
        try testing.expectError(error.MissingKey, profiles.qmsg.Parsed.parse(&r));
        const r2 = try resolvedWith("_qmsg._udp", "a", 1, &.{ .{ .key = "txtvers", .value = "1" }, .{ .key = "sn", .value = "s" }, .{ .key = "spki" } }, &.{}, 3);
        try testing.expectError(error.MissingKey, profiles.qmsg.Parsed.parse(&r2));
    }
    // The same rule for the qmesh `id`.
    {
        var upper = good;
        upper[63] = 'F';
        const r = try resolvedWith("_qmesh._udp", "a", 1, &.{ .{ .key = "id", .value = &upper }, .{ .key = "epoch", .value = "1" } }, &.{}, 3);
        try testing.expectError(error.InvalidDigest, profiles.qmesh.Parsed.parse(&r));
    }
}

/// A `_qmsg._udp` Resolved with `txtvers=1`, `sn=s` and the given `spki`
/// value.
fn qmsgRes(spki_value: []const u8) !Resolved {
    return resolvedWith("_qmsg._udp", "a", 1, &.{ .{ .key = "txtvers", .value = "1" }, .{ .key = "sn", .value = "s" }, .{ .key = "spki", .value = spki_value } }, &.{}, 3);
}

test "epoch accepts 16 and 32 hex" {
    const id_hex = hexOf(id_b);
    const Case = struct { hex: []const u8, value: u128, len: u8 };
    const cases = [_]Case{
        .{ .hex = "0000000000000001", .value = 1, .len = 8 },
        .{ .hex = "ffffffffffffffff", .value = std.math.maxInt(u64), .len = 8 },
        .{ .hex = "00000000000000000000000000000001", .value = 1, .len = 16 },
        .{ .hex = "0123456789abcdeffedcba9876543210", .value = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210, .len = 16 },
        .{ .hex = "1", .value = 1, .len = 1 },
        .{ .hex = "abc", .value = 0xabc, .len = 2 },
        .{ .hex = "DEADBEEF", .value = 0xdead_beef, .len = 4 },
    };
    for (cases) |c| {
        const r = try resolvedWith("_qmesh._udp", "a", 1, &.{ .{ .key = "id", .value = &id_hex }, .{ .key = "epoch", .value = c.hex } }, &.{}, 3);
        const p = try profiles.qmesh.Parsed.parse(&r);
        try testing.expectEqual(c.value, p.epoch.value);
        try testing.expectEqual(c.len, p.epoch.len);
        const s = try resolvedWith("_shared-studio._udp", "a", 1, &.{ .{ .key = "spki", .value = &id_hex }, .{ .key = "epoch", .value = c.hex }, .{ .key = "role", .value = "performer" } }, &.{}, 3);
        const ps = try profiles.studio.Parsed.parse(&s);
        try testing.expectEqual(c.value, ps.epoch.value);
        try testing.expectEqual(c.len, ps.epoch.len);
    }
    // 33 digits, empty, a separator, a non-hex octet, missing.
    const bad = [_][]const u8{ "000000000000000000000000000000001", "", "dead_beef", "xyz" };
    for (bad) |h| {
        const r = try resolvedWith("_qmesh._udp", "a", 1, &.{ .{ .key = "id", .value = &id_hex }, .{ .key = "epoch", .value = h } }, &.{}, 3);
        try testing.expectError(error.InvalidEpoch, profiles.qmesh.Parsed.parse(&r));
    }
    const missing = try resolvedWith("_qmesh._udp", "a", 1, &.{.{ .key = "id", .value = &id_hex }}, &.{}, 3);
    try testing.expectError(error.MissingKey, profiles.qmesh.Parsed.parse(&missing));
}

test "parsers check txtvers, alpn, fixed keys and the service type" {
    const spki_hex = hexOf(spki_a);
    const ok = [_]mdns.TxtPair{ .{ .key = "spki", .value = &spki_hex }, .{ .key = "sn", .value = "s" } };
    // Unknown keys are ignored; txtvers may be absent.
    {
        const r = try resolvedWith("_qmsg._udp", "a", 1, &.{ ok[0], ok[1], .{ .key = "future", .value = "x" }, .{ .key = "flag" } }, &.{}, 3);
        _ = try profiles.qmsg.Parsed.parse(&r);
    }
    {
        const r = try resolvedWith("_qmsg._udp", "a", 1, &.{ .{ .key = "txtvers", .value = "2" }, ok[0], ok[1] }, &.{}, 3);
        try testing.expectError(error.TxtVersionMismatch, profiles.qmsg.Parsed.parse(&r));
    }
    {
        const r = try resolvedWith("_qmsg._udp", "a", 1, &.{ .{ .key = "alpn", .value = "qmsg/2" }, ok[0], ok[1] }, &.{}, 3);
        try testing.expectError(error.AlpnMismatch, profiles.qmsg.Parsed.parse(&r));
    }
    // pat rules.
    {
        const r = try resolvedWith("_qmsg._udp", "a", 1, &.{ ok[0], ok[1], .{ .key = "pat", .value = "10000000000000000" } }, &.{}, 3);
        try testing.expectError(error.InvalidPat, profiles.qmsg.Parsed.parse(&r));
        const r2 = try resolvedWith("_qmsg._udp", "a", 1, &.{ ok[0], ok[1], .{ .key = "pat", .value = "3" } }, &.{}, 3);
        try testing.expectEqual(@as(?u64, 3), (try profiles.qmsg.Parsed.parse(&r2)).pat);
    }
    // sn rules for qmsg.
    {
        const r = try resolvedWith("_qmsg._udp", "a", 1, &.{.{ .key = "spki", .value = &spki_hex }}, &.{}, 3);
        try testing.expectError(error.MissingKey, profiles.qmsg.Parsed.parse(&r));
        const r2 = try resolvedWith("_qmsg._udp", "a", 1, &.{ .{ .key = "spki", .value = &spki_hex }, .{ .key = "sn", .value = "" } }, &.{}, 3);
        try testing.expectError(error.InvalidServerName, profiles.qmsg.Parsed.parse(&r2));
    }
    // A qmsg Resolved fed to the studio parser, and the reverse.
    {
        const r = try resolvedWith("_qmsg._udp", "a", 1, &ok, &.{}, 3);
        try testing.expectError(error.WrongServiceType, profiles.studio.Parsed.parse(&r));
        try testing.expectError(error.WrongServiceType, profiles.qmesh.Parsed.parse(&r));
        const s = try resolvedWith("_shared-studio._udp", "a", 1, &ok, &.{}, 3);
        try testing.expectError(error.WrongServiceType, profiles.qmsg.Parsed.parse(&s));
        // Case-insensitive type labels.
        const u = try resolvedWith("_QMSG._UDP", "a", 1, &ok, &.{}, 3);
        _ = try profiles.qmsg.Parsed.parse(&u);
    }
    // qmesh fv and studio sn/clip are fixed-value keys.
    {
        const id_hex = hexOf(id_b);
        const r = try resolvedWith("_qmesh._udp", "a", 1, &.{ .{ .key = "id", .value = &id_hex }, .{ .key = "epoch", .value = "1" }, .{ .key = "fv", .value = "3" } }, &.{}, 3);
        try testing.expectError(error.FormatMismatch, profiles.qmesh.Parsed.parse(&r));
        const s = try resolvedWith("_shared-studio._udp", "a", 1, &.{ .{ .key = "spki", .value = &spki_hex }, .{ .key = "epoch", .value = "1" }, .{ .key = "role", .value = "performer" }, .{ .key = "sn", .value = "other" } }, &.{}, 3);
        try testing.expectError(error.InvalidServerName, profiles.studio.Parsed.parse(&s));
        const t = try resolvedWith("_shared-studio._udp", "a", 1, &.{ .{ .key = "spki", .value = &spki_hex }, .{ .key = "epoch", .value = "1" }, .{ .key = "role", .value = "performer" }, .{ .key = "clip", .value = "v1" } }, &.{}, 3);
        try testing.expectError(error.FormatMismatch, profiles.studio.Parsed.parse(&t));
    }
}

test "_shared-studio._udp role enum round trips" {
    const Role = profiles.studio.Role;
    inline for (@typeInfo(Role).@"enum".field_names) |name| {
        const role: Role = @field(Role, name);
        try testing.expectEqualStrings(name, role.label());
        try testing.expectEqual(role, Role.parse(role.label()).?);
    }
    try testing.expectEqual(Role.conductor, Role.parse("conductor").?);
    try testing.expectEqual(Role.performer, Role.parse("performer").?);
    try testing.expect(Role.parse("Conductor") == null);
    try testing.expect(Role.parse("") == null);
    try testing.expect(Role.parse("performer ") == null);
    // Through a Resolved: each role parses back; an unknown role and a
    // missing role are rejected.
    const spki_hex = hexOf(spki_a);
    for ([_]Role{ .conductor, .performer }) |role| {
        const r = try resolvedWith("_shared-studio._udp", "a", 1, &.{ .{ .key = "spki", .value = &spki_hex }, .{ .key = "epoch", .value = "1" }, .{ .key = "role", .value = role.label() } }, &.{}, 3);
        try testing.expectEqual(role, (try profiles.studio.Parsed.parse(&r)).role);
    }
    const bad = try resolvedWith("_shared-studio._udp", "a", 1, &.{ .{ .key = "spki", .value = &spki_hex }, .{ .key = "epoch", .value = "1" }, .{ .key = "role", .value = "audience" } }, &.{}, 3);
    try testing.expectError(error.InvalidRole, profiles.studio.Parsed.parse(&bad));
    const none = try resolvedWith("_shared-studio._udp", "a", 1, &.{ .{ .key = "spki", .value = &spki_hex }, .{ .key = "epoch", .value = "1" } }, &.{}, 3);
    try testing.expectError(error.MissingKey, profiles.studio.Parsed.parse(&none));
}

// ---- SeedSet ----------------------------------------------------------------

test "qmesh SeedSet emits once per (id, epoch)" {
    const id_hex = hexOf(id_b);
    var seeds: profiles.qmesh.SeedSet = .{};
    const first = try resolvedWith("_qmesh._udp", "n", 7000, &.{ .{ .key = "id", .value = &id_hex }, .{ .key = "epoch", .value = "0a" } }, &.{v4(.{ 10, 0, 3, 9 }, 0)}, 3);

    const c1 = seeds.accept(&first) orelse return error.NoContact;
    try testing.expectEqualSlices(u8, &id_b, &c1.id);
    try testing.expectEqual(@as(u128, 0x0a), c1.epoch);
    try testing.expectEqual(v4(.{ 10, 0, 3, 9 }, 7000), c1.addr);
    try testing.expectEqual(@as(u32, 3), c1.ifindex);

    // The same resolved again (a refresh the Engine would not even
    // re-emit) and the same (id, epoch) on another interface: nothing.
    try testing.expect(seeds.accept(&first) == null);
    var other_if = first;
    other_if.ifindex = 4;
    try testing.expect(seeds.accept(&other_if) == null);
    // An address-set change under the same epoch: nothing.
    var moved = first;
    moved.addrs.clear();
    try moved.addrs.append(v4(.{ 10, 0, 3, 10 }, 0));
    try testing.expect(seeds.accept(&moved) == null);
    try testing.expectEqual(@as(u64, 3), seeds.stats.duplicates);

    // A new epoch (the peer restarted and called updateTxt): admitted
    // again, once.
    const restarted = try resolvedWith("_qmesh._udp", "n", 7000, &.{ .{ .key = "id", .value = &id_hex }, .{ .key = "epoch", .value = "0b" } }, &.{v4(.{ 10, 0, 3, 9 }, 0)}, 3);
    const c2 = seeds.accept(&restarted) orelse return error.NoContact;
    try testing.expectEqual(@as(u128, 0x0b), c2.epoch);
    try testing.expect(seeds.accept(&restarted) == null);
    // The old epoch is still remembered.
    try testing.expect(seeds.accept(&first) == null);
    try testing.expectEqual(@as(usize, 2), seeds.len);

    // A different id with the same epoch is its own pair.
    const other_hex = hexOf(spki_a);
    const other = try resolvedWith("_qmesh._udp", "m", 7001, &.{ .{ .key = "id", .value = &other_hex }, .{ .key = "epoch", .value = "0a" } }, &.{v4(.{ 10, 0, 3, 11 }, 0)}, 3);
    const c3 = seeds.accept(&other) orelse return error.NoContact;
    try testing.expectEqualSlices(u8, &spki_a, &c3.id);

    // An invalid advert (bad id) is counted, not admitted; a later valid
    // one for the same pair still passes.
    const bad = try resolvedWith("_qmesh._udp", "z", 1, &.{ .{ .key = "id", .value = "zz" }, .{ .key = "epoch", .value = "1" } }, &.{v4(.{ 10, 0, 3, 12 }, 0)}, 3);
    try testing.expect(seeds.accept(&bad) == null);
    try testing.expectEqual(@as(u64, 1), seeds.stats.rejected);

    // forget re-admits.
    try testing.expectEqual(@as(usize, 2), seeds.forget(id_b));
    try testing.expect(seeds.accept(&first) != null);
}

test "SeedSet drops fe80 without scope and prefers v4 then global v6" {
    const id_hex = hexOf(id_b);
    const pairs = [_]mdns.TxtPair{ .{ .key = "id", .value = &id_hex }, .{ .key = "epoch", .value = "1" } };
    var seeds: profiles.qmesh.SeedSet = .{};

    // Only an unscoped link-local: no contact, and the pair is not
    // consumed, so a later resolved with a usable address passes.
    const ll_only = try resolvedWith("_qmesh._udp", "n", 7000, &pairs, &.{v6(fake_lan.linkLocal6(9), 0, 0)}, 3);
    try testing.expect(seeds.accept(&ll_only) == null);
    try testing.expectEqual(@as(u64, 1), seeds.stats.no_addr);
    try testing.expectEqual(@as(usize, 0), seeds.len);

    // Scoped link-local alone is usable, and keeps its scope.
    const ll_scoped = try resolvedWith("_qmesh._udp", "n", 7000, &pairs, &.{v6(fake_lan.linkLocal6(9), 0, 3)}, 3);
    const c = seeds.accept(&ll_scoped) orelse return error.NoContact;
    try testing.expectEqual(v6(fake_lan.linkLocal6(9), 7000, 3), c.addr);
    seeds.clear();

    // Global v6 beats link-local; v4 beats both, whatever the order.
    const mixed = try resolvedWith("_qmesh._udp", "n", 7000, &pairs, &.{ v6(fake_lan.linkLocal6(9), 0, 3), v6(global6(7), 0, 0) }, 3);
    try testing.expectEqual(v6(global6(7), 7000, 0), seeds.accept(&mixed).?.addr);
    seeds.clear();
    const with_v4 = try resolvedWith("_qmesh._udp", "n", 7000, &pairs, &.{ v6(global6(7), 0, 0), v6(fake_lan.linkLocal6(9), 0, 3), v4(.{ 10, 0, 3, 9 }, 0) }, 3);
    try testing.expectEqual(v4(.{ 10, 0, 3, 9 }, 7000), seeds.accept(&with_v4).?.addr);
    seeds.clear();

    // Unspecified addresses are skipped.
    const zeros = try resolvedWith("_qmesh._udp", "n", 7000, &pairs, &.{ v4(.{ 0, 0, 0, 0 }, 0), v6(@splat(0), 0, 0), v6(global6(1), 0, 0) }, 3);
    try testing.expectEqual(v6(global6(1), 7000, 0), seeds.accept(&zeros).?.addr);
    try testing.expectEqual(v6(global6(1), 7000, 0), profiles.qmesh.pickAddr(&zeros).?);
    try testing.expect(profiles.qmesh.pickAddr(&ll_only) == null);
}
