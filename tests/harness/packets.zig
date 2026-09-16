//! Hand-built mDNS packets for the tier-1 tests: a thin wrapper over
//! `wire.Builder` that speaks DNS-SD (PTR / SRV / TXT / A / AAAA for a
//! service instance) so a test reads like the packet it injects.
//!
//! ```zig
//! var p: Packet = .response(&buf);
//! try p.ptr("_qmsg._udp", "alice", 4500);
//! try p.srv("alice", "_qmsg._udp", 4433, "host-a", 120, true);
//! try p.txt("alice", "_qmsg._udp", &.{ .{ .key = "spki", .value = "00" } }, 4500, true);
//! try p.a("host-a", .{ 10, 0, 3, 5 }, 120, true);
//! engine.handle(p.bytes(), meta, now);
//! ```
const std = @import("std");
const mdns = @import("mdns");
const wire = mdns.wire;

pub const Name = wire.Name;
pub const Builder = wire.Builder;
pub const Section = wire.Section;

/// `<type>.local`.
pub fn typeName(service_type: []const u8) Name {
    return mdns.core.querier.Querier.serviceTypeName(service_type) catch unreachable;
}

/// `<instance>.<type>.local`.
pub fn instanceName(instance: []const u8, service_type: []const u8) Name {
    return Name.serviceInstance(instance, service_type, "local") catch unreachable;
}

/// `<host>.local`.
pub fn hostName(host: []const u8) Name {
    var n = Name.parse(host) catch unreachable;
    n.appendName(Name.parse("local") catch unreachable) catch unreachable;
    return n;
}

pub const Packet = struct {
    b: Builder,
    section: Section = .answer,

    /// A multicast response (QR=1, AA=1, ID 0).
    pub fn response(buf: []u8) Packet {
        var b: Builder = .init(buf, .{});
        b.setId(0);
        b.setResponse();
        return .{ .b = b };
    }

    /// A response that may fill a 9000 B datagram (RFC 6762 section 17)
    /// instead of the 1472 B soft limit.
    pub fn responseLarge(buf: []u8) Packet {
        var b: Builder = .init(buf, .{ .soft_limit = 9000 });
        b.setId(0);
        b.setResponse();
        return .{ .b = b };
    }

    /// A query (QR=0, ID 0); records added after `question` land in the
    /// answer section as a known-answer list.
    pub fn query(buf: []u8) Packet {
        var b: Builder = .init(buf, .{});
        b.setId(0);
        return .{ .b = b };
    }

    /// Subsequent records go into `section` (answer -> additional).
    pub fn in(p: *Packet, section: Section) void {
        p.section = section;
    }

    pub fn bytes(p: *Packet) []const u8 {
        return p.b.finish();
    }

    pub fn question(p: *Packet, name: Name, rtype: wire.RType, qu: bool) !void {
        try p.b.addQuestion(name, rtype, wire.class_in, qu);
    }

    /// PTR `<type>.local -> <instance>.<type>.local` (shared: no
    /// cache-flush).
    pub fn ptr(p: *Packet, service_type: []const u8, instance: []const u8, ttl: u32) !void {
        try p.b.addRR(p.section, typeName(service_type), .ptr, wire.class_in, false, ttl, .{ .ptr = instanceName(instance, service_type) });
    }

    pub fn srv(p: *Packet, instance: []const u8, service_type: []const u8, port: u16, host: []const u8, ttl: u32, cache_flush: bool) !void {
        try p.b.addRR(p.section, instanceName(instance, service_type), .srv, wire.class_in, cache_flush, ttl, .{ .srv = .{ .port = port, .target = hostName(host) } });
    }

    pub fn txt(p: *Packet, instance: []const u8, service_type: []const u8, pairs: []const wire.TxtPair, ttl: u32, cache_flush: bool) !void {
        const t = try wire.Txt.build(pairs);
        try p.b.addRR(p.section, instanceName(instance, service_type), .txt, wire.class_in, cache_flush, ttl, .{ .txt = t.slice() });
    }

    /// Raw TXT rdata (for oversize or odd records).
    pub fn txtRaw(p: *Packet, instance: []const u8, service_type: []const u8, rdata: []const u8, ttl: u32, cache_flush: bool) !void {
        try p.b.addRR(p.section, instanceName(instance, service_type), .txt, wire.class_in, cache_flush, ttl, .{ .txt = rdata });
    }

    pub fn a(p: *Packet, host: []const u8, addr: [4]u8, ttl: u32, cache_flush: bool) !void {
        try p.b.addRR(p.section, hostName(host), .a, wire.class_in, cache_flush, ttl, .{ .a = addr });
    }

    pub fn aaaa(p: *Packet, host: []const u8, addr: [16]u8, ttl: u32, cache_flush: bool) !void {
        try p.b.addRR(p.section, hostName(host), .aaaa, wire.class_in, cache_flush, ttl, .{ .aaaa = addr });
    }

    /// A goodbye for the PTR (TTL 0, RFC 6762 section 10.1).
    pub fn ptrGoodbye(p: *Packet, service_type: []const u8, instance: []const u8) !void {
        try p.ptr(service_type, instance, 0);
    }
};

/// The four records a DNS-SD responder sends for one instance: PTR in the
/// answer section, SRV / TXT / A as additionals (RFC 6763 section 12).
pub fn fullInstance(buf: []u8, service_type: []const u8, instance: []const u8, host: []const u8, port: u16, addr: [4]u8) ![]const u8 {
    var p: Packet = .response(buf);
    try p.ptr(service_type, instance, 4500);
    p.in(.additional);
    try p.srv(instance, service_type, port, host, 120, true);
    try p.txt(instance, service_type, &.{.{ .key = "txtvers", .value = "1" }}, 4500, true);
    try p.a(host, addr, 120, true);
    return p.bytes();
}

test "packet helper builds a parseable DNS-SD response" {
    var buf: [1500]u8 = undefined;
    const bytes = try fullInstance(&buf, "_qmsg._udp", "alice", "host-a", 4433, .{ 10, 0, 3, 5 });
    const msg = try wire.Message.parse(bytes);
    try std.testing.expect(msg.isResponse());
    try std.testing.expectEqual(@as(u16, 1), msg.header.ancount);
    try std.testing.expectEqual(@as(u16, 3), msg.header.arcount);
    var it = msg.additional();
    const s = it.next().?;
    try std.testing.expectEqual(wire.RType.srv, s.rtype);
    try std.testing.expect(s.cache_flush);
    const srv = try wire.rdata.decodeSrv(bytes, s);
    try std.testing.expectEqual(@as(u16, 4433), srv.port);
    try wire.name.expectText("host-a.local", srv.target);
}
