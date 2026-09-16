//! mdns-zig: std-only mDNS (RFC 6762) and DNS-SD (RFC 6763).
const std = @import("std");

pub const version = "0.1.0";

/// UDP port every mDNS packet uses (RFC 6762 section 2).
pub const port: u16 = 5353;

/// Zero-allocation codec: names, messages, rdata, TXT and the packet
/// builder (RFC 1035, RFC 6762, RFC 6763).
pub const wire = @import("wire/root.zig");

/// Sans-IO core: value types and events (M2), Engine (M3+). Never imports
/// `platform`.
pub const core = struct {
    pub const events = @import("core/events.zig");
    pub const engine = @import("core/engine.zig");
};

/// OS-facing layer: raw sockets, option numbers, cmsg codec, membership,
/// interface enumeration. The Engine never imports this; only `Service`
/// does.
pub const platform = struct {
    pub const socket_opts = @import("platform/socket_opts.zig");
    pub const ifaces = @import("platform/ifaces.zig");
};

/// The `std.Io` shell: sockets, interface table, loop modes, `Mailbox`.
pub const service = @import("service.zig");
pub const Service = service.Service;
pub const Mailbox = service.Mailbox;
/// Sans-IO core (M2: stub internals behind the final surface).
pub const Engine = core.engine.Engine;

// ---- public value types (plan section 5) -----------------------------

/// Fixed-capacity inline array used by every value type.
pub const Bounded = core.events.Bounded;
pub const Name = core.events.Name;
pub const Txt = core.events.Txt;
pub const TxtPair = core.events.TxtPair;
pub const Prefix4 = core.events.Prefix4;
pub const Prefix6 = core.events.Prefix6;
pub const Interface = core.events.Interface;
pub const ServiceDesc = core.events.ServiceDesc;
pub const Resolved = core.events.Resolved;
pub const RegId = core.events.RegId;
pub const BrowseId = core.events.BrowseId;
pub const Family = core.events.Family;
pub const Warning = core.events.Warning;
pub const Event = core.events.Event;
pub const Limits = core.events.Limits;
pub const Stats = core.events.Stats;

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(core);
    std.testing.refAllDecls(platform);
    _ = core.events;
    _ = core.engine;
    _ = service;
    _ = platform.socket_opts;
    _ = platform.ifaces;
    _ = wire;
}

test "mdns port is 5353" {
    try std.testing.expectEqual(@as(u16, 5353), port);
}
