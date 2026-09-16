//! mdns-zig: std-only mDNS (RFC 6762) and DNS-SD (RFC 6763).
const std = @import("std");

pub const version = "0.1.0";

/// UDP port every mDNS packet uses (RFC 6762 section 2).
pub const port: u16 = 5353;

/// Zero-allocation codec: names, messages, rdata, TXT and the packet
/// builder (RFC 1035, RFC 6762, RFC 6763).
pub const wire = @import("wire/root.zig");

/// Fixed-capacity inline array used by every value type.
pub const Bounded = wire.Bounded;
pub const Name = wire.Name;
pub const Txt = wire.Txt;
pub const TxtPair = wire.TxtPair;

/// OS-facing layer: raw sockets, option numbers, cmsg codec, membership.
/// The Engine (M2+) never imports this; only `Service` does.
pub const platform = struct {
    pub const socket_opts = @import("platform/socket_opts.zig");
};

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(platform);
    _ = platform.socket_opts;
    _ = wire;
}

test "mdns port is 5353" {
    try std.testing.expectEqual(@as(u16, 5353), port);
}
