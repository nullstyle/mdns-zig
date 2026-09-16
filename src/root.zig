//! mdns-zig: std-only mDNS (RFC 6762) and DNS-SD (RFC 6763).
const std = @import("std");

pub const version = "0.1.0";

/// UDP port every mDNS packet uses (RFC 6762 section 2).
pub const port: u16 = 5353;

/// OS-facing layer: raw sockets, option numbers, cmsg codec, membership.
/// The Engine (M2+) never imports this; only `Service` does.
pub const platform = struct {
    pub const socket_opts = @import("platform/socket_opts.zig");
};

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(platform);
    _ = platform.socket_opts;
}

test "mdns port is 5353" {
    try std.testing.expectEqual(@as(u16, 5353), port);
}
