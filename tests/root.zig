//! Public-API tests for mdns-zig. Sibling test files are imported here as
//! the milestones add them (codec_test, responder_test, ...).
const std = @import("std");
const mdns = @import("mdns");

comptime {
    _ = @import("conformance_test.zig");
    _ = @import("codec_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("fixtures/loader.zig");
}

test {
    std.testing.refAllDecls(@This());
}

test "public module exposes the mdns port and the platform layer" {
    try std.testing.expectEqual(@as(u16, 5353), mdns.port);
    try std.testing.expectEqual(@as(u16, 5353), mdns.platform.socket_opts.mdns_port);
}
