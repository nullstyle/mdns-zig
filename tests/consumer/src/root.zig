const std = @import("std");
const mdns = @import("mdns");

test "consume the mdns module" {
    try std.testing.expectEqual(@as(u16, 5353), mdns.port);
}
