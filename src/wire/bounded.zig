//! Fixed-capacity inline array. The value type behind `Name`, `Txt` and
//! the `Interface` address lists (plan section 5). No pointers into any
//! Engine state: copying a `Bounded` copies its contents.
const std = @import("std");

pub fn Bounded(comptime T: type, comptime cap: usize) type {
    return struct {
        const Self = @This();

        pub const capacity = cap;
        pub const Item = T;

        len: usize = 0,
        buf: [cap]T = undefined,

        pub fn fromSlice(items: []const T) error{NoSpace}!Self {
            if (items.len > cap) return error.NoSpace;
            var b: Self = .{};
            @memcpy(b.buf[0..items.len], items);
            b.len = items.len;
            return b;
        }

        pub fn slice(b: *const Self) []const T {
            return b.buf[0..b.len];
        }

        pub fn sliceMut(b: *Self) []T {
            return b.buf[0..b.len];
        }

        pub fn append(b: *Self, item: T) error{NoSpace}!void {
            if (b.len >= cap) return error.NoSpace;
            b.buf[b.len] = item;
            b.len += 1;
        }

        pub fn appendSlice(b: *Self, items: []const T) error{NoSpace}!void {
            if (cap - b.len < items.len) return error.NoSpace;
            @memcpy(b.buf[b.len..][0..items.len], items);
            b.len += items.len;
        }

        pub fn clear(b: *Self) void {
            b.len = 0;
        }

        pub fn isFull(b: *const Self) bool {
            return b.len == cap;
        }
    };
}

test "Bounded append, slice and overflow" {
    var b: Bounded(u8, 4) = .{};
    try b.append('a');
    try b.appendSlice("bc");
    try std.testing.expectEqualStrings("abc", b.slice());
    try b.append('d');
    try std.testing.expect(b.isFull());
    try std.testing.expectError(error.NoSpace, b.append('e'));
    try std.testing.expectError(error.NoSpace, b.appendSlice("x"));
    // An empty append onto a full buffer is fine.
    try b.appendSlice("");
    const c = try Bounded(u8, 4).fromSlice("wxyz");
    try std.testing.expectEqualStrings("wxyz", c.slice());
    try std.testing.expectError(error.NoSpace, Bounded(u8, 4).fromSlice("vwxyz"));
}
