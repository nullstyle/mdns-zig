//! Fixture corpus loader for the wire-codec tests (plan §7 M1, §8 tier 2).
//!
//! Iterates `tests/fixtures/raw/NNNN.hex` + `NNNN.json` in ascending stem
//! order, decodes each datagram into a caller buffer and parses the JSON
//! sidecar (`tests/fixtures/README.md`, "Sidecar schema"). Test-only: it
//! allocates (directory listing, JSON arena) with the allocator the test
//! passes in, which is `std.testing.allocator` everywhere.
//!
//! The repo path comes from the `repo_root` build option (`build.zig`
//! `build_options`), so the test binary does not depend on its cwd.
const std = @import("std");
const Io = std.Io;
const build_options = @import("build_options");

/// Repo-relative directory holding the corpus.
pub const raw_dir = "tests/fixtures/raw";

/// Largest UDP payload the capture spike writes (RFC 6762 §17: 9000 B
/// including IP and UDP headers); a caller buffer of this size fits every
/// fixture.
pub const max_datagram = 9000;

pub const Family = enum { v4, v6 };

/// Parsed sidecar fields a codec test needs. `captured_with` and
/// `tool_running` are provenance only and are skipped
/// (`ignore_unknown_fields`), so a sidecar with extra fields stays valid.
pub const Sidecar = struct {
    source: []const u8,
    ifindex: u32,
    family: Family,
    len: u32,
};

/// One decoded fixture. A plain value: the name and source live in inline
/// buffers (read them through `stem()` and `source()`), and `bytes` points
/// into the caller's buffer passed to `Iterator.next`.
pub const Fixture = struct {
    /// Decoded datagram; a slice of the caller's buffer.
    bytes: []const u8,
    ifindex: u32,
    family: Family,
    /// `len` from the sidecar, as recorded by the spike. The unit test below
    /// proves `bytes.len == len` for every committed fixture.
    len: u32,

    stem_buf: [max_stem]u8 = @splat(0),
    stem_len: u8 = 0,
    source_buf: [max_source]u8 = @splat(0),
    source_len: u8 = 0,

    /// Room for an IPv6 source in `IpAddress` format: `[` + 39 hex/colon
    /// chars + `]:65535`.
    pub const max_source = 64;
    pub const max_stem = 16;

    /// Zero-padded sequence number, e.g. "0011".
    pub fn stem(f: *const Fixture) []const u8 {
        return f.stem_buf[0..f.stem_len];
    }

    /// Sender as the sidecar records it: `a.b.c.d:port` or `[v6]:port`.
    pub fn source(f: *const Fixture) []const u8 {
        return f.source_buf[0..f.source_len];
    }
};

pub const Error = error{
    /// `.hex` is not a single line of lowercase hex pairs.
    BadHex,
    /// `.hex` decodes to more bytes than the caller buffer holds.
    DatagramTooLong,
    /// Sidecar `source` longer than `Fixture.max_source`.
    SourceTooLong,
    /// Sidecar JSON did not match `Sidecar`.
    BadSidecar,
    /// A `.hex` without a `.json` (or the reverse).
    MissingSidecar,
};

/// Ordered iterator over the corpus. `init` lists the directory once and
/// sorts the stems; `next` reads one pair per call.
pub const Iterator = struct {
    allocator: std.mem.Allocator,
    dir: Io.Dir,
    stems: std.ArrayList(Stem),
    index: usize = 0,

    const Stem = struct {
        buf: [Fixture.max_stem]u8,
        len: u8,

        fn slice(s: *const Stem) []const u8 {
            return s.buf[0..s.len];
        }

        /// Stems are zero-padded to one width ("0011"), so a plain byte
        /// compare is the numeric order.
        fn lessThan(_: void, a: Stem, b: Stem) bool {
            return std.mem.lessThan(u8, a.slice(), b.slice());
        }
    };

    pub fn init(allocator: std.mem.Allocator, io: Io) !Iterator {
        const path = try std.fs.path.join(allocator, &.{ build_options.repo_root, raw_dir });
        defer allocator.free(path);
        var dir = try Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
        errdefer dir.close(io);

        var stems: std.ArrayList(Stem) = .empty;
        errdefer stems.deinit(allocator);

        var it = dir.iterate();
        while (try it.next(io)) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".hex")) continue;
            const stem = entry.name[0 .. entry.name.len - ".hex".len];
            if (stem.len == 0 or stem.len > Fixture.max_stem) return error.BadPathName;
            var s: Stem = .{ .buf = @splat(0), .len = @intCast(stem.len) };
            @memcpy(s.buf[0..stem.len], stem);
            try stems.append(allocator, s);
        }
        std.mem.sort(Stem, stems.items, {}, Stem.lessThan);

        return .{ .allocator = allocator, .dir = dir, .stems = stems };
    }

    pub fn deinit(self: *Iterator, io: Io) void {
        self.stems.deinit(self.allocator);
        self.dir.close(io);
        self.* = undefined;
    }

    /// Number of `.hex` files found by `init`.
    pub fn count(self: *const Iterator) usize {
        return self.stems.items.len;
    }

    /// Reads the next fixture. `buf` receives the decoded datagram and must
    /// hold at least `max_datagram` bytes to fit every committed fixture.
    /// The returned `Fixture` is a value; its slices point into `buf` and
    /// into the `Fixture` itself, so copy it before reusing `buf`.
    pub fn next(self: *Iterator, io: Io, buf: []u8) !?Fixture {
        if (self.index >= self.stems.items.len) return null;
        const stem = self.stems.items[self.index].slice();
        self.index += 1;

        var fx: Fixture = .{ .bytes = &.{}, .ifindex = 0, .family = .v4, .len = 0 };
        @memcpy(fx.stem_buf[0..stem.len], stem);
        fx.stem_len = @intCast(stem.len);

        // ---- NNNN.hex --------------------------------------------------
        var name_buf: [Fixture.max_stem + 5]u8 = undefined;
        const hex_name = try std.fmt.bufPrint(&name_buf, "{s}.hex", .{stem});
        const hex_text = try self.dir.readFileAlloc(io, hex_name, self.allocator, .limited(max_datagram * 2 + 16));
        defer self.allocator.free(hex_text);
        const hex = std.mem.trim(u8, hex_text, "\r\n");
        for (hex) |c| {
            const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
            if (!ok) return error.BadHex;
        }
        if (hex.len % 2 != 0) return error.BadHex;
        if (hex.len / 2 > buf.len) return error.DatagramTooLong;
        const bytes = std.fmt.hexToBytes(buf, hex) catch return error.BadHex;

        // ---- NNNN.json -------------------------------------------------
        const json_name = try std.fmt.bufPrint(&name_buf, "{s}.json", .{stem});
        const json_text = self.dir.readFileAlloc(io, json_name, self.allocator, .limited(64 * 1024)) catch |err| switch (err) {
            error.FileNotFound => return error.MissingSidecar,
            else => |e| return e,
        };
        defer self.allocator.free(json_text);
        const parsed = std.json.parseFromSlice(Sidecar, self.allocator, json_text, .{
            .ignore_unknown_fields = true,
        }) catch return error.BadSidecar;
        defer parsed.deinit();
        const sc = parsed.value;
        if (sc.source.len > Fixture.max_source) return error.SourceTooLong;
        @memcpy(fx.source_buf[0..sc.source.len], sc.source);
        fx.source_len = @intCast(sc.source.len);

        fx.bytes = bytes;
        fx.ifindex = sc.ifindex;
        fx.family = sc.family;
        fx.len = sc.len;
        return fx;
    }
};

test "fixtures load and hex length matches sidecar len" {
    const io = std.testing.io;
    var it = try Iterator.init(std.testing.allocator, io);
    defer it.deinit(io);
    try std.testing.expect(it.count() > 0);

    var buf: [max_datagram]u8 = undefined;
    var seen: usize = 0;
    var prev: [Fixture.max_stem]u8 = @splat(0);
    while (try it.next(io, &buf)) |fx| {
        seen += 1;
        // Ascending, unique stems.
        try std.testing.expect(std.mem.lessThan(u8, &prev, &fx.stem_buf));
        prev = fx.stem_buf;
        // The sidecar's `len` is the byte length of the payload.
        try std.testing.expectEqual(@as(usize, fx.len), fx.bytes.len);
        try std.testing.expect(fx.bytes.len > 0);
        // Every capture had a pktinfo cmsg and a non-empty source.
        try std.testing.expect(fx.ifindex != 0);
        try std.testing.expect(fx.source().len > 0);
        try std.testing.expectEqual(@as(usize, 4), fx.stem().len);
        // Sidecar family agrees with the source address syntax.
        switch (fx.family) {
            .v4 => try std.testing.expect(fx.source()[0] != '['),
            .v6 => try std.testing.expect(fx.source()[0] == '['),
        }
    }
    try std.testing.expectEqual(it.count(), seen);
}
