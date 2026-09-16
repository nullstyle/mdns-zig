//! Conformance-matrix guard (plan §8, "Conformance tracking").
//!
//! `docs/conformance.md` maps each RFC clause to a Status and a test name.
//! This test reads that file at runtime, takes every table row whose
//! Status cell is exactly `done`, and requires each backticked name in
//! its Test name cell to appear as `test "<name>"` in some `.zig` file
//! under `src/` or `tests/`. Renaming or deleting a test named in the
//! matrix therefore fails the suite instead of silently orphaning a row.
//!
//! The repo path comes from the `repo_root` build option (`build.zig`).
const std = @import("std");
const Io = std.Io;
const build_options = @import("build_options");

const conformance_doc = "docs/conformance.md";
const scanned_dirs = [_][]const u8{ "src", "tests" };
const max_doc_bytes = 1 << 20;
const max_zig_bytes = 16 << 20;

const Row = struct {
    /// Backticked test name, without the backticks.
    name: []const u8,
    /// 1-based line in the doc, for the failure message.
    line: usize,
    found: bool = false,
};

/// Collects `Row`s from every `| ... |` table line whose third cell is
/// `done`. Cells are split on `|`; the matrix has exactly four columns
/// (Clause | Requirement | Status | Test name), so a Requirement that
/// needs a literal pipe must escape it as `\|`.
fn collectDoneRows(
    allocator: std.mem.Allocator,
    doc: []const u8,
    rows: *std.ArrayList(Row),
    /// Set to the 1-based line of the first `done` row without a test name.
    bad_line: *?usize,
) !void {
    var line_no: usize = 0;
    var lines = std.mem.splitScalar(u8, doc, '\n');
    while (lines.next()) |raw_line| {
        line_no += 1;
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len < 2 or line[0] != '|' or line[line.len - 1] != '|') continue;

        var cells: [4][]const u8 = .{ "", "", "", "" };
        var ncells: usize = 0;
        var it = std.mem.splitScalar(u8, line[1 .. line.len - 1], '|');
        while (it.next()) |cell| {
            if (ncells == cells.len) {
                ncells += 1; // too many columns: not a matrix row
                break;
            }
            cells[ncells] = std.mem.trim(u8, cell, " \t");
            ncells += 1;
        }
        if (ncells != cells.len) continue;
        if (!std.mem.eql(u8, cells[2], "done")) continue;

        // Every `...` span in the Test name cell is one required test.
        var names_seen: usize = 0;
        var rest = cells[3];
        while (std.mem.findScalar(u8, rest, '`')) |open| {
            const after = rest[open + 1 ..];
            const close = std.mem.findScalar(u8, after, '`') orelse break;
            const name = after[0..close];
            if (name.len != 0) {
                try rows.append(allocator, .{ .name = name, .line = line_no });
                names_seen += 1;
            }
            rest = after[close + 1 ..];
        }
        if (names_seen == 0) {
            bad_line.* = line_no;
            return error.DoneRowWithoutTest;
        }
    }
}

/// Marks every row whose `test "<name>"` occurs in `source`.
fn markFound(rows: []Row, source: []const u8) void {
    for (rows) |*row| {
        if (row.found) continue;
        var start: usize = 0;
        while (std.mem.findPos(u8, source, start, "test \"")) |pos| {
            const name_start = pos + "test \"".len;
            const tail = source[name_start..];
            if (std.mem.startsWith(u8, tail, row.name) and tail.len > row.name.len and tail[row.name.len] == '"') {
                row.found = true;
                break;
            }
            start = name_start;
        }
    }
}

/// True when any path component starts with `.` or is `zig-out`.
fn isGeneratedPath(path: []const u8) bool {
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |component| {
        if (component.len == 0) continue;
        if (component[0] == '.') return true;
        if (std.mem.eql(u8, component, "zig-out")) return true;
    }
    return false;
}

fn scanZigFiles(allocator: std.mem.Allocator, io: Io, repo: Io.Dir, sub_dir: []const u8, rows: []Row) !usize {
    var dir = try repo.openDir(io, sub_dir, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(allocator);
    defer walker.deinit();
    var files: usize = 0;
    while (try walker.next(io)) |entry| {
        // Skip build caches and outputs (`tests/consumer/.zig-cache`,
        // `zig-out`): generated `.zig` files there would make the guard
        // depend on what was last built.
        if (isGeneratedPath(entry.path)) continue;
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;
        const source = try entry.dir.readFileAlloc(io, entry.basename, allocator, .limited(max_zig_bytes));
        defer allocator.free(source);
        markFound(rows, source);
        files += 1;
    }
    return files;
}

test "conformance doc names only existing tests" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var repo = try Io.Dir.cwd().openDir(io, build_options.repo_root, .{});
    defer repo.close(io);

    const doc = try repo.readFileAlloc(io, conformance_doc, allocator, .limited(max_doc_bytes));
    defer allocator.free(doc);

    var rows: std.ArrayList(Row) = .empty;
    defer rows.deinit(allocator);
    var bad_line: ?usize = null;
    collectDoneRows(allocator, doc, &rows, &bad_line) catch |err| {
        if (bad_line) |l| std.debug.print("{s}:{d}: Status is done but the Test name cell names no `test`\n", .{ conformance_doc, l });
        return err;
    };
    // The matrix must have at least one done row, or the guard is vacuous.
    try std.testing.expect(rows.items.len > 0);

    var files: usize = 0;
    for (scanned_dirs) |d| files += try scanZigFiles(allocator, io, repo, d, rows.items);
    try std.testing.expect(files > 0);

    var missing: usize = 0;
    for (rows.items) |row| {
        if (row.found) continue;
        missing += 1;
        std.debug.print("{s}:{d}: Status done but no `test \"{s}\"` under src/ or tests/\n", .{ conformance_doc, row.line, row.name });
    }
    if (missing != 0) return error.ConformanceTestMissing;
}

test "conformance parser reads done rows and ignores the rest" {
    const allocator = std.testing.allocator;
    const doc =
        "| Clause | Requirement | Status | Test name |\n" ++
        "|---|---|---|---|\n" ++
        "| §1 | a | done | `alpha` |\n" ++
        "| §2 | b | M3 | `beta` |\n" ++
        "| §3 | c | done | `gamma`, `delta` |\n" ++
        "| §4 | d | n/a | - |\n" ++
        "not a row | done | `zeta` |\n";
    var rows: std.ArrayList(Row) = .empty;
    defer rows.deinit(allocator);
    var bad_line: ?usize = null;
    try collectDoneRows(allocator, doc, &rows, &bad_line);
    try std.testing.expectEqual(@as(?usize, null), bad_line);
    try std.testing.expectEqual(@as(usize, 3), rows.items.len);
    try std.testing.expectEqualStrings("alpha", rows.items[0].name);
    try std.testing.expectEqual(@as(usize, 3), rows.items[0].line);
    try std.testing.expectEqualStrings("gamma", rows.items[1].name);
    try std.testing.expectEqualStrings("delta", rows.items[2].name);

    markFound(rows.items, "test \"alpha\" {}\ntest \"gammax\" {}\ntest \"delta\" {}\n");
    try std.testing.expect(rows.items[0].found);
    try std.testing.expect(!rows.items[1].found);
    try std.testing.expect(rows.items[2].found);
}

test "conformance scan skips build caches and outputs" {
    try std.testing.expect(isGeneratedPath("consumer/.zig-cache/o/abc/dependencies.zig"));
    try std.testing.expect(isGeneratedPath(".zig-cache/x.zig"));
    try std.testing.expect(isGeneratedPath("consumer/zig-out/bin/x.zig"));
    try std.testing.expect(!isGeneratedPath("consumer/build.zig"));
    try std.testing.expect(!isGeneratedPath("fixtures/loader.zig"));
    try std.testing.expect(!isGeneratedPath("codec_test.zig"));
}

test "conformance parser rejects a done row without a test name" {
    const allocator = std.testing.allocator;
    var rows: std.ArrayList(Row) = .empty;
    defer rows.deinit(allocator);
    var bad_line: ?usize = null;
    try std.testing.expectError(
        error.DoneRowWithoutTest,
        collectDoneRows(allocator, "| x |\n| §1 | a | done | - |\n", &rows, &bad_line),
    );
    try std.testing.expectEqual(@as(?usize, 2), bad_line);
}
