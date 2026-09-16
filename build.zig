const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Plain form on purpose: `preferred_optimize_mode` would stop the
    // `optimize` option from being declared, and every consumer that
    // forwards `.optimize` would fail with `invalid option` (the quic-zig
    // {target, sanitize-c} gotcha). Consumers forward {target, optimize}.
    const optimize = b.standardOptimizeOption(.{});
    if (optimize == .fast or optimize == .small) {
        @panic("mdns-zig parses untrusted UDP bytes: build with Debug or ReleaseSafe only");
    }

    const mdns = b.addModule("mdns", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // Everything below is development-only. pkg_hash is empty only for
    // the top-level build.
    if (b.pkg_hash.len != 0) return;

    const unit_tests = b.addTest(.{ .root_module = mdns });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
