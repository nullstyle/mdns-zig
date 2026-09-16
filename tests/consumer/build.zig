const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    // The option map mdns-zig supports: {target, optimize}.
    const mdns_dep = b.dependency("mdns", .{
        .target = target,
        .optimize = optimize,
    });

    const consumer_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{
                .name = "mdns",
                .module = mdns_dep.module("mdns"),
            }},
        }),
    });
    const run_consumer_tests = b.addRunArtifact(consumer_tests);
    const test_step = b.step("test", "Test external mdns package consumption");
    test_step.dependOn(&run_consumer_tests.step);
}
