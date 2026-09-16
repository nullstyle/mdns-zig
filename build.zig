const std = @import("std");
const builtin = @import("builtin");
const manifest = @import("build.zig.zon");

// The build runner parses `minimum_zig_version` but never compares it with
// the running compiler. Enforce it here so an old toolchain fails with one
// clear message instead of an unrelated error deep in std (quic-zig
// pattern). `SemanticVersion.order` ignores build metadata, so this is the
// semver floor; mise.toml carries the exact commit pin.
comptime {
    const required = std.SemanticVersion.parse(manifest.minimum_zig_version) catch
        @compileError("build.zig.zon minimum_zig_version is not valid semver: " ++
            manifest.minimum_zig_version);
    if (builtin.zig_version.order(required) == .lt) {
        @compileError(std.fmt.comptimePrint(
            "mdns-zig requires zig {s} or newer (build.zig.zon minimum_zig_version); " ++
                "this build is running zig {s}.",
            .{ manifest.minimum_zig_version, builtin.zig_version_string },
        ));
    }
}

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

    // ---- test -----------------------------------------------------------
    const unit_tests = b.addTest(.{ .root_module = mdns });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const api_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{.{ .name = "mdns", .module = mdns }},
        }),
    });
    const run_api_tests = b.addRunArtifact(api_tests);

    const test_step = b.step("test", "Run unit and public-API tests");
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(&run_api_tests.step);

    // ---- docs -----------------------------------------------------------
    const docs_object = b.addObject(.{
        .name = "mdns-docs",
        .root_module = mdns,
    });
    const install_docs = b.addInstallDirectory(.{
        .source_dir = docs_object.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Generate and install API documentation");
    docs_step.dependOn(&install_docs.step);

    // ---- spikes ---------------------------------------------------------
    // Diagnostic programs. `zig build spike-x -- args` forwards args.
    const spike_all = b.step("spike-all", "Run every spike");
    const spikes = [_]struct { name: []const u8, file: []const u8, desc: []const u8 }{
        .{ .name = "bind5353", .file = "spikes/bind5353.zig", .desc = "Reuse-option matrix on *:5353 and the unicast owner" },
        .{ .name = "join_pktinfo", .file = "spikes/join_pktinfo.zig", .desc = "Join both groups on every interface and decode pktinfo" },
        .{ .name = "zero_timeout", .file = "spikes/zero_timeout.zig", .desc = "Zero-duration and 50 ms timeouts on Threaded" },
    };
    for (spikes) |s| {
        const exe = b.addExecutable(.{
            .name = b.fmt("spike-{s}", .{s.name}),
            .root_module = b.createModule(.{
                .root_source_file = b.path(s.file),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = &.{.{ .name = "mdns", .module = mdns }},
            }),
        });
        const run = b.addRunArtifact(exe);
        run.has_side_effects = true;
        // `zig build spike-x -- a b` appends `a b` here.
        run.addPassthruArgs();
        const step = b.step(b.fmt("spike-{s}", .{s.name}), s.desc);
        step.dependOn(&run.step);
        spike_all.dependOn(step);
    }

    // ---- examples -------------------------------------------------------
    // No examples yet (M4). The step exists so `zig build examples` is
    // valid from M0 on.
    _ = b.step("examples", "Build and run the examples (none yet)");

    // ---- live -----------------------------------------------------------
    // Real-socket tests land in M2 (tests/live/). Placeholder step.
    _ = b.step("live", "Run loopback and live-socket tests (M2)");
}
