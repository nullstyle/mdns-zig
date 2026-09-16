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
    // `--fuzz` needs sancov coverage sections, which only the LLVM backend
    // emits (quic-zig build.zig: the self-hosted x86_64 backend produces a
    // binary that fuzzes with zero coverage and then dies with "pcs_len was
    // zero"). On this pin aarch64 already defaults to LLVM; the option is
    // for x86_64 hosts and CI. Off by default because the self-hosted
    // backend builds faster for every ordinary `zig build test`.
    // `false` is mapped to "compiler default" rather than `-fno-llvm`: the
    // self-hosted aarch64 backend hung the test compile on this pin.
    const use_llvm: ?bool = if (b.option(
        bool,
        "use-llvm",
        "Build the test binaries with the LLVM backend (pass with --fuzz on x86_64 so the fuzzer sees coverage)",
    ) orelse false) true else null;

    // Absolute path of this checkout for tests that read repo files at
    // runtime (docs/conformance.md, tests/fixtures/raw). Absolute so the
    // test binary does not depend on the cwd `zig build` was launched from.
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "repo_root", repoRoot(b));

    const unit_tests = b.addTest(.{ .root_module = mdns, .use_llvm = use_llvm });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const tests_mod = b.createModule(.{
        .root_source_file = b.path("tests/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{.{ .name = "mdns", .module = mdns }},
    });
    tests_mod.addOptions("build_options", build_options);
    const api_tests = b.addTest(.{ .root_module = tests_mod, .use_llvm = use_llvm });
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

/// Absolute path of the directory holding this build.zig. `b.root` is a
/// `Cache.Path` whose `root_dir.path` is null (cwd) or relative to the cwd
/// the configurer was launched from; `realPath` makes it absolute so a test
/// binary can open repo files from any cwd.
fn repoRoot(b: *std.Build) []const u8 {
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = b.root.root_dir.handle;
    const n = (if (b.root.sub_path.len == 0)
        dir.realPath(b.graph.io, &buf)
    else
        dir.realPathFile(b.graph.io, b.root.sub_path, &buf)) catch |err|
        std.debug.panic("cannot resolve the build root: {t}", .{err});
    return b.dupe(buf[0..n]);
}
