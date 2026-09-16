set shell := ["bash", "-euo", "pipefail", "-c"]

# mise.toml pins the compiler and points ZIG_GLOBAL_CACHE_DIR at
# .zig-global-cache; every recipe goes through `mise exec` so the pin holds
# even when mise is not activated in the caller's shell.
zig := "mise exec -- zig"

# Personal fork compiler (advisory only; see check-fork).
fork_zig := env_var_or_default("MDNS_FORK_ZIG", env_var_or_default("HOME", "~") + "/.zvm/fork-all/zig")

# Lima VM that runs the cross-built Linux binaries. It mounts /Users/nullstyle,
# so absolute paths from this checkout resolve unchanged inside the VM.
lima_vm := env_var_or_default("MDNS_LIMA_VM", "zig-uring")
linux_target := env_var_or_default("MDNS_LINUX_TARGET", "aarch64-linux-musl")

default:
    @just --list

# Unit and public-API tests (Debug).
test:
    {{zig}} build test

# build.zig refuses ReleaseFast/ReleaseSmall (untrusted UDP bytes).
# Same suite under ReleaseSafe.
test-safe:
    {{zig}} build test -Doptimize=ReleaseSafe

# Formatting gate, identical to the CI quality lane.
fmt-check:
    mise fmt --check
    {{zig}} fmt --check build.zig src tests spikes

# On macOS run from Terminal or SSH: GUI-launched processes may lack Local
# Network permission and silently see zero packets.
# Loopback and live-socket tests (real sockets on shared 5353).
live:
    {{zig}} build live

# Run every diagnostic spike (bind5353, join_pktinfo, zero_timeout).
spike-all:
    {{zig}} build spike-all

# Run one spike with arguments, e.g. `just spike join_pktinfo --seconds 10`.
spike name *args:
    {{zig}} build spike-{{name}} -- {{args}}

# Failures here never gate a release; they preview upcoming std changes.
# Advisory: run the suite with the personal fork compiler (newer std.Io).
check-fork:
    #!/usr/bin/env bash
    set -uo pipefail
    if [ ! -x "{{fork_zig}}" ]; then
        echo "check-fork: fork compiler not found at {{fork_zig}} (set MDNS_FORK_ZIG); skipping"
        exit 0
    fi
    echo "check-fork: $("{{fork_zig}}" version)"
    "{{fork_zig}}" build test || echo "check-fork: FAILED (advisory)"

# README fetch tag must match build.zig.zon; pass a ref to also check a tag.
release-check ref="":
    sh tools/release-check.sh {{ref}}

# Generate API docs into zig-out/docs.
docs:
    {{zig}} build docs

# The test binaries are emitted with --test-no-exec and executed by
# `limactl shell`, which sees the same absolute path via the /Users mount.
# Cross-build the tests for Linux (musl) and run them inside the Lima VM.
lima-linux optimize="Debug":
    #!/usr/bin/env bash
    set -euo pipefail
    out="$PWD/zig-out/lima-{{linux_target}}"
    mkdir -p "$out"
    {{zig}} test src/root.zig -lc -target {{linux_target}} -O {{optimize}} \
        --test-no-exec -femit-bin="$out/mdns-unit-tests"
    {{zig}} test -lc -target {{linux_target}} -O {{optimize}} \
        --dep mdns -Mroot=tests/root.zig -Mmdns=src/root.zig \
        --test-no-exec -femit-bin="$out/mdns-api-tests"
    limactl shell {{lima_vm}} -- "$out/mdns-unit-tests"
    limactl shell {{lima_vm}} -- "$out/mdns-api-tests"

# Each packet lands as <seq>.hex plus a .json sidecar; the sequence
# restarts at 0001 every run, so the target directory must be empty (the
# default is a fresh dir under tests/fixtures/; move files into raw/ by
# hand). Run `dns-sd -B _services._dns-sd._udp` or `dns-sd -R ...`
# alongside to provoke traffic from mDNSResponder.
# Capture raw mDNS datagrams via the join_pktinfo spike (see tests/fixtures/README.md).
fixtures seconds="10" label="" dir="tests/fixtures/capture-$(date +%Y%m%d-%H%M%S)":
    #!/bin/sh
    set -eu
    dir="{{dir}}"
    mkdir -p "$dir"
    if [ -n "$(ls -A "$dir")" ]; then
        echo "fixtures: $dir is not empty; refusing to overwrite NNNN.hex files" >&2
        exit 1
    fi
    {{zig}} build spike-join_pktinfo -- --seconds {{seconds}} --dump "$dir" --label "{{label}}"
    echo "fixtures: wrote $(ls "$dir" | wc -l | tr -d ' ') files to $dir"

clean:
    rm -rf .zig-cache zig-out
