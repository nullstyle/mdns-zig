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
# `limactl shell` hangs without a tty; the interop recipes use ssh with the
# VM's generated config instead.
lima_ssh := "ssh -o IdentityAgent=none -o IdentitiesOnly=yes -F " + env_var_or_default("HOME", "~") + "/.lima/" + lima_vm + "/ssh.config lima-" + lima_vm
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
    {{zig}} fmt --check build.zig src tests spikes examples

# `N` is a run count PER FUZZ TARGET with an optional K/M/G suffix
# (`--fuzz=N`; there is no time flag; the report prints the first target's
# name with totals over all of them). 2M is about 60 s on an M-series Mac
# for the four codec targets. The whole test step is the fuzz target set: a
# filtered test binary under --fuzz aborts the build runner
# (ziglang/zig#25352), so never combine this with `-Dtest-filter`. `-Duse-llvm=true` makes the fuzzer see
# coverage on x86_64 (aarch64 already defaults to LLVM); see build.zig.
# Coverage-guided fuzzing over every std.testing.fuzz target, e.g. `just fuzz 10K`.
fuzz N="10K":
    {{zig}} build test -Duse-llvm=true --fuzz={{N}}

# Prints every RFC clause whose Status is not yet `done`, then runs the
# guard test that greps the doc for the named tests.
# Conformance matrix: open items and the docs/conformance.md guard test.
conformance:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "conformance: rows not yet done (docs/conformance.md)"
    awk -F'|' 'NF==6 && $4 !~ /Status|^ *done *$|^-+$/ { gsub(/^ +| +$/, "", $2); gsub(/^ +| +$/, "", $4); printf "  %-6s %s\n", $4, $2 }' docs/conformance.md
    echo "conformance: done rows: $(awk -F'|' 'NF==6 && $4 ~ /^ *done *$/' docs/conformance.md | wc -l | tr -d ' ')"
    {{zig}} build test

# On macOS run from Terminal or SSH: GUI-launched processes may lack Local
# Network permission and silently see zero packets.
# Loopback and live-socket tests (real sockets on shared 5353).
live:
    {{zig}} build live

# Continuous browse until Ctrl-C, e.g. `just example-browse _qmsg._udp`;
# register something beside it with `dns-sd -R demo _qmsg._udp . 4433 spki=00`.
# Browse a service type with zig-out/bin/mdns-browse (real sockets on shared 5353).
example-browse *args:
    {{zig}} build example-browse -- {{args}}

# Build and install every example (mdns-browse, mdns-advertise, mdns-peer) under zig-out/bin without running them.
examples:
    {{zig}} build examples

# `dns-sd -B _qmsg._udp` then lists it; `kill -USR1 $(pgrep -f mdns-advertise)`
# bumps seq=<n> in the TXT; Ctrl-C sends the goodbye.
# Advertise one instance with zig-out/bin/mdns-advertise, e.g. `just example-advertise --name demo --port 4433 --txt k=v`.
example-advertise *args:
    {{zig}} build example-advertise -- {{args}}

# Advertise + browse _mdnszig._udp in one process, e.g. `just example-peer alice`.
example-peer *args:
    {{zig}} build example-peer -- {{args}}

# The Linux build overwrites zig-out/bin/mdns-peer, so the native binary is
# copied to /tmp/mdns-peer-mac first. Then run `/tmp/mdns-peer-mac alice`
# here and the printed ssh command in the VM; each prints the other within
# a few seconds and `gone` after the other is interrupted.
# Build the two-peer demo for this Mac and for the Lima VM, then print the two commands to run.
peer-demo:
    #!/usr/bin/env bash
    set -euo pipefail
    {{zig}} build examples
    cp zig-out/bin/mdns-peer /tmp/mdns-peer-mac
    {{zig}} build examples -Dtarget={{linux_target}}
    echo "here:   /tmp/mdns-peer-mac alice"
    echo "in VM:  {{lima_ssh}} '$PWD/zig-out/bin/mdns-peer bob'"

# Six dns-sd checks (browse, lookup, goodbye, conflict both ways, updateTxt);
# run from Terminal or SSH. SKIP_BUILD=1 skips the examples build.
# macOS interop: interop/macos-dnssd.sh against mDNSResponder.
interop-macos:
    sh interop/macos-dnssd.sh

# Cross-builds the examples, then runs interop/lima-avahi.sh inside the VM
# over ssh (avahi-browse resolves us; avahi-publish clash both ways).
# Linux interop: interop/lima-avahi.sh against avahi-daemon in the Lima VM.
interop-lima:
    #!/usr/bin/env bash
    set -euo pipefail
    {{zig}} build examples -Dtarget={{linux_target}}
    {{lima_ssh}} "sh $PWD/interop/lima-avahi.sh"

# Runs the join_pktinfo spike as the capture (no tcpdump, no sudo), e.g.
# `just flood-count --seconds 60 --service demo._qmsg._udp --assert idle-advertise`
# with mdns-advertise running beside it.
# Count the packets this host sends for one name per capture window (interop/flood-count.sh).
flood-count *args:
    sh interop/flood-count.sh {{args}}

# One legacy unicast query from an ephemeral port; checks the RFC 6762 6.7
# reply shape, e.g. `just legacy-query demo._qmsg._udp.local SRV`.
# Legacy unicast query check (interop/legacy_query.py <name> <TYPE>).
legacy-query name type="SRV" *args:
    python3 interop/legacy_query.py {{name}} {{type}} {{args}}

# avahi-daemon answers inside the VM; `avahi-publish -s demo2 _qmsg._udp 5001`
# there makes a found/resolved pair appear. Extra args go to mdns-browse.
# Cross-build zig-out/bin/mdns-browse for Linux (musl) and run it inside the Lima VM for 10 s.
lima-browse *args:
    #!/usr/bin/env bash
    set -euo pipefail
    {{zig}} build examples -Dtarget={{linux_target}}
    args=({{args}})
    if [ "${args[0]:-}" = "--" ]; then args=("${args[@]:1}"); fi
    limactl shell {{lima_vm}} -- timeout -s INT 10 "$PWD/zig-out/bin/mdns-browse" "${args[@]}"

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

# `zig build test-exe` installs both test binaries under zig-out/test
# without running them; `limactl shell` sees the same absolute path via
# the /Users mount. The API tests read docs/ and tests/fixtures/ through
# build_options.repo_root, which is absolute, so they also work there.
# Cross-build the unit and public-API tests for Linux (musl) and run them inside the Lima VM.
lima-test optimize="Debug":
    #!/usr/bin/env bash
    set -euo pipefail
    {{zig}} build test-exe -Dtarget={{linux_target}} -Doptimize={{optimize}}
    limactl shell {{lima_vm}} -- "$PWD/zig-out/test/mdns-unit-tests"
    limactl shell {{lima_vm}} -- "$PWD/zig-out/test/mdns-api-tests"

# avahi-daemon (and, on Fedora, systemd-resolved) hold *:5353 in the VM,
# so the expected line is `first_binder=false`; stop both services in the
# VM to see `first_binder=true`. Extra args go to mdns-live
# (`--seconds N`, `--ifindex N`, `--no-ipv6`, `--no-loopback`).
# Cross-build zig-out/bin/mdns-live for Linux (musl) and run it inside the Lima VM.
lima-live *args:
    #!/usr/bin/env bash
    set -euo pipefail
    {{zig}} build live -Dtarget={{linux_target}}
    # `just lima-live -- --seconds 4`: just needs the `--` before flags
    # and passes it through, so drop it here.
    args=({{args}})
    if [ "${args[0]:-}" = "--" ]; then args=("${args[@]:1}"); fi
    limactl shell {{lima_vm}} -- "$PWD/zig-out/bin/mdns-live" "${args[@]}"

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
