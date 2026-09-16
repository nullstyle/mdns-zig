# Changelog

## Unreleased

### M0 - scaffold and first macOS spike

- Repo skeleton: `build.zig` (module `mdns`, links libc, refuses ReleaseFast
  and ReleaseSmall, early return for dependency builds, steps `test`, `live`,
  `examples`, `docs`, `spike-*`), `build.zig.zon` with consumer-only `.paths`,
  `mise.toml` pin `0.17.0-dev.1786+75044cb04`, MIT `LICENSE`.
- `tests/consumer`: out-of-tree smoke build against the package via
  `.path = "../.."`.
- `tools/release-check.sh`: README fetch tag must equal the zon version;
  accepts an optional `v` prefix on tags and URLs.
- CI (`.github/workflows/ci.yml`, hamt-zig template): `test` lanes Debug and
  ReleaseSafe; `portability` on macos-15 (Debug, hermetic only); `quality`
  lane with `mise fmt --check`, `zig fmt --check`, `tools/release-check.sh`,
  `zig build docs` and the filtered-tarball check (fetch from a `git archive`
  export, extract, copy `tests/consumer` in, run its tests in Debug and
  ReleaseSafe); advisory `live` lane on ubuntu with avahi-daemon; advisory
  `fuzz` lane (`--fuzz=10K`, 20 min cap). `.zig-global-cache` is cached.
  All actions SHA-pinned.
- `justfile`: `test`, `test-safe`, `fmt-check`, `live`, `spike-all`, `spike`,
  `check-fork`, `release-check`, `docs`, `lima-linux`, `fixtures`, `clean`.
- `SECURITY.md`: untrusted-UDP posture (panics or unbounded allocation on
  adversarial input are security bugs), Debug/ReleaseSafe only, private
  reporting via GitHub security advisories, supported-versions table.
- `README.md`: pitch, installation, `{target, optimize}` option map, the
  three loop modes, platform matrix pointer, security posture, macOS Local
  Network privacy note, development workflow.
- `docs/platform-matrix.md`: socket-option, struct and coexistence tables
  for macOS, Linux, FreeBSD and OpenBSD with std and SDK line citations;
  Linux/FreeBSD/OpenBSD marked "reviewed, not run"; the macOS column
  filled from the M0 spikes run on this Mac (reuse matrix for v4 and v6,
  oldest-binder unicast ownership, 100% pktinfo ifindex decode in both
  families, 4-byte cmsg alignment confirmed by kernel-filled lengths,
  zero-timeout timings on Threaded, derived coexistence rules).
- `src/platform/socket_opts.zig` (Darwin constants with header citations,
  Linux table with comptime asserts, FreeBSD/OpenBSD tables,
  `setsockoptChecked`, raw bind with reuse options, `trialBindWithoutReuse`,
  group join/leave, pktinfo encode/decode, runtime-parameterised cmsg
  codec, `O_NONBLOCK`, `bindMdnsSocket` -> `Io.net.Socket`) with 11 unit
  tests, and the `bind5353` (reuse matrix v4+v6, unicast owner, control
  port), `join_pktinfo` (`--seconds`, `--dump`, `--label`) and
  `zero_timeout` spikes. Build steps `spike-*`, `spike-all`; `test` also
  runs `tests/root.zig` against the `mdns` module import.
- Packet fixtures: 231 raw mDNS datagrams (`tests/fixtures/raw/NNNN.hex` +
  `.json` sidecars) captured on this Mac with the `join_pktinfo` spike in
  two runs: 127 while `dns-sd -B _services._dns-sd._udp` and
  `dns-sd -R m0demo _mdnszig._udp . 4433 k=v` ran, then 104 with `-R`,
  `-B` and `-L m0demo _mdnszig._udp` where `-R` was killed before the
  window closed (16 goodbye / TTL 0 records, SRV/TXT resolve traffic);
  capture method, sidecar schema and corpus statistics in
  `tests/fixtures/README.md`. No decoder test yet (M1).
- Review fixes (M0): `BindOptions.nonblocking` defaults to `false` (see
  Known risks); FreeBSD/OpenBSD constants pinned by comptime asserts like
  Linux; `setsockoptChecked` maps `EADDRINUSE`/`EADDRNOTAVAIL`/`ENODEV`/
  `ENXIO` to typed errors and `joinGroup`/`leaveGroup` return
  `AlreadyMember`/`NotMember`; out-of-range interface indexes are
  `error.InvalidInterface` instead of an `@intCast` trap; Darwin header
  line citations corrected; `bind5353` runs the reuse matrix with the
  daemon absent too and binds v6 with `IPV6_V6ONLY`; `join_pktinfo` reads
  `ifaddrs` addresses through `align(1)` pointers, skips interfaces whose
  `if_nametoindex` is 0 and counts oversize datagrams instead of aborting;
  `zero_timeout` verifies `O_NONBLOCK` with `fcntl` and runs its battery
  on blocking fds as well; the advisory fuzz CI lane is disabled until the
  first `std.testing.fuzz` target exists (M1).

### Known risks

- `std.Io.Threaded` completes a timed receive/send after `poll(2)` with an
  untimed `operate` whose `WouldBlock => unreachable` (`Threaded.zig:2555`,
  `:2573`) would trap on a spurious readiness report. Linux `udp_poll`
  produces one for bad-checksum UDP datagrams on `O_NONBLOCK` fds only, so
  the mDNS sockets stay blocking under Threaded; the fork's Dispatch
  backend (M6, needs `O_NONBLOCK`) must mitigate first (accept-all BPF via
  `SO_ATTACH_FILTER`, or a backend fix upstream). See
  `docs/platform-matrix.md`, "Known risks and decisions for M2".

## 0.1.0 - unreleased
