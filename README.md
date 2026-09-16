# mdns-zig

[![CI](https://github.com/nullstyle/mdns-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/nullstyle/mdns-zig/actions/workflows/ci.yml)

std-only mDNS (RFC 6762) and DNS-SD (RFC 6763) for Zig.

mdns-zig advertises and browses services on the local link next to the OS
daemon (mDNSResponder, avahi) without owning a thread. A sans-IO `Engine`
holds every RFC timer and the record cache; a thin `Service` shell binds
the two multicast sockets through `std.Io` and drives the Engine from
whatever loop the caller already has. It exists to give
[qmsg](https://github.com/nullstyle/qmsg), qmesh and shared-studio peer
discovery with fixed memory, bounded send budgets and no surprises from
untrusted packets.

## Installation

```sh
zig fetch --save https://github.com/nullstyle/mdns-zig/archive/refs/tags/v0.1.0.tar.gz
```

Then in `build.zig`:

```zig
const mdns_dep = b.dependency("mdns", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("mdns", mdns_dep.module("mdns"));
```

The build option map is `{target, optimize}`. `optimize` must be `Debug`
or `ReleaseSafe`; `build.zig` refuses ReleaseFast and ReleaseSmall because
the library parses untrusted UDP bytes and relies on the safety checks
those modes remove. The module links libc (`getifaddrs`, `setsockopt`).

Minimum Zig: `0.17.0-dev.1786+75044cb04` (the pin in `mise.toml`).

## Three ways to run it

mdns-zig never spawns a thread. One `Service` runs in exactly one of these
modes on the caller's thread:

- **Tick-polled (default).** `Service.tick(now_us)` from your own loop;
  sockets are drained at most every `rx_poll_interval_us` (5 ms) or when an
  RFC deadline is due. Your clock is authoritative. *(M0: not yet implemented)*
- **Self-driven blocking.** `Service.step(cap)` does one bounded wait;
  `Service.run(shutdown)` loops it with a 250 ms cap. *(M0: not yet implemented)*
- **`Io.Group` task.** `Service.serve(mailbox)` runs the blocking loop and
  pushes events into a bounded `Mailbox`; cancel the group to stop. Start it
  with `Group.concurrent`, never `Group.async`. *(M0: not yet implemented)*

Every socket receive and send goes through a timed `std.Io` call
(`receiveManyTimeout` / `sendManyTimeout` with a `.duration` or
`.deadline`). `Timeout.none` will be a comptime error in `Service` (M2);
until `docs/design.md` lands in M5 the rule and the measurements behind it
live in [docs/platform-matrix.md](docs/platform-matrix.md) ("Zero-timeout
timings", "Known risks").

## Known risks

- **Threaded post-poll `unreachable`.** After `poll(2)` reports a socket
  readable, `std.Io.Threaded` finishes the timed receive with a blocking
  `recvmsg` that maps `WouldBlock => unreachable`. On Linux a UDP datagram
  with a bad checksum makes `poll` lie only for `O_NONBLOCK` fds, so the
  mDNS sockets are left blocking under Threaded (`BindOptions.nonblocking`
  defaults to `false`); the zero-duration drain still works because
  Threaded passes `MSG_DONTWAIT` per call. The fork's Dispatch backend
  (M6) needs `O_NONBLOCK` and must add a mitigation first. Details and
  the options in docs/platform-matrix.md, "Known risks and decisions for
  M2".
- **Darwin ignores `MSG_DONTWAIT` for datagram sends.** xnu's
  `sosendcheck` blocks a blocking-fd `sendmsg` whenever the send buffer is
  short, and a content filter (Little Snitch, Tailscale, MDM agents) can
  keep it short for as long as it holds a flow for a verdict, so the
  Service sets `O_NONBLOCK` around each send batch on Darwin only (the
  "send window") and clears it before every receive; a send the kernel
  will not take within 2 ms is a counted drop. Details in
  docs/platform-matrix.md, "Darwin send path".
- **Per-interface cache.** Records are keyed by `(name, type, class,
  ifindex)`; a responder heard on k interfaces costs k copies of each
  record, and `found` / `resolved` / `lost` fire once per interface (as
  `dns-sd -B` does; `Service.lookup` collapses them to one slot per
  instance). An interface that leaves the table drops its records
  (`lost` for its instances). Size `Limits.max_cache_records` (default
  4096, 720 B each) as interfaces x records per instance (about 5) x
  instances.

## Platforms and Io backends

macOS and Linux (Threaded backend) are the v0.1 gates: the live check and
the whole test suite run on this Mac beside mDNSResponder and, cross-built
for `aarch64-linux-musl`, in a Fedora Lima VM beside avahi-daemon and
systemd-resolved (M2). FreeBSD and OpenBSD compile with reviewed
constants and have not been run. Socket-option numbers, cmsg layouts,
coexistence rules with the OS daemon and the measured results live in
[docs/platform-matrix.md](docs/platform-matrix.md).

## Security posture

Received datagrams are hostile input. A panic or an unbounded allocation
reachable from network bytes is a security bug; see
[SECURITY.md](SECURITY.md) for the reporting channel and scope.

## macOS Local Network privacy

On macOS 15 and later, a process launched from a GUI app without the
Local Network permission can bind and join the multicast groups yet
silently receive nothing. Run the live tests, spikes and examples from
Terminal or over SSH (or as root). CI on macOS runs the hermetic tests only.

## Development

```sh
mise install            # pins zig; sets ZIG_GLOBAL_CACHE_DIR to ./.zig-global-cache
just test               # zig build test (Debug)
just test-safe          # zig build test -Doptimize=ReleaseSafe
just fmt-check          # mise fmt --check + zig fmt --check
just spike-all          # bind5353, join_pktinfo, zero_timeout diagnostics
just spike bind5353     # one spike; extra args go to the program
just fixtures 10 "label" # capture LAN packets into a fresh tests/fixtures/capture-* dir
just lima-test          # cross-build musl test binaries, run them in Lima `zig-uring`
just lima-live -- --seconds 4  # cross-build mdns-live, run it beside avahi in the VM
just check-fork         # advisory run with ~/.zvm/fork-all/zig
just release-check      # README tag == build.zig.zon version
```

The consumer smoke test in `tests/consumer` builds against the package
the same way a downstream project does (`cd tests/consumer && zig build test`).
`docs/` holds the platform matrix (the design notes and the RFC
conformance table arrive with later milestones). The `spikes/` programs
are diagnostics, not a stable API; they and `tests/` are excluded from
the published package. Raw packet captures live in `tests/fixtures/raw`;
see [tests/fixtures/README.md](tests/fixtures/README.md).

Do not run `zig fetch .` inside this checkout: `mise.toml` puts
`ZIG_GLOBAL_CACHE_DIR` under the repo, and `zig fetch <dir>` copies the
whole directory before applying `.paths`, so it recursively copies the
cache into itself until `NameTooLong` and leaves gigabytes under
`.zig-global-cache/tmp`. To check the published tarball locally, export
a clean tree first, as CI does:

```sh
src="$(mktemp -d)" && git archive --format=tar HEAD | tar -x -C "$src"
mise exec -- zig fetch "$src"     # prints the package hash
```

## License

MIT. See [LICENSE](LICENSE).
