# mdns-zig

[![CI](https://github.com/nullstyle/mdns-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/nullstyle/mdns-zig/actions/workflows/ci.yml)

std-only mDNS (RFC 6762) and DNS-SD (RFC 6763) for Zig.

> **This library was vibe coded.** Claude Code (Opus 5) wrote every line of
> code, test, script and document in this repository over two days
> (2026-09-15 to 2026-09-17), working from a plan the author approved and
> steering a fleet of implementer, reviewer and gate agents. The author
> set the goals, made the design decisions the agents asked about, and
> committed each milestone. No human has yet read the code line by line.
> What has been verified: 315 unit and fake-LAN tests in Debug and
> ReleaseSafe, fuzzing of every parser and of `Engine.handle`, and live
> interop against mDNSResponder (`dns-sd`) on macOS and avahi on Linux, all
> run on the author's machines. Treat it like any other new, unaudited
> network code: read what you depend on, and report what you find.

mdns-zig advertises and browses services on the local link next to the OS
daemon (mDNSResponder, avahi, systemd-resolved) without owning a thread.
A sans-IO `Engine` holds every RFC timer and the record cache. A thin
`Service` shell binds the two multicast sockets through `std.Io` and
drives the Engine from whatever loop the caller already has. It exists to
give [qmsg](https://github.com/nullstyle/qmsg), qmesh and shared-studio
peer discovery with fixed memory, bounded send budgets and no surprises
from untrusted packets.

What v0.1.x does:

- Browse a service type and get `found` / `resolved` / `lost` events with
  host, port, addresses and TXT, one stream per interface. Records are
  cached per interface, re-queried at 80/85/90/95 % of their TTL and
  flushed, expired or evicted by the RFC rules.
- Advertise instances: probe, tie-break, announce, defend, answer with
  the RFC 6763 §12 additionals, NSEC negative answers, legacy unicast
  replies, rename on conflict (`Name (2)`, `<host>-2`), update the TXT
  without re-probing, say goodbye on withdraw and on `deinit`.
- Coexist on UDP 5353 with the OS daemon (shared bind, multicast probe
  defence, no reliance on unicast delivery when the port is shared).
- Stay within the RFC send budgets: an idle advertised service sends
  nothing; a browse sends 35 queries per interface per day.

## Installation

```sh
zig fetch --save https://github.com/nullstyle/mdns-zig/archive/refs/tags/v0.1.1.tar.gz
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

## Example

Advertise one instance and browse the same type, in mode B. The full
programs are in `examples/` (`browse.zig`, `advertise.zig`, `peer.zig`).

```zig
const std = @import("std");
const mdns = @import("mdns");

var shutdown: std.atomic.Value(bool) = .init(false); // flipped by a signal handler

fn onStep(_: ?*anyopaque, svc: *mdns.Service, _: u64) anyerror!void {
    var evs: [8]mdns.Event = undefined;
    var n = svc.poll(&evs);
    while (n > 0) : (n = svc.poll(&evs)) for (evs[0..n]) |ev| switch (ev) {
        .resolved => |r| std.debug.print("{f} port {d} ttl {d}s\n", .{ r.instance, r.port, r.ttl_s }),
        .lost => |l| std.debug.print("{f} gone\n", .{l.instance}),
        else => {},
    };
}

pub fn main(init: std.process.Init) !void {
    var threaded: std.Io.Threaded = .init(init.gpa, .{});
    defer threaded.deinit();
    var svc = try mdns.Service.init(init.gpa, threaded.io(), .{ .host_label = "demo" });
    defer svc.deinit(); // sends the goodbyes
    _ = try svc.advertise(.{ .service_type = "_qmsg._udp", .instance = "Alice", .port = 4433, .txt = &.{.{ .key = "txtvers", .value = "1" }} });
    _ = try svc.browse("_qmsg._udp");
    try svc.run(&shutdown, .{ .ctx = null, .f = onStep }); // mode B: returns once shutdown is true
}
```

## Three ways to run it

mdns-zig never spawns a thread. One `Service` runs in exactly one of these
modes on the caller's thread, and binds to that mode's clock for life
(mixing them asserts in Debug and ReleaseSafe):

- **Tick-polled (mode A).** `Service.tick(now_us)` from your own loop with
  your own clock; sockets are drained at most every `rx_poll_interval_us`
  (5 ms) or when an RFC deadline is due. Tick at least every ~500 ms and
  keep `rx_poll_interval_us` at or below ~100 ms: an own echo is
  recognised only within `timers.echo_window_us` (1 s) of the send.
- **Self-driven blocking (mode B).** `Service.step(cap)` does one bounded
  wait (cap <= 250 ms); `Service.run(shutdown, hook)` loops it until the
  atomic flips; `Service.lookup(type, opts, out)` is a bounded one-shot
  browse that stops its browse on every exit path, cancel included.
- **`Io.Group` task (mode C).** `Service.serve(&mailbox)` runs the blocking
  loop and pushes events into a bounded `Mailbox`; a full mailbox waits
  up to 250 ms, then drops the oldest event and counts it. Start it with
  `Group.concurrent`, never `Group.async`; `Group.cancel` ends it.

Every socket receive and send is a timed `std.Io` call; an untimed call
does not compile. The sockets are blocking fds; on macOS the Service sets
`O_NONBLOCK` only inside a send window because xnu ignores `MSG_DONTWAIT`
for the send-buffer wait. [docs/design.md](docs/design.md) has the loop
modes, the clock rule, the cache model, every timer with its RFC section,
the pool sizes, the error policy and the list of deviations from the
plan.

## Platforms and Io backends

macOS and Linux on the `std.Io.Threaded` backend are the v0.1 gates. The
test suite and the live check run on macOS beside mDNSResponder and,
cross-built for `aarch64-linux-musl`, in a Fedora Lima VM beside
avahi-daemon and systemd-resolved. FreeBSD and OpenBSD compile with
reviewed constants and have not been run. Socket-option numbers, cmsg
layouts, coexistence rules with the OS daemon and the measured results
are in [docs/platform-matrix.md](docs/platform-matrix.md).

## Conformance

[docs/conformance.md](docs/conformance.md) maps every RFC 6762 / 6763
clause to its status and the test that proves it. `zig build test` fails
when a `done` row names a test that does not exist. Interop is scripted
against `dns-sd` on macOS and avahi in the Lima VM (`interop/`).

## Known limitations in v0.1.x

- No per-link re-probe when an interface is added: the new link gets the
  two announcements, and a name unique on the old link is assumed unique
  on the new one until a conflict says otherwise (M6).
- The `_services._dns-sd._udp` meta-query and `_sub` subtypes are not
  supported (M6). Dedicated service types are used instead.
- A responder heard on k interfaces costs k cache entries per record and
  emits one `found` / `resolved` / `lost` per interface; `lookup` keeps
  one slot per (instance, interface) too.
- The cross-host Mac / Lima demo needs a bridged VM network; Lima's
  user-mode NIC does not carry multicast.
- v6 addresses are not filtered by flag (tentative, deprecated,
  temporary); every kept address is advertised.

## Security posture

Received datagrams are hostile input. A panic or an unbounded allocation
reachable from network bytes is a security bug. Every pool is sized at
`init` from `Limits`; input beyond a cap is dropped and counted. See
[SECURITY.md](SECURITY.md) for the reporting channel and scope. mDNS
itself carries no authenticity: any host on the link may answer for any
name. Consumers verify identity above this library (the TXT `spki` is a
selector, the mTLS handshake is the proof).

## macOS Local Network privacy

On macOS 15 and later, a process launched from a GUI app without the
Local Network permission can bind and join the multicast groups yet
silently receive nothing. The Service emits `warning.no_packets_10s`
when it has sent for 10 s and heard nothing; `stats()` shows `tx > 0`
with `rx == 0`. Run the live tests, spikes and examples from Terminal or
over SSH. CI on macOS runs the hermetic tests only: `MDNS_HERMETIC=1`
skips the `tests/loop_test.zig` cases that exchange multicast over the
loopback (they run by default and pass from a shell on this Mac).

## Development

```sh
mise install            # pins zig; sets ZIG_GLOBAL_CACHE_DIR to ./.zig-global-cache
just test               # zig build test (Debug)
just test-safe          # zig build test -Doptimize=ReleaseSafe
just fmt-check          # mise fmt --check + zig fmt --check
just fuzz 10K           # every std.testing.fuzz target, N runs each
just conformance        # rows not yet done, then the guard test
just docs               # zig build docs -> zig-out/docs
just examples           # mdns-browse, mdns-advertise, mdns-peer under zig-out/bin
just example-browse _qmsg._udp
just example-advertise --name demo --port 4433 --txt k=v
just spike-all          # bind5353, join_pktinfo, zero_timeout diagnostics
just interop-macos      # interop/macos-dnssd.sh against mDNSResponder (six checks)
just interop-lima       # cross-build, then interop/lima-avahi.sh in the VM
just flood-count --seconds 60 --service demo._qmsg._udp --assert idle-advertise
just lima-test          # cross-build the test binaries, run them in Lima
just lima-live -- --seconds 4
just release-check      # README tag == build.zig.zon version
just tarball-check      # git-archive export -> zig fetch -> consumer smoke
just check-fork         # advisory run with ~/.zvm/fork-all/zig
```

The consumer smoke test in `tests/consumer` builds against the package
the same way a downstream project does. `spikes/` are diagnostics, not a
stable API; they, `tests/` and `interop/` are excluded from the published
package. Raw packet captures live in `tests/fixtures/raw`; see
[tests/fixtures/README.md](tests/fixtures/README.md).

Do not run `zig fetch .` inside this checkout: `mise.toml` puts
`ZIG_GLOBAL_CACHE_DIR` under the repo, and `zig fetch <dir>` copies the
whole directory before applying `.paths`, so it recursively copies the
cache into itself until `NameTooLong`. `just tarball-check` exports a
clean tree with `git archive` first, as CI does.

Lima notes: `limactl shell` hangs from a non-tty harness, so the recipes
use the VM's generated ssh config:

```sh
ssh -o IdentityAgent=none -o IdentitiesOnly=yes -F ~/.lima/zig-uring/ssh.config lima-zig-uring <cmd>
```

The VM mounts `/Users/nullstyle`, so absolute paths from this checkout
resolve unchanged inside it. On Fedora both `avahi-daemon` and
`systemd-resolved` hold `*:5353`, so `first_binder` is true only when
both are stopped (`sudo systemctl stop avahi-daemon systemd-resolved`).
Details in [interop/README.md](interop/README.md).

## License

MIT. See [LICENSE](LICENSE).
