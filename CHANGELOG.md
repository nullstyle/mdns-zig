# Changelog

## Unreleased

### M2 - sockets, interfaces, Service shell; Linux column filled

- `src/platform/ifaces.zig`: self-declared `getifaddrs`/`freeifaddrs`
  externs and `struct ifaddrs` layouts for Darwin, Linux (glibc and musl),
  FreeBSD and OpenBSD; `IFF_UP`/`IFF_LOOPBACK` asserted against
  `std.os.linux.IFF`, `IFF_MULTICAST` hard-coded (`0x1000` Linux, `0x8000`
  elsewhere); the pure fold `fromIfaddrs` (up + multicast only, loopback
  on request, `Service.Options.interfaces` allow-list, netmask to
  `prefix_len`, v6 global-first link-local-last, 8 addresses per family
  with the overflow in `v4_dropped`/`v6_dropped`, KAME scope cleared) and
  `diff()`. The plan's named tests exist under their exact names.
- `src/core/events.zig`: `Event`, `Warning`, `Interface`, `Family`,
  `Limits`, `Stats`, `Resolved`, `ServiceDesc` and friends as pointer-free
  values (checked at comptime), plus the drop-oldest `EventQueue`.
- `src/core/engine.zig`: the plan section 5 `Engine` surface with M2 stub
  internals (`setInterfaces`, `handle` with `dropped_malformed` /
  `dropped_bad_port`, a fixed `_services._dns-sd._udp.local` PTR query
  every 2 s per interface per family; `advertise`/`updateTxt`/`browse`
  return `error.NotImplemented` until M3/M4).
- M2 review fixes: `Service.sendDatagram` / `flushTx` propagate
  `error.Canceled` instead of counting it as a drop (Threaded cancelation
  is one-shot, so a `Group.cancel` landing on a send used to be lost and
  `serve` never returned); `serve` now backs off one step cap after a
  fatal step error and counts it in `rxCounters().fatal_errors` instead
  of re-stepping at once; datagrams with `MSG_TRUNC` are counted in
  `rxCounters().truncated` and never handed to the Engine; the step wait
  floor and the send timeout are 2 ms (`min_wait_us`), because Threaded
  truncates a 1 ms timeout to `poll(0)`; `socket_opts.control_buffer_size`
  is 128 on FreeBSD and OpenBSD (the `IP_RECVIF` + `IP_RECVDSTADDR` +
  `IP_RECVTTL` v4 set needs 120 / 96 B, a deviation from plan 4.5's
  `[8][64]u8`; 64 elsewhere); `EventQueue` moved to `core/events.zig`
  (the unused `EventRing` is gone; the named ring test targets the shipped
  type); `ifaces.decodeIfaddrs` calls `if_nametoindex` only for inet
  entries; BSD header citations in `docs/platform-matrix.md` replaced the
  `(unverified)` tags; `mdns-live` stops after four fatal step errors.
- `src/service.zig`: `Service` (two blocking sockets on `*:5353`, batch
  buffers allocated once at `init`, `Timed` helpers with no `.none`
  member, modes A `tick`, B `step`/`run`, C `serve` over a `Mailbox`,
  `refreshInterfaces`, `firstBinder`, `sockets`, warnings
  `v6_unavailable`/`join_failed`/`no_interfaces`/`no_packets_10s`, send
  failures counted in `stats.tx_dropped`). `mdns.Service`, `mdns.Mailbox`,
  `mdns.Engine` and `mdns.core` are exported from the module root.
- `tests/live/main.zig` -> `zig-out/bin/mdns-live` (`zig build live --
  --seconds N [--ifindex N ...] [--no-ipv6] [--no-loopback]`); plain
  `zig build [-Dtarget=...]` installs it, which is the compile-only check
  for the BSD targets. `tests/service_test.zig`: the real-socket public-API
  tests.
- `build.zig`: `test-exe` installs both test binaries under `zig-out/test/`
  without running them so a cross build can be executed elsewhere.
  `justfile`: `lima-test` (replaces `lima-linux`, which could no longer
  compile `tests/root.zig` without `build_options`) and `lima-live`.
- Linux (Lima `zig-uring`, Fedora 44, kernel 6.19.10, static
  `aarch64-linux-musl`): `mdns-unit-tests` 89/89 and `mdns-api-tests`
  22/22 pass in the VM; `mdns-live` binds beside avahi-daemon (uid
  `avahi`) and systemd-resolved with `first_binder=false`, joins `lo` (v4)
  and `eth0` (both), decodes a pktinfo ifindex on 100% of received
  datagrams in both families; `first_binder=true` once **both** daemons
  are stopped (stopping avahi alone is not enough on Fedora, where
  systemd-resolved also holds `*:5353`). Details, including the
  `IP_MULTICAST_ALL` measurements, in `docs/platform-matrix.md`, "Linux
  runs (M2)".
- macOS: `zig build live -- --seconds 3` beside mDNSResponder with
  `dns-sd -B` running: `first_binder=false`, 17 interfaces joined, 31/31
  v4 and 65/65 v6 datagrams with a decoded ifindex; `--ifindex 15` (en0)
  joins one ifindex per family with no `join_failed`.
- Fixes from the Linux runs:
  - `IPV6_MULTICAST_ALL` (29, Linux, absent from `std.os.linux.IPV6`) is
    set to 0 beside `IP_MULTICAST_ALL`: without it the v6 socket received
    every `ff02::fb` datagram on interfaces only avahi had joined
    (measured: 6 datagrams with no v6 join, 0 after the fix).
  - A loopback interface without `IFF_MULTICAST` (Linux `lo`, flags
    `0x9`) is kept for v4 only under `include_loopback`: the v6 join
    succeeds but every send to `ff02::fb` via `lo` fails with
    `ENETUNREACH`, which showed as `tx_dropped=2` per 4 s and failed the
    API test's `tx_dropped == 0` assertion in the VM.
- FreeBSD and OpenBSD: `zig build` and `zig build test-exe` for
  `aarch64-freebsd` and `aarch64-openbsd` (and `x86_64-linux-gnu`) compile;
  none ran (documented as "compile-only, reviewed, not run").
- Known deviations from the plan text: `Service.Options.include_loopback`
  keeps Linux `lo` although it lacks `IFF_MULTICAST` (v4 only, above);
  the plan's Linux acceptance line needs systemd-resolved stopped as well
  as avahi on Fedora.

### M1 - wire codec, fixtures, fuzz

- `src/wire/*` (`mdns.wire`, with `Bounded`, `Name`, `Txt`, `TxtPair`
  re-exported at the top level): the zero-allocation codec. `Name` with
  bounded compression decode (pointers backward-only and strictly
  decreasing, at most 64 hops, targets never inside the header; loops,
  forward and self pointers are `error.Malformed`), RFC 6763 §4.3 escaping,
  case-insensitive `eql`/`hash`, and the RFC 6335 §5.1 service-name
  validator. `Message.parse` validates the whole walk once (9000 B cap,
  trailing bytes tolerated) and hands out zero-copy question and record
  iterators with the QU and cache-flush bits split out. `rdata` codecs for
  A/AAAA/PTR/SRV/TXT/NSEC/HINFO plus the RFC 6762 §8.2 canonical comparison.
  `Txt`/`TxtView` with the 400 B limit, case-insensitive first-match keys and
  the boolean-vs-empty distinction. `Builder` with a 128-entry compression
  table (owner names and PTR/SRV/NSEC rdata), 1472/1452 soft targets,
  8972/8952 hard caps, the one-RR-over-MTU rule with full rollback on
  `error.NoSpace`, section ordering, and legacy mode (TTL capped at 10 s, no
  cache-flush bit, no SRV target compression). No `unreachable`, `@panic` or
  unchecked slicing on any byte fed from the network. The nine tests the
  plan names for M1 exist under those exact names.
- `docs/conformance.md`: the RFC clause matrix (RFC 1035 §3.1/§4.1, RFC 6762
  §5-§18, RFC 6763 §4/§6/§7/§9/§12, RFC 6335 §5.1, plus a library-behaviour
  table) with columns Clause | Requirement | Status | Test name. Every test
  the plan names for M1-M5 is assigned to a clause; the M1 tests, the
  fixture tests and the fuzz targets are `done`, the rest carry their
  milestone.
- `tests/conformance_test.zig`: `conformance doc names only existing tests`
  reads the matrix at runtime and fails when a `done` row names a test that
  does not exist as `test "<name>"` under `src/` or `tests/` (plus two
  parser unit tests). The repo path comes from the new `build_options`
  module (`repo_root`, absolute, from `b.root` via `realPath`) that
  `build.zig` attaches to the `tests/root.zig` module.
- `tests/fixtures/loader.zig`: ordered iterator over
  `tests/fixtures/raw/NNNN.hex` + `.json` (hex decode into a caller buffer,
  sidecar `source`/`ifindex`/`family`/`len` via `std.json` with unknown
  fields ignored) and the test `fixtures load and hex length matches sidecar
  len` over all 122 fixtures.
- `tests/codec_test.zig`: the corpus through the public API. `every fixture
  parses` (all 122 parse to exactly the payload end; every rdata of a known
  type decodes; PTR/SRV/TXT/A/AAAA/NSEC all present), `fixture re-encode is
  decode-equal` (each fixture rebuilt through the Builder parses back to the
  same header, questions and records, rdata compared after decompression;
  on this corpus every rebuild is also byte-identical), `fixture goodbye
  records have TTL 0`, `fixture probes use qtype ANY with proposed records
  in authority` (the captured mDNSResponder probes have QU clear, so QU is
  counted, not required), `fixture TXT records parse as key=value`.
- `tests/fuzz_test.zig`: four `std.testing.fuzz` targets over the Smith API
  (`smith.slice`, `smith.value*`): `fuzz Message.parse never panics`, `fuzz
  Name.decode never panics`, `fuzz Txt.iterate never panics`, `fuzz Builder
  round trip`, seeded with seven fixtures (embedded at comptime) and the
  malformed corpus, framed with the 4-byte length prefix Smith expects on
  replay; `fuzz corpus seeds replay through Smith as intended` guards that
  framing. Each target also runs as a plain test over its corpus. Measured
  on this Mac (aarch64, 0.17.0-dev.1786): `--fuzz=N` is N runs per target;
  10K takes about 2 s, 100K about 3 s, 2M about 58 s (8.4M runs, roughly
  145K runs/s, no findings). The default backend is LLVM here, so
  `-Duse-llvm` is not needed locally; `-Duse-llvm=false` now means
  "compiler default" because `-fno-llvm` hung the test compile on this pin.
- `build.zig`: `-Duse-llvm` option forwarded to both test binaries (needed
  for coverage on x86_64, harmless on aarch64); `build_options.repo_root`.
- `justfile`: `fuzz N="10K"` (`-Duse-llvm=true --fuzz=N`, whole test step,
  never with `-Dtest-filter`) and `conformance` (lists rows not yet `done`,
  then runs the suite).
- Review fixes (M1):
  - `Builder` compresses only against a prior occurrence with identical
    bytes (ASCII case included), so the uncompressed rdata a peer
    reconstructs is exactly the `Name` passed in; RFC 6762 §8.2 compares
    uncompressed rdata octet by octet, and the M4 tie-break can therefore
    use local record values. (mDNSResponder folds case; all 122 fixtures
    still rebuild byte-identical and `fixture re-encode is decode-equal`
    now asserts that.) `fuzz Builder round trip` is byte-exact by design.
  - Legacy mode never compresses the NSEC next-domain name (RFC 4034
    §4.1.1 via RFC 6762 §6.7), in addition to the SRV target.
  - `Options.hard_limit` can only lower the cap; it is clamped to the RFC
    6762 §17 payload cap of the family (8972 / 8952).
  - `Rdata.txt` is validated as a sequence of length-prefixed strings
    (`error.InvalidTxt`) and an empty slice is written as one zero octet
    (RFC 6763 §6.1); `.raw` stays verbatim. The 400 B bound stays with
    `Txt`.
  - `Nsec.set`/`fromTypes` return `error.TypeOutsideWindow0` for types
    over 255 and `error.NsecBitNotAllowed` for type 47 (RFC 6762 §6.1);
    `Nsec.wireBitmap` (used by `encodeNsec` and the Builder) never emits
    the NSEC bit. `decodeNsec` rejects duplicate or out-of-order window
    blocks (RFC 4034 §4.1.2); trailing zero octets are tolerated.
  - `docs/conformance.md`: rows now name the test that proves the clause
    (RFC 1035 §4.1.1-§4.1.3, RFC 6763 §4.3); wire-level rows for RFC 6762
    §16, §18.12, §18.13, RFC 6763 §6.1/§6.3/§6.5 are `done` with the Engine
    rows kept separately; new RFC 4034 table. The guard scan skips
    `.zig-cache`/`zig-out`.
  - CI `fuzz` lane enabled: `zig build test -Duse-llvm=true --fuzz=1M`
    (about 60 s on the hosted runner, advisory, 20 min cap).
  - `Name` deviates from the plan §5 `Bounded(u8, 255)` sketch on
    purpose: same `len`/`buf`/`slice()` shape, root by default, built only
    through validating constructors (documented on the type).

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
