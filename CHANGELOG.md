# Changelog

## Unreleased

### M3 gate fixes - Darwin send window; per-interface cache

- P1, `mdns-live` hang on macOS with the default interface set: the
  first `sendmsg` of a query round could sleep forever. xnu's
  `sosendcheck` ignores `MSG_DONTWAIT` for the send-buffer wait (only
  `O_NONBLOCK` / kernel-private `MSG_NBIO` return `EWOULDBLOCK`), and a
  content filter (`net.cfil`: Little Snitch, Tailscale, Clawpatrol on the
  gate Mac) holding a fresh multicast flow for a verdict keeps `sbspace`
  short, so `Io.Threaded`'s DONTWAIT-first timed send never reached its
  `poll` timeout. `Service` now opens a "send window" on Darwin
  (`socket_opts.send_window_needs_nonblock`): `O_NONBLOCK` on both
  sockets for one send batch, cleared before the next receive, so a
  send the kernel will not take within `send_timeout_us` is
  `error.Timeout` and a counted drop. `bindMdnsSocket` raises
  `SO_SNDLOWAT` to `SO_SNDBUF` on Darwin (`raise_send_lowat`) so the
  post-poll send of the timed path can never see `EWOULDBLOCK` (which
  Threaded maps to `unreachable`). Linux and the BSDs honour
  `MSG_DONTWAIT` and are untouched (comptime no-op). New
  `Service.txCounters()` (`timeouts`, `slow`, `max_us`,
  `window_failed`), printed by `mdns-live`; `socket_opts.setNonBlockingFlag`,
  `isNonBlocking`, `getsockoptInt`, `raiseSendLowat`. Tests: `send window
  sets O_NONBLOCK only while sending`, `send window flag toggles
  O_NONBLOCK and restores it`, `bound mDNS socket has its send low-water
  mark raised to the send buffer`, `egress skips a joined pair whose
  interface has no address of that family` (the pure filter behind
  Revision 5 item 1, which was already in place). docs/platform-matrix.md
  "Darwin send path" has the xnu citations and the live result (3/3
  default-set runs complete in 3.3 s beside `dns-sd -R`).
- P2, `resolved` flicker with a multi-homed responder: mDNSResponder
  answers a browse once per interface, each answer carrying only that
  interface's A/AAAA with cache-flush set, and the `(name, type, class)`
  cache let every answer flush the other interfaces' addresses after 1 s
  (7 `resolved` in 8 s cycling three address sets). The cache key is now
  `(name, type, class, ifindex)` (`Entry.keyEql` takes the interface,
  `Entry.rrsetEql` is the old three-part compare; `Cache.lookup` walks
  every interface, `lookupOn` / `countLiveOn` one); cache-flush and
  goodbye act within one interface; an `Instance` is (PTR target,
  interface) and every join lookup, pin, requery mark, follow-up and
  known-answer decision is scoped to it, so `found` / `resolved` / `lost`
  fire once per interface with that interface's addresses (RFC 6762
  §6.2, §14; the same per-interfaceIndex model as `dns-sd -B`).
  `Service.lookup` keeps the plan section 5 contract, one slot per
  instance: a later `resolved` for the same instance replaces the
  earlier copy whichever interface it came from (`mergeResolved`, test
  `lookup keeps one slot per instance across interfaces`), so `out`
  sized by the expected instance count is enough; the per-interface
  stream is `browse`'s. Cost: a responder heard on k
  interfaces uses k copies of each record (README "Known risks" has the
  sizing rule). Adjusted test: `upsert with identical rdata refreshes TTL
  and reports unchanged` no longer expects a refresh from another
  interface to move the entry (it is a second entry now). New tests:
  `cache-flush only flushes records from the same interface`,
  `multi-homed responder yields one stable resolved per interface`,
  `lost fires per interface`, `bridged segments report the same responder
  once per interface`; `KA half-TTL filter` checks the interface. Live:
  `mdns-browse _qmsg._udp` beside `dns-sd -R` prints 3 `found` + 3
  `resolved` (ifindex 15, 25, 27, each with its own addresses) in the
  first 2 s, nothing more for 8 s, and 3 `lost` after `dns-sd` exits.
- Review follow-ups on the two fixes:
  - An interface that leaves the table (`Engine.setInterfaces` from
    `Service.refreshInterfaces`) now takes its cache scope with it:
    `Cache.expireInterface` / `Querier.dropInterface` run the expiry
    path over that interface's records (`lost{ifindex}` for its browsed
    instances right after `.interfaces_changed`, instances freed, pins
    dropped), because with the per-interface key nothing could refresh
    them; before, they lingered to their TTL (a `lost` up to 75 min
    after the interface vanished), kept requerying on the surviving
    pairs, and would attach to a reused ifindex. `Engine.pollDatagram`
    re-checks that a built packet's pair is still joined and counts a
    stale job in `tx_dropped` instead of handing the platform a pktinfo
    for an interface it no longer has. Harness: `FakeLan.setInterfaces`.
    Tests: `interface removal drops its cached records and emits lost`,
    `pollDatagram drops a queued job for a pair that is no longer
    joined`.
  - Follow-up questions and requery marks are scoped to the interface
    of the instance / record (`Question.ifindex`; `buildNext` leaves
    them out of the other pairs' packets and encodes each question once
    per packet, `addDue` treats an every-pair entry as covering the
    scoped one), so a multi-homed querier's follow-ups no longer
    multiply with the interface count. Browse PTR questions still go to
    every joined pair. Test: `follow-ups for an instance found on one
    interface stay on that interface`.
  - `Service.flushTx` opens the Darwin send window lazily on the first
    datagram: an idle step costs no `fcntl` (was 8 per step at the 250
    ms cap). New `TxCounters.window_opened` (printed by `mdns-live`);
    `send window sets O_NONBLOCK only while sending` now asserts an
    empty flush toggles nothing.
  - docs/platform-matrix.md "Darwin send path": the `Threaded.zig`
    post-poll send citation is `:2573` (`:2555` is the receive one), and
    a note on the one send errno class (`EINVAL` & co.) Threaded maps to
    `errnoBug` (Debug panic), which xnu does not return for an unusable
    pktinfo interface (`ENXIO` / `EADDRNOTAVAIL`); the joined+addressed
    pair filter plus the `pollDatagram` re-check is the guard.
- `tests/live/main.zig` header: if a run hangs, `sample <pid> 2` before
  killing it.

### M3 - querier, cache, resolve join; Engine internals replace the stub

- `src/core/querier.zig`: browses with the RFC 6762 section 5.2 ladder
  (first query 20-120 ms, then 1 s doubling to 60 min, +0-2 % jitter),
  QM-only questions (section 5.4), every due question merged into one
  packet per joined (interface, family) pair (section 5.3) with the
  known-answer list (section 7.1, half-TTL rule) continued over further
  packets with TC (section 7.2); requery marks at 80/85/90/95 % (+0-2 %)
  only for records a browse cares about; order-independent harvesting of
  answers and additionals into the `(name, type, class)` cache (now
  `(name, type, class, ifindex)`, see the gate fixes above); `found`
  / `lost` only for browsed types (a foreign PTR is cached silently and a
  later browse starts warm); the `resolved` re-emit rule (again on SRV,
  TXT or address-set change, never on a same-data refresh, `ttl_s` = the
  shortest RR TTL); follow-up SRV/TXT/A/AAAA questions on their own
  ladder; link-local AAAA carries the arrival ifindex; `stopBrowse` keeps
  the cache.
- `src/core/engine.zig`: real internals behind the section 5 surface:
  own-echo ring AND source-address test (bridged echoes recorded for the
  M4 hook), `dropped_ignored` for OPCODE/RCODE != 0, source-port rule,
  section 11 on-link check for unicast destinations, the 2 s QU window
  (`dropped_unicast_unexpected`), joined (ifindex, family) pairs with
  `setJoined` (Revision 5 item 1; `Service` syncs them after every
  snapshot), `error.DuplicateBrowse`. `Stats` gains `rx_echo`,
  `rx_echo_bridged`, `dropped_ignored`, `dropped_unicast_unexpected`.
  `advertise` / `updateTxt` stay `error.NotImplemented` until M4.
- `src/core/cache.zig`, `timers.zig`, `echo_ring.zig` (foundation; see
  their module docs), `tests/harness/{scenario,fake_lan,packets}.zig`,
  `tests/{querier_test,dnssd_test}.zig` with every plan M3 named test,
  `fuzz Engine.handle never panics`, and a FailingAllocator sweep.
- `mdns-live` browses `--browse <type>` (default `_qmsg._udp`) and prints
  `found` / `resolved` / `lost`; verified against `dns-sd -R` on macOS.
- `examples/browse.zig` (`zig build example-browse -- <type>`, installed
  as `zig-out/bin/mdns-browse`): continuous browse in mode B
  (`Service.run` with a SIGINT-flipped shutdown atomic) printing `found`
  / `resolved` (host, port, addresses, TXT, `ttl_s`) / `lost` lines;
  `--once` prints "not yet" until M5. Verified against `dns-sd -R` on
  macOS (found, resolved port 4433, lost after the goodbye) and, cross
  built for `aarch64-linux-musl`, against `avahi-publish` in the Lima VM.
  `zig build examples` installs every example; `just example-browse`,
  `just examples`, `just lima-browse`.
- M3 review fixes. Querier: requery marks (RFC 6762 section 5.2) and
  eviction pins are derived from the resolve join, so they no longer
  depend on record order (SRV/TXT/A before the PTR, or the host's A a
  packet before the SRV, were never re-queried and silently expired);
  only the records the join consumes are pinned (one SRV and TXT per
  instance, 8 + 8 addresses per host), so junk SRV/A records for a found
  instance cannot fill the pool with protected entries; the ladder
  stores the jittered gap so consecutive gaps keep the factor of two;
  a question that does not fit one tick's batch retries at the next
  tick; a goodbye for an instance's PTR/SRV/TXT stops its follow-up
  ladder; `resolved.addrs` holds 8 A + 8 AAAA (`max_resolved_addrs`);
  instances are indexed by SRV-target hash and by PTR slot, so A/AAAA
  harvesting and pin checks never walk the instance table. Cache:
  `Flags.pinned` replaces the per-candidate `Pinned` predicate (one
  pass per eviction; a full pool of descending TTLs went from 2.9 s to
  ~3 ms per 9000 B packet), a pool with every entry pinned evicts the
  soonest-expiring pinned entry and reports it through `EvictHook`
  instead of rejecting the newcomer, bucket indexes are keyed with a
  per-cache secret seed (`Cache.init(gpa, n, seed)`), section 10.2 keeps
  a record that is exactly one second old ("more than one second ago"),
  and the RFC arithmetic lives once in `timers.zig` (`requeryMarkUs`,
  `expiryUs`, `kaOmit`, now saturating). Engine: `RxMeta.dst_known`
  (a datagram without a destination cmsg is on-link checked but not
  dropped by the QU-window rule), `Stats` gains `rx_dst_unknown`,
  `evictions_pinned`, `cache_rejected`, `instances_dropped`,
  `questions_deferred`; `rx` is documented as including echoes.
  Service: `no_packets_10s` ignores own echoes; `browse` before the
  first `step` (and in modes B/C) is stamped with `nowUs()`;
  `RxCounters.no_dst`; the joined-pair sync has a test. `timers.zig`
  documents why the M3 querier memoises scans instead of using
  `DeadlineSet` (reserved for M4).
- `tests/harness/fake_responder.zig`: a scripted DNS-SD responder (static
  instance table, PTR / SRV / TXT / A / AAAA answers via `wire.Builder`,
  knobs for record order, additionals, cache-flush, TTLs, TC, source
  port, unicast replies, known-answer suppression, goodbye) that sits on
  a `FakeLan` segment; seven LAN-level tests in `dnssd_test.zig` drive a
  browse end to end through it (resolve, KA suppression, requery
  refresh, bad source port, unicast reply, goodbye, two queriers).

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
