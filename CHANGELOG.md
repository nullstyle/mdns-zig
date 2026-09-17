# Changelog

## Unreleased

## 0.1.1 - 2026-09-17

Two bugs found by real use on one multi-homed Mac (qmesh-zig `--mdns`
and shared-studio `--discover`), plus the API they needed. No
flood-guard budget changed.

### Fixed

- **Same-host echo drop (B1).** A second program on the same host
  browsing the same type sends a query byte-identical to ours (ID 0,
  one question, empty known-answer list) from our own address, so it
  passed both own-echo tests and was dropped unanswered; the peer
  resolved us only when its query happened to fall outside the 2 s echo
  window (qmesh `seeds joined=0`, `rx_echo` counting the peer's lookup
  queries). `Engine.handle` now stops an echoed response or probe
  (Authority section present) at the echo test and lets an echoed plain
  query through to the responder. The cost is answering our own ladder
  queries when we browse a type we advertise (about 36 packets per pair
  per day under the 1 s rate rule); the bridged-echo re-announce and the
  conflict logic are unchanged. `Stats.rx_echo_answered` counts the
  answered echoes. Named test: `byte-identical query from our own
  address is still answered`; `byte-identical query from a foreign
  source is not an echo` still passes.
- **Echo window 2 s -> 1 s.** `timers.echo_window_us` is now sized
  from the longest round trip an echo can take back into `handle`: the
  path (a bridged echo through a Wi-Fi access point's DTIM hold,
  100-300 ms) plus the mode-B step cap (one 250 ms timed receive per
  step) plus mode C's mailbox wait (250 ms per event while the
  `Mailbox` is full), 800 ms worst case; mode A ages an echo by the
  embedder's tick cadence plus `rx_poll_interval_us`, so tick at least
  every ~500 ms and keep `rx_poll_interval_us` at or below ~100 ms
  (both option docs say so). The window no longer decides whether a
  query is answered, only whether a response or a probe is ours; an
  echo later than the window is parsed as a cooperating peer's packet
  (identical rdata, never a conflict), which loses the section 10.2
  re-announce for a late bridged announcement echo (test `late bridged
  echo is a peer response, not a conflict`). `bridged echo re-announces
  address records` keeps its name and now drives the re-announce with a
  fresh answer instead of replaying a 1.5 s-old datagram; the bounce
  back across the bridge is asserted suppressed by the 1 s rule.
- **Multi-homed address choice (B2).** A browser gets one `resolved`
  per interface it hears a responder on, and on a Mac with a Lima bridge
  the first can carry only `192.168.215.0` (the bridge subnet's base,
  undialable) or a VPN tunnel address; `SeedSet` admitted one `Contact`
  per `(id, epoch)`, the first, so qmesh joined an address the peer was
  not listening on. See the API below. A live capture also showed the
  first announce cohort on a freshly bound v4 socket all leaving on the
  last `IP_MULTICAST_IF` set (bridge101), so a `lookup --once` started
  at the same instant as the advertiser heard only that interface; that
  Darwin send-path quirk is documented as an open follow-up, not fixed
  here.

### Added

- `Resolved.preferredAddress(local: []const Interface) ?IpAddress` and
  `Resolved.preferred(local) ?Preferred{addr, rank, key}`: the best entry of
  `addrs` ranked against the browser's own `Service.interfaces()`
  (`AddrRank`: on-link on the arrival interface, on-link on any local
  interface, global v6, foreign-subnet v4, scoped link-local; the
  network base of a local prefix, `0.0.0.0`, `::` and an unscoped
  `fe80::` are never returned). With an empty table the pre-0.1.1
  v4-first order applies. `mdns.rankAddress` is the per-address rule;
  `Preferred.betterThan(other)` is the one comparison between two
  candidates (it reads the stored `key`, so it holds with or without a
  table; `AddrRank.better` is the raw with-table order only), and
  equal-ranked candidates keep first-arrival order.
- `profiles.qmesh.SeedSet.accept(&resolved, local)` re-admits an
  `(id, epoch)` when a strictly better-ranked address arrives
  (`SeedStats.readmitted`, `Contact.rank`); the consumer must tolerate a
  second `Contact` per id (qmesh's `startJoin` is safe to repeat, see
  `docs/integration.md`). `pickAddr(&resolved, local)` wraps
  `preferredAddress`.
- `profiles.studio.dialCandidate(&resolved, local) ?Preferred` and
  `dialAddress`: the same ranking minus link-local v6, for
  shared-studio's endpoint ring.
- Named tests: `preferredAddress ranks on-link same-interface first`,
  `SeedSet re-admits a better address for the same id and epoch`,
  `studio profile ranks the dialable on-link address first`.

### Changed (API)

- `SeedSet.accept` and `qmesh.pickAddr` take the local interface table
  as a second argument (`&.{}` for the old behaviour).
- `Stats` gains `rx_echo_answered`; `SeedStats` gains `readmitted`;
  `Contact` gains `rank`.

## 0.1.0 - 2026-09-16

First release. Every item below is in the tarball unless it says
otherwise; the milestone record after the summary has the details, the
review fixes and the measurements.

### Wire codec (`mdns.wire`)

- Zero-allocation `Name` (bounded compression decode, RFC 6763 §4.3
  escaping, ASCII case folding, RFC 6335 §5.1 service-name validator),
  `Message` parse with zero-copy question and record iterators (QU and
  cache-flush bits split out, 9000 B cap), rdata codecs for A, AAAA,
  PTR, SRV, TXT, NSEC (restricted form) and HINFO with the RFC 6762 §8.2
  canonical comparison, `Txt` / `TxtView` (400 B, case-insensitive
  first-match keys, boolean vs empty), and a `Builder` with a
  compression table, 1472 / 1452 targets, 8972 / 8952 hard caps, section
  ordering and legacy mode. No `unreachable`, `@panic` or unchecked
  slicing on any byte fed from the network.

### Engine, querier and cache (`mdns.Engine`, `src/core/`)

- Sans-IO `Engine`: `handle` / `tick` / `pollDatagram` / `nextDeadline`
  / `pollEvent` / `stats` over a caller clock and an injected
  `std.Random`; every pool preallocated from `Limits`; `handle` never
  allocates or fails after `init` (FailingAllocator sweep). Ingress
  rules: own-echo recognition (digest ring AND source address), OPCODE /
  RCODE, source port 5353, §11 on-link check, the 2 s QU window.
- Querier: browses on the §5.2 ladder (20-120 ms, then 1 s doubling to
  60 min, +0-2 %), QM only, one packet per joined (interface, family)
  pair with the known-answer list (§7.1, TC continuation §7.2), requery
  marks at 80/85/90/95 % merged into the schedule, follow-up SRV / TXT /
  A / AAAA questions on the instance's interface, order-independent
  harvesting, `found` / `lost` only for browsed types, the `resolved`
  re-emit rule (SRV, TXT or address-set change; never a same-data
  refresh; `ttl_s` = shortest RR TTL), `stopBrowse` keeps the cache,
  `error.DuplicateBrowse`.
- Cache keyed by `(name, type, class, ifindex)`: cache-flush (§10.2, 1 s
  grace), goodbye (§10.1, 1 s), expiry, eviction by soonest expiry with
  pins on the records the resolve join consumes, secret-seeded buckets,
  per-interface `found` / `resolved` / `lost` (one row per interface,
  as `dns-sd -B`), interface removal drops its scope.
- `timers.zig`: every RFC 6762 constant with its section, the 24 h query
  budget (35 + 1) derived at comptime.

### Responder

- Registrations with host A / AAAA per interface (TTL 120), SRV (120),
  TXT and PTR (4500); probing (§8.1: 0-250 ms, three probes 250 ms
  apart, qtype ANY, Authority section, QU only when first binder), §8.2
  tie-break, announcing twice with cache-flush (§8.3), §9 conflicts
  (re-probe the same name first; rename `Name (2)` / `<label>-2` only
  after a failed probe; 15 conflicts in 10 s arm a 5 s backoff), host
  rename re-announces every SRV (§8.4).
- Answering (§6): unique records at once, shared PTRs after 20-120 ms
  (400-500 ms after TC), aggregation per pair, known-answer suppression
  at half TTL, the 1 s rate limit per (record, interface, family) with
  probe defence at 250 ms, NSEC for any absent type under a unique name
  (§6.1) and for the missing address family (§6.2), per-interface
  addresses, RFC 6763 §12 additionals, legacy unicast replies (§6.7: ID
  echoed, questions repeated, TTL <= 10, no cache-flush, uncompressed
  SRV, 512 octets with TC), QU replies with the TTL/4 rule per question
  (§5.4), direct-unicast queries answered as QU (§5.5), no unicast reply
  to an off-link source (§11), multicast defence for same-host and
  shared-port probes.
- `updateTxt` as a §8.4 re-announce (no probe, no-op on identical
  rdata, deferred while probing, `error.TxtTooLarge` over 400 B keeps
  the old TXT); goodbyes on `withdraw` and on `deinit` (bounded flush,
  aggregated per pair); the bridged-echo re-announce (§10.2) under the
  1 s rule as a drop; two announcements on a new or re-addressed
  interface (no per-link re-probe, see Known limitations).

### Service and loop modes (`mdns.Service`, `mdns.Mailbox`)

- Two raw-bound sockets on `*:5353` (`SO_REUSEADDR` + `SO_REUSEPORT`,
  `first_binder` from a trial bind), joins per interface with
  `warning.join_failed{ifindex, family}` / `v6_unavailable` /
  `no_interfaces` degrades, an `ifindex` allow-list, `include_loopback`,
  `refreshInterfaces` on a 30 s cadence, batch buffers allocated once,
  events by value through `poll`.
- Mode A `tick(now_us)` with the embedder's clock and the
  `rx_poll_interval_us` drain rule; mode B `step(cap)` (timed wait on one
  socket, zero drain of the other, 250 ms cap) and `run(shutdown, hook)`;
  mode C `serve(&mailbox)` as an `Io.Group` task with the bounded
  `Mailbox.put` (non-blocking put, 10 ms retries up to the step cap, then
  drop oldest and count; `warning.events_dropped` once; a closed mailbox
  ends `serve`). One clock source per Service, asserted.
- `lookup(type, {timeout_us, quiet_us}, out)`: bounded one-shot browse
  that stops its browse on every exit path, `error.Canceled` honoured,
  one slot per `(instance, type, ifindex)`. `advertise` / `updateTxt` /
  `withdraw` / `browse` / `stopBrowse` validate at the call and are
  applied at the next tick with that tick's clock (`advertise` and
  `browse` return their ids at once from a reservation without a
  timer). `serve` ends with the goodbye flush on both exits. `stats()`
  sums Engine and Service counters; `rxCounters()` / `txCounters()` for
  operators.
- Timed calls only: `recvTimed` / `sendTimed` take a `Timed` with no
  `.none` member. Blocking fds under `Io.Threaded`; on Darwin an
  `O_NONBLOCK` send window around each send batch plus `SO_SNDLOWAT =
  SO_SNDBUF`, so a stalled send is a 2 ms timeout and a counted drop.
  `warning.no_packets_10s` for the macOS Local Network privacy case.

### Platform (`src/platform/`)

- `socket_opts.zig`: per-OS constant tables for Darwin, Linux, FreeBSD
  and OpenBSD with comptime cross-checks against std, `setsockoptChecked`
  with a typed errno map, raw bind, `trialBindWithoutReuse`, group join
  / leave (`ip_mreq` / `ip_mreqn` / `ipv6_mreq`), TTL and hop limit 255
  for multicast and unicast, `IP_MULTICAST_ALL` / `IPV6_MULTICAST_ALL`
  off on Linux, pktinfo / `IP_RECVIF` cmsg codec at 4- and 8-byte
  alignment, per-send `IP_MULTICAST_IF` where needed (the BSDs' v4
  path, and on Darwin before every v4 multicast send beside the pktinfo
  cmsg: with it unset a pktinfo send naming `lo0` succeeds once and then
  fails `ENETUNREACH` for good), the send-window and low-water helpers.
- `ifaces.zig`: self-declared `getifaddrs` / `freeifaddrs` and `ifaddrs`
  layouts per OS, up + multicast filter (Linux `lo` kept for v4 only
  under `include_loopback`), netmask to prefix length (short Darwin
  masks handled), v6 global-first order, 8 addresses per family with
  `v4_dropped` / `v6_dropped`, `diff()`.

### Profiles (`mdns.profiles`)

- `qmsg`, `qmesh` and `studio` TXT schemas (plan §3.4): `Advert` builders
  and `parse` for `_qmsg._udp`, `_qmesh._udp` and `_shared-studio._udp`
  (`txtvers=1`, `alpn`, `spki` / `id` as exactly 64 lowercase hex,
  `epoch` up to 32 hex, `sn`, `pat`, `role`, `clip`), the qmesh
  `SeedSet` (one admission per `(id, epoch)`), and an import graph of
  std plus mdns value types only.

### Examples and interop

- `examples/browse.zig` (`mdns-browse [--once] <type>`), `advertise.zig`
  (`mdns-advertise --type --name --port --txt k=v`; SIGUSR1 bumps
  `seq=<n>` through `updateTxt`, SIGINT sends the goodbye) and
  `peer.zig` (`mdns-peer <name>`: advertise + browse in one process).
- `interop/macos-dnssd.sh` (six `dns-sd` checks incl. conflicts both
  ways and the TXT update), `lima-avahi.sh` (avahi resolves us; clashes
  both ways), `flood-count.sh` (packet budgets without tcpdump),
  `legacy_query.py`, `probe_defence.py`, `interop/README.md`.

### Tests

- `zig build test` in Debug and ReleaseSafe (300+ tests): codec round
  trips and a malformed corpus, 122 packet fixtures from
  mDNSResponder with JSON sidecars (decode, byte-identical re-encode,
  goodbye and probe shapes), every plan M1-M4 named test, the fake-LAN
  harness (`tests/harness/`: N engines, per-interface fan-out, loopback
  echo, loss, bridging, a scripted responder) with 10 k seeded timing
  iterations, FailingAllocator sweeps, real-socket public-API tests,
  the flood guards (idle advertise sends nothing; 24 h browse budget;
  100 simultaneous probers converge; bridged echoes never rename), six
  `std.testing.fuzz` targets over the codec and `Engine.handle`, the
  conformance guard (`docs/conformance.md` rows marked `done` must name
  existing tests), and `tests/live/main.zig` (`zig build live`).
- `tests/consumer`: out-of-tree smoke build against the package.

### Docs, build and CI

- `README.md`, `docs/design.md` (layers, loop modes, clock rule, timed
  calls and the Darwin send window, cache model, every timer with its
  RFC section, pool sizes, error policy, protocol rules as implemented,
  deviations from the plan), `docs/conformance.md` (every RFC clause
  with a status and a test), `docs/platform-matrix.md` (constants,
  structs, coexistence, macOS and Linux measurements), `SECURITY.md`.
- `build.zig`: module `mdns` (links libc), plain `standardOptimizeOption`
  with a fast/small refusal, early return for dependency builds, steps
  `test`, `test-exe`, `live`, `examples`, `example-*`, `docs`,
  `spike-*`, `-Dtest-filter`, `-Duse-llvm`; `build.zig.zon` with
  consumer-only `.paths` (no `tests/`, `spikes/`, `interop/`).
- CI: Debug and ReleaseSafe on ubuntu, Debug on macos-15 (hermetic),
  quality lane (`mise fmt`, `zig fmt` over build.zig, src, tests,
  spikes and examples, `zig build docs`, `tools/release-check.sh`, the
  `git archive` tarball check with the consumer smoke inside the
  extracted package), advisory live lane with avahi (`zig build live --
  --seconds 3`), advisory fuzz lane (`--fuzz=1M`, 20 min cap). All
  actions SHA-pinned. `justfile` recipes for all of it, `tools/
  release-check.sh` with the `v` tag prefix.

### Known limitations

- No per-link re-probe on interface add (RFC 6762 §8 "Link Change"):
  two announcements instead. M6.
- `_services._dns-sd._udp` meta-query, `_sub` subtypes, §7.3 / §7.4
  duplicate suppression, §10.3-§10.5 cache flush on topology change and
  POOF, v6 address-flag filtering. M6.
- The Mac / Lima two-peer demo needs a bridged VM network; Lima's
  user-mode NIC does not carry multicast.
- FreeBSD and OpenBSD compile with reviewed constants; not run.

### Milestone record

The development history behind the summary, newest first.

#### M5 - loop modes, lookup, profiles, flood guards, docs

- Queued mutations (plan §4.2, Revision 7 item 7 closed): `advertise`,
  `updateTxt`, `withdraw`, `browse` and `stopBrowse` go through
  `Service.PendingMutation` (64 slots, ~26 KB inline in the Service;
  a full queue applies at once with the last tick's clock rather than
  losing the mutation). `advertise` returns its `RegId` from
  `Engine.reserveRegistration` (the slot holds the validated copy, the
  queue carries only the id); `browse` returns its `BrowseId` from
  `Engine.reserveBrowse` (slot and duplicate check taken, no timer) and
  `startBrowse` at the next tick schedules the 20-120 ms first query
  and runs the warm start from that tick's clock. `updateTxt` carries
  the built `Txt`. Tests: `advertise before first tick starts probing at
  first tick`, `stopBrowse is applied at the next tick`, `browse before
  the first tick is scheduled at that tick`, `reserved browse holds its
  slot without a timer until started`.
- `serve` (mode C) and `Mailbox`: `Mailbox.put` with the plan's full
  policy, `warning.events_dropped` once, `isClosed` polled each
  iteration. Behaviour change vs M4: `serve` withdraws every
  registration and runs the goodbye flush on BOTH exits (closed mailbox
  -> normal return; `Group.cancel` -> `error.Canceled`), so a program
  that closes the mailbox and serves again must advertise again.
  `Group.concurrent` on `Threaded.global_single_threaded` returns
  `error.ConcurrencyUnavailable` before `serve` runs (verified: its own
  `Task.create` with the `.failing` allocator).
- `lookup(type, {timeout_us, quiet_us}, out)`: the M3.1 code deduped per
  `(instance, type)` across interfaces despite Revision 6 item 1; it is
  now per `(instance, type, ifindex)` (`mergeResolved`, test `lookup
  keeps one slot per instance per interface`). Size `out` by instances
  x interfaces; `mdns-browse --once` prints one line per interface.
- Darwin: with `IP_MULTICAST_IF` unset, a v4 multicast `sendmsg` whose
  `IP_PKTINFO` names `lo0` succeeds once and then fails `ENETUNREACH`
  forever (C-verified on macOS 26; other interfaces unaffected). Every
  v4 multicast send on Darwin is now preceded by a best-effort
  `setsockopt(IP_MULTICAST_IF, ip_mreqn{ifindex, addr})`
  (`Service.pktinfo_needs_multicast_if`); `docs/platform-matrix.md`
  "macOS runs (M5)".
- Profiles (`src/profiles/`): `qmsg`, `qmesh`, `studio` schemas,
  `SeedSet` (one admission per `(id, epoch)`; when full it evicts the
  entry admitted longest ago by a per-entry admission counter, which
  holds after `forget` too; the review found the ring-cursor version
  could evict the newest entry after a swap-remove), the import-graph
  test. `docs/integration.md` for shared-studio (mode A from
  `ss_tick`), qmesh-zig (`on_iteration`), qmsg (beside `Node.tick`) and
  a foreign QUIC loop.
- Flood guards (`tests/flood_guard_test.zig`, tier 1, simulated time):
  a 24 h browse sends <= 36 queries per interface with gaps that double
  up to 3600 s (+2 % jitter, so <= 3672 s); an idle advertised service
  sends 3 probes + 2 announcements per pair and then nothing for a day;
  a hundred simultaneous probers of one name converge to `Same`,
  `Same (2)` .. `Same (100)` with 4950 renames in 3484 packets (3083
  probes, 401 responses; busiest engine 50; bounds 4000 / 60), 543
  backoffs, settled at 69 simulated seconds, 1.3-1.5 s of Debug wall
  clock on this Mac (ReleaseSafe far under); bridged echoes never rename;
  two browsers of one type get at most two answers in an hour (§7.1;
  §7.3 between browsers is M6); a 1000-probe storm gets 41 multicast
  defences (one per 250 ms) and, as QU, 1000 unicast replies at 125 B
  each for 81 B probes (1.5x, asserted under 2x; see `SECURITY.md`).
- Loopback tests (`tests/loop_test.zig`) use per-process names
  (`_mdnszig-XXXX._udp`, `quiet-XXXX`, `loop-adv-XXXX`) so two suites on
  one host cannot answer or rename each other's instances.
- Suite time: the public-API test binary went from ~9 s to ~29 s in
  Debug (the loopback tests sleep 2.5 s for the peer to probe and
  announce: serve-goodbye ~3.5 s, lookup-quiet ~3.5 s, lookup-replace
  ~5 s, mailbox-drop 2.5 s); Revision 6 item 10 asked to watch this.
- Review fixes: the flood-guard summaries are `std.log.debug` (the
  earlier `std.log.warn` and a wall-clock print made every green run
  print `failed command`); `docs/conformance.md` rows for the M5 tests
  flipped to `done` and rows added for the four flood guards and the
  serve goodbye rule; `just tarball-check` resolves the pinned compiler
  before leaving the checkout; the `lima-*` recipes use the ssh form.

#### M4 - responder: registrations, probing, announcing, answering, conflicts, goodbyes

- `src/core/responder.zig` (new): the sans-IO responder behind
  `Engine.advertise` / `withdraw` / `updateTxt`. Host A/AAAA per
  interface (TTL 120) plus per-instance SRV (120) and TXT (4500) as
  unique RRSets and the shared PTR (4500); probing per RFC 6762 8.1
  (0-250 ms, three probes 250 ms apart, qtype ANY, proposed records in
  Authority without cache-flush, QU only when `first_binder`), the host
  set probed with the first registration; 8.2 tie-break over sorted
  record sets (one comparison per name per packet; a loser waits 1 s, a
  second loss renames); 8.3 announcing twice 1 s apart with cache-flush
  on unique records, `registered` after the second one; section 9
  conflicts re-probe the same name first and rename (`Name (2)`,
  `<label>-2`) only after a failed probe, 15 conflicts in 10 s arm a 5 s
  backoff, a host rename re-announces every SRV (8.4); section 6
  answering: unique records at once, shared PTRs after 20-120 ms (400-500
  ms after TC), aggregation per (interface, family) pair, 7.1 known-
  answer suppression at half TTL, the one-second rate limit keyed by
  (record, interface, family) with probe defence exempt, 6.1 NSEC for
  any absent type under a unique name (bitmap per interface), 6.2
  per-interface addresses, 6.7 legacy unicast replies (ID echoed,
  question repeated, TTL <= 10, no cache-flush, uncompressed SRV), 5.4
  QU replies with the TTL/4 rule, RFC 6763 section 12 additionals;
  probe defence at once, by multicast plus a unicast copy when the
  prober is on our own host or the port is shared; 10.1 goodbyes on
  `withdraw` (host records with the last registration); 8.4 `updateTxt`
  (two TXT-only announcements with cache-flush, no probe; identical
  rdata is a no-op; deferred while probing; over 400 B is
  `error.TxtTooLarge` and keeps the old TXT); the bridged-echo hook
  re-announces the arrival interface's address RRSet under the
  one-second rule. Pools from `Limits` (registrations capped at 256,
  pending answers, six jobs per interface, the rate table), no
  allocation after `init`, deadlines by a scan over the pools.
- `Engine`: `Options.first_binder` (plus `setFirstBinder` /
  `firstBinder`), `InitError.InvalidHostLabel` (one UTF-8 label, 1..63
  octets, no control characters or dots; Revision 5 item 8),
  `withdrawAll`, `registrationCount`, `hostName`, `responderStats`;
  queries and responses are routed to the responder (conflict detection
  on our unique names), responder packets drain before querier packets,
  a QU probe opens the 2 s unicast window, `nextDeadline` and `stats`
  (`conflicts`, `answers_dropped`, dropped jobs into `tx_dropped`) fold
  the responder in; `setInterfaces` announces on new or re-addressed
  interfaces. `AdvertiseError` / `UpdateTxtError` lose `NotImplemented`
  and gain `InvalidTxt`.
- `Service`: passes `first_binder` to the Engine; `advertise` and
  `updateTxt` are applied at the call (stamped like `browse`); `deinit`
  withdraws every registration and runs a bounded goodbye flush (two
  send rounds) before leaving the groups; `InitError.InvalidHostLabel`.
- `core/timers.zig`: `probe_tiebreak_wait_us` (8.2, 1 s),
  `defence_rate_limit_us` (6, 250 ms).
- Review fixes (M4 review): probe defence keeps 250 ms between
  multicasts of a record per interface (6; deferred, not dropped, so a
  burst of probes gets one defence per 250 ms) instead of a blanket
  exemption, and an Authority record counts as a probe only with a
  question for that name in the packet (8.2); an announcement queued for
  the host is not sent once the host re-probes after a conflict or said
  goodbye (8.1, 10.1, 10.2); section 7.2 continuation known answers trim
  the answer still waiting for that querier; the NSEC for the missing
  address family rides in the additionals of address answers on
  one-family interfaces (6.2); a query delivered by direct unicast is
  answered as QU (5.5) and the QU bit is honoured per question (5.4);
  legacy replies echo every question (up to 4) in one 512-octet packet
  with TC on overflow (6.7) and never go to an off-link source (11),
  nor does a QU unicast reply; a query from source port 0 is dropped;
  goodbyes aggregate per pair so `withdrawAll` never drops one
  (`Engine.stats` folds the new `queries_off_link` / `queries_bad_port`
  into `dropped_off_link` / `dropped_bad_port`); a conflict while
  probing renames only after the current name was actually probed (9),
  bounding renames to the probe rate; `catch unreachable` is gone from
  the rename path. Not done, tracked in `docs/conformance.md`: no
  per-link re-probe on "Link Change" (8). `build.zig` gains
  `-Dtest-filter=<substring>` (repeatable) for both test binaries, which
  also selects the `--fuzz` target. `interop/probe_defence.py` injects
  a foreign probe from a shared 5353 socket and times the multicast
  defence (single probe, or a burst that must yield one defence per
  250 ms).
- Tests: `tests/responder_test.zig` with the 23 plan M4 named tests
  (`probe timing` sweeps 10 k seeds: first probe in [0, 250] ms, +250,
  +250, announcements 250 ms after the third probe and 1 s later) plus
  withdraw / aggregation / validation coverage, `handle never fails
  after init under a FailingAllocator sweep with a registration` (every
  failure index; the allocation count never moves after `init`), and an
  end-to-end section over `tests/harness/fake_lan.zig` with real engines
  on both sides (multicast loopback on): `advertise then browse on a
  second engine resolves within 3 simulated seconds` (nothing answered
  while probing), `withdraw sends goodbye and the browser emits lost
  within 1s`, `idle advertised service sends nothing after announcing`
  (exactly 3 probes + 2 announcements per joined pair over 30 s, then
  silence), `a query flood is answered at most once per second per
  pair`, `simultaneous probers of one name converge to distinct names`
  (four hosts, one name, bounded budget, then silence), `a second stack
  on our own IP loses to the multicast defence and renames`, `bridged
  interfaces re-announce the echoed addresses and never rename`. Inline
  unit tests for the tie-break compare, KA predicate, NSEC bitmap, rate
  table, rename helpers and validators. `tests/fuzz_test.zig`: `fuzz
  Engine.handle never panics` now advertises one instance before
  fuzzing (responder paths under random input; emitted datagrams are
  checked against the section 18 header rules) beside the dedicated
  `fuzz Engine.handle with a registration never panics` target;
  `docs/conformance.md` M4 rows flipped to `done`.
- Responder fixes found by the LAN tests: the bridged-echo re-announce
  (RFC 6762 10.2) applies the one-second rule as a drop instead of a
  deferral (a deferred re-announce landed after the peers' flush grace,
  flushed the other interface's set and echoed back across the bridge,
  one packet per second per pair, forever; now a multi-homed host on
  bridged links settles after at most one bounce); an interface that
  joins or changes its addresses is announced twice one second apart
  (8.3 "Link Change"), not once.
- `tests/live/main.zig`: `--advertise NAME` registers
  `NAME._mdnszig._udp` on 4433 and prints `registered` / `renamed` /
  `host_renamed`; `RESULT` gains `conflicts=`. Verified on macOS beside
  mDNSResponder (`dns-sd -B` Add on every interface ~1.9 s after start,
  Rmv on exit, `dns-sd -L` resolves host, port and TXT; ours-first
  conflict makes `dns-sd -R` rename to `demo (2)`) and in Lima beside
  avahi (`avahi-browse -r` resolves per-interface addresses; avahi-first
  conflict renames us to `demo (2)`, ours-first makes avahi pick
  `demo #2`).

#### M4 examples and interop (plan section 7 M4 deliverables)

- `examples/advertise.zig` (`zig-out/bin/mdns-advertise`, `zig build
  example-advertise -- ...`): registers one instance from the command
  line (`--type`, `--name`, `--port`, `--txt k=v` repeatable, `--host
  <label>` defaulting to the OS host name sanitized to one
  letter-digit-hyphen label, `--no-ipv6`, `--ifindex N` repeatable,
  `--loopback`, `--stats`), mode B `Service.run`, prints `registered` /
  `renamed` / `host_renamed` / `warning` lines. SIGINT and SIGTERM flip
  the shutdown atomic so `deinit` sends the goodbye (RFC 6762 10.1);
  SIGUSR1 counts a TXT bump that the run hook applies through
  `Service.updateTxt` as `seq=<n>` (8.4: re-announce, no probe). Signal
  handlers only touch atomics.
- `examples/peer.zig` (`zig-out/bin/mdns-peer <name>`): the two-peer
  demo, advertise `_mdnszig._udp` on 4433 with `role=peer` and browse
  the same type in one process; prints `peer <instance> at <addr>:<port>
  ifindex <n>` on `resolved` and `peer <instance> gone` on `lost`,
  skipping its own registration by instance label (tracked across a
  `renamed`).
- `build.zig`: `example-advertise` and `example-peer` run steps
  (forwarded args, install-only on cross builds); `zig build examples`
  installs all three example binaries.
- `interop/macos-dnssd.sh`: six `dns-sd` checks with PASS/FAIL lines,
  deadlines (`perl -e 'alarm N; exec @ARGV'`, no coreutils `timeout` on
  macOS) and an EXIT cleanup trap: `-B` lists us within 3 s, `-L` shows
  port and TXT, goodbye shows `Rmv` within 3 s, conflict with `dns-sd -R`
  first (we rename to `demo (2)`), conflict with ours first (mDNSResponder
  renames), SIGUSR1 -> `-L` shows `seq=1`.
- `interop/legacy_query.py`: stdlib-only one-shot query from an ephemeral
  port to 224.0.0.251:5353; parses the unicast reply and reports ID
  echoed, TTL <= 10, cache-flush clear and SRV target uncompressed (RFC
  6762 6.7, 18.14); exit 0 only when all four hold. Calibration: it
  flags mDNSResponder's `.local` pointer inside the SRV rdata.
- `interop/lima-avahi.sh`: runs inside the Lima VM (ssh form; `limactl
  shell` hangs): `avahi-browse -prt` resolves our cross-built advertise;
  `avahi-publish` first -> we rename; ours first -> `avahi-publish`
  reports a collision or renames. Checks the binary is a Linux build.
- `interop/flood-count.sh`: tcpdump-free packet budget. Runs the
  `join_pktinfo` spike with `--dump` for the window, keeps datagrams
  whose sidecar source is one of this host's addresses and whose payload
  contains the wire-encoded name, prints counts by QR bit and second, and
  asserts `--assert idle-advertise` (0 unsolicited after `--after`,
  default 30 s; a response is solicited when a foreign query for the
  name preceded it within 2 s) or `--assert idle-browse` (<= 2 queries
  after minute one).
- `interop/README.md` (macOS and Lima instructions, exit codes),
  justfile recipes `examples`, `example-advertise`, `example-peer`,
  `peer-demo`, `interop-macos`, `interop-lima`, `flood-count`,
  `legacy-query` (`lima_ssh` variable for the ssh form).

#### M3 gate fixes - Darwin send window; per-interface cache

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

#### M3 - querier, cache, resolve join; Engine internals replace the stub

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

#### M2 - sockets, interfaces, Service shell; Linux column filled

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

#### M1 - wire codec, fixtures, fuzz

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

#### M0 - scaffold and first macOS spike

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

#### Known risks

- `std.Io.Threaded` completes a timed receive/send after `poll(2)` with an
  untimed `operate` whose `WouldBlock => unreachable` (`Threaded.zig:2555`,
  `:2573`) would trap on a spurious readiness report. Linux `udp_poll`
  produces one for bad-checksum UDP datagrams on `O_NONBLOCK` fds only, so
  the mDNS sockets stay blocking under Threaded; the fork's Dispatch
  backend (M6, needs `O_NONBLOCK`) must mitigate first (accept-all BPF via
  `SO_ATTACH_FILTER`, or a backend fix upstream). See
  `docs/platform-matrix.md`, "Known risks and decisions for M2".
