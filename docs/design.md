# Design

This document describes mdns-zig v0.1.0 as built. Where the code differs
from the plan (`mdns-zig-plan.md`), this document follows the code. The
last section lists every such difference.

Section numbers in the form `§n` refer to RFC 6762 unless another RFC is
named. Plan section numbers are written "plan §n".

## 1. Layers

Dependency arrows point down. The Engine never imports `platform`.
`src/service.zig` is the only file that imports both `core` and
`platform`.

```
consumers: shared-studio / qmsg apps / qmesh Runner glue
   |   mdns.profiles.{qmsg,qmesh,studio}   TXT schema <-> std types only
   v
mdns.Service        std.Io shell: Engine + 2 sockets + interface table; ONE caller thread
   |   tick(now_us) | step(cap) | run(shutdown, hook) | serve(*Mailbox) as an Io.Group task
   v
mdns.Engine         sans-IO core: handle(bytes, meta, now_us) / tick / pollDatagram / nextDeadline / pollEvent
   |   core/{responder, querier, cache, timers, echo_ring, events}.zig   (no Io, no sockets, no clock)
   v
mdns.wire           codec: parse / build, compression, RR types, TXT, escaping (zero allocation)
---------------------------------------------------------------------------------------
mdns.platform       socket_opts.zig (raw bind, join, pktinfo, cmsg codec), ifaces.zig (getifaddrs)
[M6, reserved]      mdns.backend.dns_sd behind the same Service surface
```

"Sans-IO" means the core never touches a socket or a clock. The caller
feeds bytes and time. The core returns bytes, deadlines and events.

The profiles module (`src/profiles/*`) imports only `std` and the mdns
value types. A unit test proves the import graph. This keeps the TXT
schemas usable from a consumer that never links the Service.

## 2. The Engine contract

`Engine` (`src/core/engine.zig`) has six entry points on the hot path.

- `handle(datagram, RxMeta{from, ifindex, dst_multicast, dst_known, ttl}, now_us)`
  feeds one packet. It never returns an error. It never allocates.
- `tick(now_us)` fires due timers.
- `pollDatagram(buf, now_us) -> ?TxDatagram{len, to, ifindex}` drains one
  outbound packet into the caller's buffer. It never allocates.
- `nextDeadline(now_us) -> ?u64` returns the next timer.
- `pollEvent() -> ?Event` returns one value-type event.
- `stats() -> Stats` returns monotonic counters.

`now_us` is `u64` microseconds from a caller-owned origin. Randomness is
one `std.Random` injected at `init`. Every RFC jitter draws from it. The
Engine preallocates every pool in `init` from `Limits`. After `init`
nothing on a network path allocates or fails on OOM. A `FailingAllocator`
sweep in the tests proves this for `handle`.

Mutations on the Engine take `now_us`: `setInterfaces`, `advertise`,
`withdraw`, `updateTxt`, `browse`, `stopBrowse`. Mutations on the Service
do not take a clock. Section 3.4 says how the Service stamps them.

Ingress order in `handle`:

1. Own-echo test (section 8.1). An echo is counted and goes no further.
2. `wire.Message.parse`. Malformed input is `stats.dropped_malformed`.
3. OPCODE or RCODE not zero is `stats.dropped_ignored` (§18.3, §18.11).
4. A response (QR=1) from a source port other than 5353 is
   `stats.dropped_bad_port` (§6). A query from another port is a legacy
   query (§6.7). A query from source port 0 is dropped.
5. A unicast-destination packet is checked on-link against the arrival
   interface's prefixes (§11). Off-link is `stats.dropped_off_link`. A
   unicast response is then accepted only within 2 s of our own QU query.
   Otherwise it is `stats.dropped_unicast_unexpected`. When the platform
   reported no destination address (`dst_known = false`), the on-link
   check runs and the QU-window drop does not.
6. Responses go to the querier and to the responder (conflict detection).
   Queries go to the responder.

## 3. Loop ownership

mdns-zig never spawns a thread. One `Service` runs in exactly one of three
modes, on one caller thread, over one Engine.

### 3.1 Mode A: tick-polled

`Service.tick(now_us)` uses the embedder's clock. It applies queued
mutations, drains both sockets when the drain rule says so, ticks the
Engine, sends, and runs the interface refresh on its cadence
(`iface_refresh_ms`, default 30 s).

The drain rule (`shouldDrain`) is: drain when nothing was drained yet,
when `rx_poll_interval_us` (default 5000) has passed since the last
drain, or when `nextDeadline` is due. A 1 ms caller therefore pays the
receive syscalls about every 5 ms. mDNS does not need sub-10 ms receive
latency.

`tick` asserts that `now_us` never goes backwards. A non-monotonic clock
is an embedder bug, not a network input.

### 3.2 Mode B: self-driven blocking

`Service.step(cap)` does one bounded wait. It reads its own clock
(`nowUs()`), computes the wait as `clampToDeadline(nextDeadline, now,
cap)`, does one timed receive on one socket and a zero-duration drain of
the other, re-reads the clock, and runs the same work as `tick`.

`clampToDeadline` returns the cap when there is no deadline. It returns
`min_wait_us` (2 ms) for a due or sub-2 ms deadline, never zero, so a
due-but-unfired deadline cannot spin. Otherwise it waits until the
deadline, rounded up to whole milliseconds, and never longer than the
cap. The cap is at most `max_step_cap_us` (250 ms). The floor is 2 ms,
not 1 ms, because `Io.Threaded` truncates the remaining time to whole
milliseconds for `poll(2)` and a 1 ms timeout measured a few
microseconds later is `poll(0)`.

The timed receive alternates between the v4 and the v6 socket on every
step. The other socket gets a zero-duration drain. This bounds probe
defence latency to one step cap in the worst case (measured 2-201 ms).
An `Io.Batch` over both sockets is a follow-up (plan §11 decision 6).

`Service.run(shutdown, hook)` loops `step` with the 250 ms cap until the
caller-owned `shutdown: *std.atomic.Value(bool)` reads true. After every
step it calls `hook.f(ctx, service, now_us)`. A hook error ends `run`
with that error. Idle CPU stays low: four wakeups per second when nothing
is due.

`Service.lookup(type, opts, out)` is mode B. It starts a browse, loops
`step` and copies `resolved` events into `out`. It returns when `out` is
full, when `timeout_us` has passed, or when `quiet_us` has passed with at
least one result and no new `resolved`. On every exit path, including
errors and `error.Canceled`, it stops the browse directly on the Engine
with the current clock. No later tick is needed. `lookup` keeps one slot
per `(instance, type, ifindex)` (`mergeResolved`). The cache and the
`resolved` stream are per interface, so a responder heard on k
interfaces fills k slots, each with that link's addresses. A later
`resolved` for the same key (a TXT or address change) replaces the
earlier copy in place. `lookup` discards every event that is not
`resolved`. `lookup` on a type that already has a browse fails with
`error.DuplicateBrowse`.

### 3.3 Mode C: Io.Group task

`Service.serve(mailbox)` runs mode B as a task and pushes every event
into a `Mailbox`. The caller starts it with `Group.concurrent`, never
`Group.async`. `Group.async` may run the task inline on
`Threaded.global_single_threaded` and block the caller forever. On a
single-threaded `Io`, `Group.concurrent` itself returns
`error.ConcurrencyUnavailable` and `serve` never runs. `Group.cancel`
delivers `error.Canceled` at the next receive, sleep or queue operation.
`serve` has two exits, and both run the bounded goodbye flush (every
registration withdrawn, two send rounds, as in `deinit`): it returns
`error.Canceled` after `Group.cancel`, and it returns normally once the
mailbox is closed. After either exit the Service holds no registrations.
Under Threaded cancelation is one-shot, so the flush's sends go through.

`Mailbox` wraps `Io.Queue(Event)` over a caller-owned buffer. Its
capacity is the buffer length. `Mailbox.next(io)` returns
`Io.Cancelable || error{Closed}`. `Mailbox.close(io)` ends `serve` at
its next iteration, at most one step cap later. Queued events stay
readable until `error.Closed`.

**Mailbox full policy.** A full mailbox never blocks `serve` for longer
than one step cap. `Mailbox.put` first tries a non-blocking put
(`Queue.put(io, &.{ev}, 0)`). If the queue is full, it sleeps in 10 ms
rounds (`mailbox_retry_us`) and retries, for at most the cap (250 ms).
If the queue is still full, it removes the oldest event with
`Queue.get(io, &one, 0)`, counts the drop in `Mailbox.dropped`, and puts
the new event. `serve` mirrors `Mailbox.dropped` into
`Service.stats().events_dropped` and emits `warning.events_dropped`
once. This is the same drop-oldest rule as the Engine event ring
(section 6).

`serve` does not stop on a fatal step error. It counts the fault in
`rxCounters().fatal_errors` and sleeps one step cap before the next step.
A persistent local fault then costs four steps per second, never a spin.
The sleep is also a cancelation point.

### 3.4 Clock-source rule

A Service binds to one clock source for its lifetime. Mode A uses the
embedder's `now_us`. Modes B and C call `tick` with `nowUs()`. `nowUs()`
is `origin.durationTo(Timestamp.now(io, .awake)).toMicroseconds()`,
clamped at zero. The origin is taken at `init`.

The first `tick` sets the mode flag to `.tick`. The first `step`, `run`,
`serve` or `lookup` sets it to `.step`. A later call in the other mode
hits `std.debug.assert` (`modeAfter` returns null). Debug and
ReleaseSafe are the only supported modes, so the assert is always
active. A program that needs both `lookup` and `tick` uses two Services
(plan §3.2): the short-lived `lookup` Service is deinitialised before the
tick-mode Service exists.

**Mutation stamps.** `advertise`, `updateTxt`, `withdraw`, `browse` and
`stopBrowse` validate at the call and are queued in `PendingMutation`
(`max_pending_mutations` = 64 slots). The queue is applied at the start
of the next `tick` or `step` with that call's clock (plan §4.2).
`advertise` and `browse` still return their ids at once: the Engine
reserves the slot without scheduling (`reserveRegistration`,
`reserveBrowse`; a reserved browse already refuses a duplicate and
counts in `browseCount`, but has no timer), and the next tick starts
probing (`startRegistration`) or schedules the first query 20-120 ms
from that tick's clock and runs the warm start (`startBrowse`). So in
mode A the first probe and the first query count from the embedder's
`now_us`, and in modes B/C from the first `step` after the call; the
`init` -> `browse` -> `run` pattern loses nothing. `updateTxt` builds
the TXT at the call and applies it at the next tick, where identical
rdata is a no-op. `lookup` drives its own loop in mode B and starts its
browse directly with the Service clock.

When the queue is full, the mutation is applied at once, stamped with
`mutationClock()` (the last tick's `now_us` in mode A, else `nowUs()`,
never below the last tick), so it is never lost. That stamp never moves
`last_now_us`. Nothing goes out before the next `tick` or `step` in
either case. That is the observable half of plan §4.2.

## 4. Timed calls only, and why the sockets block

Every receive and send in `service.zig` goes through two private
helpers, `recvTimed` and `sendTimed`. They take a `Timed` value. `Timed`
has `.duration` and `.deadline` members and no `.none` member. An untimed
call is a compile error. This is plan §4.3 "Timed calls only".

**Why the sockets are blocking (Revision 3).** On `Io.Threaded` a timed
receive polls first and then does one `recvmsg`. That `recvmsg` maps
`error.WouldBlock` to `unreachable`. On Linux, `udp_poll` hides a
bad-checksum datagram only for a blocking fd. On an `O_NONBLOCK` fd one
malformed LAN datagram would make `poll` report readable, `recvmsg`
return `EAGAIN`, and the library trap. So the sockets stay blocking fds.
Threaded passes `MSG_DONTWAIT` per call, so a zero-duration receive is
still a non-blocking drain. `error.Timeout` on a zero-duration receive
means "nothing to read". A Threaded timed receive returns at most one
message after a real wait, so every later round of a drain is a
zero-duration call (`max_drain_rounds` = 64 rounds of up to 8 messages).

**The Darwin send window (Revision 6).** xnu's `sosendcheck` ignores
`MSG_DONTWAIT` for the send-buffer wait. It honours only `O_NONBLOCK`.
With a content filter active (Little Snitch, Tailscale, MDM agents) a
new UDP multicast flow can sit at `sbspace == 0` until the filter gives
a verdict, and a blocking-fd `sendmsg` sleeps in the kernel for as long
as that takes. It once hung `mdns-live` forever in the first `sendmsg`
of a query round. So on Darwin `flushTx` sets `O_NONBLOCK` on both
sockets for one send batch (`openSendWindow`) and clears it before
`flushTx` returns (`closeSendWindow`), before any receive can see it. A
short buffer is then `EWOULDBLOCK`, then a `poll(POLLOUT)` bounded by
`send_timeout_us` (2 ms), then `error.Timeout`, then a counted drop.
`bindMdnsSocket` also raises `SO_SNDLOWAT` to `SO_SNDBUF`, so a
`POLLOUT` wakeup guarantees the datagram fits and the post-poll send
never reaches Threaded's `WouldBlock => unreachable`. The window opens
lazily on the first datagram, so an idle step costs no `fcntl`. On Linux
and the BSDs `MSG_DONTWAIT` works and the window is a comptime no-op.
`txCounters()` reports `timeouts`, `slow`, `max_us`, `window_failed` and
`window_opened`.

`error.Canceled` from a send is the one send error that propagates. Under
Threaded cancelation is one-shot. A `Group.cancel` that lands on a send
must end the loop there or it is lost.

## 5. Cache model

The cache (`src/core/cache.zig`) is a preallocated pool of
`Limits.max_cache_records` entries (default 4096). Each entry holds one
resource record with its rdata copied. The key is
`(name, type, class, ifindex)`. Names compare ASCII case-insensitively
(§16). Records with the same key form one RRSet. A response updates the
RRSet in place, so the order of records inside a packet does not matter.

**Why the interface is in the key (Revision 6).** A multi-homed
responder answers on each interface with only that interface's addresses
and the cache-flush bit set (§6.2). With a three-part key every
interface's answer flushed the other interfaces' addresses after 1 s and
`resolved` flickered once a second. With the interface in the key,
cache-flush, goodbye, expiry, `found`, `lost`, `resolved`, known-answer
lists and requery marks are all per interface (§6.2, §14). This is what
mDNSResponder does (one `dns-sd -B` row per interfaceIndex). The cost:
a responder heard on k interfaces uses k entries per record. Size
`max_cache_records` as interfaces x records per instance (about 5) x
instances. An interface that leaves the table takes its records with it
and emits `lost` for its browsed instances.

**The resolve join.** The querier harvests every answer and additional
record first. Then it joins SRV, TXT, A and AAAA to each instance of a
browsed type. An instance is (PTR target, interface). `found` fires when
its PTR enters the cache. `lost` fires when the PTR leaves it. A PTR for
a type without an active browse is cached and emits nothing, so a later
browse of that type starts warm.

**The `resolved` re-emit rule.** `resolved` fires when the instance's
SRV, TXT and at least one address are live on the instance's interface.
It fires again when the SRV rdata changes, when the TXT rdata changes,
or when that interface's address set changes (added, removed, expired).
A refresh that carries the same data does not fire. `Resolved.addrs`
holds at most 8 A and 8 AAAA. `Resolved.ttl_s` is the shortest remaining
TTL among the records that built the value. A consumer that only needs a
change signal compares the new value with its last copy.

**Rules on cached records.** Cache-flush (§10.2): a record with the
cache-flush bit marks every other record of the same key that is older
than 1 s to expire in 1 s. A record exactly 1 s old is kept. Goodbye
(§10.1): a record with TTL 0 is kept for 1 s and then removed, so
`lost` fires one second after the goodbye. Expiry: a record is removed
at `received + TTL`. Eviction: a full pool evicts the soonest-expiring
record that is not pinned (`stats.evictions`). Pinned records are the
ones the resolve join consumes: browsed PTRs, one SRV and one TXT per
instance, and up to 8 + 8 addresses per host. When every entry is
pinned, the soonest-expiring pinned entry goes instead
(`stats.evictions_pinned`), so a full pool can never wedge a browse.
Bucket indexes mix the name hash with a per-cache secret seed, so a peer
cannot precompute names that collide.

## 6. Timers and TTLs

Every constant is a named comptime constant in `src/core/timers.zig`
with its RFC section. The values below are the code's values.

| Constant | Value | RFC 6762 |
|---|---|---|
| `ttl_host_s` | 120 (A, AAAA, SRV and the NSEC covering them) | §10 |
| `ttl_other_s` | 4500 (DNS-SD PTR, TXT) | §10 |
| `ttl_legacy_cap_s` | 10 | §6.7 |
| `probe_first_delay_min_us` .. `probe_first_delay_max_us` | 0-250 ms | §8.1 |
| `probe_interval_us`, `probe_count` | 250 ms, 3 probes | §8.1 |
| `probe_tiebreak_wait_us` | 1 s after losing a tie-break | §8.2 |
| `announce_interval_us`, `announce_count` | 1 s, 2 announcements | §8.3 |
| `query_first_delay_min_us` .. `query_first_delay_max_us` | 20-120 ms | §5.2 |
| `query_interval_first_us`, `query_interval_cap_us` | 1 s, doubling, cap 3600 s | §5.2 |
| `query_jitter_max_pct` | 0-2 % of the interval | §5.2 |
| `requery_marks_pct`, `requery_jitter_max_pct` | 80/85/90/95 % of TTL, + 0-2 % of TTL | §5.2 |
| `query_schedule_24h_count`, `query_schedule_24h_budget` | 35 queries per interface in 24 h; budget 36 | §5.2 |
| `answer_delay_min_us` .. `answer_delay_max_us` | 20-120 ms for shared records | §6 |
| `answer_delay_tc_min_us` .. `answer_delay_tc_max_us` | 400-500 ms after a TC query | §6, §7.2 |
| `record_rate_limit_us` | 1 s per (record, interface, family) | §6 |
| `defence_rate_limit_us` | 250 ms per (record, interface, family) for probe defence | §6 |
| `qu_unicast_window_us` | 2 s | §5.4, §6 |
| `qu_multicast_ttl_divisor` | reply by multicast when not multicast within TTL/4 | §5.4 |
| `ka_half_ttl_divisor` | omit a known answer at or past TTL/2 | §7.1 |
| `cache_flush_grace_us` | 1 s | §10.2 |
| `goodbye_grace_us` | 1 s | §10.1 |
| `conflict_backoff_count`, `conflict_backoff_window_us`, `conflict_backoff_delay_us` | 15 conflicts in 10 s gives 5 s | §9 |
| `echo_window_us` | 2 s (own-echo ring) | plan §4.8 |

The §5.2 ladder sends queries at 0, 1, 3, 7, ..., 4095 s and then every
3600 s. That is 13 queries while doubling and 22 more in the rest of the
day: 35 per interface in 24 h. `queryScheduleCount` derives it at
comptime. The flood test budget is 36, one extra for jitter.

**Requery merge rule.** A record the resolve join consumes gets four
requery marks at 80, 85, 90 and 95 % of its TTL, each plus 0-2 % of the
TTL. A due mark folds its question into the next query packet on the
record's interface, together with every other due question (§5.3) and
the known-answer list (§7.1). One packet goes out. Nothing else is ever
re-queried (§5.2 MUST NOT). The marks are armed from the join, so the
order records arrive in does not matter.

**Deadline tracking.** The querier keeps its deadlines on the browse,
instance and cache entries and memoises one `next_deadline` after every
state change. The responder scans its pools. `DeadlineSet` in
`timers.zig` exists and is tested but is unused in v0.1.

## 7. Allocator policy and pool sizes

`Engine.init` takes one `std.mem.Allocator` and preallocates every pool
from `Limits`. `Service.init` allocates its batch buffers once. After
that, `handle`, `tick`, `pollDatagram`, `Service.tick` and `Service.step`
never allocate.

| Pool | Default | Overflow behaviour |
|---|---|---|
| cache records (rdata copied) | `max_cache_records` 4096 | evict soonest-expiring unpinned; then soonest-expiring pinned; count `evictions` / `evictions_pinned` |
| registrations | `max_registrations` 32 (hard cap 256, `RegId` is a `u8`) | `error.LimitReached` |
| browses | `max_browses` 16 | `error.LimitReached`; a second browse of one type is `error.DuplicateBrowse` |
| pending answers | `max_pending_answers` 256 | drop oldest; count `answers_dropped` |
| responder jobs | 8 per joined (interface, family) pair | drop the job; count `tx_dropped`; goodbyes aggregate per pair so `withdrawAll` never drops one |
| event ring | `max_events` 64 | drop oldest; count `events_dropped`; emit `warning.events_dropped` once |
| Service warning queue | `max_events` 64 | same rule, drained by `poll` before the Engine's events |
| interfaces | `max_interfaces` 32 | `error.LimitReached` |
| addresses per interface | 8 per family (`max_addrs_per_iface`, at most 8) | extra addresses dropped; count `addrs_dropped`; `warning.addrs_truncated` once per `setInterfaces` |
| due questions per tick | 256 | retry at the next tick; count `questions_deferred` |
| echo ring | 32 digests | oldest overwritten |
| pending Service mutations | `max_pending_mutations` 64 | applied at once, stamped with `mutationClock()` (last tick in mode A, else `nowUs()`) |
| `Mailbox` (mode C) | caller's buffer | non-blocking put, retry up to the step cap, then drop oldest; count `events_dropped` |

Receive buffers: `[8]IncomingMessage`, 8 x 9000 B of data, and control as
`[8][64]u8 align(8)` (128 B on FreeBSD and OpenBSD). Threaded passes
`message.control.ptr` straight into `msghdr.control`, so control storage
must satisfy `cmsghdr` alignment. The Engine owns two 9000 B scratch
buffers for parse and build. The builder's hard cap on the DNS payload is
8972 B for IPv4 and 8952 B for IPv6, because the §17 limit of 9000 B
includes the IP and UDP headers. A datagram that does not fit its receive
slot (`MSG_TRUNC`) is counted in `rxCounters().truncated` and never
parsed.

Events are values. Every `Event`, `Warning` and `Resolved` is checked
pointer-free at comptime. `poll(out)` copies into the caller's slice.
Callers loop until `poll` returns 0.

TXT bound is 400 B on both sides. `advertise` and `updateTxt` reject a
larger TXT with `error.TxtTooLarge`. A received TXT over 400 B is
truncated in the event and counted in `stats.txt_truncated`.

## 8. Error policy

- **Wire.** Malformed input is never a propagated error. `handle` drops it
  and counts it. No `unreachable` or `@panic` exists on any path fed by
  network bytes. This is the SECURITY.md posture.
- **Build.** `build.zig` uses the plain `standardOptimizeOption` and
  refuses ReleaseFast and ReleaseSmall at configure time. The option map
  `{target, optimize}` works for `tests/consumer` and every downstream
  build. CI runs Debug and ReleaseSafe only.
- **Platform.** `Service.init` surfaces `error.{AddressInUse,
  PermissionDenied, OptionUnsupported, NoMulticastInterface, LimitReached,
  OutOfMemory, Unexpected, InvalidHostLabel}`. `setsockoptChecked` wraps
  `std.c.setsockopt` with a typed errno map. It never uses
  `std.posix.setsockopt`, whose `EINVAL` is `unreachable`.
- **Degrade.** A failed v6 bind is `warning.v6_unavailable`. A failed join
  is `warning.join_failed{ifindex, family}`. With `Options.interfaces ==
  null`, zero joined interfaces at init is `error.NoMulticastInterface`.
  With an allow-list, zero joined interfaces is `warning.no_interfaces`
  and `refreshInterfaces` joins them when they appear (the VPN case). A
  listed index that `getifaddrs` does not report is not an error.
- **Runtime.** Receive errors are classified like quic-zig. `Timeout`
  ends a drain. `ConnectionResetByPeer`, `PortUnreachable`,
  `MessageOversize`, `ConnectionTimedOut` and `SocketUnconnected` are
  tolerated and counted. `Canceled`, `SystemResources`, `NetworkDown`,
  `ConcurrencyUnavailable` and `Unexpected` are fatal for `tick` and
  `step`; `serve` backs off instead. Every send error except `Canceled`
  is a counted drop in `stats.tx_dropped`.
- **API misuse** is a typed error set: `AdvertiseError{LimitReached,
  TxtTooLarge, InvalidTxt, InvalidServiceType, InvalidInstance,
  DuplicateRegistration}`, `UpdateTxtError{TxtTooLarge, InvalidTxt,
  UnknownRegistration}`, `BrowseError{LimitReached, InvalidServiceType,
  DuplicateBrowse}`. The host label must be one UTF-8 label of 1-63
  octets without dots or control bytes.
- **macOS Local Network privacy.** If the Service has sent but received
  no foreign packet for 10 s while at least one interface is joined, it
  emits `warning.no_packets_10s` once. Own echoes do not count.
  `Service.stats()` confirms the case: `tx > 0` with `rx - rx_echo == 0`.

## 9. Thread-safety stance

None inside. No locks. No atomics except the caller-owned
`shutdown: *std.atomic.Value(bool)` that `run` reads. Every `Service`
and `Engine` method belongs to the loop thread, `stats()` included.
Cross-thread delivery is by value through `Mailbox` (whose `Io.Queue`
has its own mutex) or through the consumer's own snapshot. The Darwin
send-window toggle needs no lock for the same reason: one thread.

## 10. Protocol rules as implemented

- **Own-echo recognition.** Multicast loopback is on, so our own packets
  come back. A datagram is an echo only when both tests pass: its digest
  is in the 32-entry ring of recently sent datagrams within 2 s, AND its
  source address is one of our own interface addresses. The digest alone
  is not enough. Multicast query IDs are zero (§18.1), so a peer's first
  browse query for the same type with an empty known-answer list is
  byte-identical to ours, and it must be answered. The source test alone
  is not enough either. mDNSResponder and avahi send from the same IP and
  their packets can be real conflicts. Same IP with different rdata is a
  real conflict.
- **Bridged echo.** An echo that arrives on an interface other than the
  one whose address it carries is counted in `rx_echo_bridged`. When it
  carried cache-flush A/AAAA for our host, the responder re-announces the
  arrival interface's address RRSet at once (§10.2). The 1 s rate rule
  applies as a **drop, not a deferral** (Revision 7). A deferred
  re-announce landed after the peers' flush grace, flushed the other
  interface's set, echoed back across the bridge, and repeated once a
  second forever. With the drop, a multi-homed host on bridged links
  settles after at most one bounce.
- **Conflict order.** A conflicting response for an established unique
  record resets the record to probing with the same name (§9). Only a
  failed probe renames: a conflicting response during probing, or losing
  the §8.2 tie-break twice. A conflict while probing renames only once
  the current name was actually probed, so the visible name moves at the
  probe rate. Fifteen conflicts in 10 s delay the next probe by 5 s.
- **Renames.** A host-name conflict renames the host `<label>-2.local`.
  Every SRV then changes rdata and is re-announced (§8.4). An
  instance-name conflict renames the instance `Name (2)`. The two are
  independent.
- **Probing.** A random 0-250 ms first delay, then three probes 250 ms
  apart, qtype ANY, the proposed records in the Authority section without
  cache-flush, one packet per joined (interface, family) pair. The host
  set is probed with the first registration. QU is set on probes only
  when `first_binder` is true.
- **Announcing.** Two unsolicited responses one second apart, cache-flush
  on the unique records, PTR without. `registered` fires when the second
  one is queued. A new or re-addressed interface gets the same two
  announcements at once. **v0.1 does not re-probe per link** (§8 "Link
  Change"; Revision 7 item 1; an M6 item). A name unique on the old link
  is assumed unique on the new one until a §9 conflict says otherwise.
- **Rate limit.** A record is multicast at most once per second per
  `(record, ifindex, family)`: the egress pair, not the bare interface
  (Revision 7 item 2). A dual-stack link carries each announcement over
  v4 and v6 within the same second. Probe defence is exempt from the 1 s
  rule but keeps 250 ms between multicasts of one record on one pair. A
  defence that comes too early is deferred to that moment, and later
  probes of the burst join it. A query flood therefore gets one answer
  per second per pair, and a probe flood one defence per 250 ms per pair.
- **Probe defence.** A probe for a name we own is answered at once. When
  the prober's source IP is one of our own addresses, or when
  `first_binder` is false, the defence goes by multicast plus a unicast
  copy, and the TTL/4 rule is ignored. A same-host `dns-sd -R` probe
  therefore always sees our defence.
- **Interface model.** `Interface` carries `(address, prefix_len)` pairs:
  up to 8 v4 and 8 v6, v6 global first and link-local last. Per-interface
  A/AAAA answers include every kept address of the sending interface
  (§6.2). The prefixes implement the §11 on-link check for
  unicast-destination packets. v0.1 does not filter v6 addresses by flag
  (tentative, deprecated, temporary); that is an M6 item.
- **Interface allow-list.** `Service.Options.interfaces: ?[]const u32` is
  an allow-list of `ifindex` values. `null` means every interface that
  is up and multicast-capable. Egress uses only joined pairs whose
  interface has an address of that family (Revision 6 item 3). Linux
  `lo` lacks `IFF_MULTICAST`; `include_loopback` keeps it for v4 only.
- **TXT updates.** `updateTxt` replaces the TXT rdata of one registration.
  §8.4 applies: no probe, two announcements 1 s apart with cache-flush,
  under the rate rule. Identical rdata is a no-op. An update during
  probing is applied when the probe succeeds. An update over 400 B fails
  with `error.TxtTooLarge` and leaves the old TXT in place. On the
  querier side a TXT change re-emits `resolved`.
- **QU policy.** Browse queries and follow-up questions are always QM
  (§5.4). QU is set only on probes, and only when `first_binder` is
  true. When an interface is added, every browse ladder restarts from
  its first step (20-120 ms), still QM. The plan's "QU re-query burst
  after `setInterfaces`" is not implemented.
- **QU replies** are unicast unless the record was not multicast within
  TTL/4; then the reply is multicast (§5.4). The QU bit is honoured per
  question. A query delivered by direct unicast is answered as QU (§5.5).
  A unicast reply never goes to an off-link source (§11).
- **Legacy replies** (source port not 5353) echo the ID, repeat every
  question (up to 4), cap TTL at 10 s, clear cache-flush, never compress
  the SRV target or the NSEC next name, and fit one 512-octet packet with
  TC on overflow (§6.7, §18.14).
- **Negative answers.** A query for one of our unique names and a type we
  do not hold gets an NSEC (next = owner, bitmap of the present types),
  per interface (§6.1). An address answer on a one-family interface
  carries the NSEC for the other family in the additionals (§6.2).
- **Unicast TTL** is 255 too (`IP_TTL`, `IPV6_UNICAST_HOPS`), not only the
  multicast TTL (§11).
- **Port sharing.** A trial bind without reuse flags at init sets
  `first_binder`. When the port is shared, a unicast packet to `*:5353`
  reaches exactly one socket, and no code path relies on which. When
  `first_binder` is false, our queries never set QU, so we never depend
  on a unicast reply, and we defend probes by multicast. Any unicast
  response that does not match an outstanding QU query of ours within
  2 s is dropped. Sharing the port means the other stack may lose
  unicast replies addressed to it. On Fedora, `systemd-resolved` also
  binds `*:5353`, so `first_binder` is true only when avahi and
  systemd-resolved are both stopped.
- **Known answers.** A record listed in the query's known-answer section
  with at least half our TTL is omitted from the answer (§7.1). Known
  answers in a TC query's continuation packets trim the answer still
  waiting for that querier (§7.2). Our own known-answer lists omit
  records at or past TTL/2 and continue over further packets with TC.
- **TXT keys** compare ASCII case-insensitively in `Txt.get` and `iter`
  (RFC 6763 §6.4). The first matching key wins.
- **Queries with `ifindex == 0`** (a platform that reports no arrival
  interface) are answered on the first joined pair of the query's family.

## 11. Deviations from the plan

Each line names the revision that recorded it.

- Rev 3: sockets are blocking fds, not `O_NONBLOCK`; every call is still
  timed.
- Rev 3: `zig fetch .` is never run in the checkout; the tarball check
  fetches a `git archive` export.
- Rev 4: `Name` is built only through validating constructors; it is not
  the plain `Bounded(u8, 255)` sketch.
- Rev 4: `Message.parse` tolerates trailing bytes after the last record.
- Rev 4: the Builder compresses only against byte-identical prior
  occurrences (no case folding).
- Rev 5: `include_loopback` keeps Linux `lo` for v4 only (no
  `IFF_MULTICAST` there).
- Rev 5: `serve` backs off on a persistent local fault instead of
  returning; `Mailbox.isClosed` ends it when no events flow.
- Rev 5: the control buffer is 128 B on FreeBSD and OpenBSD (64 B
  elsewhere), not `[8][64]u8` everywhere.
- Rev 5: the step wait floor and the send timeout are 2 ms, not 1 ms.
- Rev 5: `Service.init` returns `error.InvalidHostLabel` for a bad label
  instead of truncating it.
- Rev 6: the cache key is `(name, type, class, ifindex)`, not
  `(name, type, class)`; `found`, `lost` and `resolved` fire per
  interface.
- Rev 6: `Service.lookup` keeps one slot per `(instance, type, ifindex)`,
  not one per instance; a multi-homed responder fills one slot per
  interface.
- Rev 6: on Darwin the Service opens an `O_NONBLOCK` send window around
  each send batch and raises `SO_SNDLOWAT` to `SO_SNDBUF`.
- Rev 6: egress uses only joined pairs whose interface has an address of
  that family.
- Rev 6: `_services._dns-sd._udp` is rejected by the RFC 6335 validator;
  the meta-query is an M6 item.
- Rev 6: a duplicate `browse` of one type is `error.DuplicateBrowse`.
- Rev 6: `Stats` has fields beyond the plan table (`rx_echo`,
  `rx_echo_bridged`, `dropped_ignored`, `dropped_unicast_unexpected`,
  `rx_dst_unknown`, `evictions_pinned`, `cache_rejected`,
  `instances_dropped`, `questions_deferred`) and the Service adds
  `RxCounters` and `TxCounters`.
- Rev 6: `DeadlineSet` is unused; the querier memoises, the responder
  scans.
- Rev 7: no per-link re-probe on interface add; two announcements
  instead (M6).
- Rev 7: the rate-limit key is `(record, ifindex, family)`, not
  `(record, interface)`.
- Rev 7: the bridged-echo re-announce applies the 1 s rule as a drop, not
  a deferral.
- Rev 7: probe-defence latency is bounded by the two-socket alternation
  in `step` (up to one step cap); an `Io.Batch` wait is a follow-up.
- Rev 7 (closed in M5): `advertise`, `updateTxt`, `withdraw`, `browse`
  and `stopBrowse` are all queued to the next tick as plan §4.2 says;
  the ids come back at the call from a reservation without a timer.
- Code (M5): on Darwin every v4 multicast send sets `IP_MULTICAST_IF`
  (`ip_mreqn{ifindex, addr}`) before the `IP_PKTINFO` cmsg send, because
  with it unset a v4 multicast `sendmsg` whose pktinfo names `lo0`
  succeeds once and then fails `ENETUNREACH` for the socket's lifetime
  (macOS 26, C-verified); other interfaces are unaffected. Not in the
  plan's platform matrix; see `docs/platform-matrix.md`.
- Rev 7: `AdvertiseError` and `UpdateTxtError` gain `InvalidTxt`;
  `Engine.Options` gains `first_binder`; `Stats.tx_dropped` also counts
  responder jobs with no queue slot.
- Rev 7: a query with `ifindex == 0` is answered on the first joined pair
  of its family.
- Rev 7: the cross-host Lima peer demo needs a bridged VM network; the
  user-mode NIC does not carry multicast, so the acceptance ran two peers
  on one host.
- Code: the QU re-query burst after `setInterfaces` (plan §4.8 "QU
  policy") is not implemented; the ladder restarts as QM.
- Code: probe defence keeps a 250 ms interval per pair (§6 last
  paragraph) instead of a blanket exemption from the rate rule.
