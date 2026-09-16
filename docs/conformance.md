# Conformance matrix

Every RFC clause mdns-zig implements, deliberately defers or does not apply,
mapped to the Zig test that proves it. The plan (`mdns-zig-plan.md` §7) names
the tests per milestone; this file assigns each name to a clause.

## How this file is checked

`tests/conformance_test.zig` (`test "conformance doc names only existing
tests"`) reads this file at runtime and applies one rule:

> For every table row whose **Status** cell is exactly `done`, each
> backticked name in the **Test name** cell must occur verbatim as
> `test "<name>"` in some `.zig` file under `src/` or `tests/`.

Rows with any other Status are not checked, so a planned test may be named
before it exists. Renaming or deleting a test named on a `done` row fails
`zig build test`. A `done` row with no backticked name also fails. Tables
have exactly four columns; a literal `|` inside a cell must be escaped as
`\|`. The check is textual: it proves the test exists, and `zig build test`
proves it passes.

Status legend: `done` = implemented and tested; `M2`-`M6` = scheduled for
that milestone (plan §7); `n/a` = not applicable to a library of this
scope (a user-interface rule, or behaviour delegated to the OS).

## RFC 1035 - message format

| Clause | Requirement | Status | Test name |
|---|---|---|---|
| §3.1 | A name is at most 255 octets and each label at most 63 | done | `name over 255 octets is rejected` |
| §4.1.1 | Header: ID, QR, OPCODE, AA, TC, RD, RA, Z, RCODE, four 16-bit counts | done | `header flag bit layout`, `parse a captured mDNSResponder packet` |
| §4.1.2 | Question section: QNAME, QTYPE, QCLASS; counts are bounded by the datagram | done | `malformed corpus is rejected without panicking`, `QU and cache-flush bits` |
| §4.1.3 | RR: NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA; RDLENGTH checked against the datagram | done | `malformed corpus is rejected without panicking`, `parse a captured mDNSResponder packet` |
| §4.1.4 | Compression pointers point backwards only; a loop or forward pointer is malformed; at most 64 hops | done | `compression pointer loop is rejected`, `forward pointer is rejected` |
| §4.1.4 | The Builder writes a pointer only to a prior occurrence with identical bytes, so a peer decompresses exactly the `Name` the caller passed (needed for RFC 6762 §8.2, which compares uncompressed rdata octet by octet) | done | `compression matches exact bytes and reuses rdata names`, `fuzz Builder round trip` |

## RFC 6762 - Multicast DNS

| Clause | Requirement | Status | Test name |
|---|---|---|---|
| §5.1 | One-shot queries from an ephemeral port are accepted and answered as legacy queries | M4 | `legacy reply shape` |
| §5.2 | First query delayed 20-120 ms; interval starts at 1 s, doubles, caps at 60 min | done | `first query delayed 20-120ms`, `query intervals double and cap at 60min` |
| §5.2 | Re-query at 80/85/90/95 % of TTL (+0-2 %) merged into the continuous schedule | done | `requery marks merge into one packet` |
| §5.2 | Requery marks are armed from the resolve join, so they do not depend on the order records arrive in (SRV/TXT/A before the PTR, or the host's A a packet ahead of the SRV) | done | `reversed record order still schedules requery marks`, `host records that arrive before the service still get requery marks` |
| §5.2 | Consecutive real query gaps keep the factor of two (the 0-2 % jitter compounds); a question that does not fit one tick's batch retries at the next tick instead of skipping a doubled step | done | `query intervals double and cap at 60min`, `a full due batch retries at the next tick instead of skipping a ladder step` |
| §5.2 | Query budget over 24 h follows the schedule (35 queries per interface, +1 jitter) | M5 | `browse budget over 24h matches derived schedule` |
| §5.3 | Multiple questions per query are parsed and answered independently | M4 | - |
| §5.4 | New browse questions do not set QU; QU only for probes and the post-interface-add burst | done | `browse queries never set QU` |
| §5.4 | A QU response is unicast unless the record was not multicast within TTL/4 | M4 | `QU reply multicast when not multicast within TTL/4` |
| §5.4 | Unicast responses are accepted only within 2 s of our own QU query | done | `unicast outside 2s QU window discarded` |
| §6 | Responses whose source UDP port is not 5353 are dropped and counted | done | `response from non-5353 source is ignored` |
| §6 | Shared-record answers wait 20-120 ms; unique answers go immediately | M4 | `probe timing` |
| §6 | A record is multicast at most once per second per interface, except probe defence | M4 | `record never multicast twice within 1s per interface except defence` |
| §6 | Answers are sent on the interface the query arrived on; own echoes are recognised | done | `byte-identical query from a foreign source is not an echo` |
| §6.1 | NSEC (restricted form) for any type absent under a name we own, per interface | M4 | `NSEC for any absent type under a unique name` |
| §6.1 | Restricted NSEC on the wire: a type over 255 is refused by `Nsec.set` ("MUST NOT generate these restricted-form NSEC records"), and the NSEC bit is never emitted in the Type Bit Map | done | `restricted NSEC refuses types over 255 and never sets the NSEC bit` |
| §6.2 | Address answers carry every kept address of the sending interface only | M4 | `A answer contains only the sending interface's kept addresses` |
| §6.2 | At most 8 addresses per family per interface; v6 global first, link-local last; drops counted | M2 | `ninth v6 address per interface is dropped and reported in v6_dropped`, `v6 global addresses sort before link-local` |
| §6.2 | Engine sums per-interface drops into `stats.addrs_dropped` and warns once | done | `setInterfaces sums Interface dropped counts into addrs_dropped and warns once` |
| §6.3 | Multi-question queries get one aggregated response | M4 | - |
| §6.4 | Pending answers are aggregated into one packet after the delay | M4 | - |
| §6.5 | Wildcard (ANY) queries for our own names answer with every record we hold | M4 | - |
| §6.6 | Identical rdata from another responder is cooperation, not a conflict | M4 | `identical rdata is not a conflict` |
| §6.7 | Legacy unicast reply: echo ID and question, TTL capped at 10 s, no cache-flush bit, no SRV compression, no NSEC next-name compression (a conventional unicast response, so RFC 4034 §4.1.1 applies) | done | `legacy builder never compresses SRV target` |
| §6.7 | Legacy unicast reply shape end to end (ID, question echo, TTL cap, unicast destination) | M4 | `legacy reply shape` |
| §7.1 | Known-answer list omits records at or past half TTL; KA records suppress our answer | M4 | `KA at half TTL suppresses` |
| §7.1 | Records seen only in another querier's known-answer list are never cached | done | `KA records from other queriers not cached` |
| §7.2 | TC bit on a query defers the answer 400-500 ms for the continuation packets | M4 | - |
| §7.3 | Duplicate question suppression when another querier asks the same question | M6 | - |
| §7.4 | Duplicate answer suppression when another responder answers first | M6 | - |
| §8.1 | Probe: 0-250 ms first delay, 3 probes 250 ms apart, qtype ANY, Authority section, QU when first binder | M4 | `probe timing` |
| §8.1 | A probe on the wire is a query with qtype ANY and the proposed records in the Authority section (captured mDNSResponder probes decode as such; QU is optional for a long-running host) | done | `fixture probes use qtype ANY with proposed records in authority` |
| §8.1 | A probe from our own host or over a shared port is defended by multicast | M4 | `same-host probe is defended by multicast`, `shared port probe is defended by multicast` |
| §8.2 | Simultaneous probe tie-break over lexicographically sorted record sets; the loser waits 1 s | M4 | `tie-break loser waits 1s` |
| §8.3 | Announce twice, 1 s apart, with the cache-flush bit | M4 | `SRV TTL is 120 and PTR TTL is 4500` |
| §8.4 | Updating a unique record re-announces without probing; identical rdata is a no-op | M4 | `updateTxt re-announces twice with cache-flush and never probes`, `updateTxt with identical rdata sends nothing`, `updateTxt during probing waits for the probe` |
| §9 | A conflicting response re-probes the same name first; only a failed probe renames | M4 | `conflict after announce re-probes before renaming`, `probe failure after conflict renames`, `same-IP different rdata is a conflict` |
| §9 | Host rename is `<label>-2`; instance rename is `Name (2)`; host rename re-announces SRV | M4 | `host rename to label-2 re-announces SRV` |
| §9 | 15 conflicts in 10 s gives a 5 s backoff | M4 | `fifteen conflicts trigger backoff` |
| §9 | Our own looped-back packets never trigger defence, rename or flush | M4 | `own echo via loopback never defends renames or flushes` |
| §10 | TTL 120 s for host records (A, AAAA, SRV, NSEC), 4500 s for PTR and TXT | M4 | `SRV TTL is 120 and PTR TTL is 4500` |
| §10 | Cache is bounded; eviction removes the soonest-expiring record first | done | `cache cap evicts soonest expiry` |
| §10.1 | A goodbye on the wire is a response whose answer section carries the withdrawn records with TTL 0 (captured mDNSResponder goodbyes decode as such) | done | `fixture goodbye records have TTL 0` |
| §10.1 | Goodbye (TTL 0) sets the cached TTL to 1 s; `lost` fires after that second | done | `goodbye removes after 1s` |
| §10.1 | A goodbye for an instance's PTR, SRV or TXT stops its follow-up questions until a live record returns | done | `goodbye for SRV and PTR sends no follow-up queries` |
| §10.1 | Withdrawing a registration or stopping the service sends goodbye packets | M5 | `serve returns Canceled after group.cancel and a peer sees goodbye` |
| §10.2 | Cache-flush bit: records older than 1 s are flushed, younger ones kept | done | `cache-flush keeps records younger than 1s` |
| §10.2 (with §6.2, §14) | The cache is keyed by `(name, type, class, ifindex)`: a cache-flush record flushes only records heard on the same interface, so a multi-homed responder's per-interface address RRSets (§6.2) coexist and a querier reports one `found` / `resolved` / `lost` per interface (§14, as `dns-sd -B` does per interfaceIndex). §10.2 itself does not name the interface; the scoping follows from §6.2 (each interface's answer is its own RRSet) and §14 ("discover on what interface a Multicast DNS response was received"), and mDNSResponder's per-InterfaceID cache | done | `cache-flush only flushes records from the same interface`, `multi-homed responder yields one stable resolved per interface`, `lost fires per interface`, `bridged segments report the same responder once per interface` |
| §10.2 | A bridged echo of our address records triggers an immediate re-announce | M4 | `bridged echo re-announces address records` |
| §10.3 | Cache flush on topology change (interface up/down) | M6 | - |
| §10.4 | Cache flush on failure indication (application-driven requery) | M6 | - |
| §10.5 | Passive observation of failures (POOF) | M6 | - |
| §11 | Unicast-destination packets are checked on-link against the interface prefixes; multicast skips the check | done | `off-link unicast discarded by prefix`, `multicast-destination packet skips on-link check` |
| §11 | A datagram whose destination the platform could not report is on-link checked but not dropped by the QU-window rule (`rx_dst_unknown`) | done | `unknown destination skips the QU-window drop but not the on-link check` |
| §11 | Multicast TTL and unicast TTL/hop limit are 255 | M2 | - |
| §15 | Every up, multicast-capable interface is used unless an allow-list of ifindex values is set | M2 | `allow-list keeps only listed ifindex`, `allow-listed index missing from getifaddrs is skipped`, `allow-list with zero joined interfaces emits no_interfaces and init succeeds` |
| §15 | A failed group join degrades to a warning that names the interface and family | M2 | `join_failed warning carries ifindex and family` |
| §15 | Link-local AAAA answers carry the arrival interface index as the scope | done | `link-local AAAA carries ifindex` |
| §14 | Query results are per interface: `Resolved.addrs` holds only the addresses heard on `Resolved.ifindex`, and known-answer lists name only records heard on the interface the query goes out on | done | `multi-homed responder yields one stable resolved per interface`, `KA half-TTL filter` |
| §14 | An interface that leaves the table takes its cached records and resolve state with it (`lost` per browsed instance heard there, right after `interfaces_changed`); follow-up and requery questions go out only on the interface the instance / record was heard on, the browse PTR question on every joined pair | done | `interface removal drops its cached records and emits lost`, `pollDatagram drops a queued job for a pair that is no longer joined`, `follow-ups for an instance found on one interface stay on that interface` |
| §16 | Names are UTF-8 on the wire, no Punycode; `Name` equality and hashing fold ASCII case only | done | `equality and hash fold ASCII case only`, `escaping round trip` |
| §16 | Cache keys and question matching compare names ASCII case-insensitively | done | `name compare is ASCII case-insensitive`, `same-data refresh does not re-emit resolved` |
| §17 | Packets target 1472 B (v4) / 1452 B (v6); the hard cap is 9000 B including IP and UDP headers, so the payload cap is 8972 / 8952; a caller override can only lower the cap | done | `builder payload never exceeds 8972 v4 or 8952 v6` |
| §17 | A single RR larger than the MTU target is sent alone in its own packet | done | `builder emits one RR when over MTU` |
| §18.1 | Multicast queries carry ID 0; multicast responses carry ID 0; legacy responses echo the query ID | M4 | `legacy reply shape` |
| §18.2 | QR distinguishes queries and responses; responses from non-5353 ports are dropped | done | `response from non-5353 source is ignored` |
| §18.3 | OPCODE must be 0; other values are ignored | done | `engine handle counts malformed and bad-port drops` |
| §18.4 | AA set on responses; ignored on receipt | M4 | - |
| §18.5 | TC on queries means more known answers follow; on responses ignored | M4 | - |
| §18.6-18.10 | RD, RA, Z, AD, CD are 0 on send and ignored on receipt | done | `engine ignores RD RA and Z on receipt and sends them clear` |
| §18.11 | RCODE is 0 on send; non-zero RCODE packets are ignored | done | `engine handle counts malformed and bad-port drops` |
| §18.12 | Top bit of qclass is the QU flag, split out on parse and set on build | done | `QU and cache-flush bits`, `QU and cache-flush bits round trip through the builder` |
| §18.12 | Browse queries never set QU | done | `browse queries never set QU` |
| §18.13 | Top bit of rrclass is the cache-flush bit, split out on parse and set on build | done | `QU and cache-flush bits`, `QU and cache-flush bits round trip through the builder` |
| §18.13 | Cache-flush handling in the cache | done | `cache-flush keeps records younger than 1s` |
| §18.14 | Compression is allowed in SRV rdata for multicast, never in a legacy unicast response; pointers are bounded | done | `legacy builder never compresses SRV target`, `compression pointer loop is rejected` |

## RFC 6763 - DNS-Based Service Discovery

| Clause | Requirement | Status | Test name |
|---|---|---|---|
| §4.1 | Instance names are UTF-8, 1-63 octets; the service type is `_svc._tcp` or `_svc._udp`; instance label is one label | M4 | - |
| §4.2 | User-interface presentation of instance names | n/a | - |
| §4.3 | Dots and backslashes inside an instance label are escaped in text form and stored raw on the wire | done | `escaping round trip` |
| §6.1 | TXT rdata is one or more length-prefixed strings; an empty TXT is a single zero byte, on build and when the Builder re-emits an empty rdata | done | `empty TXT is a single zero byte`, `builder writes an empty TXT as a single zero byte` |
| §6.2 | TXT rdata is at most 400 B on advertise and in events; larger is rejected or truncated and counted | done | `TXT over 400 B is rejected` |
| §6.2 | `updateTxt` over 400 B is rejected and leaves the old TXT in place | M4 | `updateTxt over 400 B is rejected and keeps the old TXT` |
| §6.3 | Each string is `key=value` or a bare `key`; each string is at most 255 B | done | `build and iterate pairs`, `TXT string over 255 and bad keys are rejected` |
| §6.3 | Captured TXT rdata decodes as `key=value` pairs with valid keys; the owned `Txt` copy agrees with the zero-copy view | done | `fixture TXT records parse as key=value` |
| §6.4 | Keys are at least 1 char of printable ASCII without `=`; compared ASCII case-insensitively; first match wins | done | `TXT key lookup is case-insensitive` |
| §6.5 | Values are opaque bytes; `key` without `=` is a boolean attribute distinct from `key=` | done | `build and iterate pairs` |
| §6.6 | Example TXT record | n/a | - |
| §6.7 | `txtvers` version tag | n/a | - |
| §7 | Service names follow RFC 6335 §5.1; the transport label is `_tcp` or `_udp` | done | `service name rejects leading hyphen, double hyphen and all-digit` |
| §7.1 | Subtypes (`_sub`) for selective instance enumeration | M6 | - |
| §7.2 | Service name length at most 15 characters | done | `service name rejects leading hyphen, double hyphen and all-digit` |
| §9 | `_services._dns-sd._udp.local` enumerates the service types we advertise | M4 | - |
| §12.1 | PTR answers include the SRV, TXT and address records as additionals | M4 | - |
| §12.2 | SRV answers include the target's A and AAAA records as additionals | M4 | - |
| §12.3 | TXT answers carry no additionals | M4 | - |
| §12.4 | Other record types carry no additionals | M4 | - |

## RFC 4034 - NSEC wire format (as used by RFC 6762 §6.1)

| Clause | Requirement | Status | Test name |
|---|---|---|---|
| §4.1.1 | The Next Domain Name is never compressed in a conventional unicast response (legacy reply); mDNS multicast replies may compress it (RFC 6762 §18.14) | done | `legacy builder never compresses SRV target` |
| §4.1.2 | Type Bit Map blocks are 1-32 octets, each window at most once, in increasing order; a duplicate or out-of-order block is malformed. Trailing zero octets are tolerated on receive | done | `rdata decoders reject wrong lengths and names that overrun rdata` |
| §4.1.2 | Encoders omit trailing zero octets and an empty bitmap emits no block | done | `encode round trips`, `restricted NSEC refuses types over 255 and never sets the NSEC bit` |

## RFC 6335 - service name syntax

| Clause | Requirement | Status | Test name |
|---|---|---|---|
| §5.1 | 1-15 characters; letters, digits and hyphens only; at least one letter; no leading or trailing hyphen; no two adjacent hyphens | done | `service name rejects leading hyphen, double hyphen and all-digit` |

## Library behaviour (plan §4.3-§4.6, no RFC clause)

| Clause | Requirement | Status | Test name |
|---|---|---|---|
| plan §4.3 | `serve` must run as a concurrent `Io.Group` task; an inline run returns `error.ConcurrencyUnavailable` | M5 | `serve refuses inline run on single-threaded Io` |
| plan §4.3 | `Mailbox.next` maps a closed queue to `error.Closed` | M5 | `mailbox next maps Closed` |
| plan §4.3 | A full mailbox waits up to the step cap, then drops the oldest event, counts it and warns once | M5 | `mailbox full waits up to the cap then drops oldest and counts`, `mailbox drop emits warning.events_dropped once` |
| plan §4.3 | One clock source per Service; mixing tick and step modes asserts in debug | M5 | `tick mode then step mode asserts in debug` |
| plan §4.3 | Tick mode drains sockets only every `rx_poll_interval_us` | M5 | `tick drains sockets only after rx_poll_interval_us` |
| plan §4.2 | Service mutations apply at the next tick with that tick's clock | M5 | `advertise before first tick starts probing at first tick`, `stopBrowse is applied at the next tick` |
| plan §4.5 | The Engine event ring drops the oldest event and counts the drop | M5 | `event ring drops oldest and counts` |
| plan §4.5 | Cache keyed by `(name, type, class, ifindex)` (the plan text says three parts; the gate fix added the interface, see the §10.2 row): records are harvested in any order, every PTR of a browsed type is a `found`, a PTR of a foreign type is cached without an event (hashicorp/mdns #145, #92, #96) | done | `reversed record order still resolves`, `three PTRs in one packet yield three found events`, `PTR for a foreign service type emits no found` |
| plan §5 | `resolved` fires once SRV, TXT and an address are present, again on SRV, TXT or address-set change, never on a same-data refresh; `ttl_s` is the shortest RR TTL | done | `resolved is emitted once when SRV, TXT and an address are present`, `resolved re-emitted on TXT change`, `resolved re-emitted on SRV port change`, `resolved re-emitted when an address is added or expires`, `same-data refresh does not re-emit resolved`, `resolved ttl_s is the shortest RR TTL` |
| plan §5 | `stopBrowse` stops the schedule and the `found` / `lost` stream; cached records stay | done | `stopBrowse stops queries and found/lost but keeps the cache` |
| plan §7 M3 | Browse end to end over the fake LAN against a scripted responder: resolve from a PTR answer with additionals, responder-side known-answer suppression on the next query, requery marks refresh without a re-emit, a non-5353 or unicast reply is dropped and counted, a goodbye yields `lost` after 1 s, reversed answer-only records resolve, two queriers on one segment both resolve | done | `a scripted responder on the LAN resolves a browse and is suppressed by the known-answer list`, `requery marks over the LAN refresh the records without re-emitting resolved`, `a responder answering from an ephemeral port is ignored over the LAN`, `a responder replying by unicast is discarded outside the QU window over the LAN`, `a goodbye over the LAN emits lost one second later`, `reversed answer-only records from a responder still resolve over the LAN`, `two queriers on one segment both resolve and see each other's queries as foreign` |
| plan §4.2 | `handle` never allocates and never fails after `init` (FailingAllocator sweep) | done | `handle never fails after init under a FailingAllocator sweep`, `engine handle never fails after init under a failing allocator` |
| plan §4.8 | Queries go out only on joined (ifindex, family) pairs; `setJoined` corrects the default (Revision 5 item 1); `Service.syncJoined` carries a failed join into the Engine | done | `engine joined pairs default to families with an address and follow setJoined`, `syncJoined carries a failed join into the Engine` |
| plan §4.8 | A `resolved` value lists at most 8 addresses per family | done | `resolved lists at most 8 addresses per family` |
| plan §4.5 | Eviction pins: only the records the resolve join consumes (browsed PTRs, one SRV and TXT per instance, 8 + 8 addresses per host) are protected; the pin is a bit on the entry, so eviction is one pass over the pool; with every entry pinned the soonest-expiring pinned record goes and the querier is told (`evictions_pinned`, a PTR eviction is a `lost`); cache and instance buckets are keyed by a secret seed | done | `eviction skips pinned records`, `junk SRV records for a found instance do not pin the pool`, `a full pool of descending TTLs is evicted without walking the instance table`, `a pool full of browse data evicts the soonest-expiring pinned record and reports it`, `bucket index depends on the secret seed` |
| plan §4.6 | `warning.no_packets_10s` counts only foreign packets (`rx - rx_echo`); a browse before the first `step` is stamped with the current clock | done | `no_packets_10s warning ignores own echoes`, `browse before the first step is stamped with the current clock` |
| plan §4.6 | `Service.stats()` sums Engine and Service counters | M5 | `stats sums Engine and Service counters` |
| plan §3.2 | `Service.lookup` returns after `quiet_us`, at `timeout_us`, or on cancel, and stops the browse on every path | M5 | `lookup returns after quiet_us with one result`, `lookup returns at timeout_us with zero results`, `lookup returns Canceled after group.cancel and the browse is stopped`, `lookup replaces an earlier resolved for the same instance` |
| plan §5 | `Service.lookup` keeps one slot per instance: a later `resolved` for the same instance replaces the earlier copy, from any interface (the pure collect rule `mergeResolved`; the multi-homed `resolved` stream stays per interface in `browse`) | done | `lookup keeps one slot per instance across interfaces` |
| plan §3.4 | Profiles import only std; TXT schemas validate their fields | M5 | `profiles import graph is std-only`, `qmesh SeedSet emits once per (id, epoch)`, `spki must be 64 lowercase hex`, `epoch accepts 16 and 32 hex` |
| plan §7 M1 | Every fixture decodes: all captured datagrams parse, every question and record walks, every rdata of a known type decodes | done | `every fixture parses`, `fixtures load and hex length matches sidecar len` |
| plan §7 M1 | Re-encode is decode-equal: each fixture rebuilt through the Builder parses back to the same header, questions and records (rdata compared after decompression) | done | `fixture re-encode is decode-equal` |
| plan §8 tier 3 | Fuzz targets over the codec (Smith API): no panic on random bytes, iterators walk exactly the header counts, names round-trip through text, canonical rdata exists for every parsed record, Builder output re-parses to the same records; seeds replay as intended | done | `fuzz Message.parse never panics`, `fuzz Name.decode never panics`, `fuzz Txt.iterate never panics`, `fuzz Builder round trip`, `fuzz corpus seeds replay through Smith as intended` |
| plan §8 tier 3 | Fuzz target over `Engine.handle`: random bytes and `RxMeta` with monotonic clock steps; no panic, cache under its cap, `nextDeadline >= now` after a tick | done | `fuzz Engine.handle never panics` |
