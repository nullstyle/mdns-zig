# Security policy

mdns-zig parses untrusted bytes from anyone on the local link: every
datagram that arrives on UDP 5353 (multicast or unicast) is decoded by
this library before any policy is applied to it. DNS names with
compression pointers, resource-record headers, A/AAAA/PTR/SRV/TXT/NSEC
rdata, TXT key/value pairs and the cache that stores them are all fed
directly by peer-controlled input.

The posture is therefore:

- **Any panic, `unreachable`, integer overflow trap or out-of-bounds
  access reachable from network bytes is a security bug**, not a
  robustness nit. Malformed input must surface as `error.Malformed` (or
  a `Warning` event) and be dropped.
- **Any unbounded allocation or state growth driven by network bytes is a
  security bug.** The cache, event ring, answer scheduler and TXT
  builder have fixed caps set at `init`; input beyond a cap is dropped,
  never grown into.
- **Debug and ReleaseSafe are the only supported build modes.**
  `build.zig` refuses ReleaseFast and ReleaseSmall because they remove
  the safety checks this posture relies on. Do not patch that check out.
- The library never spawns threads and never blocks without a timeout,
  so a hostile peer cannot wedge the caller's event loop by withholding
  or flooding traffic; excess input is dropped with a counted warning.

## Reporting a vulnerability

**Do not file public GitHub issues for vulnerabilities.** Use GitHub's
private vulnerability reporting on
[nullstyle/mdns-zig](https://github.com/nullstyle/mdns-zig/security/advisories/new)
and include:

- A description of the issue and its impact.
- Steps to reproduce. A hex dump of the offending datagram (the format
  under `tests/fixtures/`) is ideal.
- The affected revision (tag or commit SHA) and build mode.

I aim to acknowledge reports within 7 days. The intended disclosure
timeline is 90 days from acknowledgement to coordinated public
disclosure; if a fix ships earlier, disclosure follows the release.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |
| unreleased `main` | best effort; report anyway |

0.1.0 is the first release (2026-09-16). Fixes land on `main` and ship as
the next 0.1.x tag; reports against `main` are welcome too.

## Scope

In scope:

- Memory-safety bugs (out-of-bounds, use-after-free, data races)
  reachable from received datagrams or from interface enumeration.
- Panics or `unreachable` reached on adversarial wire input (names,
  compression loops, truncated records, oversized TXT, bad NSEC bitmaps).
- Algorithmic-complexity attacks (for example pointer chasing in name
  decompression or cache-key hashing) and unbounded resource use beyond
  the documented `Limits` caps.
- Flood-guard failures: input that makes this library send more than
  the RFC 6762 schedule allows (probe storms, answer amplification,
  echo loops), since that harms the whole link. The bounds v0.1 holds
  (`tests/flood_guard_test.zig`, `probe storm from a hostile peer is
  rate bounded`): a multicast defence of an owned name at most once per
  250 ms per record and interface, whatever the probe rate (RFC 6762
  §6, exempt from the 1 s rule but not unbounded); a QU probe gets one
  unicast reply, to the on-link source address only, never re-sent, so
  the byte ratio towards a spoofed source stays about 1.5x (SRV + TXT +
  address + NSEC for one name, asserted under 2x). There is no per-source
  cap on those unicast replies beyond one per probe (a follow-up for M6);
  sending more than one reply per probe, or a multicast reply faster
  than the 250 ms spacing, is in scope.

Out of scope:

- Issues that require `Limits` with a documented safety cap raised beyond its default.
- The inherent trust model of mDNS: any host on the link may answer for
  any name. Consumers that need authenticity must verify it above this
  library (the profile modules carry identity material for that).
- Issues that depend on a modified compiler or build environment.
- Behaviour of the OS daemons this library coexists with
  (mDNSResponder, avahi, systemd-resolved).
