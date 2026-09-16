# Packet fixtures

Raw mDNS datagrams captured off a real LAN, used (from M1 on) as a decode
corpus for the wire codec. M0 only captures and describes them; no test
reads them yet.

## Layout

```
tests/fixtures/
  README.md          this file
  raw/NNNN.hex       one datagram per file: the UDP payload as lowercase
                     hex on a single line, trailing newline, no spaces
  raw/NNNN.json      sidecar with the receive metadata for NNNN.hex
```

`NNNN` is the zero-padded receive sequence number within one capture run
(`0001` ..). Every `.hex` has exactly one `.json` with the same stem.

## Sidecar schema

Written by `dumpDatagram` in `spikes/join_pktinfo.zig` with
`std.json.fmt(.., .{ .whitespace = .indent_2 })`:

```json
{
  "source": "192.168.1.199:5353",
  "ifindex": 15,
  "family": "v4",
  "len": 1129,
  "captured_with": "spikes/join_pktinfo.zig",
  "tool_running": "dns-sd -B _services._dns-sd._udp; dns-sd -R m0demo _mdnszig._udp . 4433 k=v"
}
```

| Field | Type | Meaning |
|---|---|---|
| `source` | string | Sender address and port as `std.Io.net.IpAddress` formats it: `a.b.c.d:port` for v4, `[v6]:port` for v6 (the v6 scope id is not printed; it equalled `ifindex` on every packet). |
| `ifindex` | integer | Arrival interface index from the `IP_PKTINFO` / `IPV6_PKTINFO` cmsg (`0` would mean no pktinfo cmsg was present; never happened). |
| `family` | `"v4"` or `"v6"` | Address family of the receiving socket. |
| `len` | integer | Byte length of the UDP payload; `len(hex) / 2` must equal it. |
| `captured_with` | string | Repo-relative path of the program that wrote the file. |
| `tool_running` | string | The `--label` passed to the spike: what was generating traffic. Empty string when none was given. |

Not recorded: destination address (it was multicast for every packet:
`224.0.0.251` or `ff02::fb`), TTL/hop limit, and wall-clock time. If a
future capture needs them, add fields to `Sidecar` in the spike; existing
files stay valid because readers should ignore unknown fields.

## How the current corpus was captured

Date: 2026-09-15. Host: macOS 27.0 (26A428), Apple silicon, mDNSResponder
running and sharing UDP `*:5353` via `SO_REUSEPORT`. Zig
`0.17.0-dev.1786+75044cb04`, `std.Io.Threaded`. Two runs of the
`join_pktinfo` spike, numbered consecutively:

Run 1 (`0001`-`0127`, 6 s):

```sh
/usr/bin/dns-sd -B _services._dns-sd._udp &
/usr/bin/dns-sd -R m0demo _mdnszig._udp . 4433 k=v &
sleep 0.5
mise exec -- zig build spike-join_pktinfo -- --seconds 6 \
    --dump tests/fixtures/raw \
    --label "dns-sd -B _services._dns-sd._udp; dns-sd -R m0demo _mdnszig._udp . 4433 k=v"
kill %1 %2
```

Run 2 (`0128`-`0231`, 10 s; the `-R` registration started 2 s before the
window and was killed 3 s before it closed, so its goodbye records land in
the corpus; `dns-sd -L` resolved the registered name during the window):

```sh
/usr/bin/dns-sd -R m0demo _mdnszig._udp . 4433 k=v &   # pid R
sleep 2
/usr/bin/dns-sd -B _services._dns-sd._udp &            # pid B
/usr/bin/dns-sd -L m0demo _mdnszig._udp &              # pid L
mise exec -- zig build spike-join_pktinfo -- --seconds 10 \
    --dump <scratch dir> \
    --label "dns-sd -R m0demo _mdnszig._udp . 4433 k=v (started 2 s before capture, killed at t+7 s); dns-sd -B _services._dns-sd._udp; dns-sd -L m0demo _mdnszig._udp" &
sleep 7; kill $R
wait; kill $B $L
# then renumbered <scratch dir>/0001..0104 to raw/0128..0231
```

`dns-sd -L` printed `m0demo._mdnszig._udp.local. can be reached at
<host>.local.:4433 (interface 27)` with the TXT `k=v` during the window.
Run 2 used the post-review `BindOptions.nonblocking = false` default
(blocking fds; see `docs/platform-matrix.md`, "Known risks"): the
zero-duration drains behaved identically and every packet still carried a
pktinfo ifindex.

The spike binds `0.0.0.0:5353` and `[::]:5353` with `SO_REUSEADDR` +
`SO_REUSEPORT`, enables `IP_PKTINFO` / `IPV6_RECVPKTINFO` and
`IP_RECVTTL` / `IPV6_RECVHOPLIMIT`, joins `224.0.0.251` and `ff02::fb` on
every up, multicast-capable interface with an address (22 memberships:
`lo0`, `en0`, `awdl0`, `llw0`, `utun0`-`utun10`, `bridge100`, `bridge101`),
then drains both sockets with timed `receiveManyTimeout` calls for the
requested number of seconds and writes each datagram as it arrives. No
`tcpdump` or root was involved; the bytes are exactly what `recvmsg`
returned to a shared 5353 socket, i.e. what `Service` will see.

`dns-sd -B _services._dns-sd._udp` makes mDNSResponder send a
service-type enumeration query and provokes PTR answers from every host
on the LAN. `dns-sd -R m0demo _mdnszig._udp . 4433 k=v` registers a fake
service so the corpus contains a full probe / announce sequence for a
known name (`m0demo._mdnszig._udp.local`, SRV port 4433, TXT `k=v`) from
mDNSResponder on each of its interfaces; in run 2 killing it also
produced the goodbye (TTL 0) announcements. `dns-sd -L m0demo
_mdnszig._udp` issues SRV and TXT questions for that name and receives
the SRV/TXT/A/AAAA answers. Only mDNSResponder-generated traffic (plus
whatever the LAN sent unprompted) is represented; avahi and
python-zeroconf captures are still to come (below).

## What is in it

Counted from the bytes and sidecars (not from the spike log), over both
runs:

- 231 datagrams, 45 024 payload bytes; smallest 36 bytes, largest 1187.
- 91 queries (QR = 0) and 140 responses (QR = 1); no message has TC set.
- 225 have DNS ID `0x0000`; 6 carry a non-zero ID (all from the router, on
  its v4 and its link-local v6 address).
- Family: 128 IPv4, 103 IPv6. Every source port is 5353.
- Arrival interface: `en0` (15) 139 packets, `lo0` (1) 30, `bridge100` (25)
  30, `bridge101` (27) 32. The 92 non-`en0` packets are mDNSResponder on
  this Mac talking to itself on loopback and the two VM bridges.
- 29 distinct source addresses (this Mac on four interfaces, the router,
  and roughly 20 other hosts on the LAN; TTL 128 on packets from two of
  them, 1 from the router, 255 from everything else). Run 2 added no new
  sources.
- 118 datagrams mention `_mdnszig` (the `m0demo` probes, announcements,
  the `-L` resolve questions and answers, and 16 goodbye records with
  TTL 0, all in run 2: `0128`-`0231`), 127 mention
  `_services._dns-sd._udp`.
- Record types present (answer + authority + additional sections, 1096
  RRs): PTR 667, NSEC 123, TXT 97, AAAA 82, SRV 68, A 54, OPT 5. TTL 0
  appears on 16 RRs, all `m0demo._mdnszig._udp.local` goodbyes. Question
  types: PTR 99, TXT 26, ANY (255) 20 (the probes), SRV 16 (the `-L`
  resolve). 225 of 231 messages use name compression. All 231 walk end
  to end with a naive DNS parser (question and RR offsets land exactly on
  the payload end), so the corpus is well formed; malformed cases for the
  M1 decoder must be synthesised separately.

Privacy note: the original capture (231 datagrams, 29 sources) included
packets from roughly 20 other devices on the capturing LAN. Before the
first commit, the orchestrator removed every datagram whose source
address was not one of this Mac's own interface addresses. 122 datagrams
remain (numbering keeps its gaps: `0001`-`0231`). The statistics above
describe the full capture as it was measured; the counts for the pruned
set are smaller. Everything that remains was sent by mDNSResponder on
this Mac (on behalf of `dns-sd`), so it names only this host and the
service types other hosts advertise, not their hostnames or addresses.

## Adding more captures

- Use `just fixtures <seconds> "<label>" [dir]` or the `zig build` line
  above. The sequence restarts at `0001` on every run, so the recipe
  refuses a non-empty directory and defaults to a fresh
  `tests/fixtures/capture-<timestamp>/`; review the files there, then
  move them into `raw/` (renumbering) or into a subdirectory such as
  `raw/avahi/`. Never dump straight onto an existing corpus.
- Put what was generating traffic into `--label`; that is the only
  provenance the sidecar stores.
- Planned sources (plan Section 6): avahi (Lima Linux VM) and
  python-zeroconf, so that the M1 decoder is exercised against all three
  major implementations, not only mDNSResponder.
- Fixtures are excluded from the published package: `build.zig.zon`
  `.paths` does not list `tests/`, so a consumer's `zig fetch` never
  downloads them.
