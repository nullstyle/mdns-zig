# Interop checks

Scripts that run `zig-out/bin/mdns-advertise` (and the other examples)
against real mDNS stacks: mDNSResponder on macOS through `dns-sd`, and
avahi-daemon inside the Lima VM. They are the plan section 7 M4
acceptance commands, packaged so each check prints one `PASS` / `FAIL`
line, every wait has a deadline, and every process they start is killed on
exit. None of them needs root: packet counting uses our own capture (the
`join_pktinfo` spike) instead of `tcpdump`.

| Script | Where | What |
| --- | --- | --- |
| `macos-dnssd.sh` | macOS | six `dns-sd` checks: browse, lookup, goodbye, conflict both directions, `updateTxt` |
| `legacy_query.py` | any | one legacy unicast query from an ephemeral port; checks the RFC 6762 section 6.7 reply shape |
| `lima-avahi.sh` | inside the VM | `avahi-browse -rt` resolves us; `avahi-publish` clash both directions |
| `flood-count.sh` | macOS or VM | packets this host sends for one name per capture window, with the idle budgets |
| `probe_defence.py` | any | one foreign QM probe (or a burst) from a shared 5353 socket; expects the multicast AA defence within the prober's window, one per 250 ms for a burst |

The `justfile` has a recipe for each: `just interop-macos`, `just
legacy-query demo._qmsg._udp.local SRV`, `just interop-lima`, `just
flood-count --seconds 60 --service demo._qmsg._udp --assert idle-advertise`.

## macOS

Run from Terminal or SSH. A shell launched from a GUI app may lack Local
Network permission and then sees no multicast at all (zero packets, no
error). `sudo` is not needed and the scripts never ask for it.

```sh
mise exec -- zig build examples                 # zig-out/bin/mdns-{browse,advertise,peer}
sh interop/macos-dnssd.sh                       # builds first unless SKIP_BUILD=1
python3 interop/legacy_query.py demo._qmsg._udp.local SRV   # with mdns-advertise --name demo running
python3 interop/probe_defence.py demo._qmsg._udp.local --port 4433 [--burst 40 --gap 0.01]
sh interop/flood-count.sh --seconds 60 --service demo._qmsg._udp --assert idle-advertise
```

`probe_defence.py` binds a SO_REUSEPORT socket on `*:5353` (so its query
is a peer's, not a legacy one), sends a section 8.1 probe for the
instance (qtype ANY, SRV port 9999 in Authority) and prints every
response naming it with the latency; it exits 0 when a multicast AA
response carrying the advertised SRV port arrives within `--within`
(default 0.75 s, the prober's three-probe window). `--burst N --gap S`
checks the section 6 rule for defences (at least 250 ms between
multicasts of the record, so at most one defence per 250 ms, each
deferred rather than dropped). It closes the gap `lima-avahi.sh` leaves:
avahi resolves a clash from its cache without probing on the wire.

`macos-dnssd.sh` refuses to start while another `mdns-advertise` runs.
`MDNS_INTEROP_NAME` and `MDNS_INTEROP_PORT` change the instance (default
`demo`, 4433). Timeouts use `perl -e 'alarm N; exec @ARGV'` because macOS
ships no coreutils `timeout`.

`legacy_query.py` is stdlib-only Python 3. It prints the four section 6.7
checks (ID echoed, TTL <= 10, cache-flush clear, SRV target not
compressed) and exits 0 only when all four hold. Calibration: pointed at a
`dns-sd -R` registration it reports `SRV target compressed? YES (bad)`,
because mDNSResponder compresses the `.local` suffix inside the SRV rdata
of its legacy replies (section 18.14 says it MUST NOT), so a `PASS` from
our responder is a real difference, not a vacuous one.

`flood-count.sh` runs the `join_pktinfo` spike for the window, which
shares `*:5353`, joins both groups on every interface and dumps every
datagram with a JSON sidecar naming the source. It keeps the datagrams
whose source is one of this host's addresses and that name the service
(owner names and PTR/SRV/NSEC rdata, decoded, so compressed names match
too), and prints them split by the QR bit and by second. "This host"
includes mDNSResponder, so stop any `dns-sd -B` for the same type before
asserting the browse budget. `--after` (default 30 s for `idle-advertise`)
is the grace for probing and announcing; when the advertiser was already
idle before the capture started, pass `--after 0` so the whole window
counts (`--name` is an alias of `--service`).

Recorded run (2026-09-16, this Mac, after the M4 review fixes;
`mdns-advertise --type _qmsg._udp --name demo --port 4433 --txt txtvers=1
--stats` running from a scratch shell, 16 interfaces, `first_binder=false`
beside mDNSResponder):

```
$ python3 interop/legacy_query.py demo._qmsg._udp.local SRV --verbose
query    demo._qmsg._udp.local SRV id=0x3d62 from port 60452 to 224.0.0.251
reply    140 bytes from 192.168.1.75 port 5353: id=0x3d62 flags=0x8400 qd=1 an=1 ns=0 ar=3
  question demo._qmsg._udp.local SRV class=1
  answer     demo._qmsg._udp.local SRV ttl=10 class=1 0 0 4433 Mac.local
  additional Mac.local A ttl=10 class=1 192.168.1.75
  additional Mac.local AAAA ttl=10 class=1 fdc1:db50:1df4:4bb4:4f8:2467:4831:4c07
  additional Mac.local AAAA ttl=10 class=1 fe80::14a4:fb8c:9851:a152
id echoed?             yes (query 0x3d62, reply 0x3d62)
TTL <= 10?             yes (max 10 over 4 RR)
cache-flush bit clear? yes
SRV target compressed? NO (good)
question repeated?     yes (informational; section 6.7 says it MUST be)
RESULT   PASS

$ sh interop/flood-count.sh --seconds 40 --after 0 --service demo._qmsg._udp --assert idle-advertise
flood-count: 295 datagrams captured, 0 from this host naming demo._qmsg._udp: 0 queries (QR=0), 0 responses (QR=1)
flood-count: after t+0s: 0 queries, 0 responses (0 unsolicited: no foreign query for the name within 2 s before)
PASS idle-advertise: 0 unsolicited packets from this host for demo._qmsg._udp in t+0s..t+40s

$ (sleep 3; kill -USR1 "$(pgrep -f mdns-advertise)") & sh interop/flood-count.sh --seconds 10 --after 0 --service demo._qmsg._udp
flood-count: 130 datagrams captured, 38 from this host naming demo._qmsg._udp: 0 queries (QR=0), 38 responses (QR=1)
  t+  3s: 0 query 19 response
  t+  4s: 0 query 19 response
```

The USR1 capture is the two section 8.4 announcements one second apart
on the 19 joined pairs, 0 probes; decoding the dump shows every TXT with
the cache-flush bit and rdata `seq=1 txtvers=1`, and `dns-sd -L demo
_qmsg._udp` then prints ` seq=1 txtvers=1`. `sh interop/macos-dnssd.sh`
in the same session: 6 passed, 0 failed.

```
$ python3 interop/probe_defence.py demo._qmsg._udp.local --port 4433 --burst 5 --gap 0.3 --timeout 3
  t=0.002s response from 192.168.1.75:5353 aa=1 srv_port=4433 cache_flush=True len=151
  t=0.302s response from 192.168.1.75:5353 aa=1 srv_port=4433 cache_flush=True len=151
  t=0.604s response from 192.168.1.75:5353 aa=1 srv_port=4433 cache_flush=True len=151
  t=0.989s response from 192.168.1.75:5353 aa=1 srv_port=4433 cache_flush=True len=151
  t=1.240s response from 192.168.1.75:5353 aa=1 srv_port=4433 cache_flush=True len=151
spacing  5 probes over 1.204 s -> 5 defences, min gap 0.251 s
RESULT   PASS
$ python3 interop/probe_defence.py demo._qmsg._udp.local --port 4433 --burst 40 --gap 0.01 --timeout 3
  t=0.051s response from 192.168.1.75:5353 aa=1 srv_port=4433 cache_flush=True len=151
  t=0.302s response from 192.168.1.75:5353 aa=1 srv_port=4433 cache_flush=True len=151
  t=0.553s response from 192.168.1.75:5353 aa=1 srv_port=4433 cache_flush=True len=151
spacing  40 probes over 0.448 s -> 3 defences, min gap 0.251 s
RESULT   PASS
```

The first-defence latency of a single probe varied between 2 ms and
201 ms across runs: `Service.step` waits on one socket at a time (up to
250 ms) and drains the other only afterwards, so a probe on the socket
not being waited on is handled when that wait ends. Service-level, not
the responder (which schedules the defence with delay 0).

## Lima VM (`zig-uring`)

The VM mounts `/Users/nullstyle`, so the checkout's absolute paths resolve
unchanged inside it. Cross-build first; the install path is the same as
for a native build, so rebuild for the target you need right before
running:

```sh
mise exec -- zig build examples -Dtarget=aarch64-linux-musl
ssh -o IdentityAgent=none -o IdentitiesOnly=yes -F ~/.lima/zig-uring/ssh.config lima-zig-uring \
    'sh /Users/nullstyle/prj/zig/mdns-zig/interop/lima-avahi.sh'
```

Use the `ssh` form: `limactl shell` hangs when it has no tty. Inside the
VM `avahi-daemon` (running as uid `avahi`) and `systemd-resolved` both
hold `*:5353`, so our binary is never the first binder there: it shares
the port with `SO_REUSEADDR` + `SO_REUSEPORT`, QU is disabled and defence
is multicast (plan section 4.8 "Port sharing"). `lima-avahi.sh` checks
that the binary runs on Linux before starting (a native macOS build at the
same path fails with a clear message) and needs `avahi-browse`,
`avahi-publish` and coreutils `timeout` in the VM.

The two-peer demo across the boundary:

```sh
mise exec -- zig build examples && cp zig-out/bin/mdns-peer /tmp/mdns-peer-mac
mise exec -- zig build examples -Dtarget=aarch64-linux-musl
/tmp/mdns-peer-mac alice                                             # on the Mac, and in the VM:
ssh ... lima-zig-uring '/Users/nullstyle/prj/zig/mdns-zig/zig-out/bin/mdns-peer bob'
```

Each prints `peer <other> at <addr>:4433 ifindex <n>` within a few seconds
(one line per interface it was heard on) and `peer <other> gone` after the
other is interrupted (goodbye, RFC 6762 section 10.1). The copy is there
because the Linux build overwrites `zig-out/bin/mdns-peer`; `just
peer-demo` does the same dance.

Caveat, verified 2026-09-16: the `zig-uring` VM's only NIC is Lima's
user-mode `eth0` (192.168.5.15/24) and the Mac has no interface on that
subnet, so multicast does not cross the boundary in either direction
(`avahi-browse` in the VM never lists a `dns-sd -R` from the Mac, and
`dns-sd -B` never lists an `avahi-publish` from the VM). The Mac/VM peer
demo therefore needs a VM with a shared or bridged network (Lima
`networks: [{lima: shared}]`, which puts a `bridge10x` interface on the
Mac). Two peers on one host work as is (`mdns-peer alice` and `mdns-peer
bob --port 4434`; the shared `*:5353` bind and multicast loopback carry
the packets), and `lima-avahi.sh` only needs the VM-internal path.

## Exit codes

`0` every check passed; `1` at least one `FAIL`; `2` a prerequisite is
missing (tool, binary, another `mdns-advertise` already running).
