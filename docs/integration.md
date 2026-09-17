# Integration guide

How the three workspace consumers (shared-studio, qmesh-zig, qmsg) and a
foreign QUIC loop drive one `mdns.Service`, and what the TXT records of
the three service types carry. The plan (`mdns-zig-plan.md` §3, §4.3, §5)
sets the rules. This file shows the code.

Every snippet below uses the real API of `src/service.zig` and
`src/profiles/`. The mdns halves compile as written. The consumer halves
name real functions of the consumer repos, but qmesh-zig and shared-studio
pin an older Zig today, so they cannot build against mdns-zig until their
pin bump (plan §3.2, §7 M6).

## 1. One Service, one clock source

A `Service` runs in exactly one mode for its whole life:

| Mode | Call | Clock | Who |
|---|---|---|---|
| A, tick-polled | `tick(now_us)` from your loop | yours | shared-studio, qmesh `on_iteration`, qmsg apps |
| B, self-driven | `step(cap)`, `run(shutdown, hook)`, `lookup(...)` | the Service's (`nowUs()`) | CLI tools, qmesh seed lookup |
| C, `Io.Group` task | `serve(&svc, &mailbox)` | the Service's | apps that want a queue |

The first call binds the mode. A later call in another mode hits a
`std.debug.assert` in Debug and ReleaseSafe. So a program that needs both
`lookup` (mode B) and `tick` (mode A) creates two Services, one after the
other, never one for both (§3 below shows the qmesh form). `now_us` must
not go backwards; a non-monotonic value also asserts.

mdns-zig never spawns a thread. Every method of one `Service` belongs to
the thread that calls `tick` / `step` / `serve`. Events are values: copy
them out and hand them to any thread.

Mutations are one-liners without a clock. `advertise`, `updateTxt`,
`browse`, `withdraw` and `stopBrowse` validate at the call (the typed
errors and the ids come back at once) and take effect at the next
`tick` / `step`, stamped with that tick's clock: the first probe and the
first query are timed from there. Nothing is sent before that call.

## 2. shared-studio: mode A from `ss_tick`

shared-studio has one POSIX worker thread that calls `ss_tick(now_us)`
about every millisecond (`src/macos.m`, `bridge.zig`). Every `Peer`
method belongs to that thread. The mdns `Service` joins it.

`tick` touches the sockets only when `rx_poll_interval_us` (default
5000) has passed since the last drain, or when an RFC timer is due. A 1 ms
caller therefore pays two zero-timeout receives every 5 ms, not every
millisecond. Leave the default. Own-echo recognition needs the tick
cadence plus `rx_poll_interval_us` well under `timers.echo_window_us`
(1 s): tick at least every ~500 ms and keep the option at or below
~100 ms, or a looped-back response ages out of the echo ring in the
socket and is read as a peer's (shared-studio's 1 ms and qmesh's 5 ms
cadences are far inside that).

### Advertise

`Config` already has the pieces: `listen_port` from `localAddress()`
after bind, the local SPKI from `certificateSpki(cert_pem)`, `epoch: u64`.

```zig
const mdns = @import("mdns");

var svc = try mdns.Service.init(gpa, io, .{ .host_label = "studio-a" });
defer svc.deinit();

// Keep `ad` in place while it is in use: desc() returns slices into it.
var ad = try mdns.profiles.studio.Advert.init(.{
    .instance = "Alice", // the performer display name
    .port = listen_port,
    .spki = local_spki,
    .epoch = epoch,
    .role = .conductor,
});
const reg = try svc.advertise(ad.desc());
```

When the process incarnation changes, re-announce without a probe:

```zig
ad.setEpoch(new_epoch);
try svc.updateTxt(reg, ad.txt());
```

### Browse and the snapshot

```zig
_ = try svc.browse(mdns.profiles.studio.service_type);

// Inside ss_tick(now_us), on the worker thread:
svc.tick(now_us) catch |err| std.debug.print("mdns tick: {t}\n", .{err});
var evs: [8]mdns.Event = undefined;
while (true) {
    const n = svc.poll(&evs);
    if (n == 0) break;
    for (evs[0..n]) |ev| switch (ev) {
        .resolved => |r| {
            const p = mdns.profiles.studio.Parsed.parse(&r) catch continue;
            // Ranked against this host's own interface table: the peer's
            // address on the link we share beats its VM-bridge or VPN
            // address (0.1.1). `c.rank` orders a ring of candidates.
            const c = mdns.profiles.studio.dialCandidate(&r, svc.interfaces()) orelse continue;
            // Copy values into the mutex-guarded snapshot the UI reads
            // (`macos.m` statsMutex). `p.spki` is the value for
            // `Config.expected_peer_spki`; `c.addr` formats as the
            // `peer_host:peer_port` literal with "{f}".
            snapshot.setPeer(r.instance.firstLabel() orelse "", p, c.addr, c.rank);
        },
        .lost => |l| snapshot.clearPeer(l.instance.firstLabel() orelse ""),
        .warning => |w| if (w == .no_packets_10s) snapshot.noteLocalNetworkBlocked(),
        else => {},
    };
}
```

`studio.dialCandidate` is `Resolved.preferred` (see below) minus
link-local IPv6: shared-studio dials through qmsg, whose endpoint parser
rejects `%zone`. `studio.dialAddress` is the same without the rank.

`Resolved.instance` is the full name `Alice._shared-studio._udp.local`;
`firstLabel()` gives the display name back. A `resolved` arrives once per
`(instance, interface)`; a two-interface Mac sees two, a Mac with a Lima
bridge and a VPN sees four, and the first to arrive may carry an
address this host cannot dial (the bridge's `192.168.215.0`). Key the
snapshot by instance, and let a later `resolved` replace the dial
address only when `c.betterThan(previous)` (keep the previous
`Preferred`, not just its rank: `betterThan` is the one comparison that
holds with or without a table): a candidate ring (shared-studio's
`network.zig` endpoint ring) puts the best-ranked address at
`endpoint_index` and keeps the rest as fallbacks for `nextEndpoint` to
rotate through on a dial failure. Equal-ranked candidates are not
"better", so they keep first-arrival order: on this Mac `bridge100`
(192.168.139.3, a real host address on a local /24) ranks
`on_link_same_if` exactly like en0's 192.168.1.75, and whichever
`resolved` lands first stays at `endpoint_index`. A consumer bound to
one specific local address should prefer the candidate whose arrival
`r.ifindex` owns that bound address (`svc.interfaces()[i].index`); the
ranking has no such tie-break yet.

Replace `--peer host:port --expect <spki hex>` with `--discover
<instance>`: the browse fills `peer_host`, `peer_port` and
`expected_peer_spki` from the first `resolved` whose instance matches.
The TXT only selects. The pinned-CA mTLS handshake with
`expected_peer_spki` proves the peer (§7).

## 3. qmesh-zig: seeds by `lookup`, then `on_iteration`

Two Services, in order. The first does one bounded `lookup` (mode B) for
the start-up seeds and is gone before the second exists. The second runs
in mode A from `Runner.Options.on_iteration`. The plan (§3.2) chose this
form to keep the clock-source rule of §1.

### Start-up seeds

```zig
var found: [16]mdns.Resolved = undefined;
const n = blk: {
    var boot = try mdns.Service.init(gpa, io, .{ .host_label = host_label });
    defer boot.deinit();
    break :blk boot.lookup(mdns.profiles.qmesh.service_type, .{
        .timeout_us = 3 * std.time.us_per_s,
        .quiet_us = 500 * std.time.us_per_ms,
    }, &found) catch |err| switch (err) {
        error.Canceled => return err, // Group.cancel during start-up: clean exit
        else => 0, // no seeds is not fatal; the mesh can also be joined by config
    };
};
```

`lookup` stops its browse on every exit path, so `deinit` right after it
sends no stray query. It returns after `quiet_us` with at least one
result, or at `timeout_us`, or when `found` is full. One slot per
`(instance, type, ifindex)`; a peer heard on two interfaces fills two.

Each result goes through the same `SeedSet` the continuous browse uses,
so a seed found now is not joined again in a second by `on_iteration`:

```zig
var seeds: mdns.profiles.qmesh.SeedSet = .{};
// Before `boot.deinit()`: its interface table ranks the addresses (the
// mode-A Service below reports the same table, so either one serves).
for (found[0..n]) |*r| if (seeds.accept(r, boot.interfaces())) |c| joinContact(runner, c);
```

### The glue into `qmesh.Addr`

`qmesh.Addr` has no scope field and mdns-zig must stay a leaf, so the
conversion is an inline `switch` in the consumer (plan §11, decision 5).
`Addr.ipv4(octets, port)` and `Addr.ipv6(octets, port)` are the real
constructors (`qmesh-zig/src/peer.zig`):

```zig
fn joinContact(r: *qmesh_quic.Runner, c: mdns.profiles.qmesh.Contact) void {
    const addr: qmesh.Addr = switch (c.addr) {
        .ip4 => |a| qmesh.Addr.ipv4(a.bytes, a.port),
        .ip6 => |a| qmesh.Addr.ipv6(a.bytes, a.port),
    };
    r.endpoint().startJoin(.{ .id = .{ .bytes = c.id }, .addr = addr });
}
```

A link-local `c.addr.ip6` carries its scope in `.ip6.interface.index`,
which `Addr.ipv6` drops. Until qmesh-zig gains `Addr.fromIp` (M6), skip
those: `if (c.addr == .ip6 and c.addr.ip6.isLinkLocal()) return;`.
`pickAddr` only returns one when the peer has no IPv4 and no global IPv6.

`joinContact` may run twice for one `id` (0.1.1, see "Re-admission"
below). In qmesh-zig that is safe: a second `Endpoint.startJoin` for an
id overwrites the pending join's contact and re-emits the connect
effect; `connectPeer` is a no-op while a session to that id is
established or a dial to it is in flight, and the join-retry tick after
a failed dial uses the updated contact, so the better address is dialed
once the bad one times out.

### Continuous browse in `on_iteration`

```zig
const Glue = struct {
    svc: mdns.Service,
    seeds: mdns.profiles.qmesh.SeedSet = .{},

    fn onIteration(ctx: ?*anyopaque, r: *qmesh_quic.Runner, now_us: u64) anyerror!void {
        const g: *Glue = @ptrCast(@alignCast(ctx));
        try g.svc.tick(now_us);
        var evs: [8]mdns.Event = undefined;
        while (true) {
            const n = g.svc.poll(&evs);
            if (n == 0) break;
            for (evs[0..n]) |ev| {
                if (ev != .resolved) continue;
                if (g.seeds.accept(&ev.resolved, g.svc.interfaces())) |c| joinContact(r, c);
            }
        }
    }
};

// After the seed lookup above, and after the Runner bound its socket:
var glue: Glue = .{ .svc = try mdns.Service.init(gpa, io, .{ .host_label = host_label }) };
defer glue.svc.deinit();
_ = try glue.svc.browse(mdns.profiles.qmesh.service_type);

var ad = try mdns.profiles.qmesh.Advert.init(.{
    .port = local_port, // Runner.localAddress() port
    .id = local_id.bytes, // PeerId
    .epoch = boot_epoch, // Endpoint.Options.boot_epoch
});
const reg = try glue.svc.advertise(ad.desc());
// Runner.Options: .on_iteration = Glue.onIteration, .on_iteration_ctx = &glue
```

`SeedSet.accept` returns one `Contact` per `(id, epoch)`, plus one more
each time a later `resolved` for that pair carries a strictly
better-ranked address. A `resolved` re-emitted because the peer's
address set changed is a new contact only if it ranks better. A
`resolved` re-emitted with a new `epoch` always is: the peer restarted
and called `updateTxt`, and qmesh must join it again. `accept` also
rejects adverts that fail `Parsed.parse` and adverts with no dialable
address; `seeds.stats` counts each case (`readmitted` for the
re-admissions).

**Re-admission (0.1.1).** A multi-homed peer yields one `resolved` per
interface it was heard on. On a Mac with a Lima bridge the first to
arrive can be the bridge's, whose only address is `192.168.215.0` (the
subnet base, undialable), or a VPN interface's tunnel address, and a
first-wins `SeedSet` joined that address (observed: B joined A at
`192.168.215.0:4471` while A listened on `192.168.1.75`, and the session
came up only because A dialed back). `accept` now ranks the address
against `local`, this host's `Service.interfaces()`, with
`Resolved.preferred`: on-link with the arrival interface's prefix, on-link
with any local prefix, global IPv6, an IPv4 on a foreign subnet, a scoped
link-local; the network base of a local prefix is never dialable. Pass
`&.{}` to keep the old v4-first order with no re-admission by rank. The
consumer must tolerate a second `Contact` for the same `id` (the
`startJoin` semantics above). Re-admission needs a STRICTLY better rank:
two on-link interfaces of the peer (on this Mac `bridge100`'s
192.168.139.3 and en0's 192.168.1.75 both rank `on_link_same_if` when
heard on their own interface) keep first-arrival order, and a qmesh
node bound to one of those addresses should prefer the `Contact` whose
`ifindex` owns its bound address; the set has no such tie-break yet.

Open item for the qmesh-zig bump (not an mdns change): "dialed once the
bad one times out" is the QUIC handshake timeout of the in-flight dial
(`connectPeer` returns early while a session to that id is
`.connecting`, `endpoint.zig`) plus the next 2 s join retry
(`hyparview.zig` `join_timeout_us`), which can be many seconds. On a
re-admitted `Contact` (a strictly better `rank` for an id already
joining) qmesh can drop the `.connecting` session to that id before
`startJoin` so the better address is dialed at once.

The advertiser side of an epoch change:

```zig
ad.setEpoch(new_boot_epoch);
try glue.svc.updateTxt(reg, ad.txt());
```

Two caveats from the plan. Multicast does not exist on fly 6pn, so mDNS
is a LAN and dev convenience, not the production bootstrap. qmesh-zig pins
dev.1683 and cannot consume mdns-zig until its pin bump.

## 4. qmsg: `tick` / `poll` beside `Node.tick`

A qmsg app already owns a loop over `Node.tick(now_us)`, `Node.poll(out)`
and `Node.nextTimer()`. The mdns `Service` sits beside the `Node` with the
same `now_us`:

```zig
// Set-up
var svc = try mdns.Service.init(gpa, io, .{ .host_label = host_label });
defer svc.deinit();
var ad = try mdns.profiles.qmsg.Advert.init(.{
    .instance = "alice",
    .port = listen_port, // quic_listeners[id].localAddress() port
    .spki = local_spki,
    .sn = server_name, // the QuicListenOptions server name peers dial with
    .pat = supported_patterns, // optional hint; HELLO is authoritative
});
_ = try svc.advertise(ad.desc());
_ = try svc.browse(mdns.profiles.qmsg.service_type);

// Loop body
try node.tick(now_us);
try svc.tick(now_us);
var evs: [8]mdns.Event = undefined;
while (true) {
    const n = svc.poll(&evs);
    if (n == 0) break;
    for (evs[0..n]) |ev| {
        if (ev != .resolved) continue;
        const r = &ev.resolved;
        const p = mdns.profiles.qmsg.Parsed.parse(r) catch continue;
        const addr = r.preferredAddress(svc.interfaces()) orelse continue; // ranked against our own interfaces (0.1.1)
        if (addr == .ip6 and addr.ip6.isLinkLocal()) continue; // parseEndpoint rejects %zone
        var lit: [64]u8 = undefined;
        const endpoint = try std.fmt.bufPrint(&lit, "{f}", .{addr}); // "10.0.0.5:4433" or "[2a01::7]:4433"
        _ = try node.dialQuic(endpoint, .{
            .server_name = p.sn.slice(),
            .expected_peer_spki = p.spki,
            .ca_pem = ca_pem,
            .client_cert_pem = cert_pem,
            .client_key_pem = key_pem,
        });
    }
}
// Sleep until the earlier of node.nextTimer() and svc.nextDeadline(now_us),
// capped at rx_poll_interval_us so incoming mDNS is drained.
```

`Node.io` defaults to `std.Io.Threaded.global_single_threaded`. The
`Service` can share that `Io`: modes A and B never need concurrency. Only
`serve` (mode C) needs it: start it with `Group.concurrent`, which
returns `error.ConcurrencyUnavailable` on a single-threaded `Io` instead
of running `serve` inline and blocking the caller (`serve` itself only
returns `error.Canceled`).

## 5. A foreign QUIC loop: `sockets()`

A reactor that already polls file descriptors (quic-zig `udp_server`, a
`poll(2)` loop) adds the two mdns sockets to its set and calls `tick` on
wake-ups. Set `rx_poll_interval_us = 0` so every `tick` drains:

```zig
var svc = try mdns.Service.init(gpa, io, .{ .host_label = host_label, .rx_poll_interval_us = 0 });
defer svc.deinit();

// Register the fds once (v4, then v6 when bound).
for (svc.sockets()) |sock| reactor.watchReadable(sock.handle);

// Each wake-up, readable or timer:
try svc.tick(now_us);
// Then arm the timer: null means no mDNS work is pending.
const next = svc.nextDeadline(now_us);
```

`tick` does a zero-timeout receive on each socket, runs the Engine's
timers, and sends what is due. The reactor owns every wait; the Service
never blocks it. Do not call `step`, `run`, `serve` or `lookup` on this
Service: they bind mode B or C.

`firstBinder()` is false when another stack (mDNSResponder, avahi,
systemd-resolved) owns `*:5353` on the host. The Service then disables QU
queries and keeps working through multicast; nothing changes for the
reactor.

## 6. TXT schemas

All three types satisfy RFC 6335 §5.1 and use `_udp` because QUIC is not
TCP (RFC 6763 §7). Keys follow RFC 6763 §6 and compare case-insensitively.
`txtvers=1` is the first key. Every TXT stays under 400 B at maximal field
lengths (`tests/profiles_test.zig`).

| Service type | Instance | TXT keys, in order |
|---|---|---|
| `_qmsg._udp` | user label or host | `txtvers=1`, `alpn=qmsg/1`, `spki=<64 lowercase hex>`, `sn=<server_name>`, `pat=<hex u64>` (optional) |
| `_qmesh._udp` | first 16 hex of PeerId, or a label | `txtvers=1`, `alpn=qmesh/2`, `fv=2`, `id=<64 lowercase hex PeerId>`, `epoch=<32 hex u128>` |
| `_shared-studio._udp` | performer display name | `txtvers=1`, `alpn=qmsg/1`, `spki=<64 lowercase hex>`, `epoch=<16 hex u64>`, `role=conductor\|performer`, `sn=shared-studio`, `clip=v2` |

Parser rules (`mdns.profiles.*.Parsed.parse`):

- The `Resolved.service_type` must be the profile's type
  (`error.WrongServiceType`), so a qmsg record never parses as a studio one.
- `spki` and `id` must be exactly 64 lowercase hex digits
  (`error.InvalidDigest`). The check runs before `std.fmt.hexToBytes`.
- `epoch` is 1 to 32 hex digits of either case (`error.InvalidEpoch`).
  `Parsed.epoch.value` is the `u128`; `Parsed.epoch.len` is the sender's
  width in bytes (qmesh 16, shared-studio 8).
- `pat` is optional, 1 to 16 hex digits (`error.InvalidPat`). It is a
  hint; HELLO after connect is authoritative (`qmsg/AUTH.md`).
- `txtvers`, `alpn`, `fv`, `clip` and the studio `sn` are checked when
  present and accepted when absent (`error.TxtVersionMismatch`,
  `error.AlpnMismatch`, `error.FormatMismatch`, `error.InvalidServerName`).
- The qmsg `sn` is required: `dialQuic` needs a server name.
- `role` is required and byte-exact (`error.InvalidRole`).
- A required key that is absent, or present as a boolean attribute, is
  `error.MissingKey`.
- Unknown keys are ignored (RFC 6763 §6.4). Add keys freely; bump
  `txtvers` only for an incompatible change.

`Advert.init` validates the instance (one label, 1..63 octets of UTF-8
without control characters), the port (not 0) and the qmsg `sn` (1..252
printable ASCII). The Engine validates again at `advertise`; a rejected
advert costs no packet.

## 7. Security posture

A TXT record is unauthenticated. Any host on the link can publish any
`spki`, `id`, `sn` or `epoch`. mdns-zig therefore treats every TXT value
as a selector, never as proof:

- `spki` / `id` tell the consumer which peer to dial and which digest to
  pin. The pinned-CA mTLS handshake with `expected_peer_spki` (qmsg
  `QuicDialOptions`, shared-studio `Config.expected_peer_spki`) proves the
  peer. qmesh HELLO does the same with `PeerId` (`qmesh-zig/src/quic/hello.zig`).
- A forged advert can at most make a consumer dial a wrong address, where
  the handshake fails. It cannot impersonate a peer.
- `epoch` only decides whether `SeedSet` re-admits a contact. A forged
  epoch causes one extra join attempt, bounded by the mDNS query schedule.
- `pat` is a hint. HELLO after connect is authoritative.
- The parsers reject anything but the exact syntax before decoding, and
  no network-fed path in `src/profiles/` or `src/wire/` can panic
  (`SECURITY.md`).
- Do not put secrets in TXT. Every byte is multicast to the link in clear.

## 8. macOS Local Network privacy

macOS gates multicast on the local network per app. A Terminal-launched
binary (and anything run over SSH) inherits Terminal's grant. A bundled
GUI app such as shared-studio needs `NSLocalNetworkUsageDescription` and
`NSBonjourServices` (listing `_shared-studio._udp` and `_qmsg._udp`) in
its `Info.plist`, and the user must accept the prompt once.

The signature of a denied app is `warning.no_packets_10s`: a browse has
sent queries (`stats().tx > 0`) and received nothing (`rx == 0`) for 10 s.
Surface it in the UI. The Service keeps running; the grant can arrive
later and the next query schedule picks it up.

Binding `*:5353` beside mDNSResponder works on every macOS the plan
tested (`docs/platform-matrix.md`). `firstBinder()` is false there, so QU
queries are off and the OS daemon still answers unicast.

## 9. Quick reference

```zig
// Value types (no pointers into the Engine)
mdns.Event, mdns.Resolved, mdns.Txt, mdns.TxtPair, mdns.ServiceDesc, mdns.RegId, mdns.BrowseId

// Service (one mode, one clock)
mdns.Service.init(gpa, io, .{ .host_label, .ipv6, .include_loopback, .interfaces, .rx_poll_interval_us })
svc.advertise(desc) !RegId        svc.updateTxt(id, pairs) !void      svc.withdraw(id)
svc.browse(type) !BrowseId        svc.stopBrowse(id)
svc.tick(now_us) !void            svc.poll(&events) usize             svc.nextDeadline(now_us) ?u64
svc.lookup(type, opts, &out) !usize   svc.step(cap)   svc.run(&shutdown, hook)   mdns.Service.serve(&svc, &mailbox)
svc.stats() Stats                 svc.sockets() []const Io.net.Socket  svc.firstBinder() bool

// Profiles (std + value types only)
mdns.profiles.qmsg.Advert.init(.{ .instance, .port, .spki, .sn, .pat })     .desc() .txt() .setPat()
mdns.profiles.qmesh.Advert.init(.{ .instance, .port, .id, .epoch })         .desc() .txt() .setEpoch()
mdns.profiles.studio.Advert.init(.{ .instance, .port, .spki, .epoch, .role }) .desc() .txt() .setEpoch() .setRole()
mdns.profiles.{qmsg,qmesh,studio}.Parsed.parse(&resolved) ParseError!Parsed
mdns.profiles.qmesh.SeedSet .accept(&resolved, svc.interfaces()) ?Contact   .forget(id)   .clear()   .stats
mdns.profiles.qmesh.pickAddr(&resolved, local) ?Io.net.IpAddress
mdns.profiles.studio.dialCandidate(&resolved, local) ?Preferred   .dialAddress(&resolved, local) ?Io.net.IpAddress
resolved.preferredAddress(svc.interfaces()) ?Io.net.IpAddress   resolved.preferred(local) ?Preferred{addr, rank: AddrRank}
svc.interfaces() []const Interface
```
