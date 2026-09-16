# Platform matrix

Per-OS socket-option numbers, struct layouts and coexistence rules for the
two mDNS sockets, plus the measured results of the M0 spikes. "Coexistence"
means sharing UDP 5353 with the OS mDNS daemon. "cmsg" means socket
ancillary data (`struct cmsghdr`), which carries the arrival interface.

Only the macOS and Linux columns are v0.1 gates. The macOS column was
filled by the M0 spikes and the M2 live runs on this Mac; the Linux column
by the M2 runs of the cross-built `aarch64-linux-musl` binaries in the
Lima VM `zig-uring` (see "Linux runs (M2)" below). **The FreeBSD and
OpenBSD columns are compile-only, reviewed, not run**: each value was read
from the pinned std or from an OS header and cross-checked against the
plan, the library and `mdns-live` compile for `aarch64-freebsd` and
`aarch64-openbsd`, but no binary has exercised them.

## Sources

- `STD` = `/Users/nullstyle/.local/share/mise/installs/zig/0.17.0-dev.1786+75044cb04/lib/std`
  (the compiler pin in `mise.toml`).
- `SDK` = `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include`
  (symlink to `MacOSX27.0.sdk` on the dev Mac). `std.c.darwin` is not `pub`
  and `std.posix.IP`/`IPV6` resolve to `void` on Darwin under dev.1786
  (`STD/c.zig:6608-6640`, `else => void`), so the Darwin numbers in
  `src/platform/socket_opts.zig` are hard-coded and each cites its SDK line.
  `STD/c/darwin.zig:1641-1776` carries the same numbers and is quoted here
  as a second witness only.
- Linux: `STD/os/linux.zig` (`SO` 5173-5200 generic arch, `SOL` 5257-5266,
  `IP` 5295-5350, `IPV6` 5351-5435, `in_pktinfo`/`in6_pktinfo` 5471-5481,
  `IFF` 8963-8974, `cmsghdr` 10913-10917).
- FreeBSD: `STD/c/freebsd.zig` (`IP` 399-474, `IPV6` 475-537) and `STD/c.zig`
  (`SO` 6693-6732, `cmsghdr` 4237-4274, `in6_pktinfo` 4076-4090).
- OpenBSD: `STD/c/openbsd.zig` (`IP` 312-356, `IPV6` 357-397) and `STD/c.zig`
  (`SO` 6847-6876, `cmsghdr` 4237-4274).
- Values marked **(unverified)** come from the OS headers as remembered, not
  from a file opened for this document. The FreeBSD and OpenBSD struct and
  flag rows below were re-checked (M2 review) against the headers shipped in
  the pinned toolchain under `lib/libc/include/{generic-freebsd,
  generic-openbsd, aarch64-freebsd-none, aarch64-openbsd-none}` and cite
  those files; "not run" still applies to both.

## Socket-level and IPv4 options

| Item | macOS (Darwin) | Linux | FreeBSD | OpenBSD |
|---|---|---|---|---|
| Status | gate; M0 spikes and M2 live runs on this Mac | gate; M2 runs in Lima `zig-uring` (Fedora 44, kernel 6.19.10, musl static binary) | compile-only, reviewed, not run | compile-only, reviewed, not run |
| `SOL_SOCKET` | `0xffff` (`SDK/sys/socket.h:356`) | `1` on every arch except mips/sparc/alpha = `0xffff` (`linux.zig:5258-5261`) | `0xffff` (`c.zig:6641-6646`) | `0xffff` (`c.zig:6641-6646`) |
| `SO_REUSEADDR` | `0x0004` (`sys/socket.h:124`) | `2` generic (`linux.zig:5175`); mips/alpha `0x0004`, sparc `4` | `0x0004` (`c.zig:6696`) | `0x0004` (`c.zig:6850`) |
| `SO_REUSEPORT` | `0x0200` (`sys/socket.h:137`) | `15` generic (`linux.zig:5188`); mips/alpha `0x0200`, sparc `512` | `0x0200` (`c.zig:6703`); `SO_REUSEPORT_LB 0x10000` (`c.zig:6710`) not used | `0x0200` (`c.zig:6857`) |
| `IPPROTO_IP` level | `0` | `0` (`linux.zig:5263`) | `0` | `0` |
| `IP_TTL` | `4` (`netinet/in.h:408`) | `2` (`linux.zig:5297`) | `4` (`freebsd.zig:403`) | `4` (`openbsd.zig:316`) |
| `IP_MULTICAST_IF` | `9`, arg `struct in_addr` (`in.h:413`) or `struct ip_mreqn` (`in.h:515`, ifindex) | `32`, arg `ip_mreqn` (`linux.zig:5323`) | `9` (`freebsd.zig:409`) | `9` (`openbsd.zig:321`) |
| `IP_MULTICAST_TTL` | `10`, `u_char` (`in.h:414`) | `33`, `int` (`linux.zig:5324`) | `10`, `u_char` (`freebsd.zig:410`) | `10`, `u_char` (`openbsd.zig:322`) |
| `IP_MULTICAST_LOOP` | `11`, `u_char` (`in.h:415`) | `34`, `int` (`linux.zig:5325`) | `11`, `u_char` (`freebsd.zig:411`) | `11`, `u_char` (`openbsd.zig:323`) |
| `IP_ADD_MEMBERSHIP` | `12` (`in.h:416`) | `35` (`linux.zig:5326`) | `12` (`freebsd.zig:412`) | `12` (`openbsd.zig:324`) |
| `IP_DROP_MEMBERSHIP` | `13` (`in.h:417`) | `36` (`linux.zig:5327`) | `13` (`freebsd.zig:413`) | `13` (`openbsd.zig:325`) |
| `IP_PKTINFO` (recv + send) | `26`; `IP_RECVPKTINFO` is an alias (`in.h:433-434`) | `8` (`linux.zig:5303`) | none; use `IP_RECVIF` + `IP_RECVDSTADDR` | none; use `IP_RECVIF` + `IP_RECVDSTADDR` |
| `IP_RECVIF` | `20` (`in.h:424`), alternative to PKTINFO | n/a | `20` (`freebsd.zig:420`) | `30` (`openbsd.zig:337`) |
| `IP_RECVDSTADDR` | `7` (`in.h:411`) | n/a (`IP_PKTINFO` carries it) | `7` (`freebsd.zig:406`) | `7` (`openbsd.zig:319`) |
| `IP_RECVTTL` | `24` (`in.h:431`) | `12` (`linux.zig:5308`) | `65` (`freebsd.zig:447`) | `31` (`openbsd.zig:338`) |
| `IP_MULTICAST_ALL` | n/a | `49`, set to 0 so a socket only sees groups it joined (`linux.zig:5333`); **effect measured** (M2): with no joins a wildcard `*:5353` socket saw 4 datagrams in 4 s at the default and 0 with the option at 0 | n/a | n/a |
| `IP_MULTICAST_IFINDEX` | `66`, `int` ifindex (`in.h:460`); Darwin-only alternative to `ip_mreqn` for egress | n/a | n/a | n/a |

## IPv6 options

| Item | macOS (Darwin) | Linux | FreeBSD | OpenBSD |
|---|---|---|---|---|
| `IPPROTO_IPV6` level | `41` | `41` (`linux.zig:5264`) | `41` | `41` |
| `IPV6_UNICAST_HOPS` | `4` (`netinet6/in6.h:383`) | `16` (`linux.zig:5364`) | `4` (`freebsd.zig:476`) | `4` (`openbsd.zig:358`) |
| `IPV6_MULTICAST_IF` | `9`, `u_int` ifindex (`in6.h:384`) | `17` (`linux.zig:5365`) | `9` (`freebsd.zig:477`) | `9` (`openbsd.zig:359`) |
| `IPV6_MULTICAST_HOPS` | `10`, `int` (`in6.h:385`) | `18` (`linux.zig:5366`) | `10` (`freebsd.zig:478`) | `10` (`openbsd.zig:360`) |
| `IPV6_MULTICAST_LOOP` | `11`, `u_int` (`in6.h:386`) | `19` (`linux.zig:5367`) | `11` (`freebsd.zig:479`) | `11` (`openbsd.zig:361`) |
| group join | `IPV6_JOIN_GROUP 12` (`in6.h:387`) | `IPV6_ADD_MEMBERSHIP 20` (`linux.zig:5368`; std has no `JOIN_GROUP` name) | `IPV6_JOIN_GROUP 12` (`freebsd.zig:480`) | `IPV6_JOIN_GROUP 12` (`openbsd.zig:362`) |
| group leave | `IPV6_LEAVE_GROUP 13` (`in6.h:388`) | `IPV6_DROP_MEMBERSHIP 21` (`linux.zig:5369`) | `IPV6_LEAVE_GROUP 13` (`freebsd.zig:481`) | `IPV6_LEAVE_GROUP 13` (`openbsd.zig:363`) |
| `IPV6_V6ONLY` | `27` (`in6.h:415`) | `26` (`linux.zig:5374`) | `27` (`freebsd.zig:491`) | `27` (`openbsd.zig:366`) |
| `IPV6_RECVPKTINFO` | `61` (`in6.h:457`, RFC 3542 block) | `49` (`linux.zig:5394`) | `36` (`freebsd.zig:500`) | `36` (`openbsd.zig:368`) |
| `IPV6_PKTINFO` (cmsg type + send) | `46` = `IPV6_3542PKTINFO` (`in6.h:478,485`); the RFC 2292 alias `IPV6_2292PKTINFO 19` (`in6.h:404`) is not used | `50` (`linux.zig:5395`) | `46` (`freebsd.zig:510`) | `46` (`openbsd.zig:376`) |
| `IPV6_RECVHOPLIMIT` | `37` (`in6.h:459`) | `51` (`linux.zig:5396`) | `37` (`freebsd.zig:501`) | `37` (`openbsd.zig:369`) |
| `IPV6_HOPLIMIT` (cmsg type) | `47` = `IPV6_3542HOPLIMIT` (`in6.h:479,486`) | `52` (`linux.zig:5397`) | `47` (`freebsd.zig:511`) | `47` (`openbsd.zig:377`) |
| `IPV6_RECVIF` | none; `IPV6_RECVPKTINFO` covers it | n/a | n/a | n/a |
| `IPV6_MULTICAST_ALL` | n/a | `29` (`linux/in6.h`, kernel 4.20+; **not in `std.os.linux.IPV6`**, hard-coded), set to 0; **effect measured** (M2): with no v6 join `mdns-live --ifindex 1` received 6 `ff02::fb` datagrams from avahi on `eth0` before the option and 0 after; ENOPROTOOPT on older kernels is tolerated | n/a | n/a |

Darwin header note: `netinet6/in6.h` exposes the RFC 3542 names only when
`__APPLE_USE_RFC_3542` is defined and the RFC 2292 names only under
`__APPLE_USE_RFC_2292` (`in6.h:359-371, 403-411, 441-504`). The kernel
accepts the numbers regardless of the macro; we hard-code the 3542 set.

## Structs, alignment and interface enumeration

| Item | macOS (Darwin) | Linux | FreeBSD | OpenBSD |
|---|---|---|---|---|
| `ip_mreq` | `{ in_addr multiaddr, in_addr interface }`, 8 bytes (`in.h:505-508`) | same layout (not declared in std; self-declared; joins with `ip_mreqn` instead, see below) | same (`generic-freebsd/netinet/in.h:554-557`); the join struct we use there | same (`generic-openbsd/netinet/in.h:359-362`); the join struct we use there |
| `ip_mreqn` | `{ multiaddr, address, int ifindex }`, 12 bytes (`in.h:515-519`); accepted by `IP_MULTICAST_IF` | `{ multiaddr, address, int ifindex }`, 12 bytes (not in std; self-declared); the join struct we use; **verified** (M2): `IP_ADD_MEMBERSHIP` by ifindex succeeded on `lo` and `eth0` and the joined groups delivered | declared (`generic-freebsd/netinet/in.h:564-568`) and accepted by `IP_MULTICAST_IF` (`in.h:445`, "struct in_addr *or* struct ip_mreqn"); the code still joins with `ip_mreq` (`has_ip_mreqn = false`) | declared (`generic-openbsd/netinet/in.h:364-368`); the code joins with `ip_mreq` |
| `ipv6_mreq` | `{ in6_addr multiaddr, unsigned ifindex }`, 20 bytes (`in6.h:538-541`) | same layout, 4-byte ifindex (`unsigned int` in glibc, `int` in the kernel uapi) (not in std; **verified** by the M2 `eth0` join and delivery) | same (`generic-freebsd/netinet6/in6.h:539-542`) | same (`generic-openbsd/netinet6/in6.h:357-360`) |
| `in_pktinfo` | `{ u32 ifindex, in_addr spec_dst, in_addr addr }` (`in.h:616-620`; `c.zig:4065-4074`) | `{ i32 ifindex, u32 spec_dst, u32 addr }` (`linux.zig:5471-5475`) | void (`c.zig:4065-4075`) | void (`c.zig:4065-4075`) |
| `in6_pktinfo` | `{ [16]u8 addr, u32 ifindex }` (`in6.h:546-549`; `c.zig:4076-4090`) | `{ [16]u8 addr, i32 ifindex }` (`linux.zig:5478-5481`) | `{ [16]u8 addr, u32 ifindex }` (`c.zig:4076-4090`) | `{ [16]u8 addr, u32 ifindex }` (`c.zig:4076-4090`) |
| `IP_RECVIF` cmsg payload | `struct sockaddr_dl` (`sdl_index` is the ifindex); not enabled (pktinfo is) | n/a | `struct sockaddr_dl` (`generic-freebsd/net/if_dl.h:58-67`: `sdl_len, sdl_family, u_short sdl_index, ..., sdl_data[46]`, 54 bytes, `_ALIGN`ed to 56 in the cmsg) | `struct sockaddr_dl` (`generic-openbsd/net/if_dl.h:59-68`: same head, `sdl_data[24]`, 32 bytes) |
| `cmsghdr` | `{ socklen_t len, int level, int type }`, 12 bytes (`sys/socket.h:608-613`; `c.zig:4259-4274` `posix_cmsghdr`) | glibc: `{ usize len, i32 level, i32 type }` (`linux.zig:10913-10917`); musl on 64-bit: `socklen_t len` plus padding (`c.zig:4238`, `posix_cmsghdr`) | `posix_cmsghdr` (`c.zig:4242,4263-4274`) | `posix_cmsghdr` (`c.zig:4248,4263-4274`) |
| cmsg alignment | **4**: `CMSG_LEN`/`CMSG_SPACE`/`CMSG_NXTHDR` use `__DARWIN_ALIGN32` (`sys/socket.h:643-674`; `arm/_param.h:20-21`, `i386/_param.h:44-45`); confirmed live by the M0 spike (kernel-filled `control_len` 40 for v4, 48 for v6, see below) | `@sizeOf(usize)` (`CMSG_ALIGN` rounds to `sizeof(size_t)`); consistent with the M2 runs (pktinfo ifindex decoded on 100% of v4 and v6 datagrams through the 8-byte walker; the kernel-filled `control_len` was not printed) | `@sizeOf(usize)`: `_ALIGNBYTES (sizeof(long long) - 1)` (`aarch64-freebsd-none/machine/_align.h:42-43`) | `@sizeOf(usize)`: `_ALIGNBYTES (sizeof(long) - 1)` (`aarch64-openbsd-none/machine/_types.h:53-55`) |
| `getifaddrs`/`freeifaddrs` | libc, `SDK/ifaddrs.h:64-65`; not declared anywhere in `STD/c.zig` or `STD/posix.zig`, so `ifaces.zig` declares the externs itself | libc (glibc and musl); self-declared extern | libc; self-declared extern | libc; self-declared extern |
| `struct ifaddrs` | `{ next, name, u32 flags, addr, netmask, dstaddr, data }` (`ifaddrs.h:36-44`) | glibc: `{ next, name, u32 flags, addr, netmask, ifa_ifu (broadaddr/dstaddr union), data }` (`generic-glibc/ifaddrs.h:29-57`; compiled for `x86_64-linux-gnu`, only musl was run); musl: same field order (`musl/include/ifaddrs.h:12-23`), **verified** (M2, static musl binary: `lo` 127.0.0.1/8 + ::1, `eth0` one v4 /24 and one link-local v6 with the right flags and names) | `{ next, name, unsigned int flags, addr, netmask, dstaddr, data }` (`generic-freebsd/ifaddrs.h:31-39`) | `{ next, name, unsigned int flags, addr, netmask, dstaddr, data }` (`generic-openbsd/ifaddrs.h:31-39`) |
| `IFF_UP` | `0x1` (`net/if.h:93`) | `0x1`; `std.os.linux.IFF.UP` is bit 0 (`linux.zig:8963-8964`) | `0x1` (`generic-freebsd/net/if.h:139`; `IFF_LOOPBACK 0x8` at `:142`) | `0x1` (`generic-openbsd/net/if.h:203`; `IFF_LOOPBACK 0x8` at `:206`) |
| `IFF_MULTICAST` | `0x8000` (`net/if.h:109`) | `0x1000` (**verified** M2: `/sys/class/net/eth0/flags` = `0x1003`, `lo` = `0x9`); **not present in std**: `std.os.linux.IFF` is a `packed struct(u16)` whose named bits stop at `PROMISC` (bit 8) (`linux.zig:8963-8974`), so only `UP` can be asserted against std | `0x8000` (`generic-freebsd/net/if.h:155`) | `0x8000` (`generic-openbsd/net/if.h:218`) |
| `sockaddr` family field | `{ u8 len, u8 family }` (BSD `sa_len`) | `{ u16 family }` | `{ u8 len, u8 family }` | `{ u8 len, u8 family }` |
| Receive control buffer (`socket_opts.control_buffer_size`) | 64 B: pktinfo + TTL = 40 (v4) / 48 (v6) under the 4-byte layout | 64 B: 56 (v4) / 64 (v6) under the 8-byte layout (v6 fits exactly) | **128 B** (deviation from plan 4.5 `[8][64]u8`): the v4 set is `IP_RECVDSTADDR` + `IP_RECVTTL` + `IP_RECVIF` = 24 + 24 + 72 = 120 with the 56-byte `sockaddr_dl`; in 64 B every v4 datagram would be `MSG_CTRUNC` with the `IP_RECVIF` entry cut, and the arrival ifindex would never decode | **128 B**: 24 + 24 + 48 = 96 with the 32-byte `sockaddr_dl`; same reason |

## Behaviour and coexistence

| Item | macOS (Darwin) | Linux | FreeBSD | OpenBSD |
|---|---|---|---|---|
| OS daemon | mDNSResponder, binds 5353 with `SO_REUSEPORT` | avahi-daemon as uid `avahi` (`SO_REUSEADDR` + `SO_REUSEPORT`) **and** systemd-resolved (`MulticastDNS=` on): on Fedora 44 both hold `0.0.0.0:5353` and `[::]:5353` at once (`ss -ulnp`), so `firstBinder()` is `true` only when both are stopped | none by default | none by default |
| Coexistence rule | `SO_REUSEPORT` required; `SO_REUSEADDR` alone fails (M0 spike, see below) | `SO_REUSEADDR` required across uids; `SO_REUSEPORT` alone fails cross-uid; set both (M2: bind as a plain user beside root-owned systemd-resolved and uid-`avahi` avahi-daemon succeeded with both set; the single-flag cases were not re-measured on Linux) | set both | set both |
| Unicast delivery when shared | exactly one socket receives; which one is an OS detail recorded below and never relied on | hash-balanced among same-uid sockets; never relied on | one socket | one socket |
| Egress interface selection | `IP_PKTINFO` / `IPV6_PKTINFO` cmsg per send | pktinfo cmsg per send | `IPV6_PKTINFO` cmsg; v4 via `IP_MULTICAST_IF` per send | `IPV6_PKTINFO` cmsg; v4 via `IP_MULTICAST_IF` per send |
| Arrival interface | `IP_PKTINFO` (`ipi_ifindex`) and `IPV6_PKTINFO` (`ipi6_ifindex`) | `IP_PKTINFO`, `IPV6_PKTINFO` | `IP_RECVIF` (`sockaddr_dl.sdl_index`), `IPV6_PKTINFO` | `IP_RECVIF`, `IPV6_PKTINFO` |
| Destination address (RFC 6762 §11 and the QU window) | `IP_PKTINFO` (`ipi_addr`), `IPV6_PKTINFO` (`ipi6_addr`); decoded on 104/104 datagrams in the M0 spike | `IP_PKTINFO`, `IPV6_PKTINFO`; 100 % in the M2 runs | `IP_RECVDSTADDR`, `IPV6_PKTINFO` (unverified) | `IP_RECVDSTADDR`, `IPV6_PKTINFO` (unverified) |
| Datagram without a destination cmsg (option silently ineffective, `MSG_CTRUNC`) | `Service` counts it in `RxCounters.no_dst` and hands it to the Engine with `dst_known = false`: the §11 on-link check still runs as for a unicast destination, the QU-window drop (`dropped_unicast_unexpected`) does not, and `Engine.stats().rx_dst_unknown` counts it. Without this every multicast response on such a socket would be dropped and a browse would die with nothing but counters to show for it. | same | same | same |
| `std.posix.IP` under dev.1786 | `void`: hard-code, no cross-check | present: comptime assert against `std.os.linux.IP`/`IPV6`/`SO`/`SOL`/`IFF` (`socket_opts.zig`, `comptime` block) | present: the table reads `std.c.IP`/`IPV6`/`SO` and the same `comptime` block pins them to the plan section 9 numbers (`RECVIF 20`, `RECVTTL 65`, `RECVPKTINFO 36`, `PKTINFO 46`, `HOPLIMIT 47`, ...) | present: same, pinned to `RECVIF 30`, `RECVTTL 31`, `RECVPKTINFO 36`, `PKTINFO 46`, `HOPLIMIT 47` |
| Io backends | Threaded (gate, fds BLOCKING except inside the send window, see "Darwin send path" under "Known risks"); Dispatch on the fork (M6, needs `O_NONBLOCK`) | Threaded (gate, blocking fds); Uring on the fork (M6) | Threaded (blocking fds); Kqueue on the fork (M6) | Threaded (blocking fds); Kqueue on the fork (M6) |
| Local Network privacy | macOS 15+: GUI-launched processes may be blocked silently; Terminal, SSH and root are allowed | n/a | n/a | n/a |
| Test host | this Mac | Lima `zig-uring` (cross-built `aarch64-linux-musl`, run in M2) | Lima `kq-freebsd` (M6, best effort) | none |
| Unverified | `Clock.boot` for the wake heuristic; Evented Io construction API; whether Darwin `udp_input` can ever report a readable socket whose datagram then vanishes (not observed, see "Known risks") | glibc `ifaddrs` layout (`x86_64-linux-gnu` compiles, only musl ran); `IP_RECVTTL`/`IPV6_HOPLIMIT` cmsg values (delivered, not printed by `mdns-live`); the bad-checksum spurious-readiness behaviour of `udp_poll` on a blocking vs `O_NONBLOCK` fd (read from net/ipv4/udp.c, not exercised) | every constant on hardware (every header cited in the tables above is on disk in the pinned toolchain and matches the code; nothing was run) | every constant on hardware (headers on disk and matching the code; nothing was run) |

## macOS spike results (M0)

This section records what the three spike programs printed on this Mac. It
was filled by the M0 Integrate step on 2026-09-15 from re-runs of every
spike (the numbers from the first run by the socket-layer agent are quoted
where they add a second sample). Nothing here is copied from the plan.

Host: macOS 27.0 (build 26A428), Apple silicon (`arm64`). mDNSResponder
was running (`pgrep -x mDNSResponder`), and `lsof -nP -iUDP:5353` showed
two further user processes (a browser and an editor service) also holding
UDP `*:5353`, so the port was shared by at least three other sockets
during every run. The spikes were launched from a shell under Claude Code
(not a GUI app bundle); Local Network privacy did not block anything: LAN
traffic from 29 distinct source addresses arrived immediately.

Zig `0.17.0-dev.1786+75044cb04`, `std.Io.Threaded` backend, Debug build,
via `mise exec -- zig build spike-<name>`.

### Reuse matrix (`spikes/bind5353.zig`)

Bind `0.0.0.0:<port>` and `[::]:<port>` (the v6 socket with
`IPV6_V6ONLY = 1`, so its column measures the v6 rule and not a dual-stack
clash with the v4 holders) with each option set. `daemon=present`: port
5353 while mDNSResponder (and two other processes) hold it.
`daemon=absent`: the control port 53530, held only by our own v4 and v6
sockets bound with both reuse flags via `bindMdnsSocket`. Output lines are
`bind5353 daemon=<present|absent> port=<n> family=<v4|v6> case=<name>
result=<OK|errno>`.

| Options | present, v4 | present, v6 | absent, v4 | absent, v6 |
|---|---|---|---|---|
| none | `EADDRINUSE` | `EADDRINUSE` | `EADDRINUSE` | `EADDRINUSE` |
| `SO_REUSEADDR` only | `EADDRINUSE` | `EADDRINUSE` | `EADDRINUSE` | `EADDRINUSE` |
| `SO_REUSEPORT` only | `OK` | `OK` | `OK` | `OK` |
| both | `OK` | `OK` | `OK` | `OK` |

The `present` columns were identical on three runs before the review fixes
(two by the socket-layer agent, one by the Integrate step, without
`IPV6_V6ONLY`) and on the post-review run (with `IPV6_V6ONLY` and the
`absent` columns added). This matches the plan's expectation with no
deviations: on Darwin `SO_REUSEPORT` is the flag that permits sharing a
UDP port that another socket already holds, whether that socket belongs to
mDNSResponder or to our own process, and `SO_REUSEADDR` alone does nothing
for this case. `trialBindWithoutReuse` (bind without either flag, then
close) reported `first_binder=false` on 5353 and `first_binder=true` on
the control port 53530, so it distinguishes "a daemon is here" from "we
are alone" correctly.

### Unicast owner (`spikes/bind5353.zig`)

Setup: one (then two) of our sockets bound `0.0.0.0:5353` with both reuse
options via `bindMdnsSocket`; an ephemeral IPv4 sender sends one standard
mDNS query (`_services._dns-sd._udp.local PTR`, QU bit clear) to
`127.0.0.1:5353`; the spike polls our sockets for 200 ms with
zero-duration `receiveManyTimeout` and then checks whether the SENDER
received a unicast reply (a reply means the daemon got the query).

| Trial | Our sockets bound | Received by ours | Sender got a unicast reply |
|---|---|---|---|
| 1 | 1 | none | yes |
| 2 | 2 (older + newer) | none | yes |
| 3 | 1 (newer closed again) | none | yes |

Same result on all three runs. On 5353 every unicast datagram went to
mDNSResponder, which answered it; none of our sockets ever saw it, whether
we had one or two sockets bound or had just closed the newer one.

Control run on port 53530 (nobody else holds it; two of our own sockets
bound with both reuse options; three unicast sends):
`control_owner port=53530 sockets=2 receivers=ours_older,ours_older,ours_older`
on every run. So the Darwin rule for a `SO_REUSEPORT`-shared UDP port is:
**a unicast datagram is delivered to the OLDEST binder only** (never both,
never the newest). Combined with the 5353 result this means mDNSResponder,
which binds at boot, receives every unicast datagram addressed to
`*:5353` on this machine, and our socket receives none of them.

mDNSResponder kept working throughout: `dns-sd -B` and `dns-sd -R` sessions
that ran alongside the join spike kept receiving browse results and the
`-R` registration reported `Name now registered and active`.

Not measured: IPv6 unicast owner (Parts 2 and 3 of the spike are IPv4
only); whether the rule is "oldest" or "lowest fd"/"first in a hash
bucket" was not separated further, but the control run's newer socket
never received anything across 3 trials per run and 3 runs.

### pktinfo decode (`spikes/join_pktinfo.zig`)

Integrate re-run: `zig build spike-join_pktinfo -- --seconds 4` while
`/usr/bin/dns-sd -B _services._dns-sd._udp` ran in the background (killed
afterwards; `pgrep -x dns-sd` empty). Socket-layer agent's run: 6 s with
`dns-sd -B _services._dns-sd._udp` and
`dns-sd -R m0demo _mdnszig._udp . 4433 k=v` (127 packets, fixture run 1).
Post-review run: 10 s on BLOCKING fds (the new `nonblocking = false`
default) with `dns-sd -R`, `-B` and `-L m0demo _mdnszig._udp`, `-R`
killed 3 s before the end: 104 packets (57 v4, 47 v6), ifindex non-zero in
104/104, `v6_scope_matches_pktinfo` 47/47, `dst_multicast` 104/104,
`ctrunc` 0, `oversize` 0, errors 0, 22 memberships, no interface skipped
for `if_nametoindex` returning 0 (fixture run 2, `raw/0128`-`0231`,
including 16 goodbye records).

- Bind: `0.0.0.0:5353` OK, `[::]:5353` OK, both `first_binder=false`.
- Interfaces joined (22 memberships, 0 failures): v4 on `lo0` (1,
  127.0.0.1), `en0` (15, 192.168.1.75), `utun4` (23, 100.122.9.92),
  `bridge100` (25, 192.168.139.3), `bridge101` (27, 192.168.215.0); v6
  link-local on `lo0` (1, `::1`), `en0` (15), `awdl0` (16), `llw0` (17),
  `utun0`-`utun3` (18-21), `utun4` (23), `bridge100` (25), `bridge101`
  (27), `utun5`-`utun10` (28-33). Joining on loopback and on every `utun`
  succeeded; `IP_ADD_MEMBERSHIP` used `ip_mreq` with the interface's v4
  address, `IPV6_JOIN_GROUP` used `ipv6_mreq` with the ifindex.
- v4 packets received: 28 (4 s run) / 71 (6 s run); with `ipi_ifindex != 0`:
  28/28 and 71/71. The decoded destination was a multicast address
  (`224.0.0.0/4`, i.e. `224.0.0.251`) in all of them (`dst_mcast=true` on
  every line).
- v6 packets received: 21 (4 s) / 56 (6 s); `ipi6_ifindex != 0` in 21/21
  and 56/56; the `scope_id` on the source address equalled `ipi6_ifindex`
  in 21/21 and 56/56 (`v6_scope_matches_pktinfo` == `v6`). Destination was
  `ff00::/8` (i.e. `ff02::fb`) in all of them.
- Arrival interfaces seen in the 4 s run: ifindex 15 (`en0`) 37 packets,
  1 (`lo0`) 4, 25 (`bridge100`) 4, 27 (`bridge101`) 4. Every family/ifindex
  pair matched a joined interface.
- cmsg walk: `control_len=40` on every v4 packet and `control_len=48` on
  every v6 packet, `ctrunc=false` throughout. With a 12-byte `cmsghdr`
  (`socklen_t len`) and 4-byte alignment: v4 = `CMSG_SPACE(12)` for
  `in_pktinfo` (24) + `CMSG_SPACE(1)` for the TTL byte (16) = 40;
  v6 = `CMSG_SPACE(20)` for `in6_pktinfo` (32) + `CMSG_SPACE(4)` for the
  hop-limit int (16) = 48. With 8-byte alignment v4 would have been 48, so
  `__DARWIN_ALIGN32` (4-byte) cmsg alignment is **confirmed** by the
  kernel-filled lengths, not just by the headers.
- Option numbers confirmed live: `IP_PKTINFO`/`IP_RECVPKTINFO` = 26
  delivers a cmsg of type 26; `IPV6_RECVPKTINFO` = 61 makes the kernel
  deliver `IPV6_PKTINFO` = 46 (the RFC 3542 number, not the RFC 2292 alias
  19); `IP_RECVTTL` = 24 delivers a 1-byte cmsg of type 24;
  `IPV6_RECVHOPLIMIT` = 37 delivers a 4-byte `IPV6_HOPLIMIT` = 47.
- `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` values seen (4 s run): 255 on 41
  packets, 128 on 4 (two Windows hosts), 1 on 4 (the router,
  192.168.1.1 / `fe80::dab3:70ff:fe3e:bd48`). mDNS senders use 255; the
  router's TTL 1 packets are still valid mDNS on the link.
- Zero packets seen? No. Local Network permission was not an issue for a
  process launched from a shell.
- Threaded detail observed: `Io.Threaded` passes `message.control.ptr`
  straight into `msghdr.msg_control` and overwrites `message.control` with
  the filled slice, so the spike re-points each message's control slice
  before every `receiveManyTimeout` call.

### Zero-timeout timings (`spikes/zero_timeout.zig`, Threaded only)

Raw UDP sockets bound to `0.0.0.0:0`, wrapped as `Io.net.Socket`; times
are `Clock.awake` deltas around one call. The battery runs twice: on
`O_NONBLOCK` fds (what the fork's Dispatch backend needs in M6) and on
plain blocking fds (the `BindOptions.nonblocking = false` default under
Threaded, see "Known risks"). Check (e) reads the flag back with
`fcntl(F_GETFL)` so the `setNonBlocking` path is exercised, not assumed.
Measured across four runs before the review fixes (`O_NONBLOCK` only;
three by the socket-layer agent, one by the Integrate step) and one
post-review run in both modes.

| Call | Expected | Measured, `O_NONBLOCK` fd | Measured, blocking fd |
|---|---|---|---|
| `fcntl(F_GETFL) & O_NONBLOCK` (check e) | matches what was requested | `true` on rx and tx | `false` on rx and tx |
| `receiveManyTimeout` with `duration = 0` on an idle fd | returns `error.Timeout` immediately | `error.Timeout`, 0 messages, in 24 / 39 / 68 / 76 / 92 us (5 runs) | `error.Timeout`, 0 messages, in 29 us |
| `receiveManyTimeout` with `duration = 50 ms`, idle fd | returns `error.Timeout` in < 100 ms | `error.Timeout`, 0 messages, in 50 015 / 50 036 / 50 042 / 50 048 / 50 034 us | `error.Timeout`, 0 messages, in 49 293 us |
| `sendManyTimeout` with `duration = 1 ms`, one 27-byte datagram to `127.0.0.1` | 1 sent, no error | 1 sent (`sent_len=27`), no error, in 68 / 186 / 268 / 396 / 186 us | 1 sent, no error, in 139 us |
| `receiveManyTimeout` with `duration = 0`, one datagram already queued | returns the datagram immediately | 1 message, payload matched, in 27 / 28 / 45 / 29 us | 1 message, payload matched, in 30 us |
| `sendManyTimeout` with `duration = 1 ms`, full send buffer | `error.Timeout`, no panic | not exercised (no full-buffer case in the spike) | not exercised |
| untimed receive (`Timeout.none`) on an `O_NONBLOCK` fd | **never call**: `operate` maps `WouldBlock => unreachable` (`STD/Io/Threaded.zig:2550-2557`) | not run on purpose | not run on purpose (would block forever instead of trapping) |

Conclusions: on `std.Io.Threaded` a zero-duration timeout is a true
non-blocking drain (tens of microseconds, no sleep) **whether or not the
fd carries `O_NONBLOCK`**, because the first attempt passes `MSG_DONTWAIT`
per call (`Threaded.zig:13188`, `:2833`) and the wait is a `poll(2)` with
the timeout, and a 50 ms timeout is met within about 1 ms either way. The
`Timeout.none` path is the one that would hit `unreachable` on `EAGAIN`
(`Threaded.zig:2555` receive, `:2573` send; `EAGAIN => WouldBlock` at
`:13237`); the timed path polls first (`:2829-2840` receive, `:2850-2867`
send) and returns `error.Timeout` at `:2924-2932`.

Two caveats from reading `Threaded.zig`. First, after `poll()` reports
readable, `batchAwait` completes the operation with the same `operate`
(`:2942`), which performs one blocking-flag `recvmsg` on
`message_buffer[0]` only, so a timed receive that had to wait returns at
most one message (N messages only when N were already queued before the
call). Second, that post-poll `operate` is the untimed path with
`WouldBlock => unreachable`: a socket that `poll` reports readable but
whose `recvmsg` then returns `EAGAIN` traps. This was not observed on
Darwin and is the reason `O_NONBLOCK` is now off under Threaded; the full
analysis and the decision are in "Known risks" below.

One Darwin detail found while writing the spike: a datagram sent to
`0.0.0.0:<port>` is NOT delivered to a local socket bound on the wildcard;
the first version of check (d) failed for that reason and the spike now
sends to `127.0.0.1` explicitly.

### Known risks and decisions for M2 (`service.zig`)

**Post-poll `unreachable` in Threaded.** The plan's "Timed calls only"
rule (section 4.3) says the timed paths "poll on WouldBlock and are
safe". M0 verified the first half and found the second incomplete: after
`poll(2)` reports the fd readable or writable, `Threaded.batchAwait`
completes the operation through `operate` (`STD/Io/Threaded.zig:2942`),
i.e. `netReceivePosix(..., nonblocking = false)` / `netSendPosix(...,
false)` without `MSG_DONTWAIT`, and both map `error.WouldBlock =>
unreachable` (`:2555` receive, `:2573` send). So a readiness report that
is not followed by a readable datagram turns into a Debug/ReleaseSafe
panic, on a path fed by network bytes, which `SECURITY.md` classifies as
a security bug.

Linux has exactly such a case for UDP (select(2) BUGS): a datagram whose
checksum turns out bad is only verified at `recvmsg` time when no socket
filter is attached; `udp_recvmsg` drops it and returns `-EAGAIN` on a
non-blocking socket. `udp_poll` (net/ipv4/udp.c) strips this false
positive with `first_packet_length(sk)`, but only when the fd is
BLOCKING: `if ((mask & EPOLLRDNORM) && !(file->f_flags & O_NONBLOCK) &&
... first_packet_length(sk) == -1) mask &= ~(EPOLLIN | EPOLLRDNORM)`. So
with `O_NONBLOCK` on a shared 5353 socket, one malformed LAN datagram
would abort the process; with a blocking fd the kernel drops it before
`poll` returns and `recvmsg` never sees `EAGAIN`.

**Decision (taken with the review fixes): `BindOptions.nonblocking`
defaults to `false`, and `Service` leaves it false under Threaded.**
Threaded does not need `O_NONBLOCK` for the zero-duration drain (it uses
`MSG_DONTWAIT` per call; verified by the blocking-fd battery above), only
the fork's Dispatch backend does (plan section 4.3, M6). The Darwin
spikes (`bind5353`, `join_pktinfo`, the run 2 fixture capture) all ran on
blocking fds after the change with identical results. The residual
exposure is therefore: (1) Darwin, if `udp_input` could ever report a
readable socket whose datagram then vanishes (not observed; xnu
`udp_input` verifies the UDP checksum before enqueueing to a socket, so
the Linux case should not exist there **(unverified)**: from memory of
bsd/netinet/udp_usrreq.c, not from a file opened for this document), and (2) M6's Dispatch backend, which needs `O_NONBLOCK`
and must revisit this before it is enabled: attach an accept-all classic
BPF via `SO_ATTACH_FILTER` on Linux at bind time (a non-null `sk_filter`
forces `udp_lib_checksum_complete` at enqueue in
`udp_queue_rcv_one_skb`, so `poll` never lies), or patch the fork's
backend to map a post-poll `WouldBlock` to a retry / `error.Timeout`
instead of `unreachable`, and file the std issue upstream. An M2 live
test that injects a bad-checksum UDP datagram (raw socket in Lima) and
asserts no trap is the acceptance test for whichever option lands.

`README.md` and `CHANGELOG.md` carry the same bullet under "Known risks".

**Darwin send path: `MSG_DONTWAIT` does not bound a datagram send
(M3 gate hang, fixed).** `zig build live -- --seconds 3` with the default
interface set (17 interfaces incl. `utun*`, `bridge*`, `awdl0`, `llw0`)
once sat forever inside the first `sendmsg` of a query round while
`dns-sd -R` ran; every subset of interfaces worked. Root cause, from
xnu (apple-oss-distributions main, `bsd/kern/uipc_socket.c`
`sosendcheck`): when `sbspace(&so->so_snd) < resid` a datagram send
returns `EWOULDBLOCK` only for `SS_NBIO` (the fd's `O_NONBLOCK`) or the
kernel-private `MSG_NBIO` (0x20000, `sys/socket_private.h`); userland
`MSG_DONTWAIT` (0x80) is consulted only by `SBLOCKWAIT` and by the
receive paths, so a blocking-fd send goes to `sbwait`. `sbspace`
(`uipc_socket2.c`) subtracts the bytes a content filter still holds for a
verdict (`cfil_sock_data_space`, `net.cfil`), and this Mac runs three
NetworkExtension filters (Little Snitch, Tailscale, Clawpatrol;
`systemextensionsctl list`, `sysctl net.cfil.active_count` = 1). A fresh
multicast flow per (interface, family) is a new verdict each, and one the
filter never answers (a dead `utun`, an "ask" rule nobody clicks) is a
send that never returns. `Io.Threaded`'s timed send tries
`MSG_DONTWAIT` first and only polls afterwards (`Threaded.zig:2853`,
`:12970`), so its 2 ms timeout cannot fire when that first call sleeps;
neither hypothesis (a) v6 on an addressless interface, (b) `SO_SNDBUF`
exhaustion nor (c) `lo0` v6 reproduced it (about 80 default-set runs
plus per-interface probes with a full `utun0` output queue, every send
under 1.2 ms).

Fix (`socket_opts.send_window_needs_nonblock`, `service.zig`
`openSendWindow` / `closeSendWindow`): on Darwin the Service sets
`O_NONBLOCK` on both sockets for the duration of one send batch and
clears it before the next receive (single thread, `defer`-guarded, also
around a lone `sendDatagram`). A short buffer is then `EWOULDBLOCK` ->
`poll(POLLOUT)` bounded by `send_timeout_us` -> `error.Timeout` -> a
counted drop (`stats().tx_dropped`, `txCounters().timeouts`). To keep the
post-poll `operate` send (Threaded.zig:2573, `WouldBlock => unreachable`)
from ever seeing `EWOULDBLOCK`, `bindMdnsSocket` raises `SO_SNDLOWAT` to
`SO_SNDBUF` (`raise_send_lowat`): `POLLOUT` (`sowriteable`: `sbspace >=
sb_lowat`) then means the whole buffer is free, so any datagram that
passed the `EMSGSIZE` check (`resid <= sb_hiwat`) fits, and nothing else
sends on the socket between the poll and the send. The receive path is
unchanged: the fd is blocking again before every receive, so the Linux
`udp_poll` argument above still holds. Linux honours `MSG_DONTWAIT` for
the send-buffer wait (`sock_sndtimeo(sk, flags & MSG_DONTWAIT)`), FreeBSD
(`sosend_generic`) and OpenBSD (`sosend`) too, so the window is a
comptime no-op there and the fds stay blocking throughout.
`txCounters()` reports `timeouts`, `slow` (sends over `send_timeout_us`
of wall time, which the timed call did not bound) and `max_us`;
`mdns-live` prints them on its `tx` line. Tests: `send window sets
O_NONBLOCK only while sending`, `send window flag toggles O_NONBLOCK and
restores it`, `bound mDNS socket has its send low-water mark raised to
the send buffer`, `egress skips a joined pair whose interface has no
address of that family`. A kernel-level block cannot be staged from a
unit test (UDP `sb_cc` stays 0 without a filter); the live default-set
run beside `dns-sd -R` completed in 3.3 s, 3 of 3 runs, `tx timeouts=0
slow=0 max_us<=332`. The window is opened lazily by the first datagram
of a batch (`txCounters().window_opened` counts the batches), so an idle
step costs no `fcntl`.

One send errno class is not a counted drop: `Io.Threaded` maps
`EINVAL`, `EOPNOTSUPP`, `EDESTADDRREQ`, `EISCONN`, `EFAULT`, `ENOTSOCK`
and `EBADF` from `sendmsg` to `errnoBug` (Threaded.zig:13083-13089),
which panics in Debug builds and is `error.Unexpected` (a counted drop)
in ReleaseSafe. xnu answers an `IP_PKTINFO` / `IPV6_PKTINFO` control
message naming an unusable interface with `ENXIO` / `EADDRNOTAVAIL`
(`ip_output` / `ip6_output` via `in6_selectsrc`), never `EINVAL`, and
the Engine only builds a datagram for a joined pair whose interface has
an address of that family (`joinedPairs`, and `pollDatagram` re-checks
the pair when it drains, so a job queued before an interface left the
table is a counted `tx_dropped` rather than a send). That filter is the
guard; there is no assert on the send path.

**Coarse errno typing on group membership (fixed).** `setsockoptChecked`
now maps `EADDRINUSE` -> `error.AddressInUse`, `EADDRNOTAVAIL` ->
`error.AddressUnavailable` and `ENODEV`/`ENXIO` -> `error.NoInterface`;
`joinGroup` turns `EADDRINUSE` into `error.AlreadyMember` and
`leaveGroup` turns `EADDRNOTAVAIL` into `error.NotMember`, so `Service`
can treat a re-join after an interface flap as success instead of
receiving `error.Unexpected` (plus a Debug stack dump from
`posix.unexpectedErrno`). Out-of-range interface indexes (>= 2^31) are
`error.InvalidInterface`, never an `@intCast` trap.

**`ifaddrs.ifa_addr` alignment.** `struct sockaddr *` from `getifaddrs`
is only guaranteed 1-byte aligned by the type; `@alignCast` to
`sockaddr_in`/`sockaddr_in6` would be a runtime check on libc data. The
spike reads through `*align(1)` pointers and `platform/ifaces.zig` (M2)
must do the same.

### Coexistence rules derived for `Service`

- Reuse options to set on macOS: `SO_REUSEPORT` is required and
  sufficient. `Service` sets both `SO_REUSEADDR` and `SO_REUSEPORT` (the
  plan's cross-platform rule) because Linux needs `SO_REUSEADDR` for
  cross-uid sharing with avahi; on Darwin the extra flag is harmless
  (both = OK in the matrix).
- Unicast replies reaching our socket: **assume they do not.** While
  mDNSResponder is running, every unicast datagram to `*:5353` goes to
  its socket (oldest binder wins), so a legacy/unicast-response peer's
  answer to our query will not arrive on our socket. `Service` must not
  depend on unicast delivery for correctness: QU questions are still
  useful because RFC 6762 responders that see a QU question also
  multicast their answer periodically, and all normal answers are
  multicast to `224.0.0.251` / `ff02::fb`, which the shared socket does
  receive (127/127 fixture datagrams were multicast). If `first_binder`
  is true (no daemon), unicast would reach us, but nothing relies on it.
- v4 arrival interface on Darwin: `IP_PKTINFO` (26, alias
  `IP_RECVPKTINFO`) is used, not `IP_RECVIF`, because it exists on Darwin,
  it decodes the ifindex for 100% of packets, and it gives the destination
  address in the same cmsg so multicast-vs-unicast classification needs
  no second option. `IP_RECVIF` (20) + `IP_RECVDSTADDR` (7) remain in the
  table for FreeBSD/OpenBSD, where `IP_PKTINFO` is absent.
- v6 arrival interface: `IPV6_RECVPKTINFO` (61) -> `IPV6_PKTINFO` (46) is
  used; the from-address `scope_id` agreed with it on every packet, so
  either could serve, but pktinfo also gives the destination address.
- Multicast joins: `ip_mreq` with the interface's v4 address works on
  every interface that has one, including loopback and `utun`. Note that
  Darwin `netinet/in.h:515` DOES declare `struct ip_mreqn`
  (`imr_multiaddr, imr_address, imr_ifindex`), contrary to the M0 task
  brief's "Darwin has no ip_mreqn"; the code keeps `has_ip_mreqn = false` on Darwin and joins
  by address per the plan. An ifindex-only join (via `ip_mreqn` or
  `IP_MULTICAST_IFINDEX` = 66) is available if M2 needs it for interfaces
  without a v4 address.
- Differences from the plan's Section 9 macOS row: none in behaviour. Two
  additions: (1) `struct ip_mreqn` exists on Darwin (above); (2) other
  user-space processes (a browser, an editor helper) also hold `*:5353`
  with `SO_REUSEPORT`, so "the daemon holds the port" is really "several
  processes hold the port", which changes nothing for us because the
  oldest binder (mDNSResponder) still owns unicast delivery.

## Linux runs (M2)

Filled on 2026-09-16 from runs of the cross-built binaries inside the Lima
VM `zig-uring`. Nothing here is copied from the plan.

Host: Lima VM `zig-uring`, Fedora Linux 44 (Cloud Edition), kernel
`6.19.10-300.fc44.aarch64`, glibc 2.43 on the system; the binaries are
`-Dtarget=aarch64-linux-musl` (static musl, `file`: "ELF 64-bit LSB
executable, ARM aarch64, statically linked"), Debug, built on the Mac with
`0.17.0-dev.1786+75044cb04` and executed through the `/Users` mount at
the same absolute path. `avahi-daemon` runs as `uid=70(avahi)` and
`systemd-resolved` runs as root with mDNS on; `sudo ss -ulnp | grep 5353`
shows both holding `0.0.0.0:5353` and `[::]:5353`. Interfaces: `lo`
(index 1, flags `0x9`, 127.0.0.1/8 and `::1`) and `eth0` (index 2, flags
`0x1003`, one v4 /24 and one link-local v6). `avahi-publish -s m2demo
_mdnszig._udp 5001 k=v` and `avahi-browse -a -r` ran in the VM during the
timed runs to provoke traffic (`avahi-browse` listed `m2demo` on `eth0`
IPv4, `eth0` IPv6 and `lo` IPv4, so avahi itself is active on `lo` for
v4 only).

### Unit and public-API tests (`just lima-test`)

`zig build test-exe -Dtarget=aarch64-linux-musl` installs
`zig-out/test/mdns-unit-tests` and `zig-out/test/mdns-api-tests`; both
ran in the VM:

```
All 89 tests passed.        # mdns-unit-tests (src/root.zig), exit 0
All 22 tests passed.        # mdns-api-tests (tests/root.zig), exit 0
4 fuzz tests found.
```

The API run includes the real-socket tests (`Service.init binds 5353
beside the OS daemon`, `mode C serve delivers events into a Mailbox and
ends on close`, ...) beside avahi and systemd-resolved, and the
conformance and fixture tests that read `docs/` and `tests/fixtures/`
through the absolute `build_options.repo_root`. The first run failed
`Service.init binds 5353 beside the OS daemon` on `tx_dropped == 0` with
`tx_dropped = 1`: see "Loopback v6" below for the cause and the fix.

### `mdns-live` with avahi and systemd-resolved running

`zig build live -Dtarget=aarch64-linux-musl`, then
`limactl shell zig-uring -- .../zig-out/bin/mdns-live --seconds 4` (the
`just lima-live` recipe):

```
mdns-live os=linux seconds=4 ipv6=true include_loopback=true allow_len=0
bind result=OK first_binder=false sockets=2
socket local=0.0.0.0:5353
socket local=[::]:5353
iface index=1 name=lo v4_addrs=1 v6_addrs=0 joined_v4=true joined_v6=false v4_dropped=0 v6_dropped=0
iface index=2 name=eth0 v4_addrs=1 v6_addrs=1 joined_v4=true joined_v6=true v4_dropped=0 v6_dropped=0
event kind=interfaces_changed
stats rx=15 tx=6 tx_dropped=0 dropped_malformed=0 dropped_bad_port=0 events_dropped=0 addrs_dropped=0
rx v4=10 v4_with_ifindex=10 v6=5 v6_with_ifindex=5 tolerated_errors=0 steps=72 step_errors=0
RESULT bind=OK first_binder=false joined_v4=2 joined_v6=1 rx_v4_ifindex=10 rx_v6_ifindex=5 tx=6
```

- Bind: both sockets on `*:5353` as an unprivileged user with
  `SO_REUSEADDR` + `SO_REUSEPORT`, beside a root-owned and a uid-`avahi`
  holder; `first_binder=false` (the trial bind without reuse flags fails
  with `EADDRINUSE`).
- Joins: `IP_ADD_MEMBERSHIP` with `ip_mreqn` (ifindex) on `lo` and
  `eth0`; `IPV6_ADD_MEMBERSHIP` with `ipv6_mreq` on `eth0`. No
  `join_failed` warning in any run.
- pktinfo decode: `IP_PKTINFO` (8) gave a non-zero `ipi_ifindex` on 10/10
  v4 datagrams and `IPV6_PKTINFO` (50, enabled by `IPV6_RECVPKTINFO` 49)
  on 5/5 v6 datagrams, through the `@sizeOf(usize)`-aligned cmsg walker.
  Across all M2 runs in the VM every received datagram carried an ifindex
  (`rx_v4_ifindex == v4` and `rx_v6_ifindex == v6` on every line).
- The stub PTR query went out on every joined (interface, family) pair
  every 2 s (`tx=6` = 3 pairs x 2 rounds); `tx_dropped=0`.

### `first_binder` with the daemons stopped

```
=== A: stop avahi-daemon only
avahi=inactive resolved=active
UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("systemd-resolve",pid=2074,fd=16))
UNCONN 0 0    [::]:5353    [::]:* users:(("systemd-resolve",pid=2074,fd=17))
bind result=OK first_binder=false sockets=2
RESULT bind=OK first_binder=false joined_v4=2 joined_v6=1 rx_v4_ifindex=4 rx_v6_ifindex=2 tx=6
=== B: stop systemd-resolved too
avahi=inactive resolved=inactive
0                                   # ss -ulnp | grep -c 5353
bind result=OK first_binder=true sockets=2
stats rx=6 tx=6 tx_dropped=0 dropped_malformed=0 dropped_bad_port=0 events_dropped=0 addrs_dropped=0
RESULT bind=OK first_binder=true joined_v4=2 joined_v6=1 rx_v4_ifindex=4 rx_v6_ifindex=2 tx=6
=== restore
avahi=active resolved=active        # 4 sockets on 5353 again
```

The plan's acceptance line stops `avahi-daemon` alone and expects
`first_binder=true`; on this Fedora image that is not enough because
`systemd-resolved` also holds `*:5353`. With both stopped the trial bind
succeeds and `firstBinder()` is `true`; with either running it is
`false`. Both services were restarted afterwards and are active. In case
B the counts match our own multicast echoes (loop on): 2 rounds x (`lo`
v4 + `eth0` v4 + `eth0` v6) = `tx=6` and `rx v4=4 v6=2`, so the joined
groups deliver with no daemon present.

### `IP_MULTICAST_ALL` and `IPV6_MULTICAST_ALL`

Allow-list runs while `avahi-publish` and `avahi-browse -a -r` kept
`eth0` busy:

```
=== lo only (--ifindex 1), before IPV6_MULTICAST_ALL=0
RESULT bind=OK first_binder=false joined_v4=1 joined_v6=0 rx_v4_ifindex=9 rx_v6_ifindex=6 tx=3
=== lo only (--ifindex 1), with IPV6_MULTICAST_ALL=0
RESULT bind=OK first_binder=false joined_v4=1 joined_v6=0 rx_v4_ifindex=9 rx_v6_ifindex=0 tx=2
=== eth0 only (--ifindex 2)
RESULT bind=OK first_binder=false joined_v4=1 joined_v6=1 rx_v4_ifindex=6 rx_v6_ifindex=6 tx=4
=== --no-ipv6 --no-loopback (one socket)
bind result=OK first_binder=false sockets=1
RESULT bind=OK first_binder=false joined_v4=1 joined_v6=0 rx_v4_ifindex=1 rx_v6_ifindex=0 tx=1
```

With only `lo` allowed the v6 socket joined nothing, yet the first run
received 6 `ff02::fb` datagrams (avahi's traffic on `eth0`, delivered
because the host is a member there): Linux applies the "receive every
group any socket joined" default to v6 as well, through
`IPV6_MULTICAST_ALL` (29, kernel 4.20+), which `std.os.linux.IPV6` does
not name. `bindMdnsSocket` now sets it to 0 on Linux next to
`IP_MULTICAST_ALL` (49); the re-run received 0 v6 datagrams, and the
`eth0` run still received all 6. For v4 the `lo`-only counts cannot
separate `lo` from `eth0` traffic (avahi is on `lo` too), so a Python
side-by-side settled it: two wildcard `*:5353` sockets with both reuse
flags and no joins, 4 s under the same load, `IP_MULTICAST_ALL=0` received
0 datagrams and the default socket received 4.

### Loopback v6

`lo` reports flags `0x9` (`UP|LOOPBACK`) without `IFF_MULTICAST`.
`IPV6_ADD_MEMBERSHIP` for `ff02::fb` on `lo` succeeds, but every send to
`[ff02::fb]:5353` through `lo` fails: `sendmsg` with `IPV6_PKTINFO`
ifindex 1 or `sin6_scope_id = 1` returns `ENETUNREACH` (Python check in
the VM; `eth0` succeeds either way). In the first `mdns-live` run this
showed up as `tx_dropped=2` per 4 s with `include_loopback` on, and as the
failed `tx_dropped == 0` assertion in the API test. v4 multicast to
`224.0.0.251` through `lo` works. `ifaces.zig` therefore keeps a loopback
interface that lacks `IFF_MULTICAST` for v4 only (`v6_addrs=0` for `lo`
above); Darwin `lo0` carries `IFF_MULTICAST` and keeps both families.

### Cross-compile checks

`zig build -Dtarget=aarch64-freebsd`, `-Dtarget=aarch64-openbsd` and
`-Dtarget=x86_64-linux-gnu` each produced `zig-out/bin/mdns-live` for
that target (`file`: FreeBSD 14.0 dynamic, OpenBSD PIE, x86-64 glibc);
`zig build test-exe` for the same three targets produced both test
binaries. None of these ran. On this pin `zig build test -Dtarget=...`
compiles the tests and then fails only with "host system is unable to
execute binaries from the target".

## macOS runs (M2)

2026-09-16, from a shell under Claude Code (no GUI bundle), with
`/usr/bin/dns-sd -B _services._dns-sd._udp` running in the background
(killed afterwards; `pgrep -x dns-sd` empty). mDNSResponder held 5353.
Local Network privacy did not block anything.

```
=== mise exec -- zig build live -- --seconds 3
bind result=OK first_binder=false sockets=2
iface index=1 name=lo0 v4_addrs=1 v6_addrs=2 joined_v4=true joined_v6=true ...
iface index=15 name=en0 v4_addrs=1 v6_addrs=2 joined_v4=true joined_v6=true ...
... 17 interfaces in total (awdl0, llw0, utun0-utun10, bridge100, bridge101 v6-only or both)
stats rx=96 tx=44 tx_dropped=0 dropped_malformed=0 dropped_bad_port=0 events_dropped=0 addrs_dropped=0
rx v4=31 v4_with_ifindex=31 v6=65 v6_with_ifindex=65 tolerated_errors=0 steps=46 step_errors=0
RESULT bind=OK first_binder=false joined_v4=5 joined_v6=17 rx_v4_ifindex=31 rx_v6_ifindex=65 tx=44
=== mise exec -- zig build live -- --seconds 3 --ifindex 15   (en0)
iface index=15 name=en0 v4_addrs=1 v6_addrs=2 joined_v4=true joined_v6=true v4_dropped=0 v6_dropped=0
stats rx=56 tx=4 tx_dropped=0 dropped_malformed=0 dropped_bad_port=0 events_dropped=0 addrs_dropped=0
rx v4=34 v4_with_ifindex=34 v6=22 v6_with_ifindex=22 tolerated_errors=0 steps=44 step_errors=0
RESULT bind=OK first_binder=false joined_v4=1 joined_v6=1 rx_v4_ifindex=34 rx_v6_ifindex=22 tx=4
```

No `join_failed` or `addrs_truncated` warning in either run; the `en0`
run joined exactly one ifindex per family. The v6 side of the full run
also joined the `utun` interfaces (link-local only, no v4), as in M0.
