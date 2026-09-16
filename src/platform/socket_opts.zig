//! Raw socket plumbing for mDNS: per-OS option numbers, a checked
//! `setsockopt`, multicast membership structs, the cmsg (ancillary data)
//! codec, and `bindMdnsSocket`, which opens a shared UDP socket on *:5353
//! and hands it back as a `std.Io.net.Socket`.
//!
//! Every libc call goes through `std.c` and maps errno by hand. Nothing in
//! this file uses `std.posix.setsockopt` (its EINVAL is `unreachable`,
//! STD/posix.zig) and no errno path reaches `unreachable` or `@panic`.
//!
//! Option numbers (plan section 9). Darwin has no `std.posix.IP`/`IPV6` on
//! dev.1786 (both are `void`, STD/c.zig:6608-6629 `else => void`) and
//! `std.c.darwin` is not public, so the Darwin column is hard-coded from
//! the macOS SDK headers with the header line cited beside each value.
//! The Linux, FreeBSD and OpenBSD columns are hard-coded too, so that every
//! table is a value on every host (tests decode foreign layouts), and each
//! is cross-checked at comptime against `std.os.linux.IP/IPV6/SO` (on every
//! host: those are plain declarations) and against `std.c.IP/IPV6/SO/SOL`
//! when compiled for FreeBSD or OpenBSD. The BSD rows are reviewed against
//! STD/c/freebsd.zig and STD/c/openbsd.zig, not run.
const std = @import("std");
const builtin = @import("builtin");
const native_os = builtin.os.tag;
const native_endian = builtin.cpu.arch.endian();
const net = std.Io.net;
const posix = std.posix;
const c = std.c;
const linux = std.os.linux;

pub const is_darwin = native_os.isDarwin();

/// Address family of one mDNS socket.
pub const Family = enum(u8) {
    v4,
    v6,

    pub fn fromIp(f: net.IpAddress.Family) Family {
        return switch (f) {
            .ip4 => .v4,
            .ip6 => .v6,
        };
    }
};

/// RFC 6762 section 3: the mDNS multicast groups.
pub const group_v4: [4]u8 = .{ 224, 0, 0, 251 };
pub const group_v6: [16]u8 = .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb };

/// Default mDNS port (RFC 6762 section 2).
pub const mdns_port: u16 = 5353;

// ---------------------------------------------------------------------------
// Per-OS constant table
// ---------------------------------------------------------------------------

/// One row of the platform matrix (plan section 9). `?u32` entries are
/// options the OS does not have.
pub const Consts = struct {
    sol_socket: u32,
    so_reuseaddr: u32,
    so_reuseport: u32,

    ipproto_ip: u32,
    ipproto_ipv6: u32,

    ip_ttl: u32,
    ip_multicast_if: u32,
    ip_multicast_ttl: u32,
    ip_multicast_loop: u32,
    ip_add_membership: u32,
    ip_drop_membership: u32,
    /// Enable option for arrival-interface delivery (IP_PKTINFO or
    /// IP_RECVPKTINFO). `null` when the OS only has IP_RECVIF.
    ip_recvpktinfo: ?u32,
    /// cmsg type that carries `in_pktinfo`. `null` when the OS has none.
    ip_pktinfo: ?u32,
    /// BSD: bool option and cmsg type carrying a `sockaddr_dl`.
    ip_recvif: ?u32,
    /// BSD: bool option and cmsg type carrying the destination `in_addr`.
    ip_recvdstaddr: ?u32,
    /// bool option that enables the received TTL cmsg.
    ip_recvttl: u32,
    /// cmsg type that carries the received TTL (IP_TTL on Linux,
    /// IP_RECVTTL on the BSDs and Darwin).
    ip_ttl_cmsg: u32,
    /// Linux only: set 0 so the socket sees only groups it joined.
    ip_multicast_all: ?u32,
    /// Darwin only: IP_MULTICAST_IFINDEX takes an int ifindex.
    ip_multicast_ifindex: ?u32,
    /// IP_MULTICAST_TTL / IP_MULTICAST_LOOP take `u_char` on the BSDs and
    /// Darwin, `int` on Linux.
    ip_u8_options: bool,
    /// IP_ADD_MEMBERSHIP and IP_MULTICAST_IF accept `ip_mreqn` (ifindex)
    /// instead of `ip_mreq` / `in_addr`.
    has_ip_mreqn: bool,

    ipv6_unicast_hops: u32,
    ipv6_multicast_if: u32,
    ipv6_multicast_hops: u32,
    ipv6_multicast_loop: u32,
    ipv6_join_group: u32,
    ipv6_leave_group: u32,
    ipv6_v6only: u32,
    ipv6_recvpktinfo: u32,
    ipv6_pktinfo: u32,
    ipv6_recvhoplimit: u32,
    ipv6_hoplimit: u32,
    /// Linux only: the v6 twin of `ip_multicast_all` (IPV6_MULTICAST_ALL,
    /// linux/in6.h, kernel 4.20+; absent from `std.os.linux.IPV6`). Set 0
    /// so the socket sees only the groups it joined; older kernels answer
    /// ENOPROTOOPT, which the bind path tolerates.
    ipv6_multicast_all: ?u32,

    iff_up: u32,
    iff_multicast: u32,
    iff_loopback: u32,

    /// `CMSG_ALIGN` unit and `cmsg_len` field width.
    cmsg: CmsgLayout,

    /// True when the OS has no IP_PKTINFO send-side cmsg, so v4 egress is
    /// selected with `setMulticastIf` before every send (FreeBSD, OpenBSD).
    pub fn needsPerSendMulticastIf(t: Consts) bool {
        return t.ip_pktinfo == null;
    }
};

/// macOS SDK, MacOSX.sdk/usr/include. Every number cites its header line.
pub const darwin_consts: Consts = .{
    .sol_socket = 0xffff, // sys/socket.h:356 SOL_SOCKET
    .so_reuseaddr = 0x0004, // sys/socket.h:124 SO_REUSEADDR
    .so_reuseport = 0x0200, // sys/socket.h:137 SO_REUSEPORT

    .ipproto_ip = 0, // netinet/in.h:97 IPPROTO_IP
    .ipproto_ipv6 = 41, // netinet/in.h:147 IPPROTO_IPV6

    .ip_ttl = 4, // netinet/in.h:408 IP_TTL
    .ip_multicast_if = 9, // netinet/in.h:413 IP_MULTICAST_IF
    .ip_multicast_ttl = 10, // netinet/in.h:414 IP_MULTICAST_TTL (u_char)
    .ip_multicast_loop = 11, // netinet/in.h:415 IP_MULTICAST_LOOP (u_char)
    .ip_add_membership = 12, // netinet/in.h:416 IP_ADD_MEMBERSHIP
    .ip_drop_membership = 13, // netinet/in.h:417 IP_DROP_MEMBERSHIP
    .ip_recvpktinfo = 26, // netinet/in.h:434 IP_RECVPKTINFO == IP_PKTINFO
    .ip_pktinfo = 26, // netinet/in.h:433 IP_PKTINFO
    .ip_recvif = 20, // netinet/in.h:424 IP_RECVIF
    .ip_recvdstaddr = 7, // netinet/in.h:411 IP_RECVDSTADDR
    .ip_recvttl = 24, // netinet/in.h:431 IP_RECVTTL
    .ip_ttl_cmsg = 24, // xnu ip_input.c ip_savecontrol: sbcreatecontrol(..., IP_RECVTTL, IPPROTO_IP)
    .ip_multicast_all = null,
    .ip_multicast_ifindex = 66, // netinet/in.h:460 IP_MULTICAST_IFINDEX
    .ip_u8_options = true,
    // netinet/in.h:515 declares `struct ip_mreqn`, but this file follows
    // the plan and joins with `ip_mreq` (interface = the v4 address).
    .has_ip_mreqn = false,

    .ipv6_unicast_hops = 4, // netinet6/in6.h:383 IPV6_UNICAST_HOPS
    .ipv6_multicast_if = 9, // netinet6/in6.h:384 IPV6_MULTICAST_IF
    .ipv6_multicast_hops = 10, // netinet6/in6.h:385 IPV6_MULTICAST_HOPS
    .ipv6_multicast_loop = 11, // netinet6/in6.h:386 IPV6_MULTICAST_LOOP
    .ipv6_join_group = 12, // netinet6/in6.h:387 IPV6_JOIN_GROUP
    .ipv6_leave_group = 13, // netinet6/in6.h:388 IPV6_LEAVE_GROUP
    .ipv6_v6only = 27, // netinet6/in6.h:415 IPV6_V6ONLY
    .ipv6_recvpktinfo = 61, // netinet6/in6.h:457 IPV6_RECVPKTINFO (RFC 3542 block)
    .ipv6_pktinfo = 46, // netinet6/in6.h:478 IPV6_3542PKTINFO == IPV6_PKTINFO (in6.h:485) under __APPLE_USE_RFC_3542
    .ipv6_recvhoplimit = 37, // netinet6/in6.h:459 IPV6_RECVHOPLIMIT
    .ipv6_hoplimit = 47, // netinet6/in6.h:479 IPV6_3542HOPLIMIT == IPV6_HOPLIMIT (in6.h:486) under __APPLE_USE_RFC_3542
    .ipv6_multicast_all = null,

    .iff_up = 0x1, // net/if.h:93 IFF_UP
    .iff_multicast = 0x8000, // net/if.h:109 IFF_MULTICAST
    .iff_loopback = 0x8, // net/if.h:96 IFF_LOOPBACK

    // sys/socket.h:673 CMSG_SPACE uses __DARWIN_ALIGN32 (arm/_param.h:21),
    // and cmsg_len is socklen_t (sys/socket.h:609).
    .cmsg = .{ .alignment = 4, .len_size = 4 },
};

/// Linux. Numbers cite STD/os/linux.zig; the comptime block below asserts
/// every one of them against `std.os.linux` on every host. SOL_SOCKET and
/// SO_* differ on mips/ppc/sparc/alpha, so those three come from std
/// directly (arch-selected at comptime, STD/os/linux.zig:4895, 5257).
pub const linux_consts: Consts = .{
    .sol_socket = linux.SOL.SOCKET, // 1 on the mainstream ABI
    .so_reuseaddr = linux.SO.REUSEADDR, // 2
    .so_reuseport = linux.SO.REUSEPORT, // 15

    .ipproto_ip = 0, // STD/os/linux.zig:8025 IPPROTO.IP
    .ipproto_ipv6 = 41, // IPPROTO.IPV6

    .ip_ttl = 2, // STD/os/linux.zig:5297 IP.TTL
    .ip_multicast_if = 32, // :5323 IP.MULTICAST_IF
    .ip_multicast_ttl = 33, // :5324 IP.MULTICAST_TTL (int)
    .ip_multicast_loop = 34, // :5325 IP.MULTICAST_LOOP (int)
    .ip_add_membership = 35, // :5326 IP.ADD_MEMBERSHIP
    .ip_drop_membership = 36, // :5327 IP.DROP_MEMBERSHIP
    .ip_recvpktinfo = 8, // :5303 IP.PKTINFO (enable and cmsg type)
    .ip_pktinfo = 8,
    .ip_recvif = null,
    .ip_recvdstaddr = null,
    .ip_recvttl = 12, // :5308 IP.RECVTTL (enable)
    .ip_ttl_cmsg = 2, // ip_cmsg_recv_ttl puts IP_TTL with an int payload
    .ip_multicast_all = 49, // :5333 IP.MULTICAST_ALL
    .ip_multicast_ifindex = null,
    .ip_u8_options = false,
    .has_ip_mreqn = true,

    .ipv6_unicast_hops = 16, // STD/os/linux.zig:5364 IPV6.UNICAST_HOPS
    .ipv6_multicast_if = 17, // :5365 IPV6.MULTICAST_IF
    .ipv6_multicast_hops = 18, // :5366 IPV6.MULTICAST_HOPS
    .ipv6_multicast_loop = 19, // :5367 IPV6.MULTICAST_LOOP
    .ipv6_join_group = 20, // :5368 IPV6.ADD_MEMBERSHIP (Linux name for JOIN_GROUP)
    .ipv6_leave_group = 21, // :5369 IPV6.DROP_MEMBERSHIP
    .ipv6_v6only = 26, // :5374 IPV6.V6ONLY
    .ipv6_recvpktinfo = 49, // :5394 IPV6.RECVPKTINFO
    .ipv6_pktinfo = 50, // :5395 IPV6.PKTINFO
    .ipv6_recvhoplimit = 51, // :5396 IPV6.RECVHOPLIMIT
    .ipv6_hoplimit = 52, // :5397 IPV6.HOPLIMIT
    .ipv6_multicast_all = 29, // IPV6_MULTICAST_ALL: generic-musl/netinet/in.h:341, generic-glibc/bits/in.h:189 (not in std); measured in the zig-uring VM, M2

    .iff_up = 0x1, // STD/os/linux.zig:8963 IFF.UP (bit 0)
    // `std.os.linux.IFF` stops at bit 8; IFF_MULTICAST is bit 12 in
    // linux/if.h. Hard-coded (Revision 3 item 5).
    .iff_multicast = 0x1000,
    .iff_loopback = 0x8, // IFF.LOOPBACK (bit 3)

    // Kernel `cmsghdr.cmsg_len` is `__kernel_size_t` (STD/os/linux.zig:10913
    // `len: usize`) and CMSG_ALIGN is sizeof(size_t). musl's userland
    // header splits that into `socklen_t` + `int` padding
    // (STD/c.zig:4268 `posix_cmsghdr`), which is byte-identical to the
    // kernel view for any cmsg_len < 2^32, so the kernel view is used.
    .cmsg = .{ .alignment = @sizeOf(usize), .len_size = @sizeOf(usize) },
};

/// FreeBSD. Numbers cite STD/c/freebsd.zig (asserted against `std.c` when
/// compiled for FreeBSD). Reviewed, not run.
pub const freebsd_consts: Consts = .{
    .sol_socket = 0xffff, // STD/c.zig:6645 SOL.SOCKET
    .so_reuseaddr = 0x0004, // STD/c.zig:6696 SO.REUSEADDR
    .so_reuseport = 0x0200, // STD/c.zig:6704 SO.REUSEPORT (REUSEPORT_LB 0x10000 not used)

    .ipproto_ip = 0, // STD/c.zig:6257 IPPROTO.IP
    .ipproto_ipv6 = 41, // STD/c.zig:6279 IPPROTO.IPV6

    .ip_ttl = 4, // STD/c/freebsd.zig:403 IP.TTL
    .ip_multicast_if = 9, // :409 IP.MULTICAST_IF
    .ip_multicast_ttl = 10, // :410 IP.MULTICAST_TTL (u_char; int also accepted)
    .ip_multicast_loop = 11, // :411 IP.MULTICAST_LOOP (u_char; int also accepted)
    .ip_add_membership = 12, // :412 IP.ADD_MEMBERSHIP
    .ip_drop_membership = 13, // :413 IP.DROP_MEMBERSHIP
    .ip_recvpktinfo = null, // FreeBSD has no IP_PKTINFO (netinet/in.h)
    .ip_pktinfo = null,
    .ip_recvif = 20, // :420 IP.RECVIF (cmsg payload: struct sockaddr_dl)
    .ip_recvdstaddr = 7, // :406 IP.RECVDSTADDR (cmsg payload: struct in_addr)
    .ip_recvttl = 65, // :447 IP.RECVTTL
    .ip_ttl_cmsg = 65, // ip_input.c ip_savecontrol: sbcreatecontrol(&ttl, sizeof(u_char), IP_RECVTTL, IPPROTO_IP)
    .ip_multicast_all = null,
    .ip_multicast_ifindex = null,
    .ip_u8_options = true,
    // FreeBSD accepts `ip_mreqn` for IP_MULTICAST_IF (inp_set_multicast_if)
    // but the plan's join struct is `ip_mreq`; keep the portable form.
    .has_ip_mreqn = false,

    .ipv6_unicast_hops = 4, // STD/c/freebsd.zig:476 IPV6.UNICAST_HOPS
    .ipv6_multicast_if = 9, // :477 IPV6.MULTICAST_IF
    .ipv6_multicast_hops = 10, // :478 IPV6.MULTICAST_HOPS
    .ipv6_multicast_loop = 11, // :479 IPV6.MULTICAST_LOOP
    .ipv6_join_group = 12, // :480 IPV6.JOIN_GROUP
    .ipv6_leave_group = 13, // :481 IPV6.LEAVE_GROUP
    .ipv6_v6only = 27, // :491 IPV6.V6ONLY
    .ipv6_recvpktinfo = 36, // :500 IPV6.RECVPKTINFO
    .ipv6_pktinfo = 46, // :510 IPV6.PKTINFO
    .ipv6_recvhoplimit = 37, // :501 IPV6.RECVHOPLIMIT
    .ipv6_hoplimit = 47, // :511 IPV6.HOPLIMIT
    .ipv6_multicast_all = null,

    .iff_up = 0x1, // net/if.h IFF_UP
    .iff_multicast = 0x8000, // net/if.h IFF_MULTICAST
    .iff_loopback = 0x8, // net/if.h IFF_LOOPBACK

    // sys/socket.h: cmsg_len is socklen_t; _ALIGN pads to the register size
    // (STD/c.zig:4237 cmsghdr, freebsd sys/socket.h:492).
    .cmsg = .{ .alignment = @sizeOf(usize), .len_size = 4 },
};

/// OpenBSD. Numbers cite STD/c/openbsd.zig (asserted against `std.c` when
/// compiled for OpenBSD). Reviewed, not run.
pub const openbsd_consts: Consts = .{
    .sol_socket = 0xffff, // STD/c.zig:6645 SOL.SOCKET
    .so_reuseaddr = 0x0004, // STD/c.zig SO.REUSEADDR (openbsd branch)
    .so_reuseport = 0x0200, // STD/c.zig SO.REUSEPORT (openbsd branch)

    .ipproto_ip = 0, // STD/c.zig IPPROTO.IP
    .ipproto_ipv6 = 41, // STD/c.zig IPPROTO.IPV6

    .ip_ttl = 4, // STD/c/openbsd.zig:316 IP.TTL
    .ip_multicast_if = 9, // :321 IP.MULTICAST_IF
    .ip_multicast_ttl = 10, // :322 IP.MULTICAST_TTL (u_char only)
    .ip_multicast_loop = 11, // :323 IP.MULTICAST_LOOP (u_char only)
    .ip_add_membership = 12, // :324 IP.ADD_MEMBERSHIP
    .ip_drop_membership = 13, // :325 IP.DROP_MEMBERSHIP
    .ip_recvpktinfo = null, // OpenBSD has no IP_PKTINFO (netinet/in.h)
    .ip_pktinfo = null,
    .ip_recvif = 30, // :337 IP.RECVIF (cmsg payload: struct sockaddr_dl)
    .ip_recvdstaddr = 7, // :319 IP.RECVDSTADDR (cmsg payload: struct in_addr)
    .ip_recvttl = 31, // :338 IP.RECVTTL
    .ip_ttl_cmsg = 31, // ip_input.c ip_savecontrol: sbcreatecontrol(&ip->ip_ttl, sizeof(ip->ip_ttl), IP_RECVTTL, IPPROTO_IP)
    .ip_multicast_all = null,
    .ip_multicast_ifindex = null,
    .ip_u8_options = true,
    // The plan lists "ip_mreqn or ip_mreq"; `ip_mreq` is the form every
    // OpenBSD release accepts, so use it.
    .has_ip_mreqn = false,

    .ipv6_unicast_hops = 4, // STD/c/openbsd.zig:358 IPV6.UNICAST_HOPS
    .ipv6_multicast_if = 9, // :359 IPV6.MULTICAST_IF
    .ipv6_multicast_hops = 10, // :360 IPV6.MULTICAST_HOPS
    .ipv6_multicast_loop = 11, // :361 IPV6.MULTICAST_LOOP
    .ipv6_join_group = 12, // :362 IPV6.JOIN_GROUP
    .ipv6_leave_group = 13, // :363 IPV6.LEAVE_GROUP
    .ipv6_v6only = 27, // :366 IPV6.V6ONLY
    .ipv6_recvpktinfo = 36, // :368 IPV6.RECVPKTINFO
    .ipv6_pktinfo = 46, // :376 IPV6.PKTINFO
    .ipv6_recvhoplimit = 37, // :369 IPV6.RECVHOPLIMIT
    .ipv6_hoplimit = 47, // :377 IPV6.HOPLIMIT
    .ipv6_multicast_all = null,

    .iff_up = 0x1, // net/if.h IFF_UP
    .iff_multicast = 0x8000, // net/if.h IFF_MULTICAST
    .iff_loopback = 0x8, // net/if.h IFF_LOOPBACK

    // sys/socket.h:527: cmsg_len is socklen_t; _ALIGN pads to sizeof(long).
    .cmsg = .{ .alignment = @sizeOf(usize), .len_size = 4 },
};

comptime {
    // Linux: every hard-coded number above against std.os.linux. These
    // tables are plain declarations, so the check runs on every host.
    {
        const L = linux;
        const t = linux_consts;
        std.debug.assert(t.ipproto_ip == L.IPPROTO.IP);
        std.debug.assert(t.ipproto_ipv6 == L.IPPROTO.IPV6);
        std.debug.assert(t.ip_ttl == L.IP.TTL);
        std.debug.assert(t.ip_multicast_if == L.IP.MULTICAST_IF);
        std.debug.assert(t.ip_multicast_ttl == L.IP.MULTICAST_TTL);
        std.debug.assert(t.ip_multicast_loop == L.IP.MULTICAST_LOOP);
        std.debug.assert(t.ip_add_membership == L.IP.ADD_MEMBERSHIP);
        std.debug.assert(t.ip_drop_membership == L.IP.DROP_MEMBERSHIP);
        std.debug.assert(t.ip_recvpktinfo.? == L.IP.PKTINFO);
        std.debug.assert(t.ip_pktinfo.? == L.IP.PKTINFO);
        std.debug.assert(t.ip_recvttl == L.IP.RECVTTL);
        std.debug.assert(t.ip_ttl_cmsg == L.IP.TTL);
        std.debug.assert(t.ip_multicast_all.? == L.IP.MULTICAST_ALL);
        std.debug.assert(t.ipv6_unicast_hops == L.IPV6.UNICAST_HOPS);
        std.debug.assert(t.ipv6_multicast_if == L.IPV6.MULTICAST_IF);
        std.debug.assert(t.ipv6_multicast_hops == L.IPV6.MULTICAST_HOPS);
        std.debug.assert(t.ipv6_multicast_loop == L.IPV6.MULTICAST_LOOP);
        // Linux names these ADD/DROP_MEMBERSHIP, not JOIN/LEAVE_GROUP.
        std.debug.assert(t.ipv6_join_group == L.IPV6.ADD_MEMBERSHIP);
        std.debug.assert(t.ipv6_leave_group == L.IPV6.DROP_MEMBERSHIP);
        std.debug.assert(t.ipv6_v6only == L.IPV6.V6ONLY);
        std.debug.assert(t.ipv6_recvpktinfo == L.IPV6.RECVPKTINFO);
        std.debug.assert(t.ipv6_pktinfo == L.IPV6.PKTINFO);
        std.debug.assert(t.ipv6_recvhoplimit == L.IPV6.RECVHOPLIMIT);
        std.debug.assert(t.ipv6_hoplimit == L.IPV6.HOPLIMIT);
        std.debug.assert(t.iff_up == @as(u16, @bitCast(L.IFF{ .UP = true })));
        std.debug.assert(t.iff_loopback == @as(u16, @bitCast(L.IFF{ .LOOPBACK = true })));
        std.debug.assert(@sizeOf(L.in_pktinfo) == @sizeOf(in_pktinfo));
        std.debug.assert(@sizeOf(L.in6_pktinfo) == @sizeOf(in6_pktinfo));
        std.debug.assert(@sizeOf(L.cmsghdr) == @sizeOf(usize) + 8);
    }
    if (native_os == .linux) {
        // Plan section 9 Linux column, mainstream ABI only (SO_* and
        // SOL_SOCKET differ on mips/ppc/sparc/alpha).
        switch (builtin.cpu.arch) {
            .x86_64, .aarch64, .x86, .arm, .riscv64 => {
                std.debug.assert(linux_consts.sol_socket == 1);
                std.debug.assert(linux_consts.so_reuseaddr == 2);
                std.debug.assert(linux_consts.so_reuseport == 15);
            },
            else => {},
        }
        std.debug.assert(@sizeOf(c.cmsghdr) == linux_consts.cmsg.headerSize());
    }
    // FreeBSD and OpenBSD: `std.c.IP/IPV6/SO/SOL` are non-void on those
    // targets (STD/c.zig:6608-6629, 6641-6710); assert the table against
    // them when compiled for that OS.
    if (native_os == .freebsd or native_os == .openbsd) {
        const t = if (native_os == .freebsd) freebsd_consts else openbsd_consts;
        std.debug.assert(t.sol_socket == c.SOL.SOCKET);
        std.debug.assert(t.so_reuseaddr == c.SO.REUSEADDR);
        std.debug.assert(t.so_reuseport == c.SO.REUSEPORT);
        std.debug.assert(t.ipproto_ip == c.IPPROTO.IP);
        std.debug.assert(t.ipproto_ipv6 == c.IPPROTO.IPV6);
        std.debug.assert(t.ip_ttl == c.IP.TTL);
        std.debug.assert(t.ip_multicast_if == c.IP.MULTICAST_IF);
        std.debug.assert(t.ip_multicast_ttl == c.IP.MULTICAST_TTL);
        std.debug.assert(t.ip_multicast_loop == c.IP.MULTICAST_LOOP);
        std.debug.assert(t.ip_add_membership == c.IP.ADD_MEMBERSHIP);
        std.debug.assert(t.ip_drop_membership == c.IP.DROP_MEMBERSHIP);
        std.debug.assert(t.ip_recvif.? == c.IP.RECVIF);
        std.debug.assert(t.ip_recvdstaddr.? == c.IP.RECVDSTADDR);
        std.debug.assert(t.ip_recvttl == c.IP.RECVTTL);
        std.debug.assert(t.ip_ttl_cmsg == c.IP.RECVTTL);
        std.debug.assert(!@hasDecl(c.IP, "PKTINFO"));
        std.debug.assert(t.ipv6_unicast_hops == c.IPV6.UNICAST_HOPS);
        std.debug.assert(t.ipv6_multicast_if == c.IPV6.MULTICAST_IF);
        std.debug.assert(t.ipv6_multicast_hops == c.IPV6.MULTICAST_HOPS);
        std.debug.assert(t.ipv6_multicast_loop == c.IPV6.MULTICAST_LOOP);
        std.debug.assert(t.ipv6_join_group == c.IPV6.JOIN_GROUP);
        std.debug.assert(t.ipv6_leave_group == c.IPV6.LEAVE_GROUP);
        std.debug.assert(t.ipv6_v6only == c.IPV6.V6ONLY);
        std.debug.assert(t.ipv6_recvpktinfo == c.IPV6.RECVPKTINFO);
        std.debug.assert(t.ipv6_pktinfo == c.IPV6.PKTINFO);
        std.debug.assert(t.ipv6_recvhoplimit == c.IPV6.RECVHOPLIMIT);
        std.debug.assert(t.ipv6_hoplimit == c.IPV6.HOPLIMIT);
        std.debug.assert(@sizeOf(c.in6_pktinfo) == @sizeOf(in6_pktinfo));
        std.debug.assert(@sizeOf(c.cmsghdr) == 12);
    }
    if (is_darwin) {
        std.debug.assert(darwin_consts.sol_socket == c.SOL.SOCKET);
        std.debug.assert(darwin_consts.so_reuseaddr == c.SO.REUSEADDR);
        std.debug.assert(darwin_consts.so_reuseport == c.SO.REUSEPORT);
        std.debug.assert(darwin_consts.ipproto_ipv6 == c.IPPROTO.IPV6);
        std.debug.assert(@sizeOf(c.in_pktinfo) == @sizeOf(in_pktinfo));
        std.debug.assert(@sizeOf(c.in6_pktinfo) == @sizeOf(in6_pktinfo));
        std.debug.assert(@sizeOf(c.cmsghdr) == 12);
    }
}

/// The table for the target OS.
pub const consts: Consts = switch (native_os) {
    .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => darwin_consts,
    .linux => linux_consts,
    .freebsd => freebsd_consts,
    .openbsd => openbsd_consts,
    else => @compileError("mdns-zig platform/socket_opts.zig: unsupported OS " ++ @tagName(native_os)),
};

/// True on this target when v4 multicast egress must be selected with
/// `setMulticastIf` before each send because there is no IP_PKTINFO cmsg
/// (FreeBSD, OpenBSD). False on Darwin and Linux, where `encodePktInfo4`
/// picks the interface per datagram.
pub inline fn needsPerSendMulticastIf() bool {
    return comptime consts.needsPerSendMulticastIf();
}

// ---------------------------------------------------------------------------
// Membership structs (STD/c.zig has no ip_mreq/ipv6_mreq)
// ---------------------------------------------------------------------------

/// `struct ip_mreq` (netinet/in.h:505 on Darwin; identical everywhere).
pub const ip_mreq = extern struct {
    /// Group address, network byte order.
    multiaddr: [4]u8,
    /// Local address of the interface, network byte order.
    interface: [4]u8,
};

/// `struct ip_mreqn` (Linux linux/in.h; Darwin netinet/in.h:515).
pub const ip_mreqn = extern struct {
    multiaddr: [4]u8,
    address: [4]u8,
    ifindex: i32,
};

/// `struct ipv6_mreq` (netinet6/in6.h:538 on Darwin; identical everywhere).
pub const ipv6_mreq = extern struct {
    multiaddr: [16]u8,
    interface: u32,
};

/// `struct in_pktinfo` as it appears in the cmsg payload. Same layout on
/// Darwin (netinet/in.h:616) and Linux (linux/in.h).
pub const in_pktinfo = extern struct {
    ifindex: u32,
    spec_dst: [4]u8,
    addr: [4]u8,
};

/// `struct in6_pktinfo` (netinet6/in6.h:546 on Darwin; RFC 3542).
pub const in6_pktinfo = extern struct {
    addr: [16]u8,
    ifindex: u32,
};

/// Leading fields of `struct sockaddr_dl` (net/if_dl.h on Darwin, FreeBSD
/// and OpenBSD): the IP_RECVIF cmsg payload. Only `index` is read.
pub const sockaddr_dl_head = extern struct {
    len: u8,
    family: u8,
    index: u16,
};

comptime {
    std.debug.assert(@sizeOf(ip_mreq) == 8);
    std.debug.assert(@sizeOf(ip_mreqn) == 12);
    std.debug.assert(@sizeOf(ipv6_mreq) == 20);
    std.debug.assert(@sizeOf(in_pktinfo) == 12);
    std.debug.assert(@sizeOf(in6_pktinfo) == 20);
    std.debug.assert(@sizeOf(sockaddr_dl_head) == 4);
    std.debug.assert(@offsetOf(sockaddr_dl_head, "index") == 2);
}

// ---------------------------------------------------------------------------
// cmsg codec
// ---------------------------------------------------------------------------

/// Layout parameters of `struct cmsghdr` and its padding rule.
pub const CmsgLayout = struct {
    /// `CMSG_ALIGN` unit: 4 on Darwin (`__DARWIN_ALIGN32`), the register
    /// size elsewhere.
    alignment: usize,
    /// Width of `cmsg_len`: 4 (`socklen_t`) on the BSDs and Darwin, 8
    /// (`__kernel_size_t`) on 64-bit Linux.
    len_size: usize,

    /// `sizeof(struct cmsghdr)`: cmsg_len + int level + int type.
    pub fn headerSize(l: CmsgLayout) usize {
        return l.len_size + 8;
    }

    pub fn alignUp(l: CmsgLayout, n: usize) usize {
        return (n + l.alignment - 1) & ~(l.alignment - 1);
    }

    /// `CMSG_DATA` offset from the header start.
    pub fn dataOffset(l: CmsgLayout) usize {
        return l.alignUp(l.headerSize());
    }

    /// `CMSG_LEN(payload)`.
    pub fn len(l: CmsgLayout, payload: usize) usize {
        return l.dataOffset() + payload;
    }

    /// `CMSG_SPACE(payload)`.
    pub fn space(l: CmsgLayout, payload: usize) usize {
        return l.dataOffset() + l.alignUp(payload);
    }
};

/// One decoded ancillary entry. `data` points into the control buffer.
pub const Cmsg = struct {
    level: i32,
    type: i32,
    data: []const u8,
};

/// `CMSG_FIRSTHDR` / `CMSG_NXTHDR` walk. A malformed entry (short header,
/// `cmsg_len` shorter than a header, or an entry that overruns the buffer)
/// ends the walk. It never errors and never panics.
pub const CmsgIterator = struct {
    layout: CmsgLayout,
    control: []const u8,
    pos: usize = 0,

    pub fn init(layout: CmsgLayout, control: []const u8) CmsgIterator {
        return .{ .layout = layout, .control = control };
    }

    pub fn next(it: *CmsgIterator) ?Cmsg {
        const l = it.layout;
        const hdr = l.headerSize();
        const rem = it.control[@min(it.pos, it.control.len)..];
        if (rem.len < hdr) return null;
        const cmsg_len: usize = switch (l.len_size) {
            4 => std.mem.readInt(u32, rem[0..4], native_endian),
            8 => std.math.cast(usize, std.mem.readInt(u64, rem[0..8], native_endian)) orelse return null,
            else => return null,
        };
        if (cmsg_len < hdr or cmsg_len > rem.len) return null;
        const level = std.mem.readInt(i32, rem[l.len_size..][0..4], native_endian);
        const typ = std.mem.readInt(i32, rem[l.len_size + 4 ..][0..4], native_endian);
        const data_off = l.dataOffset();
        const data: []const u8 = if (cmsg_len >= data_off) rem[data_off..cmsg_len] else rem[0..0];
        const advance = l.alignUp(cmsg_len);
        it.pos += @max(advance, hdr);
        return .{ .level = level, .type = typ, .data = data };
    }
};

/// Builds a control buffer for `sendmsg`. Padding bytes are zeroed.
pub const CmsgEncoder = struct {
    layout: CmsgLayout,
    buf: []u8,
    len: usize = 0,

    pub fn init(layout: CmsgLayout, buf: []u8) CmsgEncoder {
        return .{ .layout = layout, .buf = buf };
    }

    pub fn append(e: *CmsgEncoder, level: i32, typ: i32, payload: []const u8) error{NoSpace}!void {
        const l = e.layout;
        const need = l.space(payload.len);
        if (e.buf.len - e.len < need) return error.NoSpace;
        const entry = e.buf[e.len..][0..need];
        @memset(entry, 0);
        const cmsg_len = l.len(payload.len);
        switch (l.len_size) {
            4 => std.mem.writeInt(u32, entry[0..4], @intCast(cmsg_len), native_endian),
            8 => std.mem.writeInt(u64, entry[0..8], cmsg_len, native_endian),
            else => return error.NoSpace,
        }
        std.mem.writeInt(i32, entry[l.len_size..][0..4], level, native_endian);
        std.mem.writeInt(i32, entry[l.len_size + 4 ..][0..4], typ, native_endian);
        @memcpy(entry[l.dataOffset()..][0..payload.len], payload);
        e.len += need;
    }

    pub fn bytes(e: *const CmsgEncoder) []u8 {
        return e.buf[0..e.len];
    }
};

/// Destination address as seen in the IP header.
pub const Dst = union(Family) {
    v4: [4]u8,
    v6: [16]u8,

    pub fn isMulticast(d: Dst) bool {
        return switch (d) {
            .v4 => |a| (a[0] & 0xf0) == 0xe0,
            .v6 => |a| a[0] == 0xff,
        };
    }
};

/// What the receive path learns from the control buffer.
pub const RxInfo = struct {
    /// Arrival interface. 0 when no pktinfo/recvif cmsg was present.
    ifindex: u32 = 0,
    dst: ?Dst = null,
    /// IPv4 TTL or IPv6 hop limit.
    ttl: ?u8 = null,

    pub fn dstMulticast(i: RxInfo) bool {
        return if (i.dst) |d| d.isMulticast() else false;
    }
};

/// The `Engine.RxMeta` shaped view of a control buffer (plan section 4.2):
/// arrival interface, TTL / hop limit, and whether the destination was a
/// multicast group. `dst_multicast` is `null` when no destination cmsg was
/// present (the on-link check then treats the packet as unicast).
pub const ControlMeta = struct {
    /// Arrival interface. 0 when no pktinfo/recvif cmsg was present.
    ifindex: u32 = 0,
    /// IPv4 TTL or IPv6 hop limit, when the OS delivered it.
    ttl: ?u8 = null,
    /// `true` when `in_pktinfo.ipi_addr` / `in6_pktinfo.ipi6_addr` (or
    /// IP_RECVDSTADDR) is a multicast address.
    dst_multicast: ?bool = null,
};

/// Decode IP_PKTINFO / IPV6_PKTINFO / IP_RECVIF / IP_RECVDSTADDR and the
/// TTL / hop-limit cmsgs from a control buffer filled by `recvmsg`, using
/// the native layout and constant table. Both levels are decoded.
pub fn decodeRxInfo(control: []const u8) RxInfo {
    return decodeRxInfoFor(consts, null, control);
}

/// `decodeRxInfo` with an explicit table (tests exercise foreign layouts).
pub fn decodeRxInfoWith(table: Consts, control: []const u8) RxInfo {
    return decodeRxInfoFor(table, null, control);
}

/// `decodeRxInfo` restricted to the cmsg level of `family` (`null` decodes
/// both). Malformed or foreign entries are skipped; nothing here can fail.
pub fn decodeRxInfoFor(table: Consts, family: ?Family, control: []const u8) RxInfo {
    var info: RxInfo = .{};
    const want4 = family == null or family.? == .v4;
    const want6 = family == null or family.? == .v6;
    var it: CmsgIterator = .init(table.cmsg, control);
    while (it.next()) |m| {
        if (m.level < 0) continue;
        const level: u32 = @intCast(m.level);
        if (m.type < 0) continue;
        const typ: u32 = @intCast(m.type);
        if (want4 and level == table.ipproto_ip) {
            if (table.ip_pktinfo != null and typ == table.ip_pktinfo.? and m.data.len >= @sizeOf(in_pktinfo)) {
                const pi: *align(1) const in_pktinfo = @ptrCast(m.data.ptr);
                info.ifindex = pi.ifindex;
                info.dst = .{ .v4 = pi.addr };
            } else if (table.ip_recvif != null and typ == table.ip_recvif.? and m.data.len >= @sizeOf(sockaddr_dl_head)) {
                const dl: *align(1) const sockaddr_dl_head = @ptrCast(m.data.ptr);
                info.ifindex = dl.index;
            } else if (table.ip_recvdstaddr != null and typ == table.ip_recvdstaddr.? and m.data.len >= 4) {
                info.dst = .{ .v4 = m.data[0..4].* };
            } else if (typ == table.ip_ttl_cmsg and m.data.len >= 1) {
                // u_char on the BSDs and Darwin, int on Linux.
                info.ttl = if (m.data.len >= 4)
                    @truncate(std.mem.readInt(u32, m.data[0..4], native_endian))
                else
                    m.data[0];
            }
        } else if (want6 and level == table.ipproto_ipv6) {
            if (typ == table.ipv6_pktinfo and m.data.len >= @sizeOf(in6_pktinfo)) {
                const pi: *align(1) const in6_pktinfo = @ptrCast(m.data.ptr);
                info.ifindex = pi.ifindex;
                info.dst = .{ .v6 = pi.addr };
            } else if (typ == table.ipv6_hoplimit and m.data.len >= 4) {
                info.ttl = @truncate(std.mem.readInt(u32, m.data[0..4], native_endian));
            }
        }
    }
    return info;
}

/// Decode the control buffer of one datagram received on a socket of
/// `family` into the `RxMeta` shape `Service` hands to `Engine.handle`.
/// Uses the native table and layout. Never fails.
pub fn decodeControl(family: Family, control: []const u8) ControlMeta {
    return decodeControlWith(consts, family, control);
}

/// `decodeControl` with an explicit table (tests exercise foreign layouts).
pub fn decodeControlWith(table: Consts, family: Family, control: []const u8) ControlMeta {
    const info = decodeRxInfoFor(table, family, control);
    return .{
        .ifindex = info.ifindex,
        .ttl = info.ttl,
        .dst_multicast = if (info.dst) |d| d.isMulticast() else null,
    };
}

/// Largest `struct sockaddr_dl` an IP_RECVIF cmsg carries: FreeBSD's is
/// 8 + `sdl_data[46]` = 54 bytes (generic-freebsd/net/if_dl.h:58-67),
/// rounded up to `_ALIGN` (8) by `sbcreatecontrol`; OpenBSD's is 32
/// (generic-openbsd/net/if_dl.h:59-68). The larger bounds both.
pub const max_sockaddr_dl_len: usize = 56;

/// Control bytes per received datagram.
///
/// Darwin and Linux need one pktinfo cmsg plus one TTL / hop-limit cmsg:
/// 40 / 48 B (Darwin v4 / v6, 4-byte layout) and 56 / 64 B (Linux, 8-byte
/// layout), so 64 fits (plan section 4.5, `[8][64]u8`).
///
/// FreeBSD and OpenBSD have no `IP_PKTINFO`; `bindMdnsSocket` enables
/// `IP_RECVIF` + `IP_RECVDSTADDR` + `IP_RECVTTL` instead (the same branch
/// `usesRecvIf` names) and the v4 cmsg set is `CMSG_SPACE(4) +
/// CMSG_SPACE(1) + CMSG_SPACE(sockaddr_dl)`: with the 8-byte `_ALIGN` that
/// is 24 + 24 + 72 = 120 B on FreeBSD and 24 + 24 + 48 = 96 B on OpenBSD.
/// A 64 B buffer would be `MSG_CTRUNC` on every v4 datagram and, since
/// the kernel writes the entries in that order and `IP_RECVIF` comes
/// last, the arrival ifindex would never decode. Those targets get 128 (a
/// documented deviation from the plan's `[8][64]u8`; see
/// docs/platform-matrix.md and CHANGELOG.md).
pub const control_buffer_size: usize = if (usesRecvIf(consts)) 128 else 64;

/// True when `bindMdnsSocket` under `table` has to fall back from
/// `IP_RECVPKTINFO` to `IP_RECVIF` (+ `IP_RECVDSTADDR`) for the v4
/// arrival interface: FreeBSD and OpenBSD. Darwin also knows `IP_RECVIF`
/// but has pktinfo, so it stays on the 64 B set.
pub fn usesRecvIf(table: Consts) bool {
    return table.ip_recvpktinfo == null and table.ip_recvif != null;
}

/// The v4 cmsg bytes `bindMdnsSocket` asks the kernel for under `table`,
/// counting a full-size `sockaddr_dl` where `IP_RECVIF` is the fallback.
pub fn controlBytesNeeded4(table: Consts) usize {
    var n: usize = 0;
    if (table.ip_recvpktinfo != null) {
        n += table.cmsg.space(@sizeOf(in_pktinfo));
    } else if (table.ip_recvif != null) {
        n += table.cmsg.space(max_sockaddr_dl_len);
        if (table.ip_recvdstaddr != null) n += table.cmsg.space(4);
    }
    // TTL payload: `u_char` on the BSDs and Darwin, `int` on Linux.
    n += table.cmsg.space(if (table.ip_u8_options) 1 else 4);
    return n;
}

/// The v6 cmsg bytes under `table`: pktinfo plus hop limit.
pub fn controlBytesNeeded6(table: Consts) usize {
    return table.cmsg.space(@sizeOf(in6_pktinfo)) + table.cmsg.space(4);
}

/// Encode an IPV6_PKTINFO cmsg that selects the egress interface.
pub fn encodePktInfo6(buf: []u8, ifindex: u32) error{NoSpace}![]u8 {
    var e: CmsgEncoder = .init(consts.cmsg, buf);
    const pi: in6_pktinfo = .{ .addr = @splat(0), .ifindex = ifindex };
    try e.append(@intCast(consts.ipproto_ipv6), @intCast(consts.ipv6_pktinfo), std.mem.asBytes(&pi));
    return e.bytes();
}

/// Encode an IP_PKTINFO cmsg that selects the egress interface (and,
/// optionally, the source address). `error.OptionUnsupported` on an OS
/// without IP_PKTINFO (FreeBSD, OpenBSD: `needsPerSendMulticastIf()` is
/// true there; call `setMulticastIf` before each send instead).
pub fn encodePktInfo4(buf: []u8, ifindex: u32, spec_dst: ?[4]u8) error{ NoSpace, OptionUnsupported }![]u8 {
    const typ = consts.ip_pktinfo orelse return error.OptionUnsupported;
    var e: CmsgEncoder = .init(consts.cmsg, buf);
    const pi: in_pktinfo = .{ .ifindex = ifindex, .spec_dst = spec_dst orelse @splat(0), .addr = @splat(0) };
    try e.append(@intCast(consts.ipproto_ip), @intCast(typ), std.mem.asBytes(&pi));
    return e.bytes();
}

// ---------------------------------------------------------------------------
// setsockopt with a hand-written errno map
// ---------------------------------------------------------------------------

pub const SetsockoptError = error{
    /// EINVAL, ENOPROTOOPT, EOPNOTSUPP, EAFNOSUPPORT, EPROTONOSUPPORT: the
    /// kernel does not have (or will not accept) this option here.
    OptionUnsupported,
    PermissionDenied,
    SystemResources,
    /// EADDRINUSE: for a group join, the socket is already a member on
    /// that interface (xnu in_mcast.c, Linux ip_mc_join_group).
    AddressInUse,
    /// EADDRNOTAVAIL: for a group leave, not a member; for a join or
    /// IP_MULTICAST_IF, the interface has no such v4 address.
    AddressUnavailable,
    /// ENODEV, ENXIO: the interface index no longer exists.
    NoInterface,
} || std.Io.UnexpectedError;

pub const Handle = net.Socket.Handle;

/// `setsockopt(2)` via `std.c`, with the quic-zig errno map
/// (quic-zig socket_opts.zig `setsockoptIntChecked`). Never
/// `std.posix.setsockopt`: its EINVAL is `unreachable`.
pub fn setsockoptChecked(fd: Handle, level: u32, optname: u32, value: []const u8) SetsockoptError!void {
    const rc = c.setsockopt(fd, @intCast(level), optname, value.ptr, @intCast(value.len));
    switch (c.errno(rc)) {
        .SUCCESS => {},
        .INVAL, .NOPROTOOPT, .OPNOTSUPP, .AFNOSUPPORT, .PROTONOSUPPORT => return error.OptionUnsupported,
        .PERM, .ACCES => return error.PermissionDenied,
        .NOMEM, .NOBUFS => return error.SystemResources,
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressUnavailable,
        .NODEV, .NXIO => return error.NoInterface,
        // EBADF / ENOTSOCK mean a caller bug, but this is an errno path:
        // report, never trap.
        .BADF, .NOTSOCK, .FAULT => return error.Unexpected,
        else => |err| return posix.unexpectedErrno(err),
    }
}

/// `setsockopt` with a C `int` payload.
pub fn setsockoptInt(fd: Handle, level: u32, optname: u32, value: c_int) SetsockoptError!void {
    return setsockoptChecked(fd, level, optname, std.mem.asBytes(&value));
}

/// `setsockopt` with a `u_char` payload (Darwin/BSD IP_MULTICAST_TTL/LOOP).
pub fn setsockoptU8(fd: Handle, level: u32, optname: u32, value: u8) SetsockoptError!void {
    return setsockoptChecked(fd, level, optname, std.mem.asBytes(&value));
}

/// Set an IP-level option whose width is `u_char` on the BSDs and `int` on
/// Linux (IP_MULTICAST_TTL, IP_MULTICAST_LOOP).
pub fn setIpByteOption(fd: Handle, optname: u32, value: u8) SetsockoptError!void {
    if (consts.ip_u8_options) {
        return setsockoptU8(fd, consts.ipproto_ip, optname, value);
    } else {
        return setsockoptInt(fd, consts.ipproto_ip, optname, value);
    }
}

// ---------------------------------------------------------------------------
// Raw socket, bind, non-blocking
// ---------------------------------------------------------------------------

pub const SocketError = error{
    AddressFamilyUnsupported,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    PermissionDenied,
    ProtocolUnsupported,
} || std.Io.UnexpectedError;

/// `socket(AF_INET|AF_INET6, SOCK_DGRAM, IPPROTO_UDP)` with FD_CLOEXEC.
pub fn rawUdpSocket(family: Family) SocketError!Handle {
    const domain: c_uint = switch (family) {
        .v4 => c.AF.INET,
        .v6 => c.AF.INET6,
    };
    // SOCK_CLOEXEC in the type argument is rejected by Darwin (EPROTOTYPE):
    // use the same predicate std's backends use and fall back to fcntl.
    const sock_type: c_uint = c.SOCK.DGRAM |
        (if (std.Io.Threaded.socket_flags_unsupported) 0 else @as(c_uint, c.SOCK.CLOEXEC));
    const rc = c.socket(domain, sock_type, @intCast(c.IPPROTO.UDP));
    switch (c.errno(rc)) {
        .SUCCESS => {},
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        .AFNOSUPPORT => return error.AddressFamilyUnsupported,
        .ACCES, .PERM => return error.PermissionDenied,
        .INVAL, .PROTONOSUPPORT, .PROTOTYPE => return error.ProtocolUnsupported,
        else => |err| return posix.unexpectedErrno(err),
    }
    const fd: Handle = @intCast(rc);
    if (comptime std.Io.Threaded.socket_flags_unsupported) {
        switch (c.errno(c.fcntl(fd, c.F.SETFD, @as(c_int, c.FD_CLOEXEC)))) {
            .SUCCESS => {},
            else => |err| {
                closeFd(fd);
                return posix.unexpectedErrno(err);
            },
        }
    }
    return fd;
}

/// `close(2)`. Errors are ignored: the descriptor is gone either way.
pub fn closeFd(fd: Handle) void {
    _ = c.close(fd);
}

/// Set O_NONBLOCK through `fcntl(F_GETFL/F_SETFL)`.
pub fn setNonBlocking(fd: Handle) std.Io.UnexpectedError!void {
    return setNonBlockingFlag(fd, true);
}

/// Set or clear O_NONBLOCK through `fcntl(F_GETFL/F_SETFL)`. The
/// Service opens a "send window" with it on Darwin (`send_window_needs_nonblock`)
/// and closes it again before any receive.
pub fn setNonBlockingFlag(fd: Handle, on: bool) std.Io.UnexpectedError!void {
    const flags = c.fcntl(fd, c.F.GETFL, @as(c_int, 0));
    switch (c.errno(flags)) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }
    const nonblock = nonblockBit();
    const cur: u32 = @bitCast(flags);
    const want: u32 = if (on) cur | nonblock else cur & ~nonblock;
    if (want == cur) return;
    const new_flags: c_int = @bitCast(want);
    switch (c.errno(c.fcntl(fd, c.F.SETFL, new_flags))) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }
}

/// Whether O_NONBLOCK is set on `fd` (tests and the send window's
/// self-check).
pub fn isNonBlocking(fd: Handle) std.Io.UnexpectedError!bool {
    const flags = c.fcntl(fd, c.F.GETFL, @as(c_int, 0));
    switch (c.errno(flags)) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }
    return (@as(u32, @bitCast(flags)) & nonblockBit()) != 0;
}

fn nonblockBit() u32 {
    const Backing = @typeInfo(posix.O).@"struct".backing_integer.?;
    const bit: Backing = @bitCast(posix.O{ .NONBLOCK = true });
    return @as(u32, bit);
}

/// True where a `sendmsg(2)` on a BLOCKING fd can sleep even with
/// `MSG_DONTWAIT`, so the Service must set O_NONBLOCK on the socket for
/// the duration of each send batch (the "send window") and clear it again
/// before the next receive.
///
/// XNU (`bsd/kern/uipc_socket.c` `sosendcheck`, apple-oss-distributions
/// main): when `sbspace(&so->so_snd) < resid` the send returns
/// `EWOULDBLOCK` only for `SS_NBIO` (the fd's O_NONBLOCK) or the
/// kernel-private `MSG_NBIO` (0x20000); `MSG_DONTWAIT` (0x80) is consulted
/// only by `SBLOCKWAIT` and by the receive paths, so it does NOT keep a
/// blocking-fd datagram send out of `sbwait`. `sbspace` subtracts the
/// bytes a content filter (`net.cfil`, NetworkExtension
/// NEFilterDataProvider: Little Snitch, Tailscale, MDM agents) still holds
/// for a verdict (`cfil_sock_data_space`), so with a filter attached a UDP
/// send on a fresh (interface, group) flow can sleep in the kernel until
/// the filter answers, which for a flow the filter never decides is
/// forever. `Io.Threaded`'s timed send tries `MSG_DONTWAIT` first and only
/// polls afterwards, so its timeout cannot fire when that first call
/// sleeps (Threaded.zig:2853, :12970). Linux honours `MSG_DONTWAIT` for
/// the send-buffer wait (`sock_sndtimeo(sk, flags & MSG_DONTWAIT)`), and
/// so do FreeBSD (`sosend_generic`) and OpenBSD (`sosend`): there the
/// window is not needed and the fd stays blocking throughout.
pub const send_window_needs_nonblock = is_darwin;

/// With the send window open, `Io.Threaded` maps an `EWOULDBLOCK` from
/// the first `sendmsg` to a `poll(POLLOUT)` bounded by the send timeout,
/// then one more `sendmsg` through `operate`, whose `WouldBlock` is
/// `unreachable` (Threaded.zig:2573). `POLLOUT` means `sbspace >=
/// sb_lowat` (XNU `sowriteable`), while the send needs `sbspace >= len`,
/// so with the default `sb_lowat` (MCLBYTES = 2048) a datagram larger than
/// 2 KB could poll ready and still not fit. Raising `SO_SNDLOWAT` to
/// `SO_SNDBUF` (XNU clamps it to `sb_hiwat`) makes `POLLOUT` mean "the
/// whole buffer is free", so any datagram that passed the `EMSGSIZE`
/// check fits, and the post-poll send cannot block or fail with
/// `EWOULDBLOCK` on a single-threaded socket. `bindMdnsSocket` applies it
/// where the send window is used.
pub const raise_send_lowat = send_window_needs_nonblock;

/// Darwin `sys/socket.h:155` SO_SNDBUF and `:157` SO_SNDLOWAT.
const darwin_so_sndbuf: u32 = 0x1001;
const darwin_so_sndlowat: u32 = 0x1003;

/// `getsockopt` with a C `int` payload.
pub fn getsockoptInt(fd: Handle, level: u32, optname: u32) SetsockoptError!c_int {
    var value: c_int = 0;
    var len: posix.socklen_t = @sizeOf(c_int);
    const rc = c.getsockopt(fd, @intCast(level), optname, @ptrCast(&value), &len);
    switch (c.errno(rc)) {
        .SUCCESS => return value,
        .INVAL, .NOPROTOOPT, .OPNOTSUPP => return error.OptionUnsupported,
        .BADF, .NOTSOCK, .FAULT => return error.Unexpected,
        else => |err| return posix.unexpectedErrno(err),
    }
}

/// Set `SO_SNDLOWAT` to the socket's `SO_SNDBUF` (see `raise_send_lowat`).
/// Returns the low-water mark now in force.
pub fn raiseSendLowat(fd: Handle) SetsockoptError!c_int {
    const sndbuf = try getsockoptInt(fd, consts.sol_socket, darwin_so_sndbuf);
    try setsockoptInt(fd, consts.sol_socket, darwin_so_sndlowat, sndbuf);
    return getsockoptInt(fd, consts.sol_socket, darwin_so_sndlowat);
}

pub const BindError = error{
    AddressInUse,
    AddressUnavailable,
    AddressFamilyUnsupported,
    PermissionDenied,
    SystemResources,
} || std.Io.UnexpectedError;

/// Storage large enough for `sockaddr_in6` on every supported OS.
pub const SockaddrStorage = posix.sockaddr.storage;

/// Fill `storage` with the wildcard address of `family` on `port`.
pub fn fillWildcard(family: Family, port: u16, storage: *SockaddrStorage) posix.socklen_t {
    storage.* = std.mem.zeroes(SockaddrStorage);
    switch (family) {
        .v4 => {
            const in: *posix.sockaddr.in = @ptrCast(storage);
            in.* = .{ .port = std.mem.nativeToBig(u16, port), .addr = 0 };
            return @sizeOf(posix.sockaddr.in);
        },
        .v6 => {
            const in6: *posix.sockaddr.in6 = @ptrCast(storage);
            in6.* = .{ .port = std.mem.nativeToBig(u16, port), .flowinfo = 0, .addr = @splat(0), .scope_id = 0 };
            return @sizeOf(posix.sockaddr.in6);
        },
    }
}

/// Fill `storage` from an `IpAddress` (network-order port, Darwin `len`).
pub fn fillSockaddr(address: *const net.IpAddress, storage: *SockaddrStorage) posix.socklen_t {
    storage.* = std.mem.zeroes(SockaddrStorage);
    switch (address.*) {
        .ip4 => |a| {
            const in: *posix.sockaddr.in = @ptrCast(storage);
            in.* = .{ .port = std.mem.nativeToBig(u16, a.port), .addr = @bitCast(a.bytes) };
            return @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |a| {
            const in6: *posix.sockaddr.in6 = @ptrCast(storage);
            in6.* = .{ .port = std.mem.nativeToBig(u16, a.port), .flowinfo = a.flow, .addr = a.bytes, .scope_id = a.interface.index };
            return @sizeOf(posix.sockaddr.in6);
        },
    }
}

/// Decode a `sockaddr` written by the kernel. `null` for other families.
pub fn ipAddressFromSockaddr(storage: *const SockaddrStorage, len: posix.socklen_t) ?net.IpAddress {
    const any: *const posix.sockaddr = @ptrCast(storage);
    if (any.family == c.AF.INET and len >= @sizeOf(posix.sockaddr.in)) {
        const in: *const posix.sockaddr.in = @ptrCast(storage);
        return .{ .ip4 = .{ .port = std.mem.bigToNative(u16, in.port), .bytes = @bitCast(in.addr) } };
    }
    if (any.family == c.AF.INET6 and len >= @sizeOf(posix.sockaddr.in6)) {
        const in6: *const posix.sockaddr.in6 = @ptrCast(storage);
        return .{ .ip6 = .{
            .port = std.mem.bigToNative(u16, in6.port),
            .bytes = in6.addr,
            .flow = in6.flowinfo,
            .interface = .{ .index = in6.scope_id },
        } };
    }
    return null;
}

/// `bind(2)` to `*:port` for `family`.
pub fn bindWildcard(fd: Handle, family: Family, port: u16) BindError!void {
    var storage: SockaddrStorage = undefined;
    const len = fillWildcard(family, port, &storage);
    while (true) {
        switch (c.errno(c.bind(fd, @ptrCast(&storage), len))) {
            .SUCCESS => return,
            .INTR => continue,
            .ACCES, .PERM => return error.PermissionDenied,
            .ADDRINUSE => return error.AddressInUse,
            .ADDRNOTAVAIL => return error.AddressUnavailable,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .NOMEM, .NOBUFS => return error.SystemResources,
            .BADF, .NOTSOCK, .INVAL, .FAULT => return error.Unexpected,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

/// `getsockname(2)` as an `IpAddress`.
pub fn localAddress(fd: Handle) (error{AddressFamilyUnsupported} || std.Io.UnexpectedError)!net.IpAddress {
    var storage: SockaddrStorage = undefined;
    var len: posix.socklen_t = @sizeOf(SockaddrStorage);
    switch (c.errno(c.getsockname(fd, @ptrCast(&storage), &len))) {
        .SUCCESS => {},
        .BADF, .NOTSOCK, .INVAL, .FAULT, .NOBUFS => return error.Unexpected,
        else => |err| return posix.unexpectedErrno(err),
    }
    return ipAddressFromSockaddr(&storage, len) orelse error.AddressFamilyUnsupported;
}

/// Enable SO_REUSEADDR and/or SO_REUSEPORT before bind.
pub fn setReuse(fd: Handle, reuse_addr: bool, reuse_port: bool) SetsockoptError!void {
    if (reuse_addr) try setsockoptInt(fd, consts.sol_socket, consts.so_reuseaddr, 1);
    if (reuse_port) try setsockoptInt(fd, consts.sol_socket, consts.so_reuseport, 1);
}

/// Bind a throwaway socket to `*:port` with no reuse flags and close it.
/// `true` means nobody else holds the port (we are the first binder);
/// `false` means EADDRINUSE. Other failures propagate.
pub fn trialBindWithoutReuse(family: Family, port: u16) (SocketError || BindError)!bool {
    const fd = try rawUdpSocket(family);
    defer closeFd(fd);
    bindWildcard(fd, family, port) catch |err| switch (err) {
        error.AddressInUse => return false,
        else => |e| return e,
    };
    return true;
}

// ---------------------------------------------------------------------------
// bindMdnsSocket
// ---------------------------------------------------------------------------

pub const BindOptions = struct {
    port: u16 = mdns_port,
    reuse_addr: bool = true,
    reuse_port: bool = true,
    /// RFC 6762 section 11: 255 for multicast and unicast.
    ttl: u8 = 255,
    /// Multicast loopback ON so a second stack on this host sees us.
    multicast_loop: bool = true,
    /// Enable IP_PKTINFO / IPV6_RECVPKTINFO (or IP_RECVIF+RECVDSTADDR).
    pktinfo: bool = true,
    /// Enable IP_RECVTTL / IPV6_RECVHOPLIMIT. Best-effort: a refusal is
    /// not an error.
    recv_ttl: bool = true,
    /// Set `O_NONBLOCK` on the fd. OFF by default (plan Revision 3):
    /// Threaded's timed calls pass MSG_DONTWAIT on the first attempt
    /// (`STD/Io/Threaded.zig:13188`) and, after `poll(2)` reports
    /// readiness, call `operate`, whose blocking-flag `recvmsg` maps
    /// `error.WouldBlock => unreachable` (`Threaded.zig:2555` receive,
    /// `:2573` send). Linux `udp_poll` only filters bad-checksum false
    /// positives for BLOCKING fds (net/ipv4/udp.c:
    /// `!(file->f_flags & O_NONBLOCK) && first_packet_length(sk) == -1`),
    /// so with `O_NONBLOCK` one malformed LAN datagram would turn that
    /// `unreachable` into a network-triggerable panic. Set true only for a
    /// backend that requires it (the fork's Dispatch, M6), never under
    /// Threaded. See docs/platform-matrix.md "Known risks".
    nonblocking: bool = false,
    /// Run `trialBindWithoutReuse` first to compute `first_binder`.
    trial_bind: bool = true,
};

pub const BoundSocket = struct {
    socket: net.Socket,
    /// True when a bind without reuse flags succeeded just before ours:
    /// no other process holds the port. See plan section 4.8 "Port sharing".
    first_binder: bool,
};

/// The typed error set `Service.init` surfaces for the platform layer
/// (plan section 4.6). Everything the socket, setsockopt and bind paths
/// can report is folded into these four:
/// - `AddressInUse`: `bind` failed with EADDRINUSE even with both reuse
///   flags (a non-reuse holder owns 5353).
/// - `PermissionDenied`: EACCES / EPERM from `socket`, `setsockopt` or
///   `bind` (sandbox, seccomp, restricted port).
/// - `OptionUnsupported`: the kernel lacks an option this socket needs
///   (pktinfo, V6ONLY, ...), or the family itself (AF_INET6 absent). The
///   caller degrades v6 to `warning.v6_unavailable`.
/// - `Unexpected`: resource exhaustion and every unmapped errno.
pub const BindMdnsError = error{
    AddressInUse,
    PermissionDenied,
    OptionUnsupported,
    Unexpected,
};

/// Everything the socket, setsockopt and bind paths can report.
const RawBindError = SocketError || BindError || SetsockoptError;

/// Fold a lower-level error into `BindMdnsError`.
fn narrowBindError(err: RawBindError) BindMdnsError {
    return switch (err) {
        error.AddressInUse => error.AddressInUse,
        error.PermissionDenied => error.PermissionDenied,
        error.OptionUnsupported,
        error.AddressFamilyUnsupported,
        error.ProtocolUnsupported,
        => error.OptionUnsupported,
        error.AddressUnavailable,
        error.NoInterface,
        error.SystemResources,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.Unexpected,
        => error.Unexpected,
    };
}

/// Open, configure and bind one mDNS socket on `*:port`:
/// SO_REUSEADDR + SO_REUSEPORT, IPV6_V6ONLY, TTL/hops 255 for multicast
/// and unicast (RFC 6762 section 11), multicast loop, pktinfo and TTL
/// delivery, IP_MULTICAST_ALL=0 and IPV6_MULTICAST_ALL=0 on Linux, optional O_NONBLOCK (see
/// `BindOptions.nonblocking`), bind, getsockname. The result wraps the fd
/// as `Io.net.Socket` so `receiveManyTimeout` / `sendManyTimeout` drive it
/// (timed calls only, plan section 4.3). Every errno is mapped; nothing
/// traps.
pub fn bindMdnsSocket(family: Family, opts: BindOptions) BindMdnsError!BoundSocket {
    return bindMdnsSocketInner(family, opts) catch |err| narrowBindError(err);
}

fn bindMdnsSocketInner(family: Family, opts: BindOptions) RawBindError!BoundSocket {
    const first_binder = if (opts.trial_bind) try trialBindWithoutReuse(family, opts.port) else false;

    const fd = try rawUdpSocket(family);
    errdefer closeFd(fd);

    try setReuse(fd, opts.reuse_addr, opts.reuse_port);

    const ttl: c_int = opts.ttl;
    const loop: c_int = if (opts.multicast_loop) 1 else 0;
    switch (family) {
        .v4 => {
            try setIpByteOption(fd, consts.ip_multicast_ttl, opts.ttl);
            try setsockoptInt(fd, consts.ipproto_ip, consts.ip_ttl, ttl);
            try setIpByteOption(fd, consts.ip_multicast_loop, if (opts.multicast_loop) 1 else 0);
            if (opts.pktinfo) {
                if (consts.ip_recvpktinfo) |opt| {
                    try setsockoptInt(fd, consts.ipproto_ip, opt, 1);
                } else if (consts.ip_recvif) |opt| {
                    try setsockoptInt(fd, consts.ipproto_ip, opt, 1);
                    if (consts.ip_recvdstaddr) |dst_opt| try setsockoptInt(fd, consts.ipproto_ip, dst_opt, 1);
                } else return error.OptionUnsupported;
            }
            if (opts.recv_ttl) setsockoptInt(fd, consts.ipproto_ip, consts.ip_recvttl, 1) catch |err| switch (err) {
                error.OptionUnsupported => {},
                else => |e| return e,
            };
            // Linux: a wildcard-bound socket receives every group any
            // socket on the host joined unless IP_MULTICAST_ALL is 0.
            // Kernels before 2.6.31 lack the option; that is not fatal.
            if (consts.ip_multicast_all) |opt| setsockoptInt(fd, consts.ipproto_ip, opt, 0) catch |err| switch (err) {
                error.OptionUnsupported => {},
                else => |e| return e,
            };
        },
        .v6 => {
            try setsockoptInt(fd, consts.ipproto_ipv6, consts.ipv6_v6only, 1);
            try setsockoptInt(fd, consts.ipproto_ipv6, consts.ipv6_multicast_hops, ttl);
            try setsockoptInt(fd, consts.ipproto_ipv6, consts.ipv6_unicast_hops, ttl);
            try setsockoptInt(fd, consts.ipproto_ipv6, consts.ipv6_multicast_loop, loop);
            if (opts.pktinfo) try setsockoptInt(fd, consts.ipproto_ipv6, consts.ipv6_recvpktinfo, 1);
            if (opts.recv_ttl) setsockoptInt(fd, consts.ipproto_ipv6, consts.ipv6_recvhoplimit, 1) catch |err| switch (err) {
                error.OptionUnsupported => {},
                else => |e| return e,
            };
            // Same rule as IP_MULTICAST_ALL: without it a wildcard-bound
            // v6 socket on Linux receives every ff02::fb datagram on any
            // interface another process (avahi) joined (measured in the
            // zig-uring VM with an allow-list that joined nothing on v6).
            if (consts.ipv6_multicast_all) |opt| setsockoptInt(fd, consts.ipproto_ipv6, opt, 0) catch |err| switch (err) {
                error.OptionUnsupported => {},
                else => |e| return e,
            };
        },
    }

    if (opts.nonblocking) try setNonBlocking(fd);
    if (comptime raise_send_lowat) _ = try raiseSendLowat(fd);

    try bindWildcard(fd, family, opts.port);

    const address = localAddress(fd) catch |err| switch (err) {
        error.AddressFamilyUnsupported => return error.Unexpected,
        else => |e| return e,
    };

    return .{
        .socket = .{ .handle = fd, .address = address },
        .first_binder = first_binder,
    };
}

// ---------------------------------------------------------------------------
// Multicast membership and egress interface
// ---------------------------------------------------------------------------

pub const GroupError = SetsockoptError || error{
    /// v4 join on an OS without `ip_mreqn` needs the interface's v4 address.
    InterfaceAddressRequired,
    /// `ifindex` does not fit the kernel's `int` field. Interface indexes
    /// arrive from the pktinfo cmsg and from caller allow-lists, so an
    /// out-of-range value is an error, not a cast trap.
    InvalidInterface,
    /// EADDRINUSE on a join: this socket already joined the group on that
    /// interface. `Service` treats it as success on a re-join.
    AlreadyMember,
    /// EADDRNOTAVAIL on a leave: the socket was not a member.
    NotMember,
};

/// Map the membership-specific errnos (`setsockoptChecked` returns them as
/// generic address errors) to `AlreadyMember` / `NotMember`.
fn membershipErr(err: SetsockoptError, join: bool) GroupError {
    return switch (err) {
        error.AddressInUse => if (join) error.AlreadyMember else error.AddressInUse,
        error.AddressUnavailable => if (join) error.AddressUnavailable else error.NotMember,
        else => |e| e,
    };
}

fn membership(fd: Handle, family: Family, ifindex: u32, iface_v4_addr: ?[4]u8, join: bool) GroupError!void {
    switch (family) {
        .v4 => {
            const opt = if (join) consts.ip_add_membership else consts.ip_drop_membership;
            if (consts.has_ip_mreqn) {
                // Linux: ifindex-based join; imr_address may stay 0.
                const idx = std.math.cast(i32, ifindex) orelse return error.InvalidInterface;
                const req: ip_mreqn = .{ .multiaddr = group_v4, .address = iface_v4_addr orelse @splat(0), .ifindex = idx };
                setsockoptChecked(fd, consts.ipproto_ip, opt, std.mem.asBytes(&req)) catch |err| return membershipErr(err, join);
            } else {
                // Darwin/BSD: imr_interface is the interface's own v4 address.
                const addr = iface_v4_addr orelse return error.InterfaceAddressRequired;
                const req: ip_mreq = .{ .multiaddr = group_v4, .interface = addr };
                setsockoptChecked(fd, consts.ipproto_ip, opt, std.mem.asBytes(&req)) catch |err| return membershipErr(err, join);
            }
        },
        .v6 => {
            const opt = if (join) consts.ipv6_join_group else consts.ipv6_leave_group;
            const req: ipv6_mreq = .{ .multiaddr = group_v6, .interface = ifindex };
            setsockoptChecked(fd, consts.ipproto_ipv6, opt, std.mem.asBytes(&req)) catch |err| return membershipErr(err, join);
        },
    }
}

/// Join 224.0.0.251 (v4) or ff02::fb (v6) on interface `ifindex`.
/// `iface_v4_addr` is required for v4 on Darwin and the BSDs. A second
/// join on the same interface returns `error.AlreadyMember`.
pub fn joinGroup(fd: Handle, family: Family, ifindex: u32, iface_v4_addr: ?[4]u8) GroupError!void {
    return membership(fd, family, ifindex, iface_v4_addr, true);
}

/// Leave the group joined by `joinGroup`.
pub fn leaveGroup(fd: Handle, family: Family, ifindex: u32, iface_v4_addr: ?[4]u8) GroupError!void {
    return membership(fd, family, ifindex, iface_v4_addr, false);
}

/// Select the egress interface for multicast sends on `fd`.
/// v4: `ip_mreqn` (Linux), else IP_MULTICAST_IF with the interface's v4
/// address (FreeBSD, OpenBSD, Darwin), else IP_MULTICAST_IFINDEX (Darwin,
/// when no address is given). v6: IPV6_MULTICAST_IF with the ifindex.
/// On targets where `needsPerSendMulticastIf()` is true, `Service` calls
/// this for v4 before every send; elsewhere the pktinfo cmsg does it.
pub fn setMulticastIf(fd: Handle, family: Family, ifindex: u32, iface_v4_addr: ?[4]u8) GroupError!void {
    switch (family) {
        .v4 => {
            if (consts.has_ip_mreqn) {
                const idx = std.math.cast(i32, ifindex) orelse return error.InvalidInterface;
                const req: ip_mreqn = .{ .multiaddr = @splat(0), .address = iface_v4_addr orelse @splat(0), .ifindex = idx };
                try setsockoptChecked(fd, consts.ipproto_ip, consts.ip_multicast_if, std.mem.asBytes(&req));
            } else if (iface_v4_addr) |addr| {
                try setsockoptChecked(fd, consts.ipproto_ip, consts.ip_multicast_if, &addr);
            } else if (consts.ip_multicast_ifindex) |opt| {
                const idx = std.math.cast(c_int, ifindex) orelse return error.InvalidInterface;
                try setsockoptInt(fd, consts.ipproto_ip, opt, idx);
            } else return error.InterfaceAddressRequired;
        },
        .v6 => {
            const idx = std.math.cast(c_int, ifindex) orelse return error.InvalidInterface;
            try setsockoptInt(fd, consts.ipproto_ipv6, consts.ipv6_multicast_if, idx);
        },
    }
}

// ---------------------------------------------------------------------------
// Tests (pure: no sockets)
// ---------------------------------------------------------------------------

const testing = std.testing;

const layout4: CmsgLayout = .{ .alignment = 4, .len_size = 4 };
const layout8: CmsgLayout = .{ .alignment = 8, .len_size = 8 };
const layout8_len4: CmsgLayout = .{ .alignment = 8, .len_size = 4 };

test "cmsg layout arithmetic matches CMSG_SPACE/CMSG_LEN" {
    // Darwin: header 12, __DARWIN_ALIGN32.
    try testing.expectEqual(@as(usize, 12), layout4.headerSize());
    try testing.expectEqual(@as(usize, 12), layout4.dataOffset());
    try testing.expectEqual(@as(usize, 13), layout4.len(1));
    try testing.expectEqual(@as(usize, 16), layout4.space(1));
    try testing.expectEqual(@as(usize, 32), layout4.space(20));
    // 64-bit Linux: header 16, align 8.
    try testing.expectEqual(@as(usize, 16), layout8.headerSize());
    try testing.expectEqual(@as(usize, 16), layout8.dataOffset());
    try testing.expectEqual(@as(usize, 24), layout8.space(4));
    try testing.expectEqual(@as(usize, 40), layout8.space(20));
    // 64-bit FreeBSD/OpenBSD: header 12 padded to 16, align 8.
    try testing.expectEqual(@as(usize, 12), layout8_len4.headerSize());
    try testing.expectEqual(@as(usize, 16), layout8_len4.dataOffset());
    try testing.expectEqual(@as(usize, 40), layout8_len4.space(20));
}

/// Encode pktinfo + TTL for both families under `layout`, walk it back,
/// and decode through a table whose numbers match the entries written.
fn roundTrip(layout: CmsgLayout) !void {
    var buf: [128]u8 = undefined;
    var e: CmsgEncoder = .init(layout, &buf);
    const pi4: in_pktinfo = .{ .ifindex = 7, .spec_dst = .{ 10, 0, 0, 1 }, .addr = .{ 224, 0, 0, 251 } };
    const ttl: u8 = 255;
    const pi6: in6_pktinfo = .{ .addr = group_v6, .ifindex = 12 };
    const hops: c_int = 255;
    try e.append(0, 26, std.mem.asBytes(&pi4));
    try e.append(0, 24, std.mem.asBytes(&ttl));
    try e.append(41, 46, std.mem.asBytes(&pi6));
    try e.append(41, 47, std.mem.asBytes(&hops));
    const expected_len = layout.space(12) + layout.space(1) + layout.space(20) + layout.space(4);
    try testing.expectEqual(expected_len, e.bytes().len);

    var it: CmsgIterator = .init(layout, e.bytes());
    const m0 = it.next().?;
    try testing.expectEqual(@as(i32, 0), m0.level);
    try testing.expectEqual(@as(i32, 26), m0.type);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&pi4), m0.data);
    const m1 = it.next().?;
    try testing.expectEqual(@as(i32, 24), m1.type);
    try testing.expectEqualSlices(u8, &.{255}, m1.data);
    const m2 = it.next().?;
    try testing.expectEqual(@as(i32, 41), m2.level);
    try testing.expectEqual(@as(i32, 46), m2.type);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&pi6), m2.data);
    const m3 = it.next().?;
    try testing.expectEqual(@as(i32, 47), m3.type);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&hops), m3.data);
    try testing.expect(it.next() == null);

    // Decode through the Darwin table shape (numbers 26/24/46/47) with
    // this layout substituted.
    var table = darwin_consts;
    table.cmsg = layout;
    const info = decodeRxInfoWith(table, e.bytes());
    try testing.expectEqual(@as(u32, 12), info.ifindex); // last pktinfo wins
    try testing.expect(info.dst != null);
    try testing.expect(info.dstMulticast());
    try testing.expectEqual(@as(?u8, 255), info.ttl);

    // Per-family decode sees only its own level.
    const m4 = decodeControlWith(table, .v4, e.bytes());
    try testing.expectEqual(@as(u32, 7), m4.ifindex);
    try testing.expectEqual(@as(?u8, 255), m4.ttl);
    try testing.expectEqual(@as(?bool, true), m4.dst_multicast);
    const m6 = decodeControlWith(table, .v6, e.bytes());
    try testing.expectEqual(@as(u32, 12), m6.ifindex);
    try testing.expectEqual(@as(?u8, 255), m6.ttl);
    try testing.expectEqual(@as(?bool, true), m6.dst_multicast);
}

test "cmsg codec round trips on 4- and 8-byte alignment" {
    try roundTrip(layout4); // Darwin
    try roundTrip(layout8); // 64-bit Linux
    try roundTrip(layout8_len4); // 64-bit FreeBSD / OpenBSD
}

test "cmsg walker stops on malformed entries" {
    // Header claims 3 bytes: shorter than a header.
    var short: [16]u8 = @splat(0);
    std.mem.writeInt(u32, short[0..4], 3, native_endian);
    var it: CmsgIterator = .init(layout4, &short);
    try testing.expect(it.next() == null);

    // Header claims more than the buffer holds.
    var over: [16]u8 = @splat(0);
    std.mem.writeInt(u32, over[0..4], 64, native_endian);
    it = .init(layout4, &over);
    try testing.expect(it.next() == null);

    // Truncated buffer: fewer bytes than a header.
    it = .init(layout4, over[0..5]);
    try testing.expect(it.next() == null);

    // Empty control.
    it = .init(layout4, &.{});
    try testing.expect(it.next() == null);
    try testing.expectEqual(@as(u32, 0), decodeRxInfoWith(darwin_consts, &.{}).ifindex);
    const empty = decodeControlWith(darwin_consts, .v4, &.{});
    try testing.expectEqual(@as(u32, 0), empty.ifindex);
    try testing.expect(empty.ttl == null);
    try testing.expect(empty.dst_multicast == null);

    // 8-byte cmsg_len that overflows usize on 32-bit targets or is
    // simply absurd: the walk ends, no trap.
    var huge: [32]u8 = @splat(0);
    std.mem.writeInt(u64, huge[0..8], std.math.maxInt(u64), native_endian);
    it = .init(layout8, &huge);
    try testing.expect(it.next() == null);
}

test "cmsg encoder refuses to overflow" {
    var buf: [20]u8 = undefined;
    var e: CmsgEncoder = .init(layout4, &buf);
    const pi6: in6_pktinfo = .{ .addr = group_v6, .ifindex = 1 };
    try testing.expectError(error.NoSpace, e.append(41, 46, std.mem.asBytes(&pi6)));
    try testing.expectEqual(@as(usize, 0), e.bytes().len);
}

test "v4 pktinfo decode reads ifindex and unicast destination" {
    var buf: [64]u8 = undefined;
    var e: CmsgEncoder = .init(layout4, &buf);
    const pi4: in_pktinfo = .{ .ifindex = 3, .spec_dst = .{ 192, 168, 1, 2 }, .addr = .{ 192, 168, 1, 2 } };
    try e.append(0, 26, std.mem.asBytes(&pi4));
    const info = decodeRxInfoWith(darwin_consts, e.bytes());
    try testing.expectEqual(@as(u32, 3), info.ifindex);
    try testing.expect(!info.dstMulticast());
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 2 }, &info.dst.?.v4);
    try testing.expect(info.ttl == null);
    const meta = decodeControlWith(darwin_consts, .v4, e.bytes());
    try testing.expectEqual(@as(u32, 3), meta.ifindex);
    try testing.expectEqual(@as(?bool, false), meta.dst_multicast);
    try testing.expect(meta.ttl == null);
}

test "Linux pktinfo and IP_TTL decode under the 8-byte layout" {
    var buf: [96]u8 = undefined;
    var e: CmsgEncoder = .init(linux_consts.cmsg, &buf);
    const pi4: in_pktinfo = .{ .ifindex = 2, .spec_dst = .{ 10, 0, 0, 5 }, .addr = group_v4 };
    const ttl: c_int = 255;
    try e.append(0, 8, std.mem.asBytes(&pi4)); // IP_PKTINFO
    try e.append(0, 2, std.mem.asBytes(&ttl)); // IP_TTL (int) from IP_RECVTTL
    const meta = decodeControlWith(linux_consts, .v4, e.bytes());
    try testing.expectEqual(@as(u32, 2), meta.ifindex);
    try testing.expectEqual(@as(?u8, 255), meta.ttl);
    try testing.expectEqual(@as(?bool, true), meta.dst_multicast);

    var buf6: [96]u8 = undefined;
    var e6: CmsgEncoder = .init(linux_consts.cmsg, &buf6);
    const pi6: in6_pktinfo = .{ .addr = group_v6, .ifindex = 4 };
    const hops: c_int = 1;
    try e6.append(41, 50, std.mem.asBytes(&pi6)); // IPV6_PKTINFO
    try e6.append(41, 52, std.mem.asBytes(&hops)); // IPV6_HOPLIMIT
    const meta6 = decodeControlWith(linux_consts, .v6, e6.bytes());
    try testing.expectEqual(@as(u32, 4), meta6.ifindex);
    try testing.expectEqual(@as(?u8, 1), meta6.ttl);
    try testing.expectEqual(@as(?bool, true), meta6.dst_multicast);
    // A v4 view of a v6 control buffer learns nothing.
    const cross = decodeControlWith(linux_consts, .v4, e6.bytes());
    try testing.expectEqual(@as(u32, 0), cross.ifindex);
    try testing.expect(cross.dst_multicast == null);
}

test "BSD IP_RECVIF sockaddr_dl and IP_RECVDSTADDR decode" {
    // FreeBSD (RECVIF 20, RECVDSTADDR 7, RECVTTL 65) and OpenBSD (30, 7,
    // 31), both with socklen_t cmsg_len and register-size padding.
    const tables = [_]Consts{ freebsd_consts, openbsd_consts };
    for (tables) |table| {
        // The buffer is the size those targets allocate per datagram
        // (128, `control_buffer_size` there); the kernel's order is
        // dstaddr, ttl, then the link-level sockaddr, and the sockaddr_dl
        // is the full FreeBSD size (54 rounded to 56) so a buffer that is
        // too small shows up here as `error.NoSpace`.
        const bsd_control_size: usize = 128;
        var buf: [bsd_control_size]u8 = undefined;
        var e: CmsgEncoder = .init(table.cmsg, &buf);
        try e.append(0, @intCast(table.ip_recvdstaddr.?), &group_v4);
        const ttl: u8 = 255;
        try e.append(0, @intCast(table.ip_recvttl), std.mem.asBytes(&ttl));
        // sockaddr_dl: sdl_len=54, sdl_family=AF_LINK(18), sdl_index=5,
        // then type/nlen/alen/slen and the name/lladdr work area.
        var dl: [max_sockaddr_dl_len]u8 = @splat(0);
        dl[0] = 54;
        dl[1] = 18;
        std.mem.writeInt(u16, dl[2..4], 5, native_endian);
        try e.append(0, @intCast(table.ip_recvif.?), &dl);
        try testing.expectEqual(controlBytesNeeded4(table), e.bytes().len);
        const meta = decodeControlWith(table, .v4, e.bytes());
        try testing.expectEqual(@as(u32, 5), meta.ifindex);
        try testing.expectEqual(@as(?bool, true), meta.dst_multicast);
        try testing.expectEqual(@as(?u8, 255), meta.ttl);

        // The old 64 B buffer: the last entry (IP_RECVIF) does not fit,
        // which is exactly the silent ifindex=0 the size fix removes.
        var small: [64]u8 = undefined;
        var es: CmsgEncoder = .init(table.cmsg, &small);
        try es.append(0, @intCast(table.ip_recvdstaddr.?), &group_v4);
        try es.append(0, @intCast(table.ip_recvttl), std.mem.asBytes(&ttl));
        try testing.expectError(error.NoSpace, es.append(0, @intCast(table.ip_recvif.?), &dl));

        // v6 on the BSDs is RFC 3542 pktinfo (46) + hoplimit (47).
        var buf6: [96]u8 = undefined;
        var e6: CmsgEncoder = .init(table.cmsg, &buf6);
        var ll: [16]u8 = @splat(0);
        ll[0] = 0xfe;
        ll[1] = 0x80;
        ll[15] = 1;
        const pi6: in6_pktinfo = .{ .addr = ll, .ifindex = 9 };
        const hops: c_int = 64;
        try e6.append(41, @intCast(table.ipv6_pktinfo), std.mem.asBytes(&pi6));
        try e6.append(41, @intCast(table.ipv6_hoplimit), std.mem.asBytes(&hops));
        const meta6 = decodeControlWith(table, .v6, e6.bytes());
        try testing.expectEqual(@as(u32, 9), meta6.ifindex);
        try testing.expectEqual(@as(?bool, false), meta6.dst_multicast);
        try testing.expectEqual(@as(?u8, 64), meta6.ttl);
    }
}

test "Darwin constant table matches the SDK headers" {
    // netinet/in.h, netinet6/in6.h, sys/socket.h, net/if.h (macOS SDK).
    try testing.expectEqual(@as(u32, 0xffff), darwin_consts.sol_socket);
    try testing.expectEqual(@as(u32, 0x0004), darwin_consts.so_reuseaddr);
    try testing.expectEqual(@as(u32, 0x0200), darwin_consts.so_reuseport);
    try testing.expectEqual(@as(u32, 9), darwin_consts.ip_multicast_if);
    try testing.expectEqual(@as(u32, 10), darwin_consts.ip_multicast_ttl);
    try testing.expectEqual(@as(u32, 11), darwin_consts.ip_multicast_loop);
    try testing.expectEqual(@as(u32, 12), darwin_consts.ip_add_membership);
    try testing.expectEqual(@as(u32, 13), darwin_consts.ip_drop_membership);
    try testing.expectEqual(@as(?u32, 26), darwin_consts.ip_pktinfo);
    try testing.expectEqual(@as(?u32, 20), darwin_consts.ip_recvif);
    try testing.expectEqual(@as(?u32, 7), darwin_consts.ip_recvdstaddr);
    try testing.expectEqual(@as(u32, 24), darwin_consts.ip_recvttl);
    try testing.expectEqual(@as(u32, 4), darwin_consts.ip_ttl);
    try testing.expectEqual(@as(u32, 4), darwin_consts.ipv6_unicast_hops);
    try testing.expectEqual(@as(u32, 9), darwin_consts.ipv6_multicast_if);
    try testing.expectEqual(@as(u32, 10), darwin_consts.ipv6_multicast_hops);
    try testing.expectEqual(@as(u32, 11), darwin_consts.ipv6_multicast_loop);
    try testing.expectEqual(@as(u32, 12), darwin_consts.ipv6_join_group);
    try testing.expectEqual(@as(u32, 13), darwin_consts.ipv6_leave_group);
    try testing.expectEqual(@as(u32, 27), darwin_consts.ipv6_v6only);
    try testing.expectEqual(@as(u32, 61), darwin_consts.ipv6_recvpktinfo);
    try testing.expectEqual(@as(u32, 46), darwin_consts.ipv6_pktinfo);
    try testing.expectEqual(@as(u32, 37), darwin_consts.ipv6_recvhoplimit);
    try testing.expectEqual(@as(u32, 47), darwin_consts.ipv6_hoplimit);
    try testing.expectEqual(@as(u32, 0x1), darwin_consts.iff_up);
    try testing.expectEqual(@as(u32, 0x8000), darwin_consts.iff_multicast);
    try testing.expectEqual(@as(usize, 4), darwin_consts.cmsg.alignment);
    try testing.expect(!darwin_consts.needsPerSendMulticastIf());
    if (is_darwin) {
        // Cross-check what std does export on Darwin.
        try testing.expectEqual(@as(u32, c.SOL.SOCKET), consts.sol_socket);
        try testing.expectEqual(@as(u32, c.SO.REUSEADDR), consts.so_reuseaddr);
        try testing.expectEqual(@as(u32, c.SO.REUSEPORT), consts.so_reuseport);
        try testing.expectEqual(@as(u32, c.IPPROTO.IPV6), consts.ipproto_ipv6);
        try testing.expectEqual(@sizeOf(c.in_pktinfo), @sizeOf(in_pktinfo));
        try testing.expectEqual(@sizeOf(c.in6_pktinfo), @sizeOf(in6_pktinfo));
        try testing.expectEqual(@as(usize, 12), @sizeOf(c.cmsghdr));
    }
}

test "Linux, FreeBSD and OpenBSD tables match plan section 9" {
    // Linux column.
    try testing.expectEqual(@as(u32, 32), linux_consts.ip_multicast_if);
    try testing.expectEqual(@as(u32, 33), linux_consts.ip_multicast_ttl);
    try testing.expectEqual(@as(u32, 34), linux_consts.ip_multicast_loop);
    try testing.expectEqual(@as(u32, 35), linux_consts.ip_add_membership);
    try testing.expectEqual(@as(u32, 36), linux_consts.ip_drop_membership);
    try testing.expectEqual(@as(?u32, 8), linux_consts.ip_pktinfo);
    try testing.expectEqual(@as(u32, 12), linux_consts.ip_recvttl);
    try testing.expectEqual(@as(?u32, 49), linux_consts.ip_multicast_all);
    try testing.expectEqual(@as(?u32, 29), linux_consts.ipv6_multicast_all);
    try testing.expectEqual(@as(?u32, null), darwin_consts.ipv6_multicast_all);
    try testing.expectEqual(@as(u32, 17), linux_consts.ipv6_multicast_if);
    try testing.expectEqual(@as(u32, 18), linux_consts.ipv6_multicast_hops);
    try testing.expectEqual(@as(u32, 19), linux_consts.ipv6_multicast_loop);
    try testing.expectEqual(@as(u32, 20), linux_consts.ipv6_join_group);
    try testing.expectEqual(@as(u32, 21), linux_consts.ipv6_leave_group);
    try testing.expectEqual(@as(u32, 26), linux_consts.ipv6_v6only);
    try testing.expectEqual(@as(u32, 49), linux_consts.ipv6_recvpktinfo);
    try testing.expectEqual(@as(u32, 50), linux_consts.ipv6_pktinfo);
    try testing.expectEqual(@as(u32, 0x1000), linux_consts.iff_multicast);
    try testing.expectEqual(@sizeOf(usize), linux_consts.cmsg.alignment);
    try testing.expect(linux_consts.has_ip_mreqn);
    try testing.expect(!linux_consts.ip_u8_options);
    try testing.expect(!linux_consts.needsPerSendMulticastIf());

    // FreeBSD column.
    try testing.expectEqual(@as(u32, 0xffff), freebsd_consts.sol_socket);
    try testing.expectEqual(@as(u32, 0x0004), freebsd_consts.so_reuseaddr);
    try testing.expectEqual(@as(u32, 0x0200), freebsd_consts.so_reuseport);
    try testing.expectEqual(@as(u32, 9), freebsd_consts.ip_multicast_if);
    try testing.expectEqual(@as(u32, 12), freebsd_consts.ip_add_membership);
    try testing.expectEqual(@as(?u32, null), freebsd_consts.ip_pktinfo);
    try testing.expectEqual(@as(?u32, 20), freebsd_consts.ip_recvif);
    try testing.expectEqual(@as(?u32, 7), freebsd_consts.ip_recvdstaddr);
    try testing.expectEqual(@as(u32, 65), freebsd_consts.ip_recvttl);
    try testing.expectEqual(@as(u32, 12), freebsd_consts.ipv6_join_group);
    try testing.expectEqual(@as(u32, 13), freebsd_consts.ipv6_leave_group);
    try testing.expectEqual(@as(u32, 27), freebsd_consts.ipv6_v6only);
    try testing.expectEqual(@as(u32, 36), freebsd_consts.ipv6_recvpktinfo);
    try testing.expectEqual(@as(u32, 46), freebsd_consts.ipv6_pktinfo);
    try testing.expectEqual(@as(u32, 0x8000), freebsd_consts.iff_multicast);
    try testing.expectEqual(@sizeOf(usize), freebsd_consts.cmsg.alignment);
    try testing.expectEqual(@as(usize, 4), freebsd_consts.cmsg.len_size);
    try testing.expect(freebsd_consts.needsPerSendMulticastIf());

    // OpenBSD column.
    try testing.expectEqual(@as(u32, 0xffff), openbsd_consts.sol_socket);
    try testing.expectEqual(@as(u32, 9), openbsd_consts.ip_multicast_if);
    try testing.expectEqual(@as(u32, 12), openbsd_consts.ip_add_membership);
    try testing.expectEqual(@as(?u32, null), openbsd_consts.ip_pktinfo);
    try testing.expectEqual(@as(?u32, 30), openbsd_consts.ip_recvif);
    try testing.expectEqual(@as(?u32, 7), openbsd_consts.ip_recvdstaddr);
    try testing.expectEqual(@as(u32, 31), openbsd_consts.ip_recvttl);
    try testing.expectEqual(@as(u32, 12), openbsd_consts.ipv6_join_group);
    try testing.expectEqual(@as(u32, 13), openbsd_consts.ipv6_leave_group);
    try testing.expectEqual(@as(u32, 27), openbsd_consts.ipv6_v6only);
    try testing.expectEqual(@as(u32, 36), openbsd_consts.ipv6_recvpktinfo);
    try testing.expectEqual(@as(u32, 46), openbsd_consts.ipv6_pktinfo);
    try testing.expectEqual(@as(u32, 0x8000), openbsd_consts.iff_multicast);
    try testing.expectEqual(@sizeOf(usize), openbsd_consts.cmsg.alignment);
    try testing.expectEqual(@as(usize, 4), openbsd_consts.cmsg.len_size);
    try testing.expect(openbsd_consts.ip_u8_options);
    try testing.expect(openbsd_consts.needsPerSendMulticastIf());
}

test "mreq struct sizes" {
    try testing.expectEqual(@as(usize, 8), @sizeOf(ip_mreq));
    try testing.expectEqual(@as(usize, 12), @sizeOf(ip_mreqn));
    try testing.expectEqual(@as(usize, 20), @sizeOf(ipv6_mreq));
    try testing.expectEqual(@as(usize, 12), @sizeOf(in_pktinfo));
    try testing.expectEqual(@as(usize, 20), @sizeOf(in6_pktinfo));
    try testing.expectEqual(@as(usize, 4), @offsetOf(in_pktinfo, "spec_dst"));
    try testing.expectEqual(@as(usize, 16), @offsetOf(in6_pktinfo, "ifindex"));
    try testing.expectEqual(@as(usize, 2), @offsetOf(sockaddr_dl_head, "index"));
}

test "native cmsg layout is what the OS uses" {
    if (is_darwin) {
        try testing.expectEqual(@as(usize, 4), consts.cmsg.alignment);
        try testing.expectEqual(@as(usize, 4), consts.cmsg.len_size);
    } else {
        try testing.expectEqual(@sizeOf(usize), consts.cmsg.alignment);
    }
    try testing.expect(control_buffer_size >= consts.cmsg.space(@sizeOf(in6_pktinfo)) + consts.cmsg.space(4));
    try testing.expect(control_buffer_size >= controlBytesNeeded6(consts));
    try testing.expect(control_buffer_size >= controlBytesNeeded4(consts));
    if (usesRecvIf(consts)) {
        try testing.expect(control_buffer_size >= consts.cmsg.space(max_sockaddr_dl_len) + consts.cmsg.space(4) + consts.cmsg.space(1));
    }
    try testing.expectEqual(consts.ip_pktinfo == null, needsPerSendMulticastIf());
}

test "control buffer fits every table's cmsg set" {
    // Per table: FreeBSD v4 120 (24 + 24 + 72), OpenBSD v4 also 120 here
    // because `controlBytesNeeded4` counts the larger FreeBSD sockaddr_dl
    // (the OpenBSD kernel's 32-byte one gives 96), Linux v4 56 / v6 64,
    // Darwin v4 40 / v6 48. The native size is 64 without IP_RECVIF and
    // 128 with it.
    try testing.expectEqual(@as(usize, 120), controlBytesNeeded4(freebsd_consts));
    try testing.expectEqual(@as(usize, 120), controlBytesNeeded4(openbsd_consts));
    try testing.expectEqual(@as(usize, 96), openbsd_consts.cmsg.space(4) + openbsd_consts.cmsg.space(1) + openbsd_consts.cmsg.space(32));
    try testing.expectEqual(@as(usize, 64), controlBytesNeeded6(freebsd_consts));
    try testing.expectEqual(@as(usize, 64), controlBytesNeeded6(openbsd_consts));
    try testing.expectEqual(@as(usize, 56), controlBytesNeeded4(linux_consts));
    try testing.expectEqual(@as(usize, 64), controlBytesNeeded6(linux_consts));
    try testing.expectEqual(@as(usize, 40), controlBytesNeeded4(darwin_consts));
    try testing.expectEqual(@as(usize, 48), controlBytesNeeded6(darwin_consts));
    const tables = [_]Consts{ darwin_consts, linux_consts, freebsd_consts, openbsd_consts };
    try testing.expect(usesRecvIf(freebsd_consts));
    try testing.expect(usesRecvIf(openbsd_consts));
    try testing.expect(!usesRecvIf(darwin_consts));
    try testing.expect(!usesRecvIf(linux_consts));
    for (tables) |table| {
        const size: usize = if (usesRecvIf(table)) 128 else 64;
        try testing.expect(size >= controlBytesNeeded4(table));
        try testing.expect(size >= controlBytesNeeded6(table));
        try testing.expectEqual(@as(usize, 0), size % 8);
    }
}

test "pktinfo encoders follow the native table" {
    var buf: [control_buffer_size]u8 = undefined;
    const c6 = try encodePktInfo6(&buf, 3);
    try testing.expectEqual(consts.cmsg.space(@sizeOf(in6_pktinfo)), c6.len);
    const meta6 = decodeControl(.v6, c6);
    try testing.expectEqual(@as(u32, 3), meta6.ifindex);
    if (needsPerSendMulticastIf()) {
        try testing.expectError(error.OptionUnsupported, encodePktInfo4(&buf, 3, null));
    } else {
        const c4 = try encodePktInfo4(&buf, 3, null);
        try testing.expectEqual(consts.cmsg.space(@sizeOf(in_pktinfo)), c4.len);
        try testing.expectEqual(@as(u32, 3), decodeControl(.v4, c4).ifindex);
    }
}

test "sockaddr fill and decode round trip" {
    var storage: SockaddrStorage = undefined;
    const a4: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 5353 } };
    const l4 = fillSockaddr(&a4, &storage);
    try testing.expectEqual(@as(posix.socklen_t, @sizeOf(posix.sockaddr.in)), l4);
    const back4 = ipAddressFromSockaddr(&storage, l4).?;
    try testing.expectEqual(@as(u16, 5353), back4.ip4.port);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &back4.ip4.bytes);

    const a6: net.IpAddress = .{ .ip6 = .{ .bytes = group_v6, .port = 5353, .interface = .{ .index = 9 } } };
    const l6 = fillSockaddr(&a6, &storage);
    const back6 = ipAddressFromSockaddr(&storage, l6).?;
    try testing.expectEqual(@as(u16, 5353), back6.ip6.port);
    try testing.expectEqual(@as(u32, 9), back6.ip6.interface.index);
    try testing.expectEqualSlices(u8, &group_v6, &back6.ip6.bytes);

    const lw = fillWildcard(.v6, 0, &storage);
    const w = ipAddressFromSockaddr(&storage, lw).?;
    try testing.expectEqual(@as(u16, 0), w.ip6.port);
}

test "Dst.isMulticast" {
    try testing.expect((Dst{ .v4 = group_v4 }).isMulticast());
    try testing.expect(!(Dst{ .v4 = .{ 10, 1, 2, 3 } }).isMulticast());
    try testing.expect((Dst{ .v6 = group_v6 }).isMulticast());
    var ll: [16]u8 = @splat(0);
    ll[0] = 0xfe;
    ll[1] = 0x80;
    try testing.expect(!(Dst{ .v6 = ll }).isMulticast());
}

test "out-of-range ifindex is a typed error, not a cast trap" {
    // The cast runs before any syscall, so an invalid fd never reaches the
    // kernel here.
    const bad: u32 = 0x8000_0000;
    try testing.expectError(error.InvalidInterface, setMulticastIf(-1, .v6, bad, null));
    if (consts.has_ip_mreqn) {
        try testing.expectError(error.InvalidInterface, joinGroup(-1, .v4, bad, null));
        try testing.expectError(error.InvalidInterface, setMulticastIf(-1, .v4, bad, null));
    } else {
        try testing.expectError(error.InterfaceAddressRequired, joinGroup(-1, .v4, 1, null));
    }
}

test "bindMdnsSocket error set is the four Service.init errors" {
    // Compile-time shape check: every lower-level error folds into one of
    // the four (a missing arm in `narrowBindError` fails to compile).
    const names = @typeInfo(BindMdnsError).error_set.error_names.?;
    try testing.expectEqual(@as(usize, 4), names.len);
    inline for (names) |name| {
        try testing.expect(std.mem.eql(u8, name, "AddressInUse") or
            std.mem.eql(u8, name, "PermissionDenied") or
            std.mem.eql(u8, name, "OptionUnsupported") or
            std.mem.eql(u8, name, "Unexpected"));
    }
    try testing.expect(narrowBindError(error.AddressFamilyUnsupported) == error.OptionUnsupported);
    try testing.expect(narrowBindError(error.ProtocolUnsupported) == error.OptionUnsupported);
    try testing.expect(narrowBindError(error.SystemResources) == error.Unexpected);
    try testing.expect(narrowBindError(error.ProcessFdQuotaExceeded) == error.Unexpected);
    try testing.expect(narrowBindError(error.AddressInUse) == error.AddressInUse);
    try testing.expect(narrowBindError(error.PermissionDenied) == error.PermissionDenied);
}

test "bindMdnsSocket on an ephemeral port: options apply and first_binder is true" {
    // Port 0 binds an unused port with no other holder, so this runs on
    // every host, sandboxed or not. It exercises every setsockopt in the
    // bind path against the real kernel.
    const b4 = bindMdnsSocket(.v4, .{ .port = 0 }) catch |err| switch (err) {
        // A sandbox that forbids socket(2) is not a codec bug.
        error.PermissionDenied => return error.SkipZigTest,
        else => |e| return e,
    };
    defer closeFd(b4.socket.handle);
    try testing.expect(b4.first_binder);
    try testing.expect(b4.socket.address.ip4.port != 0);

    const b6 = bindMdnsSocket(.v6, .{ .port = 0 }) catch |err| switch (err) {
        // A host without IPv6 is a degrade case, not a test failure.
        error.OptionUnsupported => return,
        else => |e| return e,
    };
    defer closeFd(b6.socket.handle);
    try testing.expect(b6.first_binder);
    try testing.expect(b6.socket.address.ip6.port != 0);

    // Egress selection through the loopback interface (index 1 on every
    // supported OS). Kernels differ on whether loopback is
    // multicast-capable, so only the errno classes an interface can
    // legitimately produce are tolerated; a trap or an unmapped errno is
    // still a failure.
    setMulticastIf(b6.socket.handle, .v6, 1, null) catch |err| switch (err) {
        error.AddressUnavailable, error.NoInterface, error.OptionUnsupported => {},
        else => |e| return e,
    };
    setMulticastIf(b4.socket.handle, .v4, 1, .{ 127, 0, 0, 1 }) catch |err| switch (err) {
        error.AddressUnavailable, error.NoInterface, error.OptionUnsupported => {},
        else => |e| return e,
    };
}

test "send window flag toggles O_NONBLOCK and restores it" {
    // The Service's send window (`service.zig` `openSendWindow`) relies on
    // this pair: set, observe, clear, observe; a no-op set or clear must
    // not fail.
    const fd = rawUdpSocket(.v4) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => |e| return e,
    };
    defer closeFd(fd);
    try testing.expect(!try isNonBlocking(fd));
    try setNonBlockingFlag(fd, true);
    try testing.expect(try isNonBlocking(fd));
    try setNonBlockingFlag(fd, true);
    try testing.expect(try isNonBlocking(fd));
    try setNonBlockingFlag(fd, false);
    try testing.expect(!try isNonBlocking(fd));
    try setNonBlockingFlag(fd, false);
    try testing.expect(!try isNonBlocking(fd));
}

test "bound mDNS socket has its send low-water mark raised to the send buffer" {
    // `raise_send_lowat` (Darwin): after `bindMdnsSocket`, POLLOUT must
    // mean the whole send buffer is free, so the post-poll send of a
    // timed `sendManyTimeout` cannot block (fd blocking) or hit
    // Threaded's `WouldBlock => unreachable` (fd non-blocking). On the
    // other platforms the option is left alone and this only checks
    // that the bind still works and the fd is blocking.
    const b4 = bindMdnsSocket(.v4, .{ .port = 0 }) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => |e| return e,
    };
    defer closeFd(b4.socket.handle);
    try testing.expect(!try isNonBlocking(b4.socket.handle));
    if (comptime raise_send_lowat) {
        const sndbuf = try getsockoptInt(b4.socket.handle, consts.sol_socket, darwin_so_sndbuf);
        const lowat = try getsockoptInt(b4.socket.handle, consts.sol_socket, darwin_so_sndlowat);
        try testing.expect(sndbuf > 0);
        try testing.expectEqual(sndbuf, lowat);
        // Setting it again is idempotent.
        try testing.expectEqual(sndbuf, try raiseSendLowat(b4.socket.handle));
    }
}
