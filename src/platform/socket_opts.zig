//! Raw socket plumbing for mDNS: per-OS option numbers, a checked
//! `setsockopt`, multicast membership structs, the cmsg (ancillary data)
//! codec, and `bindMdnsSocket`, which opens a shared, non-blocking UDP
//! socket on *:5353 and hands it back as a `std.Io.net.Socket`.
//!
//! Every libc call goes through `std.c` and maps errno by hand. Nothing in
//! this file uses `std.posix.setsockopt` (its EINVAL is `unreachable`,
//! STD/posix.zig) and no errno path reaches `unreachable` or `@panic`.
//!
//! Option numbers: Darwin has no `std.posix.IP`/`IPV6` on dev.1786 (both are
//! `void`, STD/c.zig `pub const IP = switch ... else => void`), and
//! `std.c.darwin` is not public, so the Darwin column is hard-coded from the
//! macOS SDK headers with the header line cited beside each value. Linux
//! values come from `std.os.linux` and are cross-checked at comptime.
//! FreeBSD and OpenBSD values come from `std.c` (public on those targets);
//! they are reviewed against the std tables, not run.
const std = @import("std");
const builtin = @import("builtin");
const native_os = builtin.os.tag;
const native_endian = builtin.cpu.arch.endian();
const net = std.Io.net;
const posix = std.posix;
const c = std.c;

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
    /// IP_ADD_MEMBERSHIP accepts `ip_mreqn` (ifindex) instead of `ip_mreq`.
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

    iff_up: u32,
    iff_multicast: u32,
    iff_loopback: u32,

    /// `CMSG_ALIGN` unit and `cmsg_len` field width.
    cmsg: CmsgLayout,
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

    .iff_up = 0x1, // net/if.h:93 IFF_UP
    .iff_multicast = 0x8000, // net/if.h:109 IFF_MULTICAST
    .iff_loopback = 0x8, // net/if.h:96 IFF_LOOPBACK

    // sys/socket.h:673 CMSG_SPACE uses __DARWIN_ALIGN32 (arm/_param.h:21),
    // and cmsg_len is socklen_t (sys/socket.h:609).
    .cmsg = .{ .alignment = 4, .len_size = 4 },
};

/// Linux, from `std.os.linux`. The comptime block below pins the numbers
/// the plan lists so a std table change is caught at build time.
pub const linux_consts: Consts = if (native_os == .linux) .{
    .sol_socket = std.os.linux.SOL.SOCKET,
    .so_reuseaddr = std.os.linux.SO.REUSEADDR,
    .so_reuseport = std.os.linux.SO.REUSEPORT,

    .ipproto_ip = std.os.linux.IPPROTO.IP,
    .ipproto_ipv6 = std.os.linux.IPPROTO.IPV6,

    .ip_ttl = std.os.linux.IP.TTL,
    .ip_multicast_if = std.os.linux.IP.MULTICAST_IF,
    .ip_multicast_ttl = std.os.linux.IP.MULTICAST_TTL,
    .ip_multicast_loop = std.os.linux.IP.MULTICAST_LOOP,
    .ip_add_membership = std.os.linux.IP.ADD_MEMBERSHIP,
    .ip_drop_membership = std.os.linux.IP.DROP_MEMBERSHIP,
    .ip_recvpktinfo = std.os.linux.IP.PKTINFO,
    .ip_pktinfo = std.os.linux.IP.PKTINFO,
    .ip_recvif = null,
    .ip_recvdstaddr = null,
    .ip_recvttl = std.os.linux.IP.RECVTTL,
    .ip_ttl_cmsg = std.os.linux.IP.TTL,
    .ip_multicast_all = std.os.linux.IP.MULTICAST_ALL,
    .ip_multicast_ifindex = null,
    .ip_u8_options = false,
    .has_ip_mreqn = true,

    .ipv6_unicast_hops = std.os.linux.IPV6.UNICAST_HOPS,
    .ipv6_multicast_if = std.os.linux.IPV6.MULTICAST_IF,
    .ipv6_multicast_hops = std.os.linux.IPV6.MULTICAST_HOPS,
    .ipv6_multicast_loop = std.os.linux.IPV6.MULTICAST_LOOP,
    .ipv6_join_group = std.os.linux.IPV6.ADD_MEMBERSHIP,
    .ipv6_leave_group = std.os.linux.IPV6.DROP_MEMBERSHIP,
    .ipv6_v6only = std.os.linux.IPV6.V6ONLY,
    .ipv6_recvpktinfo = std.os.linux.IPV6.RECVPKTINFO,
    .ipv6_pktinfo = std.os.linux.IPV6.PKTINFO,
    .ipv6_recvhoplimit = std.os.linux.IPV6.RECVHOPLIMIT,
    .ipv6_hoplimit = std.os.linux.IPV6.HOPLIMIT,

    .iff_up = 0x1,
    // `std.os.linux.IFF` stops at bit 8; IFF_MULTICAST is bit 12 in
    // linux/if.h. Hard-coded.
    .iff_multicast = 0x1000,
    .iff_loopback = 0x8,

    // Kernel `cmsghdr.cmsg_len` is `__kernel_size_t`; CMSG_ALIGN is
    // sizeof(size_t).
    .cmsg = .{ .alignment = @sizeOf(usize), .len_size = @sizeOf(usize) },
} else undefined;

comptime {
    if (native_os == .linux) {
        const L = std.os.linux;
        // Plan section 9, Linux column.
        std.debug.assert(L.IP.MULTICAST_IF == 32);
        std.debug.assert(L.IP.MULTICAST_TTL == 33);
        std.debug.assert(L.IP.MULTICAST_LOOP == 34);
        std.debug.assert(L.IP.ADD_MEMBERSHIP == 35);
        std.debug.assert(L.IP.DROP_MEMBERSHIP == 36);
        std.debug.assert(L.IP.PKTINFO == 8);
        std.debug.assert(L.IP.RECVTTL == 12);
        std.debug.assert(L.IP.TTL == 2);
        std.debug.assert(L.IP.MULTICAST_ALL == 49);
        std.debug.assert(L.IPV6.UNICAST_HOPS == 16);
        std.debug.assert(L.IPV6.MULTICAST_IF == 17);
        std.debug.assert(L.IPV6.MULTICAST_HOPS == 18);
        std.debug.assert(L.IPV6.MULTICAST_LOOP == 19);
        std.debug.assert(L.IPV6.ADD_MEMBERSHIP == 20);
        std.debug.assert(L.IPV6.DROP_MEMBERSHIP == 21);
        std.debug.assert(L.IPV6.V6ONLY == 26);
        std.debug.assert(L.IPV6.RECVPKTINFO == 49);
        std.debug.assert(L.IPV6.PKTINFO == 50);
        std.debug.assert(L.IPV6.RECVHOPLIMIT == 51);
        std.debug.assert(L.IPV6.HOPLIMIT == 52);
        std.debug.assert(@as(u16, @bitCast(L.IFF{ .UP = true })) == 0x1);
        // SO_* and SOL_SOCKET differ on mips/ppc/sparc/alpha; pin the
        // mainstream ABI only.
        switch (builtin.cpu.arch) {
            .x86_64, .aarch64, .x86, .arm, .riscv64 => {
                std.debug.assert(L.SOL.SOCKET == 1);
                std.debug.assert(L.SO.REUSEADDR == 2);
                std.debug.assert(L.SO.REUSEPORT == 15);
            },
            else => {},
        }
        std.debug.assert(@sizeOf(L.in_pktinfo) == 12);
        std.debug.assert(@sizeOf(L.in6_pktinfo) == 20);
    }
    // Plan section 9, FreeBSD and OpenBSD columns: the tables below read
    // std.c directly, so pin the numbers the plan quotes here.
    if (native_os == .freebsd) {
        std.debug.assert(c.IP.TTL == 4);
        std.debug.assert(c.IP.MULTICAST_IF == 9);
        std.debug.assert(c.IP.MULTICAST_TTL == 10);
        std.debug.assert(c.IP.MULTICAST_LOOP == 11);
        std.debug.assert(c.IP.ADD_MEMBERSHIP == 12);
        std.debug.assert(c.IP.DROP_MEMBERSHIP == 13);
        std.debug.assert(c.IP.RECVIF == 20);
        std.debug.assert(c.IP.RECVDSTADDR == 7);
        std.debug.assert(c.IP.RECVTTL == 65);
        std.debug.assert(c.IPV6.MULTICAST_IF == 9);
        std.debug.assert(c.IPV6.MULTICAST_HOPS == 10);
        std.debug.assert(c.IPV6.MULTICAST_LOOP == 11);
        std.debug.assert(c.IPV6.JOIN_GROUP == 12);
        std.debug.assert(c.IPV6.LEAVE_GROUP == 13);
        std.debug.assert(c.IPV6.V6ONLY == 27);
        std.debug.assert(c.IPV6.RECVPKTINFO == 36);
        std.debug.assert(c.IPV6.PKTINFO == 46);
        std.debug.assert(c.IPV6.RECVHOPLIMIT == 37);
        std.debug.assert(c.IPV6.HOPLIMIT == 47);
        std.debug.assert(c.SOL.SOCKET == 0xffff);
        std.debug.assert(c.SO.REUSEADDR == 0x0004);
        std.debug.assert(c.SO.REUSEPORT == 0x0200);
    }
    if (native_os == .openbsd) {
        std.debug.assert(c.IP.TTL == 4);
        std.debug.assert(c.IP.MULTICAST_IF == 9);
        std.debug.assert(c.IP.MULTICAST_TTL == 10);
        std.debug.assert(c.IP.MULTICAST_LOOP == 11);
        std.debug.assert(c.IP.ADD_MEMBERSHIP == 12);
        std.debug.assert(c.IP.DROP_MEMBERSHIP == 13);
        std.debug.assert(c.IP.RECVIF == 30);
        std.debug.assert(c.IP.RECVDSTADDR == 7);
        std.debug.assert(c.IP.RECVTTL == 31);
        std.debug.assert(c.IPV6.MULTICAST_IF == 9);
        std.debug.assert(c.IPV6.MULTICAST_HOPS == 10);
        std.debug.assert(c.IPV6.MULTICAST_LOOP == 11);
        std.debug.assert(c.IPV6.JOIN_GROUP == 12);
        std.debug.assert(c.IPV6.LEAVE_GROUP == 13);
        std.debug.assert(c.IPV6.V6ONLY == 27);
        std.debug.assert(c.IPV6.RECVPKTINFO == 36);
        std.debug.assert(c.IPV6.PKTINFO == 46);
        std.debug.assert(c.IPV6.RECVHOPLIMIT == 37);
        std.debug.assert(c.IPV6.HOPLIMIT == 47);
        std.debug.assert(c.SOL.SOCKET == 0xffff);
        std.debug.assert(c.SO.REUSEADDR == 0x0004);
        std.debug.assert(c.SO.REUSEPORT == 0x0200);
    }
}

/// FreeBSD, from `std.c` (STD/c/freebsd.zig). Reviewed, not run.
pub const freebsd_consts: Consts = if (native_os == .freebsd) .{
    .sol_socket = c.SOL.SOCKET,
    .so_reuseaddr = c.SO.REUSEADDR,
    .so_reuseport = c.SO.REUSEPORT,

    .ipproto_ip = c.IPPROTO.IP,
    .ipproto_ipv6 = c.IPPROTO.IPV6,

    .ip_ttl = c.IP.TTL,
    .ip_multicast_if = c.IP.MULTICAST_IF,
    .ip_multicast_ttl = c.IP.MULTICAST_TTL,
    .ip_multicast_loop = c.IP.MULTICAST_LOOP,
    .ip_add_membership = c.IP.ADD_MEMBERSHIP,
    .ip_drop_membership = c.IP.DROP_MEMBERSHIP,
    .ip_recvpktinfo = null, // no IP_PKTINFO on FreeBSD
    .ip_pktinfo = null,
    .ip_recvif = c.IP.RECVIF,
    .ip_recvdstaddr = c.IP.RECVDSTADDR,
    .ip_recvttl = c.IP.RECVTTL,
    .ip_ttl_cmsg = c.IP.RECVTTL,
    .ip_multicast_all = null,
    .ip_multicast_ifindex = null,
    .ip_u8_options = true,
    .has_ip_mreqn = false,

    .ipv6_unicast_hops = c.IPV6.UNICAST_HOPS,
    .ipv6_multicast_if = c.IPV6.MULTICAST_IF,
    .ipv6_multicast_hops = c.IPV6.MULTICAST_HOPS,
    .ipv6_multicast_loop = c.IPV6.MULTICAST_LOOP,
    .ipv6_join_group = c.IPV6.JOIN_GROUP,
    .ipv6_leave_group = c.IPV6.LEAVE_GROUP,
    .ipv6_v6only = c.IPV6.V6ONLY,
    .ipv6_recvpktinfo = c.IPV6.RECVPKTINFO,
    .ipv6_pktinfo = c.IPV6.PKTINFO,
    .ipv6_recvhoplimit = c.IPV6.RECVHOPLIMIT,
    .ipv6_hoplimit = c.IPV6.HOPLIMIT,

    .iff_up = 0x1,
    .iff_multicast = 0x8000,
    .iff_loopback = 0x8,

    // sys/socket.h: cmsg_len is socklen_t; _ALIGN pads to the register size.
    .cmsg = .{ .alignment = @sizeOf(usize), .len_size = 4 },
} else undefined;

/// OpenBSD, from `std.c` (STD/c/openbsd.zig). Reviewed, not run.
pub const openbsd_consts: Consts = if (native_os == .openbsd) .{
    .sol_socket = c.SOL.SOCKET,
    .so_reuseaddr = c.SO.REUSEADDR,
    .so_reuseport = c.SO.REUSEPORT,

    .ipproto_ip = c.IPPROTO.IP,
    .ipproto_ipv6 = c.IPPROTO.IPV6,

    .ip_ttl = c.IP.TTL,
    .ip_multicast_if = c.IP.MULTICAST_IF,
    .ip_multicast_ttl = c.IP.MULTICAST_TTL,
    .ip_multicast_loop = c.IP.MULTICAST_LOOP,
    .ip_add_membership = c.IP.ADD_MEMBERSHIP,
    .ip_drop_membership = c.IP.DROP_MEMBERSHIP,
    .ip_recvpktinfo = null, // no IP_PKTINFO on OpenBSD
    .ip_pktinfo = null,
    .ip_recvif = c.IP.RECVIF,
    .ip_recvdstaddr = c.IP.RECVDSTADDR,
    .ip_recvttl = c.IP.RECVTTL,
    .ip_ttl_cmsg = c.IP.RECVTTL,
    .ip_multicast_all = null,
    .ip_multicast_ifindex = null,
    .ip_u8_options = true,
    .has_ip_mreqn = false,

    .ipv6_unicast_hops = c.IPV6.UNICAST_HOPS,
    .ipv6_multicast_if = c.IPV6.MULTICAST_IF,
    .ipv6_multicast_hops = c.IPV6.MULTICAST_HOPS,
    .ipv6_multicast_loop = c.IPV6.MULTICAST_LOOP,
    .ipv6_join_group = c.IPV6.JOIN_GROUP,
    .ipv6_leave_group = c.IPV6.LEAVE_GROUP,
    .ipv6_v6only = c.IPV6.V6ONLY,
    .ipv6_recvpktinfo = c.IPV6.RECVPKTINFO,
    .ipv6_pktinfo = c.IPV6.PKTINFO,
    .ipv6_recvhoplimit = c.IPV6.RECVHOPLIMIT,
    .ipv6_hoplimit = c.IPV6.HOPLIMIT,

    .iff_up = 0x1,
    .iff_multicast = 0x8000,
    .iff_loopback = 0x8,

    // sys/socket.h: cmsg_len is socklen_t; _ALIGN pads to sizeof(long).
    .cmsg = .{ .alignment = @sizeOf(usize), .len_size = 4 },
} else undefined;

/// The table for the target OS.
pub const consts: Consts = switch (native_os) {
    .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => darwin_consts,
    .linux => linux_consts,
    .freebsd => freebsd_consts,
    .openbsd => openbsd_consts,
    else => @compileError("mdns-zig platform/socket_opts.zig: unsupported OS " ++ @tagName(native_os)),
};

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

comptime {
    std.debug.assert(@sizeOf(ip_mreq) == 8);
    std.debug.assert(@sizeOf(ip_mreqn) == 12);
    std.debug.assert(@sizeOf(ipv6_mreq) == 20);
    std.debug.assert(@sizeOf(in_pktinfo) == 12);
    std.debug.assert(@sizeOf(in6_pktinfo) == 20);
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

/// Decode IP_PKTINFO / IPV6_PKTINFO / IP_RECVIF / IP_RECVDSTADDR and the
/// TTL / hop-limit cmsgs from a control buffer filled by `recvmsg`, using
/// the native layout and constant table.
pub fn decodeRxInfo(control: []const u8) RxInfo {
    return decodeRxInfoWith(consts, control);
}

/// `decodeRxInfo` with an explicit table (tests exercise foreign layouts).
pub fn decodeRxInfoWith(table: Consts, control: []const u8) RxInfo {
    var info: RxInfo = .{};
    var it: CmsgIterator = .init(table.cmsg, control);
    while (it.next()) |m| {
        if (m.level < 0) continue;
        const level: u32 = @intCast(m.level);
        if (m.type < 0) continue;
        const typ: u32 = @intCast(m.type);
        if (level == table.ipproto_ip) {
            if (table.ip_pktinfo != null and typ == table.ip_pktinfo.? and m.data.len >= @sizeOf(in_pktinfo)) {
                const pi: *align(1) const in_pktinfo = @ptrCast(m.data.ptr);
                info.ifindex = pi.ifindex;
                info.dst = .{ .v4 = pi.addr };
            } else if (table.ip_recvif != null and typ == table.ip_recvif.? and m.data.len >= 4) {
                // sockaddr_dl: sdl_len u8, sdl_family u8, sdl_index u16.
                info.ifindex = std.mem.readInt(u16, m.data[2..4], native_endian);
            } else if (table.ip_recvdstaddr != null and typ == table.ip_recvdstaddr.? and m.data.len >= 4) {
                info.dst = .{ .v4 = m.data[0..4].* };
            } else if (typ == table.ip_ttl_cmsg and m.data.len >= 1) {
                // u_char on the BSDs and Darwin, int on Linux.
                info.ttl = if (m.data.len >= 4)
                    @truncate(std.mem.readInt(u32, m.data[0..4], native_endian))
                else
                    m.data[0];
            }
        } else if (level == table.ipproto_ipv6) {
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

/// Bytes needed for one pktinfo cmsg plus one TTL cmsg under any layout.
pub const control_buffer_size: usize = 64;

/// Encode an IPV6_PKTINFO cmsg that selects the egress interface.
pub fn encodePktInfo6(buf: []u8, ifindex: u32) error{NoSpace}![]u8 {
    var e: CmsgEncoder = .init(consts.cmsg, buf);
    const pi: in6_pktinfo = .{ .addr = @splat(0), .ifindex = ifindex };
    try e.append(@intCast(consts.ipproto_ipv6), @intCast(consts.ipv6_pktinfo), std.mem.asBytes(&pi));
    return e.bytes();
}

/// Encode an IP_PKTINFO cmsg that selects the egress interface (and,
/// optionally, the source address). `error.OptionUnsupported` on an OS
/// without IP_PKTINFO (FreeBSD, OpenBSD: use `setMulticastIf` instead).
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
    const flags = c.fcntl(fd, c.F.GETFL, @as(c_int, 0));
    switch (c.errno(flags)) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }
    const Backing = @typeInfo(posix.O).@"struct".backing_integer.?;
    const nonblock: Backing = @bitCast(posix.O{ .NONBLOCK = true });
    const new_flags: c_int = @bitCast(@as(u32, @bitCast(flags)) | @as(u32, nonblock));
    switch (c.errno(c.fcntl(fd, c.F.SETFL, new_flags))) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }
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
    /// Set `O_NONBLOCK` on the fd. OFF by default: Threaded's timed calls
    /// pass MSG_DONTWAIT on the first attempt (`STD/Io/Threaded.zig:13188`)
    /// and, after `poll(2)` reports readiness, call `operate`, whose
    /// blocking-flag `recvmsg` maps `error.WouldBlock => unreachable`
    /// (`Threaded.zig:2555` receive, `:2573` send). Linux `udp_poll` only
    /// filters bad-checksum false positives for BLOCKING fds (net/ipv4/udp.c:
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

pub const BindMdnsError = SocketError || BindError || SetsockoptError || error{OptionUnsupported};

/// Open, configure and bind one mDNS socket on `*:port`:
/// SO_REUSEADDR + SO_REUSEPORT, IPV6_V6ONLY, TTL/hops 255 for multicast
/// and unicast, multicast loop, pktinfo and TTL delivery, optional
/// O_NONBLOCK (see `BindOptions.nonblocking`), bind, getsockname. The result wraps the fd as `Io.net.Socket` so
/// `receiveManyTimeout` / `sendManyTimeout` drive it (timed calls only,
/// plan section 4.3).
pub fn bindMdnsSocket(family: Family, opts: BindOptions) BindMdnsError!BoundSocket {
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
        },
    }

    if (opts.nonblocking) try setNonBlocking(fd);

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
/// v4: `ip_mreqn` (Linux), IP_MULTICAST_IFINDEX (Darwin, when no address
/// is given), else IP_MULTICAST_IF with the interface's v4 address.
/// v6: IPV6_MULTICAST_IF with the ifindex.
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
}

test "cmsg codec round trip at 4-byte alignment" {
    try roundTrip(layout4);
}

test "cmsg codec round trip at 8-byte alignment" {
    try roundTrip(layout8);
    try roundTrip(layout8_len4);
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

test "mreq struct sizes" {
    try testing.expectEqual(@as(usize, 8), @sizeOf(ip_mreq));
    try testing.expectEqual(@as(usize, 12), @sizeOf(ip_mreqn));
    try testing.expectEqual(@as(usize, 20), @sizeOf(ipv6_mreq));
    try testing.expectEqual(@as(usize, 12), @sizeOf(in_pktinfo));
    try testing.expectEqual(@as(usize, 20), @sizeOf(in6_pktinfo));
    try testing.expectEqual(@as(usize, 4), @offsetOf(in_pktinfo, "spec_dst"));
    try testing.expectEqual(@as(usize, 16), @offsetOf(in6_pktinfo, "ifindex"));
}

test "native cmsg layout is what the OS uses" {
    if (is_darwin) {
        try testing.expectEqual(@as(usize, 4), consts.cmsg.alignment);
        try testing.expectEqual(@as(usize, 4), consts.cmsg.len_size);
    } else {
        try testing.expectEqual(@sizeOf(usize), consts.cmsg.alignment);
    }
    try testing.expect(control_buffer_size >= consts.cmsg.space(@sizeOf(in6_pktinfo)) + consts.cmsg.space(4));
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
    }
}
