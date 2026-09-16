//! Interface enumeration over `getifaddrs` (plan section 4.8, "Interface
//! model", "Interface allow-list", "Address overflow per interface").
//!
//! `snapshot` walks the libc list and folds it into a fixed table of
//! `Interface` values: up and multicast-capable interfaces only, loopback
//! only on request, an optional `ifindex` allow-list, v6 addresses
//! ordered global-first and link-local-last, at most 8 addresses per
//! family with the overflow counted in `v4_dropped` / `v6_dropped`.
//! `diff` compares two snapshots by `ifindex` so `Service.refreshInterfaces`
//! can join, leave and re-announce.
//!
//! The fold itself (`fromIfaddrs`) is pure: it consumes any iterator of
//! `Record` values, so the unit tests feed synthetic records and never
//! touch libc. `snapshot` is the only function that calls `getifaddrs`.
//!
//! std on this pin declares none of `getifaddrs`, `freeifaddrs`,
//! `struct ifaddrs`, `IFF_MULTICAST` (Revision 3 item 5), so they are
//! declared here against the SDK headers cited below.
//!
//! No allocation, no `unreachable` on libc data: a record the kernel
//! reports in a shape this file does not understand is skipped.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const events = @import("../core/events.zig");

pub const Interface = events.Interface;
pub const Prefix4 = events.Prefix4;
pub const Prefix6 = events.Prefix6;
pub const Family = events.Family;

const native_os = builtin.os.tag;
const is_bsd_like = native_os.isDarwin() or native_os == .freebsd or native_os == .openbsd or native_os == .netbsd or native_os == .dragonfly;

comptime {
    if (!is_bsd_like and native_os != .linux) {
        @compileError("mdns.platform.ifaces: unsupported OS " ++ @tagName(native_os));
    }
}

// ---- interface flags ---------------------------------------------------
//
// Darwin: MacOSX.sdk/usr/include/net/if.h:93 (UP), :96 (LOOPBACK), :109
// (MULTICAST). FreeBSD: libc/include/generic-freebsd/net/if.h:139/142/155.
// OpenBSD: libc/include/generic-openbsd/net/if.h:203/206/218. Linux (musl
// and glibc): libc/include/generic-musl/net/if.h:29/32/41.

/// Interface is up.
pub const IFF_UP: u32 = 0x1;
/// Interface is a loopback device.
pub const IFF_LOOPBACK: u32 = 0x8;
/// Interface supports multicast. `std.os.linux.IFF` has no MULTICAST bit
/// on this pin (it stops at PROMISC), so the Linux value is hard-coded from
/// musl's net/if.h; only UP and LOOPBACK can be cross-checked against std.
pub const IFF_MULTICAST: u32 = switch (native_os) {
    .linux => 0x1000,
    else => 0x8000,
};

comptime {
    if (native_os == .linux) {
        const L = std.os.linux.IFF;
        std.debug.assert(@as(u16, @bitCast(L{ .UP = true })) == IFF_UP);
        std.debug.assert(@as(u16, @bitCast(L{ .LOOPBACK = true })) == IFF_LOOPBACK);
    }
}

// ---- libc declarations ------------------------------------------------

/// `struct ifaddrs`. The seven fields sit in the same order on every
/// supported libc; only the sixth differs in name: `ifa_dstaddr` on
/// Darwin (MacOSX.sdk/usr/include/ifaddrs.h:36-44), FreeBSD
/// (generic-freebsd/ifaddrs.h:31-39) and OpenBSD
/// (generic-openbsd/ifaddrs.h:31-39), and the `ifa_ifu` union of two
/// `struct sockaddr *` on musl (musl/include/ifaddrs.h:12-23) and glibc
/// (generic-glibc/ifaddrs.h:29-57, including the union and the
/// `ifa_broadaddr` / `ifa_dstaddr` macros). A union of two pointers has
/// the size and alignment of one pointer, so one layout covers all four.
/// `ifa_flags` is `unsigned int` everywhere; the following pointer field
/// re-aligns to the pointer size, which `ifaddrs layout sizes per OS`
/// checks.
///
/// The `sockaddr` pointers are declared `align(1)`: libc only guarantees
/// what `sa_len` / the family implies, and a misaligned `@alignCast` would
/// be a runtime panic on kernel data.
pub const ifaddrs = extern struct {
    next: ?*const ifaddrs,
    name: [*:0]const u8,
    flags: c_uint,
    addr: ?*align(1) const posix.sockaddr,
    netmask: ?*align(1) const posix.sockaddr,
    /// `ifa_dstaddr` (BSD) / `ifa_ifu` (Linux). Unused here.
    dstaddr: ?*align(1) const posix.sockaddr,
    data: ?*anyopaque,
};

extern "c" fn getifaddrs(ifap: *?*const ifaddrs) c_int;
extern "c" fn freeifaddrs(ifa: *const ifaddrs) void;
/// Present in libc on all four OSes (POSIX.1-2001 `net/if.h`). Returns 0
/// on failure.
extern "c" fn if_nametoindex(name: [*:0]const u8) c_uint;

// ---- public surface ---------------------------------------------------

/// What `Service.Options` forwards.
pub const Options = struct {
    /// Keep loopback interfaces (`IFF_LOOPBACK`). Off by default: the
    /// loopback never carries LAN peers, and mDNS on it only sees our own
    /// echoes.
    include_loopback: bool = false,
    /// Collect IPv6 addresses. With `false` every `Interface.v6` is empty
    /// and `v6_dropped` stays 0.
    ipv6: bool = true,
    /// Allow-list of `ifindex` values. `null` keeps every up,
    /// multicast-capable interface. A listed index that `getifaddrs` does
    /// not report is simply absent from the snapshot (not an error);
    /// `refreshInterfaces` picks it up when it appears.
    allow: ?[]const u32 = null,
};

/// Maximum interfaces one snapshot holds (`Limits.max_interfaces`).
pub const max_interfaces = 32;

/// A fixed table of `Interface` values. Entry order is first-seen order
/// from the source; addresses within an entry follow the rules in the
/// file comment.
pub const Snapshot = struct {
    items: [max_interfaces]Interface = undefined,
    len: u8 = 0,

    pub const empty: Snapshot = .{};

    pub fn slice(s: *const Snapshot) []const Interface {
        return s.items[0..s.len];
    }

    /// The entry with this `ifindex`, if present.
    pub fn find(s: *const Snapshot, index: u32) ?*const Interface {
        for (s.items[0..s.len]) |*i| if (i.index == index) return i;
        return null;
    }

    fn findMut(s: *Snapshot, index: u32) ?*Interface {
        for (s.items[0..s.len]) |*i| if (i.index == index) return i;
        return null;
    }
};

pub const SnapshotError = error{
    /// `getifaddrs` failed.
    Unexpected,
    /// More than `max_interfaces` qualifying interfaces.
    LimitReached,
};

/// One `getifaddrs` entry in a libc-free shape: what `fromIfaddrs` folds.
/// `snapshot` decodes these from the real list; tests build them by hand.
pub const Record = struct {
    /// `if_nametoindex(ifa_name)`. 0 means unknown and the record is
    /// skipped (a v6 join with ifindex 0 would let the kernel pick).
    index: u32,
    name: []const u8,
    /// `ifa_flags` (`IFF_*` bits above).
    flags: u32,
    addr: Addr,

    pub const Addr = union(enum) {
        v4: V4,
        v6: V6,
        /// AF_LINK / AF_PACKET / anything else: skipped.
        other: void,

        pub const V4 = struct {
            addr: [4]u8,
            /// `null` when the kernel reported no usable netmask; treated
            /// as `/32` (only the address itself is on-link).
            netmask: ?[4]u8 = null,
        };
        pub const V6 = struct {
            addr: [16]u8,
            /// `null` is treated as `/128`.
            netmask: ?[16]u8 = null,
            /// `sin6_scope_id`; informational (the `Interface.index` is the
            /// scope mDNS uses).
            scope_id: u32 = 0,
        };
    };

    pub fn isUp(r: Record) bool {
        return (r.flags & IFF_UP) != 0;
    }

    pub fn isMulticast(r: Record) bool {
        return (r.flags & IFF_MULTICAST) != 0;
    }

    pub fn isLoopback(r: Record) bool {
        return (r.flags & IFF_LOOPBACK) != 0;
    }
};

/// Iterator over a slice of records, for tests and for callers that
/// already have their own interface source.
pub const RecordIterator = struct {
    items: []const Record,
    pos: usize = 0,

    pub fn next(it: *RecordIterator) ?Record {
        if (it.pos >= it.items.len) return null;
        const r = it.items[it.pos];
        it.pos += 1;
        return r;
    }
};

/// Fold records from any `it.next() -> ?Record` iterator into a
/// `Snapshot` under `opts`. Pure: no libc, no allocation.
///
/// Rules, in order, per record: skip index 0; skip unless `IFF_UP`; skip
/// loopback unless `include_loopback` (which also waives `IFF_MULTICAST`,
/// absent on Linux `lo`); skip other interfaces without `IFF_MULTICAST`;
/// skip an index
/// not on the allow-list; skip `other` families and, with `ipv6 == false`,
/// v6. The first kept record creates the `Interface` entry (name truncated
/// to 15 octets); an entry beyond `max_interfaces` is `error.LimitReached`.
/// v4 addresses fill in arrival order up to 8, then count in `v4_dropped`.
/// v6 addresses keep global (including ULA) before link-local: a global
/// address arriving at a full list evicts the last link-local entry (which
/// counts as dropped); a link-local address arriving at a full list is
/// dropped. Within a class arrival order is kept. A link-local address has
/// any KAME-embedded scope in octets 2-3 cleared.
pub fn fromIfaddrs(it: anytype, opts: Options) error{LimitReached}!Snapshot {
    var snap: Snapshot = .{};
    while (it.next()) |rec| {
        try foldRecord(&snap, rec, opts);
    }
    return snap;
}

fn foldRecord(snap: *Snapshot, rec: Record, opts: Options) error{LimitReached}!void {
    if (rec.index == 0) return;
    if (!rec.isUp()) return;
    if (rec.isLoopback()) {
        // Opting in to loopback waives the IFF_MULTICAST test for v4:
        // Linux `lo` reports <LOOPBACK,UP,LOWER_UP> (0x9) without it
        // (measured in the zig-uring VM, kernel 6.19) yet joins and
        // delivers 224.0.0.251, while Darwin lo0 carries 0x8049
        // (UP|LOOPBACK|RUNNING|MULTICAST). The waiver does not extend to
        // v6: without IFF_MULTICAST the kernel has no ff02::/16 route on
        // the device, `IPV6_ADD_MEMBERSHIP` still succeeds but every send
        // to ff02::fb via `lo` fails with ENETUNREACH (measured, M2), so
        // keeping the address would only feed `stats.tx_dropped`.
        if (!opts.include_loopback) return;
        if (!rec.isMulticast() and rec.addr == .v6) return;
    } else if (!rec.isMulticast()) return;
    if (opts.allow) |allow| {
        if (std.mem.indexOfScalar(u32, allow, rec.index) == null) return;
    }
    switch (rec.addr) {
        .other => return,
        .v6 => if (!opts.ipv6) return,
        .v4 => {},
    }

    const iface = snap.findMut(rec.index) orelse blk: {
        if (snap.len >= max_interfaces) return error.LimitReached;
        const slot = &snap.items[snap.len];
        slot.* = .{ .index = rec.index };
        const n = @min(rec.name.len, events.max_iface_name_len);
        // Cannot fail: n <= capacity.
        slot.name.appendSlice(rec.name[0..n]) catch {};
        snap.len += 1;
        break :blk slot;
    };

    switch (rec.addr) {
        .other => {},
        .v4 => |a| {
            const p: Prefix4 = .{
                .addr = a.addr,
                .prefix_len = if (a.netmask) |m| prefixLenFromMask(&m) else 32,
            };
            if (iface.hasAddr4(a.addr)) return; // duplicate report
            iface.v4.append(p) catch {
                iface.v4_dropped +|= 1;
            };
        },
        .v6 => |a| {
            var addr = a.addr;
            if (events.isLinkLocal6(addr)) {
                // KAME-style embedded scope (octets 2-3 hold the ifindex
                // in kernel-internal form on the BSDs). Darwin's libc
                // already returns a clean address plus `sin6_scope_id`
                // (measured, see the M2 platform-matrix entry); clearing
                // here keeps the other BSDs honest. The scope is the
                // interface index the entry lives under.
                addr[2] = 0;
                addr[3] = 0;
            }
            const p: Prefix6 = .{
                .addr = addr,
                .prefix_len = if (a.netmask) |m| prefixLenFromMask(&m) else 128,
            };
            if (iface.hasAddr6(addr)) return; // duplicate report
            insertV6(iface, p);
        },
    }
}

/// Keep `Interface.v6` ordered global-first, link-local-last, capped at 8.
fn insertV6(iface: *Interface, p: Prefix6) void {
    const cap = events.max_addrs_per_family;
    if (p.isLinkLocal()) {
        // Link-local goes at the end; if full it is the one dropped.
        iface.v6.append(p) catch {
            iface.v6_dropped +|= 1;
        };
        return;
    }
    // Global: insert after the last global entry (before the first
    // link-local), keeping arrival order among globals.
    var at: usize = 0;
    while (at < iface.v6.len and !iface.v6.buf[at].isLinkLocal()) : (at += 1) {}
    if (iface.v6.len == cap) {
        // Full: only room if the last entry is link-local (evict it).
        if (!iface.v6.buf[cap - 1].isLinkLocal()) {
            iface.v6_dropped +|= 1;
            return;
        }
        iface.v6_dropped +|= 1;
        iface.v6.len -= 1;
    }
    // Shift the link-local tail up by one and drop `p` into `at`.
    var i = iface.v6.len;
    while (i > at) : (i -= 1) iface.v6.buf[i] = iface.v6.buf[i - 1];
    iface.v6.buf[at] = p;
    iface.v6.len += 1;
}

/// Netmask to prefix length: the count of leading one bits. A
/// non-contiguous mask (a zero followed by a one) is not a prefix; it is
/// treated as the full width (`/32` or `/128`), so the section 11 on-link
/// check only ever accepts the address itself rather than a wrong subnet.
pub fn prefixLenFromMask(mask: []const u8) u8 {
    const full: u8 = @intCast(@min(mask.len * 8, 255));
    var ones: u8 = 0;
    var i: usize = 0;
    while (i < mask.len and mask[i] == 0xff) : (i += 1) ones += 8;
    if (i == mask.len) return ones;
    // The transition octet must be of the form 1..10..0.
    const b = mask[i];
    const lz: u8 = @clz(~b);
    const expected: u8 = if (lz == 0) 0 else @as(u8, 0xff) << @intCast(8 - lz);
    if (b != expected) return full;
    ones += lz;
    i += 1;
    while (i < mask.len) : (i += 1) if (mask[i] != 0) return full;
    return ones;
}

/// Walk the real `getifaddrs` list into a `Snapshot`. `error.Unexpected`
/// when libc fails; the list is always freed.
pub fn snapshot(opts: Options) SnapshotError!Snapshot {
    var list: ?*const ifaddrs = null;
    if (getifaddrs(&list) != 0) return error.Unexpected;
    defer if (list) |l| freeifaddrs(l);
    var it: IfaddrsIterator = .{ .cur = list };
    return fromIfaddrs(&it, opts);
}

/// Iterator over a live `ifaddrs` list.
pub const IfaddrsIterator = struct {
    cur: ?*const ifaddrs,

    pub fn next(it: *IfaddrsIterator) ?Record {
        const ifa = it.cur orelse return null;
        it.cur = ifa.next;
        return decodeIfaddrs(ifa);
    }
};

/// One libc entry to a `Record`. Never fails: an entry this file cannot
/// decode becomes `.other` (and is skipped by the fold). `if_nametoindex`
/// is resolved only for AF_INET / AF_INET6 entries: on Linux each call is
/// a socket + SIOCGIFINDEX ioctl + close, and getifaddrs lists an
/// AF_LINK / AF_PACKET entry per interface that the fold drops anyway, so
/// `.other` records carry `index = 0` without paying for it.
pub fn decodeIfaddrs(ifa: *const ifaddrs) Record {
    var rec: Record = .{
        .index = 0,
        .name = std.mem.span(ifa.name),
        .flags = ifa.flags,
        .addr = .other,
    };
    const sa = ifa.addr orelse return rec;
    if (sa.family != posix.AF.INET and sa.family != posix.AF.INET6) return rec;
    rec.index = if_nametoindex(ifa.name);
    if (sa.family == posix.AF.INET) {
        const In = posix.sockaddr.in;
        const addr = readAddrBytes(sa, @offsetOf(In, "addr"), 4, @sizeOf(In)) orelse return rec;
        rec.addr = .{ .v4 = .{
            .addr = addr,
            .netmask = if (ifa.netmask) |m| readMaskBytes(m, @offsetOf(In, "addr"), 4, @sizeOf(In)) else null,
        } };
    } else if (sa.family == posix.AF.INET6) {
        const In6 = posix.sockaddr.in6;
        const addr = readAddrBytes(sa, @offsetOf(In6, "addr"), 16, @sizeOf(In6)) orelse return rec;
        const scope_off = @offsetOf(In6, "scope_id");
        const scope: u32 = if (readAddrBytes(sa, scope_off, 4, @sizeOf(In6))) |b|
            std.mem.readInt(u32, &b, builtin.cpu.arch.endian())
        else
            0;
        rec.addr = .{ .v6 = .{
            .addr = addr,
            .netmask = if (ifa.netmask) |m| readMaskBytes(m, @offsetOf(In6, "addr"), 16, @sizeOf(In6)) else null,
            .scope_id = scope,
        } };
    }
    return rec;
}

/// Octets the kernel wrote: the BSD `sa_len`, or the full struct on
/// Linux, whose `sockaddr` has no length field.
fn sockaddrLen(sa: *align(1) const posix.sockaddr, full: usize) usize {
    if (@hasField(posix.sockaddr, "len")) return sa.len;
    return full;
}

/// `n` octets at `off` of an address sockaddr, only when `sa_len` covers
/// them all. A short address is not an address.
fn readAddrBytes(sa: *align(1) const posix.sockaddr, comptime off: usize, comptime n: usize, full: usize) ?[n]u8 {
    if (sockaddrLen(sa, full) < off + n) return null;
    const bytes: [*]const u8 = @ptrCast(sa);
    return bytes[off..][0..n].*;
}

/// `n` octets at `off` of a netmask sockaddr. Darwin (and the other BSDs)
/// trim a netmask to its last non-zero octet: `255.0.0.0` arrives with
/// `sa_len` 5 and `255.255.255.0` with 7 (measured on macOS 26 through
/// `getifaddrs`, see docs/platform-matrix.md). The missing tail is zero.
/// A netmask shorter than `off` carries no octets and is reported as
/// missing (the fold treats that as the host prefix).
fn readMaskBytes(sa: *align(1) const posix.sockaddr, comptime off: usize, comptime n: usize, full: usize) ?[n]u8 {
    const len = sockaddrLen(sa, full);
    if (len < off) return null;
    const have = @min(len - off, n);
    var out: [n]u8 = @splat(0);
    const bytes: [*]const u8 = @ptrCast(sa);
    @memcpy(out[0..have], bytes[off..][0..have]);
    return out;
}

// ---- diff ----------------------------------------------------------------

/// What changed between two snapshots, by `ifindex`.
pub const Diff = struct {
    added: [max_interfaces]u32 = undefined,
    added_len: u8 = 0,
    removed: [max_interfaces]u32 = undefined,
    removed_len: u8 = 0,
    /// Same index in both, different address set (order-insensitive,
    /// prefix lengths included). Name and drop counts do not count.
    changed: [max_interfaces]u32 = undefined,
    changed_len: u8 = 0,

    pub fn addedSlice(d: *const Diff) []const u32 {
        return d.added[0..d.added_len];
    }
    pub fn removedSlice(d: *const Diff) []const u32 {
        return d.removed[0..d.removed_len];
    }
    pub fn changedSlice(d: *const Diff) []const u32 {
        return d.changed[0..d.changed_len];
    }
    pub fn isEmpty(d: *const Diff) bool {
        return d.added_len == 0 and d.removed_len == 0 and d.changed_len == 0;
    }
};

pub fn diff(old: *const Snapshot, new: *const Snapshot) Diff {
    var d: Diff = .{};
    for (new.slice()) |n| {
        if (old.find(n.index)) |o| {
            if (!o.sameAddrs(&n)) {
                d.changed[d.changed_len] = n.index;
                d.changed_len += 1;
            }
        } else {
            d.added[d.added_len] = n.index;
            d.added_len += 1;
        }
    }
    for (old.slice()) |o| {
        if (new.find(o.index) == null) {
            d.removed[d.removed_len] = o.index;
            d.removed_len += 1;
        }
    }
    return d;
}

// ---- tests -----------------------------------------------------------------

const testing = std.testing;

const up_mcast: u32 = IFF_UP | IFF_MULTICAST;

fn v4rec(index: u32, name: []const u8, flags: u32, addr: [4]u8, mask: ?[4]u8) Record {
    return .{ .index = index, .name = name, .flags = flags, .addr = .{ .v4 = .{ .addr = addr, .netmask = mask } } };
}

fn v6rec(index: u32, name: []const u8, flags: u32, addr: [16]u8, mask: ?[16]u8) Record {
    return .{ .index = index, .name = name, .flags = flags, .addr = .{ .v6 = .{ .addr = addr, .netmask = mask } } };
}

fn ll6(last: u8) [16]u8 {
    var a: [16]u8 = @splat(0);
    a[0] = 0xfe;
    a[1] = 0x80;
    a[15] = last;
    return a;
}

fn g6(last: u8) [16]u8 {
    var a: [16]u8 = @splat(0);
    a[0] = 0x20;
    a[1] = 0x01;
    a[2] = 0x0d;
    a[3] = 0xb8;
    a[15] = last;
    return a;
}

const mask64: [16]u8 = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0 };

fn fold(recs: []const Record, opts: Options) error{LimitReached}!Snapshot {
    var it: RecordIterator = .{ .items = recs };
    return fromIfaddrs(&it, opts);
}

test "ifaddrs layout sizes per OS" {
    // Seven pointer-sized slots on every supported libc (file comment on
    // `ifaddrs`): `unsigned int ifa_flags` is followed by a pointer, which
    // re-aligns to the pointer width.
    const p = @sizeOf(*anyopaque);
    comptime std.debug.assert(@sizeOf(ifaddrs) == 7 * p);
    comptime std.debug.assert(@alignOf(ifaddrs) == @alignOf(*anyopaque));
    comptime std.debug.assert(@offsetOf(ifaddrs, "next") == 0);
    comptime std.debug.assert(@offsetOf(ifaddrs, "name") == 1 * p);
    comptime std.debug.assert(@offsetOf(ifaddrs, "flags") == 2 * p);
    comptime std.debug.assert(@sizeOf(c_uint) == 4);
    comptime std.debug.assert(@offsetOf(ifaddrs, "addr") == 3 * p);
    comptime std.debug.assert(@offsetOf(ifaddrs, "netmask") == 4 * p);
    comptime std.debug.assert(@offsetOf(ifaddrs, "dstaddr") == 5 * p);
    comptime std.debug.assert(@offsetOf(ifaddrs, "data") == 6 * p);
    // Flag values per OS (headers cited above the constants).
    try testing.expectEqual(@as(u32, 0x1), IFF_UP);
    try testing.expectEqual(@as(u32, 0x8), IFF_LOOPBACK);
    try testing.expectEqual(@as(u32, if (native_os == .linux) 0x1000 else 0x8000), IFF_MULTICAST);
    // sockaddr_in / sockaddr_in6 field placement the decoders rely on.
    comptime std.debug.assert(@offsetOf(posix.sockaddr.in, "addr") == 4);
    comptime std.debug.assert(@offsetOf(posix.sockaddr.in6, "addr") == 8);
    comptime std.debug.assert(@offsetOf(posix.sockaddr.in6, "scope_id") == 24);
    comptime std.debug.assert(@sizeOf(posix.sockaddr.in6) == 28);
}

test "prefix_len from netmask" {
    try testing.expectEqual(@as(u8, 24), prefixLenFromMask(&[_]u8{ 255, 255, 255, 0 }));
    try testing.expectEqual(@as(u8, 32), prefixLenFromMask(&[_]u8{ 255, 255, 255, 255 }));
    try testing.expectEqual(@as(u8, 0), prefixLenFromMask(&[_]u8{ 0, 0, 0, 0 }));
    try testing.expectEqual(@as(u8, 30), prefixLenFromMask(&[_]u8{ 255, 255, 255, 252 }));
    try testing.expectEqual(@as(u8, 17), prefixLenFromMask(&[_]u8{ 255, 255, 128, 0 }));
    try testing.expectEqual(@as(u8, 8), prefixLenFromMask(&[_]u8{ 255, 0, 0, 0 }));
    try testing.expectEqual(@as(u8, 64), prefixLenFromMask(&mask64));
    const all_ones: [16]u8 = @splat(0xff);
    try testing.expectEqual(@as(u8, 128), prefixLenFromMask(&all_ones));
    // Non-contiguous masks collapse to the full width.
    try testing.expectEqual(@as(u8, 32), prefixLenFromMask(&[_]u8{ 255, 0, 255, 0 }));
    try testing.expectEqual(@as(u8, 32), prefixLenFromMask(&[_]u8{ 255, 255, 253, 0 }));
    try testing.expectEqual(@as(u8, 32), prefixLenFromMask(&[_]u8{ 0, 255, 0, 0 }));
    try testing.expectEqual(@as(u8, 32), prefixLenFromMask(&[_]u8{ 255, 255, 255, 1 }));
    var bad6 = mask64;
    bad6[12] = 1;
    try testing.expectEqual(@as(u8, 128), prefixLenFromMask(&bad6));
    // A missing netmask is the host prefix.
    const snap = try fold(&.{
        v4rec(3, "en0", up_mcast, .{ 10, 0, 0, 1 }, null),
        v6rec(3, "en0", up_mcast, g6(1), null),
    }, .{});
    try testing.expectEqual(@as(u8, 32), snap.find(3).?.v4.slice()[0].prefix_len);
    try testing.expectEqual(@as(u8, 128), snap.find(3).?.v6.slice()[0].prefix_len);
}

test "allow-list keeps only listed ifindex" {
    const recs = [_]Record{
        v4rec(1, "lo0", up_mcast | IFF_LOOPBACK, .{ 127, 0, 0, 1 }, .{ 255, 0, 0, 0 }),
        v4rec(4, "en0", up_mcast, .{ 192, 168, 1, 10 }, .{ 255, 255, 255, 0 }),
        v6rec(4, "en0", up_mcast, ll6(1), mask64),
        v4rec(9, "utun3", up_mcast, .{ 10, 8, 0, 2 }, .{ 255, 255, 255, 255 }),
        v4rec(12, "bridge100", up_mcast, .{ 192, 168, 64, 1 }, .{ 255, 255, 255, 0 }),
    };
    // No list: every up + multicast, non-loopback interface.
    const all = try fold(&recs, .{});
    try testing.expectEqual(@as(u8, 3), all.len);
    try testing.expect(all.find(1) == null);
    try testing.expect(all.find(4) != null);
    try testing.expect(all.find(9) != null);
    try testing.expect(all.find(12) != null);
    // Allow-list: only 4 and 12, in first-seen order.
    const some = try fold(&recs, .{ .allow = &.{ 12, 4 } });
    try testing.expectEqual(@as(u8, 2), some.len);
    try testing.expectEqual(@as(u32, 4), some.slice()[0].index);
    try testing.expectEqual(@as(u32, 12), some.slice()[1].index);
    try testing.expect(some.find(9) == null);
    try testing.expectEqualStrings("en0", some.find(4).?.name.slice());
    try testing.expectEqual(@as(usize, 1), some.find(4).?.v4.len);
    try testing.expectEqual(@as(usize, 1), some.find(4).?.v6.len);
    // Listing loopback does not override include_loopback.
    const lo = try fold(&recs, .{ .allow = &.{1} });
    try testing.expectEqual(@as(u8, 0), lo.len);
    const lo2 = try fold(&recs, .{ .allow = &.{1}, .include_loopback = true });
    try testing.expectEqual(@as(u8, 1), lo2.len);
    try testing.expectEqual(@as(u32, 1), lo2.slice()[0].index);
    // Linux `lo` has no IFF_MULTICAST; include_loopback still keeps its
    // v4 address (v4 multicast via lo works) but not its v6 one (no v6
    // multicast route: ENETUNREACH on send), and a non-loopback
    // interface without the bit is skipped.
    const linux_lo = [_]Record{
        v4rec(1, "lo", IFF_UP | IFF_LOOPBACK, .{ 127, 0, 0, 1 }, .{ 255, 0, 0, 0 }),
        v6rec(1, "lo", IFF_UP | IFF_LOOPBACK, .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, null),
        v4rec(2, "dummy0", IFF_UP, .{ 10, 1, 1, 1 }, null),
    };
    const lo3 = try fold(&linux_lo, .{ .include_loopback = true });
    try testing.expectEqual(@as(u8, 1), lo3.len);
    try testing.expectEqual(@as(u32, 1), lo3.slice()[0].index);
    try testing.expectEqual(@as(usize, 1), lo3.slice()[0].v4.len);
    try testing.expectEqual(@as(usize, 0), lo3.slice()[0].v6.len);
    try testing.expectEqual(@as(u8, 0), (try fold(&linux_lo, .{})).len);
    // An empty list keeps nothing.
    const none = try fold(&recs, .{ .allow = &.{} });
    try testing.expectEqual(@as(u8, 0), none.len);
}

test "allow-listed index missing from getifaddrs is skipped" {
    const recs = [_]Record{
        v4rec(4, "en0", up_mcast, .{ 192, 168, 1, 10 }, .{ 255, 255, 255, 0 }),
    };
    // 77 is not reported (a VPN that is down): no error, just absent.
    const snap = try fold(&recs, .{ .allow = &.{ 77, 4 } });
    try testing.expectEqual(@as(u8, 1), snap.len);
    try testing.expectEqual(@as(u32, 4), snap.slice()[0].index);
    try testing.expect(snap.find(77) == null);
    // Only the missing one listed: an empty snapshot, still no error.
    const empty = try fold(&recs, .{ .allow = &.{77} });
    try testing.expectEqual(@as(u8, 0), empty.len);
    // A listed interface that is present but down is also absent.
    const down = [_]Record{
        v4rec(77, "utun9", IFF_MULTICAST, .{ 10, 8, 0, 2 }, null),
    };
    const s2 = try fold(&down, .{ .allow = &.{77} });
    try testing.expectEqual(@as(u8, 0), s2.len);
}

test "ninth v6 address per interface is dropped and reported in v6_dropped" {
    var recs: [12]Record = undefined;
    // Nine global addresses, then two link-local, then a tenth global.
    var i: u8 = 0;
    while (i < 9) : (i += 1) recs[i] = v6rec(5, "en1", up_mcast, g6(i + 1), mask64);
    recs[9] = v6rec(5, "en1", up_mcast, ll6(1), mask64);
    recs[10] = v6rec(5, "en1", up_mcast, ll6(2), mask64);
    recs[11] = v6rec(5, "en1", up_mcast, g6(10), mask64);
    const snap = try fold(&recs, .{});
    const en1 = snap.find(5).?;
    try testing.expectEqual(@as(usize, 8), en1.v6.len);
    try testing.expectEqual(@as(u8, 4), en1.v6_dropped);
    try testing.expectEqual(@as(u8, 0), en1.v4_dropped);
    // The kept eight are the first eight globals, in arrival order.
    for (en1.v6.slice(), 0..) |p, k| {
        try testing.expectEqual(g6(@intCast(k + 1)), p.addr);
        try testing.expectEqual(@as(u8, 64), p.prefix_len);
    }
    // v4 has its own independent cap and counter.
    var recs4: [10]Record = undefined;
    i = 0;
    while (i < 10) : (i += 1) recs4[i] = v4rec(6, "en2", up_mcast, .{ 10, 0, 0, i + 1 }, .{ 255, 255, 255, 0 });
    const s4 = try fold(&recs4, .{});
    try testing.expectEqual(@as(usize, 8), s4.find(6).?.v4.len);
    try testing.expectEqual(@as(u8, 2), s4.find(6).?.v4_dropped);
    try testing.expectEqual(@as(u8, 0), s4.find(6).?.v6_dropped);
    // Duplicate reports of the same address do not count.
    const dup = try fold(&.{
        v4rec(6, "en2", up_mcast, .{ 10, 0, 0, 1 }, null),
        v4rec(6, "en2", up_mcast, .{ 10, 0, 0, 1 }, null),
    }, .{});
    try testing.expectEqual(@as(usize, 1), dup.find(6).?.v4.len);
    try testing.expectEqual(@as(u8, 0), dup.find(6).?.v4_dropped);
}

test "v6 global addresses sort before link-local" {
    // Kernel order: link-local first (as Darwin reports it), then globals.
    const snap = try fold(&.{
        v6rec(4, "en0", up_mcast, ll6(9), mask64),
        v6rec(4, "en0", up_mcast, g6(1), mask64),
        v6rec(4, "en0", up_mcast, ll6(8), mask64),
        v6rec(4, "en0", up_mcast, g6(2), mask64),
    }, .{});
    const en0 = snap.find(4).?;
    try testing.expectEqual(@as(usize, 4), en0.v6.len);
    try testing.expectEqual(g6(1), en0.v6.slice()[0].addr);
    try testing.expectEqual(g6(2), en0.v6.slice()[1].addr);
    try testing.expectEqual(ll6(9), en0.v6.slice()[2].addr);
    try testing.expectEqual(ll6(8), en0.v6.slice()[3].addr);
    try testing.expectEqual(@as(u8, 0), en0.v6_dropped);

    // Eight link-locals fill the list; a late global evicts the last
    // link-local rather than being dropped itself.
    var recs: [9]Record = undefined;
    var i: u8 = 0;
    while (i < 8) : (i += 1) recs[i] = v6rec(4, "en0", up_mcast, ll6(i + 1), mask64);
    recs[8] = v6rec(4, "en0", up_mcast, g6(1), mask64);
    const s2 = try fold(&recs, .{});
    const e2 = s2.find(4).?;
    try testing.expectEqual(@as(usize, 8), e2.v6.len);
    try testing.expectEqual(g6(1), e2.v6.slice()[0].addr);
    try testing.expectEqual(ll6(1), e2.v6.slice()[1].addr);
    try testing.expectEqual(ll6(7), e2.v6.slice()[7].addr);
    try testing.expectEqual(@as(u8, 1), e2.v6_dropped);

    // A KAME-embedded scope in a link-local address is cleared; the
    // interface index is the scope.
    var kame = ll6(5);
    kame[2] = 0;
    kame[3] = 4;
    const s3 = try fold(&.{v6rec(4, "en0", up_mcast, kame, mask64)}, .{});
    try testing.expectEqual(ll6(5), s3.find(4).?.v6.slice()[0].addr);

    // ipv6 = false keeps no v6 at all and counts nothing.
    const s4 = try fold(&recs, .{ .ipv6 = false });
    try testing.expectEqual(@as(u8, 0), s4.len);
    const s5 = try fold(&.{
        v4rec(4, "en0", up_mcast, .{ 10, 0, 0, 1 }, null),
        v6rec(4, "en0", up_mcast, g6(1), mask64),
    }, .{ .ipv6 = false });
    try testing.expectEqual(@as(usize, 0), s5.find(4).?.v6.len);
    try testing.expectEqual(@as(u8, 0), s5.find(4).?.v6_dropped);
}

test "diff reports added removed and changed" {
    const old = try fold(&.{
        v4rec(4, "en0", up_mcast, .{ 192, 168, 1, 10 }, .{ 255, 255, 255, 0 }),
        v6rec(4, "en0", up_mcast, ll6(1), mask64),
        v4rec(9, "utun3", up_mcast, .{ 10, 8, 0, 2 }, null),
        v4rec(12, "bridge100", up_mcast, .{ 192, 168, 64, 1 }, .{ 255, 255, 255, 0 }),
    }, .{});
    const new = try fold(&.{
        // Same addresses, different kernel order: unchanged.
        v6rec(4, "en0", up_mcast, ll6(1), mask64),
        v4rec(4, "en0", up_mcast, .{ 192, 168, 1, 10 }, .{ 255, 255, 255, 0 }),
        // utun3 got a new address: changed.
        v4rec(9, "utun3", up_mcast, .{ 10, 8, 0, 3 }, null),
        // bridge100 gone; en5 new.
        v4rec(20, "en5", up_mcast, .{ 172, 16, 0, 2 }, .{ 255, 255, 0, 0 }),
    }, .{});
    const d = diff(&old, &new);
    try testing.expectEqualSlices(u32, &.{20}, d.addedSlice());
    try testing.expectEqualSlices(u32, &.{12}, d.removedSlice());
    try testing.expectEqualSlices(u32, &.{9}, d.changedSlice());
    try testing.expect(!d.isEmpty());
    try testing.expect(diff(&old, &old).isEmpty());
    try testing.expect(diff(&new, &new).isEmpty());
    // A prefix length change alone is a change (the on-link check uses it).
    const pl = try fold(&.{
        v4rec(4, "en0", up_mcast, .{ 192, 168, 1, 10 }, .{ 255, 255, 0, 0 }),
        v6rec(4, "en0", up_mcast, ll6(1), mask64),
        v4rec(9, "utun3", up_mcast, .{ 10, 8, 0, 2 }, null),
        v4rec(12, "bridge100", up_mcast, .{ 192, 168, 64, 1 }, .{ 255, 255, 255, 0 }),
    }, .{});
    try testing.expectEqualSlices(u32, &.{4}, diff(&old, &pl).changedSlice());
    // Empty to full: everything added.
    const e = diff(&Snapshot.empty, &old);
    try testing.expectEqual(@as(u8, 3), e.added_len);
    try testing.expectEqual(@as(u8, 0), e.removed_len);
}

test "snapshot limit is LimitReached" {
    var recs: [max_interfaces + 1]Record = undefined;
    for (&recs, 0..) |*r, k| r.* = v4rec(@intCast(k + 1), "x", up_mcast, .{ 10, 0, @intCast(k), 1 }, null);
    try testing.expectError(error.LimitReached, fold(&recs, .{}));
    const ok = try fold(recs[0..max_interfaces], .{});
    try testing.expectEqual(@as(u8, max_interfaces), ok.len);
    // A long name is truncated to 15 octets.
    const long = try fold(&.{v4rec(1, "abcdefghijklmnopqrstuvwxyz", up_mcast, .{ 10, 0, 0, 1 }, null)}, .{});
    try testing.expectEqualStrings("abcdefghijklmno", long.find(1).?.name.slice());
}

test "snapshot returns at least loopback with include_loopback" {
    // Live: real getifaddrs. Every supported OS has an up loopback with
    // 127.0.0.1/8 (Linux `lo` without IFF_MULTICAST, Darwin lo0 with it).
    const snap = try snapshot(.{ .include_loopback = true });
    var saw_lo = false;
    for (snap.slice()) |i| {
        try testing.expect(i.index != 0);
        try testing.expect(i.name.len > 0);
        for (i.v4.slice()) |p| {
            if (std.mem.eql(u8, &p.addr, &.{ 127, 0, 0, 1 })) {
                saw_lo = true;
                try testing.expectEqual(@as(u8, 8), p.prefix_len);
            }
        }
        // Every kept link-local v6 has a clean scope field and follows
        // every global address.
        var seen_ll = false;
        for (i.v6.slice()) |p| {
            if (p.isLinkLocal()) {
                seen_ll = true;
                try testing.expectEqual(@as(u8, 0), p.addr[2]);
                try testing.expectEqual(@as(u8, 0), p.addr[3]);
            } else {
                try testing.expect(!seen_ll);
            }
        }
    }
    try testing.expect(saw_lo);
    // Without include_loopback the loopback is gone and every entry is a
    // subset of the inclusive snapshot.
    const no_lo = try snapshot(.{});
    for (no_lo.slice()) |i| {
        try testing.expect(!i.hasAddr4(.{ 127, 0, 0, 1 }));
        try testing.expect(snap.find(i.index) != null);
    }
    // An allow-list naming only an absent index yields an empty snapshot.
    const absent = try snapshot(.{ .allow = &.{0xfffffff0} });
    try testing.expectEqual(@as(u8, 0), absent.len);
}

test "decodeIfaddrs resolves the index only for inet entries" {
    // Live list: every AF_INET / AF_INET6 entry of an up interface has a
    // non-zero index, and the AF_LINK / AF_PACKET entries (one per
    // interface on every supported OS) stay `.other` with index 0, so
    // `if_nametoindex` is never paid for an entry the fold discards.
    var list: ?*const ifaddrs = null;
    if (getifaddrs(&list) != 0) return error.SkipZigTest;
    defer if (list) |l| freeifaddrs(l);
    var it: IfaddrsIterator = .{ .cur = list };
    var inet: usize = 0;
    var other: usize = 0;
    while (it.next()) |rec| {
        switch (rec.addr) {
            .other => {
                other += 1;
                try testing.expectEqual(@as(u32, 0), rec.index);
            },
            .v4, .v6 => {
                inet += 1;
                if (rec.isUp()) try testing.expect(rec.index != 0);
            },
        }
    }
    try testing.expect(inet >= 1);
    try testing.expect(other >= 1);
}
