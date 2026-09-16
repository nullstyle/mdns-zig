//! spike-join_pktinfo: bind v4 and v6 shared sockets on *:5353, join
//! 224.0.0.251 and ff02::fb on every interface that is up and
//! multicast-capable, then receive with `Socket.receiveManyTimeout` and a
//! control buffer for N seconds. Every datagram prints its family, source,
//! the arrival ifindex decoded from IP_PKTINFO / IPV6_PKTINFO, the
//! TTL / hop limit, the length and whether the destination was multicast.
//!
//! Flags:
//!   --seconds N   receive window (default 5)
//!   --dump DIR    write DIR/<seq>.hex (lowercase hex, one line) and
//!                 DIR/<seq>.json sidecars for every datagram
//!   --label TEXT  free text stored as "tool_running" in each sidecar
//!
//! Interface enumeration is a minimal `getifaddrs` here; the real
//! `platform/ifaces.zig` is M2. macOS Local Network privacy can hide every
//! packet from a GUI-launched process: zero packets with zero errors is
//! reported as such, not as success.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const posix = std.posix;
const mdns = @import("mdns");
const so = mdns.platform.socket_opts;

// ---- minimal getifaddrs (Darwin ifaddrs.h:36, glibc/musl same layout) ----
const ifaddrs = extern struct {
    next: ?*ifaddrs,
    name: [*:0]const u8,
    flags: c_uint,
    addr: ?*const posix.sockaddr,
    netmask: ?*const posix.sockaddr,
    dstaddr: ?*const posix.sockaddr,
    data: ?*anyopaque,
};
extern "c" fn getifaddrs(ifap: *?*ifaddrs) c_int;
extern "c" fn freeifaddrs(ifa: *ifaddrs) void;
extern "c" fn if_nametoindex(name: [*:0]const u8) c_uint;

const Options = struct {
    seconds: u32 = 5,
    dump: ?[]const u8 = null,
    label: []const u8 = "",
};

fn parseArgs(init: std.process.Init) !Options {
    var opts: Options = .{};
    var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.arena.allocator());
    _ = it.next();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--seconds")) {
            const v = it.next() orelse return error.MissingValue;
            opts.seconds = try std.fmt.parseInt(u32, v, 10);
        } else if (std.mem.eql(u8, arg, "--dump")) {
            opts.dump = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--label")) {
            opts.label = it.next() orelse return error.MissingValue;
        } else {
            std.debug.print("unknown flag {s}\n", .{arg});
            return error.UnknownFlag;
        }
    }
    return opts;
}

const Joined = struct { ifindex: u32, family: so.Family };

fn alreadyJoined(list: []const Joined, ifindex: u32, family: so.Family) bool {
    for (list) |j| if (j.ifindex == ifindex and j.family == family) return true;
    return false;
}

const Sidecar = struct {
    source: []const u8,
    ifindex: u32,
    family: []const u8,
    len: usize,
    captured_with: []const u8,
    tool_running: []const u8,
};

const Stats = struct {
    total: usize = 0,
    v4: usize = 0,
    v6: usize = 0,
    v4_ifindex_nonzero: usize = 0,
    v6_ifindex_nonzero: usize = 0,
    v6_scope_matches_pktinfo: usize = 0,
    multicast_dst: usize = 0,
    ctrunc: usize = 0,
    errors: usize = 0,
    /// Datagrams longer than the hex dump buffer; counted, not dumped.
    oversize: usize = 0,
};

/// Largest datagram `dumpDatagram` writes; anything longer is skipped.
const max_dump_len = 9000;

pub fn main(init: std.process.Init) !void {
    var threaded: Io.Threaded = .init(init.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var out_buf: [16384]u8 = undefined;
    var stdout_writer = Io.File.stdout().writerStreaming(io, &out_buf);
    const out = &stdout_writer.interface;
    defer out.flush() catch {};

    const opts = try parseArgs(init);
    try out.print("spike-join_pktinfo os={t} seconds={d} dump={?s} label=\"{s}\"\n", .{ builtin.os.tag, opts.seconds, opts.dump, opts.label });

    if (opts.dump) |dir| Io.Dir.cwd().createDirPath(io, dir) catch |err| {
        try out.print("dump_dir path={s} result=create_failed err={t}\n", .{ dir, err });
        return;
    };

    // Bind both families. A v6 failure is a degrade, not an exit.
    const b4 = so.bindMdnsSocket(.v4, .{}) catch |err| {
        try out.print("bind family=v4 result=failed err={t}\n", .{err});
        return;
    };
    defer b4.socket.close(io);
    try out.print("bind family=v4 result=OK first_binder={} local={f}\n", .{ b4.first_binder, b4.socket.address });

    const b6: ?so.BoundSocket = so.bindMdnsSocket(.v6, .{}) catch |err| blk: {
        try out.print("bind family=v6 result=failed err={t}\n", .{err});
        break :blk null;
    };
    defer if (b6) |b| b.socket.close(io);
    if (b6) |b| try out.print("bind family=v6 result=OK first_binder={} local={f}\n", .{ b.first_binder, b.socket.address });

    // Enumerate interfaces and join.
    var joined_buf: [64]Joined = undefined;
    var joined_len: usize = 0;
    {
        var list: ?*ifaddrs = null;
        if (getifaddrs(&list) != 0) {
            try out.print("getifaddrs result=failed errno={t}\n", .{std.c.errno(-1)});
            return;
        }
        defer if (list) |l| freeifaddrs(l);
        var cur = list;
        while (cur) |ifa| : (cur = ifa.next) {
            const addr = ifa.addr orelse continue;
            const up = (ifa.flags & so.consts.iff_up) != 0;
            const mcast = (ifa.flags & so.consts.iff_multicast) != 0;
            const loopback = (ifa.flags & so.consts.iff_loopback) != 0;
            const name = std.mem.span(ifa.name);
            const ifindex: u32 = if_nametoindex(ifa.name);
            if (ifindex == 0) {
                // 0 is if_nametoindex's failure value; a v6 join with
                // ifindex 0 would let the kernel pick an interface.
                try out.print("iface name={s} action=skip reason=no_ifindex\n", .{name});
                continue;
            }
            // `ifa_addr` is only guaranteed 1-byte aligned, so read through
            // align(1) pointers: an `@alignCast` here is a runtime check that
            // panics on misaligned libc data. platform/ifaces.zig (M2) must
            // do the same.
            if (addr.family == std.c.AF.INET) {
                const in: *align(1) const posix.sockaddr.in = @ptrCast(addr);
                const bytes: [4]u8 = @bitCast(in.addr);
                if (!up or !mcast) {
                    try out.print("iface name={s} ifindex={d} family=v4 addr={d}.{d}.{d}.{d} up={} multicast={} loopback={} action=skip\n", .{ name, ifindex, bytes[0], bytes[1], bytes[2], bytes[3], up, mcast, loopback });
                    continue;
                }
                if (joined_len < joined_buf.len and !alreadyJoined(joined_buf[0..joined_len], ifindex, .v4)) {
                    const res = so.joinGroup(b4.socket.handle, .v4, ifindex, bytes);
                    if (res) |_| {
                        joined_buf[joined_len] = .{ .ifindex = ifindex, .family = .v4 };
                        joined_len += 1;
                        try out.print("join family=v4 name={s} ifindex={d} addr={d}.{d}.{d}.{d} loopback={} result=OK\n", .{ name, ifindex, bytes[0], bytes[1], bytes[2], bytes[3], loopback });
                    } else |err| {
                        try out.print("join family=v4 name={s} ifindex={d} addr={d}.{d}.{d}.{d} loopback={} result=failed err={t}\n", .{ name, ifindex, bytes[0], bytes[1], bytes[2], bytes[3], loopback, err });
                    }
                }
            } else if (addr.family == std.c.AF.INET6) {
                const in6: *align(1) const posix.sockaddr.in6 = @ptrCast(addr);
                const a6: Io.net.Ip6Address = .{ .bytes = in6.addr, .port = 0 };
                if (!up or !mcast) {
                    try out.print("iface name={s} ifindex={d} family=v6 addr={f} up={} multicast={} loopback={} action=skip\n", .{ name, ifindex, a6, up, mcast, loopback });
                    continue;
                }
                const b = b6 orelse continue;
                if (joined_len < joined_buf.len and !alreadyJoined(joined_buf[0..joined_len], ifindex, .v6)) {
                    const res = so.joinGroup(b.socket.handle, .v6, ifindex, null);
                    if (res) |_| {
                        joined_buf[joined_len] = .{ .ifindex = ifindex, .family = .v6 };
                        joined_len += 1;
                        try out.print("join family=v6 name={s} ifindex={d} addr={f} loopback={} result=OK\n", .{ name, ifindex, a6, loopback });
                    } else |err| {
                        try out.print("join family=v6 name={s} ifindex={d} addr={f} loopback={} result=failed err={t}\n", .{ name, ifindex, a6, loopback, err });
                    }
                }
            }
        }
    }
    try out.print("joined count={d}\n", .{joined_len});
    try out.flush();

    // Receive loop. Control storage is 8-aligned because Threaded passes
    // `message.control.ptr` straight into `msghdr.control`.
    const batch = 8;
    var msgs: [batch]Io.net.IncomingMessage = @splat(.init);
    var data: [batch * max_dump_len]u8 = undefined;
    var ctrl: [batch][so.control_buffer_size]u8 align(8) = undefined;

    var stats: Stats = .{};
    var seq: usize = 0;
    const deadline = Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .raw = .fromSeconds(opts.seconds), .clock = .awake });
    var timed_is_v4 = true;
    while (Io.Clock.Timestamp.now(io, .awake).compare(.lt, deadline)) {
        // Two-socket wait (plan section 4.3): timed wait on one socket,
        // zero-duration drain on the other, alternating.
        const timed: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(100), .clock = .awake } };
        const zero: Io.Timeout = .{ .duration = .{ .raw = .zero, .clock = .awake } };
        const socks = [2]?*const Io.net.Socket{ &b4.socket, if (b6) |*b| &b.socket else null };
        const fams = [2]so.Family{ .v4, .v6 };
        const order: [2]usize = if (timed_is_v4) .{ 0, 1 } else .{ 1, 0 };
        for (order, 0..) |idx, k| {
            const sock = socks[idx] orelse continue;
            for (&msgs, 0..) |*m, i| {
                m.* = .init;
                m.control = &ctrl[i];
            }
            const err, const n = sock.receiveManyTimeout(io, &msgs, &data, .{}, if (k == 0) timed else zero);
            if (err) |e| switch (e) {
                error.Timeout => {},
                else => {
                    stats.errors += 1;
                    try out.print("recv family={t} error={t}\n", .{ fams[idx], e });
                },
            };
            for (msgs[0..n]) |*m| {
                seq += 1;
                const info = so.decodeRxInfo(m.control);
                const fam: so.Family = switch (m.from) {
                    .ip4 => .v4,
                    .ip6 => .v6,
                };
                stats.total += 1;
                if (fam == .v4) {
                    stats.v4 += 1;
                    if (info.ifindex != 0) stats.v4_ifindex_nonzero += 1;
                } else {
                    stats.v6 += 1;
                    if (info.ifindex != 0) stats.v6_ifindex_nonzero += 1;
                    if (m.from.ip6.interface.index == info.ifindex and info.ifindex != 0) stats.v6_scope_matches_pktinfo += 1;
                }
                if (info.dstMulticast()) stats.multicast_dst += 1;
                if (m.flags.ctrunc) stats.ctrunc += 1;
                try out.print("pkt seq={d} family={t} src={f} ifindex={d} ttl={?d} len={d} dst_mcast={} control_len={d} ctrunc={}\n", .{
                    seq, fam, m.from, info.ifindex, info.ttl, m.data.len, info.dstMulticast(), m.control.len, m.flags.ctrunc,
                });
                if (opts.dump) |dir| {
                    if (m.data.len > max_dump_len) {
                        stats.oversize += 1;
                        try out.print("pkt seq={d} action=skip_dump reason=oversize len={d}\n", .{ seq, m.data.len });
                    } else {
                        dumpDatagram(io, dir, seq, m, fam, info, opts.label) catch |dump_err| {
                            stats.errors += 1;
                            try out.print("dump seq={d} result=failed err={t}\n", .{ seq, dump_err });
                        };
                    }
                }
            }
        }
        timed_is_v4 = !timed_is_v4;
    }

    try out.print("summary packets={d} v4={d} v6={d} v4_ifindex_nonzero={d} v6_ifindex_nonzero={d} v6_scope_matches_pktinfo={d} dst_multicast={d} ctrunc={d} oversize={d} errors={d}\n", .{
        stats.total, stats.v4, stats.v6, stats.v4_ifindex_nonzero, stats.v6_ifindex_nonzero, stats.v6_scope_matches_pktinfo, stats.multicast_dst, stats.ctrunc, stats.oversize, stats.errors,
    });
    if (stats.total == 0 and stats.errors == 0) {
        try out.print("note zero packets and zero errors: on macOS this is what Local Network privacy looks like for a GUI-launched process; run from Terminal or SSH\n", .{});
    }
}

fn dumpDatagram(io: Io, dir: []const u8, seq: usize, m: *const Io.net.IncomingMessage, fam: so.Family, info: so.RxInfo, label: []const u8) !void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var hex_buf: [2 * max_dump_len + 1]u8 = undefined;
    const hex = std.fmt.bufPrint(&hex_buf, "{x}\n", .{m.data}) catch return error.HexTooLong;
    const hex_path = try std.fmt.bufPrint(&path_buf, "{s}/{d:0>4}.hex", .{ dir, seq });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = hex_path, .data = hex });

    var src_buf: [80]u8 = undefined;
    const src = try std.fmt.bufPrint(&src_buf, "{f}", .{m.from});
    const sidecar: Sidecar = .{
        .source = src,
        .ifindex = info.ifindex,
        .family = @tagName(fam),
        .len = m.data.len,
        .captured_with = "spikes/join_pktinfo.zig",
        .tool_running = label,
    };
    var json_buf: [1024]u8 = undefined;
    const json = try std.fmt.bufPrint(&json_buf, "{f}\n", .{std.json.fmt(sidecar, .{ .whitespace = .indent_2 })});
    var path_buf2: [std.fs.max_path_bytes]u8 = undefined;
    const json_path = try std.fmt.bufPrint(&path_buf2, "{s}/{d:0>4}.json", .{ dir, seq });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = json_path, .data = json });
}
