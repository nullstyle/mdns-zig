//! spike-bind5353: which reuse options let us share UDP *:5353 with the OS
//! mDNS daemon, and which socket the kernel hands a UNICAST datagram to
//! when the port is shared (plan section 4.8 "Port sharing", section 9).
//!
//! Part 1, reuse matrix: for each of {none, REUSEADDR, REUSEPORT, both}
//! open a fresh UDP socket (IPv4, then IPv6 with IPV6_V6ONLY so the v6
//! column measures the v6 rule, not a dual-stack clash with the v4
//! holders), set the options, bind *:5353, print OK or the errno name,
//! close it. The same matrix runs again in Part 3 against a port that
//! only our own sockets hold (`daemon=absent`).
//!
//! Part 2, unicast owner: with one shared socket up, send one unicast
//! mDNS query to 127.0.0.1:5353 from an ephemeral socket and report who
//! received it within 200 ms (ours or none). Then repeat with two of our
//! shared sockets to see whether the older or the newer binder wins. The
//! sender is also polled for a unicast REPLY: one means the OS daemon got
//! the query instead of us.
//!
//! Always exits 0. One machine-readable line per case.
const std = @import("std");
const Io = std.Io;
const mdns = @import("mdns");
const so = mdns.platform.socket_opts;

const Case = struct { name: []const u8, reuse_addr: bool, reuse_port: bool };
const cases = [_]Case{
    .{ .name = "none", .reuse_addr = false, .reuse_port = false },
    .{ .name = "REUSEADDR", .reuse_addr = true, .reuse_port = false },
    .{ .name = "REUSEPORT", .reuse_addr = false, .reuse_port = true },
    .{ .name = "both", .reuse_addr = true, .reuse_port = true },
};

fn timeoutMs(ms: i64) Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
}

const zero_timeout: Io.Timeout = .{ .duration = .{ .raw = .zero, .clock = .awake } };

/// One standard mDNS query: ID 0x2a2a, QDCOUNT 1,
/// `_services._dns-sd._udp.local` PTR IN (QU bit clear).
const query = [_]u8{
    0x2a, 0x2a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    9,    '_',  's',  'e',  'r',  'v',  'i',  'c',  'e',  's',  7,    '_',
    'd',  'n',  's',  '-',  's',  'd',  4,    '_',  'u',  'd',  'p',  5,
    'l',  'o',  'c',  'a',  'l',  0,    0x00, 0x0c, 0x00, 0x01,
};

/// `daemon` is "present" (port 5353, the OS daemon holds it) or "absent"
/// (the control port, held only by our own reuse-flagged sockets).
fn bindCase(out: *Io.Writer, family: so.Family, case: Case, port: u16, daemon: []const u8) !void {
    const fd = so.rawUdpSocket(family) catch |err| {
        try out.print("bind5353 daemon={s} port={d} family={t} case={s} result=socket_failed err={t}\n", .{ daemon, port, family, case.name, err });
        return;
    };
    defer so.closeFd(fd);
    so.setReuse(fd, case.reuse_addr, case.reuse_port) catch |err| {
        try out.print("bind5353 daemon={s} port={d} family={t} case={s} result=setsockopt_failed err={t}\n", .{ daemon, port, family, case.name, err });
        return;
    };
    if (family == .v6) so.setsockoptInt(fd, so.consts.ipproto_ipv6, so.consts.ipv6_v6only, 1) catch |err| {
        try out.print("bind5353 daemon={s} port={d} family={t} case={s} result=v6only_failed err={t}\n", .{ daemon, port, family, case.name, err });
        return;
    };
    if (so.bindWildcard(fd, family, port)) |_| {
        try out.print("bind5353 daemon={s} port={d} family={t} case={s} result=OK\n", .{ daemon, port, family, case.name });
    } else |err| {
        const name: []const u8 = switch (err) {
            error.AddressInUse => "EADDRINUSE",
            error.PermissionDenied => "EACCES",
            error.AddressUnavailable => "EADDRNOTAVAIL",
            else => @errorName(err),
        };
        try out.print("bind5353 daemon={s} port={d} family={t} case={s} result={s}\n", .{ daemon, port, family, case.name, name });
    }
}

/// Run the 4-case matrix for both families against `port`.
fn reuseMatrix(out: *Io.Writer, port: u16, daemon: []const u8) !void {
    for ([_]so.Family{ .v4, .v6 }) |family| {
        for (cases) |case| try bindCase(out, family, case, port, daemon);
    }
}

fn openEphemeral() !Io.net.Socket {
    const fd = try so.rawUdpSocket(.v4);
    errdefer so.closeFd(fd);
    try so.setNonBlocking(fd);
    try so.bindWildcard(fd, .v4, 0);
    return .{ .handle = fd, .address = try so.localAddress(fd) };
}

fn sendQuery(io: Io, from: *const Io.net.Socket) !void {
    var dest: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = so.mdns_port } };
    var om: [1]Io.net.OutgoingMessage = .{.{ .address = &dest, .data_ptr = &query, .data_len = query.len }};
    const err, const n = from.sendManyTimeout(io, &om, .{}, timeoutMs(1));
    if (err) |e| return e;
    if (n != 1) return error.NothingSent;
}

/// Zero-duration drain: true when one datagram was waiting.
fn drainOne(io: Io, sock: *const Io.net.Socket, data: []u8) bool {
    var msgs: [1]Io.net.IncomingMessage = .{.init};
    const err, const n = sock.receiveManyTimeout(io, &msgs, data, .{}, zero_timeout);
    return err == null and n >= 1;
}

const Owner = enum { none, first, second, both };

/// Poll up to `budget_ms` for the query to land on either socket.
fn whoReceived(io: Io, a: *const Io.net.Socket, b: ?*const Io.net.Socket, budget_ms: i64) !Owner {
    var data: [1500]u8 = undefined;
    var got_a = false;
    var got_b = false;
    const t0 = Io.Clock.Timestamp.now(io, .awake);
    while (t0.durationTo(Io.Clock.Timestamp.now(io, .awake)).raw.toMilliseconds() < budget_ms) {
        if (!got_a and drainOne(io, a, &data)) got_a = true;
        if (b) |bs| if (!got_b and drainOne(io, bs, &data)) {
            got_b = true;
        };
        if (got_a and (b == null or got_b)) break;
        try (Io.Clock.Duration{ .raw = .fromMilliseconds(5), .clock = .awake }).sleep(io);
    }
    if (got_a and got_b) return .both;
    if (got_a) return .first;
    if (got_b) return .second;
    return .none;
}

pub fn main(init: std.process.Init) !void {
    var threaded: Io.Threaded = .init(init.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var out_buf: [8192]u8 = undefined;
    var stdout_writer = Io.File.stdout().writerStreaming(io, &out_buf);
    const out = &stdout_writer.interface;
    defer out.flush() catch {};

    try out.print("spike-bind5353 os={t} port={d}\n", .{ @import("builtin").os.tag, so.mdns_port });

    // Part 1: reuse matrix, both families, with the OS daemon on the port.
    try reuseMatrix(out, so.mdns_port, "present");

    // Parts 2 and 3 are IPv4 only.
    try out.print("unicast_owner family=v4\n", .{});

    // Part 2: unicast owner.
    const first = so.bindMdnsSocket(.v4, .{}) catch |err| {
        try out.print("unicast_owner result=skipped reason=bind_failed err={t}\n", .{err});
        return;
    };
    defer first.socket.close(io);
    try out.print("shared_bind sockets=1 first_binder={} local={f}\n", .{ first.first_binder, first.socket.address });

    const sender = try openEphemeral();
    defer sender.close(io);
    try out.print("sender local={f}\n", .{sender.address});

    var reply_buf: [1500]u8 = undefined;

    // One shared socket of ours (plus whatever daemon holds the port).
    try sendQuery(io, &sender);
    const owner1 = try whoReceived(io, &first.socket, null, 200);
    const reply1 = drainOne(io, &sender, &reply_buf);
    try out.print("unicast_owner sockets=1 receiver={s} reply_to_sender={}\n", .{
        switch (owner1) {
            .first => "ours",
            else => "none",
        },
        reply1,
    });

    // Two shared sockets of ours: does the older or the newer binder win?
    const second = so.bindMdnsSocket(.v4, .{ .trial_bind = false }) catch |err| {
        try out.print("unicast_owner sockets=2 result=skipped reason=bind_failed err={t}\n", .{err});
        return;
    };
    var second_open = true;
    defer if (second_open) second.socket.close(io);
    try sendQuery(io, &sender);
    const owner2 = try whoReceived(io, &first.socket, &second.socket, 200);
    const reply2 = drainOne(io, &sender, &reply_buf);
    try out.print("unicast_owner sockets=2 receiver={s} reply_to_sender={}\n", .{
        switch (owner2) {
            .first => "ours_older",
            .second => "ours_newer",
            .both => "both",
            .none => "none",
        },
        reply2,
    });

    // Close the newer socket and send once more: does delivery fall back
    // to the older one?
    second.socket.close(io);
    second_open = false;
    try sendQuery(io, &sender);
    const owner3 = try whoReceived(io, &first.socket, null, 200);
    const reply3 = drainOne(io, &sender, &reply_buf);
    try out.print("unicast_owner sockets=1_after_newer_closed receiver={s} reply_to_sender={}\n", .{
        switch (owner3) {
            .first => "ours",
            else => "none",
        },
        reply3,
    });

    // Part 3: control run on a port nobody else holds: the reuse matrix
    // against our own holder sockets (daemon absent), then the OS rule
    // (older or newer REUSEPORT binder) without the daemon.
    try controlRun(io, out, &sender, control_port);
}

/// A port that no daemon holds on a developer Mac.
const control_port: u16 = 53530;

fn controlRun(io: Io, out: *Io.Writer, sender: *const Io.net.Socket, port: u16) !void {
    const older = so.bindMdnsSocket(.v4, .{ .port = port }) catch |err| {
        try out.print("control_owner port={d} result=skipped reason=bind_failed err={t}\n", .{ port, err });
        return;
    };
    defer older.socket.close(io);
    const newer = so.bindMdnsSocket(.v4, .{ .port = port, .trial_bind = false }) catch |err| {
        try out.print("control_owner port={d} result=skipped reason=second_bind_failed err={t}\n", .{ port, err });
        return;
    };
    defer newer.socket.close(io);
    try out.print("control_bind port={d} first_binder={} sockets=2\n", .{ port, older.first_binder });

    // Reuse matrix with only our own sockets (both reuse flags) holding
    // the port. A v6 holder is added so the v6 column has a peer too.
    const holder6: ?so.BoundSocket = so.bindMdnsSocket(.v6, .{ .port = port, .trial_bind = false }) catch |err| blk: {
        try out.print("control_bind port={d} family=v6 result=failed err={t}\n", .{ port, err });
        break :blk null;
    };
    defer if (holder6) |h| h.socket.close(io);
    try reuseMatrix(out, port, "absent");

    var dest: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
    var trials: [3]Owner = undefined;
    for (&trials) |*t| {
        var om: [1]Io.net.OutgoingMessage = .{.{ .address = &dest, .data_ptr = &query, .data_len = query.len }};
        const err, const n = sender.sendManyTimeout(io, &om, .{}, timeoutMs(1));
        if (err != null or n != 1) {
            t.* = .none;
            continue;
        }
        t.* = try whoReceived(io, &older.socket, &newer.socket, 200);
    }
    try out.print("control_owner port={d} sockets=2 receivers={s},{s},{s}\n", .{ port, ownerName(trials[0]), ownerName(trials[1]), ownerName(trials[2]) });
}

fn ownerName(o: Owner) []const u8 {
    return switch (o) {
        .first => "ours_older",
        .second => "ours_newer",
        .both => "both",
        .none => "none",
    };
}
