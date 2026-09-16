//! spike-zero_timeout: does `std.Io.Threaded` treat a zero-duration
//! `receiveManyTimeout` on a raw O_NONBLOCK socket as a true non-blocking
//! drain, and does a 50 ms timeout come back on time? (plan section 4.3,
//! "Timed calls only", verified in M0).
//!
//! Checks, each printed as PASS/FAIL with the elapsed time:
//!   a. zero-duration receive on an idle socket -> error.Timeout, at once
//!   b. 50 ms receive on an idle socket        -> error.Timeout in < 100 ms
//!   c. sendManyTimeout(1 ms) of one datagram  -> ok, 1 message sent
//!   d. zero-duration receive with a datagram pending -> 1 message, at once
//!   e. fcntl(F_GETFL) on both fds reports the requested O_NONBLOCK state
//! The battery runs on O_NONBLOCK fds and again on blocking fds.
//!
//! Why every call is timed (documented here, deliberately NOT executed):
//! an UNTIMED receive (`Io.Timeout.none`) goes through `Io.operate`, and
//! the Threaded implementation maps `error.WouldBlock => unreachable`:
//!
//!   STD/Io/Threaded.zig:2551-2557  `.net_receive` in `operate`:
//!       netReceivePosix(...) catch |err| switch (err) {
//!           error.Canceled => |e| return e,
//!           error.WouldBlock => unreachable,      // line 2555
//!           else => |e| break :o .{ e, 0 },
//!       };
//!   STD/Io/Threaded.zig:2564-2576  `.net_send` in `operate`:
//!           error.WouldBlock => unreachable,      // line 2573
//!
//! On an idle O_NONBLOCK socket `recvmsg` returns EAGAIN, `netReceivePosix`
//! maps it to `error.WouldBlock` (Threaded.zig:13237), and `operate` traps:
//! a safety panic in Debug/ReleaseSafe, undefined behaviour in ReleaseFast.
//! The TIMED path is different: `Io.operateTimeout` (STD/Io.zig:560-569)
//! builds a one-entry `Batch` and Threaded's `batchAwait` first tries the
//! receive with MSG_DONTWAIT (a per-call flag, independent of O_NONBLOCK on
//! the fd; Threaded.zig:13188), then on `WouldBlock` adds the fd to a
//! `poll(2)` set (Threaded.zig:2829-2840 receive, :2850-2867 send) and
//! returns `error.Timeout` when the poll expires (Threaded.zig:2924-2932).
//! Hence: zero duration == "poll with timeout 0" == non-blocking drain.
//!
//! Residual hazard (found in M0, not reproducible on Darwin UDP): when
//! `poll` DOES report readiness, `batchAwait` completes the operation with
//! the same untimed `operate` (Threaded.zig:2942), i.e. a plain blocking
//! `recvmsg`/`sendmsg` with `WouldBlock => unreachable` (:2555/:2573). On
//! an O_NONBLOCK fd a spurious POLLIN therefore panics. Linux documents one
//! such spurious wakeup for UDP (select(2) BUGS: a datagram dropped for a
//! bad checksum after readiness was reported) and its `udp_poll` strips the
//! false positive ONLY for blocking fds (`!(file->f_flags & O_NONBLOCK)`).
//! That is why `BindOptions.nonblocking` defaults to false under Threaded;
//! this spike sets O_NONBLOCK explicitly because it measures the drain
//! behaviour the fork's Dispatch backend (M6) will rely on, and verifies
//! the flag took (check e).
//! (STD = /Users/nullstyle/.local/share/mise/installs/zig/0.17.0-dev.1786+75044cb04/lib/std)
const std = @import("std");
const Io = std.Io;
const mdns = @import("mdns");
const so = mdns.platform.socket_opts;

const Out = *Io.Writer;

fn elapsedUs(io: Io, t0: Io.Clock.Timestamp) i64 {
    return t0.durationTo(Io.Clock.Timestamp.now(io, .awake)).raw.toMicroseconds();
}

fn timeoutMs(ms: i64) Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
}

fn verdict(ok: bool) []const u8 {
    return if (ok) "PASS" else "FAIL";
}

/// Read O_NONBLOCK back from the fd flags; null when fcntl fails.
fn isNonBlocking(fd: std.posix.fd_t) ?bool {
    const flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    if (std.c.errno(flags) != .SUCCESS) return null;
    const Backing = @typeInfo(std.posix.O).@"struct".backing_integer.?;
    const nonblock: Backing = @bitCast(std.posix.O{ .NONBLOCK = true });
    return (@as(u32, @bitCast(flags)) & @as(u32, nonblock)) != 0;
}

fn openEphemeral(nonblocking: bool) !Io.net.Socket {
    const fd = try so.rawUdpSocket(.v4);
    errdefer so.closeFd(fd);
    if (nonblocking) try so.setNonBlocking(fd);
    try so.bindWildcard(fd, .v4, 0);
    const address = try so.localAddress(fd);
    return .{ .handle = fd, .address = address };
}

pub fn main(init: std.process.Init) !void {
    // Threaded, constructed explicitly so the backend under test is named.
    var threaded: Io.Threaded = .init(init.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var out_buf: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writerStreaming(io, &out_buf);
    const out: Out = &stdout_writer.interface;
    defer out.flush() catch {};

    try out.print("spike-zero_timeout backend=Threaded os={t}\n", .{@import("builtin").os.tag});

    // The battery runs twice: once on O_NONBLOCK fds (what the fork's
    // Dispatch backend needs, M6) and once on plain blocking fds (the
    // `BindOptions.nonblocking = false` default under Threaded). The timed
    // calls must behave identically on both.
    var all_ok = true;
    for ([_]bool{ true, false }) |nonblocking| {
        const ok = try battery(io, out, nonblocking);
        all_ok = all_ok and ok;
    }
    try out.print("summary result={s}\n", .{verdict(all_ok)});
}

/// Checks (e) then (a)-(d) on a fresh rx/tx pair; returns true when all pass.
fn battery(io: Io, out: Out, nonblocking: bool) !bool {
    const mode: []const u8 = if (nonblocking) "nonblocking" else "blocking";
    const rx = try openEphemeral(nonblocking);
    defer rx.close(io);
    const tx = try openEphemeral(nonblocking);
    defer tx.close(io);
    var all_ok = true;

    // (e) the fd flag matches what was requested (checks a-d pass
    // regardless, because Threaded's first attempt passes MSG_DONTWAIT per
    // call; this check is what exercises `setNonBlocking`).
    {
        const rx_nb = isNonBlocking(rx.handle);
        const tx_nb = isNonBlocking(tx.handle);
        const ok = rx_nb == nonblocking and tx_nb == nonblocking;
        all_ok = all_ok and ok;
        try out.print("mode={s} sockets rx={f} tx={f} rx_nonblocking={?} tx_nonblocking={?}\n", .{ mode, rx.address, tx.address, rx_nb, tx_nb });
        try out.print("mode={s} check=e o_nonblock_flag result={s} rx={?} tx={?} expect={},{}\n", .{ mode, verdict(ok), rx_nb, tx_nb, nonblocking, nonblocking });
    }

    var msgs: [4]Io.net.IncomingMessage = @splat(.init);
    var data: [4 * 1500]u8 = undefined;

    // (a) zero-duration receive on an idle socket.
    {
        for (&msgs) |*m| m.* = .init;
        const t0 = Io.Clock.Timestamp.now(io, .awake);
        const err, const n = rx.receiveManyTimeout(io, &msgs, &data, .{}, .{ .duration = .{ .raw = .zero, .clock = .awake } });
        const us = elapsedUs(io, t0);
        const ok = err != null and err.? == error.Timeout and n == 0 and us < 10_000;
        all_ok = all_ok and ok;
        try out.print("mode={s} check=a zero_duration_idle result={s} err={?t} count={d} elapsed_us={d} expect=error.Timeout,0,<10000us\n", .{ mode, verdict(ok), err, n, us });
    }

    // (b) 50 ms receive on an idle socket.
    {
        for (&msgs) |*m| m.* = .init;
        const t0 = Io.Clock.Timestamp.now(io, .awake);
        const err, const n = rx.receiveManyTimeout(io, &msgs, &data, .{}, timeoutMs(50));
        const us = elapsedUs(io, t0);
        const ok = err != null and err.? == error.Timeout and n == 0 and us >= 45_000 and us < 100_000;
        all_ok = all_ok and ok;
        try out.print("mode={s} check=b 50ms_idle result={s} err={?t} count={d} elapsed_us={d} expect=error.Timeout,0,45000..100000us\n", .{ mode, verdict(ok), err, n, us });
    }

    // (c) send one datagram with a 1 ms timeout.
    const payload = "mdns-zig zero_timeout spike";
    {
        // The socket is bound to the wildcard; send to loopback explicitly
        // (Darwin does not deliver a datagram addressed to 0.0.0.0).
        var dest: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = rx.address.ip4.port } };
        var om: [1]Io.net.OutgoingMessage = .{.{ .address = &dest, .data_ptr = payload.ptr, .data_len = payload.len }};
        const t0 = Io.Clock.Timestamp.now(io, .awake);
        const err, const n = tx.sendManyTimeout(io, &om, .{}, timeoutMs(1));
        const us = elapsedUs(io, t0);
        const ok = err == null and n == 1 and om[0].data_len == payload.len;
        all_ok = all_ok and ok;
        try out.print("mode={s} check=c send_1ms result={s} err={?t} count={d} sent_len={d} elapsed_us={d} expect=null,1,{d}\n", .{ mode, verdict(ok), err, n, om[0].data_len, us, payload.len });
    }

    // Give the loopback path a moment, then (d) zero-duration receive with
    // a datagram pending must return it at once.
    try (Io.Clock.Duration{ .raw = .fromMilliseconds(5), .clock = .awake }).sleep(io);
    {
        for (&msgs) |*m| m.* = .init;
        const t0 = Io.Clock.Timestamp.now(io, .awake);
        const err, const n = rx.receiveManyTimeout(io, &msgs, &data, .{}, .{ .duration = .{ .raw = .zero, .clock = .awake } });
        const us = elapsedUs(io, t0);
        const got = n >= 1 and std.mem.eql(u8, msgs[0].data, payload);
        const ok = err == null and got and us < 10_000;
        all_ok = all_ok and ok;
        try out.print("mode={s} check=d zero_duration_pending result={s} err={?t} count={d} match={} from={f} elapsed_us={d} expect=null,1,match,<10000us\n", .{ mode, verdict(ok), err, n, got, if (n >= 1) msgs[0].from else rx.address, us });
    }

    try out.print("mode={s} result={s}\n", .{ mode, verdict(all_ok) });
    return all_ok;
}
