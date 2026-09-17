//! mdns-live: the real-socket check (`zig build live -- [flags]`).
//!
//! Binds `*:5353` beside whatever OS daemon is present, joins both groups
//! on every interface (or only the `--ifindex` allow-list), browses
//! `--browse <type>` (default `_qmsg._udp`; the `_services._dns-sd._udp`
//! meta-query is an M6 item and is rejected by the RFC 6335 validator),
//! runs the Service in mode B (`step`) for `--seconds` and reports what
//! it saw: every `found`, `resolved` and `lost` event, then the counters.
//! Run `dns-sd -R demo _qmsg._udp . 4433 k=v` beside it to see a
//! `found` and a `resolved` line. With `--advertise NAME` it also
//! registers `NAME._mdnszig._udp.local` on port 4433 (M4 responder) and
//! prints `registered` / `renamed` / `host_renamed`; `dns-sd -B
//! _mdnszig._udp` beside it lists the instance.
//! Packet counts are informational: on macOS 15+ a GUI-launched process
//! may be blocked by Local Network privacy and receive nothing while
//! being entirely correct; the bind, the join list and `firstBinder()`
//! are the assertions.
//!
//! Flags: `--seconds N` (default 4), `--ifindex N` (repeatable; becomes
//! the allow-list), `--browse TYPE`, `--advertise NAME`, `--no-ipv6`,
//! `--no-loopback`.
//!
//! If a run ever hangs (the M3 gate saw one on macOS with a content
//! filter attached; see `socket_opts.send_window_needs_nonblock`), take
//! `sample <pid> 2 -file hang.txt` BEFORE killing it, and note the
//! concurrent processes (another `zig build test` binding *:5353, a Lima
//! VM starting, VPN or utun churn). The `tx ...` line reports sends that
//! exceeded `send_timeout_us` (`slow`) and the longest one (`max_us`).
//!
//! Last line: `RESULT bind=OK first_binder=<bool> joined_v4=<n>
//! joined_v6=<n> rx_v4_ifindex=<n> rx_v6_ifindex=<n> tx=<n>`; exit 0
//! when the bind succeeded, 1 otherwise.
const std = @import("std");

/// Fatal step errors tolerated before the loop gives up.
const max_step_errors: u64 = 4;
const builtin = @import("builtin");
const Io = std.Io;
const mdns = @import("mdns");

const Options = struct {
    seconds: u32 = 4,
    ipv6: bool = true,
    include_loopback: bool = true,
    allow: std.ArrayList(u32) = .empty,
    browse: []const u8 = "_qmsg._udp",
    advertise: ?[]const u8 = null,
};

/// Service type and port `--advertise` registers.
const advertise_type = "_mdnszig._udp";
const advertise_port: u16 = 4433;

fn parseArgs(init: std.process.Init) !Options {
    var opts: Options = .{};
    const arena = init.arena.allocator();
    var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, arena);
    _ = it.next();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--seconds")) {
            const v = it.next() orelse return error.MissingValue;
            opts.seconds = try std.fmt.parseInt(u32, v, 10);
        } else if (std.mem.eql(u8, arg, "--ifindex")) {
            const v = it.next() orelse return error.MissingValue;
            try opts.allow.append(arena, try std.fmt.parseInt(u32, v, 10));
        } else if (std.mem.eql(u8, arg, "--browse")) {
            opts.browse = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--advertise")) {
            opts.advertise = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--no-ipv6")) {
            opts.ipv6 = false;
        } else if (std.mem.eql(u8, arg, "--no-loopback")) {
            opts.include_loopback = false;
        } else {
            std.debug.print("unknown flag {s}\n", .{arg});
            return error.UnknownFlag;
        }
    }
    return opts;
}

fn printWarning(out: *Io.Writer, w: mdns.Warning) !void {
    switch (w) {
        .join_failed => |j| try out.print("warning kind=join_failed ifindex={d} family={t}\n", .{ j.ifindex, j.family }),
        .addrs_truncated => |a| try out.print("warning kind=addrs_truncated ifindex={d} family={t}\n", .{ a.ifindex, a.family }),
        else => try out.print("warning kind={t}\n", .{w}),
    }
}

fn drainEvents(svc: *mdns.Service, out: *Io.Writer) !void {
    var evs: [8]mdns.Event = undefined;
    while (true) {
        const n = svc.poll(&evs);
        if (n == 0) break;
        for (evs[0..n]) |ev| switch (ev) {
            .warning => |w| try printWarning(out, w),
            .interfaces_changed => try out.print("event kind=interfaces_changed\n", .{}),
            .found => |f| try out.print("event kind=found instance={f} ifindex={d}\n", .{ f.instance, f.ifindex }),
            .lost => |l| try out.print("event kind=lost instance={f} ifindex={d}\n", .{ l.instance, l.ifindex }),
            .resolved => |r| {
                try out.print("event kind=resolved instance={f} host={f} port={d} ttl_s={d} ifindex={d} addrs=", .{ r.instance, r.host, r.port, r.ttl_s, r.ifindex });
                for (r.addrs.slice(), 0..) |a, i| {
                    if (i != 0) try out.writeByte(',');
                    try out.print("{f}", .{a});
                }
                try out.print(" txt_len={d}\n", .{r.txt.slice().len});
            },
            .registered => |g| try out.print("event kind=registered id={d} instance={f}\n", .{ @backingInt(g.id), g.instance }),
            .renamed => |g| try out.print("event kind=renamed id={d} old={f} new={f}\n", .{ @backingInt(g.id), g.old, g.new }),
            .host_renamed => |h| try out.print("event kind=host_renamed old={f} new={f}\n", .{ h.old, h.new }),
        };
    }
}

pub fn main(init: std.process.Init) !u8 {
    var threaded: Io.Threaded = .init(init.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var out_buf: [16384]u8 = undefined;
    var stdout_writer = Io.File.stdout().writerStreaming(io, &out_buf);
    const out = &stdout_writer.interface;
    defer out.flush() catch {};

    const opts = try parseArgs(init);
    try out.print("mdns-live os={t} seconds={d} ipv6={} include_loopback={} allow_len={d}\n", .{
        builtin.os.tag, opts.seconds, opts.ipv6, opts.include_loopback, opts.allow.items.len,
    });

    var svc = mdns.Service.init(init.gpa, io, .{
        .host_label = "mdns-live",
        .ipv6 = opts.ipv6,
        .include_loopback = opts.include_loopback,
        .interfaces = if (opts.allow.items.len != 0) opts.allow.items else null,
    }) catch |err| {
        try out.print("bind result=failed err={t}\n", .{err});
        try out.print("RESULT bind=FAILED err={t}\n", .{err});
        return 1;
    };
    defer svc.deinit();

    try out.print("bind result=OK first_binder={} sockets={d}\n", .{ svc.firstBinder(), svc.sockets().len });
    for (svc.sockets()) |sock| try out.print("socket local={f}\n", .{sock.address});
    for (svc.interfaces(), 0..) |iface, i| {
        try out.print("iface index={d} name={s} v4_addrs={d} v6_addrs={d} joined_v4={} joined_v6={} v4_dropped={d} v6_dropped={d}\n", .{
            iface.index,          iface.name.slice(),   iface.v4.len,     iface.v6.len,
            svc.isJoined(i, .v4), svc.isJoined(i, .v6), iface.v4_dropped, iface.v6_dropped,
        });
    }
    try drainEvents(&svc, out);
    const browse_id = svc.browse(opts.browse) catch |err| {
        try out.print("browse type={s} err={t}\n", .{ opts.browse, err });
        try out.print("RESULT bind=OK browse=FAILED err={t}\n", .{err});
        return 1;
    };
    try out.print("browse type={s} id={d}\n", .{ opts.browse, @backingInt(browse_id) });
    if (opts.advertise) |name| {
        const reg_id = svc.advertise(.{
            .service_type = advertise_type,
            .instance = name,
            .port = advertise_port,
            .txt = &.{.{ .key = "txtvers", .value = "1" }},
        }) catch |err| {
            try out.print("advertise instance={s} type={s} err={t}\n", .{ name, advertise_type, err });
            try out.print("RESULT bind=OK advertise=FAILED err={t}\n", .{err});
            return 1;
        };
        try out.print("advertise instance={s} type={s} port={d} id={d}\n", .{ name, advertise_type, advertise_port, @backingInt(reg_id) });
    }
    try out.flush();

    // Mode B for `seconds`, 250 ms cap per step.
    const deadline_us: u64 = @as(u64, opts.seconds) * std.time.us_per_s;
    var steps: u64 = 0;
    var step_errors: u64 = 0;
    while (svc.nowUs() < deadline_us) {
        svc.step(.fromMilliseconds(250)) catch |err| {
            step_errors += 1;
            try out.print("step error={t}\n", .{err});
            // Every `StepError` is fatal and Threaded returns it before
            // any timed wait, so a persistent fault would flood this
            // line: stop after a few and still print the RESULT line.
            if (err == error.Canceled or step_errors >= max_step_errors) break;
        };
        steps += 1;
        try drainEvents(&svc, out);
    }

    const st = svc.stats();
    const rx = svc.rxCounters();
    try out.print("stats rx={d} rx_echo={d} tx={d} tx_dropped={d} dropped_malformed={d} dropped_bad_port={d} dropped_off_link={d} dropped_unicast_unexpected={d} dropped_ignored={d} events_dropped={d} addrs_dropped={d} evictions={d}\n", .{
        st.rx,               st.rx_echo,          st.tx,                         st.tx_dropped,      st.dropped_malformed,
        st.dropped_bad_port, st.dropped_off_link, st.dropped_unicast_unexpected, st.dropped_ignored, st.events_dropped,
        st.addrs_dropped,    st.evictions,
    });
    try out.print("rx v4={d} v4_with_ifindex={d} v6={d} v6_with_ifindex={d} tolerated_errors={d} steps={d} step_errors={d}\n", .{
        rx.v4, rx.v4_with_ifindex, rx.v6, rx.v6_with_ifindex, rx.tolerated_errors, steps, step_errors,
    });
    const tx = svc.txCounters();
    try out.print("tx timeouts={d} slow={d} max_us={d} window_failed={d} window_opened={d}\n", .{
        tx.timeouts, tx.slow, tx.max_us, tx.window_failed, tx.window_opened,
    });
    try out.print("RESULT bind=OK first_binder={} joined_v4={d} joined_v6={d} rx_v4_ifindex={d} rx_v6_ifindex={d} tx={d} conflicts={d}\n", .{
        svc.firstBinder(),
        svc.joinedCountFor(.v4),
        svc.joinedCountFor(.v6),
        rx.v4_with_ifindex,
        rx.v6_with_ifindex,
        st.tx,
        st.conflicts,
    });
    return 0;
}
