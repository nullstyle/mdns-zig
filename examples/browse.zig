//! mdns-browse: continuous DNS-SD browse from the command line (plan
//! section 7 M3 deliverable).
//!
//! ```
//! zig build example-browse -- _qmsg._udp
//! # in another Terminal: dns-sd -R demo _qmsg._udp . 4433 spki=00
//! ```
//!
//! Binds `*:5353` beside the OS daemon, browses `<type>` (default
//! `_qmsg._udp`) and prints one line per event until Ctrl-C:
//!
//! ```
//! found    demo._qmsg._udp.local ifindex=12
//! resolved demo._qmsg._udp.local host=mac.local port=4433 addrs=192.168.1.20:4433,[fe80::1%12]:4433 txt=spki=00 ttl_s=120
//! lost     demo._qmsg._udp.local ifindex=12
//! ```
//!
//! Mode B (`Service.run`): the loop steps the Service with a 250 ms cap and
//! a hook drains the events after every step. SIGINT flips the shutdown
//! atomic the loop watches, so Ctrl-C ends the run within one step cap.
//!
//! `--once` is the bounded one-shot of plan section 5 flow 4:
//! `Service.lookup` with a 3 s timeout and a 500 ms quiet period, one
//! `resolved` line per instance found (per interface: a responder heard
//! on two links prints twice, with each link's addresses), nothing when
//! nothing answers, exit 0 either way. The browse is stopped when
//! `lookup` returns, so no query for the type goes out after exit.
//!
//! Flags: `<type>` (positional), `--ifindex N` (repeatable allow-list),
//! `--no-ipv6`, `--loopback` (include loopback interfaces), `--stats`
//! (print counters on exit), `--once`.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const mdns = @import("mdns");

const Options = struct {
    service_type: []const u8 = "_qmsg._udp",
    ipv6: bool = true,
    include_loopback: bool = false,
    allow: std.ArrayList(u32) = .empty,
    once: bool = false,
    print_stats: bool = false,
};

const usage =
    \\usage: mdns-browse [<type>] [--ifindex N]... [--no-ipv6] [--loopback] [--stats] [--once]
    \\  <type>        service type to browse, e.g. _qmsg._udp (default)
    \\  --ifindex N   only use interface N (repeatable)
    \\  --no-ipv6     v4 only
    \\  --loopback    include loopback interfaces
    \\  --stats       print the Engine counters on exit
    \\  --once        one-shot lookup: 3 s timeout, 500 ms quiet, one line per resolved
    \\
;

fn parseArgs(init: std.process.Init) !Options {
    var opts: Options = .{};
    const arena = init.arena.allocator();
    var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, arena);
    _ = it.next();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--ifindex")) {
            const v = it.next() orelse return error.MissingValue;
            try opts.allow.append(arena, try std.fmt.parseInt(u32, v, 10));
        } else if (std.mem.eql(u8, arg, "--no-ipv6")) {
            opts.ipv6 = false;
        } else if (std.mem.eql(u8, arg, "--loopback")) {
            opts.include_loopback = true;
        } else if (std.mem.eql(u8, arg, "--stats")) {
            opts.print_stats = true;
        } else if (std.mem.eql(u8, arg, "--once")) {
            opts.once = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return error.Help;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            std.debug.print("unknown flag {s}\n", .{arg});
            return error.UnknownFlag;
        } else {
            opts.service_type = arg;
        }
    }
    return opts;
}

// ---- SIGINT -> shutdown flag ----------------------------------------------

var shutdown: std.atomic.Value(bool) = .init(false);

fn onSigInt(_: std.posix.SIG) callconv(.c) void {
    shutdown.store(true, .release);
}

fn installSigInt() void {
    if (builtin.os.tag == .windows) return;
    const act: std.posix.Sigaction = .{
        .handler = .{ .handler = onSigInt },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.INT, &act, null);
    std.posix.sigaction(.TERM, &act, null);
}

// ---- event printing -------------------------------------------------------

const Printer = struct {
    out: *Io.Writer,
    /// `--once`: only warnings, so a lookup that finds nothing prints
    /// nothing.
    warnings_only: bool = false,

    fn hook(ctx: ?*anyopaque, svc: *mdns.Service, _: u64) anyerror!void {
        const p: *Printer = @ptrCast(@alignCast(ctx.?));
        try p.drain(svc);
    }

    fn drain(p: *Printer, svc: *mdns.Service) !void {
        var evs: [8]mdns.Event = undefined;
        while (true) {
            const n = svc.poll(&evs);
            if (n == 0) break;
            for (evs[0..n]) |ev| try p.print(ev);
        }
        try p.out.flush();
    }

    fn print(p: *Printer, ev: mdns.Event) !void {
        const out = p.out;
        if (p.warnings_only and ev != .warning and ev != .resolved) return;
        switch (ev) {
            .found => |f| try out.print("found    {f} ifindex={d}\n", .{ f.instance, f.ifindex }),
            .lost => |l| try out.print("lost     {f} ifindex={d}\n", .{ l.instance, l.ifindex }),
            .resolved => |r| {
                try out.print("resolved {f} host={f} port={d} addrs=", .{ r.instance, r.host, r.port });
                if (r.addrs.len == 0) try out.writeAll("-");
                for (r.addrs.slice(), 0..) |a, i| {
                    if (i != 0) try out.writeByte(',');
                    try out.print("{f}", .{a});
                }
                try out.writeAll(" txt=");
                var it = r.txt.iterate();
                var first = true;
                while (it.next()) |pair| {
                    if (!first) try out.writeByte(',');
                    first = false;
                    if (pair.value) |v| {
                        try out.print("{s}={s}", .{ pair.key, v });
                    } else {
                        try out.print("{s}", .{pair.key});
                    }
                }
                if (first) try out.writeAll("-");
                try out.print(" ttl_s={d} ifindex={d}\n", .{ r.ttl_s, r.ifindex });
            },
            .warning => |w| switch (w) {
                .join_failed => |j| try out.print("warning  join_failed ifindex={d} family={t}\n", .{ j.ifindex, j.family }),
                .addrs_truncated => |a| try out.print("warning  addrs_truncated ifindex={d} family={t}\n", .{ a.ifindex, a.family }),
                else => try out.print("warning  {t}\n", .{w}),
            },
            .interfaces_changed => try out.print("event    interfaces_changed\n", .{}),
            else => try out.print("event    {t}\n", .{ev}),
        }
    }
};

/// `--once`: `Service.lookup` (mode B) with the plan's defaults, then one
/// `resolved` line per result. Warnings queued by `init` were printed by
/// the caller; everything `lookup` discards stays discarded.
fn lookupOnce(svc: *mdns.Service, printer: *Printer, opts: Options) !u8 {
    const out = printer.out;
    var found: [lookup_max_results]mdns.Resolved = undefined;
    const n = svc.lookup(opts.service_type, .{ .timeout_us = 3 * std.time.us_per_s, .quiet_us = 500 * std.time.us_per_ms }, &found) catch |err| {
        try out.print("lookup {s} failed: {t}\n", .{ opts.service_type, err });
        return 1;
    };
    for (found[0..n]) |r| try printer.print(.{ .resolved = r });
    if (opts.print_stats) try printStats(svc, out);
    try out.flush();
    return 0;
}

/// Results `--once` can hold (one per instance and interface).
const lookup_max_results = 32;

fn printStats(svc: *mdns.Service, out: *Io.Writer) !void {
    const st = svc.stats();
    try out.print("stats rx={d} rx_echo={d} tx={d} dropped_malformed={d} dropped_bad_port={d} dropped_off_link={d} dropped_unicast_unexpected={d} dropped_ignored={d} evictions={d} events_dropped={d}\n", .{
        st.rx,               st.rx_echo,                    st.tx,              st.dropped_malformed, st.dropped_bad_port,
        st.dropped_off_link, st.dropped_unicast_unexpected, st.dropped_ignored, st.evictions,         st.events_dropped,
    });
}

pub fn main(init: std.process.Init) !u8 {
    var threaded: Io.Threaded = .init(init.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var out_buf: [8192]u8 = undefined;
    var stdout_writer = Io.File.stdout().writerStreaming(io, &out_buf);
    const out = &stdout_writer.interface;
    defer out.flush() catch {};

    const opts = parseArgs(init) catch |err| switch (err) {
        error.Help => {
            try out.writeAll(usage);
            return 0;
        },
        else => {
            try out.writeAll(usage);
            return 2;
        },
    };
    var svc = mdns.Service.init(init.gpa, io, .{
        .host_label = "mdns-browse",
        .ipv6 = opts.ipv6,
        .include_loopback = opts.include_loopback,
        .interfaces = if (opts.allow.items.len != 0) opts.allow.items else null,
    }) catch |err| {
        try out.print("bind failed: {t}\n", .{err});
        return 1;
    };
    defer svc.deinit();

    var printer: Printer = .{ .out = out, .warnings_only = opts.once };
    try printer.drain(&svc);
    if (opts.once) return lookupOnce(&svc, &printer, opts);
    _ = svc.browse(opts.service_type) catch |err| {
        try out.print("browse {s} failed: {t}\n", .{ opts.service_type, err });
        return 1;
    };
    try out.print("browsing {s} on {d} interface(s) (v4 joined={d}, v6 joined={d}); Ctrl-C to stop\n", .{
        opts.service_type, svc.interfaces().len, svc.joinedCountFor(.v4), svc.joinedCountFor(.v6),
    });
    try out.flush();

    installSigInt();
    svc.run(&shutdown, .{ .ctx = &printer, .f = Printer.hook }) catch |err| {
        try out.print("run ended: {t}\n", .{err});
        try printer.drain(&svc);
        return 1;
    };
    try printer.drain(&svc);

    if (opts.print_stats) try printStats(&svc, out);
    try out.print("stopped\n", .{});
    return 0;
}
