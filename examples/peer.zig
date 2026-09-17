//! mdns-peer: advertise and browse in one process, the two-peer demo (plan
//! section 7 M4).
//!
//! ```
//! zig build example-peer -- alice     # on this Mac
//! zig-out/bin/mdns-peer bob           # cross-built, inside the Lima VM
//! ```
//!
//! Each process registers `<name>._mdnszig._udp.local` on port 4433 with
//! `TXT role=peer` and browses `_mdnszig._udp`. Each prints the other
//! within a few seconds and reports it gone within seconds of the other
//! exiting (the goodbye of RFC 6762 section 10.1, or the TTL otherwise):
//!
//! ```
//! peer bob at 192.168.5.15:4433 ifindex 12
//! peer bob gone
//! ```
//!
//! Its own registration is skipped by name: the Engine hands the
//! process its own announcements back through multicast loopback, and the
//! browse side resolves them like any other responder's, so the instance
//! label is compared against the name we registered (or were renamed to)
//! and dropped. Mode B (`Service.run`) with signal handlers that only set
//! an atomic; SIGINT / SIGTERM end the run and `deinit` sends the goodbye.
//!
//! Flags: `<name>` (positional, required), `--port <n>` (default 4433),
//! `--no-ipv6`, `--ifindex N` (repeatable), `--loopback`, `--all-addrs`
//! (print every address instead of the first).
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const mdns = @import("mdns");

const service_type = "_mdnszig._udp";
const default_port: u16 = 4433;
const txt = [_]mdns.TxtPair{.{ .key = "role", .value = "peer" }};
/// Fallback host label when the OS host name is unusable.
const default_host_label = "mdns-peer";
const max_host_label = 63;

const Options = struct {
    name: ?[]const u8 = null,
    port: u16 = default_port,
    ipv6: bool = true,
    include_loopback: bool = false,
    allow: std.ArrayList(u32) = .empty,
    all_addrs: bool = false,
};

const usage =
    \\usage: mdns-peer <name> [--port <n>] [--no-ipv6] [--ifindex N]... [--loopback] [--all-addrs]
    \\  <name>        instance label to register as <name>._mdnszig._udp.local
    \\  --port <n>    SRV port (default 4433)
    \\  --no-ipv6     v4 only
    \\  --ifindex N   only use interface N (repeatable)
    \\  --loopback    include loopback interfaces
    \\  --all-addrs   print every resolved address, not just the first
    \\
;

fn parseArgs(init: std.process.Init) !Options {
    var opts: Options = .{};
    const arena = init.arena.allocator();
    var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, arena);
    _ = it.next();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            const v = it.next() orelse return error.MissingValue;
            opts.port = try std.fmt.parseInt(u16, v, 10);
        } else if (std.mem.eql(u8, arg, "--ifindex")) {
            const v = it.next() orelse return error.MissingValue;
            try opts.allow.append(arena, try std.fmt.parseInt(u32, v, 10));
        } else if (std.mem.eql(u8, arg, "--no-ipv6")) {
            opts.ipv6 = false;
        } else if (std.mem.eql(u8, arg, "--loopback")) {
            opts.include_loopback = true;
        } else if (std.mem.eql(u8, arg, "--all-addrs")) {
            opts.all_addrs = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return error.Help;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            std.debug.print("unknown flag {s}\n", .{arg});
            return error.UnknownFlag;
        } else if (opts.name == null) {
            opts.name = arg;
        } else {
            std.debug.print("unexpected argument {s}\n", .{arg});
            return error.UnknownFlag;
        }
    }
    if (opts.name == null) return error.MissingName;
    return opts;
}

/// The OS host name reduced to one letter-digit-hyphen label (see
/// examples/advertise.zig).
fn hostLabel(buf: *[max_host_label]u8) []const u8 {
    var name_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const raw = std.posix.gethostname(&name_buf) catch return default_host_label;
    const first = raw[0..(std.mem.indexOfScalar(u8, raw, '.') orelse raw.len)];
    var n: usize = 0;
    for (first) |c| {
        if (n == buf.len) break;
        buf[n] = if (std.ascii.isAlphanumeric(c) or c == '-') c else '-';
        n += 1;
    }
    const trimmed = std.mem.trim(u8, buf[0..n], "-");
    return if (trimmed.len == 0) default_host_label else trimmed;
}

// ---- signals -> atomic --------------------------------------------------------

var shutdown: std.atomic.Value(bool) = .init(false);

fn onSigShutdown(_: std.posix.SIG) callconv(.c) void {
    shutdown.store(true, .release);
}

fn installSignals() void {
    if (builtin.os.tag == .windows) return;
    const act: std.posix.Sigaction = .{
        .handler = .{ .handler = onSigShutdown },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.INT, &act, null);
    std.posix.sigaction(.TERM, &act, null);
}

// ---- events -----------------------------------------------------------------------

const Peer = struct {
    out: *Io.Writer,
    /// Our current instance label: the requested name until `registered`
    /// or `renamed` says otherwise (RFC 6762 section 9 renames to
    /// `Name (2)`).
    my_label: mdns.Bounded(u8, 63),
    all_addrs: bool,

    fn hook(ctx: ?*anyopaque, svc: *mdns.Service, _: u64) anyerror!void {
        const p: *Peer = @ptrCast(@alignCast(ctx.?));
        try p.drain(svc);
    }

    fn drain(p: *Peer, svc: *mdns.Service) !void {
        var evs: [8]mdns.Event = undefined;
        while (true) {
            const n = svc.poll(&evs);
            if (n == 0) break;
            for (evs[0..n]) |ev| try p.print(ev);
        }
        try p.out.flush();
    }

    /// The instance label of a full name (`bob._mdnszig._udp.local` ->
    /// `bob`) compared ASCII case-insensitively with ours (section 4.3
    /// name comparison is case-insensitive).
    fn isSelf(p: *const Peer, instance: *const mdns.Name) bool {
        const label = instance.firstLabel() orelse return false;
        return std.ascii.eqlIgnoreCase(label, p.my_label.slice());
    }

    fn setLabel(p: *Peer, name: *const mdns.Name) void {
        const label = name.firstLabel() orelse return;
        p.my_label.clear();
        p.my_label.appendSlice(label) catch {}; // labels are <= 63 by construction
    }

    fn print(p: *Peer, ev: mdns.Event) !void {
        const out = p.out;
        switch (ev) {
            .resolved => |r| {
                if (p.isSelf(&r.instance)) return;
                const label = r.instance.firstLabel() orelse return;
                try out.print("peer {s} at ", .{label});
                if (r.addrs.len == 0) {
                    try out.writeAll("(no address)");
                } else if (p.all_addrs) {
                    for (r.addrs.slice(), 0..) |a, i| {
                        if (i != 0) try out.writeByte(',');
                        try out.print("{f}", .{a});
                    }
                } else {
                    try out.print("{f}", .{r.addrs.slice()[0]});
                }
                try out.print(" ifindex {d}\n", .{r.ifindex});
            },
            .lost => |l| {
                if (p.isSelf(&l.instance)) return;
                const label = l.instance.firstLabel() orelse return;
                try out.print("peer {s} gone\n", .{label});
            },
            .found => {},
            .registered => |r| {
                p.setLabel(&r.instance);
                try out.print("registered {f}\n", .{r.instance});
            },
            .renamed => |r| {
                p.setLabel(&r.new);
                try out.print("renamed {f} -> {f}\n", .{ r.old, r.new });
            },
            .host_renamed => |h| try out.print("host_renamed {f} -> {f}\n", .{ h.old, h.new }),
            .warning => |w| switch (w) {
                .join_failed => |j| try out.print("warning join_failed ifindex={d} family={t}\n", .{ j.ifindex, j.family }),
                .addrs_truncated => |a| try out.print("warning addrs_truncated ifindex={d} family={t}\n", .{ a.ifindex, a.family }),
                else => try out.print("warning {t}\n", .{w}),
            },
            .interfaces_changed => try out.print("event interfaces_changed\n", .{}),
        }
    }
};

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
    const name = opts.name.?;

    var host_buf: [max_host_label]u8 = undefined;
    const host_label = hostLabel(&host_buf);

    var svc = mdns.Service.init(init.gpa, io, .{
        .host_label = host_label,
        .ipv6 = opts.ipv6,
        .include_loopback = opts.include_loopback,
        .interfaces = if (opts.allow.items.len != 0) opts.allow.items else null,
    }) catch |err| {
        try out.print("bind failed: {t}\n", .{err});
        return 1;
    };
    defer svc.deinit();

    var peer: Peer = .{ .out = out, .my_label = .{}, .all_addrs = opts.all_addrs };
    peer.my_label.appendSlice(name[0..@min(name.len, 63)]) catch {};
    try peer.drain(&svc);

    _ = svc.advertise(.{
        .service_type = service_type,
        .instance = name,
        .port = opts.port,
        .txt = &txt,
    }) catch |err| {
        try out.print("advertise {s}.{s}.local failed: {s}\n", .{ name, service_type, @errorName(err) });
        return 1;
    };
    _ = svc.browse(service_type) catch |err| {
        try out.print("browse {s} failed: {t}\n", .{ service_type, err });
        return 1;
    };
    try out.print("peer {s}: advertising {s}.{s}.local port={d} host={s}.local and browsing {s} on {d} interface(s); Ctrl-C to stop\n", .{
        name, name, service_type, opts.port, host_label, service_type, svc.interfaces().len,
    });
    try out.flush();

    installSignals();
    svc.run(&shutdown, .{ .ctx = &peer, .f = Peer.hook }) catch |err| {
        try out.print("run ended: {s}\n", .{@errorName(err)});
        try peer.drain(&svc);
        return 1;
    };
    try peer.drain(&svc);
    try out.print("peer {s}: stopping (goodbye)\n", .{name});
    return 0;
}
