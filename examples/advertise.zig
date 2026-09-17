//! mdns-advertise: register one DNS-SD service instance from the command
//! line (plan section 7 M4 deliverable).
//!
//! ```
//! zig build example-advertise -- --type _qmsg._udp --name demo --port 4433 --txt txtvers=1
//! # in another Terminal: dns-sd -B _qmsg._udp        lists demo
//! #                      dns-sd -L demo _qmsg._udp   shows port 4433 and the TXT
//! kill -USR1 "$(pgrep -f mdns-advertise)"            # bumps seq=<n> in the TXT
//! ```
//!
//! Binds `*:5353` beside the OS daemon, advertises `<name>.<type>.local`
//! with `<host>.local` as the SRV target (RFC 6763 sections 4 and 6;
//! probing and announcing per RFC 6762 sections 8.1 and 8.3 happen in the
//! Engine) and prints one line per event until Ctrl-C:
//!
//! ```
//! registered   demo._qmsg._udp.local
//! renamed      demo._qmsg._udp.local -> demo (2)._qmsg._udp.local
//! host_renamed mac.local -> mac-2.local
//! warning      join_failed ifindex=12 family=v6
//! updated      seq=1
//! ```
//!
//! Mode B (`Service.run`): the loop steps the Service with a 250 ms cap and
//! a hook drains the events after every step. Signal handlers only set
//! atomics: SIGINT / SIGTERM flip the shutdown flag the loop watches and
//! `deinit` then sends the goodbye (RFC 6762 section 10.1); SIGUSR1
//! counts a TXT bump that the hook applies through `Service.updateTxt`
//! (section 8.4: re-announce, never re-probe) as `seq=<n>`.
//!
//! Flags: `--type <svc>`, `--name <instance>`, `--port <n>`, `--txt k=v`
//! (repeatable; `--txt k` is a boolean attribute), `--host <label>`
//! (default: the OS host name, sanitized to one DNS label), `--no-ipv6`,
//! `--ifindex N` (repeatable allow-list), `--loopback`, `--stats`.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const mdns = @import("mdns");

/// Longest host label the Engine keeps (RFC 1035 section 2.3.4: 63).
const max_host_label = 63;
/// Fallback host label when the OS host name is empty or unusable.
const default_host_label = "mdns-advertise";
/// TXT key the SIGUSR1 handler bumps.
const seq_key = "seq";

const Options = struct {
    service_type: []const u8 = "_qmsg._udp",
    instance: []const u8 = "demo",
    port: u16 = 4433,
    txt: std.ArrayList(mdns.TxtPair) = .empty,
    host: ?[]const u8 = null,
    ipv6: bool = true,
    include_loopback: bool = false,
    allow: std.ArrayList(u32) = .empty,
    print_stats: bool = false,
};

const usage =
    \\usage: mdns-advertise [--type <svc>] [--name <instance>] [--port <n>] [--txt k=v]...
    \\                      [--host <label>] [--no-ipv6] [--ifindex N]... [--loopback] [--stats]
    \\  --type <svc>      service type, e.g. _qmsg._udp (default)
    \\  --name <instance> instance label (default: demo)
    \\  --port <n>        SRV port (default: 4433)
    \\  --txt k=v         TXT attribute (repeatable; `--txt k` is a boolean attribute)
    \\  --host <label>    host label for <label>.local (default: sanitized OS host name)
    \\  --no-ipv6         v4 only
    \\  --ifindex N       only use interface N (repeatable)
    \\  --loopback        include loopback interfaces
    \\  --stats           print the Engine counters on exit
    \\
    \\signals: SIGINT/SIGTERM -> goodbye and exit; SIGUSR1 -> bump the seq=<n> TXT key
    \\
;

fn parseArgs(init: std.process.Init) !Options {
    var opts: Options = .{};
    const arena = init.arena.allocator();
    var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, arena);
    _ = it.next();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--type")) {
            opts.service_type = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--name")) {
            opts.instance = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--port")) {
            const v = it.next() orelse return error.MissingValue;
            opts.port = try std.fmt.parseInt(u16, v, 10);
        } else if (std.mem.eql(u8, arg, "--txt")) {
            const v = it.next() orelse return error.MissingValue;
            try opts.txt.append(arena, txtPairFromArg(v));
        } else if (std.mem.eql(u8, arg, "--host")) {
            opts.host = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--ifindex")) {
            const v = it.next() orelse return error.MissingValue;
            try opts.allow.append(arena, try std.fmt.parseInt(u32, v, 10));
        } else if (std.mem.eql(u8, arg, "--no-ipv6")) {
            opts.ipv6 = false;
        } else if (std.mem.eql(u8, arg, "--loopback")) {
            opts.include_loopback = true;
        } else if (std.mem.eql(u8, arg, "--stats")) {
            opts.print_stats = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return error.Help;
        } else {
            std.debug.print("unknown argument {s}\n", .{arg});
            return error.UnknownFlag;
        }
    }
    return opts;
}

/// `k=v` -> `{ .key = "k", .value = "v" }`; `k` alone is a boolean
/// attribute (RFC 6763 section 6.4). The slices point into argv.
fn txtPairFromArg(arg: []const u8) mdns.TxtPair {
    if (std.mem.indexOfScalar(u8, arg, '=')) |eq| {
        return .{ .key = arg[0..eq], .value = arg[eq + 1 ..] };
    }
    return .{ .key = arg, .value = null };
}

// ---- host label ------------------------------------------------------------

/// The OS host name reduced to one DNS host label: everything up to the
/// first `.`, `[A-Za-z0-9-]` kept, every other byte replaced by `-`,
/// leading and trailing `-` trimmed, at most 63 octets (RFC 1035 section
/// 2.3.1 letter-digit-hyphen form; RFC 6762 section 16 allows more but
/// stock resolvers do not). Empty or unavailable -> `default_host_label`.
fn sanitizedHostName(buf: *[max_host_label]u8) []const u8 {
    var name_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const raw = std.posix.gethostname(&name_buf) catch return default_host_label;
    return sanitizeLabel(raw, buf);
}

fn sanitizeLabel(raw: []const u8, buf: *[max_host_label]u8) []const u8 {
    const first = raw[0..(std.mem.indexOfScalar(u8, raw, '.') orelse raw.len)];
    var n: usize = 0;
    for (first) |c| {
        if (n == buf.len) break;
        buf[n] = if (std.ascii.isAlphanumeric(c) or c == '-') c else '-';
        n += 1;
    }
    const trimmed = std.mem.trim(u8, buf[0..n], "-");
    if (trimmed.len == 0) return default_host_label;
    return trimmed;
}

test sanitizeLabel {
    var buf: [max_host_label]u8 = undefined;
    try std.testing.expectEqualStrings("mac", sanitizeLabel("mac.local", &buf));
    try std.testing.expectEqualStrings("my-box", sanitizeLabel("my_box", &buf));
    try std.testing.expectEqualStrings("a-b", sanitizeLabel("--a b--", &buf));
    try std.testing.expectEqualStrings(default_host_label, sanitizeLabel("...", &buf));
    try std.testing.expectEqualStrings(default_host_label, sanitizeLabel("", &buf));
    const long: [100]u8 = @splat('x');
    try std.testing.expectEqual(@as(usize, max_host_label), sanitizeLabel(&long, &buf).len);
}

// ---- signals -> atomics --------------------------------------------------------

var shutdown: std.atomic.Value(bool) = .init(false);
/// Incremented by every SIGUSR1; the hook consumes it.
var bumps_requested: std.atomic.Value(u32) = .init(0);

fn onSigShutdown(_: std.posix.SIG) callconv(.c) void {
    shutdown.store(true, .release);
}

fn onSigUsr1(_: std.posix.SIG) callconv(.c) void {
    _ = bumps_requested.fetchAdd(1, .acq_rel);
}

fn installSignals() void {
    if (builtin.os.tag == .windows) return;
    const stop: std.posix.Sigaction = .{
        .handler = .{ .handler = onSigShutdown },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.INT, &stop, null);
    std.posix.sigaction(.TERM, &stop, null);
    const bump: std.posix.Sigaction = .{
        .handler = .{ .handler = onSigUsr1 },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.USR1, &bump, null);
}

// ---- TXT with a seq key -------------------------------------------------------------

/// The advertised TXT: the `--txt` pairs plus `seq=<n>` once SIGUSR1 has
/// fired. Owns the storage `Service.updateTxt` reads (it copies at the
/// call, so a later bump may overwrite it).
const TxtState = struct {
    base: []const mdns.TxtPair,
    pairs: []mdns.TxtPair, // base.len + 1 slots; the last is seq=<n>
    seq: u32 = 0,
    seq_buf: [16]u8 = undefined,

    fn init(arena: std.mem.Allocator, base: []const mdns.TxtPair) !TxtState {
        const pairs = try arena.alloc(mdns.TxtPair, base.len + 1);
        @memcpy(pairs[0..base.len], base);
        return .{ .base = base, .pairs = pairs };
    }

    /// Pairs for `seq == 0`: the base list without a seq key.
    fn initial(t: *const TxtState) []const mdns.TxtPair {
        return t.base;
    }

    /// Bump and return the pairs with `seq=<n>` (a `--txt seq=...` from
    /// the command line is overridden: first match wins on the reader
    /// side, RFC 6763 section 6.4, so the key is written in front).
    fn bump(t: *TxtState) []const mdns.TxtPair {
        t.seq += 1;
        const v = std.fmt.bufPrint(&t.seq_buf, "{d}", .{t.seq}) catch unreachable; // 16 bytes hold any u32
        t.pairs[0] = .{ .key = seq_key, .value = v };
        var n: usize = 1;
        for (t.base) |p| {
            if (std.ascii.eqlIgnoreCase(p.key, seq_key)) continue;
            t.pairs[n] = p;
            n += 1;
        }
        return t.pairs[0..n];
    }
};

test TxtState {
    const base = [_]mdns.TxtPair{ .{ .key = "a", .value = "1" }, .{ .key = "SEQ", .value = "9" } };
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var t = try TxtState.init(arena_state.allocator(), &base);
    try std.testing.expectEqual(@as(usize, 2), t.initial().len);
    const p1 = t.bump();
    try std.testing.expectEqual(@as(usize, 2), p1.len);
    try std.testing.expectEqualStrings("seq", p1[0].key);
    try std.testing.expectEqualStrings("1", p1[0].value.?);
    try std.testing.expectEqualStrings("a", p1[1].key);
    const p2 = t.bump();
    try std.testing.expectEqualStrings("2", p2[0].value.?);
}

// ---- event printing -----------------------------------------------------------------

const App = struct {
    out: *Io.Writer,
    txt: *TxtState,
    reg: ?mdns.RegId,

    fn hook(ctx: ?*anyopaque, svc: *mdns.Service, _: u64) anyerror!void {
        const a: *App = @ptrCast(@alignCast(ctx.?));
        try a.drain(svc);
        try a.applyBumps(svc);
    }

    fn applyBumps(a: *App, svc: *mdns.Service) !void {
        const n = bumps_requested.swap(0, .acq_rel);
        if (n == 0) return;
        const id = a.reg orelse {
            try a.out.print("updated      ignored: no registration\n", .{});
            return a.out.flush();
        };
        // Several signals between two steps collapse into one update
        // with the highest seq (§8.4: identical rdata is a no-op, so a
        // second call with the same pairs would send nothing anyway).
        var i: u32 = 1;
        while (i < n) : (i += 1) _ = a.txt.bump();
        const pairs = a.txt.bump();
        svc.updateTxt(id, pairs) catch |err| {
            try a.out.print("updateTxt failed: {t}\n", .{err});
            return a.out.flush();
        };
        try a.out.print("updated      {s}={d}\n", .{ seq_key, a.txt.seq });
        try a.out.flush();
    }

    fn drain(a: *App, svc: *mdns.Service) !void {
        var evs: [8]mdns.Event = undefined;
        while (true) {
            const n = svc.poll(&evs);
            if (n == 0) break;
            for (evs[0..n]) |ev| try a.print(ev);
        }
        try a.out.flush();
    }

    fn print(a: *App, ev: mdns.Event) !void {
        const out = a.out;
        switch (ev) {
            .registered => |r| try out.print("registered   {f}\n", .{r.instance}),
            .renamed => |r| try out.print("renamed      {f} -> {f}\n", .{ r.old, r.new }),
            .host_renamed => |h| try out.print("host_renamed {f} -> {f}\n", .{ h.old, h.new }),
            .warning => |w| switch (w) {
                .join_failed => |j| try out.print("warning      join_failed ifindex={d} family={t}\n", .{ j.ifindex, j.family }),
                .addrs_truncated => |t| try out.print("warning      addrs_truncated ifindex={d} family={t}\n", .{ t.ifindex, t.family }),
                else => try out.print("warning      {t}\n", .{w}),
            },
            .interfaces_changed => try out.print("event        interfaces_changed\n", .{}),
            // No browse is active, so found/lost/resolved never arrive.
            else => try out.print("event        {t}\n", .{ev}),
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

    var host_buf: [max_host_label]u8 = undefined;
    const host_label = if (opts.host) |h| sanitizeLabel(h, &host_buf) else sanitizedHostName(&host_buf);

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

    var txt = try TxtState.init(init.arena.allocator(), opts.txt.items);
    var app: App = .{ .out = out, .txt = &txt, .reg = null };
    try app.drain(&svc);

    app.reg = svc.advertise(.{
        .service_type = opts.service_type,
        .instance = opts.instance,
        .port = opts.port,
        .txt = txt.initial(),
    }) catch |err| {
        try out.print("advertise {s}.{s}.local failed: {s}\n", .{ opts.instance, opts.service_type, @errorName(err) });
        return 1;
    };
    try out.print("advertising  {s}.{s}.local port={d} host={s}.local first_binder={} on {d} interface(s) (v4 joined={d}, v6 joined={d}); pid={d}; Ctrl-C to stop, SIGUSR1 to bump seq\n", .{
        opts.instance,           opts.service_type,       opts.port,
        host_label,              svc.firstBinder(),       svc.interfaces().len,
        svc.joinedCountFor(.v4), svc.joinedCountFor(.v6), currentPid(),
    });
    try out.flush();

    installSignals();
    svc.run(&shutdown, .{ .ctx = &app, .f = App.hook }) catch |err| {
        try out.print("run ended: {s}\n", .{@errorName(err)});
        try app.drain(&svc);
        return 1;
    };
    try app.drain(&svc);

    if (opts.print_stats) {
        const st = svc.stats();
        try out.print("stats rx={d} rx_echo={d} tx={d} tx_dropped={d} conflicts={d} dropped_malformed={d} dropped_bad_port={d} dropped_off_link={d} events_dropped={d}\n", .{
            st.rx, st.rx_echo, st.tx, st.tx_dropped, st.conflicts, st.dropped_malformed, st.dropped_bad_port, st.dropped_off_link, st.events_dropped,
        });
    }
    try out.print("stopping     goodbye\n", .{});
    return 0;
}

fn currentPid() i64 {
    if (builtin.os.tag == .windows) return 0;
    return @intCast(std.c.getpid());
}
