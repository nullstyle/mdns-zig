//! `Service`: the `std.Io` shell around the sans-IO `Engine` (plan
//! sections 4.3, 4.5, 4.6, 4.7, 5). It owns the two mDNS sockets, the
//! interface table, the batch receive buffers and the clock origin, and it
//! is the only file that imports both `core` and `platform`.
//!
//! Rules this file enforces:
//! - One caller thread. Never spawns a thread, takes no lock, uses no
//!   atomic except the caller-owned `shutdown` flag `run` reads (4.7).
//! - Three loop modes over one Engine: A `tick(now_us)` with the
//!   embedder's clock, B `step(cap)` / `run` with the Service's own clock,
//!   C `serve(mailbox)` as an `Io.Group` task (4.3). A Service binds to
//!   one clock source for its lifetime; the first `tick` or the first
//!   `step`/`run`/`serve`/`lookup` sets a debug-only mode flag and a later
//!   call in the other mode hits `std.debug.assert`.
//! - Timed calls only (4.3, Revision 3): every receive and send goes
//!   through `recvTimed` / `sendTimed`, which accept a `Timed` value that
//!   has no `.none` member, so an untimed call is a compile error. Sockets
//!   are blocking fds; a zero-duration receive is a non-blocking drain
//!   (`error.Timeout` = nothing to read).
//! - Batch buffers are allocated once at `init` (4.5): `[8]IncomingMessage`,
//!   8 x 9000 B of data, control as `[8][control_size]u8 align(8)` (64 B;
//!   128 B on FreeBSD and OpenBSD, whose `IP_RECVIF` cmsg set does not fit
//!   in 64, see `socket_opts.control_buffer_size`) because Threaded passes
//!   `message.control.ptr` straight into `msghdr.control`. `tick` and
//!   `step` never allocate.
//! - Degrade, never fail (4.6): a failed v6 bind is `warning.v6_unavailable`,
//!   a failed join is `warning.join_failed{ifindex, family}`, and with an
//!   allow-list zero joined interfaces is `warning.no_interfaces`, not an
//!   error. Send failures are counted in `stats.tx_dropped`.
//!
//! Scope after M3: `browse`, `stopBrowse` and `lookup` drive the real
//! querier; `advertise` and `updateTxt` forward to the Engine and return
//! `error.NotImplemented` until M4; `deinit` leaves the groups and closes
//! the sockets (the bounded goodbye flush is M4). The joined (ifindex,
//! family) pairs are handed to the Engine with `Engine.setJoined` after
//! every snapshot, so queries go out only where the join succeeded
//! (Revision 5 item 1). Everything else is the final shape.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const net = Io.net;

const events = @import("core/events.zig");
const engine_mod = @import("core/engine.zig");
const so = @import("platform/socket_opts.zig");
const ifaces = @import("platform/ifaces.zig");

pub const Engine = engine_mod.Engine;
pub const Event = events.Event;
pub const Warning = events.Warning;
pub const Interface = events.Interface;
pub const Limits = events.Limits;
pub const Stats = events.Stats;
pub const Resolved = events.Resolved;
pub const ServiceDesc = events.ServiceDesc;
pub const TxtPair = events.TxtPair;
pub const RegId = events.RegId;
pub const BrowseId = events.BrowseId;
pub const Family = events.Family;

/// Messages per `receiveManyTimeout` call (plan section 4.5).
pub const batch_messages = 8;
/// Receive buffer per message: RFC 6762 section 17 caps a datagram at
/// 9000 B including IP and UDP headers. The pool is `batch_messages` x
/// this, but Threaded hands each recvmsg the whole *remaining* pool as one
/// iovec (Threaded.zig:2828-2831), so one oversized non-mDNS datagram in
/// an early slot can leave a later slot in the same batch with less than
/// 9000 B. Either way the kernel sets `flags.trunc`, and `handleIncoming`
/// counts such a datagram in `rxCounters().truncated` and never hands the
/// cut buffer to the Engine (it would only count as malformed).
pub const rx_datagram_size = 9000;
/// Control (cmsg) bytes per message: the platform's receive cmsg set
/// (pktinfo or dstaddr + recvif, plus TTL); 64, or 128 on the BSDs.
pub const control_size = so.control_buffer_size;
/// Upper bound on one `step` wait and on the `run` / `serve` cadence.
pub const max_step_cap_us: u64 = 250_000;
/// Every send is bounded by this so a full send buffer is a counted drop.
/// 2 ms, not 1: Threaded turns a duration into a deadline and then
/// truncates the remaining time to whole milliseconds for poll(2)
/// (Threaded.zig:2904-2917, `Duration.toMilliseconds` is `@divTrunc`), so
/// a 1 ms timeout measured microseconds later is poll(0), no grace at all.
pub const send_timeout_us: u64 = 2_000;
/// Smallest wait `clampToDeadline` returns, for the same truncation
/// reason: 1 ms would be poll(0) and a due-but-unfired deadline would
/// busy-loop `step`; 2 ms is at least one real 1 ms poll.
pub const min_wait_us: u64 = 2_000;
/// `warning.no_packets_10s`: `tx > 0`, `rx == 0` for this long (4.6).
pub const no_packets_window_us: u64 = 10_000_000;
/// `Mailbox.put` retry cadence while the queue is full (4.3).
pub const mailbox_retry_us: u64 = 10_000;
/// Zero-duration receive rounds one drain runs before yielding (a flood
/// guard: 64 x 8 datagrams per socket per drain).
pub const max_drain_rounds = 64;

// ---------------------------------------------------------------------------
// Timed-only helpers
// ---------------------------------------------------------------------------

/// A timeout that cannot be `Io.Timeout.none`. `recvTimed` and `sendTimed`
/// take only this type, so `svc.recvTimed(sock, .none)` and passing an
/// `Io.Timeout` value are compile errors: on `Io.Threaded` an untimed
/// receive or send maps `error.WouldBlock => unreachable` (plan 4.3,
/// "Timed calls only"). This is the plan's "`.none` is a comptime error".
pub const Timed = union(enum) {
    duration: Io.Clock.Duration,
    deadline: Io.Clock.Timestamp,

    /// Non-blocking drain: "poll with timeout 0".
    pub const zero: Timed = .{ .duration = .{ .raw = .zero, .clock = .awake } };

    pub fn micros(us: u64) Timed {
        const raw: i64 = @intCast(@min(us, std.math.maxInt(i64)));
        return .{ .duration = .{ .raw = .fromMicroseconds(raw), .clock = .awake } };
    }

    pub fn toTimeout(t: Timed) Io.Timeout {
        return switch (t) {
            .duration => |d| .{ .duration = d },
            .deadline => |d| .{ .deadline = d },
        };
    }

    pub fn isZero(t: Timed) bool {
        return switch (t) {
            .duration => |d| d.raw.nanoseconds <= 0,
            .deadline => false,
        };
    }
};

/// Wait length for one `step` (quic-zig `clampTimeoutToDeadline`): no
/// deadline waits the cap; a due or sub-`min_wait_us` deadline waits
/// `min_wait_us` (a blocking-receive floor, never a busy spin); otherwise
/// exactly until the deadline, rounded up to whole milliseconds; never
/// more than the cap, and the cap is at most `max_step_cap_us`.
pub fn clampToDeadline(deadline_us: ?u64, now_us: u64, cap_us: u64) u64 {
    const cap = @max(@min(cap_us, max_step_cap_us), min_wait_us);
    const at = deadline_us orelse return cap;
    if (at <= now_us) return min_wait_us;
    const until = at - now_us;
    const rounded = ((until + 999) / 1_000) * 1_000;
    return @min(cap, @max(rounded, min_wait_us));
}

/// Mode A drain rule (plan 4.3): drain the sockets when
/// `rx_poll_interval_us` has passed since the last drain, when the Engine
/// has a due deadline, or when nothing was drained yet. Pure, so tests
/// drive it with a fake clock.
pub fn shouldDrain(last_drain_us: ?u64, now_us: u64, interval_us: u64, deadline_us: ?u64) bool {
    const last = last_drain_us orelse return true;
    if (now_us -| last >= interval_us) return true;
    if (deadline_us) |d| if (d <= now_us) return true;
    return false;
}

/// Which clock drives the Service (plan 4.3, "Clock-source rule").
pub const Mode = enum {
    /// Before the first `tick` / `step`.
    unset,
    /// Mode A: the embedder's `now_us`.
    tick,
    /// Modes B and C: `nowUs()`.
    step,
};

/// The clock-source rule as a pure function: the mode after a call in
/// `requested`, or null when the Service is already bound to the other
/// mode. The callers assert on null in Debug and ReleaseSafe.
pub fn modeAfter(current: Mode, requested: Mode) ?Mode {
    std.debug.assert(requested != .unset);
    return switch (current) {
        .unset => requested,
        else => if (current == requested) current else null,
    };
}

pub const ReceiveDisposition = enum { timeout, tolerate, fatal };

/// quic-zig `classifyReceiveError`: peer-provoked conditions never end
/// the loop; local faults surface.
pub fn classifyReceiveError(err: net.Socket.ReceiveTimeoutError) ReceiveDisposition {
    return switch (err) {
        error.Timeout => .timeout,
        error.ConnectionResetByPeer,
        error.PortUnreachable,
        error.MessageOversize,
        error.ConnectionTimedOut,
        error.SocketUnconnected,
        => .tolerate,
        error.Canceled,
        error.SystemResources,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.NetworkDown,
        error.ConcurrencyUnavailable,
        error.Unexpected,
        => .fatal,
    };
}

// ---------------------------------------------------------------------------
// Mailbox (mode C)
// ---------------------------------------------------------------------------

/// Cross-thread event delivery by value: a wrapper over `Io.Queue(Event)`
/// with the plan's full policy (4.3): `put` tries a non-blocking put,
/// retries in 10 ms sleeps for at most `cap`, then drops the oldest event
/// and counts it. The consumer thread calls `next`.
pub const Mailbox = struct {
    queue: Io.Queue(Event),
    /// Oldest events dropped by `put` after the cap. Mirrored into
    /// `Service.stats().events_dropped` by `serve`.
    dropped: u64 = 0,

    pub const NextError = Io.Cancelable || error{Closed};
    pub const PutError = Io.Cancelable || error{Closed};

    /// `buf` is the caller-owned ring storage (its length is the capacity).
    pub fn init(buf: []Event) Mailbox {
        return .{ .queue = .init(buf) };
    }

    /// Next event; `error.Closed` once `close` was called and the queue
    /// is empty; `error.Canceled` after `Group.cancel`.
    pub fn next(m: *Mailbox, io: Io) NextError!Event {
        return m.queue.getOne(io);
    }

    /// Ends `serve` at its next iteration (at most one step cap later).
    /// Idempotent. Queued events stay readable through `next` until
    /// `error.Closed`.
    pub fn close(m: *Mailbox, io: Io) void {
        m.queue.close(io);
    }

    /// True once `close` was called. Takes the queue's own lock (the same
    /// one every `put` / `next` takes); `serve` polls it each iteration so
    /// a closed mailbox ends `serve` even when no event is pending.
    ///
    /// This reads `Io.TypeErasedQueue.mutex` / `.closed` (STD/Io.zig:2069-
    /// 2070), which std exposes as plain fields with no accessor. The
    /// comptime guard turns a pin bump that renames or hides them into a
    /// compile error here rather than a silent semantic change; no
    /// atomics are used (plan 4.7), the queue's mutex is the lock.
    pub fn isClosed(m: *Mailbox, io: Io) Io.Cancelable!bool {
        comptime {
            std.debug.assert(@hasField(Io.TypeErasedQueue, "closed"));
            std.debug.assert(@hasField(Io.TypeErasedQueue, "mutex"));
            std.debug.assert(@FieldType(Io.TypeErasedQueue, "closed") == bool);
        }
        try m.queue.type_erased.mutex.lock(io);
        defer m.queue.type_erased.mutex.unlock(io);
        return m.queue.type_erased.closed;
    }

    /// Non-blocking put; retry every 10 ms up to `cap`; then drop the
    /// oldest, count it and put. Never blocks longer than `cap` (+ one
    /// retry round).
    pub fn put(m: *Mailbox, io: Io, ev: Event, cap: Io.Duration) PutError!void {
        const cap_us: u64 = if (cap.toMicroseconds() <= 0) 0 else @intCast(cap.toMicroseconds());
        var waited_us: u64 = 0;
        while (true) {
            const n = try m.queue.put(io, &.{ev}, 0);
            if (n == 1) return;
            if (waited_us >= cap_us) break;
            const slice_us = @min(mailbox_retry_us, cap_us - waited_us);
            try (Io.Clock.Duration{ .raw = .fromMicroseconds(@intCast(slice_us)), .clock = .awake }).sleep(io);
            waited_us += slice_us;
        }
        // Still full after the cap: drop the oldest, then queue ours.
        var one: [1]Event = undefined;
        if ((try m.queue.get(io, &one, 0)) == 1) m.dropped += 1;
        const n = try m.queue.put(io, &.{ev}, 0);
        // Another thread refilled the slot between get and put: the new
        // event is the one dropped. Still bounded, still counted.
        if (n == 0) m.dropped += 1;
    }
};

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

pub const Service = struct {
    pub const Options = struct {
        /// First label of our host name (`<host_label>.local`).
        host_label: []const u8,
        limits: Limits = .{},
        /// Bind and join IPv6. A failed v6 bind degrades to
        /// `warning.v6_unavailable`.
        ipv6: bool = true,
        /// Keep loopback interfaces (tests, single-host demos).
        include_loopback: bool = false,
        /// Allow-list of `ifindex`; null = every up, multicast-capable
        /// interface. With a list, zero joined interfaces at init is
        /// `warning.no_interfaces`, not an error (the VPN case, 4.8).
        interfaces: ?[]const u32 = null,
        /// Forwarded to `Engine.Options`.
        max_addrs_per_iface: u8 = events.max_addrs_per_family,
        /// `refreshInterfaces` cadence inside `tick` / `step`.
        iface_refresh_ms: u32 = 30_000,
        /// Mode A: minimum gap between socket drains.
        rx_poll_interval_us: u64 = 5_000,
    };

    pub const LookupOptions = struct {
        /// Hard upper bound on the whole call.
        timeout_us: u64 = 3_000_000,
        /// Return early after this long with no new resolved event and
        /// >= 1 result.
        quiet_us: u64 = 500_000,
    };

    /// `run` calls it after every step with the step's `now_us`.
    pub const Hook = struct {
        ctx: ?*anyopaque,
        f: *const fn (?*anyopaque, *Service, u64) anyerror!void,
    };

    /// Plan 4.6: the platform errors `init` surfaces, plus allocation and
    /// the interface-table limit.
    pub const InitError = error{
        AddressInUse,
        PermissionDenied,
        OptionUnsupported,
        NoMulticastInterface,
        LimitReached,
        OutOfMemory,
        Unexpected,
    };
    pub const AdvertiseError = Engine.AdvertiseError;
    pub const UpdateTxtError = Engine.UpdateTxtError;
    pub const BrowseError = Engine.BrowseError;
    /// Fatal receive conditions (`classifyReceiveError` `.fatal`) and
    /// cancelation. Tolerated receive errors and every send error are
    /// counters, never a failed tick.
    pub const TickError = error{
        Canceled,
        SystemResources,
        NetworkDown,
        ConcurrencyUnavailable,
        Unexpected,
    };
    pub const StepError = TickError;
    /// `run` also propagates whatever the `Hook` returns.
    pub const RunError = anyerror;
    pub const ServeError = Io.Cancelable;
    pub const LookupError = BrowseError || StepError || Io.Cancelable;
    pub const RefreshError = error{ Unexpected, LimitReached };

    /// Per-family receive counters for operators and the live tests.
    pub const RxCounters = struct {
        v4: u64 = 0,
        v6: u64 = 0,
        /// Datagrams whose control data decoded to a non-zero ifindex.
        v4_with_ifindex: u64 = 0,
        v6_with_ifindex: u64 = 0,
        /// Tolerated receive errors (`classifyReceiveError` `.tolerate`).
        tolerated_errors: u64 = 0,
        /// Fatal step errors `serve` backed off from (`backOffAfterFault`).
        /// `step` and `run` return theirs to the caller instead.
        fatal_errors: u64 = 0,
        /// Datagrams larger than `rx_datagram_size` (`flags.trunc`),
        /// dropped before the Engine sees the cut buffer.
        truncated: u64 = 0,
        /// Datagrams delivered without a destination-address cmsg
        /// (`Engine.stats().rx_dst_unknown` counts the same events).
        no_dst: u64 = 0,
    };

    const PendingMutation = union(enum) {
        withdraw: RegId,
        stop_browse: BrowseId,
    };

    /// Join bookkeeping per interface in `table`, same index order.
    const JoinState = struct {
        v4: bool = false,
        v6: bool = false,
    };

    gpa: std.mem.Allocator,
    io: Io,
    engine: Engine,
    /// Heap-allocated so the `std.Random` the Engine holds stays valid
    /// when the Service value moves.
    prng: *std.Random.DefaultPrng,

    /// `[0]` is the v4 socket, `[1]` the v6 socket when it exists.
    socks: [2]net.Socket,
    socks_len: usize,
    first_binder: bool,

    include_loopback: bool,
    ipv6: bool,
    /// Owned copy of `Options.interfaces`.
    allow: ?[]u32,
    iface_refresh_us: u64,
    rx_poll_interval_us: u64,

    /// The interface table currently joined and handed to the Engine.
    table: ifaces.Snapshot,
    joined: [ifaces.max_interfaces]JoinState,

    /// Batch receive buffers (allocated once, 4.5).
    msgs: []net.IncomingMessage,
    data: []u8,
    ctrl: []align(8) [control_size]u8,
    /// One outbound datagram and its egress cmsg.
    tx_buf: []u8,
    tx_ctrl: [control_size]u8 align(8),

    /// Service-level warnings (`join_failed`, `v6_unavailable`,
    /// `no_interfaces`, `no_packets_10s`, `events_dropped`), drained by
    /// `poll` before the Engine's events.
    svc_events: engine_mod.EventQueue,
    svc_events_dropped: u64,

    pending: events.Bounded(PendingMutation, 64),

    // ---- clock ---------------------------------------------------------
    origin: Io.Timestamp,
    mode: Mode,
    last_now_us: u64,
    last_drain_us: ?u64,
    last_refresh_us: u64,
    /// Which socket gets the timed wait in the next `step`.
    timed_is_v4: bool,

    // ---- counters ------------------------------------------------------
    tx_dropped: u64,
    mailbox_dropped: u64,
    rx: RxCounters,
    first_tx_us: ?u64,
    no_packets_warned: bool,
    events_dropped_warned: bool,

    // ---- init / deinit --------------------------------------------------

    /// Raw-bind `*:5353` for v4 and (with `opts.ipv6`) v6, compute
    /// `firstBinder` by a trial bind without reuse flags, snapshot the
    /// interfaces (allow-list applied), join both groups on each, hand the
    /// table to the Engine and allocate the batch buffers once.
    pub fn init(gpa: std.mem.Allocator, io: Io, opts: Options) InitError!Service {
        // ---- sockets -------------------------------------------------
        const b4 = try so.bindMdnsSocket(.v4, .{});
        errdefer b4.socket.close(io);
        var socks: [2]net.Socket = undefined;
        socks[0] = b4.socket;
        var socks_len: usize = 1;
        var v6_unavailable = false;
        if (opts.ipv6) {
            if (so.bindMdnsSocket(.v6, .{ .trial_bind = false })) |b6| {
                socks[1] = b6.socket;
                socks_len = 2;
            } else |_| {
                v6_unavailable = true;
            }
        }
        errdefer if (socks_len == 2) socks[1].close(io);

        // ---- allocations (once) --------------------------------------
        const prng = try gpa.create(std.Random.DefaultPrng);
        errdefer gpa.destroy(prng);
        var seed: [8]u8 = undefined;
        io.random(&seed);
        prng.* = .init(std.mem.readInt(u64, &seed, .little));

        var engine = try Engine.init(gpa, .{
            .host_label = opts.host_label,
            .random = prng.random(),
            .limits = opts.limits,
            .qu_allowed = b4.first_binder,
            .max_addrs_per_iface = opts.max_addrs_per_iface,
        });
        errdefer engine.deinit();

        const allow: ?[]u32 = if (opts.interfaces) |list| try gpa.dupe(u32, list) else null;
        errdefer if (allow) |a| gpa.free(a);

        const msgs = try gpa.alloc(net.IncomingMessage, batch_messages);
        errdefer gpa.free(msgs);
        const data = try gpa.alloc(u8, batch_messages * rx_datagram_size);
        errdefer gpa.free(data);
        const ctrl = try gpa.alignedAlloc([control_size]u8, .@"8", batch_messages);
        errdefer gpa.free(ctrl);
        const tx_buf = try gpa.alloc(u8, rx_datagram_size);
        errdefer gpa.free(tx_buf);
        const n_events: usize = @max(@as(usize, opts.limits.max_events), 1);
        const ev_buf = try gpa.alloc(Event, n_events);
        errdefer gpa.free(ev_buf);

        var s: Service = .{
            .gpa = gpa,
            .io = io,
            .engine = engine,
            .prng = prng,
            .socks = socks,
            .socks_len = socks_len,
            .first_binder = b4.first_binder,
            .include_loopback = opts.include_loopback,
            .ipv6 = opts.ipv6 and socks_len == 2,
            .allow = allow,
            .iface_refresh_us = @as(u64, opts.iface_refresh_ms) * 1_000,
            .rx_poll_interval_us = opts.rx_poll_interval_us,
            .table = .empty,
            .joined = @splat(.{}),
            .msgs = msgs,
            .data = data,
            .ctrl = ctrl,
            .tx_buf = tx_buf,
            .tx_ctrl = undefined,
            .svc_events = .{ .buf = ev_buf },
            .svc_events_dropped = 0,
            .pending = .{},
            .origin = Io.Timestamp.now(io, .awake),
            .mode = .unset,
            .last_now_us = 0,
            .last_drain_us = null,
            .last_refresh_us = 0,
            .timed_is_v4 = true,
            .tx_dropped = 0,
            .mailbox_dropped = 0,
            .rx = .{},
            .first_tx_us = null,
            .no_packets_warned = false,
            .events_dropped_warned = false,
        };
        if (v6_unavailable) s.pushWarning(.v6_unavailable);

        // ---- interfaces ----------------------------------------------
        const snap = ifaces.snapshot(s.ifaceOptions()) catch |err| switch (err) {
            error.Unexpected => return error.Unexpected,
            error.LimitReached => return error.LimitReached,
        };
        const joined = s.applySnapshot(&snap);
        if (joined == 0) {
            if (s.allow == null) {
                s.leaveAll();
                return error.NoMulticastInterface;
            }
            s.pushWarning(.no_interfaces);
        }
        s.engine.setInterfaces(s.table.slice(), 0) catch |err| switch (err) {
            error.LimitReached => {
                s.leaveAll();
                return error.LimitReached;
            },
        };
        s.syncJoined();
        return s;
    }

    /// Leave every group and close the sockets. The bounded goodbye flush
    /// is M4.
    pub fn deinit(s: *Service) void {
        s.leaveAll();
        net.Socket.closeMany(s.io, s.socks[0..s.socks_len]);
        s.gpa.free(s.svc_events.buf);
        s.gpa.free(s.tx_buf);
        s.gpa.free(s.ctrl);
        s.gpa.free(s.data);
        s.gpa.free(s.msgs);
        if (s.allow) |a| s.gpa.free(a);
        s.engine.deinit();
        s.gpa.destroy(s.prng);
        s.* = undefined;
    }

    fn ifaceOptions(s: *const Service) ifaces.Options {
        return .{
            .include_loopback = s.include_loopback,
            .ipv6 = s.ipv6,
            .allow = s.allow,
        };
    }

    // ---- interface joins -------------------------------------------------

    /// Replace `table` with `snap`: leave interfaces that vanished or
    /// changed, join new or changed ones, keep the rest. Returns the
    /// number of interfaces with at least one successful join. Every
    /// failed join queues `warning.join_failed{ifindex, family}`.
    fn applySnapshot(s: *Service, snap: *const ifaces.Snapshot) usize {
        const d = ifaces.diff(&s.table, snap);
        // Leave removed and changed interfaces using the OLD table (v4
        // membership on Darwin/BSD is keyed by the interface's address).
        for (s.table.slice(), 0..) |*old, i| {
            const gone = contains(d.removedSlice(), old.index) or contains(d.changedSlice(), old.index);
            if (gone) {
                s.leaveInterface(old, s.joined[i]);
                s.joined[i] = .{};
            }
        }
        // Carry join state over by index, then join what is missing.
        var new_joined: [ifaces.max_interfaces]JoinState = @splat(.{});
        for (snap.slice(), 0..) |*iface, i| {
            var st: JoinState = .{};
            if (!contains(d.changedSlice(), iface.index)) {
                for (s.table.slice(), 0..) |*old, j| {
                    if (old.index == iface.index) {
                        st = s.joined[j];
                        break;
                    }
                }
            }
            new_joined[i] = s.joinInterface(iface, st);
        }
        s.table = snap.*;
        s.joined = new_joined;
        var count: usize = 0;
        for (s.joined[0..s.table.len]) |st| if (st.v4 or st.v6) {
            count += 1;
        };
        return count;
    }

    fn contains(list: []const u32, index: u32) bool {
        for (list) |x| if (x == index) return true;
        return false;
    }

    /// Join both groups on `iface` where an address of that family exists
    /// and the family is not joined yet. `error.AlreadyMember` counts as
    /// joined.
    fn joinInterface(s: *Service, iface: *const Interface, st: JoinState) JoinState {
        var out = st;
        if (!out.v4 and iface.v4.len != 0) {
            const addr = iface.v4.slice()[0].addr;
            if (so.joinGroup(s.socks[0].handle, .v4, iface.index, addr)) |_| {
                out.v4 = true;
            } else |err| switch (err) {
                error.AlreadyMember => out.v4 = true,
                else => s.pushWarning(.{ .join_failed = .{ .ifindex = iface.index, .family = .v4 } }),
            }
        }
        if (!out.v6 and s.socks_len == 2 and iface.v6.len != 0) {
            if (so.joinGroup(s.socks[1].handle, .v6, iface.index, null)) |_| {
                out.v6 = true;
            } else |err| switch (err) {
                error.AlreadyMember => out.v6 = true,
                else => s.pushWarning(.{ .join_failed = .{ .ifindex = iface.index, .family = .v6 } }),
            }
        }
        return out;
    }

    fn leaveInterface(s: *Service, iface: *const Interface, st: JoinState) void {
        if (st.v4 and iface.v4.len != 0) {
            so.leaveGroup(s.socks[0].handle, .v4, iface.index, iface.v4.slice()[0].addr) catch {};
        }
        if (st.v6 and s.socks_len == 2) {
            so.leaveGroup(s.socks[1].handle, .v6, iface.index, null) catch {};
        }
    }

    fn leaveAll(s: *Service) void {
        for (s.table.slice(), 0..) |*iface, i| {
            s.leaveInterface(iface, s.joined[i]);
            s.joined[i] = .{};
        }
    }

    /// Re-snapshot the interfaces, join added ones, leave removed ones,
    /// re-join changed ones and hand the table to the Engine, which emits
    /// `.interfaces_changed` when it differs. With an allow-list this is
    /// where a listed interface that was down at init gets joined.
    pub fn refreshInterfaces(s: *Service) RefreshError!void {
        const snap = ifaces.snapshot(s.ifaceOptions()) catch |err| switch (err) {
            error.Unexpected => return error.Unexpected,
            error.LimitReached => return error.LimitReached,
        };
        _ = s.applySnapshot(&snap);
        try s.engine.setInterfaces(s.table.slice(), s.last_now_us);
        s.syncJoined();
    }

    /// Tell the Engine which (ifindex, family) pairs are joined, so it
    /// queries (and, in M4, announces) only there.
    fn syncJoined(s: *Service) void {
        for (s.table.slice(), 0..) |*iface, i| {
            s.engine.setJoined(iface.index, .v4, s.joined[i].v4);
            s.engine.setJoined(iface.index, .v6, s.joined[i].v6);
        }
    }

    /// Number of interfaces with at least one joined family.
    pub fn joinedCount(s: *const Service) usize {
        var n: usize = 0;
        for (s.joined[0..s.table.len]) |st| if (st.v4 or st.v6) {
            n += 1;
        };
        return n;
    }

    /// Number of interfaces joined for `family`.
    pub fn joinedCountFor(s: *const Service, family: Family) usize {
        var n: usize = 0;
        for (s.joined[0..s.table.len]) |st| {
            const j = switch (family) {
                .v4 => st.v4,
                .v6 => st.v6,
            };
            if (j) n += 1;
        }
        return n;
    }

    /// The current interface table.
    pub fn interfaces(s: *const Service) []const Interface {
        return s.table.slice();
    }

    /// Join state of the interface at `interfaces()[i]`.
    pub fn isJoined(s: *const Service, i: usize, family: Family) bool {
        if (i >= s.table.len) return false;
        return switch (family) {
            .v4 => s.joined[i].v4,
            .v6 => s.joined[i].v6,
        };
    }

    // ---- accessors ---------------------------------------------------------

    /// False when another stack owns 5353: QU disabled, multicast defence.
    pub fn firstBinder(s: *const Service) bool {
        return s.first_binder;
    }

    /// The bound sockets (v4, then v6 when present) for foreign reactors.
    pub fn sockets(s: *const Service) []const net.Socket {
        return s.socks[0..s.socks_len];
    }

    /// True when the v6 socket is bound.
    pub fn hasIpv6(s: *const Service) bool {
        return s.socks_len == 2;
    }

    /// Engine counters plus the Service's own: send drops and `Mailbox`
    /// drops.
    pub fn stats(s: *const Service) Stats {
        var st = s.engine.stats();
        st.tx_dropped += s.tx_dropped;
        st.events_dropped += s.mailbox_dropped + s.svc_events_dropped;
        return st;
    }

    pub fn rxCounters(s: *const Service) RxCounters {
        return s.rx;
    }

    /// Forwards `Engine.nextDeadline`.
    pub fn nextDeadline(s: *const Service, now_us: u64) ?u64 {
        return s.engine.nextDeadline(now_us);
    }

    /// Microseconds since `init` on the awake clock, clamped at zero.
    pub fn nowUs(s: *const Service) u64 {
        const now = Io.Timestamp.now(s.io, .awake);
        const delta = s.origin.durationTo(now).toMicroseconds();
        if (delta <= 0) return 0;
        return @intCast(delta);
    }

    /// Copy queued events into `out`; loop until it returns 0.
    /// Service warnings come first, then the Engine's events.
    pub fn poll(s: *Service, out: []Event) usize {
        var n: usize = 0;
        while (n < out.len) : (n += 1) {
            out[n] = s.svc_events.pop() orelse s.engine.pollEvent() orelse break;
        }
        return n;
    }

    // ---- mutations (queued) ---------------------------------------------
    //
    // Plan 4.2: "The Service queues them and applies them at the start of
    // the next tick". `withdraw` and `stopBrowse` already go through
    // `PendingMutation`; `advertise`, `updateTxt` and `browse` call the
    // Engine directly with `last_now_us`. M4/M5 must add `advertise`,
    // `update_txt` and `browse` variants to `PendingMutation` (with the
    // `ServiceDesc` / TXT data copied into the variant, since the caller's
    // slices do not outlive the call) so the queued-at-next-tick contract
    // holds for every mutation.

    /// M4 fills it: always `error.NotImplemented`.
    pub fn advertise(s: *Service, desc: ServiceDesc) AdvertiseError!RegId {
        return s.engine.advertise(desc, s.last_now_us);
    }

    /// Queued; applied at the start of the next `tick` / `step`.
    pub fn withdraw(s: *Service, id: RegId) void {
        s.queueMutation(.{ .withdraw = id });
    }

    /// M4 fills it: always `error.NotImplemented`.
    pub fn updateTxt(s: *Service, id: RegId, txt: []const TxtPair) UpdateTxtError!void {
        return s.engine.updateTxt(id, txt, s.last_now_us);
    }

    /// Start a browse; the first query goes out 20-120 ms later, at the
    /// next `tick` / `step`. In mode A the browse is stamped with the
    /// last tick's clock (`last_now_us`). Before the first call and in
    /// modes B/C it is stamped with `nowUs()` (never below
    /// `last_now_us`), so the 20-120 ms delay counts from the call, not
    /// from `init` (the `init` -> `browse` -> `run` pattern of
    /// `examples/browse.zig`). `last_now_us` itself is untouched: a mode
    /// A embedder whose clock starts near zero is not pushed forward.
    pub fn browse(s: *Service, service_type: []const u8) BrowseError!BrowseId {
        const at = if (s.mode == .tick) s.last_now_us else @max(s.last_now_us, s.nowUs());
        return s.engine.browse(service_type, at);
    }

    /// Queued; applied at the start of the next `tick` / `step`.
    pub fn stopBrowse(s: *Service, id: BrowseId) void {
        s.queueMutation(.{ .stop_browse = id });
    }

    fn queueMutation(s: *Service, m: PendingMutation) void {
        s.pending.append(m) catch {
            // Queue full: apply now with the last known time rather than
            // lose the mutation.
            s.applyMutation(m, s.last_now_us);
        };
    }

    fn applyMutation(s: *Service, m: PendingMutation, now_us: u64) void {
        switch (m) {
            .withdraw => |id| s.engine.withdraw(id, now_us),
            .stop_browse => |id| s.engine.stopBrowse(id, now_us),
        }
    }

    fn applyPending(s: *Service, now_us: u64) void {
        for (s.pending.slice()) |m| s.applyMutation(m, now_us);
        s.pending.clear();
    }

    // ---- mode A ------------------------------------------------------------

    /// Mode A: the embedder's clock is authoritative. Applies queued
    /// mutations, drains the sockets when `shouldDrain` says so, ticks the
    /// Engine, sends, runs the interface refresh on its cadence.
    pub fn tick(s: *Service, now_us: u64) TickError!void {
        s.bindMode(.tick);
        s.advanceClock(now_us);
        try s.tickWork(now_us, false);
    }

    fn bindMode(s: *Service, requested: Mode) void {
        const next = modeAfter(s.mode, requested);
        // Clock-source rule (4.3): a Service binds to one clock for life.
        std.debug.assert(next != null);
        s.mode = next orelse s.mode;
    }

    fn advanceClock(s: *Service, now_us: u64) void {
        // A non-monotonic clock is an embedder bug, not a network input.
        std.debug.assert(now_us >= s.last_now_us);
        s.last_now_us = @max(now_us, s.last_now_us);
    }

    /// The per-iteration work shared by `tick` and `step`.
    fn tickWork(s: *Service, now_us: u64, already_drained: bool) TickError!void {
        s.applyPending(now_us);
        if (!already_drained and shouldDrain(s.last_drain_us, now_us, s.rx_poll_interval_us, s.engine.nextDeadline(now_us))) {
            var now = now_us;
            try s.drainAll(&now);
            s.last_drain_us = now_us;
        }
        s.engine.tick(now_us);
        try s.flushTx(now_us);
        s.checkNoPackets(now_us);
        if (now_us - s.last_refresh_us >= s.iface_refresh_us) {
            s.last_refresh_us = now_us;
            // A failed getifaddrs keeps the previous table; the next
            // cadence retries.
            s.refreshInterfaces() catch {};
        }
    }

    /// Zero-duration drain of every socket.
    fn drainAll(s: *Service, now: *u64) TickError!void {
        var i: usize = 0;
        while (i < s.socks_len) : (i += 1) try s.receiveOn(i, .zero, now);
    }

    // ---- mode B ------------------------------------------------------------

    /// Mode B: one bounded wait. A timed receive on one socket with
    /// `clampToDeadline(nextDeadline, cap)`, a zero-duration drain of the
    /// other, alternating each call; then the clock is re-read and the
    /// same work as `tick` runs. `cap` is clamped to 250 ms.
    pub fn step(s: *Service, cap: Io.Duration) StepError!void {
        s.bindMode(.step);
        return s.stepInner(cap);
    }

    fn stepInner(s: *Service, cap: Io.Duration) StepError!void {
        const cap_us: u64 = if (cap.toMicroseconds() <= 0) 0 else @intCast(cap.toMicroseconds());
        var now = s.nowUs();
        s.advanceClock(now);
        const wait_us = clampToDeadline(s.engine.nextDeadline(now), now, cap_us);

        const timed_idx: usize = if (s.timed_is_v4 or s.socks_len == 1) 0 else 1;
        const other_idx: usize = 1 - timed_idx;
        try s.receiveOn(timed_idx, .micros(wait_us), &now);
        if (s.socks_len == 2) try s.receiveOn(other_idx, .zero, &now);
        s.timed_is_v4 = !s.timed_is_v4;

        now = s.nowUs();
        s.advanceClock(now);
        s.last_drain_us = now;
        try s.tickWork(now, true);
    }

    /// Loop `step` with a 250 ms cap until `shutdown` reads true, calling
    /// `hook` after every step with that step's `now_us`.
    pub fn run(s: *Service, shutdown: *std.atomic.Value(bool), hook: ?Hook) RunError!void {
        s.bindMode(.step);
        while (!shutdown.load(.acquire)) {
            try s.stepInner(.fromMicroseconds(max_step_cap_us));
            if (hook) |h| try h.f(h.ctx, s, s.last_now_us);
        }
    }

    // ---- mode C ------------------------------------------------------------

    /// Mode C: mode B as an `Io.Group` task, pushing every event into
    /// `mailbox` with the bounded-put-then-drop-oldest policy. Start it
    /// with `Group.concurrent`, never `Group.async`. Returns
    /// `error.Canceled` after `Group.cancel`; returns normally once the
    /// mailbox is closed, at most one step cap after `Mailbox.close`
    /// (goodbyes are M4). A fatal step error does not end delivery: it is
    /// counted in `rxCounters().fatal_errors` and the task sleeps one
    /// step cap (`backOffAfterFault`) before the next step, because
    /// Threaded returns a failing receive before any timed wait
    /// (Threaded.zig:2826-2843) and a persistent local fault would
    /// otherwise spin this task at full CPU. The sleep is also a
    /// cancelation point.
    pub fn serve(s: *Service, mailbox: *Mailbox) ServeError!void {
        s.bindMode(.step);
        const cap: Io.Duration = .fromMicroseconds(max_step_cap_us);
        while (true) {
            if (try mailbox.isClosed(s.io)) return;
            s.stepInner(cap) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => try s.backOffAfterFault(),
            };
            var buf: [8]Event = undefined;
            while (true) {
                const n = s.poll(&buf);
                if (n == 0) break;
                for (buf[0..n]) |ev| {
                    mailbox.put(s.io, ev, cap) catch |err| switch (err) {
                        error.Closed => return,
                        error.Canceled => return error.Canceled,
                    };
                }
            }
            if (mailbox.dropped != s.mailbox_dropped) {
                s.mailbox_dropped = mailbox.dropped;
                if (!s.events_dropped_warned) {
                    s.events_dropped_warned = true;
                    mailbox.put(s.io, .{ .warning = .events_dropped }, cap) catch |err| switch (err) {
                        error.Closed => return,
                        error.Canceled => return error.Canceled,
                    };
                }
            }
        }
    }

    /// `serve`'s fatal-step policy: count the fault and sleep one step
    /// cap on the awake clock so a persistent local error costs at most
    /// four steps per second, never a spin. Propagates `error.Canceled`.
    fn backOffAfterFault(s: *Service) Io.Cancelable!void {
        s.rx.fatal_errors += 1;
        try (Io.Clock.Duration{ .raw = .fromMicroseconds(max_step_cap_us), .clock = .awake }).sleep(s.io);
    }

    /// Bounded one-shot lookup (mode B): browse, collect `resolved` into
    /// `out` (a later `resolved` for the same instance replaces the
    /// earlier copy), stop the browse on every exit path. Returns when
    /// `out` is full, after `timeout_us`, or after `quiet_us` with at
    /// least one result and no new `resolved`.
    pub fn lookup(s: *Service, service_type: []const u8, opts: LookupOptions, out: []Resolved) LookupError!usize {
        s.bindMode(.step);
        const start = s.nowUs();
        s.advanceClock(start);
        const id = try s.engine.browse(service_type, start);
        defer s.engine.stopBrowse(id, s.nowUs());

        var count: usize = 0;
        var last_new = start;
        var buf: [8]Event = undefined;
        while (count < out.len) {
            const now = s.nowUs();
            if (now - start >= opts.timeout_us) break;
            if (count > 0 and now - last_new >= opts.quiet_us) break;
            const remaining = @min(opts.timeout_us - (now - start), max_step_cap_us);
            try s.stepInner(.fromMicroseconds(@intCast(remaining)));
            while (true) {
                const n = s.poll(&buf);
                if (n == 0) break;
                for (buf[0..n]) |ev| {
                    if (ev != .resolved) continue;
                    const r = ev.resolved;
                    var slot: ?usize = null;
                    for (out[0..count], 0..) |*o, i| {
                        if (o.instance.eql(&r.instance) and o.service_type.eql(&r.service_type)) {
                            slot = i;
                            break;
                        }
                    }
                    if (slot) |i| {
                        out[i] = r;
                    } else if (count < out.len) {
                        out[count] = r;
                        count += 1;
                    }
                    last_new = s.nowUs();
                }
            }
        }
        return count;
    }

    // ---- receive / send ----------------------------------------------------

    /// The only receive path. `first` bounds the first call; every later
    /// round is a zero-duration drain, because a Threaded timed receive
    /// returns at most one message after a wait (Revision 3). `now.*` is
    /// re-read after a real wait so handled packets carry a fresh time.
    fn receiveOn(s: *Service, idx: usize, first: Timed, now: *u64) TickError!void {
        const sock = &s.socks[idx];
        const family: so.Family = if (idx == 0) .v4 else .v6;
        var timeout = first;
        var round: usize = 0;
        while (round < max_drain_rounds) : (round += 1) {
            s.resetBatch();
            const err, const n = s.recvTimed(sock, timeout);
            if (!timeout.isZero()) {
                now.* = s.nowUs();
                s.advanceClock(now.*);
            }
            for (s.msgs[0..n]) |*m| s.handleIncoming(m, family, now.*);
            if (err) |e| switch (classifyReceiveError(e)) {
                .timeout => return,
                .tolerate => {
                    s.rx.tolerated_errors += 1;
                    if (n == 0) return;
                },
                .fatal => return fatalReceive(e),
            };
            if (n == 0) return;
            timeout = .zero;
        }
    }

    fn fatalReceive(err: net.Socket.ReceiveTimeoutError) TickError {
        return switch (err) {
            error.Canceled => error.Canceled,
            error.SystemResources, error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded => error.SystemResources,
            error.NetworkDown => error.NetworkDown,
            error.ConcurrencyUnavailable => error.ConcurrencyUnavailable,
            else => error.Unexpected,
        };
    }

    /// `receiveManyTimeout` overwrites each `control` with the received
    /// length; restore the full buffers before every call.
    fn resetBatch(s: *Service) void {
        for (s.msgs, 0..) |*m, i| {
            m.* = .init;
            m.control = &s.ctrl[i];
        }
    }

    fn handleIncoming(s: *Service, m: *const net.IncomingMessage, family: so.Family, now_us: u64) void {
        // MSG_TRUNC: the datagram did not fit its slot (see
        // `rx_datagram_size`). Counted, never parsed.
        if (m.flags.trunc) {
            s.rx.truncated += 1;
            return;
        }
        const meta = so.decodeControl(family, m.control);
        switch (family) {
            .v4 => {
                s.rx.v4 += 1;
                if (meta.ifindex != 0) s.rx.v4_with_ifindex += 1;
            },
            .v6 => {
                s.rx.v6 += 1;
                if (meta.ifindex != 0) s.rx.v6_with_ifindex += 1;
            },
        }
        var from = m.from;
        // A link-local v6 source without a scope gets the arrival interface.
        if (from == .ip6 and from.ip6.interface.index == 0 and meta.ifindex != 0) {
            from.ip6.interface = .{ .index = meta.ifindex };
        }
        // No destination cmsg (a socket where IP_RECVDSTADDR /
        // IPV6_RECVPKTINFO silently failed): the Engine applies the
        // section 11 on-link check as for unicast but skips the QU-window
        // drop, and counts it in `stats.rx_dst_unknown`
        // (docs/platform-matrix.md, "Destination address").
        if (meta.dst_multicast == null) s.rx.no_dst += 1;
        s.engine.handle(m.data, .{
            .from = from,
            .ifindex = meta.ifindex,
            .dst_multicast = meta.dst_multicast orelse false,
            .dst_known = meta.dst_multicast != null,
            .ttl = meta.ttl,
        }, now_us);
    }

    /// Drain the Engine's outbound queue. Every send failure is a counted
    /// drop, except `error.Canceled`, which propagates: under
    /// `Io.Threaded` cancelation is one-shot (Io.zig:1299-1302, "only the
    /// next cancelation point ... will return error.Canceled"), so a
    /// `Group.cancel` that lands on the send must end the loop here or
    /// it is lost and `groupCancel` blocks forever.
    fn flushTx(s: *Service, now_us: u64) Io.Cancelable!void {
        while (s.engine.pollDatagram(s.tx_buf, now_us)) |d| {
            try s.sendDatagram(d);
        }
        if (s.first_tx_us == null and s.engine.stats().tx > 0) s.first_tx_us = now_us;
    }

    /// A cancelation point: `sendManyTimeout` returns `{ error.Canceled,
    /// 0 }` when the cancel lands before the first sendmsg
    /// (Threaded.zig:2855-2858) and that is the one send error that is
    /// not a drop.
    fn sendDatagram(s: *Service, d: Engine.TxDatagram) Io.Cancelable!void {
        const family: so.Family = switch (d.to) {
            .ip4 => .v4,
            .ip6 => .v6,
        };
        const idx: usize = switch (family) {
            .v4 => 0,
            .v6 => 1,
        };
        if (idx >= s.socks_len or d.len > s.tx_buf.len) {
            s.tx_dropped += 1;
            return;
        }
        const sock = &s.socks[idx];
        var control: []const u8 = &.{};
        if (d.ifindex != 0) switch (family) {
            .v4 => {
                if (comptime so.needsPerSendMulticastIf()) {
                    so.setMulticastIf(sock.handle, .v4, d.ifindex, s.ifaceV4Addr(d.ifindex)) catch {
                        s.tx_dropped += 1;
                        return;
                    };
                } else {
                    control = so.encodePktInfo4(&s.tx_ctrl, d.ifindex, null) catch &.{};
                }
            },
            .v6 => control = so.encodePktInfo6(&s.tx_ctrl, d.ifindex) catch &.{},
        };
        const to = d.to;
        var om: [1]net.OutgoingMessage = .{.{
            .address = &to,
            .data_ptr = s.tx_buf.ptr,
            .data_len = d.len,
            .control = control,
        }};
        const err, const n = s.sendTimed(sock, &om, .micros(send_timeout_us));
        if (err) |e| switch (e) {
            error.Canceled => return error.Canceled,
            else => {
                s.tx_dropped += 1;
                return;
            },
        };
        if (n != 1) s.tx_dropped += 1;
    }

    fn ifaceV4Addr(s: *const Service, ifindex: u32) ?[4]u8 {
        const iface = s.table.find(ifindex) orelse return null;
        if (iface.v4.len == 0) return null;
        return iface.v4.slice()[0].addr;
    }

    /// The only `receiveManyTimeout` call site: `timeout` is a `Timed`,
    /// so `.none` cannot be expressed (compile error).
    fn recvTimed(s: *Service, sock: *const net.Socket, timeout: Timed) struct { ?net.Socket.ReceiveTimeoutError, usize } {
        return sock.receiveManyTimeout(s.io, s.msgs, s.data, .{}, timeout.toTimeout());
    }

    /// The only `sendManyTimeout` call site; same rule as `recvTimed`.
    fn sendTimed(s: *Service, sock: *const net.Socket, msgs: []net.OutgoingMessage, timeout: Timed) struct { ?net.Socket.SendTimeoutError, usize } {
        return sock.sendManyTimeout(s.io, msgs, .{}, timeout.toTimeout());
    }

    // ---- warnings ----------------------------------------------------------

    fn pushWarning(s: *Service, w: Warning) void {
        if (s.svc_events.push(.{ .warning = w })) {
            s.svc_events_dropped += 1;
            if (!s.events_dropped_warned) {
                s.events_dropped_warned = true;
                if (s.svc_events.push(.{ .warning = .events_dropped })) s.svc_events_dropped += 1;
            }
        }
    }

    /// macOS Local Network privacy signature (4.6): we send but never
    /// receive for 10 s while at least one interface is joined. Once.
    fn checkNoPackets(s: *Service, now_us: u64) void {
        if (s.no_packets_warned) return;
        const first_tx = s.first_tx_us orelse return;
        if (s.joinedCount() == 0) return;
        // `rx` counts our own echoes too; only foreign packets disprove
        // the signature.
        const st = s.engine.stats();
        if (st.rx - st.rx_echo != 0) return;
        if (now_us - first_tx < no_packets_window_us) return;
        s.no_packets_warned = true;
        s.pushWarning(.no_packets_10s);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// A `Service` with a bogus allow-list: real sockets on 5353, nothing
/// joined, so ticks and steps touch the network only with zero-duration
/// drains. Skips when the sandbox refuses the bind.
fn initUnjoinedOrSkip() !Service {
    const bogus = [_]u32{4_000_000};
    return Service.init(testing.allocator, testing.io, .{
        .host_label = "unit",
        .interfaces = &bogus,
    }) catch |err| switch (err) {
        error.PermissionDenied, error.AddressInUse => return error.SkipZigTest,
        else => return err,
    };
}

test "tick drains sockets only after rx_poll_interval_us" {
    // The wiring: `tick` records `last_drain_us` only when it drained.
    {
        var svc = try initUnjoinedOrSkip();
        defer svc.deinit();
        try testing.expectEqual(@as(?u64, null), svc.last_drain_us);
        // First tick: nothing drained yet, so it drains.
        try svc.tick(0);
        try testing.expectEqual(@as(?u64, 0), svc.last_drain_us);
        // Inside the 5 ms interval with no Engine deadline: no drain, the
        // stamp stays.
        try svc.tick(4_000);
        try testing.expectEqual(@as(?u64, 0), svc.last_drain_us);
        try svc.tick(4_999);
        try testing.expectEqual(@as(?u64, 0), svc.last_drain_us);
        // Interval elapsed: drains and re-stamps.
        try svc.tick(5_000);
        try testing.expectEqual(@as(?u64, 5_000), svc.last_drain_us);
        try svc.tick(9_000);
        try testing.expectEqual(@as(?u64, 5_000), svc.last_drain_us);
    }
    // A due Engine deadline drains inside the interval: a browse's first
    // query (20-120 ms after `browse`) falls inside a 1 s poll interval.
    {
        const bogus = [_]u32{4_000_000};
        var svc = Service.init(testing.allocator, testing.io, .{
            .host_label = "unit",
            .interfaces = &bogus,
            .rx_poll_interval_us = 1_000_000,
        }) catch |err| switch (err) {
            error.PermissionDenied, error.AddressInUse => return error.SkipZigTest,
            else => return err,
        };
        defer svc.deinit();
        try svc.tick(0);
        _ = try svc.browse("_x._udp");
        const due = svc.nextDeadline(0).?;
        try testing.expect(due >= 20_000 and due <= 120_000);
        try svc.tick(due - 1);
        try testing.expectEqual(@as(?u64, 0), svc.last_drain_us);
        try svc.tick(due);
        try testing.expectEqual(@as(?u64, due), svc.last_drain_us);
    }

    // The predicate, with a fake clock. Nothing drained yet: drain.
    try testing.expect(shouldDrain(null, 0, 5_000, null));
    // Inside the interval, no deadline: skip.
    try testing.expect(!shouldDrain(100, 4_000, 5_000, null));
    try testing.expect(!shouldDrain(100, 5_099, 5_000, null));
    // Interval elapsed: drain.
    try testing.expect(shouldDrain(100, 5_100, 5_000, null));
    try testing.expect(shouldDrain(100, 1_000_000, 5_000, null));
    // A due deadline drains inside the interval; a future one does not.
    try testing.expect(shouldDrain(100, 2_000, 5_000, 1_500));
    try testing.expect(shouldDrain(100, 2_000, 5_000, 2_000));
    try testing.expect(!shouldDrain(100, 2_000, 5_000, 2_001));
    // A clock that went backwards (asserted elsewhere) does not underflow.
    try testing.expect(!shouldDrain(5_000, 4_000, 5_000, null));
}

test "tick mode then step mode asserts in debug" {
    // `std.testing` cannot catch `std.debug.assert`; the clock-source
    // rule is a pure function that `tick`/`step` assert on.
    try testing.expectEqual(@as(?Mode, .tick), modeAfter(.unset, .tick));
    try testing.expectEqual(@as(?Mode, .step), modeAfter(.unset, .step));
    try testing.expectEqual(@as(?Mode, .tick), modeAfter(.tick, .tick));
    try testing.expectEqual(@as(?Mode, .step), modeAfter(.step, .step));
    // The other mode after the first call is the assertion case.
    try testing.expectEqual(@as(?Mode, null), modeAfter(.tick, .step));
    try testing.expectEqual(@as(?Mode, null), modeAfter(.step, .tick));
}

test "clampToDeadline rounds up and caps at 250 ms" {
    try testing.expectEqual(@as(u64, 250_000), clampToDeadline(null, 0, 250_000));
    try testing.expectEqual(@as(u64, 250_000), clampToDeadline(null, 0, 900_000));
    try testing.expectEqual(@as(u64, 100_000), clampToDeadline(null, 0, 100_000));
    // Due or under the floor: 2 ms (1 ms would be poll(0) on Threaded).
    try testing.expectEqual(@as(u64, 2_000), min_wait_us);
    try testing.expectEqual(@as(u64, 2_000), clampToDeadline(5, 10, 250_000));
    try testing.expectEqual(@as(u64, 2_000), clampToDeadline(10, 10, 250_000));
    try testing.expectEqual(@as(u64, 2_000), clampToDeadline(10_500, 10_000, 250_000));
    try testing.expectEqual(@as(u64, 2_000), clampToDeadline(11_001, 10_000, 250_000));
    // Rounded up to whole milliseconds, never past the cap.
    try testing.expectEqual(@as(u64, 3_000), clampToDeadline(12_001, 10_000, 250_000));
    try testing.expectEqual(@as(u64, 7_000), clampToDeadline(17_000, 10_000, 250_000));
    try testing.expectEqual(@as(u64, 250_000), clampToDeadline(1_000_000, 0, 250_000));
    try testing.expectEqual(@as(u64, 50_000), clampToDeadline(1_000_000, 0, 50_000));
    // A zero cap still waits the floor (no busy spin).
    try testing.expectEqual(@as(u64, 2_000), clampToDeadline(null, 0, 0));
    try testing.expectEqual(@as(u64, 2_000), clampToDeadline(null, 0, 1_000));
}

test "receive errors are classified like quic-zig" {
    try testing.expectEqual(ReceiveDisposition.timeout, classifyReceiveError(error.Timeout));
    for ([_]net.Socket.ReceiveTimeoutError{ error.ConnectionResetByPeer, error.PortUnreachable, error.MessageOversize }) |e| {
        try testing.expectEqual(ReceiveDisposition.tolerate, classifyReceiveError(e));
    }
    for ([_]net.Socket.ReceiveTimeoutError{ error.Canceled, error.SystemResources, error.NetworkDown, error.ConcurrencyUnavailable, error.Unexpected }) |e| {
        try testing.expectEqual(ReceiveDisposition.fatal, classifyReceiveError(e));
    }
}

test "Timed cannot express none" {
    // `recvTimed rejects Timeout.none at comptime`: `Timed` has no `.none`
    // member and the helpers accept only `Timed`, so an untimed call does
    // not compile. This test only pins the conversions.
    try testing.expect(Timed.zero.isZero());
    try testing.expect(!Timed.micros(1_000).isZero());
    const t = Timed.micros(2_500).toTimeout();
    try testing.expectEqual(@as(i64, 2_500), t.duration.raw.toMicroseconds());
    try testing.expectEqual(Io.Clock.awake, t.duration.clock);
    comptime {
        // The `Timed` tag set is exactly {duration, deadline}.
        std.debug.assert(@typeInfo(Timed).@"union".field_types.len == 2);
        std.debug.assert(!@hasField(Timed, "none"));
    }
}

test "join_failed warning carries ifindex and family" {
    // A real failed join, no root needed: an interface index that does
    // not exist (and a v4 address no interface owns) makes the kernel
    // refuse both memberships. The allow-list keeps init from joining
    // anything real first.
    const bogus: u32 = 4_000_000;
    const allow = [_]u32{bogus};
    var svc = Service.init(testing.allocator, testing.io, .{
        .host_label = "unit",
        .interfaces = &allow,
    }) catch |err| switch (err) {
        error.PermissionDenied, error.AddressInUse => return error.SkipZigTest,
        else => return err,
    };
    defer svc.deinit();

    // init: zero joined with an allow-list => no_interfaces, no join_failed.
    var evs: [8]Event = undefined;
    var n = svc.poll(&evs);
    var saw_no_interfaces = false;
    for (evs[0..n]) |ev| switch (ev) {
        .warning => |w| switch (w) {
            .no_interfaces => saw_no_interfaces = true,
            .join_failed => return error.TestUnexpectedResult,
            else => {},
        },
        else => {},
    };
    try testing.expect(saw_no_interfaces);

    // Inject a snapshot naming the bogus interface with one address per
    // family; the joins fail and each failure names the interface.
    var snap: ifaces.Snapshot = .{};
    var iface: Interface = .{ .index = bogus };
    try iface.v4.append(.{ .addr = .{ 10, 254, 254, 254 }, .prefix_len = 32 });
    var a6: [16]u8 = @splat(0);
    a6[0] = 0xfe;
    a6[1] = 0x80;
    a6[15] = 1;
    try iface.v6.append(.{ .addr = a6, .prefix_len = 64 });
    snap.items[0] = iface;
    snap.len = 1;
    try testing.expectEqual(@as(usize, 0), svc.applySnapshot(&snap));

    n = svc.poll(&evs);
    var got_v4 = false;
    var got_v6 = false;
    for (evs[0..n]) |ev| {
        const w = ev.warning;
        try testing.expect(w == .join_failed);
        try testing.expectEqual(bogus, w.join_failed.ifindex);
        switch (w.join_failed.family) {
            .v4 => got_v4 = true,
            .v6 => got_v6 = true,
        }
    }
    try testing.expect(got_v4);
    try testing.expectEqual(svc.hasIpv6(), got_v6);
    try testing.expectEqual(@as(usize, 0), svc.joinedCount());
}

fn dualIface(index: u32) Interface {
    var iface: Interface = .{ .index = index };
    iface.v4.append(.{ .addr = .{ 10, 254, 254, 254 }, .prefix_len = 24 }) catch unreachable; // capacity 8
    var a6: [16]u8 = @splat(0);
    a6[0] = 0xfe;
    a6[1] = 0x80;
    a6[15] = 1;
    iface.v6.append(.{ .addr = a6, .prefix_len = 64 }) catch unreachable; // capacity 8
    return iface;
}

test "syncJoined carries a failed join into the Engine" {
    // Revision 5 item 1, Service half: the Engine defaults every family
    // with an address to joined; `syncJoined` overrides it with what the
    // sockets actually joined, so a browse queries only on those pairs.
    var svc = try initUnjoinedOrSkip();
    defer svc.deinit();
    const bogus: u32 = 4_000_000;
    svc.table.items[0] = dualIface(bogus);
    svc.table.len = 1;
    try svc.engine.setInterfaces(svc.table.slice(), 0);
    try testing.expect(svc.engine.isJoined(bogus, .v4));
    try testing.expect(svc.engine.isJoined(bogus, .v6));
    // The v6 join failed (Linux `lo`, or here: a bogus interface).
    svc.joined[0] = .{ .v4 = true, .v6 = false };
    svc.syncJoined();
    try testing.expect(svc.engine.isJoined(bogus, .v4));
    try testing.expect(!svc.engine.isJoined(bogus, .v6));
    // The browse's first tick queues one datagram, v4 only.
    _ = try svc.engine.browse("_x._udp", 0);
    const due = svc.engine.nextDeadline(0).?;
    svc.engine.tick(due);
    const d = svc.engine.pollDatagram(svc.tx_buf, due).?;
    try testing.expect(d.to == .ip4);
    try testing.expectEqual(bogus, d.ifindex);
    try testing.expectEqual(@as(?Engine.TxDatagram, null), svc.engine.pollDatagram(svc.tx_buf, due));
    // Both joined again: v4 then v6.
    svc.joined[0] = .{ .v4 = true, .v6 = true };
    svc.syncJoined();
    const due2 = svc.engine.nextDeadline(due).?;
    svc.engine.tick(due2);
    try testing.expect(svc.engine.pollDatagram(svc.tx_buf, due2).?.to == .ip4);
    try testing.expect(svc.engine.pollDatagram(svc.tx_buf, due2).?.to == .ip6);
}

test "no_packets_10s warning ignores own echoes" {
    // Plan 4.6: `tx > 0` with no foreign packet for 10 s. Our own looped
    // back queries count in `rx` (and `rx_echo`); they must not hide
    // the signature.
    var svc = try initUnjoinedOrSkip();
    defer svc.deinit();
    const bogus: u32 = 4_000_000;
    svc.table.items[0] = dualIface(bogus);
    svc.table.len = 1;
    try svc.engine.setInterfaces(svc.table.slice(), 0);
    svc.joined[0] = .{ .v4 = true, .v6 = false };
    svc.first_tx_us = 0;
    var evs: [8]Event = undefined;
    _ = svc.poll(&evs);
    // A query we sent comes back from our own address: an echo.
    var qb: [64]u8 = @splat(0);
    qb[5] = 1; // qdcount 1
    qb[12] = 1;
    qb[13] = 'x';
    qb[16] = 12; // PTR
    qb[18] = 1; // IN
    const query = qb[0..19];
    svc.engine.echoes.record(query, 0);
    svc.engine.handle(query, .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 254, 254, 254 }, .port = 5353 } }, .ifindex = bogus, .dst_multicast = true }, 0);
    try testing.expectEqual(@as(u64, 1), svc.engine.stats().rx);
    try testing.expectEqual(@as(u64, 1), svc.engine.stats().rx_echo);
    svc.checkNoPackets(9 * 1_000_000);
    try testing.expectEqual(@as(usize, 0), svc.poll(&evs));
    svc.checkNoPackets(10 * 1_000_000);
    try testing.expectEqual(@as(usize, 1), svc.poll(&evs));
    try testing.expect(evs[0] == .warning and evs[0].warning == .no_packets_10s);
    // A foreign packet disproves it: no warning even after 10 s.
    svc.no_packets_warned = false;
    svc.engine.handle(query, .{ .from = .{ .ip4 = .{ .bytes = .{ 10, 254, 254, 9 }, .port = 5353 } }, .ifindex = bogus, .dst_multicast = true }, 0);
    try testing.expectEqual(@as(u64, 2), svc.engine.stats().rx);
    svc.checkNoPackets(20 * 1_000_000);
    try testing.expectEqual(@as(usize, 0), svc.poll(&evs));
}

test "browse before the first step is stamped with the current clock" {
    // `init` -> `browse` -> `run`: the 20-120 ms first-query delay
    // counts from the browse call, not from `init` (mode unset, and
    // modes B/C). `last_now_us` stays 0 for a mode A embedder.
    var svc = try initUnjoinedOrSkip();
    defer svc.deinit();
    (Io.Clock.Duration{ .raw = .fromMilliseconds(150), .clock = .awake }).sleep(testing.io) catch |err| switch (err) {
        error.Canceled => return error.SkipZigTest,
    };
    const before = svc.nowUs();
    try testing.expect(before >= 150_000);
    _ = try svc.browse("_x._udp");
    const due = svc.nextDeadline(before).?;
    try testing.expect(due >= before + 20_000);
    try testing.expect(due <= svc.nowUs() + 120_000);
    try testing.expectEqual(@as(u64, 0), svc.last_now_us);
    try testing.expectEqual(Mode.unset, svc.mode);
}

const CancelProbe = struct {
    /// Runs as a `Group` task: waits until the cancel lands on a sleep,
    /// re-arms it with `recancel` so the next cancelation point sees it
    /// again, and makes that point a send.
    fn run(s: *Service, result: *Io.Cancelable!void, sleeps: *u32) void {
        while (true) {
            (Io.Clock.Duration{ .raw = .fromMilliseconds(1), .clock = .awake }).sleep(s.io) catch |err| switch (err) {
                error.Canceled => break,
            };
            sleeps.* += 1;
            // Safety net: never hang the test binary.
            if (sleeps.* > 20_000) {
                result.* = {};
                return;
            }
        }
        s.io.recancel();
        // With the cancel pending, `Syscall.start` returns before sendmsg
        // (Threaded.zig:1366), so nothing leaves the host.
        s.tx_buf[0] = 0;
        result.* = s.sendDatagram(.{
            .to = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9 } },
            .len = 1,
            .ifindex = 0,
        });
    }
};

test "send is a cancelation point and propagates Canceled" {
    // Regression for the M2 review: `sendDatagram` used to count
    // `error.Canceled` as a drop, which under Threaded's one-shot
    // cancelation lost the cancel and left `Group.cancel` blocked.
    var svc = try initUnjoinedOrSkip();
    defer svc.deinit();
    const io = testing.io;

    var result: Io.Cancelable!void = {};
    var sleeps: u32 = 0;
    var group: Io.Group = .init;
    group.concurrent(io, CancelProbe.run, .{ &svc, &result, &sleeps }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.SkipZigTest,
    };
    try (Io.Clock.Duration{ .raw = .fromMilliseconds(5), .clock = .awake }).sleep(io);
    group.cancel(io);

    try testing.expectError(error.Canceled, result);
    try testing.expect(sleeps <= 20_000);
    // A propagated cancel is not a drop.
    try testing.expectEqual(@as(u64, 0), svc.tx_dropped);
    try testing.expectEqual(@as(u64, 0), svc.stats().tx_dropped);
}

test "serve backs off one step cap after a fatal step error" {
    // The policy `serve` applies to a non-Canceled `StepError`: count it
    // and sleep `max_step_cap_us` on the awake clock (a cancelation
    // point), so a persistent local fault costs four steps a second
    // instead of a spin. Fault injection needs a foreign `Io`; the
    // helper is exercised directly.
    var svc = try initUnjoinedOrSkip();
    defer svc.deinit();
    const before = svc.nowUs();
    try svc.backOffAfterFault();
    const elapsed = svc.nowUs() - before;
    try testing.expectEqual(@as(u64, 1), svc.rxCounters().fatal_errors);
    // Threaded truncates to whole ms: at least 249 ms passed.
    try testing.expect(elapsed >= max_step_cap_us - 1_000);
    try testing.expectEqual(@as(u64, 0), svc.rxCounters().truncated);
}

test "mailbox put drops oldest after the cap and counts" {
    var buf: [2]Event = undefined;
    var m: Mailbox = .init(&buf);
    const io = testing.io;
    try m.put(io, .interfaces_changed, .zero);
    try m.put(io, .{ .warning = .no_interfaces }, .zero);
    // Full: the zero cap means no retry; the oldest goes.
    try m.put(io, .{ .warning = .v6_unavailable }, .zero);
    try testing.expectEqual(@as(u64, 1), m.dropped);
    try testing.expectEqual(Warning.no_interfaces, (try m.next(io)).warning);
    try testing.expectEqual(Warning.v6_unavailable, (try m.next(io)).warning);
    // A short cap sleeps in 10 ms rounds and then drops.
    try m.put(io, .interfaces_changed, .zero);
    try m.put(io, .interfaces_changed, .zero);
    try m.put(io, .{ .warning = .events_dropped }, .fromMilliseconds(15));
    try testing.expectEqual(@as(u64, 2), m.dropped);
    m.close(io);
    _ = try m.next(io);
    _ = try m.next(io);
    try testing.expectError(error.Closed, m.next(io));
    try testing.expectError(error.Closed, m.put(io, .interfaces_changed, .zero));
}
