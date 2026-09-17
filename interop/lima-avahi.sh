#!/bin/sh
# interop/lima-avahi.sh: three checks of the cross-built Linux
# zig-out/bin/mdns-advertise against avahi-daemon (plan section 7 M4).
# Runs INSIDE the Lima VM, which mounts /Users/nullstyle:
#
#   mise exec -- zig build examples -Dtarget=aarch64-linux-musl
#   ssh -o IdentityAgent=none -o IdentitiesOnly=yes -F ~/.lima/zig-uring/ssh.config lima-zig-uring \
#       'sh /Users/nullstyle/prj/zig/mdns-zig/interop/lima-avahi.sh'
#
# (`limactl shell` hangs from a non-tty; use the ssh form, or `just
# interop-lima`.) Inside the VM avahi-daemon (uid avahi) and
# systemd-resolved both hold *:5353, so our binary is never the first
# binder there: QU is off and defence is multicast (plan section 4.8).
#
# Checks (each prints PASS or FAIL; the summary counts them):
#   a `avahi-browse -rt _qmsg._udp` resolves our instance (host, address, port, TXT)
#   b avahi-publish "demo" first, ours as "demo" -> our log shows renamed "demo (2)"
#   c ours as "demo" first, then avahi-publish demo -> avahi-publish reports a
#     collision or renames itself (its own log), ours stays "demo"

set -u

root="${MDNS_REPO:-/Users/nullstyle/prj/zig/mdns-zig}"
bin="$root/zig-out/bin/mdns-advertise"
type="_qmsg._udp"
name="${MDNS_INTEROP_NAME:-demo}"
port="${MDNS_INTEROP_PORT:-4433}"
work=$(mktemp -d "${TMPDIR:-/tmp}/mdns-interop.XXXXXX")
pids=""
pass=0
fail=0

log() { printf '%s\n' "$*"; }

# Kill every background process we started: SIGTERM first (our advertise
# handles it like SIGINT and sends its goodbye; dns-sd/avahi exit; a
# background job of a non-interactive shell ignores SIGINT, so INT would
# not do), SIGKILL after 2 s, and `wait` reaps each one with stderr
# silenced so the shell's "Killed: 9" job notices do not interleave with
# the PASS/FAIL lines.
cleanup() {
    for p in $pids; do
        kill -TERM "$p" 2>/dev/null || true
    done
    for p in $pids; do
        i=0
        while kill -0 "$p" 2>/dev/null && [ "$i" -lt 10 ]; do
            sleep 0.2
            i=$((i + 1))
        done
        kill -KILL "$p" 2>/dev/null || true
        wait "$p" 2>/dev/null
    done
    pids=""
}
trap 'cleanup; rm -rf "$work"' EXIT
trap 'cleanup; exit 130' INT TERM

bg() {
    logfile=$1
    shift
    "$@" >"$logfile" 2>&1 &
    bg_pid=$!
    pids="$pids $bg_pid"
}

wait_for() {
    secs=$1
    pattern=$2
    file=$3
    i=0
    limit=$((secs * 5))
    while [ "$i" -lt "$limit" ]; do
        if grep -Eq "$pattern" "$file" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
        i=$((i + 1))
    done
    grep -Eq "$pattern" "$file" 2>/dev/null
}

start_adv() {
    adv_name=$1
    adv_log=$2
    shift 2
    bg "$adv_log" "$bin" --type "$type" --name "$adv_name" --port "$port" --txt txtvers=1 "$@"
    adv_pid=$bg_pid
}

result() {
    if [ "$1" = PASS ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
    shift
    log "$*"
}

esc() { printf '%s' "$1" | sed 's/[][()\\.*^$]/\\&/g'; }
name_re=$(esc "$name")
type_re=$(esc "$type")

# ---- prerequisites --------------------------------------------------------------

for tool in avahi-browse avahi-publish timeout; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        log "lima-avahi: $tool not found in the VM (install avahi-utils / coreutils)"
        exit 2
    fi
done
if [ ! -x "$bin" ]; then
    log "lima-avahi: $bin missing; on the host run: mise exec -- zig build examples -Dtarget=aarch64-linux-musl"
    exit 2
fi
# A native macOS build overwrites the same path; make sure this one runs here.
if ! "$bin" --help >/dev/null 2>&1; then
    log "lima-avahi: $bin does not run here (a macOS build?); rebuild with -Dtarget=aarch64-linux-musl"
    exit 2
fi
if pgrep -x mdns-advertise >/dev/null 2>&1; then
    log "lima-avahi: another mdns-advertise is running; stop it first"
    exit 2
fi
log "lima-avahi: $(hostname), work dir $work, instance $name.$type port $port"
log "lima-avahi: avahi-daemon $(systemctl is-active avahi-daemon 2>/dev/null || echo unknown), systemd-resolved $(systemctl is-active systemd-resolved 2>/dev/null || echo unknown)"

# ---- a: avahi-browse -rt resolves us ---------------------------------------------------

log "--- check a: avahi-browse -rt $type resolves $name"
start_adv "$name" "$work/a.log"
if ! wait_for 5 "^registered " "$work/a.log"; then
    log "  note: no 'registered' line within 5 s"
    sed 's/^/    /' "$work/a.log"
fi
timeout 10 avahi-browse -prt "$type" >"$work/browse-a.log" 2>&1
# Parsable resolved line: =;iface;proto;name;type;domain;host;address;port;txt
if grep -Eq "^=;[^;]*;[^;]*;$name_re;$type_re;local;[^;]+;[^;]+;$port;.*txtvers=1" "$work/browse-a.log"; then
    result PASS "PASS a avahi-browse resolved $name: $(grep -E "^=;[^;]*;IPv4;$name_re;" "$work/browse-a.log" | head -1)"
else
    result FAIL "FAIL a avahi-browse did not resolve $name.$type with port $port and txtvers=1"
    log "  advertise log:"; sed 's/^/    /' "$work/a.log"
    log "  avahi-browse log:"; sed 's/^/    /' "$work/browse-a.log"
fi
cleanup
sleep 2

# ---- b: avahi-publish first, then ours -> ours renamed ----------------------------------------

log "--- check b: avahi-publish $name first, then ours -> our log shows renamed \"$name (2)\""
bg "$work/pub-b.log" avahi-publish -s "$name" "$type" "$port" x=1
pub_pid=$bg_pid
if ! wait_for 5 "Established" "$work/pub-b.log"; then
    log "  note: avahi-publish did not report Established within 5 s"
fi
start_adv "$name" "$work/b.log"
if wait_for 8 "^renamed .* -> $name_re \\(2\\)\\.$type_re\\.local" "$work/b.log"; then
    result PASS "PASS b conflict: ours renamed to \"$name (2)\""
else
    result FAIL "FAIL b conflict: no renamed -> \"$name (2)\" in our log within 8 s"
    log "  advertise log:"; sed 's/^/    /' "$work/b.log"
    log "  avahi-publish log:"; sed 's/^/    /' "$work/pub-b.log"
fi
cleanup
sleep 2

# ---- c: ours first, then avahi-publish -> avahi collides or renames ------------------------------

log "--- check c: ours first, then avahi-publish $name -> collision or rename on avahi's side"
start_adv "$name" "$work/c.log"
if ! wait_for 5 "^registered " "$work/c.log"; then
    log "  note: no 'registered' line within 5 s"
fi
# avahi-publish exits on a local collision and renames on a network one;
# run it under a timeout so a quiet success does not hang the check.
timeout 8 avahi-publish -s "$name" "$type" "$((port + 1))" x=2 >"$work/pub-c.log" 2>&1
pub_rc=$?
theirs=0
if grep -Eiq "collision" "$work/pub-c.log"; then theirs=1; fi
if grep -Eq "$name_re #2|$name_re \\(2\\)" "$work/pub-c.log"; then theirs=1; fi
if [ "$pub_rc" -ne 0 ] && [ "$pub_rc" -ne 124 ]; then theirs=1; fi
ours_stayed=1
if grep -Eq "^renamed " "$work/c.log"; then ours_stayed=0; fi
if [ "$theirs" = 1 ] && [ "$ours_stayed" = 1 ]; then
    result PASS "PASS c avahi-publish backed off (rc=$pub_rc: $(tr '\n' ' ' <"$work/pub-c.log")), ours stayed $name"
else
    result FAIL "FAIL c theirs=$theirs (rc=$pub_rc) ours_stayed=$ours_stayed"
    log "  advertise log:"; sed 's/^/    /' "$work/c.log"
    log "  avahi-publish log:"; sed 's/^/    /' "$work/pub-c.log"
fi
cleanup

log "lima-avahi: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
