#!/bin/sh
# interop/macos-dnssd.sh: six checks of zig-out/bin/mdns-advertise against
# macOS mDNSResponder through /usr/bin/dns-sd (plan section 7 M4 acceptance).
#
#   sh interop/macos-dnssd.sh            # builds the examples first
#   SKIP_BUILD=1 sh interop/macos-dnssd.sh
#
# Run it from Terminal or SSH: a GUI-launched shell may lack Local Network
# permission and see no multicast at all. Needs nothing beyond the stock
# macOS tools (dns-sd, perl for timeouts, pgrep). Every background process
# it starts is killed by the EXIT trap; each wait has a deadline.
#
# Checks (each prints PASS or FAIL and the summary counts them):
#   1 advertise -> `dns-sd -B _qmsg._udp` lists the instance within 3 s
#   2 `dns-sd -L <name> _qmsg._udp local` shows the port and TXT
#   3 goodbye: SIGINT to advertise -> -B shows Rmv within 3 s (RFC 6762 10.1)
#   4 conflict A: dns-sd -R demo first, then ours -> our log shows renamed to
#     "demo (2)" and -B lists both (sections 8.1 probe, 9 rename)
#   5 conflict B: ours first, then dns-sd -R demo -> mDNSResponder renames
#     itself to "demo (2)" while ours stays "demo" (multicast defence, 8.1)
#   6 updateTxt: SIGUSR1 -> `dns-sd -L` shows seq=1 within 3 s (section 8.4)

set -u

here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here" || exit 2
bin="$here/zig-out/bin/mdns-advertise"
type="_qmsg._udp"
name="${MDNS_INTEROP_NAME:-demo}"
port="${MDNS_INTEROP_PORT:-4433}"
work=$(mktemp -d "${TMPDIR:-/tmp}/mdns-interop.XXXXXX")
pids=""
pass=0
fail=0

# ---- helpers ----------------------------------------------------------------

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

# Timeout wrapper (macOS has no coreutils timeout): perl forks the command
# with SIGINT/SIGTERM restored to their defaults (a background job of a
# non-interactive shell inherits INT ignored), TERMs it when the alarm
# fires or when perl itself gets TERM/INT, KILLs it 2 s later, and exits
# with the command's status, so the shell never reports a signal.
timeout_pl='
    my $t = shift @ARGV;
    my $pid = fork;
    if (!$pid) { $SIG{INT} = "DEFAULT"; $SIG{TERM} = "DEFAULT"; exec @ARGV or exit 127; }
    my $fire = sub { kill "TERM", $pid; $SIG{ALRM} = sub { kill "KILL", $pid; }; alarm 2; };
    $SIG{ALRM} = $fire; $SIG{INT} = $fire; $SIG{TERM} = $fire;
    alarm $t;
    my $r;
    do { $r = waitpid($pid, 0); } while ($r == -1 && $!{EINTR});
    exit(($? >> 8) || ($? & 127 ? 128 + ($? & 127) : 0));
'

# with_timeout SECONDS cmd args...: run cmd in the foreground for at most
# SECONDS.
with_timeout() {
    secs=$1
    shift
    perl -e "$timeout_pl" -- "$secs" "$@"
}

# bg_timeout LOGFILE SECONDS cmd args...: `bg` under the timeout wrapper.
# perl itself is the background job (not a subshell), so cleanup's TERM
# reaches the command through it.
bg_timeout() {
    logfile=$1
    secs=$2
    shift 2
    bg "$logfile" perl -e "$timeout_pl" -- "$secs" "$@"
}

# bg LOGFILE cmd args...: start cmd in the background, log to LOGFILE, and
# return its pid in $bg_pid (registered for cleanup).
bg() {
    logfile=$1
    shift
    "$@" >"$logfile" 2>&1 &
    bg_pid=$!
    pids="$pids $bg_pid"
}

# wait_for SECONDS PATTERN FILE: poll FILE (grep -E) every 0.2 s.
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

# start_adv NAME LOG [extra args]: launch mdns-advertise as NAME.
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

# ---- prerequisites ---------------------------------------------------------------

if [ ! -x /usr/bin/dns-sd ]; then
    log "macos-dnssd: /usr/bin/dns-sd not found; this script is for macOS"
    exit 2
fi
if [ "${SKIP_BUILD:-}" != 1 ]; then
    log "macos-dnssd: building examples"
    if ! mise exec -- zig build examples; then
        log "macos-dnssd: build failed"
        exit 2
    fi
fi
if [ ! -x "$bin" ]; then
    log "macos-dnssd: $bin missing (run: mise exec -- zig build examples)"
    exit 2
fi
if pgrep -x mdns-advertise >/dev/null 2>&1; then
    log "macos-dnssd: another mdns-advertise is running; stop it first"
    exit 2
fi
log "macos-dnssd: work dir $work, instance $name.$type port $port"

# ---- 1: advertise -> dns-sd -B lists it within 3 s --------------------------------

log "--- check 1: advertise -> dns-sd -B lists $name within 3 s"
bg "$work/b1.log" dns-sd -B "$type"
b_pid=$bg_pid
sleep 0.5
start_adv "$name" "$work/a1.log"
if wait_for 3 "Add .* $type_re\. +$name_re\$" "$work/b1.log"; then
    result PASS "PASS 1 dns-sd -B lists $name"
else
    result FAIL "FAIL 1 dns-sd -B did not list $name within 3 s"
    log "  advertise log:"; sed 's/^/    /' "$work/a1.log"
    log "  dns-sd -B log:"; sed 's/^/    /' "$work/b1.log"
fi
# The remaining checks need our registration to have completed.
wait_for 3 "^registered " "$work/a1.log" || log "  note: no 'registered' line in our log yet"

# ---- 2: dns-sd -L shows the port and TXT ---------------------------------------------

log "--- check 2: dns-sd -L $name $type local shows port $port and txtvers=1"
with_timeout 4 dns-sd -L "$name" "$type" local >"$work/l2.log" 2>&1
if grep -Eq "can be reached at .*:$port " "$work/l2.log" && grep -Eq "txtvers=1" "$work/l2.log"; then
    result PASS "PASS 2 dns-sd -L shows :$port and txtvers=1"
else
    result FAIL "FAIL 2 dns-sd -L did not show :$port with txtvers=1"
    log "  dns-sd -L log:"; sed 's/^/    /' "$work/l2.log"
fi

# ---- 3: goodbye: SIGINT -> dns-sd -B shows Rmv within 3 s ------------------------------

log "--- check 3: SIGINT to advertise -> dns-sd -B shows Rmv $name within 3 s"
kill -INT "$adv_pid" 2>/dev/null
if wait_for 3 "Rmv .* $type_re\. +$name_re\$" "$work/b1.log"; then
    result PASS "PASS 3 goodbye: dns-sd -B shows Rmv $name"
else
    result FAIL "FAIL 3 no Rmv $name within 3 s of SIGINT"
    log "  advertise log:"; sed 's/^/    /' "$work/a1.log"
    log "  dns-sd -B log:"; sed 's/^/    /' "$work/b1.log"
fi
cleanup
sleep 1

# ---- 4: conflict A: dns-sd -R first, then ours -> ours renamed to "demo (2)" -------------

log "--- check 4: dns-sd -R $name first, then ours -> our log shows renamed to \"$name (2)\""
bg "$work/r4.log" dns-sd -R "$name" "$type" . "$port" x=1
r_pid=$bg_pid
if ! wait_for 5 "Name now registered" "$work/r4.log"; then
    log "  note: dns-sd -R did not confirm registration within 5 s"
fi
bg "$work/b4.log" dns-sd -B "$type"
sleep 0.5
start_adv "$name" "$work/a4.log"
renamed_re="^renamed .* -> $name_re \\(2\\)\\.$type_re\\.local"
if wait_for 8 "$renamed_re" "$work/a4.log" && wait_for 3 "Add .* $type_re\. +$name_re \\(2\\)\$" "$work/b4.log" && grep -Eq "Add .* $type_re\. +$name_re\$" "$work/b4.log"; then
    result PASS "PASS 4 conflict A: ours renamed to \"$name (2)\", dns-sd -B lists both"
else
    result FAIL "FAIL 4 conflict A: expected renamed -> \"$name (2)\" in our log and both in dns-sd -B"
    log "  advertise log:"; sed 's/^/    /' "$work/a4.log"
    log "  dns-sd -B log:"; sed 's/^/    /' "$work/b4.log"
    log "  dns-sd -R log:"; sed 's/^/    /' "$work/r4.log"
fi
cleanup
sleep 2

# ---- 5: conflict B: ours first, then dns-sd -R -> mDNSResponder renames -----------------

log "--- check 5: ours first, then dns-sd -R $name -> dns-sd renames itself, ours stays $name"
start_adv "$name" "$work/a5.log"
if ! wait_for 5 "^registered .*$name_re\\.$type_re\\.local" "$work/a5.log"; then
    log "  note: no 'registered' line within 5 s"
fi
bg "$work/b5.log" dns-sd -B "$type"
bg "$work/r5.log" dns-sd -R "$name" "$type" . "$((port + 1))" x=2
r_pid=$bg_pid
if wait_for 8 "Name now registered" "$work/r5.log"; then
    :
fi
sleep 1
theirs_renamed=0
if grep -Eq "service $name_re \\(2\\)\\.$type_re\\.local" "$work/r5.log"; then theirs_renamed=1; fi
if grep -Eq "Add .* $type_re\. +$name_re \\(2\\)\$" "$work/b5.log"; then theirs_renamed=1; fi
ours_stayed=1
if grep -Eq "^renamed " "$work/a5.log"; then ours_stayed=0; fi
if [ "$theirs_renamed" = 1 ] && [ "$ours_stayed" = 1 ]; then
    result PASS "PASS 5 conflict B: dns-sd renamed itself to \"$name (2)\", ours stayed $name"
else
    result FAIL "FAIL 5 conflict B: theirs_renamed=$theirs_renamed ours_stayed=$ours_stayed"
    log "  advertise log:"; sed 's/^/    /' "$work/a5.log"
    log "  dns-sd -R log:"; sed 's/^/    /' "$work/r5.log"
    log "  dns-sd -B log:"; sed 's/^/    /' "$work/b5.log"
fi
# Stop dns-sd -R / -B but keep our advertise for check 6.
kill -INT "$r_pid" 2>/dev/null
sleep 1

# ---- 6: updateTxt: SIGUSR1 -> dns-sd -L shows seq=1 within 3 s ----------------------------

log "--- check 6: SIGUSR1 to advertise -> dns-sd -L shows seq=1 within 3 s"
kill -USR1 "$adv_pid" 2>/dev/null
bg_timeout "$work/l6.log" 3 dns-sd -L "$name" "$type" local
if wait_for 3 "seq=1" "$work/l6.log"; then
    result PASS "PASS 6 updateTxt: dns-sd -L shows seq=1"
else
    result FAIL "FAIL 6 updateTxt: seq=1 not shown by dns-sd -L within 3 s"
    log "  advertise log:"; sed 's/^/    /' "$work/a5.log"
    log "  dns-sd -L log:"; sed 's/^/    /' "$work/l6.log"
fi
cleanup

# ---- summary -------------------------------------------------------------------------

log "macos-dnssd: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
