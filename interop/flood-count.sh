#!/bin/sh
# interop/flood-count.sh: count the mDNS datagrams THIS HOST sends for one
# name over a capture window, without tcpdump (sudo is unavailable on the
# gate Mac). The join_pktinfo spike shares *:5353, joins both groups on
# every interface and dumps every datagram it receives, including our own
# through multicast loopback, with a JSON sidecar naming the source. This
# script runs the spike for the window, then keeps the datagrams whose
# source is one of this host's addresses AND whose payload contains the
# wire-encoded name, and prints the counts split by the QR bit (byte 2,
# bit 7: 0 = query, 1 = response) and by capture second.
#
#   sh interop/flood-count.sh --seconds 60 --service demo._qmsg._udp
#   sh interop/flood-count.sh --seconds 60 --service demo._qmsg._udp --assert idle-advertise
#   sh interop/flood-count.sh --seconds 120 --service _qmsg._udp --assert idle-browse
#
# Run mdns-advertise (or mdns-browse) beside it, from Terminal or SSH.
#
# --assert idle-advertise: after the first `--after` seconds (default 30;
#   probing and announcing are over by then, RFC 6762 8.1/8.3) this host
#   sends 0 unsolicited packets for the name: no query, and no response
#   that no foreign query for the name preceded within 2 s.
# --assert idle-browse: after the first `--after` seconds (default 60)
#   this host sends at most 2 queries for the name in the rest of the
#   window (the section 5.2 schedule has doubled past 1 s by then; the
#   plan's budget is <= 2 queries per 60 s after minute one).
#
# Flags: --seconds N (default 60), --after S, --service NAME (default
# _qmsg._udp; a full instance or type name, no trailing dot; --name is an
# alias), --assert MODE, --dir DIR (keep the dump there instead of a temp
# dir), --keep. With an advertiser that has been idle since before the
# capture started, pass --after 0 so the whole window counts. Pure sh plus
# python3 for the parsing.

set -u

here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here" || exit 2
seconds=60
after=""
service="_qmsg._udp"
mode=""
dir=""
keep=0
while [ $# -gt 0 ]; do
    case "$1" in
        --seconds) seconds=$2; shift 2 ;;
        --after) after=$2; shift 2 ;;
        --service|--name) service=$2; shift 2 ;;
        --assert) mode=$2; shift 2 ;;
        --dir) dir=$2; shift 2 ;;
        --keep) keep=1; shift ;;
        -h|--help) sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "flood-count: unknown argument $1" >&2; exit 2 ;;
    esac
done
case "$mode" in
    ""|idle-advertise|idle-browse) ;;
    *) echo "flood-count: --assert must be idle-advertise or idle-browse" >&2; exit 2 ;;
esac
if [ -z "$after" ]; then
    if [ "$mode" = idle-browse ]; then after=60; else after=30; fi
fi
if [ "$seconds" -le "$after" ] && [ -n "$mode" ]; then
    echo "flood-count: --seconds ($seconds) must exceed --after ($after) for --assert $mode" >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "flood-count: python3 not found" >&2
    exit 2
fi

if [ -z "$dir" ]; then
    dir=$(mktemp -d "${TMPDIR:-/tmp}/mdns-flood.XXXXXX")
else
    mkdir -p "$dir"
    if [ -n "$(ls -A "$dir")" ]; then
        echo "flood-count: $dir is not empty (the spike numbers files from 0001)" >&2
        exit 2
    fi
fi
spike_log="$dir.spike.log"
spike_pid=""
cleanup() {
    if [ -n "$spike_pid" ]; then kill "$spike_pid" 2>/dev/null || true; fi
    if [ "$keep" = 0 ]; then rm -rf "$dir" "$spike_log"; fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

# This host's addresses (v4 and v6, scope suffix stripped).
if command -v ifconfig >/dev/null 2>&1; then
    addrs=$(ifconfig | awk '/inet6? /{print $2}' | sed 's/%.*//' | sort -u)
else
    addrs=$(ip -o addr 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | sort -u)
fi
if [ -z "$addrs" ]; then
    echo "flood-count: could not list this host's addresses" >&2
    exit 2
fi

echo "flood-count: capturing $seconds s into $dir (name $service, host addresses: $(printf '%s' "$addrs" | tr '\n' ' '))"
mise exec -- zig build spike-join_pktinfo -- --seconds "$seconds" --dump "$dir" --label "flood-count $service" >"$spike_log" 2>&1 &
spike_pid=$!
# t0 is when the spike starts listening (its first output line), not when
# `zig build` started compiling.
i=0
while ! grep -q '^spike-join_pktinfo' "$spike_log" 2>/dev/null; do
    if ! kill -0 "$spike_pid" 2>/dev/null; then break; fi
    sleep 0.2
    i=$((i + 1))
    if [ "$i" -gt 3000 ]; then echo "flood-count: spike did not start" >&2; exit 2; fi
done
t0=$(date +%s)
wait "$spike_pid"
spike_rc=$?
spike_pid=""
if [ "$spike_rc" -ne 0 ]; then
    echo "flood-count: spike exited with $spike_rc" >&2
    sed 's/^/  /' "$spike_log" >&2
    exit 2
fi
grep '^summary' "$spike_log" || true

MDNS_HOST_ADDRS="$addrs" python3 - "$dir" "$t0" "$after" "$service" "$mode" "$seconds" <<'PY'
import json
import os
import struct
import sys

dump, t0, after, service, mode, seconds = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5], int(sys.argv[6])
host_addrs = {line.strip().lower() for line in os.environ["MDNS_HOST_ADDRS"].splitlines() if line.strip()}

def encode(name):
    out = bytearray()
    for label in name.strip(".").split("."):
        raw = label.encode("utf-8")
        out.append(len(raw))
        out += raw
    return bytes(out)

# Names are matched decoded, because a response compresses them (the PTR
# rdata is `demo` plus a pointer to `_qmsg._udp.local`, RFC 1035 4.1.4),
# so a contiguous wire-form search would only ever see the probes.
# Comparison is ASCII case-insensitive (RFC 6762 16) and ignores a
# trailing `.local`: `--service _qmsg._udp` matches every name under the
# type, `--service demo._qmsg._udp` one instance.
wanted = service.strip(".").lower()
if wanted.endswith(".local"):
    wanted = wanted[:-6]
needle = encode(service).lower()  # fallback for a packet the parser rejects


class Malformed(Exception):
    pass


def read_name(msg, off):
    labels = []
    end = None
    hops = 0
    while True:
        if off >= len(msg):
            raise Malformed
        length = msg[off]
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise Malformed
            target = ((length & 0x3F) << 8) | msg[off + 1]
            if target >= off:
                raise Malformed
            if end is None:
                end = off + 2
            off = target
            hops += 1
            if hops > 64:
                raise Malformed
            continue
        if length & 0xC0:
            raise Malformed
        off += 1
        if length == 0:
            return ".".join(labels), (end if end is not None else off)
        if off + length > len(msg):
            raise Malformed
        labels.append(msg[off:off + length].decode("utf-8", "replace").lower())
        off += length


def names_in(msg):
    """Every owner name plus PTR / SRV / NSEC rdata names in the message."""
    out = []
    qd, an, ns, ar = struct.unpack("!HHHH", msg[4:12])
    off = 12
    for _ in range(qd):
        name, off = read_name(msg, off)
        out.append(name)
        off += 4
    for _ in range(an + ns + ar):
        name, off = read_name(msg, off)
        out.append(name)
        if off + 10 > len(msg):
            raise Malformed
        rtype, rdlen = struct.unpack("!H", msg[off:off + 2])[0], struct.unpack("!H", msg[off + 8:off + 10])[0]
        rd_off = off + 10
        off = rd_off + rdlen
        if off > len(msg):
            raise Malformed
        if rtype == 12 or rtype == 47:
            out.append(read_name(msg, rd_off)[0])
        elif rtype == 33 and rdlen > 6:
            out.append(read_name(msg, rd_off + 6)[0])
    return out


def mentions(msg):
    try:
        names = names_in(msg)
    except (Malformed, struct.error):
        return needle in msg.lower()
    for n in names:
        if n.endswith(".local"):
            n = n[:-6]
        if n == wanted or n.endswith("." + wanted):
            return True
    return False

def source_ip(text):
    text = text.strip()
    if text.startswith("["):
        return text[1:text.index("]")].split("%")[0].lower()
    return text.rsplit(":", 1)[0].lower()

ours = []  # (t_rel, qr, seq)
foreign_queries = []  # t_rel of foreign queries naming the service
total = 0
for fn in sorted(os.listdir(dump)):
    if not fn.endswith(".hex"):
        continue
    total += 1
    seq = fn[:-4]
    path = os.path.join(dump, fn)
    try:
        payload = bytes.fromhex(open(path).read().strip())
        side = json.load(open(os.path.join(dump, seq + ".json")))
    except (ValueError, OSError):
        continue
    if len(payload) < 12:
        continue
    if not mentions(payload):
        continue
    qr = (payload[2] >> 7) & 1
    t_rel = int(os.stat(path).st_mtime) - t0
    if source_ip(side.get("source", "")) in host_addrs:
        ours.append((t_rel, qr, seq))
    elif qr == 0:
        foreign_queries.append(t_rel)

queries = [o for o in ours if o[1] == 0]
responses = [o for o in ours if o[1] == 1]
print("flood-count: %d datagrams captured, %d from this host naming %s: %d queries (QR=0), %d responses (QR=1)" % (
    total, len(ours), service, len(queries), len(responses)))
by_sec = {}
for t_rel, qr, _ in ours:
    key = max(t_rel, 0)
    by_sec.setdefault(key, [0, 0])[qr] += 1
for t_rel in sorted(by_sec):
    q, r = by_sec[t_rel]
    print("  t+%3ds: %d query %d response" % (t_rel, q, r))

late_q = [o for o in queries if o[0] >= after]
late_r = [o for o in responses if o[0] >= after]
unsolicited = [o for o in late_r if not any(0 <= o[0] - fq <= 2 for fq in foreign_queries)]
print("flood-count: after t+%ds: %d queries, %d responses (%d unsolicited: no foreign query for the name within 2 s before)" % (
    after, len(late_q), len(late_r), len(unsolicited)))

if mode == "idle-advertise":
    bad = len(late_q) + len(unsolicited)
    if bad == 0:
        print("PASS idle-advertise: 0 unsolicited packets from this host for %s in t+%ds..t+%ds" % (service, after, seconds))
    else:
        print("FAIL idle-advertise: %d unsolicited packets after t+%ds (budget 0)" % (bad, after))
        sys.exit(1)
elif mode == "idle-browse":
    if len(late_q) <= 2:
        print("PASS idle-browse: %d queries from this host for %s in t+%ds..t+%ds (budget 2)" % (len(late_q), service, after, seconds))
    else:
        print("FAIL idle-browse: %d queries after t+%ds (budget 2)" % (len(late_q), after))
        sys.exit(1)
PY
