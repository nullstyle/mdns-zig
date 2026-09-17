#!/usr/bin/env python3
"""Inject one foreign probe for an instance name and time the defence.

    python3 interop/probe_defence.py demo._qmsg._udp.local --port 4433

Binds a SO_REUSEPORT socket on *:5353 (a peer, not a legacy querier),
joins 224.0.0.251, and sends one QM probe as RFC 6762 section 8.1
describes it: qtype ANY, class IN, the proposed SRV (port 9999, target
other.local) in the Authority section. A responder that owns the name
must defend it at once (section 6: "immediately", exempt from the
one-second rule) with a multicast response, QR=1, AA=1, carrying its SRV
with the cache-flush bit, so the prober sees the conflict inside its
750 ms probe window and renames.

Prints every response naming the instance with its latency and exits 0
when a multicast AA response whose SRV port is `--port` arrived within
`--within` seconds (default 0.75, the prober's window). With `--burst N`
it sends N probes `--gap` seconds apart (default 0.01) and also checks
that the defences are spaced at least 250 ms apart (section 6: "at least
250 ms since the last time the record was multicast on that interface"),
printing the count.

Stdlib only. `--timeout` bounds the listen (default `--within` + 1 s).
Flags: --group ADDR (default 224.0.0.251), --v6 is not implemented.
"""

import argparse
import socket
import struct
import sys
import time

MDNS_PORT = 5353
GROUP4 = "224.0.0.251"
TYPE_ANY = 255
TYPE_SRV = 33
CLASS_IN = 1
CACHE_FLUSH = 0x8000


def encode_name(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        out.append(len(label))
        out += label.encode()
    out.append(0)
    return bytes(out)


def decode_name(msg, off):
    labels = []
    jumped = False
    end = None
    hops = 0
    while True:
        if off >= len(msg):
            raise ValueError("truncated name")
        l = msg[off]
        if l == 0:
            off += 1
            break
        if l & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise ValueError("truncated pointer")
            ptr = ((l & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            hops += 1
            if hops > 64:
                raise ValueError("pointer loop")
            off = ptr
            continue
        labels.append(msg[off + 1 : off + 1 + l].decode("utf-8", "replace"))
        off += 1 + l
    return ".".join(labels), (end if jumped else off)


def build_probe(name):
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 1, 0)
    question = encode_name(name) + struct.pack("!HH", TYPE_ANY, CLASS_IN)
    srv_rdata = struct.pack("!HHH", 0, 0, 9999) + encode_name("other.local")
    authority = encode_name(name) + struct.pack("!HHIH", TYPE_SRV, CLASS_IN, 120, len(srv_rdata)) + srv_rdata
    return header + question + authority


def parse_response(msg, name):
    """(qr, aa, [(name, type, class, ttl, srv_port or None)]) or None."""
    if len(msg) < 12:
        return None
    _, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", msg[:12])
    qr = flags >> 15
    aa = (flags >> 10) & 1
    off = 12
    try:
        for _ in range(qd):
            _, off = decode_name(msg, off)
            off += 4
        records = []
        for _ in range(an + ns + ar):
            rname, off = decode_name(msg, off)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", msg[off : off + 10])
            off += 10
            rdata = msg[off : off + rdlen]
            off += rdlen
            port = struct.unpack("!H", rdata[4:6])[0] if rtype == TYPE_SRV and len(rdata) >= 6 else None
            records.append((rname.lower(), rtype, rclass, ttl, port))
    except (ValueError, struct.error):
        return None
    return qr, aa, [r for r in records if r[0] == name.lower()]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name", help="instance name, e.g. demo._qmsg._udp.local")
    ap.add_argument("--port", type=int, required=True, help="the SRV port the owner advertises")
    ap.add_argument("--within", type=float, default=0.75, help="seconds the first defence must arrive in")
    ap.add_argument("--timeout", type=float, default=None, help="seconds to keep listening (default --within + 1)")
    ap.add_argument("--burst", type=int, default=1, help="number of probes to send")
    ap.add_argument("--gap", type=float, default=0.01, help="seconds between probes of a burst")
    ap.add_argument("--group", default=GROUP4)
    args = ap.parse_args()
    timeout = args.timeout if args.timeout is not None else args.within + 1.0

    name = args.name.rstrip(".")
    probe = build_probe(name)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(("0.0.0.0", MDNS_PORT))
    mreq = struct.pack("4s4s", socket.inet_aton(args.group), socket.inet_aton("0.0.0.0"))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    s.settimeout(0.002)

    t0 = time.monotonic()
    sent = 0
    next_send = t0
    send_times = []
    defences = []
    others = 0
    print("probe    %s ANY (QM) with SRV port 9999 in Authority, x%d" % (name, args.burst))
    while True:
        now = time.monotonic()
        if sent < args.burst and now >= next_send:
            s.sendto(probe, (args.group, MDNS_PORT))
            send_times.append(now - t0)
            sent += 1
            next_send = now + args.gap
        if now - t0 > timeout:
            break
        try:
            data, src = s.recvfrom(9000)
        except socket.timeout:
            continue
        parsed = parse_response(data, name)
        if parsed is None:
            continue
        qr, aa, records = parsed
        if qr != 1 or not records:
            continue
        t = time.monotonic() - t0
        srv = [r for r in records if r[1] == TYPE_SRV]
        ours = any(r[4] == args.port for r in srv)
        flush = any(r[2] & CACHE_FLUSH for r in srv)
        print("  t=%.3fs response from %s:%d aa=%d srv_port=%s cache_flush=%s len=%d" % (
            t, src[0], src[1], aa, ",".join(str(r[4]) for r in srv) or "-", flush, len(data)))
        if aa == 1 and ours:
            defences.append(t)
        else:
            others += 1

    ok = True
    if not defences:
        print("RESULT   FAIL: no AA response carrying SRV port %d within %.2f s" % (args.port, timeout))
        return 1
    first = defences[0]
    print("defence  first at %.3f s (limit %.2f s), %d defence(s), %d other response(s)" % (first, args.within, len(defences), others))
    if first > args.within:
        print("RESULT   FAIL: first defence after the %.2f s window" % args.within)
        ok = False
    if args.burst > 1:
        gaps = [b - a for a, b in zip(defences, defences[1:])]
        min_gap = min(gaps) if gaps else None
        span = send_times[-1] - send_times[0] if len(send_times) > 1 else 0.0
        print("spacing  %d probes over %.3f s -> %d defences, min gap %s" % (
            args.burst, span, len(defences), "%.3f s" % min_gap if min_gap is not None else "-"))
        # At most one defence per started 250 ms of the burst, plus one
        # for a probe landing right after the last full interval.
        allowed = int(span / 0.25) + 2
        if len(defences) > allowed:
            print("RESULT   FAIL: %d defences for a %.3f s burst (at most %d)" % (len(defences), span, allowed))
            ok = False
        # Loopback delivers our own copy of each defence once per joined
        # pair the responder sends on; 0.2 s leaves room for that skew.
        if min_gap is not None and min_gap < 0.2:
            print("RESULT   FAIL: defences closer than 250 ms (section 6)")
            ok = False
    print("RESULT   %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
