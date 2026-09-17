#!/usr/bin/env python3
"""One-shot legacy unicast mDNS query (RFC 6762 section 6.7).

    python3 interop/legacy_query.py demo._qmsg._udp.local SRV

Sends one DNS query for <name>/<TYPE> from an EPHEMERAL port (so the
responder must treat it as a legacy unicast query) to 224.0.0.251:5353,
waits up to 2 s for the unicast reply and checks the four section 6.7
rules on it:

  id echoed?             the reply's ID equals the query's random ID
  TTL <= 10?             every RR in the reply has TTL <= 10
  cache-flush bit clear? no RR has the class high bit set
  SRV target compressed? no SRV rdata contains a 0xC0 pointer

Exit status 0 only when all four hold (a missing reply is a failure).
Standard library only. Flags: --timeout SECONDS (default 2), --v6 (send
to ff02::fb; needs --ifindex N or a scope), --ifindex N, --group ADDR,
--verbose (dump the parsed reply).
"""

import argparse
import random
import socket
import struct
import sys
import time

TYPES = {"A": 1, "PTR": 12, "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
TYPE_NAMES[47] = "NSEC"
MDNS_PORT = 5353
GROUP4 = "224.0.0.251"
GROUP6 = "ff02::fb"
MAX_TTL = 10


def encode_name(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("utf-8")
        if not raw or len(raw) > 63:
            raise ValueError("bad label in %r" % name)
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def build_query(name, qtype, qid):
    header = struct.pack("!HHHHHH", qid, 0, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", qtype, 1)


class Malformed(Exception):
    pass


def read_name(msg, off, depth=0):
    """Return (text, end_offset, saw_pointer) following compression."""
    labels = []
    saw_pointer = False
    end = None
    hops = 0
    while True:
        if off >= len(msg):
            raise Malformed("name runs past the message")
        length = msg[off]
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise Malformed("truncated pointer")
            target = ((length & 0x3F) << 8) | msg[off + 1]
            if target >= off:
                raise Malformed("forward pointer")
            if end is None:
                end = off + 2
            saw_pointer = True
            off = target
            hops += 1
            if hops > 64:
                raise Malformed("pointer loop")
            continue
        if length & 0xC0:
            raise Malformed("extended label type")
        off += 1
        if length == 0:
            if end is None:
                end = off
            return ".".join(labels), end, saw_pointer
        if off + length > len(msg):
            raise Malformed("label runs past the message")
        labels.append(msg[off:off + length].decode("utf-8", "replace"))
        off += length


def parse_reply(msg):
    if len(msg) < 12:
        raise Malformed("short header")
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", msg[:12])
    off = 12
    questions = []
    for _ in range(qd):
        name, off, _ = read_name(msg, off)
        if off + 4 > len(msg):
            raise Malformed("truncated question")
        qtype, qclass = struct.unpack("!HH", msg[off:off + 4])
        off += 4
        questions.append((name, qtype, qclass))
    records = []
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            name, off, _ = read_name(msg, off)
            if off + 10 > len(msg):
                raise Malformed("truncated RR")
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
            off += 10
            if off + rdlen > len(msg):
                raise Malformed("truncated rdata")
            rd_off = off
            rdata = msg[off:off + rdlen]
            off += rdlen
            records.append({
                "section": section, "name": name, "type": rtype,
                "class": rclass & 0x7FFF, "cache_flush": bool(rclass & 0x8000),
                "ttl": ttl, "rdata": rdata, "rd_off": rd_off,
            })
    return {"id": qid, "flags": flags, "questions": questions, "records": records}


def srv_target_compressed(msg, rr):
    """True when the SRV target name inside rdata uses a 0xC0 pointer
    (section 6.7 forbids compressing it in legacy replies; the RFC 2782
    target is at rdata offset 6)."""
    rdata = rr["rdata"]
    if len(rdata) < 7:
        return False
    off = 6
    while off < len(rdata):
        length = rdata[off]
        if length & 0xC0 == 0xC0:
            return True
        if length == 0:
            return False
        off += 1 + length
    return False


def describe_rdata(msg, rr):
    t = rr["type"]
    rd = rr["rdata"]
    try:
        if t == 1 and len(rd) == 4:
            return socket.inet_ntop(socket.AF_INET, rd)
        if t == 28 and len(rd) == 16:
            return socket.inet_ntop(socket.AF_INET6, rd)
        if t == 12:
            return read_name(msg, rr["rd_off"])[0]
        if t == 33 and len(rd) >= 7:
            pri, wgt, port = struct.unpack("!HHH", rd[:6])
            target = read_name(msg, rr["rd_off"] + 6)[0]
            return "%d %d %d %s" % (pri, wgt, port, target)
        if t == 16:
            parts = []
            off = 0
            while off < len(rd):
                n = rd[off]
                parts.append(rd[off + 1:off + 1 + n].decode("utf-8", "replace"))
                off += 1 + n
            return " ".join(repr(p) for p in parts)
    except Malformed:
        pass
    return rd.hex()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name", help="fully qualified name, e.g. demo._qmsg._udp.local")
    ap.add_argument("type", help="SRV, TXT, A, AAAA, PTR, ANY or a number")
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--v6", action="store_true", help="send to ff02::fb over IPv6")
    ap.add_argument("--ifindex", type=int, default=0, help="outgoing interface index (v6 scope / v4 IP_MULTICAST_IF by index is not portable; v4 uses the default route)")
    ap.add_argument("--group", default=None, help="override the destination address")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    qtype = TYPES.get(args.type.upper())
    if qtype is None:
        try:
            qtype = int(args.type)
        except ValueError:
            print("unknown type %r" % args.type, file=sys.stderr)
            return 2

    qid = random.randrange(1, 0x10000)
    query = build_query(args.name, qtype, qid)

    if args.v6:
        family = socket.AF_INET6
        dest = (args.group or GROUP6, MDNS_PORT, 0, args.ifindex)
    else:
        family = socket.AF_INET
        dest = (args.group or GROUP4, MDNS_PORT)
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        if args.v6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
            if args.ifindex:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, args.ifindex)
        else:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        # Port 0: the kernel picks an ephemeral source port, which is what
        # makes this a legacy unicast query (section 6.7).
        sock.bind(("::" if args.v6 else "0.0.0.0", 0))
        local_port = sock.getsockname()[1]
        sock.sendto(query, dest)
        print("query    %s %s id=0x%04x from port %d to %s" % (args.name, TYPE_NAMES.get(qtype, qtype), qid, local_port, dest[0]))
        assert local_port != MDNS_PORT

        deadline = time.monotonic() + args.timeout
        reply = None
        sender = None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, sender = sock.recvfrom(9000)
            except socket.timeout:
                break
            if len(data) < 12:
                continue
            rid, flags = struct.unpack("!HH", data[:4])
            if not flags & 0x8000:
                continue  # a query, not a response
            # Any response ID that is not our ID would be a multicast
            # response leaking in (impossible on an unbound ephemeral
            # port), so the first response is the one we judge.
            reply = data
            break
    finally:
        sock.close()

    if reply is None:
        print("reply    none within %.1fs" % args.timeout)
        print("RESULT   FAIL (no unicast reply)")
        return 1

    try:
        parsed = parse_reply(reply)
    except Malformed as err:
        print("reply    %d bytes from %s: malformed (%s)" % (len(reply), sender[0], err))
        print("RESULT   FAIL")
        return 1

    records = parsed["records"]
    answers = [r for r in records if r["section"] == "answer"]
    print("reply    %d bytes from %s port %d: id=0x%04x flags=0x%04x qd=%d an=%d ns=%d ar=%d" % (
        len(reply), sender[0], sender[1], parsed["id"], parsed["flags"], len(parsed["questions"]),
        len(answers), sum(1 for r in records if r["section"] == "authority"),
        sum(1 for r in records if r["section"] == "additional")))
    if args.verbose:
        for q in parsed["questions"]:
            print("  question %s %s class=%d" % (q[0], TYPE_NAMES.get(q[1], q[1]), q[2]))
        for r in records:
            print("  %-10s %s %s ttl=%d class=%d%s %s" % (
                r["section"], r["name"], TYPE_NAMES.get(r["type"], r["type"]), r["ttl"], r["class"],
                " cache-flush" if r["cache_flush"] else "", describe_rdata(reply, r)))

    id_ok = parsed["id"] == qid
    ttl_ok = bool(answers) and all(r["ttl"] <= MAX_TTL for r in records)
    flush_ok = not any(r["cache_flush"] for r in records)
    srvs = [r for r in records if r["type"] == 33]
    srv_compressed = any(srv_target_compressed(reply, r) for r in srvs)
    srv_ok = not srv_compressed
    question_repeated = any(q[0].lower() == args.name.rstrip(".").lower() and q[1] == qtype for q in parsed["questions"])

    print("id echoed?             %s (query 0x%04x, reply 0x%04x)" % ("yes" if id_ok else "NO", qid, parsed["id"]))
    print("TTL <= 10?             %s (max %s over %d RR)" % (
        "yes" if ttl_ok else "NO", max((r["ttl"] for r in records), default="-"), len(records)))
    print("cache-flush bit clear? %s" % ("yes" if flush_ok else "NO"))
    if srvs:
        print("SRV target compressed? %s" % ("NO (good)" if srv_ok else "YES (bad)"))
    else:
        print("SRV target compressed? n/a (no SRV in the reply)")
    print("question repeated?     %s (informational; section 6.7 says it MUST be)" % ("yes" if question_repeated else "no"))
    if not answers:
        print("answer section empty: the responder did not answer %s %s" % (args.name, args.type))

    ok = id_ok and ttl_ok and flush_ok and srv_ok
    print("RESULT   %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
