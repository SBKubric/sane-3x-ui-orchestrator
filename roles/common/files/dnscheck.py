#!/usr/bin/env python3
"""The host's DNS servers, asked one by one (role common, orchestrator#62). Standard library only, Python 3.8+.

    dnscheck.py check --resolv-conf /etc/resolv.conf [--upstream-conf /run/systemd/resolve/resolv.conf]
                      [--port 53] [--timeout 2] [--tries 2] [--options timeout:1,attempts:2]
                      [--fallback 192.0.2.53,198.51.100.53] [--backup /root/resolv.conf.orig]
    dnscheck.py time  --resolv-conf /etc/resolv.conf [--port 53]

check asks every nameserver directly, all at once, for the root's NS records (no domain of anybody's needed; a
recursive resolver answers it from its cache) and prints JSON:

    {"mode": "file" | "resolved" | "managed", "servers": [...], "answering": [...], "dead": [...],
     "fallback": [...], "content": null | "<the resolv.conf it should be>"}

A server answers when it sends back NOERROR or NXDOMAIN; silence within --timeout (--tries times), SERVFAIL, REFUSED or
a network error make it dead. mode "file": /etc/resolv.conf is a plain file and is ours to fix: when some servers are
dead, content is the file without them, with the --options set, and with the answering --fallback servers when no
server of its own is left (null = leave it alone, also when nothing answers at all). mode "resolved": systemd-resolved
owns the file (its stub 127.0.0.53, or a link to its upstream list): its upstream servers (--upstream-conf) are
checked, nothing is written. mode "managed": the file is a link to something else (resolvconf, NetworkManager) that
would rewrite it: checked, nothing is written.

time looks a name up the way the libc stub resolver does: the nameservers in order (the first three), each waited for
the file's `options timeout:` (default 5 s), `attempts:` rounds (default 2), until one answers; prints
{"elapsed_ms": ..., "answered_by": ... | null, "tries": [{"server", "ok", "ms", "error"}]}.

Exit code 2 on bad arguments or an unreadable file.
"""

import argparse
import ipaddress
import json
import os
import random
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

STUBS = {"127.0.0.53", "127.0.0.54"}
MARK = "# 3ax-ui:"
QTYPE_NS = 2
LIBC_MAXNS = 3


def query_packet(qid):
    """A recursive query for the root's NS records."""
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + b"\x00" + struct.pack("!HH", QTYPE_NS, 1)


def ask(server, port, timeout, tries):
    """One server: (ok, milliseconds, error)."""
    started = time.monotonic()
    try:
        family, _, _, _, sockaddr = socket.getaddrinfo(server, port, type=socket.SOCK_DGRAM)[0]
    except (OSError, UnicodeError) as e:
        return False, 0, f"bad address: {e}"
    error = "timeout"
    for _ in range(max(1, tries)):
        qid = random.randint(0, 0xFFFF)
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            try:
                sock.connect(sockaddr)
                sock.send(query_packet(qid))
                deadline = time.monotonic() + timeout
                while True:
                    sock.settimeout(max(0.001, deadline - time.monotonic()))
                    data = sock.recv(4096)
                    if len(data) >= 12 and struct.unpack("!H", data[:2])[0] == qid and data[2] & 0x80:
                        break
            except socket.timeout:
                error = "timeout"
                continue
            except OSError as e:
                error = e.strerror or str(e)
                continue
        rcode = data[3] & 0x0F
        ms = int((time.monotonic() - started) * 1000)
        if rcode in (0, 3):
            return True, ms, ""
        return False, ms, {2: "SERVFAIL", 5: "REFUSED"}.get(rcode, f"rcode {rcode}")
    return False, int((time.monotonic() - started) * 1000), error


def ask_all(servers, port, timeout, tries):
    if not servers:
        return []
    with ThreadPoolExecutor(max_workers=min(len(servers), 16)) as pool:
        results = list(pool.map(lambda s: ask(s, port, timeout, tries), servers))
    return [{"server": s, "ok": ok, "ms": ms, "error": err} for s, (ok, ms, err) in zip(servers, results)]


def read_lines(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()


def nameservers(lines):
    found = []
    for line in lines:
        words = line.split()
        if len(words) >= 2 and words[0] == "nameserver" and words[1] not in found:
            found.append(words[1])
    return found


def options(lines):
    opts = {}
    for line in lines:
        words = line.split()
        if words and words[0] == "options":
            for word in words[1:]:
                name, _, value = word.partition(":")
                opts[name] = value
    return opts


def rewrite(lines, dead, fallback, wanted_options, backup):
    """The file without the dead servers (and our old note), the fallback servers where the first nameserver was when
    none of its own is left, the options set (other options kept), with a note on top."""
    keep, first_ns = [], None
    for line in lines:
        words = line.split()
        if line.startswith(MARK):
            continue
        if words and words[0] == "nameserver":
            if first_ns is None:
                first_ns = len(keep)
            if len(words) < 2 or words[1] in dead:
                continue
        if words and words[0] == "options":
            names = {o.partition(":")[0] for o in wanted_options}
            rest = [w for w in words[1:] if w.partition(":")[0] not in names]
            if not rest:
                continue
            line = " ".join(["options", *rest])
        keep.append(line)
    if fallback:
        at = len(keep) if first_ns is None else min(first_ns, len(keep))
        keep[at:at] = [f"nameserver {s}" for s in fallback]
    if wanted_options:
        keep.append("options " + " ".join(wanted_options))
    note = [f"{MARK} role common dropped the nameservers that did not answer: {', '.join(dead)}"]
    if fallback:
        note.append(f"{MARK} none of its own answered; common_dns_fallback: {', '.join(fallback)}")
    if backup:
        note.append(f"{MARK} the original is {backup}")
    return "\n".join(note + keep) + "\n"


def owner(resolv_conf, upstream_conf, servers):
    if servers and set(servers) <= STUBS:
        return "resolved"
    if os.path.islink(resolv_conf):
        target = os.path.realpath(resolv_conf)
        if os.path.dirname(target) == os.path.dirname(os.path.realpath(upstream_conf)):
            return "resolved"
        return "managed"
    return "file"


def check(args):
    lines = read_lines(args.resolv_conf)
    servers = nameservers(lines)
    mode = owner(args.resolv_conf, args.upstream_conf, servers)
    if mode == "resolved" and set(servers) <= STUBS and os.path.exists(args.upstream_conf):
        servers = nameservers(read_lines(args.upstream_conf))
    results = ask_all(servers, args.port, args.timeout, args.tries)
    answering = [r["server"] for r in results if r["ok"]]
    dead = [r["server"] for r in results if not r["ok"]]
    fallback_results, content = [], None
    if mode == "file" and not answering and args.fallback:
        fallback_results = ask_all([s for s in args.fallback if s not in servers], args.port, args.timeout, args.tries)
    fallback = [r["server"] for r in fallback_results if r["ok"]]
    if mode == "file" and dead and (answering or fallback):
        content = rewrite(lines, dead, fallback, args.options, args.backup)
    return {"mode": mode, "resolv_conf": args.resolv_conf, "servers": results, "answering": answering + fallback,
            "dead": dead, "fallback": fallback_results, "content": content}


def libc_lookup(args):
    lines = read_lines(args.resolv_conf)
    opts = options(lines)

    def number(name, default, low, high):
        try:
            return min(high, max(low, int(opts.get(name, default))))
        except ValueError:
            return default

    timeout, attempts = number("timeout", 5, 1, 30), number("attempts", 2, 1, 5)
    servers = nameservers(lines)[:LIBC_MAXNS] or ["127.0.0.1"]
    started, tries = time.monotonic(), []
    for _ in range(attempts):
        for server in servers:
            ok, ms, err = ask(server, args.port, timeout, 1)
            tries.append({"server": server, "ok": ok, "ms": ms, "error": err})
            if ok:
                return {"elapsed_ms": int((time.monotonic() - started) * 1000), "answered_by": server, "tries": tries}
    return {"elapsed_ms": int((time.monotonic() - started) * 1000), "answered_by": None, "tries": tries}


def address_list(text):
    out = []
    for token in (text or "").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            ipaddress.ip_address(token.split("%", 1)[0])
        except ValueError:
            raise argparse.ArgumentTypeError(f"not an IP address: {token}")
        out.append(token)
    return out


def option_list(text):
    out = [t.strip() for t in (text or "").split(",") if t.strip()]
    for token in out:
        if " " in token:
            raise argparse.ArgumentTypeError(f"bad resolver option: {token}")
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "time"):
        p = sub.add_parser(name)
        p.add_argument("--resolv-conf", default="/etc/resolv.conf")
        p.add_argument("--port", type=int, default=53)
    c = sub.choices["check"]
    c.add_argument("--upstream-conf", default="/run/systemd/resolve/resolv.conf")
    c.add_argument("--timeout", type=float, default=2.0)
    c.add_argument("--tries", type=int, default=2)
    c.add_argument("--options", type=option_list, default=["timeout:1", "attempts:2"])
    c.add_argument("--fallback", type=address_list, default=[])
    c.add_argument("--backup", default="")
    args = parser.parse_args(argv)
    if not 0 < args.port < 65536:
        parser.error(f"bad port: {args.port}")
    try:
        result = check(args) if args.command == "check" else libc_lookup(args)
    except OSError as e:
        print(f"cannot read {args.resolv_conf}: {e.strerror or e}", file=sys.stderr)
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
