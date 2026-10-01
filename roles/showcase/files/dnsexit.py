#!/usr/bin/env python3
"""Keeps one DNS record at DNSExit pointing where it should (role showcase, orchestrator#53).

    DNSEXIT_API_KEY=... dnsexit.py --zone example.com --name sub.example.com --content 203.0.113.10

Runs on the controller, standard library only. DNSExit's API can write records but not read them, so the record is
read from the zone's authoritative nameservers with a plain DNS query: the answer of a nameserver, not of a cache.
DNSExit serves different zones from different servers (orchestrator#64), so by default the nameservers are found
through the resolvers (--resolvers, else /etc/resolv.conf): the NS records of --zone, else of its parent, and so on
(a free <name>.<their domain> has none of its own). --nameservers names them instead. Only an authoritative answer
counts: SERVFAIL, REFUSED or an answer without the AA flag means that server did not answer, and the next one is asked.
When the record already holds exactly --content, nothing is posted. Otherwise the record is written with one POST to
the API ("add" with "overwrite": the A records of the name are replaced) and the nameservers are asked again until they
answer the new address (--wait seconds).

DNSExit asks for at most one update in 4 minutes: the time of the last post is kept in --state, and a post that comes
sooner waits out the rest (--min-interval). When no nameserver answers at all, --state decides: the same content posted
for the name before is not posted again.

The API key comes from the first line of stdin (--key-stdin: what the role does, so that no command line or
environment shows it) or from the environment (DNSEXIT_API_KEY), never from an argument, and is never printed. Without
it (--check-only) only the nameservers are read.

Prints one JSON object: name, type, wanted, current (the addresses, or null when no nameserver answered), nameserver
(the one that answered), nameservers (those asked: given or found), nameservers_of (the domain whose NS records they
are, null when given or not found), action (none | posted | mismatch | unknown), waited (seconds spent on the rate limit),
message. Exit status: 0 done (or only read), 1 the API refused or the new address did not show up, 2 bad arguments.
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
import urllib.error
import urllib.request
from pathlib import Path

TYPE_A = 1
TYPE_NS = 2
CLASS_IN = 1
FLAG_AA = 0x0400
FLAG_RD = 0x0100


def fail_args(message):
    print(json.dumps({"action": "error", "message": message}))
    sys.exit(2)


# --- DNS -----------------------------------------------------------------------------------------------------------

def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if label else b""
        if not raw or len(raw) > 63:
            raise ValueError(f"bad DNS label in {name!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\0"


def read_name(packet, offset):
    """(name, offset just past it) for the (possibly compressed) name at offset."""
    labels, end, jumps = [], None, 0
    while True:
        if offset >= len(packet):
            raise ValueError("truncated name")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if end is None:
                end = offset + 2
            jumps += 1
            if jumps > 32:
                raise ValueError("name compression loop")
            offset = struct.unpack(">H", packet[offset:offset + 2])[0] & 0x3FFF
            continue
        if length == 0:
            return ".".join(labels).lower(), end if end is not None else offset + 1
        labels.append(packet[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length


def query(name, rtype, server, port, timeout, recursive=False):
    """(rcode, flags, [(type, rdata offset, rdata length)], packet) of server's answer, or raises OSError/ValueError."""
    qid = random.randint(0, 0xFFFF)
    packet = (struct.pack(">HHHHHH", qid, FLAG_RD if recursive else 0, 1, 0, 0, 0) + encode_name(name)
              + struct.pack(">HH", rtype, CLASS_IN))
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, port))
        deadline = time.monotonic() + timeout
        while True:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            data, _ = sock.recvfrom(4096)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == qid:
                break
    flags, qdcount, ancount = struct.unpack(">HHH", data[2:8])
    offset = 12
    for _ in range(qdcount):
        offset = read_name(data, offset)[1] + 4
    answers = []
    for _ in range(ancount):
        offset = read_name(data, offset)[1]
        atype, aclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if aclass == CLASS_IN:
            answers.append((atype, offset, rdlength))
        offset += rdlength
    return flags & 0x000F, flags, answers, data


def query_a(name, server, port, timeout):
    """The A records of name as the zone's server answers them (no recursion asked), or raises OSError/ValueError."""
    rcode, flags, answers, data = query(name, TYPE_A, server, port, timeout)
    if rcode != 0 and rcode != 3:  # SERVFAIL, REFUSED, ...: the server did not answer, not "no record"
        raise ValueError(f"rcode {rcode}")
    if not flags & FLAG_AA:  # not the zone's server (a referral, a cache): its "nothing" says nothing
        raise ValueError("not authoritative")
    if rcode == 3:  # NXDOMAIN from the zone's server: the name has no records at all
        return []
    return sorted({socket.inet_ntoa(data[at:at + 4]) for rtype, at, length in answers if rtype == TYPE_A and length == 4})


def split_server(value, default_port=53):
    host, sep, port = value.rpartition(":")
    if sep and port.isdigit() and not host.endswith(":"):
        return host.strip("[]"), int(port)
    return value.strip("[]"), default_port


def system_resolvers(path="/etc/resolv.conf"):
    """The nameserver lines of resolv.conf (127.0.0.1 without any, as the C library does)."""
    try:
        lines = Path(path).read_text().splitlines()
    except OSError:
        lines = []
    found = [line.split()[1] for line in lines if line.split()[:1] == ["nameserver"] and len(line.split()) > 1]
    return found or ["127.0.0.1"]


def ask_resolvers(name, rtype, resolvers, timeout):
    """(rcode, answers, packet) from the first resolver that answers (NOERROR or NXDOMAIN), or None."""
    for entry in resolvers:
        host, port = split_server(entry)
        try:
            rcode, _flags, answers, data = query(name, rtype, host, port, timeout, recursive=True)
        except (OSError, ValueError, IndexError, struct.error, UnicodeError):
            continue
        if rcode in (0, 3):
            return rcode, answers, data
    return None


def address_of(host, resolvers, timeout):
    """An IPv4 address for a nameserver: itself when it is one, else through the resolvers, else the system's."""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    answer = ask_resolvers(host, TYPE_A, resolvers, timeout)
    if answer:
        rcode, answers, data = answer
        for rtype, at, length in answers:
            if rtype == TYPE_A and length == 4:
                return socket.inet_ntoa(data[at:at + 4])
    return socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]


def find_nameservers(zone, resolvers, timeout):
    """(domain, [nameserver names]) serving zone: the NS records of zone, else of its parent, and so on up to a
    two-label domain (a DNSExit zone such as <name>.<free domain> has none of its own: its parent's servers answer
    for it). (None, []) when the resolvers do not answer or no domain on the way has NS records."""
    labels = zone.split(".")
    for start in range(0, max(1, len(labels) - 1)):
        domain = ".".join(labels[start:])
        answer = ask_resolvers(domain, TYPE_NS, resolvers, timeout)
        if answer is None:
            return None, []
        rcode, answers, data = answer
        names = sorted({read_name(data, at)[0] for rtype, at, _length in answers if rtype == TYPE_NS})
        if names:
            return domain, names
    return None, []


def read_record(name, nameservers, timeout, resolvers, default_port=53):
    """(addresses, nameserver) from the first nameserver that answers for the zone, or (None, None)."""
    for entry in nameservers:
        host, port = split_server(entry, default_port)
        try:
            return query_a(name, address_of(host, resolvers, timeout), port, timeout), entry
        except (OSError, ValueError, IndexError, struct.error, UnicodeError):
            continue
    return None, None


# --- state and API -------------------------------------------------------------------------------------------------

def load_state(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}


def save_state(path, state):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    tmp.replace(target)


def post_record(api_url, key, zone, label, rtype, content, ttl, timeout):
    """None on success, else the reason (without the key)."""
    body = {"domain": zone, "add": {"type": rtype, "name": label, "content": content, "ttl": ttl, "overwrite": True}}
    request = urllib.request.Request(api_url, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "apikey": key})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return f"HTTP {err.code} from the DNSExit API"
    except (OSError, ValueError) as err:
        return f"the DNSExit API did not answer: {err}"
    try:
        answer = json.loads(raw)
    except ValueError:
        return f"the DNSExit API answered something else than JSON: {raw[:200]!r}"
    if answer.get("code") != 0:
        return f"the DNSExit API refused the update: code {answer.get('code')} {answer.get('message', '')}".strip()
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--api-url", default="https://api.dnsexit.com/dns/")
    parser.add_argument("--zone", required=True, help="the domain DNSExit hosts, e.g. example.com")
    parser.add_argument("--name", required=True, help="the full record name, e.g. sub.example.com")
    parser.add_argument("--type", default="A", choices=["A"])
    parser.add_argument("--content", required=True, help="the address the record must hold")
    parser.add_argument("--ttl", type=int, default=60, help="minutes")
    parser.add_argument("--nameservers", default="",
                        help="the zone's nameservers, comma separated, host[:port]; empty (the default) = found "
                             "through the resolvers: the NS records of --zone, else of its parent, and so on")
    parser.add_argument("--resolvers", default="",
                        help="recursive resolvers that find the nameservers, comma separated, host[:port]; "
                             "empty = the nameserver lines of /etc/resolv.conf")
    parser.add_argument("--ns-port", type=int, default=53, help="the port of the nameservers found (the tests)")
    parser.add_argument("--state", required=True, help="file that remembers the last post")
    parser.add_argument("--min-interval", type=float, default=240, help="seconds between two posts (DNSExit: 4 min)")
    parser.add_argument("--wait", type=float, default=180, help="seconds to wait for the nameservers after a post")
    parser.add_argument("--poll", type=float, default=5, help="seconds between two reads while waiting")
    parser.add_argument("--timeout", type=float, default=3, help="seconds per DNS query")
    parser.add_argument("--api-timeout", type=float, default=30)
    parser.add_argument("--check-only", action="store_true", help="read the record, never post")
    parser.add_argument("--key-stdin", action="store_true", help="read the API key from the first line of stdin")
    args = parser.parse_args()

    zone = args.zone.strip().rstrip(".").lower()
    name = args.name.strip().rstrip(".").lower()
    if name != zone and not name.endswith("." + zone):
        fail_args(f"{name} is not in the zone {zone}")
    label = "" if name == zone else name[: -len(zone) - 1]
    try:
        content = str(ipaddress.IPv4Address(args.content.strip()))
        encode_name(name)
    except ValueError as err:
        fail_args(str(err))
    given = [n.strip() for n in args.nameservers.split(",") if n.strip()]
    resolvers = [n.strip() for n in args.resolvers.split(",") if n.strip()] or system_resolvers()
    key = sys.stdin.readline().strip() if args.key_stdin else os.environ.get("DNSEXIT_API_KEY", "")
    if not args.check_only and not key:
        fail_args("DNSEXIT_API_KEY is empty; use --check-only to read the record only")

    result = {"name": name, "type": args.type, "wanted": content, "current": None, "nameserver": None,
              "nameservers": given, "nameservers_of": None, "action": "none", "waited": 0, "message": ""}

    def finish(code, message, **extra):
        result.update(extra, message=message)
        print(json.dumps(result))
        sys.exit(code)

    def lookup():
        """(addresses, nameserver) as read_record, finding the zone's nameservers first unless they were given (and
        again on the next call while they could not be found); the reason in silence when nobody answered."""
        nonlocal silence
        if not given and not result["nameservers"]:
            result["nameservers_of"], result["nameservers"] = find_nameservers(zone, resolvers, args.timeout)
        if not result["nameservers"]:
            silence = f"could not find the nameservers of {zone} (resolvers: {', '.join(resolvers)})"
            return None, None
        current, server = read_record(name, result["nameservers"], args.timeout, resolvers,
                                      53 if given else args.ns_port)
        silence = f"no nameserver answered for {name} ({', '.join(result['nameservers'])})"
        result["current"], result["nameserver"] = current, server
        return current, server

    silence = ""
    current, server = lookup()
    record_key = f"{name} {args.type}"
    state = load_state(args.state)

    if current == [content]:
        finish(0, f"{name} already points at {content} ({server})")
    if args.check_only:
        if current is None:
            finish(0, silence, action="unknown")
        finish(0, f"{name} points at {', '.join(current) or 'nothing'}, not {content} ({server})", action="mismatch")
    if current is None and state.get("records", {}).get(record_key, {}).get("content") == content:
        finish(0, f"{silence}; {content} was posted before, not posting again", action="unknown")

    wait = float(state.get("last_post", 0)) + args.min_interval - time.time()
    if wait > 0:
        time.sleep(min(wait, args.min_interval))
        result["waited"] = round(min(wait, args.min_interval))
    error = post_record(args.api_url, key, zone, label, args.type, content, args.ttl, args.api_timeout)
    now = time.time()
    state["last_post"] = now
    if error:
        save_state(args.state, state)
        finish(1, error, action="error")
    state.setdefault("records", {})[record_key] = {"content": content, "posted": now}
    save_state(args.state, state)
    result["action"] = "posted"

    deadline = time.monotonic() + args.wait
    while True:
        current, server = lookup()
        if current == [content]:
            finish(0, f"{name} now points at {content} ({server})")
        if time.monotonic() >= deadline:
            break
        time.sleep(args.poll)
    if current is None:
        finish(0, f"posted {name} -> {content}; no nameserver answered to confirm it ({silence})")
    finish(1, f"posted {name} -> {content}, but after {int(args.wait)} s {server} still answers "
              f"{', '.join(current) or 'nothing'}")


if __name__ == "__main__":
    main()
