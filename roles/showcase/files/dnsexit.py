#!/usr/bin/env python3
"""Keeps one DNS record at DNSExit pointing where it should (role showcase, orchestrator#53).

    DNSEXIT_API_KEY=... dnsexit.py --zone example.com --name sub.example.com --content 203.0.113.10

Runs on the controller, standard library only. DNSExit's API can write records but not read them, so the record is
read from the zone's authoritative nameservers (--nameservers, DNSExit's own by default) with a plain DNS query: the
answer of a nameserver, not of a cache. When it already holds exactly --content, nothing is posted. Otherwise the
record is written with one POST to the API ("add" with "overwrite": the A records of the name are replaced) and the
nameservers are asked again until they answer the new address (--wait seconds).

DNSExit asks for at most one update in 4 minutes: the time of the last post is kept in --state, and a post that comes
sooner waits out the rest (--min-interval). When no nameserver answers at all, --state decides: the same content posted
for the name before is not posted again.

The API key comes from the first line of stdin (--key-stdin: what the role does, so that no command line or
environment shows it) or from the environment (DNSEXIT_API_KEY), never from an argument, and is never printed. Without
it (--check-only) only the nameservers are read.

Prints one JSON object: name, type, wanted, current (the addresses, or null when no nameserver answered), nameserver
(the one that answered), action (none | posted | mismatch | unknown), waited (seconds spent on the rate limit),
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
CLASS_IN = 1


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


def skip_name(packet, offset):
    """Offset just past the (possibly compressed) name at offset."""
    while True:
        if offset >= len(packet):
            raise ValueError("truncated name")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length


def query_a(name, server, port, timeout):
    """The A records of name as server answers them (no recursion asked), or raises OSError/ValueError."""
    qid = random.randint(0, 0xFFFF)
    packet = struct.pack(">HHHHHH", qid, 0, 1, 0, 0, 0) + encode_name(name) + struct.pack(">HH", TYPE_A, CLASS_IN)
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
    rcode = flags & 0x000F
    if rcode == 3:  # NXDOMAIN: the name has no records at all
        return []
    if rcode != 0:
        raise ValueError(f"rcode {rcode}")
    offset = 12
    for _ in range(qdcount):
        offset = skip_name(data, offset) + 4
    addresses = []
    for _ in range(ancount):
        offset = skip_name(data, offset)
        rtype, rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rtype == TYPE_A and rclass == CLASS_IN and rdlength == 4:
            addresses.append(socket.inet_ntoa(rdata))
    return sorted(set(addresses))


def split_server(value):
    host, sep, port = value.rpartition(":")
    if sep and port.isdigit() and not host.endswith(":"):
        return host.strip("[]"), int(port)
    return value.strip("[]"), 53


def read_record(name, nameservers, timeout):
    """(addresses, nameserver) from the first nameserver that answers, or (None, None)."""
    for entry in nameservers:
        host, port = split_server(entry)
        try:
            server = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
            return query_a(name, server, port, timeout), entry
        except (OSError, ValueError, IndexError, struct.error):
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
    parser.add_argument("--nameservers", default="ns1.dnsexit.com,ns2.dnsexit.com,ns3.dnsexit.com,ns4.dnsexit.com",
                        help="authoritative nameservers, comma separated, host[:port]")
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
    nameservers = [n.strip() for n in args.nameservers.split(",") if n.strip()]
    key = sys.stdin.readline().strip() if args.key_stdin else os.environ.get("DNSEXIT_API_KEY", "")
    if not args.check_only and not key:
        fail_args("DNSEXIT_API_KEY is empty; use --check-only to read the record only")

    result = {"name": name, "type": args.type, "wanted": content, "current": None, "nameserver": None,
              "action": "none", "waited": 0, "message": ""}

    def finish(code, message, **extra):
        result.update(extra, message=message)
        print(json.dumps(result))
        sys.exit(code)

    current, server = read_record(name, nameservers, args.timeout)
    result["current"], result["nameserver"] = current, server
    record_key = f"{name} {args.type}"
    state = load_state(args.state)

    if current == [content]:
        finish(0, f"{name} already points at {content} ({server})")
    if args.check_only:
        if current is None:
            finish(0, f"no nameserver answered for {name} ({', '.join(nameservers)})", action="unknown")
        finish(0, f"{name} points at {', '.join(current) or 'nothing'}, not {content} ({server})", action="mismatch")
    if current is None and state.get("records", {}).get(record_key, {}).get("content") == content:
        finish(0, f"no nameserver answered for {name}; {content} was posted before, not posting again", action="unknown")

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
        current, server = read_record(name, nameservers, args.timeout)
        result["current"], result["nameserver"] = current, server
        if current == [content]:
            finish(0, f"{name} now points at {content} ({server})")
        if time.monotonic() >= deadline:
            break
        time.sleep(args.poll)
    if current is None:
        finish(0, f"posted {name} -> {content}; no nameserver answered to confirm it")
    finish(1, f"posted {name} -> {content}, but after {int(args.wait)} s {server} still answers "
              f"{', '.join(current) or 'nothing'}")


if __name__ == "__main__":
    main()
