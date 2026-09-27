#!/usr/bin/env python3
"""TCP connect scan of a few ports of one box, from the controller (verify.yml, the «only 443» check).

    portscan.py --host 203.0.113.7 --ports 443,80,2053,2096,8443 [--timeout 3]

Prints {"host": ..., "open": [...], "closed": [...]} as JSON: a port is open when a TCP connection is accepted, closed
when it is refused, times out (a firewall that drops) or fails otherwise. Every port is tried in parallel, so a
dropping firewall costs one timeout, not one per port. Standard library only.
"""

import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor


def is_open(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan(host, ports, timeout):
    ports = sorted(set(ports))
    with ThreadPoolExecutor(max_workers=max(1, min(len(ports), 32))) as pool:
        results = list(pool.map(lambda port: is_open(host, port, timeout), ports))
    return {"host": host, "open": [p for p, ok in zip(ports, results) if ok],
            "closed": [p for p, ok in zip(ports, results) if not ok]}


def parse_ports(text):
    ports = []
    for token in text.split(","):
        token = token.strip()
        if not token:
            continue
        port = int(token)
        if not 1 <= port <= 65535:
            raise ValueError(f"port {port} is out of range")
        ports.append(port)
    if not ports:
        raise ValueError("no ports given")
    return ports


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", required=True)
    parser.add_argument("--ports", required=True, help="comma-separated TCP ports")
    parser.add_argument("--timeout", type=float, default=3.0, help="seconds per connection attempt")
    args = parser.parse_args(argv)
    try:
        ports = parse_ports(args.ports)
    except ValueError as err:
        parser.error(str(err))
    json.dump(scan(args.host, ports, args.timeout), sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
