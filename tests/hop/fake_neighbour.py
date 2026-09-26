#!/usr/bin/env python3
"""Stand-in for roles/hop/files/neighbour.py in the tests of role hop: same command line and JSON answers, no
scanner, no xray, no network. Driven by files in $HOP_TEST_ROOT/neighbour/ (written by test_hop_role.py):

    scan.json  {"<edge address>": {"target": "...", "serverName": "..."}}: what `find` finds (absent = nothing)
    good       one "<target> <server name>" per line: the pairs `check` passes
    calls      appended by every call: "find <address>" or "check <target> <server name>"
"""

import argparse
import json
import os
import sys
from pathlib import Path

DIR = Path(os.environ["HOP_TEST_ROOT"]) / "neighbour"


def read(name, default):
    path = DIR / name
    return path.read_text() if path.exists() else default


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    net = sub.add_parser("net")
    net.add_argument("--host", required=True)
    find = sub.add_parser("find")
    find.add_argument("--address", required=True)
    check = sub.add_parser("check")
    check.add_argument("--target", required=True)
    check.add_argument("--server-name", required=True)
    args, _ = parser.parse_known_args()

    if args.command == "net":
        address = args.host
        print(json.dumps({"address": address, "network": address.rsplit(".", 1)[0] + ".0/24"}))
        return 0
    DIR.mkdir(exist_ok=True)
    with open(DIR / "calls", "a", encoding="utf-8") as calls:
        if args.command == "find":
            calls.write(f"find {args.address}\n")
        else:
            calls.write(f"check {args.target} {args.server_name}\n")
    if args.command == "find":
        found = json.loads(read("scan.json", "{}")).get(args.address)
        print(json.dumps({"found": found, "scanned": 254, "candidates": [found] if found else [],
                          "confirmed": [dict(found, ok=True, detail="3/3")] if found else []}))
        return 0
    good = {tuple(line.split()) for line in read("good", "").splitlines() if line.strip()}
    ok = (args.target, args.server_name) in good
    print(json.dumps({"ok": ok, "detail": "3/3 through the tunnel" if ok else "0/3 through the tunnel"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
