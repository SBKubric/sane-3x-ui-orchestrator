#!/usr/bin/env python3
"""geosite:ru-inside for the panel's xray (SBKubric/sane-3x-ui-orchestrator#28), installed by role panel.

    3ax-ru-inside [--config /etc/3ax-ru-inside.json] [--no-restart] refresh
    3ax-ru-inside [--config ...] [--no-restart] install <file> <sha256>
    3ax-ru-inside [--config ...] ensure

refresh  downloads the sum file and the list, checks the list's sha256 against the sum file, its size and that it
         carries the category, and replaces the kept copy (<store_dir>/<file>) atomically when the content differs;
         a current copy gets its mtime touched (its age is the time since the last good check). The systemd timer
         runs it daily.
install  the same checks and replacement for a file the controller downloaded and verified (role panel, when the
         box cannot reach the source); the file is removed afterwards.
ensure   only the link <asset_dir>/<file> -> the kept copy: install.sh removes xray's asset folder with the panel,
         so x-ui's ExecStartPre puts the link back before xray starts.

After refresh and install the link is ensured too, and xray is restarted (the config's restart command, `systemctl
reload x-ui` = `x-ui restart-xray`) when the list changed or the link was missing, unless --no-restart.
Anything that goes wrong keeps the old copy and says why on stderr (the journal under systemd).

stdout: one JSON line {"result", "sha256", "bytes", "linked", "restarted", "reason"}; result and exit code:
  updated / current  0   the copy is the source's list
  kept               3   the source's list could not be fetched or failed a check; the old copy stays
  missing            4   the same, and there is no copy at all
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

EXIT_KEPT = 3
EXIT_MISSING = 4
USER_AGENT = "3ax-ru-inside/1"


class Refused(Exception):
    """The list is not taken; the message says why."""


def log(message):
    print(f"3ax-ru-inside: {message}", file=sys.stderr, flush=True)


def fetch(url, timeout, limit):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise Refused(f"{url} is larger than {limit} bytes")
    return data


def parse_sum(text):
    """The first sha256 of a sha256sum file ("<hex>  geosite.dat"), or of a bare hex digest."""
    for line in text.splitlines():
        fields = line.split()
        if fields and re.fullmatch(r"[0-9a-fA-F]{64}", fields[0]):
            return fields[0].lower()
    raise Refused("no sha256 in the sum file")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def check(data, expected, config):
    got = sha256(data)
    if got != expected:
        raise Refused(f"sha256 mismatch: the list is {got}, the sum file says {expected}")
    if len(data) < config["min_bytes"]:
        raise Refused(f"the list has {len(data)} bytes, less than {config['min_bytes']}")
    if config["category"].upper().encode() not in data.upper():
        raise Refused(f"no category {config['category']} in the list")


def kept_sha(store):
    try:
        with open(store, "rb") as f:
            return sha256(f.read())
    except OSError:
        return None


def replace(store, data):
    """Writes the list next to the kept copy and renames it over; True when the content changed."""
    if kept_sha(store) == sha256(data):
        os.utime(store)
        return False
    directory = os.path.dirname(store)
    os.makedirs(directory, mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".incoming-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, store)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return True


def ensure_link(config, store):
    """<asset_dir>/<file> -> store; True when it had to be made. Nothing to link without the copy or the folder."""
    link = os.path.join(config["asset_dir"], config["file"])
    if not os.path.isfile(store) or not os.path.isdir(config["asset_dir"]):
        return False
    if os.path.islink(link) and os.readlink(link) == store:
        return False
    tmp = link + ".3ax-ru-inside"
    if os.path.lexists(tmp):
        os.unlink(tmp)
    os.symlink(store, tmp)
    os.replace(tmp, link)
    log(f"linked {link} -> {store}")
    return True


def restart(config):
    try:
        run = subprocess.run(config["restart"], capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError) as err:
        log(f"restarting xray failed: {err}")
        return False
    if run.returncode != 0:
        log(f"restarting xray failed ({' '.join(config['restart'])}: rc {run.returncode}): {run.stderr.strip()}")
        return False
    log("xray restarted")
    return True


def main():
    parser = argparse.ArgumentParser(description="geosite:ru-inside for the panel's xray")
    parser.add_argument("--config", default="/etc/3ax-ru-inside.json")
    parser.add_argument("--no-restart", action="store_true", help="leave restarting xray to the caller")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("refresh")
    commands.add_parser("ensure")
    install = commands.add_parser("install")
    install.add_argument("file")
    install.add_argument("sha256")
    args = parser.parse_args()

    with open(args.config, encoding="utf-8") as f:
        config = json.load(f)
    store = os.path.join(config["store_dir"], config["file"])
    report = {"result": "", "sha256": "", "bytes": 0, "linked": False, "restarted": False, "reason": ""}
    code = 0

    if args.command == "ensure":
        report["linked"] = ensure_link(config, store)
        report["result"] = "current" if os.path.isfile(store) else "missing"
        print(json.dumps(report))
        return 0

    changed = False
    try:
        if args.command == "refresh":
            expected = parse_sum(fetch(config["sha256_url"], config["timeout"], 65536).decode("utf-8", "replace"))
            data = fetch(config["url"], config["timeout"], config["max_bytes"])
        else:
            with open(args.file, "rb") as f:
                data = f.read(config["max_bytes"] + 1)
            os.unlink(args.file)
            expected = args.sha256.lower()
            if len(data) > config["max_bytes"]:
                raise Refused(f"{args.file} is larger than {config['max_bytes']} bytes")
        check(data, expected, config)
        changed = replace(store, data)
        report.update(result="updated" if changed else "current", sha256=expected, bytes=len(data))
        log(f"{report['result']}: {store} is {expected} ({len(data)} bytes)")
    except Exception as err:  # noqa: BLE001 - any failure keeps the old copy; the reason goes to the journal
        reason = str(err) or type(err).__name__
        old = kept_sha(store)
        report.update(result="kept" if old else "missing", sha256=old or "", reason=reason)
        code = EXIT_KEPT if old else EXIT_MISSING
        log(f"keeping {store}: {reason}" if old else f"no list at {store}: {reason}")

    report["linked"] = ensure_link(config, store)
    if (changed or report["linked"]) and not args.no_restart:
        report["restarted"] = restart(config)
    print(json.dumps(report))
    return code


if __name__ == "__main__":
    sys.exit(main())
