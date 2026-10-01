#!/usr/bin/env python3
"""Neighbour target of a chain edge (role hop, tasks/neighbour.yml; SBKubric/sane-3x-ui ADR 0005, orchestrator#20).

Runs on the controller, never on a box: a VPS that scans its neighbours gets flagged. Standard library only; the
scanner (XTLS RealiTLScanner) and xray are pinned release binaries, downloaded once into --cache and checked
against their sha256 (--downloads), unless --scanner / --xray name binaries to use. Every command prints JSON.

    neighbour.py net   --host H
        The edge's IPv4 address (H resolved) and its /24.

    neighbour.py dns   --name NAME --address A [--dns HOST:PORT] [--timeout S]
        The DNS check (orchestrator#66): ok = NAME's A records include an address in A's /24. Looked up through the
        DNS server --dns (UDP), else the controller's resolver. The exit code is 0 either way.

    neighbour.py check --target HOST:PORT --server-name NAME [--tries N] [--probe-url URL]
        The Reality handshake check: a VLESS-Reality server (xray, loopback only) with the target as its target and
        NAME as its server name, a client through it, and N fetches of the probe URL through the tunnel. ok = all N
        passed. The exit code is 0 either way.

    neighbour.py find  --address A [--port P] [--limit N] [--threads T] [--timeout S] [--asn-whois HOST:PORT]
                       [--cdn-asns 13335,...] [--dns HOST:PORT] [--confirm K] [check options]
        Scans the N addresses of A's /24 nearest to A (A, .0 and .255 left out) with RealiTLScanner, then keeps the
        sites that
          - answered TLS 1.3 with ALPN h2 and X25519 (or its hybrid X25519MLKEM768) to the scanner,
          - carry a certificate name usable as a server name (not an address; a wildcard *.<domain> stands for
            www.<domain>),
          - whose name resolves into the /24 (the dns check): a site that merely carries another site's certificate
            would have the clients send an SNI that points away from the edge's network,
          - still answer TLS 1.3 + h2 with that name as SNI,
          - do not redirect a GET / for that name to another host,
          - are no CDN: neither a CDN's HTTP headers (Cloudflare, CloudFront, Fastly, Akamai) nor an AS listed in
            --cdn-asns (looked up in Team Cymru's bulk whois; skipped with a note when it does not answer).
        Ranks them (a 2xx answer first, then the nearest address) and gives the best K the handshake check; the
        first that passes is "found". K = 0 takes the best candidate unchecked.
"""

import argparse
import concurrent.futures
import csv
import hashlib
import http.client
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

GOOD_CURVES = {"X25519", "X25519MLKEM768"}
NAME = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})$")
# HTTP headers that give a CDN away: (CDN, header, value pattern or None for "present").
CDN_HEADERS = [
    ("Cloudflare", "cf-ray", None),
    ("Cloudflare", "server", re.compile(r"^cloudflare", re.I)),
    ("CloudFront", "x-amz-cf-id", None),
    ("CloudFront", "x-amz-cf-pop", None),
    ("CloudFront", "via", re.compile(r"cloudfront", re.I)),
    ("Fastly", "x-fastly-request-id", None),
    ("Fastly", "fastly-debug-digest", None),
    ("Fastly", "x-served-by", re.compile(r"^cache-", re.I)),
    ("Akamai", "server", re.compile(r"^akamai", re.I)),
    ("Akamai", "x-akamai-transformed", None),
    ("Akamai", "x-akamai-request-id", None),
    ("Akamai", "akamai-grn", None),
]
# Throwaway Reality key pair and client id of the local check (loopback only, never on a box).
REALITY_PRIVATE = "aJx6lDVGIggRTwt5pUlTfclzvNUOul7jt0yOkkRL_m8"
REALITY_PUBLIC = "zsnArK_8uAg6kr-Vc-kjBBE9cHtvET90psHdDSWFe30"
CLIENT_ID = "5783a3e7-e373-51cd-8642-c83782b807c5"
SHORT_ID = "ab12"


class Failure(Exception):
    """A problem to report on stderr with exit code 2."""


# --- addresses ---------------------------------------------------------------------------------------------------
def resolve(host):
    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as err:
        raise Failure(f"cannot resolve {host}: {err}") from err
    return infos[0][4][0]


def dns_query(server, name, timeout):
    """The IPv4 addresses of name's A records from the DNS server at host:port (one UDP query, recursion desired)."""
    host, _, port = server.rpartition(":")
    ident = os.urandom(2)
    question = b"".join(bytes([len(label)]) + label.encode() for label in name.rstrip(".").split(".")) + b"\x00\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        conn.settimeout(timeout)
        conn.connect((host, int(port)))
        conn.send(ident + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question)
        while True:
            data = conn.recv(4096)
            if data[:2] == ident and data[2] & 0x80:
                break
    rcode = data[3] & 0x0F
    if rcode == 3:
        raise OSError("NXDOMAIN")
    if rcode:
        raise OSError(f"DNS rcode {rcode}")
    offset = 12
    for _ in range(int.from_bytes(data[4:6], "big")):  # the questions
        offset = skip_name(data, offset) + 4
    addresses = []
    for _ in range(int.from_bytes(data[6:8], "big")):  # the answers: a CNAME chain, then its A records
        offset = skip_name(data, offset)
        rtype, size = int.from_bytes(data[offset:offset + 2], "big"), int.from_bytes(data[offset + 8:offset + 10], "big")
        offset += 10
        if rtype == 1 and size == 4:
            addresses.append(socket.inet_ntoa(data[offset:offset + 4]))
        offset += size
    return addresses


def skip_name(data, offset):
    while True:
        size = data[offset]
        if size & 0xC0 == 0xC0:
            return offset + 2
        if size == 0:
            return offset + 1
        offset += 1 + size


def addresses_of(name, dns, timeout):
    """The IPv4 addresses name resolves to: through the DNS server dns (host:port), else the controller's resolver."""
    try:
        if dns:
            found = dns_query(dns, name, timeout)
        else:
            found = [info[4][0] for info in socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)]
    except (OSError, IndexError, ValueError) as err:
        raise Failure(f"{name} does not resolve ({err or type(err).__name__})") from err
    if not found:
        raise Failure(f"{name} does not resolve (no A record)")
    return list(dict.fromkeys(found))


def by_dns(name, network, dns, timeout):
    """(reason or None, addresses): name must resolve to an address in network (the edge's /24). A site that carries a
    name it is not the address of (another site's certificate) would make a client's SNI point elsewhere."""
    try:
        addresses = addresses_of(name, dns, timeout)
    except Failure as err:
        return str(err), []
    if any(ipaddress.IPv4Address(a) in network for a in addresses):
        return None, addresses
    return f"{name} resolves to {', '.join(addresses)}, outside {network}", addresses


def network_of(address):
    return ipaddress.IPv4Network(f"{address}/24", strict=False)


def nearest(address, limit):
    """The addresses of address's /24 by distance from it: -1, +1, -2, +2, ...; itself, .0 and .255 left out."""
    edge = ipaddress.IPv4Address(address)
    net = network_of(address)
    hosts = [ip for ip in net.hosts() if ip != edge]
    hosts.sort(key=lambda ip: (abs(int(ip) - int(edge)), int(ip) > int(edge)))
    return [str(ip) for ip in hosts[:max(limit, 0)]]


# --- tools -------------------------------------------------------------------------------------------------------
def machine():
    arch = platform.machine().lower()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(arch, arch)


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(kind, downloads, cache):
    """The pinned release file of kind (scanner|xray) for this machine, downloaded into cache once."""
    try:
        pin = json.loads(downloads or "{}")[kind][machine()]
    except (KeyError, ValueError) as err:
        raise Failure(f"no pinned {kind} download for {machine()} (--downloads); set its binary instead") from err
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    name = os.path.basename(urllib.parse.urlsplit(pin["url"]).path)
    path = cache / f"{pin['sha256'][:12]}-{name}"
    if path.exists() and sha256_of(path) == pin["sha256"]:
        return path
    partial = path.with_suffix(path.suffix + ".part")
    try:
        with urllib.request.urlopen(pin["url"], timeout=120) as answer, open(partial, "wb") as out:
            shutil.copyfileobj(answer, out)
    except OSError as err:
        partial.unlink(missing_ok=True)
        raise Failure(f"cannot download {pin['url']}: {err}") from err
    got = sha256_of(partial)
    if got != pin["sha256"]:
        partial.unlink(missing_ok=True)
        raise Failure(f"{pin['url']} has sha256 {got}, pinned {pin['sha256']}")
    partial.rename(path)
    return path


def scanner_bin(args):
    if args.scanner:
        return args.scanner
    path = fetch("scanner", args.downloads, args.cache)
    path.chmod(0o755)
    return str(path)


def xray_bin(args):
    if args.xray:
        return args.xray
    archive = fetch("xray", args.downloads, args.cache)
    binary = archive.with_name(archive.name + ".d") / "xray"
    if not binary.exists():
        with zipfile.ZipFile(archive) as bundle:
            binary.parent.mkdir(exist_ok=True)
            with bundle.open("xray") as source, open(binary, "wb") as out:
                shutil.copyfileobj(source, out)
        binary.chmod(0o755)
    return str(binary)


# --- the filters of find -----------------------------------------------------------------------------------------
def scan(args, address, workdir):
    targets = nearest(address, args.limit)
    (workdir / "in.txt").write_text("\n".join(targets) + "\n")
    command = [scanner_bin(args), "-in", "in.txt", "-port", str(args.port), "-thread", str(args.threads),
               "-timeout", str(args.timeout), "-out", "out.csv"]
    try:
        subprocess.run(command, cwd=workdir, capture_output=True, check=False, timeout=args.limit * args.timeout + 120)
    except (OSError, subprocess.TimeoutExpired) as err:
        raise Failure(f"scanner {command[0]}: {err}") from err
    out = workdir / "out.csv"
    rows = list(csv.DictReader(out.open(newline=""))) if out.exists() else []
    return targets, rows


def usable_name(name):
    if not NAME.match(name or ""):
        return False
    try:
        ipaddress.ip_address(name)
        return False
    except ValueError:
        return True


def server_name(certificate_name):
    """The server name a certificate name stands for: itself, or www.<domain> for a wildcard *.<domain>."""
    name = certificate_name or ""
    if name.startswith("*.") and usable_name(name[2:]):
        return "www." + name[2:]
    return name


def by_scanner(row):
    """Why the scanner's row is no candidate, or None."""
    tls, alpn, curve = row.get("TLS"), row.get("ALPN"), row.get("CURVE")
    if tls is not None and tls != "TLS 1.3":
        return f"{tls}, not TLS 1.3"
    if alpn is not None and alpn != "h2":
        return f"ALPN {alpn}, not h2"
    if curve is not None and curve not in GOOD_CURVES:
        return f"curve {curve}, not X25519"
    if not usable_name(server_name(row.get("CERT_DOMAIN", ""))):
        return f"certificate name {row.get('CERT_DOMAIN', '')} is no server name"
    return None


def tls_context(alpn):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(alpn)
    return context


def connect(ip, port, name, alpn, timeout):
    raw = socket.create_connection((ip, port), timeout=timeout)
    try:
        return tls_context(alpn).wrap_socket(raw, server_hostname=name)
    except (OSError, ssl.SSLError):
        raw.close()
        raise


def cdn_by_headers(headers):
    for cdn, header, pattern in CDN_HEADERS:
        for value in headers.get(header, []):
            if pattern is None or pattern.search(value):
                return cdn
    return None


def by_site(ip, port, name, timeout):
    """(reason or None, HTTP status): the site answered again with name as SNI, and its GET /."""
    try:
        with connect(ip, port, name, ["h2", "http/1.1"], timeout) as conn:
            alpn = conn.selected_alpn_protocol()
    except (OSError, ssl.SSLError) as err:
        return f"no TLS answer for {name}: {err}", 0
    if alpn != "h2":
        return f"ALPN {alpn} for {name}, not h2", 0
    try:
        with connect(ip, port, name, ["http/1.1"], timeout) as conn:
            conn.sendall(f"GET / HTTP/1.1\r\nHost: {name}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
                         "Connection: close\r\n\r\n".encode())
            answer = http.client.HTTPResponse(conn)
            answer.begin()
            status = answer.status
            headers = {}
            for key, value in answer.getheaders():
                headers.setdefault(key.lower(), []).append(value)
    except (OSError, ssl.SSLError, http.client.HTTPException) as err:
        return f"no HTTP answer for {name}: {err}", 0
    cdn = cdn_by_headers(headers)
    if cdn:
        return f"CDN {cdn} (HTTP headers)", status
    if 300 <= status < 400:
        location = (headers.get("location") or [""])[0]
        host = urllib.parse.urlsplit(urllib.parse.urljoin(f"https://{name}/", location)).hostname or ""
        if host.lower() != name.lower():
            return f"redirects to {host or location}", status
    return None, status


def asn_lookup(whois, ips, timeout):
    """{ip: (asn, as name)} from Team Cymru's bulk whois at host:port."""
    host, _, port = whois.rpartition(":")
    query = "begin\nverbose\n" + "".join(f"{ip}\n" for ip in ips) + "end\n"
    with socket.create_connection((host, int(port)), timeout=timeout) as conn:
        conn.sendall(query.encode())
        data = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
    found = {}
    for line in data.decode(errors="replace").splitlines():
        fields = [f.strip() for f in line.split("|")]
        if len(fields) >= 7 and fields[0].isdigit():
            found[fields[1]] = (fields[0], fields[6])
    return found


def cmd_find(args):
    address = resolve(args.address)
    workdir = Path(tempfile.mkdtemp(prefix="neighbour-"))
    notes, rejected = [], []
    try:
        scanned, rows = scan(args, address, workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    seen, sites = set(), []
    for row in rows:
        ip = row.get("IP", "")
        if ip in seen or ip == address:
            continue
        seen.add(ip)
        reason = by_scanner(row)
        if reason:
            rejected.append({"ip": ip, "name": row.get("CERT_DOMAIN", ""), "reason": reason})
        else:
            sites.append((ip, server_name(row["CERT_DOMAIN"])))

    network = network_of(address)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(args.threads, 1)) as pool:
        names = list(pool.map(lambda site: by_dns(site[1], network, args.dns, args.timeout), sites))
    resolving = []
    for (ip, name), (reason, _) in zip(sites, names):
        if reason:
            rejected.append({"ip": ip, "name": name, "reason": reason})
        else:
            resolving.append((ip, name))
    sites = resolving

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(args.threads, 1)) as pool:
        answers = list(pool.map(lambda site: by_site(site[0], args.port, site[1], args.timeout), sites))
    kept = []
    for (ip, name), (reason, status) in zip(sites, answers):
        if reason:
            rejected.append({"ip": ip, "name": name, "reason": reason})
        else:
            kept.append((ip, name, status))

    cdn_asns = {a.strip() for a in args.cdn_asns.split(",") if a.strip()}
    if kept and args.asn_whois and cdn_asns:
        try:
            asns = asn_lookup(args.asn_whois, [ip for ip, _, _ in kept], max(args.timeout, 10))
        except (OSError, ValueError) as err:
            notes.append(f"AS lookup at {args.asn_whois} failed ({err}); CDNs filtered by HTTP headers only")
            asns = {}
        still = []
        for ip, name, status in kept:
            asn, as_name = asns.get(ip, ("", ""))
            if asn in cdn_asns:
                rejected.append({"ip": ip, "name": name, "reason": f"CDN AS{asn} {as_name}"})
            else:
                still.append((ip, name, status))
        kept = still

    edge = int(ipaddress.IPv4Address(address))
    kept.sort(key=lambda site: (0 if 200 <= site[2] < 300 else 1, abs(int(ipaddress.IPv4Address(site[0])) - edge)))
    candidates = [{"target": f"{ip}:{args.port}", "serverName": name, "status": status} for ip, name, status in kept]

    confirmed, found = [], None
    if args.confirm <= 0:
        found = candidates[0] if candidates else None
    else:
        for candidate in candidates[:args.confirm]:
            ok, detail = handshake(args, candidate["target"], candidate["serverName"])
            confirmed.append({"target": candidate["target"], "serverName": candidate["serverName"], "ok": ok,
                              "detail": detail})
            if ok:
                found = candidate
                break
    return {"address": address, "network": str(network_of(address)), "scanned": len(scanned),
            "feasible": len(seen), "candidates": candidates, "rejected": rejected, "confirmed": confirmed,
            "found": {"target": found["target"], "serverName": found["serverName"]} if found else None,
            "notes": notes}


# --- the handshake check -----------------------------------------------------------------------------------------
def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def reality_pair(target, server_name, server_port, client_port):
    """The configs of the local xray pair, as in SBKubric/sane-3x-ui#129: VLESS + Vision + Reality."""
    server = {
        "log": {"loglevel": "debug"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": server_port, "protocol": "vless",
            "settings": {"clients": [{"id": CLIENT_ID, "flow": "xtls-rprx-vision"}], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "show": False, "target": target, "xver": 0, "serverNames": [server_name],
                "privateKey": REALITY_PRIVATE, "shortIds": [SHORT_ID]}}}],
        "outbounds": [{"protocol": "freedom"}],
    }
    client = {
        "log": {"loglevel": "debug"},
        "inbounds": [{"listen": "127.0.0.1", "port": client_port, "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": "127.0.0.1", "port": server_port, "users": [
                {"id": CLIENT_ID, "flow": "xtls-rprx-vision", "encryption": "none"}]}]},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "serverName": server_name, "fingerprint": "chrome", "publicKey": REALITY_PUBLIC,
                "shortId": SHORT_ID, "spiderX": "/"}}}],
    }
    return server, client


def recv_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise OSError("connection closed")
        data += chunk
    return data


def probe(socks_port, url, timeout):
    """GET url through the SOCKS5 proxy on socks_port; True on a 2xx answer."""
    parts = urllib.parse.urlsplit(url)
    host, port = parts.hostname, parts.port or 443
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    try:
        with socket.create_connection(("127.0.0.1", socks_port), timeout=timeout) as raw:
            raw.sendall(b"\x05\x01\x00")
            if recv_exact(raw, 2) != b"\x05\x00":
                return False
            raw.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() + port.to_bytes(2, "big"))
            head = recv_exact(raw, 4)
            if head[1] != 0:
                return False
            recv_exact(raw, {1: 4, 4: 16}.get(head[3], 0) or recv_exact(raw, 1)[0])
            recv_exact(raw, 2)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(raw, server_hostname=host) as conn:
                conn.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n"
                             .encode())
                answer = http.client.HTTPResponse(conn)
                answer.begin()
                return 200 <= answer.status < 300
    except (OSError, ssl.SSLError, http.client.HTTPException):
        return False


def log_tail(path, lines=3):
    text = path.read_text(errors="replace") if path.exists() else ""
    hits = [line.strip() for line in text.splitlines() if re.search(r"reality|tls|fail|error|invalid", line, re.I)
            and not re.search(r"Reading config|non-443 ports", line)]
    return hits[-lines:] or [line.strip() for line in text.splitlines()][-lines:]


def handshake(args, target, server_name):
    """(ok, detail) of the Reality handshake check of target with server_name."""
    xray = xray_bin(args)
    work = Path(tempfile.mkdtemp(prefix="reality-"))
    server_port, client_port = free_port(), free_port()
    processes = []
    try:
        for name, config in zip(("server", "client"), reality_pair(target, server_name, server_port, client_port)):
            (work / f"{name}.json").write_text(json.dumps(config))
            with open(work / f"{name}.log", "wb") as log:
                processes.append(subprocess.Popen([xray, "run", "-c", str(work / f"{name}.json")],
                                                  stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL))
        deadline = time.monotonic() + 10
        waiting = [server_port, client_port]
        while waiting and time.monotonic() < deadline:
            if any(process.poll() is not None for process in processes):
                break
            try:
                socket.create_connection(("127.0.0.1", waiting[0]), timeout=1).close()
                waiting.pop(0)
            except OSError:
                time.sleep(0.2)
        for name, process in zip(("server", "client"), processes):
            if process.poll() is not None:
                return False, f"xray exited ({name}, rc {process.returncode}): " + " | ".join(log_tail(work / f"{name}.log"))
        if waiting:
            return False, "xray did not listen within 10 s"
        passed = sum(probe(client_port, args.probe_url, args.probe_timeout) for _ in range(args.tries))
        detail = f"{passed}/{args.tries} through the tunnel"
        if passed < args.tries:
            detail += "; server: " + " | ".join(log_tail(work / "server.log")) + "; client: " + " | ".join(
                log_tail(work / "client.log"))
        return passed == args.tries, detail
    except OSError as err:
        return False, f"cannot run {xray}: {err}"
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        shutil.rmtree(work, ignore_errors=True)


def cmd_check(args):
    ok, detail = handshake(args, args.target, args.server_name)
    return {"target": args.target, "serverName": args.server_name, "ok": ok, "detail": detail}


def cmd_dns(args):
    address = resolve(args.address)
    network = network_of(address)
    reason, addresses = by_dns(args.name, network, args.dns, args.timeout)
    return {"name": args.name, "address": address, "network": str(network), "addresses": addresses,
            "ok": reason is None, "detail": reason or f"{args.name} resolves to {', '.join(addresses)} in {network}"}


def cmd_net(args):
    address = resolve(args.host)
    return {"address": address, "network": str(network_of(address))}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    net = sub.add_parser("net", help="the edge's address and /24")
    net.add_argument("--host", required=True)

    names = argparse.ArgumentParser(add_help=False)
    names.add_argument("--dns", default="", help="DNS server host:port for A records (default: the system's resolver)")
    dns = sub.add_parser("dns", parents=[names], help="does a server name resolve into an edge's /24")
    dns.add_argument("--name", required=True)
    dns.add_argument("--address", required=True)
    dns.add_argument("--timeout", type=int, default=4)

    tools = argparse.ArgumentParser(add_help=False)
    tools.add_argument("--cache", default=str(Path.home() / ".cache" / "neighbour"))
    tools.add_argument("--downloads", default="", help="JSON {scanner|xray: {<machine>: {url, sha256}}}")
    tools.add_argument("--xray", default="", help="xray binary to use instead of the pinned download")
    tools.add_argument("--scanner", default="", help="RealiTLScanner binary to use instead of the pinned download")
    tools.add_argument("--tries", type=int, default=3)
    tools.add_argument("--probe-url", default="https://www.cloudflare.com/cdn-cgi/trace")
    tools.add_argument("--probe-timeout", type=int, default=12)

    check = sub.add_parser("check", parents=[tools], help="Reality handshake check of one target")
    check.add_argument("--target", required=True)
    check.add_argument("--server-name", required=True)

    find = sub.add_parser("find", parents=[tools, names], help="scan the /24 of an edge for a neighbour target")
    find.add_argument("--address", required=True)
    find.add_argument("--port", type=int, default=443)
    find.add_argument("--limit", type=int, default=254)
    find.add_argument("--threads", type=int, default=8)
    find.add_argument("--timeout", type=int, default=4)
    find.add_argument("--confirm", type=int, default=3)
    find.add_argument("--asn-whois", default="whois.cymru.com:43")
    find.add_argument("--cdn-asns", default="")

    args = parser.parse_args(argv)
    try:
        result = {"net": cmd_net, "dns": cmd_dns, "check": cmd_check, "find": cmd_find}[args.command](args)
    except Failure as err:
        print(f"neighbour.py {args.command}: {err}", file=sys.stderr)
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
