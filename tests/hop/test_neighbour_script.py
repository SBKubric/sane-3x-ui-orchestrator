"""roles/hop/files/neighbour.py through its command line, with no network beyond loopback:

    python3 tests/hop/test_neighbour_script.py

A fake RealiTLScanner (writes a CSV the test chooses and records its arguments), TLS servers on 127.0.0.x standing in
for the neighbours, a fake Team Cymru whois and a fake xray (a SOCKS5 relay that fails for "broken" targets).
"""

import hashlib
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
SCRIPT = REPO / "roles" / "hop" / "files" / "neighbour.py"
sys.dont_write_bytecode = True

HEADER = "IP,ORIGIN,TLS,ALPN,CURVE,CERT_LENGTH,CERT_SIGNATURE,CERT_PUBLICKEY,CERT_DOMAIN,CERT_ISSUER,GEO_CODE\n"


def row(ip, name, tls="TLS 1.3", alpn="h2", curve="X25519"):
    return f'{ip},{ip},{tls},{alpn},{curve},3000(certs count: 2),SHA256-RSA,RSA,{name},"Let\'s Encrypt",N/A\n'


def run(*args, env=None, check=True):
    result = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True,
                            env=dict(os.environ, **(env or {})), check=False, timeout=120)
    if check and result.returncode != 0:
        raise AssertionError(f"rc {result.returncode}: {result.stdout}\n{result.stderr}")
    return result


class NetTest(unittest.TestCase):
    def test_an_address_gives_its_24(self):
        out = json.loads(run("net", "--host", "203.0.113.9").stdout)
        self.assertEqual(out, {"address": "203.0.113.9", "network": "203.0.113.0/24"})

    def test_a_name_is_resolved(self):
        out = json.loads(run("net", "--host", "localhost").stdout)
        self.assertEqual(out["network"], "127.0.0.0/24")

    def test_an_unknown_name_fails(self):
        result = run("net", "--host", "no-such-host.invalid", check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("no-such-host.invalid", result.stderr)


PORT = int(os.environ.get("NB_TEST_PORT", "18443"))

FAKE_SCANNER = """#!/usr/bin/env python3
# Fake RealiTLScanner: records its arguments and the -in list, writes $FAKE_SCAN_CSV to -out.
import json, os, shutil, sys
args = sys.argv[1:]
opts = dict(zip(args[::2], args[1::2]))
record = {"args": args, "in": open(opts["-in"]).read().split()}
json.dump(record, open(os.environ["FAKE_SCAN_RECORD"], "w"))
shutil.copy(os.environ["FAKE_SCAN_CSV"], opts["-out"])
"""


class Site(BaseHTTPRequestHandler):
    """A neighbour's web server; its behaviour comes from the server (see serve_site)."""

    def do_GET(self):  # noqa: N802 (http.server naming)
        status, headers = self.server.answer
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


def self_signed(tmp):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=site",
                    "-keyout", str(tmp / "key.pem"), "-out", str(tmp / "cert.pem")], check=True, capture_output=True)
    return tmp / "cert.pem", tmp / "key.pem"


def serve_site(ip, port, cert, status=200, headers=None, alpn=("h2", "http/1.1")):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*cert)
    context.set_alpn_protocols(list(alpn))
    server = ThreadingHTTPServer((ip, port), Site)
    server.answer = (status, headers or {})
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def serve_whois(port, answers):
    """Team Cymru's bulk whois: "begin / verbose / <ip>... / end" -> one "AS | IP | ... | AS Name" line per IP."""
    listener = socket.create_server(("127.0.0.1", port))

    def loop():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            with conn:
                data = b""
                while not data.endswith(b"end\n"):
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                lines = ["Bulk mode; whois.cymru.com [2026-09-26 00:00:00 +0000]"]
                for ip in data.decode().split("\n")[2:-2]:
                    asn, name = answers.get(ip, ("64500", "EXAMPLE-HOSTING, NL"))
                    lines.append(f"{asn:<8}| {ip:<16}| 127.0.0.0/24 | NL | ripencc | 2000-01-01 | {name}")
                conn.sendall(("\n".join(lines) + "\n").encode())

    threading.Thread(target=loop, daemon=True).start()
    return listener


class FindTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certdir = Path(tempfile.mkdtemp(prefix="nbcert-"))
        cls.cert = self_signed(cls.certdir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.certdir, ignore_errors=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nbtest-"))
        self.scanner = self.tmp / "RealiTLScanner"
        self.scanner.write_text(FAKE_SCANNER)
        self.scanner.chmod(0o755)
        self.servers = []

    def tearDown(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def site(self, ip, **kwargs):
        self.servers.append(serve_site(ip, PORT, self.cert, **kwargs))

    def find(self, rows, *extra, address="127.0.0.10"):
        (self.tmp / "scan.csv").write_text(HEADER + "".join(rows))
        env = {"FAKE_SCAN_CSV": str(self.tmp / "scan.csv"), "FAKE_SCAN_RECORD": str(self.tmp / "record.json")}
        result = run("find", "--address", address, "--scanner", str(self.scanner), "--port", str(PORT),
                     "--timeout", "2", "--asn-whois", "", "--confirm", "0", "--cache", str(self.tmp / "cache"),
                     *extra, env=env)
        self.record = json.loads((self.tmp / "record.json").read_text())
        return json.loads(result.stdout)

    @staticmethod
    def targets(out):
        return [(c["target"], c["serverName"]) for c in out["candidates"]]

    @staticmethod
    def reasons(out):
        return {r["ip"]: r["reason"] for r in out["rejected"]}

    def test_scans_the_nearest_addresses_of_the_24_with_the_limits(self):
        out = self.find([], "--limit", "4", "--threads", "3")
        self.assertEqual(self.record["in"], ["127.0.0.9", "127.0.0.11", "127.0.0.8", "127.0.0.12"])
        args = self.record["args"]
        self.assertEqual((args[args.index("-port") + 1], args[args.index("-thread") + 1], args[args.index("-timeout") + 1]),
                         (str(PORT), "3", "2"))
        self.assertEqual((out["network"], out["scanned"], out["candidates"], out["found"]), ("127.0.0.0/24", 4, [], None))

    def test_the_whole_24_leaves_out_the_edge_and_the_broadcast(self):
        self.find([], "--limit", "300", address="127.0.0.1")
        self.assertEqual(len(self.record["in"]), 253)
        self.assertEqual(self.record["in"][:3], ["127.0.0.2", "127.0.0.3", "127.0.0.4"])
        self.assertNotIn("127.0.0.1", self.record["in"])
        self.assertNotIn("127.0.0.255", self.record["in"])

    def test_keeps_tls13_h2_x25519_sites_with_a_usable_name(self):
        self.site("127.0.0.2")
        self.site("127.0.0.6")
        self.site("127.0.0.8")
        self.site("127.0.0.12")
        out = self.find([row("127.0.0.2", "far.test"), row("127.0.0.3", "old.test", tls="TLS 1.2"),
                         row("127.0.0.4", "h1.test", alpn="http/1.1"), row("127.0.0.5", "p256.test", curve="P-256"),
                         row("127.0.0.6", "*.wild.test"), row("127.0.0.7", "127.0.0.7"), row("127.0.0.9", "*"),
                         row("127.0.0.8", "near.test", curve="X25519MLKEM768"),
                         row("127.0.0.12", "xn--b1afoqkfh6e.xn--p1ai")])
        # A wildcard certificate names www.<its domain>; an IDN stays in its punycode form.
        self.assertEqual(self.targets(out), [(f"127.0.0.8:{PORT}", "near.test"),
                                             (f"127.0.0.12:{PORT}", "xn--b1afoqkfh6e.xn--p1ai"),
                                             (f"127.0.0.6:{PORT}", "www.wild.test"), (f"127.0.0.2:{PORT}", "far.test")])
        self.assertEqual(self.reasons(out), {
            "127.0.0.3": "TLS 1.2, not TLS 1.3", "127.0.0.4": "ALPN http/1.1, not h2", "127.0.0.5": "curve P-256, not X25519",
            "127.0.0.7": "certificate name 127.0.0.7 is no server name", "127.0.0.9": "certificate name * is no server name"})
        self.assertEqual(out["found"], {"target": f"127.0.0.8:{PORT}", "serverName": "near.test"})

    def test_drops_redirects_to_another_host_cdns_and_sites_without_h2_for_the_name(self):
        self.site("127.0.0.2")
        self.site("127.0.0.3", status=301, headers={"Location": "https://other.test/"})
        self.site("127.0.0.4", status=302, headers={"Location": "/login"})
        self.site("127.0.0.5", headers={"Server": "cloudflare", "CF-RAY": "8c0ffee-AMS"})
        self.site("127.0.0.6", headers={"X-Amz-Cf-Id": "abc", "Via": "1.1 abc.cloudfront.net (CloudFront)"})
        self.site("127.0.0.7", headers={"X-Fastly-Request-ID": "abc"})
        self.site("127.0.0.8", headers={"Server": "AkamaiGHost"})
        self.site("127.0.0.9", alpn=("http/1.1",))
        out = self.find([row(f"127.0.0.{i}", f"site{i}.test") for i in range(2, 10)] + [row("127.0.0.11", "gone.test")])
        self.assertEqual(self.targets(out), [(f"127.0.0.2:{PORT}", "site2.test"), (f"127.0.0.4:{PORT}", "site4.test")])
        reasons = self.reasons(out)
        self.assertEqual(reasons["127.0.0.3"], "redirects to other.test")
        self.assertEqual(reasons["127.0.0.5"], "CDN Cloudflare (HTTP headers)")
        self.assertEqual(reasons["127.0.0.6"], "CDN CloudFront (HTTP headers)")
        self.assertEqual(reasons["127.0.0.7"], "CDN Fastly (HTTP headers)")
        self.assertEqual(reasons["127.0.0.8"], "CDN Akamai (HTTP headers)")
        self.assertEqual(reasons["127.0.0.9"], "ALPN http/1.1 for site9.test, not h2")
        self.assertTrue(reasons["127.0.0.11"].startswith("no TLS answer for gone.test"), reasons["127.0.0.11"])

    def test_drops_cdns_by_their_as(self):
        self.site("127.0.0.2")
        self.site("127.0.0.3")
        whois = serve_whois(PORT + 1, {"127.0.0.3": ("13335", "CLOUDFLARENET, US")})
        try:
            out = self.find([row("127.0.0.2", "a.test"), row("127.0.0.3", "b.test")],
                            "--asn-whois", f"127.0.0.1:{PORT + 1}", "--cdn-asns", "13335,54113")
        finally:
            whois.close()
        self.assertEqual(self.targets(out), [(f"127.0.0.2:{PORT}", "a.test")])
        self.assertEqual(self.reasons(out), {"127.0.0.3": "CDN AS13335 CLOUDFLARENET, US"})

    def test_an_unreachable_whois_leaves_a_note(self):
        self.site("127.0.0.2")
        out = self.find([row("127.0.0.2", "a.test")], "--asn-whois", f"127.0.0.1:{PORT + 2}", "--cdn-asns", "13335")
        self.assertEqual(self.targets(out), [(f"127.0.0.2:{PORT}", "a.test")])
        self.assertTrue(any("AS lookup" in note for note in out["notes"]), out["notes"])



class HandshakeTest(unittest.TestCase):
    """check, and find's confirmation of the best candidates, through fake_xray.py; the probe URL is a local site."""

    @classmethod
    def setUpClass(cls):
        cls.certdir = Path(tempfile.mkdtemp(prefix="nbcert-"))
        cls.cert = self_signed(cls.certdir)
        cls.probe = serve_site("127.0.0.1", PORT + 3, cls.cert)
        cls.probe_url = f"https://127.0.0.1:{PORT + 3}/cdn-cgi/trace"

    @classmethod
    def tearDownClass(cls):
        cls.probe.shutdown()
        cls.probe.server_close()
        shutil.rmtree(cls.certdir, ignore_errors=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nbtest-"))
        (self.tmp / "record").mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def check(self, target, name, broken="", xray=str(HERE / "fake_xray.py")):
        env = {"FAKE_XRAY_BROKEN": broken, "FAKE_XRAY_RECORD": str(self.tmp / "record")}
        return json.loads(run("check", "--target", target, "--server-name", name, "--xray", xray,
                              "--probe-url", self.probe_url, "--cache", str(self.tmp / "cache"), env=env).stdout)

    def test_a_target_that_carries_the_tunnel_passes(self):
        out = self.check("198.51.100.7:443", "www.neighbour.test")
        self.assertEqual((out["ok"], out["detail"]), (True, "3/3 through the tunnel"))
        server = json.loads((self.tmp / "record" / "vless.json").read_text())["inbounds"][0]
        reality = server["streamSettings"]["realitySettings"]
        self.assertEqual((reality["target"], reality["serverNames"]), ("198.51.100.7:443", ["www.neighbour.test"]))
        self.assertEqual(server["listen"], "127.0.0.1")
        client = json.loads((self.tmp / "record" / "socks.json").read_text())
        self.assertEqual(client["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"], "www.neighbour.test")

    def test_a_target_whose_handshake_fails_does_not_pass(self):
        out = self.check("198.51.100.7:443", "www.neighbour.test", broken="198.51.100.7:443")
        self.assertFalse(out["ok"])
        self.assertTrue(out["detail"].startswith("0/3 through the tunnel"), out["detail"])

    def test_an_xray_that_does_not_start_fails_the_check(self):
        broken = self.tmp / "xray"
        broken.write_text("#!/bin/sh\necho 'Failed to start: bad config' >&2\nexit 23\n")
        broken.chmod(0o755)
        out = self.check("198.51.100.7:443", "www.neighbour.test", xray=str(broken))
        self.assertFalse(out["ok"])
        self.assertIn("xray exited", out["detail"])
        self.assertIn("Failed to start: bad config", out["detail"])

    def test_find_takes_the_first_of_the_best_candidates_that_passes(self):
        certdir = Path(tempfile.mkdtemp(prefix="nbcert-", dir=self.tmp))
        cert = self_signed(certdir)
        sites = [serve_site(f"127.0.0.{i}", PORT, cert) for i in (5, 8, 9)]
        scanner = self.tmp / "RealiTLScanner"
        scanner.write_text(FAKE_SCANNER)
        scanner.chmod(0o755)
        (self.tmp / "scan.csv").write_text(HEADER + row("127.0.0.5", "c.test") + row("127.0.0.8", "b.test")
                                          + row("127.0.0.9", "a.test"))
        env = {"FAKE_SCAN_CSV": str(self.tmp / "scan.csv"), "FAKE_SCAN_RECORD": str(self.tmp / "scan.json"),
               "FAKE_XRAY_BROKEN": f"127.0.0.9:{PORT}"}
        common = ["find", "--address", "127.0.0.10", "--scanner", str(scanner), "--xray", str(HERE / "fake_xray.py"),
                  "--port", str(PORT), "--timeout", "2", "--asn-whois", "", "--probe-url", self.probe_url,
                  "--cache", str(self.tmp / "cache")]
        try:
            out = json.loads(run(*common, "--confirm", "3", env=env).stdout)
            self.assertEqual(out["found"], {"target": f"127.0.0.8:{PORT}", "serverName": "b.test"})
            self.assertEqual([(c["target"], c["ok"]) for c in out["confirmed"]],
                             [(f"127.0.0.9:{PORT}", False), (f"127.0.0.8:{PORT}", True)])
            out = json.loads(run(*common, "--confirm", "1", env=env).stdout)
            self.assertIsNone(out["found"])
            self.assertEqual(len(out["candidates"]), 3)
        finally:
            for site in sites:
                site.shutdown()
                site.server_close()



class DownloadTest(unittest.TestCase):
    """Without --scanner/--xray the pinned release files are downloaded once into --cache, checked by sha256."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nbtest-"))
        self.cache = self.tmp / "cache"
        release = self.tmp / "release"
        release.mkdir()
        self.xray_zip = release / "Xray-linux-64.zip"
        with zipfile.ZipFile(self.xray_zip, "w") as bundle:
            bundle.write(HERE / "fake_xray.py", "xray")
            bundle.writestr("geoip.dat", "")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def downloads(self, sha=None):
        sha = sha or hashlib.sha256(self.xray_zip.read_bytes()).hexdigest()
        pin = {"url": self.xray_zip.as_uri(), "sha256": sha}
        return json.dumps({"xray": {"x86_64": pin, "aarch64": pin}})

    def check(self, downloads):
        return run("check", "--target", "198.51.100.7:443", "--server-name", "www.neighbour.test", "--tries", "1",
                   "--probe-url", "https://127.0.0.1:1/", "--probe-timeout", "1", "--cache", str(self.cache),
                   "--downloads", downloads, check=False)

    def test_the_pinned_xray_is_downloaded_once_and_unpacked(self):
        pinned = self.downloads()
        result = self.check(pinned)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("through the tunnel", json.loads(result.stdout)["detail"])  # xray ran (the probe URL is dead)
        self.assertEqual(len(list(self.cache.iterdir())), 2)  # the zip and its unpacked xray
        self.xray_zip.unlink()  # the second run needs no download
        result = self.check(pinned)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("through the tunnel", json.loads(result.stdout)["detail"])

    def test_a_download_with_another_sha256_is_refused(self):
        result = self.check(self.downloads(sha="0" * 64))
        self.assertEqual(result.returncode, 2)
        self.assertIn("pinned " + "0" * 64, result.stderr)
        self.assertEqual([p for p in self.cache.iterdir()], [], "the refused file stayed in the cache")


if __name__ == "__main__":
    unittest.main(verbosity=2)
