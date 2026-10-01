"""Role showcase (orchestrator#53) and its verify.yml step against local stand-ins; no real host is touched.

    SHOWCASE_PANEL_PORT=18084 python3 tests/showcase/test_showcase_role.py   # needs ansible-playbook, nginx, openssl, curl

The showcase box is a temp directory with a real nginx started from it on free ports (as root or not); the edges are
HTTPS stand-ins on 127.0.0.1 that answer a subscription, redirect, fail, refuse or are down; the panel is
tests/hop/mock_panel.py (the settings form with the subscription paths) and DNSExit tests/showcase/mock_dnsexit.py.
Covered: the subscription paths from the panel, the edges from group hops (the active one first), the walk over the
edges on a redirect and an error, the cover page after the last one and for every other path, the headers passed
through, port 80, the limit, the miss log (and fail2ban's filter on it, with fail2ban-regex when installed), an
idempotent rerun, check mode, the Let's Encrypt path through a fake acme.sh (issued through port 80, then kept), the
DNS record through the API (posted once, the key never printed, read only without a key), the refusals, verify.yml
(green, an edge answering the cover's 200 for an unknown subscription, nginx down) and wipe.yml.
"""

import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "hop"))
sys.dont_write_bytecode = True

import mock_panel  # noqa: E402
from mock_dnsexit import MockDNSExit  # noqa: E402

PANEL_PORT = int(os.environ.get("SHOWCASE_PANEL_PORT", "18084"))
PANEL_URL = f"http://127.0.0.1:{PANEL_PORT}"
DOMAIN = "sub.example.test"
KEY = "dnsexit-secret-key-42"
WELCOME = "<html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>\n"
SETTINGS = {"subEnable": True, "subPath": "/sub-abc123/", "subJsonEnable": True, "subJsonPath": "/json/",
            "subClashEnable": False, "subClashPath": "/clash/", "subTunPath": "/tun/"}
EDGES = ("proxy2", "proxy", "proxy3")  # the order the showcase must ask them in: proxy2 is the active edge

NGINXCTL = """#!/bin/sh
T="{root}"
N="nginx -e $T/error.log -p $T -c $T/nginx.conf"
echo "$1" >>"$T/nginx-calls"
case "$1" in
test) exec $N -t ;;
reload)
    if [ -f "$T/nginx.pid" ] && kill -0 "$(cat "$T/nginx.pid")" 2>/dev/null; then
        $N -s reload && sleep 1
    else
        $N && sleep 0.5
    fi ;;
stop) [ -f "$T/nginx.pid" ] && $N -s stop; sleep 0.3 ;;
esac
"""
NGINX_CONF = """{user}pid {root}/nginx.pid;
error_log {root}/error.log info;
worker_processes 1;
events {{ worker_connections 64; }}
http {{
    client_body_temp_path {root}/tmp/body;
    proxy_temp_path {root}/tmp/proxy;
    fastcgi_temp_path {root}/tmp/fastcgi;
    uwsgi_temp_path {root}/tmp/uwsgi;
    scgi_temp_path {root}/tmp/scgi;
    access_log off;
    include {root}/conf.d/*.conf;
}}
"""
FAKE_FAIL2BAN = """#!/bin/sh
echo "restart" >>"$(dirname "$0")/fail2ban-calls"
"""
FAKE_ACME_INSTALLER = """#!/bin/sh
mkdir -p "$HOME/.acme.sh"
cp "$HOME/../acme.sh.fake" "$HOME/.acme.sh/acme.sh"
chmod 755 "$HOME/.acme.sh/acme.sh"
echo "installer" >>"$HOME/../acme-calls"
"""
# --issue proves that nginx answers the challenge on port 80 by fetching a token through it; --install-cert copies
# the certificate of <root>/le to the given paths.
FAKE_ACME = """#!/bin/sh
T="$HOME/.."
echo "acme.sh $*" >>"$T/acme-calls"
case "$1" in
--issue)
    mkdir -p "$T/acme/.well-known/acme-challenge"
    echo token-ok >"$T/acme/.well-known/acme-challenge/tok"
    got=$(curl -s "http://127.0.0.1:$SHOWCASE_HTTP_PORT/.well-known/acme-challenge/tok")
    [ "$got" = token-ok ] || { echo "challenge not served: $got"; exit 1; }
    ;;
--install-cert)
    shift
    while [ $# -gt 0 ]; do
        case "$1" in
        --key-file) cp "$T/le/privkey.pem" "$2" ;;
        --fullchain-file) cp "$T/le/fullchain.pem" "$2" ;;
        esac
        shift
    done
    ;;
esac
exit 0
"""


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_cert(directory, san, days=30):
    directory.mkdir(parents=True, exist_ok=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-days", str(days), "-subj", "/CN=test", "-addext", f"subjectAltName={san}",
                    "-keyout", str(directory / "privkey.pem"), "-out", str(directory / "fullchain.pem")],
                   check=True, capture_output=True)


class Edge(BaseHTTPRequestHandler):
    """One edge's HTTP side: a subscription, a redirect, an error, a refusal or the cover page of a limited edge."""

    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802
        edge = self.server.edge
        edge.requests.append({"path": self.path, "host": self.headers.get("Host"),
                              "xff": self.headers.get("X-Forwarded-For")})
        if edge.mode == "redirect":
            return self._send(302, b"", {"Location": "https://elsewhere.example/"})
        if edge.mode == "error":
            return self._send(500, b"internal error")
        # An edge knows the subscriptions client-* (and the page's assets): anything else is an unknown one, 404.
        if edge.mode == "notfound" or (edge.mode == "good" and "client-" not in self.path and "assets" not in self.path):
            return self._send(404, b"")
        if edge.mode == "page200":
            return self._send(200, b"<html>an edge's own cover page</html>", {"Content-Type": "text/html"})
        body = f"subscription from {edge.name} for {self.path}".encode()
        self._send(200, body, {"Subscription-Userinfo": "upload=1; download=2; total=3; expire=0",
                               "Profile-Update-Interval": "12", "Profile-Title": "base64:dGVzdA==",
                               "Content-Disposition": 'attachment; filename="sub.txt"', "Content-Type": "text/plain"})

    def _send(self, status, body, headers=None):
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class EdgeServer:
    def __init__(self, name, cert_dir):
        self.name, self.mode, self.requests = name, "good", []
        self.port = free_port()
        self.cert_dir = cert_dir
        self.server = None
        self.up()

    def up(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), Edge)
        self.server.edge = self
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert_dir / "fullchain.pem", self.cert_dir / "privkey.pem")
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def down(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None


def post(path, payload):
    request = urllib.request.Request(PANEL_URL + path, data=json.dumps(payload).encode(), method="POST")
    urllib.request.urlopen(request).read()


class ShowcaseRoleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.panel = mock_panel.serve(PANEL_PORT, os.devnull)
        cls.certs = Path(tempfile.mkdtemp(prefix="showcase-certs-"))
        make_cert(cls.certs / "edge", "IP:127.0.0.1")

    @classmethod
    def tearDownClass(cls):
        cls.panel.shutdown()
        cls.panel.server_close()
        shutil.rmtree(cls.certs, ignore_errors=True)

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="showcase-"))
        self.root.chmod(0o755)
        for sub in ("conf.d", "sites-enabled", "tmp", "log", "welcome", "root"):
            (self.root / sub).mkdir(parents=True)
        (self.root / "sites-enabled/default").write_text("server { listen 80 default_server; }\n")
        (self.root / "welcome/index.nginx-debian.html").write_text(WELCOME)
        user = "user root;\n" if os.geteuid() == 0 else ""
        (self.root / "nginx.conf").write_text(NGINX_CONF.format(root=self.root, user=user))
        for name, content in (("nginxctl", NGINXCTL.format(root=self.root)), ("fake-fail2ban", FAKE_FAIL2BAN),
                              ("acme-install.sh", FAKE_ACME_INSTALLER), ("acme.sh.fake", FAKE_ACME)):
            (self.root / name).write_text(content)
            (self.root / name).chmod(0o755)
        make_cert(self.root / "manual", f"DNS:{DOMAIN}")
        make_cert(self.root / "le", f"DNS:{DOMAIN}", days=90)
        self.http_port, self.https_port = free_port(), free_port()
        self.edges = {name: EdgeServer(name, self.certs / "edge") for name in EDGES}
        self.dns = MockDNSExit(key=KEY, zone="example.test").start()
        post("/test/panel/reset", {"settings": SETTINGS})

    def tearDown(self):
        subprocess.run([str(self.root / "nginxctl"), "stop"], capture_output=True, check=False)
        for edge in self.edges.values():
            edge.down()
        self.dns.stop()
        shutil.rmtree(self.root, ignore_errors=True)

    # --- helpers -------------------------------------------------------------------------------------------------
    def play(self, *extra, expect_rc=0, tasks="main", env_extra=None):
        env = dict(os.environ, SHOWCASE_TEST_ROOT=str(self.root), SHOWCASE_PANEL_PORT=str(PANEL_PORT),
                   SHOWCASE_HTTP_PORT=str(self.http_port), SHOWCASE_HTTPS_PORT=str(self.https_port),
                   DNSEXIT_TEST_API=self.dns.api_url, DNSEXIT_TEST_NS=self.dns.nameserver,
                   ANSIBLE_CONFIG=str(REPO / "ansible.cfg"), ANSIBLE_ROLES_PATH=str(REPO / "roles"),
                   ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default", **(env_extra or {}))
        for name, edge in self.edges.items():
            env[f"EDGE_PORT_{name}"] = str(edge.port)
        run = subprocess.run(["ansible-playbook", "-vvv", "-i", str(HERE / "inventory.yml"), str(HERE / "site.yml"),
                              "-e", f"showcase_test_tasks={tasks}", *extra],
                             env=env, capture_output=True, text=True, check=False)
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, expect_rc, out[-8000:])
        self.assertNotIn("mock-session", out, "the panel session cookie reached the output")
        self.assertNotIn(KEY, out, "the DNSExit API key reached the output")
        return out

    def recap(self, out, host="subgateway"):
        match = re.search(rf"^{host}\s+: ok=(\d+)\s+changed=(\d+)", out, re.M)
        return int(match.group(2))

    def get(self, path, port=None, scheme="https", headers=None):
        port = port or (self.https_port if scheme == "https" else self.http_port)
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=30)
        else:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        conn.request("GET", path, headers=dict({"Host": DOMAIN}, **(headers or {})))
        response = conn.getresponse()
        body = response.read().decode()
        conn.close()
        return response.status, dict(response.getheaders()), body

    def miss_log(self, lines):
        """The miss log once it has that many lines: nginx writes it after the response has gone out."""
        path = self.root / "log/miss.log"
        for _ in range(50):
            text = path.read_text() if path.exists() else ""
            if len(text.splitlines()) >= lines:
                return text
            time.sleep(0.1)
        return text

    def conf(self):
        return (self.root / "conf.d/3ax-ui-showcase.conf").read_text()

    def modes(self, **modes):
        """Every edge answers subscriptions, but those named here; the requests seen so far are forgotten."""
        for name, edge in self.edges.items():
            edge.mode = modes.get(name, "good")
            edge.requests.clear()

    def asked(self):
        return [name for name in EDGES for _ in self.edges[name].requests]

    # --- converge --------------------------------------------------------------------------------------------------
    def test_converges_walks_the_edges_and_reruns_clean(self):
        out = self.play()
        conf = self.conf()
        locations = re.findall(r"^\s*location (/\S+) \{", conf, re.M)
        self.assertEqual(locations, ["/sub-abc123/", "/json/", "/tun/"], "the panel's paths (clash off) in order")
        url = {name: f"https://127.0.0.1:{edge.port}" for name, edge in self.edges.items()}
        self.assertEqual(re.findall(r"proxy_pass (\S+);", conf), [url["proxy2"]] * 3 + [url["proxy"], url["proxy3"]],
                         "every path starts at the active edge, then the others in inventory order")
        self.assertIn("proxy2 -> proxy -> proxy3 -> cover page", out)
        self.assertFalse((self.root / "sites-enabled/default").exists(), "the distro's default site still takes :80")
        self.assertEqual((self.root / "www/index.html").read_text(), WELCOME, "the cover is not nginx's welcome page")
        self.assertIn("[3ax-ui-showcase-probe]", (self.root / "fail2ban/jail.d/3ax-ui-showcase.conf").read_text())
        self.assertTrue((self.root / "fail2ban-calls").exists(), "fail2ban was not restarted for its new jail")

        # The active edge redirects, the next one fails: the third answers, its headers come through.
        self.modes(proxy2="redirect", proxy="error")
        status, headers, body = self.get("/sub-abc123/client-1?format=x")
        self.assertEqual((status, body), (200, "subscription from proxy3 for /sub-abc123/client-1?format=x"))
        self.assertEqual(self.asked(), ["proxy2", "proxy", "proxy3"])
        for key, value in (("Subscription-Userinfo", "upload=1; download=2; total=3; expire=0"),
                           ("Profile-Update-Interval", "12"), ("Profile-Title", "base64:dGVzdA=="),
                           ("Content-Disposition", 'attachment; filename="sub.txt"')):
            self.assertEqual(headers.get(key), value, key)
        self.assertEqual(self.edges["proxy3"].requests[0]["host"], DOMAIN, "the client's Host did not reach the edge")

        # The active edge answers: nobody else is asked. The page's assets live under subPath.
        self.modes()
        self.assertEqual(self.get("/sub-abc123/assets/app.css")[0], 200)
        self.assertEqual(self.asked(), ["proxy2"])

        # A down edge is skipped.
        self.modes()
        self.edges["proxy2"].down()
        status, _, body = self.get("/json/client-1")
        self.assertEqual((status, body), (200, "subscription from proxy for /json/client-1"))
        self.edges["proxy2"].up()

        # No edge knows it: the cover page, and a miss in the log fail2ban reads.
        self.modes(proxy2="notfound", proxy="notfound", proxy3="notfound")
        status, _, body = self.get("/tun/unknown")
        self.assertEqual((status, body), (200, WELCOME))
        self.assertEqual(self.asked(), list(EDGES))
        miss = self.miss_log(1)
        self.assertRegex(miss, r'^127\.0\.0\.1 \[[^\]]+\] miss "GET /tun/unknown" 404 : 404 : 404$')
        if shutil.which("fail2ban-regex"):
            run = subprocess.run(["fail2ban-regex", str(self.root / "log/miss.log"),
                                  str(self.root / "fail2ban/filter.d/3ax-ui-showcase-probe.conf")],
                                 capture_output=True, text=True, check=False)
            self.assertRegex(run.stdout, r"Lines: 1 lines, 0 ignored, 1 matched", run.stdout)

        # Every edge down (errors, not refusals): the cover page, but no miss.
        self.modes(proxy2="error", proxy="error", proxy3="error")
        self.assertEqual(self.get("/sub-abc123/x")[2], WELCOME)
        time.sleep(0.5)
        self.assertEqual(self.miss_log(2), miss, "edges in trouble counted as a miss")

        # Everything else: the cover page, no edge asked.
        self.modes()
        for path in ("/", "/clash/client-1", "/panel/", "/sub-abc123"):
            self.assertEqual(self.get(path)[:3:2], (200, WELCOME), path)
        self.assertEqual(self.asked(), [])

        # Port 80: a redirect to the showcase's name; the challenge path stays.
        status, headers, _ = self.get("/sub-abc123/x?y=1", scheme="http")
        self.assertEqual((status, headers.get("Location")), (301, f"https://{DOMAIN}:{self.https_port}/sub-abc123/x?y=1"))
        (self.root / "acme/.well-known/acme-challenge").mkdir(parents=True)
        (self.root / "acme/.well-known/acme-challenge/t1").write_text("challenge")
        self.assertEqual(self.get("/.well-known/acme-challenge/t1", scheme="http")[::2], (200, "challenge"))

        # A rerun changes nothing.
        out = self.play()
        self.assertEqual(self.recap(out), 0, "a converged showcase changed on a rerun")

    def test_the_limit_answers_the_cover_page(self):
        self.play("-e", "showcase_limit_rate=1r/m", "-e", "showcase_limit_burst=1", "-e", "showcase_exempt_loopback=false")
        statuses = [self.get("/sub-abc123/client-c")[2] for _ in range(4)]
        self.assertIn(WELCOME, statuses, "no request was limited")
        self.assertEqual(statuses[0], "subscription from proxy2 for /sub-abc123/client-c")
        self.assertRegex(self.miss_log(1), r'limit "GET /sub-abc123/client-c" 200')

    def test_check_mode_writes_nothing(self):
        self.play("--check")
        self.assertFalse((self.root / "conf.d/3ax-ui-showcase.conf").exists())
        self.assertFalse((self.root / "conf.d/3ax-ui-showcase-acme.conf").exists())
        self.assertFalse((self.root / "nginx.pid").exists())

    def test_edges_behind_their_front_are_asked_on_443(self):
        self.play("-e", json.dumps({"showcase_nginx_reload_command": ["true"]}),
                  env_extra={"EDGE_FRONT": "only443", "EDGE_HOST": "198.51.100.7"})
        upstreams = re.findall(r"proxy_pass (\S+);", self.conf())
        self.assertEqual(sorted(set(upstreams)), ["https://198.51.100.7:443"])
        self.assertIn("proxy_ssl_server_name off;", self.conf())

    def test_paths_and_edges_by_hand(self):
        edges = [{"name": "e1", "address": "127.0.0.1", "port": self.edges["proxy3"].port},
                 {"name": "e2", "address": "127.0.0.1", "port": self.edges["proxy"].port}]
        self.play("-e", json.dumps({"showcase_edges": edges, "showcase_sub_paths": ["/s/", "/j/"],
                                    "panel_api_url": "http://127.0.0.1:9/base/"}))
        self.assertEqual(re.findall(r"^\s*location (/\S+) \{", self.conf(), re.M), ["/s/", "/j/"])
        self.assertEqual(self.get("/j/client-x")[2], "subscription from proxy3 for /j/client-x")

    # --- certificate -----------------------------------------------------------------------------------------------
    def test_letsencrypt_is_issued_through_port_80_and_then_kept(self):
        out = self.play("-e", "showcase_tls=letsencrypt")
        calls = (self.root / "acme-calls").read_text().splitlines()
        self.assertEqual(calls[0], "installer")
        self.assertEqual(calls[1], f"acme.sh --issue -d {DOMAIN} --webroot {self.root}/acme --server letsencrypt "
                                   "--keylength ec-256")
        self.assertTrue(calls[2].startswith(f"acme.sh --install-cert -d {DOMAIN} --ecc"))
        self.assertIn(f"ssl_certificate     {self.root}/cert/fullchain.pem;", self.conf())
        self.assertEqual(self.get("/")[2], WELCOME)
        self.assertIn("issue through HTTP-01", out)

        out = self.play("-e", "showcase_tls=letsencrypt")
        self.assertEqual(len((self.root / "acme-calls").read_text().splitlines()), 3, "a valid certificate was reissued")
        self.assertIn(f"keep {self.root}/cert/fullchain.pem", out)
        self.assertEqual(self.recap(out), 0)

    def test_a_manual_certificate_for_another_name_is_refused(self):
        make_cert(self.root / "manual", "DNS:other.example.test")
        out = self.play(expect_rc=2)
        self.assertIn(f"must be a certificate for {DOMAIN}", out)

    # --- DNS -------------------------------------------------------------------------------------------------------
    def test_the_dns_record_is_posted_once(self):
        self.dns.records[DOMAIN] = ["198.51.100.1"]
        out = self.play("-e", "showcase_dns_check=true", "-e", f"dnsexit_api_key={KEY}",
                        "-e", "showcase_dns_min_interval=1")
        self.assertEqual(len(self.dns.posts), 1)
        self.assertEqual(self.dns.posts[0]["body"]["add"],
                         {"type": "A", "name": "sub", "content": "127.0.0.1", "ttl": 60, "overwrite": True})
        self.assertEqual(self.dns.records[DOMAIN], ["127.0.0.1"])
        self.assertIn(f"DNS {DOMAIN} now points at 127.0.0.1", " ".join(out.split()))

        out = self.play("-e", "showcase_dns_check=true", "-e", f"dnsexit_api_key={KEY}")
        self.assertEqual(len(self.dns.posts), 1, "a record that is right was posted again")
        self.assertIn(f"DNS {DOMAIN} already points at 127.0.0.1", " ".join(out.split()))
        self.assertEqual(self.recap(out), 0)

    def test_without_a_key_the_record_is_only_read(self):
        self.dns.records[DOMAIN] = ["198.51.100.1"]
        out = " ".join(self.play("-e", "showcase_dns_check=true").split())
        self.assertEqual(self.dns.posts, [])
        self.assertIn(f"WARNING: DNS {DOMAIN} points at 198.51.100.1, not 127.0.0.1", out)
        self.assertIn("no DNSExit API key", out)

    def test_a_refused_dns_update_stops_the_run(self):
        self.dns.refuse = {"code": 2, "message": "API Key Authentication Error"}
        out = self.play("-e", "showcase_dns_check=true", "-e", f"dnsexit_api_key={KEY}", expect_rc=2)
        self.assertIn("code 2 API Key Authentication Error", out)
        self.assertFalse((self.root / "conf.d/3ax-ui-showcase.conf").exists())

    # --- refusals --------------------------------------------------------------------------------------------------
    def test_refusals(self):
        out = self.play("-e", "showcase_domain=", expect_rc=2)
        self.assertIn("showcase_domain as a lower-case DNS name", out)
        out = self.play("-e", json.dumps({"showcase_edges": [
            {"name": "bad name", "address": "127.0.0.1"}]}), expect_rc=2)
        self.assertIn("no usable edge", out)
        post("/test/panel/reset", {"settings": dict(SETTINGS, subPath="/sub abc/")})
        out = self.play(expect_rc=2)
        self.assertIn("must each start and end with /", out)
        post("/test/panel/reset", {"settings": SETTINGS})
        out = self.play("-e", "panel_api_url=http://127.0.0.1:9/base/", expect_rc=2)
        self.assertRegex(out, r"TASK \[panel : Log in to the panel API\][^\n]*\n(.*\n)*?fatal: \[subgateway -> real\]")
        self.assertFalse((self.root / "conf.d/3ax-ui-showcase.conf").exists())

    def test_a_config_nginx_refuses_is_not_loaded(self):
        self.play()
        out = self.play("-e", "showcase_edge_read_timeout=forever", expect_rc=2)
        self.assertIn("nginx refuses its config", out)
        self.assertEqual(self.get("/sub-abc123/client-c")[2], "subscription from proxy2 for /sub-abc123/client-c", "nginx lost its config")

    # --- verify.yml ------------------------------------------------------------------------------------------------
    def test_verify(self):
        self.play()
        self.modes(proxy2="notfound", proxy="notfound", proxy3="notfound")
        out = " ".join(self.play("-e", "showcase_verify_sub=client-1", expect_rc=2, tasks="verify").split())
        self.assertIn("nginx config ok", out)
        self.assertIn(f"port {self.http_port} redirects to https://{DOMAIN}:{self.https_port}/", out)
        self.assertIn("an unknown subscription went through the edges and ended on the cover page", out)
        self.assertIn("did not come back from an edge with Subscription-Userinfo", out)

        self.modes(proxy2="notfound", proxy="good")
        out = " ".join(self.play("-e", "showcase_verify_sub=client-1", tasks="verify").split())
        self.assertIn("the known subscription comes back from an edge with its headers", out)
        self.assertNotIn("WARNING", out)

        # An edge that answers an unknown subscription with a page of its own (its limit's cover, 200).
        self.modes(proxy2="page200")
        out = " ".join(self.play(expect_rc=2, tasks="verify").split())
        self.assertIn("did not end on the cover page", out)

        self.modes()
        subprocess.run([str(self.root / "nginxctl"), "stop"], capture_output=True, check=False)
        out = " ".join(self.play(expect_rc=2, tasks="verify").split())
        self.assertIn(f"does not redirect to https://{DOMAIN}:{self.https_port}/", out)

    def test_verify_reads_the_dns_record(self):
        self.play()
        self.dns.records[DOMAIN] = ["198.51.100.1"]
        out = " ".join(self.play("-e", "showcase_dns_check=true", tasks="verify").split())
        self.assertIn(f"WARNING: DNS {DOMAIN} points at 198.51.100.1, not 127.0.0.1", out)

    # --- wipe.yml --------------------------------------------------------------------------------------------------
    def test_wipe(self):
        self.play()
        self.play(tasks="wipe")
        for rel in ("conf.d/3ax-ui-showcase.conf", "conf.d/3ax-ui-showcase-acme.conf", "www", "acme",
                    "fail2ban/jail.d/3ax-ui-showcase.conf", "fail2ban/filter.d/3ax-ui-showcase-probe.conf"):
            self.assertFalse((self.root / rel).exists(), rel)
        self.assertTrue((self.root / "manual/fullchain.pem").exists())
        out = self.play(tasks="wipe")
        self.assertEqual(self.recap(out), 0, "a second wipe changed something")


if __name__ == "__main__":
    unittest.main(verbosity=2)
