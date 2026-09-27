"""verify.yml's «only 443» step (orchestrator#21) on local listeners; no real host is touched.

    python3 tests/common/test_verify_front.py      # needs ansible-playbook on PATH

roles/common/files/portscan.py is the controller's TCP connect scan; roles/common/tasks/verify_front.yml requires the
front port open and the old ports (the panel's own, the sub port, the inbounds' ports) closed, warns about a closed
ACME port 80, and on the panel requires the cover page at <base>panel/ (not the panel UI) and a working API login on
the front. The front here is a plain-HTTP stand-in on a free local port.
"""

import json
import os
import socket
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
SCAN = REPO / "roles" / "common" / "files" / "portscan.py"
COVER = b"<html><body>Nothing to see here</body></html>"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def listen(port=0):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen()
    return s


class Front(BaseHTTPRequestHandler):
    """The front's HTTP side: the cover page for anything unpublished, the panel's login published."""
    ui_reachable = False
    login_ok = True

    def log_message(self, *args):
        pass

    def _send(self, status, body, ctype="text/html", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/base/panel/" and Front.ui_reachable:
            # The panel itself: no session, off to its login page under the base path.
            return self._send(307, b'<a href="/base/">Temporary Redirect</a>', headers={"Location": "/base/"})
        self._send(200, COVER)

    def do_POST(self):  # noqa: N802
        form = parse_qs(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode())
        if self.path != "/base/login":
            return self._send(405, COVER)
        ok = Front.login_ok and form.get("username") == ["admin"] and form.get("password") == ["secret-pass"]
        self._send(200, json.dumps({"success": ok, "msg": "" if ok else "wrong username or password"}).encode(),
                   "application/json", {"Set-Cookie": "3ax-ui=front-session; Path=/base/"} if ok else None)


class PortscanTest(unittest.TestCase):
    def scan(self, *args):
        run = subprocess.run([sys.executable, str(SCAN), *args], capture_output=True, text=True, check=False)
        return run

    def test_open_and_closed_ports(self):
        a, b = listen(), listen()
        closed = free_port()
        try:
            ports = [a.getsockname()[1], b.getsockname()[1], closed]
            run = self.scan("--host", "127.0.0.1", "--ports", ",".join(map(str, ports + [ports[0]])), "--timeout", "1")
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout), {"host": "127.0.0.1", "open": sorted(ports[:2]), "closed": [closed]})
        finally:
            a.close()
            b.close()

    def test_bad_ports_are_refused(self):
        self.assertEqual(self.scan("--host", "127.0.0.1", "--ports", "0").returncode, 2)
        self.assertEqual(self.scan("--host", "127.0.0.1", "--ports", "x").returncode, 2)


class VerifyFrontTest(unittest.TestCase):
    def setUp(self):
        Front.ui_reachable, Front.login_ok = False, True
        self.front = ThreadingHTTPServer(("127.0.0.1", 0), Front)
        threading.Thread(target=self.front.serve_forever, daemon=True).start()
        self.acme = listen()
        self.acme_port = self.acme.getsockname()[1]
        self.sockets = [self.acme]
        self.old = [free_port(), free_port(), free_port()]

    def tearDown(self):
        self.front.shutdown()
        self.front.server_close()
        for s in self.sockets:
            s.close()

    def play(self, *extra, expect_rc=0):
        env = dict(os.environ, FRONT_TEST_PORT=str(self.front.server_address[1]), ACME_TEST_PORT=str(self.acme_port),
                   ANSIBLE_CONFIG=str(REPO / "ansible.cfg"), ANSIBLE_ROLES_PATH=str(REPO / "roles"), ANSIBLE_NOCOLOR="1",
                   ANSIBLE_STDOUT_CALLBACK="default")
        run = subprocess.run(["ansible-playbook", "-i", str(HERE / "inventory.yml"), str(HERE / "verify_front.yml"),
                              "-e", json.dumps({"common_front_closed_ports": self.old}), *extra],
                             env=env, capture_output=True, text=True, check=False)
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, expect_rc, out[-5000:])
        self.assertNotIn("secret-pass", out, "the panel password reached the output")
        return " ".join(out.split())

    def test_only_the_front_answers(self):
        out = self.play()
        self.assertIn(f"only {self.front.server_address[1]}/tcp answers on 127.0.0.1", out)
        self.assertIn("the panel UI is not reachable from outside", out)
        self.assertIn("the panel API login works on the front", out)
        self.assertNotIn("WARNING", out)

    def test_an_old_port_that_still_answers_fails(self):
        self.sockets.append(listen(self.old[1]))
        out = self.play(expect_rc=2)
        self.assertIn(f"127.0.0.1 still answers on {self.old[1]}/tcp", out)

    def test_a_closed_front_fails(self):
        self.front.shutdown()
        self.front.server_close()
        out = self.play(expect_rc=2)
        self.assertIn(f"127.0.0.1 does not answer on its front port {self.front.server_address[1]}/tcp", out)

    def test_a_closed_acme_port_only_warns(self):
        self.acme.close()
        out = self.play()
        self.assertIn(f"WARNING: 127.0.0.1 does not answer on the ACME port {self.acme_port}/tcp", out)

    def test_the_panel_ui_on_the_front_fails(self):
        Front.ui_reachable = True
        out = self.play(expect_rc=2)
        self.assertIn("the panel UI answers on the front at /base/panel/ (HTTP 307)", out)

    def test_a_failing_api_login_fails(self):
        Front.login_ok = False
        out = self.play(expect_rc=2)
        self.assertIn("POST /base/login on the front failed", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
