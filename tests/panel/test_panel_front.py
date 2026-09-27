"""Role panel's «only 443» front (orchestrator#21) against the mock panel API and local fakes; no real host is touched.

    PANEL_TEST_PORT=18082 python3 tests/panel/test_panel_front.py      # needs ansible-playbook and openssl on PATH

tests/panel/front.yml runs one task file of the role (panel_test_tasks):
  front_nginx    the panel's Nginx settings (only443, subscriptions and panel behind 443, firewall, 80 kept for the
                 ACME webroot) through panel/api/nginx/plan|apply, then the 2-minute confirmation, as the UI does
  web_settings   webListen 127.0.0.1 and chainPanelHost = the public IP through the settings form (a round trip)
  ip_cert        the Let's Encrypt IP certificate of the HTTP side (/root/cert/ip) through nginx's webroot, with a
                 fake acme.sh and x-ui; reused while valid for the address
  facts          panel_url on 443 without panelCa behind the front
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / "hop"))
sys.dont_write_bytecode = True  # no __pycache__ in the checkout

import mock_panel  # noqa: E402

PORT = int(os.environ.get("PANEL_TEST_PORT", "18082"))
URL = f"http://127.0.0.1:{PORT}"
STAND = REPO / "inventories" / "stand-full" / "group_vars" / "panel.yml"
STAND_INBOUNDS = yaml.safe_load(STAND.read_text())["panel_inbounds"]
ONLY443 = {"mode": "only443", "subsBehind443": True, "panelBehind443": True, "manageFirewall": True}

FAKE_XUI = """#!/bin/sh
echo "x-ui $*" >>"$(dirname "$0")/calls"
[ "$1 $2" = "nginx acme-front" ] && echo "nginx now answers ACME challenges on port 80"
exit 0
"""
# Installs the fake acme.sh the way get.acme.sh installs the real one: into $HOME/.acme.sh.
FAKE_ACME_INSTALLER = """#!/bin/sh
mkdir -p "$HOME/.acme.sh"
cp "$(dirname "$0")/acme.sh.fake" "$HOME/.acme.sh/acme.sh"
chmod 755 "$HOME/.acme.sh/acme.sh"
echo "installer" >>"$HOME/calls"
"""
# --issue records its arguments; --installcert copies the certificate of $HOME/src to the given paths.
FAKE_ACME = """#!/bin/sh
echo "acme.sh $*" >>"$HOME/calls"
case "$1" in
--installcert)
    shift
    while [ $# -gt 0 ]; do
        case "$1" in
        --key-file) cp "$HOME/src/privkey.pem" "$2" ;;
        --fullchain-file) cp "$HOME/src/fullchain.pem" "$2" ;;
        esac
        shift
    done
    ;;
esac
exit 0
"""


def post(path, payload):
    request = urllib.request.Request(URL + path, data=json.dumps(payload).encode(), method="POST")
    urllib.request.urlopen(request).read()


def make_cert(directory, ip, days=2):
    directory.mkdir(parents=True, exist_ok=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-days", str(days), "-subj", f"/CN={ip}", "-addext", f"subjectAltName=IP:{ip}",
                    "-keyout", str(directory / "privkey.pem"), "-out", str(directory / "fullchain.pem")],
                   check=True, capture_output=True)


def flat(out):
    return re.sub(r"\s+", " ", out)


class PanelFrontTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = mock_panel.serve(PORT, os.devnull)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="panelfront-"))
        post("/test/reset", [])
        post("/test/panel/reset", {})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- helpers -------------------------------------------------------------------------------------
    def state(self):
        return json.load(urllib.request.urlopen(URL + "/test/state"))

    def panel(self):
        return self.state()["panel"]

    def play(self, tasks, *extra, expect_rc=0, playbook=HERE / "front.yml", inbounds=None):
        vars_file = self.tmp / "vars.json"
        vars_file.write_text(json.dumps({"panel_inbounds": STAND_INBOUNDS if inbounds is None else inbounds,
                                         "panel_test_tasks": tasks, "panel_test_root": str(self.tmp)}))
        env = dict(os.environ, PANEL_TEST_PORT=str(PORT), ANSIBLE_CONFIG=str(REPO / "ansible.cfg"),
                   ANSIBLE_ROLES_PATH=str(REPO / "roles"), ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default")
        before = len(self.state()["calls"])
        run = subprocess.run(["ansible-playbook", "-vvv", "-i", str(HERE / "inventory.yml"), str(playbook),
                              "-e", f"@{vars_file}", *extra], env=env, capture_output=True, text=True, check=False)
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, expect_rc, out[-6000:])
        self.assertNotIn("mock-session", out, "the session cookie reached the ansible output")
        calls = self.state()["calls"][before:]
        self.writes = [(c["method"], c["path"], json.loads(c["body"] or "{}")) for c in calls
                       if c["method"] == "POST" and c["path"] not in ("login", "setting/all", "nginx/plan")]
        self.plans = [json.loads(c["body"] or "{}") for c in calls if c["path"] == "nginx/plan"]
        return out

    def converge_inbounds(self):
        self.play("inbounds")

    # --- the Nginx settings ---------------------------------------------------------------------------
    def test_only443_is_applied_and_confirmed(self):
        self.converge_inbounds()
        out = self.play("front_nginx")
        self.assertEqual([(m, p) for m, p, _ in self.writes], [("POST", "nginx/apply"), ("POST", "nginx/confirm")])
        applied = self.writes[0][2]
        self.assertEqual({k: applied[k] for k in ONLY443}, ONLY443)
        self.assertEqual(applied["firewallExtra"], "80", "the panel's firewall keeps 80 for the ACME webroot only if told")
        self.assertEqual((applied["realityPort"], applied["domain"]), (8443, ""), "the rest goes back as the panel has it")
        self.assertEqual(len(self.plans), 1, "the plan is read before anything is applied")
        panel = self.panel()
        self.assertEqual(panel["nginx"]["mode"], "only443")
        self.assertEqual(panel["confirmDeadline"], 0, "the confirmation window is closed by the role")
        self.assertIn("front: only443", flat(out))

        # Second run: nothing to apply, nothing pending.
        out = self.play("front_nginx")
        self.assertEqual(self.writes, [])
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")

    def test_relocated_inbound_is_not_fought(self):
        self.converge_inbounds()
        self.play("front_nginx")
        vless = next(i for i in self.panel()["inbounds"] if i["remark"] == "vless-reality")
        self.assertEqual((vless["listen"], vless["port"], vless["publicPort"]), ("127.0.0.1", 8443, 443))
        self.play("inbounds")
        self.assertEqual(self.writes, [], "the inbounds converge must leave the front's relocation alone")

    def test_owners_firewall_extra_ports_are_kept(self):
        self.converge_inbounds()
        post("/test/panel/nginx", {"settings": {"firewallExtra": "53, 8000-8100"}})
        self.play("front_nginx")
        self.assertEqual(self.writes[0][2]["firewallExtra"], "53, 8000-8100, 80")
        self.play("front_nginx")
        self.assertEqual(self.writes, [])

    def test_blockers_stop_the_apply(self):
        out = self.play("front_nginx", expect_rc=2)  # no inbound yet: nothing to route
        self.assertIn("nothingToRoute", out)
        self.assertEqual(self.writes, [])
        self.assertEqual(self.panel()["nginx"]["mode"], "shared")

    def test_a_pending_confirmation_is_confirmed(self):
        # An interrupted run: the settings are in, the confirmation never came.
        self.converge_inbounds()
        post("/test/panel/nginx", {"settings": dict(ONLY443, firewallExtra="80"), "confirmDeadline": 1790000120000})
        self.play("front_nginx")
        self.assertEqual([(m, p) for m, p, _ in self.writes], [("POST", "nginx/confirm")])
        self.assertEqual(self.panel()["confirmDeadline"], 0)

    def test_panel_warnings_are_shown(self):
        self.converge_inbounds()
        post("/test/panel/nginx", {"warnings": [{"code": "noFail2ban"}]})
        out = flat(self.play("front_nginx"))
        self.assertIn("WARNING: the panel front reports noFail2ban", out)

    def test_check_mode_only_plans(self):
        self.converge_inbounds()
        out = flat(self.play("front_nginx", "--check"))
        self.assertEqual(self.writes, [])
        self.assertIn("front: shared -> only443", out)
        self.assertEqual(self.panel()["nginx"]["mode"], "shared")

    def test_front_off_leaves_the_panel_alone(self):
        self.converge_inbounds()
        self.play("front", "-e", "front_mode=off")
        self.assertEqual(self.writes, [])
        self.assertEqual(self.panel()["nginx"]["mode"], "shared")

    # --- webListen and chainPanelHost -------------------------------------------------------------------
    def test_web_listen_and_chain_panel_host_through_the_settings_form(self):
        before = self.panel()["settings"]
        out = self.play("web_settings")
        self.assertEqual([(m, p) for m, p, _ in self.writes], [("POST", "setting/update")])
        after = self.panel()["settings"]
        self.assertEqual((after["webListen"], after["chainPanelHost"]), ("127.0.0.1", "10.0.0.1"))
        self.assertEqual({k: v for k, v in after.items() if k not in ("webListen", "chainPanelHost")},
                         {k: v for k, v in before.items() if k not in ("webListen", "chainPanelHost")},
                         "the rest of the form goes back as it was")
        self.assertIn("restart the panel on its new listen address", out.lower())
        self.assertTrue((self.tmp / "restarted").exists(), "a new webListen needs a panel restart")

        (self.tmp / "restarted").unlink()
        out = self.play("web_settings")
        self.assertEqual(self.writes, [])
        self.assertFalse((self.tmp / "restarted").exists())
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")

    def test_chain_panel_host_alone_needs_no_restart(self):
        post("/test/panel/reset", {"settings": {"webListen": "127.0.0.1"}})
        self.play("web_settings")
        self.assertEqual(self.panel()["settings"]["chainPanelHost"], "10.0.0.1")
        self.assertFalse((self.tmp / "restarted").exists())

    # --- the IP certificate -------------------------------------------------------------------------------
    def fakes(self, installed=True):
        xui = self.tmp / "x-ui"
        xui.write_text(FAKE_XUI)
        xui.chmod(0o755)
        (self.tmp / "acme.sh.fake").write_text(FAKE_ACME)
        installer = self.tmp / "get-acme.sh"
        installer.write_text(FAKE_ACME_INSTALLER)
        if installed:
            home = self.tmp / ".acme.sh"
            home.mkdir()
            shutil.copy(self.tmp / "acme.sh.fake", home / "acme.sh")
            (home / "acme.sh").chmod(0o755)
        make_cert(self.tmp / "src", "10.0.0.1")

    def calls(self):
        lines = []
        for f in (self.tmp / "calls",):
            if f.exists():
                lines += f.read_text().splitlines()
                f.unlink()
        return lines

    def cert_vars(self):
        return ("-e", json.dumps({"panel_bin": str(self.tmp / "x-ui"), "panel_ip_cert_dir": str(self.tmp / "cert" / "ip"),
                                  "panel_acme_home": str(self.tmp / ".acme.sh"),
                                  "panel_acme_install_url": f"file://{self.tmp / 'get-acme.sh'}"}))

    def test_ip_certificate_is_issued_through_the_webroot_and_then_reused(self):
        self.fakes(installed=False)
        self.play("ip_cert", *self.cert_vars())
        calls = self.calls()
        self.assertEqual(calls[0], "installer")
        issue = next(c for c in calls if c.startswith("acme.sh --issue"))
        for part in ("-d 10.0.0.1", "--webroot /usr/local/x-ui/acme-webroot", "--server letsencrypt", "--listen-v4",
                     "--request-v4", "--certificate-profile shortlived", "--days 3"):
            self.assertIn(part, issue)
        self.assertNotIn("--standalone", issue)
        install = next(c for c in calls if c.startswith("acme.sh --installcert"))
        self.assertIn(f"--fullchain-file {self.tmp}/cert/ip/fullchain.pem", install)
        self.assertIn("systemctl reload nginx", install)
        self.assertIn("x-ui nginx acme-front", calls)
        self.assertTrue((self.tmp / "cert" / "ip" / "fullchain.pem").exists())
        self.assertEqual(oct((self.tmp / "cert" / "ip" / "privkey.pem").stat().st_mode & 0o777), "0o600")

        out = self.play("ip_cert", *self.cert_vars())
        self.assertEqual(self.calls(), [], "a valid certificate for the address is reused: no issuance")
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")

    def test_acme_front_runs_before_the_issue(self):
        self.fakes()
        self.play("ip_cert", *self.cert_vars())
        lines = self.calls()
        self.assertLess(lines.index("x-ui nginx acme-front"),
                        next(i for i, line in enumerate(lines) if line.startswith("acme.sh --issue")))

    def test_certificate_for_another_address_or_expiring_is_issued_again(self):
        self.fakes()
        make_cert(self.tmp / "cert" / "ip", "10.0.0.9")
        self.play("ip_cert", *self.cert_vars())
        self.assertTrue(any(c.startswith("acme.sh --issue") for c in self.calls()))
        make_cert(self.tmp / "cert" / "ip", "10.0.0.1", days=1)  # expires within a day
        self.play("ip_cert", *self.cert_vars())
        self.assertTrue(any(c.startswith("acme.sh --issue") for c in self.calls()))

    def test_check_mode_issues_nothing(self):
        self.fakes()
        out = flat(self.play("ip_cert", "--check", *self.cert_vars()))
        self.assertEqual(self.calls(), [])
        self.assertIn("IP certificate for 10.0.0.1: issue", out)

    # --- facts for mon-server and the hops -------------------------------------------------------------
    def test_facts_behind_the_front(self):
        make_cert(self.tmp / "tls", "10.0.0.1", days=10)
        out = flat(self.play("facts", "-e", json.dumps({"panel_cert_file": str(self.tmp / "tls" / "fullchain.pem")})))
        self.assertIn("panel_url=https://10.0.0.1/base/ panel_ca_pem=0 chars", out)
        out = flat(self.play("facts", "-e", json.dumps({"panel_cert_file": str(self.tmp / "tls" / "fullchain.pem"),
                                                         "front_mode": "off"})))
        self.assertRegex(out, r"panel_url=https://10\.0\.0\.1:2053/base/ panel_ca_pem=[1-9]\d* chars")


if __name__ == "__main__":
    unittest.main(verbosity=2)
