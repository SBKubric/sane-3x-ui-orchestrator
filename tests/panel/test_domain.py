"""Role panel's domain settings (orchestrator#56, map #52) against the mock panel API (tests/hop/mock_panel.py: the
settings form with the DNSExit API key masked), a fake x-ui that stores what `x-ui setting -vpnName ...` stores, and a
stand-in for DNSExit's nameserver (tests/showcase/mock_dnsexit.py); no real host is touched.

    PANEL_TEST_PORT=18087 python3 tests/panel/test_domain.py   # needs ansible-playbook

tests/panel/domain.yml runs one task file of the role (panel_test_tasks):
  domain           subPublicURL through the settings form; dnsExitApiKey, vpnName, vpnNameTtl and domainExpiry through
                   `x-ui setting`; empty variables leave the settings alone
  verify_vpn_name  verify.yml's check: the VPN name at DNSExit's nameservers against the active edge (a warning only)
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

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / "hop"))
sys.path.insert(0, str(HERE.parent / "showcase"))
sys.dont_write_bytecode = True  # no __pycache__ in the checkout

import mock_dnsexit  # noqa: E402
import mock_panel  # noqa: E402

PORT = int(os.environ.get("PANEL_TEST_PORT", "18087"))
URL = f"http://127.0.0.1:{PORT}"

KEY = "dnsexit-key-7f3a91c2"
EVERYTHING = {"dns_zone": "example.com", "vpn_name": "VPN.Example.com.", "vpn_name_ttl": 3,
              "domain_expiry": "2027-05-01", "dnsexit_api_key": KEY}
EVERYTHING_CLI = ["setting", "-dnsExitApiKey", KEY, "-vpnName", "vpn.example.com", "-vpnNameTtl", "3",
                  "-domainExpiry", "2027-05-01"]

# Records its arguments (one JSON list a line) and stores the VPN name flags in the mock panel, as the real CLI stores
# them in the database.
FAKE_XUI = """#!/usr/bin/env python3
import json, sys, urllib.request
from pathlib import Path
args = sys.argv[1:]
with open(Path(__file__).resolve().parent / "calls", "a") as f:
    f.write(json.dumps(args) + "\\n")
if args[:1] == ["setting"]:
    flags = dict(zip([a.lstrip("-") for a in args[1::2]], args[2::2]))
    req = urllib.request.Request("%s/test/panel/cli", data=json.dumps(flags).encode(), method="POST")
    urllib.request.urlopen(req).read()
    for name in flags:
        print(name + ": (set)" if name == "dnsExitApiKey" else name + ": " + flags[name])
"""


def post(path, payload):
    request = urllib.request.Request(URL + path, data=json.dumps(payload).encode(), method="POST")
    urllib.request.urlopen(request).read()


def flat(out):
    return re.sub(r"\s+", " ", out)


class DomainTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = mock_panel.serve(PORT, os.devnull)
        cls.dns = mock_dnsexit.MockDNSExit(zone="example.com").start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.dns.stop()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="panel-domain-"))
        (self.tmp / "x-ui").write_text(FAKE_XUI % URL)
        (self.tmp / "x-ui").chmod(0o755)
        post("/test/reset", [])
        post("/test/panel/reset", {})
        with self.dns.lock:
            self.dns.records, self.dns.posts, self.dns.silent = {}, [], False

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- helpers -------------------------------------------------------------------------------------
    def state(self):
        return json.load(urllib.request.urlopen(URL + "/test/state"))

    def settings(self):
        return self.state()["panel"]["settings"]

    def cli(self):
        """The fake x-ui's calls since the last look."""
        calls = self.tmp / "calls"
        if not calls.exists():
            return []
        lines = [json.loads(line) for line in calls.read_text().splitlines()]
        calls.unlink()
        return lines

    def play(self, tasks="domain", expect_rc=0, check=False, showcase=False, yaml_extra="", **extra):
        variables = dict({"panel_bin": str(self.tmp / "x-ui"), "panel_dnsexit_key_state": str(self.tmp / "dnsexit-key.sha256"),
                          "panel_vpn_name_nameservers": [self.dns.nameserver],
                          "panel_vpn_name_dns_state": str(self.tmp / "dnsexit-state.json")}, **extra, panel_test_tasks=tasks)
        files = []
        for suffix, text in ((".json", json.dumps(variables)), (".yml", yaml_extra or "{}\n")):
            with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as f:
                f.write(text)
            files.append(f.name)
        env = dict(os.environ, PANEL_TEST_PORT=str(PORT), ANSIBLE_CONFIG=str(REPO / "ansible.cfg"),
                   ANSIBLE_ROLES_PATH=str(REPO / "roles"), ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default")
        inventories = ["-i", str(HERE / "inventory.yml")] + (["-i", str(HERE / "showcase_inventory.yml")] if showcase else [])
        before = len(self.state()["calls"])
        try:
            run = subprocess.run(["ansible-playbook", "-vvv", *inventories, str(HERE / "domain.yml"),
                                  "-e", f"@{files[0]}", "-e", f"@{files[1]}"] + (["--check"] if check else []),
                                 env=env, capture_output=True, text=True, check=False)
        finally:
            for name in files:
                os.unlink(name)
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, expect_rc, out[-8000:])
        self.assertNotIn("mock-session", out, "the session cookie reached the ansible output")
        for secret in (KEY, "new-key-55e1", "hand-key-0b9d", "123456:tg-token"):
            self.assertNotIn(secret, out, "a secret reached the ansible output")
        calls = self.state()["calls"][before:]
        self.writes = [c["path"] for c in calls if c["method"] == "POST" and c["path"] not in ("login", "setting/all")]
        self.calls = calls
        return out

    # --- converge -----------------------------------------------------------------------------------------
    def test_fresh_panel_gets_every_setting_and_a_second_run_changes_nothing(self):
        out = flat(self.play(showcase=True, **EVERYTHING))
        self.assertEqual(self.writes, ["setting/update"])
        self.assertEqual(self.cli(), [EVERYTHING_CLI])
        settings = self.settings()
        self.assertEqual(settings["subPublicURL"], "https://sub.example.com")
        self.assertEqual((settings["dnsExitApiKey"], settings["vpnName"], settings["vpnNameTtl"], settings["domainExpiry"]),
                         (KEY, "vpn.example.com", 3, "2027-05-01"))
        self.assertIn('subPublicURL "" -> "https://sub.example.com"', out)
        self.assertIn('vpnName "" -> "vpn.example.com"', out)
        self.assertIn("dnsExitApiKey: set from the vault", out)

        out = self.play(showcase=True, **EVERYTHING)
        self.assertEqual(self.writes, [])
        self.assertEqual(self.cli(), [])
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")
        self.assertIn("(as wanted)", flat(out))

    def test_nothing_in_the_inventory_leaves_the_settings_alone(self):
        seed = {"subPublicURL": "https://old.example.net", "dnsExitApiKey": "hand-key-0b9d", "vpnName": "vpn.example.net",
                "vpnNameTtl": 7, "domainExpiry": "2026-12-31"}
        post("/test/panel/reset", {"settings": seed})
        out = self.play()
        self.assertEqual((self.writes, self.cli()), ([], []))
        self.assertEqual({k: self.settings()[k] for k in seed}, seed)
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")
        self.assertIn("panel domain settings: none in the inventory", flat(out))

    def test_public_address_needs_both_a_showcase_and_dns_zone(self):
        self.play(showcase=True)
        self.play(dns_zone="example.com")
        self.assertEqual((self.writes, self.cli()), ([], []))
        self.assertEqual(self.settings()["subPublicURL"], "")

    def test_public_address_follows_showcase_domain_and_sub_public_url_overrides_it(self):
        self.play(showcase=True, dns_zone="example.com", showcase_domain="links.example.com")
        self.assertEqual(self.settings()["subPublicURL"], "https://links.example.com")
        self.play(showcase=True, dns_zone="example.com", sub_public_url="https://subs.example.net:8443")
        self.assertEqual(self.settings()["subPublicURL"], "https://subs.example.net:8443")
        self.play(sub_public_url="https://subs.example.net:8443")
        self.assertEqual(self.writes, [], "sub_public_url alone is enough; already set")

    def test_public_address_is_compared_the_way_the_panel_stores_it(self):
        post("/test/panel/reset", {"settings": {"subPublicURL": "https://sub.example.com"}})
        out = self.play(sub_public_url="HTTPS://Sub.Example.COM:443/")
        self.assertEqual(self.writes, [])
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")

    def test_saving_the_public_address_keeps_the_rest_of_the_form_and_the_stored_key(self):
        post("/test/panel/reset", {"settings": {"tgBotToken": "123456:tg-token", "tgBotEnable": True,
                                                "dnsExitApiKey": "hand-key-0b9d", "vpnName": "vpn.example.net"}})
        before = self.settings()
        self.play(showcase=True, dns_zone="example.com")
        self.assertEqual(self.writes, ["setting/update"])
        self.assertEqual(self.cli(), [])
        self.assertEqual(self.settings(), dict(before, subPublicURL="https://sub.example.com"))

    def test_a_new_key_in_the_vault_is_applied_alone_and_then_kept(self):
        self.play(**EVERYTHING)
        self.cli()
        self.play(**dict(EVERYTHING, dnsexit_api_key="new-key-55e1"))
        self.assertEqual(self.cli(), [["setting", "-dnsExitApiKey", "new-key-55e1"]])
        self.assertEqual(self.settings()["dnsExitApiKey"], "new-key-55e1")
        out = self.play(**dict(EVERYTHING, dnsexit_api_key="new-key-55e1"))
        self.assertEqual(self.cli(), [])
        self.assertIn("dnsExitApiKey (as wanted)", flat(out))

    def test_a_key_set_by_hand_is_replaced_once_by_the_vaults(self):
        post("/test/panel/reset", {"settings": {"dnsExitApiKey": "hand-key-0b9d"}})
        self.play(dnsexit_api_key=KEY)
        self.assertEqual(self.cli(), [["setting", "-dnsExitApiKey", KEY]])
        self.assertEqual(self.settings()["dnsExitApiKey"], KEY)
        self.play(dnsexit_api_key=KEY)
        self.assertEqual(self.cli(), [])

    def test_a_key_cleared_in_the_panel_is_set_again(self):
        self.play(dnsexit_api_key=KEY)
        self.cli()
        post("/test/panel/cli", {"dnsExitApiKey": ""})
        self.play(dnsexit_api_key=KEY)
        self.assertEqual(self.cli(), [["setting", "-dnsExitApiKey", KEY]])

    def test_ttl_and_expiry_are_written_alone_when_only_they_differ(self):
        post("/test/panel/reset", {"settings": {"vpnName": "vpn.example.com", "vpnNameTtl": 5, "domainExpiry": "2027-05-01"}})
        self.play(vpn_name="vpn.example.com", domain_expiry="2027-05-01")
        self.assertEqual(self.cli(), [], "vpn_name_ttl defaults to the panel's 5")
        self.play(vpn_name="vpn.example.com", vpn_name_ttl=10)
        self.assertEqual(self.cli(), [["setting", "-vpnNameTtl", "10"]])
        self.play(domain_expiry="2028-01-31")
        self.assertEqual(self.cli(), [["setting", "-domainExpiry", "2028-01-31"]])
        self.assertEqual(self.settings()["vpnNameTtl"], 10, "no vpn_name: the TTL is not touched either")

    def test_an_unquoted_yaml_date_is_taken_as_the_date(self):
        self.play(yaml_extra="domain_expiry: 2027-05-01\n")
        self.assertEqual(self.cli(), [["setting", "-domainExpiry", "2027-05-01"]])

    def test_bad_values_fail_before_anything_is_written(self):
        cases = [({"vpn_name": "vpn"}, "vpn_name"), ({"vpn_name": "192.0.2.1"}, "vpn_name"),
                 ({"vpn_name": "-bad.example.com"}, "vpn_name"), ({"vpn_name": "vpn.example.com", "vpn_name_ttl": 0}, "vpn_name_ttl"),
                 ({"vpn_name": "vpn.example.com", "vpn_name_ttl": 1441}, "vpn_name_ttl"),
                 ({"vpn_name": "vpn.example.com", "vpn_name_ttl": "five"}, "vpn_name_ttl"),
                 ({"domain_expiry": "2027-13-01"}, "domain_expiry"), ({"domain_expiry": "01.05.2027"}, "domain_expiry"),
                 ({"sub_public_url": "https://sub.example.com/sub/"}, "public subscription address"),
                 ({"sub_public_url": "ftp://sub.example.com"}, "public subscription address")]
        for variables, word in cases:
            with self.subTest(**variables):
                out = flat(self.play(expect_rc=2, dnsexit_api_key=KEY, **variables))
                self.assertIn(word, out)
                self.assertEqual((self.writes, self.cli()), ([], []))

    def test_check_mode_writes_nothing_and_shows_the_plan(self):
        out = flat(self.play(check=True, showcase=True, **EVERYTHING))
        self.assertEqual((self.writes, self.cli()), ([], []))
        self.assertIn('subPublicURL "" -> "https://sub.example.com", vpnName "" -> "vpn.example.com", vpnNameTtl "5" -> "3", '
                      'domainExpiry "" -> "2027-05-01", dnsExitApiKey: set from the vault', out)
        self.assertFalse((self.tmp / "dnsexit-key.sha256").exists())

    def test_a_refusal_of_the_cli_fails_with_its_message(self):
        (self.tmp / "x-ui").write_text("#!/bin/sh\necho 'failed to set vpnName: VPN name must be a DNS name'\nexit 1\n")
        out = flat(self.play(expect_rc=2, vpn_name="vpn.example.com"))
        self.assertIn("x-ui setting refused the domain settings: failed to set vpnName", out)

    # --- verify.yml ----------------------------------------------------------------------------------------
    def edges(self, active="proxy"):
        post("/test/reset", [{"name": "proxy", "host": "203.0.113.20", "role": "edge", "isActive": active == "proxy"},
                             {"name": "proxy2", "host": "203.0.113.21", "role": "edge", "isActive": active == "proxy2"}])

    def records(self, name, addresses):
        with self.dns.lock:
            self.dns.records[name] = addresses

    def test_verify_reports_the_vpn_name_on_the_active_edge(self):
        self.edges()
        self.records("vpn.example.com", ["203.0.113.20"])
        out = flat(self.play("verify_vpn_name", vpn_name="VPN.example.com", dns_zone="example.com"))
        self.assertIn("VPN name: vpn.example.com already points at 203.0.113.20", out)
        self.assertIn("the active edge proxy", out)
        self.assertNotIn("WARNING", out)
        self.assertEqual(self.dns.posts, [], "verify only reads")

    def test_verify_warns_when_the_vpn_name_points_elsewhere(self):
        self.edges(active="proxy2")
        self.records("vpn.example.com", ["203.0.113.20"])
        out = flat(self.play("verify_vpn_name", vpn_name="vpn.example.com"))
        self.assertIn("WARNING: VPN name: vpn.example.com points at 203.0.113.20, not 203.0.113.21", out)
        self.assertIn("the active edge proxy2", out)
        self.assertIn("4 minutes", out)

    def test_verify_warns_when_no_nameserver_answers_or_no_edge_is_active(self):
        self.edges()
        with self.dns.lock:
            self.dns.silent = True
        out = flat(self.play("verify_vpn_name", vpn_name="vpn.example.com", dns_zone="example.com"))
        self.assertIn("WARNING: VPN name: no nameserver answered for vpn.example.com", out)
        self.edges(active="")
        out = flat(self.play("verify_vpn_name", vpn_name="vpn.example.com", dns_zone="example.com"))
        self.assertIn("WARNING: VPN name vpn.example.com: the chain registry has no active edge", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
