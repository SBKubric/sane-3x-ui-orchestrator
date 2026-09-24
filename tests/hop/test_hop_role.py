"""Role hop and the chain part of verify.yml against a mock of the panel chain API; no real host is touched.

    HOP_TEST_PORT=18080 python3 tests/hop/test_hop_role.py      # needs ansible-playbook on PATH

Every test seeds the mock registry, runs tests/hop/site.yml (role hop on local "hosts" bridge = inner 1,
proxy = active edge) and checks the registry, the API calls, what the fake install.sh received and that no
join token reached the ansible output (-vvv).
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
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True  # no __pycache__ in the checkout

import mock_panel  # noqa: E402

PORT = int(os.environ.get("HOP_TEST_PORT", "18080"))
URL = f"http://127.0.0.1:{PORT}"

LEGACY = [{"name": "legacy", "host": "10.0.0.3", "role": "edge", "state": "legacy", "isActive": True}]


class HopRoleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = mock_panel.serve(PORT, str(HERE / "fake_install.sh"))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="hoptest-"))
        for box in ("bridge", "proxy", "real"):
            (self.root / box).mkdir()
        panel = self.root / "real" / "x-ui"
        panel.write_text("#!/bin/sh\necho 1.9.0-chain.4\n")
        panel.chmod(0o755)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    # --- helpers -------------------------------------------------------------------------------------
    def seed(self, hops):
        request = urllib.request.Request(URL + "/test/reset", data=json.dumps(hops).encode(), method="POST")
        urllib.request.urlopen(request).read()

    def state(self):
        return json.load(urllib.request.urlopen(URL + "/test/state"))

    def play(self, *extra, expect_rc=0, playbook=HERE / "site.yml"):
        env = dict(os.environ, HOP_TEST_ROOT=str(self.root), HOP_TEST_PORT=str(PORT),
                   ANSIBLE_CONFIG=str(REPO / "ansible.cfg"), ANSIBLE_ROLES_PATH=str(REPO / "roles"),
                   ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default")
        before = len(self.state()["calls"])
        run = subprocess.run(["ansible-playbook", "-vvv", "-i", str(HERE / "inventory.yml"), str(playbook),
                              *extra], env=env, capture_output=True, text=True, check=False)
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, expect_rc, out[-6000:])
        state = self.state()
        for token in state["issued"]:
            self.assertNotIn(token, out, "a join token reached the ansible output")
        self.assertNotIn("mock-session", out, "the session cookie reached the ansible output")
        self.calls = [c for c in state["calls"][before:] if c["path"] not in ("list", "login")]
        return out

    def verify(self, *extra, expect_rc=0):
        return self.play(*extra, expect_rc=expect_rc, playbook=REPO / "verify.yml")

    def hops(self):
        return {h["name"]: h for h in self.state()["hops"]}

    def box(self, name):
        env = dict(line.split("=", 1) for line in (self.root / name / "install.env").read_text().splitlines())
        return env, (self.root / name / "installs").read_text().split()

    def writes(self):
        return [(c["method"], re.sub(r"/\d+$", "", c["path"]), json.loads(c["body"] or "{}")) for c in self.calls]

    def assert_idempotent(self):
        out = self.play()
        self.assertEqual(self.calls, [], "second run wrote to the registry")
        self.assertRegex(out, r"bridge\s+: ok=\d+\s+changed=0 ")
        self.assertRegex(out, r"proxy\s+: ok=\d+\s+changed=0 ")

    def converge_fresh(self):
        self.seed(LEGACY)
        self.play()

    # --- scenarios -----------------------------------------------------------------------------------
    def test_fresh_chain_replaces_legacy_edge(self):
        self.seed(LEGACY)
        self.play()
        self.assertEqual(self.writes(), [
            ("POST", "add", {"name": "bridge", "host": "10.0.0.2", "role": "inner", "subPort": 2096,
                             "subScheme": "http", "position": 0}),
            ("POST", "add", {"name": "proxy", "host": "10.0.0.3", "role": "edge", "subPort": 2096,
                             "subScheme": "https"}),
            ("POST", "setActive", {}),
            ("POST", "del", {"force": False}),
        ])
        hops = self.hops()
        self.assertEqual(sorted(hops), ["bridge", "proxy"])
        self.assertEqual(hops["bridge"]["state"], "joined")
        self.assertIsNone(hops["bridge"]["nextHopId"])
        self.assertEqual(hops["proxy"]["state"], "joined")
        self.assertTrue(hops["proxy"]["isActive"])
        self.assertEqual(hops["proxy"]["nextHopId"], hops["bridge"]["id"])

        bridge_env, bridge_installs = self.box("bridge")
        self.assertEqual(bridge_installs, ["v1.9.0-chain.4"])
        self.assertEqual((bridge_env["PROXY_NEXT_HOP"], bridge_env["PROXY_NEXT_HOP_SUB_PORT"],
                          bridge_env["PROXY_NEXT_HOP_SCHEME"]), ("10.0.0.1", "2096", "https"))
        self.assertEqual(bridge_env["PROXY_TLS"], "none")
        self.assertEqual(bridge_env["TOKEN_GIVEN"], "yes")
        self.assertEqual(bridge_env["XUI_REPO"], "SBKubric/3ax-ui-proxy")
        proxy_env, _ = self.box("proxy")
        self.assertEqual((proxy_env["PROXY_NEXT_HOP"], proxy_env["PROXY_NEXT_HOP_SCHEME"]), ("10.0.0.2", "http"))
        self.assertEqual(proxy_env["PROXY_TLS"], "letsencrypt-ip")
        self.assertFalse((self.root / "bridge" / "token").exists(), "token file left on the box")

        self.assert_idempotent()

    def test_new_version_rejoins_every_hop(self):
        self.converge_fresh()
        self.play("-e", "hop_test_version=v1.9.1")
        self.assertEqual([(m, p) for m, p, _ in self.writes()], [("POST", "reissueToken"), ("POST", "reissueToken")])
        self.assertEqual(self.box("bridge")[1], ["v1.9.0-chain.4", "v1.9.1"])
        self.assertEqual(self.box("proxy")[1], ["v1.9.0-chain.4", "v1.9.1"])
        hops = self.hops()
        self.assertEqual({h["state"] for h in hops.values()}, {"joined"})
        self.assertTrue(hops["proxy"]["isActive"])

    def test_new_host_updates_then_rejoins(self):
        self.converge_fresh()
        self.play("-e", "hop_test_proxy_host=10.0.0.33")
        self.assertEqual(self.writes(), [("POST", "update", {"host": "10.0.0.33"}), ("POST", "reissueToken", {})])
        self.assertEqual(self.hops()["proxy"]["host"], "10.0.0.33")
        self.assertEqual(len(self.box("bridge")[1]), 1)

    def test_broken_box_is_reinstalled(self):
        self.converge_fresh()
        (self.root / "bridge" / "joined").unlink()
        self.play()
        self.assertEqual([(m, p) for m, p, _ in self.writes()], [("POST", "reissueToken")])
        self.assertEqual(len(self.box("bridge")[1]), 2)
        self.assertEqual(len(self.box("proxy")[1]), 1)

    def test_valid_le_certificate_is_reused_on_reinstall(self):
        self.converge_fresh()
        cert = self.root / "proxy" / "cert"
        cert.mkdir()
        (cert / "privkey.pem").write_text("key")
        (cert / "fullchain.pem").write_text("cert")
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        openssl = fake_bin / "openssl"
        openssl.write_text("#!/bin/sh\necho 'Certificate will not expire'\n"
                           "echo 'X509v3 Subject Alternative Name: '\necho '    IP Address:10.0.0.3'\n")
        openssl.chmod(0o755)
        os.environ["PATH"] = f"{fake_bin}:{os.environ['PATH']}"
        try:
            self.play("-e", "hop_test_version=v1.9.1")
        finally:
            os.environ["PATH"] = os.environ["PATH"].split(":", 1)[1]
        env, _ = self.box("proxy")
        self.assertEqual((env["PROXY_TLS"], env["PROXY_CERT"]), ("manual", f"{cert}/fullchain.pem"))

    def test_extra_hops_are_deleted_edges_first(self):
        self.converge_fresh()
        self.seed([
            {"name": "bridge", "host": "10.0.0.2", "role": "inner", "subScheme": "http", "position": 0},
            {"name": "old", "host": "10.0.0.9", "role": "inner", "position": 1},
            {"name": "proxy", "host": "10.0.0.3", "role": "edge", "isActive": True},
            {"name": "spare", "host": "10.0.0.8", "role": "edge"},
        ])
        self.play()
        self.assertEqual([(m, p) for m, p, _ in self.writes()], [("POST", "del"), ("POST", "del")])
        deleted = [c["path"] for c in self.calls]
        self.assertEqual(len(deleted), 2)
        hops = self.hops()
        self.assertEqual(sorted(hops), ["bridge", "old", "proxy"])
        self.assertEqual(hops["old"]["state"], "draining")  # proxy still hung off it: the panel drains it

    def test_check_mode_only_plans(self):
        self.seed(LEGACY)
        out = self.play("--check")
        self.assertEqual(self.calls, [])
        self.assertIn("hops: bridge=add, proxy=add", out)
        self.assertIn("delete: legacy", out)
        self.assertFalse((self.root / "bridge" / "installs").exists())

    def test_active_inner_is_refused(self):
        self.seed(LEGACY)
        out = self.play("-e", "hop_test_bridge_active=true", expect_rc=2)
        self.assertIn("hop_active only on an edge", out)
        self.assertEqual(self.calls, [])

    def test_role_mismatch_is_refused(self):
        self.seed([{"name": "proxy", "host": "10.0.0.3", "role": "inner"}])
        out = self.play(expect_rc=2)
        self.assertIn("proxy is inner in the registry but edge in the inventory", out)
        self.assertEqual(self.calls, [])

    def test_limit_never_deletes_hops_outside_it(self):
        self.converge_fresh()
        self.play("--limit", "proxy")
        self.assertEqual(self.calls, [])
        self.assertEqual(sorted(self.hops()), ["bridge", "proxy"])

    # --- verify.yml ----------------------------------------------------------------------------------
    def test_verify_passes_on_a_converged_chain(self):
        self.converge_fresh()
        out = self.verify()
        self.assertEqual(self.calls, [], "verify.yml wrote to the registry")
        self.assertIn("chain registry: bridge, proxy joined; active edge proxy", out)
        self.assertIn("hop proxy: name: proxy (edge)", out)

    def test_verify_names_registry_problems(self):
        self.converge_fresh()
        self.seed([{"name": "bridge", "host": "10.0.0.2", "role": "inner", "subScheme": "http"},
                   {"name": "proxy", "host": "10.0.0.3", "role": "edge", "state": "pending"}])
        out = self.verify(expect_rc=2)
        self.assertIn("proxy is pending in the chain registry, not joined", out)
        self.assertIn("the active edge is none, but the inventory marks proxy with hop_active", out)

    def test_verify_names_a_stale_hop(self):
        self.converge_fresh()
        (self.root / "bridge" / "stale").write_text("")
        out = self.verify(expect_rc=2)
        self.assertIn("its chain document is stale", out)
        self.assertIn("the next hop is not reachable (10.0.0.1:2096 (reachable: false))", out)

    def test_verify_names_a_box_on_another_version(self):
        self.converge_fresh()
        out = self.verify("-e", "hop_test_version=v1.9.1", expect_rc=2)
        self.assertIn("is not v1.9.1", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
