"""Role panel's inbounds and the targets step of verify.yml against a mock of the panel API; no real host is touched.

    PANEL_TEST_PORT=18081 python3 tests/panel/test_panel_inbounds.py      # needs ansible-playbook on PATH

Every test seeds the mock panel (tests/hop/mock_panel.py), runs tests/panel/site.yml (tasks_from: inbounds, with
panel_inbounds from inventories/stand-full/group_vars/panel.yml unless a test passes its own) and checks the
inbounds, the AWG server, the API writes, idempotency and that no private key or session cookie reached the
ansible output (-vvv).
"""

import json
import os
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

PORT = int(os.environ.get("PANEL_TEST_PORT", "18081"))
URL = f"http://127.0.0.1:{PORT}"
STAND = REPO / "inventories" / "stand-full" / "group_vars" / "panel.yml"
STAND_INBOUNDS = yaml.safe_load(STAND.read_text())["panel_inbounds"]


def post(path, payload):
    request = urllib.request.Request(URL + path, data=json.dumps(payload).encode(), method="POST")
    urllib.request.urlopen(request).read()


def target(kind, inbound_id, path, state="UP", client="monclient"):
    return {"monClientId": client, "monClientName": client, "region": "stand", "clientState": "ONLINE",
            "inboundKind": kind, "inboundId": inbound_id, "path": path, "state": state, "since": 0, "reason": "",
            "uptime24": None, "coverage24": 0, "latAvg24": None, "retired": False}


def monitoring(inbounds):
    return {"now": 0, "lastContact": 0, "stale": False, "staleSince": 0, "override": {"enabled": True, "host": "10.0.0.3"},
            "monClients": [], "inbounds": inbounds}


class PanelInboundsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = mock_panel.serve(PORT, os.devnull)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="paneltest-"))
        post("/test/reset", [])
        post("/test/panel/reset", {})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- helpers -------------------------------------------------------------------------------------
    def state(self):
        return json.load(urllib.request.urlopen(URL + "/test/state"))

    def panel(self):
        return self.state()["panel"]

    def inbounds(self):
        return {i["remark"]: i for i in self.panel()["inbounds"]}

    def play(self, *extra, inbounds=None, expect_rc=0, playbook=HERE / "site.yml"):
        vars_file = self.tmp / "vars.json"
        vars_file.write_text(json.dumps({"panel_inbounds": STAND_INBOUNDS if inbounds is None else inbounds}))
        env = dict(os.environ, PANEL_TEST_PORT=str(PORT), ANSIBLE_CONFIG=str(REPO / "ansible.cfg"),
                   ANSIBLE_ROLES_PATH=str(REPO / "roles"), ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default")
        before = len(self.state()["calls"])
        run = subprocess.run(["ansible-playbook", "-vvv", "-i", str(HERE / "inventory.yml"), str(playbook),
                              "-e", f"@{vars_file}", *extra], env=env, capture_output=True, text=True, check=False)
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, expect_rc, out[-6000:])
        panel = self.panel()
        secrets = [pair["privateKey"] for pair in panel["x25519"]] + [panel["awg"]["privateKey"]]
        for secret in secrets:
            self.assertNotIn(secret, out, "a private key reached the ansible output")
        self.assertNotIn("mock-session", out, "the session cookie reached the ansible output")
        calls = self.state()["calls"][before:]
        self.writes = [(c["method"], c["path"], json.loads(c["body"] or "{}")) for c in calls
                       if c["method"] == "POST" and c["path"] != "login"]
        self.reads = [c["path"] for c in calls if c["method"] == "GET"]
        return out

    def assert_idempotent(self, **kwargs):
        out = self.play(**kwargs)
        self.assertEqual(self.writes, [], "second run wrote to the panel")
        self.assertNotIn("server/getNewX25519Cert", self.reads, "second run asked for new Reality keys")
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")

    def converge_fresh(self):
        self.play()
        post("/test/panel/ensure", {})  # mon-server's probe/ensure adds the probe client

    # --- scenarios -----------------------------------------------------------------------------------
    def test_fresh_panel_gets_reality_and_awg(self):
        post("/test/reset", [{"name": "bridge", "host": "10.0.0.2", "role": "inner"}])
        revision = self.state()["revision"]
        self.play()
        self.assertEqual([(m, p) for m, p, _ in self.writes],
                         [("POST", "awg/server"), ("POST", "inbounds/add"), ("POST", "inbounds/add")])
        panel = self.panel()
        self.assertEqual(len(panel["x25519"]), 1, "Reality keys come from the panel, once")
        keys = panel["x25519"][0]

        vless = self.inbounds()["vless-reality"]
        self.assertEqual((vless["protocol"], vless["port"], vless["enable"], vless["tag"]), ("vless", 443, True, "inbound-443"))
        self.assertEqual(json.loads(vless["settings"]), {"clients": [], "decryption": "none", "fallbacks": []})
        stream = json.loads(vless["streamSettings"])
        reality = stream["realitySettings"]
        self.assertEqual((stream["network"], stream["security"]), ("tcp", "reality"))
        self.assertEqual(reality["privateKey"], keys["privateKey"])
        self.assertEqual(reality["settings"]["publicKey"], keys["publicKey"])
        self.assertEqual(reality["settings"]["fingerprint"], "chrome")
        self.assertEqual(reality["serverNames"], ["www.microsoft.com"])
        self.assertEqual(len(reality["shortIds"]), 1)
        self.assertRegex(reality["shortIds"][0], r"^[0-9a-f]{16}$")
        self.assertEqual(json.loads(vless["sniffing"])["destOverride"], ["http", "tls", "quic"])

        awg = self.inbounds()["awg"]
        self.assertEqual((awg["protocol"], awg["port"], awg["enable"], awg["tag"]), ("amneziawg", 51820, True, "inbound-amneziawg"))
        self.assertEqual(json.loads(awg["settings"]), {"clients": []})
        self.assertTrue(panel["awg"]["enable"])
        self.assertEqual(panel["awg"]["listenPort"], 51820)
        self.assertEqual(panel["ports"], [443, 51820], "the chain relays both inbounds")
        self.assertGreater(self.state()["revision"], revision, "the chain revision moved with the ports")

        self.assert_idempotent()

    def test_probe_client_and_reserialized_settings_stay_idempotent(self):
        self.converge_fresh()
        vless = self.inbounds()["vless-reality"]
        self.assertIn("probe-", vless["settings"])
        self.assertIn("\n  ", vless["settings"], "the mock re-serializes like the panel")
        self.assert_idempotent()
        self.assertEqual(self.inbounds()["vless-reality"]["settings"], vless["settings"])

    def test_changed_field_updates_and_keeps_keys_and_clients(self):
        self.converge_fresh()
        before = self.inbounds()["vless-reality"]
        changed = json.loads(json.dumps(STAND_INBOUNDS))
        changed[0]["streamSettings"]["realitySettings"]["serverNames"] = ["www.microsoft.com", "microsoft.com"]
        self.play(inbounds=changed)
        self.assertEqual([(m, p) for m, p, _ in self.writes], [("POST", f"inbounds/update/{before['id']}")])
        body = self.writes[0][2]
        self.assertEqual(body["settings"], before["settings"], "untouched settings go back as the panel has them")
        after = self.inbounds()["vless-reality"]
        old_reality = json.loads(before["streamSettings"])["realitySettings"]
        reality = json.loads(after["streamSettings"])["realitySettings"]
        self.assertEqual(reality["serverNames"], ["www.microsoft.com", "microsoft.com"])
        self.assertEqual((reality["privateKey"], reality["settings"]["publicKey"], reality["shortIds"]),
                         (old_reality["privateKey"], old_reality["settings"]["publicKey"], old_reality["shortIds"]),
                         "converge must not re-key")
        self.assertEqual(json.loads(after["settings"])["clients"], json.loads(before["settings"])["clients"],
                         "the probe client survives the update")
        self.assertEqual(len(self.panel()["x25519"]), 1)
        self.assert_idempotent(inbounds=changed)

    def test_port_and_enable_are_converged(self):
        self.converge_fresh()
        changed = json.loads(json.dumps(STAND_INBOUNDS))
        changed[0]["port"] = 8443
        changed[1]["enable"] = False
        self.play(inbounds=changed)
        ids = {r: i["id"] for r, i in self.inbounds().items()}
        self.assertEqual([(m, p) for m, p, _ in self.writes],
                         [("POST", "awg/server"), ("POST", f"inbounds/update/{ids['vless-reality']}"),
                          ("POST", f"inbounds/setEnable/{ids['awg']}")])
        inbounds = self.inbounds()
        self.assertEqual((inbounds["vless-reality"]["port"], inbounds["vless-reality"]["tag"]), (8443, "inbound-8443"))
        self.assertFalse(inbounds["awg"]["enable"])
        self.assertFalse(self.panel()["awg"]["enable"])
        self.assertEqual(self.panel()["ports"], [8443])
        self.assert_idempotent(inbounds=changed)

    def test_awg_server_switched_off_by_hand_is_switched_on(self):
        self.converge_fresh()
        post("/test/panel/reset", {"inbounds": [{k: v for k, v in i.items() if k != "id"} for i in self.panel()["inbounds"]],
                                   "awg": dict(self.panel()["awg"], enable=False)})
        self.play()
        self.assertEqual([(m, p) for m, p, _ in self.writes], [("POST", "awg/server")])
        self.assertEqual(self.writes[0][2]["privateKey"], self.panel()["awg"]["privateKey"], "the save keeps the keys")
        self.assertTrue(self.panel()["awg"]["enable"])

    def test_awg_port_defaults_to_the_panels(self):
        self.play(inbounds=[{"remark": "awg", "protocol": "amneziawg"}])
        self.assertEqual([(m, p) for m, p, _ in self.writes], [("POST", "awg/server"), ("POST", "inbounds/add")])
        self.assertEqual(self.inbounds()["awg"]["port"], 38810)
        self.assertEqual(self.panel()["awg"]["listenPort"], 38810)
        self.assert_idempotent(inbounds=[{"remark": "awg", "protocol": "amneziawg"}])

    def test_unlisted_inbounds_are_left_alone(self):
        post("/test/panel/reset", {"inbounds": [{"remark": "hand-made", "protocol": "trojan", "port": 8080,
                                                 "settings": '{"clients": [{"password": "x", "email": "u"}]}'}]})
        self.play()
        self.assertNotIn("hand-made", [b.get("remark") for _, _, b in self.writes])
        self.assertTrue(all("update" not in p for _, p, _ in self.writes))
        self.assertEqual(sorted(self.inbounds()), ["awg", "hand-made", "vless-reality"])

    def test_check_mode_only_plans(self):
        out = self.play("--check")
        self.assertEqual(self.writes, [])
        self.assertIn("inbound vless-reality (vless): add", out)
        self.assertIn("inbound awg (amneziawg): add", out)
        self.assertIn("AmneziaWG server: save", out)
        self.assertEqual(self.panel()["inbounds"], [])

    def test_empty_list_touches_nothing(self):
        self.play(inbounds=[])
        self.assertEqual(self.writes, [])
        self.assertEqual(self.reads, [])

    def test_malformed_entries_are_refused(self):
        bad = [{"remark": "a", "protocol": "vless", "port": 443, "settings": {"clients": []}},
               {"remark": "b", "protocol": "vless"},
               {"remark": "c", "protocol": "amneziawg", "settings": {}},
               {"remark": "d", "protocol": "vless", "port": 444, "sreamSettings": {}},
               {"remark": "d", "protocol": "mtproto", "port": 445}]
        out = self.play(inbounds=bad, expect_rc=2)
        for text in ("a: settings.clients is not managed", "b: port is required", "c: unknown or unsupported fields settings",
                     "d: unknown or unsupported fields sreamSettings", "protocol mtproto is not managed",
                     "remarks must be unique"):
            self.assertIn(text, out)
        self.assertEqual(self.writes, [])

    def test_protocol_change_is_refused(self):
        post("/test/panel/reset", {"inbounds": [{"remark": "vless-reality", "protocol": "trojan", "port": 443,
                                                 "settings": '{"clients": []}'}]})
        out = self.play(expect_rc=2)
        self.assertIn("vless-reality is trojan in the panel but vless in panel_inbounds", out)
        self.assertEqual(self.writes, [])

    # --- verify.yml: monitoring targets --------------------------------------------------------------
    def seed_targets(self, awg_targets):
        vless = {"kind": "xray", "inboundId": 1, "tag": "inbound-443", "remark": "vless-reality", "protocol": "vless",
                 "port": 443, "enable": True, "worst": "UP",
                 "targets": [target("xray", 1, "direct"), target("xray", 1, "proxy")]}
        awg = {"kind": "awg", "inboundId": 0, "tag": "inbound-amneziawg", "remark": "awg", "protocol": "amneziawg",
               "port": 51820, "enable": True, "worst": "UP", "targets": awg_targets}
        post("/test/panel/targets", monitoring([vless, awg]))

    def test_verify_targets_passes_with_every_inbound_up_on_both_paths(self):
        self.seed_targets([target("awg", 0, "direct"), target("awg", 0, "proxy")])
        out = self.play(playbook=HERE / "verify_targets.yml")
        self.assertRegex(out, r"monitoring: 4 targets UP on\s+vless-reality, awg")

    def test_verify_targets_names_an_inbound_without_targets(self):
        self.seed_targets([])
        out = self.play(playbook=HERE / "verify_targets.yml", expect_rc=2)
        self.assertIn("awg (awg 0, port 51820) has no target for monclient/direct, monclient/proxy", out)

    def test_verify_targets_names_a_missing_path_and_a_down_target(self):
        self.seed_targets([target("awg", 0, "direct", state="DOWN")])
        out = self.play(playbook=HERE / "verify_targets.yml", expect_rc=2)
        self.assertIn("monclient/direct -> awg (awg 0, port 51820): DOWN", out)
        self.assertIn("awg (awg 0, port 51820) has no target for monclient/proxy", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
