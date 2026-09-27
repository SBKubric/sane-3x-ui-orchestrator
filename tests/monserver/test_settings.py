"""Role monserver's Settings step (roles/monserver/tasks/settings.yml) against a mock of mon-server's admin API.

    MON_TEST_PORT=18083 python3 tests/monserver/test_settings.py      # needs ansible-playbook on PATH

Behind the panel's «only 443» front (orchestrator#21) role panel leaves panel_url = https://<ip>/<base>/ on 443 and no
panelCa: mon-server must be switched over from the panel's own port and its self-signed certificate, keeping the token.
"""

import json
import os
import subprocess
import sys
import unittest
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True

import mock_monserver  # noqa: E402

PORT = int(os.environ.get("MON_TEST_PORT", "18083"))
URL = f"http://127.0.0.1:{PORT}"
PEM = "-----BEGIN CERTIFICATE-----\nMIIBself-signed\n-----END CERTIFICATE-----"
OLD = {"panelUrl": "https://10.0.0.1:2053/base/", "monToken": "mon-token-1234", "panelCa": PEM, "realHost": "10.0.0.1"}


def post(path, payload):
    urllib.request.urlopen(urllib.request.Request(URL + path, data=json.dumps(payload).encode(), method="POST")).read()


class SettingsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = mock_monserver.serve(PORT)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def state(self):
        return json.load(urllib.request.urlopen(URL + "/test/state"))

    def play(self, panel_url, panel_ca, expect_rc=0):
        env = dict(os.environ, MON_TEST_PORT=str(PORT), ANSIBLE_CONFIG=str(REPO / "ansible.cfg"),
                   ANSIBLE_ROLES_PATH=str(REPO / "roles"), ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default")
        before = len(self.state()["calls"])
        run = subprocess.run(["ansible-playbook", "-vvv", "-i", str(HERE / "settings_inventory.yml"),
                              str(HERE / "settings.yml"), "-e",
                              json.dumps({"mon_test_panel_url": panel_url, "mon_test_panel_ca": panel_ca})],
                             env=env, capture_output=True, text=True, check=False)
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, expect_rc, out[-6000:])
        self.assertNotIn("mon-token-1234", out, "the monitoring token reached the ansible output")
        self.assertNotIn("mock-mon-session", out, "the session cookie reached the ansible output")
        calls = self.state()["calls"][before:]
        self.saves = [json.loads(c["body"]) for c in calls if c["path"] == "/admin/api/settings" and c["method"] == "POST"]
        self.checks = [json.loads(c["body"]) for c in calls if c["path"] == "/admin/api/settings/check"]
        return out

    def test_panel_behind_the_front_is_reached_on_443_without_panel_ca(self):
        post("/test/reset", OLD)
        self.play("https://10.0.0.1/base/", "")
        self.assertEqual(len(self.saves), 1)
        settings = self.state()["settings"]
        self.assertEqual((settings["panelUrl"], settings["panelCa"], settings["monToken"]),
                         ("https://10.0.0.1/base/", "", "mon-token-1234"))
        self.assertEqual(settings["realHost"], "10.0.0.1", "the rest of the form stays")
        self.assertEqual((self.checks[0]["panelUrl"], self.checks[0]["panelCa"]), ("https://10.0.0.1/base/", ""))

        self.play("https://10.0.0.1/base/", "")
        self.assertEqual(self.saves, [], "a second run saves nothing")

    def test_front_off_keeps_the_panels_own_port_and_certificate(self):
        post("/test/reset", {})
        self.play("https://10.0.0.1:2053/base/", PEM)
        settings = self.state()["settings"]
        self.assertEqual((settings["panelUrl"], settings["panelCa"]), ("https://10.0.0.1:2053/base/", PEM))


if __name__ == "__main__":
    unittest.main(verbosity=2)
