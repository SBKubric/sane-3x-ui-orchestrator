"""Role panel's captcha host (orchestrator#80, SBKubric/sane-3x-ui#243) against the mock panel API (tests/hop/mock_panel.py:
tgCaptchaHost in the settings form, panel/setting/botPath, the captcha page under /third-party/) and a fake x-ui that
stores what `x-ui setting -tgCaptchaHost ...` stores; no real host is touched.

    PANEL_TEST_PORT=18088 python3 tests/panel/test_captcha_host.py   # needs ansible-playbook

tests/panel/domain.yml runs one task file of the role (panel_test_tasks):
  captcha_host          `x-ui setting -tgCaptchaHost <tg_captcha_host>` and a panel restart, only on a difference
  verify_captcha_host   verify.yml's check: the panel's value is the inventory's; with panel, the captcha page from the
                        controller at the address panel/setting/botPath hands out
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
sys.dont_write_bytecode = True  # no __pycache__ in the checkout

import mock_panel  # noqa: E402

PORT = int(os.environ.get("PANEL_TEST_PORT", "18088"))
URL = f"http://127.0.0.1:{PORT}"
SECRET = mock_panel.BOT_PATH.strip("/").split("/")[-1]

# Records its arguments (one JSON list a line) and stores the flags in the mock panel, as the real CLI stores them in
# the database.
FAKE_XUI = """#!/usr/bin/env python3
import json, sys, urllib.error, urllib.request
from pathlib import Path
args = sys.argv[1:]
with open(Path(__file__).resolve().parent / "calls", "a") as f:
    f.write(json.dumps(args) + "\\n")
if args[:1] == ["setting"]:
    flags = dict(zip([a.lstrip("-") for a in args[1::2]], args[2::2]))
    req = urllib.request.Request("%s/test/panel/cli", data=json.dumps(flags).encode(), method="POST")
    try:
        urllib.request.urlopen(req).read()
    except (urllib.error.URLError, OSError):
        print("flag provided but not defined: -" + next(iter(flags)))
        sys.exit(2)
    for name in flags:
        print(name + ": " + flags[name])
"""


def post(path, payload):
    request = urllib.request.Request(URL + path, data=json.dumps(payload).encode(), method="POST")
    urllib.request.urlopen(request).read()


def flat(out):
    return re.sub(r"\s+", " ", out)


class CaptchaHostTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = mock_panel.serve(PORT, os.devnull)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="panel-captcha-"))
        (self.tmp / "x-ui").write_text(FAKE_XUI % URL)
        (self.tmp / "x-ui").chmod(0o755)
        post("/test/reset", [])
        post("/test/panel/reset", {})

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

    def restarted(self):
        """Whether the panel restart handler ran since the last look."""
        mark = self.tmp / "restarted"
        ran = mark.exists()
        if ran:
            mark.unlink()
        return ran

    def play(self, tasks="captcha_host", expect_rc=0, check=False, hops=None, **extra):
        # panel_port: the restart handler waits for the panel's port, here the mock's.
        variables = dict({"panel_bin": str(self.tmp / "x-ui"), "panel_port": PORT,
                          "panel_restart_command": ["touch", str(self.tmp / "restarted")]}, **extra, panel_test_tasks=tasks)
        files = []
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write(json.dumps(variables))
        files.append(f.name)
        env = dict(os.environ, PANEL_TEST_PORT=str(PORT), ANSIBLE_CONFIG=str(REPO / "ansible.cfg"),
                   ANSIBLE_ROLES_PATH=str(REPO / "roles"), ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default")
        inventories = ["-i", str(HERE / "inventory.yml")]
        if hops:
            # Hosts of group hops with vars of their own ({inventory name: {hop_name: ...}}), never contacted.
            with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
                f.write(json.dumps({"all": {"children": {"hops": {"hosts": hops}}}}))
            files.append(f.name)
            inventories += ["-i", f.name]
        before = len(self.state()["calls"])
        try:
            run = subprocess.run(["ansible-playbook", "-vvv", *inventories, str(HERE / "domain.yml"),
                                  "-e", f"@{files[0]}"] + (["--check"] if check else []),
                                 env=env, capture_output=True, text=True, check=False)
        finally:
            for name in files:
                os.unlink(name)
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, expect_rc, out[-8000:])
        self.assertNotIn("mock-session", out, "the session cookie reached the ansible output")
        self.assertNotIn(SECRET, out, "the bot's secret reached the ansible output")
        self.calls = [c["path"] for c in self.state()["calls"][before:]]
        return out

    # --- converge -----------------------------------------------------------------------------------------
    def test_a_different_host_is_set_with_a_restart_and_a_second_run_changes_nothing(self):
        out = flat(self.play(tg_captcha_host="panel"))
        self.assertEqual(self.cli(), [["setting", "-tgCaptchaHost", "panel"]])
        self.assertEqual(self.settings()["tgCaptchaHost"], "panel")
        self.assertTrue(self.restarted(), "a new captcha host takes a panel restart")
        self.assertIn('tgCaptchaHost "" -> "panel"', out)

        out = self.play(tg_captcha_host="panel")
        self.assertEqual(self.cli(), [])
        self.assertFalse(self.restarted())
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")
        self.assertIn('tgCaptchaHost "panel" (as wanted)', flat(out))

    def test_an_equal_host_is_left_alone(self):
        post("/test/panel/reset", {"settings": {"tgCaptchaHost": "edge"}})
        out = self.play(tg_captcha_host="edge")
        self.assertEqual(self.cli(), [])
        self.assertFalse(self.restarted())
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")

    def test_a_host_changed_in_the_panel_is_put_back(self):
        post("/test/panel/reset", {"settings": {"tgCaptchaHost": "edge"}})
        self.play(tg_captcha_host="panel")
        self.assertEqual(self.cli(), [["setting", "-tgCaptchaHost", "panel"]])
        self.assertTrue(self.restarted())

    def test_a_hop_of_group_hops_is_taken_by_its_hop_name(self):
        hops = {"proxy": {"hop_name": "edge-a"}, "inner1": {}}
        self.play(tg_captcha_host="edge-a", hops=hops)
        self.assertEqual(self.settings()["tgCaptchaHost"], "edge-a")
        self.cli()
        self.play(tg_captcha_host="inner1", hops=hops)
        self.assertEqual(self.cli(), [["setting", "-tgCaptchaHost", "inner1"]], "no hop_name: the inventory hostname")

    def test_an_unknown_host_fails_before_anything_is_written(self):
        for value in ("proxy", "Panel", "real"):
            with self.subTest(value=value):
                out = flat(self.play(expect_rc=2, tg_captcha_host=value, hops={"proxy": {"hop_name": "edge-a"}}))
                self.assertIn(f"tg_captcha_host '{value}' must be edge (the active edge), panel", out)
                self.assertIn("(edge-a)", out)
                self.assertEqual(self.cli(), [])
        self.assertEqual(self.settings()["tgCaptchaHost"], "")

    def test_a_panel_without_the_setting_fails_and_check_mode_warns(self):
        post("/test/panel/reset", {"without": ["tgCaptchaHost"]})
        out = flat(self.play(expect_rc=2, tg_captcha_host="panel"))
        self.assertIn("the panel has no tgCaptchaHost setting (SBKubric/sane-3x-ui#243): xui_version must be v1.9.1", out)
        self.assertEqual(self.cli(), [])
        self.assertFalse(self.restarted())
        out = flat(self.play(check=True, tg_captcha_host="panel"))
        self.assertIn("WARNING: the panel has no tgCaptchaHost yet (it predates v1.9.1)", out)
        self.assertEqual(self.cli(), [])

    def test_check_mode_shows_the_plan_and_writes_nothing(self):
        out = flat(self.play(check=True, tg_captcha_host="panel"))
        self.assertIn('tgCaptchaHost "" -> "panel" (a panel restart)', out)
        self.assertEqual(self.cli(), [])
        self.assertFalse(self.restarted())
        self.assertEqual(self.settings()["tgCaptchaHost"], "")

    def test_a_refusal_of_the_cli_fails_with_its_message(self):
        (self.tmp / "x-ui").write_text("#!/bin/sh\necho 'failed to set tgCaptchaHost: unknown host'\nexit 1\n")
        out = flat(self.play(expect_rc=2, tg_captcha_host="panel"))
        self.assertIn("x-ui setting refused tgCaptchaHost panel: failed to set tgCaptchaHost: unknown host", out)
        self.assertFalse(self.restarted())

    # --- verify.yml ----------------------------------------------------------------------------------------
    def test_verify_opens_the_captcha_on_the_panels_front(self):
        post("/test/panel/reset", {"settings": {"tgCaptchaHost": "panel"}, "captchaBases": {"panel": URL}})
        out = flat(self.play("verify_captcha_host", tg_captcha_host="panel", panel_tg_captcha_validate_certs=False))
        self.assertIn("the bot's captcha host is panel", out)
        self.assertIn(f"the captcha answers on the front of the panel: {URL}/third-party/<secret>/captcha", out)
        self.assertRegex(out, r"real : ok=\d+ changed=0 ")
        self.assertEqual(self.calls.count("third-party"), 1)

    def test_verify_fails_on_another_host_in_the_panel(self):
        post("/test/panel/reset", {"settings": {"tgCaptchaHost": "edge"}, "captchaBases": {"panel": URL}})
        out = flat(self.play("verify_captcha_host", expect_rc=2, tg_captcha_host="panel"))
        self.assertIn('the panel has tgCaptchaHost "edge", the inventory tg_captcha_host "panel"', out)

    def test_verify_of_another_host_only_compares(self):
        post("/test/panel/reset", {"settings": {"tgCaptchaHost": "edge"}})
        out = flat(self.play("verify_captcha_host", tg_captcha_host="edge"))
        self.assertIn("the bot's captcha host is edge", out)
        self.assertNotIn("setting/botPath", self.calls)
        self.assertNotIn("third-party", self.calls)

    def test_verify_fails_without_a_captcha_address(self):
        post("/test/panel/reset", {"settings": {"tgCaptchaHost": "panel"}})
        out = flat(self.play("verify_captcha_host", expect_rc=2, tg_captcha_host="panel"))
        self.assertIn("the panel hands out no captcha address with tgCaptchaHost panel", out)

    def test_verify_fails_on_the_cover_page(self):
        post("/test/panel/reset", {"settings": {"tgCaptchaHost": "panel"}, "captchaBases": {"panel": URL}, "captchaCover": True})
        out = flat(self.play("verify_captcha_host", expect_rc=2, tg_captcha_host="panel"))
        self.assertIn(f"GET {URL}/third-party/<secret>/captcha from the controller: HTTP 200, not the captcha page", out)

    def test_verify_fails_when_the_captcha_does_not_answer(self):
        # A base whose path the front does not pass on (a bare 404), then one where nothing listens.
        post("/test/panel/reset", {"settings": {"tgCaptchaHost": "panel"}, "captchaBases": {"panel": URL + "/elsewhere"}})
        out = flat(self.play("verify_captcha_host", expect_rc=2, tg_captcha_host="panel"))
        self.assertIn(f"GET {URL}/elsewhere/third-party/<secret>/captcha from the controller: HTTP 404", out)
        post("/test/panel/reset", {"settings": {"tgCaptchaHost": "panel"}, "captchaBases": {"panel": "http://127.0.0.1:9"}})
        out = flat(self.play("verify_captcha_host", expect_rc=2, tg_captcha_host="panel"))
        self.assertIn("GET http://127.0.0.1:9/third-party/<secret>/captcha from the controller got no answer", out)

    def test_verify_fails_on_a_panel_without_the_setting(self):
        post("/test/panel/reset", {"without": ["tgCaptchaHost"]})
        out = flat(self.play("verify_captcha_host", expect_rc=2, tg_captcha_host="panel"))
        self.assertIn("the panel has no tgCaptchaHost (it predates v1.9.1", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
