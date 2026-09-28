"""Role panel's geosite:ru-inside (orchestrator#28) against the mock panel API, a local source of the list and a box
laid out under a temp dir; no real host is touched.

    PANEL_TEST_PORT=18083 RU_INSIDE_SOURCE_PORT=18084 python3 tests/panel/test_ru_inside.py   # needs ansible-playbook

tests/panel/ru_inside.yml runs one task file of the role (panel_test_tasks):
  ru_inside         the list on the box (download on the box, sha256 against the sum file, the controller's copy when
                    the box cannot fetch it), the link into xray's asset folder, the timer and the routing rule in the
                    panel's Xray template, xray restarted through the panel API
  verify_ru_inside  verify.yml's check: the rule, the file and its age
The refresh script (roles/panel/files/ru_inside.py) is also run directly, the way the timer and the panel's
ExecStartPre run it.
"""

import hashlib
import json
import os
import re
import shutil
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
SCRIPT = REPO / "roles" / "panel" / "files" / "ru_inside.py"
sys.path.insert(0, str(HERE.parent / "hop"))
sys.dont_write_bytecode = True  # no __pycache__ in the checkout

import mock_panel  # noqa: E402

PORT = int(os.environ.get("PANEL_TEST_PORT", "18083"))
URL = f"http://127.0.0.1:{PORT}"
SOURCE_PORT = int(os.environ.get("RU_INSIDE_SOURCE_PORT", "18084"))
SOURCE = f"http://127.0.0.1:{SOURCE_PORT}"
RULE = {"type": "field", "ruleTag": "3ax-ru-inside", "domain": ["ext:ru-inside.dat:ru-inside"], "outboundTag": "blocked"}
API_RULE = {"type": "field", "inboundTag": ["api"], "outboundTag": "api"}


def geosite(marker, size=4096):
    """A stand-in for golukon's geosite.dat: the category name in the protobuf, padded to a plausible size."""
    body = b"\n\tRU-INSIDE\x12\x10\x08\x02\x12\x0c" + marker.encode() + b".example.ru"
    return body + b"\x00" * max(0, size - len(body))


def sumfile(data):
    return f"{hashlib.sha256(data).hexdigest()}  geosite.dat\n"


class Source(BaseHTTPRequestHandler):
    """raw.githubusercontent.com for the test: /geosite.dat and /geosite.dat.sha256sum from `files`; a User-Agent
    starting with one of `deny` gets a connection reset (a box without GitHub), `down` answers 404 to everyone."""

    files = {}
    deny = []
    down = False
    hits = []

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        agent = self.headers.get("User-Agent") or ""
        Source.hits.append((self.path, agent))
        if any(agent.startswith(prefix) for prefix in Source.deny):
            self.connection.close()
            return
        data = None if Source.down else Source.files.get(self.path)
        if data is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def post(path, payload):
    request = urllib.request.Request(URL + path, data=json.dumps(payload).encode(), method="POST")
    urllib.request.urlopen(request).read()


def flat(out):
    return re.sub(r"\s+", " ", out)


class RuInsideTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = mock_panel.serve(PORT, os.devnull)
        cls.source = ThreadingHTTPServer(("127.0.0.1", SOURCE_PORT), Source)
        threading.Thread(target=cls.source.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for server in (cls.server, cls.source):
            server.shutdown()
            server.server_close()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ruinside-"))
        self.box = self.tmp / "box"
        self.bin = self.box / "usr/local/x-ui/bin"
        self.bin.mkdir(parents=True)
        self.store = self.box / "var/lib/3ax-ru-inside/ru-inside.dat"
        self.units = self.box / "etc/systemd/system"
        self.restarted = self.tmp / "xray-reloaded"
        post("/test/reset", [])
        post("/test/panel/reset", {"xrayAssetDir": str(self.bin)})
        self.serve(geosite("a"))
        Source.deny, Source.down, Source.hits = [], False, []

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- helpers -------------------------------------------------------------------------------------
    def serve(self, data, checksum=None):
        Source.files = {"/geosite.dat": data, "/geosite.dat.sha256sum": (checksum or sumfile(data)).encode()}

    def state(self):
        return json.load(urllib.request.urlopen(URL + "/test/state"))

    def panel(self):
        return self.state()["panel"]

    def rules(self):
        return self.panel()["xrayTemplate"]["routing"]["rules"]

    def box_vars(self, **extra):
        return dict({
            "panel_ru_inside_url": f"{SOURCE}/geosite.dat",
            "panel_ru_inside_sha256_url": f"{SOURCE}/geosite.dat.sha256sum",
            "panel_ru_inside_asset_dir": str(self.bin),
            "panel_ru_inside_store_dir": str(self.store.parent),
            "panel_ru_inside_script": str(self.box / "usr/local/sbin/3ax-ru-inside"),
            "panel_ru_inside_config": str(self.box / "etc/3ax-ru-inside.json"),
            "panel_ru_inside_systemd_dir": str(self.units),
            "panel_ru_inside_systemd": False,
            "panel_ru_inside_restart_command": ["touch", str(self.restarted)],
            "panel_ru_inside_timeout": 5,
        }, **extra)

    def play(self, tasks="ru_inside", expect_rc=0, **extra):
        vars_file = self.tmp / "vars.json"
        vars_file.write_text(json.dumps(dict(self.box_vars(**extra), panel_test_tasks=tasks)))
        env = dict(os.environ, PANEL_TEST_PORT=str(PORT), ANSIBLE_CONFIG=str(REPO / "ansible.cfg"),
                   ANSIBLE_ROLES_PATH=str(REPO / "roles"), ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default")
        before = len(self.state()["calls"])
        run = subprocess.run(["ansible-playbook", "-vvv", "-i", str(HERE / "inventory.yml"), str(HERE / "ru_inside.yml"),
                              "-e", f"@{vars_file}"], env=env, capture_output=True, text=True, check=False)
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, expect_rc, out[-8000:])
        self.assertNotIn("mock-session", out, "the session cookie reached the ansible output")
        calls = self.state()["calls"][before:]
        self.writes = [(c["method"], c["path"]) for c in calls if c["method"] == "POST" and c["path"] not in ("login", "xray/")]
        return out

    def script(self, *args, expect_rc=0):
        run = subprocess.run([sys.executable, str(SCRIPT), "--config", str(self.box / "etc/3ax-ru-inside.json"), *args],
                             capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, expect_rc, run.stdout + run.stderr)
        return json.loads(run.stdout), run.stderr

    def assert_file(self, data):
        self.assertEqual(self.store.read_bytes(), data)
        link = self.bin / "ru-inside.dat"
        self.assertTrue(link.is_symlink(), "xray's asset folder links to the kept copy")
        self.assertEqual(os.readlink(link), str(self.store))

    def assert_rule_once(self, rules=None):
        rules = self.rules() if rules is None else rules
        self.assertEqual(rules[:2], [API_RULE, RULE], "the rule comes right after the panel's api rule")
        self.assertEqual(sum(1 for r in rules if "ext:ru-inside.dat:ru-inside" in r.get("domain", [])), 1)

    # --- converge -----------------------------------------------------------------------------------------
    def test_fresh_box_gets_the_file_the_timer_and_the_rule(self):
        out = self.play()
        self.assert_file(geosite("a"))
        self.assert_rule_once()
        self.assertEqual(self.rules()[2:], mock_panel.DEFAULT_XRAY_TEMPLATE["routing"]["rules"][1:])
        self.assertEqual(self.writes, [("POST", "xray/update"), ("POST", "server/restartXrayService")])
        self.assertEqual(self.panel()["outboundTestUrl"], "https://www.google.com/generate_204")
        self.assertFalse(self.restarted.exists(), "the play restarts xray through the panel, once")
        self.assertIn("ru-inside: updated", flat(out))

        timer = (self.units / "3ax-ru-inside.timer").read_text()
        self.assertIn("OnCalendar=*-*-* 05:00:00 UTC\n", timer)
        self.assertIn("RandomizedDelaySec=1h\n", timer)
        self.assertIn("Persistent=true\n", timer)
        service = (self.units / "3ax-ru-inside.service").read_text()
        self.assertIn(f"ExecStart={self.box}/usr/local/sbin/3ax-ru-inside --config {self.box}/etc/3ax-ru-inside.json refresh\n",
                      service)
        self.assertIn("Type=oneshot\n", service)
        dropin = (self.units / "x-ui.service.d" / "3ax-ru-inside.conf").read_text()
        self.assertIn(f"ExecStartPre=-{self.box}/usr/local/sbin/3ax-ru-inside --config {self.box}/etc/3ax-ru-inside.json"
                      " ensure\n", dropin)
        config = json.loads((self.box / "etc/3ax-ru-inside.json").read_text())
        self.assertEqual(config["url"], f"{SOURCE}/geosite.dat")
        self.assertEqual(config["restart"], ["touch", str(self.restarted)])

        # Second run: same file, rule in place, units as they are.
        out = self.play()
        self.assertEqual(self.writes, [])
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")
        self.assertIn("ru-inside: current", flat(out))

    def test_other_rules_stay_and_a_rule_the_ui_rewrote_is_not_doubled(self):
        warp = {"type": "field", "outboundTag": "warp", "domain": ["geosite:openai"]}
        # The panel's routing editor drops fields it does not know: our rule without its ruleTag, at the end.
        stripped = {"type": "field", "domain": ["ext:ru-inside.dat:ru-inside"], "outboundTag": "blocked"}
        template = json.loads(json.dumps(mock_panel.DEFAULT_XRAY_TEMPLATE))
        template["routing"]["rules"] += [warp, stripped]
        template["outbounds"].append({"tag": "warp", "protocol": "wireguard", "settings": {}})
        post("/test/panel/xray", {"template": template, "outboundTestUrl": "https://example.test/204"})
        self.play()
        rules = self.rules()
        self.assert_rule_once(rules)
        self.assertEqual(rules[2:], template["routing"]["rules"][1:-1])
        self.assertEqual(self.panel()["outboundTestUrl"], "https://example.test/204", "the rest of the form stays")
        self.assertEqual(self.panel()["xrayTemplate"]["outbounds"], template["outbounds"])
        self.play()
        self.assertEqual(self.writes, [])

    def test_api_rule_elsewhere_ends_first_and_the_next_run_is_quiet(self):
        template = json.loads(json.dumps(mock_panel.DEFAULT_XRAY_TEMPLATE))
        rules = template["routing"]["rules"]
        rules.append(rules.pop(0))
        post("/test/panel/xray", {"template": template})
        self.play()
        self.assert_rule_once()
        self.play()
        self.assertEqual(self.writes, [])

    def test_missing_blackhole_outbound_is_added(self):
        template = json.loads(json.dumps(mock_panel.DEFAULT_XRAY_TEMPLATE))
        template["outbounds"] = template["outbounds"][:1]
        post("/test/panel/xray", {"template": template})
        self.play()
        self.assertIn({"tag": "blocked", "protocol": "blackhole", "settings": {}}, self.panel()["xrayTemplate"]["outbounds"])
        self.assert_rule_once()

    def test_blocked_tag_on_another_protocol_is_refused(self):
        template = json.loads(json.dumps(mock_panel.DEFAULT_XRAY_TEMPLATE))
        template["outbounds"][1] = {"tag": "blocked", "protocol": "freedom", "settings": {}}
        post("/test/panel/xray", {"template": template})
        out = self.play(expect_rc=2)
        self.assertIn("outbound blocked is freedom, not blackhole", flat(out))
        self.assertEqual(self.panel()["xrayTemplate"], template)

    def test_new_list_restarts_xray(self):
        self.play()
        self.serve(geosite("b"))
        out = self.play()
        self.assert_file(geosite("b"))
        self.assertEqual(self.writes, [("POST", "server/restartXrayService")], "same rule, new file: a restart only")
        self.assertIn("ru-inside: updated", flat(out))

    def test_box_without_github_gets_the_file_from_the_controller(self):
        Source.deny = ["3ax-ru-inside"]  # the box's script; the controller's get_url says ansible-httpget
        out = flat(self.play())
        self.assertIn("the panel host could not fetch the list", out)
        self.assertIn("ru-inside: updated", out)
        self.assert_file(geosite("a"))
        self.assert_rule_once()
        self.assertTrue(any(agent.startswith("ansible-httpget") for _, agent in Source.hits))
        self.assertEqual(list(self.store.parent.iterdir()), [self.store], "the controller's copy is not left behind")

        out = self.play()
        self.assertEqual(self.writes, [])
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")

    def test_bad_checksum_keeps_the_old_file_and_warns(self):
        self.play()
        self.serve(geosite("b"), checksum="0" * 64 + "  geosite.dat\n")
        out = flat(self.play())
        self.assert_file(geosite("a"))
        self.assertIn("WARNING: geosite ru-inside: keeping the list", out)
        self.assertIn("sha256 mismatch", out)
        self.assertEqual(self.writes, [], "old file, same rule: nothing to restart")
        self.assert_rule_once()

    def test_list_without_the_category_is_not_installed(self):
        self.play()
        data = geosite("b").replace(b"RU-INSIDE", b"RU-BLOCKED")
        self.serve(data)
        out = flat(self.play())
        self.assert_file(geosite("a"))
        self.assertIn("no category ru-inside", out)

    def test_no_list_anywhere_leaves_the_template_alone(self):
        Source.down = True
        before = self.panel()["xrayTemplate"]
        out = flat(self.play())
        self.assertIn("WARNING: geosite ru-inside: no list on the panel host", out)
        self.assertEqual(self.writes, [])
        self.assertEqual(self.panel()["xrayTemplate"], before, "no rule without its file: xray would not start")
        self.assertFalse(self.store.exists())

    def test_rule_without_its_file_is_taken_out(self):
        template = json.loads(json.dumps(mock_panel.DEFAULT_XRAY_TEMPLATE))
        template["routing"]["rules"].insert(1, RULE)
        post("/test/panel/xray", {"template": template})
        Source.down = True
        self.play()
        self.assertNotIn(RULE, self.rules())
        self.assertEqual(self.writes, [("POST", "xray/update"), ("POST", "server/restartXrayService")])

    def test_failed_restart_puts_the_old_template_back(self):
        before = self.panel()["xrayTemplate"]
        post("/test/panel/xray", {"restartFails": True})
        out = flat(self.play(expect_rc=2))
        self.assertIn("xray did not restart with the ru-inside rule; the previous template is back", out)
        self.assertEqual(self.panel()["xrayTemplate"], before)

    def test_disabled_takes_the_rule_out(self):
        self.play()
        self.play(panel_ru_inside_enabled=False)
        self.assertNotIn(RULE, self.rules())
        self.assertIn({"tag": "blocked", "protocol": "blackhole", "settings": {}}, self.panel()["xrayTemplate"]["outbounds"])
        self.assertEqual(self.writes, [("POST", "xray/update"), ("POST", "server/restartXrayService")])
        self.play(panel_ru_inside_enabled=False)
        self.assertEqual(self.writes, [])

    # --- the script, as the timer and x-ui's ExecStartPre run it ---------------------------------------------
    def test_timer_refresh_restarts_xray_only_on_a_new_list(self):
        self.play()
        report, _ = self.script("refresh")
        self.assertEqual(report["result"], "current")
        self.assertFalse(self.restarted.exists())

        self.serve(geosite("b"))
        report, log = self.script("refresh")
        self.assertEqual((report["result"], report["restarted"]), ("updated", True))
        self.assertIn("updated", log)
        self.assertTrue(self.restarted.exists())
        self.assert_file(geosite("b"))

        self.restarted.unlink()
        self.serve(geosite("c"), checksum="f" * 64 + "  geosite.dat\n")
        report, log = self.script("refresh", expect_rc=3)
        self.assertEqual(report["result"], "kept")
        self.assertIn(f"keeping {self.store}: sha256 mismatch", log)
        self.assertFalse(self.restarted.exists())
        self.assert_file(geosite("b"))

        Source.deny = ["3ax-ru-inside"]
        report, log = self.script("refresh", expect_rc=3)
        self.assertEqual(report["result"], "kept")
        self.assertIn(f"keeping {self.store}:", log)

    def test_current_list_marks_the_check_time(self):
        self.play()
        old = time.time() - 10 * 86400
        os.utime(self.store, (old, old))
        self.script("refresh")
        self.assertGreater(self.store.stat().st_mtime, time.time() - 60, "the file's age is the last good check")

    def test_link_comes_back_after_the_panel_reinstalls(self):
        self.play()
        shutil.rmtree(self.bin)  # install.sh: rm -rf /usr/local/x-ui/, then the release tarball
        self.bin.mkdir()
        report, _ = self.script("ensure")
        self.assertTrue(report["linked"])
        self.assert_file(geosite("a"))
        self.assertFalse(self.restarted.exists(), "ExecStartPre runs before xray: no restart")

    # --- verify.yml ------------------------------------------------------------------------------------------
    def test_verify_passes_on_a_converged_box(self):
        self.play()
        out = flat(self.play("verify_ru_inside"))
        self.assertIn("geosite ru-inside: rule in the Xray template, list", out)
        self.assertNotIn("WARNING", out)
        self.assertEqual(self.writes, [])

    def test_verify_warns_about_an_old_list(self):
        self.play()
        old = time.time() - 5 * 86400
        os.utime(self.store, (old, old))
        out = flat(self.play("verify_ru_inside"))
        self.assertIn("WARNING: geosite ru-inside: the list was last checked 5 days ago", out)

    def test_verify_fails_without_the_rule_or_the_file(self):
        self.play()
        post("/test/panel/xray", {"template": mock_panel.DEFAULT_XRAY_TEMPLATE})
        out = flat(self.play("verify_ru_inside", expect_rc=2))
        self.assertIn("no ru-inside rule in the panel's Xray template", out)

        self.play()
        (self.bin / "ru-inside.dat").unlink()
        out = flat(self.play("verify_ru_inside", expect_rc=2))
        self.assertIn(f"{self.bin}/ru-inside.dat is missing", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
