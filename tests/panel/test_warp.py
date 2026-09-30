"""Role panel's WARP (orchestrator#41) against the mock panel API (tests/hop/mock_panel.py: the Xray template, the
xray restart and panel/xray/warp/<action> with a stand-in of api.cloudflareclient.com); no real host is touched.

    PANEL_TEST_PORT=18085 python3 tests/panel/test_warp.py   # needs ansible-playbook

tests/panel/warp.yml runs one task file of the role (panel_test_tasks):
  warp         the registration (reused when the panel has one), the WireGuard outbound `warp` and the last routing
               rule «tcp,udp -> warp» in the panel's Xray template, xray restarted through the panel API
  verify_warp  verify.yml's check: the outbound, the rule last, the host's own cdn-cgi/trace
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / "hop"))
sys.dont_write_bytecode = True  # no __pycache__ in the checkout

import mock_panel  # noqa: E402

PORT = int(os.environ.get("PANEL_TEST_PORT", "18085"))
URL = f"http://127.0.0.1:{PORT}"
TRACE_PORT = int(os.environ.get("WARP_TRACE_PORT", "18086"))

# What xray x25519 prints (base64url, no padding) and the same keys as WireGuard writes them.
KEYS_URL = {"privateKey": "UtwJRX8diXeZVTs12cn5WEtXlf2XqBV-C_Lj8D1SruU",
            "publicKey": "utqCViPm55YnV18HZhYveAta8zdQwWRjJpZoSOP_-mU"}
PRIVATE = "UtwJRX8diXeZVTs12cn5WEtXlf2XqBV+C/Lj8D1SruU="
PUBLIC = "utqCViPm55YnV18HZhYveAta8zdQwWRjJpZoSOP/+mU="

RULE = {"type": "field", "ruleTag": "3ax-warp", "network": "tcp,udp", "outboundTag": "warp"}
API_RULE = {"type": "field", "inboundTag": ["api"], "outboundTag": "api"}
RU_INSIDE = {"type": "field", "ruleTag": "3ax-ru-inside", "domain": ["ext:ru-inside.dat:ru-inside"], "outboundTag": "blocked"}
PRIVATE_IP = {"type": "field", "outboundTag": "blocked", "ip": ["geoip:private"]}
TORRENT = {"type": "field", "outboundTag": "blocked", "protocol": ["bittorrent"]}

# The outbound the panel's WARP modal builds from DEFAULT_WARP_DEVICE (warp_modal.html collectConfig, Outbound.toJson),
# with MTU 1280 instead of 1420 and ForceIPv4 instead of ForceIP: reserved = the bytes of client_id "8/+A".
OUTBOUND = {
    "protocol": "wireguard",
    "settings": {
        "mtu": 1280,
        "secretKey": PRIVATE,
        "address": ["172.16.0.2/32", "2606:4700:110:8a36:df92:102a:9602:fa18/128"],
        "workers": 2,
        "domainStrategy": "ForceIPv4",
        "reserved": [243, 255, 128],
        "peers": [{"publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "allowedIPs": ["0.0.0.0/0", "::/0"],
                   "endpoint": "engage.cloudflareclient.com:2408", "keepAlive": 0}],
        "noKernelTun": True,
    },
    "tag": "warp",
}
REGISTERED = {"access_token": "cf-token-3c9d", "device_id": "t.0f5d2c1e-3b1a-4d9e-9c7a-2b8f6e4d1a90",
              "license_key": "free-lic-0001", "private_key": PRIVATE}


def post(path, payload):
    request = urllib.request.Request(URL + path, data=json.dumps(payload).encode(), method="POST")
    urllib.request.urlopen(request).read()


def flat(out):
    return re.sub(r"\s+", " ", out)


def template(rules=None, outbounds=None):
    tpl = json.loads(json.dumps(mock_panel.DEFAULT_XRAY_TEMPLATE))
    if rules is not None:
        tpl["routing"]["rules"] = rules
    if outbounds is not None:
        tpl["outbounds"] = outbounds
    return tpl


class Trace(BaseHTTPRequestHandler):
    """www.cloudflare.com/cdn-cgi/trace as the panel host sees it: its own address, no WARP."""

    body = "fl=123f45\nh=www.cloudflare.com\nip=203.0.113.7\nts=1759230000.1\nvisit_scheme=https\nwarp=off\n"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        data = Trace.body.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class WarpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = mock_panel.serve(PORT, os.devnull)
        cls.trace = ThreadingHTTPServer(("127.0.0.1", TRACE_PORT), Trace)
        threading.Thread(target=cls.trace.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for server in (cls.server, cls.trace):
            server.shutdown()
            server.server_close()

    def setUp(self):
        # xray's asset folder with the ru-inside list, for templates that carry the ru-inside rule.
        self.assets = tempfile.mkdtemp(prefix="warp-assets-")
        Path(self.assets, "ru-inside.dat").write_bytes(b"\n\tRU-INSIDE\x12")
        post("/test/reset", [])
        post("/test/panel/reset", {"x25519Next": [KEYS_URL], "xrayAssetDir": self.assets})

    def tearDown(self):
        shutil.rmtree(self.assets, ignore_errors=True)

    # --- helpers -------------------------------------------------------------------------------------
    def state(self):
        return json.load(urllib.request.urlopen(URL + "/test/state"))

    def panel(self):
        return self.state()["panel"]

    def rules(self):
        return self.panel()["xrayTemplate"]["routing"]["rules"]

    def outbounds(self):
        return self.panel()["xrayTemplate"]["outbounds"]

    def play(self, tasks="warp", expect_rc=0, check=False, **extra):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(dict({"panel_warp_trace_url": f"http://127.0.0.1:{TRACE_PORT}/cdn-cgi/trace"}, **extra,
                           panel_test_tasks=tasks), f)
        env = dict(os.environ, PANEL_TEST_PORT=str(PORT), ANSIBLE_CONFIG=str(REPO / "ansible.cfg"),
                   ANSIBLE_ROLES_PATH=str(REPO / "roles"), ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default")
        before = len(self.state()["calls"])
        try:
            run = subprocess.run(["ansible-playbook", "-vvv", "-i", str(HERE / "inventory.yml"), str(HERE / "warp.yml"),
                                  "-e", f"@{f.name}"] + (["--check"] if check else []), env=env, capture_output=True, text=True, check=False)
        finally:
            os.unlink(f.name)
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, expect_rc, out[-8000:])
        self.assertNotIn("mock-session", out, "the session cookie reached the ansible output")
        for secret in (PRIVATE, KEYS_URL["privateKey"], "cf-token-3c9d"):
            self.assertNotIn(secret, out, "a WARP secret reached the ansible output")
        calls = self.state()["calls"][before:]
        reads = ("login", "xray/", "xray/warp/data", "xray/warp/config")
        self.writes = [c["path"] for c in calls if c["method"] == "POST" and c["path"] not in reads]
        self.calls = calls
        return out

    # --- converge -----------------------------------------------------------------------------------------
    def test_fresh_panel_registers_and_sends_everything_else_to_warp(self):
        out = flat(self.play())
        self.assertEqual(self.writes, ["xray/warp/reg", "xray/update", "server/restartXrayService"])
        reg = next(c for c in self.calls if c["path"] == "xray/warp/reg")
        self.assertEqual(urllib.parse.parse_qs(reg["body"]), {"privateKey": [PRIVATE], "publicKey": [PUBLIC]},
                         "the panel's X25519 pair, as WireGuard keys")
        self.assertEqual(json.loads(self.panel()["warp"]), REGISTERED)
        self.assertEqual(self.outbounds(), mock_panel.DEFAULT_XRAY_TEMPLATE["outbounds"] + [OUTBOUND])
        self.assertEqual(self.rules(), mock_panel.DEFAULT_XRAY_TEMPLATE["routing"]["rules"] + [RULE])
        self.assertEqual(self.panel()["outboundTestUrl"], "https://www.google.com/generate_204")
        self.assertIn("WARP: registered", out)

    def test_second_run_reuses_the_registration_and_changes_nothing(self):
        self.play()
        out = self.play()
        self.assertEqual(self.writes, [], "no second registration, no save, no restart")
        self.assertIn("xray/warp/config", [c["path"] for c in self.calls], "the device is read, not registered again")
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")
        self.assertIn("(as wanted)", flat(out))
        self.assertEqual(json.loads(self.panel()["warp"]), REGISTERED)
        self.assertEqual(self.rules()[-1], RULE)
        self.assertEqual(sum(1 for o in self.outbounds() if o.get("tag") == "warp"), 1)

    def test_existing_rules_keep_their_order_and_the_modal_outbound_is_converged_in_place(self):
        owner_warp = {"type": "field", "outboundTag": "warp", "domain": ["geosite:openai"]}
        per_inbound = {"type": "field", "inboundTag": ["awg-tproxy-in"], "outboundTag": "direct", "ip": ["10.8.0.0/24"]}
        # The panel's routing editor drops fields it does not know: our rule without its ruleTag, in the middle.
        stripped = {"type": "field", "network": "tcp,udp", "outboundTag": "warp"}
        # What the WARP modal saved by hand before (MTU 1420, kernel TUN), plus a key the role does not set.
        modal = json.loads(json.dumps(OUTBOUND))
        modal["settings"].update(mtu=1420, noKernelTun=False, kernelMode=False)
        modal["sendThrough"] = "0.0.0.0"
        rules = [API_RULE, RU_INSIDE, PRIVATE_IP, owner_warp, stripped, TORRENT, per_inbound]
        outbounds = mock_panel.DEFAULT_XRAY_TEMPLATE["outbounds"][:1] + [modal] + mock_panel.DEFAULT_XRAY_TEMPLATE["outbounds"][1:]
        post("/test/panel/xray", {"template": template(rules, outbounds), "outboundTestUrl": "https://example.test/204"})
        post("/test/panel/warp", {"data": REGISTERED})
        self.play()
        self.assertEqual(self.writes, ["xray/update", "server/restartXrayService"], "the panel's registration is reused")
        self.assertEqual(self.rules(), [API_RULE, RU_INSIDE, PRIVATE_IP, owner_warp, TORRENT, per_inbound, RULE])
        converged = json.loads(json.dumps(OUTBOUND))
        converged["settings"]["kernelMode"] = False
        converged["sendThrough"] = "0.0.0.0"
        self.assertEqual(self.outbounds(), outbounds[:1] + [converged] + outbounds[2:], "in place, not doubled")
        self.assertEqual(self.panel()["outboundTestUrl"], "https://example.test/204", "the rest of the form stays")
        self.play()
        self.assertEqual(self.writes, [])

    def test_second_warp_outbound_is_dropped(self):
        extra = {"tag": "warp", "protocol": "wireguard", "settings": {"secretKey": "old"}}
        post("/test/panel/xray", {"template": template(outbounds=mock_panel.DEFAULT_XRAY_TEMPLATE["outbounds"] + [OUTBOUND, extra])})
        post("/test/panel/warp", {"data": REGISTERED})
        self.play()
        self.assertEqual(self.outbounds(), mock_panel.DEFAULT_XRAY_TEMPLATE["outbounds"] + [OUTBOUND])
        self.assertEqual(self.panel()["xrayRestarts"], 1, "xray refuses two outbounds with one tag")

    def test_disabled_takes_out_our_rule_and_the_outbound_only(self):
        rules = [API_RULE, RU_INSIDE, PRIVATE_IP, TORRENT]
        post("/test/panel/xray", {"template": template(rules)})
        self.play()
        self.assertEqual(self.rules(), rules + [RULE])
        self.play(warp_enabled=False)
        self.assertEqual(self.writes, ["xray/update", "server/restartXrayService"])
        self.assertEqual(self.rules(), rules)
        self.assertEqual(self.outbounds(), mock_panel.DEFAULT_XRAY_TEMPLATE["outbounds"])
        self.assertEqual(json.loads(self.panel()["warp"]), REGISTERED, "the registration stays in the panel")
        out = self.play(warp_enabled=False)
        self.assertEqual(self.writes, [])
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")
        self.assertNotIn("xray/warp/", " ".join(c["path"] for c in self.calls), "disabled: WARP is not touched")

    def test_disabled_keeps_the_outbound_another_rule_points_at(self):
        owner_warp = {"type": "field", "outboundTag": "warp", "domain": ["geosite:openai"]}
        post("/test/panel/xray", {"template": template([API_RULE, owner_warp, PRIVATE_IP])})
        self.play()
        self.play(warp_enabled=False)
        self.assertEqual(self.rules(), [API_RULE, owner_warp, PRIVATE_IP])
        self.assertIn(OUTBOUND, self.outbounds())

    def test_failed_registration_writes_no_rule_and_warns(self):
        before = self.panel()["xrayTemplate"]
        post("/test/panel/warp", {"fail": "network"})
        out = flat(self.play())
        self.assertIn("WARNING: WARP: the registration failed:", out)
        self.assertIn("i/o timeout", out)
        self.assertIn("no rule «tcp,udp -> warp» in the Xray template", out)
        self.assertEqual(self.writes, ["xray/warp/reg"])
        self.assertEqual(self.panel()["xrayTemplate"], before, "no rule into an outbound that is not there")
        self.assertEqual(self.panel()["warp"], "")

        # Cloudflare answers without an account: RegWarp says success with nothing in it.
        post("/test/panel/warp", {"fail": "empty"})
        out = flat(self.play())
        self.assertIn("WARNING: WARP: the registration failed: the panel got no account from api.cloudflareclient.com", out)
        self.assertEqual(self.panel()["xrayTemplate"], before)
        self.assertRegex(out, r"real : ok=\d+ changed=0 ")

        # Cloudflare back: the next run registers and routes.
        post("/test/panel/warp", {"fail": ""})
        self.play()
        self.assertEqual(self.rules()[-1], RULE)

    def test_rule_without_a_registration_is_taken_out(self):
        # The registration was deleted in the panel (WARP modal -> Delete) and Cloudflare is out of reach.
        stale = json.loads(json.dumps(OUTBOUND))
        stale["settings"]["secretKey"] = "c3RhbGUta2V5LXN0YWxlLWtleS1zdGFsZS1rZXktMDA="
        rules = mock_panel.DEFAULT_XRAY_TEMPLATE["routing"]["rules"] + [RULE]
        post("/test/panel/xray", {"template": template(rules, mock_panel.DEFAULT_XRAY_TEMPLATE["outbounds"] + [stale])})
        post("/test/panel/warp", {"fail": "network"})
        out = flat(self.play())
        self.assertIn("WARNING: WARP: the registration failed", out)
        self.assertEqual(self.rules(), mock_panel.DEFAULT_XRAY_TEMPLATE["routing"]["rules"])
        self.assertIn(stale, self.outbounds(), "the outbound is left as it is")

    def test_device_out_of_reach_keeps_the_outbound_of_the_registration(self):
        self.play()
        post("/test/panel/warp", {"fail": "network"})
        out = self.play(warp_mtu=1380)
        self.assertEqual(self.writes, ["xray/update", "server/restartXrayService"])
        self.assertEqual(self.rules()[-1], RULE)
        warp = next(o for o in self.outbounds() if o.get("tag") == "warp")
        self.assertEqual(warp["settings"], dict(OUTBOUND["settings"], mtu=1380), "peer data kept, MTU converged")
        self.assertNotIn("WARNING", out)

        # A device Cloudflare no longer knows: the same.
        post("/test/panel/warp", {"fail": "config"})
        out = self.play(warp_mtu=1380)
        self.assertEqual(self.writes, [])
        self.assertEqual(self.rules()[-1], RULE)

        # ... but not an outbound made with another key: no rule then.
        post("/test/panel/warp", {"data": dict(REGISTERED, private_key="b3RoZXIta2V5LW90aGVyLWtleS1vdGhlci1rZXktMDA=")})
        out = flat(self.play(warp_mtu=1380))
        self.assertIn("WARNING: WARP: the WARP device could not be read (Cloudflare answered without the device) and the Xray"
                      " template has no warp outbound with the registration", out)
        self.assertNotIn(RULE, self.rules())

    def test_license_is_set_once(self):
        self.play(warp_license="plus-7Kq2")
        self.assertEqual(self.writes, ["xray/warp/reg", "xray/warp/license", "xray/update", "server/restartXrayService"])
        self.assertEqual(json.loads(self.panel()["warp"])["license_key"], "plus-7Kq2")
        out = self.play(warp_license="plus-7Kq2")
        self.assertEqual(self.writes, [])
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")

    def test_refused_license_warns_and_keeps_warp(self):
        post("/test/panel/warp", {"badLicense": "plus-bad"})
        out = flat(self.play(warp_license="plus-bad"))
        self.assertIn("WARNING: WARP: the WARP+ license was not accepted", out)
        self.assertIn("Invalid license", out)
        self.assertNotIn("plus-bad", out.replace('"warp_license": "plus-bad"', ""), "the key is not echoed")
        self.assertEqual(json.loads(self.panel()["warp"])["license_key"], "free-lic-0001")
        self.assertEqual(self.rules()[-1], RULE)

    def test_check_mode_registers_and_saves_nothing(self):
        before = self.panel()["xrayTemplate"]
        out = flat(self.play(check=True))
        self.assertEqual(self.writes, [])
        self.assertIn("check mode: the panel has no WARP registration yet, site.yml makes one", out)
        self.assertEqual(self.panel()["xrayTemplate"], before)
        self.play()
        out = self.play(check=True)
        self.assertEqual(self.writes, [])
        self.assertIn("(as wanted)", flat(out))

    def test_failed_restart_puts_the_old_template_back(self):
        before = self.panel()["xrayTemplate"]
        post("/test/panel/xray", {"restartFails": True})
        out = flat(self.play(expect_rc=2))
        self.assertIn("xray did not restart with the WARP outbound and rule; the previous template is back", out)
        self.assertEqual(self.panel()["xrayTemplate"], before)

    # --- verify.yml ------------------------------------------------------------------------------------------
    def test_verify_passes_on_a_converged_panel_and_reports_the_hosts_own_trace(self):
        self.play()
        out = flat(self.play("verify_warp"))
        self.assertIn("WARP: outbound warp (wireguard, MTU 1280, noKernelTun) and the rule «tcp,udp -> warp» last", out)
        self.assertIn("the panel host itself: warp=off, ip=203.0.113.7 (the baseline; clients see warp=on)", out)
        self.assertNotIn("WARNING", out)
        self.assertEqual(self.writes, [])
        self.assertNotIn("xray/warp/reg", [c["path"] for c in self.calls])

    def test_verify_fails_without_the_outbound_or_with_the_rule_not_last(self):
        out = flat(self.play("verify_warp", expect_rc=2))
        self.assertIn("no warp outbound in the panel's Xray template", out)

        self.play()
        tpl = self.panel()["xrayTemplate"]
        tpl["routing"]["rules"].append(TORRENT)
        post("/test/panel/xray", {"template": tpl})
        out = flat(self.play("verify_warp", expect_rc=2))
        self.assertIn("the rule «tcp,udp -> warp» is not the last routing rule", out)

    def test_verify_warns_when_the_trace_does_not_answer(self):
        self.play()
        out = flat(self.play("verify_warp", panel_warp_trace_url="http://127.0.0.1:9/cdn-cgi/trace"))
        self.assertIn("WARNING: WARP: outbound warp", out)
        self.assertIn("no cdn-cgi/trace from the panel host (", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
