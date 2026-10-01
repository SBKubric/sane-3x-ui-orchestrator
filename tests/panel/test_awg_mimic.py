"""Role panel's AmneziaWG protocol mimicry (I1-I5, awg_obfuscation) and its verify.yml step against the mock panel.

    PANEL_TEST_PORT=18084 python3 tests/panel/test_awg_mimic.py      # needs ansible-playbook on PATH

The templates of roles/panel/vars/awg_mimic.yml are checked byte by byte first (what the tags put on the wire).
Then every test seeds the mock panel (tests/hop/mock_panel.py) with a new AWG server (no AWG inbound, no AWG
clients) or one in use, runs tests/panel/site.yml (tasks_from: inbounds, the stand's panel_inbounds) with the
mimicry variables and checks what reached POST awg/server, the warning or the note, and idempotency.
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

PORT = int(os.environ.get("PANEL_TEST_PORT", "18084"))
URL = f"http://127.0.0.1:{PORT}"
STAND_INBOUNDS = yaml.safe_load((REPO / "inventories" / "stand-full" / "group_vars" / "panel.yml").read_text())["panel_inbounds"]
MIMIC = yaml.safe_load((REPO / "roles" / "panel" / "vars" / "awg_mimic.yml").read_text())
TEMPLATES = {name: {k: "".join(v) for k, v in packets.items()} for name, packets in MIMIC["panel_awg_mimic_templates"].items()}
KEYS = ["i1", "i2", "i3", "i4", "i5"]
# The panel's seed of a new server in the mock: I1 random bytes, I2-I5 its own protocol headers.
SEEDED = {k: mock_panel.Registry().panel.awg[k] for k in KEYS}
TAG = re.compile(r"<(b|r|rc|rd|t)(?: ([^>]*))?>")
# The AWG entry alone: a panel whose server is in use has its AWG inbound, nothing else to add.
AWG_ONLY = [i for i in STAND_INBOUNDS if i["protocol"] == "amneziawg"]


def post(path, payload):
    request = urllib.request.Request(URL + path, data=json.dumps(payload).encode(), method="POST")
    urllib.request.urlopen(request).read()


def render(packet, fill=0x00):
    """The bytes a packet puts on the wire, random parts as `fill` (digits as '0'); None for a tag nobody parses."""
    out, pos = bytearray(), 0
    for match in TAG.finditer(packet):
        if match.start() != pos:
            return None
        tag, value = match.group(1), match.group(2)
        if tag == "b":
            out += bytes.fromhex(value[2:])
        elif tag == "t":
            out += b"\x00" * 4
        elif tag == "rd":
            out += b"0" * int(value)
        elif tag == "rc":
            out += b"a" * int(value)
        else:
            out += bytes([fill]) * int(value)
        pos = match.end()
    return bytes(out) if pos == len(packet) else None


class TemplatesTest(unittest.TestCase):
    """What each template puts on the wire, and that both the kernel module and amneziawg-go take it."""

    def test_every_packet_is_tags_both_parsers_take(self):
        pattern = re.compile(MIMIC["panel_awg_mimic_packet_re"])
        for name, packets in TEMPLATES.items():
            for key, packet in packets.items():
                self.assertIn(key, KEYS)
                self.assertRegex(packet, pattern, f"{name}.{key}")
                self.assertNotIn("<c>", packet, f"{name}.{key}: amneziawg-go refuses <c>")
                self.assertIsNotNone(render(packet), f"{name}.{key}")
        self.assertEqual(sorted(TEMPLATES), ["dns", "quic", "sip"])

    def test_quic_is_a_1200_byte_initial(self):
        wire = render(TEMPLATES["quic"]["i1"])
        self.assertEqual(len(wire), 1200, "a client Initial is padded to 1200 bytes (RFC 9000 §14.1)")
        self.assertEqual(wire[0] & 0xF0, 0xC0, "long header, fixed bit, type Initial")
        self.assertEqual(wire[1:5], b"\x00\x00\x00\x01", "QUIC version 1")
        self.assertEqual(wire[5], 8, "8-byte Destination Connection ID")
        self.assertEqual(wire[14], 0, "no Source Connection ID")
        self.assertEqual(wire[15], 0, "no token")
        length = int.from_bytes(wire[16:18], "big")
        self.assertEqual(length >> 14, 1, "a 2-byte varint")
        self.assertEqual(18 + (length & 0x3FFF), 1200, "Length covers the rest of the datagram")
        self.assertEqual(set(TEMPLATES["quic"]), {"i1"})

    def test_dns_is_an_answer_for_icloud(self):
        wire = render(TEMPLATES["dns"]["i1"], fill=0x11)
        self.assertEqual(len(wire), 44)
        self.assertEqual(wire[2:12], bytes.fromhex("85800001000100000000"), "response, one question, one answer")
        self.assertEqual(wire[12:28], b"\x06icloud\x03com\x00\x00\x01\x00\x01")
        self.assertEqual(wire[28:34], bytes.fromhex("c00c00010001"), "answer: the question's name, A, IN")
        self.assertEqual(wire[34:36], b"\x00\x00", "TTL below 65536 s")
        self.assertEqual(wire[38:40], b"\x00\x04", "RDLENGTH 4, an IPv4 address")

    def test_sip_is_a_register_request(self):
        wire = render(TEMPLATES["sip"]["i1"])
        self.assertEqual(len(wire), 383)
        text = wire.decode("ascii")
        self.assertTrue(text.endswith("\r\n\r\n"))
        lines = text[:-4].split("\r\n")
        self.assertEqual(lines[0], "REGISTER sip:sip.linphone.org SIP/2.0")
        headers = dict(line.split(": ", 1) for line in lines[1:])
        self.assertEqual(sorted(headers), ["CSeq", "Call-ID", "Contact", "Content-Length", "Expires", "From", "Max-Forwards",
                                           "To", "User-Agent", "Via"])
        self.assertRegex(headers["Via"], r";branch=z9hG4bK0{10}$")
        self.assertEqual(headers["Content-Length"], "0")


class PanelCase(unittest.TestCase):
    """The mock panel, a playbook run against it, and what the run sent."""

    @classmethod
    def setUpClass(cls):
        cls.server = mock_panel.serve(PORT, os.devnull)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()  # the next class binds the same port

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="awgmimictest-"))
        post("/test/reset", [])
        post("/test/panel/reset", {})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- helpers -------------------------------------------------------------------------------------
    def state(self):
        return json.load(urllib.request.urlopen(URL + "/test/state"))

    def awg(self):
        return self.state()["panel"]["awg"]

    def play(self, extra_vars=None, *args, expect_rc=0, playbook=HERE / "site.yml", inbounds=None):
        """Runs the playbook; returns its output with the callback's line wrapping and quote doubling undone."""
        vars_file = self.tmp / "vars.json"
        vars_file.write_text(json.dumps(dict({"panel_inbounds": STAND_INBOUNDS if inbounds is None else inbounds},
                                             **(extra_vars or {}))))
        env = dict(os.environ, PANEL_TEST_PORT=str(PORT), ANSIBLE_CONFIG=str(REPO / "ansible.cfg"),
                   ANSIBLE_ROLES_PATH=str(REPO / "roles"), ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default")
        before = len(self.state()["calls"])
        run = subprocess.run(["ansible-playbook", "-i", str(HERE / "inventory.yml"), str(playbook), "-e", f"@{vars_file}", *args],
                             env=env, capture_output=True, text=True, check=False)
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, expect_rc, out[-6000:])
        self.assertNotIn(self.awg()["privateKey"], out, "the AWG private key reached the ansible output")
        for key in [self.awg()["headerProtectionKey"], VAULT_KEY, *self.state()["panel"]["awgGenerated"]]:
            if key:
                self.assertNotIn(key, out, "a header protection key reached the ansible output")
        calls = self.state()["calls"][before:]
        self.writes = [(c["path"], json.loads(c["body"] or "{}")) for c in calls if c["method"] == "POST" and c["path"] != "login"]
        self.reads = [c["path"] for c in calls if c["method"] == "GET"]
        return re.sub(r"\s+", " ", out.replace("\\n", "\n")).replace("''", "'")

    def saved(self):
        """The body of the one POST awg/server of the last run."""
        saves = [body for path, body in self.writes if path == "awg/server"]
        self.assertEqual(len(saves), 1, self.writes)
        return saves[0]

    def assert_idempotent(self, extra_vars=None, inbounds=None):
        out = self.play(extra_vars, inbounds=inbounds)
        self.assertEqual(self.writes, [], "second run wrote to the panel")
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")
        self.assertNotIn("WARNING", out)
        return out

    def seed_in_use(self):
        """A server made before the mimicry: the panel's own I1-I5, switched on at 51820, its inbound and clients."""
        post("/test/panel/reset", {
            "awg": {"enable": True, "listenPort": 51820, "routeViaXray": True},
            "inbounds": [{"remark": "awg", "protocol": "amneziawg", "port": 51820, "tag": "inbound-amneziawg",
                          "settings": '{"clients": []}'}],
            "awgClients": [{"id": 1, "name": "alice", "email": "alice", "enable": True},
                           {"id": 2, "name": "probe", "email": "Probe-AWG-1", "enable": True}]})



class AwgMimicTest(PanelCase):
    # --- a new server --------------------------------------------------------------------------------
    def test_new_server_gets_the_quic_template_before_its_inbound(self):
        before = self.awg()
        out = self.play()
        self.assertEqual([path for path, _ in self.writes], ["awg/server", "server/restartXrayService", "inbounds/add", "inbounds/add"],
                         "I1-I5 go with the server's first save (routeViaXray too), before the AWG inbound (and so any client) exists")
        body = self.saved()
        self.assertEqual({k: body[k] for k in KEYS}, {"i1": TEMPLATES["quic"]["i1"], "i2": "", "i3": "", "i4": "", "i5": ""})
        self.assertTrue(body["routeViaXray"], "one save carries the route through xray and the packets alike")
        for key in ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "privateKey"]:
            self.assertEqual(body[key], before[key], f"{key} stays the panel's")
        self.assertIn("awg/clients", self.reads, "a new server is one without clients")
        self.assertIn("obfuscation i1 i2 i3 i4 i5", out)
        self.assertNotIn("WARNING", out)
        self.assertNotIn("NOTE", out)
        self.assert_idempotent()

    def test_new_server_with_dns_sip_and_overrides(self):
        for protocol in ["dns", "sip"]:
            post("/test/panel/reset", {})
            self.play({"awg_mimic_protocol": protocol})
            self.assertEqual(self.saved()["i1"], TEMPLATES[protocol]["i1"], protocol)
        post("/test/panel/reset", {})
        before = self.awg()
        overrides = {"jc": 3, "jmin": 40, "jmax": 70, "h1": "100000-200000", "s4": 20}
        self.play({"awg_obfuscation": overrides})
        body = self.saved()
        self.assertEqual({k: body[k] for k in overrides}, overrides)
        self.assertEqual((body["s1"], body["h2"]), (before["s1"], before["h2"]), "undeclared fields stay the panel's")
        self.assertEqual(body["i1"], TEMPLATES["quic"]["i1"])
        self.assert_idempotent({"awg_obfuscation": overrides})

    def test_custom_packets(self):
        custom = {"i1": "<b 0x0102abcd><r 16><t>", "i3": "<rc 8><rd 4>"}
        self.play({"awg_mimic_protocol": "custom", "awg_mimic_custom": custom})
        body = self.saved()
        self.assertEqual({k: body[k] for k in KEYS}, {"i1": custom["i1"], "i2": "", "i3": custom["i3"], "i4": "", "i5": ""})
        self.assert_idempotent({"awg_mimic_protocol": "custom", "awg_mimic_custom": custom})

    def test_none_leaves_the_panels_packets(self):
        none = {"awg_mimic_protocol": "none", "awg_v3": False}  # awg_v3 sets fields of its own (AwgV3Test)
        out = self.play(none)
        body = self.saved()  # the server is still switched on and moved to its port
        self.assertEqual({k: body[k] for k in KEYS}, SEEDED)
        self.assertNotIn("awg/clients", self.reads)
        self.assertNotRegex(out, r"AmneziaWG server: \w+ \([^)]*obfuscation")
        self.assert_idempotent(none)

    def test_check_mode_only_plans(self):
        out = self.play(None, "--check")
        self.assertEqual(self.writes, [])
        self.assertIn("AmneziaWG server: save", out)
        self.assertIn("obfuscation i1 i2 i3 i4 i5", out)
        self.assertEqual({k: self.awg()[k] for k in KEYS}, SEEDED)

    # --- a server in use -----------------------------------------------------------------------------
    def test_server_in_use_gets_a_warning_and_no_change(self):
        self.seed_in_use()
        out = self.play(inbounds=AWG_ONLY)
        self.assertEqual(self.writes, [])
        self.assertIn("WARNING: the AmneziaWG server is in use (its AWG inbound exists)", out)
        self.assertIn("Current I1: '<r 153>'", out)
        self.assertIn(f"desired I1: '{TEMPLATES['quic']['i1']}'", out)
        self.assertIn("awg_obfuscation_apply=true", out)
        self.assertNotIn("awg/clients", self.reads, "the inbound alone makes it a server in use")
        self.assertEqual({k: self.awg()[k] for k in KEYS}, SEEDED)
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")

    def test_clients_without_an_inbound_make_a_server_in_use(self):
        post("/test/panel/reset", {"awg": {"enable": False, "listenPort": 51820, "routeViaXray": True}, "awgClients": [{"id": 1, "name": "alice"}]})
        out = self.play(inbounds=AWG_ONLY)
        self.assertIn("WARNING: the AmneziaWG server is in use (1 AWG client(s))", out)
        self.assertIn("awg/clients", self.reads)
        self.assertEqual([path for path, _ in self.writes], ["awg/server", "inbounds/add"])
        self.assertEqual({k: self.saved()[k] for k in KEYS}, SEEDED, "the save that switches it on keeps the packets")

    def test_apply_changes_a_server_in_use(self):
        self.seed_in_use()
        out = self.play({"awg_obfuscation_apply": True, "awg_obfuscation": {"jc": 4}}, inbounds=AWG_ONLY)
        self.assertEqual([path for path, _ in self.writes], ["awg/server"])
        body = self.saved()
        self.assertEqual(body["i1"], TEMPLATES["quic"]["i1"])
        self.assertEqual((body["i2"], body["jc"]), ("", 4))
        self.assertEqual(body["privateKey"], self.awg()["privateKey"], "the save keeps the keys")
        self.assertTrue(self.awg()["routeViaXray"], "the obfuscation save keeps the route through xray")
        self.assertIn("NOTE: awg_obfuscation_apply changes the obfuscation of an AmneziaWG server in use", out)
        self.assertIn("SendAwgConfigsToClients", out)
        self.assertNotIn("WARNING", out)
        self.assert_idempotent({"awg_obfuscation_apply": True, "awg_obfuscation": {"jc": 4}}, inbounds=AWG_ONLY)
        self.assert_idempotent({"awg_obfuscation": {"jc": 4}}, inbounds=AWG_ONLY)  # without the flag: nothing differs

    # --- inputs --------------------------------------------------------------------------------------
    def test_malformed_inputs_are_refused_before_the_login(self):
        cases = [
            ({"awg_mimic_protocol": "http"}, "awg_mimic_protocol must be one of quic, dns, sip, none, custom, not http"),
            ({"awg_mimic_protocol": "custom"}, "awg_mimic_protocol custom needs awg_mimic_custom.i1"),
            ({"awg_mimic_protocol": "custom", "awg_mimic_custom": {"i1": "<b 0x01><c>"}}, "awg_mimic_custom.i1: no <c>"),
            ({"awg_mimic_protocol": "custom", "awg_mimic_custom": {"i1": "<b 0x012>"}}, "awg_mimic_custom.i1 must be tags only"),
            ({"awg_mimic_protocol": "custom", "awg_mimic_custom": {"i1": "<r 4> <r 4>"}}, "awg_mimic_custom.i1 must be tags only"),
            ({"awg_mimic_protocol": "custom", "awg_mimic_custom": {"i1": "<t><t>"}}, "awg_mimic_custom.i1: one <t> per packet"),
            ({"awg_mimic_protocol": "custom", "awg_mimic_custom": {"i1": "<r 4>", "i6": "<r 4>"}}, "awg_mimic_custom takes i1..i5, not i6"),
            ({"awg_obfuscation": {"i1": "<r 4>"}}, "not i1 (I1-I5 come from awg_mimic_protocol)"),
            ({"awg_obfuscation": {"jc": "many"}}, "awg_obfuscation.jc must be a non-negative integer"),
            ({"awg_obfuscation": {"h1": "1-2-3"}}, "awg_obfuscation.h1 must be a number or a low-high range"),
            ({"awg_obfuscation_apply": "maybe"}, "awg_obfuscation_apply must be true or false"),
        ]
        for extra, text in cases:
            with self.subTest(text):
                out = self.play(extra, expect_rc=2)
                self.assertIn(text, out)
                self.assertEqual((self.writes, self.reads), ([], []))

    # --- verify.yml ----------------------------------------------------------------------------------
    def test_verify_reports_the_template_and_warns_about_another_i1(self):
        self.play()
        out = self.play(playbook=HERE / "verify_awg_mimic.yml")
        self.assertIn("AmneziaWG mimicry: I1 is the quic template", out)
        self.assertEqual(self.writes, [])

        out = self.play({"awg_mimic_protocol": "dns"}, playbook=HERE / "verify_awg_mimic.yml")
        self.assertIn(f"WARNING: AmneziaWG mimicry: the server's I1 is '{TEMPLATES['quic']['i1']}', not the dns template", out)

        self.seed_in_use()
        post("/test/panel/reset", {"awg": {"i1": ""}})
        out = self.play(playbook=HERE / "verify_awg_mimic.yml")
        self.assertIn("WARNING: AmneziaWG mimicry: the server's I1 is empty, not the quic template", out)


# The role's 3.0 ranges when the inventory sets none (roles/panel/defaults/main.yml, README "AmneziaWG 3.0").
V3_DEFAULTS = {"contentPaddingAddition": "8-40", "rekeyAfterTime": "105-125", "rekeyTimeout": "4-7",
               "rejectAfterTime": "170-195", "keepaliveTimeout": "8-12", "maxHandshakeAttempts": "15-21"}
# A key in the shape awg genkey prints (base64 of 32 bytes); test data only.
VAULT_KEY = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
# A server made before 3.0 on a host that now takes it, as the stand had it: the 2.0 set with S3/S4 below the
# 12-byte nonce, no key, the panel's own ContentPaddingAddition, no timers.
V2_SERVER = {"s1": 5, "s2": 73, "s3": 8, "s4": 4, "headerProtectionKey": "", "contentPaddingAddition": "4-20",
             "rekeyAfterTime": "", "rekeyTimeout": "", "rejectAfterTime": "", "keepaliveTimeout": "",
             "maxHandshakeAttempts": ""}


class AwgV3Test(PanelCase):
    """AmneziaWG 3.0 (awg_v3, default on): HeaderProtectionKey, S1-S4 >= 12, the ranges; and verify.yml's check."""

    def test_new_server_takes_the_default_ranges_and_keeps_the_panels_key(self):
        before = self.awg()
        self.play()
        body = self.saved()
        self.assertEqual({k: body[k] for k in V3_DEFAULTS}, V3_DEFAULTS)
        self.assertEqual(body["headerProtectionKey"], before["headerProtectionKey"], "the key the panel made stays")
        self.assertEqual([body[f"s{i}"] for i in range(1, 5)], [40, 120, 20, 16], "S1-S4 already hold the nonce")
        self.assertNotIn("awg/server/generate", [path for path, _ in self.writes])
        self.assertIn("awg/server/status", self.reads, "the role asks whether the kernel takes 3.0")
        self.assert_idempotent()


    def seed_v2_in_use(self, **extra):
        """The stand before 3.0: a server in use (its inbound, a user and a probe peer) with V2_SERVER's fields."""
        seed = {"awg": dict({"enable": True, "listenPort": 51820, "routeViaXray": True, "i1": TEMPLATES["quic"]["i1"],
                             "i2": "", "i3": "", "i4": "", "i5": ""}, **V2_SERVER),
                "inbounds": [{"remark": "awg", "protocol": "amneziawg", "port": 51820, "tag": "inbound-amneziawg",
                              "settings": '{"clients": []}'}],
                "awgClients": [{"id": 1, "name": "alice", "email": "alice", "enable": True},
                               {"id": 2, "name": "probe", "email": "Probe-AWG-1", "enable": True}]}
        seed.update(extra)
        post("/test/panel/reset", seed)

    def test_new_server_without_a_key_gets_one_from_the_panel_and_padding_for_the_nonce(self):
        post("/test/panel/reset", {"awg": V2_SERVER})
        self.play()
        self.assertEqual([path for path, _ in self.writes][:2], ["awg/server/generate", "awg/server"],
                         "the panel makes the key right before the save")
        body = self.saved()
        generated = self.state()["panel"]["awgGenerated"]
        self.assertEqual(len(generated), 1)
        self.assertEqual(body["headerProtectionKey"], generated[0])
        # S1 5 -> 17 would make S1 + 56 = S2 (73): the kernel refuses that, so S1 goes one further.
        self.assertEqual([body[f"s{i}"] for i in range(1, 5)], [18, 73, 20, 16])
        self.assertEqual({k: body[k] for k in V3_DEFAULTS}, V3_DEFAULTS)
        self.assert_idempotent()

    def test_server_in_use_keeps_its_2_0_set_with_a_warning(self):
        self.seed_v2_in_use()
        out = self.play(inbounds=AWG_ONLY)
        self.assertEqual(self.writes, [], "no save, and no key made for nothing")
        self.assertIn("WARNING: the AmneziaWG server is in use (its AWG inbound exists)", out)
        self.assertIn("/ awg_v3.", out)
        self.assertIn("AmneziaWG 3.0 is not on yet: header protection (HeaderProtectionKey, S1-S4 >= 12)", out)
        self.assertIn("awg_obfuscation_apply=true", out)
        self.assertEqual(self.awg()["headerProtectionKey"], "")
        self.assertRegex(out, r"real\s+: ok=\d+\s+changed=0 ")

    def test_apply_turns_on_3_0_on_a_server_in_use(self):
        self.seed_v2_in_use()
        out = self.play({"awg_obfuscation_apply": True}, inbounds=AWG_ONLY)
        self.assertEqual([path for path, _ in self.writes], ["awg/server/generate", "awg/server"])
        body = self.saved()
        self.assertEqual(body["headerProtectionKey"], self.state()["panel"]["awgGenerated"][0])
        self.assertEqual([body[f"s{i}"] for i in range(1, 5)], [18, 73, 20, 16])
        self.assertEqual({k: body[k] for k in V3_DEFAULTS}, V3_DEFAULTS)
        self.assertEqual(body["i1"], TEMPLATES["quic"]["i1"])
        self.assertIn("NOTE: awg_obfuscation_apply changes the obfuscation of an AmneziaWG server in use", out)
        self.assertIn("With header protection (AmneziaWG 3.0) an old .conf gets no handshake at all", out)
        self.assertNotIn("WARNING", out)
        self.assert_idempotent({"awg_obfuscation_apply": True}, inbounds=AWG_ONLY)
        self.assert_idempotent(None, inbounds=AWG_ONLY)

    def test_the_vault_key_and_awg_v3_params_win(self):
        params = {"rekeyAfterTime": "90-100", "maxHandshakeAttempts": 20}
        self.play({"awg_header_protection_key": VAULT_KEY, "awg_v3_params": params})
        body = self.saved()
        self.assertEqual(body["headerProtectionKey"], VAULT_KEY)
        self.assertEqual((body["rekeyAfterTime"], body["maxHandshakeAttempts"], body["rekeyTimeout"]), ("90-100", "20", "4-7"))
        self.assertNotIn("awg/server/generate", [path for path, _ in self.writes])
        self.assert_idempotent({"awg_header_protection_key": VAULT_KEY, "awg_v3_params": params})

    def test_awg_v3_false_leaves_the_3_0_fields_alone(self):
        post("/test/panel/reset", {"awg": V2_SERVER})
        self.play({"awg_v3": False})
        body = self.saved()
        for key, value in V2_SERVER.items():
            self.assertEqual(body[key], value, key)
        self.assertNotIn("awg/server/status", self.reads)
        self.assert_idempotent({"awg_v3": False})

    def test_a_host_without_3_0_gets_a_warning_and_the_mimicry_alone(self):
        post("/test/panel/reset", {"awg": V2_SERVER, "supportsV3": False})
        out = self.play()
        body = self.saved()
        self.assertEqual(body["i1"], TEMPLATES["quic"]["i1"])
        for key, value in V2_SERVER.items():
            self.assertEqual(body[key], value, key)
        self.assertIn("WARNING: AmneziaWG 3.0: the kernel module on real does not take the 3.0 parameters", out)
        self.assertNotIn("awg/server/generate", [path for path, _ in self.writes])

    def test_check_mode_makes_no_key(self):
        post("/test/panel/reset", {"awg": V2_SERVER})
        out = self.play(None, "--check")
        self.assertEqual(self.writes, [])
        self.assertRegex(out, r"AmneziaWG server: save \([^)]*obfuscation [^)]*headerProtectionKey")


    def test_malformed_3_0_inputs_are_refused_before_the_login(self):
        cases = [
            ({"awg_v3": "maybe"}, "awg_v3 must be true or false"),
            ({"awg_v3_params": ["8-40"]}, "awg_v3_params must be a mapping"),
            ({"awg_v3_params": {"persistentKeepalive": "20-30"}}, "awg_v3_params takes contentPaddingAddition, rekeyAfterTime"),
            ({"awg_v3_params": {"rekeyTimeout": "7-4"}}, "awg_v3_params.rekeyTimeout must be a number or a low-high range"),
            ({"awg_v3_params": {"keepaliveTimeout": "70000"}}, "awg_v3_params.keepaliveTimeout must be a number or a low-high range"),
            ({"awg_v3_params": {"rekeyAfterTime": "150-200"}},
             "awg_v3_params: rekeyAfterTime (up to 200) must stay below rejectAfterTime (from 170)"),
            ({"awg_header_protection_key": "not-a-key"}, "awg_header_protection_key must be base64 of 32 bytes (awg genkey)"),
            ({"awg_obfuscation": {"s4": 8}}, "awg_obfuscation.s4 must be at least 12 with awg_v3 (header protection carries its nonce in the padding)"),
        ]
        for extra, text in cases:
            with self.subTest(text):
                out = self.play(extra, expect_rc=2)
                self.assertIn(text, out)
                self.assertEqual((self.writes, self.reads), ([], []))
        post("/test/panel/reset", {"awg": V2_SERVER})
        self.play({"awg_v3": False, "awg_obfuscation": {"s4": 8}})  # without 3.0 (and no key) a small padding is fine
        self.assertEqual(self.saved()["s4"], 8)


    # --- verify.yml ----------------------------------------------------------------------------------
    def verify(self, extra_vars=None, expect_rc=0):
        return self.play(dict({"panel_awg_conf_dir": str(self.tmp)}, **(extra_vars or {})), expect_rc=expect_rc,
                         playbook=HERE / "verify_awg_v3.yml", inbounds=AWG_ONLY)

    def test_verify_checks_awg0_conf_and_a_clients_conf_against_the_panel(self):
        self.seed_v2_in_use(awgConfDir=str(self.tmp))
        self.play({"awg_obfuscation_apply": True}, inbounds=AWG_ONLY)
        conf = self.tmp / "awg0.conf"
        self.assertIn("HeaderProtectionKey = ", conf.read_text(), "the mock panel wrote the applied server")
        out = self.verify()
        self.assertEqual(self.writes, [])
        self.assertIn("AmneziaWG 3.0: awg0.conf has HeaderProtectionKey, S1-S4 18/73/20/16 and the panel's 3.0 fields;"
                      " the .conf of client alice carries the same key", out)
        self.assertIn("awg/client/1/config", self.reads)
        out = self.verify({"awg_verify_client": "Probe-AWG-1"})
        self.assertIn("the .conf of client Probe-AWG-1 carries the same key", out)

        conf.write_text("".join(line for line in conf.read_text().splitlines(True)
                                if not line.startswith(("HeaderProtectionKey", "RekeyTimeout"))))
        out = self.verify(expect_rc=2)
        self.assertIn("AmneziaWG 3.0: " + str(conf) + " differs from the panel's AWG server in HeaderProtectionKey, RekeyTimeout"
                      " (the kernel module took fewer fields, or the panel did not apply the last save)", out)

    def test_verify_fails_on_a_client_conf_with_another_key(self):
        self.seed_v2_in_use(awgConfDir=str(self.tmp))
        self.play({"awg_obfuscation_apply": True}, inbounds=AWG_ONLY)
        # alice still has a .conf from before (the mock hands out "config" as it is).
        post("/test/panel/reset", {"awg": self.awg(), "awgConfDir": str(self.tmp),
                                   "awgClients": [{"id": 1, "name": "alice", "email": "alice", "enable": True,
                                                   "config": "[Interface]\nS1 = 18\nHeaderProtectionKey = " + VAULT_KEY + "\n"}]})
        out = self.verify(expect_rc=2)
        self.assertIn("AmneziaWG 3.0: the .conf of client alice has another HeaderProtectionKey than the server", out)

    def test_verify_warns_about_a_server_still_on_2_0_and_a_host_without_3_0(self):
        self.seed_v2_in_use(awgConfDir=str(self.tmp))
        out = self.verify()
        self.assertIn("WARNING: AmneziaWG 3.0: the panel's AWG server has no HeaderProtectionKey and S1, S3, S4 below 12"
                      " (a server in use keeps its set until site.yml runs with awg_obfuscation_apply=true)", out)
        self.seed_v2_in_use(awgConfDir=str(self.tmp), supportsV3=False)
        out = self.verify()
        self.assertIn("WARNING: AmneziaWG 3.0: the kernel module on real does not take the 3.0 parameters", out)
        self.assertNotIn("awg/client/1/config", self.reads)


if __name__ == "__main__":
    unittest.main(verbosity=2)
