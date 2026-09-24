"""wipe.yml on local stand-in boxes; no real host is touched.

    python3 tests/wipe/test_wipe.py      # needs ansible-playbook on PATH

Every test lays out what the roles and install.sh leave on each box (under a temp dir, see inventory.yml),
runs wipe.yml and checks what is gone, what is kept, and that a second wipe changes nothing.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

NGINX_CONF = """user www-data;
events {}
# --- BEGIN 3AX-UI STREAM ---
stream { include /etc/nginx/stream-enabled/*.conf; }
# --- END 3AX-UI STREAM ---
http { include /etc/nginx/conf.d/*.conf; }
"""

# Files per box, relative to the box directory.
PANEL = ["etc/x-ui/x-ui.db", "etc/x-ui/tls/panel.crt", "etc/x-ui/tls/panel.key", "usr/local/x-ui/x-ui",
         "usr/local/x-ui/bin/xray-linux-amd64", "usr/bin/x-ui", "var/log/x-ui/3xipl.log", "root/3ax-ui-install.sh",
         "etc/amnezia/amneziawg/awg0.conf", "etc/wireguard/wg0.conf", "etc/nginx/stream-enabled/3ax-ui.conf",
         "etc/nginx/conf.d/3ax-ui.conf", "etc/nginx/conf.d/other-site.conf"]
HOP = ["etc/x-ui/proxy.json", "etc/x-ui/chain/secret", "etc/x-ui/chain/document.json", "etc/x-ui/chain-join.url",
       "usr/local/x-ui/x-ui", "usr/bin/x-ui", "var/log/x-ui/x.log", "root/3ax-ui-install.sh",
       "root/.3ax-ui-join-token", "root/cert/ip/fullchain.pem", "root/cert/ip/privkey.pem",
       "root/.acme.sh/account.conf", "root/.acme.sh/203.0.113.7_ecc/203.0.113.7.cer"]
MONSERVER = ["usr/local/bin/mon-server", "etc/mon-server/config.json", "var/lib/mon-server/mon-server.db",
             "var/lib/mon-server/mon-server.db-wal", "var/lib/mon-server/certs/acme/key.pem",
             "var/cache/3ax-ui-orchestrator/mon-server/v0.1.0-stand.3/mon-server"]
MONCLIENT = ["usr/local/bin/mon-client", "usr/local/bin/xray", "etc/mon-client/le-staging-roots.pem",
             "var/lib/mon-client/state.json", "var/cache/3ax-ui-orchestrator/mon-client/v0.1.0-stand.3/mon-client",
             "var/cache/3ax-ui-orchestrator/xray/v26.3.27/xray"]


class WipeTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="wipetest-"))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    # --- helpers -------------------------------------------------------------------------------------
    def seed(self):
        for box, files in (("real", PANEL), ("bridge", HOP), ("proxy", HOP), ("mon-server", MONSERVER),
                           ("mon-client", MONCLIENT)):
            for rel in files:
                path = self.root / box / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(rel)
        (self.root / "real/etc/nginx/nginx.conf").write_text(NGINX_CONF)

    def play(self, *extra, expect_rc=0):
        env = dict(os.environ, WIPE_TEST_ROOT=str(self.root), ANSIBLE_CONFIG=str(REPO / "ansible.cfg"),
                   ANSIBLE_ROLES_PATH=str(REPO / "roles"), ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default")
        run = subprocess.run(["ansible-playbook", "-i", str(HERE / "inventory.yml"), str(REPO / "wipe.yml"), *extra],
                             env=env, capture_output=True, text=True, check=False)
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, expect_rc, out[-6000:])
        return out

    def wipe(self, *extra):
        return self.play("-e", "wipe_confirm=yes", *extra)

    def exists(self, box, rel):
        return (self.root / box / rel).exists()

    def assert_unchanged(self, out):
        for host in ("real", "bridge", "proxy", "mon-server", "mon-client"):
            self.assertRegex(out, rf"{re.escape(host)}\s+: ok=\d+\s+changed=0 ", f"{host} changed on a repeated wipe")

    # --- scenarios -----------------------------------------------------------------------------------
    def test_refuses_without_confirmation(self):
        self.seed()
        out = self.play(expect_rc=2)
        self.assertIn("rerun with -e wipe_confirm=yes", out)
        self.assertTrue(self.exists("real", "etc/x-ui/x-ui.db"))

    def test_wipe_keeps_certificates_and_repeats_cleanly(self):
        self.seed()
        self.wipe()
        for rel in ("etc/x-ui", "usr/local/x-ui", "usr/bin/x-ui", "var/log/x-ui", "root/3ax-ui-install.sh",
                    "etc/amnezia/amneziawg/awg0.conf", "etc/wireguard/wg0.conf",
                    "etc/nginx/stream-enabled/3ax-ui.conf", "etc/nginx/conf.d/3ax-ui.conf"):
            self.assertFalse(self.exists("real", rel), f"panel: {rel} left")
        self.assertTrue(self.exists("real", "etc/nginx/conf.d/other-site.conf"), "an unrelated nginx site was removed")
        nginx = (self.root / "real/etc/nginx/nginx.conf").read_text()
        self.assertNotIn("3AX-UI", nginx)
        self.assertIn("http { include", nginx)
        for box in ("bridge", "proxy"):
            for rel in ("etc/x-ui", "usr/local/x-ui", "usr/bin/x-ui", "var/log/x-ui", "root/3ax-ui-install.sh",
                        "root/.3ax-ui-join-token"):
                self.assertFalse(self.exists(box, rel), f"{box}: {rel} left")
            self.assertTrue(self.exists(box, "root/cert/ip/fullchain.pem"), f"{box}: LE certificate removed")
            self.assertTrue(self.exists(box, "root/.acme.sh/203.0.113.7_ecc/203.0.113.7.cer"))
        for rel in ("usr/local/bin/mon-server", "etc/mon-server", "var/lib/mon-server/mon-server.db",
                    "var/lib/mon-server/mon-server.db-wal", "var/cache/3ax-ui-orchestrator/mon-server"):
            self.assertFalse(self.exists("mon-server", rel), f"mon-server: {rel} left")
        self.assertTrue(self.exists("mon-server", "var/lib/mon-server/certs/acme/key.pem"), "mon-server certs removed")
        for rel in ("usr/local/bin/mon-client", "usr/local/bin/xray", "etc/mon-client", "var/lib/mon-client",
                    "var/cache/3ax-ui-orchestrator/mon-client", "var/cache/3ax-ui-orchestrator/xray"):
            self.assertFalse(self.exists("mon-client", rel), f"mon-client: {rel} left")

        self.assert_unchanged(self.wipe())

    def test_flags_delete_certificates(self):
        self.seed()
        self.wipe("-e", "hop_wipe_le_cert=true", "-e", "monserver_wipe_certs=true")
        for box in ("bridge", "proxy"):
            self.assertFalse(self.exists(box, "root/cert/ip"))
            self.assertFalse(self.exists(box, "root/.acme.sh/203.0.113.7_ecc"))
            self.assertTrue(self.exists(box, "root/.acme.sh/account.conf"), "acme.sh itself was removed")
        self.assertFalse(self.exists("mon-server", "var/lib/mon-server"))
        self.assert_unchanged(self.wipe("-e", "hop_wipe_le_cert=true", "-e", "monserver_wipe_certs=true"))

    def test_bare_boxes(self):
        self.assert_unchanged(self.wipe("-e", "hop_wipe_le_cert=true"))

    def test_tags_wipe_one_group(self):
        self.seed()
        self.wipe("--tags", "monclient")
        self.assertFalse(self.exists("mon-client", "var/lib/mon-client"))
        self.assertTrue(self.exists("real", "etc/x-ui/x-ui.db"))
        self.assertTrue(self.exists("bridge", "etc/x-ui/proxy.json"))
        self.assertTrue(self.exists("mon-server", "var/lib/mon-server/mon-server.db"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
