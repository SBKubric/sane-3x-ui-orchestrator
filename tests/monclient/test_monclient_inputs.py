"""Role monclient's inputs (roles/monclient/tasks/inputs.yml: the contract-3 paths vocabulary, mon_gomemlimit) and
the GOMEMLIMIT line of its unit; no host is touched.

    python3 tests/monclient/test_monclient_inputs.py      # needs ansible-playbook on PATH
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent


class MonclientInputsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="monclienttest-"))
        self.unit = self.tmp / "mon-client.service"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def play(self, extra_vars=None, expect_rc=0):
        env = dict(os.environ, ANSIBLE_CONFIG=str(REPO / "ansible.cfg"), ANSIBLE_ROLES_PATH=str(REPO / "roles"),
                   ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default")
        extra = dict(extra_vars or {}, unit_dest=str(self.unit))
        run = subprocess.run(["ansible-playbook", "-i", str(HERE / "inventory.yml"), str(HERE / "inputs.yml"),
                              "-e", json.dumps(extra)], env=env, capture_output=True, text=True, check=False)
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, expect_rc, out[-4000:])
        return out

    def test_default_paths_are_direct_and_hops(self):
        out = self.play()
        self.assertIn('paths ["direct", "hops"]', out)

    def test_hop_paths_are_accepted(self):
        self.play({"mon_paths": ["direct", "edge:proxy", "inner:bridge-2"]})

    def test_old_proxy_path_is_refused(self):
        out = self.play({"mon_paths": ["direct", "proxy"]}, expect_rc=2)
        self.assertIn("contract 3 calls it hops", out)

    def test_malformed_paths_are_refused(self):
        for paths in (["edge:Proxy"], ["edge:"], ["hop:proxy"], [], "direct"):
            with self.subTest(paths=paths):
                self.play({"mon_paths": paths}, expect_rc=2)

    def test_unit_carries_gomemlimit(self):
        self.play()
        self.assertIn("Environment=GOMEMLIMIT=128MiB\n", self.unit.read_text())

    def test_empty_gomemlimit_leaves_the_unit_without_it(self):
        self.play({"mon_gomemlimit": ""})
        self.assertNotIn("GOMEMLIMIT", self.unit.read_text())

    def test_malformed_gomemlimit_is_refused(self):
        self.play({"mon_gomemlimit": "128M"}, expect_rc=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
