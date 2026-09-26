"""The probe-links step of verify.yml on the mon-server host (roles/monserver/tasks/verify_paths.yml), fed with
Settings -> Check answers; no host is touched.

    python3 tests/monserver/test_verify_paths.py      # needs ansible-playbook on PATH
"""

import json
import os
import subprocess
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
CHAIN = ("-i", str(REPO / "tests" / "panel" / "hops.yml"))


def play(probe_items, *extra, expect_rc=0, case=None):
    env = dict(os.environ, ANSIBLE_CONFIG=str(REPO / "ansible.cfg"), ANSIBLE_ROLES_PATH=str(REPO / "roles"),
               ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default")
    run = subprocess.run(["ansible-playbook", "-i", str(HERE / "inventory.yml"), *extra, str(HERE / "verify_paths.yml"),
                          "-e", json.dumps({"probe_items": probe_items})],
                         env=env, capture_output=True, text=True, check=False)
    out = run.stdout + run.stderr
    case.assertEqual(run.returncode, expect_rc, out[-4000:])
    return out


class VerifyPathsTest(unittest.TestCase):
    def test_chain_with_links_on_every_hop_passes(self):
        out = play({"direct": 2, "inner:bridge": 2, "edge:proxy": 2}, *CHAIN, case=self)
        self.assertIn("probe links per path: direct=2, edge:proxy=2, inner:bridge=2", out)

    def test_hop_the_panel_does_not_serve_is_named(self):
        out = play({"direct": 2, "edge:proxy": 2}, *CHAIN, expect_rc=2, case=self)
        self.assertIn("inner:bridge: not served by the panel (hop not joined?)", out)

    def test_hop_without_links_is_named(self):
        out = play({"direct": 2, "inner:bridge": 0, "edge:proxy": 2}, *CHAIN, expect_rc=2, case=self)
        self.assertIn("inner:bridge: no probe links", out)

    def test_proxy_or_an_unknown_hop_next_to_a_chain_is_named(self):
        out = play({"direct": 2, "inner:bridge": 2, "edge:proxy": 2, "edge:old": 1, "proxy": 2}, *CHAIN,
                   expect_rc=2, case=self)
        self.assertIn("edge:old: served by the panel, not in the inventory", out)
        self.assertIn("proxy: served by the panel, not in the inventory", out)

    def test_without_a_chain_direct_is_enough(self):
        out = play({"direct": 2, "proxy": 0}, case=self)
        self.assertIn("probe links per path: direct=2, proxy=0", out)

    def test_direct_without_links_is_named(self):
        out = play({"direct": 0}, expect_rc=2, case=self)
        self.assertIn("direct: no probe links", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
