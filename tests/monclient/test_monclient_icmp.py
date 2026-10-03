"""Role monclient's net.ipv4.ping_group_range (roles/monclient/tasks/icmp.yml) and its verify.yml check
(tasks/verify_icmp.yml); no host is touched: the kernel's /proc/sys/net/ipv4/ping_group_range and the sysctl.d file
are files in a temp dir, the mon-client group is the test runner's own group.

    python3 tests/monclient/test_monclient_icmp.py      # needs ansible-playbook on PATH
"""

import grp
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
GID = os.getgid()
GROUP = grp.getgrgid(GID).gr_name


class MonclientIcmpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="monclienticmp-"))
        self.proc = self.tmp / "ping_group_range"
        self.conf = self.tmp / "sysctl.d" / "60-mon-client-ping.conf"
        self.conf.parent.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def kernel(self, lo, hi):
        """The running kernel's range as /proc prints it (tab-separated)."""
        self.proc.write_text(f"{lo}\t{hi}\n")

    def play(self, step, expect_rc=0, **extra):
        env = dict(os.environ, ANSIBLE_CONFIG=str(REPO / "ansible.cfg"), ANSIBLE_ROLES_PATH=str(REPO / "roles"),
                   ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default")
        extra_vars = {"icmp_step": step, "monclient_user": GROUP, "monclient_ping_group_range_proc": str(self.proc),
                      "monclient_ping_group_range_file": str(self.conf)}
        extra_vars.update(extra)
        run = subprocess.run(["ansible-playbook", "-i", str(HERE / "inventory.yml"), str(HERE / "icmp.yml"),
                              "-e", json.dumps(extra_vars)], env=env, capture_output=True, text=True, check=False)
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, expect_rc, out[-4000:])
        return out

    def converge(self):
        return self.play("converge")

    def assert_range(self, lo, hi):
        self.assertEqual(self.proc.read_text().split(), [str(lo), str(hi)])
        self.assertIn(f"\nnet.ipv4.ping_group_range = {lo} {hi}\n", self.conf.read_text())

    def assert_idempotent(self):
        out = self.converge()
        self.assertRegex(out, r"mon-client\s+: ok=\d+\s+changed=0 ")

    def test_closed_range_becomes_the_group_alone(self):
        self.kernel(1, 0)  # the kernel's default: nobody
        self.converge()
        self.assert_range(GID, GID)
        self.assert_idempotent()

    def test_open_range_is_kept_and_written_for_boots(self):
        self.kernel(0, 2147483647)  # systemd's default: every group
        out = self.converge()
        self.assertEqual(self.proc.read_text(), "0\t2147483647\n", "the kernel's range was rewritten")
        self.assertRegex(out, r"mon-client\s+: ok=\d+\s+changed=1 ")  # the file only
        self.assertIn("\nnet.ipv4.ping_group_range = 0 2147483647\n", self.conf.read_text())
        self.assert_idempotent()

    def test_range_without_the_group_is_widened_not_narrowed(self):
        self.kernel(GID + 10, GID + 20)
        self.converge()
        self.assert_range(GID, GID + 20)
        self.assert_idempotent()

    def test_verify_passes_after_converge(self):
        self.kernel(1, 0)
        self.converge()
        out = self.play("verify")
        self.assertIn(f"takes in group {GROUP}", out)

    def test_verify_names_a_kernel_range_without_the_group(self):
        self.kernel(1, 0)
        self.converge()
        self.kernel(1, 0)  # e.g. a sysctl.d file sorted after ours put it back
        out = self.play("verify", expect_rc=2)
        self.assertIn('net.ipv4.ping_group_range is "1 0" now', out)
        self.assertIn(f"group {GROUP} is GID {GID}", out)

    def test_verify_needs_the_sysctl_file_for_boots(self):
        self.kernel(0, 2147483647)
        out = self.play("verify", expect_rc=2)
        self.assertIn("not set in " + str(self.conf), out)

    def test_verify_names_a_missing_group(self):
        self.kernel(0, 2147483647)
        self.converge()
        out = self.play("verify", expect_rc=2, monclient_user="3axui-no-such-group")
        self.assertIn("cannot send ICMP echo (the host reachability check of a diagnostic sweep): no group 3axui-no-such-group", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
