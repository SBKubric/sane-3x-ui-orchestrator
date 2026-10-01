"""roles/showcase/files/dnsexit.py (orchestrator#53) against a stand-in for DNSExit; no real DNS or API is touched.

    python3 tests/showcase/test_dnsexit_script.py

The record already right (no post), wrong or missing (one post, read back from the nameserver), the API refusing (the
key never printed), the 4-minute limit kept across runs through the state file, a nameserver that does not answer
(the state decides), --check-only, bad arguments.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
SCRIPT = REPO / "roles" / "showcase" / "files" / "dnsexit.py"
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True

from mock_dnsexit import MockDNSExit  # noqa: E402

KEY = "dnsexit-secret-key-42"


class DNSExitScriptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dnsexit-"))
        self.dns = MockDNSExit(key=KEY).start()

    def tearDown(self):
        self.dns.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_script(self, *extra, key=KEY, content="203.0.113.10", name="sub.example.test", interval="240",
                   nameservers=None):
        env = dict(os.environ, DNSEXIT_API_KEY=key)
        run = subprocess.run([sys.executable, str(SCRIPT), "--api-url", self.dns.api_url, "--zone", "example.test",
                              "--name", name, "--content", content, "--nameservers", nameservers or self.dns.nameserver,
                              "--state", str(self.tmp / "state.json"), "--min-interval", interval, "--wait", "3",
                              "--poll", "0.2", "--timeout", "0.5", *extra],
                             env=env, capture_output=True, text=True, check=False)
        self.assertNotIn(KEY, run.stdout + run.stderr, "the API key reached the output")
        return run.returncode, json.loads(run.stdout)

    def test_a_record_already_right_is_not_posted(self):
        self.dns.records["sub.example.test"] = ["203.0.113.10"]
        rc, out = self.run_script()
        self.assertEqual((rc, out["action"], out["current"]), (0, "none", ["203.0.113.10"]))
        self.assertEqual(self.dns.posts, [])

    def test_a_wrong_record_is_posted_and_read_back(self):
        self.dns.records["sub.example.test"] = ["198.51.100.1", "198.51.100.2"]
        rc, out = self.run_script("--ttl", "5")
        self.assertEqual((rc, out["action"], out["current"]), (0, "posted", ["203.0.113.10"]), out)
        self.assertEqual(self.dns.posts, [{"apikey": KEY, "body": {
            "domain": "example.test",
            "add": {"type": "A", "name": "sub", "content": "203.0.113.10", "ttl": 5, "overwrite": True}}}])
        self.assertIn("now points at 203.0.113.10", out["message"])

    def test_a_missing_record_is_posted(self):
        rc, out = self.run_script()
        self.assertEqual((rc, out["action"]), (0, "posted"))
        self.assertEqual(self.dns.records["sub.example.test"], ["203.0.113.10"])

    def test_the_zone_apex_is_the_empty_name(self):
        rc, _ = self.run_script(name="example.test")
        self.assertEqual(rc, 0)
        self.assertEqual(self.dns.posts[0]["body"]["add"]["name"], "")

    def test_a_refusal_fails_without_the_key(self):
        self.dns.refuse = {"code": 2, "message": "API Key Authentication Error"}
        rc, out = self.run_script()
        self.assertEqual((rc, out["action"]), (1, "error"))
        self.assertIn("code 2 API Key Authentication Error", out["message"])

    def test_a_wrong_key_is_refused(self):
        rc, out = self.run_script(key="another-key")
        self.assertEqual(rc, 1)
        self.assertIn("code 2", out["message"])

    def test_the_rate_limit_is_kept_across_runs(self):
        rc, out = self.run_script(interval="2")
        self.assertEqual((rc, out["waited"]), (0, 0))
        started = time.monotonic()
        rc, out = self.run_script(content="203.0.113.11", interval="2")
        self.assertEqual((rc, out["action"]), (0, "posted"))
        self.assertGreaterEqual(time.monotonic() - started, 1.0, "the second post did not wait for the limit")
        self.assertEqual(len(self.dns.posts), 2)

    def test_a_silent_nameserver_leaves_it_to_the_state(self):
        self.dns.silent = True
        rc, out = self.run_script()
        # Posted (nothing known), but nobody could confirm it: not a failure.
        self.assertEqual((rc, out["action"], out["current"]), (0, "posted", None))
        self.assertIn("no nameserver answered to confirm it", out["message"])
        rc, out = self.run_script()
        self.assertEqual((rc, out["action"]), (0, "unknown"))
        self.assertEqual(len(self.dns.posts), 1, "the same content was posted again")

    def test_the_next_nameserver_is_asked(self):
        self.dns.records["sub.example.test"] = ["203.0.113.10"]
        rc, out = self.run_script(nameservers=f"127.0.0.1:9,{self.dns.nameserver}")
        self.assertEqual((rc, out["action"], out["nameserver"]), (0, "none", self.dns.nameserver))

    def test_check_only_reads_and_never_posts(self):
        self.dns.records["sub.example.test"] = ["198.51.100.1"]
        rc, out = self.run_script("--check-only", key="")
        self.assertEqual((rc, out["action"], out["current"]), (0, "mismatch", ["198.51.100.1"]))
        self.dns.silent = True
        rc, out = self.run_script("--check-only", key="")
        self.assertEqual((rc, out["action"]), (0, "unknown"))
        self.assertEqual(self.dns.posts, [])

    def test_the_key_can_come_on_stdin(self):
        run = subprocess.run([sys.executable, str(SCRIPT), "--api-url", self.dns.api_url, "--zone", "example.test",
                              "--name", "sub.example.test", "--content", "203.0.113.10", "--nameservers",
                              self.dns.nameserver, "--state", str(self.tmp / "state.json"), "--wait", "2", "--poll",
                              "0.2", "--key-stdin"], input=KEY + "\n", env=dict(os.environ, DNSEXIT_API_KEY="wrong"),
                             capture_output=True, text=True, check=False)
        self.assertEqual((run.returncode, json.loads(run.stdout)["action"]), (0, "posted"), run.stdout)
        self.assertEqual(self.dns.posts[0]["apikey"], KEY)

    def test_bad_arguments(self):
        self.assertEqual(self.run_script(name="sub.example.org")[0], 2)
        self.assertEqual(self.run_script(content="not-an-ip")[0], 2)
        self.assertEqual(self.run_script(key="")[0], 2)
        self.assertEqual(self.dns.posts, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
