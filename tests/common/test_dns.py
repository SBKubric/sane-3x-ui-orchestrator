"""Role common's DNS check (orchestrator#62) and its verify.yml step against local stand-in nameservers; no real host
or resolver is touched.

    python3 tests/common/test_dns.py      # needs ansible-playbook on PATH

roles/common/files/dnscheck.py asks every nameserver of a resolv.conf directly (the root's NS, UDP, short timeout) and
says what the file should look like: the dead servers dropped, `options timeout:1 attempts:2`, common_dns_fallback when
none is left. roles/common/tasks/dns.yml writes that (the original kept once), fails when nothing answers and only warns
under systemd-resolved or another manager of the file; roles/common/tasks/verify_dns.yml warns when a lookup the way
the libc stub does it takes longer than common_dns_slow_ms. The nameservers here are UDP sockets on 127.0.0.1-127.0.0.4
sharing one free port: one answers, one says nothing, one refuses.
"""

import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
SCRIPT = REPO / "roles" / "common" / "files" / "dnscheck.py"

OK, SILENT, REFUSED = "127.0.0.1", "127.0.0.2", "127.0.0.3"
SPARE = "127.0.0.4"  # silent unless a test makes it answer (the fallback)


class Nameserver:
    """A UDP nameserver stand-in: answers NOERROR (an empty answer section), REFUSED, or nothing at all."""

    def __init__(self, addr, port, mode):
        self.mode, self.delay, self.queries = mode, 0.0, 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((addr, port))
        self.sock.settimeout(0.2)
        self.running = True
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while self.running:
            try:
                data, peer = self.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            self.queries += 1
            if self.mode == "silent" or len(data) < 12:
                continue
            if self.delay:
                time.sleep(self.delay)
            qid, flags = struct.unpack("!HH", data[:4])
            rcode = 5 if self.mode == "refused" else 0
            reply = struct.pack("!HHHHHH", qid, 0x8000 | (flags & 0x0100) | 0x0080 | rcode, 1, 0, 0, 0) + data[12:]
            try:
                self.sock.sendto(reply, peer)
            except OSError:
                pass

    def close(self):
        self.running = False
        self.thread.join()
        self.sock.close()


def start_nameservers():
    """One free UDP port on all four loopback addresses (retried on a clash)."""
    for _ in range(20):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind((OK, 0))
        port = probe.getsockname()[1]
        probe.close()
        servers = {}
        try:
            for addr, mode in ((OK, "ok"), (SILENT, "silent"), (REFUSED, "refused"), (SPARE, "silent")):
                servers[addr] = Nameserver(addr, port, mode)
            return port, servers
        except OSError:
            for s in servers.values():
                s.close()
    raise RuntimeError("no free UDP port shared by 127.0.0.1-4")


class Base(unittest.TestCase):
    def setUp(self):
        self.port, self.ns = start_nameservers()
        self.dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.dir.name)
        self.resolv = self.tmp / "resolv.conf"
        self.upstream = self.tmp / "run-resolve" / "resolv.conf"
        self.backup = self.tmp / "resolv.conf.orig"

    def tearDown(self):
        for s in self.ns.values():
            s.close()
        self.dir.cleanup()

    def write(self, text, path=None):
        path = path or self.resolv
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


class DnscheckScriptTest(Base):
    def run_script(self, *args, expect_rc=0):
        run = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, expect_rc, run.stdout + run.stderr)
        return json.loads(run.stdout) if expect_rc == 0 else run

    def check(self, *extra):
        return self.run_script("check", "--resolv-conf", str(self.resolv), "--upstream-conf", str(self.upstream),
                               "--port", str(self.port), "--timeout", "0.5", "--tries", "1",
                               "--options", "timeout:1,attempts:2", "--backup", str(self.backup), *extra)

    def test_all_servers_answer_leaves_the_file_alone(self):
        self.write(f"nameserver {OK}\n")
        out = self.check()
        self.assertEqual(out["mode"], "file")
        self.assertEqual(out["answering"], [OK])
        self.assertEqual(out["dead"], [])
        self.assertIsNone(out["content"])

    def test_dead_servers_are_dropped_and_the_options_set(self):
        self.write(f"# from the hoster\nsearch example.net\nnameserver {SILENT}\nnameserver {OK}\n"
                   f"nameserver {REFUSED}\noptions rotate timeout:5\n")
        out = self.check()
        self.assertEqual(out["answering"], [OK])
        self.assertEqual(out["dead"], [SILENT, REFUSED])
        errors = {s["server"]: s["error"] for s in out["servers"]}
        self.assertEqual(errors, {SILENT: "timeout", OK: "", REFUSED: "REFUSED"})
        self.assertEqual(out["content"],
                         f"# 3ax-ui: role common dropped the nameservers that did not answer: {SILENT}, {REFUSED}\n"
                         f"# 3ax-ui: the original is {self.backup}\n"
                         f"# from the hoster\nsearch example.net\nnameserver {OK}\noptions rotate\n"
                         f"options timeout:1 attempts:2\n")

    def test_a_rewritten_file_is_rewritten_without_doubling_the_note(self):
        self.write(f"# 3ax-ui: role common dropped the nameservers that did not answer: {SILENT}\n"
                   f"# 3ax-ui: the original is {self.backup}\nnameserver {OK}\nnameserver {REFUSED}\n"
                   f"options timeout:1 attempts:2\n")
        out = self.check()
        self.assertEqual(out["content"],
                         f"# 3ax-ui: role common dropped the nameservers that did not answer: {REFUSED}\n"
                         f"# 3ax-ui: the original is {self.backup}\nnameserver {OK}\noptions timeout:1 attempts:2\n")

    def test_nothing_answering_writes_nothing(self):
        self.write(f"nameserver {SILENT}\nnameserver {REFUSED}\n")
        out = self.check()
        self.assertEqual(out["answering"], [])
        self.assertIsNone(out["content"])

    def test_the_fallback_takes_over_when_nothing_answers(self):
        self.ns[SPARE].mode = "ok"
        self.write(f"nameserver {SILENT}\nnameserver {REFUSED}\n")
        out = self.check("--fallback", f"{SPARE},{SILENT}")
        self.assertEqual(out["answering"], [SPARE])
        self.assertEqual([f["server"] for f in out["fallback"]], [SPARE])  # SILENT is already known dead
        self.assertIn(f"nameserver {SPARE}\noptions timeout:1 attempts:2\n", out["content"])
        self.assertNotIn(f"nameserver {SILENT}", out["content"])
        self.assertIn(f"common_dns_fallback: {SPARE}", out["content"])

    def test_the_fallback_is_not_asked_while_a_server_answers(self):
        self.ns[SPARE].mode = "ok"
        self.write(f"nameserver {SILENT}\nnameserver {OK}\n")
        out = self.check("--fallback", SPARE)
        self.assertEqual(out["fallback"], [])
        self.assertEqual(self.ns[SPARE].queries, 0)
        self.assertNotIn(SPARE, out["content"])

    def test_a_dead_fallback_writes_nothing(self):
        self.write(f"nameserver {SILENT}\n")
        out = self.check("--fallback", SPARE)
        self.assertEqual(out["answering"], [])
        self.assertIsNone(out["content"])

    def test_the_systemd_resolved_stub_checks_its_upstreams(self):
        self.write("nameserver 127.0.0.53\noptions edns0 trust-ad\n")
        self.write(f"nameserver {OK}\nnameserver {SILENT}\n", self.upstream)
        out = self.check()
        self.assertEqual(out["mode"], "resolved")
        self.assertEqual(out["answering"], [OK])
        self.assertEqual(out["dead"], [SILENT])
        self.assertIsNone(out["content"])

    def test_a_link_to_the_resolved_upstream_list_is_resolved_too(self):
        self.write(f"nameserver {SILENT}\nnameserver {OK}\n", self.upstream)
        self.resolv.symlink_to(self.upstream)
        out = self.check()
        self.assertEqual(out["mode"], "resolved")
        self.assertEqual(out["dead"], [SILENT])
        self.assertIsNone(out["content"])

    def test_a_link_elsewhere_is_managed_and_left_alone(self):
        other = self.tmp / "run-resolvconf" / "resolv.conf"
        self.write(f"nameserver {SILENT}\nnameserver {OK}\n", other)
        self.resolv.symlink_to(other)
        out = self.check()
        self.assertEqual(out["mode"], "managed")
        self.assertEqual(out["dead"], [SILENT])
        self.assertIsNone(out["content"])

    def test_bad_arguments_and_a_missing_file_are_refused(self):
        self.write(f"nameserver {OK}\n")
        run = self.run_script("check", "--resolv-conf", str(self.resolv), "--fallback", "example.com", expect_rc=2)
        self.assertIn("not an IP address", run.stderr)
        run = self.run_script("check", "--resolv-conf", str(self.tmp / "missing"), expect_rc=2)
        self.assertIn("cannot read", run.stderr)

    def test_time_follows_the_libc_order_and_timeout(self):
        self.write(f"nameserver {SILENT}\nnameserver {OK}\noptions timeout:1 attempts:2\n")
        out = self.run_script("time", "--resolv-conf", str(self.resolv), "--port", str(self.port))
        self.assertEqual(out["answered_by"], OK)
        self.assertGreaterEqual(out["elapsed_ms"], 1000)
        self.assertEqual([(t["server"], t["ok"]) for t in out["tries"]], [(SILENT, False), (OK, True)])

    def test_time_of_a_good_first_server_is_short(self):
        self.write(f"nameserver {OK}\nnameserver {SILENT}\n")
        out = self.run_script("time", "--resolv-conf", str(self.resolv), "--port", str(self.port))
        self.assertEqual(out["answered_by"], OK)
        self.assertLess(out["elapsed_ms"], 500)

    def test_time_with_nothing_answering(self):
        self.write(f"nameserver {SILENT}\nnameserver {REFUSED}\noptions timeout:1 attempts:1\n")
        out = self.run_script("time", "--resolv-conf", str(self.resolv), "--port", str(self.port))
        self.assertIsNone(out["answered_by"])
        self.assertEqual(len(out["tries"]), 2)


class DnsRoleTest(Base):
    """tasks/dns.yml and tasks/verify_dns.yml through ansible-playbook on the local box."""

    def play(self, playbook="dns.yml", *extra, expect_rc=0, **overrides):
        variables = {"common_dns_resolv_conf": str(self.resolv), "common_dns_resolved_upstream_conf": str(self.upstream),
                     "common_dns_backup": str(self.backup), "common_dns_port": self.port,
                     "common_dns_probe_timeout": 0.5, "common_dns_probe_tries": 1}
        variables.update(overrides)
        env = dict(os.environ, ANSIBLE_CONFIG=str(REPO / "ansible.cfg"), ANSIBLE_ROLES_PATH=str(REPO / "roles"),
                   ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default")
        run = subprocess.run(["ansible-playbook", "-i", str(HERE / "inventory.yml"), str(HERE / playbook),
                              "-e", json.dumps(variables), *extra], env=env, capture_output=True, text=True, check=False)
        out = run.stdout + run.stderr
        self.assertEqual(run.returncode, expect_rc, out[-5000:])
        return " ".join(out.split())

    def assertChanged(self, out, n):  # noqa: N802
        self.assertRegex(out, rf"real : ok=\d+ changed={n} ")

    def test_dead_servers_are_dropped_once_and_the_original_kept(self):
        original = f"nameserver {SILENT}\nnameserver {OK}\n"
        self.write(original)
        out = self.play()
        self.assertChanged(out, 2)  # the backup and the file
        self.assertIn(f"dropped the nameservers that did not answer: {SILENT}", out)
        text = self.resolv.read_text()
        self.assertNotIn(SILENT, text.replace(f"answer: {SILENT}", ""))
        self.assertIn(f"nameserver {OK}\noptions timeout:1 attempts:2\n", text)
        self.assertEqual(self.backup.read_text(), original)
        out = self.play()
        self.assertChanged(out, 0)
        self.assertEqual(self.resolv.read_text(), text)

    def test_an_earlier_original_is_not_overwritten(self):
        self.backup.write_text("nameserver 192.0.2.1\n")
        self.write(f"nameserver {SILENT}\nnameserver {OK}\n")
        out = self.play()
        self.assertChanged(out, 1)
        self.assertEqual(self.backup.read_text(), "nameserver 192.0.2.1\n")

    def test_check_mode_writes_nothing(self):
        original = f"nameserver {SILENT}\nnameserver {OK}\n"
        self.write(original)
        self.play("dns.yml", "--check", "--diff")
        self.assertEqual(self.resolv.read_text(), original)
        self.assertFalse(self.backup.exists())

    def test_nothing_answering_fails_clearly(self):
        original = f"nameserver {SILENT}\nnameserver {REFUSED}\n"
        self.write(original)
        out = self.play(expect_rc=2)
        self.assertIn(f"none of the DNS servers in {self.resolv} answers ({SILENT}: timeout, {REFUSED}: REFUSED)", out)
        self.assertIn("common_dns_fallback", out)
        self.assertEqual(self.resolv.read_text(), original)

    def test_the_fallback_is_written_when_nothing_answers(self):
        self.ns[SPARE].mode = "ok"
        self.write(f"nameserver {SILENT}\n")
        out = self.play(common_dns_fallback=[SPARE])
        self.assertChanged(out, 2)
        self.assertIn(f"nameserver {SPARE}\n", self.resolv.read_text())

    def test_systemd_resolved_is_only_warned_about(self):
        self.write("nameserver 127.0.0.53\n")
        self.write(f"nameserver {OK}\nnameserver {SILENT}\n", self.upstream)
        out = self.play()
        self.assertChanged(out, 0)
        self.assertIn(f"WARNING: upstream DNS servers of systemd-resolved that do not answer: {SILENT}", out)
        self.assertEqual(self.resolv.read_text(), "nameserver 127.0.0.53\n")

    def test_systemd_resolved_without_an_answering_upstream_fails(self):
        self.write("nameserver 127.0.0.53\n")
        self.write(f"nameserver {SILENT}\n", self.upstream)
        out = self.play(expect_rc=2, common_dns_fallback=[SPARE])
        self.assertIn(f"none of the upstream DNS servers of systemd-resolved answers ({SILENT}: timeout)", out)
        self.assertIn("/etc/systemd/resolved.conf.d/", out)

    def test_a_managed_link_is_only_warned_about(self):
        other = self.tmp / "run-resolvconf" / "resolv.conf"
        self.write(f"nameserver {SILENT}\nnameserver {OK}\n", other)
        self.resolv.symlink_to(other)
        out = self.play()
        self.assertChanged(out, 0)
        self.assertIn(f"WARNING: DNS servers in {self.resolv} that do not answer: {SILENT}", out)
        self.assertTrue(self.resolv.is_symlink())

    def test_verify_warns_about_a_slow_lookup(self):
        self.write(f"nameserver {SILENT}\nnameserver {OK}\noptions timeout:1 attempts:2\n")
        out = self.play("verify_dns.yml")
        self.assertChanged(out, 0)
        self.assertRegex(out, rf"WARNING: a DNS lookup on real took \d+ ms \(more than 1000 ms\): {SILENT} did not"
                              rf" answer \(timeout\), {OK} did")

    def test_verify_reports_a_quick_lookup(self):
        self.write(f"nameserver {OK}\nnameserver {SILENT}\n")
        out = self.play("verify_dns.yml")
        self.assertRegex(out, rf"a DNS lookup on real took \d+ ms \(answered by {OK}\)")
        self.assertNotIn("WARNING", out)

    def test_verify_warns_when_nothing_answers(self):
        self.write(f"nameserver {SILENT}\noptions timeout:1 attempts:1\n")
        out = self.play("verify_dns.yml")
        self.assertIn(f"WARNING: no DNS server in {self.resolv} answered a lookup on real", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
