import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

AI_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AI_DIR))
import hornet_tools as ht  # noqa: E402

BOG = timezone(timedelta(hours=-5))
FP = "SHA256:Y8iGrwsAhbrILKvbyCfJT3er/NuG3k3KlqQIVChZ/SM"
ISO_PUBKEY = f"2026-09-25T10:00:05.123456-05:00 vmi sshd[11]: Accepted publickey for alore from 191.95.52.193 port 5000 ssh2: ED25519 {FP}"
ISO_PASSWORD = "2026-09-25T10:30:00.000001-05:00 vmi sshd[12]: Accepted password for wordev from 45.1.2.3 port 6000 ssh2"
CLASSIC = "Sep 25 10:45:00 vmi sshd[13]: Accepted publickey for alore from 10.0.0.9 port 7000 ssh2: RSA SHA256:abcdefghijkl"
FAILED = "2026-09-25T10:31:00.000001-05:00 vmi sshd[14]: Failed password for invalid user admin from 80.1.1.1 port 1 ssh2"
LAST_OUTPUT = """alore    pts/0        191.95.52.193    2026-09-25T10:00:01-05:00 - 2026-09-25T10:26:45-05:00  (00:26)
alore    pts/2        0.0.0.0          2026-09-25T10:03:36-05:00   still logged in
reboot   system boot  6.8.0-107-generi 2026-09-20T08:00:00-05:00   still running

wtmp begins 2026-08-03T11:28:07-05:00
"""


class TmpEnvCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.log = self.tmp / "auth.log"
        patcher = mock.patch.dict(os.environ, {
            "HORNET_AUTH_LOG": str(self.log),
            "HORNET_FAIL2BAN_LOG": str(self.tmp / "fail2ban.log"),
            "HORNET_AUTHORIZED_KEYS": str(self.tmp / "authorized_keys"),
            "HORNET_DIR": str(self.tmp),
            "HORNET_STATE_FILE": str(self.tmp / "state"),
        })
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)


class ParseAuthLineTest(unittest.TestCase):
    def test_iso_publickey(self):
        ev = ht.parse_auth_line(ISO_PUBKEY)
        self.assertEqual(ev["user"], "alore")
        self.assertEqual(ev["ip"], "191.95.52.193")
        self.assertEqual(ev["port"], 5000)
        self.assertEqual(ev["method"], "publickey")
        self.assertEqual(ev["fingerprint"], FP)
        self.assertEqual(ev["ts"], datetime(2026, 9, 25, 10, 0, 5, 123456, tzinfo=BOG))

    def test_iso_password(self):
        ev = ht.parse_auth_line(ISO_PASSWORD)
        self.assertEqual(ev["method"], "password")
        self.assertIsNone(ev["fingerprint"])

    def test_classic_syslog_format(self):
        with mock.patch.object(ht, "_now", return_value=datetime(2026, 9, 25, 12, 0, tzinfo=BOG)):
            ev = ht.parse_auth_line(CLASSIC)
        self.assertEqual(ev["ts"], datetime(2026, 9, 25, 10, 45, 0, tzinfo=BOG))
        self.assertEqual(ev["fingerprint"], "SHA256:abcdefghijkl")

    def test_other_lines_are_ignored(self):
        self.assertIsNone(ht.parse_auth_line(FAILED))
        self.assertIsNone(ht.parse_auth_line("garbage"))


class AcceptedLoginsTest(TmpEnvCase):
    def test_since_cursor(self):
        self.log.write_text("\n".join([ISO_PUBKEY, FAILED, ISO_PASSWORD]) + "\n")
        evs = ht.accepted_logins(datetime(2026, 9, 25, 10, 10, tzinfo=BOG))
        self.assertEqual([e["user"] for e in evs], ["wordev"])

    def test_reads_rotated_file_when_cursor_is_older(self):
        Path(str(self.log) + ".1").write_text(ISO_PUBKEY + "\n")
        self.log.write_text(ISO_PASSWORD + "\n")
        evs = ht.accepted_logins(datetime(2026, 9, 25, 9, 0, tzinfo=BOG))
        self.assertEqual([e["user"] for e in evs], ["alore", "wordev"])

    def test_invalid_utf8_does_not_crash(self):
        self.log.write_bytes(b"\xff\xfe garbage\n" + ISO_PASSWORD.encode() + b"\n")
        self.assertEqual(len(ht.accepted_logins(datetime(2026, 9, 25, 0, 0, tzinfo=BOG))), 1)

    def test_unreadable_log_returns_none(self):
        self.assertIsNone(ht.accepted_logins(datetime(2026, 9, 25, tzinfo=BOG)))


class SshLoginsToolTest(TmpEnvCase):
    def test_summary_from_auth_log(self):
        self.log.write_text("\n".join([ISO_PUBKEY, FAILED, ISO_PASSWORD]) + "\n")
        with mock.patch.object(ht, "_now", return_value=datetime(2026, 9, 25, 11, 0, tzinfo=BOG)), \
                mock.patch.object(ht, "key_comments", return_value={FP: "kev.castrillon.dev@gmail.com"}):
            out = ht.call_tool("ssh_logins", {"hours": 24})
        self.assertIn("191.95.52.193", out)
        self.assertIn("k***@gmail.com", out)  # key comment is an email → redacted
        self.assertIn("wordev", out)
        self.assertIn("contraseña", out)
        self.assertIn("Intentos fallidos: 1", out)

    def test_falls_back_to_last_when_auth_log_unreadable(self):
        with mock.patch.object(ht, "_now", return_value=datetime(2026, 9, 25, 11, 0, tzinfo=BOG)), \
                mock.patch.object(ht, "_run", return_value=LAST_OUTPUT):
            out = ht.call_tool("ssh_logins", {"hours": 24})
        self.assertIn("auth.log no legible", out)
        self.assertIn("191.95.52.193", out)
        self.assertNotIn("0.0.0.0", out)
        self.assertNotIn("reboot", out)


class CallToolTest(TmpEnvCase):
    def test_unknown_tool(self):
        with self.assertRaises(ht.ToolError):
            ht.call_tool("rm_rf", {})

    def test_invalid_argument_type(self):
        with self.assertRaises(ht.ToolError):
            ht.call_tool("top_processes", {"limit": "abc"})

    def test_all_eight_tools_registered(self):
        self.assertEqual(set(ht.TOOLS), {
            "server_status", "top_processes", "docker_ps", "docker_stats",
            "container_logs", "open_ports", "hornet_history", "ssh_logins"})

    def test_top_processes_clamps_and_never_uses_args(self):
        calls = []
        rows = "".join(f"{i} root 0.0 0.1 1024 100 proc{i}\n" for i in range(20))

        def fake_run(cmd, timeout=10, merge_stderr=False):
            calls.append(cmd)
            return rows

        with mock.patch.object(ht, "_run", side_effect=fake_run):
            out = ht.call_tool("top_processes", {"sort": "bogus", "limit": 99})
        cmd = calls[0]
        self.assertIn("--sort=-rss", cmd)
        self.assertTrue(any("comm" in part for part in cmd))
        self.assertFalse(any("args" in part for part in cmd))
        self.assertIn("proc14", out)
        self.assertNotIn("proc15", out)

    def test_container_logs_rejects_unknown_name(self):
        calls = []

        def fake_run(cmd, timeout=10, merge_stderr=False):
            calls.append(cmd)
            return "app\ndb\n"

        with mock.patch.object(ht, "_run", side_effect=fake_run):
            out = ht.call_tool("container_logs", {"name": "app; rm -rf /", "lines": 10})
        self.assertIn("no existe", out)
        self.assertFalse(any(c[:2] == ["docker", "logs"] for c in calls))

    def test_container_logs_clamps_and_redacts(self):
        calls = []

        def fake_run(cmd, timeout=10, merge_stderr=False):
            calls.append(cmd)
            if cmd[:2] == ["docker", "ps"]:
                return "app\n"
            return "ok\nDB_PASSWORD=hunter2\n"

        with mock.patch.object(ht, "_run", side_effect=fake_run):
            out = ht.call_tool("container_logs", {"name": "app", "lines": 500})
        self.assertIn(["docker", "logs", "--tail", "50", "app"], calls)
        self.assertNotIn("hunter2", out)

    def test_output_is_truncated(self):
        with mock.patch.object(ht, "_run", return_value="x" * 10000):
            out = ht.call_tool("docker_ps", {})
        self.assertTrue(out.endswith(ht.TRUNC_MARKER))

    def test_command_failure_becomes_error_text(self):
        with mock.patch.object(ht, "_run", side_effect=ht.ToolUnavailable("timeout")):
            out = ht.call_tool("docker_stats", {})
        self.assertTrue(out.startswith("error: docker_stats no disponible"), out)

    def test_server_status_reads_proc(self):
        out = ht.call_tool("server_status", {})
        for word in ("RAM", "Swap", "Load", "Disco", "Uptime"):
            self.assertIn(word, out)

    def test_hornet_history(self):
        (self.tmp / "hornet.log").write_text(
            "[2026-09-25 11:15:00] Hornet scan complete. Issues: none\n"
            "[2026-09-25 11:20:00] ERROR telegram: HTTP 401 — Unauthorized\n"
            "[2026-09-25 11:30:00] Hornet scan complete. Issues: new_user_x|\n")
        (self.tmp / "alerts.jsonl").write_text(json.dumps({
            "ts": "2026-09-25T11:30:00-05:00", "level": "alert", "title": "HORNET — Shaw!",
            "issues": "new_user_x|", "message": "USUARIO NUEVO x", "analysis": "Causa probable: prueba"}) + "\n")
        (self.tmp / "state").write_text("new_user_x|\n")
        out = ht.call_tool("hornet_history", {"limit": 5})
        self.assertIn("new_user_x", out)
        self.assertIn("Hornet scan complete", out)
        self.assertIn("USUARIO NUEVO x", out)
        self.assertIn("Causa probable: prueba", out)


class CliTest(TmpEnvCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(AI_DIR / "hornet_tools.py"), *args],
                              capture_output=True, text=True, timeout=30, env=os.environ.copy())

    def test_ssh_since(self):
        self.log.write_text("\n".join([ISO_PUBKEY, ISO_PASSWORD]) + "\n")
        res = self.run_cli("ssh-since", "2026-09-25T10:10:00-05:00")
        self.assertEqual(res.returncode, 0, res.stderr)
        events = [json.loads(line) for line in res.stdout.splitlines() if line.strip()]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["user"], "wordev")
        self.assertEqual(events[0]["method"], "password")
        self.assertEqual(events[0]["key"], "")

    def test_ssh_lookup_found(self):
        self.log.write_text(ISO_PUBKEY + "\n")
        res = self.run_cli("ssh-lookup", "alore", "191.95.52.193", "5000")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(json.loads(res.stdout)["method"], "publickey")

    def test_ssh_lookup_not_found(self):
        self.log.write_text(ISO_PUBKEY + "\n")
        res = self.run_cli("ssh-lookup", "alore", "191.95.52.193", "9999")
        self.assertEqual(res.returncode, 0)
        self.assertEqual(json.loads(res.stdout), {})

    def test_ssh_lookup_unreadable_exits_3(self):
        res = self.run_cli("ssh-lookup", "alore", "1.2.3.4", "1")
        self.assertEqual(res.returncode, 3)

    def test_tool_command(self):
        res = self.run_cli("tool", "server_status")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("RAM", res.stdout)


if __name__ == "__main__":
    unittest.main()
