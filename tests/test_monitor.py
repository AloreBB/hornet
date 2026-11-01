import getpass
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

REPO = Path(__file__).resolve().parents[1]
BOG = timezone(timedelta(hours=-5))
ANALYSIS = "Causa probable: prueba"


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        self.server.requests.append((self.path, body))
        status, payload = 200, {"ok": True}
        if "/sendMessage" in self.path:
            status = self.server.telegram_status
        elif self.path.endswith("/v1/messages"):
            status = self.server.ai_status
            payload = {"content": [{"type": "text", "text": ANALYSIS}]} if status == 200 else {"error": {"message": "boom"}}
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_HEAD = _handle


class MonitorTestBase(unittest.TestCase):
    def setUp(self):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        self.srv.requests, self.srv.telegram_status, self.srv.ai_status = [], 200, 200
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.app = self.tmp / "app"
        self.app.mkdir()
        shutil.copy(REPO / "monitor.sh", self.app / "monitor.sh")
        shutil.copytree(REPO / "ai", self.app / "ai", ignore=shutil.ignore_patterns("tests", "__pycache__"))
        (self.app / "VERSION").write_text("test\n")
        xdg = self.tmp / "xdg" / "hornet"
        xdg.mkdir(parents=True)
        (xdg / "credentials").write_text("TELEGRAM_BOT_TOKEN=123:abc\nNTFY_TOKEN=\nAI_API_KEY=k-test\n")
        (self.tmp / "home").mkdir()
        self.auth_log = self.tmp / "auth.log"
        self.write_config()

    def write_config(self, ai=True, explain_alerts=True, healthcheck=True):
        config = {
            "notifications": {"telegram_chat_id": "1", "url": "", "topic": "", "icon": ""},
            "baseline": {"users": ["nobody-such:/bin/false"], "ssh_keys": [], "crontabs": []},
            "whitelist": {"ports": [], "processes": [], "containers": [], "extensions": []},
            "healthcheck_url": f"{self.url}/hc/abc" if healthcheck else "",
        }
        if ai:
            config["ai"] = {"base_url": f"{self.url}/ai", "model": "MiniMax-M3", "explain_alerts": explain_alerts}
        (self.app / "config.json").write_text(json.dumps(config))

    def run_monitor(self, *args, checks=None, extra_env=None):
        env = {k: v for k, v in os.environ.items() if k not in ("TELEGRAM_BOT_TOKEN", "NTFY_TOKEN", "AI_API_KEY")}
        env.update({
            "HOME": str(self.tmp / "home"),
            "XDG_CONFIG_HOME": str(self.tmp / "xdg"),
            "TELEGRAM_API_BASE": self.url,
            "HORNET_STATE_FILE": str(self.tmp / "state"),
            "HORNET_AUTH_LOG": str(self.auth_log),
            "HORNET_AUTHORIZED_KEYS": str(self.tmp / "authorized_keys"),
        })
        if checks is not None:
            env["HORNET_CHECKS"] = checks
        env.update(extra_env or {})
        return subprocess.run(["bash", str(self.app / "monitor.sh"), *args], env=env,
                              capture_output=True, text=True, timeout=120)

    def telegram_texts(self):
        return [parse_qs(body)["text"][0] for path, body in self.srv.requests if "/sendMessage" in path]

    def paths(self):
        return [path for path, _ in self.srv.requests]


class DeliveryTest(MonitorTestBase):
    def test_test_mode_sends_one_message(self):
        res = self.run_monitor("--test")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(len(self.telegram_texts()), 1)

    def test_test_mode_prints_analysis_when_ai_configured(self):
        res = self.run_monitor("--test")
        self.assertIn(ANALYSIS, res.stdout)

    def test_alert_includes_analysis_and_is_recorded(self):
        res = self.run_monitor(checks="check_users_and_keys")
        self.assertEqual(res.returncode, 0, res.stderr)
        texts = self.telegram_texts()
        self.assertEqual(len(texts), 1)
        self.assertIn("🧠 Análisis (IA): " + ANALYSIS, texts[0])
        records = [json.loads(line) for line in (self.app / "alerts.jsonl").read_text().splitlines()]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["analysis"], ANALYSIS)
        self.assertEqual(records[0]["level"], "alert")
        self.assertIn("/hc/abc", self.paths())
        self.assertIn("Hornet scan complete", res.stdout)

    def test_alert_sent_without_analysis_when_ai_fails(self):
        self.srv.ai_status = 500
        res = self.run_monitor(checks="check_users_and_keys")
        texts = self.telegram_texts()
        self.assertEqual(len(texts), 1)
        self.assertNotIn("Análisis", texts[0])
        self.assertIn("ERROR explain", res.stderr)

    def test_failed_delivery_pings_fail_and_keeps_state(self):
        self.srv.telegram_status = 500
        self.run_monitor(checks="check_users_and_keys")
        self.assertIn("/hc/abc/fail", self.paths())
        self.assertFalse((self.tmp / "state").exists())
        self.assertFalse((self.app / "alerts.jsonl").exists())

    def test_without_ai_section_no_analysis_requested(self):
        self.write_config(ai=False)
        self.run_monitor(checks="check_users_and_keys")
        self.assertEqual(len(self.telegram_texts()), 1)
        self.assertFalse(any(p.endswith("/v1/messages") for p in self.paths()))

    def test_unchanged_state_sends_nothing_but_pings(self):
        self.run_monitor(checks="check_users_and_keys")
        self.srv.requests.clear()
        self.run_monitor(checks="check_users_and_keys")
        self.assertEqual(self.telegram_texts(), [])
        self.assertIn("/hc/abc", self.paths())


class SshTest(MonitorTestBase):
    USER = getpass.getuser()

    def auth_line(self, method, user, ip, port, when=None, pid=1):
        ts = (when or datetime.now(BOG)).isoformat(timespec="microseconds")
        suffix = " ssh2: ED25519 SHA256:unknownfp" if method == "publickey" else " ssh2"
        return f"{ts} vmi sshd[{pid}]: Accepted {method} for {user} from {ip} port {port}{suffix}\n"

    def ssh_login(self, ip="191.95.52.193", port="5000", conn_id=""):
        return self.run_monitor("--ssh-login", extra_env={"SSH_CONNECTION": f"{ip} {port} 10.0.0.1 22",
                                                          "HORNET_SSH_CONN_ID": conn_id})

    def fake_connection(self):
        """A live process standing in for a connection's sshd; returns its "pid starttime" id."""
        proc = subprocess.Popen(["sleep", "60"])
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        stat = Path(f"/proc/{proc.pid}/stat").read_text()
        return proc, f"{proc.pid} {stat.rsplit(') ', 1)[1].split()[19]}"

    def test_new_ip_is_warning_then_deduplicated(self):
        self.auth_log.write_text(self.auth_line("publickey", self.USER, "191.95.52.193", 5000))
        res = self.ssh_login()
        self.assertEqual(res.returncode, 0, res.stderr)
        texts = self.telegram_texts()
        self.assertEqual(len(texts), 1)
        self.assertIn("⚠️", texts[0])
        self.assertIn("191.95.52.193", texts[0])
        self.assertIn("IP nueva", texts[0])
        self.ssh_login()
        self.assertEqual(len(self.telegram_texts()), 1)

    def test_known_ip_with_key_is_info(self):
        self.auth_log.write_text(self.auth_line("publickey", self.USER, "191.95.52.193", 5000))
        (self.app / "ssh-known-ips").write_text("191.95.52.193\n")
        self.ssh_login()
        text = self.telegram_texts()[0]
        self.assertIn("🔑", text)
        self.assertIn("IP conocida", text)

    def test_password_login_is_warning(self):
        self.auth_log.write_text(self.auth_line("password", self.USER, "191.95.52.193", 5000))
        (self.app / "ssh-known-ips").write_text("191.95.52.193\n")
        self.ssh_login()
        text = self.telegram_texts()[0]
        self.assertIn("⚠️", text)
        self.assertIn("contraseña", text)

    def expire_dedup_window(self, ip="191.95.52.193"):
        (self.app / "ssh-last-notified").write_text(f"{ip} 1000\n")

    def test_new_channel_on_same_connection_is_silent_after_window(self):
        # Clients like Argos keep one SSH connection open and open new channels on it
        # (tmux attach, sftp upload, list-sessions); sshd runs ~/.ssh/rc for each one.
        self.auth_log.write_text(self.auth_line("publickey", self.USER, "191.95.52.193", 5000))
        _, conn = self.fake_connection()
        self.ssh_login(conn_id=conn)
        self.expire_dedup_window()
        self.ssh_login(conn_id=conn)
        self.assertEqual(len(self.telegram_texts()), 1)

    def test_new_connection_from_same_ip_alerts_after_window(self):
        self.auth_log.write_text(
            self.auth_line("publickey", self.USER, "191.95.52.193", 5000)
            + self.auth_line("publickey", self.USER, "191.95.52.193", 5001)
        )
        _, first = self.fake_connection()
        _, second = self.fake_connection()
        self.ssh_login(port="5000", conn_id=first)
        self.expire_dedup_window()
        self.ssh_login(port="5001", conn_id=second)
        self.assertEqual(len(self.telegram_texts()), 2)

    def test_closed_connection_is_forgotten(self):
        # Same ip:port and even a recycled PID must alert again once the old connection closed.
        self.auth_log.write_text(self.auth_line("publickey", self.USER, "191.95.52.193", 5000))
        proc, conn = self.fake_connection()
        self.ssh_login(conn_id=conn)
        proc.kill()
        proc.wait()
        self.expire_dedup_window()
        _, new_conn = self.fake_connection()
        self.ssh_login(conn_id=new_conn)
        self.assertEqual(len(self.telegram_texts()), 2)
        self.assertNotIn(conn, (self.app / "ssh-notified-conns").read_text().splitlines())

    def test_failed_delivery_does_not_silence_the_connection(self):
        self.auth_log.write_text(self.auth_line("publickey", self.USER, "191.95.52.193", 5000))
        _, conn = self.fake_connection()
        self.srv.telegram_status = 500
        self.ssh_login(conn_id=conn)
        self.srv.telegram_status = 200
        self.ssh_login(conn_id=conn)
        self.assertEqual(len(self.telegram_texts()), 2)  # failed attempt + retry on next channel

    def test_forged_auth_line_from_other_pid_is_ignored(self):
        # The fake connection's parent (this test process) plays the root sshd monitor.
        _, conn = self.fake_connection()
        (self.app / "ssh-known-ips").write_text("191.95.52.193\n")
        self.auth_log.write_text(self.auth_line("publickey", self.USER, "191.95.52.193", 5000, pid=os.getpid() + 1))
        self.ssh_login(conn_id=conn)
        text = self.telegram_texts()[0]
        self.assertIn("método desconocido", text)
        self.assertIn("⚠️", text)

    def test_duplicate_auth_lines_are_flagged(self):
        _, conn = self.fake_connection()
        (self.app / "ssh-known-ips").write_text("191.95.52.193\n")
        older = datetime.now(BOG) - timedelta(seconds=30)
        self.auth_log.write_text(self.auth_line("password", self.USER, "191.95.52.193", 5000, pid=os.getpid())
                                 + self.auth_line("publickey", self.USER, "191.95.52.193", 5000, when=older,
                                                  pid=os.getpid()))
        self.ssh_login(conn_id=conn)
        text = self.telegram_texts()[0]
        self.assertIn("falsificado", text)
        self.assertIn("⚠️", text)

    def test_genuine_line_from_monitor_pid_is_used(self):
        _, conn = self.fake_connection()
        (self.app / "ssh-known-ips").write_text("191.95.52.193\n")
        self.auth_log.write_text(self.auth_line("publickey", self.USER, "191.95.52.193", 5000, pid=os.getpid()))
        self.ssh_login(conn_id=conn)
        text = self.telegram_texts()[0]
        self.assertIn("🔑", text)

    def test_ssh_rc_skips_dedup_without_root_sshd_monitor(self):
        # sshd chain where no ancestor sshd has a root-owned sshd parent (e.g. a user-run
        # sshd daemon): rc must not invent a connection id that could merge connections.
        fake_bin = self.tmp / "fakebin"
        fake_bin.mkdir()
        shutil.copy("/bin/sh", fake_bin / "sshd")
        home = self.tmp / "rc-home"
        (home / ".hornet").mkdir(parents=True)
        out = self.tmp / "rc-out"
        monitor = home / ".hornet" / "monitor.sh"
        monitor.write_text(f'#!/bin/sh\necho "$HORNET_SSH_CONN_ID" > "{out}"\n')
        monitor.chmod(0o755)
        script = f'"{fake_bin}/sshd" -c \'sh "{REPO}/ssh-rc"; :\'; :'
        subprocess.run([str(fake_bin / "sshd"), "-c", script], env={"HOME": str(home), "PATH": os.environ["PATH"]},
                       timeout=10, check=True)
        for _ in range(50):
            if out.exists():
                break
            time.sleep(0.1)
        self.assertEqual(out.read_text().strip(), "")

    def test_ssh_login_without_ssh_connection_is_silent(self):
        res = self.run_monitor("--ssh-login", extra_env={"SSH_CONNECTION": ""})
        self.assertEqual(res.returncode, 0)
        self.assertEqual(self.telegram_texts(), [])

    def test_check_reports_other_users_once_and_never_recovers(self):
        self.run_monitor(checks="check_ssh_logins")  # first run only creates the cursor
        self.assertTrue((self.app / "ssh-scan.cursor").exists())
        self.assertEqual(self.telegram_texts(), [])
        (self.app / "ssh-scan.cursor").write_text("2026-01-01T00:00:00-05:00\n")
        self.auth_log.write_text(self.auth_line("password", "intruso", "45.1.2.3", 6000)
                                 + self.auth_line("publickey", self.USER, "191.95.52.193", 5000))
        self.run_monitor(checks="check_ssh_logins")
        texts = self.telegram_texts()
        self.assertEqual(len(texts), 1)
        self.assertIn("Intruso en la puerta", texts[0])
        self.assertIn("intruso", texts[0])
        self.assertIn("45.1.2.3", texts[0])
        self.assertNotIn("191.95.52.193", texts[0])
        self.run_monitor(checks="check_ssh_logins")
        self.assertEqual(len(self.telegram_texts()), 1)

    def test_ssh_rc_is_silent_without_install(self):
        empty_home = self.tmp / "empty-home"
        empty_home.mkdir()
        res = subprocess.run(["sh", str(REPO / "ssh-rc")], env={"HOME": str(empty_home), "PATH": os.environ["PATH"]},
                             capture_output=True, text=True, timeout=5)
        self.assertEqual(res.returncode, 0)
        self.assertEqual((res.stdout, res.stderr), ("", ""))


if __name__ == "__main__":
    unittest.main()
