import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

AI_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AI_DIR))
import mcp_server  # noqa: E402


def req(method, params=None, id_=1):
    msg = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


class HandleTest(unittest.TestCase):
    def test_initialize_echoes_supported_version(self):
        r = mcp_server.handle(req("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                                 "clientInfo": {"name": "t", "version": "0"}}))
        self.assertEqual(r["id"], 1)
        self.assertEqual(r["result"]["protocolVersion"], "2025-03-26")
        self.assertIn("tools", r["result"]["capabilities"])
        self.assertEqual(r["result"]["serverInfo"]["name"], "hornet")

    def test_initialize_unknown_version_falls_back(self):
        r = mcp_server.handle(req("initialize", {"protocolVersion": "1999-01-01"}))
        self.assertEqual(r["result"]["protocolVersion"], "2025-06-18")

    def test_initialized_notification_has_no_response(self):
        self.assertIsNone(mcp_server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_ping(self):
        self.assertEqual(mcp_server.handle(req("ping"))["result"], {})

    def test_tools_list(self):
        tools = mcp_server.handle(req("tools/list"))["result"]["tools"]
        names = {t["name"] for t in tools}
        self.assertEqual(len(names), 8)
        by_name = {t["name"]: t for t in tools}
        self.assertEqual(by_name["container_logs"]["inputSchema"]["required"], ["name"])
        self.assertEqual(by_name["top_processes"]["inputSchema"]["properties"]["sort"]["enum"], ["mem", "cpu"])
        for t in tools:
            self.assertEqual(t["inputSchema"]["type"], "object")
            self.assertTrue(t["description"].startswith("Solo lectura."))

    def test_tools_call_success_is_marked_as_data(self):
        with mock.patch.object(mcp_server.hornet_tools, "call_tool", return_value="RAM 50%"):
            r = mcp_server.handle(req("tools/call", {"name": "server_status", "arguments": {}}))
        self.assertFalse(r["result"]["isError"])
        text = r["result"]["content"][0]["text"]
        self.assertTrue(text.startswith(mcp_server.DATA_PREFIX))
        self.assertIn("RAM 50%", text)

    def test_tools_call_unknown_tool_is_error_result(self):
        r = mcp_server.handle(req("tools/call", {"name": "rm_rf", "arguments": {}}))
        self.assertTrue(r["result"]["isError"])

    def test_tools_call_invalid_arguments_is_error_result(self):
        r = mcp_server.handle(req("tools/call", {"name": "top_processes", "arguments": {"limit": "abc"}}))
        self.assertTrue(r["result"]["isError"])

    def test_unknown_method(self):
        self.assertEqual(mcp_server.handle(req("resources/list"))["error"]["code"], -32601)


class StdioTest(unittest.TestCase):
    def start(self):
        return subprocess.Popen([sys.executable, str(AI_DIR / "mcp_server.py")], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def send(self, proc, msg):
        proc.stdin.write((msg if isinstance(msg, str) else json.dumps(msg)) + "\n")
        proc.stdin.flush()

    def test_handshake_over_stdio(self):
        proc = self.start()
        self.send(proc, req("initialize", {"protocolVersion": "2025-06-18"}, 1))
        self.send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.send(proc, req("tools/list", None, 2))
        first = json.loads(proc.stdout.readline())
        second = json.loads(proc.stdout.readline())
        proc.stdin.close()
        self.assertEqual(proc.wait(timeout=5), 0)
        self.assertEqual((first["id"], second["id"]), (1, 2))
        self.assertEqual(len(second["result"]["tools"]), 8)

    def test_malformed_line_does_not_kill_server(self):
        proc = self.start()
        self.send(proc, "not json")
        self.send(proc, req("ping", None, 7))
        err = json.loads(proc.stdout.readline())
        ok = json.loads(proc.stdout.readline())
        proc.stdin.close()
        proc.wait(timeout=5)
        self.assertEqual(err["error"]["code"], -32700)
        self.assertEqual(ok["id"], 7)


if __name__ == "__main__":
    unittest.main()
