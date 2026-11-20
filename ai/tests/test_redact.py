import base64
import json
import secrets
import string
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hornet_tools import TRUNC_MARKER, redact, truncate  # noqa: E402


def rand(n, alphabet=string.ascii_letters + string.digits):
    """Random filler: fixtures are built at runtime so secret scanners never see a literal token."""
    return "".join(secrets.choice(alphabet) for _ in range(n))


def b64url(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


FAKE_BOT_TOKEN = f"{rand(10, string.digits)}:{rand(35)}"


class RedactTest(unittest.TestCase):
    def assertMasked(self, raw, secret):
        out = redact(raw)
        self.assertNotIn(secret, out, out)
        self.assertIn("***", out)

    def test_key_value_pairs(self):
        self.assertMasked("DB_PASSWORD=hunter2", "hunter2")
        self.assertMasked("api_key: abcdef123456", "abcdef123456")
        self.assertMasked('{"token": "s3cr3tvalue"}', "s3cr3tvalue")
        self.assertMasked("SESSION_SECRET=xyz789", "xyz789")
        self.assertMasked("auth=Zm9vOmJhcg", "Zm9vOmJhcg")
        self.assertMasked("client_credential = abc123", "abc123")

    def test_authorization_header(self):
        self.assertMasked("Authorization: Bearer abc.def.ghi", "abc.def.ghi")
        self.assertMasked("authorization: Basic Zm9vOmJhcg==", "Zm9vOmJhcg==")

    def test_url_credentials(self):
        url = "postgres://app" + ":" + rand(12) + "@db:5432/prod"  # split so scanners see no credential URI
        self.assertEqual(redact(url), "postgres://***@db:5432/prod")

    def test_jwt(self):
        jwt = f"{b64url({'alg': 'HS256'})}.{b64url({'sub': rand(6)})}.{rand(43)}"
        self.assertMasked(f"cookie jwt {jwt} end", jwt)

    def test_known_token_shapes(self):
        for tok in [
            "sk-" + rand(20),
            "ghp_" + rand(36),
            "github_pat_" + rand(22) + "_" + rand(10),
            "gho_" + rand(21),
            "xoxb-" + rand(3, string.digits) + "-" + rand(3, string.digits) + "-" + rand(6),
            "AKIA" + rand(16, string.ascii_uppercase + string.digits),
            FAKE_BOT_TOKEN,
        ]:
            self.assertMasked(f"value {tok} here", tok)

    def test_pem_block(self):
        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----"
        out = redact("before\n" + pem + "\nafter")
        self.assertNotIn("b3BlbnNzaC1rZXktdjEAAAA", out)
        self.assertIn("before", out)
        self.assertIn("after", out)

    def test_email(self):
        self.assertEqual(redact("user kevin@gmail.com logged"), "user k***@gmail.com logged")

    def test_leaves_useful_data_untouched(self):
        for s in [
            "Accepted publickey for alore from 191.95.52.193 port 5000 ssh2: ED25519 SHA256:Y8iGrwsAhbrILKvbyCfJT3er/NuG3k3KlqQIVChZ/SM",
            "wordev-erpvowtech-6dowtc-vowtech-app-1  Up 7 hours",
            "/var/lib/docker/overlay2",
            "commit 5ed157d",
            "tokens used: 42",
            "pam_unix(sshd:session): session opened for user alore(uid=1001)",
        ]:
            self.assertEqual(redact(s), s)


class TruncateTest(unittest.TestCase):
    def test_short_text_unchanged(self):
        self.assertEqual(truncate("abc", 10), "abc")

    def test_long_text_truncated_with_marker(self):
        out = truncate("x" * 5000, 4000)
        self.assertTrue(out.endswith(TRUNC_MARKER))
        self.assertEqual(len(out), 4000 + len(TRUNC_MARKER))


if __name__ == "__main__":
    unittest.main()
