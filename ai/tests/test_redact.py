import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hornet_tools import TRUNC_MARKER, redact, truncate  # noqa: E402

FAKE_BOT_TOKEN = "1234567890:AAAbbbCCCdddEEEfffGGGhhhIIIjjjKKKll"


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
        self.assertEqual(redact("postgres://app:s3cret@db:5432/prod"), "postgres://***@db:5432/prod")

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        self.assertMasked(f"cookie jwt {jwt} end", jwt)

    def test_known_token_shapes(self):
        for tok in [
            "sk-abcdefghijklmnop1234",
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "github_pat_11ABCDEFG0123456789_abcdefghij",
            "gho_abcdefghijklmnopqrstu",
            "xoxb-123-456-abcdef",
            "AKIAABCDEFGHIJKLMNOP",
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
