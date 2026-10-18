"""Non-GUI regression tests for the Windows read-only refresh service."""
import sys
import unittest
from pathlib import Path
from queue import Queue

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_refresh_service import fetch_into_queue


class RefreshServiceTests(unittest.TestCase):
    def test_success_keeps_request_id_and_data(self):
        inbox = Queue()
        data = [{"id": "job-1", "status": "RUNNING"}]
        fetch_into_queue(42, "https://example.invalid", "secret", inbox,
                         fetcher=lambda endpoint, token: data)
        self.assertEqual(inbox.get_nowait(), (42, data, None))

    def test_failure_does_not_leak_token_or_url(self):
        inbox = Queue()
        secret = "TOP_SECRET_TOKEN_123"
        endpoint = "https://private.example.invalid"
        def fail(_endpoint, _token):
            raise RuntimeError(f"{secret} {endpoint}")
        fetch_into_queue(7, endpoint, secret, inbox, fetcher=fail)
        request_id, data, error = inbox.get_nowait()
        self.assertEqual(request_id, 7)
        self.assertIsNone(data)
        self.assertNotIn(secret, error)
        self.assertNotIn(endpoint, error)

    def test_http_auth_error_has_safe_diagnostic(self):
        from urllib.error import HTTPError
        inbox = Queue()
        def fail(_endpoint, _token):
            raise HTTPError("https://secret.invalid", 401, "Unauthorized", None, None)
        fetch_into_queue(3, "https://secret.invalid", "token", inbox, fetcher=fail)
        request_id, data, error = inbox.get_nowait()
        self.assertEqual(request_id, 3)
        self.assertIsNone(data)
        self.assertIn("401", error)
        self.assertNotIn("secret.invalid", error)


if __name__ == "__main__":
    unittest.main()
