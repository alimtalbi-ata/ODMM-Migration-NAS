"""Adversarial tests for strict read-only registry JSON decoding."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_registry_client_v2267 import fetch_registry_jobs


class FakeResponse:
    status = 200
    headers = {"Content-Type": "application/json"}
    def __init__(self, payload):
        self.payload = payload
    def __enter__(self):
        return self
    def __exit__(self, *_):
        return False
    def read(self, _):
        return self.payload


class FakeOpener:
    def __init__(self, payload):
        self.payload = payload
    def open(self, request, timeout):
        return FakeResponse(self.payload)


class RegistryJsonSecurityTests(unittest.TestCase):
    def fetch(self, payload):
        with patch("odmm_registry_client_v2267.validate_origin", return_value="https://odmm.invalid"):
            return fetch_registry_jobs("https://odmm.invalid", "valid-token-123", opener=FakeOpener(payload.encode("utf-8")))

    def test_valid_registry(self):
        self.assertEqual(self.fetch('{"schema":"odmm.jobs.v1","read_only":true,"items":[{"id":"j1","state":"DONE"}]}')[0]["status"], "COMPLETED")

    def test_duplicate_root_member_rejected(self):
        with self.assertRaisesRegex(ValueError, "INVALID_JSON"):
            self.fetch('{"schema":"odmm.jobs.v1","read_only":true,"read_only":false,"items":[]}')

    def test_duplicate_nested_member_rejected(self):
        with self.assertRaisesRegex(ValueError, "INVALID_JSON"):
            self.fetch('{"schema":"odmm.jobs.v1","read_only":true,"items":[{"id":"a","id":"b","state":"DONE"}]}')

    def test_nonstandard_nan_rejected(self):
        with self.assertRaisesRegex(ValueError, "INVALID_JSON"):
            self.fetch('{"schema":"odmm.jobs.v1","read_only":true,"items":[],"extra":NaN}')


if __name__ == "__main__":
    unittest.main()
