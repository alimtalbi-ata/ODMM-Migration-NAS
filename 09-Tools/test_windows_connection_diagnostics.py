"""Connection diagnostics contract: safe, actionable and credential-free."""
import sys
import unittest
from pathlib import Path
from urllib.error import HTTPError
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_desktop_api_v2266 import validate_origin
from odmm_connection_diagnostics_v22851 import explain_connection_failure


class ConnectionDiagnosticsTests(unittest.TestCase):
    def test_remote_plain_http_rejected_with_specific_tls_code(self):
        with self.assertRaisesRegex(ValueError, "^TLS_REQUIRED$") as ctx:
            validate_origin("http://example.com:8090")
        self.assertIn("HTTPS", explain_connection_failure(ctx.exception))

    def test_local_http_allowed(self):
        self.assertEqual(validate_origin("http://127.0.0.1:8090/"), "http://127.0.0.1:8090")

    def test_ambiguous_origins_rejected(self):
        for origin in ("", "https://example.com:", "https://example.com\\\\evil", "https://example.com\\n", "https://example.com:443\\t", " https://example.com", "https://example.com/path"):
            with self.subTest(origin=repr(origin)):
                with self.assertRaisesRegex(ValueError, "INVALID_ORIGIN"):
                    validate_origin(origin)

    def test_redirect_diagnostic_never_exposes_credentials(self):
        self.assertNotIn("secret", explain_connection_failure(ValueError("REDIRECT_REFUSED secret")).lower())
        self.assertIn("Redirection", explain_connection_failure(ValueError("REDIRECT_REFUSED")))

    def test_http_timeout_and_auth_are_distinct(self):
        for code, fragment in [(408, "Délai"), (504, "Délai"), (401, "Authentification"), (429, "requêtes")]:
            error = HTTPError("https://host.invalid/secret", code, "private", {}, None)
            message = explain_connection_failure(error)
            self.assertIn(fragment, message)
            self.assertNotIn("host.invalid", message)
            self.assertNotIn("private", message)


if __name__ == "__main__":
    unittest.main()
