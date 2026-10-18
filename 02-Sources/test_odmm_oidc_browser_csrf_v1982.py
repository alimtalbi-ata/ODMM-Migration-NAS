"""V198.2 middleware security regression. Author: Abdelhalim Talbi."""
import unittest
from odmm_oidc_security_policy import require_csrf
class BrowserBoundaryTests(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(require_csrf(method='POST',origin='https://odmm.example',expected_origin='https://odmm.example',cookie_token='a'*40,submitted_token='a'*40))
    def test_bad_origin(self):
        with self.assertRaises(PermissionError): require_csrf(method='POST',origin='https://evil.example',expected_origin='https://odmm.example',cookie_token='a'*40,submitted_token='a'*40)
    def test_bad_token(self):
        with self.assertRaises(PermissionError): require_csrf(method='DELETE',origin='https://odmm.example',expected_origin='https://odmm.example',cookie_token='a'*40,submitted_token='b'*40)
    def test_missing_token(self):
        with self.assertRaises(PermissionError): require_csrf(method='POST',origin='https://odmm.example',expected_origin='https://odmm.example',cookie_token=None,submitted_token=None)
if __name__=='__main__': unittest.main()
