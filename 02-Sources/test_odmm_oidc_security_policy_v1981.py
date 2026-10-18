"""Author: Abdelhalim Talbi."""
import unittest
from odmm_oidc_security_policy import validate_origin, require_csrf, require_fresh_session

ORIGIN='https://odmm.example.test'
TOKEN='a'*48
class SecurityPolicyTests(unittest.TestCase):
    def test_valid_origin(self): self.assertTrue(validate_origin(ORIGIN, ORIGIN))
    def test_origin_rejects_different_port(self):
        with self.assertRaises(PermissionError): validate_origin(ORIGIN+':444', ORIGIN)
    def test_origin_rejects_path(self):
        with self.assertRaises(PermissionError): validate_origin(ORIGIN+'/a', ORIGIN+'/a')
    def test_origin_rejects_http(self):
        with self.assertRaises(PermissionError): validate_origin('http://odmm.example.test','http://odmm.example.test')
    def test_post_accepts(self): self.assertTrue(require_csrf(method='POST',origin=ORIGIN,expected_origin=ORIGIN,cookie_token=TOKEN,submitted_token=TOKEN))
    def test_post_rejects_missing(self):
        with self.assertRaises(PermissionError): require_csrf(method='POST',origin=ORIGIN,expected_origin=ORIGIN,cookie_token=TOKEN,submitted_token='')
    def test_post_rejects_mismatch(self):
        with self.assertRaises(PermissionError): require_csrf(method='POST',origin=ORIGIN,expected_origin=ORIGIN,cookie_token=TOKEN,submitted_token='b'*48)
    def test_post_rejects_origin(self):
        with self.assertRaises(PermissionError): require_csrf(method='POST',origin='https://evil.test',expected_origin=ORIGIN,cookie_token=TOKEN,submitted_token=TOKEN)
    def test_get_no_csrf(self): self.assertTrue(require_csrf(method='GET',origin=None,expected_origin=ORIGIN,cookie_token=None,submitted_token=None))
    def test_session_fresh(self): self.assertTrue(require_fresh_session(issued_at=100,expires_at=500,now=200))
    def test_session_expired(self):
        with self.assertRaises(PermissionError): require_fresh_session(issued_at=100,expires_at=200,now=200)
    def test_session_future(self):
        with self.assertRaises(PermissionError): require_fresh_session(issued_at=300,expires_at=500,now=200)
    def test_session_over_age(self):
        with self.assertRaises(PermissionError): require_fresh_session(issued_at=100,expires_at=5000,now=1100)
if __name__=='__main__': unittest.main()
