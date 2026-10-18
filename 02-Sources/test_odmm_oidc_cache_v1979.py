import unittest
from test_odmm_oidc_hot_reload_v1978 import HotReloadTests
from odmm_oidc_hot_reload import ReloadingOIDCVerifier

class CacheTests(HotReloadTests):
    def test_cache_skips_io_until_deadline(self):
        now=[100.0]
        v=ReloadingOIDCVerifier(issuer='https://id.example/realm',audience='odmm',jwks_path=self.path,check_interval=2,clock=lambda:now[0])
        self.write([self.k2])
        with self.assertRaises(PermissionError):v.verify('bad-token')
        self.assertEqual(set(v._verifier.keys),{'old'})
        now[0]+=2.01
        with self.assertRaises(PermissionError):v.verify('bad-token')
        self.assertEqual(set(v._verifier.keys),{'new'})
    def test_invalid_interval(self):
        for n in (-1,6):
            with self.assertRaises(ValueError):ReloadingOIDCVerifier(issuer='https://id.example/realm',audience='odmm',jwks_path=self.path,check_interval=n)
    def test_cache_failure_after_deadline_fails_closed(self):
        now=[100.0]
        v=ReloadingOIDCVerifier(issuer='https://id.example/realm',audience='odmm',jwks_path=self.path,check_interval=1,clock=lambda:now[0])
        self.path.unlink();now[0]+=2
        with self.assertRaises(PermissionError):v.verify('bad-token')
        self.assertIsNone(v._verifier)
