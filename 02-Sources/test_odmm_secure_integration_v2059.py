import unittest
from fastapi import FastAPI
from odmm_secure_integration_v2059 import csrf_for_session, attach_hardened_collection
from odmm_collection_security_v2058 import SecurityGate
import tempfile

class TestHardenedIntegration(unittest.TestCase):
    def test_csrf_stable(self):
        self.assertEqual(csrf_for_session('session-123456789', b'a'*32), csrf_for_session('session-123456789', b'a'*32))
    def test_csrf_session_bound(self):
        self.assertNotEqual(csrf_for_session('session-123456789', b'a'*32), csrf_for_session('session-987654321', b'a'*32))
    def test_short_secret(self):
        with self.assertRaises(ValueError): csrf_for_session('session-123456789', b'x')
    def test_short_session(self):
        with self.assertRaises(ValueError): csrf_for_session('x', b'a'*32)
    def _params(self):
        return dict(gate=SecurityGate(':memory:'), identity_provider=lambda r:('actor','operator'),session_provider=lambda r:'session-123456789',csrf_secret=b'a'*32,expected_origin='https://odmm.example',token_provider=lambda *a:'token',allow_hosts={'nas.example'})
    def test_route_added(self):
        app=FastAPI();attach_hardened_collection(app,**self._params())
        self.assertTrue(any(r.path.endswith('/collect-hardened') for r in app.routes))
    def test_duplicate_route_blocked(self):
        app=FastAPI();attach_hardened_collection(app,**self._params())
        with self.assertRaisesRegex(ValueError,'LEGACY_COLLECTION_ROUTE_PRESENT'):attach_hardened_collection(app,**self._params())
    def test_legacy_route_blocked(self):
        app=FastAPI();app.add_api_route('/api/v1/qualification/collect-secure',lambda:None)
        with self.assertRaisesRegex(ValueError,'LEGACY_COLLECTION_ROUTE_PRESENT'):attach_hardened_collection(app,**self._params())
    def test_bad_secret_rejected(self):
        app=FastAPI();params=self._params();params['csrf_secret']=b'a'
        with self.assertRaises(ValueError):attach_hardened_collection(app,**params)

if __name__=='__main__': unittest.main()
