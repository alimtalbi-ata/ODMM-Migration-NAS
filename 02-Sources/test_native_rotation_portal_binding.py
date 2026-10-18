import asyncio
import tempfile
import unittest
from pathlib import Path
from native_rotation_portal_binding import build_rotation_endpoint, bind_rotation_portal, preview_portal_routes
from native_rotation_startup_guard import RotationAdmissionASGI

try:
    from fastapi import FastAPI, HTTPException
    from starlette.requests import Request
except ImportError:
    FastAPI=None

@unittest.skipIf(FastAPI is None,'FastAPI optional integration dependency')
class PortalBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/'registry.db'
    def _endpoint(self, auth=lambda req:True, provider=lambda:{}):
        return build_rotation_endpoint(db=self.db,authorization=auth,secrets_provider=provider)
    def _request(self,payload):
        import json
        body=json.dumps(payload).encode()
        async def receive():return {'type':'http.request','body':body,'more_body':False}
        return Request({'type':'http','method':'POST','path':'/','headers':[]},receive)
    def test_providers_required(self):
        with self.assertRaisesRegex(ValueError,'PROVIDERS_REQUIRED'):
            build_rotation_endpoint(db=self.db,authorization=None,secrets_provider=lambda:{})
    def test_unauthorized_denied_before_payload(self):
        ep=self._endpoint(auth=lambda r:False)
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(ep(self._request({})))
        self.assertEqual(403,cm.exception.status_code)
    def test_unexpected_fields_rejected(self):
        ep=self._endpoint()
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(ep(self._request({'request_id':'x','target_key_id':'b','signed_target':{},'keys':'attacker'})))
        self.assertEqual(400,cm.exception.status_code)
    def test_missing_trust_rejected(self):
        ep=self._endpoint()
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(ep(self._request({'request_id':'x','target_key_id':'b','signed_target':{}})))
        self.assertEqual(503,cm.exception.status_code)
    def test_preview_and_wrapper(self):
        app=FastAPI()
        ep=self._endpoint()
        app.add_api_route('/api/v1/security/rotation',ep,methods=['POST'])
        fingerprint=preview_portal_routes(app,endpoint=ep)['sha256']
        wrapper=RotationAdmissionASGI(app,allowed_endpoint=ep,expected_sha256=fingerprint)
        self.assertEqual(fingerprint,wrapper.verify()['sha256'])
    def test_legacy_route_rejected(self):
        app=FastAPI();ep=self._endpoint()
        app.add_api_route('/api/v1/security/rotation',ep,methods=['POST'])
        async def old_rotate():pass
        app.add_api_route('/api/v1/epoch/rotate',old_rotate,methods=['POST'])
        with self.assertRaisesRegex(ValueError,'LIVE_UNGUARDED'):
            preview_portal_routes(app,endpoint=ep)
    def test_incorrect_pinned_digest_denied(self):
        app=FastAPI()
        wrapper,ep=bind_rotation_portal(app,db=self.db,authorization=lambda r:True,secrets_provider=lambda:{},expected_routes_sha256='0'*64)
        with self.assertRaisesRegex(ValueError,'ANCHOR_MISMATCH'):
            wrapper.verify()
    def test_duplicate_rotation_route_denied(self):
        app=FastAPI();ep=self._endpoint()
        app.add_api_route('/api/v1/security/rotation',ep,methods=['POST'])
        app.add_api_route('/api/v1/security/rotation2',ep,methods=['POST'])
        with self.assertRaisesRegex(ValueError,'COUNT_INVALID'):
            preview_portal_routes(app,endpoint=ep)
