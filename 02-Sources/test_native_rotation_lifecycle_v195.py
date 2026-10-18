"""ASGI lifecycle regression tests for rotation admission."""
import asyncio
import unittest
from native_rotation_startup_guard import RotationAdmissionASGI
from native_rotation_portal_binding import build_rotation_endpoint, preview_portal_routes
try:
    from fastapi import FastAPI
except ImportError:
    FastAPI = None

@unittest.skipIf(FastAPI is None, 'FastAPI optional')
class LifecycleTests(unittest.TestCase):
    def make(self, pinned=True):
        app=FastAPI()
        ep=build_rotation_endpoint(db='/tmp/unused-odmm-lifecycle.db',authorization=lambda r:False,secrets_provider=lambda:{})
        app.add_api_route('/api/v1/security/rotation',ep,methods=['POST'])
        sha=preview_portal_routes(app,endpoint=ep)['sha256'] if pinned else '0'*64
        return app,RotationAdmissionASGI(app,allowed_endpoint=ep,expected_sha256=sha)
    async def lifecycle(self,wrapper):
        queue=asyncio.Queue();sent=[]
        await queue.put({'type':'lifespan.startup'})
        await queue.put({'type':'lifespan.shutdown'})
        async def receive():return await queue.get()
        async def send(msg):sent.append(msg)
        await wrapper({'type':'lifespan'},receive,send)
        return sent
    async def request(self,wrapper):
        sent=[]
        async def receive():return {'type':'http.request','body':b'', 'more_body':False}
        async def send(msg):sent.append(msg)
        await wrapper({'type':'http','method':'GET','path':'/health','headers':[],'query_string':b''},receive,send)
        return next(x['status'] for x in sent if x['type']=='http.response.start')
    def test_startup_and_shutdown_forwarded(self):
        _,wrapper=self.make();messages=asyncio.run(self.lifecycle(wrapper))
        self.assertEqual(['lifespan.startup.complete','lifespan.shutdown.complete'],[m['type'] for m in messages]);self.assertFalse(wrapper.admitted)
    def test_invalid_anchor_blocks_startup(self):
        _,wrapper=self.make(False);messages=asyncio.run(self.lifecycle(wrapper))
        self.assertEqual('lifespan.startup.failed',messages[0]['type']);self.assertFalse(wrapper.admitted)
    def test_request_before_startup_denied(self):
        _,wrapper=self.make();self.assertEqual(503,asyncio.run(self.request(wrapper)))
    def test_request_after_shutdown_denied(self):
        _,wrapper=self.make();asyncio.run(self.lifecycle(wrapper));self.assertEqual(503,asyncio.run(self.request(wrapper)))
    def test_mutation_detected_on_request(self):
        app,wrapper=self.make();wrapper.verify()
        async def unsafe():return {'ok':True}
        app.add_api_route('/api/v1/epoch/rotate',unsafe,methods=['POST'])
        self.assertEqual(503,asyncio.run(self.request(wrapper)));self.assertFalse(wrapper.admitted)
    def test_restart_requires_new_admission(self):
        _,wrapper=self.make();asyncio.run(self.lifecycle(wrapper));self.assertFalse(wrapper.admitted)
        messages=asyncio.run(self.lifecycle(wrapper));self.assertEqual('lifespan.startup.complete',messages[0]['type']);self.assertFalse(wrapper.admitted)
