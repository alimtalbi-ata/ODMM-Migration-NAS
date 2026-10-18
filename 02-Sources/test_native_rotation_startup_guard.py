import asyncio
import unittest
from types import SimpleNamespace as NS
from native_rotation_live_route_gate import inspect_live_routes
from native_rotation_startup_guard import RotationAdmissionASGI


def rotate(): pass
def health(): pass

def route(path, fn, methods=('POST',)):
    return NS(path=path, endpoint=fn, methods=set(methods))

class Inner:
    def __init__(self):
        self.routes=[route('/rotate', rotate)]
        self.called=0
    async def __call__(self, scope, receive, send):
        self.called+=1
        if scope['type']=='lifespan':
            while True:
                m=await receive()
                if m['type']=='lifespan.startup':
                    await send({'type':'lifespan.startup.complete'})
                else:
                    await send({'type':'lifespan.shutdown.complete'});return
        elif scope['type']=='http':
            await send({'type':'http.response.start','status':200,'headers':[]})
            await send({'type':'http.response.body','body':b'ok'})

async def invoke(app, typ, messages):
    items=iter(messages); sent=[]
    async def recv():return next(items)
    async def send(x):sent.append(x)
    await app({'type':typ},recv,send)
    return sent

class StartupGuardTests(unittest.TestCase):
    def setUp(self):
        self.inner=Inner()
        self.anchor=inspect_live_routes(self.inner,allowed_endpoint=rotate)['sha256']
        self.guard=RotationAdmissionASGI(self.inner,allowed_endpoint=rotate,expected_sha256=self.anchor)
    def run_async(self,c):return asyncio.run(c)
    def test_no_http_before_startup(self):
        result=self.run_async(invoke(self.guard,'http',[]))
        self.assertEqual(503,result[0]['status']);self.assertEqual(0,self.inner.called)
    def test_successful_lifespan(self):
        result=self.run_async(invoke(self.guard,'lifespan',[{'type':'lifespan.startup'},{'type':'lifespan.shutdown'}]))
        self.assertEqual(['lifespan.startup.complete','lifespan.shutdown.complete'],[x['type'] for x in result])
        self.assertFalse(self.guard.admitted)
        self.assertEqual(503,self.run_async(invoke(self.guard,'http',[]))[0]['status'])
    def test_bad_anchor_fails_startup(self):
        self.guard.expected_sha256='0'*64
        result=self.run_async(invoke(self.guard,'lifespan',[{'type':'lifespan.startup'}]))
        self.assertEqual('lifespan.startup.failed',result[0]['type'])
        self.assertEqual(0,self.inner.called)
    def test_legacy_route_fails_startup(self):
        self.inner.routes.append(route('/old/epoch',health))
        result=self.run_async(invoke(self.guard,'lifespan',[{'type':'lifespan.startup'}]))
        self.assertEqual('lifespan.startup.failed',result[0]['type'])
    def test_route_drift_denies_request(self):
        self.run_async(invoke(self.guard,'lifespan',[{'type':'lifespan.startup'},{'type':'lifespan.shutdown'}]))
        self.inner.routes.append(route('/old/epoch',health))
        self.assertEqual(503,self.run_async(invoke(self.guard,'http',[]))[0]['status'])
        self.assertFalse(self.guard.admitted)
    def test_route_drift_denies_websocket(self):
        self.run_async(invoke(self.guard,'lifespan',[{'type':'lifespan.startup'},{'type':'lifespan.shutdown'}]))
        self.inner.routes.append(route('/old/epoch',health))
        self.assertEqual('websocket.close',self.run_async(invoke(self.guard,'websocket',[]))[0]['type'])
    def test_missing_endpoint(self):
        self.inner.routes.clear()
        self.assertEqual('lifespan.startup.failed',self.run_async(invoke(self.guard,'lifespan',[{'type':'lifespan.startup'}]))[0]['type'])
    def test_invalid_config(self):
        with self.assertRaisesRegex(ValueError,'CONFIG'):
            RotationAdmissionASGI(self.inner,allowed_endpoint=rotate,expected_sha256='bad')
    def test_mutated_method_denied(self):
        self.run_async(invoke(self.guard,'lifespan',[{'type':'lifespan.startup'},{'type':'lifespan.shutdown'}]))
        self.inner.routes[0].methods={'GET'}
        self.assertEqual(503,self.run_async(invoke(self.guard,'http',[]))[0]['status'])
