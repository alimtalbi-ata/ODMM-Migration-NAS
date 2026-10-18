import unittest
from native_rotation_production_lockdown import verify_production_routes, production_policy_digest
from native_rotation_live_route_gate import inspect_live_routes

class Route:
    def __init__(self,path,endpoint,methods=('POST',)):
        self.path=path;self.endpoint=endpoint;self.methods=set(methods)
class App:
    def __init__(self,*routes):self.routes=list(routes)

def rotate():pass
def health():pass
def impostor():pass

class ProductionLockdownTests(unittest.TestCase):
    def setUp(self):
        self.app=App(Route('/api/v1/security/rotation',rotate),Route('/health',health,('GET',)))
        self.allowed=[('/health',('GET',),health)]
        self.policy=production_policy_digest(self.allowed)
        self.routes=inspect_live_routes(self.app,allowed_endpoint=rotate)['sha256']
    def verify(self,**kw):
        return verify_production_routes(self.app,rotation_endpoint=rotate,allowed_routes=kw.get('allowed',self.allowed),trusted_policy_sha256=kw.get('policy',self.policy),trusted_routes_sha256=kw.get('routes',self.routes))
    def test_valid(self):self.assertTrue(self.verify()['admitted'])
    def test_policy_pin_required(self):
        with self.assertRaisesRegex(ValueError,'POLICY_ANCHOR_REQUIRED'):self.verify(policy=None)
    def test_route_pin_required(self):
        with self.assertRaisesRegex(ValueError,'ROUTE_ANCHOR_REQUIRED'):self.verify(routes=None)
    def test_policy_drift(self):
        with self.assertRaisesRegex(ValueError,'POLICY_ANCHOR_MISMATCH'):self.verify(policy='0'*64)
    def test_route_drift(self):
        with self.assertRaisesRegex(ValueError,'ROUTE_ANCHOR_MISMATCH'):self.verify(routes='0'*64)
    def test_alias_handler_rejected_even_with_updated_route_pin(self):
        self.app.routes.append(Route('/api/v1/execute',impostor))
        new_hash=inspect_live_routes(self.app,allowed_endpoint=rotate)['sha256']
        with self.assertRaisesRegex(ValueError,'UNAPPROVED_ROUTE'):self.verify(routes=new_hash)
    def test_replaced_handler_rejected_even_with_updated_route_pin(self):
        self.app.routes[1].endpoint=impostor
        new_hash=inspect_live_routes(self.app,allowed_endpoint=rotate)['sha256']
        with self.assertRaisesRegex(ValueError,'UNAPPROVED_ROUTE'):self.verify(routes=new_hash)
    def test_duplicate_route_rejected(self):
        self.app.routes.append(Route('/health',health,('GET',)))
        new_hash=inspect_live_routes(self.app,allowed_endpoint=rotate)['sha256']
        with self.assertRaisesRegex(ValueError,'DUPLICATE_ROUTE'):self.verify(routes=new_hash)
    def test_extra_allowlist_rejected(self):
        with self.assertRaisesRegex(ValueError,'POLICY_ANCHOR_MISMATCH'):self.verify(allowed=self.allowed+[('/x',('GET',),health)])
    def test_rotation_alias_rejected(self):
        self.app.routes.append(Route('/api/v1/epoch/rotate',impostor))
        with self.assertRaisesRegex(ValueError,'LIVE_UNGUARDED'):self.verify()

class AdmissionCallbackTests(unittest.TestCase):
    def test_rejects_denied_callback(self):
        from native_rotation_startup_guard import RotationAdmissionASGI
        app=App(Route('/api/v1/security/rotation',rotate))
        digest=inspect_live_routes(app,allowed_endpoint=rotate)['sha256']
        wrapper=RotationAdmissionASGI(lambda *a:None,allowed_endpoint=rotate,expected_sha256=digest,additional_admission=lambda:{'admitted':False})
        wrapper.app=app
        with self.assertRaisesRegex(ValueError,'ADMISSION_DENIED'):wrapper.verify()
    def test_accepts_callback(self):
        from native_rotation_startup_guard import RotationAdmissionASGI
        app=App(Route('/api/v1/security/rotation',rotate))
        digest=inspect_live_routes(app,allowed_endpoint=rotate)['sha256']
        wrapper=RotationAdmissionASGI(lambda *a:None,allowed_endpoint=rotate,expected_sha256=digest,additional_admission=lambda:{'admitted':True})
        wrapper.app=app
        self.assertEqual(digest,wrapper.verify()['sha256'])
