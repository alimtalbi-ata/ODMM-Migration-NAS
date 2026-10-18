import unittest
from odmm_operations_security import Principal, require_permission, make_request_authorizer
from odmm_operations_app import create_operations_app

class SecurityTests(unittest.TestCase):
    def test_verified_viewer_can_read(self):
        self.assertEqual(require_permission(Principal('alice',frozenset({'viewer'}),True),'operations:read').subject,'alice')
    def test_unverified_denied(self):
        with self.assertRaises(PermissionError): require_permission(Principal('alice',frozenset({'admin'})),'operations:read')
    def test_unknown_role_denied(self):
        with self.assertRaises(PermissionError): require_permission(Principal('alice',frozenset({'root'}),True),'operations:read')
    def test_empty_subject_denied(self):
        with self.assertRaises(PermissionError): require_permission(Principal(' ',frozenset({'viewer'}),True),'operations:read')
    def test_viewer_cannot_read_audit(self):
        with self.assertRaises(PermissionError): require_permission(Principal('alice',frozenset({'viewer'}),True),'audit:read')
    def test_auditor_can_read_audit(self):
        require_permission(Principal('alice',frozenset({'auditor'}),True),'audit:read')
    def test_unsupported_permission_denied(self):
        with self.assertRaises(PermissionError): require_permission(Principal('alice',frozenset({'admin'}),True),'operations:write')
    def test_fail_closed_resolver(self):
        auth=make_request_authorizer(lambda req: (_ for _ in ()).throw(ValueError('invalid')))
        self.assertFalse(auth(object()))
    def test_authorizer_verified_only(self):
        auth=make_request_authorizer(lambda req: Principal('alice',frozenset({'viewer'}),True))
        self.assertTrue(auth(object()))
    def test_missing_resolver_denied(self):
        with self.assertRaises(ValueError): create_operations_app(registry_path='x',resolve_verified_principal=None)
    def test_composed_app_same_boundary(self):
        try: import fastapi
        except ImportError: self.skipTest('FastAPI optional')
        import tempfile,sqlite3,os
        with tempfile.TemporaryDirectory() as d:
            p=os.path.join(d,'registry.db')
            with sqlite3.connect(p) as db: db.execute('create table jobs (id text,source text,target text,state text,created_at text)')
            app=create_operations_app(registry_path=p,resolve_verified_principal=lambda r: Principal('alice',frozenset({'viewer'}),True))
            paths={route.path for route in app.routes}
            self.assertIn('/operations',paths)
            self.assertIn('/api/v1/operations/overview',paths)
            self.assertFalse(any('POST' in (route.methods or set()) for route in app.routes))
