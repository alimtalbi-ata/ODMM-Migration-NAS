import unittest
from odmm_operations_portal import PAGE, _csp, attach_operations_portal

class PortalTests(unittest.TestCase):
    def test_no_mutation_actions(self):
        self.assertNotIn('method="post"',PAGE.lower())
        self.assertNotIn("method:'POST'",PAGE)
        self.assertIn("credentials:'same-origin'",PAGE)
    def test_safe_dom(self):
        self.assertIn('td.textContent=',PAGE)
        self.assertNotIn('innerHTML',PAGE)
    def test_csp_hashes(self):
        self.assertNotIn('PLACEHOLDER',_csp())
        self.assertIn("frame-ancestors 'none'",_csp())
        self.assertNotIn('unsafe-inline',_csp())
    def test_authorization_mandatory(self):
        with self.assertRaises(ValueError): attach_operations_portal(object(),authorize=None)
    def test_fake_app_route(self):
        class App:
            def __init__(self): self.routes=[]
            def add_api_route(self,*a,**kw): self.routes.append((a,kw))
        try: import fastapi
        except ImportError: self.skipTest('FastAPI optional')
        app=App(); attach_operations_portal(app,authorize=lambda _:True)
        self.assertEqual(app.routes[0][0][0],'/operations')
    def test_denied(self):
        try:
            import fastapi
            from starlette.requests import Request
        except ImportError: self.skipTest('FastAPI optional')
        class App:
            def add_api_route(self,*a,**kw): pass
        fn=attach_operations_portal(App(),authorize=lambda _:False)
        import asyncio
        with self.assertRaises(fastapi.HTTPException) as err:
            asyncio.run(fn(Request({'type':'http','method':'GET','path':'/operations','headers':[]})))
        self.assertEqual(err.exception.status_code,403)
