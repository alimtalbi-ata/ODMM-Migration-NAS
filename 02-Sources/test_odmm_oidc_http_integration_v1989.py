"""Signed JWT + real ASGI HTTP OIDC session integration tests. Author: Abdelhalim Talbi."""
from pathlib import Path
from fastapi.testclient import TestClient
from odmm_oidc_browser import create_browser_app
from odmm_oidc_session_store import SQLiteOIDCStore
from test_odmm_oidc_browser_v1975 import BrowserFlowTests

class BrowserHTTPIntegrationTests(BrowserFlowTests):
    def setUp(self):
        super().setUp()
        self.store_path = Path(self.tmp.name) / 'oidc-sessions.sqlite'
        self.client.close()
        self.client = TestClient(self.make_app(), base_url='https://odmm.example', follow_redirects=False)

    def make_app(self):
        def exchange(code, pkce, redirect):
            self.assertEqual(code, 'valid-code')
            return {'id_token':self.token(nonce=self.nonce),'access_token':self.token()}
        return create_browser_app(registry_path=str(self.db),grants_path=str(self.grants),
            verifier=self.verifier,config=self.config,exchange_code=exchange,
            session_store=SQLiteOIDCStore(self.store_path))

    def login(self):
        state=self.begin()
        response=self.client.get('/auth/callback',params={'state':state,'code':'valid-code'})
        self.assertEqual(response.status_code,303)

    def test_csrf_required_for_logout(self):
        self.login()
        self.assertEqual(self.client.post('/auth/logout',headers={'origin':'https://odmm.example'}).status_code,403)
        self.assertEqual(self.client.post('/auth/logout',headers={'origin':'https://odmm.example','x-odmm-csrf':'wrong'}).status_code,403)
        token=self.client.cookies.get('__Host-odmm_csrf')
        self.assertEqual(self.client.post('/auth/logout',headers={'origin':'https://odmm.example','x-odmm-csrf':token}).status_code,303)
        self.assertEqual(self.client.get('/api/v1/operations/jobs').status_code,403)

    def test_restart_and_revocation(self):
        self.login()
        cookies=self.client.cookies
        self.client.close()
        self.client=TestClient(self.make_app(),base_url='https://odmm.example',follow_redirects=False,cookies=cookies)
        self.assertEqual(self.client.get('/api/v1/operations/jobs').status_code,200)
        token=self.client.cookies.get('__Host-odmm_csrf')
        self.assertEqual(self.client.post('/auth/logout',headers={'origin':'https://odmm.example','x-odmm-csrf':token}).status_code,303)
        self.assertEqual(self.client.get('/api/v1/operations/jobs').status_code,403)
