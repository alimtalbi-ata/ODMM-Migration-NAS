import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from odmm_oidc_http_entrypoint import create_from_environment, create_oidc_app

class HTTPEntrypointTests(unittest.TestCase):
    def test_missing_config_fails_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'MISSING_REQUIRED_CONFIGURATION'):
                create_from_environment()

    def test_invalid_jwks_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'jwks.json'; p.write_text(json.dumps({'keys':[]}))
            with self.assertRaisesRegex(ValueError,'JWKS_EMPTY'):
                create_oidc_app(registry_path='unused',grants_path='unused',issuer='https://issuer.example',audience='odmm',jwks_path=p)

    def test_missing_jwks_fails_closed(self):
        with self.assertRaises(FileNotFoundError):
            create_oidc_app(registry_path='unused',grants_path='unused',issuer='https://issuer.example',audience='odmm',jwks_path='/not/existing/jwks.json')

    def test_valid_jwks_mounts_only_approved_routes(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        import base64
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        pub=key.public_key().public_numbers()
        enc=lambda x: base64.urlsafe_b64encode(x.to_bytes((x.bit_length()+7)//8,'big')).rstrip(b'=').decode()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'jwks.json'; p.write_text(json.dumps({'keys':[{'kid':'k1','kty':'RSA','alg':'RS256','n':enc(pub.n),'e':enc(pub.e)}]}))
            import sqlite3
            from registry import Registry
            with Registry(str(Path(d)/'registry.db')): pass
            with sqlite3.connect(str(Path(d)/'grants.db')) as conn:
                conn.execute('CREATE TABLE job_grants (subject TEXT, job_id TEXT)')
            app=create_oidc_app(registry_path=str(Path(d)/'registry.db'),grants_path=str(Path(d)/'grants.db'),issuer='https://issuer.example',audience='odmm',jwks_path=p)
            routes={r.path for r in app.routes}
            self.assertIn('/api/v1/operations/jobs',routes)
            self.assertNotIn('/api/v1/operations/unscoped',routes)
            self.assertTrue(all('POST' not in r.methods for r in app.routes))
