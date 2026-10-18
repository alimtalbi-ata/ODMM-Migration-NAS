import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from fastapi import Response
from odmm_session_registry_v2062 import SessionRegistry
from odmm_session_lifecycle_v2064 import rotate_session,set_session_cookies,clear_session_cookies

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.now=[1000]
        self.reg=SessionRegistry(Path(self.tmp.name)/'session.sqlite',key=b'k'*32,clock=lambda:self.now[0])
        self.token=self.reg.issue('alice','operator',ttl=200)
    def test_rotation(self):
        new=rotate_session(self.reg,self.token,ttl=60)
        self.assertIsNotNone(new);self.assertIsNone(self.reg.resolve(self.token))
        self.assertEqual(self.reg.resolve(new),{'actor':'alice','role':'operator'})
    def test_no_lifetime_extension(self):
        new=rotate_session(self.reg,self.token,ttl=900)
        self.now[0]=1200
        self.assertIsNone(self.reg.resolve(new))
    def test_replay_rejected(self):
        self.assertIsNotNone(rotate_session(self.reg,self.token))
        self.assertIsNone(rotate_session(self.reg,self.token))
    def test_revoked_rejected(self):
        self.reg.revoke(self.token)
        self.assertIsNone(rotate_session(self.reg,self.token))
    def test_expired_rejected(self):
        self.now[0]=1201
        self.assertIsNone(rotate_session(self.reg,self.token))
    def test_concurrent_single_winner(self):
        with ThreadPoolExecutor(max_workers=12) as pool:
            results=list(pool.map(lambda _:rotate_session(self.reg,self.token),range(20)))
        self.assertEqual(sum(x is not None for x in results),1)
    def test_cookie_flags(self):
        resp=set_session_cookies(Response(),self.token,b'c'*32)
        cookies=resp.headers.getlist('set-cookie')
        self.assertEqual(len(cookies),2)
        self.assertTrue(all('secure' in c.lower() and 'samesite=strict' in c.lower() for c in cookies))
        self.assertIn('httponly',cookies[0].lower())
        self.assertNotIn('httponly',cookies[1].lower())
        self.assertEqual(resp.headers['cache-control'],'no-store')
    def test_clear(self):
        resp=clear_session_cookies(Response())
        self.assertEqual(len(resp.headers.getlist('set-cookie')),2)
    def test_invalid_secret(self):
        with self.assertRaises(ValueError):set_session_cookies(Response(),self.token,b'bad')

if __name__=='__main__':unittest.main()
