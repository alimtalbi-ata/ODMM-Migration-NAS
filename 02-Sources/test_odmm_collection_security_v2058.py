import sqlite3,tempfile,unittest
from pathlib import Path
from odmm_collection_security_v2058 import SecurityGate
class GateTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.now=[1000];self.g=SecurityGate(Path(self.tmp.name)/'audit.sqlite',max_requests=2,clock=lambda:self.now[0]);self.kw=dict(actor='alice',role='operator',origin='https://odmm.example',expected_origin='https://odmm.example',csrf_cookie='a'*32,csrf_header='a'*32)
 def tearDown(self):self.tmp.cleanup()
 def test_allow(self):self.assertEqual(self.g.check(**self.kw),'ALLOW')
 def test_rbac(self):self.assertEqual(self.g.check(**{**self.kw,'role':'viewer'}),'DENY_RBAC')
 def test_csrf(self):self.assertEqual(self.g.check(**{**self.kw,'csrf_header':'b'*32}),'DENY_CSRF')
 def test_origin(self):self.assertEqual(self.g.check(**{**self.kw,'origin':'https://evil.example'}),'DENY_CSRF')
 def test_http(self):self.assertEqual(self.g.check(**{**self.kw,'origin':'http://odmm.example'}),'DENY_CSRF')
 def test_rate(self):
  self.assertEqual(self.g.check(**self.kw),'ALLOW');self.assertEqual(self.g.check(**self.kw),'ALLOW');self.assertEqual(self.g.check(**self.kw),'DENY_RATE')
 def test_reset(self):
  self.g.check(**self.kw);self.g.check(**self.kw);self.now[0]+=61;self.assertEqual(self.g.check(**self.kw),'ALLOW')
 def test_audit_no_actor(self):
  self.g.check(**self.kw)
  with sqlite3.connect(self.g.db_path) as db:
   row=db.execute('select actor_hash,event,outcome from audit').fetchone()
  self.assertNotIn('alice',str(row));self.assertEqual(row[2],'ALLOW')
if __name__=='__main__':unittest.main()
