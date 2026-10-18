import tempfile, unittest
from pathlib import Path
from odmm_mount_risk_preflight_v2021 import assess, verify, classify
class Tests(unittest.TestCase):
 def pair(self,**kwargs):
  with tempfile.TemporaryDirectory() as d:
   a=Path(d)/'a';b=Path(d)/'b';a.mkdir();b.mkdir()
   return assess(a,b,required=['content','acl','xattrs'],**kwargs)
 def test_report(self):
  r=self.pair();self.assertTrue(verify(r));self.assertFalse(r['cutover_authorized'])
 def test_no_writes(self):
  with tempfile.TemporaryDirectory() as d:
   a=Path(d)/'a';b=Path(d)/'b';a.mkdir();b.mkdir()
   assess(a,b,required=['content']);self.assertEqual(list(a.iterdir()),[]);self.assertEqual(list(b.iterdir()),[])
 def test_tamper(self):
  r=self.pair();r['status']='PASS';self.assertFalse(verify(r))
 def test_cutover_tamper(self):
  r=self.pair();r['cutover_authorized']=True;self.assertFalse(verify(r))
 def test_classify_nfs(self):
  self.assertEqual(classify({'mount':{'status':'OBSERVED','filesystem_type':'nfs4'}})['protocol'],'NFS')
 def test_classify_smb(self):
  self.assertEqual(classify({'mount':{'status':'OBSERVED','filesystem_type':'cifs'}})['protocol'],'SMB')
 def test_unknown(self):
  self.assertEqual(classify({'mount':{'status':'UNKNOWN'}})['protocol'],'UNKNOWN')
 def test_no_promote(self):
  r=self.pair(source_capabilities={'content':'SUPPORTED','acl':'SUPPORTED','xattrs':'SUPPORTED'},target_capabilities={'content':'SUPPORTED','acl':'SUPPORTED','xattrs':'SUPPORTED'});self.assertTrue(any(x['risk']=='INDEPENDENT_FIDELITY_NOT_PROVEN' for x in r['risks']))
 def test_overlap(self):
  with tempfile.TemporaryDirectory() as d:
   a=Path(d)/'a';b=a/'b';b.mkdir(parents=True)
   with self.assertRaisesRegex(ValueError,'OVERLAPPING'): assess(a,b,required=['content'])
 def test_bad_domains(self):
  with self.assertRaises(ValueError):self.pair() if False else assess('/tmp','/var',required=['nonsense'])
 def test_external_explicit(self):
  r=self.pair(strategy='EXPLICIT_EXTERNAL');self.assertFalse(r['native_engine_default']);self.assertFalse(r['silent_fallback_allowed'])
if __name__=='__main__':unittest.main()
