import tempfile,unittest
from pathlib import Path
from odmm_windows_mount_preflight_v2022 import classify_windows_path,observe_windows,assess_pair,verify,severity_risks
class Tests(unittest.TestCase):
 def test_linux_unavailable(self): self.assertEqual(classify_windows_path('/tmp',platform='posix')['status'],'UNSUPPORTED_PLATFORM')
 def test_unc(self): self.assertEqual(classify_windows_path(r'\\server\share',platform='nt')['protocol'],'SMB_CANDIDATE')
 def test_remote_drive(self): self.assertEqual(classify_windows_path('Z:\\',platform='nt',drive_type=4)['protocol'],'REMOTE_UNVERIFIED_PROTOCOL')
 def test_local_drive(self): self.assertEqual(classify_windows_path('C:\\',platform='nt',drive_type=3)['protocol'],'LOCAL')
 def test_unknown_drive(self): self.assertEqual(classify_windows_path('C:\\',platform='nt',drive_type=0)['status'],'UNKNOWN')
 def test_platform_probe(self):
  import os
  if os.name!='nt': self.assertEqual(observe_windows('/tmp')['status'],'UNSUPPORTED_PLATFORM')
 def pair(self,**kw):
  with tempfile.TemporaryDirectory() as d:
   a=Path(d)/'source';b=Path(d)/'target';a.mkdir();b.mkdir()
   return assess_pair(a,b,required=['content','acl','ads'],**kw)
 def test_report(self):
  r=self.pair();self.assertTrue(verify(r));self.assertFalse(r['cutover_authorized'])
 def test_tamper(self):
  r=self.pair();r['risks'][0]['severity']='LOW';self.assertFalse(verify(r))
 def test_no_writes(self):
  with tempfile.TemporaryDirectory() as d:
   a=Path(d)/'a';b=Path(d)/'b';a.mkdir();b.mkdir();assess_pair(a,b,required=['content']);self.assertEqual(list(a.iterdir())+list(b.iterdir()),[])
 def test_remote_risk(self):
  p={'status':'OBSERVED_PATH_SYNTAX','protocol':'SMB_CANDIDATE'};r=self.pair(windows_probes={'source':p,'target':p});self.assertEqual(sum(x['risk']=='REMOTE_PROTOCOL_AND_ACL_UNATTESTED' for x in r['risks']),2)
 def test_invalid_probes(self):
  with self.assertRaises(ValueError): self.pair(windows_probes={'source':{}})
 def test_external_engine(self): self.assertFalse(self.pair(strategy='EXPLICIT_EXTERNAL')['native_engine_default'])
 def test_all_blocker(self): self.assertTrue(all(x['severity']=='BLOCKER' for x in self.pair()['risks']))
if __name__=='__main__':unittest.main()
