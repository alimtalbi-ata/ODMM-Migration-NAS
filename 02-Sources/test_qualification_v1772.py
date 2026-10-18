import unittest, tempfile, sqlite3, os
from pathlib import Path
from qualification_v1772 import compare_metadata,sqlite_health,protocol_capability_report

class QualificationV1772Tests(unittest.TestCase):
 def test_identical_metadata_not_acl_certification(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'a';p.write_bytes(b'abc')
   r=compare_metadata(p,p)
   self.assertEqual(r['status'],'MATCH_METADATA_ONLY')
   self.assertFalse(r['acl_verified'])
 def test_detect_content_size_divergence(self):
  with tempfile.TemporaryDirectory() as d:
   a=Path(d)/'a';b=Path(d)/'b';a.write_bytes(b'a');b.write_bytes(b'ab')
   self.assertIn('size',compare_metadata(a,b)['mismatches'])
 def test_sqlite_integrity_read_only(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'db.sqlite';c=sqlite3.connect(p);c.execute('CREATE TABLE t(id INTEGER PRIMARY KEY)');c.commit();c.close()
   self.assertEqual(sqlite_health(p)['status'],'PASS')
 def test_nas_capability_fail_closed(self):
  with tempfile.TemporaryDirectory() as d:
   r=protocol_capability_report(d)
   self.assertFalse(r['ready_for_remote_writes'])
   self.assertEqual(r['protocol'],'UNDETERMINED')
 def test_symlink_capability_flag(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'link';p.symlink_to('missing')
   self.assertTrue(protocol_capability_report(p)['is_symlink'])
if __name__=='__main__':unittest.main()
