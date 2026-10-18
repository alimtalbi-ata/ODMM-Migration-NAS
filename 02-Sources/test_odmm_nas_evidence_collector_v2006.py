import os
import tempfile
import unittest
from pathlib import Path
from odmm_nas_evidence_collector_v2006 import collect,compare,CollectionError
class Tests(unittest.TestCase):
 def test_equal_content_and_metadata(self):
  with tempfile.TemporaryDirectory() as d:
   a=Path(d)/'a';b=Path(d)/'b';a.mkdir();b.mkdir()
   (a/'x').write_bytes(b'hello');(b/'x').write_bytes(b'hello')
   st=(a/'x').stat();os.utime(b/'x',ns=(st.st_atime_ns,st.st_mtime_ns))
   r=compare(collect(a),collect(b));self.assertEqual(r['difference_count'],0);self.assertFalse(r['cutover_authorized'])
 def test_content_mismatch(self):
  with tempfile.TemporaryDirectory() as d:
   a=Path(d)/'a';b=Path(d)/'b';a.mkdir();b.mkdir();(a/'x').write_bytes(b'hello');(b/'x').write_bytes(b'world')
   self.assertIn('MISMATCH_SHA256',[x['issue'] for x in compare(collect(a),collect(b))['differences']])
 def test_missing_file(self):
  with tempfile.TemporaryDirectory() as d:
   a=Path(d)/'a';b=Path(d)/'b';a.mkdir();b.mkdir();(a/'x').write_text('x')
   self.assertIn('TARGET_MISSING',[x['issue'] for x in compare(collect(a),collect(b))['differences']])
 def test_symlink_not_followed(self):
  with tempfile.TemporaryDirectory() as d:
   a=Path(d)/'a';a.mkdir();(a/'loop').symlink_to(a,target_is_directory=True)
   self.assertEqual(collect(a)['entries']['loop']['kind'],'symlink')
 def test_limit_fail_closed(self):
  with tempfile.TemporaryDirectory() as d:
   a=Path(d);(a/'x').write_bytes(b'hello')
   with self.assertRaises(CollectionError):collect(a,max_bytes=4)
 def test_bad_root(self):
  with tempfile.TemporaryDirectory() as d:
   a=Path(d);(a/'link').symlink_to(a,target_is_directory=True)
   with self.assertRaises(CollectionError):collect(a/'link')
if __name__=='__main__':unittest.main()
