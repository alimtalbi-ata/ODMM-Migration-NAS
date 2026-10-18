import tempfile,unittest
from pathlib import Path
from registry import Registry
from collector_provenance import ProvenanceRegistry
class LifecycleTests(unittest.TestCase):
 def test_registry_context_closes(self):
  with tempfile.TemporaryDirectory() as d:
   with Registry(Path(d)/'db.sqlite') as r: db=r.db; r.create_job('a','b')
   with self.assertRaises(Exception): db.execute('SELECT 1')
 def test_provenance_context_closes(self):
  with tempfile.TemporaryDirectory() as d:
   with ProvenanceRegistry(Path(d)/'db.sqlite',{}) as p: db=p.db
   with self.assertRaises(Exception): db.execute('SELECT 1')
