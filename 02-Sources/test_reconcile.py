import hashlib
import tempfile
import unittest
from pathlib import Path
from reconcile import ReconciliationRegistry, probe_local_capabilities

class RecoveryClassificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.registry = ReconciliationRegistry(str(self.root/'state.db'))
        self.addCleanup(self.registry.db.close)

    def test_remote_capabilities_not_claimed(self):
        cap = probe_local_capabilities(self.root)
        self.assertFalse(cap['nfs_durability_qualified'])
        self.assertFalse(cap['smb_durability_qualified'])

    def test_unknown_intent(self):
        with self.assertRaises(KeyError):
            self.registry.classify_recovery('missing')

    def test_unsafe_directory(self):
        with self.assertRaises(ValueError):
            probe_local_capabilities(self.root/'not-here')

if __name__ == '__main__':
    unittest.main()
