import tempfile
import unittest
from pathlib import Path
from odmm_native_transaction_v2119 import NativeStaging, MigrationBlocked

class StagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        p = Path(self.tmp.name)
        self.src, self.dst = p/'source', p/'target'
        self.src.mkdir(); self.dst.mkdir()
        (self.src/'a.txt').write_bytes(b'hello')
        self.db = p/'audit.sqlite'
        self.stage = NativeStaging(self.src, self.dst, self.db)

    def tearDown(self):
        self.stage.close(); self.tmp.cleanup()

    def test_stage_and_verify(self):
        result = self.stage.stage('a.txt', fence=lambda: True)
        self.assertEqual(result['state'], 'VERIFIED')
        self.assertFalse(result['cutover_authorized'])
        self.assertEqual((self.dst/'a.txt').read_bytes(), b'hello')

    def test_fence_fail_closed(self):
        with self.assertRaises(MigrationBlocked): self.stage.stage('a.txt', fence=lambda: 1)
        self.assertFalse((self.dst/'a.txt').exists())

    def test_traversal(self):
        with self.assertRaises(MigrationBlocked): self.stage.stage('../a.txt', fence=lambda: True)

    def test_existing_target_protected(self):
        (self.dst/'a.txt').write_bytes(b'original')
        with self.assertRaises(MigrationBlocked): self.stage.stage('a.txt', fence=lambda: True)
        self.assertEqual((self.dst/'a.txt').read_bytes(), b'original')

    def test_recovery_pending_after_lost_fence(self):
        checks = iter((True, False))
        with self.assertRaises(MigrationBlocked): self.stage.stage('a.txt', fence=lambda: next(checks))
        self.assertEqual(self.stage.pending(), ['a.txt'])
        self.assertFalse((self.dst/'a.txt').exists())

    def test_recovery_retry(self):
        checks = iter((True, False))
        with self.assertRaises(MigrationBlocked): self.stage.stage('a.txt', fence=lambda: next(checks))
        self.stage.close()
        self.stage = NativeStaging(self.src, self.dst, self.db)
        self.stage.stage('a.txt', fence=lambda: True)
        self.assertEqual(self.stage.pending(), [])

    def test_source_symlink_blocked(self):
        (self.src/'link').symlink_to(self.src/'a.txt')
        with self.assertRaises(MigrationBlocked): self.stage.stage('link', fence=lambda: True)

    def test_target_symlink_blocked(self):
        (self.dst/'a.txt').symlink_to(self.src/'a.txt')
        with self.assertRaises(MigrationBlocked): self.stage.stage('a.txt', fence=lambda: True)

    def test_nested_without_target_parent_blocked(self):
        (self.src/'sub').mkdir(); (self.src/'sub'/'b').write_bytes(b'b')
        with self.assertRaises(MigrationBlocked): self.stage.stage('sub/b', fence=lambda: True)

if __name__ == '__main__': unittest.main()
