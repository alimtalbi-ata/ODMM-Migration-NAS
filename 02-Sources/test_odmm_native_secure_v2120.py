import tempfile
import unittest
from pathlib import Path
from odmm_native_secure_v2120 import SecureStaging, Blocked

class SecureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        p = Path(self.temp.name)
        self.src = p/'src'; self.dst = p/'dst'
        self.src.mkdir(); self.dst.mkdir()
        (self.src/'x').write_bytes(b'hello')
        self.engine = SecureStaging(self.src, self.dst, p/'audit.db')
    def tearDown(self):
        self.engine.close(); self.temp.cleanup()
    def test_copy(self):
        r = self.engine.stage('x', fence=lambda: True)
        self.assertEqual(r['state'], 'VERIFIED')
        self.assertFalse(r['cutover_authorized'])
        self.assertEqual((self.dst/'x').read_bytes(), b'hello')
    def test_strict_fence(self):
        with self.assertRaises(Blocked): self.engine.stage('x', fence=lambda: 1)
    def test_second_fence(self):
        checks = iter([True, False])
        with self.assertRaises(Blocked): self.engine.stage('x', fence=lambda: next(checks))
        self.assertEqual(self.engine.pending(), ['x'])
        self.assertFalse((self.dst/'x').exists())
    def test_existing(self):
        (self.dst/'x').write_bytes(b'old')
        with self.assertRaises(Blocked): self.engine.stage('x', fence=lambda: True)
        self.assertEqual((self.dst/'x').read_bytes(), b'old')
    def test_traversal(self):
        for p in ('../x', '/x', 'a//x', 'a/../x', 'a/./x', 'a\\x'):
            with self.subTest(p=p), self.assertRaises(Blocked): self.engine.stage(p, fence=lambda: True)
    def test_symlink_source(self):
        (self.src/'link').symlink_to('x')
        with self.assertRaises(Blocked): self.engine.stage('link', fence=lambda: True)
    def test_symlink_parent(self):
        (self.src/'dir').symlink_to(self.src, target_is_directory=True)
        (self.dst/'dir').mkdir()
        with self.assertRaises(OSError): self.engine.stage('dir/x', fence=lambda: True)
    def test_nested(self):
        (self.src/'sub').mkdir(); (self.dst/'sub').mkdir()
        (self.src/'sub'/'a').write_bytes(b'a')
        self.engine.stage('sub/a', fence=lambda: True)
        self.assertEqual((self.dst/'sub'/'a').read_bytes(), b'a')
    def test_hardlink_source(self):
        (self.src/'hard').hardlink_to(self.src/'x')
        with self.assertRaises(Blocked): self.engine.stage('x', fence=lambda: True)
    def test_restart_pending(self):
        checks = iter([True, False])
        with self.assertRaises(Blocked): self.engine.stage('x', fence=lambda: next(checks))
        self.engine.close()
        self.engine = SecureStaging(self.src, self.dst, self.src.parent/'audit.db')
        self.engine.stage('x', fence=lambda: True)
        self.assertEqual(self.engine.pending(), [])
if __name__ == '__main__': unittest.main()
