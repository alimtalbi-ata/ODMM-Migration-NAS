import os
import tempfile
import unittest
from pathlib import Path
from native_dirfd_guard import parent_fd, read_regular, publish_noreplace, parts_of
from native_posix_migration import MigrationBlocked

class DirfdGuardTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup)
        self.root = Path(self.t.name); (self.root/'dir').mkdir()
        (self.root/'dir'/'a').write_bytes(b'abc')
    def test_nested_read(self):
        self.assertEqual(read_regular(self.root, 'dir/a')[0], b'abc')
    def test_invalid_paths(self):
        for p in ('../a', 'dir//a', '/dir/a', 'dir/./a', 'dir/../a', 'dir\\a', 'dir/\x00a', ''):
            with self.subTest(p=p), self.assertRaises(MigrationBlocked): parts_of(p)
    def test_symlink_parent(self):
        (self.root/'link').symlink_to(self.root/'dir',target_is_directory=True)
        with self.assertRaises(MigrationBlocked): read_regular(self.root,'link/a')
    def test_symlink_file(self):
        (self.root/'dir'/'b').symlink_to('a')
        with self.assertRaises(MigrationBlocked): read_regular(self.root,'dir/b')
    def test_fifo_rejected_without_block(self):
        os.mkfifo(self.root/'dir'/'fifo')
        with self.assertRaises(MigrationBlocked): read_regular(self.root,'dir/fifo')
    def test_oversize_rejected(self):
        (self.root/'dir'/'a').write_bytes(b'a'*(1024*1024+1))
        with self.assertRaises(MigrationBlocked): read_regular(self.root,'dir/a')
    def test_pinned_parent_survives_rename(self):
        with parent_fd(self.root,'dir/a') as (fd,name):
            (self.root/'dir').rename(self.root/'moved')
            self.assertEqual(os.stat(name,dir_fd=fd).st_size,3)
    def test_publish_noreplace(self):
        (self.root/'dir'/'temp').write_bytes(b'data')
        with parent_fd(self.root,'dir/final') as (fd,name):
            publish_noreplace(fd,'temp',name)
            with self.assertRaises(MigrationBlocked): publish_noreplace(fd,'temp',name)
        self.assertEqual((self.root/'dir'/'final').read_bytes(),b'data')
    def test_publish_rejects_path_escape(self):
        with parent_fd(self.root,'dir/a') as (fd,name):
            with self.assertRaises(MigrationBlocked): publish_noreplace(fd,'../a','b')
