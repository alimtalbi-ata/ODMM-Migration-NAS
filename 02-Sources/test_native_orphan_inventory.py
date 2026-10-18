import os
import unittest
from native_orphan_inventory import inspect_orphans
from native_posix_migration import MigrationBlocked
from test_native_posix_migration import NativeMigrationTests

class OrphanInventoryTests(unittest.TestCase):
    setUp=NativeMigrationTests.setUp
    engine=NativeMigrationTests.engine
    def test_empty(self):
        with self.engine() as e: self.assertEqual(inspect_orphans(e),[])
    def test_regular(self):
        name='.odmm-'+'a'*32+'.part'; (self.dst/name).write_bytes(b'abc')
        with self.engine() as e:
            rows=inspect_orphans(e)
            self.assertEqual(len(rows),1)
            self.assertFalse(rows[0]['auto_delete_authorized'])
        self.assertTrue((self.dst/name).exists())
    def test_nonmatching_ignored(self):
        (self.dst/'.odmm-unsafe.part').write_bytes(b'abc')
        with self.engine() as e: self.assertEqual(inspect_orphans(e),[])
    def test_symlink_rejected(self):
        (self.dst/('.odmm-'+'a'*32+'.part')).symlink_to(self.src/'a')
        with self.engine() as e, self.assertRaises(MigrationBlocked): inspect_orphans(e)
    def test_nested(self):
        (self.dst/'nested').mkdir(); (self.dst/'nested'/('.odmm-'+'b'*32+'.part')).write_bytes(b'x')
        with self.engine() as e: self.assertEqual(len(inspect_orphans(e,'nested')),1)
    def test_traversal_rejected(self):
        with self.engine() as e, self.assertRaises(MigrationBlocked): inspect_orphans(e,'../src')
    def test_root_replacement_rejected(self):
        with self.engine() as e:
            os.rename(self.dst,self.dst.with_name('old'))
            self.dst.mkdir()
            with self.assertRaises(MigrationBlocked): inspect_orphans(e)
