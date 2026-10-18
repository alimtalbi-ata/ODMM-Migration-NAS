import tempfile
import unittest
from pathlib import Path
from native_posix_migration import NativePosixMigration, MigrationBlocked
from native_incremental_inventory import IncrementalInventory

class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); root=Path(self.tmp.name)
        self.src=root/'src'; self.dst=root/'dst'; self.src.mkdir(); self.dst.mkdir()
        self.engine=NativePosixMigration(self.src,self.dst,root/'state.db')
        self.inv=IncrementalInventory(self.engine)
    def tearDown(self): self.engine.close(); self.tmp.cleanup()
    def test_empty(self): self.assertEqual(self.inv.capture()['count'],0)
    def test_add_modify_delete(self):
        (self.src/'a').write_text('one'); (self.src/'b').write_text('two')
        a=self.inv.capture()['pass_id']
        (self.src/'a').write_text('changed'); (self.src/'b').unlink(); (self.src/'c').write_text('new')
        b=self.inv.capture()['pass_id']; d=self.inv.diff(a,b)
        self.assertEqual(d['added'],['c']);self.assertEqual(d['deleted'],['b']);self.assertEqual(d['modified'],['a'])
        self.assertFalse(d['cutover_authorized'])
    def test_nested(self):
        (self.src/'d').mkdir(); (self.src/'d'/'a').write_bytes(b'x')
        self.assertEqual(self.inv.capture()['count'],1)
    def test_symlink_refused(self):
        (self.src/'bad').symlink_to('/tmp')
        with self.assertRaises(MigrationBlocked):self.inv.capture()
        self.assertEqual(self.engine.db.execute('SELECT status FROM inventory_passes').fetchone()[0],'FAILED')
    def test_unknown_pass_refused(self):
        with self.assertRaises(MigrationBlocked):self.inv.diff('no','no')
    def test_restart_persistence(self):
        a=self.inv.capture()['pass_id']; self.engine.close()
        self.engine=NativePosixMigration(self.src,self.dst,Path(self.tmp.name)/'state.db')
        self.inv=IncrementalInventory(self.engine)
        b=self.inv.capture()['pass_id']; self.assertEqual(self.inv.diff(a,b)['unchanged_count'],0)
    def test_no_copy(self):
        (self.src/'a').write_text('x');self.inv.capture()
        self.assertFalse((self.dst/'a').exists())
    def test_same_content_replaced_inode(self):
        (self.src/'a').write_text('x'); a=self.inv.capture()['pass_id']
        (self.src/'a').unlink();(self.src/'a').write_text('x');b=self.inv.capture()['pass_id']
        self.assertEqual(self.inv.diff(a,b)['modified'],['a'])
if __name__=='__main__':unittest.main()
