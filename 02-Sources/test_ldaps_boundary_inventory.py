import os
import tempfile
import unittest
from pathlib import Path
from ldaps_boundary_inventory import LegacyBoundaryInventory, BoundaryInventoryError

class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'ldaps_old.py').write_text('class Old:\n    def acknowledge(self): pass\n    def set_grant(self): pass\n')
        self.db=self.root/'rbac.sqlite'; self.db.write_bytes(b'fake'); self.db.chmod(0o600)
        self.inv=LegacyBoundaryInventory(self.root,database_paths=[self.db])
    def test_detects_sensitive_entrypoints(self):
        self.assertEqual({x['method'] for x in self.inv.inspect()['legacy_entrypoints']},{'acknowledge','set_grant'})
    def test_never_claims_runtime_isolation(self):self.assertFalse(self.inv.inspect()['runtime_isolation_verified'])
    def test_never_authorizes_cutover(self):self.assertFalse(self.inv.inspect()['cutover_authorized'])
    def test_stable_hash(self):self.assertEqual(self.inv.inspect()['sha256'],self.inv.inspect()['sha256'])
    def test_review_requires_confirmation(self):
        with self.assertRaisesRegex(BoundaryInventoryError,'REVIEW_REQUIRED'):
            self.inv.require_review(approved_hash=self.inv.inspect()['sha256'],operator_confirmed=False)
    def test_review_requires_exact_hash(self):
        with self.assertRaisesRegex(BoundaryInventoryError,'REVIEW_REQUIRED'):
            self.inv.require_review(approved_hash='0'*64,operator_confirmed=True)
    def test_review_current_inventory(self):
        out=self.inv.require_review(approved_hash=self.inv.inspect()['sha256'],operator_confirmed=True)
        self.assertEqual(out['status'],'INVENTORY_REVIEWED_NOT_ISOLATION_PROOF')
    def test_change_invalidates_review(self):
        h=self.inv.inspect()['sha256']; (self.root/'ldaps_old.py').write_text('def recover(): pass\n')
        with self.assertRaises(BoundaryInventoryError):self.inv.require_review(approved_hash=h,operator_confirmed=True)
    def test_group_writable_database_rejected(self):
        self.db.chmod(0o660)
        with self.assertRaisesRegex(BoundaryInventoryError,'DATABASE_WRITE_EXPOSURE'):
            self.inv.require_review(approved_hash=self.inv.inspect()['sha256'],operator_confirmed=True)
    def test_symlink_source_rejected(self):
        (self.root/'ldaps_link.py').symlink_to(self.root/'ldaps_old.py')
        with self.assertRaisesRegex(BoundaryInventoryError,'SYMLINKED_SOURCE_REFUSED'):self.inv.inspect()
    def test_bad_syntax_rejected(self):
        (self.root/'ldaps_bad.py').write_text('def broken(:')
        with self.assertRaisesRegex(BoundaryInventoryError,'SOURCE_UNREADABLE'):self.inv.inspect()
    def test_missing_database_rejected(self):
        self.db.unlink()
        with self.assertRaisesRegex(BoundaryInventoryError,'DATABASE_PATH_MISSING'):self.inv.inspect()
    def test_directory_as_database_rejected(self):
        self.db.unlink();self.db.mkdir()
        with self.assertRaisesRegex(BoundaryInventoryError,'UNSAFE_DATABASE_FILE_TYPE'):self.inv.inspect()
