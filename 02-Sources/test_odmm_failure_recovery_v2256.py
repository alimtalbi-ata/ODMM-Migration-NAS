"""V225.6: fail-closed tests for filesystem and registry failures (Linux POSIX)."""
import os
import sqlite3
import tempfile
from pathlib import Path
import pytest
from native_posix_migration import NativePosixMigration
from native_migration_errors import MigrationBlocked


def fixture_tree(root):
    src, dst, db = root/'source', root/'target', root/'registry.sqlite'
    src.mkdir(); dst.mkdir()
    (src/'file.bin').write_bytes(b'odmm-failure-recovery' * 4096)
    return src, dst, db


def test_target_exists_never_overwritten():
    with tempfile.TemporaryDirectory() as t:
        src,dst,db=fixture_tree(Path(t))
        (dst/'file.bin').write_bytes(b'existing-critical-data')
        with NativePosixMigration(src,dst,db) as m:
            with pytest.raises(MigrationBlocked,match='TARGET_EXISTS'):
                m.copy('file.bin')
            assert m.db.execute('select count(*) from files').fetchone()[0]==0
        assert (dst/'file.bin').read_bytes()==b'existing-critical-data'


def test_temporary_sync_failure_no_published_file():
    with tempfile.TemporaryDirectory() as t:
        src,dst,db=fixture_tree(Path(t))
        with NativePosixMigration(src,dst,db) as m:
            def disk_error(): raise OSError(28,'Simulated ENOSPC after temp fsync')
            with pytest.raises(OSError): m.copy('file.bin',after_temp_sync=disk_error)
            assert m.db.execute('select count(*) from files').fetchone()[0]==0
            assert m.db.execute('select count(*) from intents').fetchone()[0]==0
        assert not (dst/'file.bin').exists()
        assert not list(dst.glob('.odmm-*.part'))


def test_post_publish_failure_requires_operator_reconciliation():
    with tempfile.TemporaryDirectory() as t:
        src,dst,db=fixture_tree(Path(t))
        with NativePosixMigration(src,dst,db) as m:
            def simulated_failure(): raise OSError(5,'Simulated I/O failure')
            with pytest.raises(OSError): m.copy('file.bin',after_publish=simulated_failure)
        with NativePosixMigration(src,dst,db) as m:
            with pytest.raises(MigrationBlocked,match='PENDING_INTENT'):
                m.copy('file.bin')
            with pytest.raises(MigrationBlocked,match='OPERATOR_CONFIRMATION_REQUIRED'):
                m.reconcile('file.bin')
            assert m.reconcile('file.bin',operator_confirmed=True)['status']=='RECONCILED_VERIFIED'
            assert m.verify('file.bin')['status']=='VERIFIED_POSIX_SUBSET_ONLY'


def test_post_publish_corruption_blocks_reconciliation():
    with tempfile.TemporaryDirectory() as t:
        src,dst,db=fixture_tree(Path(t))
        with NativePosixMigration(src,dst,db) as m:
            with pytest.raises(OSError):
                m.copy('file.bin',after_publish=lambda: (_ for _ in ()).throw(OSError('fault')))
        (dst/'file.bin').write_bytes(b'corrupt')
        with NativePosixMigration(src,dst,db) as m:
            with pytest.raises(MigrationBlocked,match='RECONCILIATION_CONTENT_MISMATCH'):
                m.reconcile('file.bin',operator_confirmed=True)
            assert m.db.execute('select count(*) from intents').fetchone()[0]==1
            assert m.db.execute('select count(*) from files').fetchone()[0]==0


def test_corrupt_registry_refuses_operation_without_modifying_source():
    with tempfile.TemporaryDirectory() as t:
        src,dst,db=fixture_tree(Path(t))
        original=(src/'file.bin').read_bytes()
        db.write_bytes(b'not a sqlite database')
        with pytest.raises(sqlite3.DatabaseError):
            NativePosixMigration(src,dst,db)
        assert (src/'file.bin').read_bytes()==original
        assert not (dst/'file.bin').exists()
