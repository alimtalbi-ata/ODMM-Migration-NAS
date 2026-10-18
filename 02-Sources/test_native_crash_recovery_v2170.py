"""Real process-death tests of the native POSIX subset. Author: Abdelhalim Talbi."""
import multiprocessing as mp
import os
import sqlite3
import tempfile
from pathlib import Path
import pytest
from native_posix_migration import NativePosixMigration, MigrationBlocked


def _worker(src, dst, db, phase):
    with NativePosixMigration(src, dst, db) as engine:
        def die():
            os._exit(73)
        engine.copy('file.bin', **{'after_temp_sync' if phase == 'temp' else 'after_publish': die})

@pytest.mark.parametrize('phase', ['temp', 'published'])
def test_native_process_death_and_recovery(phase):
    with tempfile.TemporaryDirectory() as root:
        root = Path(root)
        src, dst, db = root/'source', root/'target', root/'journal.sqlite'
        src.mkdir(); dst.mkdir()
        payload = os.urandom(1024*1024+91)
        (src/'file.bin').write_bytes(payload)
        process = mp.get_context('spawn').Process(target=_worker, args=(src,dst,db,phase))
        process.start(); process.join(20)
        assert process.exitcode == 73
        with NativePosixMigration(src,dst,db) as engine:
            assert not list(dst.glob('.odmm-*.part')) or phase == 'temp'
            if phase == 'temp':
                assert not (dst/'file.bin').exists()
                assert engine.copy('file.bin')['status'] == 'COPIED_VERIFIED'
            else:
                assert (dst/'file.bin').read_bytes() == payload
                with pytest.raises(MigrationBlocked, match='PENDING_INTENT'):
                    engine.copy('file.bin')
                with pytest.raises(MigrationBlocked, match='OPERATOR_CONFIRMATION_REQUIRED'):
                    engine.reconcile('file.bin')
                assert engine.reconcile('file.bin', operator_confirmed=True)['status'] == 'RECONCILED_VERIFIED'
            assert engine.verify('file.bin')['status'] == 'VERIFIED_POSIX_SUBSET_ONLY'
            assert engine.copy('file.bin')['status'] == 'ALREADY_VERIFIED'
        assert (dst/'file.bin').read_bytes() == payload
        with sqlite3.connect(db) as conn:
            assert conn.execute('SELECT count(*) FROM intents').fetchone()[0] == 0
            assert conn.execute('SELECT count(*) FROM files').fetchone()[0] == 1


def test_reconciliation_rejects_changed_target_after_crash():
    with tempfile.TemporaryDirectory() as root:
        root=Path(root); src=root/'src'; dst=root/'dst'; db=root/'db.sqlite'
        src.mkdir(); dst.mkdir(); (src/'file.bin').write_bytes(b'original')
        process=mp.get_context('spawn').Process(target=_worker,args=(src,dst,db,'published'))
        process.start(); process.join(20)
        assert process.exitcode == 73
        (dst/'file.bin').write_bytes(b'corrupted')
        with NativePosixMigration(src,dst,db) as engine:
            with pytest.raises(MigrationBlocked,match='RECONCILIATION_CONTENT_MISMATCH'):
                engine.reconcile('file.bin',operator_confirmed=True)
            assert engine.db.execute('SELECT count(*) FROM intents').fetchone()[0] == 1
