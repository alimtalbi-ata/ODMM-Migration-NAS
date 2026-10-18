"""Native crash cleanup and multi-file resume tests. Author: Abdelhalim Talbi."""
import multiprocessing as mp
import os
import tempfile
from pathlib import Path
import pytest
from native_posix_migration import NativePosixMigration, MigrationBlocked


def _die_mid_copy(src, dst, db):
    with NativePosixMigration(src, dst, db) as engine:
        engine.copy('b.bin', after_temp_sync=lambda: os._exit(73))


def test_multifile_resume_with_explicit_temp_cleanup():
    with tempfile.TemporaryDirectory() as d:
        root=Path(d); src=root/'src'; dst=root/'dst'; src.mkdir();dst.mkdir();db=root/'journal.db'
        for name in ('a.bin','b.bin','c.bin'):
            (src/name).write_bytes(os.urandom(4097))
        with NativePosixMigration(src,dst,db) as engine:
            assert engine.copy('a.bin')['status']=='COPIED_VERIFIED'
        proc=mp.get_context('spawn').Process(target=_die_mid_copy,args=(src,dst,db))
        proc.start();proc.join(15)
        assert proc.exitcode==73
        assert list(dst.glob('.odmm-*.part'))
        with NativePosixMigration(src,dst,db) as engine:
            with pytest.raises(MigrationBlocked,match='OPERATOR_CONFIRMATION_REQUIRED'):
                engine.cleanup_orphan_temps('b.bin')
            assert len(engine.cleanup_orphan_temps('b.bin',operator_confirmed=True)['removed'])==1
            assert engine.copy('a.bin')['status']=='ALREADY_VERIFIED'
            assert engine.copy('b.bin')['status']=='COPIED_VERIFIED'
            assert engine.copy('c.bin')['status']=='COPIED_VERIFIED'
            for name in ('a.bin','b.bin','c.bin'):
                assert engine.verify(name)['status']=='VERIFIED_POSIX_SUBSET_ONLY'
                assert (src/name).read_bytes()==(dst/name).read_bytes()


def test_cleanup_refuses_symlink_and_pending_intent():
    with tempfile.TemporaryDirectory() as d:
        root=Path(d);src=root/'src';dst=root/'dst';src.mkdir();dst.mkdir();db=root/'db.sqlite'
        (src/'x').write_bytes(b'x')
        with NativePosixMigration(src,dst,db) as engine:
            name='.odmm-'+'a'*32+'.part'
            (dst/name).symlink_to(src/'x')
            with pytest.raises(MigrationBlocked,match='UNSAFE_TEMP_ENTRY'):
                engine.cleanup_orphan_temps('x',operator_confirmed=True)
            assert (src/'x').read_bytes()==b'x'
            (dst/name).unlink()
            engine.db.execute('INSERT INTO intents VALUES (?,?,?,?,?)',('x',1,'0'*64,0o644,0))
            with pytest.raises(MigrationBlocked,match='PENDING_INTENT'):
                engine.cleanup_orphan_temps('x',operator_confirmed=True)
