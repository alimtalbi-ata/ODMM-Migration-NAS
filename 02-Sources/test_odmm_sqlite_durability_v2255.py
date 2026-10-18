"""ODMM V225.5: SQLite corruption, durable intent and concurrent recovery checks."""
import multiprocessing as mp
import os
import sqlite3
import tempfile
from pathlib import Path
import pytest
from native_posix_migration import NativePosixMigration
from native_migration_errors import MigrationBlocked


def setup(tmp):
    root=Path(tmp); src=root/'src'; dst=root/'dst'; src.mkdir(); dst.mkdir()
    (src/'a.bin').write_bytes(b'odmm-2255' * 4096)
    return src,dst,root/'registry.sqlite'

def worker(src,dst,db,q):
    try:
        with NativePosixMigration(src,dst,db) as m:
            q.put(m.copy('a.bin')['status'])
    except Exception as e:
        q.put(type(e).__name__+':'+str(e))

def test_two_processes_no_duplicate_commit():
    with tempfile.TemporaryDirectory() as d:
        src,dst,db=setup(d)
        q=mp.Queue(); procs=[mp.Process(target=worker,args=(src,dst,db,q)) for _ in range(2)]
        for p in procs: p.start()
        for p in procs: p.join(20); assert p.exitcode==0
        assert sorted([q.get(timeout=3) for _ in procs])==['ALREADY_VERIFIED','COPIED_VERIFIED']
        with sqlite3.connect(db) as c:
            assert c.execute('select count(*) from files').fetchone()[0]==1
            assert c.execute('pragma integrity_check').fetchone()[0]=='ok'

def test_corrupt_registry_fails_closed():
    with tempfile.TemporaryDirectory() as d:
        src,dst,db=setup(d)
        with NativePosixMigration(src,dst,db) as m: m.copy('a.bin')
        for suffix in ('-wal','-shm'):
            p=Path(str(db)+suffix)
            if p.exists(): p.unlink()
        db.write_bytes(b'not a valid sqlite database')
        with pytest.raises((sqlite3.DatabaseError,sqlite3.OperationalError)):
            NativePosixMigration(src,dst,db)
        assert (dst/'a.bin').read_bytes()==(src/'a.bin').read_bytes()

def test_uncommitted_intent_blocks_even_after_reopen():
    with tempfile.TemporaryDirectory() as d:
        src,dst,db=setup(d)
        with NativePosixMigration(src,dst,db) as m:
            def crash(): raise RuntimeError('injected after publish')
            with pytest.raises(RuntimeError): m.copy('a.bin',after_publish=crash)
        with NativePosixMigration(src,dst,db) as m:
            with pytest.raises(MigrationBlocked,match='PENDING_INTENT'): m.copy('a.bin')
            assert m.reconcile('a.bin',operator_confirmed=True)['status']=='RECONCILED_VERIFIED'
            assert m.verify('a.bin')['status']=='VERIFIED_POSIX_SUBSET_ONLY'
            assert m.db.execute('pragma integrity_check').fetchone()[0]=='ok'

def test_sqlite_pragmas_and_no_cutover():
    with tempfile.TemporaryDirectory() as d:
        src,dst,db=setup(d)
        with NativePosixMigration(src,dst,db) as m:
            assert m.db.execute('pragma journal_mode').fetchone()[0]=='wal'
            assert m.db.execute('pragma synchronous').fetchone()[0]==2
            assert m.copy('a.bin')['cutover_authorized'] is False
