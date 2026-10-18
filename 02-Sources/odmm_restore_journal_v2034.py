"""ODMM V203.4: local durable restore intent journal and portable advisory lock.
Author: Abdelhalim Talbi. No NAS writes, no cutover.
"""
import contextlib
import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path

SCHEMA='odmm.restore.journal.v2034'

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

@contextlib.contextmanager
def advisory_lock(path):
    """Lock must be cooperatively used by all writers; OS releases it on crash."""
    p=Path(path)
    if not p.parent.is_dir() or p.parent.is_symlink(): raise ValueError('UNSAFE_LOCK_PARENT')
    fd=os.open(p,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        if os.name=='nt':
            import msvcrt
            os.lseek(fd,0,os.SEEK_SET)
            if os.fstat(fd).st_size==0: os.write(fd,b'0')
            os.lseek(fd,0,os.SEEK_SET)
            msvcrt.locking(fd,msvcrt.LK_LOCK,1)
        else:
            import fcntl
            fcntl.flock(fd,fcntl.LOCK_EX)
        yield
    finally:
        if os.name=='nt':
            os.lseek(fd,0,os.SEEK_SET)
            msvcrt.locking(fd,msvcrt.LK_UNLCK,1)
        else: fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)

def _connect(path):
    con=sqlite3.connect(path,timeout=10,isolation_level=None)
    con.execute('PRAGMA synchronous=FULL')
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('CREATE TABLE IF NOT EXISTS restore_events (seq INTEGER PRIMARY KEY AUTOINCREMENT, operation TEXT NOT NULL, phase TEXT NOT NULL, payload TEXT NOT NULL, prev_hash TEXT NOT NULL, event_hash TEXT NOT NULL)')
    return con

def append(db,operation,phase,details=None):
    if not isinstance(operation,str) or not operation or len(operation)>128: raise ValueError('INVALID_OPERATION')
    if phase not in ('INTENT','VERIFIED','PUBLISHED','FAILED'): raise ValueError('INVALID_PHASE')
    payload=json.dumps(details or {},sort_keys=True,separators=(',',':'))
    with advisory_lock(str(db)+'.lock'):
        con=_connect(db)
        try:
            con.execute('BEGIN IMMEDIATE')
            last=con.execute('SELECT seq,event_hash FROM restore_events ORDER BY seq DESC LIMIT 1').fetchone()
            seq=last[0]+1 if last else 1
            prev=last[1] if last else '0'*64
            item={'seq':seq,'operation':operation,'phase':phase,'payload':payload,'prev_hash':prev}
            h=digest(item)
            con.execute('INSERT INTO restore_events(seq,operation,phase,payload,prev_hash,event_hash) VALUES(?,?,?,?,?,?)',(seq,operation,phase,payload,prev,h))
            con.execute('COMMIT')
            return h
        except BaseException:
            if con.in_transaction: con.execute('ROLLBACK')
            raise
        finally: con.close()

def verify(db, *, lock=True):
    """Read-only verification: absent journals never get created or changed."""
    from contextlib import closing
    from urllib.parse import quote
    p=Path(db)
    if not p.is_file() or p.is_symlink():
        raise ValueError('JOURNAL_MISSING_OR_SYMLINK')
    # A caller already holding this process lock must not acquire it again.
    with (advisory_lock(str(p)+'.lock') if lock else contextlib.nullcontext()):
        uri='file:'+quote(str(p.resolve()),safe='/')+'?mode=ro'
        with closing(sqlite3.connect(uri,uri=True,timeout=10)) as con:
            if con.execute('PRAGMA integrity_check').fetchone()!=('ok',):
                raise ValueError('SQLITE_INTEGRITY_FAILED')
            rows=con.execute('SELECT seq,operation,phase,payload,prev_hash,event_hash FROM restore_events ORDER BY seq').fetchall()
    previous='0'*64
    pending={}
    for expected,row in enumerate(rows,1):
        seq,operation,phase,payload,prev,h=row
        if (seq!=expected or prev!=previous or phase not in ('INTENT','VERIFIED','PUBLISHED','FAILED')
            or digest({'seq':seq,'operation':operation,'phase':phase,'payload':payload,'prev_hash':prev})!=h):
            return {'valid':False,'events':len(rows),'cutover_authorized':False}
        try:
            details=json.loads(payload)
        except (TypeError,ValueError):
            return {'valid':False,'events':len(rows),'cutover_authorized':False}
        if not isinstance(details,dict):
            return {'valid':False,'events':len(rows),'cutover_authorized':False}
        if phase=='INTENT':
            pending[operation]=seq
        elif phase in ('PUBLISHED','FAILED'):
            if operation not in pending: return {'valid':False,'events':len(rows),'cutover_authorized':False}
            pending.pop(operation)
        elif operation not in pending:
            return {'valid':False,'events':len(rows),'cutover_authorized':False}
        previous=h
    return {'schema':SCHEMA,'valid':True,'events':len(rows),'chain_head':previous,
            'pending_operations':sorted(pending),'cutover_authorized':False,'writes_to_nas':False}

def restore_with_journal(archive,destination,*,key,expected_sha256,journal,operation,expected_chain_head=None):
    """Journal intent and terminal state around V203.3 verified restore; never overwrite."""
    from odmm_registry_secure_recovery_v2033 import encrypted_restore
    append(journal,operation,'INTENT',{'destination':str(destination),'archive_sha256':expected_sha256})
    try:
        result=encrypted_restore(archive,destination,key=key,expected_sha256=expected_sha256,expected_chain_head=expected_chain_head)
        append(journal,operation,'PUBLISHED',{'destination':str(destination),'chain_head':result['chain_head']})
        return result
    except Exception as exc:
        append(journal,operation,'FAILED',{'error_type':type(exc).__name__})
        raise
