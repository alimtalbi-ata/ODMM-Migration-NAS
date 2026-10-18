"""ODMM V203.6: consistent, non-destructive reconciliation under cooperative process lock.
Author: Abdelhalim Talbi. No NAS writes or cutover authorization.
"""
import contextlib
import hashlib
import json
import sqlite3
from pathlib import Path
from odmm_restore_journal_v2034 import advisory_lock, verify, append
from odmm_restore_reconcile_v2035 import inspect

SCHEMA='odmm.reconcile.guard.v2036'

def inspect_locked(journal, operation, *, expected_destination=None, expected_sha256=None):
    """Cooperative writer lock avoids inspection while a journal append is in progress."""
    with advisory_lock(str(journal)+'.lock'):
        result=inspect(journal,operation,expected_destination=expected_destination,expected_sha256=expected_sha256)
        result=dict(result)
        result['schema']=SCHEMA
        result['journal_locked']=True
        result['requires_manual_approval']=True
        result['writes_to_nas']=False
        result['cutover_authorized']=False
        return result

def review_locked(journal, operation, *, reviewer, comment):
    """Serialize read and review append with a dedicated review lock; no automatic closure."""
    if not isinstance(reviewer,str) or not reviewer.strip() or len(reviewer)>128: raise ValueError('INVALID_REVIEWER')
    if not isinstance(comment,str) or not comment.strip() or len(comment)>1000: raise ValueError('INVALID_COMMENT')
    with advisory_lock(str(journal)+'.review.lock'):
        with advisory_lock(str(journal)+'.lock'):
            state=inspect(journal,operation)
        if state['status']=='UNKNOWN': raise ValueError('UNKNOWN_OPERATION')
        append(journal,operation,'VERIFIED',{'reviewer':reviewer,'comment':comment,'reconciliation_status':state['status']})
        return inspect_locked(journal,operation)

def verify_readonly(journal, *, lock=True):
    """Verify an existing journal without creating or modifying its SQLite file."""
    p=Path(journal)
    if not p.is_file() or p.is_symlink(): raise ValueError('JOURNAL_MISSING_OR_SYMLINK')
    with (advisory_lock(str(journal)+'.lock') if lock else contextlib.nullcontext()):
        with contextlib.closing(sqlite3.connect('file:'+str(p.resolve())+'?mode=ro',uri=True)) as con:
            if con.execute('PRAGMA integrity_check').fetchone()!=('ok',): raise ValueError('SQLITE_INTEGRITY_FAILED')
            rows=con.execute('SELECT seq,operation,phase,payload,prev_hash,event_hash FROM restore_events ORDER BY seq').fetchall()
        prev='0'*64
        for expected,(seq,op,phase,payload,old,h) in enumerate(rows,1):
            item={'seq':seq,'operation':op,'phase':phase,'payload':payload,'prev_hash':old}
            digest=hashlib.sha256(json.dumps(item,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            if seq!=expected or old!=prev or digest!=h or phase not in ('INTENT','VERIFIED','PUBLISHED','FAILED'):
                raise ValueError('JOURNAL_CORRUPT')
            prev=h
        return {'schema':SCHEMA,'valid':True,'events':len(rows),'chain_head':prev,'writes_to_nas':False,'cutover_authorized':False}
