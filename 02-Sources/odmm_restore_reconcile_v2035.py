"""ODMM V203.5: non-destructive, fail-closed local restore reconciliation.
Author: Abdelhalim Talbi. Never modifies a destination or NAS.
"""
import hashlib
import contextlib
import json
import sqlite3
from pathlib import Path
from odmm_restore_journal_v2034 import advisory_lock, verify, append

SCHEMA='odmm.restore.reconcile.v2035'
def _sha_file(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def inspect(journal, operation, *, expected_destination=None, expected_sha256=None, _journal_locked=False):
    """Inspection only: a present destination is not proof of successful restoration."""
    if not isinstance(operation,str) or not operation: raise ValueError('INVALID_OPERATION')
    if expected_sha256 is not None and (not isinstance(expected_sha256,str) or len(expected_sha256)!=64 or any(c not in '0123456789abcdef' for c in expected_sha256)):
        raise ValueError('INVALID_DIGEST')
    result=verify(journal, lock=not _journal_locked)
    if not result['valid']: raise ValueError('JOURNAL_CORRUPT')
    with contextlib.closing(sqlite3.connect('file:'+str(Path(journal).resolve())+'?mode=ro',uri=True)) as con:
        rows=con.execute('SELECT phase,payload FROM restore_events WHERE operation=? ORDER BY seq',(operation,)).fetchall()
    if not rows: return {'schema':SCHEMA,'operation':operation,'status':'UNKNOWN','writes_to_nas':False,'cutover_authorized':False}
    intents=[json.loads(payload) for phase,payload in rows if phase=='INTENT']
    terminal=rows[-1][0] in ('PUBLISHED','FAILED')
    if terminal: status='CLOSED_'+rows[-1][0]
    elif not intents: status='UNVERIFIED'
    else:
        paths={p.get('destination') for p in intents}
        if len(paths)!=1 or not next(iter(paths)): status='CONFLICT'
        else:
            target=next(iter(paths))
            if expected_destination is not None and str(expected_destination)!=target: status='CONFLICT'
            else:
                p=Path(target)
                if p.is_symlink(): status='UNSAFE_DESTINATION'
                elif not p.exists(): status='MISSING_DESTINATION'
                elif not p.is_file(): status='UNSAFE_DESTINATION'
                elif expected_sha256 is None: status='PRESENT_UNVERIFIED'
                elif _sha_file(p)==expected_sha256: status='PRESENT_DIGEST_MATCH_UNVERIFIED'
                else: status='DIGEST_MISMATCH'
    return {'schema':SCHEMA,'operation':operation,'status':status,'requires_manual_approval':True,'writes_to_nas':False,'cutover_authorized':False}

def record_review(journal,operation,*,reviewer,comment):
    """Append a review only; never silently closes an interrupted operation."""
    if not isinstance(reviewer,str) or not reviewer.strip() or len(reviewer)>128: raise ValueError('INVALID_REVIEWER')
    if not isinstance(comment,str) or not comment.strip() or len(comment)>1000: raise ValueError('INVALID_COMMENT')
    with advisory_lock(str(journal)+'.review.lock'):
        state=inspect(journal,operation)
        if state['status']=='UNKNOWN': raise ValueError('UNKNOWN_OPERATION')
        append(journal,operation,'VERIFIED',{'reviewer':reviewer,'comment':comment,'reconciliation_status':state['status']})
        return inspect(journal,operation)
