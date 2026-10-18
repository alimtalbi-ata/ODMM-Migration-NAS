"""ODMM V203.7: non-destructive post-crash journal assessment.
Author: Abdelhalim Talbi. Never performs NAS writes or automatic cutover.
"""
import hashlib
import json
import sqlite3
from pathlib import Path
from contextlib import closing
from odmm_restore_journal_v2034 import advisory_lock
from odmm_reconcile_guard_v2036 import verify_readonly

SCHEMA='odmm.crash.recovery.v2037'

def assess(journal):
    """Read a consistent journal snapshot; never mark an operation complete."""
    p=Path(journal)
    if not p.is_file() or p.is_symlink(): raise ValueError('JOURNAL_MISSING_OR_SYMLINK')
    with advisory_lock(str(p)+'.lock'):
        integrity=verify_readonly(p, lock=False)  # already under the cooperative lock
        with closing(sqlite3.connect('file:'+str(p.resolve())+'?mode=ro',uri=True,timeout=10)) as db:
            rows=db.execute('SELECT operation,phase,payload FROM restore_events ORDER BY seq').fetchall()
    state={}
    for op,phase,payload in rows:
        try: details=json.loads(payload)
        except (TypeError,ValueError) as exc: raise ValueError('INVALID_JOURNAL_PAYLOAD') from exc
        if not isinstance(details,dict): raise ValueError('INVALID_JOURNAL_PAYLOAD')
        item=state.setdefault(op,{'intents':0,'terminal':None,'last_phase':None})
        if phase=='INTENT':
            if item['terminal'] is not None: raise ValueError('OPERATION_REUSED_AFTER_TERMINAL')
            item['intents']+=1
        elif phase in ('PUBLISHED','FAILED'):
            if item['intents']==0 or item['terminal'] is not None: raise ValueError('INVALID_TERMINAL_TRANSITION')
            item['terminal']=phase
        elif item['intents']==0: raise ValueError('REVIEW_WITHOUT_INTENT')
        item['last_phase']=phase
    operations=[]
    for op,st in sorted(state.items()):
        status=('MANUAL_REVIEW_REQUIRED' if st['terminal'] is None else 'CLOSED_'+st['terminal'])
        operations.append({'operation':op,'status':status,'intent_count':st['intents'],'last_phase':st['last_phase']})
    result={'schema':SCHEMA,'author':'Abdelhalim Talbi','journal_chain_head':integrity['chain_head'],
            'journal_events':integrity['events'],'operations':operations,
            'requires_manual_approval':True,'writes_to_nas':False,'cutover_authorized':False}
    result['sha256']=hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return result
