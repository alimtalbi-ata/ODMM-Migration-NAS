"""V196.7 common read-only operations contract for API and CLI.

Never instantiates Registry (which creates tables) and never runs migrations.
"""
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

STATES = frozenset({'PENDING','RUNNING','DONE','FAILED'})

class OperationsView:
    def __init__(self, db_path):
        p = Path(db_path).resolve(strict=True)
        if not p.is_file():
            raise ValueError('REGISTRY_FILE_REQUIRED')
        self.path = p

    @contextmanager
    def _connect(self):
        uri = 'file:' + quote(str(self.path), safe='/') + '?mode=ro&immutable=0'
        db = sqlite3.connect(uri, uri=True, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA query_only=ON')
        try:
            yield db
        finally:
            db.close()

    def overview(self):
        with self._connect() as db:
            jobs = db.execute('SELECT COUNT(*) AS n FROM jobs').fetchone()['n']
            rows = db.execute('SELECT state, COUNT(*) AS n FROM operations GROUP BY state').fetchall()
            audit = db.execute('SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
        return {'schema':'odmm.operations.v1','jobs':jobs,'operations':{r['state']:r['n'] for r in rows},
                'audit_head':dict(audit) if audit else None,'read_only':True}

    def jobs(self, limit=50):
        limit = _limit(limit)
        with self._connect() as db:
            rows = db.execute('SELECT id,source,target,state,created_at FROM jobs ORDER BY created_at DESC,id DESC LIMIT ?', (limit,)).fetchall()
        return {'schema':'odmm.jobs.v1','items':[dict(r) for r in rows],'read_only':True}

    def operations(self, job_id, limit=50):
        if not isinstance(job_id,str) or not 1 <= len(job_id) <= 128:
            raise ValueError('JOB_ID_INVALID')
        limit = _limit(limit)
        with self._connect() as db:
            exists = db.execute('SELECT 1 FROM jobs WHERE id=?',(job_id,)).fetchone()
            if not exists: raise LookupError('JOB_NOT_FOUND')
            rows = db.execute('SELECT id,job_id,state,owner,epoch,lease_until,updated_at FROM operations WHERE job_id=? ORDER BY updated_at DESC,id DESC LIMIT ?', (job_id,limit)).fetchall()
        return {'schema':'odmm.operations.v1','job_id':job_id,'items':[dict(r) for r in rows],'read_only':True}

def _limit(value):
    if isinstance(value,bool) or not isinstance(value,int) or not 1 <= value <= 200:
        raise ValueError('LIMIT_OUT_OF_RANGE')
    return value
