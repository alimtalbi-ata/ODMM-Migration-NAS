"""Reference SQLite CAS adapter and bounded paging diagnostics (local qualification only).
Author: Abdelhalim Talbi. Store MUST be separate from audit DB in production.
"""
import json
from contextlib import closing
import sqlite3
import time
from pathlib import Path

class SQLiteCASAnchor:
    """Reference single-host atomic CAS; never a substitute for independent WORM storage."""
    def __init__(self, path):
        self.path=str(path)
        Path(path).parent.mkdir(parents=True,exist_ok=True)
        with closing(self._db()) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS anchor (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL)')
    def _db(self):
        db=sqlite3.connect(self.path, timeout=15, isolation_level=None)
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA busy_timeout=15000')
        return db
    def read(self):
        with closing(self._db()) as db, db:
            row=db.execute('SELECT payload FROM anchor WHERE id=1').fetchone()
            return json.loads(row[0]) if row else None
    def cas(self, expected, replacement):
        if not isinstance(replacement,dict):raise ValueError('INVALID_ANCHOR')
        with closing(self._db()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT payload FROM anchor WHERE id=1').fetchone()
            current=json.loads(row[0]) if row else None
            if current!=expected:
                db.execute('ROLLBACK')
                return False
            encoded=json.dumps(replacement,sort_keys=True,separators=(',',':'))
            if row:db.execute('UPDATE anchor SET payload=? WHERE id=1',(encoded,))
            else:db.execute('INSERT INTO anchor(id,payload) VALUES(1,?)',(encoded,))
            db.execute('COMMIT')
            return True

def benchmark_history_pagination(history, *, records=1000, page_size=100):
    """Measure actual existing records only; no synthetic records inserted or NAS calls."""
    if type(records) is not int or not 1<=records<=100000 or type(page_size) is not int or not 1<=page_size<=100:
        raise ValueError('INVALID_BENCHMARK_BOUNDS')
    if not history.verify_chain():raise ValueError('AUDIT_INTEGRITY_FAILED')
    cursor=0; seen=0; pages=0; start=time.perf_counter()
    while seen<records:
        page=history.page(cursor=cursor,limit=min(page_size,records-seen))
        items=page['items']
        if not items:break
        if any(x['seq']<=cursor for x in items):raise ValueError('INVALID_PAGINATION')
        seen+=len(items); pages+=1; cursor=items[-1]['seq']
    elapsed=time.perf_counter()-start
    return {'schema':'odmm.nas.acl.pagination.v2155','records_scanned':seen,'pages':pages,
            'elapsed_seconds':round(elapsed,6),'pages_per_second':round(pages/max(elapsed,1e-9),2),
            'environment':'synthetic-local','cutover_authorized':False}
