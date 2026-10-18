"""Bounded, signed ACL export history. Author: Abdelhalim Talbi.
Local SQLite WAL history, not a WORM store or hardware attestation.
"""
import hashlib, hmac, json, sqlite3, threading
from pathlib import Path
from odmm_nas_acl_export_v2148 import canonical, verify_export

class AuditHistory:
    def __init__(self, path, key):
        if not isinstance(key, bytes) or len(key)<32: raise ValueError('INVALID_HISTORY_KEY')
        self.key=key
        self.path=str(path)
        self.lock=threading.RLock()
        Path(path).parent.mkdir(parents=True,exist_ok=True)
        with self._db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS acl_audit_history (seq INTEGER PRIMARY KEY AUTOINCREMENT, digest TEXT NOT NULL, previous TEXT NOT NULL, chain_mac TEXT NOT NULL, report TEXT NOT NULL)')
    def _db(self):
        db=sqlite3.connect(self.path,timeout=10)
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        return db
    def record(self, document):
        if not verify_export(document,self.key): raise ValueError('UNVERIFIED_AUDIT_EXPORT')
        serialized=canonical(document).decode('utf-8')
        digest=hashlib.sha256(serialized.encode()).hexdigest()
        with self.lock, self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            previous=db.execute('SELECT chain_mac FROM acl_audit_history ORDER BY seq DESC LIMIT 1').fetchone()
            previous=previous[0] if previous else 'GENESIS'
            mac=hmac.new(self.key,(previous+'|'+digest).encode(),hashlib.sha256).hexdigest()
            cur=db.execute('INSERT INTO acl_audit_history(digest,previous,chain_mac,report) VALUES(?,?,?,?)',(digest,previous,mac,serialized))
            return cur.lastrowid
    def page(self, *, cursor=0, limit=50):
        if type(cursor) is not int or cursor<0 or type(limit) is not int or not 1<=limit<=100: raise ValueError('INVALID_PAGE')
        with self._db() as db:
            rows=db.execute('SELECT seq,digest,previous,chain_mac,report FROM acl_audit_history WHERE seq>? ORDER BY seq LIMIT ?', (cursor,limit+1)).fetchall()
        more=len(rows)>limit
        result=[]
        for seq,digest,previous,mac,report in rows[:limit]:
            doc=json.loads(report)
            result.append({'seq':seq,'digest':digest,'chain_mac':mac,'previous':previous,'protocol':doc.get('protocol'),'report_count':len(doc.get('reports',[])),'cutover_authorized':False})
        return {'schema':'odmm.nas.acl.history.v2149','items':result,'next_cursor':result[-1]['seq'] if more and result else None,'cutover_authorized':False}
    def verify_chain(self):
        previous='GENESIS'
        with self._db() as db:
            rows=db.execute('SELECT digest,previous,chain_mac,report FROM acl_audit_history ORDER BY seq')
            while True:
                batch=rows.fetchmany(256)
                if not batch: break
                for digest,prev,mac,raw in batch:
                    if prev!=previous or not hmac.compare_digest(hashlib.sha256(raw.encode()).hexdigest(),digest):return False
                    if not hmac.compare_digest(hmac.new(self.key,(prev+'|'+digest).encode(),hashlib.sha256).hexdigest(),mac):return False
                    try:
                        if not verify_export(json.loads(raw),self.key):return False
                    except (ValueError,TypeError):return False
                    previous=mac
        return True


def attach_acl_history(app, *, authorize, history):
    from fastapi import Request
    from fastapi.responses import JSONResponse
    from odmm_nas_acl_portal_v2147 import HEADERS
    @app.get('/api/v1/operations/nas-acl-audit/history')
    def history_page(request:Request,cursor:int=0,limit:int=50):
        try: allowed=authorize(request) is True
        except Exception: allowed=False
        if not allowed:return JSONResponse({'error':'ACCESS_DENIED'},status_code=403,headers=HEADERS)
        try:return JSONResponse(history.page(cursor=cursor,limit=limit),headers=HEADERS)
        except ValueError:return JSONResponse({'error':'INVALID_PAGE'},status_code=400,headers=HEADERS)
    @app.get('/api/v1/operations/nas-acl-audit/history/verify')
    def history_verify(request:Request):
        try: allowed=authorize(request) is True
        except Exception: allowed=False
        if not allowed:return JSONResponse({'error':'ACCESS_DENIED'},status_code=403,headers=HEADERS)
        try: ok=history.verify_chain()
        except Exception:ok=False
        return JSONResponse({'valid':ok,'cutover_authorized':False},status_code=200 if ok else 503,headers=HEADERS)
