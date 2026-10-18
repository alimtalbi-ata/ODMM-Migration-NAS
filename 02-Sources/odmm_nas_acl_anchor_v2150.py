"""External checkpoint verification for local ACL history. Author: Abdelhalim Talbi.
The caller MUST supply independently protected durable anchor storage. No WORM claims.
"""
import hashlib,hmac,json,sqlite3
from odmm_nas_acl_export_v2148 import canonical

class AnchoredAuditHistory:
    def __init__(self, history, *, read_anchor, write_anchor, anchor_key):
        if not callable(read_anchor) or not callable(write_anchor) or type(anchor_key) is not bytes or len(anchor_key)<32:
            raise ValueError('INVALID_ANCHOR_DEPENDENCIES')
        self.history=history
        self.read_anchor=read_anchor
        self.write_anchor=write_anchor
        self.key=anchor_key

    def _checkpoint(self):
        with self.history._db() as db:
            row=db.execute('SELECT seq,chain_mac FROM acl_audit_history ORDER BY seq DESC LIMIT 1').fetchone()
        return {'seq':row[0] if row else 0,'chain_mac':row[1] if row else 'GENESIS'}

    def _seal(self,point):
        payload={'schema':'odmm.nas.acl.anchor.v2150',**point}
        payload['signature']=hmac.new(self.key,canonical(payload),hashlib.sha256).hexdigest()
        return payload

    def _read(self):
        doc=self.read_anchor()
        if doc is None:return None
        if type(doc) is not dict or set(doc)!= {'schema','seq','chain_mac','signature'} or doc.get('schema')!='odmm.nas.acl.anchor.v2150':
            raise ValueError('INVALID_EXTERNAL_ANCHOR')
        if type(doc['seq']) is not int or doc['seq']<0 or type(doc['chain_mac']) is not str or type(doc['signature']) is not str:
            raise ValueError('INVALID_EXTERNAL_ANCHOR')
        signature=doc['signature']; base={k:v for k,v in doc.items() if k!='signature'}
        if not hmac.compare_digest(hmac.new(self.key,canonical(base),hashlib.sha256).hexdigest(),signature):
            raise ValueError('INVALID_EXTERNAL_ANCHOR')
        return doc

    def verify(self):
        try:
            anchor=self._read()
            if anchor is None:return False # no trusted baseline
            if not self.history.verify_chain():return False
            checkpoint=self._checkpoint()
            if checkpoint['seq']<anchor['seq']:return False
            with self.history._db() as db:
                row=db.execute('SELECT chain_mac FROM acl_audit_history WHERE seq=?',(anchor['seq'],)).fetchone() if anchor['seq'] else None
            return (row[0] if row else 'GENESIS')==anchor['chain_mac']
        except Exception:return False

    def bootstrap_empty(self):
        """One-time setup; NEVER silently bootstrap a previously populated or lost history."""
        with self.history.lock:
            if self._read() is not None or self._checkpoint()['seq']!=0 or not self.history.verify_chain():
                raise ValueError('ANCHOR_BOOTSTRAP_REFUSED')
            self.write_anchor(self._seal({'seq':0,'chain_mac':'GENESIS'}))
            if not self.verify():raise ValueError('ANCHOR_BOOTSTRAP_FAILED')

    def record(self,document):
        with self.history.lock:
            if not self.verify():raise ValueError('ANCHOR_VERIFICATION_FAILED')
            seq=self.history.record(document)
            # Failure is fail-closed to the export caller; operator reconciliation required.
            self.write_anchor(self._seal(self._checkpoint()))
            if not self.verify():raise ValueError('ANCHOR_WRITE_FAILED')
            return seq

    def page(self,*,cursor=0,limit=50):
        if not self.verify():raise ValueError('ANCHOR_VERIFICATION_FAILED')
        return self.history.page(cursor=cursor,limit=limit)

def attach_anchor_status(app, *, authorize, anchored_history):
    from fastapi import Request
    from fastapi.responses import JSONResponse
    from odmm_nas_acl_portal_v2147 import HEADERS
    @app.get('/api/v1/operations/nas-acl-audit/anchor/verify')
    def verify(request:Request):
        try: allowed=authorize(request) is True
        except Exception: allowed=False
        if not allowed:return JSONResponse({'error':'ACCESS_DENIED'},status_code=403,headers=HEADERS)
        ok=anchored_history.verify()
        return JSONResponse({'anchor_valid':ok,'cutover_authorized':False},status_code=200 if ok else 503,headers=HEADERS)
