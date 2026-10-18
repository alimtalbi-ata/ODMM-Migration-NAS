"""Fail-closed atomic external anchor CAS and read-only Operations status.
Author: Abdelhalim Talbi. CAS durability and independent storage are integrator obligations.
"""
import hmac
from odmm_nas_acl_recovery_v2151 import RecoverableAnchoredHistory

class CASAnchoredHistory(RecoverableAnchoredHistory):
    """cas_anchor(expected, replacement) must atomically compare entire signed document.

    Return True only after durable commit, False on conflict. The caller must use
    a genuinely independent storage backend and prevent key/anchor rollback.
    """
    def __init__(self, history, *, read_anchor, cas_anchor, anchor_key):
        if not callable(cas_anchor):raise ValueError('INVALID_CAS_DEPENDENCY')
        self.cas_anchor=cas_anchor
        super().__init__(history,read_anchor=read_anchor,write_anchor=self._no_direct_write,anchor_key=anchor_key)

    def _no_direct_write(self, value):
        raise ValueError('CAS_REQUIRED')

    def _cas(self, expected, point):
        result=self.cas_anchor(expected,self._seal(point))
        if result is not True:raise ValueError('ANCHOR_CAS_CONFLICT')

    def bootstrap_empty(self):
        with self.history.lock:
            if self._read() is not None or self._checkpoint()['seq']!=0 or not self.history.verify_chain():
                raise ValueError('ANCHOR_BOOTSTRAP_REFUSED')
            self._cas(None,{'seq':0,'chain_mac':'GENESIS'})
            if not self.verify():raise ValueError('ANCHOR_BOOTSTRAP_FAILED')

    def record(self,document):
        with self.history.lock:
            if not self.verify():raise ValueError('ANCHOR_VERIFICATION_FAILED')
            before=self._read()
            seq=self.history.record(document)
            self._cas(before,self._checkpoint())
            if not self.verify():raise ValueError('ANCHOR_WRITE_FAILED')
            return seq

    def reconcile_explicit(self, *, expected_anchor_seq, expected_local_seq, approved=False):
        if approved is not True or type(expected_anchor_seq) is not int or type(expected_local_seq) is not int:
            raise ValueError('RECOVERY_APPROVAL_REQUIRED')
        with self.history.lock:
            state=self.inspect_recovery()
            if state.get('state')!='PENDING_ANCHOR' or state['anchor_seq']!=expected_anchor_seq or state['local_seq']!=expected_local_seq:
                raise ValueError('RECOVERY_PRECONDITION_FAILED')
            before=self._read()
            if before['seq']!=expected_anchor_seq:raise ValueError('RECOVERY_PRECONDITION_FAILED')
            self._cas(before,self._checkpoint())
            if not self.verify():raise ValueError('RECOVERY_ANCHOR_VERIFICATION_FAILED')
            return {'state':'RECOVERED','seq':expected_local_seq,'cutover_authorized':False}


def attach_acl_recovery_status(app, *, authorize, anchored_history):
    from fastapi import Request
    from fastapi.responses import JSONResponse
    from odmm_nas_acl_portal_v2147 import HEADERS
    @app.get('/api/v1/operations/nas-acl-audit/recovery/status')
    def status(request:Request):
        try: allowed=authorize(request) is True
        except Exception: allowed=False
        if not allowed:return JSONResponse({'error':'ACCESS_DENIED'},status_code=403,headers=HEADERS)
        try:
            state=anchored_history.inspect_recovery()
            name=state.get('state','VERIFICATION_ERROR')
            if name not in ('CONSISTENT','PENDING_ANCHOR','LOCAL_ROLLBACK','DIVERGED','NO_ANCHOR','INVALID_LOCAL_CHAIN','VERIFICATION_ERROR'):
                name='VERIFICATION_ERROR'
            return JSONResponse({'state':name,'recoverable':state.get('recoverable') is True,
                                 'cutover_authorized':False},status_code=200 if name=='CONSISTENT' else 503,headers=HEADERS)
        except Exception:
            return JSONResponse({'state':'VERIFICATION_ERROR','recoverable':False,'cutover_authorized':False},status_code=503,headers=HEADERS)
