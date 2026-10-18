"""Explicit fail-closed recovery of SQLite/anchor split commits. Author: Abdelhalim Talbi.

Not a distributed transaction. Caller must serialize writers and provide an external
anchor with durable compare-and-swap / no-rollback guarantees.
"""
from odmm_nas_acl_anchor_v2150 import AnchoredAuditHistory

class RecoverableAnchoredHistory(AnchoredAuditHistory):
    def inspect_recovery(self):
        """Read-only diagnosis; never advances the external checkpoint."""
        try:
            anchor=self._read()
            if anchor is None:return {'state':'NO_ANCHOR','recoverable':False}
            if not self.history.verify_chain():return {'state':'INVALID_LOCAL_CHAIN','recoverable':False}
            local=self._checkpoint()
            if local['seq']<anchor['seq']:return {'state':'LOCAL_ROLLBACK','recoverable':False}
            with self.history._db() as db:
                row=db.execute('SELECT chain_mac FROM acl_audit_history WHERE seq=?',(anchor['seq'],)).fetchone() if anchor['seq'] else None
            if (row[0] if row else 'GENESIS')!=anchor['chain_mac']:
                return {'state':'DIVERGED','recoverable':False}
            if local['seq']==anchor['seq']:
                return {'state':'CONSISTENT','recoverable':False,'seq':local['seq']}
            return {'state':'PENDING_ANCHOR','recoverable':True,'anchor_seq':anchor['seq'],'local_seq':local['seq']}
        except Exception:
            return {'state':'VERIFICATION_ERROR','recoverable':False}

    def verify(self):
        state=self.inspect_recovery()
        return state.get('state')=='CONSISTENT' and super().verify()

    def reconcile_explicit(self, *, expected_anchor_seq, expected_local_seq, approved=False):
        """Operator-approved forward-only repair after independent investigation.

        External read/write MUST be protected against concurrent updates (CAS or
        exclusive lock) by the integrator; no automatic repair on startup.
        """
        if approved is not True or type(expected_anchor_seq) is not int or type(expected_local_seq) is not int:
            raise ValueError('RECOVERY_APPROVAL_REQUIRED')
        with self.history.lock:
            state=self.inspect_recovery()
            if state.get('state')!='PENDING_ANCHOR' or state['anchor_seq']!=expected_anchor_seq or state['local_seq']!=expected_local_seq:
                raise ValueError('RECOVERY_PRECONDITION_FAILED')
            self.write_anchor(self._seal(self._checkpoint()))
            if not self.verify():raise ValueError('RECOVERY_ANCHOR_VERIFICATION_FAILED')
            return {'state':'RECOVERED','seq':expected_local_seq,'cutover_authorized':False}
