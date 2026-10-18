"""Fail-closed manual recovery for a durable receipt whose intent unlink was interrupted.

The receipt and filesystem unlink cannot commit atomically. No automated retry.
"""
import hashlib
import hmac
import json
from ldaps_durable_ack import DurableAcknowledgement
from ldaps_transition_reconciliation import TransitionReconciliationError

class InterruptedAckRecovery:
    def __init__(self, durable):
        if not isinstance(durable, DurableAcknowledgement):
            raise TransitionReconciliationError('INVALID_DURABLE_ACK')
        self.durable=durable
        self.db=durable.db
        self.db.execute('''CREATE TABLE IF NOT EXISTS ack_recovery_events (
            seq INTEGER PRIMARY KEY, intent_hash TEXT NOT NULL UNIQUE,
            receipt_hash TEXT NOT NULL UNIQUE, reviewer TEXT NOT NULL,
            recovered_at INTEGER NOT NULL, previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL)''')

    @staticmethod
    def _hash(seq, ih, rh, reviewer, at, prev):
        return hashlib.sha256(json.dumps([seq,ih,rh,reviewer,at,prev],separators=(',',':')).encode()).hexdigest()

    def _rows(self):
        rows=self.db.execute('SELECT seq,intent_hash,receipt_hash,reviewer,recovered_at,previous_hash,event_hash FROM ack_recovery_events ORDER BY seq').fetchall()
        prev='0'*64
        for expected_seq,(seq,ih,rh,reviewer,at,old,digest) in enumerate(rows,1):
            if seq!=expected_seq or old!=prev or not hmac.compare_digest(self._hash(seq,ih,rh,reviewer,at,prev),digest):
                raise TransitionReconciliationError('RECOVERY_AUDIT_TAMPERED')
            prev=digest
        return rows

    def inspect(self):
        with self.durable.reconciler._lock():
            receipts=self.durable._rows()
            recoveries=self._rows()
            intent=self.durable.reconciler.transition._read()
            if intent is None:
                return {'status':'NO_PENDING_INTENT','execution_authorized':False,'cutover_authorized':False}
            ih=self.durable._intent_hash(intent)
            matching=[row for row in receipts if row[2]==ih]
            if len(matching)!=1:
                return {'status':'NO_DURABLE_RECEIPT_MANUAL_INVESTIGATION','execution_authorized':False,'cutover_authorized':False}
            if any(row[1]==ih for row in recoveries):
                return {'status':'RECOVERY_RECORDED_INTENT_PRESENT_MANUAL_INVESTIGATION','execution_authorized':False,'cutover_authorized':False}
            if self.durable.reconciler.transition.inspect()['status']!='PUBLISHED_AWAITING_OPERATOR_ACK':
                return {'status':'POLICY_NOT_VERIFIED_MANUAL_INVESTIGATION','execution_authorized':False,'cutover_authorized':False}
            return {'status':'RECOVERABLE_WITH_INDEPENDENT_REVIEW','receipt_hash':matching[0][5],
                    'intent_hash':ih,'acknowledged_at':matching[0][3],
                    'execution_authorized':False,'cutover_authorized':False}

    def recover(self, *, reviewer, original_operator, operator_confirmed, now, max_age_seconds):
        if operator_confirmed is not True:
            raise TransitionReconciliationError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        if not isinstance(reviewer,str) or not reviewer.strip() or not isinstance(original_operator,str) or not original_operator.strip() or reviewer==original_operator:
            raise TransitionReconciliationError('INDEPENDENT_REVIEWER_REQUIRED')
        if type(now)!=int or type(max_age_seconds)!=int or now<0 or max_age_seconds<0:
            raise TransitionReconciliationError('INVALID_TIME_PARAMETERS')
        with self.durable.reconciler._lock():
            receipts=self.durable._rows()
            intent=self.durable.reconciler.transition._read()
            if intent is None:raise TransitionReconciliationError('NO_PENDING_INTENT')
            ih=self.durable._intent_hash(intent)
            matching=[row for row in receipts if row[2]==ih]
            if len(matching)!=1:raise TransitionReconciliationError('DURABLE_RECEIPT_REQUIRED')
            receipt=matching[0]
            if now<receipt[3] or now-receipt[3]>max_age_seconds:
                raise TransitionReconciliationError('STALE_RECEIPT')
            if self.durable.reconciler.transition.inspect()['status']!='PUBLISHED_AWAITING_OPERATOR_ACK':
                raise TransitionReconciliationError('POLICY_NOT_VERIFIED')
            self.db.execute('BEGIN IMMEDIATE')
            try:
                rows=self._rows()
                if any(row[1]==ih or row[2]==receipt[5] for row in rows):
                    raise TransitionReconciliationError('RECOVERY_REPLAY_BLOCKED')
                seq=len(rows)+1;prev=rows[-1][6] if rows else '0'*64
                digest=self._hash(seq,ih,receipt[5],reviewer,now,prev)
                self.db.execute('INSERT INTO ack_recovery_events VALUES (?,?,?,?,?,?,?)',
                                (seq,ih,receipt[5],reviewer,now,prev,digest))
                self.db.commit()
            except BaseException:
                self.db.rollback();raise
            # Filesystem unlink happens only AFTER durable recovery record.
            # Failure is intentionally left for further manual investigation.
            result=self.durable.reconciler.transition.acknowledge(operator_confirmed=True)
            return {**result,'recovery_hash':digest,'execution_authorized':False,'cutover_authorized':False}

    def verify(self):
        self.durable._rows()
        return {'valid':True,'count':len(self._rows())}
