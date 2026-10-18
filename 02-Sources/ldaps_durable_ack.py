"""Durable one-use transition acknowledgement ledger (cooperating callers only).

Receipt is committed before intent unlink. An interrupted unlink is explicitly
recoverable by operator; never automatically retries or authorizes execution.
"""
import hashlib
import hmac
import json
import sqlite3
from ldaps_transition_reconciliation import TransitionReconciler, TransitionReconciliationError

class DurableAcknowledgement:
    def __init__(self, reconciler, db):
        if not isinstance(reconciler, TransitionReconciler):
            raise TransitionReconciliationError('INVALID_RECONCILER')
        self.reconciler = reconciler
        self.db = db
        db.execute('''CREATE TABLE IF NOT EXISTS transition_ack_receipts (
            seq INTEGER PRIMARY KEY, evidence_hash TEXT NOT NULL UNIQUE,
            intent_hash TEXT NOT NULL UNIQUE, acknowledged_at INTEGER NOT NULL,
            previous_hash TEXT NOT NULL, receipt_hash TEXT NOT NULL)''')

    def _rows(self):
        rows=self.db.execute('SELECT seq,evidence_hash,intent_hash,acknowledged_at,previous_hash,receipt_hash FROM transition_ack_receipts ORDER BY seq').fetchall()
        previous='0'*64
        for seq,eh,ih,at,prev,rh in rows:
            expected=self._hash(seq,eh,ih,at,previous)
            if prev!=previous or not hmac.compare_digest(expected,rh):
                raise TransitionReconciliationError('ACK_LEDGER_TAMPERED')
            previous=rh
        return rows

    @staticmethod
    def _hash(seq,eh,ih,at,previous):
        payload=json.dumps([seq,eh,ih,at,previous],separators=(',',':')).encode()
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _intent_hash(intent):
        return hashlib.sha256(json.dumps(intent,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def verify(self):
        return {'count':len(self._rows()),'valid':True}

    def acknowledge(self,evidence,*,operator_confirmed,now,max_age_seconds):
        r=self.reconciler
        r.verify_evidence(evidence)
        if operator_confirmed is not True:
            raise TransitionReconciliationError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        if type(now)!=int or type(max_age_seconds)!=int or now<0 or max_age_seconds<0:
            raise TransitionReconciliationError('INVALID_TIME_PARAMETERS')
        if now<evidence['observed_at'] or now-evidence['observed_at']>max_age_seconds:
            raise TransitionReconciliationError('STALE_EVIDENCE')
        with r._lock():
            intent=r.transition._read()
            if intent is None or intent!=evidence['intent'] or evidence['status']!='PUBLISHED_AWAITING_OPERATOR_ACK':
                raise TransitionReconciliationError('EVIDENCE_CHANGED_OR_NOT_READY')
            if r.transition.inspect()['status']!='PUBLISHED_AWAITING_OPERATOR_ACK':
                raise TransitionReconciliationError('EVIDENCE_CHANGED_OR_NOT_READY')
            eh=evidence['sha256']; ih=self._intent_hash(intent)
            self.db.execute('BEGIN IMMEDIATE')
            try:
                rows=self._rows()
                if any(x[1]==eh or x[2]==ih for x in rows):
                    raise TransitionReconciliationError('ACK_REPLAY_BLOCKED')
                seq=len(rows)+1; previous=rows[-1][5] if rows else '0'*64
                rh=self._hash(seq,eh,ih,now,previous)
                self.db.execute('INSERT INTO transition_ack_receipts VALUES (?,?,?,?,?,?)',(seq,eh,ih,now,previous,rh))
                self.db.commit()
            except BaseException:
                self.db.rollback(); raise
            # A crash here leaves a durable receipt and intact intent: manual recovery.
            result=r.transition.acknowledge(operator_confirmed=True)
            return {**result,'receipt_hash':rh,'execution_authorized':False,'cutover_authorized':False}

    def inspect_interruption(self):
        with self.reconciler._lock():
            rows=self._rows()
            intent=self.reconciler.transition._read()
            if intent is None:return {'status':'NO_PENDING_INTENT','execution_authorized':False}
            ih=self._intent_hash(intent)
            if any(x[2]==ih for x in rows):
                return {'status':'RECEIPT_COMMITTED_INTENT_PRESENT_MANUAL_RECOVERY','execution_authorized':False}
            return {'status':'NO_RECEIPT_FOR_INTENT','execution_authorized':False}
