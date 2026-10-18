"""Read-only reconciliation and operator-controlled acknowledgement of policy transitions.

File lock serializes cooperating administrators; no automatic anchor repair.
"""
import fcntl
import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from ldaps_policy_transition import SupervisedPolicyTransition, PolicyTransitionError
from ldaps_freshness_policy_audit import AuditedFreshnessPolicy

class TransitionReconciliationError(PolicyTransitionError): pass

class TransitionReconciler:
    def __init__(self, transition, *, lock_path):
        if not isinstance(transition, SupervisedPolicyTransition):
            raise TransitionReconciliationError('INVALID_TRANSITION')
        self.transition=transition
        self.lock_path=Path(lock_path)
        if self.lock_path.resolve() in {transition.intent.resolve(),transition.anchor.path.resolve()}:
            raise TransitionReconciliationError('LOCK_PATH_COLLISION')

    @contextmanager
    def _lock(self):
        self.lock_path.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(self.lock_path,os.O_CREAT|os.O_RDWR,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            yield
        except BlockingIOError as exc:
            raise TransitionReconciliationError('ADMINISTRATOR_CONCURRENCY_BLOCKED') from exc
        finally:
            fcntl.flock(fd,fcntl.LOCK_UN)
            os.close(fd)

    def inspect(self, *, now, max_age_seconds):
        if type(now)!=int or now<0 or type(max_age_seconds)!=int or max_age_seconds<0:
            raise TransitionReconciliationError('INVALID_TIME_PARAMETERS')
        with self._lock():
            intent=self.transition._read()
            status=self.transition.inspect()['status']
            if intent is not None:
                if intent['requested_at']>now:
                    status='FUTURE_INTENT_MANUAL_REVIEW'
                elif now-intent['requested_at']>max_age_seconds:
                    status='STALE_INTENT_MANUAL_REVIEW'
            evidence={'status':status,'intent':intent,'observed_at':now,
                      'review_allowed':False,'execution_authorized':False,'cutover_authorized':False}
            canonical=json.dumps(evidence,sort_keys=True,separators=(',',':')).encode()
            evidence['sha256']=hashlib.sha256(canonical).hexdigest()
            return evidence

    @staticmethod
    def verify_evidence(evidence):
        if not isinstance(evidence,dict) or 'sha256' not in evidence:
            raise TransitionReconciliationError('INVALID_EVIDENCE')
        data=dict(evidence); expected=data.pop('sha256')
        if not isinstance(expected,str) or len(expected)!=64:
            raise TransitionReconciliationError('INVALID_EVIDENCE')
        actual=hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if not __import__('hmac').compare_digest(actual,expected):
            raise TransitionReconciliationError('EVIDENCE_TAMPERED')
        return True

    def acknowledge(self, evidence, *, operator_confirmed, now, max_age_seconds):
        self.verify_evidence(evidence)
        if operator_confirmed is not True:
            raise TransitionReconciliationError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        if type(now)!=int or type(max_age_seconds)!=int or max_age_seconds<0 or now<0:
            raise TransitionReconciliationError('INVALID_TIME_PARAMETERS')
        if now<evidence['observed_at'] or now-evidence['observed_at']>max_age_seconds:
            raise TransitionReconciliationError('STALE_EVIDENCE')
        with self._lock():
            intent=self.transition._read()
            if intent!=evidence['intent'] or evidence['status']!='PUBLISHED_AWAITING_OPERATOR_ACK':
                raise TransitionReconciliationError('EVIDENCE_CHANGED_OR_NOT_READY')
            if self.transition.inspect()['status']!='PUBLISHED_AWAITING_OPERATOR_ACK':
                raise TransitionReconciliationError('EVIDENCE_CHANGED_OR_NOT_READY')
            return self.transition.acknowledge(operator_confirmed=True)
