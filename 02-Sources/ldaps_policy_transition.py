"""Supervised two-resource policy transition; fail-closed on interrupted publication.

SQLite and a filesystem anchor cannot commit atomically. A durable intent marker
is created first and is NEVER cleared automatically after an ambiguous failure.
Only an explicit operator acknowledgement clears a verified completed transition.
"""
import json
import os
import tempfile
from pathlib import Path
from ldaps_external_anchor import ExternalPolicyAnchor, ExternalAnchorError
from ldaps_freshness_policy_audit import AuditedFreshnessPolicy

class PolicyTransitionError(ExternalAnchorError): pass

class SupervisedPolicyTransition:
    def __init__(self, rbac, *, anchor_path, key, intent_path):
        self.rbac=rbac
        self.anchor=ExternalPolicyAnchor(rbac,anchor_path=anchor_path,key=key)
        self.intent=Path(intent_path)
        if self.intent.resolve()==Path(anchor_path).resolve():
            raise PolicyTransitionError('INTENT_AND_ANCHOR_COLLIDE')

    def _write(self, obj):
        self.intent.parent.mkdir(parents=True,exist_ok=True)
        fd,tmp=tempfile.mkstemp(prefix='.transition-',dir=self.intent.parent)
        try:
            with os.fdopen(fd,'w',encoding='utf-8') as f:
                os.fchmod(f.fileno(),0o600)
                json.dump(obj,f,sort_keys=True,separators=(',',':'))
                f.flush();os.fsync(f.fileno())
            os.replace(tmp,self.intent)
            dfd=os.open(self.intent.parent,os.O_RDONLY)
            try:os.fsync(dfd)
            finally:os.close(dfd)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)

    def _read(self):
        try:obj=json.loads(self.intent.read_text(encoding='utf-8'))
        except FileNotFoundError:return None
        except (OSError,ValueError) as exc:raise PolicyTransitionError('TRANSITION_INTENT_INVALID') from exc
        if not isinstance(obj,dict) or set(obj)!={'version','previous_head','new_limit','requested_at'} or obj['version']!=1 or type(obj['new_limit'])!=int or type(obj['requested_at'])!=int or not isinstance(obj['previous_head'],str):
            raise PolicyTransitionError('TRANSITION_INTENT_INVALID')
        return obj

    def change(self, *, max_age_seconds, security_reviewer, operations_reviewer, now):
        if self.intent.exists():raise PolicyTransitionError('TRANSITION_RECONCILIATION_REQUIRED')
        self.anchor.verify()
        before=AuditedFreshnessPolicy(self.rbac).verify()['last_hash']
        if type(max_age_seconds)!=int or max_age_seconds<0 or type(now)!=int or now<0:
            raise PolicyTransitionError('INVALID_TRANSITION_PARAMETERS')
        self._write({'version':1,'previous_head':before,'new_limit':max_age_seconds,'requested_at':now})
        # Any error leaves a durable intent; never silently repair/retry.
        result=AuditedFreshnessPolicy(self.rbac).configure(max_age_seconds=max_age_seconds,
            security_reviewer=security_reviewer,operations_reviewer=operations_reviewer,now=now)
        self.anchor.checkpoint()
        self.anchor.verify()
        return {'status':'POLICY_PUBLISHED_PENDING_ACK','event_hash':result['event_hash'],
                'review_allowed':False,'execution_authorized':False,'cutover_authorized':False}

    def inspect(self):
        intent=self._read()
        if intent is None:return {'status':'NO_PENDING_TRANSITION','review_allowed':False}
        try:
            current=AuditedFreshnessPolicy(self.rbac).verify()['last_hash']
        except Exception:
            return {'status':'EVIDENCE_INVALID_MANUAL_REVIEW','review_allowed':False}
        if current==intent['previous_head']:
            return {'status':'INTENT_ONLY_MANUAL_REVIEW','review_allowed':False}
        row=self.rbac.db.execute('SELECT max_age_seconds FROM ldaps_rbac_directory_freshness WHERE id=1').fetchone()
        if row is None or row[0]!=intent['new_limit']:
            return {'status':'POLICY_MISMATCH_MANUAL_REVIEW','review_allowed':False}
        try:self.anchor.verify()
        except ExternalAnchorError:
            return {'status':'SQLITE_COMMITTED_ANCHOR_UNCERTAIN','review_allowed':False}
        return {'status':'PUBLISHED_AWAITING_OPERATOR_ACK','review_allowed':False}

    def acknowledge(self, *, operator_confirmed):
        if operator_confirmed is not True:raise PolicyTransitionError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        if self.inspect()['status']!='PUBLISHED_AWAITING_OPERATOR_ACK':
            raise PolicyTransitionError('TRANSITION_NOT_VERIFIED')
        self.intent.unlink()
        dfd=os.open(self.intent.parent,os.O_RDONLY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
        return {'status':'TRANSITION_ACKNOWLEDGED','execution_authorized':False,'cutover_authorized':False}
