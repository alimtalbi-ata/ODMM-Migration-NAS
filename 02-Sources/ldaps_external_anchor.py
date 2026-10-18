"""External HMAC checkpoint for audited policy state; requires protected external key/file.

Not a distributed transaction. A checkpoint is explicitly refreshed after policy updates.
A privileged operator controlling key and anchor can still forge or roll back evidence.
"""
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from ldaps_freshness_policy_audit import AuditedFreshnessPolicy
from ldaps_rbac_reconciliation import ReconciliationRBACError

class ExternalAnchorError(ReconciliationRBACError): pass

class ExternalPolicyAnchor:
    def __init__(self, rbac, *, anchor_path, key):
        self.rbac=rbac
        self.path=Path(anchor_path)
        if not isinstance(key,bytes) or len(key)<32:
            raise ExternalAnchorError('ANCHOR_KEY_TOO_SHORT')
        self.key=key

    def _state(self):
        audit=AuditedFreshnessPolicy(self.rbac).verify()
        row=self.rbac.db.execute('SELECT synced_at,max_age_seconds FROM ldaps_rbac_directory_freshness WHERE id=1').fetchone()
        strict=self.rbac.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ldaps_strict_security'").fetchone()
        enabled=bool(strict and self.rbac.db.execute('SELECT 1 FROM ldaps_strict_security WHERE id=1').fetchone())
        if not audit['events'] or row is None:
            raise ExternalAnchorError('AUDITED_POLICY_REQUIRED')
        return {'schema':1,'policy_events':audit['events'],'policy_head':audit['last_hash'],
                'synced_at':row[0],'max_age_seconds':row[1],'strict_enabled':enabled}

    def _mac(self, state):
        payload=json.dumps(state,sort_keys=True,separators=(',',':')).encode()
        return hmac.new(self.key,payload,hashlib.sha256).hexdigest()

    def checkpoint(self):
        """Explicit administrative checkpoint; never automatically repairs mismatch."""
        state=self._state()
        record={'state':state,'hmac_sha256':self._mac(state)}
        self.path.parent.mkdir(parents=True,exist_ok=True)
        fd,name=tempfile.mkstemp(prefix='.anchor-',dir=self.path.parent)
        try:
            with os.fdopen(fd,'w',encoding='utf-8') as f:
                os.fchmod(f.fileno(),0o600)
                json.dump(record,f,sort_keys=True,separators=(',',':'))
                f.flush();os.fsync(f.fileno())
            os.replace(name,self.path)
            dfd=os.open(self.path.parent,os.O_RDONLY)
            try:os.fsync(dfd)
            finally:os.close(dfd)
        finally:
            if os.path.exists(name):os.unlink(name)
        return {'status':'EXTERNAL_ANCHOR_WRITTEN','execution_authorized':False,'cutover_authorized':False}

    def verify(self):
        try:
            record=json.loads(self.path.read_text(encoding='utf-8'))
        except (OSError,ValueError) as exc:
            raise ExternalAnchorError('ANCHOR_MISSING_OR_INVALID') from exc
        if not isinstance(record,dict) or set(record)!={'state','hmac_sha256'} or not isinstance(record['state'],dict) or not isinstance(record['hmac_sha256'],str):
            raise ExternalAnchorError('ANCHOR_FORMAT_INVALID')
        if not hmac.compare_digest(self._mac(record['state']),record['hmac_sha256']):
            raise ExternalAnchorError('ANCHOR_SIGNATURE_MISMATCH')
        if record['state']!=self._state():
            raise ExternalAnchorError('ANCHOR_STATE_MISMATCH')
        return {'status':'EXTERNAL_ANCHOR_VERIFIED','execution_authorized':False,'cutover_authorized':False}
