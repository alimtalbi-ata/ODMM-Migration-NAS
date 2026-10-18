"""Authenticated dual-review gate for IPC pin rotation; fail-closed, no implicit repair.

Only this facade enforces OIDC. Legacy direct APIs must be isolated by deployment.
"""
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError

class AuthenticatedPinRotation:
    def __init__(self, controller, verifier, *, checkpoint_path, checkpoint_key):
        if not isinstance(checkpoint_key, bytes) or len(checkpoint_key) < 32:
            raise IdentityPinError('CHECKPOINT_KEY_TOO_SHORT')
        self.controller = controller
        self.verifier = verifier
        self.path = Path(checkpoint_path)
        self.key = checkpoint_key
        if self.path.resolve() in (controller.gate_path.resolve(), controller.pin.path.resolve()):
            raise IdentityPinError('CHECKPOINT_PATH_COLLISION')

    def _mac(self, record):
        return hmac.new(self.key, json.dumps(record, sort_keys=True, separators=(',', ':')).encode(), hashlib.sha256).hexdigest()

    def _checkpoint(self):
        if self.path.is_symlink():
            raise IdentityPinError('CHECKPOINT_SYMLINK_FORBIDDEN')
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return None
        if len(raw) > 8192:
            raise IdentityPinError('CHECKPOINT_INVALID')
        try:
            obj = json.loads(raw)
            rec = obj['record']
            if (set(obj) != {'record','hmac_sha256'} or set(rec) != {'version','audit_mac','pin_mac'}
                or rec['version'] != 1 or not isinstance(rec['audit_mac'],str)
                or not isinstance(rec['pin_mac'],str) or not hmac.compare_digest(obj['hmac_sha256'], self._mac(rec))):
                raise ValueError()
            return rec
        except (ValueError, KeyError, TypeError) as exc:
            raise IdentityPinError('CHECKPOINT_INVALID') from exc

    def _write(self, record):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise IdentityPinError('CHECKPOINT_SYMLINK_FORBIDDEN')
        fd, temp = tempfile.mkstemp(prefix='.ipc-anchor-', dir=self.path.parent)
        try:
            with os.fdopen(fd,'w',encoding='utf-8') as out:
                os.fchmod(out.fileno(),0o600)
                json.dump({'record':record,'hmac_sha256':self._mac(record)},out,sort_keys=True)
                out.flush();os.fsync(out.fileno())
            os.replace(temp,self.path)
            dfd=os.open(self.path.parent,os.O_RDONLY)
            try:os.fsync(dfd)
            finally:os.close(dfd)
        finally:
            if os.path.exists(temp):os.unlink(temp)

    def inspect(self):
        """Read-only comparison. A mismatch requires operator investigation."""
        try:
            anchor=self._checkpoint()
            audit=self.controller.verify_audit()['last_mac']
            pin=self.controller.pin._read()
            if pin is None:
                return {'status':'PIN_MISSING_MANUAL_REVIEW'}
            pin_mac=self.controller.pin._mac(pin)
            if anchor is None:
                return {'status':'CHECKPOINT_MISSING_MANUAL_REVIEW'}
            if audit != anchor['audit_mac']:
                return {'status':'AUDIT_CHECKPOINT_MISMATCH_MANUAL_REVIEW'}
            if pin_mac != anchor['pin_mac']:
                return {'status':'PIN_CHECKPOINT_MISMATCH_MANUAL_REVIEW'}
            return {'status':'CHECKPOINT_VERIFIED','execution_authorized':False,'cutover_authorized':False}
        except (IdentityPinError, OSError, ValueError):
            return {'status':'EVIDENCE_INVALID_MANUAL_REVIEW'}

    def enroll_checkpoint(self, *, operator_confirmed):
        """Explicit initial trust bootstrap, never silently re-anchor an existing checkpoint."""
        if operator_confirmed is not True:
            raise IdentityPinError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        if self.path.exists() or self.path.is_symlink():
            raise IdentityPinError('CHECKPOINT_ALREADY_EXISTS')
        audit=self.controller.verify_audit()['last_mac']
        pin=self.controller.pin._read()
        if pin is None:raise IdentityPinError('PIN_MISSING')
        self._write({'version':1,'audit_mac':audit,'pin_mac':self.controller.pin._mac(pin)})
        return {'status':'CHECKPOINT_ENROLLED','execution_authorized':False,'cutover_authorized':False}

    def rotate(self, *, security_token, operations_token, now, expected_pid, expected_start_ticks, operator_confirmed):
        if operator_confirmed is not True:
            raise IdentityPinError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        if type(now) is not int or now < 0:
            raise IdentityPinError('INVALID_TIME')
        # Both JWTs must be signed, time-valid and unrevoked by the configured verifier.
        sec=self.verifier.verify(security_token,now=now)
        ops=self.verifier.verify(operations_token,now=now)
        if (sec['subject']==ops['subject'] or sec['token_id']==ops['token_id']
            or sec['issuer']!=ops['issuer']):
            raise IdentityPinError('REVIEWER_SEPARATION_REQUIRED')
        if self.inspect()['status']!='CHECKPOINT_VERIFIED':
            raise IdentityPinError('CHECKPOINT_RECONCILIATION_REQUIRED')
        # Explicit role claims are intentionally not trusted from arbitrary JWTs.
        # Role authority must be supplied by a verifier-backed, trusted RBAC policy.
        if not hasattr(self.verifier,'assert_role'):
            raise IdentityPinError('ROLE_AUTHORITY_REQUIRED')
        self.verifier.assert_role(sec, 'SECURITY')
        self.verifier.assert_role(ops, 'OPERATIONS')
        result=self.controller.rotate(security_reviewer=sec['subject'],operations_reviewer=ops['subject'],
                                      operator_confirmed=True,expected_pid=expected_pid,
                                      expected_start_ticks=expected_start_ticks)
        # Crash here leaves checkpoint mismatch and forces manual review.
        pin=self.controller.pin._read()
        self._write({'version':1,'audit_mac':result['audit_mac'],'pin_mac':self.controller.pin._mac(pin)})
        return {'status':'AUTHENTICATED_PIN_ROTATED','execution_authorized':False,'cutover_authorized':False}
