"""Persistent HMAC-protected Linux IPC identity pin; no automatic trust-on-first-use.

An HMAC protects file contents only if its key is stored separately and securely.
This is a local trust pin, not remote attestation or proof of binary integrity.
"""
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from ldaps_ipc_process_guard import ProcessGuard

class IdentityPinError(ValueError):
    pass

class PersistentProcessIdentity:
    def __init__(self, guard: ProcessGuard, *, pin_path, key):
        if not isinstance(key, bytes) or len(key) < 32:
            raise IdentityPinError('PIN_KEY_TOO_SHORT')
        self.guard = guard
        self.path = Path(pin_path)
        self.key = key

    def _mac(self, record):
        payload = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
        return hmac.new(self.key, payload, hashlib.sha256).hexdigest()

    def _read(self):
        try:
            if self.path.is_symlink():
                raise IdentityPinError('PIN_SYMLINK_FORBIDDEN')
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise IdentityPinError('PIN_UNREADABLE') from exc
        try:
            if len(raw) > 8192:
                raise ValueError('oversize')
            obj = json.loads(raw)
            rec = obj['record']
            if set(obj) != {'record', 'hmac_sha256'} or set(rec) != {'version','pid','start_ticks','exe_sha256'}:
                raise ValueError('shape')
            if rec['version'] != 1 or type(rec['pid']) is not int or rec['pid'] <= 0 or type(rec['start_ticks']) is not int or rec['start_ticks'] < 0 or rec['exe_sha256'] != self.guard.digest:
                raise ValueError('fields')
            if not isinstance(obj['hmac_sha256'], str) or not hmac.compare_digest(self._mac(rec), obj['hmac_sha256']):
                raise ValueError('mac')
            return rec
        except (ValueError, KeyError, TypeError) as exc:
            raise IdentityPinError('PIN_INVALID_OR_TAMPERED') from exc

    def _write(self, rec):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise IdentityPinError('PIN_SYMLINK_FORBIDDEN')
        fd, tmp = tempfile.mkstemp(prefix='.identity-pin-', dir=self.path.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                os.fchmod(stream.fileno(), 0o600)
                json.dump({'record': rec, 'hmac_sha256': self._mac(rec)}, stream, sort_keys=True, separators=(',', ':'))
                stream.flush(); os.fsync(stream.fileno())
            os.replace(tmp, self.path)
            dfd = os.open(self.path.parent, os.O_RDONLY)
            try: os.fsync(dfd)
            finally: os.close(dfd)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)

    def check(self):
        safe = {'execution_authorized': False, 'cutover_authorized': False, 'automatic_restart': False}
        try:
            rec = self._read()
        except IdentityPinError:
            return dict(safe, status='PIN_EVIDENCE_INVALID_MANUAL_REVIEW')
        if rec is None:
            return dict(safe, status='PIN_MISSING_MANUAL_ENROLLMENT')
        result = self.guard.check()
        if result['status'] == 'PEER_RESTART_REVIEW_REQUIRED':
            return dict(safe, status='PEER_CHANGED_MANUAL_REVIEW')
        if result['status'] != 'PEER_PROCESS_VERIFIED':
            return dict(safe, status=result['status'])
        if (result['peer_pid'], result['process_start_ticks']) != (rec['pid'], rec['start_ticks']):
            return dict(safe, status='PEER_CHANGED_MANUAL_REVIEW')
        return dict(safe, status='PERSISTENT_PEER_VERIFIED', peer_pid=rec['pid'])

    def enroll(self, *, operator_confirmed, expected_pid, expected_start_ticks):
        if operator_confirmed is not True:
            raise IdentityPinError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        if type(expected_pid) is not int or expected_pid <= 0 or type(expected_start_ticks) is not int or expected_start_ticks < 0:
            raise IdentityPinError('INVALID_EXPECTED_IDENTITY')
        # Fail closed on damaged pin: it must never be overwritten by enrollment.
        existing = self._read()
        result = self.guard.check()
        if result['status'] not in ('PEER_PROCESS_VERIFIED','PEER_RESTART_REVIEW_REQUIRED'):
            raise IdentityPinError('PEER_NOT_VERIFIED')
        if (result.get('peer_pid'), result.get('process_start_ticks')) != (expected_pid, expected_start_ticks):
            # ProcessGuard intentionally hides changed start ticks; require explicit reset before enrollment.
            raise IdentityPinError('IDENTITY_NOT_CONFIRMED')
        if existing is not None:
            raise IdentityPinError('PIN_ALREADY_EXISTS_REQUIRES_EXPLICIT_ROTATION')
        self._write({'version':1,'pid':expected_pid,'start_ticks':expected_start_ticks,'exe_sha256':self.guard.digest})
        return {'status':'PIN_ENROLLED','execution_authorized':False,'cutover_authorized':False}

    def rotate(self, *, operator_confirmed, expected_pid, expected_start_ticks):
        if operator_confirmed is not True:
            raise IdentityPinError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        if self._read() is None:
            raise IdentityPinError('PIN_MISSING')
        result = self.guard.check()
        if result['status'] != 'PEER_PROCESS_VERIFIED' or (result['peer_pid'],result['process_start_ticks']) != (expected_pid,expected_start_ticks):
            raise IdentityPinError('IDENTITY_NOT_CONFIRMED')
        self._write({'version':1,'pid':expected_pid,'start_ticks':expected_start_ticks,'exe_sha256':self.guard.digest})
        return {'status':'PIN_ROTATED','execution_authorized':False,'cutover_authorized':False}
