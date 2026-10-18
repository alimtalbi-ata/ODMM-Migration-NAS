"""V187.2: independent HMAC checkpoint for the durable IPC review ledger.

The checkpoint lives outside the ledger SQLite database. A checkpoint is only
published following explicit operator confirmation, never during verification.
Full simultaneous rollback of both files and key compromise remain out of scope.
"""
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')


class AnchoredIPCReview:
    def __init__(self, ledger, *, anchor_path, key):
        if not isinstance(key, bytes) or len(key) < 32:
            raise IdentityPinError('REVIEW_ANCHOR_KEY_TOO_SHORT')
        self.ledger = ledger
        self.path = Path(anchor_path)
        self.key = key
        protected = [ledger.path, ledger.serialized.lock_path,
                     ledger.serialized.facade.path,
                     ledger.serialized.facade.controller.pin.path]
        if self.path.resolve() in [p.resolve() for p in protected] or self.path.is_symlink():
            raise IdentityPinError('REVIEW_ANCHOR_PATH_UNSAFE')

    def _mac(self, state):
        return hmac.new(self.key, canonical(state), hashlib.sha256).hexdigest()

    def _read(self):
        if self.path.is_symlink():
            raise IdentityPinError('REVIEW_ANCHOR_PATH_UNSAFE')
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
        except FileNotFoundError:
            raise IdentityPinError('REVIEW_ANCHOR_MISSING')
        except (OSError, ValueError) as exc:
            raise IdentityPinError('REVIEW_ANCHOR_INVALID') from exc
        if not isinstance(data, dict) or set(data) != {'state', 'hmac_sha256'}:
            raise IdentityPinError('REVIEW_ANCHOR_INVALID')
        state = data['state']
        if (not isinstance(state, dict) or set(state) != {'version','count','last_mac'}
                or state['version'] != 1 or type(state['count']) is not int
                or state['count'] < 0 or not isinstance(state['last_mac'], str)
                or len(state['last_mac']) != 64 or not isinstance(data['hmac_sha256'], str)
                or not hmac.compare_digest(self._mac(state), data['hmac_sha256'])):
            raise IdentityPinError('REVIEW_ANCHOR_INVALID')
        return state

    def _state_locked(self):
        db = self.ledger._open()
        try:
            result = self.ledger._verify(db)
            return {'version': 1, 'count': result['count'], 'last_mac': result['last_mac']}
        finally:
            db.close()

    def _write_locked(self, state):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise IdentityPinError('REVIEW_ANCHOR_PATH_UNSAFE')
        fd, temp = tempfile.mkstemp(prefix='.ipc-review-anchor-', dir=self.path.parent)
        try:
            with os.fdopen(fd, 'wb') as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(canonical({'state':state,'hmac_sha256':self._mac(state)}))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
        finally:
            if os.path.exists(temp): os.unlink(temp)

    def enroll(self, *, operator_confirmed):
        if operator_confirmed is not True:
            raise IdentityPinError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        def action():
            if self.path.exists() or self.path.is_symlink():
                raise IdentityPinError('REVIEW_ANCHOR_ALREADY_EXISTS')
            state = self._state_locked()
            self._write_locked(state)
            return {'status':'REVIEW_ANCHOR_ENROLLED','count':state['count'], 'cutover_authorized':False}
        return self.ledger.serialized._locked(action)

    def verify(self):
        def action():
            old = self._read()
            current = self._state_locked()
            if old != current:
                raise IdentityPinError('REVIEW_ANCHOR_LEDGER_MISMATCH')
            return {'status':'REVIEW_ANCHOR_VERIFIED','count':current['count'],
                    'recovery_authorized':False,'cutover_authorized':False}
        return self.ledger.serialized._locked(action)

    def archive(self, **kwargs):
        """Fail closed if checkpoint publication was interrupted.

        Caller must explicitly reconcile an interrupted publication; no silent retry.
        """
        self.verify()
        result = self.ledger.review(**kwargs)
        # Another cooperative writer could intervene between these calls;
        # therefore do not publish an anchor automatically here.
        return {**result, 'status':'REVIEW_ARCHIVED_ANCHOR_UPDATE_REQUIRED',
                'recovery_authorized':False,'cutover_authorized':False}

    def checkpoint(self, *, operator_confirmed, expected_count, expected_last_mac):
        if operator_confirmed is not True:
            raise IdentityPinError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        def action():
            old = self._read()
            current = self._state_locked()
            if (type(expected_count) is not int or expected_count != current['count']
                    or expected_last_mac != current['last_mac']):
                raise IdentityPinError('REVIEW_ANCHOR_STALE_EVIDENCE')
            if current['count'] < old['count']:
                raise IdentityPinError('REVIEW_ANCHOR_ROLLBACK_DETECTED')
            if current['count'] == old['count'] and current != old:
                raise IdentityPinError('REVIEW_ANCHOR_LEDGER_MISMATCH')
            self._write_locked(current)
            return {'status':'REVIEW_ANCHOR_CHECKPOINTED','count':current['count'],
                    'recovery_authorized':False,'cutover_authorized':False}
        return self.ledger.serialized._locked(action)
