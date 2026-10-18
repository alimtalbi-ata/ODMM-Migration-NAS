"""V187.3: independent append-only *cooperative* witness for IPC review anchors.

Witness must be stored in a separately administered failure domain. This local
reference implementation does not prevent an attacker restoring every copy.
Never performs automatic repair or cutover.
"""
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError
from ldaps_ipc_review_anchor import canonical


class ExternalReviewWitness:
    def __init__(self, anchored, *, witness_path, key):
        if not isinstance(key, bytes) or len(key) < 32:
            raise IdentityPinError('WITNESS_KEY_TOO_SHORT')
        self.anchored = anchored
        self.path = Path(witness_path)
        self.key = key
        protected = (anchored.path, anchored.ledger.path,
                     anchored.ledger.serialized.lock_path,
                     anchored.ledger.serialized.facade.path,
                     anchored.ledger.serialized.facade.controller.pin.path)
        if self.path.is_symlink() or self.path.resolve() in [p.resolve() for p in protected]:
            raise IdentityPinError('WITNESS_PATH_UNSAFE')

    def _mac(self, record):
        return hmac.new(self.key, canonical(record), hashlib.sha256).hexdigest()

    def _read(self):
        if self.path.is_symlink():
            raise IdentityPinError('WITNESS_PATH_UNSAFE')
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
        except FileNotFoundError:
            raise IdentityPinError('WITNESS_MISSING')
        except (OSError, ValueError) as exc:
            raise IdentityPinError('WITNESS_INVALID') from exc
        if not isinstance(data, dict) or set(data) != {'version', 'entries'} or data['version'] != 1 or not isinstance(data['entries'], list) or not data['entries']:
            raise IdentityPinError('WITNESS_INVALID')
        prev = '0' * 64
        for index, entry in enumerate(data['entries'], 1):
            if not isinstance(entry, dict) or set(entry) != {'seq','count','last_mac','previous','hmac_sha256'}:
                raise IdentityPinError('WITNESS_INVALID')
            record = {k: entry[k] for k in ('seq','count','last_mac','previous')}
            if (type(entry['seq']) is not int or entry['seq'] != index
                or type(entry['count']) is not int or entry['count'] < 0
                or not isinstance(entry['last_mac'], str) or len(entry['last_mac']) != 64
                or entry['previous'] != prev or not isinstance(entry['hmac_sha256'], str)
                or not hmac.compare_digest(self._mac(record), entry['hmac_sha256'])):
                raise IdentityPinError('WITNESS_INVALID')
            if index > 1 and entry['count'] <= data['entries'][index-2]['count']:
                raise IdentityPinError('WITNESS_INVALID')
            prev = entry['hmac_sha256']
        return data

    def _write(self, data):
        if self.path.is_symlink():
            raise IdentityPinError('WITNESS_PATH_UNSAFE')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix='.review-witness-', dir=self.path.parent)
        try:
            with os.fdopen(fd, 'wb') as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(canonical(data))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
        finally:
            if os.path.exists(temp): os.unlink(temp)

    def _snapshot_locked(self):
        anchor = self.anchored._read()
        current = self.anchored._state_locked()
        if anchor != current:
            raise IdentityPinError('WITNESS_ANCHOR_LEDGER_MISMATCH')
        return current

    def enroll(self, *, operator_confirmed):
        if operator_confirmed is not True:
            raise IdentityPinError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        def action():
            if self.path.exists() or self.path.is_symlink():
                raise IdentityPinError('WITNESS_ALREADY_EXISTS')
            state = self._snapshot_locked()
            record = {'seq':1,'count':state['count'],'last_mac':state['last_mac'],'previous':'0'*64}
            self._write({'version':1,'entries':[{**record,'hmac_sha256':self._mac(record)}]})
            return {'status':'WITNESS_ENROLLED','count':state['count'],'cutover_authorized':False}
        return self.anchored.ledger.serialized._locked(action)

    def verify(self):
        def action():
            data = self._read()
            last = data['entries'][-1]
            state = self._snapshot_locked()
            if state['count'] != last['count'] or state['last_mac'] != last['last_mac']:
                raise IdentityPinError('WITNESS_ROLLBACK_OR_DIVERGENCE')
            return {'status':'WITNESS_VERIFIED','count':state['count'],
                    'recovery_authorized':False,'cutover_authorized':False}
        return self.anchored.ledger.serialized._locked(action)

    def publish(self, *, operator_confirmed, expected_count, expected_last_mac):
        if operator_confirmed is not True:
            raise IdentityPinError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        def action():
            data = self._read()
            last = data['entries'][-1]
            state = self._snapshot_locked()
            if (type(expected_count) is not int or expected_count != state['count']
                    or expected_last_mac != state['last_mac']):
                raise IdentityPinError('WITNESS_STALE_EVIDENCE')
            if state['count'] <= last['count']:
                raise IdentityPinError('WITNESS_REPLAY_OR_ROLLBACK')
            record = {'seq':last['seq']+1,'count':state['count'],
                      'last_mac':state['last_mac'],'previous':last['hmac_sha256']}
            data['entries'].append({**record,'hmac_sha256':self._mac(record)})
            self._write(data)
            return {'status':'WITNESS_PUBLISHED','count':state['count'],
                    'recovery_authorized':False,'cutover_authorized':False}
        return self.anchored.ledger.serialized._locked(action)

    def restoration_report(self):
        """Read-only report; any mismatch requires independent operator review."""
        def action():
            try:
                entries = self._read()['entries']
                state = self._snapshot_locked()
                last = entries[-1]
                status = ('MATCH' if (state['count'],state['last_mac']) == (last['count'],last['last_mac'])
                          else 'ROLLBACK_OR_DIVERGENCE_MANUAL_REVIEW')
                return {'status':status,'witness_count':last['count'],
                        'observed_count':state['count'], 'recovery_authorized':False,
                        'cutover_authorized':False}
            except IdentityPinError:
                return {'status':'EVIDENCE_INVALID_MANUAL_REVIEW',
                        'recovery_authorized':False,'cutover_authorized':False}
        return self.anchored.ledger.serialized._locked(action)
