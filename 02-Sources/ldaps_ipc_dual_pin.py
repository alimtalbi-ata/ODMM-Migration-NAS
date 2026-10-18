"""Cooperating-process SQLite lock and dual-reviewed persistent IPC pin rotation.

Reviewer identities are DECLARATIVE, not authenticated. Legacy pin.rotate() remains
callable. Journal is HMAC-protected but not an external anti-rollback anchor.
"""
import hashlib
import hmac
import json
import sqlite3
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError


class DualPinController:
    def __init__(self, pin, *, gate_path, key):
        if not isinstance(key, bytes) or len(key) < 32:
            raise IdentityPinError('AUDIT_KEY_TOO_SHORT')
        self.pin = pin
        self.key = key
        self.gate_path = Path(gate_path)
        if self.gate_path.resolve() == pin.path.resolve():
            raise IdentityPinError('GATE_PIN_COLLISION')

    def _mac(self, record):
        return hmac.new(self.key, json.dumps(record, sort_keys=True, separators=(',', ':')).encode(), hashlib.sha256).hexdigest()

    def _open(self):
        self.gate_path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(str(self.gate_path), timeout=0.2, isolation_level=None)
        db.execute('PRAGMA busy_timeout=200')
        db.execute('CREATE TABLE IF NOT EXISTS pin_audit (seq INTEGER PRIMARY KEY, event TEXT NOT NULL, mac TEXT NOT NULL)')
        return db

    def verify_audit(self):
        with self._open() as db:
            previous = '0' * 64
            for seq, event, mac in db.execute('SELECT seq,event,mac FROM pin_audit ORDER BY seq'):
                try:
                    record = json.loads(event)
                except (ValueError, TypeError) as exc:
                    raise IdentityPinError('PIN_AUDIT_CORRUPT') from exc
                if (record.get('seq') != seq or record.get('previous_mac') != previous
                        or not hmac.compare_digest(self._mac(record), mac)):
                    raise IdentityPinError('PIN_AUDIT_CORRUPT')
                previous = mac
            return {'status': 'PIN_AUDIT_VERIFIED', 'last_mac': previous}

    def rotate(self, *, security_reviewer, operations_reviewer, operator_confirmed,
               expected_pid, expected_start_ticks):
        if operator_confirmed is not True:
            raise IdentityPinError('EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED')
        if (not isinstance(security_reviewer, str) or not security_reviewer.strip()
                or not isinstance(operations_reviewer, str) or not operations_reviewer.strip()
                or security_reviewer.strip() == operations_reviewer.strip()):
            raise IdentityPinError('TWO_DISTINCT_REVIEWERS_REQUIRED')
        db = self._open()
        try:
            try:
                db.execute('BEGIN IMMEDIATE')
            except sqlite3.OperationalError as exc:
                raise IdentityPinError('PIN_GATE_BUSY') from exc
            previous = '0' * 64
            for seq, event, mac in db.execute('SELECT seq,event,mac FROM pin_audit ORDER BY seq'):
                try:
                    record = json.loads(event)
                except (ValueError, TypeError) as exc:
                    raise IdentityPinError('PIN_AUDIT_CORRUPT') from exc
                if record.get('seq') != seq or record.get('previous_mac') != previous or not hmac.compare_digest(self._mac(record), mac):
                    raise IdentityPinError('PIN_AUDIT_CORRUPT')
                previous = mac
            # Any journaled rotation whose target does not match the pin is ambiguous.
            last = db.execute('SELECT event FROM pin_audit ORDER BY seq DESC LIMIT 1').fetchone()
            existing = self.pin._read()
            if last and existing is not None:
                prior = json.loads(last[0])
                if (existing['pid'], existing['start_ticks']) != (prior['new_pid'], prior['new_start_ticks']):
                    raise IdentityPinError('PENDING_ROTATION_MANUAL_REVIEW')
            # Validate all inputs and live peer before any pin file write.
            if existing is None:
                raise IdentityPinError('PIN_MISSING')
            peer = self.pin.guard.check()
            if (peer.get('status') != 'PEER_PROCESS_VERIFIED'
                    or (peer.get('peer_pid'), peer.get('process_start_ticks')) != (expected_pid, expected_start_ticks)):
                raise IdentityPinError('IDENTITY_NOT_CONFIRMED')
            if type(expected_pid) is not int or type(expected_start_ticks) is not int:
                raise IdentityPinError('INVALID_EXPECTED_IDENTITY')
            if (existing['pid'], existing['start_ticks']) == (expected_pid, expected_start_ticks):
                raise IdentityPinError('IDENTITY_UNCHANGED')
            seq = db.execute('SELECT COALESCE(MAX(seq),0)+1 FROM pin_audit').fetchone()[0]
            record = {'seq': seq, 'previous_mac': previous, 'old_pin_mac': self.pin._mac(existing),
                      'new_pid': expected_pid, 'new_start_ticks': expected_start_ticks,
                      'security_reviewer': security_reviewer.strip(),
                      'operations_reviewer': operations_reviewer.strip()}
            event = json.dumps(record, sort_keys=True, separators=(',', ':'))
            mac = self._mac(record)
            # Commit intent before filesystem change; interruption remains manual-review only.
            db.execute('INSERT INTO pin_audit(seq,event,mac) VALUES(?,?,?)', (seq,event,mac))
            db.execute('COMMIT')
            # No automated recovery on error. A recorded intent with old pin blocks further rotation.
            self.pin.rotate(operator_confirmed=True, expected_pid=expected_pid, expected_start_ticks=expected_start_ticks)
            return {'status': 'DUAL_PIN_ROTATED', 'audit_mac': mac,
                    'execution_authorized': False, 'cutover_authorized': False}
        except Exception:
            if db.in_transaction:
                db.execute('ROLLBACK')
            raise
        finally:
            db.close()
