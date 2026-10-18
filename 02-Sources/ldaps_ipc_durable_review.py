"""V187.1: durable, HMAC-chained review receipts. Never authorizes recovery.

Uses the same cooperative SQLite gate as IPC rotation. The journal is a separate
SQLite resource: no distributed atomicity or anti-rollback against full snapshots.
"""
import hashlib
import hmac
import json
import sqlite3
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError
from ldaps_ipc_reconciliation import canonical

class DurableIPCReview:
    def __init__(self, reconciliation, *, journal_path, key):
        if not isinstance(key, bytes) or len(key) < 32:
            raise IdentityPinError('DURABLE_REVIEW_KEY_TOO_SHORT')
        self.reconciliation = reconciliation
        self.serialized = reconciliation.serialized
        self.path = Path(journal_path)
        self.key = key
        protected = (self.serialized.lock_path, self.serialized.facade.path,
                     self.serialized.facade.controller.pin.path)
        if self.path.resolve() in [p.resolve() for p in protected] or self.path.is_symlink():
            raise IdentityPinError('DURABLE_REVIEW_PATH_UNSAFE')

    def _mac(self, record):
        return hmac.new(self.key, canonical(record), hashlib.sha256).hexdigest()

    def _open(self):
        if self.path.is_symlink():
            raise IdentityPinError('DURABLE_REVIEW_PATH_UNSAFE')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(str(self.path), isolation_level=None, timeout=0.2)
        db.execute('PRAGMA busy_timeout=200')
        db.execute('CREATE TABLE IF NOT EXISTS ipc_review_receipts (seq INTEGER PRIMARY KEY, evidence TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, previous_mac TEXT NOT NULL, mac TEXT NOT NULL)')
        return db

    def _verify(self, db):
        previous = '0' * 64
        rows = db.execute('SELECT seq,evidence,payload,previous_mac,mac FROM ipc_review_receipts ORDER BY seq').fetchall()
        for index, (seq,evidence,payload,prev,mac) in enumerate(rows,1):
            try: receipt = json.loads(payload)
            except (TypeError,ValueError) as exc: raise IdentityPinError('DURABLE_REVIEW_AUDIT_INVALID') from exc
            record = {'seq':seq,'evidence':evidence,'receipt':receipt,'previous_mac':prev}
            if (seq != index or prev != previous or not hmac.compare_digest(self._mac(record),mac)
                or receipt.get('receipt',{}).get('evidence_sha256') != evidence):
                raise IdentityPinError('DURABLE_REVIEW_AUDIT_INVALID')
            self.reconciliation.verify_receipt(receipt)
            previous=mac
        return {'count':len(rows),'last_mac':previous,'recovery_authorized':False,'cutover_authorized':False}

    def verify(self):
        def action():
            db=self._open()
            try:return self._verify(db)
            finally:db.close()
        return self.serialized._locked(action)

    def review(self, **kwargs):
        def action():
            db=self._open()
            try:
                db.execute('BEGIN IMMEDIATE')
                state=self._verify(db)
                evidence=kwargs.get('expected_evidence_sha256')
                if db.execute('SELECT 1 FROM ipc_review_receipts WHERE evidence=?',(evidence,)).fetchone():
                    raise IdentityPinError('REVIEW_EVIDENCE_ALREADY_ARCHIVED')
                # Outer cooperative gate is already held; do not re-acquire it.
                receipt=self.reconciliation._review_locked(**kwargs)
                record={'seq':state['count']+1,'evidence':evidence,'receipt':receipt,'previous_mac':state['last_mac']}
                db.execute('INSERT INTO ipc_review_receipts(seq,evidence,payload,previous_mac,mac) VALUES(?,?,?,?,?)',
                    (record['seq'],evidence,json.dumps(receipt,sort_keys=True,separators=(',',':')),
                     record['previous_mac'],self._mac(record)))
                db.execute('COMMIT')
                return {'status':'REVIEW_DURABLY_ARCHIVED','sequence':record['seq'],
                        'receipt_mac':self._mac(record),'recovery_authorized':False,
                        'execution_authorized':False,'cutover_authorized':False}
            except BaseException:
                if db.in_transaction:db.execute('ROLLBACK')
                raise
            finally:db.close()
        return self.serialized._locked(action)
