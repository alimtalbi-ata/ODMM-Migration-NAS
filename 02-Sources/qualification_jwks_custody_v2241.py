"""Supervised JWKS witness custody handoff. Author: Abdelhalim Talbi.

No network transmission: an independent custodian must issue the authenticated receipt.
"""
import hashlib
import hmac
import json
import os
import sqlite3
from pathlib import Path
from qualification_jwks_witness_v2240 import issue_witness, verify_witness


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


def receipt_for(witness, *, custodian, reference, custody_secret):
    if not isinstance(custody_secret, bytes) or len(custody_secret) < 32:
        raise ValueError('CUSTODY_SECRET_INVALID')
    if not custodian or not reference:
        raise ValueError('CUSTODY_IDENTITY_REQUIRED')
    payload = {'witness_sha256': hashlib.sha256(_canonical(witness)).hexdigest(),
               'custodian': custodian, 'reference': reference}
    return {**payload, 'mac': hmac.new(custody_secret, _canonical(payload), hashlib.sha256).hexdigest()}


def _check_receipt(witness, receipt, custody_secret):
    if not isinstance(receipt, dict):
        raise ValueError('CUSTODY_RECEIPT_INVALID')
    expected = receipt_for(witness, custodian=receipt.get('custodian'),
                           reference=receipt.get('reference'), custody_secret=custody_secret)
    if set(receipt) != set(expected) or any(not hmac.compare_digest(str(receipt[k]), str(v)) for k, v in expected.items()):
        raise ValueError('CUSTODY_RECEIPT_INVALID')


class JWKSWitnessHandoff:
    def __init__(self, *, ledger_path, witness_path, witness_secret, custody_secret):
        self.ledger_path = str(ledger_path)
        self.witness_path = str(witness_path)
        self.witness_secret = witness_secret
        self.custody_secret = custody_secret
        with self._db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS handoff (id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL, witness TEXT NOT NULL, receipt TEXT)')

    def _db(self):
        db = sqlite3.connect(self.ledger_path, timeout=5)
        db.execute('PRAGMA busy_timeout=5000')
        return db

    def prepare(self, state):
        witness = issue_witness(state, secret=self.witness_secret)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM handoff WHERE id=1').fetchone():
                raise ValueError('CUSTODY_HANDOFF_PENDING')
            db.execute('INSERT INTO handoff VALUES (1,?,?,NULL)', ('PENDING_CUSTODY_ACK', json.dumps(witness, sort_keys=True)))
        return witness

    def confirm(self, *, receipt, current_state):
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT state,witness,receipt FROM handoff WHERE id=1').fetchone()
            if not row:
                raise ValueError('CUSTODY_HANDOFF_MISSING')
            status, witness_json, old_receipt = row
            witness = json.loads(witness_json)
            if witness != issue_witness(current_state, secret=self.witness_secret):
                raise ValueError('CUSTODY_GENERATION_STALE')
            _check_receipt(witness, receipt, self.custody_secret)
            if status == 'CUSTODY_CONFIRMED':
                if json.loads(old_receipt) != receipt:
                    raise ValueError('CUSTODY_RECEIPT_CONFLICT')
                return status
            if status != 'PENDING_CUSTODY_ACK':
                raise ValueError('CUSTODY_HANDOFF_INVALID')
            # Fail closed: publish witness atomically on same filesystem; if interrupted,
            # keep pending record and require operator replay with identical receipt.
            target = Path(self.witness_path)
            tmp = target.with_name(target.name + '.pending-' + str(os.getpid()))
            try:
                with tmp.open('x', encoding='utf-8') as f:
                    json.dump(witness, f, sort_keys=True)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, target)
                directory_fd = os.open(str(target.parent), os.O_RDONLY)
                try: os.fsync(directory_fd)
                finally: os.close(directory_fd)
                verify_witness(current_state, witness_path=target, secret=self.witness_secret)
                db.execute('UPDATE handoff SET state=?, receipt=? WHERE id=1',
                           ('CUSTODY_CONFIRMED', json.dumps(receipt, sort_keys=True)))
            finally:
                if tmp.exists(): tmp.unlink()
        return 'CUSTODY_CONFIRMED'

    def status(self):
        with self._db() as db:
            row = db.execute('SELECT state FROM handoff WHERE id=1').fetchone()
            return row[0] if row else 'NONE'
