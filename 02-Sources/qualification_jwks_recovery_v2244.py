"""Fail-closed JWKS handoff recovery inspection. Author: Abdelhalim Talbi.

Read-only diagnosis; never publishes a witness or repairs evidence automatically.
"""
import json
import sqlite3
from pathlib import Path
from qualification_jwks_custody_v2241 import _check_receipt
from qualification_jwks_witness_v2240 import issue_witness, verify_witness


def inspect_handoff(*, ledger_path, witness_path, current_state, witness_secret, custody_secret):
    """Return a non-secret diagnostic; reject inconsistent or unauthenticated evidence."""
    try:
        with sqlite3.connect(f'file:{Path(ledger_path).resolve()}?mode=ro', uri=True) as db:
            row = db.execute('SELECT state,witness,receipt FROM handoff WHERE id=1').fetchone()
    except (sqlite3.Error, OSError) as exc:
        raise ValueError('CUSTODY_EVIDENCE_UNAVAILABLE') from exc
    if row is None:
        raise ValueError('CUSTODY_EVIDENCE_UNAVAILABLE')
    status, witness_json, receipt_json = row
    try:
        witness = json.loads(witness_json)
        expected = issue_witness(current_state, secret=witness_secret)
        if not isinstance(witness, dict) or witness != expected:
            raise ValueError('CUSTODY_GENERATION_STALE')
        if status == 'PENDING_CUSTODY_ACK':
            if receipt_json is not None:
                raise ValueError('CUSTODY_PENDING_RECEIPT_CONFLICT')
            # Witness may have been published before SQLite commit. Do not
            # silently mark the handoff complete even if its content matches.
            try:
                verify_witness(current_state, witness_path=witness_path, secret=witness_secret)
                published = True
            except ValueError:
                published = False
            return {'state': status, 'witness_published': published,
                    'requires_operator_replay': True, 'authentication_allowed': False}
        if status != 'CUSTODY_CONFIRMED' or receipt_json is None:
            raise ValueError('CUSTODY_HANDOFF_INVALID')
        receipt = json.loads(receipt_json)
        if not isinstance(receipt, dict) or not all(receipt.get(k) for k in ('custodian', 'reference', 'mac')):
            raise ValueError('CUSTODY_RECEIPT_INVALID')
        _check_receipt(witness, receipt, custody_secret)
        verify_witness(current_state, witness_path=witness_path, secret=witness_secret)
        return {'state': status, 'witness_published': True,
                'requires_operator_replay': False, 'authentication_allowed': True}
    except (TypeError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError('CUSTODY_EVIDENCE_INVALID') from exc
