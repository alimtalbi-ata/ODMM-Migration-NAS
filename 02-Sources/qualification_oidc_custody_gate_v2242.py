"""Fail-closed OIDC gate requiring independently acknowledged JWKS witness.
Author: Abdelhalim Talbi. Receipt verification uses a separately provisioned custody secret.
"""
import json
import sqlite3
from qualification_jwks_custody_v2241 import _check_receipt
from qualification_jwks_witness_v2240 import issue_witness
from qualification_oidc_persistent_v2240 import WitnessedJWKSRotation
from qualification_oidc_production_v2237 import create_oidc_production_review_app, REVIEW_ROLES


class CustodyGatedJWKSRotation(WitnessedJWKSRotation):
    def __init__(self, *, custody_ledger_path, custody_secret, **kwargs):
        self.custody_ledger_path = str(custody_ledger_path)
        self.custody_secret = custody_secret
        super().__init__(**kwargs)
        self.assert_custody()

    def assert_custody(self):
        # SQLite ledger is never created implicitly: missing custody evidence is fatal.
        try:
            with sqlite3.connect(f'file:{self.custody_ledger_path}?mode=ro', uri=True) as db:
                row = db.execute('SELECT state,witness,receipt FROM handoff WHERE id=1').fetchone()
        except (sqlite3.Error, OSError) as exc:
            raise ValueError('CUSTODY_EVIDENCE_UNAVAILABLE') from exc
        if row is None or row[0] != 'CUSTODY_CONFIRMED' or not row[2]:
            raise ValueError('CUSTODY_ACK_PENDING')
        try:
            witness = json.loads(row[1]); receipt = json.loads(row[2])
            if witness != issue_witness(self.rotation.state, secret=self.witness_secret):
                raise ValueError('CUSTODY_GENERATION_STALE')
            _check_receipt(witness, receipt, self.custody_secret)
            self.assert_witness()
        except (TypeError, KeyError, json.JSONDecodeError) as exc:
            raise ValueError('CUSTODY_EVIDENCE_INVALID') from exc
        return True

    def resolve_request(self, request):
        self.assert_custody()
        return super().resolve_request(request)


def create_custody_gated_oidc_app(*, custody_ledger_path, custody_secret,
                                  witness_path, witness_secret, jwks_db_path,
                                  issuer, audience, jwks, role_claim='roles', clock=None, **kwargs):
    rotation = CustodyGatedJWKSRotation(
        path=jwks_db_path, issuer=issuer, audience=audience, initial_jwks=jwks,
        role_claim=role_claim, clock=clock,
        witness_path=witness_path, witness_secret=witness_secret,
        custody_ledger_path=custody_ledger_path, custody_secret=custody_secret)
    return create_oidc_production_review_app(issuer=issuer, audience=audience,
        jwks=jwks, role_claim=role_claim, clock=clock, rotation=rotation, **kwargs)
