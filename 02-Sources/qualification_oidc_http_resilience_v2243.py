"""Fail-closed HTTP boundary for custody evidence; author Abdelhalim Talbi.

No custody recovery endpoints are exposed. Evidence faults produce HTTP 503,
not a traceback or an incorrect claim that a user's JWT was invalid.
"""
from fastapi import HTTPException
from qualification_oidc_custody_gate_v2242 import CustodyGatedJWKSRotation
from qualification_oidc_production_v2237 import create_oidc_production_review_app


class HTTPResilientCustodyRotation(CustodyGatedJWKSRotation):
    def resolve_request(self, request):
        try:
            return super().resolve_request(request)
        except PermissionError:
            raise
        except (ValueError, OSError) as exc:
            raise HTTPException(status_code=503, detail='OIDC_CUSTODY_EVIDENCE_UNVERIFIED',
                                headers={'Cache-Control': 'no-store'}) from exc


def create_resilient_custody_oidc_app(*, custody_ledger_path, custody_secret,
                                      witness_path, witness_secret, jwks_db_path,
                                      issuer, audience, jwks, role_claim='roles', clock=None, **kwargs):
    rotation = HTTPResilientCustodyRotation(
        path=jwks_db_path, issuer=issuer, audience=audience, initial_jwks=jwks,
        role_claim=role_claim, clock=clock, witness_path=witness_path,
        witness_secret=witness_secret, custody_ledger_path=custody_ledger_path,
        custody_secret=custody_secret)
    return create_oidc_production_review_app(
        issuer=issuer, audience=audience, jwks=jwks, role_claim=role_claim,
        clock=clock, rotation=rotation, **kwargs)


def create_diagnostic_custody_oidc_app(*, custody_ledger_path, custody_secret,
                                         witness_path, witness_secret, jwks_db_path,
                                         issuer, audience, jwks, role_claim='roles', clock=None, **kwargs):
    """Secure OIDC app with a read-only, role-gated custody diagnostic route."""
    from qualification_oidc_production_v2237 import oidc_authenticator
    from qualification_oidc_recovery_http_v2245 import attach_custody_diagnostic
    rotation = HTTPResilientCustodyRotation(
        path=jwks_db_path, issuer=issuer, audience=audience, initial_jwks=jwks,
        role_claim=role_claim, clock=clock, witness_path=witness_path,
        witness_secret=witness_secret, custody_ledger_path=custody_ledger_path,
        custody_secret=custody_secret)
    app = create_oidc_production_review_app(
        issuer=issuer, audience=audience, jwks=jwks, role_claim=role_claim,
        clock=clock, rotation=rotation, **kwargs)
    return attach_custody_diagnostic(app, authenticate=oidc_authenticator(
        issuer=issuer, audience=audience, jwks=jwks, role_claim=role_claim,
        clock=clock, rotation=rotation), rotation=rotation,
        ledger_path=custody_ledger_path, witness_path=witness_path,
        witness_secret=witness_secret, custody_secret=custody_secret)
