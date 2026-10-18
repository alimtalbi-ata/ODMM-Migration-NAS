"""Production OIDC app backed by SQLite JWKS and mandatory witness.
Author: Abdelhalim Talbi.
"""
from qualification_jwks_persistent_v2239 import PersistentJWKSRotation
from qualification_jwks_witness_v2240 import verify_witness
from qualification_oidc_production_v2237 import create_oidc_production_review_app, REVIEW_ROLES

class WitnessedJWKSRotation:
    def __init__(self, *, witness_path, witness_secret, **rotation_kwargs):
        self.rotation = PersistentJWKSRotation(allowed_roles=REVIEW_ROLES, **rotation_kwargs)
        self.witness_path = witness_path
        self.witness_secret = witness_secret
        self.assert_witness()

    def assert_witness(self):
        return verify_witness(self.rotation.state, witness_path=self.witness_path, secret=self.witness_secret)

    def resolve_request(self, request):
        self.assert_witness()  # verify on every request, not just startup
        return self.rotation.resolve_request(request)

    @property
    def state(self):
        self.assert_witness()
        return self.rotation.state


def create_persistent_oidc_production_review_app(*, witness_path, witness_secret,
                                                 jwks_db_path, issuer, audience, jwks,
                                                 role_claim='roles', clock=None, **kwargs):
    rotation = WitnessedJWKSRotation(path=jwks_db_path, issuer=issuer, audience=audience,
                                    initial_jwks=jwks, role_claim=role_claim, clock=clock,
                                    witness_path=witness_path, witness_secret=witness_secret)
    return create_oidc_production_review_app(issuer=issuer, audience=audience, jwks=jwks,
                                             role_claim=role_claim, clock=clock, rotation=rotation, **kwargs)
