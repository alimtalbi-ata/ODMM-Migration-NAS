"""ODMM V210.7: pinned JWKS OIDC bearer verification for read-only Operations.
Author: Abdelhalim Talbi. No implicit trust of headers or unsigned JWTs.
"""
import jwt
from jwt.algorithms import RSAAlgorithm
from odmm_operations_security import Principal, ROLE_PERMISSIONS

class OIDCConfigurationError(ValueError):
    pass

class OIDCVerifier:
    def __init__(self, *, issuer, audience, jwks_provider, roles_claim='odmm_roles', leeway=30):
        if not isinstance(issuer,str) or not issuer.startswith('https://') or not issuer.rstrip('/') == issuer or not issuer:
            raise OIDCConfigurationError('INVALID_ISSUER')
        if not isinstance(audience,str) or not audience or len(audience)>256:
            raise OIDCConfigurationError('INVALID_AUDIENCE')
        if not callable(jwks_provider): raise OIDCConfigurationError('JWKS_PROVIDER_REQUIRED')
        if roles_claim not in ('odmm_roles','roles'): raise OIDCConfigurationError('INVALID_ROLES_CLAIM')
        if type(leeway) is not int or not 0 <= leeway <= 120: raise OIDCConfigurationError('INVALID_LEEWAY')
        self.issuer,self.audience,self.provider,self.roles_claim,self.leeway=issuer,audience,jwks_provider,roles_claim,leeway

    def verify(self, token):
        try:
            if not isinstance(token,str) or not 0 < len(token) <= 16384: raise ValueError()
            header=jwt.get_unverified_header(token)
            if header.get('alg') != 'RS256' or not isinstance(header.get('kid'),str) or not header['kid'] or len(header['kid'])>128:
                raise ValueError()
            jwks=self.provider()
            if not isinstance(jwks,dict) or not isinstance(jwks.get('keys'),list) or len(jwks['keys'])>64: raise ValueError()
            matches=[k for k in jwks['keys'] if isinstance(k,dict) and k.get('kid')==header['kid'] and k.get('kty')=='RSA' and k.get('alg','RS256')=='RS256' and k.get('use','sig')=='sig']
            if len(matches)!=1 and callable(getattr(self.provider,'__call__',None)) and hasattr(self.provider,'ttl'):
                jwks=self.provider(force_refresh=True)
                matches=[k for k in jwks['keys'] if isinstance(k,dict) and k.get('kid')==header['kid'] and k.get('kty')=='RSA' and k.get('alg','RS256')=='RS256' and k.get('use','sig')=='sig']
            if len(matches)!=1: raise ValueError()
            key=RSAAlgorithm.from_jwk(matches[0])
            claims=jwt.decode(token,key,algorithms=['RS256'],issuer=self.issuer,audience=self.audience,
                              leeway=self.leeway,options={'require':['exp','iat','nbf','iss','aud','sub']})
            roles=claims.get(self.roles_claim)
            if not isinstance(roles,list) or not roles or any(not isinstance(r,str) for r in roles): raise ValueError()
            role_set=frozenset(roles)
            if not role_set <= ROLE_PERMISSIONS.keys(): raise ValueError()
            subject=claims['sub']
            if not isinstance(subject,str) or not subject.strip() or len(subject)>256: raise ValueError()
            return Principal(subject,role_set,True)
        except Exception as exc:
            raise PermissionError('OIDC_IDENTITY_REJECTED') from None

    def resolve_request(self,request):
        try:
            authorization=request.headers.get('authorization','')
            if not authorization.startswith('Bearer ') or authorization.count(' ')!=1: raise ValueError()
            return self.verify(authorization[7:])
        except Exception:
            raise PermissionError('OIDC_IDENTITY_REJECTED') from None


def create_oidc_vault_operations_app(*, issuer, audience, jwks_provider, ha_client, **kwargs):
    """Explicit opt-in OIDC boundary. Hosting proxy must not bypass this resolver."""
    from odmm_vault_prometheus_v2105 import create_vault_prometheus_operations_app
    verifier=OIDCVerifier(issuer=issuer,audience=audience,jwks_provider=jwks_provider)
    return create_vault_prometheus_operations_app(ha_client=ha_client,
        resolve_verified_principal=verifier.resolve_request,**kwargs)
