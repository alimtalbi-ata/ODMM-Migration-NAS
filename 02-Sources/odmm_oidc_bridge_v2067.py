"""OIDC verified-claims adapter. No JWT verification is performed here. Auteur: Abdelhalim Talbi."""
import time
from urllib.parse import urlsplit

class OIDCClaimsError(ValueError):pass

def verified_claims_to_session(registry, claims, *, issuer, audience, nonce, role_claim='groups', role_mapping=None, clock=None, ttl=900):
    """Only call AFTER a trusted OIDC middleware has verified signature, alg, JWKS, token type and issuer.
    Never feed raw or decoded unverified JWT payloads. Require an independently stored login nonce.
    """
    if not isinstance(claims,dict) or not isinstance(issuer,str) or not isinstance(audience,str) or not isinstance(nonce,str) or len(nonce)<16:
        raise OIDCClaimsError('INVALID_OIDC_CONFIGURATION')
    u=urlsplit(issuer)
    if u.scheme!='https' or not u.netloc or u.username or u.password or u.query or u.fragment:
        raise OIDCClaimsError('INVALID_ISSUER')
    now=(clock or time.time)()
    if claims.get('iss')!=issuer or claims.get('nonce')!=nonce:raise OIDCClaimsError('ISSUER_OR_NONCE_MISMATCH')
    aud=claims.get('aud'); audiences=aud if isinstance(aud,list) else [aud]
    if audience not in audiences or not all(isinstance(a,str) for a in audiences):raise OIDCClaimsError('AUDIENCE_MISMATCH')
    if len(audiences)>1 and claims.get('azp')!=audience:raise OIDCClaimsError('AUTHORIZED_PARTY_MISMATCH')
    sub=claims.get('sub')
    if not isinstance(sub,str) or not sub.strip() or len(sub)>256:raise OIDCClaimsError('SUBJECT_INVALID')
    exp=claims.get('exp');iat=claims.get('iat')
    if type(exp) not in (int,float) or type(iat) not in (int,float) or exp<=now or iat>now+60 or iat<now-86400 or exp<=iat:
        raise OIDCClaimsError('TOKEN_TIME_INVALID')
    groups=claims.get(role_claim,[])
    if not isinstance(groups,list) or any(not isinstance(x,str) for x in groups):raise OIDCClaimsError('GROUPS_INVALID')
    mapping=role_mapping or {'odmm-admin':'admin','odmm-operator':'operator','odmm-viewer':'viewer'}
    if any(v not in ('viewer','operator','admin') for v in mapping.values()):raise OIDCClaimsError('ROLE_MAPPING_INVALID')
    assigned={mapping[g] for g in groups if g in mapping}
    role=next((r for r in ('admin','operator','viewer') if r in assigned),None)
    if role is None:raise OIDCClaimsError('NO_AUTHORIZED_ROLE')
    effective_ttl=min(ttl,int(exp-now))
    if effective_ttl<1:raise OIDCClaimsError('TOKEN_TOO_CLOSE_TO_EXPIRY')
    return registry.issue(issuer+'|'+sub,role,ttl=effective_ttl)
