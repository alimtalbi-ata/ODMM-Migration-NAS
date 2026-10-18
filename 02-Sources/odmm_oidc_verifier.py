"""Strict offline RS256 OIDC JWT verification with deployment-pinned public JWKS.

Deployment must refresh and authenticate JWKS out-of-band. Never fetch keys from
JWT headers or accept a token-supplied JWK URL. This is a stateless bearer
verifier, not a complete OIDC login/session implementation.
"""
import base64
import json
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from odmm_operations_security import Principal


def _decode(segment):
    if not isinstance(segment, str) or not segment or len(segment) > 16384:
        raise PermissionError('TOKEN_INVALID')
    try:
        raw = base64.b64decode(segment + '=' * (-len(segment) % 4), altchars=b'-_', validate=True)
        def unique(pairs):
            obj={}
            for k,v in pairs:
                if k in obj: raise ValueError('duplicate')
                obj[k]=v
            return obj
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError, json.JSONDecodeError):
        raise PermissionError('TOKEN_INVALID') from None


def _integer_b64(s):
    if not isinstance(s,str) or len(s)>2048 or not s: raise PermissionError('JWK_INVALID')
    try: return int.from_bytes(base64.b64decode(s+'='*(-len(s)%4),altchars=b'-_',validate=True),'big')
    except ValueError: raise PermissionError('JWK_INVALID') from None


class OIDCVerifier:
    def __init__(self, *, issuer, audience, jwks, role_claim='roles', allowed_roles=None, clock=None):
        if not isinstance(issuer,str) or not issuer.startswith('https://') or not issuer.rstrip('/') == issuer:
            raise ValueError('ISSUER_INVALID')
        if not isinstance(audience,str) or not audience: raise ValueError('AUDIENCE_INVALID')
        if not isinstance(jwks,dict) or not isinstance(jwks.get('keys'),list): raise ValueError('JWKS_INVALID')
        if not isinstance(role_claim,str) or not role_claim: raise ValueError('ROLE_CLAIM_INVALID')
        self.issuer=issuer; self.audience=audience; self.role_claim=role_claim
        self.allowed_roles=frozenset(allowed_roles or ('viewer','operator','auditor','admin'))
        self.clock=clock or time.time
        self.keys={}
        for k in jwks['keys']:
            if not isinstance(k,dict) or k.get('kty')!='RSA' or k.get('alg','RS256')!='RS256' or k.get('use','sig')!='sig':
                raise ValueError('JWK_UNSUPPORTED')
            kid=k.get('kid')
            if not isinstance(kid,str) or not kid or kid in self.keys: raise ValueError('JWK_KID_INVALID')
            n=_integer_b64(k.get('n')); e=_integer_b64(k.get('e'))
            if n.bit_length()<2048 or e<3 or e%2==0: raise ValueError('JWK_WEAK_KEY')
            self.keys[kid]=rsa.RSAPublicNumbers(e,n).public_key()
        if not self.keys: raise ValueError('JWKS_EMPTY')

    def verify(self, token):
        if not isinstance(token,str) or len(token)>16384: raise PermissionError('TOKEN_INVALID')
        parts=token.split('.')
        if len(parts)!=3: raise PermissionError('TOKEN_INVALID')
        header=_decode(parts[0]); payload=_decode(parts[1])
        if not isinstance(header,dict) or not isinstance(payload,dict): raise PermissionError('TOKEN_INVALID')
        if header.get('alg')!='RS256' or header.get('typ','JWT')!='JWT' or 'crit' in header or any(x in header for x in ('jku','jwk','x5u','x5c')):
            raise PermissionError('ALGORITHM_REJECTED')
        key=self.keys.get(header.get('kid')) if isinstance(header.get('kid'),str) else None
        if key is None: raise PermissionError('KEY_NOT_TRUSTED')
        try:
            signature=base64.b64decode(parts[2]+'='*(-len(parts[2])%4),altchars=b'-_',validate=True)
            key.verify(signature, (parts[0]+'.'+parts[1]).encode('ascii'),padding.PKCS1v15(),hashes.SHA256())
        except (InvalidSignature,ValueError,UnicodeError): raise PermissionError('SIGNATURE_INVALID') from None
        now=self.clock()
        if payload.get('iss')!=self.issuer: raise PermissionError('ISSUER_REJECTED')
        aud=payload.get('aud')
        if not (aud==self.audience or isinstance(aud,list) and self.audience in aud):
            raise PermissionError('AUDIENCE_REJECTED')
        if isinstance(aud,list) and len(aud)>1 and payload.get('azp')!=self.audience:
            raise PermissionError('AUTHORIZED_PARTY_REJECTED')
        if not isinstance(payload.get('exp'),int) or isinstance(payload['exp'],bool) or payload['exp']<=now or payload['exp']>now+3600:
            raise PermissionError('TOKEN_EXPIRED')
        for field in ('nbf','iat'):
            if field in payload and (not isinstance(payload[field],int) or isinstance(payload[field],bool) or payload[field]>now+30):
                raise PermissionError('TOKEN_NOT_YET_VALID')
        sub=payload.get('sub'); roles=payload.get(self.role_claim)
        if not isinstance(sub,str) or not sub.strip() or len(sub)>256: raise PermissionError('SUBJECT_INVALID')
        if not isinstance(roles,list) or not roles or any(not isinstance(r,str) for r in roles):
            raise PermissionError('ROLES_INVALID')
        role_set=frozenset(roles)
        if not role_set<=self.allowed_roles: raise PermissionError('ROLES_INVALID')
        return Principal(sub,role_set,True)

    def resolve_request(self, request):
        auth=request.headers.get('authorization','')
        if not isinstance(auth,str) or not auth.startswith('Bearer ') or auth.count(' ')!=1:
            raise PermissionError('BEARER_REQUIRED')
        return self.verify(auth[7:])
