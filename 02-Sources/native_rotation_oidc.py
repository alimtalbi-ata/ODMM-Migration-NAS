"""V195.2: offline RS256 JWT verification with deployment-pinned public keys.

The deployment owns JWKS retrieval, rotation, transport security and revocation.
Never accept a JWK or algorithm from an untrusted JWT as a trust anchor.
"""
import base64
import json
import re
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_B64 = re.compile(r'^[A-Za-z0-9_-]+$')


def _decode(part):
    if not isinstance(part, str) or len(part)>16384 or not _B64.fullmatch(part):
        raise ValueError('JWT_ENCODING_INVALID')
    data=base64.urlsafe_b64decode(part+'='*(-len(part)%4))
    return json.loads(data.decode('utf-8'))


def build_oidc_identity_provider(*, issuer, audience, pinned_public_keys, revoked_jti,
                                 clock=None, leeway_seconds=30, max_token_age=900):
    """Return identity_provider(request) for native_rotation_rbac.

    `pinned_public_keys`: mapping kid -> PEM RSA public key, from trusted config.
    `revoked_jti(jti)`: externally durable revocation check, must fail closed.
    """
    if not issuer or not audience or not isinstance(pinned_public_keys,dict) or not pinned_public_keys:
        raise ValueError('OIDC_TRUST_CONFIG_REQUIRED')
    if not callable(revoked_jti) or not (0<=leeway_seconds<=120) or not (1<=max_token_age<=86400):
        raise ValueError('OIDC_POLICY_INVALID')
    keys={}
    for kid,pem in pinned_public_keys.items():
        if not isinstance(kid,str) or not kid or len(kid)>128:
            raise ValueError('OIDC_KID_INVALID')
        key=serialization.load_pem_public_key(pem.encode() if isinstance(pem,str) else pem)
        if not isinstance(key,rsa.RSAPublicKey) or key.key_size<2048:
            raise ValueError('OIDC_KEY_INVALID')
        keys[kid]=key

    def identity_provider(request):
        try:
            auth=request.headers.get('authorization','')
            if not isinstance(auth,str) or not auth.startswith('Bearer ') or len(auth)>16384:
                return {'authenticated':False}
            token=auth[7:]
            parts=token.split('.')
            if len(parts)!=3:
                return {'authenticated':False}
            header=_decode(parts[0]); claims=_decode(parts[1])
            if not isinstance(header,dict) or set(header)-{'alg','typ','kid'} or header.get('alg')!='RS256':
                return {'authenticated':False}
            if header.get('typ','JWT')!='JWT' or header.get('kid') not in keys or not isinstance(claims,dict):
                return {'authenticated':False}
            signature=base64.urlsafe_b64decode(parts[2]+'='*(-len(parts[2])%4))
            keys[header['kid']].verify(signature,(parts[0]+'.'+parts[1]).encode('ascii'),padding.PKCS1v15(),hashes.SHA256())
            now=time.time() if clock is None else clock()
            iat=claims.get('iat'); nbf=claims.get('nbf'); exp=claims.get('exp')
            if any(isinstance(x,bool) or not isinstance(x,(int,float)) for x in (iat,nbf,exp)):
                return {'authenticated':False}
            if iat>now+leeway_seconds or nbf>now+leeway_seconds or exp<=now-leeway_seconds:
                return {'authenticated':False}
            if exp<=iat or now-iat>max_token_age+leeway_seconds or exp-iat>max_token_age:
                return {'authenticated':False}
            aud=claims.get('aud')
            if claims.get('iss')!=issuer or not (aud==audience or isinstance(aud,list) and audience in aud):
                return {'authenticated':False}
            sub=claims.get('sub'); jti=claims.get('jti'); roles=claims.get('roles')
            if not isinstance(sub,str) or not sub or not isinstance(jti,str) or not jti:
                return {'authenticated':False}
            if not isinstance(roles,list) or any(not isinstance(r,str) for r in roles):
                return {'authenticated':False}
            if revoked_jti(jti) is not False:
                return {'authenticated':False}
            return {'authenticated':True,'subject':sub,'roles':roles}
        except Exception:
            return {'authenticated':False}
    return identity_provider
