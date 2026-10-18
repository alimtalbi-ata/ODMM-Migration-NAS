"""Offline OIDC RS256 JWT validation against operator-pinned JWKS.
No discovery, network calls, login, or implicit authorization. Fail closed.
"""
import base64
import json
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from ldaps_transition_reconciliation import TransitionReconciliationError

class OIDCIdentityVerifier:
    def __init__(self, *, issuer, audience, jwks, registry=None, clock_skew=0):
        if not isinstance(issuer,str) or not issuer.startswith('https://') or not isinstance(audience,str) or not audience or type(clock_skew)!=int or not 0<=clock_skew<=60:
            raise ValueError('INVALID_OIDC_CONFIGURATION')
        if not isinstance(jwks,dict) or not isinstance(jwks.get('keys'),list) or not jwks['keys']:
            raise ValueError('INVALID_JWKS')
        self.issuer=issuer;self.audience=audience;self.registry=registry;self.skew=clock_skew
        self.keys={}
        for item in jwks['keys']:
            if not isinstance(item,dict) or item.get('kty')!='RSA' or item.get('alg','RS256')!='RS256' or item.get('use','sig')!='sig':
                raise ValueError('UNSUPPORTED_JWK')
            kid=item.get('kid')
            if not isinstance(kid,str) or not kid or kid in self.keys:
                raise ValueError('INVALID_JWK_KID')
            try:
                n=int.from_bytes(self._decode(item['n']),'big');e=int.from_bytes(self._decode(item['e']),'big')
                if n.bit_length()<2048 or e<3 or e%2==0:raise ValueError()
                self.keys[kid]=rsa.RSAPublicNumbers(e,n).public_key()
            except (ValueError,KeyError,TypeError) as exc:raise ValueError('INVALID_JWK_RSA_KEY') from exc

    @staticmethod
    def _decode(s):
        if not isinstance(s,str) or not s or len(s)>8192 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in s):
            raise ValueError('INVALID_BASE64URL')
        return base64.urlsafe_b64decode(s+'='*(-len(s)%4))

    def verify(self, token, *, now=None):
        try:
            if not isinstance(token,str) or len(token)>16384:raise ValueError()
            parts=token.split('.')
            if len(parts)!=3:raise ValueError()
            head=json.loads(self._decode(parts[0]));claims=json.loads(self._decode(parts[1]));signature=self._decode(parts[2])
            if not isinstance(head,dict) or not isinstance(claims,dict) or head.get('alg')!='RS256' or head.get('typ','JWT')!='JWT' or not isinstance(head.get('kid'),str) or head['kid'] not in self.keys:
                raise ValueError()
            self.keys[head['kid']].verify(signature,(parts[0]+'.'+parts[1]).encode('ascii'),padding.PKCS1v15(),hashes.SHA256())
            at=int(time.time()) if now is None else now
            if type(at)!=int or at<0:raise ValueError()
            if claims.get('iss')!=self.issuer or self.audience not in (claims.get('aud') if isinstance(claims.get('aud'),list) else [claims.get('aud')]):raise ValueError()
            if any(type(claims.get(k))!=int for k in ('exp','iat')) or type(claims.get('nbf',0))!=int:raise ValueError()
            if not (at<claims['exp']+self.skew and at+self.skew>=claims['iat'] and at+self.skew>=claims.get('nbf',0)):raise ValueError()
            if any(not isinstance(claims.get(k),str) or not claims[k].strip() or len(claims[k])>128 for k in ('sub','jti')):raise ValueError()
            if self.registry is not None:self.registry.assert_active(issuer=claims['iss'],subject=claims['sub'],token_id=claims['jti'])
            return {'issuer':claims['iss'],'subject':claims['sub'],'token_id':claims['jti'],'verified':True,'roles_authorized':False,'cutover_authorized':False}
        except TransitionReconciliationError:raise
        except (ValueError,TypeError,KeyError,UnicodeError,InvalidSignature,OverflowError) as exc:
            raise TransitionReconciliationError('OIDC_TOKEN_REJECTED') from exc
