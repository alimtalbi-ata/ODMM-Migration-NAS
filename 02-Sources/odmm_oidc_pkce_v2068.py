"""OIDC Authorization Code PKCE and offline RS256/JWKS ID token verifier.
No remote discovery or token exchange: those require a configured trusted IdP.
Auteur: Abdelhalim Talbi.
"""
import base64, hashlib, json, secrets, time, hmac
from urllib.parse import urlencode, urlsplit
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

class OIDCVerificationError(ValueError): pass

def _b64(data):return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')
def _decode(s):
    if not isinstance(s,str) or not s or len(s)>16384:raise OIDCVerificationError('INVALID_ENCODING')
    try:return base64.b64decode(s+'='*((-len(s))%4),altchars=b'-_',validate=True)
    except (ValueError,base64.binascii.Error):raise OIDCVerificationError('INVALID_ENCODING')

def _https_url(url):
    if not isinstance(url,str):raise OIDCVerificationError('INVALID_URL')
    p=urlsplit(url)
    if p.scheme!='https' or not p.hostname or p.username or p.password or p.fragment or p.query:raise OIDCVerificationError('INVALID_URL')
    return url

class PKCETransactions:
    """In-memory one-time login transaction store. Use shared transactional store for multi-worker deployments."""
    def __init__(self,*,clock=None,ttl=300):
        if not 30<=ttl<=600:raise ValueError('INVALID_TTL')
        self.clock=clock or time.time;self.ttl=ttl;self._pending={}
        import threading
        self._lock=threading.Lock()
    def begin(self,*,authorize_endpoint,client_id,redirect_uri,scope='openid profile email'):
        _https_url(authorize_endpoint);_https_url(redirect_uri)
        if not isinstance(client_id,str) or not client_id or len(client_id)>256:raise OIDCVerificationError('INVALID_CLIENT')
        state=secrets.token_urlsafe(32);nonce=secrets.token_urlsafe(32);verifier=secrets.token_urlsafe(48)
        challenge=_b64(hashlib.sha256(verifier.encode('ascii')).digest())
        with self._lock:
            self._pending={k:v for k,v in self._pending.items() if v['expires']>self.clock()}
            self._pending[state]={'nonce':nonce,'verifier':verifier,'expires':self.clock()+self.ttl,'redirect_uri':redirect_uri}
        params={'response_type':'code','client_id':client_id,'redirect_uri':redirect_uri,'scope':scope,'state':state,'nonce':nonce,'code_challenge':challenge,'code_challenge_method':'S256'}
        return {'url':authorize_endpoint+'?'+urlencode(params),'state':state}
    def consume(self,*,state,code):
        if not isinstance(state,str) or not isinstance(code,str) or not code or len(code)>4096:raise OIDCVerificationError('INVALID_CALLBACK')
        with self._lock:txn=self._pending.pop(state,None)
        if txn is None or txn['expires']<=self.clock():raise OIDCVerificationError('STATE_UNKNOWN_OR_EXPIRED')
        return {'code':code,'code_verifier':txn['verifier'],'nonce':txn['nonce'],'redirect_uri':txn['redirect_uri']}

def verify_id_token(token,*,jwks,issuer,audience,nonce,clock=None,leeway=30):
    """Verify a compact signed RS256 ID token against caller-supplied trusted JWKS."""
    _https_url(issuer)
    if not isinstance(audience,str) or not audience or not isinstance(nonce,str) or len(nonce)<16:raise OIDCVerificationError('INVALID_CONFIGURATION')
    if not isinstance(token,str) or len(token)>32768 or token.count('.')!=2:raise OIDCVerificationError('INVALID_TOKEN')
    parts=token.split('.')
    try:
        header=json.loads(_decode(parts[0]));claims=json.loads(_decode(parts[1]));signature=_decode(parts[2])
    except (ValueError,TypeError):raise OIDCVerificationError('INVALID_TOKEN')
    if not isinstance(header,dict) or header.get('alg')!='RS256' or header.get('typ','JWT')!='JWT' or not isinstance(header.get('kid'),str) or not header['kid'] or 'crit' in header or not isinstance(claims,dict):raise OIDCVerificationError('INVALID_HEADER')
    if not isinstance(jwks,dict) or not isinstance(jwks.get('keys'),list):raise OIDCVerificationError('INVALID_JWKS')
    keys=[k for k in jwks['keys'] if isinstance(k,dict) and k.get('kid')==header['kid'] and k.get('kty')=='RSA' and k.get('use','sig')=='sig' and k.get('alg','RS256')=='RS256']
    if len(keys)!=1:raise OIDCVerificationError('UNKNOWN_OR_AMBIGUOUS_KEY')
    k=keys[0]
    try:
        n=int.from_bytes(_decode(k['n']),'big');e=int.from_bytes(_decode(k['e']),'big')
        if n.bit_length()<2048 or e<3 or e%2==0:raise ValueError('WEAK_KEY')
        public=rsa.RSAPublicNumbers(e,n).public_key()
        public.verify(signature,(parts[0]+'.'+parts[1]).encode('ascii'),padding.PKCS1v15(),hashes.SHA256())
    except (ValueError,KeyError,TypeError,InvalidSignature):raise OIDCVerificationError('SIGNATURE_INVALID')
    now=(clock or time.time)()
    if claims.get('iss')!=issuer or claims.get('nonce')!=nonce:raise OIDCVerificationError('CLAIMS_MISMATCH')
    aud=claims.get('aud');audiences=aud if isinstance(aud,list) else [aud]
    if audience not in audiences or any(not isinstance(x,str) for x in audiences):raise OIDCVerificationError('AUDIENCE_MISMATCH')
    if len(audiences)>1 and claims.get('azp')!=audience:raise OIDCVerificationError('AZP_MISMATCH')
    if not isinstance(claims.get('sub'),str) or not claims['sub'] or len(claims['sub'])>256:raise OIDCVerificationError('SUBJECT_INVALID')
    exp=claims.get('exp');iat=claims.get('iat')
    if type(exp) not in (int,float) or type(iat) not in (int,float) or exp<=now-leeway or iat>now+leeway or iat<now-86400 or exp<=iat:raise OIDCVerificationError('TOKEN_TIME_INVALID')
    if 'nbf' in claims and (type(claims['nbf']) not in (int,float) or claims['nbf']>now+leeway):raise OIDCVerificationError('NOT_YET_VALID')
    return claims

def verified_id_token_to_session(registry, token, *, jwks, issuer, audience, nonce, role_mapping=None, clock=None):
    """Only verified claims may be passed into the V206.7 session adapter."""
    from odmm_oidc_bridge_v2067 import verified_claims_to_session
    claims=verify_id_token(token,jwks=jwks,issuer=issuer,audience=audience,nonce=nonce,clock=clock)
    return verified_claims_to_session(registry,claims,issuer=issuer,audience=audience,nonce=nonce,role_mapping=role_mapping,clock=clock)
