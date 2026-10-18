"""Pinned OIDC discovery, HTTPS code exchange, and bounded JWKS cache.
Auteur: Abdelhalim Talbi. A caller must supply a TLS-verifying HTTP client.
"""
import json,time,threading
from urllib.parse import urlsplit
from odmm_oidc_pkce_v2068 import OIDCVerificationError, _https_url, verify_id_token

class TrustedOIDCTransport:
    def __init__(self, *, issuer, client_id, http_get, http_post, clock=None, cache_seconds=300):
        _https_url(issuer)
        if issuer.endswith('/') or not client_id or not callable(http_get) or not callable(http_post) or not 30<=cache_seconds<=3600:
            raise OIDCVerificationError('INVALID_CONFIGURATION')
        self.issuer=issuer;self.client_id=client_id;self.get=http_get;self.post=http_post
        self.clock=clock or time.time;self.ttl=cache_seconds;self._cache={};self._lock=threading.RLock()
    def _same_origin(self,url):
        _https_url(url)
        base=urlsplit(self.issuer);target=urlsplit(url)
        if (base.hostname,base.port or 443)!=(target.hostname,target.port or 443):
            raise OIDCVerificationError('UNTRUSTED_ENDPOINT')
        return url
    def _read(self,url,limit=65536):
        self._same_origin(url)
        data=self.get(url)
        if not isinstance(data,bytes) or len(data)>limit:raise OIDCVerificationError('INVALID_RESPONSE')
        try:
            obj=json.loads(data)
        except (ValueError,UnicodeError):raise OIDCVerificationError('INVALID_RESPONSE')
        if not isinstance(obj,dict):raise OIDCVerificationError('INVALID_RESPONSE')
        return obj
    def discovery(self):
        with self._lock:
            cached=self._cache.get('discovery')
            if cached and cached[0]>self.clock():return cached[1]
            # For issuers with a path, OIDC discovery appends to the issuer.
            data=self._read(self.issuer+'/.well-known/openid-configuration')
            if data.get('issuer')!=self.issuer:raise OIDCVerificationError('ISSUER_MISMATCH')
            for name in ('authorization_endpoint','token_endpoint','jwks_uri'):
                self._same_origin(data.get(name))
            self._cache['discovery']=(self.clock()+self.ttl,data)
            return data
    def jwks(self,*,refresh=False):
        with self._lock:
            cached=self._cache.get('jwks')
            if cached and cached[0]>self.clock() and not refresh:return cached[1]
            keys=self._read(self.discovery()['jwks_uri'],limit=131072)
            if not isinstance(keys.get('keys'),list) or len(keys['keys'])>64:raise OIDCVerificationError('INVALID_JWKS')
            self._cache['jwks']=(self.clock()+self.ttl,keys)
            return keys
    def exchange(self, *, code, verifier, redirect_uri):
        if not all(isinstance(x,str) and 1<=len(x)<=4096 for x in (code,verifier,redirect_uri)):
            raise OIDCVerificationError('INVALID_CALLBACK')
        _https_url(redirect_uri)
        body={'grant_type':'authorization_code','code':code,'code_verifier':verifier,'redirect_uri':redirect_uri,'client_id':self.client_id}
        url=self.discovery()['token_endpoint']
        self._same_origin(url)
        data=self.post(url,body)
        if not isinstance(data,bytes) or len(data)>65536:raise OIDCVerificationError('INVALID_TOKEN_RESPONSE')
        try:result=json.loads(data)
        except (ValueError,UnicodeError):raise OIDCVerificationError('INVALID_TOKEN_RESPONSE')
        if not isinstance(result,dict) or not isinstance(result.get('id_token'),str):raise OIDCVerificationError('INVALID_TOKEN_RESPONSE')
        return result['id_token']
    def complete(self,*,transaction,code):
        # transaction must be consumed once by PKCETransactions.consume before this call.
        token=self.exchange(code=code,verifier=transaction['code_verifier'],redirect_uri=transaction['redirect_uri'])
        keys=self.jwks()
        try:return verify_id_token(token,jwks=keys,issuer=self.issuer,audience=self.client_id,nonce=transaction['nonce'],clock=self.clock)
        except OIDCVerificationError as exc:
            if str(exc)!='UNKNOWN_OR_AMBIGUOUS_KEY':raise
            return verify_id_token(token,jwks=self.jwks(refresh=True),issuer=self.issuer,audience=self.client_id,nonce=transaction['nonce'],clock=self.clock)
