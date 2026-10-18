"""ODMM V210.8: bounded, fail-closed JWKS HTTPS cache. Author: Abdelhalim Talbi."""
import json
import ssl
import time
import urllib.request
from urllib.parse import urlsplit

class JWKSUnavailable(RuntimeError):
    pass

class CachedJWKSProvider:
    """Pinned HTTPS JWKS URL; no stale-key fallback when IdP is unavailable."""
    def __init__(self, url, *, ttl_seconds=300, timeout=3, max_bytes=65536,
                 clock=None, opener=None):
        parts=urlsplit(url) if isinstance(url,str) else None
        if (not parts or parts.scheme!='https' or not parts.hostname or parts.username or
            parts.password or parts.fragment or parts.port not in (None,443) or
            not 1 <= len(url) <= 2048):
            raise ValueError('INVALID_JWKS_URL')
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 3600:
            raise ValueError('INVALID_JWKS_TTL')
        if not isinstance(timeout,(int,float)) or isinstance(timeout,bool) or not 0 < timeout <= 30:
            raise ValueError('INVALID_JWKS_TIMEOUT')
        if type(max_bytes) is not int or not 1024 <= max_bytes <= 1048576:
            raise ValueError('INVALID_JWKS_SIZE')
        self.url=url; self.ttl=ttl_seconds; self.timeout=timeout; self.max_bytes=max_bytes
        self.clock=clock or time.monotonic
        self.opener=opener or urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        self._value=None; self._expires=0

    def __call__(self, *, force_refresh=False):
        now=self.clock()
        if not force_refresh and self._value is not None and now < self._expires:
            return self._value
        # Expired keys are discarded even if fetching fails.
        self._value=None; self._expires=0
        try:
            request=urllib.request.Request(self.url,headers={'Accept':'application/json','Cache-Control':'no-cache'})
            with self.opener.open(request,timeout=self.timeout) as response:
                # Reject redirect destinations, including redirects to insecure/private endpoints.
                if response.geturl()!=self.url or getattr(response,'status',200)!=200:
                    raise ValueError('UNEXPECTED_JWKS_RESPONSE')
                body=response.read(self.max_bytes+1)
            if len(body)>self.max_bytes: raise ValueError('OVERSIZED_JWKS')
            obj=json.loads(body)
            if not isinstance(obj,dict) or not isinstance(obj.get('keys'),list) or not 1 <= len(obj['keys']) <= 64:
                raise ValueError('INVALID_JWKS')
            seen=set()
            for key in obj['keys']:
                if not isinstance(key,dict) or key.get('kty')!='RSA' or not isinstance(key.get('kid'),str) or not key['kid'] or len(key['kid'])>128 or key['kid'] in seen or key.get('alg','RS256')!='RS256' or key.get('use','sig')!='sig' or not isinstance(key.get('n'),str) or not isinstance(key.get('e'),str):
                    raise ValueError('INVALID_JWKS_KEY')
                seen.add(key['kid'])
            self._value=obj; self._expires=self.clock()+self.ttl
            return obj
        except Exception:
            raise JWKSUnavailable('JWKS_UNAVAILABLE') from None


def create_cached_oidc_vault_operations_app(*, issuer, audience, jwks_url, ha_client, **kwargs):
    from odmm_oidc_boundary_v2107 import create_oidc_vault_operations_app
    provider=CachedJWKSProvider(jwks_url)
    return create_oidc_vault_operations_app(issuer=issuer,audience=audience,jwks_provider=provider,ha_client=ha_client,**kwargs)
