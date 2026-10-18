"""Vault HTTPS transport and AppRole authentication, ODMM V210.1.

Author: Abdelhalim Talbi. No automatic cutover or key rotation.
"""
import json
import re
import ssl
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

class VaultTransportError(RuntimeError):
    def __init__(self):
        super().__init__('VAULT_TRANSPORT_UNAVAILABLE')


def _endpoint(base_url):
    if not isinstance(base_url, str):
        raise ValueError('INVALID_VAULT_URL')
    parts = urlsplit(base_url)
    if (parts.scheme != 'https' or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment or parts.path not in ('', '/')
            or any(ch.isspace() for ch in base_url)):
        raise ValueError('INVALID_VAULT_URL')
    return base_url.rstrip('/')


class VaultHTTPSClient:
    """TLS-verified, bounded JSON requests. Never log tokens, payloads or exceptions."""
    def __init__(self, base_url, *, ca_file=None, timeout=5.0, max_response_bytes=65536, opener=None):
        self._url = _endpoint(base_url)
        if isinstance(timeout, bool) or not isinstance(timeout, (int,float)) or not 0 < timeout <= 30:
            raise ValueError('INVALID_TIMEOUT')
        if isinstance(max_response_bytes,bool) or not isinstance(max_response_bytes,int) or not 1024 <= max_response_bytes <= 1048576:
            raise ValueError('INVALID_RESPONSE_LIMIT')
        self._timeout = timeout
        self._limit = max_response_bytes
        self._context = ssl.create_default_context(cafile=ca_file)
        if self._context.verify_mode != ssl.CERT_REQUIRED or not self._context.check_hostname:
            raise ValueError('TLS_VERIFICATION_REQUIRED')
        self._opener = opener or urlopen

    def request(self, path, headers=None, *, payload=None):
        if not isinstance(path,str) or not path.startswith('/v1/') or not re.fullmatch(r'/v1/[A-Za-z0-9_./%-]+',path) or '..' in path:
            raise ValueError('INVALID_VAULT_PATH')
        if headers is None:
            headers = {}
        if not isinstance(headers,dict) or any(not isinstance(k,str) or not isinstance(v,str) for k,v in headers.items()):
            raise ValueError('INVALID_HEADERS')
        data = None
        if payload is not None:
            data = json.dumps(payload,allow_nan=False,separators=(',',':')).encode('utf-8')
            if len(data)>8192:
                raise ValueError('INVALID_REQUEST_SIZE')
        request = Request(self._url+path,data=data,headers={**headers,'Accept':'application/json',**({'Content-Type':'application/json'} if data is not None else {})},method='POST' if data is not None else 'GET')
        try:
            with self._opener(request,timeout=self._timeout,context=self._context) as response:
                if response.status != 200:
                    raise VaultTransportError()
                raw=response.read(self._limit+1)
            if len(raw)>self._limit:
                raise VaultTransportError()
            result=json.loads(raw.decode('utf-8'))
            if not isinstance(result,dict):
                raise VaultTransportError()
            return result
        except Exception:
            raise VaultTransportError() from None

    def __call__(self,path,headers):
        return self.request(path,headers)


class VaultAppRoleTokenProvider:
    """Obtain a short-lived Vault token from externally supplied AppRole credentials.

    This implementation intentionally does not cache tokens; credential retrieval and
    Vault token TTL/revocation remain the deployment operator's responsibility.
    """
    def __init__(self, client, *, role_id_provider, secret_id_provider):
        if not callable(role_id_provider) or not callable(secret_id_provider) or not hasattr(client,'request'):
            raise ValueError('INVALID_APPROLE_CONFIGURATION')
        self._client=client
        self._role=role_id_provider
        self._secret=secret_id_provider

    def __call__(self):
        try:
            role=self._role()
            secret=self._secret()
            if not isinstance(role,str) or not role.strip() or not isinstance(secret,str) or not secret.strip():
                raise VaultTransportError()
            result=self._client.request('/v1/auth/approle/login',payload={'role_id':role,'secret_id':secret})
            auth=result['auth']
            token=auth['client_token']
            if not isinstance(token,str) or not token.strip() or auth.get('renewable') not in (True,False):
                raise VaultTransportError()
            ttl=auth.get('lease_duration')
            if isinstance(ttl,bool) or not isinstance(ttl,int) or not 0 < ttl <= 86400:
                raise VaultTransportError()
            return token
        except Exception:
            raise VaultTransportError() from None


def create_vault_kv2_resolver(base_url, *, role_id_provider, secret_id_provider, mount='secret', prefix='odmm/hmac', ca_file=None, timeout=5.0, opener=None):
    """Wire V210.0 KV2 resolver to TLS-verified Vault AppRole transport."""
    from odmm_vault_v2100 import VaultKV2Resolver
    client=VaultHTTPSClient(base_url,ca_file=ca_file,timeout=timeout,opener=opener)
    token=VaultAppRoleTokenProvider(client,role_id_provider=role_id_provider,secret_id_provider=secret_id_provider)
    return VaultKV2Resolver(client=client,token_provider=token,mount=mount,prefix=prefix)
