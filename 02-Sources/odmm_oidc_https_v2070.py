"""Strict HTTPS transport for pinned OIDC provider endpoints. Auteur: Abdelhalim Talbi."""
import json
import ssl
import httpx
from urllib.parse import urlsplit
from odmm_oidc_pkce_v2068 import OIDCVerificationError, _https_url
from odmm_oidc_transport_v2069 import TrustedOIDCTransport

class StrictOIDCHTTP:
    """HTTPS-only, no redirects, verified certificates, bounded responses and timeouts.
    Configure a private CA with ca_file. Do not use untrusted forward proxies.
    """
    def __init__(self, *, issuer, ca_file=None, timeout=5.0, client=None):
        _https_url(issuer)
        if not isinstance(timeout,(float,int)) or not 0.5<=timeout<=30:raise ValueError('INVALID_TIMEOUT')
        self.issuer=issuer
        self._owned=client is None
        self.client=client or httpx.Client(verify=ssl.create_default_context(cafile=ca_file) if ca_file else True,follow_redirects=False,trust_env=False,timeout=timeout)
    def _url(self,url):
        _https_url(url)
        a,b=urlsplit(self.issuer),urlsplit(url)
        if (a.hostname,a.port or 443)!=(b.hostname,b.port or 443):raise OIDCVerificationError('UNTRUSTED_ENDPOINT')
        return url
    def _response(self,response,limit):
        if response.status_code!=200:raise OIDCVerificationError('OIDC_HTTP_STATUS')
        if len(response.content)>limit:raise OIDCVerificationError('OIDC_RESPONSE_TOO_LARGE')
        if 'application/json' not in response.headers.get('content-type','').lower():raise OIDCVerificationError('OIDC_CONTENT_TYPE')
        return response.content
    def get(self,url):
        self._url(url)
        with self.client.stream('GET',url,follow_redirects=False) as response:
            if response.status_code!=200:raise OIDCVerificationError('OIDC_HTTP_STATUS')
            if 'application/json' not in response.headers.get('content-type','').lower():raise OIDCVerificationError('OIDC_CONTENT_TYPE')
            data=b''
            for chunk in response.iter_bytes():
                data+=chunk
                if len(data)>131072:raise OIDCVerificationError('OIDC_RESPONSE_TOO_LARGE')
            return data
    def post(self,url,body):
        self._url(url)
        with self.client.stream('POST',url,data=body,headers={'Accept':'application/json'},follow_redirects=False) as response:
            if response.status_code!=200:raise OIDCVerificationError('OIDC_HTTP_STATUS')
            if 'application/json' not in response.headers.get('content-type','').lower():raise OIDCVerificationError('OIDC_CONTENT_TYPE')
            data=b''
            for chunk in response.iter_bytes():
                data+=chunk
                if len(data)>65536:raise OIDCVerificationError('OIDC_RESPONSE_TOO_LARGE')
            return data
    def close(self):
        if self._owned:self.client.close()

def make_trusted_oidc(*,issuer,client_id,ca_file=None,timeout=5.0,client=None,clock=None):
    http=StrictOIDCHTTP(issuer=issuer,ca_file=ca_file,timeout=timeout,client=client)
    return TrustedOIDCTransport(issuer=issuer,client_id=client_id,http_get=http.get,http_post=http.post,clock=clock),http
