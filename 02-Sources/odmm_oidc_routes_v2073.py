"""Fail-closed OIDC routes with sanitized provider outage responses.
Auteur: Abdelhalim Talbi.
"""
import secrets
import httpx
from urllib.parse import urlsplit
from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse, JSONResponse
from odmm_oidc_pkce_v2068 import OIDCVerificationError
from odmm_oidc_bridge_v2067 import verified_claims_to_session
from odmm_session_lifecycle_v2064 import set_session_cookies

NETWORK_ERRORS=(httpx.TimeoutException,httpx.TransportError,ConnectionError,TimeoutError,OSError)

def attach_oidc_routes(app, *, transport, transactions, sessions, csrf_secret, redirect_uri, role_mapping=None):
    if not isinstance(csrf_secret,bytes) or len(csrf_secret)<32 or not isinstance(redirect_uri,str):
        raise ValueError('INVALID_OIDC_ROUTE_CONFIGURATION')
    target=urlsplit(redirect_uri)
    if target.scheme!='https' or not target.hostname or target.query or target.fragment or target.username or target.password or target.path!='/auth/oidc/callback':
        raise ValueError('INVALID_CALLBACK_URL')
    if any(getattr(r,'path',None) in ('/auth/oidc/login','/auth/oidc/callback') for r in app.routes):
        raise ValueError('OIDC_ROUTE_CONFLICT')
    def no_store(response):
        response.headers['Cache-Control']='no-store'
        response.headers['Referrer-Policy']='no-referrer'
        return response
    @app.get('/auth/oidc/login')
    def login(request:Request):
        if request.url.scheme!='https':raise HTTPException(403,'HTTPS_REQUIRED')
        binding=secrets.token_urlsafe(48)
        try:
            discovery=transport.discovery()
            transaction=transactions.begin(authorize_endpoint=discovery['authorization_endpoint'],client_id=transport.client_id,redirect_uri=redirect_uri,browser_binding=binding)
        except (OIDCVerificationError,ValueError,KeyError,TypeError,*NETWORK_ERRORS):
            raise HTTPException(503,'OIDC_LOGIN_UNAVAILABLE',headers={'Cache-Control':'no-store','Retry-After':'30'})
        response=no_store(RedirectResponse(transaction['url'],status_code=303))
        response.set_cookie('odmm_oidc_binding',binding,secure=True,httponly=True,samesite='lax',path='/auth/oidc',max_age=transactions.ttl)
        return response
    @app.get('/auth/oidc/callback')
    def callback(request:Request, state:str='', code:str='', error:str=''):
        if request.url.scheme!='https':raise HTTPException(403,'HTTPS_REQUIRED')
        binding=request.cookies.get('odmm_oidc_binding','')
        if error or not state or not code or not binding:raise HTTPException(401,'OIDC_CALLBACK_REJECTED')
        # Consume before remote exchange. A timeout cannot make this authorization code reusable.
        try:
            transaction=transactions.consume(state=state,code=code,browser_binding=binding)
        except (OIDCVerificationError,ValueError,KeyError,TypeError):
            raise HTTPException(401,'OIDC_CALLBACK_REJECTED')
        try:
            claims=transport.complete(transaction=transaction,code=code)
            token=verified_claims_to_session(sessions,claims,issuer=transport.issuer,audience=transport.client_id,nonce=transaction['nonce'],role_mapping=role_mapping)
        except NETWORK_ERRORS:
            raise HTTPException(503,'OIDC_PROVIDER_UNAVAILABLE',headers={'Cache-Control':'no-store','Retry-After':'30'})
        except (OIDCVerificationError,ValueError,KeyError,TypeError):
            raise HTTPException(401,'OIDC_CALLBACK_REJECTED')
        response=no_store(JSONResponse({'status':'AUTHENTICATED'}))
        response.delete_cookie('odmm_oidc_binding',secure=True,httponly=True,samesite='lax',path='/auth/oidc')
        return set_session_cookies(response,token,csrf_secret)
    return app
