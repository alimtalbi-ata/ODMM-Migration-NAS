"""V197.5: single-process OIDC Authorization Code + PKCE browser session adapter.

Requires TLS reverse proxy, pinned OIDC endpoints and a trusted token exchanger.
No refresh tokens stored. Sessions are ephemeral and not cluster-safe.
"""
import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode
from odmm_oidc_verifier import OIDCVerifier, _decode
from odmm_scoped_app import create_scoped_app


def _b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')

@dataclass(frozen=True)
class BrowserOIDCConfig:
    authorization_endpoint: str
    token_endpoint: str
    client_id: str
    redirect_uri: str
    public_origin: str
    state_ttl: int = 300
    session_ttl: int = 900

    def validate(self):
        from urllib.parse import urlsplit
        for url in (self.authorization_endpoint,self.token_endpoint,self.redirect_uri,self.public_origin):
            parsed=urlsplit(url)
            if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
                raise ValueError('HTTPS_URL_REQUIRED')
        if self.redirect_uri!=self.public_origin.rstrip('/')+'/auth/callback':
            raise ValueError('REDIRECT_MISMATCH')
        if not self.client_id or not self.client_id.strip() or not 60<=self.state_ttl<=600 or not 60<=self.session_ttl<=3600:
            raise ValueError('OIDC_CONFIG_INVALID')


def create_browser_app(*, registry_path, grants_path, verifier:OIDCVerifier, config:BrowserOIDCConfig, exchange_code=None, clock=None, session_store=None):
    """Exchange callback signature (code, verifier, redirect_uri)-> token response.

    When omitted, performs an HTTPS backchannel request via httpx.
    """
    config.validate()
    if not isinstance(verifier,OIDCVerifier): raise ValueError('VERIFIER_REQUIRED')
    now=clock or time.time
    pending={}; sessions={}; csrf_bindings={}
    def sid_key(sid): return hashlib.sha256(sid.encode("utf-8")).hexdigest()
    if exchange_code is None:
        def exchange_code(code, pkce, redirect):
            import httpx
            with httpx.Client(timeout=8,follow_redirects=False,trust_env=False) as client:
                response=client.post(config.token_endpoint,data={'grant_type':'authorization_code','code':code,'code_verifier':pkce,'redirect_uri':redirect,'client_id':config.client_id})
                response.raise_for_status()
                return response.json()

    from fastapi import HTTPException, Request
    from fastapi.responses import RedirectResponse
    def resolve(request):
        sid=request.cookies.get('__Host-odmm_session','')
        if session_store is not None:
            principal=session_store.get_session(sid_key(sid)) if sid else None
            if principal is None: raise PermissionError('SESSION_REQUIRED')
            return principal
        session=sessions.get(sid)
        if not session or session[1]<=now():
            sessions.pop(sid,None)
            raise PermissionError('SESSION_REQUIRED')
        return session[0]
    app=create_scoped_app(registry_path=registry_path,grants_path=grants_path,resolve_verified_principal=resolve)
    app.docs_url=None
    # Remove interactive API documentation routes, which are not part of the user portal.
    app.router.routes[:]=[r for r in app.routes if r.path not in ('/docs','/redoc','/docs/oauth2-redirect','/openapi.json')]

    # V198.2: enforce origin and double-submit CSRF for all browser cookie writes.
    # The CSRF cookie is host-only, secure and readable by same-origin JS.
    from odmm_oidc_security_policy import require_csrf
    from fastapi.responses import JSONResponse
    @app.middleware('http')
    async def browser_csrf_boundary(request, call_next):
        if request.method.upper() not in ('GET', 'HEAD', 'OPTIONS'):
            if request.cookies.get('__Host-odmm_session'):
                try:
                    require_csrf(method=request.method,
                        origin=request.headers.get('origin'),
                        expected_origin=config.public_origin,
                        cookie_token=request.cookies.get('__Host-odmm_csrf'),
                        submitted_token=request.headers.get('x-odmm-csrf'))
                    sid=request.cookies.get('__Host-odmm_session','')
                    token=request.headers.get('x-odmm-csrf','')
                    bound=(session_store.verify_csrf(sid_key(sid),token) if session_store is not None else
                           secrets.compare_digest(csrf_bindings.get(sid,''),token))
                    if not bound: raise PermissionError('CSRF_SESSION_BINDING_REJECTED')
                except PermissionError:
                    return JSONResponse({'detail':'CSRF_REJECTED'},status_code=403,
                        headers={'Cache-Control':'no-store'})
        return await call_next(request)

    @app.get('/auth/login',include_in_schema=False)
    def login():
        state=secrets.token_urlsafe(32); nonce=secrets.token_urlsafe(32)
        pkce=secrets.token_urlsafe(64)
        challenge=_b64(hashlib.sha256(pkce.encode('ascii')).digest())
        if session_store is not None: session_store.put_pending(state,nonce,pkce,now()+config.state_ttl)
        else: pending[state]=(nonce,pkce,now()+config.state_ttl)
        query=urlencode({'response_type':'code','client_id':config.client_id,'redirect_uri':config.redirect_uri,'scope':'openid','state':state,'nonce':nonce,'code_challenge':challenge,'code_challenge_method':'S256'})
        return RedirectResponse(config.authorization_endpoint+'?'+query,status_code=303,headers={'Cache-Control':'no-store'})

    @app.get('/auth/callback',include_in_schema=False)
    def callback(code:str='',state:str='',error:str=''):
        transaction=session_store.consume_pending(state) if session_store is not None else pending.pop(state,None)
        if error or not transaction or not code or len(code)>4096 or transaction[2]<=now():
            raise HTTPException(403,'LOGIN_REJECTED')
        nonce,pkce,_=transaction
        try:
            tokens=exchange_code(code,pkce,config.redirect_uri)
            if not isinstance(tokens,dict): raise ValueError('TOKEN_RESPONSE_INVALID')
            id_token=tokens['id_token']; access_token=tokens['access_token']
            identity=verifier.verify(id_token)
            access=verifier.verify(access_token)
            payload=_decode(id_token.split('.')[1])
            if payload.get('nonce')!=nonce or identity.subject!=access.subject:
                raise PermissionError('OIDC_BINDING_INVALID')
            # Bound session duration to both signed token expiries.
            access_exp=_decode(access_token.split('.')[1])['exp']
            identity_exp=payload['exp']
            expiry=min(now()+config.session_ttl,access_exp,identity_exp)
            if expiry<=now(): raise PermissionError('TOKEN_EXPIRED')
        except (ValueError,KeyError,TypeError,PermissionError,IndexError):
            raise HTTPException(403,'LOGIN_REJECTED') from None
        sid=secrets.token_urlsafe(48)
        if session_store is not None: session_store.put_session(sid_key(sid),access,expiry)
        else: sessions[sid]=(access,expiry)
        response=RedirectResponse('/operations',status_code=303,headers={'Cache-Control':'no-store'})
        response.set_cookie('__Host-odmm_session',sid,secure=True,httponly=True,samesite='lax',path='/',max_age=max(1,int(expiry-now())))
        csrf_token=secrets.token_urlsafe(32)
        if session_store is not None: session_store.bind_csrf(sid_key(sid),csrf_token)
        else: csrf_bindings[sid]=csrf_token
        response.set_cookie('__Host-odmm_csrf',csrf_token,secure=True,httponly=False,samesite='lax',path='/',max_age=max(1,int(expiry-now())))
        return response

    @app.post('/auth/logout',include_in_schema=False)
    def logout(request:Request):
        if request.headers.get('origin')!=config.public_origin:
            raise HTTPException(403,'ORIGIN_REJECTED')
        sid=request.cookies.get('__Host-odmm_session','')
        if session_store is not None:
            if sid: session_store.delete_session(sid_key(sid))
        else:
            sessions.pop(sid,None)
            csrf_bindings.pop(sid,None)
        response=RedirectResponse('/auth/login',status_code=303,headers={'Cache-Control':'no-store'})
        response.delete_cookie('__Host-odmm_session',path='/',secure=True,httponly=True,samesite='lax')
        response.delete_cookie('__Host-odmm_csrf',path='/',secure=True,samesite='lax')
        return response
    return app
