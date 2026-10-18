"""HTTPS session rotation/logout endpoints; external authenticated login remains prerequisite.
Auteur: Abdelhalim Talbi.
"""
from urllib.parse import urlsplit
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from odmm_session_lifecycle_v2064 import rotate_session, set_session_cookies, clear_session_cookies
from odmm_session_registry_v2062 import SessionRegistry
from odmm_secure_integration_v2059 import csrf_for_session
import hmac

PATHS=('/api/v1/session/rotate','/api/v1/session/logout')

def _origin(value):
    try:
        p=urlsplit(value)
        return bool(p.scheme=='https' and p.hostname and p.netloc and not p.username and not p.password and p.path=='' and p.query=='' and p.fragment=='')
    except ValueError:
        return False

def attach_session_routes(app, *, registry, csrf_secret, expected_origin, ttl=900):
    if not isinstance(registry,SessionRegistry) or not isinstance(csrf_secret,bytes) or len(csrf_secret)<32 or not _origin(expected_origin) or not 1<=ttl<=86400:
        raise ValueError('INVALID_SESSION_ROUTE_CONFIGURATION')
    if set(PATHS)&{getattr(r,'path',None) for r in app.routes}:
        raise ValueError('SESSION_ROUTE_CONFLICT')
    def verify(request:Request):
        if not _origin(request.headers.get('origin','')) or request.headers.get('origin')!=expected_origin:
            raise HTTPException(403,'ORIGIN_DENIED')
        token=request.cookies.get('odmm_session','')
        if registry.resolve(token) is None:
            raise HTTPException(401,'SESSION_INVALID')
        expected=csrf_for_session(token,csrf_secret)
        cookie=request.cookies.get('odmm_csrf','')
        header=request.headers.get('x-odmm-csrf','')
        if not cookie or not header or not hmac.compare_digest(cookie,expected) or not hmac.compare_digest(header,expected):
            raise HTTPException(403,'CSRF_DENIED')
        return token
    @app.post(PATHS[0])
    def rotate(request:Request):
        token=verify(request)
        replacement=rotate_session(registry,token,ttl=ttl)
        if replacement is None: raise HTTPException(401,'SESSION_INVALID')
        response=JSONResponse({'status':'ROTATED'})
        return set_session_cookies(response,replacement,csrf_secret,max_age=ttl)
    @app.post(PATHS[1])
    def logout(request:Request):
        token=verify(request)
        if not registry.revoke(token): raise HTTPException(401,'SESSION_INVALID')
        return clear_session_cookies(JSONResponse({'status':'LOGGED_OUT'}))
    return app
