"""Atomic rotation and hardened cookie issuance for ODMM. Auteur: Abdelhalim Talbi.

OIDC authentication is an external prerequisite; this module does not implement OIDC.
"""
import secrets
import time
from odmm_session_registry_v2062 import SessionRegistry
from odmm_secure_integration_v2059 import csrf_for_session

SESSION_COOKIE='odmm_session'
CSRF_COOKIE='odmm_csrf'


def rotate_session(registry, old_token, *, ttl=900):
    """One-use rotation: concurrent attempts cannot both succeed."""
    if not isinstance(registry, SessionRegistry) or not 1 <= ttl <= 86400:
        raise ValueError('INVALID_ROTATION_CONFIGURATION')
    digest=registry._digest(old_token)
    if digest is None: return None
    new_token=secrets.token_urlsafe(48)
    new_digest=registry._digest(new_token)
    now=registry.clock()
    with registry._db() as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT actor,role,expires,revoked FROM sessions WHERE digest=?',(digest,)).fetchone()
        if row is None or row[3] or row[2]<=now:
            return None
        updated=db.execute('UPDATE sessions SET revoked=1 WHERE digest=? AND revoked=0 AND expires>?',(digest,now))
        if updated.rowcount!=1: return None
        db.execute('INSERT INTO sessions(digest,actor,role,expires) VALUES(?,?,?,?)',
                   (new_digest,row[0],row[1],min(now+ttl,row[2])))
    return new_token


def set_session_cookies(response, token, csrf_secret, *, max_age=900):
    """Only call after trusted HTTPS login or rotation; no untrusted identity input."""
    if not isinstance(token,str) or len(token)<32 or not isinstance(max_age,int) or not 1<=max_age<=86400:
        raise ValueError('INVALID_COOKIE_CONFIGURATION')
    csrf=csrf_for_session(token,csrf_secret)
    response.set_cookie(SESSION_COOKIE,token,max_age=max_age,secure=True,httponly=True,samesite='strict',path='/')
    response.set_cookie(CSRF_COOKIE,csrf,max_age=max_age,secure=True,httponly=False,samesite='strict',path='/')
    response.headers['Cache-Control']='no-store'
    return response


def clear_session_cookies(response):
    response.delete_cookie(SESSION_COOKIE,secure=True,httponly=True,samesite='strict',path='/')
    response.delete_cookie(CSRF_COOKIE,secure=True,httponly=False,samesite='strict',path='/')
    response.headers['Cache-Control']='no-store'
    return response
