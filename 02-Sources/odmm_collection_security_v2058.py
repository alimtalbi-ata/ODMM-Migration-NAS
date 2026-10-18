"""V205.8 security gate for NAS collection; author Abdelhalim Talbi.
Fail-closed authorization, same-origin CSRF, per-identity throttling, SQLite audit.
"""
import hashlib
import hmac
import json
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

class SecurityGate:
    def __init__(self, db_path, *, interval=60, max_requests=3, clock=None):
        self.db_path = str(db_path)
        self.interval = interval
        self.max_requests = max_requests
        self.clock = clock or time.time
        self.lock = threading.Lock()
        with sqlite3.connect(self.db_path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, at REAL NOT NULL, actor_hash TEXT NOT NULL, event TEXT NOT NULL, outcome TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS rate (actor_hash TEXT NOT NULL, at REAL NOT NULL)')
    def check(self, *, actor, role, origin, expected_origin, csrf_cookie, csrf_header):
        if not isinstance(actor,str) or not actor or role not in ('operator','admin'):
            return self._record(actor,'collect','DENY_RBAC')
        try:
            actual=urlsplit(origin); expected=urlsplit(expected_origin)
            origin_ok=(actual.scheme,actual.netloc)==(expected.scheme,expected.netloc) and actual.scheme=='https' and not actual.username and not actual.password
        except (TypeError,ValueError): origin_ok=False
        if not origin_ok or not isinstance(csrf_cookie,str) or len(csrf_cookie)<32 or len(csrf_cookie)>256 or not isinstance(csrf_header,str) or not hmac.compare_digest(csrf_cookie,csrf_header):
            return self._record(actor,'collect','DENY_CSRF')
        key=hashlib.sha256(actor.encode()).hexdigest()
        now=self.clock()
        with self.lock,sqlite3.connect(self.db_path,timeout=5) as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM rate WHERE at < ?', (now-self.interval,))
            count=db.execute('SELECT count(*) FROM rate WHERE actor_hash=?',(key,)).fetchone()[0]
            if count>=self.max_requests:
                outcome='DENY_RATE'
            else:
                db.execute('INSERT INTO rate VALUES (?,?)',(key,now));outcome='ALLOW'
            db.execute('INSERT INTO audit (at,actor_hash,event,outcome) VALUES (?,?,?,?)',(now,key,'collect',outcome))
        return outcome
    def _record(self,actor,event,outcome):
        key=hashlib.sha256(str(actor).encode()).hexdigest()
        with self.lock,sqlite3.connect(self.db_path) as db:
            db.execute('INSERT INTO audit (at,actor_hash,event,outcome) VALUES (?,?,?,?)',(self.clock(),key,event,outcome))
        return outcome

def attach_secure_collection_api(app, *, gate, identity_provider, expected_origin, token_provider, allow_hosts, collector=None):
    from fastapi import Request, HTTPException
    from fastapi.responses import JSONResponse
    from odmm_collection_service_v2056 import collect_inventory
    from odmm_vendor_api_readonly_v2055 import CollectionError
    if not isinstance(gate,SecurityGate) or not callable(identity_provider) or not callable(token_provider) or not expected_origin.startswith('https://'):
        raise ValueError('SECURITY_DEPENDENCIES_REQUIRED')
    collector=collector or collect_inventory
    async def route(request:Request):
        actor,role=identity_provider(request)
        result=gate.check(actor=actor,role=role,origin=request.headers.get('origin',''),expected_origin=expected_origin,csrf_cookie=request.cookies.get('odmm_csrf'),csrf_header=request.headers.get('x-odmm-csrf'))
        if result!='ALLOW':raise HTTPException(429 if result=='DENY_RATE' else 403,detail=result)
        if request.headers.get('content-type','').split(';')[0].strip().lower()!='application/json':raise HTTPException(415,'JSON_REQUIRED')
        body=await request.body()
        if len(body)>4096:raise HTTPException(413,'TOO_LARGE')
        try:
            data=json.loads(body)
            if not isinstance(data,dict) or set(data)!={'vendor','host'} or not all(isinstance(x,str) for x in data.values()):raise ValueError('INVALID_INPUT')
            report=collector(data['vendor'],data['host'],token_provider=token_provider,allow_hosts=allow_hosts)
        except (ValueError,CollectionError):raise HTTPException(422,'COLLECTION_REJECTED')
        return JSONResponse(report,headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    app.add_api_route('/api/v1/qualification/collect-secure',route,methods=['POST'])
    return route
