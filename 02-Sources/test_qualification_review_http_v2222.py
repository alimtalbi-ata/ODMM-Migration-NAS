"""HTTP retry semantics with a real ASGI app and synthetic review data."""
import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import httpx
import pytest
from fastapi import FastAPI
from qualification_review_http_v2222 import parse_request_id, append_http_review
from qualification_decisions_v2215 import review_status
from qualification_dossier_v2214 import canonical_bytes

KEY=b'z'*32

def dossier():
    p={'review':{'decision':'PENDING_HUMAN_REVIEW'},'cutover_authorized':False}
    return {'payload':p,'payload_sha256':hashlib.sha256(canonical_bytes(p)).hexdigest(),'digest_algorithm':'SHA-256','signature_verified':False}

def test_header_validation():
    for value in (None,'short','has space','x'*129):
        with pytest.raises(Exception):parse_request_id(SimpleNamespace(headers={} if value is None else {'Idempotency-Key':value}))
    assert parse_request_id(SimpleNamespace(headers={'Idempotency-Key':'req-12345678'}))=='req-12345678'

def test_http_retry_and_conflict(tmp_path):
    db=tmp_path/'reviews.sqlite'; d=dossier(); app=FastAPI()
    @app.post('/review')
    async def review(request: __import__('fastapi').Request):
        rid=parse_request_id(request)
        body=await request.json()
        try:
            return append_http_review(db,None,d,identity={'subject':'alice'},action=body['action'],reason='checked',secret=KEY,request_id=rid,strict=False)
        except ValueError as exc:
            from fastapi import HTTPException
            raise HTTPException(409,str(exc))
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as c:
            h={'Idempotency-Key':'request-12345678'}
            a=await c.post('/review',headers=h,json={'action':'APPROVE_REVIEW'})
            b=await c.post('/review',headers=h,json={'action':'APPROVE_REVIEW'})
            conflict=await c.post('/review',headers=h,json={'action':'REVOKE_REVIEW'})
            missing=await c.post('/review',json={'action':'APPROVE_REVIEW'})
            return a,b,conflict,missing
    a,b,c,m=asyncio.run(run())
    assert a.status_code==200 and b.status_code==200
    assert a.json()['mac']==b.json()['mac'] and b.json()['idempotent_replay']
    assert c.status_code==409 and m.status_code==400
    assert len(review_status(db,d,secret=KEY)['events'])==1
