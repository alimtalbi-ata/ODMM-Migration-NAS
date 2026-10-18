"""Transactional campaign qualification history; read-only Operations view.
Author: Abdelhalim Talbi.
"""
import hashlib
import hmac
import json
import re
import sqlite3
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from odmm_campaign_v2095 import verify_campaign

_ID = re.compile(r'^[A-Za-z0-9_.-]{1,128}$')

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()

class CampaignHistory:
    def __init__(self, path):
        self.path = str(path)
        if self.path != ':memory:':
            p=Path(self.path)
            p.parent.mkdir(parents=True, exist_ok=True)
            if not p.exists():
                import os
                try: fd=os.open(str(p), os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600); os.close(fd)
                except FileExistsError: pass
        with self._db() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS campaign_history (
                campaign_id TEXT NOT NULL, version INTEGER NOT NULL,
                digest TEXT NOT NULL, previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL, recorded_at TEXT NOT NULL,
                payload TEXT NOT NULL, PRIMARY KEY(campaign_id,version),
                UNIQUE(campaign_id,digest))''')

    def _db(self):
        db=sqlite3.connect(self.path, timeout=20, isolation_level=None)
        db.execute('PRAGMA busy_timeout=20000')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA journal_mode=WAL')
        return db

    def append(self, report, *, expected_version):
        if not isinstance(report,dict) or not verify_campaign(report) or not _ID.fullmatch(str(report.get('campaign_id',''))):
            raise ValueError('INVALID_CAMPAIGN_REPORT')
        if report.get('status')!='BLOCKED' or report.get('cutover_authorized') is not False:
            raise ValueError('UNSAFE_REPORT')
        if type(expected_version) is not int or expected_version<0:raise ValueError('INVALID_EXPECTED_VERSION')
        cid=report['campaign_id']; digest=report['sha256']; payload=canonical(report).decode()
        with self._db() as db:
            try:
                db.execute('BEGIN IMMEDIATE')
                row=db.execute('SELECT version,event_hash FROM campaign_history WHERE campaign_id=? ORDER BY version DESC LIMIT 1',(cid,)).fetchone()
                version=row[0] if row else 0
                if version!=expected_version:raise ValueError('VERSION_CONFLICT')
                if db.execute('SELECT 1 FROM campaign_history WHERE campaign_id=? AND digest=?',(cid,digest)).fetchone():raise ValueError('DUPLICATE_REPORT')
                previous=row[1] if row else '0'*64
                stamp=datetime.now(timezone.utc).isoformat()
                event_hash=hashlib.sha256(canonical({'campaign_id':cid,'version':version+1,'digest':digest,'previous_hash':previous,'recorded_at':stamp})).hexdigest()
                db.execute('INSERT INTO campaign_history VALUES (?,?,?,?,?,?,?)',(cid,version+1,digest,previous,event_hash,stamp,payload))
                db.execute('COMMIT')
            except BaseException:
                if db.in_transaction:db.execute('ROLLBACK')
                raise
        return {'campaign_id':cid,'version':version+1,'event_hash':event_hash,'status':'BLOCKED','cutover_authorized':False}

    def timeline(self, campaign_id):
        if not isinstance(campaign_id,str) or not _ID.fullmatch(campaign_id):raise ValueError('CAMPAIGN_INVALID')
        with self._db() as db:
            rows=db.execute('SELECT version,digest,previous_hash,event_hash,recorded_at,payload FROM campaign_history WHERE campaign_id=? ORDER BY version',(campaign_id,)).fetchall()
        events=[]; prev='0'*64
        for version,digest,previous,event_hash,stamp,payload in rows:
            report=json.loads(payload)
            expected=hashlib.sha256(canonical({'campaign_id':campaign_id,'version':version,'digest':digest,'previous_hash':previous,'recorded_at':stamp})).hexdigest()
            if version!=len(events)+1 or previous!=prev or not hmac.compare_digest(expected,event_hash) or not verify_campaign(report) or report.get('campaign_id')!=campaign_id or not hmac.compare_digest(digest,report['sha256']):
                raise ValueError('HISTORY_INTEGRITY_FAILURE')
            events.append({'version':version,'digest':digest,'event_hash':event_hash,'recorded_at':stamp,'report_count':report['report_count'],'blockers':report['blockers'],'status':'BLOCKED'})
            prev=event_hash
        return {'schema':'odmm.campaign.timeline.v2096','campaign_id':campaign_id,'events':events,'version':len(events),'head_hash':prev,'status':'BLOCKED','cutover_authorized':False,'limitations':['UNSIGNED_HASH_CHAIN','NO_EXTERNAL_ANCHOR','NO_CUTOVER_APPROVAL']}

def create_history_operations_app(*,history_path,registry_path,resolve_verified_principal,get_netapp_inventories,get_netapp_differences,get_lif_evidence,get_campaign_reports):
    from fastapi import Request,HTTPException
    from fastapi.responses import JSONResponse,HTMLResponse
    from odmm_campaign_v2095 import create_campaign_operations_app
    from odmm_operations_security import make_request_authorizer
    app=create_campaign_operations_app(registry_path=registry_path,resolve_verified_principal=resolve_verified_principal,get_netapp_inventories=get_netapp_inventories,get_netapp_differences=get_netapp_differences,get_lif_evidence=get_lif_evidence,get_campaign_reports=get_campaign_reports)
    history=CampaignHistory(history_path)
    authorize=make_request_authorizer(resolve_verified_principal)
    async def get(request:Request,campaign_id:str):
        try:
            if authorize(request) is not True:raise HTTPException(403,'FORBIDDEN')
        except HTTPException:raise
        except Exception:raise HTTPException(403,'FORBIDDEN')
        try:return history.timeline(campaign_id)
        except ValueError as exc:
            if str(exc)=='CAMPAIGN_INVALID':raise HTTPException(400,'CAMPAIGN_INVALID')
            raise HTTPException(503,'HISTORY_INTEGRITY_FAILURE')
        except Exception:raise HTTPException(503,'HISTORY_UNAVAILABLE')
    async def api(request:Request,campaign_id:str):
        return JSONResponse(await get(request,campaign_id),headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    async def page(request:Request,campaign_id:str):
        data=await get(request,campaign_id)
        items=''.join('<li>Version '+str(e['version'])+' — '+escape(e['recorded_at'])+' — '+str(e['report_count'])+' rapports — '+str(len(e['blockers']))+' blocages</li>' for e in data['events'])
        html='<html lang="fr"><meta charset="utf-8"><title>ODMM Historique</title><main><h1>Campagne '+escape(campaign_id)+'</h1><strong>BASCULE BLOQUÉE</strong><ol>'+items+'</ol><p>Chaîne non signée : ancrage externe requis.</p></main></html>'
        return HTMLResponse(html,headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none';frame-ancestors 'none';base-uri 'none'"})
    app.add_api_route('/api/v1/operations/netapp/campaigns/{campaign_id}/timeline',api,methods=['GET'])
    app.add_api_route('/operations/netapp/campaigns/{campaign_id}/timeline',page,methods=['GET'],include_in_schema=False)
    return app
