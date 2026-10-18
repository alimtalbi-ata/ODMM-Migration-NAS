"""ODMM V202.9 persistent campaign registry, resumable evidence tracking and audit.
Author: Abdelhalim Talbi. Only writes to a local SQLite registry; no NAS writes.
"""
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA = 'odmm.campaign.registry.v2029'
STATES = ('PENDING', 'PARTIAL', 'COMPLETE', 'MISMATCH', 'UNVERIFIED')

def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()).hexdigest()

def _id(value):
    if not isinstance(value, str) or not value or len(value)>256 or '\x00' in value:
        raise ValueError('INVALID_IDENTIFIER')
    return value

class Registry:
    def __init__(self, path):
        if not isinstance(path, (str, Path)) or str(path) in ('', ':memory:'):
            raise ValueError('PERSISTENT_LEDGER_REQUIRED')
        self.path = str(path)
        with self._db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS campaigns(id TEXT PRIMARY KEY, manifest TEXT NOT NULL, manifest_hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS observations(campaign TEXT NOT NULL, asset TEXT NOT NULL, side TEXT NOT NULL,
                    evidence_id TEXT NOT NULL UNIQUE, result TEXT NOT NULL, evidence_hash TEXT NOT NULL,
                    PRIMARY KEY(campaign, asset, side), FOREIGN KEY(campaign) REFERENCES campaigns(id));
            ''')

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA busy_timeout=10000')
            with db:
                yield db
        finally:
            db.close()

    def create(self, campaign_id, assets):
        _id(campaign_id)
        if not isinstance(assets, list) or not assets or len(assets)>100000:
            raise ValueError('INVALID_ASSETS')
        for a in assets: _id(a)
        if len(set(assets)) != len(assets): raise ValueError('DUPLICATE_ASSET')
        manifest = json.dumps(sorted(assets), ensure_ascii=False, separators=(',', ':'))
        manifest_hash = digest(sorted(assets))
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT manifest_hash FROM campaigns WHERE id=?', (campaign_id,)).fetchone()
            if row and row[0] != manifest_hash: raise ValueError('CAMPAIGN_MANIFEST_CONFLICT')
            if not row:
                db.execute('INSERT INTO campaigns VALUES (?,?,?)', (campaign_id,manifest,manifest_hash))
        return manifest_hash

    def record(self, campaign_id, asset, side, evidence_id, result, evidence_hash):
        _id(campaign_id); _id(asset); _id(evidence_id)
        if side not in ('source','target') or result not in ('MATCH','MISMATCH','UNVERIFIED'):
            raise ValueError('INVALID_OBSERVATION')
        if not isinstance(evidence_hash,str) or len(evidence_hash)!=64 or any(c not in '0123456789abcdef' for c in evidence_hash):
            raise ValueError('INVALID_EVIDENCE_HASH')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT manifest FROM campaigns WHERE id=?',(campaign_id,)).fetchone()
            if row is None or asset not in json.loads(row[0]): raise ValueError('UNKNOWN_CAMPAIGN_ASSET')
            existing=db.execute('SELECT evidence_id,result,evidence_hash FROM observations WHERE campaign=? AND asset=? AND side=?',(campaign_id,asset,side)).fetchone()
            if existing:
                if existing != (evidence_id,result,evidence_hash): raise ValueError('CONFLICTING_EVIDENCE')
                return False
            try:
                db.execute('INSERT INTO observations VALUES (?,?,?,?,?,?)',(campaign_id,asset,side,evidence_id,result,evidence_hash))
            except sqlite3.IntegrityError as exc:
                raise ValueError('REPLAYED_EVIDENCE_ID') from exc
        return True

    def report(self, campaign_id):
        _id(campaign_id)
        with self._db() as db:
            row=db.execute('SELECT manifest,manifest_hash FROM campaigns WHERE id=?',(campaign_id,)).fetchone()
            if not row: raise ValueError('UNKNOWN_CAMPAIGN')
            assets=json.loads(row[0]); observations=db.execute('SELECT asset,side,evidence_id,result,evidence_hash FROM observations WHERE campaign=? ORDER BY asset,side',(campaign_id,)).fetchall()
        by_asset={a:{} for a in assets}
        for a,side,eid,result,h in observations: by_asset[a][side]={'evidence_id':eid,'result':result,'evidence_hash':h}
        details=[]
        for asset, sides in by_asset.items():
            if len(sides)!=2: status='PARTIAL' if sides else 'PENDING'
            elif 'MISMATCH' in (sides['source']['result'],sides['target']['result']): status='MISMATCH'
            elif 'UNVERIFIED' in (sides['source']['result'],sides['target']['result']): status='UNVERIFIED'
            else: status='COMPLETE'
            details.append({'asset':asset,'status':status,'sides':sides,'missing_sides':[s for s in ('source','target') if s not in sides]})
        counts={s:sum(d['status']==s for d in details) for s in STATES}
        status='MISMATCH' if counts['MISMATCH'] else ('UNVERIFIED' if counts['UNVERIFIED'] else ('PARTIAL' if counts['PARTIAL'] or counts['PENDING'] else 'COMPLETE'))
        report={'schema':SCHEMA,'author':'Abdelhalim Talbi','campaign_id':campaign_id,'manifest_sha256':row[1],
                'status':status,'counts':counts,'assets':details,'cutover_authorized':False,'writes_to_nas':False,
                'native_engine_default':True,'silent_fallback_allowed':False,
                'limitations':['EVIDENCE_HASHES_ARE_REFERENCES_NOT_CRYPTOGRAPHIC_VERIFICATION',
                               'LOCAL_SQLITE_ONLY','NO_REMOTE_NAS_CERTIFICATION']}
        report['report_sha256']=digest(report)
        return report

def verify_report(report):
    if not isinstance(report,dict): return False
    try:
        return (report.get('schema')==SCHEMA and report.get('cutover_authorized') is False
                and report.get('writes_to_nas') is False and report.get('native_engine_default') is True
                and report.get('silent_fallback_allowed') is False
                and report.get('report_sha256')==digest({k:v for k,v in report.items() if k!='report_sha256'}))
    except (TypeError,ValueError): return False
