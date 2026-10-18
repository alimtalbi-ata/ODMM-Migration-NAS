"""ODMM V203.0: atomic signed evidence ingestion, resume and hash-chained audit.
Author: Abdelhalim Talbi. Writes local SQLite only. No NAS writes/cutover.
"""
import hashlib
import json
import sqlite3
from pathlib import Path
from odmm_campaign_registry_v2029 import Registry, digest, _id
from odmm_access_attestation_v2027 import verify as verify_envelope, as_comparison_record
from odmm_effective_access_v2026 import compare

SCHEMA = 'odmm.integrated.registry.v2030'

def _json(x):
    return json.dumps(x, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)

class IntegratedRegistry(Registry):
    def __init__(self, path):
        super().__init__(path)
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS signed_evidence(
                evidence_id TEXT PRIMARY KEY, campaign TEXT NOT NULL, asset TEXT NOT NULL,
                side TEXT NOT NULL, envelope TEXT NOT NULL, key_id TEXT NOT NULL,
                UNIQUE(campaign,asset,side), FOREIGN KEY(campaign) REFERENCES campaigns(id))""")
            db.execute("""CREATE TABLE IF NOT EXISTS audit_chain(
                seq INTEGER PRIMARY KEY AUTOINCREMENT, previous_hash TEXT NOT NULL,
                event_json TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE)""")

    def ingest(self, campaign_id, asset, side, envelope, *, key, key_id, now_ns=None, max_age_seconds=3600):
        _id(campaign_id); _id(asset)
        if side not in ('source','target'): raise ValueError('INVALID_SIDE')
        if not verify_envelope(envelope,key=key,expected_key_id=key_id,
                               expected_campaign_id=campaign_id,now_ns=now_ns,max_age_seconds=max_age_seconds):
            raise ValueError('INVALID_ATTESTATION')
        # Avoid a second freshness check using the current clock when a simulated now_ns is supplied.
        evidence_id=hashlib.sha256(_json(envelope).encode()).hexdigest()
        payload=envelope['payload']
        result='MATCH' if payload['decision']=='ALLOW' else 'UNVERIFIED'
        encoded=_json(envelope)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT manifest FROM campaigns WHERE id=?',(campaign_id,)).fetchone()
            if row is None or asset not in json.loads(row[0]): raise ValueError('UNKNOWN_CAMPAIGN_ASSET')
            old=db.execute('SELECT evidence_id,envelope,key_id FROM signed_evidence WHERE campaign=? AND asset=? AND side=?',(campaign_id,asset,side)).fetchone()
            if old:
                if old != (evidence_id,encoded,key_id): raise ValueError('CONFLICTING_EVIDENCE')
                return False
            if db.execute('SELECT 1 FROM signed_evidence WHERE evidence_id=?',(evidence_id,)).fetchone():
                raise ValueError('REPLAYED_EVIDENCE_ID')
            db.execute('INSERT INTO signed_evidence VALUES (?,?,?,?,?,?)',(evidence_id,campaign_id,asset,side,encoded,key_id))
            db.execute('INSERT INTO observations VALUES (?,?,?,?,?,?)',(campaign_id,asset,side,evidence_id,result,evidence_id))
            last=db.execute('SELECT event_hash FROM audit_chain ORDER BY seq DESC LIMIT 1').fetchone()
            prev=last[0] if last else '0'*64
            event={'campaign_id':campaign_id,'asset':asset,'side':side,'evidence_id':evidence_id,'key_id':key_id}
            event_json=_json(event)
            event_hash=digest({'previous_hash':prev,'event':event})
            db.execute('INSERT INTO audit_chain(previous_hash,event_json,event_hash) VALUES (?,?,?)',(prev,event_json,event_hash))
        return True

    def qualify(self,campaign_id,asset,*,source_key,target_key,source_key_id,target_key_id,principal_mapping,now_ns=None,max_age_seconds=3600):
        _id(campaign_id); _id(asset)
        if source_key == target_key or source_key_id == target_key_id: raise ValueError('SOURCE_TARGET_KEYS_MUST_DIFFER')
        with self._db() as db:
            rows=db.execute('SELECT side,envelope,key_id FROM signed_evidence WHERE campaign=? AND asset=?',(campaign_id,asset)).fetchall()
        records={}
        for side,encoded,key_id in rows:
            key,expected_id=(source_key,source_key_id) if side=='source' else (target_key,target_key_id)
            envelope=json.loads(encoded)
            if key_id!=expected_id or not verify_envelope(envelope,key=key,expected_key_id=expected_id,expected_campaign_id=campaign_id,now_ns=now_ns,max_age_seconds=max_age_seconds):
                raise ValueError('INVALID_OR_EXPIRED_STORED_EVIDENCE')
            p=envelope['payload']
            records[side]={'path':p['path'],'principal':p['principal'],'action':p['action'],'decision':p['decision'],
                           'method':p['method'],'evidence_id':hashlib.sha256(encoded.encode()).hexdigest()}
        compared=compare([records['source']] if 'source' in records else [],
                         [records['target']] if 'target' in records else [],
                         principal_mapping=principal_mapping,source_attested='source' in records,
                         target_attested='target' in records)
        result={'schema':SCHEMA,'author':'Abdelhalim Talbi','campaign_id':campaign_id,'asset':asset,
                'status':compared['status'],'checks':compared['checks'],
                'attestation_cryptographically_verified':len(records)==2,
                'cutover_authorized':False,'writes_to_nas':False,
                'native_engine_default':True,'silent_fallback_allowed':False,
                'limitations':['LOCAL_HMAC_SHARED_KEYS_NOT_REMOTE_NAS_IDENTITY',
                               'NO_AD_LDAP_AUTHENTICATION','NO_VENDOR_CERTIFICATION']}
        result['report_sha256']=digest(result)
        return result

    def audit(self):
        with self._db() as db:
            rows=db.execute('SELECT seq,previous_hash,event_json,event_hash FROM audit_chain ORDER BY seq').fetchall()
            count=db.execute('SELECT COUNT(*) FROM signed_evidence').fetchone()[0]
        previous='0'*64
        for seq,prev,encoded,h in rows:
            if prev!=previous or digest({'previous_hash':prev,'event':json.loads(encoded)})!=h:
                raise ValueError('AUDIT_CHAIN_BROKEN')
            previous=h
        if count!=len(rows): raise ValueError('AUDIT_EVIDENCE_COUNT_MISMATCH')
        report={'schema':SCHEMA+'.audit','author':'Abdelhalim Talbi','events':len(rows),
                'chain_head':previous,'cutover_authorized':False,'writes_to_nas':False}
        report['report_sha256']=digest(report)
        return report

def verify_report(report):
    return (isinstance(report,dict) and report.get('schema')==SCHEMA and
            report.get('cutover_authorized') is False and report.get('writes_to_nas') is False and
            report.get('native_engine_default') is True and report.get('silent_fallback_allowed') is False and
            report.get('report_sha256')==digest({k:v for k,v in report.items() if k!='report_sha256'}))
