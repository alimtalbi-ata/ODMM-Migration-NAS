"""ODMM V202.8: HMAC-verified two-sided campaign with local SQLite replay ledger.
Author: Abdelhalim Talbi. Read-only NAS operations; SQLite writes ONLY to local audit ledger.
"""
import hashlib
import json
import sqlite3
from pathlib import Path
from odmm_access_attestation_v2027 import verify as verify_attestation, as_comparison_record
from odmm_effective_access_v2026 import compare

SCHEMA = 'odmm.verified.campaign.v2028'

def _hash(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()).hexdigest()

def _verify_side(envelopes, key, key_id, campaign_id, now_ns, max_age_seconds, max_records):
    if not isinstance(envelopes, list) or len(envelopes) > max_records:
        raise ValueError('INVALID_EVIDENCE_LIST')
    records=[]; identifiers=[]
    for envelope in envelopes:
        if not verify_attestation(envelope, key=key, expected_key_id=key_id, expected_campaign_id=campaign_id, now_ns=now_ns, max_age_seconds=max_age_seconds):
            raise ValueError('INVALID_ATTESTATION')
        record=as_comparison_record(envelope, key=key, expected_key_id=key_id, expected_campaign_id=campaign_id)
        records.append(record)
        identifiers.append(record['evidence_id'])
    if len(set(identifiers)) != len(identifiers):
        raise ValueError('DUPLICATE_EVIDENCE')
    return records, identifiers

def qualify(source_envelopes, target_envelopes, *, source_key, target_key, source_key_id, target_key_id,
            campaign_id, principal_mapping, ledger_path, now_ns=None, max_age_seconds=3600, max_records=10000):
    """Fail closed; consume evidence IDs atomically in a local SQLite replay ledger.

    Ledger must be a local persistent file (not :memory:). One signed envelope cannot
    qualify both sides. An invalid batch leaves the replay ledger unchanged.
    """
    if not isinstance(campaign_id,str) or not campaign_id or not isinstance(ledger_path,(str,Path)) or str(ledger_path) in ('', ':memory:'):
        raise ValueError('INVALID_CAMPAIGN_OR_LEDGER')
    if type(max_records) is not int or not 1 <= max_records <= 100000:
        raise ValueError('INVALID_MAX_RECORDS')
    if not isinstance(source_envelopes,list) or not isinstance(target_envelopes,list) or len(source_envelopes)+len(target_envelopes)>max_records:
        raise ValueError('INVALID_EVIDENCE_COUNT')
    if source_key_id == target_key_id or source_key == target_key:
        raise ValueError('SOURCE_TARGET_KEYS_MUST_DIFFER')
    source, source_ids = _verify_side(source_envelopes, source_key, source_key_id, campaign_id, now_ns, max_age_seconds, max_records)
    target, target_ids = _verify_side(target_envelopes, target_key, target_key_id, campaign_id, now_ns, max_age_seconds, max_records)
    if set(source_ids).intersection(target_ids):
        raise ValueError('CROSS_SIDE_EVIDENCE_REUSE')
    compared=compare(source,target,principal_mapping=principal_mapping,source_attested=True,target_attested=True,max_records=max_records)
    # Attestation is a property of the envelope verification, NOT the legacy compare() report.
    report={'schema':SCHEMA,'author':'Abdelhalim Talbi','campaign_id':campaign_id,
            'status':compared['status'],'counts':compared['counts'],'checks':compared['checks'],
            'source_key_id':source_key_id,'target_key_id':target_key_id,
            'source_evidence_ids':sorted(source_ids),'target_evidence_ids':sorted(target_ids),
            'attestation_cryptographically_verified':True,
            'replay_protection':'LOCAL_SQLITE_UNIQUE_EVIDENCE_ID',
            'source_target_identity_verified':False,
            'remote_nas_identity_verified':False,'cutover_authorized':False,'writes_to_nas':False,
            'native_engine_default':True,'silent_fallback_allowed':False,
            'limitations':['HMAC_SHARED_KEY_NOT_REMOTE_NAS_IDENTITY','LOCAL_LEDGER_ONLY','READ_DATA_ONLY',
                           'NO_AD_LDAP_AUTHENTICATION','NO_VENDOR_CERTIFICATION']}
    report['report_sha256']=_hash(report)
    # sqlite file is local audit metadata, not a NAS write. BEGIN IMMEDIATE ensures atomic replay claims.
    with sqlite3.connect(str(ledger_path),timeout=10,isolation_level=None) as db:
        db.execute('CREATE TABLE IF NOT EXISTS evidence_claims (evidence_id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, side TEXT NOT NULL, report_sha256 TEXT NOT NULL)')
        try:
            db.execute('BEGIN IMMEDIATE')
            for side, identifiers in (('source',source_ids),('target',target_ids)):
                for evidence_id in identifiers:
                    db.execute('INSERT INTO evidence_claims VALUES (?,?,?,?)',(evidence_id,campaign_id,side,report['report_sha256']))
            db.execute('COMMIT')
        except (sqlite3.IntegrityError,sqlite3.OperationalError) as exc:
            db.execute('ROLLBACK')
            raise ValueError('REPLAY_OR_LEDGER_FAILURE') from exc
    return report

def verify_report(report):
    if not isinstance(report,dict): return False
    try:
        return (report.get('schema')==SCHEMA and report.get('cutover_authorized') is False
                and report.get('writes_to_nas') is False and report.get('native_engine_default') is True
                and report.get('silent_fallback_allowed') is False
                and report.get('attestation_cryptographically_verified') is True
                and report.get('status') in ('MATCH','MISMATCH','UNVERIFIED')
                and report.get('report_sha256')==_hash({k:v for k,v in report.items() if k!='report_sha256'}))
    except (TypeError,ValueError): return False
