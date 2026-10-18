"""ODMM V201.5 fixture-to-campaign evidence binding. Author: Abdelhalim Talbi.
Read-only source/target; no automatic cutover; fixture manifest is not a live ACL attestation.
"""
import hashlib
import json
from pathlib import Path
from odmm_fidelity_fixtures_v2014 import verify_fixtures
from odmm_qualification_campaign_v2012 import qualify, verify_campaign

SCHEMA = "odmm.fixture.campaign.v2015"

def digest(obj):
    return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()

def bind_fixture_campaign(source, target, manifest, *, max_entries=100000, max_bytes=1<<40):
    """Bind a known source fixture to a read-only NAS pair comparison.

    The source must still match its signed-by-hash (not authenticated) fixture manifest.
    The target may differ; differences are recorded, never auto-repaired.
    """
    if not verify_fixtures(source, manifest):
        raise ValueError("SOURCE_FIXTURE_MISMATCH")
    campaign=qualify(source,target,max_entries=max_entries,max_bytes=max_bytes)
    if not verify_campaign(campaign):
        raise ValueError("CAMPAIGN_INTEGRITY_FAILURE")
    domains=campaign['fidelity']['domains']
    report={'schema':SCHEMA,'author':'Abdelhalim Talbi',
            'fixture_manifest_sha256':manifest['manifest_sha256'],
            'campaign_sha256':campaign['report_sha256'],
            'campaign':campaign,
            'domain_status':{k:v['status'] for k,v in domains.items()},
            'fixture_acl_cases_declarative':True,
            'acl_applied':False,'remote_identity_verified':False,
            'smb_ads_verified':False,'cutover_authorized':False,
            'native_engine_default':True,'writes_to_nas':False,
            'status':'BLOCKED_PENDING_INDEPENDENT_QUALIFICATION'}
    report['report_sha256']=digest(report)
    return report

def verify_binding(report):
    if not isinstance(report,dict) or report.get('schema')!=SCHEMA:return False
    if report.get('cutover_authorized') is not False or report.get('writes_to_nas') is not False:return False
    campaign=report.get('campaign')
    if not verify_campaign(campaign):return False
    if report.get('campaign_sha256')!=campaign['report_sha256']:return False
    return report.get('report_sha256')==digest({k:v for k,v in report.items() if k!='report_sha256'})
