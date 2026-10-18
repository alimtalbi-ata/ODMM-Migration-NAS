"""ODMM V202.3 pair qualification: read-only evidence composition.
Author: Abdelhalim Talbi. Not a production migration or cutover authorization.
"""
import hashlib
import json
from pathlib import Path
from odmm_qualification_campaign_v2012 import qualify, verify_campaign
from odmm_extended_fidelity_v2016 import compare as compare_extended, verify as verify_extended
from odmm_windows_mount_preflight_v2022 import assess_pair, verify as verify_mount

SCHEMA = 'odmm.pair.qualification.v2023'

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def campaign(source, target, *, required, source_capabilities=None, target_capabilities=None,
             evidence=None, strategy='NATIVE', max_entries=100000, max_bytes=1<<40,
             windows_probes=None):
    if not isinstance(max_entries, int) or isinstance(max_entries,bool) or max_entries < 1:
        raise ValueError('INVALID_MAX_ENTRIES')
    if not isinstance(max_bytes,int) or isinstance(max_bytes,bool) or max_bytes < 0:
        raise ValueError('INVALID_MAX_BYTES')
    if strategy != 'NATIVE':
        raise ValueError('EXTERNAL_ENGINE_REQUIRES_SEPARATE_EXPLICIT_APPROVAL')
    # Validate roots and content inventory first; never write into NAS roots.
    content = qualify(source, target, max_entries=max_entries, max_bytes=max_bytes)
    if not verify_campaign(content): raise ValueError('INVALID_CONTENT_REPORT')
    extended = compare_extended(source, target, max_entries=max_entries)
    if not verify_extended(extended): raise ValueError('INVALID_EXTENDED_REPORT')
    mounts = assess_pair(source, target, required=required,
                         source_capabilities=source_capabilities,
                         target_capabilities=target_capabilities, evidence=evidence,
                         strategy=strategy, windows_probes=windows_probes)
    if not verify_mount(mounts): raise ValueError('INVALID_MOUNT_REPORT')
    content_status = content['fidelity'].get('status', 'UNVERIFIED')
    differences = list(extended.get('differences', []))
    risks = list(mounts['risks'])
    if differences:
        risks.append({'side':'pair','risk':'EXTENDED_METADATA_MISMATCH',
                      'severity':'BLOCKER','impact':'METADATA_FIDELITY',
                      'difference_count':len(differences)})
    if content_status not in ('MATCH', 'PASS'):
        risks.append({'side':'pair','risk':'CONTENT_FIDELITY_NOT_ATTESTED',
                      'severity':'BLOCKER','impact':'DATA_INTEGRITY',
                      'observed_status':content_status})
    result = {'schema':SCHEMA,'author':'Abdelhalim Talbi',
              'source_root':content['source_root'],'target_root':content['target_root'],
              'required_domains':list(required),'risk_count':len(risks),'risks':risks,
              'content_status':content_status,'metadata_status':extended['status'],
              'content_report_sha256':content['report_sha256'],
              'extended_report_sha256':extended['report_sha256'],
              'mount_report_sha256':mounts['report_sha256'],
              'status':'MISMATCH' if differences else 'BLOCKED_UNVERIFIED',
              'cutover_authorized':False,'writes_to_nas':False,
              'native_engine_default':True,'silent_fallback_allowed':False,
              'limitations':['ACL_AND_EFFECTIVE_ACCESS_REQUIRE_INDEPENDENT_TESTS',
                             'ADS_AND_SPARSE_REQUIRE_PER_FILE_EVIDENCE',
                             'WINDOWS_API_AND_VENDOR_PAIR_NOT_CERTIFIED',
                             'POINT_IN_TIME_CONSISTENCY_NOT_PROVEN']}
    result['report_sha256']=digest(result)
    return result

def verify(report):
    return (isinstance(report,dict) and report.get('schema')==SCHEMA and
            report.get('cutover_authorized') is False and report.get('writes_to_nas') is False and
            report.get('native_engine_default') is True and
            report.get('silent_fallback_allowed') is False and
            isinstance(report.get('risks'),list) and
            report.get('risk_count')==len(report['risks']) and
            digest({k:v for k,v in report.items() if k!='report_sha256'})==report.get('report_sha256'))
