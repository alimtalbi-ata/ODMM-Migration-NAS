"""Offline normalized capability snapshots. No network, no inferred ACL certification.
Auteur : Abdelhalim Talbi.
"""
import json
from pathlib import Path
from vendor_evidence_profiles_v2046 import VENDORS, REQUIRED_OBSERVATIONS

SUPPORTED = frozenset(('netapp_ontap','dell_powerscale','truenas_scale'))

def normalize_export(export):
    if not isinstance(export, dict): raise ValueError('INVALID_EXPORT')
    vendor = export.get('vendor')
    if vendor not in SUPPORTED: raise ValueError('UNSUPPORTED_OFFLINE_ADAPTER')
    observed = export.get('observed')
    if not isinstance(observed,dict): raise ValueError('INVALID_OBSERVATIONS')
    endpoint = {'vendor':vendor, 'capabilities_observed':False,
                'datasheet_version_verified':False}
    for key in REQUIRED_OBSERVATIONS:
        if key == 'vendor': continue
        value = observed.get(key)
        if isinstance(value, (str,int,float)) and not isinstance(value,bool) and str(value).strip():
            endpoint[key] = str(value).strip()
    # An export is NOT proof of live observation or documentation-version verification.
    missing=[key for key in REQUIRED_OBSERVATIONS if not endpoint.get(key)]
    return {'schema':'odmm.offline_capabilities.v2047','endpoint':endpoint,
            'missing':missing,'status':'UNVERIFIED','cutover_authorized':False,
            'documentation_index':VENDORS[vendor][1],
            'evidence_type':'USER_SUPPLIED_OFFLINE_EXPORT'}

def load_export(path):
    p=Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 1024*1024:
        raise ValueError('INVALID_EXPORT_FILE')
    return normalize_export(json.loads(p.read_text(encoding='utf-8')))
