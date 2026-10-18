"""ODMM V202.2 Windows mount observation and risk severity. Author: Abdelhalim Talbi.
All probes read-only. No inferred preservation guarantee or cutover authorization.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
from odmm_mount_risk_preflight_v2021 import assess, verify as verify_prior
SCHEMA = 'odmm.windows.mount.risk.v2022'

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def classify_windows_path(path, *, platform=None, drive_type=None):
    """Classify a path without network access. drive_type is GetDriveTypeW result.
    UNC paths are SMB candidates, NOT proof of SMB protocol or ACL support.
    """
    platform = os.name if platform is None else platform
    value = str(path)
    if platform != 'nt':
        return {'status':'UNSUPPORTED_PLATFORM','protocol':'UNKNOWN','preservation':'UNVERIFIED'}
    if value.startswith('\\\\'):
        return {'status':'OBSERVED_PATH_SYNTAX','protocol':'SMB_CANDIDATE','preservation':'UNVERIFIED'}
    mapping={2:'REMOVABLE',3:'LOCAL',4:'REMOTE_UNVERIFIED_PROTOCOL',5:'OPTICAL',6:'RAMDISK'}
    return {'status':'OBSERVED_DRIVE_TYPE' if drive_type in mapping else 'UNKNOWN',
            'protocol':mapping.get(drive_type,'UNKNOWN'),'preservation':'UNVERIFIED'}

def observe_windows(root):
    """Read-only Win32 GetVolumePathNameW/GetDriveTypeW/GetVolumeInformationW.
    No write probes, credential handling, or destructive tests.
    """
    if os.name != 'nt':
        return {'status':'UNSUPPORTED_PLATFORM','protocol':'UNKNOWN','preservation':'UNVERIFIED'}
    p=Path(root)
    if p.is_symlink(): raise ValueError('SYMLINK_ROOT_REFUSED')
    if not p.is_dir(): raise ValueError('ROOT_NOT_DIRECTORY')
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    from ctypes import wintypes
    volume=ctypes.create_unicode_buffer(32768)
    kernel.GetVolumePathNameW.argtypes=[wintypes.LPCWSTR,wintypes.LPWSTR,wintypes.DWORD]
    kernel.GetVolumePathNameW.restype=wintypes.BOOL
    if not kernel.GetVolumePathNameW(str(p.resolve()),volume,len(volume)):
        return {'status':'UNKNOWN','reason':'VOLUME_PATH_QUERY_FAILED','protocol':'UNKNOWN','preservation':'UNVERIFIED'}
    kernel.GetDriveTypeW.argtypes=[wintypes.LPCWSTR]
    kernel.GetDriveTypeW.restype=wintypes.UINT
    kind=int(kernel.GetDriveTypeW(volume.value))
    result=classify_windows_path(str(p),platform='nt',drive_type=kind)
    result['volume_path']=volume.value
    result['filesystem_type']='UNVERIFIED'
    fs=ctypes.create_unicode_buffer(256)
    kernel.GetVolumeInformationW.argtypes=[wintypes.LPCWSTR,wintypes.LPWSTR,wintypes.DWORD,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.LPWSTR,wintypes.DWORD]
    kernel.GetVolumeInformationW.restype=wintypes.BOOL
    if kernel.GetVolumeInformationW(volume.value,None,0,None,None,None,fs,len(fs)):
        result['filesystem_type']=fs.value
    return result

def severity_risks(previous, source_probe, target_probe):
    """Add severity and impact to prior risks; observations never reduce severity."""
    if not verify_prior(previous): raise ValueError('INVALID_PREVIOUS_REPORT')
    out=[]
    for risk in previous['risks']:
        row=dict(risk)
        row['impact']='FIDELITY_OR_CUTOVER_UNVERIFIED'
        row['severity']='BLOCKER'
        out.append(row)
    for side,probe in (('source',source_probe),('target',target_probe)):
        if probe['status'] in ('UNKNOWN','UNSUPPORTED_PLATFORM'):
            out.append({'side':side,'risk':'WINDOWS_MOUNT_PROBE_UNAVAILABLE','severity':'BLOCKER','impact':'PROTOCOL_UNKNOWN'})
        elif probe['protocol'] in ('SMB_CANDIDATE','REMOTE_UNVERIFIED_PROTOCOL'):
            out.append({'side':side,'risk':'REMOTE_PROTOCOL_AND_ACL_UNATTESTED','severity':'BLOCKER','impact':'ACL_OR_ADS_LOSS_POSSIBLE'})
    return out

def assess_pair(source,target,*,required,source_capabilities=None,target_capabilities=None,evidence=None,strategy='NATIVE',windows_probes=None):
    previous=assess(source,target,required=required,source_capabilities=source_capabilities,target_capabilities=target_capabilities,evidence=evidence,strategy=strategy)
    if windows_probes is None:
        probes={'source':observe_windows(source),'target':observe_windows(target)}
    else:
        if not isinstance(windows_probes,dict) or set(windows_probes)!={'source','target'} or any(not isinstance(v,dict) or 'status' not in v or 'protocol' not in v for v in windows_probes.values()):
            raise ValueError('INVALID_WINDOWS_PROBES')
        probes=windows_probes
    result={'schema':SCHEMA,'windows_observations':probes,'risks':severity_risks(previous,probes['source'],probes['target']),
            'previous_report_sha256':previous['report_sha256'], 'required_domains':list(required),
            'status':'BLOCKED_PENDING_REAL_NAS_VALIDATION','cutover_authorized':False,
            'writes_to_nas':False,'silent_fallback_allowed':False,
            'native_engine_default':strategy=='NATIVE',
            'limitations':['WINDOWS_VOLUME_PROBE_NOT_FIDELITY_ATTESTATION','UNC_SYNTAX_NOT_PROTOCOL_PROOF','NO_VENDOR_CERTIFICATION']}
    result['report_sha256']=digest(result)
    return result

def verify(report):
    return isinstance(report,dict) and report.get('schema')==SCHEMA and report.get('cutover_authorized') is False and report.get('writes_to_nas') is False and report.get('silent_fallback_allowed') is False and isinstance(report.get('risks'),list) and digest({k:v for k,v in report.items() if k!='report_sha256'})==report.get('report_sha256')
