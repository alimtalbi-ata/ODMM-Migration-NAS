"""Offline, read-only bridge for collector metadata; NOT a live access test."""
import hashlib
from qualification_bench import canonical
from vendor_qualification import VENDORS, PROTOCOLS, CHECKS

class BridgeError(ValueError): pass

def bridge_collection(vendor, protocol, endpoint_alias, collection):
    if vendor not in VENDORS or protocol not in PROTOCOLS:
        raise BridgeError('UNSUPPORTED_PROFILE')
    if not isinstance(endpoint_alias, str) or not endpoint_alias.strip() or len(endpoint_alias)>128 or any(c in endpoint_alias for c in '/\\\r\n'):
        raise BridgeError('INVALID_ALIAS')
    if not isinstance(collection,dict): raise BridgeError('INVALID_COLLECTION')
    att=collection.get('mount_attestation'); ident=collection.get('path_identity')
    if not isinstance(att,dict) or not isinstance(ident,dict): raise BridgeError('MISSING_ATTESTATION')
    if att.get('protocol') != protocol or not all(k in att for k in ('mount_id','device','source','mountpoint','fstype')):
        raise BridgeError('MOUNT_MISMATCH')
    if not all(type(ident.get(k)) is int for k in ('device','inode','mode')):
        raise BridgeError('INVALID_FILE_IDENTITY')
    if not isinstance(collection.get('limitations'),list) or not all(isinstance(x,str) for x in collection['limitations']):
        raise BridgeError('MISSING_LIMITATIONS')
    # Never persist raw ACL, remote source, mount paths, credentials or identity context.
    evidence={'schema':'odmm.collector-evidence.v1','vendor':vendor,'protocol':protocol,
              'endpoint_alias':endpoint_alias,'check':'acl_capture',
              'mount_type':att['fstype'],'mount_id_present':bool(att['mount_id']),
              'file_identity_present':True,'limitations':sorted(set(collection['limitations'])),
              'source':'collector-metadata-import','collector_authenticated':False,
              'remote_nas_authenticated':False,'effective_access_verified':False,
              'production_qualified':False,'manual_review_required':True}
    try: digest=hashlib.sha256(canonical(evidence)).hexdigest()
    except (TypeError,ValueError,OverflowError) as exc: raise BridgeError('NONCANONICAL_EVIDENCE') from exc
    return {'report':evidence,'sha256':digest}

def verify_bridge(bundle):
    if not isinstance(bundle,dict) or set(bundle)!={'report','sha256'} or not isinstance(bundle['report'],dict):
        raise BridgeError('INVALID_BUNDLE')
    report=bundle['report']
    if report.get('schema')!='odmm.collector-evidence.v1' or report.get('check')!='acl_capture':
        raise BridgeError('INVALID_SCHEMA')
    if report.get('production_qualified') is not False or report.get('effective_access_verified') is not False or report.get('collector_authenticated') is not False:
        raise BridgeError('UNSAFE_CLAIMS')
    try: expected=hashlib.sha256(canonical(report)).hexdigest()
    except (TypeError,ValueError,OverflowError) as exc: raise BridgeError('INVALID_REPORT') from exc
    if expected!=bundle['sha256']: raise BridgeError('HASH_MISMATCH')
    return True

def missing_checks():
    return [c for c in CHECKS if c!='acl_capture']
