"""Offline evidence-envelope validation. Hashes prove consistency, NOT provenance or NAS qualification."""
import hashlib
import json
from qualification_bench import run_fixture, canonical, BenchError
from vendor_qualification import CHECKS

class EvidenceError(ValueError):
    pass

def seal_observation(vendor, protocol, endpoint_alias, check, expected, actual, source='offline-fixture'):
    if check not in CHECKS or source not in ('offline-fixture', 'operator-import'):
        raise EvidenceError('INVALID_CHECK_OR_SOURCE')
    payload={'vendor':vendor,'protocol':protocol,'endpoint_alias':endpoint_alias,'check':check,
             'expected':expected,'actual':actual,'source':source}
    # Reject non-JSON, NaN and noncanonical types before hashing.
    _validate_payload(payload)
    return {'payload':payload,'sha256':hashlib.sha256(canonical(payload)).hexdigest()}

def _validate_payload(payload):
    try:
        encoded=json.dumps(payload,allow_nan=False,sort_keys=True,ensure_ascii=True)
        if len(encoded)>65536 or not isinstance(payload['expected'],(str,int,float,bool,type(None),list,dict)):
            raise ValueError('invalid payload')
    except (TypeError,ValueError,OverflowError) as exc:
        raise EvidenceError('INVALID_PAYLOAD') from exc

def verify_envelopes(envelopes):
    if not isinstance(envelopes,list) or len(envelopes)!=len(CHECKS):
        raise EvidenceError('INCOMPLETE_EVIDENCE')
    observations={}; identity=None; sources=set()
    for envelope in envelopes:
        if not isinstance(envelope,dict) or set(envelope)!={'payload','sha256'}:
            raise EvidenceError('INVALID_ENVELOPE')
        payload=envelope['payload']
        if not isinstance(payload,dict) or set(payload)!={'vendor','protocol','endpoint_alias','check','expected','actual','source'}:
            raise EvidenceError('INVALID_PAYLOAD')
        _validate_payload(payload)
        digest=hashlib.sha256(canonical(payload)).hexdigest()
        if not isinstance(envelope['sha256'],str) or digest!=envelope['sha256']:
            raise EvidenceError('HASH_MISMATCH')
        check=payload['check']
        if check not in CHECKS or check in observations:
            raise EvidenceError('INVALID_OR_DUPLICATE_CHECK')
        if payload['source'] not in ('offline-fixture','operator-import'):
            raise EvidenceError('INVALID_SOURCE')
        current=(payload['vendor'],payload['protocol'],payload['endpoint_alias'])
        if identity is None: identity=current
        if identity!=current: raise EvidenceError('MIXED_ENDPOINT')
        sources.add(payload['source'])
        observations[check]={'expected':payload['expected'],'actual':payload['actual']}
    try:
        result=run_fixture({'vendor':identity[0],'protocol':identity[1],
                            'endpoint_alias':identity[2],'observations':observations})
    except BenchError as exc:
        raise EvidenceError('INVALID_PROFILE') from exc
    report=dict(result['report'])
    report.update({'schema':'odmm.evidence-bench.v1','evidence_sources':sorted(sources),
                   'evidence_integrity_verified':True,'evidence_provenance_verified':False,
                   'effective_access_verified':False,'production_qualified':False,
                   'manual_review_required':True})
    return {'report':report,'sha256':hashlib.sha256(canonical(report)).hexdigest()}
