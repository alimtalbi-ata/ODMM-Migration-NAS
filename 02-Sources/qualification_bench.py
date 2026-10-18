"""Offline deterministic fixture runner. Simulated checks are NOT NAS qualification."""
import hashlib
import json
from vendor_qualification import VENDORS, PROTOCOLS, CHECKS

class BenchError(ValueError): pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')

def run_fixture(fixture):
    if not isinstance(fixture, dict) or set(fixture) != {'vendor','protocol','endpoint_alias','observations'}:
        raise BenchError('INVALID_FIXTURE')
    vendor,protocol,alias=fixture['vendor'],fixture['protocol'],fixture['endpoint_alias']
    if vendor not in VENDORS or protocol not in PROTOCOLS:
        raise BenchError('UNSUPPORTED_PROFILE')
    if not isinstance(alias,str) or not alias.strip() or len(alias)>128 or any(c in alias for c in '/\\\n\r'):
        raise BenchError('INVALID_ALIAS')
    observations=fixture['observations']
    if not isinstance(observations,dict) or set(observations)!=set(CHECKS):
        raise BenchError('INCOMPLETE_OBSERVATIONS')
    results=[]
    for check in CHECKS:
        obs=observations[check]
        if not isinstance(obs,dict) or set(obs)!={'expected','actual'}:
            raise BenchError('INVALID_OBSERVATION')
        # Equality is only a fixture assertion, never a real effective-access test.
        passed=type(obs['expected']) is type(obs['actual']) and obs['expected']==obs['actual']
        digest=hashlib.sha256(canonical({'check':check,'observation':obs})).hexdigest()
        results.append({'check':check,'result':'SIMULATED_PASS' if passed else 'SIMULATED_FAIL','evidence_sha256':digest})
    report={'schema':'odmm.offline-bench.v1','vendor':vendor,'protocol':protocol,'endpoint_alias':alias,
            'mode':'OFFLINE_FIXTURE','checks':results,'simulated_pass':all(x['result']=='SIMULATED_PASS' for x in results),
            'production_qualified':False,'manual_review_required':True}
    return {'report':report,'sha256':hashlib.sha256(canonical(report)).hexdigest()}

def matrix_report(fixtures):
    if not isinstance(fixtures,list): raise BenchError('INVALID_FIXTURE_LIST')
    seen=set(); entries=[]
    for fixture in fixtures:
        item=run_fixture(fixture); key=(item['report']['vendor'],item['report']['protocol'],item['report']['endpoint_alias'])
        if key in seen: raise BenchError('DUPLICATE_PROFILE')
        seen.add(key); entries.append(item)
    entries.sort(key=lambda x:(x['report']['vendor'],x['report']['protocol'],x['report']['endpoint_alias']))
    payload={'schema':'odmm.offline-matrix.v1','entries':entries,'production_qualified':False}
    return {'report':payload,'sha256':hashlib.sha256(canonical(payload)).hexdigest()}
