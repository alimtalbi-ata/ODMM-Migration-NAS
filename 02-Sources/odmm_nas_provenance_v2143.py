"""Fail-closed freshness and provenance envelope for NAS access evidence.

This validates self-consistency, NOT authenticity of a collector or its clock.
Author: Abdelhalim Talbi.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import hmac
import json
import re
from odmm_nas_probe_adapters_v2138 import ReadOnlyEvidence, compare_collected_evidence

_HEX = re.compile(r'^[0-9a-f]{64}$')

@dataclass(frozen=True)
class ProvenanceEnvelope:
    evidence: ReadOnlyEvidence
    collector_id: str
    endpoint_id: str
    observed_at: str
    collection_digest: str
    envelope_digest: str
    certified: bool = False
    cutover_authorized: bool = False

def _text(v):
    if type(v) is not str or not 1 <= len(v) <= 128 or not v.strip() or any(ord(c)<32 or ord(c)==127 for c in v):
        raise ValueError('INVALID_PROVENANCE_FIELD')
    return v

def _time(v):
    if type(v) is not str or not v.endswith('Z'):
        raise ValueError('INVALID_TIMESTAMP')
    try:
        parsed = datetime.strptime(v,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError('INVALID_TIMESTAMP') from exc
    return parsed

def _digest(evidence, collector, endpoint, observed):
    payload={'schema':'odmm.nas.provenance.v2143','vendor':evidence.vendor,
             'evidence_digest':evidence.digest,'collector_id':collector,
             'endpoint_id':endpoint,'observed_at':observed}
    return sha256(json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def wrap_provenance(*, evidence, collector_id, endpoint_id, observed_at):
    if type(evidence) is not ReadOnlyEvidence or evidence.cutover_authorized is not False or evidence.independently_attested is not False:
        raise ValueError('UNTRUSTED_EVIDENCE')
    collector_id=_text(collector_id); endpoint_id=_text(endpoint_id)
    _time(observed_at)
    if type(evidence.digest) is not str or not _HEX.fullmatch(evidence.digest):
        raise ValueError('INVALID_EVIDENCE_DIGEST')
    # Recheck the underlying digest, not merely its format.
    from odmm_nas_probe_adapters_v2138 import _string
    _string(evidence.firmware,'INVALID_FIRMWARE'); _string(evidence.collection_id,'INVALID_COLLECTION_ID')
    payload={'schema':'odmm.nas.readonly.v2138','vendor':evidence.vendor,
             'firmware':evidence.firmware,'collection_id':evidence.collection_id,'rows':evidence.observations}
    expected=sha256(json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    if not hmac.compare_digest(expected,evidence.digest): raise ValueError('EVIDENCE_DIGEST_MISMATCH')
    return ProvenanceEnvelope(evidence,collector_id,endpoint_id,observed_at,evidence.digest,
                              _digest(evidence,collector_id,endpoint_id,observed_at))

def compare_fresh_provenance(source,target,*,now,max_age_seconds=900,max_skew_seconds=120):
    if type(source) is not ProvenanceEnvelope or type(target) is not ProvenanceEnvelope:
        raise ValueError('INVALID_PROVENANCE')
    if type(now) is not str or type(max_age_seconds) is not int or type(max_skew_seconds) is not int or not 1<=max_age_seconds<=86400 or not 0<=max_skew_seconds<=3600:
        raise ValueError('INVALID_FRESHNESS_POLICY')
    clock=_time(now)
    for item in (source,target):
        if item.certified is not False or item.cutover_authorized is not False or item.collection_digest != item.evidence.digest:
            raise ValueError('UNTRUSTED_PROVENANCE')
        validated=wrap_provenance(evidence=item.evidence,collector_id=item.collector_id,
                                  endpoint_id=item.endpoint_id,observed_at=item.observed_at)
        if not hmac.compare_digest(validated.envelope_digest,item.envelope_digest):
            raise ValueError('PROVENANCE_DIGEST_MISMATCH')
        age=(clock-_time(item.observed_at)).total_seconds()
        if age<0 or age>max_age_seconds: raise ValueError('STALE_OR_FUTURE_EVIDENCE')
    if abs((_time(source.observed_at)-_time(target.observed_at)).total_seconds())>max_skew_seconds:
        raise ValueError('SOURCE_TARGET_TIME_SKEW')
    if source.collector_id==target.collector_id and source.endpoint_id==target.endpoint_id:
        raise ValueError('AMBIGUOUS_ENDPOINT_PROVENANCE')
    result=compare_collected_evidence(source.evidence,target.evidence)
    result['provenance']={'source_envelope_digest':source.envelope_digest,
                          'target_envelope_digest':target.envelope_digest,
                          'source_collector_id':source.collector_id,
                          'target_collector_id':target.collector_id,
                          'freshness_checked':True,'independently_attested':False}
    result['blockers']=sorted(set(result['blockers'])|{'PROVENANCE_NOT_CRYPTOGRAPHICALLY_ATTESTED','COLLECTOR_CLOCK_NOT_TRUSTED'})
    return result
