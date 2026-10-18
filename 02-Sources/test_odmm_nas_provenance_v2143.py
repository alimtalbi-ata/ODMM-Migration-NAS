import dataclasses
import pytest
from odmm_nas_probe_adapters_v2138 import collect_readonly_evidence
from odmm_nas_provenance_v2143 import wrap_provenance, compare_fresh_provenance
V=('netapp_ontap','pure_flashblade','dell_onefs')
NOW='2026-10-15T12:00:00Z'
def evidence(v,allowed=True):
    return collect_readonly_evidence(vendor=v,firmware='synthetic',collection_id='run1',requests=[{'principal':'user','path':'/data','right':'READ'}],collector=lambda *a:{'allowed':allowed,'method':'ACL_READONLY','identity_resolved':True})
def pair(a='netapp_ontap',b='pure_flashblade',ta=NOW,tb=NOW):
    return (wrap_provenance(evidence=evidence(a),collector_id='collector-'+a,endpoint_id='endpoint-'+a,observed_at=ta),wrap_provenance(evidence=evidence(b),collector_id='collector-'+b,endpoint_id='endpoint-'+b,observed_at=tb))
@pytest.mark.parametrize('a,b',[(a,b) for a in V for b in V if a!=b])
def test_six_directions(a,b):
    result=compare_fresh_provenance(*pair(a,b),now=NOW)
    assert result['status']=='BLOCKED' and result['cutover_authorized'] is False
    assert result['provenance']['freshness_checked'] is True
@pytest.mark.parametrize('bad', ['2026-10-15T11:00:00Z','2026-10-15T12:00:01Z'])
def test_stale_or_future(bad):
    with pytest.raises(ValueError,match='STALE_OR_FUTURE_EVIDENCE'): compare_fresh_provenance(*pair(ta=bad),now=NOW)
def test_skew():
    with pytest.raises(ValueError,match='SOURCE_TARGET_TIME_SKEW'): compare_fresh_provenance(*pair(tb='2026-10-15T11:57:00Z'),now=NOW)
def test_tamper_envelope():
    a,b=pair()
    with pytest.raises(ValueError,match='PROVENANCE_DIGEST_MISMATCH'): compare_fresh_provenance(dataclasses.replace(a,collector_id='forged'),b,now=NOW)
def test_tamper_evidence():
    a,b=pair()
    with pytest.raises(ValueError,match='EVIDENCE_DIGEST_MISMATCH'): compare_fresh_provenance(dataclasses.replace(a,evidence=dataclasses.replace(a.evidence,observations=(('x','/data','READ',True,'ACL_READONLY'),))),b,now=NOW)
def test_invalid_timestamp():
    with pytest.raises(ValueError,match='INVALID_TIMESTAMP'):pair(ta='yesterday')
def test_invalid_policy():
    with pytest.raises(ValueError,match='INVALID_FRESHNESS_POLICY'):compare_fresh_provenance(*pair(),now=NOW,max_age_seconds=True)
def test_ambiguous_endpoint():
    a,b=pair()
    b=wrap_provenance(evidence=b.evidence,collector_id=a.collector_id,endpoint_id=a.endpoint_id,observed_at=NOW)
    with pytest.raises(ValueError,match='AMBIGUOUS_ENDPOINT_PROVENANCE'):compare_fresh_provenance(a,b,now=NOW)
