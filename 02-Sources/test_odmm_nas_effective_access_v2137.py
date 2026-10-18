import pytest
from odmm_nas_effective_access_v2137 import compare_effective_access
R=[{'principal':'AD\\alice','path':'/data','right':'READ'}]
def run(**kwargs):
    opts=dict(source_vendor='netapp_ontap',target_vendor='pure_flashblade',requests=R,source_probe=lambda *x: True,target_probe=lambda *x: True)
    opts.update(kwargs)
    return compare_effective_access(**opts)
def test_equal_is_still_blocked():
    r=run();assert r.checked==1 and not r.discrepancies and not r.cutover_authorized and not r.independently_attested
    assert 'PROBES_NOT_INDEPENDENTLY_ATTESTED' in r.blockers
def test_mismatch():
    r=run(target_probe=lambda *x:False);assert 'EFFECTIVE_ACCESS_MISMATCH' in r.blockers and len(r.discrepancies)==1
def test_deterministic():
    assert run().comparison_digest==run().comparison_digest
@pytest.mark.parametrize('bad',[[],[R[0],R[0]],[{'principal':'a','path':'/../etc','right':'READ'}],[{'principal':'a','path':'/data','right':'ROOT'}],[{'principal':'a','path':'//server','right':'READ'}]])
def test_bad_requests(bad):
    with pytest.raises(ValueError):run(requests=bad)
@pytest.mark.parametrize('bad',[None,1,'ALLOW'])
def test_bad_result(bad):
    with pytest.raises(ValueError,match='PROBE_RESULT_UNVERIFIED'):run(source_probe=lambda *x:bad)
def test_probe_exception_fail_closed():
    def fail(*x):raise RuntimeError('secret')
    with pytest.raises(ValueError,match='PROBE_EXECUTION_FAILED'):run(source_probe=fail)
def test_vendor_rejection():
    with pytest.raises(ValueError):run(target_vendor='netapp_ontap')
def test_read_only_callbacks():
    calls=[]
    def p(*args):calls.append(args);return False
    r=run(source_probe=p,target_probe=p)
    assert calls==[('AD\\alice','/data','READ')]*2 and r.checked==1
