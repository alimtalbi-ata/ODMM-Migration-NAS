import pytest
from odmm_payload_gate_v2285 import validate_jobs

def test_valid():
    rows=[{"id":"job-1","status":"RUNNING"}]
    assert validate_jobs(rows) is rows

@pytest.mark.parametrize("payload", [None,{},"x",[None],[{"id":1,"status":"RUNNING"}],[{"id":"  x","status":"RUNNING"}],[{"id":"x"*257,"status":"RUNNING"}],[{"id":"x","status":"BROKEN"}],[{"id":"x","status":"RUNNING"},{"id":"x","status":"FAILED"}]])
def test_invalid(payload):
    with pytest.raises(ValueError): validate_jobs(payload)

def test_limit():
    with pytest.raises(ValueError, match="REGISTRY_TOO_LARGE"): validate_jobs([{}]*100001)
