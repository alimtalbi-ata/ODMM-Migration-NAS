import pytest
from odmm_payload_gate_v2284 import validate_jobs

def test_valid():
    assert validate_jobs([{"id":"a","status":"RUNNING"}])[0]["id"] == "a"
@pytest.mark.parametrize("rows", [None,{},[None],[{"id":"","status":"RUNNING"}],[{"id":"a","status":"BOGUS"}],[{"id":"a","status":"RUNNING"},{"id":"a","status":"FAILED"}]])
def test_invalid(rows):
    with pytest.raises(ValueError): validate_jobs(rows)
def test_empty():
    assert validate_jobs([]) == []
