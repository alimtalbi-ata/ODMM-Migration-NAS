import pytest
from odmm_health_v2283 import assess

def test_empty_is_not_healthy():
    assert assess([])["level"] == "NO_DATA"
def test_duplicate_blocks():
    a=assess([{"id":"x","status":"RUNNING"},{"id":"x","status":"COMPLETED"}]); assert a["level"]=="DATA_QUALITY" and a["duplicate_ids"]==["x"]
def test_unknown_alert():
    assert assess([{"id":"a","status":"UNKNOWN"}])["level"]=="ATTENTION"
def test_invalid_status():
    assert assess([{"id":"a","status":"SUCCEEDED"}])["invalid_states"]==1
def test_no_false_cutover():
    a=assess([{"id":"a","status":"COMPLETED"}]); assert a["level"]=="NO_ALERT_DETECTED" and not a["cutover_authorized"]
def test_bad_payload():
    with pytest.raises(ValueError): assess([None])
