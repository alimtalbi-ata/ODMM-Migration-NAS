import pytest
from odmm_ui_state_v22811 import resolve_refresh,selection_after_filter
from odmm_payload_gate_v2285 import validate_jobs

def test_stale():
    old=[{"id":"x","status":"RUNNING"}]
    assert resolve_refresh(old,1,2,[],None,validate_jobs)==(old,"STALE")
def test_network_error_keeps_rows():
    old=[{"id":"x","status":"RUNNING"}]
    assert resolve_refresh(old,2,2,[],"TimeoutError",validate_jobs)==(old,"ERROR")
def test_invalid_keeps_rows():
    old=[{"id":"x","status":"RUNNING"}]
    assert resolve_refresh(old,2,2,[{"id":"","status":"FAILED"}],None,validate_jobs)==(old,"INVALID")
def test_success():
    incoming=[{"id":"a","status":"FAILED"}]
    assert resolve_refresh([],2,2,incoming,None,validate_jobs)==(incoming,"OK")
def test_selection_preserved():
    assert selection_after_filter({"a","b"},[{"id":"b"},{"id":"c"}])=={"b"}
def test_empty_selection():
    assert selection_after_filter({"a"},[])==set()
