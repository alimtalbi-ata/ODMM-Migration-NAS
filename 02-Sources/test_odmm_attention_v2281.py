import pytest
from odmm_attention_v2281 import attention_summary

def test_empty():
    assert attention_summary([])["needs_attention"] == 0

def test_failed_unknown_and_running():
    s = attention_summary([{"id":"1","status":"FAILED"},{"id":"2","status":"RUNNING"},
                           {"id":"3","status":"ODD"},{"id":"4","status":"COMPLETED"}])
    assert (s["failed"], s["unknown"], s["running"], s["needs_attention"]) == (1,1,1,2)
    assert [x["id"] for x in s["jobs"]] == ["1", "3"]

def test_no_mutation():
    rows=[{"id":"x","status":"FAILED"}]
    attention_summary(rows)["jobs"][0]["id"]="changed"
    assert rows[0]["id"] == "x"

def test_bad_input():
    with pytest.raises(ValueError): attention_summary([None])
