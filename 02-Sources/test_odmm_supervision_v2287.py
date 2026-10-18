import pytest
from odmm_supervision_v2287 import supervision, overview_lines

def test_empty():
    assert supervision([])["total"] == 0

def test_counts():
    rows = [{"id":str(i),"status":state} for i,state in enumerate(("FAILED","UNKNOWN","COMPLETED","RUNNING","PENDING"))]
    s = supervision(rows)
    assert s["needs_review"] == 2
    assert s["completed_unverified"] == 1
    assert s["cutover_approved"] is False
    assert "Bascule autorisée : NON" in overview_lines(s)[1]

@pytest.mark.parametrize("rows", [None, {}, [None], [{"status":"IMPOSSIBLE"}]])
def test_invalid(rows):
    with pytest.raises(ValueError): supervision(rows)
