import pytest
from odmm_job_triage_v2280 import triage_job, triage_lines
from odmm_editions_v2280 import EDITIONS

def test_failed():
    x=triage_job({"id":"A", "status":"FAILED", "error":"timeout"})
    assert x["label"] == "À examiner" and x["error_reported"]
    assert "timeout" in " ".join(triage_lines(x))

def test_completed_not_verified():
    x=triage_job({"id":"A", "status":"COMPLETED"})
    assert "ACL" in x["next_step"] and "déclaré" in x["label"]

def test_unknown():
    assert triage_job({"id":"A", "status":"other"})["label"] == "État non reconnu"

def test_missing_id():
    with pytest.raises(ValueError): triage_job({"status":"FAILED"})

def test_no_invented_metrics():
    x=triage_job({"id":"A", "status":"RUNNING"})
    assert "progress_percent" in x["detail"]["unreported_metrics"]

def test_three_editions():
    assert set(EDITIONS) == {"linux-full", "linux-compact", "windows-compact"}
