import json
import pytest
from odmm_supervision_export_v2288 import summary_document, write_summary

def test_export_has_no_sensitive_fields():
    data = summary_document([{"id":"secret-job","status":"FAILED","token":"secret-token","password":"private"}])
    encoded = json.dumps(data)
    assert "secret-job" not in encoded and "secret-token" not in encoded and "private" not in encoded
    assert data["summary"]["needs_review"] == 1
    assert data["cutover_approved"] is False

def test_empty_registry_not_certified():
    assert summary_document([])["summary"]["total"] == 0
    assert summary_document([])["cutover_approved"] is False

def test_export_exclusive(tmp_path):
    path = tmp_path / "summary.json"
    write_summary([{"id":"x","status":"COMPLETED"}],path)
    assert json.loads(path.read_text())["summary"]["completed_unverified"] == 1
    with pytest.raises(FileExistsError): write_summary([],path)

def test_invalid_payload_rejected():
    with pytest.raises(ValueError): summary_document([{"status":"invalid"}])
