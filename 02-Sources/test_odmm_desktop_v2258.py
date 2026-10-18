import json
import pytest
from odmm_desktop_model_v2258 import read_report, report_summary, pretty_report
from odmm_windows_desktop_v2258 import valid_console_url

def test_report_read(tmp_path):
    p = tmp_path / 'r.json'; p.write_text('{"status":"PASS","items":[1,2]}', encoding='utf-8')
    assert read_report(p)['status'] == 'PASS'
    assert report_summary(read_report(p))['status'] == 'PASS'

def test_report_reject_scalar(tmp_path):
    p = tmp_path / 'r.json'; p.write_text('42')
    with pytest.raises(ValueError): read_report(p)

def test_report_reject_oversized(tmp_path):
    p = tmp_path / 'r.json'; p.write_bytes(b'x' * 5000001)
    with pytest.raises(ValueError): read_report(p)

def test_summary_does_not_invent_pass():
    assert report_summary({'hello': 'world'})['status'] == 'non déclaré'
    assert report_summary([1,2])['entries'] == 2

def test_filter():
    assert 'alpha' in pretty_report({'alpha': 1, 'beta': 2}, 'alpha')
    assert 'beta' not in pretty_report({'alpha': 1, 'beta': 2}, 'alpha')

def test_url_security():
    assert valid_console_url('https://example.org')
    assert valid_console_url('http://127.0.0.1:8080')
    for value in ['http://example.org', 'https://u:p@example.org', 'https://example.org/evil', 'javascript:alert(1)', 'https://example.org?x=1']:
        assert not valid_console_url(value)
