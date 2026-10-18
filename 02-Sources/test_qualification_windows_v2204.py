import hashlib
import json
from qualification_windows_v2204 import consolidate


def test_missing(tmp_path):
    assert consolidate(tmp_path)['status'] == 'NOT_EXECUTED'


def test_bad_json(tmp_path):
    (tmp_path / 'recette-result.json').write_text('{')
    assert consolidate(tmp_path)['status'] == 'FAIL'


def test_valid(tmp_path):
    data = b'fake image for integrity test'
    (tmp_path / 'dashboard-initial.png').write_bytes(data)
    evidence = {'schema': 'odmm-browser-acceptance-v2203', 'status': 'PASS',
                'checks': {'http': True, 'security_headers': True, 'filters': True},
                'screenshots': [{'name': 'dashboard-initial.png', 'sha256': hashlib.sha256(data).hexdigest()}],
                'console_error_count': 0, 'page_error_count': 0}
    (tmp_path / 'recette-result.json').write_text(json.dumps(evidence))
    result = consolidate(tmp_path)
    assert result['status'] == 'PASS' and not result['windows_qualified']
    (tmp_path / 'dashboard-initial.png').write_bytes(b'tampered')
    assert 'SCREENSHOT_HASH_MISMATCH' in consolidate(tmp_path)['failures']


def test_browser_failure(tmp_path):
    (tmp_path / 'recette-result.json').write_text(json.dumps({'schema': 'odmm-browser-acceptance-v2203', 'status': 'FAIL', 'checks': {}, 'screenshots': []}))
    assert consolidate(tmp_path)['status'] == 'FAIL'


def test_path_traversal_rejected(tmp_path):
    (tmp_path / 'recette-result.json').write_text(json.dumps({'schema': 'odmm-browser-acceptance-v2203', 'status': 'PASS', 'checks': {}, 'screenshots': [{'name': '../secret', 'sha256': 'x'}]}))
    assert 'REPORT_INVALID' in consolidate(tmp_path)['failures']
