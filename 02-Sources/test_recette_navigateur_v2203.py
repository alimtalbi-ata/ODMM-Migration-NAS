import json
import pytest
from recette_navigateur_v2203 import safe_url, validate_header, main, sha256

def test_safe_url_redacts_query_fragment():
    assert safe_url('https://example.org/a?token=SECRET#x') == 'https://example.org/a'

def test_safe_url_rejects_credentials_and_non_http():
    for url in ('file:///etc/passwd', 'https://alice:secret@example.org/a', 'not-a-url'):
        with pytest.raises(ValueError): safe_url(url)

def test_header_validation():
    assert validate_header('X-Token: secret') == ('X-Token', 'secret')
    for h in ('Invalid Header: a', 'X-Test: a\r\nInjected: b', 'missing'):
        with pytest.raises(ValueError): validate_header(h)

def test_report_failure_no_url_secret(tmp_path, capsys):
    rc = main(['--url', 'http://127.0.0.1:1/a?token=SECRET', '--output', str(tmp_path)])
    assert rc == 1
    result = (tmp_path / 'recette-result.json').read_text()
    assert 'SECRET' not in result
    data = json.loads(result)
    assert data['status'] == 'FAIL' and data['url'] == 'http://127.0.0.1:1/a'
    assert 'SECRET' not in capsys.readouterr().out

def test_hash(tmp_path):
    import hashlib
    p = tmp_path / 'a'; p.write_bytes(b'abc')
    assert sha256(p) == hashlib.sha256(b'abc').hexdigest()
