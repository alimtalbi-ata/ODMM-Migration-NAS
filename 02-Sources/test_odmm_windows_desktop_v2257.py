from odmm_windows_desktop_v2257 import valid_console_url

def test_urls():
    assert valid_console_url('https://odmm.example.com')
    assert valid_console_url('http://127.0.0.1:8090')
    for url in ['http://example.com','https://user:pass@example.com','file:///tmp/x','https://example.com/evil','https://example.com?x=1','javascript:alert(1)']:
        assert not valid_console_url(url)
