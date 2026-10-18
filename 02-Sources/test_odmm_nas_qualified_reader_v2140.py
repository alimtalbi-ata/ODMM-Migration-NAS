import json
import pytest
from odmm_nas_qualified_reader_v2140 import Profile, collect_pages

P = Profile('netapp_ontap', '9.15.1', '/api/storage/volumes', 'records', 'next', 'EV001')

def call(transport, **kw):
    return collect_pages(base_url='https://nas.example.org:443', profile=P,
                         transport=transport, authorization='Bearer SECRET', **kw)

def test_two_pages():
    calls=[]
    def fetch(url, **opts):
        calls.append((url,opts))
        return json.dumps({'records':[{'id':len(calls)}], 'next':'a/b' if len(calls)==1 else None}).encode()
    result=call(fetch)
    assert result['record_count']==2 and result['pagination_complete']
    assert result['cutover_authorized'] is False and result['certified'] is False
    assert calls[1][0].endswith('?cursor=a%2Fb')
    assert all(c[1]['tls_verify'] is True and c[1]['redirects'] is False for c in calls)
    assert 'SECRET' not in repr(result)

@pytest.mark.parametrize('url', ['http://nas.example.org:443', 'https://127.0.0.1:443',
    'https://localhost:443', 'https://user:pw@nas.example.org:443',
    'https://nas.example.org:443/?token=x', 'https://nas.example.org'])
def test_reject_urls(url):
    with pytest.raises(ValueError):
        collect_pages(base_url=url,profile=P,transport=lambda *a,**k:b'{}',authorization='Bearer SECRET')

def test_cycle():
    with pytest.raises(ValueError,match='CURSOR_CYCLE'):
        call(lambda *a,**k:b'{"records":[],"next":"repeat"}')

def test_missing_pagination_field():
    with pytest.raises(ValueError,match='NAS_COLLECTION_FAILED'):
        call(lambda *a,**k:b'{"records":[]}')

def test_transport_error_no_secret_leak():
    def bad(*a,**k): raise RuntimeError('Bearer SECRET')
    with pytest.raises(ValueError) as exc: call(bad)
    assert 'SECRET' not in str(exc.value)

def test_page_limit():
    with pytest.raises(ValueError,match='PAGINATION_LIMIT_EXCEEDED'):
        call(lambda *a,**k:b'{"records":[],"next":"other"}',max_pages=1)

def test_record_limit():
    with pytest.raises(ValueError,match='RECORD_LIMIT_EXCEEDED'):
        call(lambda *a,**k:b'{"records":[{},{}],"next":null}',max_records=1)

def test_reject_route():
    with pytest.raises(ValueError,match='INVALID_ROUTE'):
        collect_pages(base_url='https://nas.example.org:443',profile=Profile('netapp_ontap','9.15.1','/../admin','records','next','EV001'),transport=lambda *a,**k:b'{}',authorization='Bearer SECRET')
