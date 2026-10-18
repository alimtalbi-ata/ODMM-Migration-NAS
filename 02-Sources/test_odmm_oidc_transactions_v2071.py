import tempfile, threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit,parse_qs
import pytest
from odmm_oidc_transactions_v2071 import SQLitePKCETransactions
from odmm_oidc_pkce_v2068 import OIDCVerificationError

def store(path,clock=lambda:1000):return SQLitePKCETransactions(path,key=b'k'*32,clock=clock)
def begin(s):return s.begin(authorize_endpoint='https://idp.example/auth',client_id='odmm',redirect_uri='https://odmm.example/callback',browser_binding='browser-session-secret-123456')
def test_round_trip_and_pkce():
 with tempfile.TemporaryDirectory() as d:
  s=store(d+'/tx.db');tx=begin(s);params=parse_qs(urlsplit(tx['url']).query)
  assert params['code_challenge_method']==['S256']
  result=s.consume(state=tx['state'],code='authorization-code',browser_binding='browser-session-secret-123456')
  assert result['code_verifier'] and result['nonce'] and result['code']=='authorization-code'
  with pytest.raises(OIDCVerificationError):s.consume(state=tx['state'],code='replay',browser_binding='browser-session-secret-123456')
def test_cross_worker_single_use():
 with tempfile.TemporaryDirectory() as d:
  path=d+'/tx.db';s=store(path);tx=begin(s)
  def consume(_):
   try:store(path).consume(state=tx['state'],code='c',browser_binding='browser-session-secret-123456');return True
   except OIDCVerificationError:return False
  with ThreadPoolExecutor(max_workers=16) as ex:results=list(ex.map(consume,range(32)))
  assert sum(results)==1
def test_browser_binding_mismatch_does_not_consume():
 with tempfile.TemporaryDirectory() as d:
  s=store(d+'/tx.db');tx=begin(s)
  with pytest.raises(OIDCVerificationError):s.consume(state=tx['state'],code='c',browser_binding='another-browser-secret-123')
  assert s.consume(state=tx['state'],code='c',browser_binding='browser-session-secret-123456')['nonce']
def test_expiry():
 with tempfile.TemporaryDirectory() as d:
  clock=[1000];s=store(d+'/tx.db',clock=lambda:clock[0]);tx=begin(s);clock[0]=1301
  with pytest.raises(OIDCVerificationError):s.consume(state=tx['state'],code='c',browser_binding='browser-session-secret-123456')
def test_bad_configuration():
 with pytest.raises(ValueError):SQLitePKCETransactions('/tmp/unused.db',key=b'short')
