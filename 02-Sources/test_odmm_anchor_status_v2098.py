import pytest
from odmm_anchor_status_v2098 import assess_anchor_status
from odmm_campaign_anchor_v2097 import create_anchor
from test_odmm_campaign_anchor_v2097 import history,RESOLVER

def test_verified(tmp_path):
    h=history(tmp_path); a=create_anchor(h,'demo',key_id='vault-key-1',resolver=RESOLVER)
    s=assess_anchor_status(h,'demo',anchor_provider=lambda cid:a,resolver=RESOLVER)
    assert s['integrity']=='VERIFIED' and s['version']==2 and s['cutover_authorized'] is False

def test_unavailable(tmp_path):
    h=history(tmp_path)
    assert assess_anchor_status(h,'demo',anchor_provider=lambda _:None,resolver=RESOLVER)['integrity']=='UNVERIFIED'

def test_wrong_campaign(tmp_path):
    h=history(tmp_path); a=create_anchor(h,'demo',key_id='vault-key-1',resolver=RESOLVER)
    assert assess_anchor_status(h,'other',anchor_provider=lambda _:a,resolver=RESOLVER)['reason']=='ANCHOR_MISMATCH'

def test_revoked_key(tmp_path):
    h=history(tmp_path); a=create_anchor(h,'demo',key_id='vault-key-1',resolver=RESOLVER)
    s=assess_anchor_status(h,'demo',anchor_provider=lambda _:a,resolver=lambda _:None)
    assert s['reason']=='SIGNER_UNAVAILABLE' and not s['cutover_authorized']

def test_modified_anchor(tmp_path):
    h=history(tmp_path); a=create_anchor(h,'demo',key_id='vault-key-1',resolver=RESOLVER)
    a['head_hash']='0'*64
    assert assess_anchor_status(h,'demo',anchor_provider=lambda _:a,resolver=RESOLVER)['reason']=='INVALID_ANCHOR_MAC'

def test_provider_failure(tmp_path):
    h=history(tmp_path)
    def fail(_):raise RuntimeError('private details')
    s=assess_anchor_status(h,'demo',anchor_provider=fail,resolver=RESOLVER)
    assert s['reason']=='ANCHOR_VERIFICATION_FAILED' and 'private' not in str(s)
