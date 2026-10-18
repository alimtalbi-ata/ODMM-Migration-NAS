from unittest.mock import patch
import pytest
from odmm_vault_v2100 import VaultKV2Resolver,VaultUnavailable,assess_vault_campaign

def adapter(payload=None,token='token'):
    calls=[]
    def client(path,headers):
        calls.append((path,headers));return payload
    return VaultKV2Resolver(client=client,token_provider=lambda:token),calls

def test_vault_kv2_valid():
    a,c=adapter({'data':{'data':{'hmac_key_hex':'ab'*32},'metadata':{'destroyed':False,'deletion_time':''}}})
    assert a('key1')==bytes.fromhex('ab'*32)
    assert c[0][0]=='/v1/secret/data/odmm/hmac/key1'
    assert c[0][1]['X-Vault-Token']=='token'

@pytest.mark.parametrize('payload', [None,{}, {'data':{'data':{},'metadata':{}}},
    {'data':{'data':{'hmac_key_hex':'aa'*31},'metadata':{}}},
    {'data':{'data':{'hmac_key_hex':'aa'*32},'metadata':{'destroyed':True}}},
    {'data':{'data':{'hmac_key_hex':'aa'*32},'metadata':{'deletion_time':'2026-01-01'}}}])
def test_invalid_secret_fails_closed(payload):
    a,_=adapter(payload)
    with pytest.raises(VaultUnavailable):a('key1')

def test_no_token():
    a,_=adapter({},token='')
    with pytest.raises(VaultUnavailable):a('key1')

def test_invalid_id_no_http():
    a,c=adapter({})
    with pytest.raises(ValueError,match='INVALID_KEY_ID'):a('../escape')
    assert not c

def test_no_secret_in_exception():
    def fail(path,headers):raise RuntimeError('SECRET-LEAK')
    a=VaultKV2Resolver(client=fail,token_provider=lambda:'TOKEN-LEAK')
    with pytest.raises(VaultUnavailable) as err:a('key1')
    assert 'LEAK' not in str(err.value)

def test_invalid_config():
    with pytest.raises(ValueError):VaultKV2Resolver(client=lambda *_:None,token_provider=lambda:'x',prefix='../')

@patch('odmm_vault_v2100.assess_rotation')
def test_campaign_healthy(rotation):
    rotation.return_value={'integrity':'VERIFIED','rotation':'CURRENT','reason':'ANCHOR_VALID'}
    r=assess_vault_campaign(None,'camp1',anchor_provider=None,secret_resolver=None,policy_provider=None,vault_health=lambda:{'available':True})
    assert r['alert']=='NONE' and r['cutover_authorized'] is False and r['status']=='BLOCKED'

@patch('odmm_vault_v2100.assess_rotation')
def test_expiring(rotation):
    rotation.return_value={'integrity':'VERIFIED','rotation':'EXPIRING','reason':'KEY_EXPIRING'}
    r=assess_vault_campaign(None,'camp1',anchor_provider=None,secret_resolver=None,policy_provider=None,vault_health=lambda:{'available':True})
    assert r['manual_renewal_recommended'] and r['alert']=='KEY_EXPIRING'

@patch('odmm_vault_v2100.assess_rotation')
def test_vault_unavailable(rotation):
    r=assess_vault_campaign(None,'camp1',anchor_provider=None,secret_resolver=None,policy_provider=None,vault_health=lambda:{'available':False})
    assert r['alert']=='VAULT_UNAVAILABLE' and not rotation.called

@patch('odmm_vault_v2100.assess_rotation')
def test_revoked(rotation):
    rotation.return_value={'integrity':'VERIFIED','rotation':'REVOKED','reason':'KEY_NOT_ACTIVE'}
    r=assess_vault_campaign(None,'camp1',anchor_provider=None,secret_resolver=None,policy_provider=None,vault_health=lambda:{'available':True})
    assert r['alert']=='KEY_REVOKED' and not r['cutover_authorized']

def test_bad_campaign():
    r=assess_vault_campaign(None,'../escape',anchor_provider=None,secret_resolver=None,policy_provider=None,vault_health=None)
    assert r['reason']=='CAMPAIGN_INVALID'
