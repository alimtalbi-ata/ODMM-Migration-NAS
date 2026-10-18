from odmm_vault_readiness_v2100 import assess_vault_readiness
import pytest

class History: pass

@pytest.fixture
def verified(monkeypatch):
    import odmm_vault_readiness_v2100 as module
    def stub(*a, **kw):
        return {'integrity':'VERIFIED','rotation':'CURRENT','key_id':'key-1','reason':'OK','status':'BLOCKED','cutover_authorized':False}
    monkeypatch.setattr(module, 'assess_rotation', stub)
    return module

def run(module, probe):
    return module.assess_vault_readiness(History(), 'c1', anchor_provider=None, resolver=None,
        policy_provider=None, vault_probe=probe)

def test_good(verified):
    result=run(verified, lambda key:{'key_id':key,'reachable':True,'enabled':True,'version':'v2'})
    assert result['vault']=='READY' and result['renewal_action']=='NONE' and result['cutover_authorized'] is False

def test_unavailable(verified):
    assert run(verified, None)['reason']=='VAULT_PROBE_UNAVAILABLE'

def test_rejected_wrong_key(verified):
    assert run(verified, lambda k:{'key_id':'other','reachable':True,'enabled':True,'version':'v2'})['vault']=='UNVERIFIED'

def test_no_secret_output(verified):
    assert 'secret' not in str(run(verified,lambda k:{'key_id':k,'reachable':True,'enabled':True,'version':'v2'})).lower()

def test_expiring(verified, monkeypatch):
    monkeypatch.setattr(verified,'assess_rotation',lambda *a,**k:{'integrity':'VERIFIED','rotation':'EXPIRING','key_id':'k','reason':'OK'})
    assert run(verified,lambda k:{'key_id':k,'reachable':True,'enabled':True,'version':'v'})['renewal_action']=='PLAN_MANUAL_ROTATION'

def test_expired(verified, monkeypatch):
    monkeypatch.setattr(verified,'assess_rotation',lambda *a,**k:{'integrity':'VERIFIED','rotation':'EXPIRED','key_id':'k','reason':'EXPIRED'})
    assert run(verified,lambda k: (_ for _ in ()).throw(Exception('should not probe')))['vault']=='UNVERIFIED'

def test_probe_exception(verified):
    assert run(verified,lambda k:1/0)['reason']=='VAULT_PROBE_FAILED'

def test_probe_disabled(verified):
    assert run(verified,lambda k:{'key_id':k,'reachable':True,'enabled':False,'version':'v'})['reason']=='VAULT_KEY_UNAVAILABLE'
