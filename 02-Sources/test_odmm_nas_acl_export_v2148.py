from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_nas_acl_portal_v2147 import attach_acl_audit_portal
from odmm_nas_acl_export_v2148 import attach_acl_signed_export,verify_export
from test_odmm_nas_acl_portal_v2147 import evidence
from odmm_nas_acl_semantics_v2146 import VENDORS
import pytest
KEY=b'local-only-test-signing-key-32-bytes-minimum'

def setup(allowed=True,broken=None):
    app=FastAPI()
    providers={v:(lambda protocol,v=v:evidence(v,protocol)) for v in VENDORS}
    if broken: providers[broken]=lambda protocol: (_ for _ in ()).throw(RuntimeError('TOP_SECRET'))
    attach_acl_signed_export(app,authorize=lambda r:allowed,providers=providers,hmac_key=KEY)
    return TestClient(app)

def test_six_directions_and_verify():
    r=setup().get('/api/v1/operations/nas-acl-audit/export')
    assert r.status_code==200 and len(r.json()['reports'])==6
    assert verify_export(r.json(),KEY)
    assert all(x['status']=='BLOCKED' and x['cutover_authorized'] is False for x in r.json()['reports'])
    assert 'secret-user' not in r.text and '/private/customer' not in r.text

def test_tamper_and_wrong_key():
    data=setup().get('/api/v1/operations/nas-acl-audit/export').json()
    assert not verify_export(data,b'x'*32)
    data['reports'][0]['status']='AUTHORIZED'
    assert not verify_export(data,KEY)

def test_auth_and_filter():
    assert setup(False).get('/api/v1/operations/nas-acl-audit/export').status_code==403
    assert setup().get('/api/v1/operations/nas-acl-audit/export?protocol=BAD').status_code==400
    assert len(setup().get('/api/v1/operations/nas-acl-audit/export?source=netapp_ontap&protocol=SMB3').json()['reports'])==2

def test_provider_failure_is_redacted_and_signed():
    r=setup(broken='dell_onefs').get('/api/v1/operations/nas-acl-audit/export')
    assert r.status_code==200 and verify_export(r.json(),KEY)
    assert sum(x['status']=='UNAVAILABLE' for x in r.json()['reports'])==4
    assert 'TOP_SECRET' not in r.text

def test_key_validation():
    with pytest.raises(ValueError):attach_acl_signed_export(FastAPI(),authorize=lambda r:True,providers={v:(lambda p:None) for v in VENDORS},hmac_key=b'weak')
