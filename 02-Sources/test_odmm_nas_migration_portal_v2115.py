from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_nas_migration_portal_v2115 import attach_nas_migration_comparison

def inventory():
    from odmm_flashblade_protocol_v2114 import FIELDS
    return {p:{k:False if k in ('read_only','root_squash','abe_enabled','encryption_required','continuously_available') else 'test' for k in fields} for p,fields in (('nfs',FIELDS['NFS']),('smb',FIELDS['SMB']))}

def app_factory(auth=lambda req:True, ontap=inventory, blade=inventory):
    app=FastAPI()
    attach_nas_migration_comparison(app,authorize=auth,get_ontap_inventory=ontap,get_flashblade_inventory=blade)
    return TestClient(app)

def test_both_directions():
    c=app_factory()
    for d in ('NETAPP_TO_FLASHBLADE','FLASHBLADE_TO_NETAPP'):
        r=c.get('/api/v1/operations/nas-migration/compare/'+d)
        assert r.status_code==200
        assert r.json()['cutover_authorized'] is False
        assert r.json()['nfs']['status']=='BLOCKED'

def test_invalid_direction():
    assert app_factory().get('/api/v1/operations/nas-migration/compare/ISILON').status_code==400

def test_denied_before_provider():
    def forbidden():raise AssertionError('provider called')
    c=app_factory(lambda req:False,forbidden,forbidden)
    assert c.get('/operations/nas-migration').status_code==403
    assert c.get('/api/v1/operations/nas-migration/compare/NETAPP_TO_FLASHBLADE').status_code==403

def test_provider_outage_fail_closed():
    def down():raise RuntimeError('secret token must not leak')
    r=app_factory(ontap=down).get('/api/v1/operations/nas-migration/compare/NETAPP_TO_FLASHBLADE')
    assert r.status_code==503 and 'secret' not in r.text

def test_portal_readonly():
    c=app_factory()
    r=c.get('/operations/nas-migration')
    assert r.status_code==200 and 'BLOCKED' in r.text
    assert 'no-store' in r.headers['cache-control']
    assert c.post('/operations/nas-migration').status_code==405

def test_requires_trusted_providers():
    import pytest
    with pytest.raises(ValueError): attach_nas_migration_comparison(FastAPI(),authorize=lambda r:True,get_ontap_inventory=None,get_flashblade_inventory=inventory)
