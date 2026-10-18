import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_onefs_discovery_v2116 import OneFSInventory
from odmm_onefs_flashblade_v2118 import compare_onefs_flashblade, attach_onefs_flashblade_operations

ONEFS = OneFSInventory({'namespace':'/ifs/data','protocol':'UNVERIFIED','identity_domain':'UNVERIFIED',
                        'acl_model':'UNVERIFIED','discovered_protocols':('NFS',)}, {}, (), ())

def test_bidirectional():
    for direction in ('ONEFS_TO_FLASHBLADE','FLASHBLADE_TO_ONEFS'):
        result=compare_onefs_flashblade(ONEFS, {'namespace_id':'/blade'}, direction=direction)
        assert result['status']=='BLOCKED' and result['cutover_authorized'] is False
        assert result['engine']=='ODMM_NATIVE'
        assert result['source_namespace']==('/ifs/data' if direction.startswith('ONEFS') else '/blade')

def test_untrusted():
    with pytest.raises(ValueError): compare_onefs_flashblade({}, {}, direction='ONEFS_TO_FLASHBLADE')
    with pytest.raises(ValueError): compare_onefs_flashblade(ONEFS, {}, direction='BAD')

def fetch(route):
    if route.endswith('/zones'): return {'zones':[{'name':'System'}]}
    if route.endswith('/exports'): return {'exports':[{'paths':['/ifs/data']}]}
    if route.endswith('/shares'): return {'shares':[]}
    raise AssertionError('Unexpected route')

def client(auth=True, fetcher=fetch, approved=('v16',)):
    app=FastAPI()
    attach_onefs_flashblade_operations(app,authorize=lambda _: auth,
        get_flashblade_inventory=lambda:{'namespace_id':'/blade'}, onefs_fetch=fetcher,
        access_zone='System',path='/ifs/data',approved_versions=approved)
    return TestClient(app)

def test_http_bidirectional():
    for direction in ('ONEFS_TO_FLASHBLADE','FLASHBLADE_TO_ONEFS'):
        response=client().get('/api/v1/operations/onefs-flashblade/compare/'+direction)
        assert response.status_code==200 and response.json()['cutover_authorized'] is False
        assert response.headers['cache-control']=='no-store'

def test_denied_no_fetch():
    def never(_): raise AssertionError('must not call fetch')
    assert client(auth=False,fetcher=never).get('/api/v1/operations/onefs-flashblade/compare/ONEFS_TO_FLASHBLADE').status_code==403

def test_api_not_approved():
    assert client(approved=()).get('/api/v1/operations/onefs-flashblade/compare/ONEFS_TO_FLASHBLADE').status_code==503

def test_bad_direction():
    assert client().get('/api/v1/operations/onefs-flashblade/compare/UNKNOWN').status_code==400

def test_failed_fetch():
    assert client(fetcher=lambda _: (_ for _ in ()).throw(OSError('offline'))).get('/api/v1/operations/onefs-flashblade/compare/ONEFS_TO_FLASHBLADE').status_code==200
    # Discovery reports missing evidence as explicit blockers, never grants cutover.

def test_prior_portal_auth_fail_closed():
    from odmm_nas_migration_portal_v2115 import attach_nas_migration_comparison
    for authorize in (lambda _: 1, lambda _: 'yes', lambda _: (_ for _ in ()).throw(RuntimeError())):
        app=FastAPI()
        attach_nas_migration_comparison(app,authorize=authorize,
            get_ontap_inventory=lambda: (_ for _ in ()).throw(AssertionError('no access')),
            get_flashblade_inventory=lambda: (_ for _ in ()).throw(AssertionError('no access')))
        c=TestClient(app)
        assert c.get('/operations/nas-migration').status_code==403
        assert c.get('/api/v1/operations/nas-migration/compare/NETAPP_TO_FLASHBLADE').status_code==403
