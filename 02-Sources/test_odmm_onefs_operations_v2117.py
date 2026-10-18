from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
from odmm_onefs_operations_v2117 import attach_onefs_ontap_operations, qualify_onefs_api
from test_odmm_onefs_discovery_v2116 import fetch


def client(*, auth=lambda req: True, inventory=lambda: {'namespace_id': 'svm/vol'},
           discovery=fetch, approved=('v16',)):
    app = FastAPI()
    attach_onefs_ontap_operations(app, authorize=auth, get_ontap_inventory=inventory,
                                  onefs_fetch=discovery, access_zone='zoneA', path='/ifs/data',
                                  approved_versions=approved)
    return TestClient(app)


@pytest.mark.parametrize('direction', ['ONEFS_TO_NETAPP', 'NETAPP_TO_ONEFS'])
def test_both_directions(direction):
    response = client().get('/api/v1/operations/onefs-ontap/compare/' + direction)
    assert response.status_code == 200
    data = response.json()
    assert data['direction'] == direction and data['status'] == 'BLOCKED'
    assert data['engine'] == 'ODMM_NATIVE' and data['cutover_authorized'] is False
    assert response.headers['cache-control'] == 'no-store'


def test_denied_before_discovery():
    def forbidden(*args): raise AssertionError('PROVIDER_MUST_NOT_RUN')
    r = client(auth=lambda req: False, inventory=forbidden, discovery=forbidden).get('/api/v1/operations/onefs-ontap/compare/ONEFS_TO_NETAPP')
    assert r.status_code == 403


def test_authorizer_exception_denied():
    def bad(_): raise RuntimeError('token leak')
    assert client(auth=bad).get('/api/v1/operations/onefs-ontap/compare/ONEFS_TO_NETAPP').status_code == 403


def test_unapproved_version_blocks_without_fetch():
    def forbidden(*args): raise AssertionError('PROVIDER_MUST_NOT_RUN')
    r = client(discovery=forbidden, approved=()).get('/api/v1/operations/onefs-ontap/compare/ONEFS_TO_NETAPP')
    assert r.status_code == 503 and r.json()['cutover_authorized'] is False


def test_outage_is_blocked():
    def bad(_): raise RuntimeError('secret credential')
    r = client(discovery=bad).get('/api/v1/operations/onefs-ontap/compare/ONEFS_TO_NETAPP')
    assert r.status_code == 200 and r.json()['status'] == 'BLOCKED'
    assert 'secret' not in r.text


def test_bad_inventory_fails_closed():
    r = client(inventory=lambda: None).get('/api/v1/operations/onefs-ontap/compare/ONEFS_TO_NETAPP')
    assert r.status_code == 503


def test_bad_direction():
    assert client().get('/api/v1/operations/onefs-ontap/compare/ONEFS_TO_FLASHBLADE').status_code == 400


def test_no_write_route():
    assert client().post('/api/v1/operations/onefs-ontap/compare/ONEFS_TO_NETAPP').status_code == 405


def test_capability_explicit():
    with pytest.raises(ValueError): qualify_onefs_api(fetch, version='v15', approved_versions=('v15',))
    assert qualify_onefs_api(fetch, version='v16', approved_versions=('v16',)) == 'v16'


def test_bad_providers():
    with pytest.raises(ValueError): attach_onefs_ontap_operations(FastAPI(), authorize=None,
        get_ontap_inventory=lambda: {}, onefs_fetch=fetch, access_zone='zoneA', path='/ifs/data')
