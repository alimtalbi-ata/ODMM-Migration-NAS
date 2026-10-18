from fastapi.testclient import TestClient
import sqlite3

def registry(tmp_path):
    p=tmp_path/"reg.db"
    with sqlite3.connect(p) as db: db.execute("CREATE TABLE jobs (id TEXT)")
    return p
from odmm_operations_app import create_nas_qualification_operations_app
from odmm_nas_share_inventory_v2133 import normalize_namespaces

def providers():
    out={}
    for v in ('netapp_ontap','pure_flashblade','dell_onefs'):
        def provider(v=v):
            return normalize_namespaces(vendor=v,firmware='test',endpoint_id='test',records=[],pagination_complete=True,
                provenance=dict(vendor=v,firmware='test',endpoint_id='test',evidence_id='test',collector_id='test'))
        out[v]=provider
    return out

def test_composition_fail_closed(tmp_path):
    app=create_nas_qualification_operations_app(registry_path=registry(tmp_path),resolve_verified_principal=lambda _:None,nas_providers=providers())
    c=TestClient(app)
    assert c.get('/operations/nas-pairs').status_code==403
    assert c.get('/api/v1/operations/nas-pairs/netapp_ontap/dell_onefs').status_code==403

def test_no_providers(tmp_path):
    import pytest
    with pytest.raises(ValueError):create_nas_qualification_operations_app(registry_path=registry(tmp_path),resolve_verified_principal=lambda _:None,nas_providers={})
