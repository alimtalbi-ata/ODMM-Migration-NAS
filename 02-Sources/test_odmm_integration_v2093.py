import sqlite3
from fastapi.testclient import TestClient
from odmm_netapp_integration_v2093 import create_netapp_qualified_operations_app
from odmm_key_migration_v2093 import inspect_legacy_registry

def test_migration_missing(tmp_path):
    assert inspect_legacy_registry(tmp_path/'missing.db')['reason']=='DATABASE_MISSING'
def test_migration_legacy(tmp_path):
    p=tmp_path/'old.db'
    with sqlite3.connect(p) as db:
        db.execute('create table keys(collector text,kid text,secret blob,status text)')
        db.execute('insert into keys values(?,?,?,?)',('a','b',b'supersecret','active'))
    result=inspect_legacy_registry(p)
    assert result['active_refs']==1 and result['cutover_authorized'] is False
    assert b'supersecret' not in repr(result).encode()
def test_migration_bad_schema(tmp_path):
    p=tmp_path/'bad.db'
    with sqlite3.connect(p) as db: db.execute('create table keys(foo text)')
    assert inspect_legacy_registry(p)['reason']=='LEGACY_SCHEMA_INVALID'
def test_provider_required(tmp_path):
    import pytest
    with pytest.raises(ValueError):create_netapp_qualified_operations_app(registry_path=str(tmp_path/'x'),resolve_verified_principal=lambda r:None,get_netapp_inventories=lambda:None,get_netapp_differences=lambda:None,get_lif_evidence=None)
