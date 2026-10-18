from test_odmm_oidc_boundary_v2107 import keys
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import pytest
from odmm_oidc_sqlite_audit_v2111 import SQLiteOperationsAudit,GENESIS

def test_reopen_chain_and_trusted_head(tmp_path):
    p=tmp_path/'audit.db'; a=SQLiteOperationsAudit(p)
    a.record(outcome='ALLOW',reason='VERIFIED')
    a.record(outcome='DENY',reason='IDENTITY_REJECTED')
    head=a.verify()['head']
    assert SQLiteOperationsAudit(p).verify(trusted_head=head)['valid']
    assert not a.verify(trusted_head=GENESIS)['valid']
    assert [x['seq'] for x in a.snapshot()]==[1,2]

def test_tampering_detected(tmp_path):
    p=tmp_path/'audit.db'; a=SQLiteOperationsAudit(p)
    a.record(outcome='DENY',reason='RESOLVER_FAILURE')
    with sqlite3.connect(p) as db:db.execute("UPDATE auth_events SET reason='VERIFIED' WHERE seq=1")
    assert a.verify()['reason']=='CHAIN_MISMATCH'

def test_concurrent_writes(tmp_path):
    p=tmp_path/'audit.db'; a=SQLiteOperationsAudit(p)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _:a.record(outcome='DENY',reason='IDENTITY_REJECTED'),range(80)))
    assert a.verify()['valid'] and a.verify()['events_checked']==80

def test_rejects_invalid_events(tmp_path):
    a=SQLiteOperationsAudit(tmp_path/'audit.db')
    with pytest.raises(ValueError):a.record(outcome='ALLOW',reason='bearer secret')
    with pytest.raises(ValueError):a.snapshot(limit=0)
    with pytest.raises(ValueError):SQLiteOperationsAudit(':memory:')

def test_http_integration(tmp_path,monkeypatch,keys):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import odmm_vault_readiness_v2100 as upstream
    from odmm_oidc_sqlite_audit_v2111 import create_sqlite_audited_oidc_operations_app
    from test_odmm_oidc_boundary_v2107 import signed
    from test_odmm_vault_observability_v2104 import Fake
    monkeypatch.setattr(upstream,'create_vault_operations_app',lambda **kw:FastAPI())
    p=tmp_path/'auth.db'
    app=create_sqlite_audited_oidc_operations_app(audit_path=p,issuer='https://idp.example.org',
        audience='odmm-operations',jwks_provider=lambda:keys[1],ha_client=Fake(),
        allowed_roles={'viewer'},revocation_check=lambda j,s:False)
    with TestClient(app) as client:
        assert client.get('/api/v1/operations/vault/ha-health').status_code==403
        assert client.get('/api/v1/operations/vault/ha-health',headers={'Authorization':'Bearer '+signed(keys,jti='valid')}).status_code==200
    a=SQLiteOperationsAudit(p)
    assert [e['outcome'] for e in a.snapshot()]==['DENY','ALLOW']
    assert a.verify()['valid']
