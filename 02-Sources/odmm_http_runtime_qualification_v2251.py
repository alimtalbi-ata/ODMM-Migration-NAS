"""Isolated HTTP app startup and authorization qualification. Author: Abdelhalim Talbi.

Synthetic verified principals exercise the HTTP boundary only; not an IdP integration test.
"""
from __future__ import annotations
import json, sqlite3, tempfile
from pathlib import Path

def qualify():
    from fastapi.testclient import TestClient
    from odmm_operations_app import create_operations_app
    from odmm_scoped_app import create_scoped_app
    from odmm_operations_security import Principal
    checks=[]
    def record(name, passed, detail=''):
        checks.append({'name':name,'status':'PASS' if passed else 'FAIL','detail':detail})
    with tempfile.TemporaryDirectory(prefix='odmm-v2251-') as tmp:
        root=Path(tmp); db=root/'registry.sqlite'; grants=root/'grants.sqlite'
        with sqlite3.connect(db) as conn:
            conn.executescript('''CREATE TABLE jobs(id TEXT,source TEXT,target TEXT,state TEXT,created_at TEXT);
                CREATE TABLE operations(id TEXT,job_id TEXT,state TEXT,owner TEXT,epoch INTEGER,lease_until TEXT,updated_at TEXT);
                CREATE TABLE audit(seq INTEGER,hash TEXT);''')
        with sqlite3.connect(grants) as conn:
            from odmm_scoped_operations import initialize_grants_schema
            initialize_grants_schema(conn)
        verified=lambda req:Principal('test-operator',frozenset({'viewer'}),True)
        rejected=lambda req:None
        for name,factory,kwargs in (
            ('full',create_operations_app,{'registry_path':str(db)}),
            ('compact-scoped',create_scoped_app,{'registry_path':str(db),'grants_path':str(grants)}),
        ):
            for access,resolver,expected in (('verified',verified,200),('unverified',rejected,403)):
                try:
                    app=factory(**kwargs,resolve_verified_principal=resolver)
                    with TestClient(app) as client:
                        response=client.get('/operations')
                        record(f'{name}-{access}-portal',response.status_code==expected,f'HTTP {response.status_code}')
                        response=client.get('/api/v1/operations/overview')
                        if access=='unverified':
                            record(f'{name}-{access}-api',response.status_code==403,f'HTTP {response.status_code}')
                        elif name=='full':
                            record(f'{name}-{access}-api',response.status_code==200 and response.json().get('read_only') is True,f'HTTP {response.status_code}')
                        else:
                            # Scoped grants need a separately provisioned policy; no implicit grants.
                            record(f'{name}-{access}-api-empty-scope',response.status_code==200 and response.json().get('jobs')==0,f'HTTP {response.status_code}')
                except Exception as exc:
                    record(f'{name}-{access}-startup',False,f'{type(exc).__name__}: {str(exc)[:160]}')
    checks.extend({'name':name,'status':'NOT_TESTED'} for name in ('real-oidc-idp','windows-native-execution','nas-nfs-smb-e2e','acl-effective-access'))
    return {'version':'225.1','compact_version':'7.6.1','author':'Abdelhalim Talbi','status':'FAIL' if any(x['status']=='FAIL' for x in checks) else 'PASS_WITH_UNQUALIFIED_ITEMS','checks':checks}

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path);args=parser.parse_args()
    result=qualify();rendered=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
    if args.output:args.output.write_text(rendered,encoding='utf-8')
    print(rendered)
    raise SystemExit(result['status']=='FAIL')
