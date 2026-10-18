"""V197.2 scoped-only CLI: requires externally verified identity and explicit grants.

The operator supplies a verified identity assertion through an injected callable;
no --subject/--role/--verified flags are accepted.
"""
import argparse
import json
from odmm_scoped_operations import ScopedOperationsView
from odmm_operations_security import require_permission

def run(argv=None, *, resolve_verified_principal=None, output=None):
    p=argparse.ArgumentParser(description='ODMM scoped read-only operations CLI')
    p.add_argument('--db',required=True)
    p.add_argument('--grants-db',required=True)
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('overview')
    jobs=sub.add_parser('jobs'); jobs.add_argument('--limit',type=int,default=50)
    ops=sub.add_parser('operations'); ops.add_argument('--job-id',required=True); ops.add_argument('--limit',type=int,default=50)
    a=p.parse_args(argv)
    if not callable(resolve_verified_principal): raise PermissionError('VERIFIED_IDENTITY_PROVIDER_REQUIRED')
    principal=require_permission(resolve_verified_principal(),'operations:read')
    view=ScopedOperationsView(a.db,a.grants_db)
    result=view.overview(principal) if a.command=='overview' else view.jobs(principal,a.limit) if a.command=='jobs' else view.operations(principal,a.job_id,a.limit)
    rendered=json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)
    if output is None: print(rendered)
    else: output(rendered)
    return 0

def main(argv=None):
    # No insecure standalone identity fallback. Integrate run() with the deployment's
    # authenticated OS/SSO identity provider instead.
    raise SystemExit('VERIFIED_IDENTITY_PROVIDER_REQUIRED: use an authenticated launcher')

if __name__=='__main__': main()
