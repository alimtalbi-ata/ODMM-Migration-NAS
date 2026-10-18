"""V197.1 scoped composition root. No unscoped routes are mounted."""
from odmm_scoped_operations import ScopedOperationsView
from odmm_operations_portal import attach_operations_portal
from odmm_operations_security import require_permission

def create_scoped_app(*, registry_path, grants_path, resolve_verified_principal):
    if not callable(resolve_verified_principal): raise ValueError('VERIFIED_PRINCIPAL_RESOLVER_REQUIRED')
    from fastapi import FastAPI, HTTPException, Request
    app=FastAPI(title='ODMM Scoped Operations',version='197.1')
    view=ScopedOperationsView(registry_path,grants_path)
    def principal(request):
        try: return require_permission(resolve_verified_principal(request),'operations:read')
        except (PermissionError,ValueError,TypeError,KeyError): raise HTTPException(status_code=403,detail='FORBIDDEN')
    async def overview(request:Request): return view.overview(principal(request))
    async def jobs(request:Request,limit:int=50):
        p=principal(request)
        try: return view.jobs(p,limit)
        except ValueError: raise HTTPException(status_code=400,detail='LIMIT_INVALID')
    async def operations(request:Request,job_id:str,limit:int=50):
        p=principal(request)
        try: return view.operations(p,job_id,limit)
        except ValueError: raise HTTPException(status_code=400,detail='PARAMETER_INVALID')
        except LookupError: raise HTTPException(status_code=404,detail='JOB_NOT_FOUND')
    app.add_api_route('/api/v1/operations/overview',overview,methods=['GET'])
    app.add_api_route('/api/v1/operations/jobs',jobs,methods=['GET'])
    app.add_api_route('/api/v1/operations/jobs/{job_id}/operations',operations,methods=['GET'])
    def authorize(request):
        try: principal(request); return True
        except HTTPException: return False
    attach_operations_portal(app,authorize=authorize)
    return app
