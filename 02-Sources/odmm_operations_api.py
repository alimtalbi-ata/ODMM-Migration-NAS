"""Optional FastAPI read-only adapter; authentication is mandatory, supplied by deployment."""
from odmm_operations import OperationsView

def attach_readonly_routes(app, *, registry_path, authorize):
    if not callable(authorize):
        raise ValueError('AUTHORIZATION_PROVIDER_REQUIRED')
    if not hasattr(app,'add_api_route'):
        raise ValueError('FASTAPI_APP_REQUIRED')
    view=OperationsView(registry_path)
    from fastapi import HTTPException, Request

    def checked(request):
        if authorize(request) is not True:
            raise HTTPException(status_code=403,detail='FORBIDDEN')

    async def overview(request: Request):
        checked(request); return view.overview()

    async def jobs(request: Request, limit: int=50):
        checked(request)
        try: return view.jobs(limit)
        except ValueError: raise HTTPException(status_code=400,detail='LIMIT_INVALID')

    async def operations(request: Request, job_id: str, limit: int=50):
        checked(request)
        try: return view.operations(job_id,limit)
        except ValueError: raise HTTPException(status_code=400,detail='PARAMETER_INVALID')
        except LookupError: raise HTTPException(status_code=404,detail='JOB_NOT_FOUND')

    app.add_api_route('/api/v1/operations/overview',overview,methods=['GET'])
    app.add_api_route('/api/v1/operations/jobs',jobs,methods=['GET'])
    app.add_api_route('/api/v1/operations/jobs/{job_id}/operations',operations,methods=['GET'])
    return view
