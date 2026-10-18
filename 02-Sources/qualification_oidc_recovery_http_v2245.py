"""Read-only, authenticated custody recovery diagnostics. Author: Abdelhalim Talbi."""
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from qualification_jwks_recovery_v2244 import inspect_handoff


def attach_custody_diagnostic(app, *, authenticate, rotation, ledger_path, witness_path,
                              witness_secret, custody_secret):
    """Attach only a GET endpoint; no mutation/replay endpoint is exposed."""
    if not callable(authenticate) or rotation is None:
        raise ValueError('RECOVERY_DIAGNOSTIC_CONFIG_INVALID')

    async def diagnostic(request: Request):
        try:
            identity = authenticate(request)
            if not isinstance(identity, dict) or 'qualification:read' not in identity.get('roles', ()):
                raise HTTPException(403, 'INSUFFICIENT_ROLE')
            # Reload the current persistent generation, not a caller-provided state.
            state = rotation.rotation.state
            result = inspect_handoff(ledger_path=ledger_path, witness_path=witness_path,
                                     current_state=state, witness_secret=witness_secret,
                                     custody_secret=custody_secret)
            return JSONResponse(result, headers={'Cache-Control': 'no-store'})
        except HTTPException:
            raise
        except PermissionError as exc:
            raise HTTPException(401, 'INVALID_ACCESS_TOKEN') from exc
        except (ValueError, OSError) as exc:
            raise HTTPException(503, 'OIDC_CUSTODY_EVIDENCE_UNVERIFIED',
                                headers={'Cache-Control': 'no-store'}) from exc

    path = '/api/v1/security/oidc/custody-diagnostic'
    if any(path == getattr(route, 'path', None) for route in app.routes):
        raise ValueError('RECOVERY_DIAGNOSTIC_ROUTE_DUPLICATE')
    app.add_api_route(path, diagnostic, methods=['GET'], include_in_schema=False)
    return app
