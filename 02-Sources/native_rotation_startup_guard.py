"""V194.7: ASGI boundary admission. Mount this as the OUTERMOST ASGI app.

Requires an independently pinned route digest. Rechecks on each request to
prevent post-startup route mutations. Does not sandbox direct Python imports.
"""
import re
from native_rotation_live_route_gate import inspect_live_routes

_DIGEST = re.compile(r'^[0-9a-f]{64}$')


class RotationAdmissionASGI:
    def __init__(self, app, *, allowed_endpoint, expected_sha256, additional_admission=None):
        if not callable(app) or not callable(allowed_endpoint) or not isinstance(expected_sha256, str) or not _DIGEST.fullmatch(expected_sha256):
            raise ValueError('ROTATION_STARTUP_CONFIG_INVALID')
        self.app = app
        self.allowed_endpoint = allowed_endpoint
        self.expected_sha256 = expected_sha256
        if additional_admission is not None and not callable(additional_admission):
            raise ValueError('ROTATION_ADMISSION_CALLBACK_INVALID')
        self.additional_admission = additional_admission
        self.admitted = False

    def verify(self):
        result = inspect_live_routes(self.app, allowed_endpoint=self.allowed_endpoint,
                                     expected_sha256=self.expected_sha256)
        if self.additional_admission is not None:
            admission = self.additional_admission()
            if not isinstance(admission, dict) or admission.get('admitted') is not True:
                raise ValueError('ROTATION_PRODUCTION_ADMISSION_DENIED')
        self.admitted = True
        return result

    async def __call__(self, scope, receive, send):
        typ = scope.get('type')
        if typ == 'lifespan':
            while True:
                message = await receive()
                if message['type'] == 'lifespan.startup':
                    try:
                        self.verify()
                    except Exception as exc:
                        self.admitted = False
                        await send({'type': 'lifespan.startup.failed', 'message': 'ODMM_ROTATION_ADMISSION_FAILED:' + type(exc).__name__})
                        return
                    # Do not swallow the inner app's startup/shutdown; forward the
                    # complete lifespan stream with a prefetched startup message.
                    async def inner_receive():
                        nonlocal message
                        if message is not None:
                            m, message = message, None
                            return m
                        return await receive()
                    try:
                        await self.app(scope, inner_receive, send)
                    finally:
                        # A terminated lifespan must never leave a reusable wrapper admitted.
                        self.admitted = False
                    return
                if message['type'] == 'lifespan.shutdown':
                    await send({'type': 'lifespan.shutdown.complete'})
                    return
                raise ValueError('ROTATION_LIFESPAN_INVALID')
        if typ in ('http', 'websocket'):
            if not self.admitted:
                if typ == 'http':
                    await send({'type': 'http.response.start', 'status': 503, 'headers': [(b'content-type', b'text/plain')]})
                    await send({'type': 'http.response.body', 'body': b'ODMM_ROTATION_NOT_ADMITTED'})
                else:
                    await send({'type': 'websocket.close', 'code': 1013})
                return
            try:
                self.verify()
            except Exception:
                self.admitted = False
                if typ == 'http':
                    await send({'type': 'http.response.start', 'status': 503, 'headers': []})
                    await send({'type': 'http.response.body', 'body': b'ODMM_ROTATION_ROUTE_DRIFT'})
                else:
                    await send({'type': 'websocket.close', 'code': 1013})
                return
        await self.app(scope, receive, send)
