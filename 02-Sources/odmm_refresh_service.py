"""Read-only registry refresh worker with bounded, credential-safe diagnostics.

Author: Abdelhalim Talbi.
UI state is updated only on the Tk main thread. No migration operations.
"""
from queue import Full

from odmm_connection_diagnostics_v22851 import explain_connection_failure
from odmm_registry_client_v2267 import fetch_registry_jobs


def _publish(inbox, result):
    """Never block a worker indefinitely if a bounded queue is saturated.

    The UI identifies stale results by request ID; dropping a full-queue result
    is safer than blocking an abandoned refresh worker.
    """
    try:
        inbox.put_nowait(result)
        return True
    except Full:
        return False


def fetch_into_queue(request_id, endpoint, token, inbox, fetcher=None):
    """Fetch registry data once and publish an outcome without leaking secrets.

    A fetcher may be injected for deterministic tests. The API token is never
    included in the published error or success tuple.
    """
    fetch = fetch_registry_jobs if fetcher is None else fetcher
    try:
        data = fetch(endpoint, token)
    except Exception as exc:
        return _publish(inbox, (request_id, None, explain_connection_failure(exc)))
    return _publish(inbox, (request_id, data, None))
