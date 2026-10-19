"""Read-only registry refresh worker with bounded, credential-safe diagnostics.

Author: Abdelhalim Talbi.
UI state is updated only on the Tk main thread. No migration operations.
"""
from odmm_connection_diagnostics_v22851 import explain_connection_failure
from odmm_registry_client_v2267 import fetch_registry_jobs


def _publish(inbox, result):
    """Atomically coalesce pending results, keeping only the newest generation.

    Queue.mutex guards comparison and replacement against concurrent producers
    and consumers. Account for discarded pending tasks so Queue.join remains
    correct; tasks already taken by consumers are never touched.
    """
    with inbox.mutex:
        pending = inbox.queue
        if any(item[0] >= result[0] for item in pending):
            return False
        removed = len(pending)
        pending.clear()
        inbox.unfinished_tasks -= removed
        pending.append(result)
        inbox.unfinished_tasks += 1
        inbox.not_empty.notify()
        return True


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
