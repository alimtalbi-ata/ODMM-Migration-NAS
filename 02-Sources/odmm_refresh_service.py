"""Read-only registry refresh worker with bounded, credential-safe diagnostics.

Author: Abdelhalim Talbi.
UI state is updated only on the Tk main thread. No migration operations.
"""
from queue import Full

from odmm_connection_diagnostics_v22851 import explain_connection_failure
from odmm_registry_client_v2267 import fetch_registry_jobs


def _publish(inbox, result):
    """Publish newest request without blocking, coalescing stale queue results.

    Only a strictly newer request may evict an older queued response. The
    queue mutex makes comparison and replacement atomic against consumers.
    Never evict a newer result for an older worker finishing late.
    """
    try:
        inbox.put_nowait(result)
        return True
    except Full:
        pass
    # Queue's mutex protects coalescing against concurrent producers/consumers.
    # Never manipulate unfinished_tasks: discarded items were not taken by
    # consumers, and the GUI does not use join/task_done semantics.
    with inbox.mutex:
        queued = inbox.queue
        if not queued:
            queued.append(result)
            inbox.unfinished_tasks += 1
            inbox.not_empty.notify()
            return True
        if any(item[0] >= result[0] for item in queued):
            return False
        discarded = len(queued)
        queued.clear()
        inbox.unfinished_tasks -= discarded
        queued.append(result)
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
