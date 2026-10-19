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
    # queue.Queue exposes mutex/queue for a bounded, atomic coalescing
    # operation. GUI consumers still receive ordinary queue tuples.
    with inbox.mutex:
        queued = inbox.queue
        if not queued:
            # Consumer drained it while we waited for the mutex.
            queued.append(result)
            inbox.unfinished_tasks += 1
            inbox.not_empty.notify()
            return True
        if any(item[0] >= result[0] for item in queued):
            return False
        # Every queued response is older; retain only the newest completion.
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
