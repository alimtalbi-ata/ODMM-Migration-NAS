"""Windows Compact refresh service: no Tk dependency, no secret logging.

This module only reads registry jobs and puts results on a queue. UI state
updates remain on the Tk main thread. It never executes migrations.
"""
from odmm_connection_diagnostics_v22851 import explain_connection_failure
from odmm_registry_client_v2267 import fetch_registry_jobs


def fetch_into_queue(request_id, endpoint, token, inbox, fetcher=None):
    """Fetch a registry snapshot and publish one result to the UI queue.

    Errors are converted to credential-safe diagnostics. A caller may inject a
    fetcher in tests; production defaults to the existing registry client.
    """
    fetch = fetch_registry_jobs if fetcher is None else fetcher
    try:
        data = fetch(endpoint, token)
        inbox.put((request_id, data, None))
    except Exception as exc:
        inbox.put((request_id, None, explain_connection_failure(exc)))
