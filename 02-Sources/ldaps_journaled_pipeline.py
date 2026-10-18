"""Explicit LDAPS sync attempt logging; failures fail closed, not cutover authority.

Important: import and journal commits are separate transactions. A successful
import followed by journal failure raises JOURNAL_WRITE_FAILED; the caller must
reconcile before retrying. This is not a distributed atomic transaction.
"""
import re
from ldaps_directory_pipeline import import_ldaps_directory
from directory_sync_journal import DirectorySyncJournal

class JournaledPipelineError(ValueError):
    pass

def _failure_type(error):
    s=(type(error).__name__+' '+str(error)).upper()
    if 'TLS' in s or 'CERTIFICATE' in s: return 'TLS_FAILURE'
    if 'PAGE' in s or 'COOKIE' in s or 'PAGINATION' in s: return 'PAGINATION_FAILURE'
    if 'NETWORK' in s or 'TIMEOUT' in s or 'SOCKET' in s or 'CONNECT' in s: return 'NETWORK_FAILURE'
    return 'IMPORT_FAILURE'

def sync_and_record(ledger, *, event_id, now, journal=None, **kwargs):
    """Record each attempted import, including failures, with monotonic event times.

    Caller owns event_id and timestamp uniqueness; no automatic retries.
    """
    if not isinstance(event_id,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',event_id):
        raise JournaledPipelineError('INVALID_EVENT_ID')
    if type(now) is not int or now < 0:
        raise JournaledPipelineError('INVALID_TIME')
    journal = journal if journal is not None else DirectorySyncJournal(ledger.db)
    # Validate existing journal before initiating any external network I/O.
    journal.verify()
    if ledger.db.execute('SELECT 1 FROM directory_sync_events WHERE event_id=?',(event_id,)).fetchone():
        raise JournaledPipelineError('DUPLICATE_EVENT_ID')
    latest=ledger.db.execute('SELECT MAX(at) FROM directory_sync_events').fetchone()[0]
    if latest is not None and now<=latest:
        raise JournaledPipelineError('NON_MONOTONIC_TIME')
    try:
        outcome=import_ldaps_directory(ledger,now=now,**kwargs)
    except Exception as error:
        try:
            journal.append(event_id,now,_failure_type(error))
        except Exception as log_error:
            raise JournaledPipelineError('IMPORT_FAILED_AND_JOURNAL_FAILED') from log_error
        raise
    try:
        event=journal.append(event_id,now,'SUCCESS',outcome['sha256'])
    except Exception as error:
        raise JournaledPipelineError('IMPORT_COMMITTED_JOURNAL_FAILED_RECONCILIATION_REQUIRED') from error
    return {**outcome,'journal_event':event,'cutover_authorized':False}
