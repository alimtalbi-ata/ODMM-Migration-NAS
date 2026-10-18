"""LDAPS success sync/quarantine/journal committed atomically in one SQLite transaction.

Network collection occurs before SQLite lock. Failure observations are logged
separately because no successful directory import exists to roll back.
"""
from ldaps_directory_pipeline import import_ldaps_directory
from directory_sync_journal import DirectorySyncJournal
from ldaps_journaled_pipeline import JournaledPipelineError, _failure_type

class _TransactionBoundLedger:
    def __init__(self, ledger): self.ledger=ledger
    def synchronize_and_quarantine(self, export, **kwargs):
        return self.ledger.synchronize_and_quarantine(export, _within_transaction=True, **kwargs)

def sync_atomically(ledger, *, event_id, now, journal=None, **kwargs):
    from ldaps_journaled_pipeline import re
    if not isinstance(event_id,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',event_id):
        raise JournaledPipelineError('INVALID_EVENT_ID')
    if type(now) is not int or now < 0: raise JournaledPipelineError('INVALID_TIME')
    journal = journal if journal is not None else DirectorySyncJournal(ledger.db)
    journal.verify()
    if ledger.db.execute('SELECT 1 FROM directory_sync_events WHERE event_id=?',(event_id,)).fetchone():
        raise JournaledPipelineError('DUPLICATE_EVENT_ID')
    latest=ledger.db.execute('SELECT MAX(at) FROM directory_sync_events').fetchone()[0]
    if latest is not None and now<=latest: raise JournaledPipelineError('NON_MONOTONIC_TIME')
    # Collect network evidence first, then acquire one database write transaction.
    # A wrapper suppresses nested BEGIN/COMMIT in the existing directory importer.
    # Failures during collection are logged separately; successful imports are atomic.
    class CollectorFailed(Exception): pass
    called=False
    def wrapped_collector(**kw):
        nonlocal called
        called=True
        return kwargs.get('collector', _default_collector)(**kw)
    from ldap_tls_client import collect_ldaps_snapshot as _default_collector
    try:
        snapshot=wrapped_collector(**{k:kwargs[k] for k in ('endpoint','base_dn','version','bind_dn','password','ca_file','timeout','page_size','max_pages','ldap_module') if k in kwargs})
    except Exception as exc:
        journal.append(event_id,now,_failure_type(exc))
        raise
    # Recheck all journal invariants under the same SQLite write lock.
    try:
        ledger.db.execute('BEGIN IMMEDIATE')
        journal._verify_locked()
        if ledger.db.execute('SELECT 1 FROM directory_sync_events WHERE event_id=?',(event_id,)).fetchone():
            raise JournaledPipelineError('DUPLICATE_EVENT_ID')
        latest=ledger.db.execute('SELECT MAX(at) FROM directory_sync_events').fetchone()[0]
        if latest is not None and now<=latest: raise JournaledPipelineError('NON_MONOTONIC_TIME')
        outcome=import_ldaps_directory(_TransactionBoundLedger(ledger), **{k:v for k,v in kwargs.items() if k!='collector'},now=now,collector=lambda **kw:snapshot)
        event=journal.append(event_id,now,'SUCCESS',outcome['sha256'],_within_transaction=True)
        ledger.db.execute('COMMIT')
        return {**outcome,'journal_event':event,'cutover_authorized':False}
    except BaseException:
        if ledger.db.in_transaction: ledger.db.execute('ROLLBACK')
        raise
