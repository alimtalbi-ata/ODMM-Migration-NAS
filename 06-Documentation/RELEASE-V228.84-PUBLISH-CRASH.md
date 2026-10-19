# ODMM V228.84 — Real crash after target publication
Author: Abdelhalim Talbi

## Failure injection
The native POSIX engine publishes a destination with no-overwrite semantics,
fsyncs the target directory and retains a durable SQLite intent until the
file ledger commit. This release adds a spawned process which terminates
with os._exit(93) from the after_publish hook.

The parent process must observe:
1. Published target bytes remain readable.
2. Exactly one pending intent and zero committed file records.
3. Retrying copy is refused (no blind overwrite).
4. Reconciliation without operator confirmation is refused.
5. Reconciliation with explicit operator confirmation verifies source/target,
   commits the ledger, clears the intent, and leaves cutover unauthorized.
6. SQLite integrity_check reports ok.

Run on Linux:
`PYTHONPATH=02-Sources python -m unittest discover -s 02-Sources -p 'test_native_sqlite_commit_crash_v22831.py' -v`

## Operational limits
This is a controlled POSIX fault-injection test on temporary local directories.
It is not proof of durability across power loss on any NAS array, of NFS/SMB
protocol semantics, of ACL/ADS preservation, or of an authorized cutover.
No screenshots are claimed. CI results are execution evidence only when green.

## Next priorities
V228.85: signed artifact provenance, SBOM, dependency locks.
V228.86: UI connection state machine and actual Windows screenshots.
V228.87: vendor simulator and protocol qualification fixtures.
