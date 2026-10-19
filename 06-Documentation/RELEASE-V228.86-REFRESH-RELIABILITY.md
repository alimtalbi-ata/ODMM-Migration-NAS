# ODMM V228.86 — Read-only refresh concurrency reliability
Author: Abdelhalim Talbi

## Root cause and correction
Previously, _publish() attempted Queue.put_nowait() before comparing request
generation IDs. When the queue had free capacity, a late stale worker could
append an obsolete result after a newer one. The bounded queue did not by
itself enforce freshness.

V228.86 uses Queue.mutex for a single atomic compare/coalesce/publish
transaction. Older/equal pending generations cannot evict a newer pending
result; newer generations replace stale pending items even when capacity is
available. Queue.unfinished_tasks is adjusted for discarded *pending* items,
so Queue.join() does not hang. Consumers already holding an item are not
modified; the GUI must still reject stale generations on application.

## Regression coverage
- Non-full queue, newer result then late older result.
- Non-full queue, several pending results then newest replacement.
- Full queue replacement and late completion.
- Eight concurrent producer threads.
- Queue.task_done() and join() accounting.

## Scope and limits
Windows Compact remains read-only supervision. These tests prove deterministic
queue logic, not a full GUI interaction/screenshot audit. CI success is
required before calling the Windows package qualified.

## Next architectural milestones
V228.87: connection timeout/cancellation and explicit UI state machine.
V228.88: accessibility and genuine Windows UI snapshots.
V228.89: vendor NAS compatibility matrix and effective ACL tests.
