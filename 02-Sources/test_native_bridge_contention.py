"""V191.4 multiprocess WAL stress: committed key rotations and read-only verification."""
import multiprocessing as mp
import sqlite3
import time
import unittest
from native_bridge_consistency import verify_bridge_snapshot
from test_native_audit_bridge import BridgeTests, OLD, NEW

KEY2=b'R'*32
KEY3=b'S'*32
KEYS={'k1':NEW,'k2':KEY2,'k3':KEY3}


def _rotator(path, start, queue):
    from native_segmented_audit import rotate
    try:
        start.wait(10)
        db=sqlite3.connect(path, timeout=10, isolation_level=None)
        db.execute('PRAGMA busy_timeout=10000')
        active={'k1':NEW}
        for key_id,key in [('k2',KEY2),('k3',KEY3)]:
            db.execute('BEGIN IMMEDIATE')
            try:
                rotate(db, active, key_id, key)
                db.execute('COMMIT')
                active[key_id]=key
            except BaseException:
                db.execute('ROLLBACK'); raise
        db.close()
        queue.put(('writer','OK'))
    except BaseException as exc:
        queue.put(('writer','ERROR:'+repr(exc)))


def _reader(path, start, queue, count):
    try:
        start.wait(10)
        durations=[]
        for _ in range(count):
            t=time.monotonic()
            result=verify_bridge_snapshot(path, legacy_key=OLD, segment_keys=KEYS)
            assert result['status']=='CONSISTENT'
            durations.append(time.monotonic()-t)
        queue.put(('reader',len(durations),max(durations)))
    except BaseException as exc:
        queue.put(('reader','ERROR:'+repr(exc)))


class ContentiousAuditTests(BridgeTests):
    def test_three_readers_during_two_committed_rotations(self):
        self.activate()
        ctx=mp.get_context('spawn'); start=ctx.Event(); q=ctx.Queue()
        processes=[ctx.Process(target=_rotator,args=(str(self.t.db),start,q))]
        processes += [ctx.Process(target=_reader,args=(str(self.t.db),start,q,12)) for _ in range(3)]
        for p in processes: p.start()
        try:
            start.set()
            results=[q.get(timeout=30) for _ in processes]
        finally:
            for p in processes:
                p.join(10)
                if p.is_alive(): p.terminate(); p.join()
        self.assertTrue(all(p.exitcode==0 for p in processes),results)
        self.assertEqual(len([r for r in results if r[0]=='reader' and r[1]==12]),3,results)
        self.assertIn(('writer','OK'),results)
        from native_segmented_audit import verify
        self.assertEqual(verify(self.engine.db,KEYS)['segments'],3)
        self.assertEqual(verify_bridge_snapshot(self.t.db,legacy_key=OLD,segment_keys=KEYS)['status'],'CONSISTENT')

if __name__=='__main__': unittest.main()
