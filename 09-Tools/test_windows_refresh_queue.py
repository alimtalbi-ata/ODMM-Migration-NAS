import queue
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_refresh_service import fetch_into_queue

class RefreshWorkerTests(unittest.TestCase):
    def test_success(self):
        q = queue.Queue(maxsize=1)
        rows = [{"id": "a", "status": "RUNNING"}]
        self.assertTrue(fetch_into_queue(7, "endpoint", "token", q, fetcher=lambda a,b: rows))
        self.assertEqual(q.get_nowait(), (7, rows, None))

    def test_error_is_safe(self):
        q = queue.Queue(maxsize=1)
        def fail(a, b):
            raise ValueError("INVALID_TOKEN")
        self.assertTrue(fetch_into_queue(3, "endpoint", "token", q, fetcher=fail))
        rid, data, error = q.get_nowait()
        self.assertEqual(rid, 3)
        self.assertIsNone(data)
        self.assertNotIn("token", error.lower())

    def test_full_queue(self):
        q = queue.Queue(maxsize=1)
        q.put_nowait((1, [], None))
        self.assertTrue(fetch_into_queue(2, "endpoint", "token", q, fetcher=lambda a,b: []))
        self.assertEqual(q.get_nowait()[0], 2)
        q.task_done()
        q.join()

    def test_late_stale_worker_cannot_displace_newest(self):
        q = queue.Queue(maxsize=1)
        q.put_nowait((5, [], None))
        self.assertFalse(fetch_into_queue(4, "endpoint", "token", q, fetcher=lambda a,b: []))
        self.assertEqual(q.get_nowait()[0], 5)
        q.task_done()
        q.join()

    def test_multiple_stale_results_are_coalesced(self):
        q = queue.Queue(maxsize=3)
        for rid in (1, 2, 3):
            q.put_nowait((rid, [], None))
        self.assertTrue(fetch_into_queue(9, "endpoint", "token", q, fetcher=lambda a,b: []))
        self.assertEqual(q.qsize(), 1)
        self.assertEqual(q.get_nowait()[0], 9)
        q.task_done()
        q.join()

if __name__ == "__main__":
    unittest.main()
