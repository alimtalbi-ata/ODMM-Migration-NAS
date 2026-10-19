import queue
import threading
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

    def test_out_of_order_completion_keeps_newest(self):
        q = queue.Queue(maxsize=1)
        self.assertTrue(fetch_into_queue(12, "endpoint", "token", q, fetcher=lambda a,b: []))
        self.assertFalse(fetch_into_queue(11, "endpoint", "token", q, fetcher=lambda a,b: []))
        self.assertTrue(fetch_into_queue(13, "endpoint", "token", q, fetcher=lambda a,b: []))
        self.assertEqual(q.get_nowait()[0], 13)
        q.task_done()
        q.join()

    def test_concurrent_producers_never_lose_highest_request(self):
        q = queue.Queue(maxsize=1)
        q.put_nowait((0, [], None))
        barrier = threading.Barrier(9)
        workers = []
        for rid in range(1, 9):
            def run(request_id=rid):
                barrier.wait()
                fetch_into_queue(request_id, "endpoint", "token", q,
                                 fetcher=lambda a, b: [])
            thread = threading.Thread(target=run)
            workers.append(thread)
            thread.start()
        barrier.wait()
        for thread in workers:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive(), "Refresh producer deadlocked")
        self.assertEqual(q.qsize(), 1)
        self.assertEqual(q.get_nowait()[0], 8)
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
