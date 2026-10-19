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

    def test_full_queue(self):
        q = queue.Queue(maxsize=1)
        q.put_nowait((1, [], None))
        self.assertFalse(fetch_into_queue(2, "endpoint", "token", q, fetcher=lambda a,b: []))
        self.assertEqual(q.get_nowait()[0], 1)

if __name__ == "__main__":
    unittest.main()
