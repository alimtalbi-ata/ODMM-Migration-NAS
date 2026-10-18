import unittest, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_pagination_v22859 import paginate, sort_jobs

class PaginationTests(unittest.TestCase):
    def test_empty(self): self.assertEqual(paginate([]), ([], 0, 1))
    def test_first(self): self.assertEqual(paginate(list(range(450)))[0], list(range(200)))
    def test_last(self): self.assertEqual(len(paginate(list(range(450)), 2)[0]), 50)
    def test_clamp(self): self.assertEqual(paginate(list(range(2)), 99)[1], 0)
    def test_invalid(self):
        with self.assertRaises(ValueError): paginate([], size=0)
    def test_sort(self): self.assertEqual([r['id'] for r in sort_jobs([{'id':'z'}, {'id':'A'}])], ['A','z'])
    def test_immutable(self):
        original=[{'id':'z'},{'id':'a'}]
        sort_jobs(original)
        self.assertEqual(original[0]['id'], 'z')
if __name__ == '__main__': unittest.main()
