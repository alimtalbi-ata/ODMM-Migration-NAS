import unittest
from benchmark_verification_v22837 import benchmark, hash_file
from pathlib import Path
from tempfile import TemporaryDirectory

class BenchmarkVerificationTests(unittest.TestCase):
    def test_known_digest(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / 'x'
            path.write_bytes(b'abc')
            self.assertEqual(hash_file(path), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    def test_small_benchmark(self):
        result = benchmark((4096,), 2)
        self.assertEqual(result['rows'][0]['repeats'], 2)
        self.assertGreater(result['rows'][0]['double_pass_median_ms'], 0)

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            benchmark((0,), 1)
        with self.assertRaises(ValueError):
            benchmark((4096,), 0)

if __name__ == '__main__':
    unittest.main()
