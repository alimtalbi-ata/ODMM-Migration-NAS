import importlib.util
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("delivery", Path(__file__).with_name("VERIFY-DELIVERY-MANIFEST.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ManifestTests(unittest.TestCase):
    def make_archive(self, filename="file.txt", value=b"hello", digest=None):
        tmp = tempfile.TemporaryDirectory()
        path = Path(tmp.name) / "sample.zip"
        with zipfile.ZipFile(path, "w") as z:
            z.writestr(filename, value)
            z.writestr("DELIVERY-MANIFEST.json", json.dumps({"files": {filename: digest or hashlib.sha256(value).hexdigest()}}))
        return tmp, path

    def test_valid(self):
        tmp, path = self.make_archive()
        with tmp:
            self.assertEqual(module.verify(path)["status"], "PASS")

    def test_bad_digest(self):
        tmp, path = self.make_archive(digest="0" * 64)
        with tmp, self.assertRaisesRegex(ValueError, "hash mismatch"):
            module.verify(path)

    def test_unsafe_path(self):
        tmp, path = self.make_archive(filename="../escape.txt")
        with tmp, self.assertRaisesRegex(ValueError, "unsafe ZIP path"):
            module.verify(path)


if __name__ == "__main__":
    unittest.main()
