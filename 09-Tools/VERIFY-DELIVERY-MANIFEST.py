"""Verify ODMM ZIP delivery manifest against archive bytes (no extraction).

Usage: python 09-Tools/VERIFY-DELIVERY-MANIFEST.py package.zip
Manifest must be embedded at DELIVERY-MANIFEST.json, with per-file SHA256.
The manifest itself is excluded from the file hash listing.
"""
import argparse
import hashlib
import json
import zipfile
from pathlib import PurePosixPath


def verify(archive):
    with zipfile.ZipFile(archive) as z:
        members = [i for i in z.infolist() if not i.is_dir()]
        names = [i.filename for i in members]
        if len(names) != len(set(names)):
            raise ValueError("duplicate ZIP entries")
        for name in names:
            p = PurePosixPath(name)
            if p.is_absolute() or ".." in p.parts or "\\" in name:
                raise ValueError("unsafe ZIP path: " + name)
        manifest = json.loads(z.read("DELIVERY-MANIFEST.json"))
        expected = manifest["files"]
        if set(expected) != set(names) - {"DELIVERY-MANIFEST.json"}:
            raise ValueError("manifest file set does not match ZIP")
        for name, digest in expected.items():
            if hashlib.sha256(z.read(name)).hexdigest() != digest:
                raise ValueError("hash mismatch: " + name)
        return {"status": "PASS", "files": len(expected), "source_commit": manifest.get("source_commit"), "source_type": manifest.get("source_type")}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    args = parser.parse_args()
    print(json.dumps(verify(args.archive), ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
