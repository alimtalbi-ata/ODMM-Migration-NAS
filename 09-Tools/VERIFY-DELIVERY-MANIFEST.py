"""Verify ODMM ZIP delivery manifest against archive bytes (no extraction).

Usage: python 09-Tools/VERIFY-DELIVERY-MANIFEST.py package.zip
Manifest must be embedded at DELIVERY-MANIFEST.json, with per-file SHA256.
The manifest itself is excluded from the file hash listing.
"""
import argparse
import hashlib
import json
import zipfile
import re
from pathlib import PurePosixPath


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON key")
        obj[key] = value
    return obj


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
        manifest = json.loads(z.read("DELIVERY-MANIFEST.json"), object_pairs_hook=_unique_object)
        if manifest.get("schema_version") != 1 or not isinstance(manifest.get("files"), dict):
            raise ValueError("unsupported or invalid manifest")
        expected = manifest["files"]
        if set(expected) != set(names) - {"DELIVERY-MANIFEST.json"}:
            raise ValueError("manifest file set does not match ZIP")
        for name, digest in expected.items():
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise ValueError("invalid SHA-256 digest: " + name)
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
