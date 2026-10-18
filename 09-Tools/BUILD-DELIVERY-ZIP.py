"""Build deterministic source ZIP from a checked-out Git commit.

Uses 'git ls-files' so untracked files are excluded. Produces a manifest
with SHA256 for each file, source commit and provenance.
"""
import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def build(root, output):
    root = root.resolve()
    output = output.resolve()
    commit = git(root, "rev-parse", "HEAD")
    if git(root, "status", "--porcelain"):
        raise ValueError("Refusing to package a dirty checkout")
    files = sorted(git(root, "ls-files", "-z").split("\0"))
    files = [x for x in files if x and x != "DELIVERY-MANIFEST.json"]
    digests = {}
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name in files:
            path = root / name
            if not path.is_file() or path.is_symlink():
                raise ValueError("Missing or symlinked tracked file: " + name)
            data = path.read_bytes()
            digests[name] = hashlib.sha256(data).hexdigest()
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
        manifest = {
            "schema_version": 1,
            "source_type": "git-checkout",
            "source_commit": commit,
            "files": digests,
            "note": "Source ZIP only. Windows executables are separate CI artifacts."
        }
        info = zipfile.ZipInfo("DELIVERY-MANIFEST.json", (1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        archive.writestr(info, json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"archive": str(output), "commit": commit, "files": len(files)}))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    build(a.root, a.output)


if __name__ == "__main__":
    main()
