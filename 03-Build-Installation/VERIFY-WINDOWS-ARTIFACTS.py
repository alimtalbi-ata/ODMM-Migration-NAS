"""Check compiled Windows artifacts; no claim of signing or native runtime qualification."""
import hashlib
import json
from pathlib import Path
import sys

def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def verify(root, version):
    root = Path(root)
    names = ("portable/ODMM-Compact.exe", f"installer/ODMM-Compact-Setup-V{version}.exe")
    result = {"qualified_on_windows": False, "artifacts": []}
    for name in names:
        path = root / name
        if not path.is_file() or path.stat().st_size < 1024:
            raise ValueError(f"Missing or empty artifact: {name}")
        with path.open("rb") as handle:
            if handle.read(2) != b"MZ":
                raise ValueError(f"Not a Windows PE artifact: {name}")
            handle.seek(0x3c)
            pe_offset = int.from_bytes(handle.read(4), "little")
            if pe_offset < 64 or pe_offset > path.stat().st_size - 24:
                raise ValueError(f"Invalid PE header offset: {name}")
            handle.seek(pe_offset)
            if handle.read(4) != b"PE\x00\x00":
                raise ValueError(f"Invalid PE signature: {name}")
        result["artifacts"].append({"file": name, "size": path.stat().st_size, "sha256": sha256_file(path)})
    (root / "SHA256-WINDOWS.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result

if __name__ == "__main__":
    try: verify(sys.argv[1], sys.argv[2])
    except (ValueError, OSError, IndexError) as exc:
        print(f"BUILD VERIFICATION FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
