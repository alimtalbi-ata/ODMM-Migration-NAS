"""Record artifact build success only after verifier has produced checksums."""
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

def write_status(folder, version):
    folder = Path(folder)
    manifest = json.loads((folder / "SHA256-WINDOWS.json").read_text(encoding="utf-8"))
    if len(manifest.get("artifacts", [])) != 2:
        raise ValueError("Both verified artifacts are required")
    status = {"version": version, "build": "completed", "built_at_utc": datetime.now(timezone.utc).isoformat(), "native_windows_runtime_qualified": False, "artifacts": manifest["artifacts"]}
    (folder / "BUILD-STATUS.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
    return status

if __name__ == "__main__":
    write_status(sys.argv[1], sys.argv[2])
