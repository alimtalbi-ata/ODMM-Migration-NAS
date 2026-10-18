"""Validate required build inputs without importing UI or contacting services."""
import ast
import json
from pathlib import Path
import sys

REQUIRED = ["02-Sources/odmm_windows_compact_v22811.py", "02-Sources/odmm_connection_diagnostics_v22851.py", "03-Build-Installation/ODMM-COMPACT-WINDOWS.iss", "03-Build-Installation/WINDOWS-BUILD-REQUIREMENTS.txt"]
def check(root):
    root = Path(root)
    errors = []
    for name in REQUIRED:
        path = root / name
        if not path.is_file():
            errors.append("Missing: " + name)
        elif name.endswith(".py"):
            try: ast.parse(path.read_text(encoding="utf-8-sig"), filename=name)
            except (SyntaxError, UnicodeError) as exc: errors.append("Invalid Python: " + name + ": " + str(exc))
    result = {"status": "PASS" if not errors else "FAIL", "checked": REQUIRED, "errors": errors}
    print(json.dumps(result, indent=2))
    return not errors
if __name__ == "__main__":
    sys.exit(0 if check(sys.argv[1] if len(sys.argv)>1 else Path(__file__).resolve().parent.parent) else 1)
