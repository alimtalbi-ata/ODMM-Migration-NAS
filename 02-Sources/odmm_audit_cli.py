"""Read-only code inventory CLI; does not perform migration."""
import argparse, ast, json
from pathlib import Path

def inventory(root):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("SOURCE_ROOT_NOT_FOUND")
    modules = sorted(root.glob("*.py"))
    errors = []
    for file in modules:
        try:
            ast.parse(file.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeError) as exc:
            errors.append({"module": file.name, "error": type(exc).__name__})
    return {"modules": len([p for p in modules if not p.name.startswith("test_")]),
            "test_modules": len([p for p in modules if p.name.startswith("test_")]),
            "syntax_errors": errors, "production_qualified": False}

def main(argv=None):
    parser = argparse.ArgumentParser(description="ODMM read-only source inventory")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent))
    args = parser.parse_args(argv)
    print(json.dumps(inventory(args.root), sort_keys=True, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
