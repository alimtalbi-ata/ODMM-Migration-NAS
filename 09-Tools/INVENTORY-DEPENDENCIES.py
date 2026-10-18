"""Static, non-destructive Python import inventory for ODMM cumulative source tree.

Outputs a deterministic JSON report. Missing imports are candidates for review,
not proof of dead code: dynamic imports, CLI entrypoints and plugins may exist.
"""
import argparse
import ast
import json
from collections import defaultdict
from pathlib import Path


def scan(root: Path) -> dict:
    root = root.resolve()
    source = root / "02-Sources"
    files = sorted(source.glob("*.py"))
    names = {p.stem for p in files}
    imports = {}
    parse_errors = {}
    unresolved = {}
    reverse = defaultdict(list)
    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        except (SyntaxError, UnicodeError, OSError) as exc:
            parse_errors[path.name] = str(exc)
            continue
        deps = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                deps.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                deps.add(node.module.split(".")[0])
        local = sorted(deps & names)
        imports[path.name] = local
        for dep in local:
            reverse[dep].append(path.name)
        # Imports outside the source directory may be stdlib or third party.
        unresolved[path.name] = sorted(deps - names)
    return {
        "schema_version": 1,
        "scope": "02-Sources/*.py (top-level files only)",
        "source_count": len(files),
        "parsed_count": len(imports),
        "parse_errors": dict(sorted(parse_errors.items())),
        "local_imports": imports,
        "reverse_local_imports": {k: sorted(v) for k, v in sorted(reverse.items())},
        "no_static_inbound_imports": sorted(p.name for p in files if p.stem not in reverse),
        "external_or_stdlib_imports": unresolved,
        "limitations": [
            "No static inbound import does not imply unused code.",
            "Dynamic imports, importlib, subprocess, entrypoints, plugins and non-Python references are not resolved.",
            "Only top-level Python files in 02-Sources are scanned.",
            "Do not delete or move modules based solely on this report."
        ]
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = scan(args.root)
    data = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(data, encoding="utf-8")
    else:
        print(data)
    if report["parse_errors"]:
        raise SystemExit(f"{len(report['parse_errors'])} Python syntax/read errors; see report")


if __name__ == "__main__":
    main()
