"""Conservative reachability report from explicit ODMM Python entrypoints.

Does not delete files; dynamic imports and shell/CI references require manual review.
"""
import argparse
import json
from collections import deque
from pathlib import Path

ENTRYPOINTS = (
    "odmm_windows_compact_v22811.py",
    "native_posix_migration.py",
    "odmm_operations_portal.py",
)


def report(inventory, entrypoints=ENTRYPOINTS):
    edges = inventory["local_imports"]
    modules = set(edges)
    roots = [x for x in entrypoints if x in modules]
    missing = sorted(set(entrypoints) - set(roots))
    queue = deque(roots)
    reached = set()
    while queue:
        name = queue.popleft()
        if name in reached:
            continue
        reached.add(name)
        for dependency in edges.get(name, []):
            dep_file = dependency + ".py"
            if dep_file in modules and dep_file not in reached:
                queue.append(dep_file)
    return {
        "schema_version": 1,
        "entrypoints": roots,
        "missing_entrypoints": missing,
        "statically_reachable": sorted(reached),
        "not_reachable_from_selected_entrypoints": sorted(modules - reached),
        "limitations": [
            "Entrypoints cover selected Windows Compact, POSIX prototype and operations portal only.",
            "Other Linux editions, dynamic imports, subprocesses and shell/build references are not modeled.",
            "Not reachable does NOT mean dead code. No deletion is authorized by this report."
        ]
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--inventory", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--entrypoint", action="append", default=[])
    a = p.parse_args()
    data = json.loads(a.inventory.read_text(encoding="utf-8"))
    result = report(data, tuple(a.entrypoint) if a.entrypoint else ENTRYPOINTS)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Selected entrypoints:", len(result["entrypoints"]))
    print("Statically reachable:", len(result["statically_reachable"]))
    print("Candidates requiring manual review:", len(result["not_reachable_from_selected_entrypoints"]))
    if result["missing_entrypoints"]:
        raise SystemExit("Missing selected entrypoints: " + ", ".join(result["missing_entrypoints"]))


if __name__ == "__main__":
    main()
