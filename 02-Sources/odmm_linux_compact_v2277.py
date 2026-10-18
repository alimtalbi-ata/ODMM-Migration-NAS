"""Linux Compact — read-only local audit/remote jobs viewer; no datamover."""
import argparse
import json
from pathlib import Path
from odmm_compact_model_v2275 import filter_rows, summarize_rows
from odmm_editions_v2277 import EDITIONS

def main(argv=None):
    p = argparse.ArgumentParser(description=EDITIONS["linux-compact"]["name"])
    p.add_argument("--report", type=Path, help="Local JSON jobs report")
    p.add_argument("--origin", help="ODMM server HTTPS origin (or loopback HTTP)")
    p.add_argument("--token-env", default="ODMM_API_TOKEN", help="Environment variable holding API token")
    p.add_argument("--state", default="ALL", choices=sorted(("ALL", "PENDING", "RUNNING", "FAILED", "COMPLETED", "UNKNOWN")))
    p.add_argument("--search", default="")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    if bool(args.report) == bool(args.origin):
        p.error("Choose exactly one: --report or --origin")
    if args.report:
        content = json.loads(args.report.read_text(encoding="utf-8"))
        rows = content.get("items") if isinstance(content, dict) else content
        if not isinstance(rows, list):
            p.error("Report must be a JSON list or an object with items")
    else:
        import os
        from odmm_registry_client_v2267 import fetch_registry_jobs
        token = os.environ.get(args.token_env, "")
        if not token:
            p.error("Missing API token environment variable")
        rows = fetch_registry_jobs(args.origin, token)
    rows = filter_rows(rows, args.search, args.state)
    result = {"edition": EDITIONS["linux-compact"]["name"], "read_only": True, "summary": summarize_rows(rows), "jobs": rows}
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(result["edition"] + " | lecture seule")
        print("Jobs: %s | En cours: %s | Échecs: %s" % (result["summary"]["total"],result["summary"]["running"],result["summary"]["failed"]))
        for job in rows:
            print("%s  %s" % (job.get("status", "UNKNOWN"), job.get("id", "?")))
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
