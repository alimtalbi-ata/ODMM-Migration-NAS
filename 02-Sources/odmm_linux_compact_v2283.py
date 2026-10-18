"""Linux Compact — read-only local audit/remote jobs viewer; no datamover."""
import argparse
import json
from pathlib import Path
from odmm_compact_dashboard_v2280 import dashboard
from odmm_editions_v2283 import EDITIONS
from odmm_job_detail_v2279 import select_job
from odmm_job_triage_v2280 import triage_job, triage_lines
from odmm_attention_v2281 import attention_summary

def main(argv=None):
    p = argparse.ArgumentParser(description=EDITIONS["linux-compact"]["name"])
    p.add_argument("--report", type=Path, help="Local JSON jobs report")
    p.add_argument("--origin", help="ODMM server HTTPS origin (or loopback HTTP)")
    p.add_argument("--token-env", default="ODMM_API_TOKEN", help="Environment variable holding API token")
    p.add_argument("--state", default="ALL", choices=sorted(("ALL", "PENDING", "RUNNING", "FAILED", "COMPLETED", "UNKNOWN")))
    p.add_argument("--search", default="")
    p.add_argument("--json", action="store_true")
    p.add_argument("--job-id", help="Afficher la fiche détaillée d’un job unique")
    p.add_argument("--attention", action="store_true", help="Afficher uniquement les jobs en échec ou d’état inconnu")
    p.add_argument("--health", action="store_true", help="Afficher la qualité des données et les alertes sans certifier la migration")
    args = p.parse_args(argv)
    if bool(args.report) == bool(args.origin):
        p.error("Choose exactly one: --report or --origin")
    if args.report:
        try:
            content = json.loads(args.report.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            p.error("Cannot read valid UTF-8 JSON report (path, permissions or syntax)")
        rows = content.get("items") if isinstance(content, dict) else content
        if not isinstance(rows, list):
            p.error("Report must be a JSON list or an object with items")
    else:
        import os
        from odmm_registry_client_v2267 import fetch_registry_jobs
        token = os.environ.get(args.token_env, "")
        if not token:
            p.error("Missing API token environment variable")
        try:
            rows = fetch_registry_jobs(args.origin, token)
        except Exception as exc:
            p.error("Server consultation failed: " + type(exc).__name__)
    try:
        view = dashboard(rows, args.search, args.state)
    except (ValueError, TypeError):
        p.error("Invalid job registry payload")
    if args.attention:
        view["jobs"] = attention_summary(view["jobs"])["jobs"]
        from odmm_compact_model_v2275 import summarize_rows
        view["visible"] = summarize_rows(view["jobs"])
    from odmm_health_v2283 import assess
    health = assess(rows)
    result = {"health": health, "attention": attention_summary(rows), "edition": EDITIONS["linux-compact"]["name"], "read_only": True, "summary": view["visible"], "global_summary": view["total"], "metrics_available": False, "jobs": view["jobs"]}
    if args.job_id:
        try:
            result["triage"] = triage_job(select_job(rows, args.job_id)["fields"])
            result["detail"] = result["triage"]["detail"]
        except ValueError as exc:
            p.error(str(exc))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(result["edition"] + " | lecture seule")
        if args.health: print("Supervision : %s | Doublons : %s | IDs absents : %s | États invalides : %s" % (health["level"], len(health["duplicate_ids"]), health["missing_ids"], health["invalid_states"]))
        print("Jobs: %s | En cours: %s | Échecs: %s" % (result["summary"]["total"],result["summary"]["running"],result["summary"]["failed"]))
        if args.job_id:
            print("\n".join(triage_lines(result["triage"])))
        else:
            for job in result["jobs"]:
                print("%s  %s" % (job.get("status", "UNKNOWN"), job.get("id", "?")))
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
