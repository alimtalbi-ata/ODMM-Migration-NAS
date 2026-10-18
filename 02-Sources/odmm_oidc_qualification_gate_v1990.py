"""ODMM V199.0 reproducible offline OIDC qualification gate.
Author: Abdelhalim Talbi. No production writes or network access.
"""
import argparse
import datetime as dt
import hashlib
import json
import pathlib
import subprocess
import sys

SUITES = (
    "test_odmm_oidc_http_integration_v1989",
    "test_odmm_oidc_live_probe_v1987",
    "test_odmm_oidc_lab_v1988",
    "test_odmm_oidc_concurrency_v1984",
    "test_odmm_oidc_restart_fault_v1986",
    "test_odmm_oidc_csrf_binding_v1983",
    "test_odmm_oidc_rotation_outage_v1992",
    "test_odmm_oidc_jwks_health_v1993",
    "test_odmm_oidc_provider_health_v1994",
    "test_odmm_oidc_health_history_v1995",
    "test_odmm_oidc_portal_v1996",
    "test_odmm_oidc_sqlite_fault_v1991",
    "test_odmm_oidc_alerts_v1997",
    "test_odmm_oidc_timeline_v1998",
    "test_odmm_oidc_connection_lifecycle_v1999",
    "test_odmm_oidc_sqlite_audit_v2000",
    "test_odmm_sqlite_inventory_v2001",
)
def run_gate(root, *, suites=SUITES, timeout=90, runner=None):
    root = pathlib.Path(root).resolve()
    runner = runner or subprocess.run
    results = []
    for name in suites:
        if not name.startswith("test_odmm_") or not name.replace("_","").isalnum():
            raise ValueError("INVALID_TEST_SUITE")
        cmd=[sys.executable,"-m","unittest","-q",name]
        try:
            done=runner(cmd,cwd=str(root),capture_output=True,text=True,timeout=timeout)
            status="PASS" if done.returncode == 0 else "FAIL"
            output=(done.stdout or "")+"\n"+(done.stderr or "")
            count=next((line for line in output.splitlines() if line.startswith("Ran ") and " tests " in line),None)
            result={"suite":name,"status":status,"returncode":done.returncode,"test_count_line":count,
                    "output_sha256":hashlib.sha256(output.encode()).hexdigest(),
                    "output_tail":output[-1200:]}
        except subprocess.TimeoutExpired:
            result={"suite":name,"status":"TIMEOUT","returncode":None,"test_count_line":None}
        results.append(result)
    return {
        "version":"200.1","compact_version":"5.1.1","author":"Abdelhalim Talbi",
        "generated_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
        "status":"PASS_OFFLINE_ONLY" if all(x["status"]=="PASS" for x in results) else "FAIL",
        "production_qualified":False,
        "keycloak_live_tested":False,
        "native_engine_modified":False,
        "results":results,
        "outstanding":["Real Keycloak TLS/PKCE/JWT integration","JWKS rotation under live sessions",
                       "Provider outage and recovery","Review remaining SQLite connection callsites across all subsystems"]
    }
def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",required=True)
    parser.add_argument("--timeout",type=int,default=90)
    args=parser.parse_args(argv)
    if args.timeout < 1 or args.timeout > 600:
        parser.error("timeout must be between 1 and 600")
    report=run_gate(pathlib.Path(__file__).parent,timeout=args.timeout)
    path=pathlib.Path(args.output)
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"status":report["status"],"report":str(path),"suites":len(report["results"])},sort_keys=True))
    return 0 if report["status"]=="PASS_OFFLINE_ONLY" else 1
if __name__=="__main__":
    raise SystemExit(main())
