"""OIDC provider health state machine; read-only, no authentication or migration writes.
Author: Abdelhalim Talbi.
"""
import argparse
import json
import time
from odmm_oidc_live_probe import qualify, fetch_json

class ProviderHealth:
    """Explicit state transitions; only discovery/JWKS tested, not login availability."""
    def __init__(self, issuer, fetch=fetch_json, clock=time.monotonic, failure_threshold=2, recovery_threshold=2):
        if failure_threshold < 1 or recovery_threshold < 1:
            raise ValueError("INVALID_THRESHOLD")
        self.issuer, self.fetch, self.clock = issuer, fetch, clock
        self.failure_threshold, self.recovery_threshold = failure_threshold, recovery_threshold
        self.state, self.failures, self.successes = "UNKNOWN", 0, 0
        self.last_latency_ms = None
    def check(self):
        start=self.clock()
        try:
            details=qualify(self.issuer, fetch=self.fetch)
            ok=True
        except (ValueError, OSError, TimeoutError, json.JSONDecodeError) as exc:
            ok=False
            details={"error_type":type(exc).__name__}
        self.last_latency_ms=round(max(0,self.clock()-start)*1000,2)
        if ok:
            self.failures=0
            self.successes+=1
            if self.successes>=self.recovery_threshold:
                self.state="AVAILABLE"
            elif self.state in ("UNKNOWN","UNAVAILABLE"):
                self.state="RECOVERING"
        else:
            self.successes=0
            self.failures+=1
            if self.failures>=self.failure_threshold:
                self.state="UNAVAILABLE"
            elif self.state in ("UNKNOWN","AVAILABLE"):
                self.state="DEGRADED"
        return {"state":self.state,"discovery_jwks_ok":ok,"latency_ms":self.last_latency_ms,
                "consecutive_failures":self.failures,"consecutive_successes":self.successes,
                "authentication_flow_tested":False,"production_qualified":False,"details":details}

def main(argv=None):
    p=argparse.ArgumentParser(description="Opt-in live read-only OIDC discovery/JWKS health")
    p.add_argument("--issuer",required=True)
    p.add_argument("--output",required=True)
    p.add_argument("--checks",type=int,default=2)
    p.add_argument("--interval",type=float,default=1)
    a=p.parse_args(argv)
    if not 1<=a.checks<=20 or not 0<=a.interval<=60:
        p.error("invalid checks/interval")
    health=ProviderHealth(a.issuer)
    observations=[]
    for n in range(a.checks):
        observations.append(health.check())
        if n<a.checks-1:time.sleep(a.interval)
    from pathlib import Path
    path=Path(a.output);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps({"author":"Abdelhalim Talbi","version":"199.4","checks":observations,
      "scope":"OIDC discovery/JWKS only","production_qualified":False},indent=2)+"\n")
    print(json.dumps({"state":health.state,"report":str(path),"checks":len(observations)}))
    return 0 if health.state=="AVAILABLE" else 2
if __name__=="__main__":raise SystemExit(main())
