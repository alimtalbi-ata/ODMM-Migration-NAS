"""Read-only pinned JWKS health probe; no remote network or migration writes.
Author: Abdelhalim Talbi.
"""
import argparse
import hashlib
import json
from pathlib import Path
from odmm_oidc_hot_reload import ReloadingOIDCVerifier

def inspect(*,issuer,audience,jwks_path):
    """Fail-closed local trust-material check; never include public key material in report."""
    path=Path(jwks_path)
    try:
        verifier=ReloadingOIDCVerifier(issuer=issuer,audience=audience,jwks_path=path)
        raw=verifier._read()
        document=json.loads(raw)
        kids=[key.get('kid') for key in document['keys']]
        if any(not isinstance(k,str) or not k for k in kids) or len(set(kids))!=len(kids):
            raise ValueError('INVALID_OR_DUPLICATE_KID')
        return {'status':'HEALTHY_LOCAL_JWKS','keys':len(kids),'kids_sha256':hashlib.sha256(json.dumps(sorted(kids)).encode()).hexdigest(),
                'file_sha256':hashlib.sha256(raw).hexdigest(),'production_qualified':False,
                'provider_reachable':None,'native_engine_modified':False}
    except Exception as exc:
        return {'status':'UNHEALTHY_LOCAL_JWKS','error_code':type(exc).__name__,
                'production_qualified':False,'provider_reachable':None,'native_engine_modified':False}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--issuer',required=True)
    parser.add_argument('--audience',required=True)
    parser.add_argument('--jwks-path',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    report=inspect(issuer=args.issuer,audience=args.audience,jwks_path=args.jwks_path)
    output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(report['status'])
    return 0 if report['status']=='HEALTHY_LOCAL_JWKS' else 2
if __name__=='__main__':raise SystemExit(main())
