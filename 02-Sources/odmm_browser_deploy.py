"""Explicit opt-in browser entrypoint. Must run behind trusted HTTPS reverse proxy."""
import json
import os
from pathlib import Path
from odmm_secure_deploy import validate_deployment
from odmm_oidc_verifier import OIDCVerifier
from odmm_oidc_browser import BrowserOIDCConfig, create_browser_app
from odmm_oidc_session_store import SQLiteOIDCStore

def create_from_environment():
    required=('ODMM_REGISTRY_DB','ODMM_GRANTS_DB','ODMM_OIDC_JWKS_PATH','ODMM_OIDC_ISSUER',
              'ODMM_OIDC_AUDIENCE','ODMM_OIDC_AUTHORIZATION_ENDPOINT','ODMM_OIDC_TOKEN_ENDPOINT',
              'ODMM_OIDC_CLIENT_ID','ODMM_PUBLIC_ORIGIN','ODMM_OIDC_REDIRECT_URI','ODMM_SESSION_DB')
    missing=[k for k in required if not os.environ.get(k)]
    if missing: raise RuntimeError('MISSING_REQUIRED_CONFIGURATION:'+','.join(missing))
    validate_deployment(host='127.0.0.1',registry_path=os.environ['ODMM_REGISTRY_DB'],
                        grants_path=os.environ['ODMM_GRANTS_DB'],jwks_path=os.environ['ODMM_OIDC_JWKS_PATH'])
    db_path=Path(os.environ['ODMM_SESSION_DB']).absolute()
    if db_path in {Path(os.environ[k]).absolute() for k in ('ODMM_REGISTRY_DB','ODMM_GRANTS_DB','ODMM_OIDC_JWKS_PATH')}:
        raise ValueError('SESSION_DB_MUST_BE_SEPARATE')
    jwks=json.loads(Path(os.environ['ODMM_OIDC_JWKS_PATH']).read_text())
    verifier=OIDCVerifier(issuer=os.environ['ODMM_OIDC_ISSUER'],audience=os.environ['ODMM_OIDC_AUDIENCE'],jwks=jwks)
    config=BrowserOIDCConfig(authorization_endpoint=os.environ['ODMM_OIDC_AUTHORIZATION_ENDPOINT'],
                             token_endpoint=os.environ['ODMM_OIDC_TOKEN_ENDPOINT'],
                             client_id=os.environ['ODMM_OIDC_CLIENT_ID'],
                             redirect_uri=os.environ['ODMM_OIDC_REDIRECT_URI'],public_origin=os.environ['ODMM_PUBLIC_ORIGIN'])
    return create_browser_app(registry_path=os.environ['ODMM_REGISTRY_DB'],grants_path=os.environ['ODMM_GRANTS_DB'],
                              verifier=verifier,config=config,session_store=SQLiteOIDCStore(db_path))

def main():
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--host',default='127.0.0.1');parser.add_argument('--port',type=int,default=8787)
    args=parser.parse_args()
    import ipaddress
    try: loopback=ipaddress.ip_address(args.host).is_loopback
    except ValueError: loopback=False
    if not loopback or not 1<=args.port<=65535: parser.error('loopback address and valid port required')
    app=create_from_environment()
    import uvicorn
    uvicorn.run(app,host=args.host,port=args.port,proxy_headers=False,access_log=False)

if __name__=='__main__': main()
