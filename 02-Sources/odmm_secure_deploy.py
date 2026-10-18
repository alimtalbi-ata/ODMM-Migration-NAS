"""V197.4 local-only launch guard. TLS termination and PKCE login remain external."""
import ipaddress
import os
from pathlib import Path

def validate_deployment(*, host, registry_path, grants_path, jwks_path):
    try:
        address=ipaddress.ip_address(host)
    except ValueError:
        raise ValueError('NUMERIC_LOOPBACK_ADDRESS_REQUIRED') from None
    if not address.is_loopback:
        raise ValueError('NON_LOOPBACK_BIND_REJECTED')
    paths=[Path(x).absolute() for x in (registry_path,grants_path,jwks_path)]
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError('INPUT_FILE_MUST_EXIST_AND_NOT_BE_SYMLINK')
    if len(set(paths))!=3:
        raise ValueError('SEPARATE_REGISTRY_GRANTS_JWKS_REQUIRED')
    if os.name=='posix':
        jwks=paths[2]
        if jwks.stat().st_mode & 0o022:
            raise ValueError('JWKS_WRITABLE_BY_GROUP_OR_OTHER')
    return True

def main():
    import argparse
    parser=argparse.ArgumentParser(description='ODMM V197.4 guarded local OIDC server')
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=8787)
    args=parser.parse_args()
    required=('ODMM_REGISTRY_DB','ODMM_GRANTS_DB','ODMM_OIDC_JWKS_PATH')
    if any(not os.environ.get(k) for k in required):
        parser.error('Missing required ODMM paths')
    validate_deployment(host=args.host,registry_path=os.environ[required[0]],grants_path=os.environ[required[1]],jwks_path=os.environ[required[2]])
    if not 1<=args.port<=65535: parser.error('Invalid port')
    from odmm_oidc_http_entrypoint import create_from_environment
    app=create_from_environment()
    import uvicorn
    uvicorn.run(app,host=args.host,port=args.port,proxy_headers=False,access_log=False)

if __name__=='__main__': main()
