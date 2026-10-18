"""Offline configuration checks for an operator-supplied OIDC test environment."""
import ipaddress
import os
from urllib.parse import urlsplit

REQUIRED = ('ODMM_OIDC_ISSUER','ODMM_OIDC_AUTHORIZATION_ENDPOINT','ODMM_OIDC_TOKEN_ENDPOINT','ODMM_PUBLIC_ORIGIN','ODMM_OIDC_REDIRECT_URI','ODMM_OIDC_CLIENT_ID')

def validate_config(env):
    missing=[k for k in REQUIRED if not env.get(k)]
    if missing: raise ValueError('MISSING:'+','.join(missing))
    parsed={k:urlsplit(env[k]) for k in REQUIRED if k!='ODMM_OIDC_CLIENT_ID'}
    for key,url in parsed.items():
        if url.scheme!='https' or not url.hostname or url.username or url.password or url.fragment:
            raise ValueError('INVALID_HTTPS_URL:'+key)
        try:
            if not ipaddress.ip_address(url.hostname).is_global: raise ValueError('NON_PUBLIC_IP:'+key)
        except ValueError as exc:
            if str(exc).startswith('NON_PUBLIC_IP:'): raise
    if env['ODMM_OIDC_REDIRECT_URI'] != env['ODMM_PUBLIC_ORIGIN'].rstrip('/')+'/auth/callback':
        raise ValueError('REDIRECT_MISMATCH')
    if not env['ODMM_OIDC_CLIENT_ID'].strip(): raise ValueError('EMPTY_CLIENT_ID')
    return True

def main():
    try: validate_config(os.environ)
    except ValueError as exc:
        print('FAIL:',exc)
        return 2
    print('PASS: OIDC URL configuration shape (no network or identity-provider verification)')
    return 0

if __name__=='__main__': raise SystemExit(main())
