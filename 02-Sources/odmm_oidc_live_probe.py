"""ODMM V198.7: safe read-only OIDC discovery/JWKS qualification probe.
Author: Abdelhalim Talbi. No migration engine interaction.
"""
import argparse
import json
import ssl
import urllib.parse
import urllib.request

MAX_BYTES = 1024 * 1024

def validate_https(url):
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.fragment:
        raise ValueError("HTTPS_REQUIRED")
    return url.rstrip("/")

def validate_discovery(issuer, discovery):
    if not isinstance(discovery, dict) or discovery.get("issuer") != issuer:
        raise ValueError("ISSUER_MISMATCH")
    for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        endpoint = validate_https(discovery.get(name, ""))
        if urllib.parse.urlsplit(endpoint).hostname != urllib.parse.urlsplit(issuer).hostname:
            raise ValueError("CROSS_HOST_ENDPOINT:" + name)
    if "S256" not in discovery.get("code_challenge_methods_supported", []):
        raise ValueError("PKCE_S256_NOT_ADVERTISED")
    return True

def validate_jwks(data):
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        raise ValueError("INVALID_JWKS")
    kids = set()
    for key in data["keys"]:
        if not isinstance(key, dict) or key.get("kty") not in ("RSA", "EC") or not isinstance(key.get("kid"), str) or not key["kid"]:
            raise ValueError("INVALID_KEY")
        if key["kid"] in kids:
            raise ValueError("DUPLICATE_KID")
        kids.add(key["kid"])
        if key.get("kty") == "RSA" and not (key.get("n") and key.get("e")):
            raise ValueError("INCOMPLETE_RSA_KEY")
        if key.get("kty") == "EC" and not all(key.get(k) for k in ("crv", "x", "y")):
            raise ValueError("INCOMPLETE_EC_KEY")
    if not kids:
        raise ValueError("EMPTY_JWKS")
    return len(kids)

def fetch_json(url, context=None, timeout=8):
    validate_https(url)
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "ODMM-OIDC-Qualification/198.7"})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            raise ValueError("REDIRECT_FORBIDDEN")
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context or ssl.create_default_context()), NoRedirect())
    with opener.open(req, timeout=timeout) as resp:
        if resp.geturl() != url:
            raise ValueError("REDIRECT_FORBIDDEN")
        content = resp.read(MAX_BYTES + 1)
        if len(content) > MAX_BYTES:
            raise ValueError("OVERSIZED_RESPONSE")
        return json.loads(content)

def qualify(issuer, fetch=fetch_json):
    issuer = validate_https(issuer)
    discovery_url = issuer + "/.well-known/openid-configuration"
    discovery = fetch(discovery_url)
    validate_discovery(issuer, discovery)
    keys = validate_jwks(fetch(discovery["jwks_uri"]))
    return {"status": "PASS", "issuer": issuer, "jwks_key_count": keys,
            "scope": "discovery-and-jwks-only", "authentication_flow_tested": False}

def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only TLS-verified OIDC discovery/JWKS probe")
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--output", help="Optional JSON report path")
    args = parser.parse_args(argv)
    try:
        result = qualify(args.issuer)
        rc = 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        result = {"status": "FAIL", "reason": type(exc).__name__ + ":" + str(exc)}
        rc = 2
    payload = json.dumps(result, indent=2, sort_keys=True)
    print(payload)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
    return rc

if __name__ == "__main__":
    raise SystemExit(main())
