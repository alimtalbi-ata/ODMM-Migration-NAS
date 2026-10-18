# ODMM V197.4 / Compact V4.8.4 — Local-only deployment guard

Auteur : Abdelhalim Talbi

## Delivered
- `odmm_secure_deploy.py` CLI launcher: numeric loopback bind only, no forwarded-header trust, no access logs, three separate existing files, no JWKS symlinks or group/world writable JWKS.
- OIDC verifier: reject token-provided remote key references; cap token lifetime at 1 hour; enforce authorized party when multiple audiences are present.
- `test_odmm_secure_deploy_v1974.py` tests.

## Run (Linux/Windows)
Install `fastapi`, `uvicorn`, `cryptography`; configure `ODMM_REGISTRY_DB`, `ODMM_GRANTS_DB`, `ODMM_OIDC_JWKS_PATH`, `ODMM_OIDC_ISSUER`, `ODMM_OIDC_AUDIENCE` and run:

`python -m odmm_secure_deploy --host 127.0.0.1 --port 8787`

For remote access, use an externally configured and audited TLS reverse proxy and trusted identity provider. **Not a full Authorization Code + PKCE login**; requires bearer token acquired through an external trusted flow. Do not expose the listener directly. No automatic cutover, migration write, external-engine fallback or destructive action. Existing legacy entrypoints must not be distributed. Production qualification outstanding.
