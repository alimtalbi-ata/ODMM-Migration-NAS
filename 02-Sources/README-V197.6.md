# ODMM V197.6 / Compact V4.8.6 — Persistent OIDC sessions
Auteur : Abdelhalim Talbi

## Delivered
- `odmm_oidc_session_store.py`: separate SQLite database for one-time authorization state and hashed session identifiers; atomic state consumption with `BEGIN IMMEDIATE`; shared across local workers; expiration and explicit `cleanup()`; no access/ID tokens stored in session database.
- `odmm_oidc_browser.py`: optional persistent store while preserving existing in-memory adapter for backward compatibility.
- `odmm_browser_deploy.py`: opt-in browser deployment using environment-pinned issuer, audience, JWKS, authorization and token endpoints, exact HTTPS origin/callback, separate session database and loopback-only listener.
- `test_odmm_oidc_session_store.py`: cross-instance and expiry tests.

## Launch
Supply `ODMM_REGISTRY_DB`, `ODMM_GRANTS_DB`, `ODMM_OIDC_JWKS_PATH`, `ODMM_OIDC_ISSUER`, `ODMM_OIDC_AUDIENCE`, `ODMM_OIDC_AUTHORIZATION_ENDPOINT`, `ODMM_OIDC_TOKEN_ENDPOINT`, `ODMM_OIDC_CLIENT_ID`, `ODMM_PUBLIC_ORIGIN`, `ODMM_OIDC_REDIRECT_URI`, `ODMM_SESSION_DB`.

Run `python -m odmm_browser_deploy --host 127.0.0.1 --port 8787` behind a trusted HTTPS reverse proxy. Do not expose the loopback HTTP port. Sessions are shared only if processes access the same SQLite database on a supported local filesystem. Invoke `SQLiteOIDCStore.cleanup()` from a trusted scheduled maintenance task; no autonomous cleanup daemon is installed.

## Not qualified
No live Keycloak test, no HA across hosts, no automatic JWKS rotation, no production reverse proxy deployment, no browser penetration test, no full suite rerun. Historical unscoped code is still in cumulative archive. This is a development package, not a production-ready installer.
